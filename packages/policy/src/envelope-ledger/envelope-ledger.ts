/**
 * envelope-ledger.ts -- EnvelopeLedger production implementation
 *
 * Responsibilities:
 *   - claim(envelopeId): atomically insert a PENDING row + TTL lease
 *   - finalize(envelopeId, resultSummary?): PENDING → COMMITTED + same-transaction ActionRecord write
 *   - reject(envelopeId): PENDING → REJECTED
 *   - expireStalePending(): batch-reclaim TTL-expired PENDING rows → EXPIRED
 *   - getEntry(envelopeId): query the latest non-EXPIRED row (or the latest among all rows)
 *
 * Same-transaction pattern (frozen, reused by PostgresSideTableAppender):
 *   withTransaction(pool, async (client) => {
 *     await client.query('UPDATE ... SET status=COMMITTED WHERE ...');
 *     await actionRecorder.record(input); // ActionRecorder also runs inside the same client transaction
 *   });
 *
 * Note: ActionRecorder.record() internally calls withTransaction(this.dbPool, ...),
 * which opens a new transaction. EnvelopeLedger.finalize() does not call record() directly;
 * instead, after finalize returns FinalizeSuccess, the caller (orchestrator) calls
 * actionRecorder.record() within the same outer transaction, passing the shared
 * transaction through the client parameter.
 *
 * A cleaner pattern: EnvelopeLedger exposes a finalizeWithinTransaction(client, ...) method,
 * and the caller uses withTransaction(pool, async (client) => {
 *   await ledger.finalizeWithinTransaction(client, envelopeId, resultSummary);
 *   await actionRecorder.recordWithClient(client, input); // future pattern
 * });
 *
 * Current implementation: two paths coexist:
 *   1. finalize() — self-managed transaction (suitable when no ActionRecord is needed)
 *   2. finalizeWithinTransaction(client) — caller passes in a PoolClient (shared-transaction pattern)
 *
 * Constraints:
 *   - the status field is validated at runtime (parseLedgerClaimStatus); no brand cast allowed
 *   - fail-closed; an invalid status throws
 *   - SQL migration 006 pre-allocated
 *
 */

import type { PoolClient } from 'pg';

import { withTransaction, type DatabasePool } from '@coivitas/shared';

import type {
    ClaimResult,
    ExpireResult,
    FinalizeResult,
    RejectResult,
} from './types.js';
import {
    parseLedgerClaimStatus,
    type EnvelopeLedgerEntry,
    type ClaimConflictReason,
} from './types.js';

// ---------------------------------------------------------------------------
// DB row mapping (internal)
// ---------------------------------------------------------------------------

interface DbRow {
    id: string;
    envelope_id: string;
    status: unknown; // validated at runtime
    ttl_seconds: string; // pg: int4 → string? node pg parses int as number by default, but handle defensively
    claimer_id: string | null; // optional ownership binding
    claimed_at: Date;
    finalized_at: Date | null;
    result_summary: Record<string, unknown> | null;
    created_at: Date;
}

function mapRow(row: DbRow): EnvelopeLedgerEntry {
    return {
        id: String(row.id),
        envelopeId: row.envelope_id,
        status: parseLedgerClaimStatus(row.status), // runtime validation (no brand cast)
        ttlSeconds: typeof row.ttl_seconds === 'string'
            ? parseInt(row.ttl_seconds, 10)
            : Number(row.ttl_seconds),
        claimerId: row.claimer_id ?? null, // ownership identifier
        claimedAt: row.claimed_at,
        finalizedAt: row.finalized_at,
        resultSummary: row.result_summary,
        createdAt: row.created_at,
    };
}

// ---------------------------------------------------------------------------
// EnvelopeLedgerOptions
// ---------------------------------------------------------------------------

export interface EnvelopeLedgerOptions {
    /** PostgreSQL connection pool */
    readonly pool: DatabasePool;
    /** Default TTL in seconds (used on claim; defaults to 30s) */
    readonly defaultTtlSeconds?: number;
}

// ---------------------------------------------------------------------------
// EnvelopeLedger
// ---------------------------------------------------------------------------

/**
 * EnvelopeLedger — EnvelopeLedger production implementation.
 *
 * Thread safety: all write operations use SELECT FOR UPDATE row-level locks, supporting concurrent access.
 */
export class EnvelopeLedger {
    private readonly pool: DatabasePool;
    private readonly defaultTtlSeconds: number;

    constructor(options: EnvelopeLedgerOptions) {
        this.pool = options.pool;
        this.defaultTtlSeconds = options.defaultTtlSeconds ?? 30;
    }

    // -----------------------------------------------------------------------
    // claim() -- atomically insert PENDING + TTL lease
    // -----------------------------------------------------------------------

    /**
     * Atomic claim: insert a PENDING row.
     *
     * Concurrency safety:
     *   - the entire terminal-state check + INSERT is wrapped in a single transaction (SELECT FOR UPDATE locks the terminal row),
     *     preventing TOCTOU: another transaction commits finalize after the check, causing claim to still insert a PENDING after a terminal row exists
     *   - relies on the partial unique index (WHERE status='PENDING') to guarantee concurrent uniqueness
     *   - on a racing claim, INSERT triggers a unique violation (PG code 23505) → ClaimConflict (ALREADY_PENDING)
     *
     * @param envelopeId envelope business identifier
     * @param ttlSeconds TTL in seconds (overrides the default)
     * @param claimerId optional claimer identifier (ownership binding, used for finalize/reject verification)
     */
    async claim(
        envelopeId: string,
        ttlSeconds?: number,
        claimerId?: string | null,
    ): Promise<ClaimResult> {
        const ttl = ttlSeconds ?? this.defaultTtlSeconds;

        // Atomic terminal-state check + INSERT within the transaction.
        // Problem: locking only terminal rows is not enough — a concurrent transaction may hold a PENDING row
        // and finalize it (PENDING → COMMITTED) only after the terminal-state check, making the PENDING
        // partial unique index entry disappear, causing INSERT to create a new (dangling) PENDING.
        // Fix: also lock the PENDING row within SELECT FOR UPDATE.
        // - If another transaction is finalizing the PENDING, FOR UPDATE blocks until that transaction commits, after which:
        // a) if it became COMMITTED → this SELECT sees COMMITTED → returns ALREADY_TERMINAL
        // b) if unchanged (not finalized) → this SELECT sees PENDING → INSERT unique violation → ALREADY_PENDING
        // - This way no dangling PENDING is produced under any concurrent ordering
        return withTransaction(this.pool, async (client) => {
            // Lock any existing PENDING / COMMITTED / REJECTED row (FOR UPDATE)
            const existingCheck = await client.query<{ id: string; status: unknown }>(
                `SELECT id, status FROM policy.envelope_ledger
                 WHERE envelope_id = $1
                   AND status IN ('PENDING', 'COMMITTED', 'REJECTED')
                 LIMIT 1
                 FOR UPDATE`,
                [envelopeId],
            );

            if (existingCheck.rows.length > 0) {
                const existingStatus = existingCheck.rows[0]!.status;
                if (existingStatus === 'COMMITTED' || existingStatus === 'REJECTED') {
                    return {
                        claimed: false,
                        reason: 'ALREADY_TERMINAL' satisfies ClaimConflictReason,
                        envelopeId,
                    } satisfies ClaimResult;
                }
                // existingStatus === 'PENDING': a PENDING row already exists
                return {
                    claimed: false,
                    reason: 'ALREADY_PENDING' satisfies ClaimConflictReason,
                    envelopeId,
                } satisfies ClaimResult;
            }

            // No active row (or only EXPIRED rows): attempt INSERT.
            // Note: even if two concurrent transactions both see 0 rows and INSERT simultaneously,
            // the partial unique index still blocks the second INSERT (23505). This catch handles that extreme concurrency case.
            try {
                const result = await client.query<DbRow>(
                    `INSERT INTO policy.envelope_ledger
                        (envelope_id, status, ttl_seconds, claimer_id, claimed_at, created_at)
                     VALUES ($1, 'PENDING', $2, $3, clock_timestamp(), clock_timestamp())
                     RETURNING id, envelope_id, status, ttl_seconds, claimer_id,
                               claimed_at, finalized_at, result_summary, created_at`,
                    [envelopeId, ttl, claimerId ?? null],
                );

                const row = result.rows[0];
                if (!row) {
                    throw new Error(
                        `EnvelopeLedger.claim: INSERT returned no rows for envelope_id=${envelopeId}`,
                    );
                }

                const entry = mapRow(row);

                return {
                    claimed: true,
                    id: entry.id,
                    envelopeId: entry.envelopeId,
                    status: 'PENDING',
                    claimedAt: entry.claimedAt,
                    ttlSeconds: entry.ttlSeconds,
                } satisfies ClaimResult;
            } catch (error: unknown) {
                // Extreme concurrency (both transactions SELECT 0 rows and INSERT simultaneously) → unique violation
                if (isPgUniqueViolation(error)) {
                    return {
                        claimed: false,
                        reason: 'ALREADY_PENDING' satisfies ClaimConflictReason,
                        envelopeId,
                    } satisfies ClaimResult;
                }
                throw error;
            }
        });
    }

    // -----------------------------------------------------------------------
    // finalize() -- self-managed transaction (single-operation case)
    // -----------------------------------------------------------------------

    /**
     * finalize: PENDING → COMMITTED (self-managed transaction).
     *
     * Suitable when no same-transaction ActionRecord write is needed.
     * When a same-transaction ActionRecord write is needed, use finalizeWithinTransaction().
     *
     * @param envelopeId envelope business identifier
     * @param resultSummary final result summary (optional)
     * @param claimerId optional ownership verification: only the same claimer as in claim() may finalize
     */
    async finalize(
        envelopeId: string,
        resultSummary?: Record<string, unknown> | null,
        claimerId?: string | null,
    ): Promise<FinalizeResult> {
        return withTransaction(this.pool, (client) =>
            this.finalizeWithinTransaction(client, envelopeId, resultSummary, claimerId),
        );
    }

    // -----------------------------------------------------------------------
    // finalizeWithinTransaction() -- shared-transaction pattern (reuse point)
    // -----------------------------------------------------------------------

    /**
     * finalize (shared-transaction version): PENDING → COMMITTED, executed within a PoolClient transaction provided by the caller.
     *
     * Design notes (shared-transaction reuse interface contract):
     *   - the caller uses withTransaction(pool, async (client) => {
     *       await ledger.finalizeWithinTransaction(client, envelopeId, resultSummary);
     *       await sideTableAppender.append(entry, client); // same client, same transaction
     *     });
     *   - if any operation fails → the whole transaction ROLLBACKs and both are rolled back
     *   - the client is managed by the caller (no BEGIN/COMMIT/ROLLBACK/release inside this method)
     *
     * Ownership and expiry handling:
     *   - optional claimerId parameter; if provided, SELECT/UPDATE add the ownership verification condition
     *     `AND (claimer_id IS NULL OR claimer_id = $claimerId)`
     *   - on LEASE_EXPIRED, the row is passively marked as EXPIRED (atomically, without waiting for the sweeper),
     *     so subsequent claim() is no longer blocked by ALREADY_PENDING
     *
     * @param client transaction PoolClient held by the caller
     * @param envelopeId envelope business identifier
     * @param resultSummary final result summary (optional)
     * @param claimerId optional ownership verification: only the same claimer as in claim() is allowed
     */
    async finalizeWithinTransaction(
        client: PoolClient,
        envelopeId: string,
        resultSummary?: Record<string, unknown> | null,
        claimerId?: string | null,
    ): Promise<FinalizeResult> {
        // SELECT FOR UPDATE: row-level lock to prevent concurrent finalize.
        // Also check that the TTL has not expired (claimed_at + ttl_seconds * interval < NOW()).
        // If claimerId is provided, add the ownership verification condition (claimer_id IS NULL OR claimer_id = $2).
        const ownershipClause =
            claimerId != null
                ? `AND (claimer_id IS NULL OR claimer_id = $2)`
                : '';
        const selectParams: unknown[] = claimerId != null
            ? [envelopeId, claimerId]
            : [envelopeId];

        // Use clock_timestamp() rather than NOW().
        // PostgreSQL's NOW() returns the transaction start time (transaction_timestamp()),
        // which does not advance over time during a long transaction or lock wait.
        // clock_timestamp() returns the current real wall-clock time, correctly reflecting whether the TTL has expired.
        const selectResult = await client.query<DbRow>(
            `SELECT id, envelope_id, status, ttl_seconds, claimer_id,
                    claimed_at, finalized_at, result_summary, created_at
             FROM policy.envelope_ledger
             WHERE envelope_id = $1
               AND status = 'PENDING'
               AND claimed_at + ttl_seconds * interval '1 second' >= clock_timestamp()
               ${ownershipClause}
             FOR UPDATE`,
            selectParams,
        );

        if (selectResult.rows.length === 0) {
            // No valid PENDING row; the reason needs to be distinguished further.
            // First check whether an expired (TTL-expired) PENDING row exists, and atomically mark it as EXPIRED.
            // Also use clock_timestamp() to ensure accurate TTL comparison.
            const expiredPendingResult = await client.query<{ id: string }>(
                `UPDATE policy.envelope_ledger
                 SET status = 'EXPIRED',
                     finalized_at = clock_timestamp()
                 WHERE envelope_id = $1
                   AND status = 'PENDING'
                   AND claimed_at + ttl_seconds * interval '1 second' < clock_timestamp()
                 RETURNING id`,
                [envelopeId],
            );

            if (expiredPendingResult.rows.length > 0) {
                // The PENDING row exists but its TTL has expired → passively mark it as EXPIRED.
                // Subsequent claim() is no longer blocked by ALREADY_PENDING.
                return {
                    finalized: false,
                    reason: 'LEASE_EXPIRED',
                    envelopeId,
                };
            }

            // Check whether a terminal row already exists
            const finalResult = await client.query<{ status: unknown }>(
                `SELECT status FROM policy.envelope_ledger
                 WHERE envelope_id = $1
                   AND status IN ('COMMITTED', 'REJECTED')
                 LIMIT 1`,
                [envelopeId],
            );

            if (finalResult.rows.length > 0) {
                return {
                    finalized: false,
                    reason: 'ALREADY_FINAL',
                    envelopeId,
                };
            }

            return {
                finalized: false,
                reason: 'NOT_FOUND',
                envelopeId,
            };
        }

        // The PENDING row exists and its TTL is valid: UPDATE to COMMITTED.
        // The ownership clause is also added to the UPDATE (to prevent a race between SELECT → UPDATE).
        const updateParams: unknown[] =
            claimerId != null
                ? [envelopeId, resultSummary ?? null, claimerId]
                : [envelopeId, resultSummary ?? null];
        const updateOwnershipClause =
            claimerId != null
                ? `AND (claimer_id IS NULL OR claimer_id = $3)`
                : '';

        // The UPDATE also uses clock_timestamp() to keep the TTL check consistent with the SELECT
        const updateResult = await client.query<{
            finalized_at: Date;
        }>(
            `UPDATE policy.envelope_ledger
             SET status = 'COMMITTED',
                 finalized_at = clock_timestamp(),
                 result_summary = $2
             WHERE envelope_id = $1
               AND status = 'PENDING'
               AND claimed_at + ttl_seconds * interval '1 second' >= clock_timestamp()
               ${updateOwnershipClause}
             RETURNING finalized_at`,
            updateParams,
        );

        const finalizedAt = updateResult.rows[0]?.finalized_at;
        if (!finalizedAt) {
            throw new Error(
                `EnvelopeLedger.finalizeWithinTransaction: UPDATE returned no rows ` +
                    `for envelope_id=${envelopeId}. Concurrent modification detected.`,
            );
        }

        return {
            finalized: true,
            envelopeId,
            status: 'COMMITTED',
            finalizedAt,
        };
    }

    // -----------------------------------------------------------------------
    // reject() -- PENDING → REJECTED
    // -----------------------------------------------------------------------

    /**
     * reject: PENDING → REJECTED (self-managed transaction).
     *
     * @param envelopeId envelope business identifier
     * @param claimerId optional ownership verification: only the same claimer as in claim() may reject
     */
    async reject(envelopeId: string, claimerId?: string | null): Promise<RejectResult> {
        return withTransaction(this.pool, (client) =>
            this.rejectWithinTransaction(client, envelopeId, claimerId),
        );
    }

    /**
     * reject (shared-transaction version): executed within a PoolClient transaction provided by the caller.
     *
     * Symmetric to finalizeWithinTransaction(), for use in same-transaction multi-operation scenarios.
     *
     * Optional claimerId ownership verification.
     *
     * @param client transaction PoolClient held by the caller
     * @param envelopeId envelope business identifier
     * @param claimerId optional ownership verification
     */
    async rejectWithinTransaction(
        client: PoolClient,
        envelopeId: string,
        claimerId?: string | null,
    ): Promise<RejectResult> {
        // SELECT FOR UPDATE: row-level lock.
        // If claimerId is provided, add the ownership verification condition.
        // reject may operate on a PENDING row in any TTL state (no TTL guard needed).
        const ownershipClause =
            claimerId != null
                ? `AND (claimer_id IS NULL OR claimer_id = $2)`
                : '';
        const selectParams: unknown[] = claimerId != null
            ? [envelopeId, claimerId]
            : [envelopeId];

        const selectResult = await client.query<DbRow>(
            `SELECT id FROM policy.envelope_ledger
             WHERE envelope_id = $1
               AND status = 'PENDING'
               ${ownershipClause}
             FOR UPDATE`,
            selectParams,
        );

        if (selectResult.rows.length === 0) {
            const finalResult = await client.query<{ status: unknown }>(
                `SELECT status FROM policy.envelope_ledger
                 WHERE envelope_id = $1
                   AND status IN ('COMMITTED', 'REJECTED')
                 LIMIT 1`,
                [envelopeId],
            );

            if (finalResult.rows.length > 0) {
                return {
                    rejected: false,
                    reason: 'ALREADY_FINAL',
                    envelopeId,
                };
            }

            return {
                rejected: false,
                reason: 'NOT_FOUND',
                envelopeId,
            };
        }

        const updateParams: unknown[] =
            claimerId != null
                ? [envelopeId, claimerId]
                : [envelopeId];
        const updateOwnershipClause =
            claimerId != null
                ? `AND (claimer_id IS NULL OR claimer_id = $2)`
                : '';

        const updateResult = await client.query<{
            finalized_at: Date;
        }>(
            `UPDATE policy.envelope_ledger
             SET status = 'REJECTED',
                 finalized_at = NOW()
             WHERE envelope_id = $1
               AND status = 'PENDING'
               ${updateOwnershipClause}
             RETURNING finalized_at`,
            updateParams,
        );

        const finalizedAt = updateResult.rows[0]?.finalized_at;
        if (!finalizedAt) {
            throw new Error(
                `EnvelopeLedger.rejectWithinTransaction: UPDATE returned no rows ` +
                    `for envelope_id=${envelopeId}. Concurrent modification detected.`,
            );
        }

        return {
            rejected: true,
            envelopeId,
            status: 'REJECTED',
            finalizedAt,
        };
    }

    // -----------------------------------------------------------------------
    // expireStalePending() -- batch TTL reclamation
    // -----------------------------------------------------------------------

    /**
     * Batch-reclaim TTL-expired PENDING rows → EXPIRED.
     *
     * The TTL comparison uses DB server-side time (to avoid app clock drift):
     *   claimed_at + ttl_seconds * interval '1 second' < NOW()
     *
     * EXPIRED rows are not constrained by the partial unique index, allowing the same envelope to be EXPIRED multiple times.
     * The caller may claim again after EXPIRED (crash-recovery scenario).
     *
     * @param limit maximum rows reclaimed per call (to prevent large-batch lock contention; defaults to 1000)
     */
    async expireStalePending(limit = 1000): Promise<ExpireResult> {
        // Fix: PostgreSQL does not support using LIMIT directly in UPDATE.
        // Correct approach: first select ids via a SELECT subquery with LIMIT (SKIP LOCKED to avoid lock contention),
        // then UPDATE the selected set of ids.
        // clock_timestamp() is used for the TTL comparison: accurately reflects the expiry time in long-transaction scenarios
        const result = await this.pool.query<{ count: string }>(
            `WITH to_expire AS (
                SELECT id
                FROM policy.envelope_ledger
                WHERE status = 'PENDING'
                  AND claimed_at + ttl_seconds * interval '1 second' < clock_timestamp()
                ORDER BY claimed_at ASC
                LIMIT $1
                FOR UPDATE SKIP LOCKED
             ),
             expired AS (
                UPDATE policy.envelope_ledger
                SET status = 'EXPIRED',
                    finalized_at = clock_timestamp()
                WHERE id IN (SELECT id FROM to_expire)
                RETURNING id
             )
             SELECT COUNT(*)::text AS count FROM expired`,
            [limit],
        );

        const count = parseInt(result.rows[0]?.count ?? '0', 10);
        return { expiredCount: count };
    }

    // -----------------------------------------------------------------------
    // getEntry() -- query the latest entry
    // -----------------------------------------------------------------------

    /**
     * Query the latest non-EXPIRED row for envelope_id.
     *
     * Prefers returning PENDING / COMMITTED / REJECTED (terminal rows);
     * if only EXPIRED rows exist, returns null (treated as "no valid claim").
     *
     * @param envelopeId envelope business identifier
     */
    async getEntry(envelopeId: string): Promise<EnvelopeLedgerEntry | null> {
        const result = await this.pool.query<DbRow>(
            `SELECT id, envelope_id, status, ttl_seconds, claimer_id,
                    claimed_at, finalized_at, result_summary, created_at
             FROM policy.envelope_ledger
             WHERE envelope_id = $1
               AND status != 'EXPIRED'
             ORDER BY id DESC
             LIMIT 1`,
            [envelopeId],
        );

        if (result.rows.length === 0) {
            return null;
        }

        return mapRow(result.rows[0]!);
    }

    /**
     * Query the latest row of any kind for envelope_id (including EXPIRED).
     *
     * For debugging and testing; production code should prefer getEntry().
     */
    async getLatestRow(envelopeId: string): Promise<EnvelopeLedgerEntry | null> {
        const result = await this.pool.query<DbRow>(
            `SELECT id, envelope_id, status, ttl_seconds, claimer_id,
                    claimed_at, finalized_at, result_summary, created_at
             FROM policy.envelope_ledger
             WHERE envelope_id = $1
             ORDER BY id DESC
             LIMIT 1`,
            [envelopeId],
        );

        if (result.rows.length === 0) {
            return null;
        }

        return mapRow(result.rows[0]!);
    }
}

// ---------------------------------------------------------------------------
// Internal helper: PG error type guard
// ---------------------------------------------------------------------------

/** Determine whether the error is a PostgreSQL unique violation (SQLSTATE 23505). */
function isPgUniqueViolation(error: unknown): boolean {
    return (
        typeof error === 'object' &&
        error !== null &&
        'code' in error &&
        (error as { code: unknown }).code === '23505'
    );
}
