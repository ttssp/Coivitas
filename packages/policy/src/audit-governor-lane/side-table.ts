/**
 * side-table.ts -- shadow audit side table append-only appender.
 *
 * Maintains a shadow side table for the action_records main table, providing a
 * tamper-evidence anchor. Each side table row contains:
 *   - the main table recordId + recordHash (cross-table reference)
 *   - rowHash = SHA-256(prevRowHash || recordId || recordHash || agentDid || createdAt)
 *   - prevRowHash (the previous row's rowHash, forming a hash chain)
 *
 * append-only constraint: the side table only allows INSERT, never UPDATE / DELETE.
 * tamper-evidence: if any main table row is tampered with, the side table row hash and the
 * main table row hash become inconsistent.
 *
 * Provides two implementations:
 *   - InMemorySideTableAppender: in-memory stub, for test fixtures only (@internal)
 *   - PostgresSideTableAppender: durable implementation, same-transaction atomic write
 *
 */

import { createHash } from 'node:crypto';

import { ProtocolError, type DID } from '@coivitas/types';
import type { PoolClient } from 'pg';

import type {
    MainTableRecordLoader,
    SideTableAppender,
    SideTableEntry,
    SideTableVerifyResult,
} from './types.js';

// ---------------------------------------------------------------------------
// GENESIS hash constant
// ---------------------------------------------------------------------------

/**
 * The genesis value of the side table hash chain (the prevRowHash at the head of the chain).
 * SHA-256 of the empty string = a known constant that any implementation can verify independently.
 */
export const SIDE_TABLE_GENESIS_HASH = createHash('sha256')
    .update('')
    .digest('hex');

// ---------------------------------------------------------------------------
// computeRowHash -- computes the side table row hash
// ---------------------------------------------------------------------------

/**
 * Computes the side table row hash.
 *
 * rowHash = SHA-256(prevRowHash || recordId || recordHash || agentDid || createdAt)
 *
 * Uses the '|' separator to prevent field-value concatenation ambiguity.
 */
export function computeRowHash(
    prevRowHash: string,
    recordId: string,
    recordHash: string,
    agentDid: string,
    createdAt: string,
): string {
    const preimage = [
        prevRowHash,
        recordId,
        recordHash,
        agentDid,
        createdAt,
    ].join('|');

    return createHash('sha256').update(preimage).digest('hex');
}

// ---------------------------------------------------------------------------
// Internal row structure
// ---------------------------------------------------------------------------

interface SideTableRow {
    recordId: string;
    recordHash: string;
    agentDid: DID;
    createdAt: string;
    rowHash: string;
    prevRowHash: string;
}

// ---------------------------------------------------------------------------
// InMemorySideTableAppender
// ---------------------------------------------------------------------------

/**
 * In-memory side table append-only appender.
 *
 * @internal Stub - RUNTIME_DEFERRED.
 * Minimal viable implementation, for use in test fixtures only.
 * Production environments must replace it with PostgresSideTableAppender (the durable version),
 * using the migration 010_audit_side_table.sql schema,
 * injected into the ActionRecorder(kind='control-plane') constructor.
 */
export class InMemorySideTableAppender implements SideTableAppender {
    /** Global chain (in append order) */
    private readonly rows: SideTableRow[] = [];

    /**
     * Appends a single side table record.
     *
     * @throws ProtocolError('INTERNAL_ERROR') if recordId already exists (guards against duplicate appends)
     */
    public append(
        entry: SideTableEntry,
        _transactionClient?: unknown,
    ): Promise<{ rowHash: string }> {
        // Guard against duplicate appends (append-only does not allow writing the same recordId twice)
        const exists = this.rows.some((r) => r.recordId === entry.recordId);
        if (exists) {
            return Promise.reject(
                new ProtocolError(
                    'INTERNAL_ERROR',
                    `SIDE_TABLE_ANCHOR_MISMATCH: recordId '${entry.recordId}' already exists in side table. ` +
                        `Append-only constraint violated.`,
                ),
            );
        }

        const prevRowHash =
            this.rows.length > 0
                ? this.rows[this.rows.length - 1]!.rowHash
                : SIDE_TABLE_GENESIS_HASH;

        const rowHash = computeRowHash(
            prevRowHash,
            entry.recordId,
            entry.recordHash,
            entry.agentDid as string,
            entry.createdAt as string,
        );

        this.rows.push({
            recordId: entry.recordId,
            recordHash: entry.recordHash,
            agentDid: entry.agentDid,
            createdAt: entry.createdAt as string,
            rowHash,
            prevRowHash,
        });

        return Promise.resolve({ rowHash });
    }

    /**
     * Verifies the integrity of the side table chain.
     *
     * Row-by-row verification:
     * 1. prevRowHash points to the previous row's rowHash (or genesis)
     * 2. rowHash === computeRowHash(prevRowHash, recordId, recordHash, agentDid, createdAt)
     * 3. When mainTableLoader is injected, for each row recordId read the main table's
     *    current hash and compare side-table snapshot.recordHash vs the current main hash:
     *    - main table row does not exist -> SIDE_TABLE_ANCHOR_MISSING
     *    - hash mismatch -> SIDE_TABLE_ROW_TAMPERED (the main table was tampered with)
     *
     * @param agentDid optional restriction to a given agent (the current implementation walks the whole chain, filtering by agentDid)
     * @param mainTableLoader optional main table record loader (cross-table tamper detection)
     */
    public async verifyChain(
        agentDid?: DID,
        mainTableLoader?: MainTableRecordLoader,
    ): Promise<SideTableVerifyResult> {
        const targetRows =
            agentDid !== undefined
                ? this.rows.filter(
                      (r) => (r.agentDid as string) === (agentDid as string),
                  )
                : this.rows;

        if (targetRows.length === 0) {
            return { valid: true as const };
        }

        // Whole-chain verification (even when filtering by agent, the global chain order is verified)
        for (let i = 0; i < this.rows.length; i++) {
            const row = this.rows[i]!;
            const expectedPrev =
                i === 0 ? SIDE_TABLE_GENESIS_HASH : this.rows[i - 1]!.rowHash;

            if (row.prevRowHash !== expectedPrev) {
                return {
                    valid: false as const,
                    brokenAt: row.recordId,
                    errorCode: 'SIDE_TABLE_ANCHOR_MISMATCH' as const,
                };
            }

            const expectedHash = computeRowHash(
                row.prevRowHash,
                row.recordId,
                row.recordHash,
                row.agentDid as string,
                row.createdAt,
            );

            if (row.rowHash !== expectedHash) {
                return {
                    valid: false as const,
                    brokenAt: row.recordId,
                    errorCode: 'SIDE_TABLE_ROW_TAMPERED' as const,
                };
            }

            // Cross-table comparison -- read the main table's current recordHash
            // to detect a main table row that was deleted or tampered with.
            if (mainTableLoader) {
                const mainRecord = await mainTableLoader.loadRecord(
                    row.recordId,
                );

                if (mainRecord === null) {
                    return {
                        valid: false as const,
                        brokenAt: row.recordId,
                        errorCode: 'SIDE_TABLE_ANCHOR_MISSING' as const,
                    };
                }

                if (mainRecord.recordHash !== row.recordHash) {
                    return {
                        valid: false as const,
                        brokenAt: row.recordId,
                        errorCode: 'SIDE_TABLE_ROW_TAMPERED' as const,
                    };
                }
            }
        }

        return { valid: true as const };
    }

    /** Internal: get the current row count (for tests). */
    public get size(): number {
        return this.rows.length;
    }

    /** Internal: clear the store (for tests). */
    public clear(): void {
        this.rows.length = 0;
    }

    /** Internal: get the last row's rowHash (for tests). */
    public getLastRowHash(): string | undefined {
        return this.rows[this.rows.length - 1]?.rowHash;
    }

    /** Internal: tamper with the recordHash of the given recordId (tests only, simulates tampering). */
    public _tamperRecordHash(recordId: string, newHash: string): void {
        const row = this.rows.find((r) => r.recordId === recordId);
        if (row) {
            row.recordHash = newHash;
        }
    }

    /** Internal: tamper with the prevRowHash of the given recordId (tests only, simulates tampering). */
    public _tamperPrevRowHash(recordId: string, newHash: string): void {
        const row = this.rows.find((r) => r.recordId === recordId);
        if (row) {
            row.prevRowHash = newHash;
        }
    }
}

// ---------------------------------------------------------------------------
// PostgresSideTableAppender
// ---------------------------------------------------------------------------

/** DB row structure (internal, corresponds to policy.audit_side_table). */
interface AuditSideTableRow {
    record_id: string;
    record_hash: string;
    agent_did: string;
    /**
     * pg deserializes TIMESTAMPTZ into a JavaScript Date object by default.
     * After reading a row, verifyChain must call normalizeCreatedAt() to convert it to an
     * ISO string before it participates in the hash computation, to ensure it matches the
     * ISO string format passed in at append time.
     */
    created_at: string | Date;
    row_hash: string;
    prev_row_hash: string;
}

// ---------------------------------------------------------------------------
// Utility: normalizeCreatedAt — unifies the TIMESTAMPTZ type to an ISO string
// ---------------------------------------------------------------------------

/**
 * Normalizes a TIMESTAMPTZ column value to an ISO 8601 string.
 *
 * The pg driver deserializes TIMESTAMPTZ into a JavaScript Date object by default,
 * whereas append() writes using SideTableEntry.createdAt (an ISO string).
 * Feeding the two formats directly into the hash yields different results
 * (Date.toString() vs Date.toISOString()).
 *
 * Rule: whether the input is a Date or already a string, always output an ISO 8601 string.
 */
function normalizeCreatedAt(value: string | Date): string {
    return value instanceof Date ? value.toISOString() : String(value);
}

// ---------------------------------------------------------------------------
// advisory lock constant
// ---------------------------------------------------------------------------

/**
 * PostgreSQL advisory lock ID for audit_side_table append operations.
 *
 * Uses a transaction-level advisory lock (pg_advisory_xact_lock), acquired before
 * SELECT FOR UPDATE, to ensure that only one transaction can append a new row at a time,
 * eliminating concurrent-write races.
 *
 * Value: 0x5ADD7AB1E_0001n (a play on "side table" + a fixed low-order sequence number)
 * bigint range: a PostgreSQL advisory lock id is int8 (64-bit signed); this constant is well within range.
 */
const AUDIT_SIDE_TABLE_ADVISORY_LOCK_ID = BigInt('0x5ADD7AB10001');

/**
 * Postgres durable side table append-only appender.
 *
 * Implementation notes:
 *   - Must execute within the same pg transaction as the main table INSERT (same-transaction atomic write pattern, reusing the finalize pattern)
 *   - A missing or invalid-type transactionClient -> throw fail-closed
 *   - prevRowHash is obtained via SELECT FOR UPDATE on the latest row (exclusive lock against concurrent-write races)
 *   - rowHash computation is identical to InMemorySideTableAppender (using the shared computeRowHash)
 *   - verifyChain uses the injected pool (read-only path, no transaction needed)
 *
 */
export class PostgresSideTableAppender implements SideTableAppender {
    /**
     * @param pool pg.Pool instance, used for verifyChain read-only queries.
     *   append() does not use this pool; it must use the passed-in transactionClient.
     */
    constructor(private readonly pool: { query: (sql: string, params?: unknown[]) => Promise<{ rows: unknown[] }> }) {}

    /**
     * Appends a single side table record.
     *
     * A valid pg.PoolClient (within a transaction) must be passed in.
     * Missing or invalid -> throw ProtocolError('INTERNAL_ERROR') fail-closed.
     *
     * Algorithm:
     *   1. type guard verifies transactionClient is a PoolClient (checks the .query method)
     *   2. SELECT FOR UPDATE fetches the latest row's row_hash (exclusive lock against concurrent-write races)
     *   3. compute the new row's rowHash (identical to InMemory)
     *   4. INSERT INTO policy.audit_side_table (within the passed-in client transaction)
     *
     * @throws ProtocolError('INTERNAL_ERROR') when transactionClient is missing/invalid or the INSERT fails
     */
    public async append(
        entry: SideTableEntry,
        transactionClient?: unknown,
    ): Promise<{ rowHash: string }> {
        // fail-closed: transactionClient must be a valid PoolClient
        const client = assertPoolClient(transactionClient);

        // advisory lock (transaction-level): serializes audit_side_table append operations.
        // pg_advisory_xact_lock is released automatically when the transaction ends; it only
        // blocks concurrent appends holding the same lock ID and does not affect read-only
        // paths such as verifyChain.
        await client.query(
            `SELECT pg_advisory_xact_lock($1)`,
            [AUDIT_SIDE_TABLE_ADVISORY_LOCK_ID.toString()],
        );

        // SELECT FOR UPDATE: fetch the latest row's row_hash (exclusive lock, prevents concurrent racing writes)
        // Same pattern as FOR UPDATE in finalizeWithinTransaction
        const prevResult = await client.query<{ row_hash: string }>(
            `SELECT row_hash
             FROM policy.audit_side_table
             ORDER BY id DESC
             LIMIT 1
             FOR UPDATE`,
        );

        const prevRowHash =
            prevResult.rows.length > 0
                ? prevResult.rows[0]!.row_hash
                : SIDE_TABLE_GENESIS_HASH;

        // Compute the new row's rowHash (identical to InMemory)
        const createdAt = entry.createdAt as string;
        const rowHash = computeRowHash(
            prevRowHash,
            entry.recordId,
            entry.recordHash,
            entry.agentDid as string,
            createdAt,
        );

        // INSERT uses the passed-in client (no new connection)
        await client.query(
            `INSERT INTO policy.audit_side_table
                (record_id, record_hash, agent_did, created_at, row_hash, prev_row_hash)
             VALUES ($1, $2, $3, $4, $5, $6)`,
            [
                entry.recordId,
                entry.recordHash,
                entry.agentDid as string,
                createdAt,
                rowHash,
                prevRowHash,
            ],
        );

        return { rowHash };
    }

    /**
     * Verifies the integrity of the side table chain (Postgres implementation).
     *
     * Reads all rows from the DB (ordered by id ASC) and verifies the hash chain integrity row by row.
     * Supports optional agentDid filtering and mainTableLoader cross-table comparison (semantics identical to InMemory).
     */
    public async verifyChain(
        agentDid?: DID,
        mainTableLoader?: MainTableRecordLoader,
    ): Promise<SideTableVerifyResult> {
        // Read the whole chain (read-only query, uses pool rather than transactionClient)
        const allResult = await this.pool.query(
            `SELECT record_id, record_hash, agent_did, created_at, row_hash, prev_row_hash
             FROM policy.audit_side_table
             ORDER BY id ASC`,
        );

        const allRows = allResult.rows as AuditSideTableRow[];

        // agentDid filter (same semantics as InMemory: filter target rows by agentDid, verify the whole-chain order)
        const targetRows =
            agentDid !== undefined
                ? allRows.filter((r) => r.agent_did === (agentDid as string))
                : allRows;

        if (targetRows.length === 0) {
            return { valid: true as const };
        }

        // Whole-chain verification (same as InMemory: even with an agentDid filter, the global chain order is still verified)
        for (let i = 0; i < allRows.length; i++) {
            const row = allRows[i]!;
            const expectedPrev =
                i === 0 ? SIDE_TABLE_GENESIS_HASH : allRows[i - 1]!.row_hash;

            if (row.prev_row_hash !== expectedPrev) {
                return {
                    valid: false as const,
                    brokenAt: row.record_id,
                    errorCode: 'SIDE_TABLE_ANCHOR_MISMATCH' as const,
                };
            }

            // The pg driver deserializes TIMESTAMPTZ into a Date, so it must first be
            // normalized to an ISO string before participating in the hash computation
            // (matching the format written by append()).
            const createdAtNormalized = normalizeCreatedAt(row.created_at);

            const expectedHash = computeRowHash(
                row.prev_row_hash,
                row.record_id,
                row.record_hash,
                row.agent_did,
                createdAtNormalized,
            );

            if (row.row_hash !== expectedHash) {
                return {
                    valid: false as const,
                    brokenAt: row.record_id,
                    errorCode: 'SIDE_TABLE_ROW_TAMPERED' as const,
                };
            }

            // Cross-table tamper detection (same as InMemory)
            if (mainTableLoader) {
                const mainRecord = await mainTableLoader.loadRecord(row.record_id);

                if (mainRecord === null) {
                    return {
                        valid: false as const,
                        brokenAt: row.record_id,
                        errorCode: 'SIDE_TABLE_ANCHOR_MISSING' as const,
                    };
                }

                if (mainRecord.recordHash !== row.record_hash) {
                    return {
                        valid: false as const,
                        brokenAt: row.record_id,
                        errorCode: 'SIDE_TABLE_ROW_TAMPERED' as const,
                    };
                }
            }
        }

        return { valid: true as const };
    }
}

// ---------------------------------------------------------------------------
// Utility: assertPoolClient — type guard
// ---------------------------------------------------------------------------

/**
 * Asserts that transactionClient is a valid pg.PoolClient (duck typing).
 *
 * Checks:
 *   - typeof === 'object' && not null
 *   - has a .query function (both PoolClient and Pool have it, so it cannot decide alone)
 *   - has a .release function (unique to PoolClient; pg.Pool has no .release, but has .connect/.end)
 *
 * If a pg.Pool is passed in (pool.query auto-acquires/releases, not within a transaction),
 * append would execute on a new connection, breaking the same-transaction atomic write contract.
 * This check rejects pg.Pool at the type level, ensuring the caller must pass client = await pool.connect().
 *
 * Failure -> throw ProtocolError('INTERNAL_ERROR') fail-closed.
 * Avoids a direct instanceof check (sidesteps circular dependencies + the types package must not depend on pg).
 */
function assertPoolClient(transactionClient: unknown): PoolClient {
    if (
        typeof transactionClient === 'object' &&
        transactionClient !== null &&
        'query' in transactionClient &&
        typeof (transactionClient as Record<string, unknown>)['query'] === 'function' &&
        'release' in transactionClient &&
        typeof (transactionClient as Record<string, unknown>)['release'] === 'function'
    ) {
        return transactionClient as PoolClient;
    }

    // Diagnostics: distinguish pg.Pool from other invalid types, giving a clear error hint
    const gotDescription =
        typeof transactionClient === 'object' && transactionClient !== null
            ? 'totalCount' in transactionClient
                ? 'pg.Pool (use pool.connect() to get a PoolClient before passing to append)'
                : 'release' in transactionClient
                    ? 'object with .release but missing .query'
                    : 'object without .release() — not a PoolClient'
            : String(typeof transactionClient);

    throw new ProtocolError(
        'INTERNAL_ERROR',
        'PostgresSideTableAppender.append: transactionClient is missing or not a PoolClient. ' +
            `Got: ${gotDescription}. ` +
            'A valid pg.PoolClient (with .query and .release) must be provided ' +
            '(same-transaction atomic write pattern). ' +
            'fail-closed: refusing to append without a transaction context. ' +
            '(atomic write contract).',
    );
}

