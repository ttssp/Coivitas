/**
 * revocation-list-store.ts -- RevocationList PostgreSQL persistence layer
 *
 * Implements the read/write paths for the policy.revocation_records table:
 *   - revoke(): write a revocation record (idempotent ON CONFLICT DO NOTHING + duplicate detection)
 *   - isRevoked(): check whether a token has been revoked (the query path is cache-first)
 *   - getRevocation(): look up a single record by tenant_id + token_id
 *   - getRevocations(): batch query (filtering + pagination)
 *   - getNextListVersion(): get the next monotonically increasing listVersion for a listId
 *
 * Design constraints:
 *   - REVOCATION_DUPLICATE: idempotent duplicate prevention (UNIQUE INDEX + ON CONFLICT)
 *   - fail-closed: query errors throw directly; never silently return false
 *   - multi-tenant: every query MUST carry a tenantId prefix filter
 *   - listVersion monotonic increase: getNextListVersion() uses SELECT MAX + 1 FOR UPDATE
 *   - raw DB strings must be validated at runtime, no brand cast
 *
 */

import type { Pool, PoolClient } from 'pg';
import { randomUUID } from 'node:crypto';

import type {
    RevocationCheckResult,
    RevocationQueryFilters,
    RevocationRecord,
    RevocationWriteInput,
    RevocationWriteResult,
} from './revocation-record.js';
import {
    parseRevocationReason,
    validateIssuerSignaturePayload,
    REVOCATION_REASONS,
} from './revocation-record.js';

// ---------------------------------------------------------------------------
// Utility: DB row -> RevocationRecord (runtime validation, no brand cast)
// ---------------------------------------------------------------------------

/**
 * Map a pg query row to a RevocationRecord (fail-closed runtime validation).
 *
 * @throws Error if the reason stored in the DB is not a valid RevocationReason
 */
function rowToRecord(row: Record<string, unknown>): RevocationRecord {
    return {
        id: String(row['id']),
        tenantId: String(row['tenant_id']),
        tokenId: String(row['token_id']),
        revokedBy: String(row['revoked_by']),
        revokedAt: row['revoked_at'] as Date,
        reason: parseRevocationReason(row['reason']),
        listId: String(row['list_id']),
        listVersion: Number(row['list_version']),
        issuerSignaturePayload:
            row['issuer_signature_payload'] != null
                ? validateIssuerSignaturePayload(row['issuer_signature_payload'])
                : null,
    };
}

// ---------------------------------------------------------------------------
// RevocationListStore
// ---------------------------------------------------------------------------

/** RevocationListStore constructor options. */
export interface RevocationListStoreOptions {
    /** PostgreSQL connection pool (policy schema privileges). */
    pool: Pool;
    /**
     * Write timeout (ms).
     * Default 5000ms (5s).
     */
    writeTimeoutMs?: number;
    /**
     * Read timeout (ms).
     * Default 2000ms (2s).
     */
    readTimeoutMs?: number;
}

/**
 * RevocationList PostgreSQL persistence layer.
 *
 * Persistence path: the policy.revocation_records table (migration 023).
 * All write operations run inside a transaction (listVersion increment + record insert atomicity).
 */
export class RevocationListStore {
    private readonly pool: Pool;
    private readonly writeTimeoutMs: number;
    private readonly readTimeoutMs: number;

    constructor(opts: RevocationListStoreOptions) {
        this.pool = opts.pool;
        this.writeTimeoutMs = opts.writeTimeoutMs ?? 5_000;
        this.readTimeoutMs = opts.readTimeoutMs ?? 2_000;
    }

    // -------------------------------------------------------------------------
    // revoke() -- write a revocation record (in-transaction: getNextListVersion + INSERT)
    // -------------------------------------------------------------------------

    /**
     * Write a revocation record.
     *
     * Idempotency semantics:
     *   - a revocation record already exists for the same (tenantId, tokenId) -> returns REVOCATION_DUPLICATE (no throw)
     *   - any other DB error -> returns REVOCATION_STORE_ERROR (no throw)
     *
     * listVersion is auto-incremented internally by the store (SELECT MAX(list_version) + 1 FOR UPDATE).
     *
     * @param input revoke write parameters
     */
    async revoke(input: RevocationWriteInput): Promise<RevocationWriteResult> {
        const { tenantId, tokenId, revokedBy, listId } = input;
        const reason = input.reason ?? 'UNSPECIFIED';

        if (!tenantId || !tokenId || !revokedBy || !listId) {
            return {
                ok: false,
                code: 'REVOCATION_INVALID_PARAMS',
                message: 'tenantId, tokenId, revokedBy, listId are required',
            };
        }

        // Validate the reason value (fail-closed: reject invalid values directly)
        if (!(REVOCATION_REASONS as readonly string[]).includes(reason)) {
            return {
                ok: false,
                code: 'REVOCATION_INVALID_PARAMS',
                message: `Invalid reason: ${reason}. Expected one of: ${REVOCATION_REASONS.join(', ')}`,
            };
        }

        const client = await this.pool.connect();
        try {
            return await this._revokeWithClient(client, input, reason);
        } finally {
            client.release();
        }
    }

    private async _revokeWithClient(
        client: PoolClient,
        input: RevocationWriteInput,
        reason: string,
    ): Promise<RevocationWriteResult> {
        const { tenantId, tokenId, revokedBy, listId, issuerSignaturePayload } =
            input;

        await client.query('BEGIN');
        try {
            // Step 1: listVersion monotonic increase (FOR UPDATE locks the listId dimension)
            const nextVersionRes = await client.query<{ next_version: string }>(
                `SELECT COALESCE(MAX(list_version), 0) + 1 AS next_version
                 FROM policy.revocation_records
                 WHERE tenant_id = $1 AND list_id = $2
                 FOR UPDATE`,
                [tenantId, listId],
            );
            const listVersion = Number(
                nextVersionRes.rows[0]?.['next_version'] ?? 1,
            );

            // Step 2: check whether a duplicate record already exists (idempotent dedup)
            const dupRes = await client.query<{ id: string }>(
                `SELECT id FROM policy.revocation_records
                 WHERE tenant_id = $1 AND token_id = $2
                 LIMIT 1`,
                [tenantId, tokenId],
            );
            if (dupRes.rowCount && dupRes.rowCount > 0) {
                await client.query('ROLLBACK');
                return {
                    ok: false,
                    code: 'REVOCATION_DUPLICATE',
                    message: `token_id '${tokenId}' is already revoked in tenant '${tenantId}'`,
                };
            }

            // Step 3: write the revocation record
            const id = randomUUID();
            const insertRes = await client.query<Record<string, unknown>>(
                `INSERT INTO policy.revocation_records
                    (id, tenant_id, token_id, revoked_by, reason, list_id, list_version, issuer_signature_payload)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                 RETURNING
                    id, tenant_id, token_id, revoked_by, revoked_at, reason,
                    list_id, list_version, issuer_signature_payload`,
                [
                    id,
                    tenantId,
                    tokenId,
                    revokedBy,
                    reason,
                    listId,
                    listVersion,
                    issuerSignaturePayload != null
                        ? JSON.stringify(issuerSignaturePayload)
                        : null,
                ],
            );

            await client.query('COMMIT');

            const row = insertRes.rows[0];
            if (!row) {
                return {
                    ok: false,
                    code: 'REVOCATION_STORE_ERROR',
                    message: 'INSERT returned no row (unexpected)',
                };
            }

            return { ok: true, record: rowToRecord(row) };
        } catch (err) {
            await client.query('ROLLBACK');
            // Extract the error message: use .message when err is an Error; otherwise fall back to String()
            const errMessage = err instanceof Error ? err.message : String(err);
            // PostgreSQL UNIQUE violation (error code 23505):
            // - if the constraint name contains 'list_version', a concurrent write hit the same listVersion (concurrency conflict)
            // -> REVOCATION_LIST_VERSION_CONFLICT (the caller may retry)
            // - any other UNIQUE violation or non-UNIQUE error
            // -> REVOCATION_STORE_ERROR (general DB error)
            if (
                typeof err === 'object' &&
                err !== null &&
                'code' in err &&
                (err as { code?: string }).code === '23505'
            ) {
                const constraint = (err as { constraint?: string }).constraint ?? '';
                if (constraint.includes('list_version')) {
                    return {
                        ok: false,
                        code: 'REVOCATION_LIST_VERSION_CONFLICT',
                        message: `Concurrent list_version conflict on constraint '${constraint}': ${errMessage}`,
                    };
                }
            }
            return {
                ok: false,
                code: 'REVOCATION_STORE_ERROR',
                message: `DB error during revoke: ${errMessage}`,
            };
        }
    }

    // -------------------------------------------------------------------------
    // isRevoked() -- fast revocation check (single boolean; queries only tenantId + tokenId)
    // -------------------------------------------------------------------------

    /**
     * Check whether a token has been revoked.
     *
     * fail-closed: throws directly on DB error; never silently returns false.
     * Callers should go through the cache first (RevocationCache); this method is the DB fallback path for a cache miss.
     *
     * @throws Error when the DB query fails
     */
    async isRevoked(tenantId: string, tokenId: string): Promise<boolean> {
        const res = await this.pool.query<{ exists: boolean }>(
            `SELECT EXISTS(
                SELECT 1 FROM policy.revocation_records
                WHERE tenant_id = $1 AND token_id = $2
             ) AS exists`,
            [tenantId, tokenId],
        );
        const row = res.rows[0];
        // fail-closed: treat as revoked when no definitive result can be obtained from the DB
        if (!row) {
            throw new Error(
                `RevocationListStore.isRevoked: unexpected empty result for tenant='${tenantId}' tokenId='${tokenId}'`,
            );
        }
        return Boolean(row['exists']);
    }

    // -------------------------------------------------------------------------
    // getRevocation() -- exact single-record lookup
    // -------------------------------------------------------------------------

    /**
     * Look up a single revocation record by tenantId + tokenId.
     *
     * @returns RevocationCheckResult (found/not-found discriminated union)
     * @throws Error when the DB query fails
     */
    async getRevocation(
        tenantId: string,
        tokenId: string,
    ): Promise<RevocationCheckResult> {
        const res = await this.pool.query<Record<string, unknown>>(
            `SELECT id, tenant_id, token_id, revoked_by, revoked_at, reason,
                    list_id, list_version, issuer_signature_payload
             FROM policy.revocation_records
             WHERE tenant_id = $1 AND token_id = $2
             LIMIT 1`,
            [tenantId, tokenId],
        );

        if (!res.rows[0]) {
            return { found: false };
        }
        return { found: true, record: rowToRecord(res.rows[0]) };
    }

    // -------------------------------------------------------------------------
    // getRevocations() -- batch query (filtering + pagination)
    // -------------------------------------------------------------------------

    /**
     * Batch query revocation records (supports filtering + pagination).
     *
     * Enforces tenantId as a precondition (multi-tenant isolation).
     * Default limit = 100, max 1000 (truncated when exceeded).
     *
     * @throws Error when the DB query fails
     */
    async getRevocations(
        filters: RevocationQueryFilters,
    ): Promise<RevocationRecord[]> {
        const limit = Math.min(filters.limit ?? 100, 1000);
        const offset = filters.offset ?? 0;

        const conditions: string[] = ['r.tenant_id = $1'];
        const params: unknown[] = [filters.tenantId];
        let idx = 2;

        if (filters.tokenId !== undefined) {
            conditions.push(`r.token_id = $${idx}`);
            params.push(filters.tokenId);
            idx++;
        }
        if (filters.listId !== undefined) {
            conditions.push(`r.list_id = $${idx}`);
            params.push(filters.listId);
            idx++;
        }
        if (filters.revokedAfter !== undefined) {
            conditions.push(`r.revoked_at >= $${idx}`);
            params.push(filters.revokedAfter);
            idx++;
        }
        if (filters.revokedBefore !== undefined) {
            conditions.push(`r.revoked_at <= $${idx}`);
            params.push(filters.revokedBefore);
            idx++;
        }

        const where = conditions.join(' AND ');

        const res = await this.pool.query<Record<string, unknown>>(
            `SELECT r.id, r.tenant_id, r.token_id, r.revoked_by, r.revoked_at, r.reason,
                    r.list_id, r.list_version, r.issuer_signature_payload
             FROM policy.revocation_records r
             WHERE ${where}
             ORDER BY r.revoked_at DESC
             LIMIT $${idx} OFFSET $${idx + 1}`,
            [...params, limit, offset],
        );

        return res.rows.map(rowToRecord);
    }

    // -------------------------------------------------------------------------
    // getNextListVersion() -- query the next listVersion for a list (no lock, query only)
    // -------------------------------------------------------------------------

    /**
     * Query the next listVersion for a listId (MAX + 1, no lock).
     *
     * Used for an estimate at the API layer; the actual increment happens inside the revoke() transaction.
     *
     * @returns the next listVersion (returns 1 when the list is empty)
     * @throws Error when the DB query fails
     */
    async getNextListVersion(
        tenantId: string,
        listId: string,
    ): Promise<number> {
        const res = await this.pool.query<{ next_version: string }>(
            `SELECT COALESCE(MAX(list_version), 0) + 1 AS next_version
             FROM policy.revocation_records
             WHERE tenant_id = $1 AND list_id = $2`,
            [tenantId, listId],
        );
        const row = res.rows[0];
        if (!row) {
            return 1;
        }
        return Number(row['next_version']);
    }
}
