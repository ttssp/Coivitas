/**
 * Usage recorder: aggregates daily INCR into managed_service.usage_log.
 *
 * Design notes (conclusions first, details after):
 * 1. INSERT...ON CONFLICT...DO UPDATE:
 *    - Unique key over tenant_id / api_key_id / endpoint / bucket_day.
 *    - DO UPDATE SET request_count = usage_log.request_count + EXCLUDED.request_count.
 * 2. NULL column handling: anonymous FREE tier access has tenant_id IS NULL;
 *    by default PostgreSQL treats NULL != NULL, so a plain UNIQUE constraint cannot drive ON CONFLICT;
 *    SQL 008 reinforces this with partial unique indexes (uniq_usage_anon_per_endpoint_day, etc.).
 *    This module selects the conflict target based on NULL state.
 * 3. fire-and-forget by default: record() performs an async INSERT and **does not block the response**;
 *    a failed record only triggers console.warn and does not affect business logic (a lost usage count
 *    is far cheaper than blocking the user request).
 * 4. Synchronous mode recordSync(): for tests; throws on write failure.
 * 5. bucket_day uses the UTC date (toISOString().slice(0, 10)): the daily aggregation boundary does not
 *    drift across timezone deployments, and it matches the SQL DATE type.
 *
 */

import type { DatabasePool } from '@coivitas/shared';

import type { Endpoint } from './types.js';

export interface UsageRecord {
    tenantId: string | null;
    apiKeyId: string | null;
    endpoint: Endpoint;
    /** Whether to count toward error_count (4xx/5xx response). */
    isError: boolean;
    /** Count increment; defaults to 1 (only > 1 when batching). */
    delta?: number;
    /** Injected by tests; defaults to new Date(). */
    occurredAt?: Date;
}

export interface UsageRecorderConfig {
    pool: DatabasePool;
    /** Callback for record failures; defaults to console.warn. */
    onError?: (error: unknown, record: UsageRecord) => void;
}

/**
 * Usage recorder (fire-and-forget API).
 *
 * Usage:
 * ```ts
 * const recorder = new UsageRecorder({ pool });
 * res.on('finish', => {
 *     recorder.record({
 *         tenantId: req.auth?.tenant?.id ?? null,
 *         apiKeyId: req.auth?.apiKey?.id ?? null,
 *         endpoint: 'resolver',
 *         isError: res.statusCode >= 400,
 *     });
 * });
 * ```
 */
export class UsageRecorder {
    private readonly pool: DatabasePool;
    private readonly onError: (error: unknown, record: UsageRecord) => void;

    public constructor(config: UsageRecorderConfig) {
        this.pool = config.pool;
        this.onError =
            config.onError ??
            ((error, record) =>
                console.warn(
                    '[usage-recorder] failed to record usage:',
                    error,
                    record,
                ));
    }

    /**
     * Records usage asynchronously; does not block the caller (fire-and-forget).
     */
    public record(record: UsageRecord): void {
        void this.recordSync(record).catch((error) =>
            this.onError(error, record),
        );
    }

    /**
     * Records usage synchronously (await); throws on write failure.
     *
     * Use for tests / synchronous audit scenarios; use record() on the production hot path.
     */
    public async recordSync(record: UsageRecord): Promise<void> {
        const delta = record.delta ?? 1;
        if (delta < 1 || !Number.isInteger(delta)) {
            throw new Error(
                `usage record delta must be positive integer, got ${String(delta)}`,
            );
        }
        const errorIncrement = record.isError ? delta : 0;
        const bucketDay = formatBucketDay(record.occurredAt ?? new Date());

        await runIncr(this.pool, {
            tenantId: record.tenantId,
            apiKeyId: record.apiKeyId,
            endpoint: record.endpoint,
            bucketDay,
            delta,
            errorDelta: errorIncrement,
        });
    }
}

// ---------------------------------------------------------------------------
// SQL ops
// ---------------------------------------------------------------------------

interface IncrParams {
    tenantId: string | null;
    apiKeyId: string | null;
    endpoint: Endpoint;
    bucketDay: string;
    delta: number;
    errorDelta: number;
}

/**
 * INSERT...ON CONFLICT...DO UPDATE...request_count = request_count + delta.
 *
 * Selects the partial unique index used as the conflict target based on the NULL state:
 * - Both NULL (anonymous FREE tier) -> uniq_usage_anon_per_endpoint_day (partial index).
 * - Both non-NULL (standard PRO tier path) -> uniq_usage_per_tenant_endpoint_day (plain UNIQUE constraint).
 * - tenant non-NULL + api_key NULL -> plain INSERT with no conflict
 *   (after ON DELETE SET NULL, historical rows allow multiple NULLs to coexist, so no partial unique index is used).
 *
 * The current callers (resolver/revocation server) only produce (NULL, NULL) or (T, K);
 * (T, NULL) only arises from the SQL ON DELETE SET NULL path (never written via the record entry point).
 */
async function runIncr(
    pool: DatabasePool,
    params: IncrParams,
): Promise<void> {
    const { tenantId, apiKeyId, endpoint, bucketDay, delta, errorDelta } =
        params;

    if (tenantId !== null && apiKeyId === null) {
        // (T, NULL) historical rows do not participate in ON CONFLICT; in principle this
        // is never reached via the record entry point, but as a defensive measure INSERT without
        // conflict, writing a new row each time (coexisting with history rows).
        const sql = `
            INSERT INTO managed_service.usage_log (
                tenant_id, api_key_id, endpoint, bucket_day, request_count, error_count
            )
            VALUES ($1, $2, $3, $4, $5, $6)
        `;
        await pool.query(sql, [
            tenantId,
            apiKeyId,
            endpoint,
            bucketDay,
            delta,
            errorDelta,
        ]);
        return;
    }

    let conflictClause: string;
    if (tenantId === null && apiKeyId === null) {
        // Anonymous FREE tier
        conflictClause =
            'ON CONFLICT (endpoint, bucket_day) WHERE tenant_id IS NULL AND api_key_id IS NULL';
    } else {
        // PRO tier: both tenant and api_key are present
        conflictClause =
            'ON CONFLICT ON CONSTRAINT uniq_usage_per_tenant_endpoint_day';
    }

    const sql = `
        INSERT INTO managed_service.usage_log (
            tenant_id, api_key_id, endpoint, bucket_day, request_count, error_count
        )
        VALUES ($1, $2, $3, $4, $5, $6)
        ${conflictClause}
        DO UPDATE SET
            request_count = managed_service.usage_log.request_count + EXCLUDED.request_count,
            error_count   = managed_service.usage_log.error_count + EXCLUDED.error_count
    `;

    await pool.query(sql, [
        tenantId,
        apiKeyId,
        endpoint,
        bucketDay,
        delta,
        errorDelta,
    ]);
}

/**
 * Formats a Date as 'YYYY-MM-DD' (UTC).
 *
 * Exported for use by tests and external batch tools.
 */
export function formatBucketDay(date: Date): string {
    return date.toISOString().slice(0, 10);
}
