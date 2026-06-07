/**
 * usage-recorder.test.ts
 *
 * Test target: UsageRecorder (packages/managed-service-runtime/src/usage-recorder.ts)
 *
 * Coverage strategy:
 * - Unit tests (mock pool): cover NULL branch selection + delta validation + format
 * - Integration tests (DATABASE_URL gated): real DB INSERT...ON CONFLICT...DO UPDATE INCR
 */

import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';

import {
    formatBucketDay,
    UsageRecorder,
} from '../usage-recorder.js';

import type { DatabasePool } from '@coivitas/shared';

describe('usage-recorder unit tests', () => {
    function makePool(): { pool: DatabasePool; query: ReturnType<typeof vi.fn> } {
        const query = vi.fn().mockResolvedValue({ rowCount: 1 });
        const pool = { query } as unknown as DatabasePool;
        return { pool, query };
    }

    describe('formatBucketDay', () => {
        it('should format Date to YYYY-MM-DD UTC', () => {
            // 2026-05-06T14:30:00Z -> '2026-05-06'
            expect(formatBucketDay(new Date('2026-05-06T14:30:00Z'))).toBe(
                '2026-05-06',
            );
        });

        it('should normalize across timezones (always UTC slice)', () => {
            // 2026-12-31T23:59:00Z -> '2026-12-31'
            expect(formatBucketDay(new Date('2026-12-31T23:59:00Z'))).toBe(
                '2026-12-31',
            );
        });
    });

    describe('recordSync conflict target selection', () => {
        it('should use anonymous partial index when both ids are NULL', async () => {
            const { pool, query } = makePool();
            const recorder = new UsageRecorder({ pool });

            await recorder.recordSync({
                tenantId: null,
                apiKeyId: null,
                endpoint: 'resolver',
                isError: false,
                occurredAt: new Date('2026-05-06T00:00:00Z'),
            });

            expect(query).toHaveBeenCalledOnce();
            const sql = query.mock.calls[0]?.[0] as string;
            expect(sql).toContain(
                'ON CONFLICT (endpoint, bucket_day) WHERE tenant_id IS NULL AND api_key_id IS NULL',
            );
        });

        it('should INSERT without ON CONFLICT for (tenant, NULL) — historical rows allow multiple NULLs to coexist', async () => {
            // The original partial index uniq_usage_tenant_no_key_per_endpoint_day has been removed,
            // so (T, NULL) no longer takes the ON CONFLICT path; each record() writes a new row
            // (coexisting with ON DELETE SET NULL historical rows).
            // The current server path never reaches (T, NULL) from the record entry point
            // (it only produces (NULL,NULL) or (T,K)), but the defensive INSERT path is kept
            // in case record() is called directly from the outside.
            const { pool, query } = makePool();
            const recorder = new UsageRecorder({ pool });

            await recorder.recordSync({
                tenantId: 'tenant-1',
                apiKeyId: null,
                endpoint: 'resolver',
                isError: false,
            });

            const sql = query.mock.calls[0]?.[0] as string;
            expect(sql).toContain('INSERT INTO managed_service.usage_log');
            expect(sql).not.toContain('ON CONFLICT');
        });

        it('should use full unique constraint when both ids present (PRO path)', async () => {
            const { pool, query } = makePool();
            const recorder = new UsageRecorder({ pool });

            await recorder.recordSync({
                tenantId: 'tenant-1',
                apiKeyId: 'key-1',
                endpoint: 'revocation',
                isError: true,
            });

            const sql = query.mock.calls[0]?.[0] as string;
            expect(sql).toContain(
                'ON CONFLICT ON CONSTRAINT uniq_usage_per_tenant_endpoint_day',
            );
        });

        it('should INCR error_count when isError=true', async () => {
            const { pool, query } = makePool();
            const recorder = new UsageRecorder({ pool });

            await recorder.recordSync({
                tenantId: 't',
                apiKeyId: 'k',
                endpoint: 'resolver',
                isError: true,
                delta: 5,
            });

            const params = query.mock.calls[0]?.[1] as unknown[];
            // [tenantId, apiKeyId, endpoint, bucketDay, delta, errorDelta]
            expect(params[4]).toBe(5);
            expect(params[5]).toBe(5);
        });

        it('should set error_count=0 when isError=false even with non-1 delta', async () => {
            const { pool, query } = makePool();
            const recorder = new UsageRecorder({ pool });

            await recorder.recordSync({
                tenantId: null,
                apiKeyId: null,
                endpoint: 'resolver',
                isError: false,
                delta: 3,
            });

            const params = query.mock.calls[0]?.[1] as unknown[];
            expect(params[4]).toBe(3);
            expect(params[5]).toBe(0);
        });
    });

    describe('delta validation', () => {
        it('should reject delta < 1', async () => {
            const { pool } = makePool();
            const recorder = new UsageRecorder({ pool });
            await expect(
                recorder.recordSync({
                    tenantId: null,
                    apiKeyId: null,
                    endpoint: 'resolver',
                    isError: false,
                    delta: 0,
                }),
            ).rejects.toThrow(/positive integer/);
        });

        it('should reject non-integer delta', async () => {
            const { pool } = makePool();
            const recorder = new UsageRecorder({ pool });
            await expect(
                recorder.recordSync({
                    tenantId: null,
                    apiKeyId: null,
                    endpoint: 'resolver',
                    isError: false,
                    delta: 1.5,
                }),
            ).rejects.toThrow(/positive integer/);
        });
    });

    describe('record (fire-and-forget)', () => {
        it('should call onError callback when DB write fails', async () => {
            const errorMsg = 'pg connection refused';
            const query = vi.fn().mockRejectedValue(new Error(errorMsg));
            const pool = { query } as unknown as DatabasePool;
            const onError = vi.fn();
            const recorder = new UsageRecorder({ pool, onError });

            recorder.record({
                tenantId: 't',
                apiKeyId: 'k',
                endpoint: 'resolver',
                isError: false,
            });

            await new Promise((r) => setImmediate(r));
            expect(onError).toHaveBeenCalledOnce();
            const errArg = onError.mock.calls[0]?.[0] as Error;
            expect(errArg.message).toBe(errorMsg);
        });

        it('should default to console.warn when no onError provided', async () => {
            const query = vi.fn().mockRejectedValue(new Error('boom'));
            const pool = { query } as unknown as DatabasePool;
            const warnSpy = vi
                .spyOn(console, 'warn')
                .mockImplementation(() => undefined);
            const recorder = new UsageRecorder({ pool });

            recorder.record({
                tenantId: null,
                apiKeyId: null,
                endpoint: 'resolver',
                isError: false,
            });

            await new Promise((r) => setImmediate(r));
            expect(warnSpy).toHaveBeenCalled();
            warnSpy.mockRestore();
        });

        it('should not block on success path', () => {
            const { pool } = makePool();
            const recorder = new UsageRecorder({ pool });
            // The synchronous call must not throw
            expect(() =>
                recorder.record({
                    tenantId: null,
                    apiKeyId: null,
                    endpoint: 'resolver',
                    isError: false,
                }),
            ).not.toThrow();
        });
    });
});

// ---------------------------------------------------------------------------
// Integration tests (DATABASE_URL gated; same pattern as packages/policy)
// ---------------------------------------------------------------------------

const describeIfDatabase = process.env.DATABASE_URL
    ? describe
    : describe.skip;

describeIfDatabase('UsageRecorder integration', () => {
    let cleanup: (() => Promise<void>) | undefined;
    let dbPool: import('@coivitas/shared').DatabasePool;
    let recorder: UsageRecorder;

    beforeAll(async () => {
        const { createTestDatabase } = await import('@coivitas/shared');
        const db = await createTestDatabase();
        cleanup = db.cleanup;
        dbPool = db.pool;
        recorder = new UsageRecorder({ pool: dbPool });
    });

    afterAll(async () => {
        await cleanup?.();
    });

    it('should INCR request_count on second write to same bucket (anonymous)', async () => {
        const today = formatBucketDay(new Date());

        await recorder.recordSync({
            tenantId: null,
            apiKeyId: null,
            endpoint: 'resolver',
            isError: false,
            delta: 1,
        });
        await recorder.recordSync({
            tenantId: null,
            apiKeyId: null,
            endpoint: 'resolver',
            isError: false,
            delta: 1,
        });

        const result = await dbPool.query<{ request_count: string }>(
            `SELECT request_count FROM managed_service.usage_log
             WHERE tenant_id IS NULL AND api_key_id IS NULL
               AND endpoint='resolver' AND bucket_day=$1`,
            [today],
        );
        const row = result.rows[0];
        expect(row).toBeDefined();
        expect(Number(row?.request_count)).toBeGreaterThanOrEqual(2);
    });

    it('should isolate buckets across endpoints', async () => {
        const today = formatBucketDay(new Date());

        await recorder.recordSync({
            tenantId: null,
            apiKeyId: null,
            endpoint: 'revocation',
            isError: false,
        });

        const result = await dbPool.query<{ request_count: string }>(
            `SELECT request_count FROM managed_service.usage_log
             WHERE tenant_id IS NULL AND api_key_id IS NULL
               AND endpoint='revocation' AND bucket_day=$1`,
            [today],
        );
        const row = result.rows[0];
        expect(row).toBeDefined();
        expect(Number(row?.request_count)).toBeGreaterThanOrEqual(1);
    });

    it('should record error_count separately from request_count', async () => {
        const today = formatBucketDay(new Date());
        const tenantInsert = await dbPool.query<{ id: string }>(
            `INSERT INTO managed_service.tenants (tenant_did, tier, display_name)
             VALUES ($1, 'PRO', 'Test') RETURNING id`,
            [`did:agent:test-${Date.now()}`],
        );
        const tenantId = tenantInsert.rows[0]?.id;
        if (!tenantId) throw new Error('tenant insert failed');

        const keyInsert = await dbPool.query<{ id: string }>(
            `INSERT INTO managed_service.api_keys (tenant_id, key_hash, key_prefix)
             VALUES ($1, $2, 'ap_test_') RETURNING id`,
            [tenantId, 'test_hash_' + Date.now()],
        );
        const apiKeyId = keyInsert.rows[0]?.id;
        if (!apiKeyId) throw new Error('key insert failed');

        await recorder.recordSync({
            tenantId,
            apiKeyId,
            endpoint: 'resolver',
            isError: false,
        });
        await recorder.recordSync({
            tenantId,
            apiKeyId,
            endpoint: 'resolver',
            isError: true,
        });

        const result = await dbPool.query<{
            request_count: string;
            error_count: string;
        }>(
            `SELECT request_count, error_count FROM managed_service.usage_log
             WHERE tenant_id=$1 AND api_key_id=$2
               AND endpoint='resolver' AND bucket_day=$3`,
            [tenantId, apiKeyId, today],
        );
        const row = result.rows[0];
        expect(row).toBeDefined();
        expect(Number(row?.request_count)).toBe(2);
        expect(Number(row?.error_count)).toBe(1);
    });
});
