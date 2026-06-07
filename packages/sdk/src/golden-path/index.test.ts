import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { createTestDatabase } from '@coivitas/shared';

import { runGoldenPath } from './index.js';

const describeIfE2E =
    process.env.DATABASE_URL && process.env.ENABLE_SOCKET_TESTS === '1'
        ? describe
        : describe.skip;

describeIfE2E('runGoldenPath', () => {
    let cleanup: (() => Promise<void>) | undefined;
    let pool: Awaited<ReturnType<typeof createTestDatabase>>['pool'];

    beforeAll(async () => {
        const database = await createTestDatabase();
        pool = database.pool;
        cleanup = database.cleanup;
    });

    afterAll(async () => {
        await cleanup?.();
    });

    it('completes the full 33-step phase-3 happy path', async () => {
        const result = await runGoldenPath({
            pool,
            verbose: false,
        });

        // Full step count: Step 0-25 (26 steps) + Step 26-30 (5 implemented steps)
        // + Step 31 (RESOLVED: EnvelopeLedger crash recovery, really executed) + Step 32 (SESSION_SUPERSEDED) = 33
        // Step 31 RESOLVED: now enters records as a really-executed record (no longer skipped)
        expect(result.success).toBe(true);
        expect(result.steps).toHaveLength(33);

        // Step 31 now really executes (path A: lease expire + path B: idempotent finalize)
        const step31 = result.steps.find((s) => s.number === 31);
        expect(step31).toBeDefined();
        expect(step31?.skipped).toBeUndefined();
        expect(step31?.skipReason).toBeUndefined();
        expect(step31?.durationMs).toBeGreaterThan(0);

        // step number is monotonically increasing (no 30 → 32 numbering gap)
        const numbers = result.steps.map((s) => s.number);
        for (let i = 1; i < numbers.length; i += 1) {
            expect(numbers[i]).toBeGreaterThan(numbers[i - 1]!);
        }

        // coreFlow = the Step 6-11 handshake→inquiry→confirm chain, which the spec requires to stay fast
        expect(result.coreFlowDurationMs).toBeLessThan(5_000);
        // total-duration hard cap ("< 15s")
        expect(result.totalDurationMs).toBeLessThan(15_000);
        expect(result.errors).toEqual([]);
    });
});
