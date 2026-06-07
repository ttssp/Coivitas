import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { createTestDatabase } from '../../packages/shared/src/index.js';
import { runGoldenPath } from '../../packages/sdk/src/index.js';

const describeIfE2E =
    process.env.DATABASE_URL && process.env.ENABLE_SOCKET_TESTS === '1'
        ? describe
        : describe.skip;

describeIfE2E('golden path e2e', () => {
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

    it('runs all 26 steps without mocks', async () => {
        const result = await runGoldenPath({ pool, verbose: false });

        expect(result.success).toBe(true);
        expect(result.steps.every((step) => step.passed)).toBe(true);
        expect(result.totalDurationMs).toBeLessThan(60_000);
        expect(result.coreFlowDurationMs).toBeLessThan(5_000);
    });
});
