import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { createTestDatabase } from '../../packages/shared/src/index.js';
import { ScenarioRunner } from '../../packages/sdk/src/index.js';

const describeIfE2E =
    process.env.DATABASE_URL && process.env.ENABLE_SOCKET_TESTS === '1'
        ? describe
        : describe.skip;

describeIfE2E('scenario fixtures e2e', () => {
    let cleanup: (() => Promise<void>) | undefined;

    beforeAll(async () => {
        // cleanup is the single contract for pool.end + drop database: do not call pool.end
        // again here, otherwise pg-pool will throw "Called end on pool more than once" inside the afterAll cleanup.
        const database = await createTestDatabase();
        cleanup = database.cleanup;
    });

    afterAll(async () => {
        await cleanup?.();
    });

    it('runs the curated scenario fixtures through the runner', async () => {
        const runner = new ScenarioRunner({
            orchestrator: {
                handleEnvelope: (envelope) =>
                    Promise.resolve({
                        handled: true,
                        responseEnvelope: {
                            ...envelope,
                            messageType: 'NEGOTIATION_RESPONSE',
                            body: {
                                status: 'SUCCESS',
                            },
                        },
                    }),
            },
        });

        const results = await runner.runAll([
            'examples/scenarios/scenario-1-data.json',
            'examples/scenarios/scenario-2-data.json',
        ]);

        expect(results).toHaveLength(2);
        expect(results.every((result) => result.passed)).toBe(true);
    });
});
