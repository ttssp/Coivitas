import { createTestDatabase } from '../../packages/shared/src/index.js';
import { runGoldenPath } from '../../packages/sdk/src/index.js';

async function main(): Promise<void> {
    if (!process.env.DATABASE_URL || process.env.ENABLE_SOCKET_TESTS !== '1') {
        throw new Error(
            'DATABASE_URL and ENABLE_SOCKET_TESTS=1 are required for the E2E benchmark.',
        );
    }

    const database = await createTestDatabase();

    try {
        const result = await runGoldenPath({
            pool: database.pool,
            verbose: false,
        });

        console.log(
            JSON.stringify(
                {
                    success: result.success,
                    totalDurationMs: result.totalDurationMs,
                    coreFlowDurationMs: result.coreFlowDurationMs,
                    steps: result.steps,
                    errors: result.errors,
                },
                null,
                2,
            ),
        );
    } finally {
        await database.cleanup();
    }
}

void main();
