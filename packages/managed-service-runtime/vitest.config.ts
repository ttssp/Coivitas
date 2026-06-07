import { defineConfig } from 'vitest/config';

export default defineConfig({
    test: {
        environment: 'node',
        include: ['src/**/*.test.ts'],
        coverage: {
            provider: 'v8',
            reporter: ['text', 'json-summary', 'html'],
            include: ['src/**/*.ts'],
            exclude: [
                'src/**/__tests__/**',
                'src/**/*.test.ts',
                'src/index.ts',
                // bin/ is the docker-compose entrypoint (top-level main + try/catch);
                // test coverage would require starting a real process, and the actual logic is already
                // tested inside createResolverApp / createRevocationApp.
                'src/bin/**',
                // types.ts is pure type/interface declarations with no runtime code (v8 coverage falsely reports 0%).
                'src/types.ts',
            ],
            // The global thresholds satisfy the task requirements (>=95% line / >=90% branch).
            // A few files like server.ts contain defensive fail-closed branches (auth missing / params missing /
            // headersSent guard) -- the Express routing layer guarantees these branches are never entered, so the
            // coverage cost outweighs the benefit.
            // These defensive behaviors must still be kept (fail-closed).
            thresholds: {
                lines: 95,
                branches: 90,
                functions: 95,
                statements: 95,
            },
        },
    },
});
