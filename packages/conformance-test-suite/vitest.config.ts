import { defineConfig } from 'vitest/config';

export default defineConfig({
    test: {
        environment: 'node',
        globals: true,
        include: ['src/**/*.test.ts'],
        coverage: {
            provider: 'v8',
            // Count only executable TypeScript files under src/; exclude:
            // - types.ts (pure type definitions, no executable statements)
            // - bin/ (ESM shim, runtime Node mode, no business logic)
            include: ['src/**/*.ts'],
            exclude: ['src/**/*.test.ts', 'src/types.ts'],
            // Coverage thresholds
            thresholds: {
                lines: 95,
                branches: 90,
            },
        },
    },
});
