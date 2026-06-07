import { defineWorkspace } from 'vitest/config';

export default defineWorkspace([
    {
        extends: './vitest.config.ts',
        test: {
            name: '@coivitas/types',
            root: './packages/types',
        },
    },
    {
        extends: './vitest.config.ts',
        test: {
            name: '@coivitas/crypto',
            root: './packages/crypto',
        },
    },
    {
        extends: './vitest.config.ts',
        test: {
            name: '@coivitas/identity',
            root: './packages/identity',
        },
    },
    {
        extends: './vitest.config.ts',
        test: {
            name: '@coivitas/policy',
            root: './packages/policy',
        },
    },
    {
        extends: './vitest.config.ts',
        test: {
            name: '@coivitas/communication',
            root: './packages/communication',
        },
    },
    {
        extends: './vitest.config.ts',
        test: {
            name: '@coivitas/sdk',
            root: './packages/sdk',
        },
    },
    {
        extends: './vitest.config.ts',
        test: {
            name: '@coivitas/shared',
            root: './packages/shared',
        },
    },
]);
