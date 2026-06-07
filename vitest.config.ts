import fs from 'node:fs';
import path from 'node:path';

import { defaultExclude, defineConfig } from 'vitest/config';

// Load the project root .env into the main process's process.env; workers inherit the
// main process env by default via child_process.fork, so there is no need to re-inject it in
// test.env (re-injecting would make the vitest worker's setupCommonEnv unconditionally
// override the shell's explicit values with raw .env values, breaking the shell > .env precedence).
// Parse KEY=VALUE lines directly (compatible with the .env / .env.example format) to avoid pulling in an extra dependency.
// Do not override already-existing environment variables, so CI or the local shell can override explicitly.
function loadDotenv(file: string): Record<string, string> {
    const out: Record<string, string> = {};
    if (!fs.existsSync(file)) return out;
    const text = fs.readFileSync(file, 'utf8');
    for (const rawLine of text.split(/\r?\n/)) {
        const line = rawLine.trim();
        if (!line || line.startsWith('#')) continue;
        const eq = line.indexOf('=');
        if (eq <= 0) continue;
        const key = line.slice(0, eq).trim();
        let value = line.slice(eq + 1).trim();
        if (
            (value.startsWith('"') && value.endsWith('"')) ||
            (value.startsWith("'") && value.endsWith("'"))
        ) {
            value = value.slice(1, -1);
        }
        out[key] = value;
    }
    return out;
}

const rootEnv = loadDotenv(path.resolve(__dirname, '.env'));
// Sync to the main process so the config phase and plugins can read it; but do not override
// existing values, preserving the precedence of values explicitly set by the shell.
// Workers inherit the main process env via fork (which at this point is already the merged "shell ?? .env" result),
// so it is **forbidden** to re-inject rootEnv into the test.env below, otherwise setupCommonEnv would
// unconditionally override shell values with raw .env values.
for (const [k, v] of Object.entries(rootEnv)) {
    if (process.env[k] === undefined) process.env[k] = v;
}

// Used only by the tests/test-infra/dotenv-precedence.test.ts subprocess: enable the fixture probe.
const probeDotenv = process.env.VITEST_PROBE_DOTENV === '1';
const fixturesExclude = probeDotenv ? [] : ['tests/test-infra/fixtures/**'];

export default defineConfig({
    resolve: {
        alias: {
            '@coivitas/types': path.resolve(
                __dirname,
                'packages/types/src/index.ts',
            ),
            '@coivitas/crypto': path.resolve(
                __dirname,
                'packages/crypto/src/index.ts',
            ),
            '@coivitas/identity': path.resolve(
                __dirname,
                'packages/identity/src/index.ts',
            ),
            '@coivitas/policy': path.resolve(
                __dirname,
                'packages/policy/src/index.ts',
            ),
            '@coivitas/communication': path.resolve(
                __dirname,
                'packages/communication/src/index.ts',
            ),
            '@coivitas/sdk': path.resolve(
                __dirname,
                'packages/sdk/src/index.ts',
            ),
            '@coivitas/shared': path.resolve(
                __dirname,
                'packages/shared/src/index.ts',
            ),
        },
    },
    test: {
        environment: 'node',
        globals: true,
        passWithNoTests: true,
        testTimeout: 10000,
        // Fix: vitest 3.x defaults to pool=forks + maxWorkers=CPU core count,
        // and a single worker loading the full TS source + node_modules takes ~3-4 GB.
        // The policy package with 5+ concurrent workers -> 15-20 GB memory -> local Mac freezes.
        // Limit to 2 workers (vs the default 8+), trading speed for stability; consistent CI/local behavior.
        pool: 'forks',
        poolOptions: {
            forks: {
                maxForks: 2,
                minForks: 1,
            },
        },
        include: [
            'src/**/*.test.ts',
            'tests/**/*.test.ts',
            'tests/**/*.integration.test.ts',
        ],
        // Reuse vitest's default exclude (node_modules/dist/cypress/.git/*.config.* etc.),
        // and append the fixture exclusion; the fixture is only invoked by the dotenv-precedence.test.ts subprocess.
        exclude: [...defaultExclude, ...fixturesExclude],
        projects: [
            {
                test: {
                    name: '@coivitas/types',
                    root: './packages/types',
                    include: ['src/**/*.test.ts'],
                },
            },
            {
                test: {
                    name: '@coivitas/crypto',
                    root: './packages/crypto',
                    include: ['src/**/*.test.ts', 'tests/**/*.test.ts'],
                },
            },
            {
                test: {
                    name: '@coivitas/identity',
                    root: './packages/identity',
                    include: ['src/**/*.test.ts', 'tests/**/*.test.ts'],
                },
            },
            {
                test: {
                    name: '@coivitas/policy',
                    root: './packages/policy',
                    include: ['src/**/*.test.ts', 'tests/**/*.test.ts'],
                },
            },
            {
                test: {
                    name: '@coivitas/communication',
                    root: './packages/communication',
                    include: ['src/**/*.test.ts', 'tests/**/*.test.ts'],
                },
            },
            {
                test: {
                    name: '@coivitas/sdk',
                    root: './packages/sdk',
                    include: ['src/**/*.test.ts', 'tests/**/*.test.ts'],
                    // The sdk project must exclude golden-path-style tests, consistent with the integration project.
                    // Background: packages/sdk/src/golden-path/index.test.ts contains the runGoldenPath 33-step
                    // PostgreSQL state mutation, which causes a DB state cross if run by the sdk project.
                    // If the sdk project does not exclude them, only half the root cause of the state cross is removed.
                    exclude: [
                        ...defaultExclude,
                        'src/golden-path/**/*.test.ts',
                        'src/golden-path/**/*.integration.test.ts',
                    ],
                },
            },
            {
                test: {
                    name: '@coivitas/shared',
                    root: './packages/shared',
                    include: ['src/**/*.test.ts', 'tests/**/*.test.ts'],
                },
            },
            {
                test: {
                    name: '@coivitas/wallet-interface',
                    root: './packages/wallet-interface',
                    include: [
                        'src/**/*.test.ts',
                        'src/**/__tests__/**/*.test.ts',
                    ],
                },
            },
            {
                test: {
                    name: 'integration',
                    root: '.',
                    include: [
                        'tests/**/*.test.ts',
                        'tests/**/*.integration.test.ts',
                    ],
                    // golden-path-style test files are excluded from the integration project,
                    // and only run via `pnpm run golden-path`.
                    // Background: repeatedly running the 32-step operations against the same PostgreSQL database
                    // causes a DB state cross and flakiness; isolated runs avoid this problem.
                    exclude: [
                        ...defaultExclude,
                        ...fixturesExclude,
                        'tests/e2e/golden-path.test.ts',
                        'tests/e2e/golden-path-step-31.test.ts',
                        'tests/e2e/cross-domain-settle.test.ts',
                    ],
                },
            },
        ],
        coverage: {
            provider: 'v8',
            reporter: ['text', 'json', 'html'],
            // The coverage denominator includes only product code (packages/*/src).
            // Exclude non-product code such as PoC archives, one-off migration/build scripts, and type declarations.
            include: ['packages/*/src/**/*.ts'],
            exclude: [
                '**/*.test.ts',
                '**/*.integration.test.ts',
                '**/__tests__/**',
                '**/dist/**',
                '**/*.d.ts',
            ],
            thresholds: {
                statements: 80,
                branches: 80,
                functions: 80,
                lines: 80,
            },
        },
    },
});
