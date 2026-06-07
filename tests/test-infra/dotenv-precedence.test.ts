// Preserve vitest.config.ts's "shell > .env" precedence promise.

// Failure signal: the vitest worker's setupCommonEnv unconditionally overrides the shell's
// explicitly injected DATABASE_URL with the raw .env value, causing the assertion inside the fixture subprocess to fail -> subprocess exit code != 0.

// Implementation approach:
// 1. The parent process spawns a fresh vitest subprocess via spawnSync, reusing the main vitest.config.ts
// (ensuring the dotenv loading logic under test takes effect).
// 2. VITEST_PROBE_DOTENV=1 makes vitest.config.ts temporarily lift the fixture exclusion,
// so that tests/test-infra/fixtures/dotenv-precedence-probe.test.ts can be picked up.
// 3. DATABASE_URL=shell-precedence-<ts> simulates the "shell explicit override" scenario;
// inside the fixture, assert process.env.DATABASE_URL is still the sentinel value.
// If vitest overrides the sentinel with .env's DATABASE_URL inside the worker, the assertion fails.
import { spawnSync } from 'node:child_process';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

const REPO_ROOT = path.resolve(__dirname, '..', '..');
const VITEST_BIN = path.join(REPO_ROOT, 'node_modules', 'vitest', 'vitest.mjs');
const FIXTURE = path.join(
    REPO_ROOT,
    'tests',
    'test-infra',
    'fixtures',
    'dotenv-precedence-probe.test.ts',
);

describe('vitest dotenv precedence', () => {
    it('prefers shell-exported env over .env when running workers', () => {
        const sentinel = `shell-precedence-${Date.now()}`;
        const result = spawnSync(
            process.execPath,
            [
                VITEST_BIN,
                'run',
                '--config',
                path.join(REPO_ROOT, 'vitest.config.ts'),
                FIXTURE,
            ],
            {
                cwd: REPO_ROOT,
                env: {
                    ...process.env,
                    DATABASE_URL: sentinel,
                    VITEST_PROBE_DOTENV: '1',
                },
                encoding: 'utf8',
                // The fixture is tiny: 3 process starts + 1 assertion; a 60s cap is more than enough to cover cold start.
                timeout: 60_000,
            },
        );

        const debugOutput = `\n--- stdout ---\n${result.stdout}\n--- stderr ---\n${result.stderr}`;
        expect(result.status, debugOutput).toBe(0);
    }, 90_000);
});
