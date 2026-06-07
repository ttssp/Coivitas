// Subprocess probe: triggered by ../dotenv-precedence.test.ts via VITEST_PROBE_DOTENV=1
// plus the shell-injected DATABASE_URL=shell-precedence-*.
// During a normal `pnpm test` (VITEST_PROBE_DOTENV unset), both the vitest.config.ts top-level
// and the integration project's exclude skip tests/test-infra/fixtures/**,
// so this file is not executed.
import { expect, test } from 'vitest';

test('worker sees shell-provided DATABASE_URL sentinel', () => {
    expect(process.env.DATABASE_URL).toMatch(/^shell-precedence-\d+$/);
});
