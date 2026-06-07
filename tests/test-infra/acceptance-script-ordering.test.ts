// acceptance-script-test-ordering guard

// Purpose: ensure vitest.config.ts's integration project correctly excludes the 3
// golden-path-style test files, and ensure phase5-acceptance.sh contains the
// fail-on-error and before-each-section TRUNCATE markers.

// Negative-test principle: use grep guards to assert on content that must NOT be present, preventing regression (someone mistakenly deleting an exclude).

import fs from 'node:fs';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

const REPO_ROOT = path.resolve(__dirname, '..', '..');
const VITEST_CONFIG = path.join(REPO_ROOT, 'vitest.config.ts');
const ACCEPTANCE_SCRIPT = path.join(
    REPO_ROOT,
    'scripts',
    'phase5-acceptance.sh',
);

// ============================================================
// vitest.config.ts: integration project exclude guards (negative tests)
// ============================================================
describe('vitest.config.ts integration project exclude guards', () => {
    it('should have vitest.config.ts readable', () => {
        expect(fs.existsSync(VITEST_CONFIG)).toBe(true);
    });

    it('should NOT include golden-path.test.ts in integration project include list without exclusion', () => {
        const content = fs.readFileSync(VITEST_CONFIG, 'utf8');
        // The integration project's exclude array must explicitly exclude golden-path.test.ts
        // Method: check that the exclude section contains the file name
        const integrationProjectBlock = extractIntegrationProjectBlock(content);
        expect(integrationProjectBlock).toContain('golden-path.test.ts');
        // And it must appear in the exclude context (not include)
        expect(integrationProjectBlock).toMatch(
            /exclude[\s\S]*golden-path\.test\.ts/,
        );
    });

    it('should NOT include golden-path-step-31.test.ts in integration project include list without exclusion', () => {
        const content = fs.readFileSync(VITEST_CONFIG, 'utf8');
        const integrationProjectBlock = extractIntegrationProjectBlock(content);
        expect(integrationProjectBlock).toContain(
            'golden-path-step-31.test.ts',
        );
        expect(integrationProjectBlock).toMatch(
            /exclude[\s\S]*golden-path-step-31\.test\.ts/,
        );
    });

    it('should NOT include cross-domain-settle.test.ts in integration project include list without exclusion', () => {
        const content = fs.readFileSync(VITEST_CONFIG, 'utf8');
        const integrationProjectBlock = extractIntegrationProjectBlock(content);
        expect(integrationProjectBlock).toContain(
            'cross-domain-settle.test.ts',
        );
        expect(integrationProjectBlock).toMatch(
            /exclude[\s\S]*cross-domain-settle\.test\.ts/,
        );
    });
});

// ============================================================
// phase5-acceptance.sh: fail-on-error + before-each-section guards
// Note: scripts/phase5-acceptance.sh was deleted, so the whole describe is skipped;
// if the script is restored in the future this can be changed back to describe
// ============================================================
describe.skip('phase5-acceptance.sh structural guards', () => {
    // Single-line bodies: scripts/phase5-acceptance.sh was deleted,
    // so if describe.skip is ever flipped back to describe by mistake, you get a clear SKIPPED hint instead of an ENOENT.
    const skipReason =
        'phase5-acceptance.sh missing: deleted; restore scripts/phase5-acceptance.sh to re-enable';

    it('should have phase5-acceptance.sh readable', () => {
        expect.fail(skipReason);
    });

    it('should contain set -euo pipefail (fail-on-error requirement)', () => {
        expect.fail(skipReason);
    });

    it('should contain TRUNCATE keyword (before-each-section fresh state requirement)', () => {
        expect.fail(skipReason);
    });

    it('should contain before_each_section function definition', () => {
        expect.fail(skipReason);
    });

    it('should contain script attribution header', () => {
        expect.fail(skipReason);
    });
});

// ============================================================
// grep guard extension: guard the sdk project exclude — vitest.config.ts assertions only, active
// ============================================================
describe('vitest.config.ts sdk project exclude guards', () => {
    it('should have sdk project exclude golden-path test files', () => {
        // Guard: the sdk project must exclude src/golden-path/**/*.test.ts
        // Reason: if the sdk project does not exclude them, the 33-step state cross occurs and only half the root cause is removed
        const content = fs.readFileSync(VITEST_CONFIG, 'utf8');
        const sdkProjectBlock = extractSdkProjectBlock(content);
        // The sdk project must contain an exclude array
        expect(sdkProjectBlock).toMatch(/exclude\s*:/);
        // The exclude array must contain the golden-path pattern
        expect(sdkProjectBlock).toMatch(/src\/golden-path/);
    });
});

// ============================================================
// phase5-acceptance.sh schema-qualified + PL/pgSQL guards
// Note: scripts/phase5-acceptance.sh was deleted, so the whole describe is skipped;
//    all 5 it cases readFileSync(ACCEPTANCE_SCRIPT), so this can be changed back to describe if the script is restored
// ============================================================
describe.skip('phase5-acceptance.sh schema-qualified + PL/pgSQL guards', () => {
    // Single-line bodies: same reason as the describe.skip above (the script was deleted)
    const skipReason =
        'phase5-acceptance.sh missing: deleted; restore scripts/phase5-acceptance.sh to re-enable';

    it('should have TRUNCATE function using schema-qualified table names', () => {
        expect.fail(skipReason);
    });

    it('should have CHECK_2 use failed_line detection instead of grep-passed', () => {
        expect.fail(skipReason);
    });

    it('should have TRUNCATE table list ≥ 19 schema-qualified tables', () => {
        expect.fail(skipReason);
    });

    it('should have #variable_conflict use_variable pragma in PL/pgSQL block', () => {
        expect.fail(skipReason);
    });

    it('should have VITEST_POOL_FORKS + VITEST_DISABLE_WORKER_RECONNECT_TIMEOUT export in CHECK_1', () => {
        expect.fail(skipReason);
    });
});

// ============================================================
// Helper functions: extract the integration project block from vitest.config.ts
// ============================================================

/**
 * Extract the project config block named `@coivitas/sdk` from the vitest.config.ts content.
 * Uses brace counting to locate the block boundaries, same pattern as extractIntegrationProjectBlock.
 * Guard: verify the sdk project has excluded the golden-path-style test files.
 */
function extractSdkProjectBlock(content: string): string {
    const markerIndex = content.indexOf("name: '@coivitas/sdk'");
    if (markerIndex === -1) {
        throw new Error(
            "name: '@coivitas/sdk' marker not found in vitest.config.ts — sdk project block does not exist",
        );
    }

    // Scan backward from the marker to the nearest `{` as the block start
    let braceStart = markerIndex;
    while (braceStart > 0 && content[braceStart] !== '{') {
        braceStart--;
    }

    // Count braces forward from braceStart to find the matching closing `}`
    let depth = 0;
    let i = braceStart;
    while (i < content.length) {
        if (content[i] === '{') depth++;
        else if (content[i] === '}') {
            depth--;
            if (depth === 0) break;
        }
        i++;
    }

    return content.slice(braceStart, i + 1);
}

/**
 * Extract the project config block named `integration` from the vitest.config.ts content.
 * Uses simple brace counting to locate the block boundaries.
 */
function extractIntegrationProjectBlock(content: string): string {
    const markerIndex = content.indexOf("name: 'integration'");
    if (markerIndex === -1) {
        throw new Error(
            "name: 'integration' marker not found in vitest.config.ts — integration project block does not exist",
        );
    }

    // Scan backward from the marker to the nearest `{` as the block start
    let braceStart = markerIndex;
    while (braceStart > 0 && content[braceStart] !== '{') {
        braceStart--;
    }

    // Count braces forward from braceStart to find the matching closing `}`
    let depth = 0;
    let i = braceStart;
    while (i < content.length) {
        if (content[i] === '{') depth++;
        else if (content[i] === '}') {
            depth--;
            if (depth === 0) break;
        }
        i++;
    }

    return content.slice(braceStart, i + 1);
}
