// Preserve the canonical form of the '//' string literal inside conformance test files.
//
// Failure signal: a jargon-strip state machine scans incorrectly (e.g. it does not recognize the JS regex literal /'[^']*'/g)
// and mistakes '//' for the start of a comment, inserting a space in the middle so it becomes '// '.
// Consequence: code like `if (trimmed.startsWith('//')) return false;` no longer filters
// JavaScript-style comments, and tests such as T41-T46 silently break.
//
// Implementation approach:
// 1. Scan packages/communication/src/bridge/__tests__/conformance/T*.conformance.test.ts (narrow scope,
//    the damage occurred here before and the canonical form is baselined at 6 sites).
// 2. Match the post-damage form directly: "// " between the opening/closing quote (a space inserted after the slashes),
//    i.e. /(['"`])\/\/ \1/.
// 3. Any match is treated as a regression.
//
// Background: a batch comment cleanup once mistakenly changed 2 '//' into '// ' (space inserted after the slashes) in T41-T46,
//   causing the startsWith('//')-based comment filter in the conformance tests to silently break. This guard locks down that form.

import { readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

const REPO_ROOT = path.resolve(__dirname, '..', '..');
const CONFORMANCE_DIR = path.join(
    REPO_ROOT,
    'packages',
    'communication',
    'src',
    'bridge',
    '__tests__',
    'conformance',
);

// Damage state: "// " immediately inside the quote (no character between the slashes, followed by a space, then the closing quote)
// Note: `/` does not need escaping inside a character class, but after escaping `\` to `\\` the JS regex is equivalent to `/'\/\/ '/`
const DAMAGE_PATTERN = /(['"`])\/\/ \1/;

describe('comment-marker-string-literal-guard', () => {
    it('should preserve canonical "//" string literals (no inserted space) when scanning T*.conformance.test.ts', () => {
        const entries = readdirSync(CONFORMANCE_DIR).filter(
            (n) => n.startsWith('T') && n.endsWith('.conformance.test.ts'),
        );
        // Baseline: 8 T*-T*.conformance.test.ts files; fewer than 5 is treated as an empty-scan anomaly
        expect(entries.length).toBeGreaterThan(5);

        const violations: { relPath: string; lineNo: number; text: string }[] =
            [];
        for (const name of entries) {
            const full = path.join(CONFORMANCE_DIR, name);
            const relPath = path.relative(REPO_ROOT, full);
            const lines = readFileSync(full, 'utf-8').split('\n');
            for (let i = 0; i < lines.length; i += 1) {
                if (DAMAGE_PATTERN.test(lines[i])) {
                    violations.push({
                        relPath,
                        lineNo: i + 1,
                        text: lines[i].trim(),
                    });
                }
            }
        }

        if (violations.length > 0) {
            const detail = violations
                .map((v) => `  ${v.relPath}:${v.lineNo}\n    ${v.text}`)
                .join('\n');
            throw new Error(
                `Comment-marker string literal regression — ${violations.length} site(s) found '// ' (expected '//'):\n${detail}`,
            );
        }
        expect(violations).toEqual([]);
    });
});
