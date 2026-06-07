// Preserve the parenthesis pairing of NOW() / gen_random_uuid() inside packages/**/sql/*.sql.
//
// Failure signal: a sed/regex batch rewrite swallows the `)` of a zero-argument function call, e.g.
//   DEFAULT NOW()           --> DEFAULT NOW(
//   DEFAULT gen_random_uuid()  --> DEFAULT gen_random_uuid
// This kind of syntax damage does not fail-fast on static load (Postgres only blows up when the migration actually runs),
// so this guard must catch it early inside vitest.
//
// Implementation approach:
// 1. Recursively scan all .sql files under packages/ (covering packages/{policy,identity,communication,sdk}/sql/
//    + packages/shared/fixtures/*.sql).
// 2. Run 6 regexes line by line over each file to match the post-damage forms (open paren missing its close / bare function name after DEFAULT).
// 3. Collect all violations and list them all in a single expect failure message, for locating multiple sites at once.
//
// Background: 38 SQL files were once damaged by a batch rewrite, so a regression guard is needed.

import { readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

const REPO_ROOT = path.resolve(__dirname, '..', '..');
const PACKAGES_ROOT = path.join(REPO_ROOT, 'packages');

// Post-damage regexes (a match means an error)
const DAMAGE_PATTERNS: { pattern: RegExp; label: string }[] = [
    // NOW( followed by a non-whitespace non-) character => swallowed ) + an argument follows, syntax damage
    { pattern: /\bNOW\s*\(\s*[^)\s]/, label: 'NOW( followed by non-)' },
    // NOW( at end of line => missing close paren (multi-line function calls are very rare in SQL, so treat as damage)
    { pattern: /\bNOW\s*\(\s*$/, label: 'NOW( at end of line (missing ))' },
    {
        pattern: /\bgen_random_uuid\s*\(\s*[^)\s]/,
        label: 'gen_random_uuid( followed by non-)',
    },
    {
        pattern: /\bgen_random_uuid\s*\(\s*$/,
        label: 'gen_random_uuid( at end of line (missing ))',
    },
    // Bare function name after DEFAULT (no () => the parens were swallowed by sed)
    {
        pattern: /\bDEFAULT\s+NOW\b(?!\s*\()/i,
        label: 'DEFAULT NOW without parens',
    },
    {
        pattern: /\bDEFAULT\s+gen_random_uuid\b(?!\s*\()/i,
        label: 'DEFAULT gen_random_uuid without parens',
    },
];

function listSqlFiles(dir: string): string[] {
    const out: string[] = [];
    const entries = readdirSync(dir);
    for (const name of entries) {
        const full = path.join(dir, name);
        const stat = statSync(full);
        if (stat.isDirectory()) {
            // Skip node_modules / dist / .turbo etc.
            if (
                name === 'node_modules' ||
                name === 'dist' ||
                name === '.turbo' ||
                name === '__tests__'
            ) {
                continue;
            }
            out.push(...listSqlFiles(full));
        } else if (name.endsWith('.sql')) {
            out.push(full);
        }
    }
    return out;
}

interface Violation {
    relPath: string;
    lineNo: number;
    label: string;
    text: string;
}

describe('sql-syntax-guard', () => {
    it('should preserve NOW() and gen_random_uuid() parens when scanning packages/**/*.sql', () => {
        const files = listSqlFiles(PACKAGES_ROOT);
        // Should find at least 30+ SQL files (guards against a false negative where an empty scan still passes)
        expect(files.length).toBeGreaterThan(20);

        const violations: Violation[] = [];
        for (const filePath of files) {
            const relPath = path.relative(REPO_ROOT, filePath);
            const lines = readFileSync(filePath, 'utf-8').split('\n');
            for (let i = 0; i < lines.length; i += 1) {
                const line = lines[i];
                for (const { pattern, label } of DAMAGE_PATTERNS) {
                    if (pattern.test(line)) {
                        violations.push({
                            relPath,
                            lineNo: i + 1,
                            label,
                            text: line.trim(),
                        });
                    }
                }
            }
        }

        if (violations.length > 0) {
            const detail = violations
                .map(
                    (v) =>
                        `  ${v.relPath}:${v.lineNo}  [${v.label}]\n    ${v.text}`,
                )
                .join('\n');
            throw new Error(
                `SQL syntax regression — ${violations.length} site(s) detected:\n${detail}`,
            );
        }
        expect(violations).toEqual([]);
    });
});
