/**
 * check-encoding-migration.ts
 * Scans all target files for hardcoded hex length checks and format assumptions.
 * Target file types:
 *   - .ts files (excluding node_modules, dist, .d.ts)
 *   - tests/fixtures/conformance/**\/*.json (containing fields such as paramsHash/ledgerSignature)
 * Purpose: before the v0.2 encoding migration, identify the locations that need changing and the blast radius.
 *
 * Usage:
 *   npx tsx scripts/check-encoding-migration.ts [--path=<dir>] [--format=text|json]
 *
 * Output: file path, line number, matched content, migration suggestion.
 */

import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = fileURLToPath(new URL('.', import.meta.url));
const ROOT = join(__dirname, '..');

// Migration scan rule definitions.
// Each rule: pattern (regex), category (classification), suggestion (migration advice).
const SCAN_RULES: Array<{
    pattern: RegExp;
    category: string;
    suggestion: string;
}> = [
    // 1. Hardcoded hex length checks (signature 128-char, hash/public-key 64-char)
    {
        pattern: /\.length\s*===?\s*128\b/g,
        category: 'HEX_LENGTH_CHECK_128',
        suggestion:
            'v0.2 migration: signatures change from 128-char hex to 86-char base64url; switch to a dynamic byte-length check (64 bytes)',
    },
    {
        pattern: /\.length\s*===?\s*64\b/g,
        category: 'HEX_LENGTH_CHECK_64',
        suggestion:
            'v0.2 migration: public keys/hashes change from 64-char hex to 43-char base64url; switch to a dynamic byte-length check (32 bytes)',
    },
    {
        pattern: /\.length\s*!==?\s*128\b/g,
        category: 'HEX_LENGTH_CHECK_128_NEQ',
        suggestion:
            'v0.2 migration: the signature length inequality check must be updated to accept both hex(128) and base64url(86) formats',
    },
    {
        pattern: /\.length\s*!==?\s*64\b/g,
        category: 'HEX_LENGTH_CHECK_64_NEQ',
        suggestion:
            'v0.2 migration: the hash/public-key length inequality check must be updated to accept both hex(64) and base64url(43) formats',
    },
    // 2. Explicit encoding: 'hex' format declaration
    {
        pattern: /encoding\s*:\s*['"]hex['"]/g,
        category: 'EXPLICIT_HEX_ENCODING',
        suggestion:
            "v0.2 migration: explicit encoding: 'hex' must be replaced with encoding: 'base64url' or made a configurable parameter",
    },
    // 3. hex string literals (as default values or comparisons)
    {
        pattern: /['"]hex['"]/g,
        category: 'HEX_STRING_LITERAL',
        suggestion:
            "v0.2 migration: the 'hex' literal may be a format default; evaluate whether it should become 'base64url' or support both formats",
    },
    // 4. hex-format regex validation
    {
        pattern: /\/\^?\[0-9a-f[A-F]?\][+*][^/]*\//g,
        category: 'HEX_REGEX_VALIDATION',
        suggestion:
            'v0.2 migration: the hex-format regex must be extended to accept the base64url character set [A-Za-z0-9_-]',
    },
    {
        pattern: /\/\^\[0-9a-f\]/g,
        category: 'HEX_PATTERN_ANCHOR',
        suggestion:
            'v0.2 migration: the hex start-anchor pattern must be updated to accept the base64url format',
    },
    // 5. hex pattern inside an AJV schema
    {
        pattern: /pattern\s*:\s*['"][^'"]*\[0-9a-f\][^'"]*['"]/g,
        category: 'SCHEMA_HEX_PATTERN',
        suggestion:
            'v0.2 migration: the AJV schema hex pattern needs an added base64url pattern, or should be switched to anyOf dual-format validation',
    },
    // 6. hex64Pattern / hex128Pattern variable references
    {
        pattern: /\bhex(?:64|128)Pattern\b/g,
        category: 'HEX_PATTERN_VARIABLE',
        suggestion:
            'v0.2 migration: references to the hex64/128Pattern variables need a corresponding base64url pattern variable and should switch to anyOf',
    },
    // 7. Explicit fromHex / toHex calls
    {
        pattern: /\bfromHex\s*\(/g,
        category: 'FROM_HEX_CALL',
        suggestion:
            'v0.2 migration: fromHex() calls must be replaced with detectEncoding() + fromHex()/fromBase64Url() dual-format support',
    },
    {
        pattern: /\btoHex\s*\(/g,
        category: 'TO_HEX_CALL',
        suggestion:
            'v0.2 migration: toHex() calls must be replaced with toBase64Url() or a helper that accepts an encoding parameter',
    },
    // 8. hex-format notes in wire-format comments
    {
        pattern: /128-char\s+hex|64-char\s+hex/g,
        category: 'HEX_FORMAT_COMMENT',
        suggestion:
            'v0.2 migration: hex-format notes in comments must be updated to describe the base64url format (or both formats)',
    },
];

// JSON-fixture-specific scan rules: match hex field values (64/128-digit hexadecimal strings).
// Covers frozen fields such as paramsHash, ledgerSignature, prevHash.
const JSON_SCAN_RULES: Array<{
    pattern: RegExp;
    category: string;
    suggestion: string;
}> = [
    {
        // 64-char hex values (SHA-256 hashes: paramsHash, prevHash, etc.)
        pattern: /"[0-9a-f]{64}"/g,
        category: 'JSON_HEX64_VALUE',
        suggestion:
            'v0.2 migration: 64-char hex values (SHA-256 hashes) in JSON fixtures must be updated to a v0.2 fixture using the 43-char base64url format',
    },
    {
        // 128-char hex values (Ed25519 signatures: ledgerSignature, signature, etc.)
        pattern: /"[0-9a-f]{128}"/g,
        category: 'JSON_HEX128_VALUE',
        suggestion:
            'v0.2 migration: 128-char hex values (Ed25519 signatures) in JSON fixtures must be updated to a v0.2 fixture using the 86-char base64url format',
    },
];

// Markdown-document-specific scan rules: match hex literal references (including code blocks and prose).
const MD_SCAN_RULES: Array<{
    pattern: RegExp;
    category: string;
    suggestion: string;
}> = [
    {
        // Descriptive references to 64-char hex or 128-char hex
        pattern: /\b(?:64|128)-char\s+hex\b/g,
        category: 'MD_HEX_FORMAT_REFERENCE',
        suggestion:
            'v0.2 migration: hex-format descriptions in the docs (64/128-char hex) must be updated to also describe the equivalent base64url format',
    },
    {
        // hex pattern references (such as [0-9a-f]{64} or ^[0-9a-f]{128}$)
        pattern: /\[0-9a-f\]\{(?:64|128)\}/g,
        category: 'MD_HEX_REGEX_REFERENCE',
        suggestion:
            'v0.2 migration: hex regex examples in the docs need a corresponding base64url pattern added',
    },
    {
        // hex-format notes in the frozen-field inventory
        pattern: /paramsHash|ledgerSignature|prevHash|bindingProof\.signature/g,
        category: 'MD_FROZEN_FIELD_REFERENCE',
        suggestion:
            'v0.2 migration: field references in the frozen-field inventory must be cross-checked against their v0.2 encoding-format plan (anyOf hex/base64url)',
    },
];

interface ScanMatch {
    file: string;
    line: number;
    column: number;
    content: string;
    category: string;
    suggestion: string;
}

interface ScanSummary {
    totalFiles: number;
    scannedFiles: number;
    totalMatches: number;
    byCategory: Record<string, number>;
    matches: ScanMatch[];
}

// Recursively list all .ts files under a directory (excluding node_modules, dist, .d.ts).
// Renamed alias kept for backward compatibility; the internal logic is centralized in listTargetFiles.
function listTsFiles(dir: string): string[] {
    return listTargetFiles(dir);
}

// Collect all target files to scan:
//   1. .ts files (excluding node_modules, dist, .d.ts, and the script itself)
//   2. tests/fixtures/conformance/**/*.json (containing paramsHash/ledgerSignature fields)
function listTargetFiles(dir: string): string[] {
    const results: string[] = [];
    _collectTsFiles(dir, results);
    _collectJsonFixtures(join(ROOT, 'tests', 'fixtures', 'conformance'), results);
    return results;
}

// Recursively collect .ts files
function _collectTsFiles(dir: string, results: string[]): void {
    let entries: string[];
    try {
        entries = readdirSync(dir);
    } catch {
        return;
    }

    for (const entry of entries) {
        // Skip directories that don't need scanning
        if (
            entry === 'node_modules' ||
            entry === 'dist' ||
            entry === '.git' ||
            entry === 'coverage'
        ) {
            continue;
        }

        const fullPath = join(dir, entry);
        let stat;
        try {
            stat = statSync(fullPath);
        } catch {
            continue;
        }

        if (stat.isDirectory()) {
            _collectTsFiles(fullPath, results);
        } else if (
            entry.endsWith('.ts') &&
            !entry.endsWith('.d.ts') &&
            // Exclude the script itself
            !fullPath.includes('check-encoding-migration')
        ) {
            results.push(fullPath);
        }
    }
}

// Recursively collect conformance fixture JSON files (including subdirectories such as identity/, communication/)
function _collectJsonFixtures(dir: string, results: string[]): void {
    let entries: string[];
    try {
        entries = readdirSync(dir);
    } catch {
        return;
    }

    for (const entry of entries) {
        const fullPath = join(dir, entry);
        let stat;
        try {
            stat = statSync(fullPath);
        } catch {
            continue;
        }

        if (stat.isDirectory()) {
            // Recurse into subdirectories (such as identity/, communication/)
            _collectJsonFixtures(fullPath, results);
        } else if (entry.endsWith('.json')) {
            results.push(fullPath);
        }
    }
}

function scanFile(filePath: string): ScanMatch[] {
    let content: string;
    try {
        content = readFileSync(filePath, 'utf-8');
    } catch {
        return [];
    }

    // Select the rule set based on file type.
    // JSON and Markdown files use dedicated rules; .ts files use the general rules.
    const isJson = filePath.endsWith('.json');
    const isMd = filePath.endsWith('.md');
    const rules = isJson ? JSON_SCAN_RULES : isMd ? MD_SCAN_RULES : SCAN_RULES;

    const lines = content.split('\n');
    const matches: ScanMatch[] = [];
    const relPath = relative(ROOT, filePath);

    for (const rule of rules) {
        for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
            const line = lines[lineIdx]!;
            // Skip comment lines (only for .ts files; JSON/Markdown have no such notion)
            const trimmed = line.trimStart();
            const isComment =
                !isJson &&
                !isMd &&
                (trimmed.startsWith('//') || trimmed.startsWith('*'));

            // Reset lastIndex (required when the regex has the g flag)
            rule.pattern.lastIndex = 0;

            let match: RegExpExecArray | null;
            while ((match = rule.pattern.exec(line)) !== null) {
                matches.push({
                    file: relPath,
                    line: lineIdx + 1,
                    column: match.index + 1,
                    content: line.trim(),
                    category: isComment
                        ? `${rule.category}__IN_COMMENT`
                        : rule.category,
                    suggestion: rule.suggestion,
                });
            }
        }
    }

    return matches;
}

function scan(targetDir: string): ScanSummary {
    const files = listTargetFiles(targetDir);
    const allMatches: ScanMatch[] = [];
    const byCategory: Record<string, number> = {};

    let scannedFiles = 0;
    for (const file of files) {
        const fileMatches = scanFile(file);
        if (fileMatches.length > 0) {
            allMatches.push(...fileMatches);
            scannedFiles++;
        }
    }

    for (const m of allMatches) {
        byCategory[m.category] = (byCategory[m.category] ?? 0) + 1;
    }

    return {
        totalFiles: files.length,
        scannedFiles,
        totalMatches: allMatches.length,
        byCategory,
        matches: allMatches,
    };
}

function printTextReport(summary: ScanSummary): void {
    console.log('='.repeat(70));
    console.log('  Encoding migration impact scan report (v0.2 migration prep)');
    console.log('='.repeat(70));
    console.log(
        `\nTotal files scanned: ${summary.totalFiles}, files with matches: ${summary.scannedFiles}`,
    );
    console.log(`Total matches: ${summary.totalMatches}\n`);

    // Per-category statistics
    console.log('--- Category statistics ---');
    const sortedCategories = Object.entries(summary.byCategory).sort(
        ([, a], [, b]) => b - a,
    );
    for (const [category, count] of sortedCategories) {
        console.log(`  ${category.padEnd(40)} ${count} match(es)`);
    }

    // Output matches grouped by file
    console.log('\n--- Detailed matches ---');
    const byFile: Record<string, ScanMatch[]> = {};
    for (const m of summary.matches) {
        (byFile[m.file] ??= []).push(m);
    }

    for (const [file, matches] of Object.entries(byFile).sort()) {
        console.log(`\n[${file}]`);
        for (const m of matches) {
            console.log(`  L${m.line}:${m.column}  [${m.category}]`);
            console.log(`    code: ${m.content.slice(0, 100)}`);
            console.log(`    suggestion: ${m.suggestion}`);
        }
    }

    console.log('\n' + '='.repeat(70));
    console.log(
        '  Note: matches tagged __IN_COMMENT live inside comments and usually only require updating the documentation',
    );
    console.log('='.repeat(70));
}

// CLI entrypoint
// Note: the --path argument only affects the scan root for TypeScript files;
//       JSON fixtures (tests/fixtures/conformance/)
//       are always resolved relative to the project root (ROOT) and are unaffected by --path.
const args = process.argv.slice(2);
const pathArg = args.find((a) => a.startsWith('--path='));
const formatArg = args.find((a) => a.startsWith('--format='));
const scanPath = pathArg ? pathArg.slice('--path='.length) : ROOT;
const format = formatArg ? formatArg.slice('--format='.length) : 'text';

const summary = scan(scanPath);

if (format === 'json') {
    console.log(JSON.stringify(summary, null, 2));
} else {
    printTextReport(summary);
}

// Export the summary helpers as a module for unit tests to consume.
// listTsFiles is kept as an alias of listTargetFiles for backward compatibility with existing test references.
export {
    scan,
    scanFile,
    listTsFiles,
    listTargetFiles,
    type ScanMatch,
    type ScanSummary,
};
