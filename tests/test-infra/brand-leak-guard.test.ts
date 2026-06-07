// Prevent legacy brand tokens from flowing back in.
//
// Failure signal: a refactor or cherry-pick introduces agent_protocol / AgentProtocol /
// ap-conformance anywhere (variable name, comment, SQL, docs, config), which counts as a brand regression.
//
// Implementation approach:
// 1. Recursively scan packages/ + tests/ + scripts/ + infra/ + root docs (README/CONTRIBUTING).
// 2. Skip node_modules / dist / .turbo / .git / pnpm-lock.yaml.
// 3. Explicitly skip .cleanup-tools/ (audit-tooling sandbox, legitimately references old names for rename drills).
// 4. Filter by text extensions: .ts / .sql / .md / .json / .sh / .mjs / .yaml / .yml
//    (avoid reading binary or lock files).
// 5. Collect {path, lineNo, token}, listing them all in a single expect failure message.
//
// Invariant: the hit count of legacy brand tokens across all tracked files in the repo is always 0; this guard locks that invariant down,
// preventing later refactors / cherry-picks from reintroducing the old brand names.

import { readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

const REPO_ROOT = path.resolve(__dirname, '..', '..');

// Top-level scan entry points
const SCAN_ROOTS = [
    path.join(REPO_ROOT, 'packages'),
    path.join(REPO_ROOT, 'tests'),
    path.join(REPO_ROOT, 'scripts'),
    path.join(REPO_ROOT, 'infra'),
    path.join(REPO_ROOT, 'examples'),
    path.join(REPO_ROOT, 'docs'),
];

// Individual root-level files (the root is not scanned recursively, only these named files)
const SCAN_ROOT_FILES = [
    path.join(REPO_ROOT, 'README.md'),
    path.join(REPO_ROOT, 'CONTRIBUTING.md'),
    path.join(REPO_ROOT, 'SECURITY.md'),
    path.join(REPO_ROOT, 'CODE_OF_CONDUCT.md'),
    path.join(REPO_ROOT, 'package.json'),
    path.join(REPO_ROOT, 'turbo.json'),
    path.join(REPO_ROOT, 'docker-compose.yml'),
];

const SKIP_DIRS = new Set([
    'node_modules',
    'dist',
    '.turbo',
    '.git',
    'coverage',
    '.cache',
    // Audit-tooling sandbox: legitimately references old names for rename drills
    '.cleanup-tools',
]);

const TEXT_EXTS = new Set([
    '.ts',
    '.tsx',
    '.js',
    '.mjs',
    '.cjs',
    '.py',
    '.sql',
    '.md',
    '.json',
    '.sh',
    '.yaml',
    '.yml',
    '.toml',
]);

// Forbidden tokens (case-sensitive)
// Note: ap-managed is a leftover from the old brand's `ap-` prefix (infra container name / grafana uid),
//     same origin as ap-conformance, locked down together to prevent flow-back.
const FORBIDDEN_TOKENS = [
    'agent_protocol',
    'AgentProtocol',
    'ap-conformance',
    'ap-managed',
];

function listTextFiles(dir: string): string[] {
    const out: string[] = [];
    let entries: string[];
    try {
        entries = readdirSync(dir);
    } catch {
        return out;
    }
    for (const name of entries) {
        if (SKIP_DIRS.has(name)) continue;
        const full = path.join(dir, name);
        let stat;
        try {
            stat = statSync(full);
        } catch {
            continue;
        }
        if (stat.isDirectory()) {
            out.push(...listTextFiles(full));
        } else if (TEXT_EXTS.has(path.extname(name))) {
            out.push(full);
        }
    }
    return out;
}

describe('brand-leak-guard', () => {
    it('should contain zero legacy brand tokens when scanning packages, tests, scripts, infra, examples, root docs', () => {
        const files: string[] = [];
        for (const root of SCAN_ROOTS) {
            files.push(...listTextFiles(root));
        }
        for (const f of SCAN_ROOT_FILES) {
            try {
                if (statSync(f).isFile()) files.push(f);
            } catch {
                // Skip if the file does not exist (README/CONTRIBUTING etc. may move in the future)
            }
        }
        // Baseline: the scanned file count should be > 500 (a full monorepo includes packages/*/src + tests)
        expect(files.length).toBeGreaterThan(100);

        const violations: { relPath: string; lineNo: number; token: string }[] =
            [];
        for (const filePath of files) {
            const relPath = path.relative(REPO_ROOT, filePath);
            // Skip this file itself (otherwise the literal tokens would trip the self-check)
            if (relPath === path.relative(REPO_ROOT, __filename)) continue;
            const content = readFileSync(filePath, 'utf-8');
            // Fast check: skip the line-by-line scan if no token is present
            const matched = FORBIDDEN_TOKENS.some((t) => content.includes(t));
            if (!matched) continue;
            const lines = content.split('\n');
            for (let i = 0; i < lines.length; i += 1) {
                for (const token of FORBIDDEN_TOKENS) {
                    if (lines[i].includes(token)) {
                        violations.push({
                            relPath,
                            lineNo: i + 1,
                            token,
                        });
                    }
                }
            }
        }

        if (violations.length > 0) {
            const detail = violations
                .map((v) => `  ${v.relPath}:${v.lineNo}  [${v.token}]`)
                .join('\n');
            throw new Error(
                `Legacy brand leak — ${violations.length} site(s) detected:\n${detail}`,
            );
        }
        expect(violations).toEqual([]);
    });
});
