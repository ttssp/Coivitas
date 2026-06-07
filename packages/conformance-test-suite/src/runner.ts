/**
 * ConformanceRunner: load fixtures and run conformance tests at the local schema-validation layer.
 *
 * Summary first:
 * - Current stage: use local schema validation (@coivitas/types validateAgainstSchema);
 *   the target endpoint URL is recorded in the report metadata for a future HTTP-mode extension.
 * - Supports the four fixture shapes ValidInvalid / CrossVersion (cases/matrix) / EncodingPairs / NestedGroup.
 * - EncodingPairs shape: verify that the encoding_pairs array exists and is non-empty (PASS), no schema validation.
 * - NestedGroup shape: actively SKIP (DEFER, per-group schema routing not yet implemented).
 * - Failure path: a fixture-loading exception → report as FAIL and record the error.
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { validateAgainstSchema, SCHEMA_IDS } from '@coivitas/types';
import { validateWithArchivedValidator } from './multi-version-validator.js';

// SchemaId is not publicly exported from @coivitas/types; derive it from the SCHEMA_IDS constant
type SchemaId = (typeof SCHEMA_IDS)[keyof typeof SCHEMA_IDS];

import type {
    AnyFixtureFile,
    ConformanceReport,
    ConformanceResult,
    CrossVersionFixtureFile,
    EncodingPairsFixtureFile,
    FixtureCase,
    RunnerOptions,
    ValidInvalidFixtureFile,
} from './types.js';

// Built-in fixture root directory (relative to the monorepo root; located at runtime via __filename)
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Path derivation (correct in both execution scenarios):
// src execution (tsx/ts-node): packages/conformance-test-suite/src/runner.ts
// __dirname = .../packages/conformance-test-suite/src
// → 3 segments up (src → pkg → packages → monorepo root)
// dist execution (compiled node): packages/conformance-test-suite/dist/runner.js
// __dirname = .../packages/conformance-test-suite/dist
// → 3 segments up (dist → pkg → packages → monorepo root)
// Both cases go up 3 `..` rather than 4.
// Note: a published package has no monorepo context, so getBuiltinFixturePaths() prefers to
// load the package-internal fixtures/ (copied in during the build stage), without relying on MONOREPO_ROOT.
const PACKAGE_ROOT = path.resolve(__dirname, '..');
const MONOREPO_ROOT = path.resolve(__dirname, '..', '..', '..');
const BUILTIN_FIXTURE_ROOT = path.resolve(
    MONOREPO_ROOT,
    'tests',
    'fixtures',
    'conformance',
);

// Package-internal fixtures (copied from tests/fixtures/conformance at build time; the published package uses this path)
// - fixtures/v0.3.0/ : v0.3.0 breaking-format-change fixtures (exact single-directory match)
// - fixtures/baseline/: v0.1 + v0.2 baseline fixtures (copied from the scattered .json files at the conformance root)
const PKG_FIXTURE_DIR = path.resolve(PACKAGE_ROOT, 'fixtures', 'v0.3.0');
const PKG_BASELINE_DIR = path.resolve(PACKAGE_ROOT, 'fixtures', 'baseline');

// Built-in v0.3.0 fixture directory (monorepo scenario)
const BUILTIN_V030_DIR = path.resolve(BUILTIN_FIXTURE_ROOT, 'v0.3.0');

// schemaId registry for v0.3.0 fixture files (consistent with tests/interop/conformance-suite.test.ts)
const V030_SCHEMA_REGISTRY: Record<string, SchemaId> = {
    'dual-key-rotation.v0.3.json': 'resolvedPublicKeys',
    'delegation-depth-boundary.v0.3.json': 'actionRecord',
    'action-vocabulary-supersede.v0.3.json': 'actionRecord',
    'cross-version.v0.3.json': 'negotiationEnvelope',
    'control-plane-action-isolation.v0.3.json': 'capabilityToken',
};

// Set of supported schemaIds (limited to what @coivitas/types validateAgainstSchema covers)
const SUPPORTED_SCHEMA_IDS: ReadonlySet<string> = new Set<SchemaId>([
    'agentIdentityDocument',
    'capabilityToken',
    'capability',
    'actionRecord',
    'agentCard',
    'negotiationEnvelope',
    'handshakeChallenge',
    'handshakeResponse',
    'resolvedPublicKeys',
    'sessionSupersededParams',
    'keyRotationState',
]);

/** Helper functions for detecting fixture shapes */
function isEncodingPairs(
    fixture: AnyFixtureFile,
): fixture is EncodingPairsFixtureFile {
    return (
        'encoding_pairs' in fixture &&
        Array.isArray((fixture as { encoding_pairs?: unknown }).encoding_pairs)
    );
}

function isCrossVersion(
    fixture: AnyFixtureFile,
): fixture is CrossVersionFixtureFile {
    if (
        'cases' in fixture &&
        Array.isArray((fixture as CrossVersionFixtureFile).cases)
    ) {
        return true;
    }
    if (
        'matrix' in fixture &&
        Array.isArray((fixture as CrossVersionFixtureFile).matrix)
    ) {
        return true;
    }
    return false;
}

/**
 * Nested-group fixture detection (v030-base64url-field-extensions shape):
 * a group key at the root level organizes valid/invalid as an object.
 */
function isNestedGroup(fixture: AnyFixtureFile): boolean {
    const f = fixture as Record<string, unknown>;
    for (const key of Object.keys(f)) {
        if (key === 'description' || key === '$schema' || key === 'schemaId')
            continue;
        const value = f[key];
        if (
            typeof value === 'object' &&
            value !== null &&
            !Array.isArray(value) &&
            ('valid' in (value as Record<string, unknown>) ||
                'invalid' in (value as Record<string, unknown>))
        ) {
            return true;
        }
    }
    return false;
}

/** Load a fixture JSON file, throwing on failure. */
function loadFixtureFile(filePath: string): AnyFixtureFile {
    const raw = fs.readFileSync(filePath, 'utf8');
    return JSON.parse(raw) as AnyFixtureFile;
}

/** Compute the list of all .json file paths for a fixture directory or file. */
function resolveFixturePaths(input: string): string[] {
    const stat = fs.statSync(input);
    if (stat.isDirectory()) {
        return fs
            .readdirSync(input, { withFileTypes: true })
            .filter((e) => e.isFile() && e.name.endsWith('.json'))
            .map((e) => path.join(input, e.name))
            .sort();
    }
    if (stat.isFile() && input.endsWith('.json')) {
        return [input];
    }
    throw new Error(`fixture path must be a .json file or directory: ${input}`);
}

/** Infer the schemaId from the file path (prefer the fixture's top-level schemaId, then the registry, otherwise undefined). */
function inferSchemaId(
    filename: string,
    fixture: AnyFixtureFile,
): SchemaId | undefined {
    const f = fixture as { schemaId?: string };
    if (f.schemaId && SUPPORTED_SCHEMA_IDS.has(f.schemaId)) {
        return f.schemaId as SchemaId;
    }
    const base = path.basename(filename);
    const fromRegistry = V030_SCHEMA_REGISTRY[base];
    return fromRegistry;
}

/**
 * assertRejectionMatches — verify that the schema error chain matches the expectedError description.
 *
 * Match levels (L1 → L4, degrading in order):
 * - L1 (exact substring): expectedError is a substring of any error.message → match
 * - L2 (keyword token): at least one >4-character token from expectedError appears in
 *   the concatenated error messages → match (covers exact field-name scenarios like 'delegationDepth')
 * - L3 (instancePath field extraction): a field name mentioned in expectedError (alphanumeric sequence >3 chars)
 *   appears in any error.instancePath → match (covers the case-2/case-3 semantic-description scenarios)
 * - L4: no match → return a mismatch diagnostic (the caller decides FAIL)
 *
 * Design constraints:
 * - Does not throw; returns null on a match, returns a string for the mismatch reason
 * - An empty errors array is treated as "no error information" → L4 no match
 */
function assertRejectionMatches(
    expectedError: string,
    errors: Array<{ instancePath?: string; message?: string }>,
): string | null /* null = matched*/ {
    if (errors.length === 0) {
        return `expectedError '${expectedError}' but no error messages in validation result`;
    }

    const allMessages = errors.map((e) => e.message ?? '').join(' ');
    const allPaths = errors.map((e) => e.instancePath ?? '').join(' ');

    // L1: exact substring match (expectedError appears in some error message)
    for (const e of errors) {
        if (e.message && e.message.includes(expectedError)) {
            return null; // matched
        }
    }

    // L2: keyword token match (>4-character tokens extracted from expectedError)
    const tokens = expectedError
        .split(/[\s'".()[\]{}:,;/\\]+/)
        .filter((t) => t.length > 4);
    if (tokens.length > 0) {
        const matched = tokens.some((tok) =>
            allMessages.toLowerCase().includes(tok.toLowerCase()),
        );
        if (matched) {
            return null; // matched
        }
    }

    // L3: instancePath field extraction (alphanumeric identifiers >3 chars in expectedError, check for a path hit)
    const fieldTokens = expectedError
        .match(/[a-zA-Z][a-zA-Z0-9]{3,}/g) ?? [];
    if (fieldTokens.length > 0) {
        const pathMatched = fieldTokens.some((tok) =>
            allPaths.toLowerCase().includes(tok.toLowerCase()),
        );
        if (pathMatched) {
            return null; // matched
        }
    }

    // L4: no match
    return (
        `expectedError '${expectedError}' not matched by error chain. ` +
        `messages=${JSON.stringify(errors.slice(0, 3).map((e) => e.message))}`
    );
}

/** Run a single FixtureCase and return a ConformanceResult. */
function runCase(
    fixtureCase: FixtureCase,
    fixtureFile: string,
    schemaId: SchemaId | undefined,
    expectedBool: boolean,
    startMs: number,
): ConformanceResult {
    const id =
        fixtureCase.id ?? fixtureCase.description ?? '<unnamed>';
    const effectiveSchemaId = (fixtureCase.schemaId &&
    SUPPORTED_SCHEMA_IDS.has(fixtureCase.schemaId)
        ? fixtureCase.schemaId
        : schemaId) as SchemaId | undefined;

    if (!effectiveSchemaId) {
        return {
            fixtureId: id,
            status: 'SKIP',
            latencyMs: 0,
            error: `no schemaId for fixture case; add to V030_SCHEMA_REGISTRY or declare top-level schemaId`,
            fixtureFile,
            expected: expectedBool,
        };
    }

    const t0 = Date.now();
    const result = validateAgainstSchema(fixtureCase.data, effectiveSchemaId);
    const latencyMs = Date.now() - t0 + (Date.now() - startMs > 0 ? 0 : 0);

    const actual = result.valid;
    const pass = actual === expectedBool;

    if (!pass) {
        const errorMsg = expectedBool
            ? `expected PASS (schema accept) but got FAIL: ${JSON.stringify(result.errors?.slice(0, 2))}`
            : `expected FAIL (schema reject) but got PASS`;
        return {
            fixtureId: id,
            status: 'FAIL',
            latencyMs,
            error: errorMsg,
            fixtureFile,
            expected: expectedBool,
            actual,
        };
    }

    // valid/invalid direction already matches; if it is REJECT and has an expectedError, further verify the error reason
    if (!expectedBool && fixtureCase.expectedError) {
        const mismatch = assertRejectionMatches(
            fixtureCase.expectedError,
            result.errors ?? [],
        );
        if (mismatch !== null) {
            return {
                fixtureId: id,
                status: 'FAIL',
                latencyMs,
                error: mismatch,
                fixtureFile,
                expected: expectedBool,
                actual,
            };
        }
    }

    return {
        fixtureId: id,
        status: 'PASS',
        latencyMs,
        fixtureFile,
        expected: expectedBool,
        actual,
    };
}

/** Parse the tri-state expected value of a single case in a CrossVersion fixture. */
function parseCrossVersionExpected(
    c: FixtureCase,
): boolean | null /* null=RUNTIME_DEPENDENT */ {
    if (c.expectedResult === undefined) {
        return c.valid ?? true;
    }
    if (c.expectedResult === 'PASS') return true;
    if (c.expectedResult === 'REJECT' || c.expectedResult === 'FAIL')
        return false;
    if (c.expectedResult === 'RUNTIME_DEPENDENT') return null;
    throw new Error(
        `unknown expectedResult='${String(c.expectedResult)}'; expected PASS/REJECT/FAIL/RUNTIME_DEPENDENT`,
    );
}

/** Run a single fixture file and return all of its ConformanceResults. */
function runFixtureFile(
    filePath: string,
    fixture: AnyFixtureFile,
): ConformanceResult[] {
    const results: ConformanceResult[] = [];
    const startMs = Date.now();
    const basename = path.basename(filePath);
    const schemaId = inferSchemaId(filePath, fixture);

    // encoding_pairs shape: only verify the array is non-empty
    if (isEncodingPairs(fixture)) {
        const enc = fixture.encoding_pairs;
        const pass = Array.isArray(enc) && enc.length > 0;
        results.push({
            fixtureId: `${basename}::encoding_pairs`,
            status: pass ? 'PASS' : 'FAIL',
            latencyMs: Date.now() - startMs,
            fixtureFile: basename,
            expected: true,
            actual: pass,
            error: pass ? undefined : 'encoding_pairs array is empty',
        });
        return results;
    }

    // Nested-group shape: SKIP (DEFER per-group schema routing)
    if (isNestedGroup(fixture)) {
        results.push({
            fixtureId: `${basename}::nested-group`,
            status: 'SKIP',
            latencyMs: 0,
            fixtureFile: basename,
            expected: true,
            error: 'DEFER: nested-group fixture (per-group schema routing not yet implemented)',
        });
        return results;
    }

    // CrossVersion (cases / matrix) shape
    if (isCrossVersion(fixture)) {
        const cv = fixture;
        const samples = cv.cases ?? cv.matrix ?? [];
        for (const c of samples) {
            const expectedTri = parseCrossVersionExpected(c);
            if (expectedTri === null) {
                // RUNTIME_DEPENDENT → SKIP
                results.push({
                    fixtureId: c.id ?? c.description ?? '<unnamed>',
                    status: 'SKIP',
                    latencyMs: 0,
                    fixtureFile: basename,
                    expected: true,
                    error: 'RUNTIME_DEPENDENT: requires authoritative historical schema snapshot',
                });
                continue;
            }
            // cross-version reject path: prefer the package-internal multi-version validator
            const needsMultiVersion =
                c.validatorVersion !== undefined &&
                c.inputSpecVersion !== undefined &&
                c.validatorVersion !== c.inputSpecVersion;
            if (needsMultiVersion && !expectedTri) {
                // expectedTri=false (REJECT/FAIL) + cross-version → try the archived validator
                const t0mv = Date.now();
                const mvResult = schemaId
                    ? validateWithArchivedValidator(c.data, schemaId, c.validatorVersion!)
                    : null;
                const latencyMv = Date.now() - t0mv;
                const fixtureId = c.id ?? c.description ?? '<unnamed>';
                if (mvResult === null) {
                    // Not in the archived validator coverage set → D5 SKIP
                    results.push({
                        fixtureId,
                        status: 'SKIP',
                        latencyMs: 0,
                        fixtureFile: basename,
                        expected: false,
                        error: `DEFER D5: multi-version validator (v${c.validatorVersion} vs v${c.inputSpecVersion}) not in coverage set for schemaId=${schemaId ?? '<none>'}`,
                    });
                } else {
                    // In the coverage set: expectedTri=false means REJECT is expected (valid=false)
                    const pass = mvResult.valid === false;
                    if (!pass) {
                        results.push({
                            fixtureId,
                            status: 'FAIL',
                            latencyMs: latencyMv,
                            fixtureFile: basename,
                            expected: false,
                            actual: true,
                            error: `expected REJECT (archived v${c.validatorVersion} validator) but data was accepted`,
                        });
                    } else {
                        // REJECT direction already matches; if there is an expectedError, further verify the error reason
                        const errMismatch = c.expectedError
                            ? assertRejectionMatches(c.expectedError, mvResult.errors)
                            : null;
                        if (errMismatch !== null) {
                            results.push({
                                fixtureId,
                                status: 'FAIL',
                                latencyMs: latencyMv,
                                fixtureFile: basename,
                                expected: false,
                                actual: false,
                                error: errMismatch,
                            });
                        } else {
                            results.push({
                                fixtureId,
                                status: 'PASS',
                                latencyMs: latencyMv,
                                fixtureFile: basename,
                                expected: false,
                                actual: false,
                            });
                        }
                    }
                }
                continue;
            }
            results.push(
                runCase(c, basename, schemaId, expectedTri, startMs),
            );
        }
        return results;
    }

    // ValidInvalid shape (valid / invalid / cross_version / boundary)
    const vi = fixture as ValidInvalidFixtureFile;

    for (const c of vi.valid ?? []) {
        results.push(runCase(c, basename, schemaId, true, startMs));
    }
    for (const c of vi.invalid ?? []) {
        results.push(runCase(c, basename, schemaId, false, startMs));
    }
    for (const c of vi.cross_version ?? []) {
        const expected = c.valid ?? true;
        results.push(runCase(c, basename, schemaId, expected, startMs));
    }
    for (const c of vi.boundary ?? []) {
        const expected = c.valid ?? true;
        results.push(runCase(c, basename, schemaId, expected, startMs));
    }

    return results;
}

/**
 * ConformanceRunner: the fixture-loading + schema-validation execution engine.
 */
export class ConformanceRunner {
    private readonly options: Required<RunnerOptions>;

    constructor(options: RunnerOptions) {
        this.options = {
            target: options.target,
            fixturePaths: options.fixturePaths ?? [],
            allowSkip: options.allowSkip ?? false,
        };
    }

    /**
     * Run all fixtures and return a ConformanceReport.
     * Does not throw on failure (fixture-level errors are recorded in result.error + status=FAIL).
     */
    // eslint-disable-next-line @typescript-eslint/require-await
    async run(): Promise<ConformanceReport> {
        const runAt = new Date().toISOString();
        const allResults: ConformanceResult[] = [];

        // Determine the list of fixture files to load
        const fixturePaths =
            this.options.fixturePaths.length > 0
                ? this.options.fixturePaths
                : this.getBuiltinFixturePaths();

        for (const inputPath of fixturePaths) {
            let filePaths: string[];
            try {
                filePaths = resolveFixturePaths(inputPath);
            } catch (e) {
                allResults.push({
                    fixtureId: `<load-error::${inputPath}>`,
                    status: 'FAIL',
                    latencyMs: 0,
                    fixtureFile: path.basename(inputPath),
                    expected: true,
                    error: `failed to resolve fixture path: ${String(e)}`,
                });
                continue;
            }

            for (const fp of filePaths) {
                let fixture: AnyFixtureFile;
                try {
                    fixture = loadFixtureFile(fp);
                } catch (e) {
                    allResults.push({
                        fixtureId: `<parse-error::${path.basename(fp)}>`,
                        status: 'FAIL',
                        latencyMs: 0,
                        fixtureFile: path.basename(fp),
                        expected: true,
                        error: `fixture JSON parse error: ${String(e)}`,
                    });
                    continue;
                }

                const fileResults = runFixtureFile(fp, fixture);
                allResults.push(...fileResults);
            }
        }

        const summary = {
            total: allResults.length,
            pass: allResults.filter((r) => r.status === 'PASS').length,
            fail: allResults.filter((r) => r.status === 'FAIL').length,
            skip: allResults.filter((r) => r.status === 'SKIP').length,
        };

        // passed determination:
        // - fail-closed when there are no results (passed=false)
        // - always false when fail > 0
        // - allowSkip=false (default): skip > 0 counts as not-passed (contract: 0=all fixtures pass)
        // - allowSkip=true: skip does not affect passed (explicitly declared that skipping is allowed)
        const passed =
            summary.total > 0 &&
            summary.fail === 0 &&
            (this.options.allowSkip || summary.skip === 0);

        return {
            target: this.options.target,
            runAt,
            passed,
            summary,
            results: allResults,
        };
    }

    /**
     * Return the list of built-in fixture directory/file paths (in version order: v0.1/v0.2 baseline → v0.3.0).
     *
     * Lookup priority:
     * 1. Package-internal fixtures/v0.3.0/ exists → published-package scenario:
     *    return [fixtures/baseline/, fixtures/v0.3.0/]
     *    (when fixtures/baseline/ does not exist, warn but do not fail, still return v0.3.0)
     * 2. monorepo tests/fixtures/conformance/v0.3.0/ exists → local development/CI:
     *    return [tests/fixtures/conformance/, tests/fixtures/conformance/v0.3.0/]
     *    (the top-level .json files at the conformance/ root are the v0.1/v0.2 baseline;
     *     resolveFixturePaths takes only top-level files, not recursing into subdirectories)
     * 3. Neither path exists → throw.
     *
     * Baseline coverage depends on the actual existence of the corresponding directory/file; WARN rather than FAIL when absent.
     */
    private getBuiltinFixturePaths(): string[] {
        // Preferred: package-internal fixtures/ (published package or post-build scenario)
        if (fs.existsSync(PKG_FIXTURE_DIR)) {
            const paths: string[] = [];
            if (fs.existsSync(PKG_BASELINE_DIR)) {
                paths.push(PKG_BASELINE_DIR);
            } else {
                // When the baseline directory does not exist, warn but do not fail; v0.1/v0.2 baseline coverage is reduced.
                // Reason: the copy-fixtures build script may not have run, or the baseline is empty.
                process.stderr.write(
                    `[conformance] WARN: baseline fixture directory not found: ${PKG_BASELINE_DIR}\n` +
                        `  v0.1/v0.2 baseline coverage will be absent. Run 'npm run build' to copy fixtures.\n`,
                );
            }
            paths.push(PKG_FIXTURE_DIR);
            return paths;
        }
        // Next: the monorepo tests/ tree (local development / CI)
        // The top-level .json files under BUILTIN_FIXTURE_ROOT contain the v0.1/v0.2 baseline (scattered at the conformance/ root)
        if (fs.existsSync(BUILTIN_V030_DIR)) {
            return [BUILTIN_FIXTURE_ROOT, BUILTIN_V030_DIR];
        }
        throw new Error(
            `builtin fixture directory not found.\n` +
                `Checked:\n` +
                `  [package] ${PKG_FIXTURE_DIR}\n` +
                `  [monorepo] ${BUILTIN_V030_DIR}\n` +
                `In monorepo: ensure tests/fixtures/conformance/v0.3.0/ exists.\n` +
                `In published package: run 'npm run build' to copy fixtures.\n` +
                `Note: baseline coverage (v0.1/v0.2) depends on fixture directory existence.`,
        );
    }
}
