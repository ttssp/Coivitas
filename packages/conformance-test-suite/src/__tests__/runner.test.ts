/**
 * Unit tests for ConformanceRunner.
 *
 * Summary first:
 * - Isolate tests with a temporary directory + inline fixture JSON, not relying on the real fixture directory
 * - Cover the four shapes ValidInvalid / CrossVersion / EncodingPairs / NestedGroup
 * - Cover RUNTIME_DEPENDENT skip / multi-version D5 skip / no-schemaId skip
 * - Cover the three error paths: fixture path does not exist / JSON parse failure / non-json file
 * - Cover passed=false when total===0 (fail-closed)
 */

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ConformanceRunner } from '../runner.js';

// Temporary directory management
let tmpDir: string;

beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'conformance-runner-test-'));
});

afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
    vi.restoreAllMocks();
});

/** Write a temporary fixture file and return its path. */
function writeFixture(name: string, content: object): string {
    const fp = path.join(tmpDir, name);
    fs.writeFileSync(fp, JSON.stringify(content), 'utf8');
    return fp;
}

// ---------------------------------------------------------------------------
// Basic construction & empty run
// ---------------------------------------------------------------------------

describe('ConformanceRunner construction', () => {
    it('should accept options with fixturePaths', () => {
        const runner = new ConformanceRunner({
            target: 'http://example.com',
            fixturePaths: [],
        });
        expect(runner).toBeDefined();
    });

    it('should accept options without fixturePaths', () => {
        // Omitting fixturePaths does not throw (the built-in directory is resolved only at run())
        const runner = new ConformanceRunner({ target: 'http://example.com' });
        expect(runner).toBeDefined();
    });
});

// ---------------------------------------------------------------------------
// ValidInvalid shape
// ---------------------------------------------------------------------------

describe('ValidInvalid fixture shape', () => {
    it('should PASS valid case when schema accepts it', async () => {
        // resolvedPublicKeys schema: current(64-hex) + rotationState=STABLE
        const fp = writeFixture('test-valid-invalid.json', {
            schemaId: 'resolvedPublicKeys',
            valid: [
                {
                    id: 'vi-valid-01',
                    description: 'STABLE single key',
                    data: {
                        current: 'a'.repeat(64),
                        rotationState: 'STABLE',
                    },
                },
            ],
            invalid: [],
        });

        const runner = new ConformanceRunner({
            target: 'http://localhost:3000',
            fixturePaths: [fp],
        });
        const report = await runner.run();

        expect(report.summary.total).toBe(1);
        expect(report.summary.pass).toBe(1);
        expect(report.summary.fail).toBe(0);
        expect(report.results[0].status).toBe('PASS');
        expect(report.results[0].fixtureId).toBe('vi-valid-01');
        expect(report.passed).toBe(true);
    });

    it('should PASS invalid case when schema rejects it', async () => {
        const fp = writeFixture('test-reject.json', {
            schemaId: 'resolvedPublicKeys',
            valid: [],
            invalid: [
                {
                    id: 'vi-invalid-01',
                    description: 'missing required current field',
                    data: { rotationState: 'STABLE' },
                },
            ],
        });

        const runner = new ConformanceRunner({
            target: 'http://localhost:3000',
            fixturePaths: [fp],
        });
        const report = await runner.run();

        expect(report.summary.pass).toBe(1);
        expect(report.results[0].status).toBe('PASS');
        expect(report.results[0].expected).toBe(false);
    });

    it('should FAIL valid case when schema rejects it', async () => {
        // Construct a case where the schema rejects but the fixture expects it to pass
        const fp = writeFixture('test-should-fail.json', {
            schemaId: 'resolvedPublicKeys',
            valid: [
                {
                    id: 'vi-fail-01',
                    description: 'expected valid but actually invalid data',
                    data: { rotationState: 'STABLE' /* missing current*/ },
                },
            ],
            invalid: [],
        });

        const runner = new ConformanceRunner({
            target: 'http://localhost:3000',
            fixturePaths: [fp],
        });
        const report = await runner.run();

        expect(report.summary.fail).toBe(1);
        expect(report.passed).toBe(false);
        const r = report.results[0];
        expect(r.status).toBe('FAIL');
        expect(r.error).toContain('expected PASS');
    });

    it('should FAIL invalid case when schema accepts it', async () => {
        // Schema accepts but the fixture expects rejection
        const fp = writeFixture('test-invalid-fail.json', {
            schemaId: 'resolvedPublicKeys',
            valid: [],
            invalid: [
                {
                    id: 'vi-invalid-fail-01',
                    description: 'expected reject but schema accepts',
                    data: {
                        current: 'b'.repeat(64),
                        rotationState: 'STABLE',
                    },
                },
            ],
        });

        const runner = new ConformanceRunner({
            target: 'http://localhost:3000',
            fixturePaths: [fp],
        });
        const report = await runner.run();

        expect(report.summary.fail).toBe(1);
        const r = report.results[0];
        expect(r.status).toBe('FAIL');
        expect(r.error).toContain('expected FAIL');
    });

    it('should run boundary and cross_version arrays in ValidInvalid fixture', async () => {
        const fp = writeFixture('test-boundary.json', {
            schemaId: 'resolvedPublicKeys',
            valid: [],
            invalid: [],
            boundary: [
                {
                    id: 'boundary-01',
                    valid: true,
                    data: { current: 'c'.repeat(64), rotationState: 'STABLE' },
                },
            ],
            cross_version: [
                {
                    id: 'cv-01',
                    valid: false,
                    data: { rotationState: 'STABLE' /* no current*/ },
                },
            ],
        });

        const runner = new ConformanceRunner({
            target: 'http://localhost:3000',
            fixturePaths: [fp],
        });
        const report = await runner.run();

        expect(report.summary.total).toBe(2);
        // boundary-01: valid=true, data is valid schema → PASS
        expect(report.results.find((r) => r.fixtureId === 'boundary-01')?.status).toBe('PASS');
        // cv-01: valid=false, data missing current → schema rejects → PASS
        expect(report.results.find((r) => r.fixtureId === 'cv-01')?.status).toBe('PASS');
    });

    it('should use description as fixtureId when id is absent', async () => {
        const fp = writeFixture('test-desc-id.json', {
            schemaId: 'resolvedPublicKeys',
            valid: [
                {
                    description: 'my desc case',
                    data: { current: 'd'.repeat(64), rotationState: 'STABLE' },
                },
            ],
        });

        const runner = new ConformanceRunner({
            target: 'http://localhost:3000',
            fixturePaths: [fp],
        });
        const report = await runner.run();

        expect(report.results[0].fixtureId).toBe('my desc case');
    });

    it('should use <unnamed> when both id and description are absent', async () => {
        const fp = writeFixture('test-unnamed.json', {
            schemaId: 'resolvedPublicKeys',
            valid: [
                {
                    data: { current: 'e'.repeat(64), rotationState: 'STABLE' },
                },
            ],
        });

        const runner = new ConformanceRunner({
            target: 'http://localhost:3000',
            fixturePaths: [fp],
        });
        const report = await runner.run();

        expect(report.results[0].fixtureId).toBe('<unnamed>');
    });

    it('should SKIP case when no schemaId available', async () => {
        const fp = writeFixture('unknown-schema.json', {
            // No top-level schemaId, and the filename is not in the registry either
            valid: [{ id: 'no-schema-case', data: { foo: 'bar' } }],
        });

        const runner = new ConformanceRunner({
            target: 'http://localhost:3000',
            fixturePaths: [fp],
        });
        const report = await runner.run();

        expect(report.results[0].status).toBe('SKIP');
        expect(report.results[0].error).toContain('no schemaId');
    });

    it('should use per-case schemaId when provided and valid', async () => {
        const fp = writeFixture('per-case-schema.json', {
            // No top-level schemaId
            valid: [
                {
                    id: 'per-case-01',
                    schemaId: 'resolvedPublicKeys',
                    data: { current: 'f'.repeat(64), rotationState: 'STABLE' },
                },
            ],
        });

        const runner = new ConformanceRunner({
            target: 'http://localhost:3000',
            fixturePaths: [fp],
        });
        const report = await runner.run();

        expect(report.results[0].status).toBe('PASS');
    });
});

// ---------------------------------------------------------------------------
// CrossVersion (cases / matrix) shape
// ---------------------------------------------------------------------------

describe('CrossVersion fixture shape', () => {
    it('should run cases array and return results', async () => {
        const fp = writeFixture('cross-version-test.json', {
            schemaId: 'resolvedPublicKeys',
            cases: [
                {
                    id: 'cv-case-01',
                    valid: true,
                    data: { current: 'a'.repeat(64), rotationState: 'STABLE' },
                },
                {
                    id: 'cv-case-02',
                    valid: false,
                    data: { rotationState: 'STABLE' /* missing current*/ },
                },
            ],
        });

        const runner = new ConformanceRunner({
            target: 'http://localhost:3000',
            fixturePaths: [fp],
        });
        const report = await runner.run();

        expect(report.summary.total).toBe(2);
        expect(report.results.find((r) => r.fixtureId === 'cv-case-01')?.status).toBe('PASS');
        expect(report.results.find((r) => r.fixtureId === 'cv-case-02')?.status).toBe('PASS');
    });

    it('should run matrix array similarly to cases', async () => {
        const fp = writeFixture('cross-version-matrix.json', {
            schemaId: 'resolvedPublicKeys',
            matrix: [
                {
                    id: 'matrix-01',
                    expectedResult: 'PASS',
                    data: { current: 'b'.repeat(64), rotationState: 'STABLE' },
                },
            ],
        });

        const runner = new ConformanceRunner({
            target: 'http://localhost:3000',
            fixturePaths: [fp],
        });
        const report = await runner.run();

        expect(report.summary.total).toBe(1);
        expect(report.results[0].status).toBe('PASS');
    });

    it('should SKIP RUNTIME_DEPENDENT cases', async () => {
        const fp = writeFixture('cross-version-runtime.json', {
            schemaId: 'resolvedPublicKeys',
            cases: [
                {
                    id: 'runtime-dep-01',
                    expectedResult: 'RUNTIME_DEPENDENT',
                    data: {},
                },
            ],
        });

        const runner = new ConformanceRunner({
            target: 'http://localhost:3000',
            fixturePaths: [fp],
        });
        const report = await runner.run();

        expect(report.results[0].status).toBe('SKIP');
        expect(report.results[0].error).toContain('RUNTIME_DEPENDENT');
    });

    it('should SKIP D5 multi-version reject cases', async () => {
        const fp = writeFixture('cross-version-d5.json', {
            schemaId: 'resolvedPublicKeys',
            cases: [
                {
                    id: 'd5-skip-01',
                    expectedResult: 'REJECT',
                    validatorVersion: '0.1.0',
                    inputSpecVersion: '0.3.0',
                    data: { current: 'c'.repeat(64), rotationState: 'STABLE' },
                },
            ],
        });

        const runner = new ConformanceRunner({
            target: 'http://localhost:3000',
            fixturePaths: [fp],
        });
        const report = await runner.run();

        expect(report.results[0].status).toBe('SKIP');
        expect(report.results[0].error).toContain('D5');
    });

    it('should PASS (REJECT) via archived negotiationEnvelope v0.1.0 validator when specVersion is 0.3.0 (xv-03 pattern)', async () => {
        // xv-03: negotiationEnvelope + v0.1.0 validator + specVersion=0.3.0 → archived validator REJECT → PASS
        const fp = writeFixture('cross-version-xv03.json', {
            schemaId: 'negotiationEnvelope',
            cases: [
                {
                    id: 'xv-03',
                    expectedResult: 'REJECT',
                    validatorVersion: '0.1.0',
                    inputSpecVersion: '0.3.0',
                    data: {
                        specVersion: '0.3.0',
                        sessionId: 'test-session',
                        proposedCapabilities: [],
                    },
                },
            ],
        });

        const runner = new ConformanceRunner({
            target: 'http://localhost:3000',
            fixturePaths: [fp],
        });
        const report = await runner.run();

        // archived v0.1.0 validator: specVersion !== '0.1.0' → valid=false → PASS
        expect(report.results[0].status).toBe('PASS');
        expect(report.results[0].expected).toBe(false);
        expect(report.results[0].actual).toBe(false);
    });

    it('should PASS (REJECT) via archived actionRecord v0.2.0 validator when action is SESSION_SUPERSEDED (xv-06 pattern)', async () => {
        // xv-06: actionRecord + v0.2.0 validator + action=SESSION_SUPERSEDED → archived validator REJECT → PASS
        const fp = writeFixture('cross-version-xv06.json', {
            schemaId: 'actionRecord',
            cases: [
                {
                    id: 'xv-06',
                    expectedResult: 'REJECT',
                    validatorVersion: '0.2.0',
                    inputSpecVersion: '0.3.0',
                    data: {
                        action: 'SESSION_SUPERSEDED',
                        agentId: 'did:agent:test',
                        timestamp: new Date().toISOString(),
                    },
                },
            ],
        });

        const runner = new ConformanceRunner({
            target: 'http://localhost:3000',
            fixturePaths: [fp],
        });
        const report = await runner.run();

        // archived v0.2.0 validator: action === 'SESSION_SUPERSEDED' → valid=false → PASS
        expect(report.results[0].status).toBe('PASS');
        expect(report.results[0].expected).toBe(false);
        expect(report.results[0].actual).toBe(false);
    });

    it('should FAIL when archived validator accepts data that should be REJECTED', async () => {
        // negotiationEnvelope + v0.1.0 validator + specVersion=0.1.0 → validator returns valid=true → FAIL (expected REJECT but accepted)
        const fp = writeFixture('cross-version-mv-fail.json', {
            schemaId: 'negotiationEnvelope',
            cases: [
                {
                    id: 'mv-fail-01',
                    expectedResult: 'REJECT',
                    validatorVersion: '0.1.0',
                    inputSpecVersion: '0.3.0',
                    data: {
                        specVersion: '0.1.0', // matches v0.1.0 enum → validator accepts → but we EXPECT REJECT
                    },
                },
            ],
        });

        const runner = new ConformanceRunner({
            target: 'http://localhost:3000',
            fixturePaths: [fp],
        });
        const report = await runner.run();

        // archived v0.1.0 validator: specVersion === '0.1.0' → valid=true → expected REJECT but accepted → FAIL
        expect(report.results[0].status).toBe('FAIL');
        expect(report.results[0].error).toContain('expected REJECT (archived v0.1.0 validator) but data was accepted');
    });

    it('should handle FAIL expectedResult same as REJECT', async () => {
        const fp = writeFixture('cross-version-fail-expected.json', {
            schemaId: 'resolvedPublicKeys',
            cases: [
                {
                    id: 'fail-expected-01',
                    expectedResult: 'FAIL',
                    data: { rotationState: 'STABLE' /* missing current*/ },
                },
            ],
        });

        const runner = new ConformanceRunner({
            target: 'http://localhost:3000',
            fixturePaths: [fp],
        });
        const report = await runner.run();

        // expected=false (FAIL/REJECT), data is invalid → schema rejects → PASS
        expect(report.results[0].status).toBe('PASS');
    });

    it('should throw on unknown expectedResult value', async () => {
        const fp = writeFixture('cross-version-unknown.json', {
            schemaId: 'resolvedPublicKeys',
            cases: [
                {
                    id: 'unknown-01',
                    expectedResult: 'BOGUS',
                    data: {},
                },
            ],
        });

        const runner = new ConformanceRunner({
            target: 'http://localhost:3000',
            fixturePaths: [fp],
        });
        // parseCrossVersionExpected throws; runFixtureFile propagates → runCase exception
        // runner.run() does not catch this exception at runtime (fixture logic errors should be caught during review)
        await expect(runner.run()).rejects.toThrow('unknown expectedResult');
    });
});

// ---------------------------------------------------------------------------
// EncodingPairs shape
// ---------------------------------------------------------------------------

describe('EncodingPairs fixture shape', () => {
    it('should PASS when encoding_pairs array is non-empty', async () => {
        const fp = writeFixture('encoding-pairs-test.json', {
            description: 'encoding pairs fixture',
            encoding_pairs: [
                { hex: 'aabb', base64url: 'qrs', description: 'test pair' },
            ],
        });

        const runner = new ConformanceRunner({
            target: 'http://localhost:3000',
            fixturePaths: [fp],
        });
        const report = await runner.run();

        expect(report.results[0].status).toBe('PASS');
        expect(report.results[0].fixtureId).toContain('encoding_pairs');
    });

    it('should FAIL when encoding_pairs array is empty', async () => {
        const fp = writeFixture('encoding-pairs-empty.json', {
            description: 'empty encoding pairs',
            encoding_pairs: [],
        });

        const runner = new ConformanceRunner({
            target: 'http://localhost:3000',
            fixturePaths: [fp],
        });
        const report = await runner.run();

        expect(report.results[0].status).toBe('FAIL');
        expect(report.results[0].error).toContain('empty');
    });
});

// ---------------------------------------------------------------------------
// NestedGroup shape
// ---------------------------------------------------------------------------

describe('NestedGroup fixture shape', () => {
    it('should SKIP nested-group fixture with DEFER message', async () => {
        const fp = writeFixture('nested-group-test.json', {
            description: 'nested group',
            group_a: {
                valid: [{ id: 'g-valid-01', data: {} }],
                invalid: [],
            },
        });

        const runner = new ConformanceRunner({
            target: 'http://localhost:3000',
            fixturePaths: [fp],
        });
        const report = await runner.run();

        expect(report.results[0].status).toBe('SKIP');
        expect(report.results[0].error).toContain('DEFER');
        expect(report.results[0].fixtureId).toContain('nested-group');
    });
});

// ---------------------------------------------------------------------------
// Error paths
// ---------------------------------------------------------------------------

describe('error path handling', () => {
    it('should FAIL with error when fixture path does not exist', async () => {
        const nonExistent = path.join(tmpDir, 'not-exists.json');

        const runner = new ConformanceRunner({
            target: 'http://localhost:3000',
            fixturePaths: [nonExistent],
        });
        const report = await runner.run();

        expect(report.summary.fail).toBe(1);
        expect(report.results[0].status).toBe('FAIL');
        expect(report.results[0].error).toContain('failed to resolve fixture path');
    });

    it('should FAIL with error when fixture JSON is malformed', async () => {
        const fp = path.join(tmpDir, 'malformed.json');
        fs.writeFileSync(fp, '{ invalid json }', 'utf8');

        const runner = new ConformanceRunner({
            target: 'http://localhost:3000',
            fixturePaths: [fp],
        });
        const report = await runner.run();

        expect(report.summary.fail).toBe(1);
        expect(report.results[0].status).toBe('FAIL');
        expect(report.results[0].error).toContain('fixture JSON parse error');
    });

    it('should throw when fixture path is not a .json file and not a directory', async () => {
        const fp = path.join(tmpDir, 'test.txt');
        fs.writeFileSync(fp, 'not json', 'utf8');

        const runner = new ConformanceRunner({
            target: 'http://localhost:3000',
            fixturePaths: [fp],
        });
        const report = await runner.run();

        // resolveFixturePaths throws for .txt → caught and recorded as FAIL
        expect(report.summary.fail).toBe(1);
        expect(report.results[0].error).toContain('failed to resolve fixture path');
    });

    it('should load all .json files from a directory', async () => {
        // Write two fixture files into tmpDir
        writeFixture('file-a.json', {
            schemaId: 'resolvedPublicKeys',
            valid: [
                { id: 'dir-a-01', data: { current: 'a'.repeat(64), rotationState: 'STABLE' } },
            ],
        });
        writeFixture('file-b.json', {
            schemaId: 'resolvedPublicKeys',
            valid: [
                { id: 'dir-b-01', data: { current: 'b'.repeat(64), rotationState: 'STABLE' } },
            ],
        });

        const runner = new ConformanceRunner({
            target: 'http://localhost:3000',
            fixturePaths: [tmpDir],
        });
        const report = await runner.run();

        expect(report.summary.total).toBe(2);
        const ids = report.results.map((r) => r.fixtureId);
        expect(ids).toContain('dir-a-01');
        expect(ids).toContain('dir-b-01');
    });
});

// ---------------------------------------------------------------------------
// Report metadata
// ---------------------------------------------------------------------------

describe('ConformanceReport metadata', () => {
    it('should set target and runAt in report', async () => {
        const fp = writeFixture('meta-test.json', {
            schemaId: 'resolvedPublicKeys',
            valid: [
                { id: 'meta-01', data: { current: 'a'.repeat(64), rotationState: 'STABLE' } },
            ],
        });

        const runner = new ConformanceRunner({
            target: 'http://my-target:9000',
            fixturePaths: [fp],
        });
        const report = await runner.run();

        expect(report.target).toBe('http://my-target:9000');
        expect(report.runAt).toMatch(/^\d{4}-\d{2}-\d{2}T/); // ISO 8601
    });

    it('should report passed=false when total===0 (fail-closed)', async () => {
        // Empty fixture file (no valid/invalid/cases)
        const fp = writeFixture('empty-fixture.json', {
            schemaId: 'resolvedPublicKeys',
            valid: [],
            invalid: [],
        });

        const runner = new ConformanceRunner({
            target: 'http://localhost:3000',
            fixturePaths: [fp],
        });
        const report = await runner.run();

        expect(report.summary.total).toBe(0);
        expect(report.passed).toBe(false); // fail-closed
    });

    it('should report passed=true when all results are PASS', async () => {
        const fp = writeFixture('all-pass.json', {
            schemaId: 'resolvedPublicKeys',
            valid: [
                { id: 'p1', data: { current: 'a'.repeat(64), rotationState: 'STABLE' } },
                { id: 'p2', data: { current: 'b'.repeat(64), rotationState: 'FROZEN' } },
            ],
        });

        const runner = new ConformanceRunner({
            target: 'http://localhost:3000',
            fixturePaths: [fp],
        });
        const report = await runner.run();

        expect(report.passed).toBe(true);
        expect(report.summary.fail).toBe(0);
    });

    it('should record latencyMs as non-negative number', async () => {
        const fp = writeFixture('latency-test.json', {
            schemaId: 'resolvedPublicKeys',
            valid: [
                { id: 'lat-01', data: { current: 'a'.repeat(64), rotationState: 'STABLE' } },
            ],
        });

        const runner = new ConformanceRunner({
            target: 'http://localhost:3000',
            fixturePaths: [fp],
        });
        const report = await runner.run();

        expect(report.results[0].latencyMs).toBeGreaterThanOrEqual(0);
    });

    // SKIP is treated as not-passed (exit 1) unless --allow-skip
    it('should report passed=false when skip > 0 and allowSkip=false (default)', async () => {
        // The NestedGroup shape always SKIPs (no FAIL); allowSkip defaults to false → passed=false
        const fp = writeFixture('skip-nested.json', {
            description: 'nested group',
            group_a: {
                valid: [{ id: 'ng-01', data: {} }],
            },
        });

        const runner = new ConformanceRunner({
            target: 'http://localhost:3000',
            fixturePaths: [fp],
        });
        const report = await runner.run();

        expect(report.summary.skip).toBe(1);
        expect(report.summary.fail).toBe(0);
        expect(report.passed).toBe(false); // SKIP does not count as passing (exit 1 contract)
    });

    it('should report passed=true when skip > 0 but allowSkip=true', async () => {
        // Same NestedGroup, but explicitly set allowSkip=true
        const fp = writeFixture('skip-allowed.json', {
            description: 'nested group',
            group_b: {
                invalid: [{ id: 'ng-02', data: {} }],
            },
        });

        const runner = new ConformanceRunner({
            target: 'http://localhost:3000',
            fixturePaths: [fp],
            allowSkip: true,
        });
        const report = await runner.run();

        expect(report.summary.skip).toBe(1);
        expect(report.summary.fail).toBe(0);
        expect(report.passed).toBe(true); // allowSkip=true → skip does not affect passing
    });
});

// ---------------------------------------------------------------------------
// NestedGroup: invalid-only branch (covers runner.ts line 115)
// ---------------------------------------------------------------------------

describe('NestedGroup invalid-only branch', () => {
    it('should detect nested-group when group has only invalid array', async () => {
        // Nested group containing only an invalid array (no valid key)
        const fp = writeFixture('nested-invalid-only.json', {
            description: 'nested group invalid only',
            group_b: {
                // Only invalid, no valid
                invalid: [{ id: 'ng-inv-01', data: {} }],
            },
        });

        const runner = new ConformanceRunner({
            target: 'http://localhost:3000',
            fixturePaths: [fp],
        });
        const report = await runner.run();

        // Should be detected as a NestedGroup shape and SKIPped
        expect(report.results[0].status).toBe('SKIP');
        expect(report.results[0].error).toContain('DEFER');
    });
});

// ---------------------------------------------------------------------------
// getBuiltinFixturePaths (built-in path fallback, covers runner.ts lines 415-434)
// ---------------------------------------------------------------------------

describe('getBuiltinFixturePaths built-in paths', () => {
    // Path lookup priority:
    // 1. Package-internal PKG_FIXTURE_DIR (fixtures/v0.3.0/) exists →
    // [PKG_BASELINE_DIR (if present), PKG_FIXTURE_DIR] (v0.1/v0.2 baseline + v0.3.0)
    // 2. monorepo BUILTIN_V030_DIR (tests/fixtures/conformance/v0.3.0/) exists →
    // [BUILTIN_FIXTURE_ROOT, BUILTIN_V030_DIR] (top-level .json baseline at the root + v0.3.0)
    // 3. Neither exists → throw

    it('should use pkg-internal fixtures when pkg dir exists (first priority, includes baseline)', async () => {
        // mock: 1st existsSync (PKG_FIXTURE_DIR) → true; 2nd (PKG_BASELINE_DIR) → true
        // Returns [PKG_BASELINE_DIR, PKG_FIXTURE_DIR]; both directories are mocked with the same testDir contents
        const testJsonPath = writeFixture('pkg-builtin.json', {
            schemaId: 'resolvedPublicKeys',
            valid: [
                { id: 'pkg-01', data: { current: 'a'.repeat(64), rotationState: 'STABLE' } },
            ],
        });
        const testDir = path.dirname(testJsonPath);

        const existsSyncSpy = vi.spyOn(fs, 'existsSync').mockReturnValue(true);
        const readdirSyncSpy = vi.spyOn(fs, 'readdirSync').mockReturnValue(
            fs.readdirSync(testDir, { withFileTypes: true }) as ReturnType<typeof fs.readdirSync>,
        );
        const readFileSyncSpy = vi.spyOn(fs, 'readFileSync').mockImplementation((p, enc) => {
            if (typeof p === 'string' && p.endsWith('pkg-builtin.json')) {
                return fs.readFileSync(testJsonPath, enc as BufferEncoding);
            }
            return fs.readFileSync(p, enc as BufferEncoding);
        });

        const runner = new ConformanceRunner({ target: 'http://localhost:3000' });
        const report = await runner.run();

        expect(report.summary.total).toBeGreaterThan(0);

        existsSyncSpy.mockRestore();
        readdirSyncSpy.mockRestore();
        readFileSyncSpy.mockRestore();
    });

    it('should use monorepo BUILTIN_V030_DIR when pkg dir absent (second priority)', async () => {
        // mock: 1st (PKG_FIXTURE_DIR) → false; 2nd (BUILTIN_V030_DIR) → true
        const devFixture = writeFixture('dev-builtin.json', {
            schemaId: 'resolvedPublicKeys',
            valid: [
                { id: 'dev-01', data: { current: 'c'.repeat(64), rotationState: 'STABLE' } },
            ],
        });
        const devDir = path.dirname(devFixture);

        let callCount = 0;
        const existsSyncSpy = vi.spyOn(fs, 'existsSync').mockImplementation(() => {
            callCount++;
            return callCount > 1; // 1st false, 2nd and later true
        });
        const readdirSyncSpy = vi.spyOn(fs, 'readdirSync').mockReturnValue(
            fs.readdirSync(devDir, { withFileTypes: true }) as ReturnType<typeof fs.readdirSync>,
        );
        const readFileSyncSpy = vi.spyOn(fs, 'readFileSync').mockImplementation((p, enc) => {
            if (typeof p === 'string' && p.endsWith('dev-builtin.json')) {
                return fs.readFileSync(devFixture, enc as BufferEncoding);
            }
            return fs.readFileSync(p, enc as BufferEncoding);
        });

        const runner = new ConformanceRunner({ target: 'http://localhost:3000' });
        const report = await runner.run();
        expect(report.summary.total).toBeGreaterThan(0);

        existsSyncSpy.mockRestore();
        readdirSyncSpy.mockRestore();
        readFileSyncSpy.mockRestore();
    });

    it('should warn and still return v0.3.0 when PKG_BASELINE_DIR absent', async () => {
        // mock: PKG_FIXTURE_DIR → true; PKG_BASELINE_DIR → false → warn + still return v0.3.0
        const testJsonPath = writeFixture('pkg-v030-only.json', {
            schemaId: 'resolvedPublicKeys',
            valid: [
                { id: 'v030-only-01', data: { current: 'a'.repeat(64), rotationState: 'STABLE' } },
            ],
        });
        const testDir = path.dirname(testJsonPath);

        // 1st (PKG_FIXTURE_DIR) → true; 2nd (PKG_BASELINE_DIR) → false
        let existsCallCount = 0;
        const existsSyncSpy = vi.spyOn(fs, 'existsSync').mockImplementation(() => {
            existsCallCount++;
            return existsCallCount === 1; // Only the 1st call is true (PKG_FIXTURE_DIR)
        });
        const readdirSyncSpy = vi.spyOn(fs, 'readdirSync').mockReturnValue(
            fs.readdirSync(testDir, { withFileTypes: true }) as ReturnType<typeof fs.readdirSync>,
        );
        const readFileSyncSpy = vi.spyOn(fs, 'readFileSync').mockImplementation((p, enc) => {
            if (typeof p === 'string' && p.endsWith('pkg-v030-only.json')) {
                return fs.readFileSync(testJsonPath, enc as BufferEncoding);
            }
            return fs.readFileSync(p, enc as BufferEncoding);
        });

        const stderrSpy = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);

        const runner = new ConformanceRunner({ target: 'http://localhost:3000' });
        const report = await runner.run();

        // Still has results (the v0.3.0 fixture is loaded)
        expect(report.summary.total).toBeGreaterThan(0);
        // Should emit a WARN
        expect(stderrSpy).toHaveBeenCalledWith(expect.stringContaining('WARN: baseline fixture directory not found'));

        existsSyncSpy.mockRestore();
        readdirSyncSpy.mockRestore();
        readFileSyncSpy.mockRestore();
        stderrSpy.mockRestore();
    });

    it('should throw when neither pkg dir nor monorepo dir exists', async () => {
        // Both paths return false → throw
        const existsSyncSpy = vi.spyOn(fs, 'existsSync').mockReturnValue(false);

        const runner = new ConformanceRunner({ target: 'http://localhost:3000' });
        await expect(runner.run()).rejects.toThrow('builtin fixture directory not found');

        existsSyncSpy.mockRestore();
    });
});

// ---------------------------------------------------------------------------
// expectedError verification
// ---------------------------------------------------------------------------

describe('expectedError error-reason verification', () => {
    // L1 exact substring: expectedError is a substring of the AJV error.message → PASS
    it('should PASS when expectedError is exact substring of AJV error message (L1 match)', async () => {
        // actionRecord missing delegationDepth → AJV: "must have required property 'delegationDepth'"
        // expectedError is an exact substring of the AJV message → L1 match → PASS
        const fp = writeFixture('expected-error-l1-match.json', {
            schemaId: 'actionRecord',
            invalid: [
                {
                    id: 'l1-match-01',
                    expectedError: "must have required property 'delegationDepth'",
                    data: {
                        id: 'rec-test-01',
                        specVersion: '0.3.0',
                        agentDid: 'did:agent:a3f1b2c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0',
                        principalDid: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
                        action: 'INQUIRY',
                        parametersSummary: {},
                        authorizationRef: { tokenId: 'urn:cap:test' },
                        resultSummary: { status: 'SUCCESS' },
                        timestamp: '2026-05-01T00:00:00.000Z',
                        prevHash: null,
                        ledgerSignature: 'a'.repeat(128),
                        actorSignature: 'b'.repeat(128),
                        // delegationDepth intentionally missing → AJV rejects
                    },
                },
            ],
        });

        const runner = new ConformanceRunner({
            target: 'http://localhost:3000',
            fixturePaths: [fp],
        });
        const report = await runner.run();

        // Schema rejects (expected=false) and the error reason matches → PASS
        expect(report.results[0].status).toBe('PASS');
        expect(report.results[0].expected).toBe(false);
    });

    // L3 instancePath field match: expectedError is a semantic description whose field name appears in instancePath → PASS
    it('should PASS when expectedError field name appears in AJV instancePath (L3 match)', async () => {
        // specVersion const mismatch → AJV: instancePath=/specVersion, message="must be equal to constant"
        // expectedError: "specVersion must be 0.2.0 when header.capabilityTokenRef is present"
        // "specVersion" appears in instancePath → L3 match → PASS
        const fp = writeFixture('expected-error-l3-match.json', {
            schemaId: 'negotiationEnvelope',
            cases: [
                {
                    id: 'l3-match-01',
                    valid: false,
                    expectedError: 'specVersion must be 0.2.0 when header.capabilityTokenRef is present',
                    data: {
                        id: '550e8400-e29b-41d4-a716-05cf00000002',
                        specVersion: '0.3.0',
                        header: {
                            senderDid: 'did:agent:a3f1b2c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0',
                            recipientDid: 'did:agent:b4e2c3d5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1',
                            sessionId: '550e8400-e29b-41d4-a716-446655440099',
                            sequenceNumber: 1,
                            capabilityTokenRef: 'urn:cap:550e8400-e29b-41d4-a716-446655440001',
                        },
                        messageType: 'NEGOTIATION_REQUEST',
                        body: { action: 'QUOTE', params: { sku: 'SKU-001', quantity: 5 }, requestId: 'req-cross-002' },
                        signature: '22aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff001122334455667788',
                        timestamp: '2026-04-27T02:02:00.000Z',
                    },
                },
            ],
        });

        const runner = new ConformanceRunner({
            target: 'http://localhost:3000',
            fixturePaths: [fp],
        });
        const report = await runner.run();

        expect(report.results[0].status).toBe('PASS');
    });

    // expectedError matches no level → FAIL with mismatch reason
    it('should FAIL when expectedError does not match AJV error chain', async () => {
        // actionRecord missing delegationDepth → AJV error chain has 'delegationDepth'
        // but expectedError is set to a completely unrelated string
        const fp = writeFixture('expected-error-mismatch.json', {
            schemaId: 'actionRecord',
            invalid: [
                {
                    id: 'err-mismatch-01',
                    expectedError: 'completely unrelated error reason xyz789',
                    data: {
                        id: 'rec-test-02',
                        specVersion: '0.3.0',
                        agentDid: 'did:agent:a3f1b2c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0',
                        principalDid: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
                        action: 'INQUIRY',
                        parametersSummary: {},
                        authorizationRef: { tokenId: 'urn:cap:test' },
                        resultSummary: { status: 'SUCCESS' },
                        timestamp: '2026-05-01T00:00:00.000Z',
                        prevHash: null,
                        ledgerSignature: 'a'.repeat(128),
                        actorSignature: 'b'.repeat(128),
                        // delegationDepth intentionally missing → AJV rejects
                    },
                },
            ],
        });

        const runner = new ConformanceRunner({
            target: 'http://localhost:3000',
            fixturePaths: [fp],
        });
        const report = await runner.run();

        // Schema rejects (correct direction) but expectedError does not match → FAIL
        expect(report.results[0].status).toBe('FAIL');
        expect(report.results[0].error).toContain('not matched');
    });

    // No expectedError → decided solely by the valid/invalid direction, behavior unchanged
    it('should PASS when expectedError absent and schema correctly rejects (no change to old behavior)', async () => {
        const fp = writeFixture('no-expected-error.json', {
            schemaId: 'resolvedPublicKeys',
            invalid: [
                {
                    id: 'no-exp-err-01',
                    data: { rotationState: 'STABLE' /* missing current*/ },
                },
            ],
        });

        const runner = new ConformanceRunner({
            target: 'http://localhost:3000',
            fixturePaths: [fp],
        });
        const report = await runner.run();

        expect(report.results[0].status).toBe('PASS');
    });

    // multi-version validator path: expectedError matches → PASS (xv-03 pattern)
    it('should PASS when archived multi-version validator expectedError matches (xv-03 L1 match)', async () => {
        // negotiationEnvelope + v0.1.0 validator: specVersion=0.3.0 → REJECT
        // expectedError exactly matches the inline validator message → L1 match → PASS
        const fp = writeFixture('mv-expected-error-match.json', {
            schemaId: 'negotiationEnvelope',
            cases: [
                {
                    id: 'mv-err-match-01',
                    expectedResult: 'REJECT',
                    expectedError: 'specVersion must be equal to one of the allowed values',
                    validatorVersion: '0.1.0',
                    inputSpecVersion: '0.3.0',
                    data: { specVersion: '0.3.0', sessionId: 'test', proposedCapabilities: [] },
                },
            ],
        });

        const runner = new ConformanceRunner({
            target: 'http://localhost:3000',
            fixturePaths: [fp],
        });
        const report = await runner.run();

        expect(report.results[0].status).toBe('PASS');
    });

    // multi-version validator path: expectedError does not match → FAIL
    it('should FAIL when archived multi-version validator REJECT but expectedError not matched', async () => {
        // negotiationEnvelope + v0.1.0 validator: REJECT, but expectedError is completely unrelated
        const fp = writeFixture('mv-expected-error-mismatch.json', {
            schemaId: 'negotiationEnvelope',
            cases: [
                {
                    id: 'mv-err-mismatch-01',
                    expectedResult: 'REJECT',
                    expectedError: 'completely wrong reason that will never match',
                    validatorVersion: '0.1.0',
                    inputSpecVersion: '0.3.0',
                    data: { specVersion: '0.3.0', sessionId: 'test', proposedCapabilities: [] },
                },
            ],
        });

        const runner = new ConformanceRunner({
            target: 'http://localhost:3000',
            fixturePaths: [fp],
        });
        const report = await runner.run();

        expect(report.results[0].status).toBe('FAIL');
        expect(report.results[0].error).toContain('not matched');
    });
});

// ---------------------------------------------------------------------------
// V030_SCHEMA_REGISTRY (filename registry inference)
// ---------------------------------------------------------------------------

describe('V030_SCHEMA_REGISTRY filename registry', () => {
    it('should infer schemaId=resolvedPublicKeys from dual-key-rotation.v0.3.json', async () => {
        // Name the fixture file with a name known to the registry and write it into tmpDir
        const fixtureName = 'dual-key-rotation.v0.3.json';
        writeFixture(fixtureName, {
            // No top-level schemaId, relies on the registry
            valid: [
                { id: 'reg-01', data: { current: 'a'.repeat(64), rotationState: 'STABLE' } },
            ],
        });

        const runner = new ConformanceRunner({
            target: 'http://localhost:3000',
            fixturePaths: [path.join(tmpDir, fixtureName)],
        });
        const report = await runner.run();

        // If registry inference succeeds, the case should be schema-validated (not SKIPped)
        expect(report.results[0].status).not.toBe('SKIP');
    });

    it('should SKIP when filename not in registry and no schemaId declared', async () => {
        writeFixture('unknown-fixture.json', {
            valid: [{ id: 'no-schema-01', data: {} }],
        });

        const runner = new ConformanceRunner({
            target: 'http://localhost:3000',
            fixturePaths: [path.join(tmpDir, 'unknown-fixture.json')],
        });
        const report = await runner.run();

        expect(report.results[0].status).toBe('SKIP');
    });
});
