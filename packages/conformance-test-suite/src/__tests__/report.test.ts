/**
 * Unit tests for generateReport.
 *
 * Summary first:
 * - JSON format: valid JSON containing all top-level fields
 * - Markdown format: title line + table header + one row per result
 * - Latency display rules for each PASS/FAIL/SKIP status
 * - Pipe characters are escaped inside the Markdown table
 */

import { describe, expect, it } from 'vitest';
import { generateReport } from '../report.js';
import type { ConformanceReport, ConformanceResult } from '../types.js';

function makeReport(overrides: Partial<ConformanceReport> = {}): ConformanceReport {
    const results: ConformanceResult[] = overrides.results ?? [
        {
            fixtureId: 'test-01',
            status: 'PASS',
            latencyMs: 42,
            fixtureFile: 'test.json',
            expected: true,
            actual: true,
        },
    ];
    const pass = results.filter((r) => r.status === 'PASS').length;
    const fail = results.filter((r) => r.status === 'FAIL').length;
    const skip = results.filter((r) => r.status === 'SKIP').length;
    return {
        target: 'http://localhost:3000',
        runAt: '2026-05-06T10:00:00.000Z',
        passed: fail === 0 && results.length > 0,
        summary: { total: results.length, pass, fail, skip },
        results,
        ...overrides,
    };
}

// ---------------------------------------------------------------------------
// JSON format
// ---------------------------------------------------------------------------

describe('generateReport JSON format', () => {
    it('should return valid JSON string', () => {
        const report = makeReport();
        const output = generateReport(report, 'json');
        expect(() => { JSON.parse(output); }).not.toThrow();
    });

    it('should include all top-level fields in JSON output', () => {
        const report = makeReport();
        const parsed = JSON.parse(generateReport(report, 'json')) as ConformanceReport;
        expect(parsed.target).toBe('http://localhost:3000');
        expect(parsed.runAt).toBe('2026-05-06T10:00:00.000Z');
        expect(typeof parsed.passed).toBe('boolean');
        expect(parsed.summary).toBeDefined();
        expect(Array.isArray(parsed.results)).toBe(true);
    });

    it('should pretty-print with 2-space indent', () => {
        const report = makeReport();
        const output = generateReport(report, 'json');
        // Pretty-printed output contains at least one newline
        expect(output).toContain('\n');
        expect(output).toContain('  ');
    });

    it('should include all ConformanceResult fields', () => {
        const report = makeReport({
            results: [
                {
                    fixtureId: 'xv-01',
                    status: 'FAIL',
                    latencyMs: 99,
                    fixtureFile: 'x.json',
                    expected: true,
                    actual: false,
                    error: 'schema rejected',
                },
            ],
        });
        const parsed = JSON.parse(generateReport(report, 'json')) as ConformanceReport;
        const r = parsed.results[0];
        expect(r.fixtureId).toBe('xv-01');
        expect(r.status).toBe('FAIL');
        expect(r.latencyMs).toBe(99);
        expect(r.error).toBe('schema rejected');
    });
});

// ---------------------------------------------------------------------------
// Markdown format
// ---------------------------------------------------------------------------

describe('generateReport Markdown format', () => {
    it('should start with top-level heading title', () => {
        const output = generateReport(makeReport(), 'markdown');
        expect(output.startsWith('# Coivitas Conformance Report')).toBe(true);
    });

    it('should include Target, Date, Result lines', () => {
        const output = generateReport(makeReport(), 'markdown');
        expect(output).toContain('**Target**: http://localhost:3000');
        expect(output).toContain('**Date**: 2026-05-06T10:00:00.000Z');
        expect(output).toContain('**Result**:');
    });

    it('should show PASS result label when all passed', () => {
        const output = generateReport(makeReport({ passed: true }), 'markdown');
        expect(output).toContain('PASS');
    });

    it('should show FAIL result label with counts when there are failures', () => {
        const report = makeReport({
            results: [
                {
                    fixtureId: 'f1',
                    status: 'PASS',
                    latencyMs: 10,
                    fixtureFile: 't.json',
                    expected: true,
                },
                {
                    fixtureId: 'f2',
                    status: 'FAIL',
                    latencyMs: 20,
                    fixtureFile: 't.json',
                    expected: true,
                    error: 'oops',
                },
            ],
            passed: false,
        });
        const output = generateReport(report, 'markdown');
        expect(output).toContain('FAIL');
        expect(output).toContain('1 passed');
        expect(output).toContain('1 failed');
    });

    it('should include skip count in FAIL label when skips > 0', () => {
        const report = makeReport({
            results: [
                {
                    fixtureId: 'f1',
                    status: 'FAIL',
                    latencyMs: 10,
                    fixtureFile: 't.json',
                    expected: true,
                    error: 'err',
                },
                {
                    fixtureId: 'f2',
                    status: 'SKIP',
                    latencyMs: 0,
                    fixtureFile: 't.json',
                    expected: true,
                    error: 'skipped',
                },
            ],
            passed: false,
        });
        const output = generateReport(report, 'markdown');
        expect(output).toContain('1 skipped');
    });

    it('should include table header with correct columns', () => {
        const output = generateReport(makeReport(), 'markdown');
        expect(output).toContain('| Fixture ID | Status | Latency | Error |');
        expect(output).toContain('| ---------- | ------ | ------- | ----- |');
    });

    it('should include each result as table row', () => {
        const report = makeReport({
            results: [
                {
                    fixtureId: 'xv-01',
                    status: 'PASS',
                    latencyMs: 42,
                    fixtureFile: 'x.json',
                    expected: true,
                },
                {
                    fixtureId: 'xv-02',
                    status: 'FAIL',
                    latencyMs: 51,
                    fixtureFile: 'x.json',
                    expected: true,
                    error: 'schema validation failed',
                },
            ],
        });
        const output = generateReport(report, 'markdown');
        expect(output).toContain('| xv-01 | PASS | 42ms |');
        expect(output).toContain('| xv-02 | FAIL | 51ms | schema validation failed |');
    });

    it('should show - for latency when status is SKIP', () => {
        const report = makeReport({
            results: [
                {
                    fixtureId: 'sk-01',
                    status: 'SKIP',
                    latencyMs: 0,
                    fixtureFile: 's.json',
                    expected: true,
                    error: 'deferred',
                },
            ],
            passed: false,
        });
        const output = generateReport(report, 'markdown');
        expect(output).toContain('| sk-01 | SKIP | - | deferred |');
    });

    it('should escape pipe characters in error messages', () => {
        const report = makeReport({
            results: [
                {
                    fixtureId: 'esc-01',
                    status: 'FAIL',
                    latencyMs: 10,
                    fixtureFile: 'e.json',
                    expected: true,
                    error: 'error with | pipe char',
                },
            ],
            passed: false,
        });
        const output = generateReport(report, 'markdown');
        // Pipe characters should be escaped to \|
        expect(output).toContain('error with \\| pipe char');
    });

    it('should render empty error cell when error is undefined', () => {
        const report = makeReport({
            results: [
                {
                    fixtureId: 'no-err-01',
                    status: 'PASS',
                    latencyMs: 5,
                    fixtureFile: 'n.json',
                    expected: true,
                },
            ],
        });
        const output = generateReport(report, 'markdown');
        expect(output).toContain('| no-err-01 | PASS | 5ms |  |');
    });

    it('should include ## Results section', () => {
        const output = generateReport(makeReport(), 'markdown');
        expect(output).toContain('## Results');
    });
});

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

describe('generateReport edge cases', () => {
    it('should handle empty results array', () => {
        const report = makeReport({ results: [], summary: { total: 0, pass: 0, fail: 0, skip: 0 }, passed: false });
        const jsonOutput = generateReport(report, 'json');
        const parsed = JSON.parse(jsonOutput) as ConformanceReport;
        expect(parsed.results).toHaveLength(0);

        const mdOutput = generateReport(report, 'markdown');
        expect(mdOutput).toContain('# Coivitas Conformance Report');
    });

    it('should handle report with only SKIP results', () => {
        const report = makeReport({
            results: [
                {
                    fixtureId: 'skip-only-01',
                    status: 'SKIP',
                    latencyMs: 0,
                    fixtureFile: 's.json',
                    expected: true,
                    error: 'deferred',
                },
            ],
            passed: false,
        });
        const output = generateReport(report, 'markdown');
        expect(output).toContain('SKIP');
    });
});
