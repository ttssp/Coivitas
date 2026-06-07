/**
 * Report generation module.
 *
 * Summary first:
 * - generateReport(report, format) returns a JSON string or a Markdown string
 * - JSON format: pretty-printed JSON.stringify of the ConformanceReport
 * - Markdown format: title, summary, results table
 */

import type { ConformanceReport, ReportFormat } from './types.js';

/**
 * Serialize a ConformanceReport into a string of the given format.
 * @param report - the complete conformance report object
 * @param format - 'json' or 'markdown'
 * @returns the formatted string (without a trailing newline)
 */
export function generateReport(report: ConformanceReport, format: ReportFormat): string {
    if (format === 'json') {
        return JSON.stringify(report, null, 2);
    }
    return renderMarkdown(report);
}

/**
 * Render the Markdown report.
 * Structure: title → metadata → summary → results table
 */
function renderMarkdown(report: ConformanceReport): string {
    const { target, runAt, passed, summary, results } = report;

    // Summary line
    const overallLabel = passed
        ? `PASS (${summary.pass} passed)`
        : `FAIL (${summary.pass} passed, ${summary.fail} failed${summary.skip > 0 ? `, ${summary.skip} skipped` : ''})`;

    const lines: string[] = [
        '# Coivitas Conformance Report',
        '',
        `**Target**: ${target}`,
        `**Date**: ${runAt}`,
        `**Result**: ${overallLabel}`,
        '',
        '## Results',
        '',
        '| Fixture ID | Status | Latency | Error |',
        '| ---------- | ------ | ------- | ----- |',
    ];

    for (const r of results) {
        const latency = r.status === 'SKIP' ? '-' : `${r.latencyMs}ms`;
        const error = r.error ? r.error.replace(/\|/g, '\\|') : '';
        lines.push(`| ${r.fixtureId} | ${r.status} | ${latency} | ${error} |`);
    }

    return lines.join('\n');
}
