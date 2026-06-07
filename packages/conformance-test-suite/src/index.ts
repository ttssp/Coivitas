/**
 * @coivitas/conformance-test-suite CLI entry point.
 *
 * Summary first:
 * - Subcommand `run`: run conformance tests against a target endpoint
 * - Exit codes: 0=all passed / 1=at least one FAIL / 2=configuration error
 * - Also serves as the public API export entry point of the library
 *
 * --mode design decision:
 * - The v0.1 fixture format has no request field, so the HTTP POST body cannot be normalized
 * - schema mode (default): local schema validation; --target is written to report metadata (advisory)
 * - endpoint mode: to be implemented once the v0.2 fixture schema is finalized; v0.1 throws explicitly to prevent misuse
 * - Chose an explicit throw on --mode rather than silently ignoring it, because silence would mislead the caller into thinking a real request was sent
 */

import { Command } from 'commander';
import { ConformanceRunner } from './runner.js';
import { generateReport } from './report.js';
import type { ReportFormat } from './types.js';

/** Conformance run mode. */
export type ConformanceMode = 'schema' | 'endpoint';

// Public library API exports
export { ConformanceRunner } from './runner.js';
export { generateReport } from './report.js';
export type {
    ConformanceResult,
    ConformanceReport,
    ReportFormat,
    RunnerOptions,
    FixtureCase,
} from './types.js';

/**
 * Build and return a commander Program instance.
 * Exported separately for ease of testing (no process.argv side effects).
 */
export function buildProgram(): Command {
    const program = new Command();

    program
        .name('coivitas-conformance')
        .description('Coivitas conformance test suite CLI')
        .version('0.1.0');

    program
        .command('run')
        .description('Run conformance tests against a target endpoint')
        .requiredOption('--target <url>', 'Target endpoint URL', 'http://localhost:3000')
        .option('--fixture <path>', 'Path to fixture file or directory (default: built-in v0.3.0 suite)')
        .option('--report <format>', 'Output format: json or markdown', 'json')
        .option(
            '--allow-skip',
            'Treat SKIP results as not-failed (default: SKIP causes exit 1)',
            false,
        )
        .option(
            '--mode <mode>',
            'Conformance mode: schema (local validation) or endpoint (HTTP POST to --target). ' +
            'v0.1 only supports schema mode; endpoint mode is not yet implemented.',
            'schema',
        )
        .action(async (options: {
            target: string;
            fixture?: string;
            report: string;
            allowSkip: boolean;
            mode: string;
        }) => {
            // Validate --mode (endpoint mode is not implemented in v0.1, reject explicitly)
            const mode = options.mode as ConformanceMode;
            if (mode !== 'schema' && mode !== 'endpoint') {
                process.stderr.write(
                    `Error: --mode must be "schema" or "endpoint", got "${options.mode}"\n`,
                );
                process.exit(2);
            }
            if (mode === 'endpoint') {
                process.stderr.write(
                    `Error: --mode endpoint is not yet implemented in v0.1.\n` +
                    `  Fixture POST schema (request body format) is TBD for v0.2.\n` +
                    `  Use --mode schema (default) for local schema validation.\n` +
                    `  See README §Usage for details.\n`,
                );
                process.exit(2);
            }

            // Validate the report format
            const format = options.report as ReportFormat;
            if (format !== 'json' && format !== 'markdown') {
                process.stderr.write(
                    `Error: --report must be "json" or "markdown", got "${options.report}"\n`,
                );
                process.exit(2);
            }

            const fixturePaths = options.fixture ? [options.fixture] : undefined;

            // The ConformanceRunner constructor does not throw; run() already catches fixture-loading errors internally.
            // Only report with exit 2 when run() throws (e.g. the built-in fixture directory does not exist).
            const runner = new ConformanceRunner({
                target: options.target,
                fixturePaths,
                allowSkip: options.allowSkip,
            });

            let report;
            try {
                report = await runner.run();
            } catch (err: unknown) {
                process.stderr.write(`Error running conformance suite: ${String(err)}\n`);
                process.exit(2);
            }

            const output = generateReport(report, format);
            process.stdout.write(output + '\n');

            // Exit codes: 0=all passed, 1=at least one FAIL
            process.exit(report.passed ? 0 : 1);
        });

    return program;
}

/**
 * Run the CLI only when executed directly (not triggered when imported as a library).
 * The ESM shim (bin/coivitas-conformance.mjs) is responsible for calling this function.
 */
export async function runCli(argv?: string[]): Promise<void> {
    const program = buildProgram();
    await program.parseAsync(argv ?? process.argv);
}
