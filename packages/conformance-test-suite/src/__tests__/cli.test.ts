/**
 * Unit tests for the CLI entry point (index.ts).
 *
 * Summary first:
 * - Import the commander program via buildProgram() to avoid process.argv side effects
 * - Test --report format validation of the run subcommand (exit 2)
 * - Test the exit 2 path when the --fixture path does not exist
 * - Test that normal runs produce the correct output format (JSON / Markdown)
 * - Test process.exit(1) on FAIL
 * - Do not test runCli (which calls parseAsync directly on process.argv) to avoid side effects
 */

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { buildProgram, runCli } from '../index.js';
import * as runnerModule from '../runner.js';

let tmpDir: string;

beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'conformance-cli-test-'));
});

afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
    vi.restoreAllMocks();
});

/** Write a temporary fixture JSON file and return its path. */
function writeFixture(name: string, content: object): string {
    const fp = path.join(tmpDir, name);
    fs.writeFileSync(fp, JSON.stringify(content), 'utf8');
    return fp;
}

// ---------------------------------------------------------------------------
// buildProgram basics
// ---------------------------------------------------------------------------

describe('buildProgram', () => {
    it('should return a commander Program instance', () => {
        const program = buildProgram();
        expect(program).toBeDefined();
        expect(typeof program.parseAsync).toBe('function');
    });

    it('should have run subcommand registered', () => {
        const program = buildProgram();
        const commands = program.commands.map((c) => c.name());
        expect(commands).toContain('run');
    });
});

// ---------------------------------------------------------------------------
// --report format validation (exit 2)
// ---------------------------------------------------------------------------

describe('--report format validation', () => {
    it('should exit 2 on invalid --report format', async () => {
        const exitSpy = vi.spyOn(process, 'exit').mockImplementation((_code?: number | string) => {
            throw new Error(`process.exit(${_code})`);
        });
        const stderrSpy = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);

        const program = buildProgram();
        await expect(
            program.parseAsync(['node', 'coivitas-conformance', 'run', '--target', 'http://localhost', '--report', 'xml']),
        ).rejects.toThrow('process.exit(2)');

        expect(exitSpy).toHaveBeenCalledWith(2);
        expect(stderrSpy).toHaveBeenCalledWith(
            expect.stringContaining('--report must be'),
        );
    });
});

// ---------------------------------------------------------------------------
// Normal run (JSON output)
// ---------------------------------------------------------------------------

describe('run subcommand JSON output', () => {
    it('should write JSON report to stdout and exit 0 when all pass', async () => {
        const fp = writeFixture('cli-pass.json', {
            schemaId: 'resolvedPublicKeys',
            valid: [
                { id: 'cli-01', data: { current: 'a'.repeat(64), rotationState: 'STABLE' } },
            ],
        });

        const stdoutChunks: string[] = [];
        vi.spyOn(process.stdout, 'write').mockImplementation((chunk: unknown) => {
            stdoutChunks.push(String(chunk));
            return true;
        });
        const exitSpy = vi.spyOn(process, 'exit').mockImplementation((_code?: number | string) => {
            throw new Error(`process.exit(${_code})`);
        });

        const program = buildProgram();
        await expect(
            program.parseAsync(['node', 'coivitas-conformance', 'run', '--target', 'http://localhost', '--fixture', fp]),
        ).rejects.toThrow('process.exit(0)');

        expect(exitSpy).toHaveBeenCalledWith(0);
        const output = stdoutChunks.join('');
        const parsed = JSON.parse(output) as { passed: boolean };
        expect(parsed.passed).toBe(true);
    });

    it('should exit 1 when there are FAILs', async () => {
        const fp = writeFixture('cli-fail.json', {
            schemaId: 'resolvedPublicKeys',
            valid: [
                {
                    id: 'cli-fail-01',
                    data: { rotationState: 'STABLE' /* missing current*/ },
                },
            ],
        });

        vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
        const exitSpy = vi.spyOn(process, 'exit').mockImplementation((_code?: number | string) => {
            throw new Error(`process.exit(${_code})`);
        });

        const program = buildProgram();
        await expect(
            program.parseAsync(['node', 'coivitas-conformance', 'run', '--target', 'http://localhost', '--fixture', fp]),
        ).rejects.toThrow('process.exit(1)');

        expect(exitSpy).toHaveBeenCalledWith(1);
    });
});

// ---------------------------------------------------------------------------
// run subcommand Markdown output
// ---------------------------------------------------------------------------

describe('run subcommand Markdown output', () => {
    it('should write Markdown report to stdout when --report markdown', async () => {
        const fp = writeFixture('cli-md.json', {
            schemaId: 'resolvedPublicKeys',
            valid: [
                { id: 'md-01', data: { current: 'b'.repeat(64), rotationState: 'STABLE' } },
            ],
        });

        const stdoutChunks: string[] = [];
        vi.spyOn(process.stdout, 'write').mockImplementation((chunk: unknown) => {
            stdoutChunks.push(String(chunk));
            return true;
        });
        vi.spyOn(process, 'exit').mockImplementation((_code?: number | string) => {
            throw new Error(`process.exit(${_code})`);
        });

        const program = buildProgram();
        await expect(
            program.parseAsync([
                'node', 'coivitas-conformance', 'run',
                '--target', 'http://localhost',
                '--fixture', fp,
                '--report', 'markdown',
            ]),
        ).rejects.toThrow('process.exit(0)');

        const output = stdoutChunks.join('');
        expect(output).toContain('# Coivitas Conformance Report');
        expect(output).toContain('| md-01 | PASS |');
    });
});

// ---------------------------------------------------------------------------
// --fixture path does not exist (exit 2 due to runner throwing)
// ---------------------------------------------------------------------------

describe('run subcommand fixture path errors', () => {
    it('should exit 1 (not 2) when fixture path does not exist (runner returns FAIL)', async () => {
        // ConformanceRunner.run() does not throw; instead it records a FAIL in results,
        // so the exit code is 1 (not passed) rather than 2
        const nonExistent = path.join(tmpDir, 'missing.json');

        vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
        const exitSpy = vi.spyOn(process, 'exit').mockImplementation((_code?: number | string) => {
            throw new Error(`process.exit(${_code})`);
        });

        const program = buildProgram();
        await expect(
            program.parseAsync([
                'node', 'coivitas-conformance', 'run',
                '--target', 'http://localhost',
                '--fixture', nonExistent,
            ]),
        ).rejects.toThrow('process.exit(1)');

        expect(exitSpy).toHaveBeenCalledWith(1);
    });

    it('should exit 2 when runner.run() throws unexpectedly (Error instance)', async () => {
        vi.spyOn(runnerModule.ConformanceRunner.prototype, 'run').mockRejectedValueOnce(
            new Error('unexpected internal error'),
        );

        vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
        const stderrSpy = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
        const exitSpy = vi.spyOn(process, 'exit').mockImplementation((_code?: number | string) => {
            throw new Error(`process.exit(${_code})`);
        });

        const fp = writeFixture('throw-test.json', {
            schemaId: 'resolvedPublicKeys',
            valid: [{ id: 'th-01', data: { current: 'a'.repeat(64), rotationState: 'STABLE' } }],
        });

        const program = buildProgram();
        await expect(
            program.parseAsync([
                'node', 'coivitas-conformance', 'run',
                '--target', 'http://localhost',
                '--fixture', fp,
            ]),
        ).rejects.toThrow('process.exit(2)');

        expect(exitSpy).toHaveBeenCalledWith(2);
        expect(stderrSpy).toHaveBeenCalledWith(
            expect.stringContaining('Error running conformance suite'),
        );
    });

    it('should exit 2 when runner.run() throws a non-Error value', async () => {
        // Cover the String(err) path (a non-Error object is thrown)
        vi.spyOn(runnerModule.ConformanceRunner.prototype, 'run').mockRejectedValueOnce(
            'string error thrown',
        );

        vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
        const stderrSpy = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
        vi.spyOn(process, 'exit').mockImplementation((_code?: number | string) => {
            throw new Error(`process.exit(${_code})`);
        });

        const fp = writeFixture('throw-string-test.json', {
            schemaId: 'resolvedPublicKeys',
            valid: [{ id: 'ts-01', data: { current: 'a'.repeat(64), rotationState: 'STABLE' } }],
        });

        const program = buildProgram();
        await expect(
            program.parseAsync([
                'node', 'coivitas-conformance', 'run',
                '--target', 'http://localhost',
                '--fixture', fp,
            ]),
        ).rejects.toThrow('process.exit(2)');

        expect(stderrSpy).toHaveBeenCalledWith(
            expect.stringContaining('string error thrown'),
        );
    });
});

// ---------------------------------------------------------------------------
// runCli function
// ---------------------------------------------------------------------------

describe('runCli function', () => {
    it('should delegate to buildProgram().parseAsync with provided argv', async () => {
        const fp = writeFixture('runcli-test.json', {
            schemaId: 'resolvedPublicKeys',
            valid: [
                { id: 'rc-01', data: { current: 'c'.repeat(64), rotationState: 'STABLE' } },
            ],
        });

        vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
        vi.spyOn(process, 'exit').mockImplementation((_code?: number | string) => {
            throw new Error(`process.exit(${_code})`);
        });

        await expect(
            runCli(['node', 'coivitas-conformance', 'run', '--target', 'http://localhost', '--fixture', fp]),
        ).rejects.toThrow('process.exit(0)');
    });

    it('should fall back to process.argv when no argv provided', async () => {
        // Set process.argv to the help command (does not trigger the run action, no exit mock needed)
        const originalArgv = process.argv;
        process.argv = ['node', 'coivitas-conformance', '--help'];

        // commander calls process.exit(0) on --help
        const exitSpy = vi.spyOn(process, 'exit').mockImplementation((_code?: number | string) => {
            throw new Error(`process.exit(${_code})`);
        });
        // Mock stdout to consume the help output
        vi.spyOn(process.stdout, 'write').mockImplementation(() => true);

        try {
            await runCli(undefined);
        } catch {
            // Expect the mocked exit(0) to be thrown
        } finally {
            process.argv = originalArgv;
            exitSpy.mockRestore();
        }
    });
});

// ---------------------------------------------------------------------------
// --mode flag (R1- acceptance)
// ---------------------------------------------------------------------------

describe('--mode flag', () => {
    it('should exit 2 on invalid --mode value', async () => {
        const exitSpy = vi.spyOn(process, 'exit').mockImplementation((_code?: number | string) => {
            throw new Error(`process.exit(${_code})`);
        });
        const stderrSpy = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
        vi.spyOn(process.stdout, 'write').mockImplementation(() => true);

        const fp = writeFixture('mode-invalid.json', {
            schemaId: 'resolvedPublicKeys',
            valid: [{ id: 'm-01', data: { current: 'a'.repeat(64), rotationState: 'STABLE' } }],
        });

        const program = buildProgram();
        await expect(
            program.parseAsync([
                'node', 'coivitas-conformance', 'run',
                '--target', 'http://localhost',
                '--fixture', fp,
                '--mode', 'rest',
            ]),
        ).rejects.toThrow('process.exit(2)');

        expect(exitSpy).toHaveBeenCalledWith(2);
        expect(stderrSpy).toHaveBeenCalledWith(expect.stringContaining('--mode must be'));
    });

    it('should exit 2 when --mode endpoint is specified (not yet implemented in v0.1)', async () => {
        const exitSpy = vi.spyOn(process, 'exit').mockImplementation((_code?: number | string) => {
            throw new Error(`process.exit(${_code})`);
        });
        const stderrSpy = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
        vi.spyOn(process.stdout, 'write').mockImplementation(() => true);

        const fp = writeFixture('mode-endpoint.json', {
            schemaId: 'resolvedPublicKeys',
            valid: [{ id: 'ep-01', data: { current: 'b'.repeat(64), rotationState: 'STABLE' } }],
        });

        const program = buildProgram();
        await expect(
            program.parseAsync([
                'node', 'coivitas-conformance', 'run',
                '--target', 'http://localhost',
                '--fixture', fp,
                '--mode', 'endpoint',
            ]),
        ).rejects.toThrow('process.exit(2)');

        expect(exitSpy).toHaveBeenCalledWith(2);
        expect(stderrSpy).toHaveBeenCalledWith(
            expect.stringContaining('not yet implemented in v0.1'),
        );
    });

    it('should succeed with --mode schema (default behavior, no change)', async () => {
        const fp = writeFixture('mode-schema.json', {
            schemaId: 'resolvedPublicKeys',
            valid: [{ id: 'sc-01', data: { current: 'c'.repeat(64), rotationState: 'STABLE' } }],
        });

        vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
        const exitSpy = vi.spyOn(process, 'exit').mockImplementation((_code?: number | string) => {
            throw new Error(`process.exit(${_code})`);
        });

        const program = buildProgram();
        await expect(
            program.parseAsync([
                'node', 'coivitas-conformance', 'run',
                '--target', 'http://localhost',
                '--fixture', fp,
                '--mode', 'schema',
            ]),
        ).rejects.toThrow('process.exit(0)');

        expect(exitSpy).toHaveBeenCalledWith(0);
    });
});

// ---------------------------------------------------------------------------
// --allow-skip flag (R1- acceptance)
// ---------------------------------------------------------------------------

describe('--allow-skip flag', () => {
    it('should exit 1 when fixture has SKIP and --allow-skip not set', async () => {
        // A NestedGroup fixture always SKIPs; without --allow-skip → exit 1
        const fp = writeFixture('cli-skip-no-flag.json', {
            description: 'nested group',
            group_x: {
                valid: [{ id: 'skip-01', data: {} }],
            },
        });

        vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
        const exitSpy = vi.spyOn(process, 'exit').mockImplementation((_code?: number | string) => {
            throw new Error(`process.exit(${_code})`);
        });

        const program = buildProgram();
        await expect(
            program.parseAsync([
                'node', 'coivitas-conformance', 'run',
                '--target', 'http://localhost',
                '--fixture', fp,
            ]),
        ).rejects.toThrow('process.exit(1)');

        expect(exitSpy).toHaveBeenCalledWith(1);
    });

    it('should exit 0 when fixture has SKIP and --allow-skip is set', async () => {
        // Same NestedGroup, but adding --allow-skip → exit 0
        const fp = writeFixture('cli-skip-with-flag.json', {
            description: 'nested group',
            group_y: {
                invalid: [{ id: 'skip-02', data: {} }],
            },
        });

        vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
        const exitSpy = vi.spyOn(process, 'exit').mockImplementation((_code?: number | string) => {
            throw new Error(`process.exit(${_code})`);
        });

        const program = buildProgram();
        await expect(
            program.parseAsync([
                'node', 'coivitas-conformance', 'run',
                '--target', 'http://localhost',
                '--fixture', fp,
                '--allow-skip',
            ]),
        ).rejects.toThrow('process.exit(0)');

        expect(exitSpy).toHaveBeenCalledWith(0);
    });
});
