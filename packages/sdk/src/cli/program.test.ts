import { afterEach, describe, expect, it, vi } from 'vitest';

import { buildCliProgram } from './program.js';

describe('buildCliProgram', () => {
    afterEach(() => {
        vi.restoreAllMocks();
        // stubEnv cleanup must be called explicitly; restoreAllMocks does not cover it.
        vi.unstubAllEnvs();
    });

    it('registers all top-level command groups', () => {
        const program = buildCliProgram();

        expect(
            program.commands.map((command) => command.name()).sort(),
        ).toEqual([
            'audit',
            'demo',
            'discover',
            'identity',
            'ledger',
            'session',
            'token',
        ]);
    });

    it('exposes required help text for the token issue command', () => {
        const program = buildCliProgram();
        const help = program.commands
            .find((command) => command.name() === 'token')
            ?.commands.find((command) => command.name() === 'issue')
            ?.helpInformation();

        expect(help).toContain('--issuer-did <did>');
        expect(help).toContain('--agent-did <did>');
        expect(help).toContain('--action <action>');
        expect(help).toContain('--scope <json>');
    });

    it('fails fast with a friendly error when demo prerequisites are missing', async () => {
        // In the integration test environment, DATABASE_URL is already exported by the outer
        // layer. To exercise the missing-prerequisite path the test must explicitly clear this
        // variable; otherwise createCliPool returns successfully, the action runs runGoldenPath,
        // parseAsync resolves → assertion fails.
        vi.stubEnv('DATABASE_URL', '');

        const program = buildCliProgram();

        await expect(
            program.parseAsync(
                ['node', 'coivitas', 'demo', 'golden-path', '--verbose'],
                { from: 'node' },
            ),
        ).rejects.toThrow('DATABASE_URL is required');
    });
});
