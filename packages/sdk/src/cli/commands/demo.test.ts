import { afterEach, describe, expect, it, vi } from 'vitest';

// Mock golden-path before importing demo command
vi.mock('../../golden-path/index.js', () => ({
    runGoldenPath: vi.fn(),
}));

// Mock runtime createCliPool
vi.mock('../runtime.js', async (importOriginal) => {
    const actual = await importOriginal<typeof import('../runtime.js')>();
    return {
        ...actual,
        createCliPool: vi.fn(),
        printOutput: vi.fn(),
    };
});

import { createDemoCommand } from './demo.js';
import { createCliPool, printOutput } from '../runtime.js';
import { runGoldenPath } from '../../golden-path/index.js';

describe('demo golden-path command', () => {
    afterEach(() => {
        vi.restoreAllMocks();
        process.exitCode = 0;
    });

    it('should throw when DATABASE_URL is missing (createCliPool throws)', async () => {
        vi.mocked(createCliPool).mockImplementation(() => {
            throw new Error(
                'DATABASE_URL is required for ledger and demo commands.',
            );
        });

        const command = createDemoCommand();
        // parseAsync with demo golden-path should propagate the error
        await expect(
            command.parseAsync(['node', 'demo', 'golden-path'], {
                from: 'node',
            }),
        ).rejects.toThrow(/DATABASE_URL/);
    });

    it('should call runGoldenPath and print result on success', async () => {
        const fakePool = { end: vi.fn().mockResolvedValue(undefined) };
        vi.mocked(createCliPool).mockReturnValue(fakePool as never);
        vi.mocked(runGoldenPath).mockResolvedValue({
            success: true,
            steps: [],
        } as never);

        const command = createDemoCommand();
        await command.parseAsync(['node', 'demo', 'golden-path'], {
            from: 'node',
        });

        expect(runGoldenPath).toHaveBeenCalledWith(
            expect.objectContaining({ pool: fakePool }),
        );
        expect(printOutput).toHaveBeenCalledWith(
            expect.objectContaining({ success: true }),
            false,
        );
        expect(fakePool.end).toHaveBeenCalled();
        expect(process.exitCode).not.toBe(1);
    });

    it('should set process.exitCode to 1 when runGoldenPath returns success=false', async () => {
        const fakePool = { end: vi.fn().mockResolvedValue(undefined) };
        vi.mocked(createCliPool).mockReturnValue(fakePool as never);
        vi.mocked(runGoldenPath).mockResolvedValue({
            success: false,
            steps: [],
        } as never);

        const command = createDemoCommand();
        await command.parseAsync(['node', 'demo', 'golden-path'], {
            from: 'node',
        });

        expect(process.exitCode).toBe(1);
        expect(fakePool.end).toHaveBeenCalled();
    });

    it('should call pool.end even when runGoldenPath throws', async () => {
        const fakePool = { end: vi.fn().mockResolvedValue(undefined) };
        vi.mocked(createCliPool).mockReturnValue(fakePool as never);
        vi.mocked(runGoldenPath).mockRejectedValue(new Error('step failure'));

        const command = createDemoCommand();
        await expect(
            command.parseAsync(['node', 'demo', 'golden-path'], {
                from: 'node',
            }),
        ).rejects.toThrow('step failure');

        expect(fakePool.end).toHaveBeenCalled();
    });

    it('should pass --registry-url and --verbose options to runGoldenPath', async () => {
        const fakePool = { end: vi.fn().mockResolvedValue(undefined) };
        vi.mocked(createCliPool).mockReturnValue(fakePool as never);
        vi.mocked(runGoldenPath).mockResolvedValue({
            success: true,
            steps: [],
        } as never);

        const command = createDemoCommand();
        await command.parseAsync(
            [
                'node',
                'demo',
                'golden-path',
                '--registry-url',
                'https://reg.example.com',
                '--verbose',
            ],
            { from: 'node' },
        );

        expect(runGoldenPath).toHaveBeenCalledWith(
            expect.objectContaining({
                identityRegistryUrl: 'https://reg.example.com',
                verbose: true,
            }),
        );
    });
});
