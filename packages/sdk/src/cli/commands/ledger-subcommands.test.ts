/**
 * Additional action-path tests for the ledger query subcommand.
 * Tests related to runLedgerVerify are already covered in ledger.test.ts; this file only fills in the uncovered branches.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

// mock ActionRecorder + IntegrityChecker
vi.mock('@coivitas/policy', async (importOriginal) => {
    const actual =
        await importOriginal<typeof import('@coivitas/policy')>();
    return {
        ...actual,
        ActionRecorder: vi.fn(),
        IntegrityChecker: vi.fn(),
    };
});

// mock runtime
vi.mock('../runtime.js', async (importOriginal) => {
    const actual = await importOriginal<typeof import('../runtime.js')>();
    return {
        ...actual,
        createCliPool: vi.fn(),
        printOutput: vi.fn(),
        resolveRegistryUrl: vi.fn().mockReturnValue('https://reg.example.com'),
    };
});

// mock golden-path utils to avoid real HTTP in resolveDemoPublicKey
vi.mock('../../golden-path/utils.js', () => ({
    resolveDemoPublicKey: vi.fn().mockResolvedValue('fakepubkey'),
}));

import { createLedgerCommand, runLedgerVerify } from './ledger.js';
import { createCliPool, printOutput } from '../runtime.js';
import { ActionRecorder } from '@coivitas/policy';
import type { DID } from '@coivitas/types';

let fakePool: { end: ReturnType<typeof vi.fn> };

beforeEach(() => {
    fakePool = { end: vi.fn().mockResolvedValue(undefined) };
    vi.mocked(createCliPool).mockReturnValue(fakePool as never);
});

afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllEnvs();
    process.exitCode = 0;
});

// ── ledger query ──────────────────────────────────────────────────────────────
describe('ledger query subcommand', () => {
    it('should call ActionRecorder.query and print results when LEDGER_PRIVATE_KEY is set', async () => {
        vi.stubEnv('LEDGER_PRIVATE_KEY', 'fakeprivkey');
        vi.stubEnv('DATABASE_URL', 'postgresql://localhost/test');

        const mockQuery = vi.fn().mockResolvedValue({
            records: [{ id: 'rec1', agentDid: 'did:agent:abc' }],
        });
        vi.mocked(ActionRecorder).mockImplementation(
            () =>
                ({
                    query: mockQuery,
                }) as never,
        );

        const command = createLedgerCommand();
        await command.parseAsync(
            ['node', 'ledger', 'query', '--agent-did', 'did:agent:abc'],
            { from: 'node' },
        );

        expect(ActionRecorder).toHaveBeenCalledWith(
            fakePool,
            expect.objectContaining({ ledgerPrivateKey: 'fakeprivkey' }),
        );
        expect(mockQuery).toHaveBeenCalledWith(
            expect.objectContaining({ agentDid: 'did:agent:abc' }),
        );
        expect(printOutput).toHaveBeenCalledWith(
            [{ id: 'rec1', agentDid: 'did:agent:abc' }],
            false,
        );
        expect(fakePool.end).toHaveBeenCalled();
    });

    it('should throw when LEDGER_PRIVATE_KEY is not set for query', async () => {
        delete process.env.LEDGER_PRIVATE_KEY;
        vi.stubEnv('DATABASE_URL', 'postgresql://localhost/test');

        const command = createLedgerCommand();
        await expect(
            command.parseAsync(
                ['node', 'ledger', 'query', '--agent-did', 'did:agent:abc'],
                { from: 'node' },
            ),
        ).rejects.toThrow(/LEDGER_PRIVATE_KEY/);
    });

    it('should pass --since filter to ActionRecorder.query', async () => {
        vi.stubEnv('LEDGER_PRIVATE_KEY', 'fakeprivkey');
        vi.stubEnv('DATABASE_URL', 'postgresql://localhost/test');

        const mockQuery = vi.fn().mockResolvedValue({ records: [] });
        vi.mocked(ActionRecorder).mockImplementation(
            () =>
                ({
                    query: mockQuery,
                }) as never,
        );

        const sinceTs = '2025-01-01T00:00:00.000Z';
        const command = createLedgerCommand();
        await command.parseAsync(
            [
                'node',
                'ledger',
                'query',
                '--agent-did',
                'did:agent:abc',
                '--since',
                sinceTs,
            ],
            { from: 'node' },
        );

        expect(mockQuery).toHaveBeenCalledWith(
            expect.objectContaining({ createdFrom: sinceTs }),
        );
    });

    it('should print JSON when --json flag is set', async () => {
        vi.stubEnv('LEDGER_PRIVATE_KEY', 'fakeprivkey');
        vi.stubEnv('DATABASE_URL', 'postgresql://localhost/test');

        const records = [{ id: 'rec1' }];
        const mockQuery = vi.fn().mockResolvedValue({ records });
        vi.mocked(ActionRecorder).mockImplementation(
            () =>
                ({
                    query: mockQuery,
                }) as never,
        );

        const command = createLedgerCommand();
        await command.parseAsync(
            [
                'node',
                'ledger',
                'query',
                '--agent-did',
                'did:agent:abc',
                '--json',
            ],
            { from: 'node' },
        );

        // printOutput called with json=true
        expect(printOutput).toHaveBeenCalledWith(records, true);
    });

    it('should call pool.end even when ActionRecorder.query throws', async () => {
        vi.stubEnv('LEDGER_PRIVATE_KEY', 'fakeprivkey');
        vi.stubEnv('DATABASE_URL', 'postgresql://localhost/test');

        vi.mocked(ActionRecorder).mockImplementation(
            () =>
                ({
                    query: vi.fn().mockRejectedValue(new Error('DB error')),
                }) as never,
        );

        const command = createLedgerCommand();
        await expect(
            command.parseAsync(
                ['node', 'ledger', 'query', '--agent-did', 'did:agent:abc'],
                { from: 'node' },
            ),
        ).rejects.toThrow('DB error');

        expect(fakePool.end).toHaveBeenCalled();
    });
});

// ── defaultGenesisProbeFactory (indirect coverage) ───────────────────────────
describe('runLedgerVerify defaultGenesisProbeFactory path', () => {
    const AGENT_DID = 'did:agent:genesis-probe-test' as DID;

    it('should use ActionRecorder to probe genesis when no genesisProbeFactory is injected', async () => {
        vi.stubEnv('LEDGER_PRIVATE_KEY', 'fakeprivkey');
        vi.stubEnv('DATABASE_URL', 'postgresql://localhost/test');

        // ActionRecorder.query is used by defaultGenesisProbeFactory
        const genesisCreatedAt = '2025-01-01T00:00:00.000Z';
        const mockQuery = vi.fn().mockResolvedValue({
            records: [{ createdAt: genesisCreatedAt }],
        });
        vi.mocked(ActionRecorder).mockImplementation(
            () =>
                ({
                    query: mockQuery,
                }) as never,
        );

        // checker is injected so we skip the GOVERNOR_PUBLIC_KEY path
        const mockVerify = vi.fn().mockResolvedValue({ valid: true });
        const checkerFactory = (_pool: unknown) => ({
            verifyIntegrity: mockVerify,
        });

        vi.spyOn(console, 'log').mockImplementation(() => {});

        // --chain --from == genesisCreatedAt → same timestamp → allowed (NOT strictly after)
        await runLedgerVerify(
            {
                agentDid: AGENT_DID,
                chain: true,
                from: genesisCreatedAt,
            },
            { checkerFactory },
            // no genesisProbeFactory → uses defaultGenesisProbeFactory
        );

        // ActionRecorder should have been constructed and queried by defaultGenesisProbeFactory
        expect(ActionRecorder).toHaveBeenCalledWith(
            fakePool,
            expect.objectContaining({ ledgerPrivateKey: 'fakeprivkey' }),
        );
        expect(mockQuery).toHaveBeenCalledWith(
            expect.objectContaining({ agentDid: AGENT_DID, limit: 1 }),
        );
        expect(mockVerify).toHaveBeenCalled();
    });

    it('should allow --chain --from when no genesis record exists (null)', async () => {
        vi.stubEnv('LEDGER_PRIVATE_KEY', 'fakeprivkey');
        vi.stubEnv('DATABASE_URL', 'postgresql://localhost/test');

        const mockQuery = vi.fn().mockResolvedValue({ records: [] });
        vi.mocked(ActionRecorder).mockImplementation(
            () =>
                ({
                    query: mockQuery,
                }) as never,
        );

        const mockVerify = vi.fn().mockResolvedValue({ valid: true });
        const checkerFactory = (_pool: unknown) => ({
            verifyIntegrity: mockVerify,
        });

        vi.spyOn(console, 'log').mockImplementation(() => {});

        await runLedgerVerify(
            {
                agentDid: AGENT_DID,
                chain: true,
                from: '2025-06-01T00:00:00.000Z',
            },
            { checkerFactory },
        );

        // null genesis → no restriction, verifyIntegrity should be called
        expect(mockVerify).toHaveBeenCalled();
    });
});
