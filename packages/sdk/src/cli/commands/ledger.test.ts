import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import type { IntegrityCheckResult } from '@coivitas/policy';
import type { DID } from '@coivitas/types';

import { runLedgerVerify } from './ledger.js';

vi.mock('../runtime.js', async () => {
    const actual =
        await vi.importActual<typeof import('../runtime.js')>('../runtime.js');
    return {
        ...actual,
        createCliPool: vi.fn(),
    };
});

const runtime = await import('../runtime.js');
const mockedCreatePool = runtime.createCliPool as unknown as ReturnType<
    typeof vi.fn
>;

let endSpy: ReturnType<typeof vi.fn>;

beforeEach(() => {
    vi.stubEnv('DATABASE_URL', 'postgresql://stub/test');
    endSpy = vi.fn().mockResolvedValue(undefined);
    mockedCreatePool.mockReturnValue({ end: endSpy });
});

afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllEnvs();
    mockedCreatePool.mockReset();
    process.exitCode = 0;
});

const AGENT_DID = 'did:agent:1111222233334444555566667777888899990000' as DID;

function makeFakeChecker(result: IntegrityCheckResult) {
    return {
        verifyIntegrity: vi.fn().mockResolvedValue(result),
    };
}

// By default make the probe report "no records found" -- equivalent to "--from is not later than genesis", which lets verifyIntegrity proceed.
function fakeProbe(genesisCreatedAt: string | null = null) {
    return {
        findGenesisCreatedAt: vi.fn().mockResolvedValue(genesisCreatedAt),
    };
}

describe('runLedgerVerify', () => {
    it('passes (createdFrom, createdTo) to verifyIntegrity when --chain is set and window starts at genesis', async () => {
        const checker = makeFakeChecker({ valid: true });
        // genesis record at the same instant as --from -> window start <= genesis, so it proceeds
        const probe = fakeProbe('2026-04-20T00:00:00.000Z');
        vi.spyOn(console, 'log').mockImplementation(() => {});

        await runLedgerVerify(
            {
                agentDid: AGENT_DID,
                chain: true,
                from: '2026-04-20T00:00:00.000Z',
                to: '2026-04-23T23:59:59.999Z',
                json: true,
            },
            {
                checkerFactory: () => checker,
                genesisProbeFactory: () => probe,
            },
        );

        expect(checker.verifyIntegrity).toHaveBeenCalledWith(AGENT_DID, {
            createdFrom: '2026-04-20T00:00:00.000Z',
            createdTo: '2026-04-23T23:59:59.999Z',
        });
        expect(probe.findGenesisCreatedAt).toHaveBeenCalledWith(AGENT_DID);
        expect(endSpy).toHaveBeenCalledTimes(1);
        expect(process.exitCode).not.toBe(1);
    });

    it('refuses --chain --from when window starts strictly after the genesis record', async () => {
        const checker = makeFakeChecker({ valid: true });
        // genesis earlier than --from -> a non-genesis anchor, which IntegrityChecker does not currently support, so it must be rejected
        const probe = fakeProbe('2026-04-01T00:00:00.000Z');

        await expect(
            runLedgerVerify(
                {
                    agentDid: AGENT_DID,
                    chain: true,
                    from: '2026-04-20T00:00:00.000Z',
                },
                {
                    checkerFactory: () => checker,
                    genesisProbeFactory: () => probe,
                },
            ),
        ).rejects.toThrow(
            /Non-genesis chain-segment verification is not yet supported/,
        );
        expect(checker.verifyIntegrity).not.toHaveBeenCalled();
        expect(endSpy).toHaveBeenCalledTimes(1);
    });

    it('rejects --chain without any window bound', async () => {
        const checker = makeFakeChecker({ valid: true });

        await expect(
            runLedgerVerify(
                { agentDid: AGENT_DID, chain: true },
                { checkerFactory: () => checker },
            ),
        ).rejects.toThrow(/--chain requires/);

        expect(checker.verifyIntegrity).not.toHaveBeenCalled();
        // pool.end must still be called to release resources
        expect(endSpy).toHaveBeenCalledTimes(1);
    });

    it('omits filters when --chain is not set', async () => {
        const checker = makeFakeChecker({ valid: true });
        vi.spyOn(console, 'log').mockImplementation(() => {});

        await runLedgerVerify(
            { agentDid: AGENT_DID },
            { checkerFactory: () => checker },
        );

        expect(checker.verifyIntegrity).toHaveBeenCalledWith(AGENT_DID, {});
    });

    it('sets process.exitCode=1 and prints failure detail when checker reports invalid', async () => {
        const checker = makeFakeChecker({
            valid: false,
            brokenAt: 'urn:rec:abc',
            reason: 'record_hash mismatch',
        });
        const probe = fakeProbe('2026-04-20T00:00:00.000Z'); // genesis == from -> proceeds
        const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

        const result = await runLedgerVerify(
            {
                agentDid: AGENT_DID,
                chain: true,
                from: '2026-04-20T00:00:00.000Z',
            },
            {
                checkerFactory: () => checker,
                genesisProbeFactory: () => probe,
            },
        );

        expect(result.valid).toBe(false);
        expect(process.exitCode).toBe(1);
        const output = logSpy.mock.calls
            .map((call) => String(call[0]))
            .join('\n');
        expect(output).toContain('Ledger verification FAILED');
        expect(output).toContain('urn:rec:abc');
        expect(output).toContain('record_hash mismatch');
    });

    it('emits JSON envelope when --json is set', async () => {
        const checker = makeFakeChecker({ valid: true });
        const probe = fakeProbe(null);
        const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

        await runLedgerVerify(
            {
                agentDid: AGENT_DID,
                chain: true,
                from: '2026-04-20T00:00:00.000Z',
                json: true,
            },
            {
                checkerFactory: () => checker,
                genesisProbeFactory: () => probe,
            },
        );

        const printed = logSpy.mock.calls[0]![0] as string;
        const parsed = JSON.parse(printed) as Record<string, unknown>;
        expect(parsed['agentDid']).toBe(AGENT_DID);
        expect(parsed['chain']).toBe(true);
        expect(parsed['from']).toBe('2026-04-20T00:00:00.000Z');
        expect(parsed['valid']).toBe(true);
    });

    it('prints "Ledger verified for ..." in non-chain non-json mode', async () => {
        const checker = makeFakeChecker({ valid: true });
        const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

        await runLedgerVerify(
            { agentDid: AGENT_DID },
            { checkerFactory: () => checker },
        );

        const output = logSpy.mock.calls
            .map((call) => String(call[0]))
            .join('\n');
        expect(output).toContain(`Ledger verified for ${AGENT_DID}`);
    });

    it('prints "Chain segment verified ..." with bound markers in chain non-json mode', async () => {
        const checker = makeFakeChecker({ valid: true });
        const probe = fakeProbe(null);
        const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

        await runLedgerVerify(
            {
                agentDid: AGENT_DID,
                chain: true,
                from: '2026-04-20T00:00:00.000Z',
            },
            {
                checkerFactory: () => checker,
                genesisProbeFactory: () => probe,
            },
        );

        const output = logSpy.mock.calls
            .map((call) => String(call[0]))
            .join('\n');
        expect(output).toContain('Chain segment verified');
        expect(output).toContain('2026-04-20T00:00:00.000Z');
        expect(output).toContain('+∞');
    });

    it('drives the verify wrapper through commander parseAsync (--chain --from)', async () => {
        // Exercise the commander path: to hit the default IntegrityChecker we set LEDGER_PRIVATE_KEY;
        // the real IntegrityChecker goes through ActionRecorder.query -> SQL and will fail -- but finally still closes the pool.
        // We only care whether the commander wrapper is reached: trigger it via the verify failure path (missing LEDGER_PRIVATE_KEY).
        vi.unstubAllEnvs();
        vi.stubEnv('DATABASE_URL', 'postgresql://stub/test');
        mockedCreatePool.mockReturnValue({ end: endSpy });

        const { createLedgerCommand } = await import('./ledger.js');
        const command = createLedgerCommand();
        await expect(
            command.parseAsync(
                [
                    'node',
                    'ledger',
                    'verify',
                    '--agent-did',
                    AGENT_DID,
                    '--chain',
                    '--from',
                    '2026-04-20T00:00:00.000Z',
                ],
                { from: 'node' },
            ),
        ).rejects.toThrow(/LEDGER_PRIVATE_KEY is required/);
    });

    it('errors fast without LEDGER_PRIVATE_KEY when no checker override is supplied', async () => {
        // Drop the ledger key to confirm the production branch throws explicitly rather than silently using an empty string
        vi.unstubAllEnvs();
        vi.stubEnv('DATABASE_URL', 'postgresql://stub/test');
        // re-wire the createCliPool stub -- unstubAllEnvs does not affect mocks, but do this to be safe
        mockedCreatePool.mockReturnValue({ end: endSpy });

        await expect(runLedgerVerify({ agentDid: AGENT_DID })).rejects.toThrow(
            /LEDGER_PRIVATE_KEY is required/,
        );
        expect(endSpy).toHaveBeenCalledTimes(1);
    });

    // The old GOVERNOR_PUBLIC_KEY env-check test has been removed.
    // After the refactor, standard mode no longer needs the governor public key (guaranteed mutually exclusive at compile time),
    // so the GOVERNOR_PUBLIC_KEY env check no longer exists in the CLI verify path.
    // Governor chain verification requires a separate control-plane checker (a future CLI extension).

    it('should pass env checks and reach IntegrityChecker when LEDGER_PRIVATE_KEY is set (standard path)', async () => {
        // After the refactor, standard mode only needs LEDGER_PRIVATE_KEY.
        // Without a real DB, IntegrityChecker construction or query throws some other error --
        // the key assertion is that it does not hit 'LEDGER_PRIVATE_KEY is required'.
        vi.unstubAllEnvs();
        vi.stubEnv('DATABASE_URL', 'postgresql://stub/test');
        vi.stubEnv(
            'LEDGER_PRIVATE_KEY',
            '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
        );
        mockedCreatePool.mockReturnValue({ end: endSpy });

        // Do not use checkerFactory; take the real production branch.
        // Expected to fail during IntegrityChecker construction / DB query, but not via the env fail-fast.
        try {
            await runLedgerVerify({ agentDid: AGENT_DID });
        } catch (error) {
            const message =
                error instanceof Error ? error.message : String(error);
            // core assertion: the env fail-fast is not hit
            expect(message).not.toContain('LEDGER_PRIVATE_KEY is required');
        }
    });

    // ── governor lane regression tests ────────────────────────────
    // Problem: if the CLI always used kind='standard', it would falsely report
    // 'agent public key unavailable' for SESSION_GOVERNOR_DID -> the governance lane becomes unobservable.
    // Handling: runLedgerVerify automatically picks the control-plane checker based on isSessionGovernorDid(agentDid)
    // and injects GOVERNOR_PUBLIC_KEY as resolveControlPlanePublicKey.
    describe('governor lane verification', () => {
        const GOVERNOR_DID = 'did:system:session-governor' as unknown as DID;

        it('errors fast without GOVERNOR_PUBLIC_KEY when --agent-did is SESSION_GOVERNOR_DID', async () => {
            vi.unstubAllEnvs();
            vi.stubEnv('DATABASE_URL', 'postgresql://stub/test');
            vi.stubEnv(
                'LEDGER_PRIVATE_KEY',
                '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
            );
            // do not set GOVERNOR_PUBLIC_KEY -> should fail-fast
            mockedCreatePool.mockReturnValue({ end: endSpy });

            await expect(
                runLedgerVerify({ agentDid: GOVERNOR_DID }),
            ).rejects.toThrow(/GOVERNOR_PUBLIC_KEY is required/);
            expect(endSpy).toHaveBeenCalledTimes(1);
        });

        it('passes env checks and reaches IntegrityChecker(control-plane) when both env are set', async () => {
            vi.unstubAllEnvs();
            vi.stubEnv('DATABASE_URL', 'postgresql://stub/test');
            vi.stubEnv(
                'LEDGER_PRIVATE_KEY',
                '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
            );
            vi.stubEnv(
                'GOVERNOR_PUBLIC_KEY',
                'fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210',
            );
            mockedCreatePool.mockReturnValue({ end: endSpy });

            // take the real production branch (no checkerFactory).
            // expected to fail during the DB query, but should not hit the env fail-fast.
            try {
                await runLedgerVerify({ agentDid: GOVERNOR_DID });
            } catch (error) {
                const message =
                    error instanceof Error ? error.message : String(error);
                expect(message).not.toContain('LEDGER_PRIVATE_KEY is required');
                expect(message).not.toContain(
                    'GOVERNOR_PUBLIC_KEY is required',
                );
            }
        });

        it('verifies SESSION_GOVERNOR_DID chain successfully via injected control-plane checker', async () => {
            const checker = makeFakeChecker({ valid: true });
            vi.spyOn(console, 'log').mockImplementation(() => {});

            const result = await runLedgerVerify(
                {
                    agentDid: GOVERNOR_DID,
                    json: true,
                },
                {
                    checkerFactory: () => checker,
                },
            );

            expect(checker.verifyIntegrity).toHaveBeenCalledWith(
                GOVERNOR_DID,
                {},
            );
            expect(result.valid).toBe(true);
            expect(process.exitCode).not.toBe(1);
        });
    });
});
