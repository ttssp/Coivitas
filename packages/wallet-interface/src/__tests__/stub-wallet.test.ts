/**
 * stub-wallet.test.ts — unit tests for StubWallet fail-closed behavior
 *
 * Test strategy (fail-closed):
 * - Every stub method asserts ok: false (the success path is not tested -- the stub has no success).
 * - recoverFromShares additionally tests stub behavior (currentShardVersion omitted).
 * - No fetch / external dependencies are used.
 * - Test naming convention: should ... when ...
 */

import { describe, expect, it } from 'vitest';

import type { DID } from '@coivitas/types';

import { createStubWallet } from '../stub-wallet.js';
import type {
    CreateKeyParams,
    CreateRecoverySharesParams,
    DecryptedShare,
    RecoverFromSharesParams,
} from '../types.js';

// ── Helpers ────────────────────────────────────────────────────────────────

/** Constructs a did:key branded DID (for tests; no crypto verification). */
function makeDid(s: string): DID {
    return s as DID;
}

// ── Test suite ────────────────────────────────────────────────────────────────

describe('createStubWallet — fail-closed stub', () => {
    const wallet = createStubWallet();

    // ── Key management ─────────────────────────────────────────────────────────────

    describe('createKey', () => {
        it('should return WALLET_STUB_NOT_FOR_PRODUCTION when called', async () => {
            const params: CreateKeyParams = { label: 'test-key' };
            const result = await wallet.createKey(params);
            expect(result.ok).toBe(false);
            if (!result.ok) {
                expect(result.error.code).toBe('WALLET_STUB_NOT_FOR_PRODUCTION');
            }
        });

        it('should return WALLET_STUB_NOT_FOR_PRODUCTION when called without params fields', async () => {
            const result = await wallet.createKey({});
            expect(result.ok).toBe(false);
            if (!result.ok) {
                expect(result.error.code).toBe('WALLET_STUB_NOT_FOR_PRODUCTION');
                expect(result.error.message).toContain('Stub wallet');
            }
        });
    });

    describe('getPublicKey', () => {
        it('should return WALLET_STUB_NOT_FOR_PRODUCTION when called with keyId', async () => {
            const result = await wallet.getPublicKey('key-001' as never);
            expect(result.ok).toBe(false);
            if (!result.ok) {
                expect(result.error.code).toBe('WALLET_STUB_NOT_FOR_PRODUCTION');
            }
        });

        it('should return WALLET_STUB_NOT_FOR_PRODUCTION when called without keyId', async () => {
            const result = await wallet.getPublicKey();
            expect(result.ok).toBe(false);
            if (!result.ok) {
                expect(result.error.code).toBe('WALLET_STUB_NOT_FOR_PRODUCTION');
            }
        });
    });

    describe('listKeys', () => {
        it('should return WALLET_STUB_NOT_FOR_PRODUCTION when called', async () => {
            const result = await wallet.listKeys();
            expect(result.ok).toBe(false);
            if (!result.ok) {
                expect(result.error.code).toBe('WALLET_STUB_NOT_FOR_PRODUCTION');
            }
        });
    });

    // ── Signing (Hot/Cold split) ──────────────────────────────────────────────

    describe('signSessionAuth (Hot Passkey path)', () => {
        it('should return WALLET_STUB_NOT_FOR_PRODUCTION when called', async () => {
            const result = await wallet.signSessionAuth({
                payload: new Uint8Array([1, 2, 3]),
            });
            expect(result.ok).toBe(false);
            if (!result.ok) {
                expect(result.error.code).toBe('WALLET_STUB_NOT_FOR_PRODUCTION');
            }
        });

        it('should return WALLET_STUB_NOT_FOR_PRODUCTION when called with keyId', async () => {
            const result = await wallet.signSessionAuth({
                payload: new Uint8Array([4, 5, 6]),
                keyId: 'passkey-001' as never,
            });
            expect(result.ok).toBe(false);
        });
    });

    describe('signCold (Cold Ed25519 path)', () => {
        it('should return WALLET_STUB_NOT_FOR_PRODUCTION for ROTATION_PROOF when called', async () => {
            const result = await wallet.signCold({
                payload: new Uint8Array([7, 8, 9]),
                operationType: 'ROTATION_PROOF',
            });
            expect(result.ok).toBe(false);
            if (!result.ok) {
                expect(result.error.code).toBe('WALLET_STUB_NOT_FOR_PRODUCTION');
            }
        });

        it('should return WALLET_STUB_NOT_FOR_PRODUCTION for BINDING_PROOF when called', async () => {
            const result = await wallet.signCold({
                payload: new Uint8Array([10, 11, 12]),
                operationType: 'BINDING_PROOF',
            });
            expect(result.ok).toBe(false);
        });

        it('should return WALLET_STUB_NOT_FOR_PRODUCTION for DEACTIVATION_PROOF when called', async () => {
            const result = await wallet.signCold({
                payload: new Uint8Array([13, 14, 15]),
                operationType: 'DEACTIVATION_PROOF',
            });
            expect(result.ok).toBe(false);
        });
    });

    // ── Encrypt/decrypt ────────────────────────────────────────────────────────────

    describe('encrypt', () => {
        it('should return WALLET_STUB_NOT_FOR_PRODUCTION when called', async () => {
            const result = await wallet.encrypt({
                plaintext: new Uint8Array([1, 2, 3]),
            });
            expect(result.ok).toBe(false);
            if (!result.ok) {
                expect(result.error.code).toBe('WALLET_STUB_NOT_FOR_PRODUCTION');
            }
        });
    });

    describe('decrypt', () => {
        it('should return WALLET_STUB_NOT_FOR_PRODUCTION when called', async () => {
            const result = await wallet.decrypt({
                ciphertext: new Uint8Array([0xde, 0xad, 0xbe, 0xef]),
                nonce: new Uint8Array(24).fill(0),
            });
            expect(result.ok).toBe(false);
            if (!result.ok) {
                expect(result.error.code).toBe('WALLET_STUB_NOT_FOR_PRODUCTION');
            }
        });
    });

    // ── Recovery ─────────────────────────────────────────────────────────────────

    describe('createRecoveryShares', () => {
        it('should return WALLET_STUB_NOT_FOR_PRODUCTION when called with valid (2,3) topology', async () => {
            const params: CreateRecoverySharesParams = {
                threshold: 2,
                totalShares: 3,
                recipients: [
                    { kind: 'local', credentialId: 'cred-001' },
                    {
                        kind: 'hardware',
                        deviceId: 'yubikey-001',
                        wrappingPublicKey: 'a'.repeat(64),
                    },
                    {
                        kind: 'guardian',
                        guardianPublicKey: 'b'.repeat(64),
                        guardianLabel: 'Alice',
                    },
                ],
            };
            const result = await wallet.createRecoveryShares(params);
            expect(result.ok).toBe(false);
            if (!result.ok) {
                expect(result.error.code).toBe('WALLET_STUB_NOT_FOR_PRODUCTION');
            }
        });
    });

    describe('recoverFromShares — version-provenance stub behavior', () => {
        const shares: DecryptedShare[] = [
            { index: 1, shareData: new Uint8Array([1, 2, 3]), shardVersion: 1 },
            { index: 2, shareData: new Uint8Array([4, 5, 6]), shardVersion: 1 },
        ];
        const expectedDid = makeDid('did:key:z6Mktest');

        it('should return WALLET_RECOVERY_VERSION_UNVERIFIED when currentShardVersion is absent', async () => {
            const params: RecoverFromSharesParams = {
                shares,
                expectedDid,
                // currentShardVersion deliberately omitted — triggers the version-unverified branch
            };
            const result = await wallet.recoverFromShares(params);
            expect(result.ok).toBe(false);
            if (!result.ok) {
                expect(result.error.code).toBe(
                    'WALLET_RECOVERY_VERSION_UNVERIFIED',
                );
                expect(result.error.message).toContain('currentShardVersion');
            }
        });

        it('should return WALLET_RECOVERY_VERSION_UNVERIFIED when currentShardVersion is explicitly undefined', async () => {
            const params: RecoverFromSharesParams = {
                shares,
                expectedDid,
                currentShardVersion: undefined,
            };
            const result = await wallet.recoverFromShares(params);
            expect(result.ok).toBe(false);
            if (!result.ok) {
                expect(result.error.code).toBe(
                    'WALLET_RECOVERY_VERSION_UNVERIFIED',
                );
            }
        });

        it('should return WALLET_STUB_NOT_FOR_PRODUCTION when currentShardVersion is provided', async () => {
            // When currentShardVersion is provided, the version-unverified branch is not triggered and it falls back to the generic stub error
            const params: RecoverFromSharesParams = {
                shares,
                expectedDid,
                currentShardVersion: 1,
            };
            const result = await wallet.recoverFromShares(params);
            expect(result.ok).toBe(false);
            if (!result.ok) {
                expect(result.error.code).toBe('WALLET_STUB_NOT_FOR_PRODUCTION');
            }
        });

        it('should return WALLET_STUB_NOT_FOR_PRODUCTION when currentShardVersion is 0', async () => {
            const params: RecoverFromSharesParams = {
                shares,
                expectedDid,
                currentShardVersion: 0,
            };
            const result = await wallet.recoverFromShares(params);
            expect(result.ok).toBe(false);
            if (!result.ok) {
                expect(result.error.code).toBe('WALLET_STUB_NOT_FOR_PRODUCTION');
            }
        });

        it('should return ok false and not throw when params is undefined (fail-closed entry guard)', async () => {
            // Entry-guard acceptance: when the caller passes undefined, do not throw and return ok: false.
            // This guard ensures the interface promise "never throws + returns Promise<WalletResult<...>>" still holds for the worst-case caller.
            // eslint-disable-next-line @typescript-eslint/no-unsafe-argument, @typescript-eslint/no-explicit-any
            const result = await wallet.recoverFromShares(undefined as any);
            expect(result.ok).toBe(false);
            if (!result.ok) {
                expect(result.error.code).toBe('WALLET_STUB_NOT_FOR_PRODUCTION');
            }
        });
    });

    describe('rotateRecoverySecret', () => {
        it('should return WALLET_STUB_NOT_FOR_PRODUCTION when called', async () => {
            const result = await wallet.rotateRecoverySecret({
                recipients: [
                    { kind: 'local', credentialId: 'cred-001' },
                    {
                        kind: 'hardware',
                        deviceId: 'yubikey-001',
                        wrappingPublicKey: 'a'.repeat(64),
                    },
                    {
                        kind: 'guardian',
                        guardianPublicKey: 'b'.repeat(64),
                    },
                ],
            });
            expect(result.ok).toBe(false);
            if (!result.ok) {
                expect(result.error.code).toBe('WALLET_STUB_NOT_FOR_PRODUCTION');
            }
        });
    });

    // ── Topology configuration ──────────────────────────────────────────────────────────────

    describe('setRecoveryTopology', () => {
        it('should return WALLET_STUB_NOT_FOR_PRODUCTION when called with valid (2,3) topology', async () => {
            const result = await wallet.setRecoveryTopology({
                threshold: 2,
                totalShares: 3,
            });
            expect(result.ok).toBe(false);
            if (!result.ok) {
                expect(result.error.code).toBe('WALLET_STUB_NOT_FOR_PRODUCTION');
            }
        });
    });

    // ── Ownership proof ────────────────────────────────────────────────────────────

    describe('proveOwnership', () => {
        it('should return WALLET_STUB_NOT_FOR_PRODUCTION when called without params', async () => {
            const result = await wallet.proveOwnership({});
            expect(result.ok).toBe(false);
            if (!result.ok) {
                expect(result.error.code).toBe('WALLET_STUB_NOT_FOR_PRODUCTION');
            }
        });

        it('should return WALLET_STUB_NOT_FOR_PRODUCTION when called with challenge', async () => {
            const result = await wallet.proveOwnership({
                challenge: new Uint8Array(32).fill(0xab),
            });
            expect(result.ok).toBe(false);
            if (!result.ok) {
                expect(result.error.code).toBe('WALLET_STUB_NOT_FOR_PRODUCTION');
            }
        });
    });

    // ── Lifecycle ─────────────────────────────────────────────────────────────

    describe('lock', () => {
        it('should return WALLET_STUB_NOT_FOR_PRODUCTION when called', async () => {
            const result = await wallet.lock();
            expect(result.ok).toBe(false);
            if (!result.ok) {
                expect(result.error.code).toBe('WALLET_STUB_NOT_FOR_PRODUCTION');
            }
        });
    });

    describe('unlock', () => {
        it('should return WALLET_STUB_NOT_FOR_PRODUCTION when called with biometric method', async () => {
            const result = await wallet.unlock({ method: 'biometric' });
            expect(result.ok).toBe(false);
            if (!result.ok) {
                expect(result.error.code).toBe('WALLET_STUB_NOT_FOR_PRODUCTION');
            }
        });

        it('should return WALLET_STUB_NOT_FOR_PRODUCTION when called without method', async () => {
            const result = await wallet.unlock({});
            expect(result.ok).toBe(false);
        });
    });

    describe('getState', () => {
        it('should return WALLET_STUB_NOT_FOR_PRODUCTION when called', async () => {
            const result = await wallet.getState();
            expect(result.ok).toBe(false);
            if (!result.ok) {
                expect(result.error.code).toBe('WALLET_STUB_NOT_FOR_PRODUCTION');
            }
        });
    });

    // ── WalletResult shape validation ─────────────────────────────────────────────────

    describe('WalletResult structure invariant', () => {
        it('should always return WalletError with code and message when ok is false', async () => {
            const result = await wallet.createKey({});
            expect(result.ok).toBe(false);
            if (!result.ok) {
                expect(typeof result.error.code).toBe('string');
                expect(typeof result.error.message).toBe('string');
                expect(result.error.message.length).toBeGreaterThan(0);
            }
        });

        it('should never return ok true from any stub method', async () => {
            // Invoke all 15 methods concurrently and verify none returns ok: true
            const dummyDid = makeDid('did:key:z6Mktest');
            const dummyShares: DecryptedShare[] = [
                {
                    index: 1,
                    shareData: new Uint8Array([1]),
                    shardVersion: 0,
                },
            ];

            const results = await Promise.all([
                wallet.createKey({}),
                wallet.getPublicKey(),
                wallet.listKeys(),
                wallet.signSessionAuth({ payload: new Uint8Array([1]) }),
                wallet.signCold({
                    payload: new Uint8Array([1]),
                    operationType: 'BINDING_PROOF',
                }),
                wallet.encrypt({ plaintext: new Uint8Array([1]) }),
                wallet.decrypt({
                    ciphertext: new Uint8Array([1]),
                    nonce: new Uint8Array(24),
                }),
                wallet.createRecoveryShares({
                    threshold: 2,
                    totalShares: 3,
                    recipients: [
                        { kind: 'local', credentialId: 'c' },
                        {
                            kind: 'hardware',
                            deviceId: 'd',
                            wrappingPublicKey: 'e'.repeat(64),
                        },
                        {
                            kind: 'guardian',
                            guardianPublicKey: 'f'.repeat(64),
                        },
                    ],
                }),
                // Pass currentShardVersion=0 to bypass the version-unverified branch (tests the generic stub fallback)
                wallet.recoverFromShares({
                    shares: dummyShares,
                    expectedDid: dummyDid,
                    currentShardVersion: 0,
                }),
                wallet.rotateRecoverySecret({
                    recipients: [
                        { kind: 'local', credentialId: 'c' },
                        {
                            kind: 'hardware',
                            deviceId: 'd',
                            wrappingPublicKey: 'e'.repeat(64),
                        },
                        {
                            kind: 'guardian',
                            guardianPublicKey: 'f'.repeat(64),
                        },
                    ],
                }),
                wallet.setRecoveryTopology({ threshold: 2, totalShares: 3 }),
                wallet.proveOwnership({}),
                wallet.lock(),
                wallet.unlock({}),
                wallet.getState(),
            ]);

            for (const result of results) {
                expect(result.ok).toBe(false);
            }
        });
    });
});
