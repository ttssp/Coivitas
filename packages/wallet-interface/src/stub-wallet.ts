/**
 * StubWallet — fail-closed stub implementation
 *
 * Design conventions:
 * - All methods return { ok: false, error: { code: 'WALLET_STUB_NOT_FOR_PRODUCTION' } }.
 * - recoverFromShares additionally checks: when currentShardVersion is omitted, it returns WALLET_RECOVERY_VERSION_UNVERIFIED
 *   (stub behavior; a future release closes the loop by externalizing version provenance).
 * - No stub method's response contains success data (fail-closed guard).
 * - In the production implementation this is replaced with a real Passkey adapter / HSM adapter.
 */

import type { WalletInterface } from './interface.js';
import type { RecoverFromSharesParams, WalletResult } from './types.js';

/** Stub failure-response factory (shared by all methods). */
function stubFail<T>(): Promise<WalletResult<T>> {
    return Promise.resolve({
        ok: false as const,
        error: {
            code: 'WALLET_STUB_NOT_FOR_PRODUCTION' as const,
            message:
                'Stub wallet — not for production use. Real adapter implementations are not bundled in this release.',
        },
    });
}

/**
 * createStubWallet — creates a fail-closed stub instance
 *
 * Purpose: in integration tests, verifies the fail-closed behavior when the wallet is unavailable;
 *          serves as a placeholder adapter in identity-layer tests.
 *
 * Note: the stub instance is stateless; every call returns the same error.
 */
export function createStubWallet(): WalletInterface {
    return {
        // ── Key management ──────────────────────────────────────────────────────────

        createKey: () => stubFail(),
        getPublicKey: () => stubFail(),
        listKeys: () => stubFail(),

        // ── Signing (R3 Hot/Cold split) ──────────────────────────────────────────

        signSessionAuth: () => stubFail(),
        signCold: () => stubFail(),

        // ── Encrypt/decrypt ──────────────────────────────────────────────────────────

        encrypt: () => stubFail(),
        decrypt: () => stubFail(),

        // ── Recovery ─────────────────────────────────────────────────────────────

        createRecoveryShares: () => stubFail(),

        /**
         * recoverFromShares — stub behavior
         *
         * When currentShardVersion is omitted, it returns WALLET_RECOVERY_VERSION_UNVERIFIED in preference
         * to the generic WALLET_STUB_NOT_FOR_PRODUCTION, so the caller can distinguish the two error semantics.
         * After a future release closes the loop, this is replaced with real version-provenance logic.
         */
        recoverFromShares: (
            params: RecoverFromSharesParams,
        ): Promise<WalletResult<never>> => {
            // Entry guard: when params itself is null/undefined, fail-closed (before any field deref)
            if (params == null) {
                return Promise.resolve({
                    ok: false as const,
                    error: {
                        code: 'WALLET_STUB_NOT_FOR_PRODUCTION' as const,
                        message:
                            'recoverFromShares called with invalid params (null/undefined). ' +
                            'Stub wallet — not for production use.',
                    },
                });
            }
            if (params.currentShardVersion === undefined) {
                return Promise.resolve({
                    ok: false as const,
                    error: {
                        code: 'WALLET_RECOVERY_VERSION_UNVERIFIED' as const,
                        message:
                            'currentShardVersion is absent — cannot verify shard freshness. ' +
                            'Caller must supply currentShardVersion to proceed.',
                    },
                });
            }
            return stubFail();
        },

        rotateRecoverySecret: () => stubFail(),

        // ── Topology configuration ──────────────────────────────────────────────────────────

        setRecoveryTopology: () => stubFail(),

        // ── Ownership proof ────────────────────────────────────────────────────────

        proveOwnership: () => stubFail(),

        // ── Lifecycle ──────────────────────────────────────────────────────────

        lock: () => stubFail(),
        unlock: () => stubFail(),
        getState: () => stubFail(),
    };
}
