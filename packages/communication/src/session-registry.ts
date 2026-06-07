/**
 * SessionRegistryImpl — encrypted session registry implementation
 *
 * Implements the SessionRegistry interface defined in packages/types/src/encryption.ts.
 * Satisfies the following 13 end-to-end encryption invariants:
 *   Inv 1: sessionId → handle unique index (the same sessionId must not be registered twice)
 *   Inv 2: lookupHandle returns a transient brand (callers must not cache it across operations)
 *   Inv 3: encrypt precondition (performed internally by the handle)
 *   Inv 4: the decrypt path must use lookupHandleForDecrypt; no trial-and-error
 *   Inv 5: dual-key fallback window of 30s (swapForDualKey is idempotent)
 *   Inv 6: closeSession atomic cleanup (cancel timer + zeroize + remove)
 *   Inv 7: monotonic nonce increment (performed internally by the handle)
 *   Inv 8: authorizedTokenId is immutable at runtime (Object.defineProperty)
 *   Inv 9: sender Receipt write timing (a caller responsibility, not in the registry)
 *   Inv 10: specVersion boundary (a caller responsibility)
 *   Inv 11: impossible wire state (a caller responsibility)
 *   Inv 12: no sessionTrustDomain (guaranteed at compile time)
 *   Inv 13: calling rekey again during PENDING_REKEY throws REKEY_FAILED (performed by the handle)
 *
 * @frozen
 */

import { deriveChainKeyRekeyKeys } from '@coivitas/crypto';
import { ProtocolError } from '@coivitas/types';
import type {
    NewSessionData,
    SessionCloseReason,
    SessionCryptoHandle,
    SessionRegistry,
} from '@coivitas/types';
import { SessionCryptoHandleImpl } from './session/crypto-state.js';

// ─── Internal registry entry ──────────────────────────────────────────────────────────

/**
 * Registry entry (one per sessionId)
 *
 * Normal operating state (ACTIVE): currentHandle is valid, previousHandle is null, dualKeyTimer is null.
 * Dual-key window (PENDING_REKEY): currentHandle is the new generation (PENDING_REKEY),
 *   previousHandle is the old generation, and dualKeyTimer references the 30s timer.
 */
interface RegistryEntry {
    /** Current-generation handle (always used by the encrypt path) */
    currentHandle: SessionCryptoHandleImpl;
    /** Old-generation handle (only set during PENDING_REKEY, used for routing decrypt of the old keyId) */
    previousHandle: SessionCryptoHandleImpl | null;
    /** 30s fallback window timer ID (null means inactive) */
    dualKeyTimer: ReturnType<typeof setTimeout> | null;
}

// ─── Inv 2 transient brand type ──────────────────────────────────────────────────────

/**
 * The transient brand type of lookupHandle's return value
 *
 * Callers must not assign the return value to a variable that outlives the function scope.
 * Enforced at the TypeScript type level (Inv 2); a lint rule serves as an additional line of defense.
 */
type TransientHandle = Readonly<SessionCryptoHandle> & {
    readonly __brand: 'transient';
};

// ─── SessionRegistryImpl ────────────────────────────────────────────────────

/**
 * Encrypted session registry implementation (production-grade)
 *
 * Runtime guarantees:
 * - All sessionId → handle mappings are maintained in a private Map, inaccessible from outside
 * - swapForDualKey is idempotent: no-op during PENDING_REKEY
 * - closeSession is atomic: clearTimeout first, then zeroize, then delete (a failure in any step leaves no data corruption)
 * - dualKeyFallbackMs is set at construction; tests can inject a small value (e.g. 100ms)
 */
export class SessionRegistryImpl implements SessionRegistry {
    private readonly _entries = new Map<string, RegistryEntry>();

    /** Dual-key fallback window duration (milliseconds), injected at construction */
    public readonly dualKeyFallbackMs: number;

    constructor(options?: { dualKeyFallbackMs?: number }) {
        this.dualKeyFallbackMs = options?.dualKeyFallbackMs ?? 30_000;
    }

    // ─── createSession (factory method) ──────────────────────────────────────────

    /**
     * Registers a new encrypted session (called after the handshake completes)
     *
     * Inv 1: the same sessionId must not be registered twice (throws INTERNAL_ERROR)
     */
    createSession(
        sessionId: string,
        role: 'initiator' | 'responder',
        authorizedTokenId: string | null,
        data: NewSessionData,
    ): void {
        // Inv 1: unique index check
        if (this._entries.has(sessionId)) {
            throw new ProtocolError(
                'INTERNAL_ERROR',
                `createSession: sessionId=${sessionId} already registered`,
            );
        }

        const handle = new SessionCryptoHandleImpl(
            sessionId,
            data.generation,
            role,
            authorizedTokenId,
            data.trafficKeys,
            data.sessionSalt,
            data.rekeyChainKey,
            'ACTIVE',
        );

        this._entries.set(sessionId, {
            currentHandle: handle,
            previousHandle: null,
            dualKeyTimer: null,
        });
    }

    // ─── lookupHandle (encrypt path) ────────────────────────────────────────

    /**
     * encrypt path: returns the current-generation handle
     *
     * Inv 1: always returns currentHandle (the registry guarantees at most one currentHandle per sessionId)
     * Inv 2: the return value carries __brand: 'transient' (callers must not cache it across operations)
     * Inv 5: even during PENDING_REKEY, only the new-generation handle is returned (the old generation does not participate in encrypt)
     * Inv 6: if the session is closed, entries has no such sessionId → returns null
     *
     * @returns the current-generation handle (with the transient brand) or null
     */
    lookupHandle(sessionId: string): SessionCryptoHandle | null {
        const entry = this._entries.get(sessionId);
        if (!entry) return null;

        // Inv 2: inject the transient brand (the TypeScript layer forbids caching across scopes)
        return entry.currentHandle as unknown as TransientHandle;
    }

    // ─── lookupHandleForDecrypt (decrypt path) ──────────────────────────────

    /**
     * decrypt path: exact routing by keyId
     *
     * Inv 4: no trial-and-error; returns null directly on a miss (the caller must throw DECRYPTION_FAILED)
     * Inv 5: supports matching either the new or old generation within the dual-key 30s window
     *
     * Matching logic:
     * 1. Exact match on currentHandle.peerKeyId → return currentHandle
     * 2. Exact match on previousHandle.peerKeyId (only within the PENDING_REKEY window) → return previousHandle
     * 3. No match in either generation → return null
     *
     * @param sessionId session ID
     * @param keyId the keyId field from the ciphertext (from EncryptedBody.keyId)
     * @returns the matching handle or null (the caller must not fall back to lookupHandle on null)
     */
    lookupHandleForDecrypt(
        sessionId: string,
        keyId: string,
    ): SessionCryptoHandle | null {
        const entry = this._entries.get(sessionId);
        if (!entry) return null;

        // Exact match on the current generation (peerKeyId = the keyId of the peer's send direction)
        if (entry.currentHandle.peerKeyId === keyId) {
            return entry.currentHandle;
        }

        // Exact match on the old generation (previousHandle exists only within the PENDING_REKEY window)
        if (
            entry.previousHandle !== null &&
            entry.previousHandle.peerKeyId === keyId
        ) {
            return entry.previousHandle;
        }

        // Inv 4: no match in either generation → return null; the caller must throw DECRYPTION_FAILED
        return null;
    }

    // ─── swapForDualKey (start the dual-key fallback window) ────────────────────────────

    /**
     * Starts the dual-key 30s fallback window
     *
     * Inv 5 + Inv 13:
     * - Idempotent: no-op when currentHandle.state === 'PENDING_REKEY' (the implementation of Inv 13)
     * - Atomic operation: once the new-generation handle is created, it immediately replaces currentHandle, and the old generation moves to previousHandle
     * - When the 30s timer expires, the old generation is automatically zeroized and the new generation transitions to ACTIVE
     *
     * Key derivation (chain_key mode):
     * - Calls deriveChainKeyRekeyKeys(prevRekeyChainKey, prevInitToResp, prevRespToInit)
     * - newSession.trafficKeys is passed by the caller (the caller has already derived them; this only creates the new handle)
     * - The registry does not handle full_handshake_required internally (the caller is responsible for initiating a new handshake)
     */
    swapForDualKey(sessionId: string, newSession: NewSessionData): void {
        const entry = this._entries.get(sessionId);
        if (!entry) {
            throw new ProtocolError(
                'INTERNAL_ERROR',
                `swapForDualKey: sessionId=${sessionId} not found`,
            );
        }

        // Inv 13 / Inv 5 idempotence: no-op if already in PENDING_REKEY
        if (entry.currentHandle.state === 'PENDING_REKEY') {
            return;
        }

        const oldHandle = entry.currentHandle;

        // Create the new-generation handle (state = PENDING_REKEY, copying role + authorizedTokenId)
        const newHandle = new SessionCryptoHandleImpl(
            sessionId,
            newSession.generation,
            oldHandle.role,
            oldHandle.authorizedTokenId,
            newSession.trafficKeys,
            newSession.sessionSalt,
            newSession.rekeyChainKey,
            'PENDING_REKEY',
        );

        // Atomic switch (Inv 5: the encrypt path immediately uses the new generation)
        entry.currentHandle = newHandle;
        entry.previousHandle = oldHandle;

        // Start the 30s fallback window timer (Inv 5)
        entry.dualKeyTimer = setTimeout(() => {
            this._expireDualKeyWindow(sessionId);
        }, this.dualKeyFallbackMs);
    }

    /**
     * The chain_key variant of swapForDualKey: the caller provides the derivation material, and the registry derives and registers the new generation automatically
     *
     * This helper is for use by tests and the integration layer; it wraps the deriveChainKeyRekeyKeys call.
     * The production L4 wrapper may also call swapForDualKey directly (with derivation done ahead of time).
     */
    swapForDualKeyChainMode(sessionId: string): void {
        const entry = this._entries.get(sessionId);
        if (!entry) {
            throw new ProtocolError(
                'INTERNAL_ERROR',
                `swapForDualKeyChainMode: sessionId=${sessionId} not found`,
            );
        }

        // Idempotence check
        if (entry.currentHandle.state === 'PENDING_REKEY') {
            return;
        }

        const oldHandle = entry.currentHandle;
        const prevRekeyChainKey = oldHandle.getRekeyChainKey();
        const prevTrafficKeys = oldHandle.getTrafficKeys();

        // chain-key HKDF derives the next-generation traffic keys + a new rekeyChainKey
        // Note: chain-key rekey does not change session_salt
        const derived = deriveChainKeyRekeyKeys(
            prevRekeyChainKey,
            prevTrafficKeys.initToResp,
            prevTrafficKeys.respToInit,
        );

        const newSession: NewSessionData = {
            trafficKeys: {
                initToResp: derived.initToResp,
                respToInit: derived.respToInit,
            },
            sessionSalt: oldHandle._getSessionSalt(), // sessionSalt is unchanged during chain rekey
            rekeyChainKey: derived.rekeyChainKey,
            generation: oldHandle.generation + 1,
        };

        this.swapForDualKey(sessionId, newSession);
    }

    // ─── closeSession (atomic cleanup) ────────────────────────────────────────────

    /**
     * Closes a session: atomically performs cancel timer + zeroize all handles + remove entry
     *
     * Inv 6: after this call returns, lookupHandle(sessionId) immediately returns null
     * Idempotent: returns directly (no-op) when sessionId does not exist
     *
     * @param sessionId the session ID to close
     * @param reason close reason (CLOSED / TOKEN_REVOKED / REKEY_FAILED)
     */
    closeSession(sessionId: string, _reason: SessionCloseReason): void {
        const entry = this._entries.get(sessionId);
        if (!entry) return; // idempotent

        // Inv 6: atomic cleanup steps
        // 1. Cancel the timer (prevents an undefined access if the timer fires after the entry is deleted)
        if (entry.dualKeyTimer !== null) {
            clearTimeout(entry.dualKeyTimer);
            entry.dualKeyTimer = null;
        }

        // 2. Zeroize all handles (fill key material with zeros)
        entry.currentHandle.zeroize();
        if (entry.previousHandle !== null) {
            entry.previousHandle.zeroize();
        }

        // 3. Remove the registry entry (Inv 6: subsequent lookupHandle returns null immediately)
        this._entries.delete(sessionId);
    }

    // ─── Debug / test helper API ────────────────────────────────────────────────

    /** Number of currently registered sessions (for tests) */
    get size(): number {
        return this._entries.size;
    }

    /** Checks whether the given session is in PENDING_REKEY (for tests) */
    _isPendingRekey(sessionId: string): boolean {
        return (
            this._entries.get(sessionId)?.currentHandle.state ===
            'PENDING_REKEY'
        );
    }

    /** Gets the old-generation handle (for tests, to verify dual-key window state) */
    _getPreviousHandle(sessionId: string): SessionCryptoHandleImpl | null {
        return this._entries.get(sessionId)?.previousHandle ?? null;
    }

    /** Gets the current-generation handle (for tests, direct access to impl) */
    _getCurrentHandle(sessionId: string): SessionCryptoHandleImpl | null {
        return this._entries.get(sessionId)?.currentHandle ?? null;
    }

    // ─── Internal: 30s window expiry handling ─────────────────────────────────────────────

    /**
     * 30s dual-key fallback window expiry: zeroize the old generation + transition the new generation to ACTIVE
     *
     * Inv 5: after expiry the old keyId no longer routes (previousHandle set to null)
     * Inv 7: the new-generation handle's sequenceNumber was already reset to 0 at creation
     */
    private _expireDualKeyWindow(sessionId: string): void {
        const entry = this._entries.get(sessionId);
        if (!entry) return; // the session may have been closeSession'd during the window

        // Zeroize the old-generation key (PFS: old key material is zeroized immediately)
        if (entry.previousHandle !== null) {
            entry.previousHandle.zeroize();
            entry.previousHandle = null;
        }

        // Transition the new-generation handle to ACTIVE (can encrypt + decrypt normally)
        if (entry.currentHandle.state === 'PENDING_REKEY') {
            entry.currentHandle._setState('ACTIVE');
        }

        entry.dualKeyTimer = null;
    }
}
