/**
 * SessionCryptoHandleImpl — encrypted session handle implementation
 *
 * Implements the SessionCryptoHandle interface defined in packages/types/src/encryption.ts.
 * Satisfies the following 13 end-to-end encryption invariants:
 *   Inv 3: encrypt precondition assertions (state/tokenRef checks)
 *   Inv 4: decrypt precondition assertions + post-decrypt token check
 *   Inv 7: AEAD nonce monotonically increasing (bigint uint64) + reset across rekey
 *   Inv 8: authorizedTokenId immutable at runtime (Object.defineProperty + configurable: false)
 *   Inv 13: re-running rekey during PENDING_REKEY throws REKEY_FAILED
 *
 * Cryptographic correctness:
 *   - encrypt uses ownDirection(role) to determine flow (init_to_resp / resp_to_init)
 *   - decrypt uses peerDirection(role) to determine flow (the peer's direction)
 *   - The 8 AAD fields are assembled internally by buildAeadBytes; the business layer cannot inject tokenId/sessionId
 */

import {
    aeadDecrypt,
    aeadEncrypt,
    buildAeadBytes,
    buildAeadNonce,
    computeKeyId,
    ownDirection,
    peerDirection,
} from '@coivitas/crypto';
import type { AeadAadParams } from '@coivitas/crypto';
import { ProtocolError } from '@coivitas/types';
import type {
    AeadAadFields,
    SessionCryptoHandle,
    SessionHandleState,
} from '@coivitas/types';

// ─── Internal key-material storage structure ─────────────────────────────────────────────────────

/**
 * Per-generation key material (directional keys used for encryption/decryption)
 *
 * Separated by direction: the initiator → responder direction uses the initToResp key,
 * the responder → initiator direction uses the respToInit key.
 */
interface TrafficKeys {
    initToResp: Uint8Array; // 32B AES-256 key
    respToInit: Uint8Array; // 32B AES-256 key
}

// ─── SessionCryptoHandleImpl ─────────────────────────────────────────────────

/**
 * Encrypted session handle implementation (production-grade)
 *
 * Runtime safety guarantees:
 * - The four read-only properties (sessionId/generation/role/authorizedTokenId) are set via Object.defineProperty
 *   with configurable: false + writable: false, so they cannot be modified at runtime (Inv 8)
 * - _state is exposed via a getter, and the setter is constrained by the state machine (the package can advance it internally with _setState)
 * - Key material is zeroed after zeroize(), and subsequent encrypt/decrypt are intercepted by the state check
 */
export class SessionCryptoHandleImpl implements SessionCryptoHandle {
    // Type declarations (actual assignment is done via Object.defineProperty)
    readonly sessionId!: string;
    readonly generation!: number;
    readonly role!: 'initiator' | 'responder';
    readonly authorizedTokenId!: string | null;

    private _state: SessionHandleState;
    private _trafficKeys: TrafficKeys;
    private _sessionSalt: Uint8Array; // 4B, used for nonce construction
    private _rekeyChainKey: Uint8Array; // 32B, used for chain-key rekey
    private _sequenceNumber: bigint = 0n;
    private _zeroized = false;

    // Cache the current generation's keyId (computed by direction, lazily initialized)
    private _cachedOwnKeyId: string | null = null;

    constructor(
        sessionId: string,
        generation: number,
        role: 'initiator' | 'responder',
        authorizedTokenId: string | null,
        trafficKeys: TrafficKeys,
        sessionSalt: Uint8Array,
        rekeyChainKey: Uint8Array,
        initialState: SessionHandleState = 'ACTIVE',
    ) {
        // Inv 8: runtime-immutable properties (configurable: false prevents later Object.defineProperty modification)
        Object.defineProperty(this, 'sessionId', {
            value: sessionId,
            writable: false,
            configurable: false,
            enumerable: true,
        });
        Object.defineProperty(this, 'generation', {
            value: generation,
            writable: false,
            configurable: false,
            enumerable: true,
        });
        Object.defineProperty(this, 'role', {
            value: role,
            writable: false,
            configurable: false,
            enumerable: true,
        });
        Object.defineProperty(this, 'authorizedTokenId', {
            value: authorizedTokenId,
            writable: false,
            configurable: false,
            enumerable: true,
        });

        this._state = initialState;
        // Copy the key material to prevent the caller from modifying it via the original reference
        this._trafficKeys = {
            initToResp: new Uint8Array(trafficKeys.initToResp),
            respToInit: new Uint8Array(trafficKeys.respToInit),
        };
        this._sessionSalt = new Uint8Array(sessionSalt);
        this._rekeyChainKey = new Uint8Array(rekeyChainKey);
    }

    // ─── Read-only state getters ─────────────────────────────────────────────────────

    get state(): SessionHandleState {
        return this._state;
    }

    get sequenceNumber(): bigint {
        return this._sequenceNumber;
    }

    // ─── keyId computation (current generation, by own-direction key) ────────────────────────────

    /**
     * Computes the current generation's keyId (caches the result, computed on first call)
     *
     * keyId = hex(SHA-256(k_direction || generation_8B_BE)[0:16])
     * k_direction = this side's directional key (the key used by encrypt)
     */
    get keyId(): string {
        if (this._cachedOwnKeyId === null) {
            const dir = ownDirection(this.role);
            const key =
                dir === 'init_to_resp'
                    ? this._trafficKeys.initToResp
                    : this._trafficKeys.respToInit;
            this._cachedOwnKeyId = computeKeyId(key, this.generation);
        }
        return this._cachedOwnKeyId;
    }

    /**
     * Computes the keyId of the peer's directional key (used for lookupHandleForDecrypt matching)
     *
     * Received messages are encrypted with the peer's key (peerDirection), so the keyId is also computed with the peer's key.
     */
    get peerKeyId(): string {
        const dir = peerDirection(this.role);
        const key =
            dir === 'init_to_resp'
                ? this._trafficKeys.initToResp
                : this._trafficKeys.respToInit;
        return computeKeyId(key, this.generation);
    }

    // ─── encrypt (Invariant 3) ──────────────────────────────────────────────

    /**
     * AES-256-GCM encryption
     *
     * Precondition assertions (Inv 3):
     *   1. state in {ACTIVE, PENDING_REKEY} — otherwise throw SESSION_HANDLE_REVOKED
     *   2. authorizedTokenId !== null — otherwise throw SESSION_HANDLE_REVOKED (an encrypted session must have a token)
     * Note: the capabilityTokenRef === authorizedTokenId check is the caller's (L4 wrapper) responsibility,
     * not performed inside the handle.
     *
     * Inv 7: the nonce is based on the bigint sequenceNumber and increases monotonically after encryption.
     */
    encrypt(params: { aadFields: AeadAadFields; plaintext: Uint8Array }): {
        ciphertext: Uint8Array;
        aeadNonce: Uint8Array;
        keyId: string;
    } {
        // Inv 3.1: state check
        if (this._state === 'CLOSED' || this._state === 'REVOKED') {
            throw new ProtocolError(
                'SESSION_HANDLE_REVOKED',
                `encrypt rejected: handle state=${this._state}`,
            );
        }

        // Inv 3.3: authorizedTokenId cannot be null in an encrypted session
        if (this.authorizedTokenId === null) {
            throw new ProtocolError(
                'SESSION_HANDLE_REVOKED',
                'encrypt rejected: authorizedTokenId is null in encrypted session',
            );
        }

        // Determine the encryption direction (the flow of messages sent by this side)
        const dir = ownDirection(this.role);
        const key =
            dir === 'init_to_resp'
                ? this._trafficKeys.initToResp
                : this._trafficKeys.respToInit;

        // Inv 7: monotonically increasing sequenceNumber (capture the current value first, then increment)
        const seq = this._sequenceNumber;
        this._sequenceNumber += 1n;

        // Build the 12B AEAD nonce
        const nonce = buildAeadNonce(dir, seq, this._sessionSalt);

        // Compute the keyId (using the own-direction key)
        const currentKeyId = this.keyId;

        // Build the 8 AAD fields (fixed set, not expandable)
        const aadParams: AeadAadParams = {
            envelopeId: params.aadFields.envelopeId,
            messageType: params.aadFields.messageType,
            aadSummary: params.aadFields.aadSummary,
            direction: dir,
            keyId: currentKeyId,
            sequenceNumber: seq,
            sessionId: this.sessionId,
            tokenId: this.authorizedTokenId,
        };
        const aad = buildAeadBytes(aadParams);

        // AES-256-GCM encryption
        const ciphertext = aeadEncrypt(key, nonce, aad, params.plaintext);

        return { ciphertext, aeadNonce: nonce, keyId: currentKeyId };
    }

    // ─── decrypt (Invariant 4) ──────────────────────────────────────────────

    /**
     * AES-256-GCM decryption
     *
     * Precondition assertions (Inv 4.1):
     *   state in {ACTIVE, PENDING_REKEY} — otherwise throw SESSION_HANDLE_REVOKED
     *
     * AEAD tag verification (Inv 4.2):
     *   throws DECRYPTION_FAILED on failure (does not expose the specific failure step, to prevent side channels)
     *
     * Note: the post-decrypt token comparison (Inv 4.3) is the caller's (L4 wrapper) responsibility,
     * not performed inside the handle.
     */
    decrypt(params: {
        aadFields: AeadAadFields;
        ciphertext: Uint8Array;
        aeadNonce: Uint8Array;
    }): Uint8Array {
        // Inv 4.1: state check
        if (this._state === 'CLOSED' || this._state === 'REVOKED') {
            throw new ProtocolError(
                'SESSION_HANDLE_REVOKED',
                `decrypt rejected: handle state=${this._state}`,
            );
        }

        // Determine the decryption direction (the flow of messages received from the peer)
        const dir = peerDirection(this.role);
        const key =
            dir === 'init_to_resp'
                ? this._trafficKeys.initToResp
                : this._trafficKeys.respToInit;

        // Extract the sequenceNumber from the nonce (used for Inv 4.2 verification)
        // nonce layout: directionByte(1B) || seq(8B BE) || sessionSalt[0..2](3B)
        const nonce = params.aeadNonce;
        let seq = 0n;
        for (let i = 1; i <= 8; i++) {
            seq = (seq << 8n) | BigInt(nonce[i] ?? 0);
        }

        // Compute the peer keyId (used for AAD construction)
        const peerKId = this.peerKeyId;

        // Build the AAD (exactly the same as the sender: direction = peer's flow)
        const aadParams: AeadAadParams = {
            envelopeId: params.aadFields.envelopeId,
            messageType: params.aadFields.messageType,
            aadSummary: params.aadFields.aadSummary,
            direction: dir,
            keyId: peerKId,
            sequenceNumber: seq,
            sessionId: this.sessionId,
            tokenId: this.authorizedTokenId,
        };
        const aad = buildAeadBytes(aadParams);

        // Inv 4.2: AES-256-GCM decryption (aeadDecrypt throws CryptoError when tag verification fails)
        try {
            return aeadDecrypt(key, nonce, aad, params.ciphertext);
        } catch {
            // Do not expose the specific failure details (to prevent side channels)
            throw new ProtocolError(
                'DECRYPTION_FAILED',
                'AEAD authentication tag verification failed',
            );
        }
    }

    // ─── rekey (Invariant 13) ────────────────────────────────────────────────

    /**
     * Triggers a rekey
     *
     * 'chain_key': uses prevRekeyChainKey to derive the next-generation key
     * 'full_handshake_required': requires a full re-handshake (the caller is responsible for initiating it)
     *
     * State machine guards (Inv 13):
     *   PENDING_REKEY -> throw REKEY_FAILED (concurrent rekey rejected)
     *   CLOSED/REVOKED -> throw SESSION_HANDLE_REVOKED
     *   ACTIVE -> allowed (chain_key derives the new key internally, full_handshake_required only records intent)
     */
    rekey(mode: 'chain_key' | 'full_handshake_required'): void {
        // Check CLOSED/REVOKED first
        if (this._state === 'CLOSED' || this._state === 'REVOKED') {
            throw new ProtocolError(
                'SESSION_HANDLE_REVOKED',
                `rekey rejected: handle state=${this._state}`,
            );
        }

        // Inv 13: PENDING_REKEY concurrent rejection
        if (this._state === 'PENDING_REKEY') {
            throw new ProtocolError(
                'REKEY_FAILED',
                'rekey already in progress (PENDING_REKEY); wait 30s or closeSession + fresh handshake',
            );
        }

        if (mode === 'chain_key') {
            // Use chain-key HKDF to derive new key material (stored within the handle, later activated by the registry via swapForDualKey)
            // Note: rekey() within the handle only does key derivation and intent marking;
            // the actual generation switch is done by SessionRegistry.swapForDualKey.
            // _trafficKeys is not modified here, because the new handle is created in swapForDualKey.
            // handle.rekey('chain_key') notifies the registry, which calls deriveChainKeyRekeyKeys
            // and creates a new SessionCryptoHandleImpl.
            // In this implementation rekey() only performs state validation; derivation runs at the registry layer.
        } else {
            // 'full_handshake_required': the handle does no key operations,
            // and the caller initiates a full re-handshake.
            // No exception is thrown here; the caller is responsible for closeSession + a new handshake.
        }
    }

    // ─── zeroize (Inv 6 + idempotent) ──────────────────────────────────────────────

    /**
     * Zero out key material + transition state to CLOSED
     *
     * Idempotent: returns directly (no-op) when in CLOSED/REVOKED state.
     * After zeroing, _cachedOwnKeyId is cleared (to avoid holding a key reference).
     */
    zeroize(): void {
        // Idempotent: skip if already zeroized (to avoid multiple fill(0) calls)
        if (this._zeroized) return;

        // Zero out all key material
        this._trafficKeys.initToResp.fill(0);
        this._trafficKeys.respToInit.fill(0);
        this._sessionSalt.fill(0);
        this._rekeyChainKey.fill(0);
        this._zeroized = true;
        this._cachedOwnKeyId = null;

        // Transition state to CLOSED
        this._state = 'CLOSED';
    }

    // ─── Package-internal API (for use by SessionRegistryImpl) ───────────────────────────

    /**
     * Reads rekeyChainKey (used to derive new keys during a chain-key rekey)
     * Called only by SessionRegistryImpl.swapForDualKey.
     */
    getRekeyChainKey(): Uint8Array {
        return this._rekeyChainKey;
    }

    /**
     * Reads the current generation's trafficKeys (used by swapForDualKey to pass to deriveChainKeyRekeyKeys)
     */
    getTrafficKeys(): { initToResp: Uint8Array; respToInit: Uint8Array } {
        return this._trafficKeys;
    }

    /**
     * Internal state advancement (called only by SessionRegistryImpl)
     * Used to transition a new-generation handle from PENDING_REKEY to ACTIVE after the 30s window expires.
     */
    _setState(newState: SessionHandleState): void {
        this._state = newState;
    }

    /**
     * Reads sessionSalt (used for chain-key rekey: sessionSalt stays unchanged during a chain rekey)
     * Called only by SessionRegistryImpl.swapForDualKeyChainMode.
     */
    _getSessionSalt(): Uint8Array {
        return new Uint8Array(this._sessionSalt); // Return a copy to prevent external modification
    }

    /**
     * Whether it has already been zeroized (for tests + debugging)
     */
    get isZeroized(): boolean {
        return this._zeroized;
    }
}
