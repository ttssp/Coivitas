/**
 * E2E encryption type definitions
 *
 * Field names/types are frozen.
 * Key invariants: the 12+1 invariants, no sessionTrustDomain, the AAD 8-field set cannot expand.
 *
 * This file contains:
 *   - EncryptedBody: encrypted envelope body shape
 *   - MessageReceipt: non-repudiation receipt
 *   - SessionCryptoHandle: encrypted session handle (runtime interface)
 *   - SessionRegistry: encrypted session registry (runtime interface)
 *   - SessionHandleState: encrypted handle state enum
 *   - SessionCloseReason: close-reason enum
 *   - AeadAadFields: business-layer AAD submission fields
 *   - NewSessionData: swapForDualKey new-generation construction parameters
 *
 * Impact of the 12 invariants:
 *   - Inv 1-6: semantic contract of the SessionRegistry interface
 *   - Inv 7: AEAD nonce construction is guaranteed internally by SessionCryptoHandle.encrypt
 *   - Inv 8: token rotation does not switch in-place inside the handle
 *   - Inv 9: timing of the sender Receipt write
 *   - Inv 10: handshake/business specVersion boundary (not constrained in this file)
 *   - Inv 11: explicit list of impossible wire states (not constrained in this file)
 *   - Inv 12: sessionTrustDomain does not exist
 *   - Inv 13: handling of concurrent rekey triggers
 */

import type { Timestamp } from './base.js';

// ---------------------------------------------------------------------------
// EncryptedBody — encrypted envelope body shape
// ---------------------------------------------------------------------------

/**
 * Encrypted envelope body structure
 *
 * This shape is used when NegotiationEnvelope.body is an encrypted carrier.
 * body.encrypted === true is the type-guard criterion.
 *
 * @breaking no (internal body structure, does not touch the frozen wire-format)
 * @frozen frozen
 */
export interface EncryptedBody {
    /** marks this body as an encrypted carrier (literal true)*/
    readonly encrypted: true;

    /** protocol version (the only valid value)*/
    readonly encryptionProtocolVersion: 'ap/e2e/v1';

    /**
     * carrier type:
     * - 'BUSINESS': carries business plaintext
     * - 'RECEIPT': carries a MessageReceipt
     * Mandatory under an encrypted session; missing → INVALID_ENCRYPTED_BODY
     */
    readonly type: 'BUSINESS' | 'RECEIPT';

    /** AEAD ciphertext (includes the GCM authentication tag, hex or base64url)*/
    readonly ciphertext: string;

    /** AEAD nonce (12B, hex or base64url)*/
    readonly aeadNonce: string;

    /**
     * Session key identifier
     * first 16 bytes of SHA-256(k_{direction} || generation) hex = 32 hex chars
     * 128-bit provides a 2^64 birthday-collision budget
     */
    readonly keyId: string;

    /** digest of business fields in the AAD (protected by the AEAD tag but visible in plaintext)*/
    readonly aadSummary?: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// MessageReceipt — non-repudiation receipt
// ---------------------------------------------------------------------------

/**
 * The receiver's non-repudiation commitment to a decrypted envelope
 *
 * Signed payload = canonicalize({ackEnvelopeId, sessionId, paramsHash,
 *   auditIntentId, receivedAt}), i.e. the RFC 8785 canonicalized JSON bytes of the first 5 fields.
 *
 * @breaking no (internal body structure)
 * @frozen frozen
 */
export interface MessageReceipt {
    /** the acknowledged envelope id*/
    readonly ackEnvelopeId: string;

    /** session id*/
    readonly sessionId: string;

    /** SHA-256(canonicalize(decrypted_params))*/
    readonly paramsHash: string;

    /**
     * audit intent id returned by beforeExecute.
     * receiver-local audit anchor;
     * cross-organization query anchor is deferred to a later release
     */
    readonly auditIntentId: string;

    /** time the Responder issued the receipt (ISO 8601)*/
    readonly receivedAt: Timestamp;

    /**
     * Ed25519 signature, using the receiver identity key (not the session key).
     * Signed payload = canonicalize({ackEnvelopeId, sessionId, paramsHash,
     *   auditIntentId, receivedAt})
     */
    readonly receiptSignature: string;
}

// ---------------------------------------------------------------------------
// SessionHandleState — encrypted handle state enum
// ---------------------------------------------------------------------------

/**
 * Encrypted handle state enum
 *
 * Four-state state machine, corresponding to the state-operation matrix.
 *
 * @frozen frozen
 */
export type SessionHandleState =
    | 'ACTIVE'
    | 'PENDING_REKEY'
    | 'CLOSED'
    | 'REVOKED';

// ---------------------------------------------------------------------------
// AeadAadFields — business-layer AAD submission fields
// ---------------------------------------------------------------------------

/**
 * AAD fields submitted by the business layer to the crypto layer
 *
 * Must not contain handle-authoritative fields such as tokenRef/tokenId/sessionId/direction
 * (these are injected internally by the crypto layer into the AAD 8-field set; cannot expand).
 *
 * @frozen frozen
 */
export interface AeadAadFields {
    /** envelope ID (from NegotiationEnvelope.id)*/
    readonly envelopeId: string;

    /** message type (from NegotiationEnvelope.messageType)*/
    readonly messageType: string;

    /**
     * business plaintext digest;
     * must not contain handle-authoritative fields such as tokenRef/tokenId/sessionId/direction
     */
    readonly aadSummary?: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// SessionCryptoHandle — encrypted session handle
// ---------------------------------------------------------------------------

/**
 * Encrypted session handle (runtime interface)
 *
 * Each encrypted session holds a unique handle in the SessionRegistry.
 * The business layer does not cache handle references (Inv 2).
 *
 * @breaking N/A (runtime interface, does not enter the wire format)
 * @frozen frozen
 *
 * Impact of the 12 invariants:
 *   - Inv 2: the caller does not cache handle references
 *   - Inv 3: encrypt preconditions (state/tokenRef)
 *   - Inv 4: decrypt preconditions + post-decrypt check
 *   - Inv 7: AEAD nonce monotonically increasing + reset across rekey
 *   - Inv 8: authorizedTokenId readonly (cannot switch in-place)
 *   - Inv 12: no sessionTrustDomain field
 *   - Inv 13: rekey again while PENDING_REKEY -> REKEY_FAILED
 */
export interface SessionCryptoHandle {
    /** session ID (bound at construction, immutable)*/
    readonly sessionId: string;

    /** key generation (monotonically increasing; +1 on rekey)*/
    readonly generation: number;

    /** role (initiator or responder)*/
    readonly role: 'initiator' | 'responder';

    /**
     * the bound CapabilityToken ID
     * must be non-null for an encrypted session; null is allowed for a non-encrypted session or the transition period
     * Inv 8: immutable after construction (cannot switch in-place)
     */
    readonly authorizedTokenId: string | null;

    /** current state (four-state enum)*/
    readonly state: SessionHandleState;

    /**
     * AEAD encryption
     *
     * Preconditions (Inv 3):
     *   1. state in {ACTIVE, PENDING_REKEY}
     *   2. capabilityTokenRef === authorizedTokenId
     *   3. authorizedTokenId !== null (encrypted session)
     */
    encrypt(params: { aadFields: AeadAadFields; plaintext: Uint8Array }): {
        ciphertext: Uint8Array;
        aeadNonce: Uint8Array;
        keyId: string;
    };

    /**
     * AEAD decryption
     *
     * Preconditions (Inv 4):
     *   1. state in {ACTIVE, PENDING_REKEY}
     *   2. AEAD tag verification passes
     *   3. post-decrypt: capabilityTokenRef === authorizedTokenId
     */
    decrypt(params: {
        aadFields: AeadAadFields;
        ciphertext: Uint8Array;
        aeadNonce: Uint8Array;
    }): Uint8Array;

    /**
     * Trigger a rekey
     *
     * - 'chain_key': same-generation key-chain rotation (Inv 13: throws REKEY_FAILED while PENDING_REKEY)
     * - 'full_handshake_required': triggers a full re-handshake
     */
    rekey(mode: 'chain_key' | 'full_handshake_required'): void;

    /**
     * Zeroize key material + transition state to CLOSED/REVOKED
     * idempotent; no-op when CLOSED/REVOKED
     */
    zeroize(): void;
}

// ---------------------------------------------------------------------------
// SessionCloseReason — close-reason enum
// ---------------------------------------------------------------------------

/**
 * Close reason for SessionRegistry.closeSession
 *
 * @frozen frozen
 */
export type SessionCloseReason = 'CLOSED' | 'TOKEN_REVOKED' | 'REKEY_FAILED';

// ---------------------------------------------------------------------------
// NewSessionData — swapForDualKey new-generation construction parameters
// ---------------------------------------------------------------------------

/**
 * New-generation session construction parameters required by swapForDualKey
 *
 * @frozen frozen
 */
export interface NewSessionData {
    /** new-generation AES-256 traffic keys (both directions)*/
    readonly trafficKeys: {
        readonly initToResp: Uint8Array;
        readonly respToInit: Uint8Array;
    };

    /** new-generation session salt (4B)*/
    readonly sessionSalt: Uint8Array;

    /** new-generation rekey chain key (32B)*/
    readonly rekeyChainKey: Uint8Array;

    /** new-generation generation (previous generation + 1)*/
    readonly generation: number;
}

// ---------------------------------------------------------------------------
// SessionRegistry — encrypted session registry
// ---------------------------------------------------------------------------

/**
 * Encrypted session registry (runtime interface)
 *
 * Manages the lifecycle of SessionCryptoHandle.
 * The implementation must satisfy the 13 invariants.
 *
 * @breaking N/A (runtime interface, does not enter the wire format)
 * @frozen frozen
 *
 * Full coverage of the 12+1 invariants:
 *   - Inv 1: unique index (sessionId -> handle 1:1)
 *   - Inv 2: the caller does not cache references
 *   - Inv 5: dual-key fallback window of 30s
 *   - Inv 6: lookup fail-fast after close
 *   - Inv 13: concurrent rekey rejection
 */
export interface SessionRegistry {
    /**
     * encrypt path: returns the current-generation handle
     *
     * Returns null if the session is already closed/revoked (Inv 6).
     * Returns the new-generation handle while PENDING_REKEY (Inv 5).
     *
     * @param sessionId session ID
     * @returns current-generation handle or null
     */
    lookupHandle(sessionId: string): SessionCryptoHandle | null;

    /**
     * decrypt path: exact routing by keyId
     *
     * Falling back to lookupHandle is forbidden, trial-and-error is forbidden (Inv 4).
     * Returning null -> the caller directly throws DECRYPTION_FAILED.
     *
     * @param sessionId session ID
     * @param keyId the keyId field in the ciphertext
     * @returns matching handle or null
     */
    lookupHandleForDecrypt(
        sessionId: string,
        keyId: string,
    ): SessionCryptoHandle | null;

    /**
     * start the dual-key fallback window (30s); idempotent (Inv 5)
     *
     * @param sessionId the session ID to switch
     * @param newSession new-generation construction parameters
     */
    swapForDualKey(sessionId: string, newSession: NewSessionData): void;

    /**
     * close the session: atomically transition the handle state to CLOSED + zeroize + remove from registry (Inv 6)
     *
     * @param sessionId the session ID to close
     * @param reason close reason
     */
    closeSession(sessionId: string, reason: SessionCloseReason): void;
}
