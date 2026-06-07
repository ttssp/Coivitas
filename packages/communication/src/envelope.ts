import { randomUUID } from 'node:crypto';

import type {
    AeadAadFields,
    DID,
    EncryptedBody,
    MessageType,
    NegotiationEnvelope,
    SessionRegistry,
    Signature,
    Timestamp,
} from '@coivitas/types';
import {
    ProtocolError,
    SPEC_VERSION,
    SPEC_VERSION_0_2_0,
    SPEC_VERSION_0_3_0,
    SUPPORTED_SPEC_VERSIONS,
    MESSAGE_TYPES,
} from '@coivitas/types';
import { canonicalize, sign, verify } from '@coivitas/crypto';
import { isDidAgent, isDidKey } from '@coivitas/identity';
import { ENVELOPE_ENCODING } from './encoding-config.js';

// ─── SequenceNumber replay tracker ─────────────────────────────────────

// Tracks the highest seen sequenceNumber per (sessionId, directionByte, keyId).

// Design: a module-level Map holds in-process state; callers may reset it
// between tests via _clearReplayTracker() (a test helper, not part of the public API exports).

// Regression fix:
// An earlier implementation keyed only on (sessionId, directionByte), but after
// rekey/swapForDualKey, SessionCryptoHandleImpl resets sequenceNumber to 0. The first
// frame of the new generation (seq=0) then fell into the (seq <= maxSeen) branch and
// was wrongly flagged as ENCRYPTED_REPLAY_DETECTED.

// Fix: include keyId in the replay key — SessionRegistry guarantees a unique keyId per
// generation (keyId = hex(SHA-256(k_direction || generation_8B_BE)[0:16])), so the
// (sessionId, directionByte, keyId) triple automatically starts a fresh seq count after a rekey.

// Note: in a distributed environment, this module-level Map must be replaced with an
// external store (Redis/PG); this implementation satisfies the intra-org single-process requirement.

const _replayTracker: Map<string, bigint> = new Map();

/**
 * Builds the replay-tracking key: sessionId + direction byte (nonce[0]) + keyId (distinguishes generations)
 * nonce layout: directionByte(1B) || seq(8B BE) || sessionSalt[0..2](3B)
 */
function _replayKey(
    sessionId: string,
    nonceByte0: number,
    keyId: string,
): string {
    return `${sessionId}:${nonceByte0}:${keyId}`;
}

/**
 * Extracts the sequenceNumber (bytes[1..8] BE) from a 12B AEAD nonce (hex or base64url)
 * Returns a bigint; throws ProtocolError('INVALID_ENCRYPTED_BODY', ...) on decode failure
 */
function _extractSequenceNumber(aeadNonce: string): {
    seq: bigint;
    directionByte: number;
    nonce: Uint8Array;
} {
    let bytes: Uint8Array;
    try {
        if (/^[0-9a-f]{24}$/i.test(aeadNonce)) {
            // 12B hex = 24 chars
            bytes = new Uint8Array(12);
            for (let i = 0; i < 12; i++) {
                bytes[i] = parseInt(aeadNonce.slice(i * 2, i * 2 + 2), 16);
            }
        } else {
            // base64url (16 chars = 12B)
            const bin = Buffer.from(aeadNonce, 'base64url');
            if (bin.length !== 12) {
                throw new Error(`nonce length ${bin.length} !== 12`);
            }
            bytes = new Uint8Array(bin);
        }
    } catch (e) {
        throw new ProtocolError(
            'INVALID_ENCRYPTED_BODY',
            `Invalid aeadNonce format: ${e instanceof Error ? e.message : String(e)}`,
        );
    }
    const directionByte = bytes[0]!;
    let seq = 0n;
    for (let i = 1; i <= 8; i++) {
        seq = (seq << 8n) | BigInt(bytes[i] ?? 0);
    }
    return { seq, directionByte, nonce: bytes };
}

/** Test helper: resets the replay tracker (not exported from index.ts) */
export function _clearReplayTracker(): void {
    _replayTracker.clear();
}

/**
 * Decodes an EncryptedBody field (hex or base64url).
 * The schema for EncryptedBody.ciphertext / aeadNonce is anyOf [hex, base64url],
 * so the format must be detected rather than assumed to be hex. The detection rule matches _extractSequenceNumber:
 *   - all hex characters (even length) → hex
 *   - otherwise → base64url
 * Decode failures are wrapped by the caller into ProtocolError('INVALID_ENCRYPTED_BODY', ...).
 */
function _decodeEncryptedField(value: string): Uint8Array {
    if (/^[0-9a-f]+$/i.test(value) && value.length % 2 === 0) {
        return new Uint8Array(Buffer.from(value, 'hex'));
    }
    return new Uint8Array(Buffer.from(value, 'base64url'));
}

// ─── Encrypted envelope body path + anti-replay parameter types ──────────────────────

/**
 * Input parameters for encryptEnvelopeBody
 *
 */
export interface EncryptEnvelopeBodyParams {
    /** Session registry (provides lookupHandle) */
    registry: SessionRegistry;
    /** Session ID */
    sessionId: string;
    /**
     * The capabilityTokenRef from the envelope header;
     * Inv 3.2: must match handle.authorizedTokenId (an L4 wrapper responsibility)
     */
    capabilityTokenRef: string;
    /** Business-layer AAD fields (envelopeId + messageType + optional aadSummary) */
    aadFields: AeadAadFields;
    /** Plaintext bytes to encrypt */
    plaintext: Uint8Array;
    /**
     * body type: 'BUSINESS' | 'RECEIPT'
     * It carries no meaning on the encrypt side when absent, but type must be passed explicitly (Inv 11)
     */
    bodyType: 'BUSINESS' | 'RECEIPT';
}

/**
 * Input parameters for decryptEnvelopeBody
 *
 */
export interface DecryptEnvelopeBodyParams {
    /** Session registry (provides lookupHandleForDecrypt) */
    registry: SessionRegistry;
    /** Session ID */
    sessionId: string;
    /** The EncryptedBody to decrypt (from NegotiationEnvelope.body) */
    body: EncryptedBody;
    /** Business-layer AAD fields (envelopeId + messageType + optional aadSummary) */
    aadFields: AeadAadFields;
    /**
     * The capabilityTokenRef from the envelope header;
     * Inv 4.3 post-decrypt: must match handle.authorizedTokenId (an L4 wrapper responsibility)
     */
    capabilityTokenRef: string;
}

export interface BuildEnvelopeParams {
    senderDid: DID;
    /** Ed25519 private key, hex-encoded (32-byte or 64-byte extended format) */
    senderPrivateKey: string;
    recipientDid: DID;
    sessionId: string | null;
    messageType: MessageType;
    body: Record<string, unknown>;
    sequenceNumber?: number;
    /** capabilityTokenRef field (specVersion 0.2.0), included in the signature coverage */
    capabilityTokenRef?: string;
    /** Signature output encoding, defaults to hex (consistent with the v0.1.0 wire format baseline) */
    signatureEncoding?: 'hex' | 'base64url';
    /**
     * Explicitly specify specVersion to build a v0.3.0 envelope
     * (required for v0.3.0-only message types such as DISCOVERY_REQUEST / DISCOVERY_RESPONSE).
     *
     * When omitted, it is inferred by the existing rule: capabilityTokenRef present → '0.2.0'; otherwise SPEC_VERSION ('0.1.0').
     */
    specVersion?: '0.1.0' | '0.2.0' | '0.3.0';
}

export interface EnvelopeVerificationResult {
    valid: boolean;
    reason?: string;
}

export interface VerifyEnvelopeOptions {
    /** Resolves the sender's public key (hex) by DID; returns null if not found */
    resolvePublicKey: (did: DID) => Promise<string | null>;
    /** Allowed clock skew (milliseconds, default 300_000 = 5 minutes) */
    clockSkewMs?: number;
    /** Current time (injectable, defaults to Date.now()) */
    now?: () => number;
}

/**
 * Builds and signs a NegotiationEnvelope
 *
 * Signed object: the full envelope with the signature field removed (RFC 8785 canonicalization)
 *
 * @throws ProtocolError('INTERNAL_ERROR', ...) if signing fails
 */
export function buildEnvelope(
    params: BuildEnvelopeParams,
): NegotiationEnvelope {
    const id = randomUUID();
    const timestamp = new Date().toISOString() as Timestamp;

    const header = {
        senderDid: params.senderDid,
        recipientDid: params.recipientDid,
        sessionId: params.sessionId,
        ...(params.sequenceNumber !== undefined
            ? { sequenceNumber: params.sequenceNumber }
            : {}),
        ...(params.capabilityTokenRef !== undefined
            ? { capabilityTokenRef: params.capabilityTokenRef }
            : {}),
    };

    // Explicit params.specVersion takes precedence;
    // otherwise keep the original inference (capabilityTokenRef → 0.2.0; otherwise SPEC_VERSION)
    const inferredSpecVersion =
        params.capabilityTokenRef !== undefined
            ? SPEC_VERSION_0_2_0
            : SPEC_VERSION;
    const effectiveSpecVersion = params.specVersion ?? inferredSpecVersion;

    const signedPayload = {
        id,
        specVersion: effectiveSpecVersion,
        header,
        messageType: params.messageType,
        body: params.body,
        timestamp,
    };

    let signature: Signature;
    try {
        const canonical = canonicalize(signedPayload);
        const bytes = new TextEncoder().encode(canonical);
        // specVersion encoding compatibility matrix:
        // the v0.1.0 path defaults to hex (the v0.1.0 wire format baseline is unchanged);
        // the v0.2.0 / v0.3.0 paths default to base64url.
        // Callers may override explicitly via the signatureEncoding parameter (for backward-compatibility testing).
        // Regression fix: the original implementation switched to base64url only for v0.3.0, but the
        // compatibility matrix mandates that from v0.2.0 onward all NegotiationEnvelope.signature values default to base64url.
        // Otherwise v0.2.0 envelopes still emit hex and the encoding switch never takes effect.
        const v = signedPayload.specVersion as string;
        const defaultEncoding =
            v === SPEC_VERSION_0_3_0 || v === SPEC_VERSION_0_2_0
                ? ENVELOPE_ENCODING
                : 'hex';
        const encoding = params.signatureEncoding ?? defaultEncoding;
        signature = sign(bytes, params.senderPrivateKey, encoding) as Signature;
    } catch (error) {
        throw new ProtocolError(
            'INTERNAL_ERROR',
            `Envelope signing failed: ${error instanceof Error ? error.message : String(error)}`,
        );
    }

    return {
        ...signedPayload,
        signature,
    };
}

/**
 * Parses raw data into a NegotiationEnvelope
 *
 * @throws ProtocolError('INVALID_MESSAGE', '...') if the format is invalid
 */
export function parseEnvelope(raw: unknown): NegotiationEnvelope {
    if (!raw || typeof raw !== 'object') {
        throw new ProtocolError('INVALID_MESSAGE', 'Envelope must be an object');
    }

    const obj = raw as Record<string, unknown>;

    if (!obj['id'] || typeof obj['id'] !== 'string') {
        throw new ProtocolError('INVALID_MESSAGE', 'Envelope is missing a valid id field');
    }

    if (!obj['specVersion'] || typeof obj['specVersion'] !== 'string') {
        throw new ProtocolError(
            'INVALID_MESSAGE',
            'Envelope is missing a valid specVersion field',
        );
    }
    if (!/^\d+\.\d+\.\d+$/.test(obj['specVersion'])) {
        throw new ProtocolError(
            'SPEC_VERSION_MISMATCH',
            `Invalid specVersion format: ${obj['specVersion']}`,
        );
    }

    if (!obj['header'] || typeof obj['header'] !== 'object') {
        throw new ProtocolError(
            'INVALID_MESSAGE',
            'Envelope is missing a valid header field',
        );
    }

    const header = obj['header'] as Record<string, unknown>;
    if (!header['senderDid'] || typeof header['senderDid'] !== 'string') {
        throw new ProtocolError(
            'INVALID_MESSAGE',
            'header is missing a valid senderDid',
        );
    }
    if (!isDidAgent(header['senderDid']) && !isDidKey(header['senderDid'])) {
        throw new ProtocolError(
            'INVALID_MESSAGE',
            `header senderDid is not a valid DID: ${header['senderDid']}`,
        );
    }
    if (!header['recipientDid'] || typeof header['recipientDid'] !== 'string') {
        throw new ProtocolError(
            'INVALID_MESSAGE',
            'header is missing a valid recipientDid',
        );
    }
    if (
        !isDidAgent(header['recipientDid']) &&
        !isDidKey(header['recipientDid'])
    ) {
        throw new ProtocolError(
            'INVALID_MESSAGE',
            `header recipientDid is not a valid DID: ${header['recipientDid']}`,
        );
    }

    if (
        typeof obj['messageType'] !== 'string' ||
        !MESSAGE_TYPES.includes(obj['messageType'] as MessageType)
    ) {
        throw new ProtocolError(
            'INVALID_MESSAGE',
            `Invalid messageType: ${String(obj['messageType'])}`,
        );
    }

    if (!obj['body'] || typeof obj['body'] !== 'object') {
        throw new ProtocolError('INVALID_MESSAGE', 'Envelope is missing a valid body field');
    }

    if (!obj['signature'] || typeof obj['signature'] !== 'string') {
        throw new ProtocolError(
            'INVALID_MESSAGE',
            'Envelope is missing a valid signature field',
        );
    }

    if (!obj['timestamp'] || typeof obj['timestamp'] !== 'string') {
        throw new ProtocolError(
            'INVALID_MESSAGE',
            'Envelope is missing a valid timestamp field',
        );
    }

    // Version gate: capabilityTokenRef is a breaking-format-change field (specVersion 0.2.0) that
    // must use specVersion "0.2.0"; it must not appear in envelopes of other versions (0.1.0 / 0.3.0 / future).
    // Regression fix: the original code's inverted check (=== SPEC_VERSION = 0.1.0) let 0.3.0 slip through,
    // letting a v0.3.0 envelope carry capabilityTokenRef past the gate and bypass the design intent.
    if (
        header['capabilityTokenRef'] !== undefined &&
        obj['specVersion'] !== SPEC_VERSION_0_2_0
    ) {
        throw new ProtocolError(
            'SPEC_VERSION_MISMATCH',
            `The capabilityTokenRef field requires specVersion 0.2.0, but it is ${obj['specVersion']}`,
        );
    }

    return raw as NegotiationEnvelope;
}

/**
 * Verifies an envelope's signature and timestamp
 *
 * Verification steps:
 * 1. Check that specVersion ∈ SUPPORTED_SPEC_VERSIONS (fail-closed:
 *    any version not in the supported set is rejected; "forward-compatible pass-through" for a future minor would bypass the wire trust boundary)
 * 2. Verify the timestamp falls within now ± clockSkewMs
 * 3. Resolve the public key for header.senderDid
 * 4. Rebuild signed_payload (with the signature field removed)
 * 5. Verify the Ed25519 signature
 */
export async function verifyEnvelope(
    envelope: NegotiationEnvelope,
    options: VerifyEnvelopeOptions,
): Promise<EnvelopeVerificationResult> {
    const clockSkewMs = options.clockSkewMs ?? 300_000;
    const now = options.now?.() ?? Date.now();

    // 1) specVersion must be present and exactly equal to one of SUPPORTED_SPEC_VERSIONS
    const specVersion = envelope.specVersion;
    if (typeof specVersion !== 'string' || specVersion.length === 0) {
        return {
            valid: false,
            reason: `Envelope is missing a valid specVersion field`,
        };
    }
    if (!(SUPPORTED_SPEC_VERSIONS as readonly string[]).includes(specVersion)) {
        return {
            valid: false,
            reason: `Incompatible specVersion: ${specVersion} (supported range: ${SUPPORTED_SPEC_VERSIONS.join(
                ', ',
            )})`,
        };
    }

    const envelopeTime = new Date(envelope.timestamp).getTime();
    if (!isFinite(envelopeTime) || Math.abs(envelopeTime - now) > clockSkewMs) {
        return {
            valid: false,
            reason: `Clock skew exceeds the allowed range (±${clockSkewMs}ms)`,
        };
    }

    const publicKey = await options.resolvePublicKey(envelope.header.senderDid);

    if (!publicKey) {
        return {
            valid: false,
            reason: `Unable to resolve the public key for senderDid: ${envelope.header.senderDid}`,
        };
    }

    const signedPayload = {
        id: envelope.id,
        specVersion: envelope.specVersion,
        header: envelope.header,
        messageType: envelope.messageType,
        body: envelope.body,
        timestamp: envelope.timestamp,
    };

    try {
        const canonical = canonicalize(signedPayload);
        const bytes = new TextEncoder().encode(canonical);
        const isValid = verify(bytes, envelope.signature, publicKey);

        if (!isValid) {
            return { valid: false, reason: 'Signature verification failed' };
        }

        return { valid: true };
    } catch (error) {
        return {
            valid: false,
            reason: `Signature verification error: ${error instanceof Error ? error.message : String(error)}`,
        };
    }
}

// ─── encryptEnvelopeBody ────────────────────────────────────────────

/**
 * Encrypts the envelope body (the encrypt path of the L4 wrapper layer)
 *
 * Execution order:
 * 1. lookupHandle(sessionId) — SESSION_NOT_FOUND if not found
 * 2. Inv 3.2 precondition: capabilityTokenRef === handle.authorizedTokenId,
 *    SESSION_TOKEN_MISMATCH on mismatch (this check is an L4 wrapper responsibility; the handle does not do it internally)
 * 3. Call handle.encrypt() (internally performs the Inv 3.1 state check + Inv 7 monotonic nonce increment)
 * 4. Encode ciphertext/aeadNonce as hex strings and build the EncryptedBody
 *
 * @throws ProtocolError('SESSION_NOT_FOUND') handle does not exist
 * @throws ProtocolError('SESSION_TOKEN_MISMATCH') Inv 3.2 precondition failed
 * @throws ProtocolError('SESSION_HANDLE_REVOKED') handle state is CLOSED/REVOKED (thrown internally by the handle)
 *
 */
export function encryptEnvelopeBody(
    params: EncryptEnvelopeBodyParams,
): EncryptedBody {
    const {
        registry,
        sessionId,
        capabilityTokenRef,
        aadFields,
        plaintext,
        bodyType,
    } = params;

    // Step 1: look up the handle (the encrypt path uses lookupHandle)
    const handle = registry.lookupHandle(sessionId);
    if (handle === null) {
        throw new ProtocolError(
            'SESSION_NOT_FOUND',
            `encryptEnvelopeBody: session not found: ${sessionId}`,
        );
    }

    // Step 2: Inv 3.2 precondition (capabilityTokenRef === authorizedTokenId)
    // An L4 wrapper responsibility; the handle does not perform this check internally
    if (handle.authorizedTokenId !== capabilityTokenRef) {
        throw new ProtocolError(
            'SESSION_TOKEN_MISMATCH',
            `encryptEnvelopeBody: capabilityTokenRef mismatch: expected=${handle.authorizedTokenId ?? 'null'} got=${capabilityTokenRef}`,
        );
    }

    // Step 3: call handle.encrypt() (Inv 3.1 + Inv 7 are performed internally by the handle)
    const { ciphertext, aeadNonce, keyId } = handle.encrypt({
        aadFields,
        plaintext,
    });

    // Step 4: build the EncryptedBody (ciphertext/aeadNonce encoded as hex)
    const body: EncryptedBody = {
        encrypted: true,
        encryptionProtocolVersion: 'ap/e2e/v1',
        type: bodyType,
        ciphertext: Buffer.from(ciphertext).toString('hex'),
        aeadNonce: Buffer.from(aeadNonce).toString('hex'),
        keyId,
        ...(aadFields.aadSummary !== undefined
            ? { aadSummary: aadFields.aadSummary }
            : {}),
    };

    return body;
}

// ─── decryptEnvelopeBody ────────────────────────────────────────────

/**
 * Decrypts the envelope body (the decrypt path of the L4 wrapper layer)
 *
 * Execution order:
 * 1. Inv 11 precondition: body.type must be present (INVALID_ENCRYPTED_BODY)
 * 2. Extract sequenceNumber + directionByte from aeadNonce
 * 3. Replay detection (ENCRYPTED_REPLAY_DETECTED): seq ≤ the highest seen value
 * 4. lookupHandleForDecrypt(sessionId, body.keyId) — DECRYPTION_FAILED if not found (Inv 4)
 * 5. Call handle.decrypt() (internally performs the Inv 4.1 state check + Inv 4.2 AEAD tag verification)
 * 6. Inv 4.3 post-decrypt: capabilityTokenRef === handle.authorizedTokenId,
 *    SESSION_TOKEN_MISMATCH on mismatch
 * 7. Update the replay tracker's maxSeen
 * 8. Return the plaintext Uint8Array
 *
 * Replay detection design:
 * - Tracks maxSeenSequenceNumber per (sessionId, directionByte)
 * - Throws ENCRYPTED_REPLAY_DETECTED when seq ≤ maxSeen (does not update maxSeen)
 * - Updates maxSeen when seq > maxSeen (after successful decryption)
 * - Note: in the initial state (no record), any seq is allowed through
 *
 * @throws ProtocolError('INVALID_ENCRYPTED_BODY') body.type is missing
 * @throws ProtocolError('ENCRYPTED_REPLAY_DETECTED') sequenceNumber replay
 * @throws ProtocolError('DECRYPTION_FAILED') handle not found or AEAD tag verification failed
 * @throws ProtocolError('SESSION_TOKEN_MISMATCH') Inv 4.3 post-decrypt assertion failed
 * @throws ProtocolError('SESSION_HANDLE_REVOKED') handle state is CLOSED/REVOKED (thrown internally by the handle)
 *
 */
export function decryptEnvelopeBody(
    params: DecryptEnvelopeBodyParams,
): Uint8Array {
    const { registry, sessionId, body, aadFields, capabilityTokenRef } = params;

    // Step 1: Inv 11 precondition: EncryptedBody.type must be present
    if (!body.type) {
        throw new ProtocolError(
            'INVALID_ENCRYPTED_BODY',
            'decryptEnvelopeBody: EncryptedBody.type is missing (Inv 11)',
        );
    }

    // Step 2: extract sequenceNumber + directionByte from aeadNonce
    const { seq, directionByte } = _extractSequenceNumber(body.aeadNonce);

    // Step 3: replay detection (ENCRYPTED_REPLAY_DETECTED)
    // Uses the (sessionId, directionByte, keyId) composite key to track the max seq per generation and direction
    // Regression fix: keyId is part of the key, so swapForDualKey after a rekey automatically starts a fresh count
    const rKey = _replayKey(sessionId, directionByte, body.keyId);
    const maxSeen = _replayTracker.get(rKey);
    if (maxSeen !== undefined && seq <= maxSeen) {
        throw new ProtocolError(
            'ENCRYPTED_REPLAY_DETECTED',
            `decryptEnvelopeBody: replay detected: seq=${seq} <= maxSeen=${maxSeen} (session=${sessionId} keyId=${body.keyId})`,
        );
    }

    // Step 4: Inv 4 routing (must use lookupHandleForDecrypt; trial-and-error is forbidden)
    const handle = registry.lookupHandleForDecrypt(sessionId, body.keyId);
    if (handle === null) {
        throw new ProtocolError(
            'DECRYPTION_FAILED',
            `decryptEnvelopeBody: no handle for sessionId=${sessionId} keyId=${body.keyId}`,
        );
    }

    // Step 5: AEAD decryption (Inv 4.1 state + Inv 4.2 tag verification are performed internally by the handle)
    // The EncryptedBody fields (ciphertext/aeadNonce) allow hex or base64url per the schema;
    // they must be decoded by detecting the format (consistent with _extractSequenceNumber), not hardcoded to hex.
    let ciphertextBytes: Uint8Array;
    let aeadNonceBytes: Uint8Array;
    try {
        ciphertextBytes = _decodeEncryptedField(body.ciphertext);
        aeadNonceBytes = _decodeEncryptedField(body.aeadNonce);
    } catch (e) {
        throw new ProtocolError(
            'INVALID_ENCRYPTED_BODY',
            `decryptEnvelopeBody: encrypted field decode failed: ${e instanceof Error ? e.message : String(e)}`,
        );
    }

    const plaintext = handle.decrypt({
        aadFields,
        ciphertext: ciphertextBytes,
        aeadNonce: aeadNonceBytes,
    });

    // Step 6: Inv 4.3 post-decrypt token comparison (an L4 wrapper responsibility)
    if (handle.authorizedTokenId !== capabilityTokenRef) {
        throw new ProtocolError(
            'SESSION_TOKEN_MISMATCH',
            `decryptEnvelopeBody: post-decrypt token mismatch: expected=${handle.authorizedTokenId ?? 'null'} got=${capabilityTokenRef}`,
        );
    }

    // Step 7: update the replay tracker after successful decryption (only after both decryption and the token check pass)
    if (maxSeen === undefined || seq > maxSeen) {
        _replayTracker.set(rKey, seq);
    }

    // Step 8: return the plaintext
    return plaintext;
}
