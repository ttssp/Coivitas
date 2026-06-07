/**
 * Key-rotation executor
 *
 * Responsibilities:
 *   1. initiateKeyRotation — generate a triple-signature RotationProof, return the ROTATING intermediate document
 *   2. completeKeyRotation — convert a RotatingDocument into a normal AgentIdentityDocument
 *   3. verifyRotationProof — statelessly verify the validity of the triple signature
 *
 * Note: this module only handles document-level format and signatures; Registry state transitions are handled by IdentityRegistry.
 */

import { canonicalize, sign, verify } from '@coivitas/crypto';
import type { KeyPair } from '@coivitas/crypto';
import { IDENTITY_ENCODING } from './encoding-config.js';
import type {
    AgentIdentityDocument,
    DID,
    KeyRotationState,
    RotationProof,
    Signature,
    Timestamp,
} from '@coivitas/types';
import { SPEC_VERSION_0_2_0 } from '@coivitas/types';

import { extractPublicKeyFromDIDKey, isDidAgent, isDidKey } from './did.js';

// -------- Constants --------

/**
 * Strict ISO 8601 UTC timestamp format (with milliseconds).
 * Conclusion: the wire format requires YYYY-MM-DDTHH:mm:ss.SSSZ, forbidding timezone offsets and omitted milliseconds.
 * new Date().toISOString() always produces a valid format; validation is only needed when the caller passes it manually.
 */
const ISO_UTC_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

// -------- Types --------

/**
 * Rotation intermediate document: publicKey has been updated to the new key, while also carrying rotationProof and previousPublicKey.
 * The authoritative rotationState is maintained by the Registry; this type is only used for internal function boundaries in key-rotation.ts.
 *
 * _rotatingState is a runtime-internal marker used to distinguish "rotating" from "rotation complete" —
 * both carry the rotationProof field, so they cannot be distinguished by field presence alone.
 *
 * Callers must convert it to an AgentIdentityDocument via completeKeyRotation() before serializing;
 * _rotatingState must not appear in the wire format.
 */
export type RotatingDocument = AgentIdentityDocument & {
    rotationProof: RotationProof;
    previousPublicKey: string;
    _rotatingState: true;
};

/**
 * The shared payload of the triple signature
 *
 * The old key, the new key, and the principal all sign the same payload, preventing cross-scenario replay.
 */
type RotationProofSignedPayload = {
    agentDid: DID;
    newPublicKey: string;
    oldPublicKey: string;
    rotatedAt: Timestamp;
};

// -------- Internal utilities --------

/**
 * Build and encode the signing payload.
 * Conclusion: canonicalize guarantees deterministic field ordering, and TextEncoder unifies UTF-8 bytes.
 */
function buildSignedPayloadBytes(
    payload: RotationProofSignedPayload,
): Uint8Array {
    return new TextEncoder().encode(
        canonicalize({
            agentDid: payload.agentDid,
            newPublicKey: payload.newPublicKey,
            oldPublicKey: payload.oldPublicKey,
            rotatedAt: payload.rotatedAt,
        }),
    );
}

/**
 * Validate public-key format (ed25519 32-byte public key)
 *
 * Conclusion: supports both formats:
 *   - v0.1.0 hex: 64-char lowercase hex (/^[0-9a-f]{64}$/)
 *   - v0.2.0 base64url: 43-char base64url (/^[A-Za-z0-9_-]{43}$/, no padding)
 * Both correspond to 32 bytes (hex 64=32*2, base64url ceil(32*8/6)=43).
 */
function isValidPublicKey(key: string): boolean {
    if (typeof key !== 'string') return false;
    // v0.1.0 hex format
    if (/^[0-9a-f]{64}$/.test(key)) return true;
    // v0.2.0 base64url format (32 bytes, no padding = 43 chars)
    if (/^[A-Za-z0-9_-]{43}$/.test(key)) return true;
    return false;
}

// -------- Exported functions --------

/**
 * Initiate key rotation
 *
 * Preconditions:
 *   - currentDoc is not in the ROTATING state (determined by the coexistence of rotationProof and previousPublicKey)
 *     Note: this function cannot access the Registry; it blocks consecutive operations by checking that "the document is already in a rotation intermediate state"
 *   - newKeyPair format is valid
 *   - the new and old public keys must not be identical
 *
 * Returns a RotatingDocument: publicKey has been switched to the new key, and rotationProof carries the triple signature.
 */
export function initiateKeyRotation(params: {
    currentDoc: AgentIdentityDocument;
    currentPrivateKey: string;
    newKeyPair: KeyPair;
    /** The principal's private key must not enter the Agent Runtime; the caller signs externally and passes in the pre-signed result*/
    principalApproval: Signature;
    /**
     * Rotation-initiation timestamp (ISO 8601 UTC).
     * The caller and the principal must use the same rotatedAt to build the signing payload, so the caller generates it and passes it in.
     * When omitted, it is generated internally (only suitable for tests or single-process scenarios).
     */
    rotatedAt?: Timestamp;
    /** Optional: the authoritative rotation state passed in by the Registry; when omitted, the in-memory _rotatingState marker is used for single-process-scenario compatibility*/
    currentRotationState?: KeyRotationState;
}): RotatingDocument {
    const { currentDoc, currentPrivateKey, newKeyPair, principalApproval } =
        params;

    // Precondition: forbid re-initiating rotation while in the ROTATING intermediate state
    // Prefer the authoritative Registry state passed in by the caller, for compatibility with the case where _rotatingState is lost after JSON deserialization
    const rotationState =
        params.currentRotationState ??
        ('_rotatingState' in currentDoc ? 'ROTATING' : 'ACTIVE');
    if (rotationState === 'ROTATING') {
        throw new Error(
            'Cannot initiate key rotation: document is already in ROTATING state.',
        );
    }

    // Validate the new key pair's format
    if (!isValidPublicKey(newKeyPair.publicKey)) {
        throw new Error(
            'Invalid newKeyPair: publicKey must be a 64-character hex string.',
        );
    }
    if (
        typeof newKeyPair.privateKey !== 'string' ||
        newKeyPair.privateKey.length !== 128
    ) {
        throw new Error(
            'Invalid newKeyPair: privateKey must be a 128-character hex string.',
        );
    }

    // The new and old public keys must not be identical
    if (newKeyPair.publicKey === currentDoc.publicKey) {
        throw new Error(
            'Cannot initiate key rotation: new public key is identical to the current public key.',
        );
    }

    // Strictly validate a caller-supplied rotatedAt format; an auto-generated one via new Date().toISOString() needs no validation
    if (params.rotatedAt !== undefined) {
        if (!ISO_UTC_RE.test(params.rotatedAt)) {
            throw new Error(
                'Invalid rotatedAt: must be ISO 8601 UTC with milliseconds (YYYY-MM-DDTHH:mm:ss.SSSZ)',
            );
        }
    }
    const rotatedAt = (params.rotatedAt ??
        new Date().toISOString()) as Timestamp;
    const payload: RotationProofSignedPayload = {
        agentDid: currentDoc.id,
        newPublicKey: newKeyPair.publicKey,
        oldPublicKey: currentDoc.publicKey,
        rotatedAt,
    };
    const payloadBytes = buildSignedPayloadBytes(payload);

    // Triple signature: the old key and the new key are signed internally at runtime, while the principal signature is pre-signed by the caller and passed in
    // All RotationProof fields use the same encoding (IDENTITY_ENCODING)
    const oldKeySignature = sign(
        payloadBytes,
        currentPrivateKey,
        IDENTITY_ENCODING,
    ) as RotationProof['oldKeySignature'];
    const newKeySignature = sign(
        payloadBytes,
        newKeyPair.privateKey,
        IDENTITY_ENCODING,
    ) as RotationProof['newKeySignature'];
    const principalSignature = principalApproval;

    const rotationProof: RotationProof = {
        oldPublicKey: currentDoc.publicKey,
        newPublicKey: newKeyPair.publicKey,
        oldKeySignature,
        newKeySignature,
        principalSignature,
        agentDid: currentDoc.id,
        rotatedAt,
    };

    // principalApproval must be verified; throw immediately on failure
    if (!verifyRotationProof(rotationProof, currentDoc.principalDid)) {
        throw new Error(
            'ProtocolError: SIGNATURE_INVALID — principalApproval verification failed',
        );
    }

    const newVersion = (currentDoc.version ?? 1) + 1;

    const rotatingDoc: RotatingDocument = {
        ...currentDoc,
        specVersion: SPEC_VERSION_0_2_0,
        publicKey: newKeyPair.publicKey,
        previousPublicKey: currentDoc.publicKey,
        rotationProof,
        version: newVersion,
        updatedAt: rotatedAt,
        _rotatingState: true,
    };

    return rotatingDoc;
}

/**
 * Complete key rotation
 *
 * Accepts a document in the rotation intermediate state and returns a normal AgentIdentityDocument.
 * Conclusion: this function only confirms the document format and changes no fields; the Registry handles state transitions.
 *
 * Two legitimate paths:
 *   - In-memory path: rotatingDoc._rotatingState === true (returned directly by initiateKeyRotation)
 *   - Registry path: opts.currentRotationState === 'ROTATING' (after loading from the Registry and JSON-deserializing, _rotatingState is lost)
 */
export function completeKeyRotation(
    rotatingDoc: RotatingDocument | AgentIdentityDocument,
    opts?: { currentRotationState?: KeyRotationState },
): AgentIdentityDocument {
    // Compatible with both the in-memory path (_rotatingState brand) and the Registry path (opts passes the authoritative state)
    const isRotating =
        ('_rotatingState' in rotatingDoc &&
            rotatingDoc._rotatingState === true) ||
        opts?.currentRotationState === 'ROTATING';
    if (!isRotating) {
        throw new Error(
            'Cannot complete key rotation: document is not in ROTATING state.',
        );
    }

    // rotationProof must exist, otherwise it cannot be verified
    if (!rotatingDoc.rotationProof) {
        throw new Error(
            'Cannot complete key rotation: rotationProof missing from document.',
        );
    }

    // Re-verify rotationProof integrity before completing, to prevent the intermediate document from being tampered with
    if (
        !verifyRotationProof(
            rotatingDoc.rotationProof,
            rotatingDoc.principalDid,
        )
    ) {
        throw new Error(
            'RotationProof verification failed in completeKeyRotation',
        );
    }

    // Remove the internal runtime marker _rotatingState to get a clean AgentIdentityDocument.
    // publicKey/previousPublicKey/rotationProof are all kept (for historical audit).
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { _rotatingState, ...rest } = rotatingDoc as AgentIdentityDocument & {
        _rotatingState?: true;
    };
    const completed: AgentIdentityDocument = rest;
    return completed;
}

/**
 * Verify the rotation proof's triple signature
 *
 * Verification order (return false on any failure):
 *   1. Format check (old and new public keys valid and different)
 *   2. Reconstruct the signing payload
 *   3. Verify the old key's signature
 *   4. Verify the new key's signature
 *   5. Verify the principal public key's signature (extracted from the principalDid did:key)
 */
export function verifyRotationProof(
    proof: RotationProof,
    principalDid: DID,
): boolean {
    try {
        // Step 1: format check
        if (
            !isValidPublicKey(proof.oldPublicKey) ||
            !isValidPublicKey(proof.newPublicKey)
        ) {
            return false;
        }
        if (proof.oldPublicKey === proof.newPublicKey) {
            return false;
        }
        // Validate agentDid format
        if (!isDidAgent(proof.agentDid)) {
            return false;
        }
        // Validate that rotatedAt strictly matches the required format: YYYY-MM-DDTHH:mm:ss.SSSZ
        if (!ISO_UTC_RE.test(proof.rotatedAt)) {
            return false;
        }

        // Step 2: reconstruct the signing payload
        const payload: RotationProofSignedPayload = {
            agentDid: proof.agentDid,
            newPublicKey: proof.newPublicKey,
            oldPublicKey: proof.oldPublicKey,
            rotatedAt: proof.rotatedAt,
        };
        const payloadBytes = buildSignedPayloadBytes(payload);

        // Step 3: verify the old key's signature
        if (!verify(payloadBytes, proof.oldKeySignature, proof.oldPublicKey)) {
            return false;
        }

        // Step 4: verify the new key's signature
        if (!verify(payloadBytes, proof.newKeySignature, proof.newPublicKey)) {
            return false;
        }

        // Step 5: extract the principal public key from principalDid and verify the principal signature
        if (!isDidKey(principalDid)) {
            return false;
        }
        const principalPublicKey = extractPublicKeyFromDIDKey(principalDid);
        if (
            !verify(payloadBytes, proof.principalSignature, principalPublicKey)
        ) {
            return false;
        }

        return true;
    } catch {
        // Any exception (format error, wrong signature length, etc.) is treated as verification failure
        return false;
    }
}
