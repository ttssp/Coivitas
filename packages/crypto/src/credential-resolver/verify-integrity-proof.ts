/**
 * verifyResolvedCredentialIntegrityProofSignature — CR L1 crypto primitive
 *
 * Responsibility: ed25519Verify injection;
 *            csp 5-field invariant (verify-time signed payload primitive)
 *
 * Algorithm:
 *   1. extractIntegrityProofSignedPayload(proof) → signed payload (5 fields + cspVersion);
 *   2. canonicalizeResolvedCredentialIntegrityProof(signedPayload) → recomputedBytes (RFC 8785 JCS);
 *   3. hex-decode proofSignature (128 lowercase hex → 64 bytes;
 *      pattern `^[0-9a-f]{128}$`);
 *   4. Ed25519 verify(recomputedBytes, signatureBytes, publicKey) → boolean;
 *   5. fail-closed: signature verify failure → throw CrError(CR_INTEGRITY_PROOF_INVALID) + reason 'signature_verify_failed'.
 *
 * Note: this L1 primitive only does cryptographic-layer verify (canonicalize + Ed25519 verify);
 *     semantic-layer checks (challenge / audience / notAfter / cspVersion / crVersion / userId) are
 *     implemented by the L2 identity layer verifyResolvedCredential.
 *
 * Anti-phantom defense:
 *   - top-level import of ed25519 / canonicalize (no in-body require);
 *   - every one of the 14 CrErrorCode codes has a throw-path (this file throws CR_INTEGRITY_PROOF_INVALID;
 *     verify failure path);
 *   - no stub default success / silent return true allowed (auth/verification primitive is strict);
 *   - non-conforming publicKey length / format → throw (fail-closed; no stub default verify ok).
 */

import { ed25519 } from '@noble/curves/ed25519';

import type { ResolvedCredentialIntegrityProof } from '@coivitas/types';
import { CrError } from '@coivitas/types';

import {
    canonicalizeResolvedCredentialIntegrityProof,
    extractIntegrityProofSignedPayload,
} from './canonicalize-integrity-proof.js';

/**
 * proofSignature hex regex (Ed25519 64-byte → 128 lowercase hex)
 */
const PROOF_SIGNATURE_HEX_PATTERN = /^[0-9a-f]{128}$/;

/**
 * Ed25519 publicKey length (32 bytes; @noble/curves/ed25519 standard)
 */
const ED25519_PUBLIC_KEY_LENGTH = 32;

/**
 * Ed25519 signature length (64 bytes; @noble/curves/ed25519 standard)
 */
const ED25519_SIGNATURE_LENGTH = 64;

/**
 * VerifyIntegrityProofSignatureResult — returns { valid: true } when verify passes; throws CrError otherwise
 *
 * Does not return a { valid: false } type — auth/verification primitives have strict fail-closed
 * semantics; every verify failure must throw + error code +
 * detail text description (the consumer must handle it with try/catch; no silent skip allowed).
 */
export interface VerifyIntegrityProofSignatureResult {
    readonly valid: true;
}

/**
 * verifyResolvedCredentialIntegrityProofSignature — verify Ed25519 signature on JCS canonical bytes
 *
 * @param proof full integrity proof object (containing proofSignature)
 * @param publicKey Ed25519 public key (32-byte Uint8Array; resolved via resolverDid)
 * @returns VerifyIntegrityProofSignatureResult — { valid: true } only when verify passes
 * @throws CrError(CR_INTEGRITY_PROOF_INVALID) — verify failure / canonicalize failure / format error
 * @throws CrError(CR_PORT_CONTRACT_VIOLATION) — non-conforming publicKey format / length
 */
export function verifyResolvedCredentialIntegrityProofSignature(
    proof: ResolvedCredentialIntegrityProof,
    publicKey: Uint8Array,
): VerifyIntegrityProofSignatureResult {
    // step 1: publicKey format check (fail-closed; publicKey is resolved by the L2 caller via resolverDid,
    // L1 does not trust the input format; stub default verify ok strictly forbidden)
    if (!(publicKey instanceof Uint8Array)) {
        throw new CrError('CR_PORT_CONTRACT_VIOLATION', {
            reason: 'public_key_not_uint8array',
            received: typeof publicKey,
        });
    }
    if (publicKey.length !== ED25519_PUBLIC_KEY_LENGTH) {
        throw new CrError('CR_PORT_CONTRACT_VIOLATION', {
            reason: 'public_key_invalid_length',
            expected: ED25519_PUBLIC_KEY_LENGTH,
            received: publicKey.length,
        });
    }

    // step 2: proofSignature format check (128 lowercase hex)
    if (typeof proof.proofSignature !== 'string') {
        throw new CrError('CR_INTEGRITY_PROOF_INVALID', {
            reason: 'proof_signature_not_string',
            received: typeof proof.proofSignature,
        });
    }
    if (!PROOF_SIGNATURE_HEX_PATTERN.test(proof.proofSignature)) {
        throw new CrError('CR_INTEGRITY_PROOF_INVALID', {
            reason: 'proof_signature_invalid_hex_format',
            expectedPattern: '^[0-9a-f]{128}$',
        });
    }

    // step 3: hex-decode proofSignature → 64-byte Uint8Array
    const signatureBytes = hexToBytes(proof.proofSignature);
    if (signatureBytes.length !== ED25519_SIGNATURE_LENGTH) {
        // unreachable branch — PROOF_SIGNATURE_HEX_PATTERN already guarantees 128 hex chars = 64 bytes;
        // but defense-in-depth fail-closed
        /* v8 ignore next 5*/
        throw new CrError('CR_INTEGRITY_PROOF_INVALID', {
            reason: 'signature_bytes_invalid_length',
            expected: ED25519_SIGNATURE_LENGTH,
            received: signatureBytes.length,
        });
    }

    // step 4: extract signed payload (5 fields + cspVersion; excludes proofSignature / resolverDid)
    const signedPayload = extractIntegrityProofSignedPayload(proof);

    // step 5: JCS canonicalize → recomputedBytes (RFC 8785; UTF-8)
    // Note: canonicalizeResolvedCredentialIntegrityProof internally throws CR_INTEGRITY_PROOF_INVALID
    // (canonicalize failure / input contains an illegal type) — propagated here
    const recomputedBytes =
        canonicalizeResolvedCredentialIntegrityProof(signedPayload);

    // step 6: Ed25519 verify (fail-closed; stub return true not allowed)
    let isValid = false;
    try {
        isValid = ed25519.verify(signatureBytes, recomputedBytes, publicKey);
    } catch (err) {
        // ed25519.verify may throw on certain malformed inputs (e.g. non-canonical signature form);
        // step 2 above already checked the signature hex format + step 3 the decode length → defense-in-depth fail-closed here
        /* v8 ignore next 4*/
        throw new CrError('CR_INTEGRITY_PROOF_INVALID', {
            reason: 'ed25519_verify_threw',
            detail: err instanceof Error ? err.message : String(err),
        });
    }

    if (!isValid) {
        throw new CrError('CR_INTEGRITY_PROOF_INVALID', {
            reason: 'signature_verify_failed',
            detail: 'Ed25519 signature does not match canonical bytes (potentially tampered payload OR wrong publicKey)',
        });
    }

    return { valid: true };
}

/**
 * hexToBytes — hex string → Uint8Array (internal helper; strictly lowercase hex input)
 *
 * Note: the caller is responsible for ensuring the input is lowercase hex (already checked by
 * PROOF_SIGNATURE_HEX_PATTERN); this function does not re-check the format.
 */
function hexToBytes(hex: string): Uint8Array {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i += 1) {
        bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
    }
    return bytes;
}
