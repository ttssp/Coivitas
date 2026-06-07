/**
 * signResolvedCredentialIntegrityProof — CR L1 crypto primitive (issuer-side sign)
 *
 * Responsibility: ed25519Sign + resolverPrivateKey injection + toSignature factory call
 *
 * Algorithm:
 *   1. canonicalizeResolvedCredentialIntegrityProof(signedPayload) → canonical Uint8Array (RFC 8785);
 *   2. Ed25519 sign(canonicalBytes, privateKey) → 64-byte signature;
 *   3. bytes → hex (128 lowercase chars; pattern);
 *   4. return hex string (used to fill ResolvedCredentialIntegrityProof.proofSignature).
 *
 * Anti-phantom defense:
 *   - top-level import of ed25519 / canonicalize (no in-body require);
 *   - non-conforming privateKey length / format → throw (fail-closed; no stub default sign placeholder);
 *   - no PLACEHOLDER_SIGNATURE placeholder allowed (real ed25519Sign +
 *     resolverPrivateKey injection is mandatory; placeholder cast bypass is strictly forbidden).
 */

import { ed25519 } from '@noble/curves/ed25519';

import { CrError } from '@coivitas/types';

import {
    canonicalizeResolvedCredentialIntegrityProof,
    type ResolvedCredentialIntegrityProofSignedPayload,
} from './canonicalize-integrity-proof.js';

/**
 * Ed25519 privateKey length (32 bytes seed; @noble/curves/ed25519 standard)
 */
const ED25519_PRIVATE_KEY_LENGTH = 32;

/**
 * Ed25519 signature length (64 bytes; @noble/curves/ed25519 standard)
 */
const ED25519_SIGNATURE_LENGTH = 64;

/**
 * bytesToHex — Uint8Array → lowercase hex string (internal helper)
 *
 * Outputs lowercase hex (paired with verify-integrity-proof.ts hexToBytes).
 */
function bytesToHex(bytes: Uint8Array): string {
    return Array.from(bytes)
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('');
}

/**
 * signResolvedCredentialIntegrityProof — Ed25519 sign on JCS canonical bytes (issuer-side sign primitive)
 *
 * @param signedPayload signed payload object (5 fields + cspVersion; from
 *                       extractIntegrityProofSignedPayload OR constructed directly by the caller)
 * @param privateKey Ed25519 private key (32-byte seed; Uint8Array; should be HSM-isolated in production)
 * @returns string — hex encoding of the 64-byte signature (128 lowercase hex chars;
 *                   filled into ResolvedCredentialIntegrityProof.proofSignature)
 * @throws CrError(CR_INTEGRITY_PROOF_INVALID) — canonicalize failure / sign exception
 * @throws CrError(CR_PORT_CONTRACT_VIOLATION) — non-conforming privateKey format / length
 */
export function signResolvedCredentialIntegrityProof(
    signedPayload: ResolvedCredentialIntegrityProofSignedPayload,
    privateKey: Uint8Array,
): string {
    // step 1: privateKey format check (fail-closed; stub default sign placeholder strictly forbidden)
    if (!(privateKey instanceof Uint8Array)) {
        throw new CrError('CR_PORT_CONTRACT_VIOLATION', {
            reason: 'private_key_not_uint8array',
            received: typeof privateKey,
        });
    }
    if (privateKey.length !== ED25519_PRIVATE_KEY_LENGTH) {
        throw new CrError('CR_PORT_CONTRACT_VIOLATION', {
            reason: 'private_key_invalid_length',
            expected: ED25519_PRIVATE_KEY_LENGTH,
            received: privateKey.length,
        });
    }

    // step 2: JCS canonicalize (RFC 8785; UTF-8)
    // Note: canonicalizeResolvedCredentialIntegrityProof internally throws CR_INTEGRITY_PROOF_INVALID
    // (canonicalize failure / input contains an illegal type) — propagated here
    const canonicalBytes =
        canonicalizeResolvedCredentialIntegrityProof(signedPayload);

    // step 3: Ed25519 sign (@noble/curves/ed25519; fail-closed)
    let signatureBytes: Uint8Array;
    try {
        signatureBytes = ed25519.sign(canonicalBytes, privateKey);
    } catch (err) {
        // ed25519.sign may throw at the production edge (e.g. malformed privateKey content);
        // step 1 above already checked the privateKey length; defense-in-depth fail-closed here
        /* v8 ignore next 4*/
        throw new CrError('CR_INTEGRITY_PROOF_INVALID', {
            reason: 'ed25519_sign_threw',
            detail: err instanceof Error ? err.message : String(err),
        });
    }

    // step 4: signature length check (defense-in-depth; ed25519.sign always returns 64 bytes)
    if (signatureBytes.length !== ED25519_SIGNATURE_LENGTH) {
        // unreachable branch — ed25519.sign always returns 64 bytes; defense-in-depth fail-closed
        /* v8 ignore next 5*/
        throw new CrError('CR_INTEGRITY_PROOF_INVALID', {
            reason: 'signature_unexpected_length',
            expected: ED25519_SIGNATURE_LENGTH,
            received: signatureBytes.length,
        });
    }

    // step 5: bytes → hex (lowercase; 128 chars; pattern `^[0-9a-f]{128}$`)
    return bytesToHex(signatureBytes);
}
