/**
 * preimage-helpers — HCC v0.2 L1 crypto preimage helpers
 *
 *   - preimage = canonicalPayloadBytes ‖ chainIdentityJcsBytes
 *     (canonicalPayload first; chainIdentity second)
 *   - I2 invariant: canonicalPayloadHash = SHA-256(canonicalPayloadBytes ‖ chainIdentityJcsBytes) lowercase hex 64 chars
 *
 * v0.2 upgrade core:
 *   - chainIdentity enters the hash-preimage cryptographic-enforce scope (mutating any field → hash mismatch)
 *   - replaces the v0.1 SQL WHERE / wrapper revocation path — v0.2 enforces cryptographically at the hash layer directly
 *
 * Byte order:
 *   - preimage = canonicalPayloadBytes ‖ chainIdentityJcsBytes (payload first; identity second)
 *   - no other order allowed (identity-first has no technical advantage; nested hashing carries high cross-lang risk)
 *   - cross-lang consistency enforced (TS + Python must use the same order)
 *
 * Robustness defenses:
 *   - top-level import sha256 from @noble/hashes (no in-function require / dynamic import)
 *   - SHA-256 digest length strictly 32 bytes (RFC 6234 standard; defensive fallback)
 *   - lowercase hex output (consistent with the existing v0.1 toCanonicalPayloadHash factory pattern)
 */

import { sha256 } from '@noble/hashes/sha256';

import { HashChainError } from '@coivitas/types';

const textEncoder = new TextEncoder();

/**
 * concatPreimage — concatenate canonicalPayload + chainIdentityJcs into the SHA-256 preimage
 *
 * Byte order: payload first; identity second.
 *
 * Design intent:
 *   - preimage = canonicalPayloadBytes ‖ chainIdentityJcsBytes (byte order fixed; cross-lang consistent)
 *   - mutating any input → preimage UTF-8 bytes mutate → SHA-256 digest mutates → verifyHashChain fails
 *
 * @param canonicalPayload payload string after JCS canonicalize (RFC 8785)
 * @param chainIdentityJcs string produced by canonicalizeChainIdentity() (will switch to the ChainIdentityJcs brand after the L0 types upgrade)
 * @returns Uint8Array preimage (SHA-256 input)
 */
export function concatPreimage(
    canonicalPayload: string,
    chainIdentityJcs: string,
): Uint8Array {
    const canonicalPayloadBytes = textEncoder.encode(canonicalPayload);
    const chainIdentityJcsBytes = textEncoder.encode(chainIdentityJcs);
    const preimage = new Uint8Array(
        canonicalPayloadBytes.length + chainIdentityJcsBytes.length,
    );
    preimage.set(canonicalPayloadBytes, 0);
    preimage.set(chainIdentityJcsBytes, canonicalPayloadBytes.length);
    return preimage;
}

/**
 * computeCanonicalPayloadHashHex — SHA-256(preimage) → lowercase hex 64 chars
 *
 * Robustness defenses (RFC 6234 standard SHA-256 digest is fixed at 32 bytes; defensive fallback on deviation):
 *   - sha256 internal throw → wrapped as HC_HASH_MISMATCH
 *   - digest length ≠ 32 → wrapped as HC_HASH_MISMATCH (unreachable in practice; noble/hashes standard)
 *
 * @param preimage `concatPreimage()` output OR an equivalent Uint8Array (SHA-256 input)
 * @returns lowercase hex 64 chars (will switch to the toCanonicalPayloadHash brand factory input after the L0 types upgrade)
 *
 * @throws HashChainError(HC_HASH_MISMATCH)
 *   - sha256 internal throw (unreachable under the RFC 6234 standard; defensive fallback)
 *   - digest length ≠ 32 (deviation from the RFC 6234 fixed BlockHash size; defensive fallback)
 */
export function computeCanonicalPayloadHashHex(preimage: Uint8Array): string {
    let digest: Uint8Array;
    /* v8 ignore start -- @noble/hashes sha256 does not throw (RFC 6234 standard); defensive fallback, unreachable*/
    try {
        digest = sha256(preimage);
    } catch (error) {
        throw new HashChainError(
            'HC_HASH_MISMATCH',
            'computeCanonicalPayloadHashHex: SHA-256 hash threw (preimage corrupted)',
            error instanceof Error ? error : undefined,
        );
    }
    /* v8 ignore stop*/

    /* v8 ignore next 6 -- sha256 BlockHash is fixed at 32 bytes; defensive fallback, unreachable*/
    if (digest.length !== 32) {
        throw new HashChainError(
            'HC_HASH_MISMATCH',
            `computeCanonicalPayloadHashHex: SHA-256 digest length unexpected (got ${digest.length}; expected 32)`,
        );
    }

    // lowercase hex encode (same semantics as the v0.1 toHex helper; inlined here to avoid a cross-module dep)
    let hex = '';
    for (const byte of digest) {
        hex += byte.toString(16).padStart(2, '0');
    }
    return hex;
}
