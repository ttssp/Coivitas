/**
 * canonicalHash — CSP L1 crypto primitive
 *
 * Algorithm:
 *   1. canonicalSerialize → canonical bytes (RFC 8785 JCS; UTF-8);
 *   2. SHA-256 hash (@noble/hashes/sha256) → 32-byte digest;
 *   3. fail-closed: any failing step throws CspError.
 *
 * Use cases:
 *   - idempotency key derivation;
 *   - verify-pipeline canonicalize consistency check (recomputedBytes comparison);
 *   - hash chain canonicalize sub-protocol integration;
 *   - audit-tamper-proof sub-protocol integration;
 *   - multisig Merkle inclusion proof leaf encoding
 *     ("leaf = SHA-256(JCS({id,role,signature}))").
 *
 * Defensive hardening:
 *   - top-level import of @noble/hashes/sha256 (no in-body require/dynamic import);
 *   - SHA-256 is mandatory (no fallback to any other hash algorithm; protocol-level invariant);
 *   - requires active invocation (no stub default success / partial PASS).
 */

import { sha256 } from '@noble/hashes/sha256';

import { toBase64Url, toHex } from '../encoding.js';

import { canonicalSerialize } from './canonical-serialize.js';
import { CspError } from './types.js';

/**
 * canonicalHash — JCS canonical encode + SHA-256 → digest string
 *
 * @param payload csp signed payload (any JSON-serializable Record); typically
 *   the 5 CanonicalSignedPayload fields + cspVersion; reuses the canonicalSerialize core.
 * @param encoding output encoding (default 'hex', matching the frozen wire format; optional
 *   'base64url' for compact scenarios such as a Merkle proof leaf; brand-type style unified).
 * @returns SHA-256 digest (hex: 64 chars / base64url: 43 chars, no padding); consumed by
 *   idempotency key / canonicalize consistency check / Merkle leaf and similar scenarios.
 * @throws CspError(CSP_CANONICALIZE_MISMATCH) — payload is not JCS-serializable (propagated from
 *   canonicalSerialize).
 */
export function canonicalHash(
    payload: Record<string, unknown>,
    encoding: 'hex' | 'base64url' = 'hex',
): string {
    // step 1: JCS canonical encode (propagates canonicalSerialize fail-closed throw)
    const canonicalBytes = canonicalSerialize(payload);

    // step 2: SHA-256 hash → 32-byte digest
    let digest: Uint8Array;
    try {
        digest = sha256(canonicalBytes);
    } catch (error) {
        throw new CspError(
            'CSP_CANONICALIZE_MISMATCH',
            'canonicalHash: SHA-256 hash threw (canonical bytes corrupted).',
            error instanceof Error ? error : undefined,
        );
    }

    // step 3: defensive hardening — sha256 must return 32 bytes (fixed BlockHash size)
    if (digest.length !== 32) {
        throw new CspError(
            'CSP_CANONICALIZE_MISMATCH',
            `canonicalHash: SHA-256 digest length unexpected (got ${digest.length}; expected 32).`,
        );
    }

    // step 4: encode (default hex matches the frozen wire format; base64url for compact scenarios)
    return encoding === 'base64url' ? toBase64Url(digest) : toHex(digest);
}

/**
 * canonicalHashBytes — JCS canonical encode + SHA-256 → Uint8Array (32-byte digest)
 *
 * Shares the same core as canonicalHash; outputs the raw 32-byte digest for:
 *   - direct Merkle proof leaf concatenation (sibling hash concatenation operates on bytes);
 *   - hash chain link (hash(prev_hash || canonical_bytes) chains over bytes);
 *   - production hot-path that avoids string encode/decode conversion.
 *
 * Primary consumers:
 *   - hash chain canonicalize sub-protocol L1;
 *   - multisig Merkle inclusion proof L1.
 */
export function canonicalHashBytes(
    payload: Record<string, unknown>,
): Uint8Array {
    const canonicalBytes = canonicalSerialize(payload);

    let digest: Uint8Array;
    try {
        digest = sha256(canonicalBytes);
    } catch (error) {
        throw new CspError(
            'CSP_CANONICALIZE_MISMATCH',
            'canonicalHashBytes: SHA-256 hash threw (canonical bytes corrupted).',
            error instanceof Error ? error : undefined,
        );
    }

    if (digest.length !== 32) {
        throw new CspError(
            'CSP_CANONICALIZE_MISMATCH',
            `canonicalHashBytes: SHA-256 digest length unexpected (got ${digest.length}; expected 32).`,
        );
    }

    return digest;
}
