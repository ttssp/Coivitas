/**
 * verify-helpers — HCC v0.2 L1 crypto verify helpers
 *
 *   - verifyHashChain helper functions, refined
 *   - Step 3 chainIdentity preimage cryptographic enforce
 *   - I9 invariant: chainIdentity preimage consistency (recomputeCanonicalPayloadHash literal-equality verify)
 *
 * v0.2 upgrade core:
 *   - verify path reuses the write path algorithm (canonicalize chainIdentity → concatPreimage → SHA-256)
 *   - tampering with any entry's chainIdentity OR canonicalPayload → recomputed hash mismatch → throw
 *
 * L0 types upgrade hand-off:
 *   - the v0.2 HashChainEntry interface includes a chainIdentity field; the current L0 types HashChainEntry is the v0.1 7-field shape (no chainIdentity)
 *   - this helper uses the inline HashChainEntryV02Shape (includes chainIdentity);
 *     after the L0 HashChainEntry upgrade, this helper switches to the L0 import
 *
 * Error-code usage hand-off (v0.2's 8 vs the current L0 types union difference):
 *   - added HC_CHAIN_IDENTITY_PREIMAGE_FAILED (verify inconsistency → this code) +
 *     HC_CHAIN_IDENTITY_SCHEMA_BREAKING (hccVersion not "2.0.0" → this code)
 *   - the L0 types HccErrorCode union currently has 6 (not including v0.2's added 2; this implementation strictly stays within L1 crypto scope and does not change L0)
 *   - this helper throws HC_CHAIN_IDENTITY_PREIMAGE_FAILED (literal-inequality verify)
 *
 * Robustness defenses:
 *   - top-level import (no in-function require / dynamic import)
 *   - literal-equality verify (recomputed === entry.canonicalPayloadHash); any mismatch throws
 *   - fail-closed required (no stub default success / silent return / partial-PASS allowed)
 */

import canonicalizePackage from 'canonicalize';

import { HashChainError } from '@coivitas/types';

import {
    canonicalizeChainIdentity,
    type ChainIdentityShape,
} from './canonicalize-chain-identity.js';
import {
    computeCanonicalPayloadHashHex,
    concatPreimage,
} from './preimage-helpers.js';

/**
 * HashChainEntryV02Shape — v0.2 HashChainEntry inline shape (includes chainIdentity)
 *
 * After the v0.2 L0 types HashChainEntry interface is upgraded it will include the chainIdentity field;
 * this helper uses the inline shape and switches to an import after the L0 HashChainEntry upgrade.
 *
 * Field semantics (v0.2 8 fields):
 *   - canonicalPayload: JCS-canonicalized payload string
 *   - canonicalPayloadHash: SHA-256(canonicalPayloadBytes ‖ chainIdentityJcsBytes) lowercase hex 64 chars
 *   - chainIdentity: v0.2's newly required field (chainNamespace + tenantId? + auditClass?)
 *   - other fields (entryId / previousHash / chainPosition / timestamp / hccVersion) do not participate in the preimage recompute
 */
export interface HashChainEntryV02Shape {
    /** JCS-canonicalized payload string (RFC 8785)*/
    canonicalPayload: string;
    /** SHA-256(canonicalPayloadBytes ‖ chainIdentityJcsBytes) lowercase hex 64 chars (v0.2 upgrade)*/
    canonicalPayloadHash: string;
    /** chainIdentity three fields (v0.2's newly required field)*/
    chainIdentity: ChainIdentityShape;
}

/**
 * recomputeCanonicalPayloadHash — recompute entry.canonicalPayloadHash (cryptographic enforce at verify time)
 *
 * Fixed algorithm:
 *   canonicalizeChainIdentity → concatPreimage → computeCanonicalPayloadHashHex.
 *   preimage = canonicalPayloadBytes ‖ chainIdentityJcsBytes.
 *
 * @param entry v0.2 HashChainEntry shape (includes chainIdentity + canonicalPayload)
 * @returns lowercase hex 64 chars (the recomputed result; caller does a literal-equality verify against entry.canonicalPayloadHash)
 *
 * @throws HashChainError(HC_CANONICALIZE_FAILED) — chainIdentity canonicalize failed (pass-through)
 * @throws HashChainError(HC_SCHEMA_VIOLATION) — any of the three chainIdentity fields non-conformant (pass-through)
 * @throws HashChainError(HC_CHAIN_IDENTITY_PREIMAGE_FAILED) — SHA-256 internal failure (unreachable under the RFC 6234 standard; pass-through)
 */
export function recomputeCanonicalPayloadHash(
    entry: HashChainEntryV02Shape,
): string {
    const chainIdentityJcs = canonicalizeChainIdentity(entry.chainIdentity);
    const preimage = concatPreimage(entry.canonicalPayload, chainIdentityJcs);
    return computeCanonicalPayloadHashHex(preimage);
}

/**
 * assertCanonicalPayloadIsCanonical — entry.canonicalPayload itself must be in JCS canonical form
 *
 * Security root cause:
 *   Before this, the verify path treated entry.canonicalPayload as an opaque string and fed it straight into the preimage hash,
 *   while the schema only required it to be a string. An attacker could craft a non-JCS payload (e.g. unsorted keys / extra whitespace),
 *   recompute the hash over that non-canonical string and pass verification → the same logical payload would have multiple accepted hashes,
 *   breaking the canonical-preimage injective invariant (I1).
 *
 * Fix (fail-closed):
 *   At verify time, parse canonicalPayload → re-run the same JCS canonicalizer (same-source algorithm as the write path) →
 *   require the result to be literally equal to entry.canonicalPayload; unparseable OR non-canonical → throw.
 *
 * @param entry v0.2 HashChainEntry shape (includes canonicalPayload string)
 * @param entryIndex the entry's index in the entries array (for error-message localization)
 *
 * @throws HashChainError(HC_CANONICALIZE_FAILED) — canonicalPayload not JSON.parse-able / not JCS-serializable
 * @throws HashChainError(HC_CHAIN_IDENTITY_PREIMAGE_FAILED) — canonicalPayload not in canonical form (re-run JCS output ≠ stored)
 */
export function assertCanonicalPayloadIsCanonical(
    entry: HashChainEntryV02Shape,
    entryIndex: number,
): void {
    // step 1: parse — canonicalPayload must be valid JSON
    let parsed: unknown;
    try {
        parsed = JSON.parse(entry.canonicalPayload);
    } catch (error) {
        throw new HashChainError(
            'HC_CANONICALIZE_FAILED',
            `entries[${entryIndex}].canonicalPayload is not valid JSON (cannot re-canonicalize for canonical-form verify)`,
            error instanceof Error ? error : undefined,
        );
    }

    // step 2: re-run the same JCS canonicalizer (same source as the write path — canonicalize npm RFC 8785)
    let recanonicalized: string | undefined;
    try {
        recanonicalized = (
            canonicalizePackage as unknown as (
                input: unknown,
            ) => string | undefined
        )(parsed);
    } catch (error) {
        throw new HashChainError(
            'HC_CANONICALIZE_FAILED',
            `entries[${entryIndex}].canonicalPayload not JCS-serializable per RFC 8785`,
            error instanceof Error ? error : undefined,
        );
    }
    if (typeof recanonicalized !== 'string') {
        throw new HashChainError(
            'HC_CANONICALIZE_FAILED',
            `entries[${entryIndex}].canonicalPayload re-canonicalize returned non-string (not JCS-serializable per RFC 8785)`,
        );
    }

    // step 3: literal-equality verify — fail-closed on non-canonical form
    if (recanonicalized !== entry.canonicalPayload) {
        throw new HashChainError(
            'HC_CHAIN_IDENTITY_PREIMAGE_FAILED',
            `entries[${entryIndex}].canonicalPayload is not canonical JCS form (stored="${entry.canonicalPayload}", canonical="${recanonicalized}"); non-canonical payload rejected to preserve injective preimage invariant`,
        );
    }
}

/**
 * assertCanonicalPayloadHashConsistent — verify entry.canonicalPayloadHash is literally equal to the recomputed hash
 *
 * Algorithm:
 *   1. recomputeCanonicalPayloadHash(entry) recomputes the hash hex (runs the full canonicalize chainIdentity → concatPreimage → SHA-256 pipeline)
 *   2. literal-equality verify of entry.canonicalPayloadHash against expectedHashHex
 *   3. any mismatch → fail-closed throw
 *
 * Tampering-detection coverage:
 *   - mutating any of the three chainIdentity fields → JCS canonicalize output mutates → preimage UTF-8 bytes mutate → SHA-256 digest mutates → mismatch throw
 *   - mutating any character of the canonicalPayload string → preimage UTF-8 bytes mutate → SHA-256 digest mutates → mismatch throw
 *
 * Error codes (the L0 types HccErrorCode v0.2 union of 8 already includes HC_CHAIN_IDENTITY_PREIMAGE_FAILED):
 *   - HC_CHAIN_IDENTITY_PREIMAGE_FAILED — entry tampering (chainIdentity or canonicalPayload tampering) cryptographic enforce fail
 *   - HC_CANONICALIZE_FAILED / HC_SCHEMA_VIOLATION — pass-through
 *
 * @param entry v0.2 HashChainEntry shape (includes chainIdentity + canonicalPayload + canonicalPayloadHash)
 * @param entryIndex the entry's index in the entries array (for error-message localization)
 *
 * @throws HashChainError(HC_CHAIN_IDENTITY_PREIMAGE_FAILED) — entry.canonicalPayloadHash not equal to the recomputed hash (chainIdentity or canonicalPayload tampering)
 * @throws HashChainError(HC_CANONICALIZE_FAILED) — chainIdentity canonicalize failed (pass-through)
 * @throws HashChainError(HC_SCHEMA_VIOLATION) — any of the three chainIdentity fields non-conformant (pass-through)
 */
export function assertCanonicalPayloadHashConsistent(
    entry: HashChainEntryV02Shape,
    entryIndex: number,
): void {
    // canonicalPayload itself must be in canonical form
    // (otherwise a non-canonical payload could recompute its own hash and pass verification, breaking the I1 injective invariant)
    assertCanonicalPayloadIsCanonical(entry, entryIndex);

    const expectedHashHex = recomputeCanonicalPayloadHash(entry);
    if (entry.canonicalPayloadHash !== expectedHashHex) {
        // the L0 types HccErrorCode v0.2 union of 8 already includes HC_CHAIN_IDENTITY_PREIMAGE_FAILED
        throw new HashChainError(
            'HC_CHAIN_IDENTITY_PREIMAGE_FAILED',
            `entries[${entryIndex}].canonicalPayloadHash ("${entry.canonicalPayloadHash}") mismatch with recomputed preimage hash ("${expectedHashHex}"); chainIdentity or canonicalPayload tampering → cryptographic enforce fail`,
        );
    }
}
