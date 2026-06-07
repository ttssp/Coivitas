/**
 * canonicalizeResolvedCredentialIntegrityProof — CR L1 crypto primitive
 *
 * Responsibility:
 *            csp 5-field invariant +
 *            RFC 8785 JCS canonicalize
 *
 * Algorithm:
 *   1. extract the 5-field invariant + cspVersion metadata to form the canonical payload
 *      (token / disclosedClaims / challenge / audience / notAfter + cspVersion);
 *   2. JCS canonical encoding (RFC 8785; canonicalize npm by Erdtman;
 *      consistent pattern with csp v0.1; JSON.stringify fallback forbidden);
 *   3. UTF-8 encode to Uint8Array (consumed by Ed25519 sign / verify);
 *   4. fail-closed: any invariant violation throws CrError + error code CR_INTEGRITY_PROOF_INVALID.
 *
 * Anti-phantom defense:
 *   - top-level import of canonicalize (no in-body require/dynamic import);
 *   - the canonicalize npm package is enforced (JSON.stringify fallback forbidden);
 *   - undefined / function / symbol / BigInt / NaN / Infinity not supported (canonicalize npm
 *     silently yields undefined / throws TypeError for these; pre-check + explicit throw here).
 *
 * Shares the canonicalize npm foundation with csp canonicalSerialize / hcc canonicalizeHashChainEntry:
 *   - the csp / hcc / cr sub-protocols share the single RFC 8785 JCS implementation (canonicalize npm by Erdtman);
 *   - no canonicalize algorithm divergence introduced (single canonicalize);
 *   - error-code namespace isolation: CR_INTEGRITY_PROOF_INVALID vs CSP_SCHEMA_VIOLATION vs HC_CANONICALIZE_FAILED.
 *
 * 5-field invariant order (consistent with csp v0.1):
 *   {token, disclosedClaims, challenge, audience, notAfter, cspVersion}
 *   Note: JCS canonical encoding automatically sorts by field name lexicographically (RFC 8785);
 *   the "order" here refers to the object field names; JCS output is always lexicographic token-sorted.
 */

import canonicalizePackage from 'canonicalize';

import type { ResolvedCredentialIntegrityProof } from '@coivitas/types';
import { CrError } from '@coivitas/types';

const textEncoder = new TextEncoder();

/**
 * ResolvedCredentialIntegrityProofSignedPayload — JCS canonical input (5 fields + cspVersion; no proofSignature / resolverDid)
 *
 * Field composition:
 *   {token, disclosedClaims, challenge, audience, notAfter, cspVersion}
 *
 * Note: excludes proofSignature (the verifier side reassembles this payload → JCS canonicalize →
 * compares against the stored signature to verify; proofSignature is the verify object itself, it
 * cannot sign itself) and excludes resolverDid (resolverDid is the signer's public DID; it is
 * associated to the corresponding publicKey via proofSignature verification; exposing unsigned fields
 * inline in the payload is strictly forbidden).
 */
export interface ResolvedCredentialIntegrityProofSignedPayload {
    /** csp 5-field invariant, field 1*/
    readonly token: string;
    /** csp 5-field invariant, field 2*/
    readonly disclosedClaims: readonly string[];
    /** csp 5-field invariant, field 3*/
    readonly challenge: string;
    /** csp 5-field invariant, field 4 (did:* DID string)*/
    readonly audience: string;
    /** csp 5-field invariant, field 5 (ISO 8601)*/
    readonly notAfter: string;
    /** csp mandatory metadata (v0.1 only value "1.0.0")*/
    readonly cspVersion: string;
}

/**
 * assertSerializable — rejects inputs for which canonicalize npm silently yields undefined / throws TypeError
 *
 * The canonicalize npm package (RFC 8785) silently returns an undefined string for
 * undefined / function / symbol; throws TypeError for BigInt; silently produces a "null"
 * serialization result for NaN / Infinity.
 *
 * This function pre-checks + explicitly throws CrError(CR_INTEGRITY_PROOF_INVALID) to prevent
 * downstream hash/sign from receiving undefined/garbage bytes and triggering a hard-to-diagnose
 * ed25519 verify FAIL (fail-closed fallback).
 *
 * Anti-phantom: same semantics as the csp / hcc canonicalize primitive;
 * implemented independently here rather than reused via import — because of the CrError vs CspError
 * vs HashChainError error-code namespace isolation.
 */
function assertSerializable(
    value: unknown,
    seen: WeakSet<object>,
    path: string,
): void {
    if (
        value === undefined ||
        typeof value === 'function' ||
        typeof value === 'symbol' ||
        typeof value === 'bigint'
    ) {
        throw new CrError('CR_INTEGRITY_PROOF_INVALID', {
            reason: 'jcs_unsupported_value_type',
            path: path || '$',
            valueType: typeof value,
            detail: 'undefined/function/symbol/bigint not JCS-serializable per RFC 8785',
        });
    }

    if (typeof value === 'number' && !Number.isFinite(value)) {
        throw new CrError('CR_INTEGRITY_PROOF_INVALID', {
            reason: 'jcs_non_finite_number',
            path: path || '$',
            detail: 'NaN/Infinity not JCS-serializable per RFC 8785',
        });
    }

    if (value === null || typeof value !== 'object') {
        return;
    }

    if (seen.has(value)) {
        throw new CrError('CR_INTEGRITY_PROOF_INVALID', {
            reason: 'jcs_circular_reference',
            path: path || '$',
            detail: 'cyclic graph not JCS-serializable per RFC 8785',
        });
    }

    seen.add(value);

    if (Array.isArray(value)) {
        value.forEach((item, idx) => {
            assertSerializable(item, seen, `${path}[${idx}]`);
        });
        return;
    }

    for (const [key, val] of Object.entries(value)) {
        assertSerializable(val, seen, path ? `${path}.${key}` : key);
    }
}

/**
 * extractSignedPayload — extracts the signed payload from a full ResolvedCredentialIntegrityProof (strips proofSignature)
 *
 * signedPayload has 5 fields + cspVersion; excludes proofSignature.
 *
 * Note: resolverDid does not enter signedPayload (resolverDid is the signer identity; the verifier
 * resolves publicKey via resolverDid, then uses publicKey to verify proofSignature);
 * inlining resolverDid in signedPayload would not guard against audience hijack — an attacker could
 * change resolverDid and then verify successfully using the attacker's publicKey.
 *
 * @param proof full integrity proof object
 * @returns 6-field signed payload (5-field invariant + cspVersion)
 */
export function extractIntegrityProofSignedPayload(
    proof: ResolvedCredentialIntegrityProof,
): ResolvedCredentialIntegrityProofSignedPayload {
    return {
        token: proof.token,
        disclosedClaims: proof.disclosedClaims,
        challenge: proof.challenge,
        audience: proof.audience,
        notAfter: proof.notAfter,
        cspVersion: proof.cspVersion,
    };
}

/**
 * canonicalizeResolvedCredentialIntegrityProof — JCS canonical encode → Uint8Array
 *
 * Algorithm (buildIntegrityProof + reconstructed during verify-side checks):
 *   1. assertSerializable(payload) → rejects undefined/function/symbol/bigint/NaN/Infinity/circular;
 *   2. canonicalize(payload) → JCS canonical JSON string (RFC 8785);
 *   3. canonicalize returns undefined → throw CR_INTEGRITY_PROOF_INVALID (canonicalize npm silent failure);
 *   4. textEncoder.encode → Uint8Array (UTF-8 byte sequence);
 *   5. return Uint8Array (consumed by Ed25519 sign / verify).
 *
 * @param payload signed payload object (5 fields + cspVersion; constructed by extractIntegrityProofSignedPayload)
 * @returns Uint8Array — canonical bytes (UTF-8)
 * @throws CrError(CR_INTEGRITY_PROOF_INVALID) — canonicalize failure OR input contains an illegal type
 */
export function canonicalizeResolvedCredentialIntegrityProof(
    payload: ResolvedCredentialIntegrityProofSignedPayload,
): Uint8Array {
    // step 1: pre-check (fail-closed; guards against canonicalize npm silent failure)
    assertSerializable(payload as unknown, new WeakSet<object>(), '');

    // step 2: JCS canonical encode (RFC 8785; canonicalize npm by Erdtman)
    let canonicalString: string | undefined;
    try {
        canonicalString = (
            canonicalizePackage as unknown as (
                input: unknown,
            ) => string | undefined
        )(payload);
    } catch (err) {
        // canonicalize npm throws TypeError or similar → fail-closed (production-only edge;
        // assertSerializable already pre-checks the main types; defense-in-depth fallback here)
        /* v8 ignore next 4*/
        throw new CrError('CR_INTEGRITY_PROOF_INVALID', {
            reason: 'jcs_canonicalize_threw',
            detail: err instanceof Error ? err.message : String(err),
        });
    }

    // step 3: canonicalize npm silent-failure fallback (returns undefined;
    // assertSerializable already pre-checks the main unsupported types → theoretically unreachable here; defense-in-depth)
    if (canonicalString === undefined) {
        /* v8 ignore next 4*/
        throw new CrError('CR_INTEGRITY_PROOF_INVALID', {
            reason: 'jcs_canonicalize_returned_undefined',
            detail: 'canonicalize npm produced undefined (likely unsupported value type passed pre-check)',
        });
    }

    // step 4: UTF-8 encode to Uint8Array
    return textEncoder.encode(canonicalString);
}

/**
 * canonicalizeResolvedCredentialIntegrityProofToString — JCS canonical encode → string
 *
 * Equivalent to canonicalizeResolvedCredentialIntegrityProof, but returns a string (rather than a
 * Uint8Array); used in debugging / logging / hash digest hex and similar scenarios.
 *
 * @param payload signed payload object
 * @returns string — canonical JSON string
 * @throws CrError(CR_INTEGRITY_PROOF_INVALID)
 */
export function canonicalizeResolvedCredentialIntegrityProofToString(
    payload: ResolvedCredentialIntegrityProofSignedPayload,
): string {
    assertSerializable(payload as unknown, new WeakSet<object>(), '');

    let canonicalString: string | undefined;
    try {
        canonicalString = (
            canonicalizePackage as unknown as (
                input: unknown,
            ) => string | undefined
        )(payload);
    } catch (err) {
        // canonicalize npm throws TypeError or similar → fail-closed defense-in-depth
        /* v8 ignore next 4*/
        throw new CrError('CR_INTEGRITY_PROOF_INVALID', {
            reason: 'jcs_canonicalize_threw',
            detail: err instanceof Error ? err.message : String(err),
        });
    }

    if (canonicalString === undefined) {
        // canonicalize returns undefined fallback (defense-in-depth; assertSerializable already pre-checks)
        /* v8 ignore next 4*/
        throw new CrError('CR_INTEGRITY_PROOF_INVALID', {
            reason: 'jcs_canonicalize_returned_undefined',
            detail: 'canonicalize npm produced undefined (likely unsupported value type passed pre-check)',
        });
    }

    return canonicalString;
}
