/**
 * canonicalSerialize — CSP L1 crypto primitive
 *
 * Algorithm:
 *   1. JCS canonical encoding (RFC 8785; built on the canonicalize npm package by Erdtman);
 *   2. UTF-8 encode into a Uint8Array (consumed by SHA-256 hash + Ed25519 sign);
 *   3. fail-closed: any invariant violation throws CspError('CSP_SCHEMA_VIOLATION').
 *
 * Robustness hardening:
 *   - top-level import of canonicalize (no in-body require/dynamic import);
 *   - the canonicalize npm package is mandatory (no JSON.stringify fallback);
 *   - undefined / function / symbol / BigInt / NaN / Infinity are unsupported (the canonicalize npm
 *     package does not throw but yields the string "undefined"; here a pre-check assertSerializable adds catch + throw).
 *
 * Distinguished from the existing packages/crypto/src/canonicalization.ts (canonicalize function):
 *   - existing canonicalize: returns a string (JSON string); consumed by hash.sign and similar;
 *   - this canonicalSerialize: returns a Uint8Array (canonical bytes); optimized specifically for the
 *     csp signed payload pipeline (canonicalSerialize → canonicalHash → verifySignature);
 *     its output "signedBytes" has Uint8Array semantics;
 *   - both share the canonicalize npm package core (the sole RFC 8785 implementation);
 *     no divergence in the canonicalize algorithm is introduced (design principle: a single canonicalize).
 */

import canonicalizePackage from 'canonicalize';

import { CspError } from './types.js';

const textEncoder = new TextEncoder();

/**
 * assertSerializable — rejects input types for which canonicalize npm silently yields "undefined"
 *
 * The canonicalize npm package (RFC 8785) silently returns the string "undefined" for
 * undefined / function / symbol; throws TypeError for BigInt; and silently produces a "null"
 * serialization for NaN/Infinity. This function pre-checks and explicitly throws
 * CspError(CSP_SCHEMA_VIOLATION) to prevent downstream hash/sign from receiving
 * undefined/garbage bytes and triggering a hard-to-diagnose ed25519 verify FAIL (fail-closed safeguard).
 *
 * Same semantics as packages/crypto/src/canonicalization.ts:assertSerializable;
 * implemented independently here rather than reused via import — because of the CryptoError vs CspError error-code namespace isolation.
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
        throw new CspError(
            'CSP_SCHEMA_VIOLATION',
            `canonicalSerialize: unsupported value type at ${path || '$'} (undefined/function/symbol/bigint not JCS-serializable per RFC 8785).`,
        );
    }

    if (typeof value === 'number' && !Number.isFinite(value)) {
        throw new CspError(
            'CSP_SCHEMA_VIOLATION',
            `canonicalSerialize: non-finite number at ${path || '$'} (NaN/Infinity not JCS-serializable per RFC 8785).`,
        );
    }

    if (value === null || typeof value !== 'object') {
        return;
    }

    if (seen.has(value)) {
        throw new CspError(
            'CSP_SCHEMA_VIOLATION',
            `canonicalSerialize: circular reference detected at ${path || '$'} (cyclic graph not JCS-serializable per RFC 8785).`,
        );
    }

    seen.add(value);

    if (Array.isArray(value)) {
        value.forEach((entry, index) => {
            assertSerializable(entry, seen, `${path}[${index}]`);
        });
        seen.delete(value);
        return;
    }

    for (const [key, entry] of Object.entries(value)) {
        assertSerializable(entry, seen, path ? `${path}.${key}` : key);
    }

    seen.delete(value);
}

/**
 * canonicalSerialize — JCS canonical encode + UTF-8 encode into a Uint8Array
 *
 * @param payload csp signed payload (any JSON-serializable Record); the typical input is the 5
 *   CanonicalSignedPayload interface fields + the cspVersion metadata field; the caller instance is not
 *   constrained; any sub-protocol primitive may reuse this function (e.g. the single-signer
 *   signed payload reuse for multisig signers[i].signature).
 * @returns canonical bytes (RFC 8785 JCS UTF-8); consumed by canonicalHash / Ed25519 sign.
 * @throws CspError(CSP_SCHEMA_VIOLATION) — payload is not JCS-serializable (undefined/function/symbol/
 *   bigint/NaN/Infinity/circular ref) OR canonicalize npm fails internally.
 */
export function canonicalSerialize(
    payload: Record<string, unknown>,
): Uint8Array {
    // step 1: pre-check (canonicalize npm does not strictly reject some invalid values)
    assertSerializable(payload, new WeakSet<object>(), '$');

    // step 2: JCS canonical encode (RFC 8785; canonicalize npm by Erdtman)
    let serialized: string | undefined;
    try {
        serialized = (
            canonicalizePackage as unknown as (
                input: unknown,
            ) => string | undefined
        )(payload);
    } catch (error) {
        throw new CspError(
            'CSP_SCHEMA_VIOLATION',
            'canonicalSerialize: canonicalize npm package threw (input not JCS-serializable per RFC 8785).',
            error instanceof Error ? error : undefined,
        );
    }

    // step 3: safeguard for canonicalize npm silently returning undefined
    if (typeof serialized !== 'string') {
        throw new CspError(
            'CSP_SCHEMA_VIOLATION',
            'canonicalSerialize: canonicalize npm package returned non-string (payload not JCS-serializable per RFC 8785).',
        );
    }

    // step 4: UTF-8 encode into a Uint8Array ("signedBytes" semantics)
    return textEncoder.encode(serialized);
}

/**
 * canonicalSerializeToString — JCS canonical encode → string form (for testing / debugging)
 *
 * Shares the same canonicalize npm package core as canonicalSerialize; outputs a string rather than a Uint8Array.
 * Primary uses:
 *   - unit-test assertions (string comparison is more readable);
 *   - debug log output (binary signedBytes is not human-readable);
 *   - cross-sub-protocol-primitive debugging (sharing the same JCS canonicalize algorithm).
 *
 * Production code paths should prefer canonicalSerialize (Uint8Array; fed directly to hash/sign;
 * avoiding repeated string ↔ Uint8Array conversion).
 */
export function canonicalSerializeToString(
    payload: Record<string, unknown>,
): string {
    assertSerializable(payload, new WeakSet<object>(), '$');

    let serialized: string | undefined;
    try {
        serialized = (
            canonicalizePackage as unknown as (
                input: unknown,
            ) => string | undefined
        )(payload);
    } catch (error) {
        throw new CspError(
            'CSP_SCHEMA_VIOLATION',
            'canonicalSerializeToString: canonicalize npm package threw (input not JCS-serializable per RFC 8785).',
            error instanceof Error ? error : undefined,
        );
    }

    if (typeof serialized !== 'string') {
        throw new CspError(
            'CSP_SCHEMA_VIOLATION',
            'canonicalSerializeToString: canonicalize npm package returned non-string (payload not JCS-serializable per RFC 8785).',
        );
    }

    return serialized;
}
