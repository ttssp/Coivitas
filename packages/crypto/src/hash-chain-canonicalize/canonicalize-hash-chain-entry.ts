/**
 * canonicalizeHashChainEntry — HCC L1 crypto primitive
 *
 * Design principle: RFC 8785 JCS enforced and exclusive (no JSON.stringify fallback);
 * top-level import canonicalize; canonicalize is the sole carrier of uniqueness.
 *
 * Algorithm:
 *   1. assertSerializable pre-check (guards against canonicalize npm silently producing undefined);
 *   2. JCS canonical encoding (RFC 8785; canonicalize npm by Erdtman);
 *   3. UTF-8 encode to Uint8Array (consumed by the SHA-256 hash);
 *   4. fail-closed: any invariant violation throws HashChainError(HC_CANONICALIZE_FAILED).
 *
 * Distinction from the existing packages/crypto/src/canonicalization.ts (canonicalize function):
 *   - existing canonicalize: returns string; consumed generically by hash/sign etc.;
 *   - this canonicalizeHashChainEntry: returns Uint8Array; optimized for the hcc entry pipeline
 *     (canonicalize → SHA-256 → previousHash linking);
 *   - both share the canonicalize npm package underneath (RFC 8785 single implementation; canonicalize exclusive).
 *
 * Distinction from the existing csp canonicalSerialize (packages/crypto/src/canonical-signed-payload/canonical-serialize.ts):
 *   - csp canonicalSerialize throws CspError(CSP_SCHEMA_VIOLATION); hcc throws HashChainError(HC_CANONICALIZE_FAILED);
 *   - error-code namespace isolation (HC_* does not clash with CSP_*);
 *   - the algorithm layer is 100% shared via the canonicalize npm package (RFC 8785 single implementation; no algorithmic divergence introduced).
 *
 * Robustness defenses:
 *   - top-level import canonicalize (no in-function require/dynamic import);
 *   - canonicalize npm package enforced (JSON.stringify fallback forbidden);
 *   - assertSerializable pre-check (guards against canonicalize npm silently returning undefined for undefined/function/symbol);
 *   - no stub default success / silent return allowed (crypto primitive is strictly fail-closed).
 */

import canonicalizePackage from 'canonicalize';

import { HashChainError } from '@coivitas/types';

const textEncoder = new TextEncoder();

/**
 * assertSerializable — rejects input types that make canonicalize npm silently produce undefined
 *
 * The canonicalize npm package (RFC 8785) silently returns an undefined string for
 * undefined / function / symbol; throws TypeError for BigInt; and silently produces a "null"
 * serialization for NaN/Infinity. This function does a pre-check plus an explicit
 * throw HashChainError(HC_CANONICALIZE_FAILED) so the downstream hash never receives
 * undefined/garbage bytes that would trigger a hard-to-diagnose verify FAIL (fail-closed fallback).
 *
 * Same semantics as csp canonicalSerialize's assertSerializable;
 * implemented independently here rather than imported and reused — because of the CspError vs HashChainError error-code namespace isolation.
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
        throw new HashChainError(
            'HC_CANONICALIZE_FAILED',
            `canonicalizeHashChainEntry: unsupported value type at ${path || '$'} (undefined/function/symbol/bigint not JCS-serializable per RFC 8785).`,
        );
    }

    if (typeof value === 'number' && !Number.isFinite(value)) {
        throw new HashChainError(
            'HC_CANONICALIZE_FAILED',
            `canonicalizeHashChainEntry: non-finite number at ${path || '$'} (NaN/Infinity not JCS-serializable per RFC 8785).`,
        );
    }

    if (value === null || typeof value !== 'object') {
        return;
    }

    if (seen.has(value)) {
        throw new HashChainError(
            'HC_CANONICALIZE_FAILED',
            `canonicalizeHashChainEntry: circular reference detected at ${path || '$'} (cyclic graph not JCS-serializable per RFC 8785).`,
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
 * canonicalizeHashChainEntry — JCS canonical encode + UTF-8 encode to Uint8Array
 *
 * Design principle: canonicalize exclusive.
 *
 * @param payload Raw payload object; after JCS canonicalization it is written to
 *   HashChainEntry.canonicalPayload (converted to string via TextDecoder.decode). Accepts any
 *   JSON-serializable Record; not tied to a specific caller; reusable by any upstream such as
 *   audit-tamper-proof / policy / governance.
 * @returns canonical bytes (RFC 8785 JCS UTF-8); consumed by sha256 + previousHash linking.
 * @throws HashChainError(HC_CANONICALIZE_FAILED) — payload not JCS-serializable (undefined / function /
 *   symbol / bigint / NaN / Infinity / circular ref) OR an internal failure in canonicalize npm.
 */
export function canonicalizeHashChainEntry(
    payload: Record<string, unknown>,
): Uint8Array {
    // step 1: pre-check (canonicalize npm does not strictly reject some invalid values)
    assertSerializable(payload, new WeakSet<object>(), '$');

    // step 2: JCS canonical encode (RFC 8785; canonicalize npm by Erdtman)
    let serialized: string | undefined;
    /* v8 ignore start -- canonicalize npm does not throw for input that passed assertSerializable; defensive fallback, unreachable*/
    try {
        serialized = (
            canonicalizePackage as unknown as (
                input: unknown,
            ) => string | undefined
        )(payload);
    } catch (error) {
        throw new HashChainError(
            'HC_CANONICALIZE_FAILED',
            'canonicalizeHashChainEntry: canonicalize npm package threw (input not JCS-serializable per RFC 8785).',
            error instanceof Error ? error : undefined,
        );
    }
    /* v8 ignore stop*/

    // step 3: fallback for canonicalize npm silently returning undefined
    /* v8 ignore next 6 -- canonicalize npm always returns a string after assertSerializable PASS; defensive fallback, unreachable*/
    if (typeof serialized !== 'string') {
        throw new HashChainError(
            'HC_CANONICALIZE_FAILED',
            'canonicalizeHashChainEntry: canonicalize npm package returned non-string (payload not JCS-serializable per RFC 8785).',
        );
    }

    // step 4: UTF-8 encode to Uint8Array
    return textEncoder.encode(serialized);
}

/**
 * canonicalizeHashChainEntryToString — JCS canonical encode → string form
 *
 * Shares the underlying canonicalize npm package with canonicalizeHashChainEntry; outputs a string instead of a Uint8Array.
 * Primary uses:
 *   - the HashChainEntry.canonicalPayload field value (the JCS-canonicalized JSON string);
 *   - unit-test assertions (string comparison is more readable);
 *   - the cross-lang fixture pipeline (TypeScript writes a string fixture → Python reads the string);
 *   - JSON Schema validation (the canonicalPayload field is of string type).
 *
 * The algorithm path is identical to canonicalizeHashChainEntry (assertSerializable + canonicalize npm);
 * only the output format differs (string vs Uint8Array); both are allowed on the production code path.
 */
export function canonicalizeHashChainEntryToString(
    payload: Record<string, unknown>,
): string {
    assertSerializable(payload, new WeakSet<object>(), '$');

    let serialized: string | undefined;
    /* v8 ignore start -- canonicalize npm does not throw for input that passed assertSerializable; defensive fallback, unreachable*/
    try {
        serialized = (
            canonicalizePackage as unknown as (
                input: unknown,
            ) => string | undefined
        )(payload);
    } catch (error) {
        throw new HashChainError(
            'HC_CANONICALIZE_FAILED',
            'canonicalizeHashChainEntryToString: canonicalize npm package threw (input not JCS-serializable per RFC 8785).',
            error instanceof Error ? error : undefined,
        );
    }
    /* v8 ignore stop*/

    /* v8 ignore next 6 -- canonicalize npm always returns a string after assertSerializable PASS; defensive fallback, unreachable*/
    if (typeof serialized !== 'string') {
        throw new HashChainError(
            'HC_CANONICALIZE_FAILED',
            'canonicalizeHashChainEntryToString: canonicalize npm package returned non-string (payload not JCS-serializable per RFC 8785).',
        );
    }

    return serialized;
}
