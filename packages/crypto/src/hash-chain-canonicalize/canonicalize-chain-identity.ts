/**
 * canonicalizeChainIdentity — HCC v0.2 L1 crypto helper
 *
 * Responsibility (hcc v0.2 L1 crypto preimage helpers):
 *   - ChainIdentity JCS canonicalize path
 *   - ChainIdentity JCS canonicalize edge-case breakdown
 *   - verifyCanonicalizeConsistency anti-self-equal consistency verify
 *   - RFC 8785 standard skips undefined fields
 *
 * v0.2 upgrade core:
 *   - the chainIdentity three fields (chainNamespace + tenantId? + auditClass?) produce a unique string after RFC 8785 JCS canonicalize
 *   - that string's UTF-8 bytes are concatenated with canonicalPayload UTF-8 bytes and fed into the SHA-256 hash preimage
 *   - any field mutation → the string after JCS canonicalize mutates → SHA-256 digest mutates → verifyHashChain fails
 *
 * L0 types upgrade note:
 *   - the ChainIdentity interface + toChainIdentityJcs() factory + ChainIdentityJcs brand type are currently not in L0 types
 *   - this helper uses an inline ChainIdentityShape (Record-like) input + string output;
 *     once L0 types is extended, this helper switches to the ChainIdentity interface + ChainIdentityJcs brand output.
 *
 * Error-code usage note (vs the current L0 types union difference):
 *   - v0.2 freezes 8 entries (v0.1's 6 + HC_CHAIN_IDENTITY_PREIMAGE_FAILED + HC_CHAIN_IDENTITY_SCHEMA_BREAKING)
 *   - the L0 types HccErrorCode union currently only has v0.1's 6 entries (this helper does not modify L0 types — out of scope)
 *   - this helper throws HC_CANONICALIZE_FAILED (canonicalize undefined / input exception) +
 *     HC_SCHEMA_VIOLATION (empty string / sentinel value) — both are within the v0.1 freeze union,
 *     and after L0 types expands the v0.2 union they can be split into more granular error codes (HC_CHAIN_IDENTITY_CANONICALIZE_FAILED and similar candidates).
 *
 * Anti-phantom defense:
 *   - top-level import of canonicalize npm (no in-body require / dynamic import)
 *   - assertSerializable pre-check (fallback for canonicalize silently returning undefined for undefined / function / symbol)
 *   - must fail-closed throw (no stub default success / silent return allowed; crypto primitive is strict)
 *   - anti-self-equal: verifyCanonicalizeConsistency runs canonicalize twice and compares literal equality
 */

import canonicalizePackage from 'canonicalize';

import { HashChainError } from '@coivitas/types';

/**
 * ChainIdentityShape — chainIdentity three-field inline shape
 *
 * The v0.2 L0 types ChainIdentity interface has not landed in packages/types/;
 * this helper takes a Record-like inline shape; switches to importing ChainIdentity once L0 types is extended.
 *
 * Field semantics (v0.1 + v0.2):
 *   - chainNamespace: mandatory non-empty string (atp / policy / federation, etc.)
 *   - tenantId?: atp callers must provide a UUID v4 (enforced at the factory boundary; sentinel reject); non-atp upstreams may leave it undefined
 *   - auditClass?: atp callers must provide an enum {"L1","L2","L3"}; non-atp upstreams may leave it undefined
 */
export interface ChainIdentityShape {
    /** chain namespace; mandatory non-empty string*/
    chainNamespace: string;
    /** tenant identifier; atp callers must provide a UUID v4; non-atp upstreams may leave it undefined*/
    tenantId?: string;
    /** audit class; atp callers must provide the L1/L2/L3 enum; non-atp upstreams may leave it undefined*/
    auditClass?: string;
}

/**
 * canonicalizeChainIdentity — JCS canonicalize the ChainIdentity three fields to produce a unique string
 *
 * RFC 8785 standard skips undefined fields.
 *
 * Implementation strategy:
 *   - only populate non-undefined fields into obj (RFC 8785 treats skipping undefined as semantically equivalent to a missing field — Case 2)
 *   - canonicalize() internally sorts keys alphabetically (RFC 8785) — Case 3
 *   - undefined → skip; null → factory reject (intercepted by the toChainIdentity factory before this helper); empty string → rejected by this helper (HC_SCHEMA_VIOLATION)
 *
 * @param identity chainIdentity three fields (chainNamespace mandatory non-empty; tenantId/auditClass optional)
 * @returns the string after JCS canonicalize (RFC 8785; changed to the ChainIdentityJcs brand once L0 types is upgraded)
 *
 * @throws HashChainError(HC_SCHEMA_VIOLATION)
 *   - chainNamespace non-string / empty string / sentinel "__NULL__"
 *   - tenantId present but non-string / empty string
 *   - auditClass present but non-string / empty string
 * @throws HashChainError(HC_CANONICALIZE_FAILED)
 *   - canonicalize npm returns undefined (phantom fallback; unreachable after assertSerializable PASS)
 */
export function canonicalizeChainIdentity(
    identity: ChainIdentityShape,
): string {
    // ── step 1: chainNamespace mandatory non-empty + sentinel reject ──
    if (typeof identity.chainNamespace !== 'string') {
        throw new HashChainError(
            'HC_SCHEMA_VIOLATION',
            `canonicalizeChainIdentity: chainNamespace must be string, got: ${typeof identity.chainNamespace}`,
        );
    }
    if (identity.chainNamespace.length === 0) {
        throw new HashChainError(
            'HC_SCHEMA_VIOLATION',
            'canonicalizeChainIdentity: chainNamespace must be non-empty string',
        );
    }
    if (identity.chainNamespace === '__NULL__') {
        throw new HashChainError(
            'HC_SCHEMA_VIOLATION',
            'canonicalizeChainIdentity: chainNamespace must not be sentinel "__NULL__" (SQL COALESCE reserved)',
        );
    }

    // ── step 2: tenantId, if present, must be a non-empty string ──
    if (identity.tenantId !== undefined) {
        if (typeof identity.tenantId !== 'string') {
            throw new HashChainError(
                'HC_SCHEMA_VIOLATION',
                `canonicalizeChainIdentity: tenantId must be string when present, got: ${typeof identity.tenantId}`,
            );
        }
        if (identity.tenantId.length === 0) {
            throw new HashChainError(
                'HC_SCHEMA_VIOLATION',
                'canonicalizeChainIdentity: tenantId must be non-empty string when present',
            );
        }
    }

    // ── step 3: auditClass, if present, must be a non-empty string ──
    if (identity.auditClass !== undefined) {
        if (typeof identity.auditClass !== 'string') {
            throw new HashChainError(
                'HC_SCHEMA_VIOLATION',
                `canonicalizeChainIdentity: auditClass must be string when present, got: ${typeof identity.auditClass}`,
            );
        }
        if (identity.auditClass.length === 0) {
            throw new HashChainError(
                'HC_SCHEMA_VIOLATION',
                'canonicalizeChainIdentity: auditClass must be non-empty string when present',
            );
        }
    }

    // ── step 4: populate obj (only non-undefined fields; RFC 8785 treats skipping undefined as equivalent to missing) ──
    const obj: Record<string, string> = {
        chainNamespace: identity.chainNamespace,
    };
    if (identity.tenantId !== undefined) {
        obj.tenantId = identity.tenantId;
    }
    if (identity.auditClass !== undefined) {
        obj.auditClass = identity.auditClass;
    }

    // ── step 5: canonicalize (RFC 8785 alphabetical key sort) ──
    let serialized: string | undefined;
    try {
        serialized = (
            canonicalizePackage as unknown as (
                input: unknown,
            ) => string | undefined
        )(obj);
    } catch (error) {
        throw new HashChainError(
            'HC_CANONICALIZE_FAILED',
            'canonicalizeChainIdentity: canonicalize npm package threw (input not JCS-serializable per RFC 8785)',
            error instanceof Error ? error : undefined,
        );
    }

    /* v8 ignore next 6 -- after the assertSerializable-equivalent pre-check (step 1-3) PASSes, canonicalize must return a string; phantom fallback*/
    if (typeof serialized !== 'string') {
        throw new HashChainError(
            'HC_CANONICALIZE_FAILED',
            'canonicalizeChainIdentity: canonicalize npm package returned non-string (chainIdentity not JCS-serializable per RFC 8785)',
        );
    }

    return serialized;
}

/**
 * verifyCanonicalizeConsistency — anti-self-equal canonicalize consistency verify
 *
 * Design intent:
 *   - call canonicalize() twice → literal equality verify (same payload, same literal output)
 *   - guards against canonicalize library bug / non-deterministic output / runtime drift
 *   - anti-self-equal: not merely a canonicalize(x) === canonicalize(x) tautology guard,
 *     but rather catches library state drift
 *
 * Usage:
 *   - used at the start of the cross-lang fixture pipeline (TS Producer-side self-consistency verify)
 *   - unnecessary in production code (canonicalize is already deterministic; this helper is test-oriented)
 *
 * @param payload any JSON-serializable input
 * @returns the first canonicalize output string (on PASS)
 *
 * @throws HashChainError(HC_CANONICALIZE_FAILED)
 *   - either canonicalize call returns undefined
 *   - the two canonicalize outputs are not literally equal (canonicalize implementation is non-deterministic)
 */
export function verifyCanonicalizeConsistency(payload: unknown): string {
    let first: string | undefined;
    let second: string | undefined;

    try {
        first = (
            canonicalizePackage as unknown as (
                input: unknown,
            ) => string | undefined
        )(payload);
        second = (
            canonicalizePackage as unknown as (
                input: unknown,
            ) => string | undefined
        )(payload);
    } catch (error) {
        throw new HashChainError(
            'HC_CANONICALIZE_FAILED',
            'verifyCanonicalizeConsistency: canonicalize npm package threw',
            error instanceof Error ? error : undefined,
        );
    }

    if (typeof first !== 'string' || typeof second !== 'string') {
        throw new HashChainError(
            'HC_CANONICALIZE_FAILED',
            `verifyCanonicalizeConsistency: canonicalize returned non-string (first: ${typeof first}, second: ${typeof second})`,
        );
    }

    if (first !== second) {
        throw new HashChainError(
            'HC_CANONICALIZE_FAILED',
            `verifyCanonicalizeConsistency: JCS canonicalize non-deterministic output (first: "${first}", second: "${second}")`,
        );
    }

    return first;
}
