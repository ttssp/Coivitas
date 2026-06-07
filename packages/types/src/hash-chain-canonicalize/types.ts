/**
 * Hash Chain Canonicalize (HCC) L0 type definitions.
 *
 * hcc v0.2 sub-protocol
 *
 * v0.2 upgrade contents:
 *   - ChainIdentity interface + ChainNamespace brand added (v0.1 → v0.2, promoted into L0)
 *   - ChainIdentityJcs brand added (new brand in v0.2; string produced by JCS canonicalize)
 *   - HashChainEntry upgraded to 8 fields (added the required chainIdentity field; v0.1 7 fields → v0.2 8 fields)
 *   - HccErrorCode now 8 entries (v0.1 6 entries + 2 added in v0.2: HC_CHAIN_IDENTITY_PREIMAGE_FAILED + HC_CHAIN_IDENTITY_SCHEMA_BREAKING)
 *   - HCC_SUPPORTED_VERSIONS upgraded to ["2.0.0"]; HCC_VERSION_CURRENT = "2.0.0"
 *   - JSON Schema: hash-chain-entry-v0.2.schema.json (chainIdentity required + hccVersion const "2.0.0")
 *
 * Triple defense (reuses the csp pattern):
 *   Line 1: TypeScript brand types (compile time; this file)
 *   Line 2: JSON Schema format (runtime Schema layer; hash-chain-entry-v0.2.schema.json)
 *   Line 3: AJV strict mode (runtime Schema-engine layer; hcc-validation.ts)
 *
 * "no brand cast" guard: all brand types can only be obtained through the to*() factory functions;
 *           directly casting via `as CanonicalPayloadHash` / `as PreviousHash` / `as ChainPosition` etc. is strictly forbidden.
 *
 * Error-code namespace isolation (v0.2 freezes 8 entries; v0.1's 6 entries retained + 2 added in v0.2):
 *   v0.1 6 entries (retained):
 *   - HC_CANONICALIZE_FAILED — JCS canonicalize failed
 *   - HC_HASH_MISMATCH — SHA-256 recomputation does not match
 *   - HC_PREVIOUS_HASH_BROKEN — previousHash link broken
 *   - HC_CHAIN_POSITION_NONMONOTONIC — chainPosition non-monotonic
 *   - HC_FIXTURE_CROSS_LANG_MISMATCH — cross-lang fixture digest mismatch
 *   - HC_SCHEMA_VIOLATION — Schema validation failed / brand factory validation failed
 *   v0.2 2 added entries:
 *   - HC_CHAIN_IDENTITY_PREIMAGE_FAILED — chainIdentity-in-preimage recomputation does not match (preimage integrity invariant)
 *   - HC_CHAIN_IDENTITY_SCHEMA_BREAKING — hccVersion is not "2.0.0" (version-isolation invariant; schema breaking change)
 */

import type { Timestamp } from '../base.js';

// ─── Brand Types (first line of defense; "no brand cast" guard) ───────────────────────────────────────

/**
 * ChainNamespace — hash-chain namespace brand type (added in v0.2).
 *
 * Legal path: the toChainNamespace() factory (non-empty string; length [1, 128]);
 * represents the application domain the chain belongs to (e.g. "atp" / "policy" / "governance").
 * Directly casting via `s as ChainNamespace` is strictly forbidden (no brand cast).
 */
export type ChainNamespace = string & { readonly __brand: 'ChainNamespace' };

/**
 * ChainIdentityJcs — brand for the string produced by JCS-canonicalizing chainIdentity's three fields (added in v0.2).
 *
 * Design intent:
 *   - the three chainIdentity fields (chainNamespace + tenantId? + auditClass?) produce a unique string after RFC 8785 JCS canonicalize
 *   - that string's UTF-8 bytes, concatenated after the canonicalPayload UTF-8 bytes, enter the SHA-256 hash preimage
 *   - mutating any field → mutates the JCS-canonicalized string → mutates the SHA-256 digest → verifyHashChain fails
 *   - sentinel reject: '__NULL__' is reserved for SQL COALESCE; the factory rejects this value
 *
 * Legal path: the toChainIdentityJcs() factory (called after the L1 crypto layer's canonicalizeChainIdentity() produces the string);
 * directly casting via `s as ChainIdentityJcs` is strictly forbidden (no brand cast).
 */
export type ChainIdentityJcs = string & {
    readonly __brand: 'ChainIdentityJcs';
};

/**
 * HashChainEntryId — unique identifier for a hash-chain entry (UUID v4 brand).
 *
 * factory: toHashChainEntryId().
 * Directly casting via `as HashChainEntryId` is not allowed (no brand cast).
 */
export type HashChainEntryId = string & {
    readonly __brand: 'HashChainEntryId';
};

/**
 * CanonicalPayloadHash — SHA-256 digest after JCS canonicalization (64 lowercase hex).
 *
 * factory: toCanonicalPayloadHash().
 * Directly casting via `as CanonicalPayloadHash` is not allowed (no brand cast).
 */
export type CanonicalPayloadHash = string & {
    readonly __brand: 'CanonicalPayloadHash';
};

/**
 * PreviousHash — the previous entry's canonicalPayloadHash (link field).
 *
 * factory: toPreviousHash().
 * genesis entry: PreviousHash = "0".repeat(64) (64 zeros);
 * directly casting via `as PreviousHash` is not allowed (no brand cast).
 */
export type PreviousHash = string & { readonly __brand: 'PreviousHash' };

/**
 * ChainPosition — the ordinal position of an entry within the hash chain (non-negative safe integer; monotonically increasing).
 *
 * factory: toChainPosition().
 * Invariant: chainPosition(n+1) = chainPosition(n) + 1.
 * Directly casting via `as ChainPosition` is not allowed (no brand cast).
 */
export type ChainPosition = number & { readonly __brand: 'ChainPosition' };

/**
 * HccVersionString — HCC protocol version brand type (independent namespace).
 *
 * v0.1's only legal value is "1.0.0".
 * Directly casting via `as HccVersionString` is not allowed (no brand cast).
 */
export type HccVersionString = string & {
    readonly __brand: 'HccVersionString';
};

// ─── HCC error codes (namespace-isolated HC_*) ─────────────────

/**
 * HccErrorCode — hcc error-code namespace (HC_* prefix; v0.2 freezes 8 entries).
 *
 * v0.1 6 entries (frozen; rename / remove not allowed):
 *   HC_CANONICALIZE_FAILED → JCS canonicalize forced path failed (function / Symbol / circular ref, etc.)
 *   HC_HASH_MISMATCH → SHA-256 recomputation ≠ stored canonicalPayloadHash
 *   HC_PREVIOUS_HASH_BROKEN → previousHash link broken (intermediate deleted / tampered)
 *   HC_CHAIN_POSITION_NONMONOTONIC → chainPosition gap / duplicate / not equal to i
 *   HC_FIXTURE_CROSS_LANG_MISMATCH → cross-lang fixture digest mismatch
 *   HC_SCHEMA_VIOLATION → schema validation failed / brand factory validation failed / field missing
 *
 * v0.2 2 added entries (chain-identity preimage upgrade):
 *   HC_CHAIN_IDENTITY_PREIMAGE_FAILED → chainIdentity-in-preimage recomputation does not match (tampering any field → hash mismatch)
 *   HC_CHAIN_IDENTITY_SCHEMA_BREAKING → hccVersion is not "2.0.0" (schema breaking change, version isolation)
 *
 * Frozen: 8 error codes; later v0.3+ may only add new ones.
 */
export type HccErrorCode =
    | 'HC_CANONICALIZE_FAILED'
    | 'HC_HASH_MISMATCH'
    | 'HC_PREVIOUS_HASH_BROKEN'
    | 'HC_CHAIN_POSITION_NONMONOTONIC'
    | 'HC_FIXTURE_CROSS_LANG_MISMATCH'
    | 'HC_SCHEMA_VIOLATION'
    | 'HC_CHAIN_IDENTITY_PREIMAGE_FAILED'
    | 'HC_CHAIN_IDENTITY_SCHEMA_BREAKING';

// ─── HashChainEntry Interface ─────────────────────────────────────────

/**
 * ChainIdentity — the hash chain's identity-constraint triple (required in v0.2; promoted into L0).
 *
 * In v0.1, ChainIdentity was an L3 manager boundary contract; in v0.2 it is promoted into the L0 types:
 *   - the three chainIdentity fields, JCS-canonicalized, have their UTF-8 bytes enter the SHA-256 hash preimage
 *   - mutating any field → hash mismatch → verifyHashChain fails (preimage integrity invariant)
 *
 * Fields:
 *   - chainNamespace: required non-empty string (e.g. "atp" / "policy" / "governance")
 *   - tenantId?: required for atp callers; may be undefined for non-atp upstreams (UUID v4 string)
 *   - auditClass?: required as L1/L2/L3 for atp callers; may be undefined for non-atp upstreams
 *
 * JSON Schema: hash-chain-entry-v0.2.schema.json $defs/ChainIdentity
 *   required: ["chainNamespace"] + optional tenantId (format: uuid) + optional auditClass (enum: L1/L2/L3)
 */
export interface ChainIdentity {
    /** required non-empty string; the application domain the chain belongs to*/
    chainNamespace: ChainNamespace;
    /** tenant UUID; required for atp callers; may be undefined for non-atp upstreams*/
    tenantId?: string;
    /** audit level; required as L1/L2/L3 for atp callers; may be undefined for non-atp upstreams*/
    auditClass?: 'L1' | 'L2' | 'L3';
}

/**
 * HashChainEntry — the complete structure of a single entry in the hash chain (v0.2 upgrade; 8 fields).
 *
 * The primary data structure of hcc v0.2.
 *
 * Invariants (the v0.2 upgrade adds chainIdentity preimage + version isolation):
 *   - entryId: HashChainEntryId (UUID v4; the entry's unique identifier)
 *   - canonicalPayload: string (JCS-canonicalized JSON string; RFC 8785; JSON.stringify output is not allowed)
 *   - canonicalPayloadHash: CanonicalPayloadHash (SHA-256(canonicalPayloadBytes || chainIdentityJcsBytes), lowercase hex, 64 chars; v0.2 upgrade)
 *   - previousHash: PreviousHash (the previous entry's canonicalPayloadHash; genesis = "0".repeat(64))
 *   - chainPosition: ChainPosition (starts at 0; monotonically increasing; no gaps allowed)
 *   - chainIdentity: ChainIdentity (required in v0.2; chainNamespace+tenantId?+auditClass?; enters the preimage after JCS)
 *   - timestamp: Timestamp (ISO 8601 UTC; the entry's write time)
 *   - hccVersion: HccVersionString (v0.2's only legal value "2.0.0"; schema breaking change)
 *
 * v0.2 changes:
 *   - added the required field chainIdentity (L3 manager v0.1 boundary contract → promoted into L0 types; replaces the misplaced scope)
 *   - upgraded the canonicalPayloadHash computation: SHA-256(canonicalPayloadBytes || chainIdentityJcsBytes)
 *   - hccVersion raised to "2.0.0" (schema breaking change; SQL migration 028 backward compatibility actually implemented)
 */
export interface HashChainEntry {
    /** the entry's unique identifier (UUID v4)*/
    entryId: HashChainEntryId;
    /** JCS-canonicalized payload JSON string (RFC 8785 JCS; JSON.stringify output is not allowed)*/
    canonicalPayload: string;
    /** SHA-256(canonicalPayloadBytes || chainIdentityJcsBytes), lowercase hex, 64 chars; v0.2 upgraded preimage*/
    canonicalPayloadHash: CanonicalPayloadHash;
    /**
     * the previous entry's canonicalPayloadHash
     * genesis entry: PreviousHash = "0000000000000000000000000000000000000000000000000000000000000000" (64 zeros)
     */
    previousHash: PreviousHash;
    /** starts at 0, monotonically increasing; position within the chain (monotonic-increase invariant)*/
    chainPosition: ChainPosition;
    /**
     * chain namespace + tenant + audit class (required field added in v0.2)
     * after JCS canonicalize, the UTF-8 bytes are concatenated after the canonicalPayload bytes and enter the SHA-256 hash preimage
     * tampering any field → hash mismatch → verifyHashChain fails (preimage integrity invariant)
     */
    chainIdentity: ChainIdentity;
    /** the entry's write time (ISO 8601 UTC)*/
    timestamp: Timestamp;
    /** HCC protocol version (v0.2's only legal value "2.0.0"; schema breaking change)*/
    hccVersion: HccVersionString;
}

// ─── Constants (factory function dependencies + genesis convention) ──────────────

/**
 * GENESIS_PREVIOUS_HASH — the fixed previousHash value of the genesis entry (64 zeros).
 *
 * `"0".repeat(64)`.
 * Callers may not construct other 64-zero variants themselves; reference this constant uniformly.
 */
export const GENESIS_PREVIOUS_HASH = '0'.repeat(64);

/**
 * The set of HCC-supported versions (v0.2's only value "2.0.0"; independent hccVersion namespace).
 *
 * Used by the toHccVersionString factory; independent hccVersion namespace.
 * v0.1 "1.0.0" → v0.2 "2.0.0" upgrade
 * (schema breaking change; SQL migration 028 backward compatibility actually implemented).
 * Later v0.3+ extensions are added to this array.
 *
 * Note: HCC_SUPPORTED_VERSIONS stores a runtime set of strings;
 * the brand-type constraint is guaranteed by the toHccVersionString() factory at its return value.
 */
export const HCC_SUPPORTED_VERSIONS: readonly string[] = ['2.0.0'] as const;

/**
 * HCC v0.2 current version (factory function default; v0.2 = "2.0.0").
 */
export const HCC_VERSION_CURRENT = '2.0.0' as const;

// ─── HashChainError class definition ─────────────────────────────────────────────

/**
 * HashChainError — hcc L0/L1 exception class.
 *
 * Orthogonal in namespace to CryptoError (existing in packages/crypto/src/types.ts) + CspError (csp L1);
 * the HC_* error codes do not conflict with CSP_* / CryptoError's 9 codes / RFP_* / TB_*, etc.
 * (grep verified 0 hits).
 *
 * extends Error; does not extend ProtocolError (to avoid introducing a cross-package dependency).
 *
 * The pattern across all sub-protocol L0 error classes is not forced to be uniform — the `.detail`
 * field type conflict makes an inline refactor infeasible; HashChainError stays as extends Error.
 */
export class HashChainError extends Error {
    public override readonly name = 'HashChainError';
    public readonly code: HccErrorCode;
    public override readonly cause?: Error;

    public constructor(code: HccErrorCode, message: string, cause?: Error) {
        super(`[${code}] ${message}`);
        this.code = code;
        this.cause = cause;
    }
}

// ─── assertNeverHccError exhaustive-switch guard ──────────────────────────────

/**
 * assertNeverHccError — fallback for the HccErrorCode union's exhaustive switch.
 *
 * Usage: at the end of switch (code), default → assertNeverHccError(code);
 * if the HccErrorCode union adds a new member the switch does not cover → TypeScript compile-time failure
 * (the Never type is not assignable). This is structural prevention against missed union-member coverage.
 *
 * Anti-phantom defense:
 *   - no stub default success / silent return / partial-PASS paths allowed;
 *   - any union expansion not matched by switch coverage → compile-time failure (Never is not assignable);
 *   - unreachable at runtime; if triggered it means the type system was bypassed (throws HC_SCHEMA_VIOLATION as a fallback).
 */
export function assertNeverHccError(code: never): never {
    throw new HashChainError(
        'HC_SCHEMA_VIOLATION',
        `assertNeverHccError: unexpected HccErrorCode value (compile-time exhaustive switch escape; phantom enforcement guard): ${String(code)}`,
    );
}

// ─── Factory Functions ("no brand cast" guard; the only legal path for a brand cast) ───────────────────

/**
 * toChainNamespace — ChainNamespace factory function (added in v0.2).
 *
 * "no brand cast" guard: the only legal path to obtain a ChainNamespace;
 * runtime validation: non-empty string; length [1, 128].
 * Callers may not directly cast via `s as ChainNamespace`.
 *
 * Added in v0.2; the factory validates a non-empty string of [1, 128] chars.
 *
 * @throws HashChainError(HC_SCHEMA_VIOLATION) — empty string / too long / not a string
 */
export function toChainNamespace(s: string): ChainNamespace {
    if (typeof s !== 'string') {
        throw new HashChainError(
            'HC_SCHEMA_VIOLATION',
            `toChainNamespace: expected string, got: ${typeof s}`,
        );
    }
    if (s.length < 1 || s.length > 128) {
        throw new HashChainError(
            'HC_SCHEMA_VIOLATION',
            `toChainNamespace: length must be [1, 128], got: ${s.length} ("${s.slice(0, 32)}")`,
        );
    }
    return s as ChainNamespace;
}

/**
 * toChainIdentityJcs — ChainIdentityJcs factory function (added in v0.2).
 *
 * "no brand cast" guard: the only legal path to obtain a ChainIdentityJcs;
 * runtime validation: non-empty string; length >= 2 (shortest is '{}'); rejects the '__NULL__' sentinel.
 * Design constraints:
 *   - called after the L1 crypto layer's canonicalizeChainIdentity() produces the string — the caller does not construct it
 *   - '__NULL__' is reserved for SQL COALESCE; the factory rejects this sentinel value
 *   - length >= 2 corresponds to JCS's shortest output '{}' (empty object)
 * Callers may not directly cast via `s as ChainIdentityJcs` (no brand cast).
 *
 * @throws HashChainError(HC_SCHEMA_VIOLATION) — empty string / length < 2 / '__NULL__' sentinel / not a string
 */
export function toChainIdentityJcs(s: string): ChainIdentityJcs {
    if (typeof s !== 'string') {
        throw new HashChainError(
            'HC_SCHEMA_VIOLATION',
            `toChainIdentityJcs: expected string, got: ${typeof s}`,
        );
    }
    if (s.length < 2) {
        throw new HashChainError(
            'HC_SCHEMA_VIOLATION',
            `toChainIdentityJcs: length must be >= 2 (JCS minimum '{}'), got: ${s.length}`,
        );
    }
    if (s === '__NULL__') {
        throw new HashChainError(
            'HC_CHAIN_IDENTITY_PREIMAGE_FAILED',
            `toChainIdentityJcs: '__NULL__' is a reserved SQL sentinel value; chainIdentity JCS canonicalize must not produce this`,
        );
    }
    return s as ChainIdentityJcs;
}

/**
 * toHashChainEntryId — HashChainEntryId factory function.
 *
 * "no brand cast" guard: the only legal path to obtain a HashChainEntryId; runtime validation of the UUID v4 format.
 * Callers may not directly cast via `s as HashChainEntryId`.
 *
 * @throws HashChainError(HC_SCHEMA_VIOLATION) — does not conform to the UUID v4 format
 */
export function toHashChainEntryId(s: string): HashChainEntryId {
    if (typeof s !== 'string') {
        throw new HashChainError(
            'HC_SCHEMA_VIOLATION',
            `toHashChainEntryId: expected string, got: ${typeof s}`,
        );
    }
    const UUID_V4 =
        /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    if (!UUID_V4.test(s)) {
        throw new HashChainError(
            'HC_SCHEMA_VIOLATION',
            `toHashChainEntryId: not a valid UUID v4: "${s}"`,
        );
    }
    // the factory accepts a case-insensitive UUID as input but normalizes to a lowercase output —
    // aligning with the lowercase-only semantics of the JSON Schema pattern `^[0-9a-f]...`;
    // this prevents the factory from returning an uppercase UUID that the schema-validation stage would REJECT,
    // which would make the triple defense's L1 brand semantically inconsistent with the L2/L3 schema (reuses the csp brand-factory normalize pattern).
    return s.toLowerCase() as HashChainEntryId;
}

/**
 * toCanonicalPayloadHash — CanonicalPayloadHash factory function.
 *
 * "no brand cast" guard: the only legal path to obtain a CanonicalPayloadHash;
 * runtime validation of the SHA-256 hex pattern (64 lowercase hex chars).
 * Callers may not directly cast via `s as CanonicalPayloadHash`.
 *
 * Strictly lowercase hex (in contrast to toPreviousHash, which accepts uppercase and then normalizes).
 *
 * @throws HashChainError(HC_SCHEMA_VIOLATION) — not a 64-lowercase-hex string
 */
export function toCanonicalPayloadHash(s: string): CanonicalPayloadHash {
    if (typeof s !== 'string') {
        throw new HashChainError(
            'HC_SCHEMA_VIOLATION',
            `toCanonicalPayloadHash: expected string, got: ${typeof s}`,
        );
    }
    if (!/^[a-f0-9]{64}$/.test(s)) {
        throw new HashChainError(
            'HC_SCHEMA_VIOLATION',
            `toCanonicalPayloadHash: expected 64 lowercase hex chars, got: "${s.slice(0, 8)}..."`,
        );
    }
    return s as CanonicalPayloadHash;
}

/**
 * toPreviousHash — PreviousHash factory function.
 *
 * "no brand cast" guard: the only legal path to obtain a PreviousHash;
 * accepts hex (uppercase / lowercase); internally normalizes to lowercase before casting.
 * genesis value: GENESIS_PREVIOUS_HASH = "0".repeat(64).
 *
 * @throws HashChainError(HC_SCHEMA_VIOLATION) — not a 64-hex string
 */
export function toPreviousHash(s: string): PreviousHash {
    if (typeof s !== 'string') {
        throw new HashChainError(
            'HC_SCHEMA_VIOLATION',
            `toPreviousHash: expected string, got: ${typeof s}`,
        );
    }
    const normalized = s.toLowerCase();
    if (!/^[a-f0-9]{64}$/.test(normalized)) {
        throw new HashChainError(
            'HC_SCHEMA_VIOLATION',
            `toPreviousHash: expected 64 hex chars (uppercase/lowercase), got: "${s.slice(0, 8)}..."`,
        );
    }
    return normalized as PreviousHash;
}

/**
 * toChainPosition — ChainPosition factory function.
 *
 * "no brand cast" guard: the only legal path to obtain a ChainPosition;
 * runtime validation of a non-negative safe integer.
 *
 * Strictly Number.isInteger + Number.isSafeInteger + >= 0.
 *
 * @throws HashChainError(HC_SCHEMA_VIOLATION) — not a non-negative safe integer
 */
export function toChainPosition(n: number): ChainPosition {
    if (
        typeof n !== 'number' ||
        !Number.isInteger(n) ||
        n < 0 ||
        !Number.isSafeInteger(n)
    ) {
        throw new HashChainError(
            'HC_SCHEMA_VIOLATION',
            `toChainPosition: expected non-negative safe integer, got: ${n}`,
        );
    }
    return n as ChainPosition;
}

/**
 * toHccVersionString — HccVersionString factory function.
 *
 * "no brand cast" guard: the only legal path to obtain a HccVersionString;
 * runtime validation of the semver X.Y.Z format + membership in the legal-value set (HCC_SUPPORTED_VERSIONS).
 *
 * v0.1's only legal value is "1.0.0".
 *
 * @throws HashChainError(HC_SCHEMA_VIOLATION) — does not conform to semver format / not in the supported set
 */
export function toHccVersionString(s: string): HccVersionString {
    if (typeof s !== 'string' || !/^[0-9]+\.[0-9]+\.[0-9]+$/.test(s)) {
        throw new HashChainError(
            'HC_SCHEMA_VIOLATION',
            `toHccVersionString: not valid semver (X.Y.Z): "${s}"`,
        );
    }
    if (!HCC_SUPPORTED_VERSIONS.includes(s)) {
        throw new HashChainError(
            'HC_SCHEMA_VIOLATION',
            `toHccVersionString: unsupported hccVersion "${s}"; supported: ${HCC_SUPPORTED_VERSIONS.join(', ')}`,
        );
    }
    return s as HccVersionString;
}

// ─── HccErrorContext + handleHccError exhaustive switch ──────────────────────

/**
 * HccErrorContext — the result of handleHccError.
 *
 * Every error has severity = ERROR (WARNING-only is not allowed; fail-closed enforced).
 * HTTP status-code mapping: all FATAL → the 400/500 series; stub 200 is not allowed.
 */
export interface HccErrorContext {
    /** error code*/
    code: HccErrorCode;
    /** HTTP status code (4xx/5xx fail-closed; a stub default 200 is forbidden)*/
    httpStatus: 400 | 422 | 500;
    /** error message*/
    message: string;
    /** whether the error is fatal (all HC_* errors are FATAL)*/
    fatal: boolean;
}

/**
 * handleHccError — full coverage of the 8 HccErrorCode switch cases + assertNeverHccError exhaustive.
 *
 * Every HccErrorCode value must have a corresponding case;
 * assertNeverHccError(code) in the default branch ensures a compile-time exhaustive check.
 *
 * fail-closed principle: all errors map to 4xx/5xx; stub 200 is not allowed.
 *
 * Severity: all 8 entries ERROR / FATAL → 400 (caller input problem) /
 *   422 (cross-lang fixture mismatch — semantically processable but invariant violated) /
 *   500 (canonicalize engine internal failure).
 * v0.2 2 added entries: HC_CHAIN_IDENTITY_PREIMAGE_FAILED (400) + HC_CHAIN_IDENTITY_SCHEMA_BREAKING (400).
 */
export function handleHccError(code: HccErrorCode): HccErrorContext {
    switch (code) {
        case 'HC_CANONICALIZE_FAILED':
            return {
                code,
                httpStatus: 500,
                message:
                    'HCC JCS canonicalize failed (payload contains function/symbol/bigint/NaN/Infinity/circular ref or canonicalize npm internal failure)',
                fatal: true,
            };
        case 'HC_HASH_MISMATCH':
            return {
                code,
                httpStatus: 400,
                message:
                    'HCC SHA-256 recompute mismatch (data tampered or canonicalize path inconsistency)',
                fatal: true,
            };
        case 'HC_PREVIOUS_HASH_BROKEN':
            return {
                code,
                httpStatus: 400,
                message:
                    'HCC previousHash link broken (chain entry deleted/inserted/tampered between adjacent positions)',
                fatal: true,
            };
        case 'HC_CHAIN_POSITION_NONMONOTONIC':
            return {
                code,
                httpStatus: 400,
                message:
                    'HCC chainPosition non-monotonic (gap/duplicate/out-of-order position relative to array index)',
                fatal: true,
            };
        case 'HC_FIXTURE_CROSS_LANG_MISMATCH':
            return {
                code,
                httpStatus: 422,
                message:
                    'HCC cross-lang fixture digest mismatch (TypeScript canonicalize !== Python canonicaljson;RFC 8785 incompatibility)',
                fatal: true,
            };
        case 'HC_SCHEMA_VIOLATION':
            return {
                code,
                httpStatus: 400,
                message:
                    'HCC JSON Schema validation failed (field missing / format wrong / additionalProperties / brand factory rejection)',
                fatal: true,
            };
        case 'HC_CHAIN_IDENTITY_PREIMAGE_FAILED':
            return {
                code,
                httpStatus: 400,
                message:
                    'HCC chainIdentity preimage recompute mismatch (chainNamespace / tenantId / auditClass tampered; preimage integrity invariant violated)',
                fatal: true,
            };
        case 'HC_CHAIN_IDENTITY_SCHEMA_BREAKING':
            return {
                code,
                httpStatus: 400,
                message:
                    'HCC hccVersion is not "2.0.0" (schema breaking change; version isolation invariant; upgrade to v0.2 wire format required)',
                fatal: true,
            };
        default:
            // assertNeverHccError exhaustive: if a newly added HccErrorCode value is not handled in this switch → compile-time error
            // triggered at runtime via a type-cast bypass (anti-phantom enforcement guard); covered literally by tests
            return assertNeverHccError(code);
    }
}
