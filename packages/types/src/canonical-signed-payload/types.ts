/**
 * Canonical Signed Payload (CSP) L0 type definitions
 *
 * csp v0.1 sub-protocol
 *
 * Triple defense:
 *   Layer 1: TypeScript brand types (compile-time; this file)
 *   Layer 2: JSON Schema format (runtime schema layer; canonical-signed-payload.schema.json)
 *   Layer 3: AJV strict mode (runtime schema-engine layer; csp-validation.ts)
 *
 * No-brand-cast guard: every brand type can only be obtained via a to*() factory function; direct casts like `as UuidV4String` are strictly forbidden.
 */

import type {
    CapabilityToken,
    Capability,
} from '../authorization.js';
import type { DID, Timestamp } from '../base.js';
import { SUPPORTED_SPEC_VERSIONS } from '../base.js';

// ─── Brand Types (layer-1 defense; no-brand-cast guard) ───────────────────────────────────

/**
 * UUID v4 brand type
 *
 * Compile-time enforcement: the challenge field must be constructed via the
 * toUuidV4String() factory; a direct `s as UuidV4String` cast is not allowed.
 *
 * Consistent in style with DID/Signature/Hash/Timestamp.
 */
export type UuidV4String = string & { readonly __brand: 'UuidV4String' };

/**
 * HTTPS URL brand type
 *
 * Compile-time enforcement: the https-URL branch of the audience field must be
 * constructed via the toHttpsUrl() factory. A direct `s as HttpsUrl` cast is not allowed.
 */
export type HttpsUrl = string & { readonly __brand: 'HttpsUrl' };

/**
 * CSP audience union type: DID or HTTPS URL
 *
 * Single-value design: strict binding; guards against audience hijack;
 * multi-audience scenarios are handled by issuing multiple tokens.
 */
export type CspAudience = DID | HttpsUrl;

/**
 * CSP protocol version brand type
 *
 * Independent cspVersion namespace; not coupled to token.specVersion.
 * v0.1 only legal value: "1.0.0"
 */
export type CspVersionString = string & { readonly __brand: 'CspVersionString' };

// ─── Supporting types ────────────────────────────────────────────────────────────────

/**
 * ScopeClaim: a claim disclosed by mode-B selective disclosure
 *
 * The selective-disclosure representation of a single Capability in token.capabilities.
 * disclosedClaims ⊆ the claim set derived from token.capabilities.
 */
export type ScopeClaim = Capability;

// ─── CSP error codes (namespace-isolated CSP_*) ────────────────

/**
 * CspErrorCode — csp error-code namespace (CSP_* prefix)
 *
 * Frozen: 13 error codes; no rename / remove / severity change allowed.
 * Later csp v0.2+ may only add new CSP_* error codes.
 *
 * Invariant mapping:
 *   CSP_PAYLOAD_INCOMPLETE → field completeness
 *   CSP_TOKEN_MISSING → token non-null
 *   CSP_TOKEN_VERSION_UNSUPPORTED → specVersion
 *   CSP_DISCLOSURE_INVALID → disclosedClaims
 *   CSP_CHALLENGE_INVALID → challenge format / replay defense
 *   CSP_CHALLENGE_EXPIRED → challenge timing
 *   CSP_AUDIENCE_MISMATCH → audience strict equality
 *   CSP_PAYLOAD_EXPIRED → notAfter window
 *   CSP_CANONICALIZE_MISMATCH → JCS byte equality
 *   CSP_SIGNATURE_INVALID → signature verification
 *   CSP_REVOCATION_QUERY_UNAVAILABLE → revocation query fail-closed
 *   CSP_SCHEMA_VIOLATION → JSON Schema validate
 *   CSP_VERSION_UNSUPPORTED → cspVersion set
 */
export type CspErrorCode =
    | 'CSP_PAYLOAD_INCOMPLETE'
    | 'CSP_TOKEN_MISSING'
    | 'CSP_TOKEN_VERSION_UNSUPPORTED'
    | 'CSP_DISCLOSURE_INVALID'
    | 'CSP_CHALLENGE_INVALID'
    | 'CSP_CHALLENGE_EXPIRED'
    | 'CSP_AUDIENCE_MISMATCH'
    | 'CSP_PAYLOAD_EXPIRED'
    | 'CSP_CANONICALIZE_MISMATCH'
    | 'CSP_SIGNATURE_INVALID'
    | 'CSP_REVOCATION_QUERY_UNAVAILABLE'
    | 'CSP_SCHEMA_VIOLATION'
    | 'CSP_VERSION_UNSUPPORTED';

// ─── CanonicalSignedPayload Interface ─────────────────────────────────

/**
 * CanonicalSignedPayload — csp sub-protocol
 *
 * 5 required fields (mode B): cspVersion + token + disclosedClaims + challenge + audience + notAfter
 * 4 required fields (mode A): cspVersion + token + challenge + audience + notAfter (disclosedClaims = [])
 *
 * Invariants:
 *   cspVersion ∈ {"1.0.0"} (v0.1 only value; independent of token.specVersion)
 *   token non-null; token.specVersion ∈ SUPPORTED_SPEC_VERSIONS
 *   disclosedClaims array; mode A = []; mode B ⊆ claim set derived from token.capabilities
 *   challenge UUID v4 format; verifier-side issued nonce; guards against first-contact replay
 *   audience DID or https URL; strict === equality comparison on the verifier side
 *   notAfter > now + minWindow (1s); independent of token.expiresAt; guards against stale replay
 *   field completeness; mode B fully populated; mode A disclosedClaims = []
 *   JCS(payload) === signedBytes (RFC 8785; `canonicalize` npm)
 *
 * Distinction: CanonicalSignedPayload.notAfter (signed-payload-level; verify-pipeline window)
 *              TemporalScope.notAfter (scope-level; capability availability time window)
 */
export interface CanonicalSignedPayload {
    /**
     * csp protocol version metadata field
     *
     * Independent namespace; v0.1 only value "1.0.0".
     * Not coupled to token.specVersion (tri-state coexistence 0.1.0/0.2.0/0.3.0 unchanged).
     */
    cspVersion: CspVersionString;

    /** the full signed CapabilityToken (including proof)*/
    token: CapabilityToken;

    /**
     * mode-B selective-disclosure disclosed claim set
     *
     * mode A: must be [] (empty array; does not count as CSP_PAYLOAD_INCOMPLETE)
     * mode B: must be ⊆ the claim set derived from token.capabilities
     */
    disclosedClaims: ScopeClaim[];

    /**
     * verifier-side bound nonce (UUID v4 brand)
     *
     * Inverted semantics: the challenge is issued by the verifier side, not the holder side.
     * The verifier issues a fresh UUID v4 at the entry of each verify pipeline; single-use.
     */
    challenge: UuidV4String;

    /**
     * the token's intended consumer (DID or https URL)
     *
     * Strict equality comparison (===) on the verifier side;
     * startsWith / match / wildcard are not allowed.
     * A single-value CspAudience.
     */
    audience: CspAudience;

    /**
     * the csp signed payload's independent expiry window (ISO 8601 UTC)
     *
     * Guards against stale replay: even if the token is long-lived, the csp signed
     * payload of each verify pipeline must be valid within a short window
     * (now < notAfter ≤ token.expiresAt).
     *
     * Distinguished from TemporalScope.notAfter (scope-level capability availability window):
     *   TemporalScope.notAfter = capability availability time window
     *   CanonicalSignedPayload.notAfter = signed-payload expiry window (verify-pipeline window)
     * Both coexist; semantically different; must not be conflated. Verify passes iff both notAfter values are unexpired.
     */
    notAfter: Timestamp;
}

// ─── Constants (factory-function dependencies; must be defined before toCspVersionString) ──────────────────────

/**
 * CSP supported version set (v0.1 only value "1.0.0")
 *
 * Independent cspVersion namespace; not coupled to token.specVersion.
 * Later csp v0.2+ extensions are added to this array; they do not trigger a token.specVersion bump.
 *
 * Note: CSP_SUPPORTED_VERSIONS stores a runtime string set;
 * the brand-type constraint is guaranteed by the toCspVersionString() factory at the return value.
 * Here only a readonly string[] is needed for the includes() check.
 */
export const CSP_SUPPORTED_VERSIONS: readonly string[] = ['1.0.0'] as const;

/**
 * csp v0.1 current version (factory-function default)
 */
export const CSP_VERSION_CURRENT = '1.0.0' as const;

/**
 * notAfter minimum validity window (milliseconds; notAfter timing invariant)
 *
 * Verifier-side check: notAfter > now + CSP_MIN_VALIDITY_WINDOW_MS
 * Guards against boundary rejects caused by clock skew.
 */
export const CSP_MIN_VALIDITY_WINDOW_MS = 1000; // 1 second (in milliseconds)

// ─── Factory Functions (no-brand-cast guard; the only legal path for brand casts) ──────────────────

/**
 * toUuidV4String — UUID v4 brand-type factory function
 *
 * The only legal path to obtain a UuidV4String; validates UUID v4 format at runtime.
 * Callers are not allowed to do `s as UuidV4String` directly.
 *
 * @throws Error CSP_CHALLENGE_INVALID if the format is non-compliant
 */
export function toUuidV4String(s: string): UuidV4String {
    if (
        !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
            s,
        )
    ) {
        throw new Error(`CSP_CHALLENGE_INVALID: not valid UUID v4: "${s}"`);
    }
    return s as UuidV4String;
}

/**
 * toHttpsUrl — HTTPS URL brand-type factory function
 *
 * The only legal path to obtain an HttpsUrl; the URL constructor rejects malformed URLs.
 * Callers are not allowed to do `s as HttpsUrl` directly.
 *
 * @throws Error CSP_AUDIENCE_INVALID if the format is non-compliant
 */
export function toHttpsUrl(s: string): HttpsUrl {
    let parsed: URL;
    try {
        parsed = new URL(s);
    } catch {
        throw new Error(
            `CSP_AUDIENCE_INVALID: not a well-formed HTTPS URL: "${s}"`,
        );
    }
    if (parsed.protocol !== 'https:') {
        throw new Error(
            `CSP_AUDIENCE_INVALID: scheme must be https:, got "${parsed.protocol}"`,
        );
    }
    /* v8 ignore next 3 -- Node.js URL parser rejects https:// (no host) before this guard*/
    if (parsed.hostname.length === 0) {
        throw new Error('CSP_AUDIENCE_INVALID: hostname required');
    }
    return s as HttpsUrl;
}

/**
 * toCspAudience — CspAudience factory function (DID or HTTPS URL branch routing)
 *
 * The only legal path to obtain a CspAudience.
 * DID branch: starts with "did:" → direct cast (DID brand type)
 * HTTPS branch: starts with "https://" → validated via toHttpsUrl()
 *
 * @throws Error CSP_AUDIENCE_MISMATCH if it is neither a DID nor an https URL
 */
export function toCspAudience(s: string): CspAudience {
    if (s.startsWith('did:')) {
        return s as DID;
    }
    if (s.startsWith('https://')) {
        return toHttpsUrl(s);
    }
    throw new Error(
        `CSP_AUDIENCE_MISMATCH: audience must be a did:* DID or https:// URL, got "${s}"`,
    );
}

/**
 * toCspVersionString — CspVersionString brand-type factory function
 *
 * The only legal path to obtain a CspVersionString; validates semver format + the legal value set at runtime.
 * v0.1 only legal value: "1.0.0"
 *
 * @throws Error CSP_VERSION_UNSUPPORTED if the format or version is non-compliant
 */
export function toCspVersionString(s: string): CspVersionString {
    if (!/^[0-9]+\.[0-9]+\.[0-9]+$/.test(s)) {
        throw new Error(
            `CSP_VERSION_UNSUPPORTED: not valid semver (X.Y.Z): "${s}"`,
        );
    }
    if (!CSP_SUPPORTED_VERSIONS.includes(s)) {
        throw new Error(
            `CSP_VERSION_UNSUPPORTED: unsupported cspVersion "${s}"; supported: ${CSP_SUPPORTED_VERSIONS.join(', ')}`,
        );
    }
    return s as CspVersionString;
}

// ─── Factory: createCanonicalSignedPayload (single-cast enforcement) ───────────

/**
 * CreateCanonicalSignedPayloadInput — factory-function input type
 *
 * Accepts raw strings; the factory function converts them to brand types internally via factory functions.
 * Callers are not allowed to bypass the factory and construct a CanonicalSignedPayload directly.
 */
export interface CreateCanonicalSignedPayloadInput {
    /** csp version; v0.1 only value "1.0.0"*/
    cspVersion: string;
    /** the full signed CapabilityToken*/
    token: CapabilityToken;
    /** selective-disclosure claim set; pass [] for mode A*/
    disclosedClaims: ScopeClaim[];
    /** verifier-side issued nonce; UUID v4 format string*/
    challenge: string;
    /** the intended consumer; a DID or https URL string*/
    audience: string;
    /** csp signed-payload expiry time; ISO 8601 UTC string*/
    notAfter: string;
}

/**
 * createCanonicalSignedPayload — CanonicalSignedPayload factory function
 *
 * Single-cast enforcement: all brand types are converted once inside this function;
 * external callers do not need to and are not allowed to cast again.
 *
 * Runtime validation:
 *   - cspVersion: toCspVersionString() → CSP_SUPPORTED_VERSIONS set check
 *   - token: specVersion ∈ SUPPORTED_SPEC_VERSIONS check
 *   - challenge: toUuidV4String() → UUID v4 format check
 *   - audience: toCspAudience() → DID or https URL format check
 *   - disclosedClaims: array-type check
 *   - notAfter: ISO 8601 format + not-expired check
 *
 * @throws Error CSP_* error code if any field fails validation (fail-closed)
 */
export function createCanonicalSignedPayload(
    input: CreateCanonicalSignedPayloadInput,
): CanonicalSignedPayload {
    // cspVersion validation
    const cspVersion = toCspVersionString(input.cspVersion);

    // token validation
    if (input.token === null || input.token === undefined) {
        throw new Error('CSP_TOKEN_MISSING: token must not be null or undefined');
    }
    if (!SUPPORTED_SPEC_VERSIONS.includes(input.token.specVersion as '0.1.0' | '0.2.0' | '0.3.0')) {
        throw new Error(
            `CSP_TOKEN_VERSION_UNSUPPORTED: token.specVersion "${input.token.specVersion}" not in supported set ${SUPPORTED_SPEC_VERSIONS.join(', ')}`,
        );
    }

    // disclosedClaims validation (array type; the full subset check is the verifier side's responsibility)
    if (!Array.isArray(input.disclosedClaims)) {
        throw new Error('CSP_DISCLOSURE_INVALID: disclosedClaims must be an array');
    }

    // challenge validation
    const challenge = toUuidV4String(input.challenge);

    // audience validation
    const audience = toCspAudience(input.audience);

    // notAfter validation: ISO 8601 format + timing check
    const notAfterDate = new Date(input.notAfter);
    if (isNaN(notAfterDate.getTime())) {
        throw new Error(
            `CSP_PAYLOAD_EXPIRED: notAfter is not a valid ISO 8601 date: "${input.notAfter}"`,
        );
    }
    if (notAfterDate.getTime() <= Date.now() + CSP_MIN_VALIDITY_WINDOW_MS) {
        throw new Error(
            `CSP_PAYLOAD_EXPIRED: notAfter "${input.notAfter}" must be > now + ${CSP_MIN_VALIDITY_WINDOW_MS}ms`,
        );
    }

    return {
        cspVersion,
        token: input.token,
        disclosedClaims: input.disclosedClaims,
        challenge,
        audience,
        notAfter: input.notAfter as Timestamp,
    };
}

// ─── assertNever exhaustive (CspErrorCode union N case) ──────────────────────

/**
 * assertNeverCspError — CspErrorCode exhaustive-switch fallback
 *
 * Used in the default branch of the handleCspError switch statement;
 * if a newly added CspErrorCode value is not handled in the switch → compile-time error.
 *
 * @throws Error unreachable at runtime; if triggered, the type system was bypassed
 */
export function assertNeverCspError(code: never): never {
    throw new Error(
        `Unreachable: unhandled CspErrorCode "${String(code)}"`,
    );
}

// ─── handleCspError — switch N case + assertNever exhaustive ─────────────────

/**
 * CspErrorContext — handleCspError result
 */
export interface CspErrorContext {
    /** error code*/
    code: CspErrorCode;
    /** HTTP status code (5xx fail-closed; no stub default 200)*/
    httpStatus: 400 | 401 | 403 | 422 | 503;
    /** error message*/
    message: string;
    /** whether this is a fatal error (all CSP_* errors are FATAL)*/
    fatal: boolean;
}

/**
 * handleCspError — full CspErrorCode N-case switch coverage + assertNever exhaustive
 *
 * Every CspErrorCode value must have a corresponding case;
 * assertNeverCspError(code) in the default branch ensures a compile-time exhaustiveness check.
 *
 * fail-closed principle: all errors map to 4xx/5xx; a stub 200 is not allowed.
 *
 *  Severity:
 *   CSP_VERSION_UNSUPPORTED → MED → 422 Unprocessable Entity
 *   the other 13 → FATAL → 400/401/403/503
 */
export function handleCspError(code: CspErrorCode): CspErrorContext {
    switch (code) {
        case 'CSP_PAYLOAD_INCOMPLETE':
            return {
                code,
                httpStatus: 400,
                message: 'CSP signed payload is incomplete: required fields missing',
                fatal: true,
            };
        case 'CSP_TOKEN_MISSING':
            return {
                code,
                httpStatus: 400,
                message: 'CSP payload token is null or undefined',
                fatal: true,
            };
        case 'CSP_TOKEN_VERSION_UNSUPPORTED':
            return {
                code,
                httpStatus: 400,
                message: 'CSP token.specVersion is not in the supported set',
                fatal: true,
            };
        case 'CSP_DISCLOSURE_INVALID':
            return {
                code,
                httpStatus: 400,
                message: 'CSP disclosedClaims is invalid: not an array, non-empty in mode A, or not a subset of token.capabilities',
                fatal: true,
            };
        case 'CSP_CHALLENGE_INVALID':
            return {
                code,
                httpStatus: 401,
                message: 'CSP challenge is not a valid UUID v4 or does not match verifier-issued challenge',
                fatal: true,
            };
        case 'CSP_CHALLENGE_EXPIRED':
            return {
                code,
                httpStatus: 401,
                message: 'CSP challenge was issued in the future (clock skew or replay)',
                fatal: true,
            };
        case 'CSP_AUDIENCE_MISMATCH':
            return {
                code,
                httpStatus: 403,
                message: 'CSP audience does not match verifier expected audience',
                fatal: true,
            };
        case 'CSP_PAYLOAD_EXPIRED':
            return {
                code,
                httpStatus: 401,
                message: 'CSP signed payload notAfter has expired or is too close to expiry',
                fatal: true,
            };
        case 'CSP_CANONICALIZE_MISMATCH':
            return {
                code,
                httpStatus: 400,
                message: 'CSP JCS canonicalize result does not match signed bytes (RFC 8785)',
                fatal: true,
            };
        case 'CSP_SIGNATURE_INVALID':
            return {
                code,
                httpStatus: 401,
                message: 'CSP Ed25519 signature verification failed',
                fatal: true,
            };
        case 'CSP_REVOCATION_QUERY_UNAVAILABLE':
            return {
                code,
                httpStatus: 503,
                message: 'CSP revocation list client is unreachable (fail-closed)',
                fatal: true,
            };
        case 'CSP_SCHEMA_VIOLATION':
            return {
                code,
                httpStatus: 400,
                message: 'CSP JSON Schema validation failed (format / additionalProperties / required)',
                fatal: true,
            };
        case 'CSP_VERSION_UNSUPPORTED':
            return {
                code,
                httpStatus: 422,
                message: 'CSP cspVersion is not in the supported set or not valid semver',
                fatal: true,
            };
        default:
            // assertNever exhaustive: if a newly added CspErrorCode value is not handled in this switch → compile-time error
            /* v8 ignore next*/
            return assertNeverCspError(code);
    }
}
