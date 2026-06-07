/**
 * Audit Tamper-Proof (atp) v0.1 L0 type definitions
 *
 * sub-protocol — atp v0.1
 *
 * Triple defense:
 *   Layer 1: TypeScript brand type (compile-time; this file)
 *   Layer 2: JSON Schema format (runtime schema layer; audit-event-v0.1.schema.json)
 *   Layer 3: AJV strict mode (runtime schema engine layer; atp-validation.ts)
 *
 * Guard: every brand type can only be obtained via a to*() factory function; a direct brand cast such as `as TenantId` is strictly forbidden.
 *
 * fail-closed enforcement (atp is a verification primitive that only admits verified paths):
 *   canonicalize failure / hash chain break / tenantId scope violation / schema validate failure = reject the write by default;
 *   fail-degraded / fail-open / partial-PASS are not allowed.
 *
 * Namespace isolation:
 *   atp's own 17 AUDIT_* error codes coexist with the existing audit-access 13 AUDIT_* union with 0 literal collisions.
 *   audit-access errors.ts + audit.ts already occupy theirs; atp v0.1 freezes 17 without duplication.
 *
 * Key SSOT decision:
 *   AuditError does **not** extend ProtocolError (to avoid modifying the L0 ProtocolErrorCode wire-format main union);
 *   AuditError is a standalone class extends Error; atp has its own AuditErrorCode union (17 items frozen).
 *   Writing `super(code, message, 'ERROR')` is inconsistent with the existing ProtocolError(code, detail, requestId?)
 *   constructor signature where the 3rd argument is requestId, not severity → take the standalone class path, with severity stored in its own field.
 */

import type { DID, Hash, Signature, Timestamp } from '../base.js';
import {
    toUuidV4String,
    type UuidV4String,
} from '../canonical-signed-payload/types.js';

// ─── Brand Types (defense layer 1; brand cast guard) ───────────────────────────────────

/**
 * Audit event UUID v4 ID brand type
 *
 * Reuses the UuidV4String pattern;
 * generated DB-side by gen_random_uuid(); client-side forgery is not allowed.
 */
export type AuditEventId = UuidV4String;

/**
 * Audit event tamper-proof hash brand type
 *
 * Reuses the existing Hash brand from base.ts; SHA-256 hex, 64 chars;
 * the factory layer validates the hex format at runtime.
 */
export type AuditEventHash = Hash;

/**
 * Tenant ID brand type
 *
 * Reuses the UuidV4String pattern; does not create a separate TenantId brand;
 * cross-protocol reuse of UuidV4String across multiple sub-protocols takes priority for generality.
 */
export type TenantId = UuidV4String;

/**
 * atp protocol version number brand type
 *
 * Separate atpVersion namespace; v0.1 sole valid value "1.0.0";
 * not coupled with token.specVersion / cspVersion / tbVersion / rfpVersion.
 */
export type AtpVersionString = string & { readonly __brand: 'AtpVersionString' };

/**
 * Audit class brand type
 *
 * per-class independent hash chain (each audit_class maintains its own prev_hash head).
 * L1: business plane (token verify / envelope recorded);
 * L2: governance plane (revocation / policy change);
 * L3: control plane (session governor / cross-domain settle).
 */
export type AuditClass = 'L1' | 'L2' | 'L3';

/**
 * Audit class valid value set (anchor reconciled across runtime schema validation + L3 SQL CHECK)
 */
export const AUDIT_CLASSES: readonly AuditClass[] = ['L1', 'L2', 'L3'] as const;

/**
 * Audit action brand type
 *
 * Defined at the application layer (e.g. "TOKEN_VERIFY" / "ENVELOPE_RECORDED" / "SD_DISCLOSURE_REVEAL");
 * the protocol does not enumerate specific values; the factory validates length [1, 256] at runtime.
 */
export type AuditAction = string & { readonly __brand: 'AuditAction' };

// ─── Constants (factory function dependencies; defined first) ────────────────────────────────────────────

/**
 * atp supported version set (v0.1 sole value "1.0.0")
 *
 * Future atp v0.2+ extensions are added to this array; they do not trigger a token.specVersion upgrade.
 */
export const ATP_SUPPORTED_VERSIONS: readonly string[] = ['1.0.0'] as const;

/**
 * atp v0.1 current version (factory function default value)
 */
export const ATP_VERSION_CURRENT = '1.0.0' as const;

/**
 * GENESIS marker (per-audit_class chain-head hash input placeholder)
 *
 * buildTamperProofHashInput: previousHash === null → GENESIS_MARKER (64 "0" chars);
 * rule — "previousHash: (ev.previousHash || GENESIS_MARKER)".
 */
export const ATP_GENESIS_MARKER = '0'.repeat(64);

/**
 * Audit action maximum length (characters; length invariant)
 */
export const ATP_AUDIT_ACTION_MAX_LENGTH = 256;

// ─── atp error codes (namespace-isolated AUDIT_*) ────────────────

/**
 * AuditErrorCode — atp error code namespace (AUDIT_* prefix)
 *
 * Frozen: 17 error codes; v0.1 freeze; no rename / remove / severity changes allowed.
 * Future atp v0.2+ may only add new AUDIT_* error codes (coexisting with the existing audit-access 13; 0 literal collision).
 *
 * Invariant mapping:
 *   AUDIT_VERSION_UNSUPPORTED → atpVersion not in the supported set
 *   AUDIT_SCHEMA_VIOLATION → field completeness + format
 *   AUDIT_TENANT_SCOPE_VIOLATION → tenantId mismatch with caller principal / cross-tenant write
 *   AUDIT_CANONICALIZE_BYPASS_DETECTED → canonicalize failure / caller bypassed via JSON.stringify
 *   AUDIT_CANONICALIZE_MISMATCH → verifier re-canonicalize !== event.canonicalPayload
 *   AUDIT_HASH_CHAIN_BROKEN → previousHash mismatch
 *   AUDIT_TAMPER_DETECTED → reverse hash chain replay recomputedHash !== tamperProofHash
 *   AUDIT_FAIL_CLOSED → fail-closed
 *   AUDIT_ATOMICITY_VIOLATED → atomic boundary
 *   AUDIT_GENESIS_VIOLATION → GENESIS invariant (i===0 → previousHash===null; i>0 → previousHash!==null)
 *   AUDIT_TIMESTAMP_INVALID → timestamp format / client forgery
 *   AUDIT_EVENT_SIGNATURE_INVALID → Ed25519 verify failure
 *                                       (distinct from audit-access AUDIT_SIGNATURE_INVALID)
 *   AUDIT_ACTOR_DID_INVALID → actorDid not prefixed with did:*
 *   AUDIT_ACTION_INVALID → action empty string OR length > 256
 *   AUDIT_ADVISORY_LOCK_FAILED → per-(tenantId, audit_class) advisory lock acquire failure
 *   AUDIT_FETCH_LAST_HASH_FAILED → fetchLastTamperProofHash query failure
 *   AUDIT_REVERSE_REPLAY_FAILED → verifier reverse replay DB query / canonicalize failure
 */
export type AuditErrorCode =
    | 'AUDIT_VERSION_UNSUPPORTED'
    | 'AUDIT_SCHEMA_VIOLATION'
    | 'AUDIT_TENANT_SCOPE_VIOLATION'
    | 'AUDIT_CANONICALIZE_BYPASS_DETECTED'
    | 'AUDIT_CANONICALIZE_MISMATCH'
    | 'AUDIT_HASH_CHAIN_BROKEN'
    | 'AUDIT_TAMPER_DETECTED'
    | 'AUDIT_FAIL_CLOSED'
    | 'AUDIT_ATOMICITY_VIOLATED'
    | 'AUDIT_GENESIS_VIOLATION'
    | 'AUDIT_TIMESTAMP_INVALID'
    | 'AUDIT_EVENT_SIGNATURE_INVALID'
    | 'AUDIT_ACTOR_DID_INVALID'
    | 'AUDIT_ACTION_INVALID'
    | 'AUDIT_ADVISORY_LOCK_FAILED'
    | 'AUDIT_FETCH_LAST_HASH_FAILED'
    | 'AUDIT_REVERSE_REPLAY_FAILED';

/**
 * AuditErrorCode complete set (assertNever exhaustive + test coverage anchor)
 *
 * 17 items v0.1 freeze; rename / remove / severity changes strictly forbidden;
 * any atp v0.2+ addition must be kept in sync in the ATP_ERROR_CODES literal + the handleAuditError switch + unit test coverage.
 */
export const ATP_ERROR_CODES: readonly AuditErrorCode[] = [
    'AUDIT_VERSION_UNSUPPORTED',
    'AUDIT_SCHEMA_VIOLATION',
    'AUDIT_TENANT_SCOPE_VIOLATION',
    'AUDIT_CANONICALIZE_BYPASS_DETECTED',
    'AUDIT_CANONICALIZE_MISMATCH',
    'AUDIT_HASH_CHAIN_BROKEN',
    'AUDIT_TAMPER_DETECTED',
    'AUDIT_FAIL_CLOSED',
    'AUDIT_ATOMICITY_VIOLATED',
    'AUDIT_GENESIS_VIOLATION',
    'AUDIT_TIMESTAMP_INVALID',
    'AUDIT_EVENT_SIGNATURE_INVALID',
    'AUDIT_ACTOR_DID_INVALID',
    'AUDIT_ACTION_INVALID',
    'AUDIT_ADVISORY_LOCK_FAILED',
    'AUDIT_FETCH_LAST_HASH_FAILED',
    'AUDIT_REVERSE_REPLAY_FAILED',
] as const;

// ─── AuditEvent Interface (12 mandatory fields) ─────────────────────────────────

/**
 * AuditEvent — atp v0.1 sub-protocol
 *
 * 12 mandatory fields (11 required + 1 optional signature):
 *   atpVersion + eventId + tenantId + auditClass + actorDid + action + target +
 *   canonicalPayload + tamperProofHash + previousHash + timestamp + signature
 *
 * The tamperProofHash computation covers the full 10 audit metadata fields:
 *   a DBA changing any metadata field → recomputed hash mismatch → tampering detected;
 *   covering only the canonicalPayload + previousHash + tenantId subset is strictly forbidden.
 *
 * tenantId scope is strictly validated (multi-tenant audit isolation);
 * fail-closed fallback before writing the audit event.
 */
export interface AuditEvent {
    /** atp protocol version number metadata field (v0.1 sole value "1.0.0")*/
    atpVersion: AtpVersionString;
    /** Audit event UUID v4 ID (generated DB-side by gen_random_uuid(); client forgery not accepted)*/
    eventId: AuditEventId;
    /** Tenant scope (multi-tenant audit isolation; mandatory non-empty; cross-tenant writes forbidden)*/
    tenantId: TenantId;
    /** Audit class (per-class independent hash chain)*/
    auditClass: AuditClass;
    /** DID of the subject that triggered the audit event (reuses the base.ts DID brand)*/
    actorDid: DID;
    /** Audit event action (defined at the application layer; length [1, 256])*/
    action: AuditAction;
    /** Object affected by the audit event (target identifier; may be an empty string but the field is mandatory)*/
    target: string;
    /** Application-layer payload string after RFC 8785 JCS canonicalize (JSON.stringify forbidden)*/
    canonicalPayload: string;
    /** Tamper-proof hash (SHA-256; hex-encoded; all 10 fields bound)*/
    tamperProofHash: AuditEventHash;
    /** tamperProofHash of the previous audit event; per-audit_class independent chain; GENESIS = null*/
    previousHash: AuditEventHash | null;
    /** Audit event creation timestamp (ISO 8601 UTC; locked by server-side NOW(); client forgery not accepted)*/
    timestamp: Timestamp;
    /** Optional Ed25519 signature (the second layer of cryptographic tamper-proofing; optional in v0.1)*/
    signature: Signature | null;
}

// ─── Factory Functions (brand cast guards; the sole valid path) ──────────────────

/**
 * toAtpVersionString — AtpVersionString brand type factory function
 *
 * Guard: the sole valid path to obtain an AtpVersionString; validates semver format + the valid value set at runtime.
 * v0.1 sole valid value: "1.0.0"
 *
 * @throws Error AUDIT_VERSION_UNSUPPORTED if the format or version is non-compliant
 */
export function toAtpVersionString(s: string): AtpVersionString {
    if (!/^[0-9]+\.[0-9]+\.[0-9]+$/.test(s)) {
        throw new Error(
            `AUDIT_VERSION_UNSUPPORTED: not valid semver (X.Y.Z): "${s}"`,
        );
    }
    if (!ATP_SUPPORTED_VERSIONS.includes(s)) {
        throw new Error(
            `AUDIT_VERSION_UNSUPPORTED: unsupported atpVersion "${s}"; supported: ${ATP_SUPPORTED_VERSIONS.join(', ')}`,
        );
    }
    return s as AtpVersionString;
}

/**
 * toTenantId — TenantId brand type factory function (reuses UuidV4String)
 *
 * Guard: the sole valid path to obtain a TenantId; reuses the toUuidV4String validation chain;
 * on validation failure throws AUDIT_TENANT_SCOPE_VIOLATION (semantically aligned; not CSP_CHALLENGE_INVALID).
 *
 * @throws Error AUDIT_TENANT_SCOPE_VIOLATION if the format is non-compliant
 */
export function toTenantId(s: string): TenantId {
    if (
        !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
            s,
        )
    ) {
        throw new Error(
            `AUDIT_TENANT_SCOPE_VIOLATION: tenantId not valid UUID v4: "${s}"`,
        );
    }
    return s as TenantId;
}

/**
 * toAuditEventId — AuditEventId brand type factory function (reuses csp toUuidV4String)
 *
 * Guard: the sole valid path to obtain an AuditEventId; reuses the existing csp v0.1 factory.
 *
 * @throws Error CSP_CHALLENGE_INVALID if the format is non-compliant (reuses csp validation semantics)
 */
export function toAuditEventId(s: string): AuditEventId {
    return toUuidV4String(s);
}

/**
 * toAuditEventHash — AuditEventHash brand type factory function
 *
 * Guard: the sole valid path to obtain an AuditEventHash; validates lowercase SHA-256 hex, 64 chars, at runtime.
 *
 * @throws Error AUDIT_HASH_CHAIN_BROKEN if the format is non-compliant
 */
export function toAuditEventHash(s: string): AuditEventHash {
    if (!/^[0-9a-f]{64}$/.test(s)) {
        throw new Error(
            `AUDIT_HASH_CHAIN_BROKEN: tamperProofHash not valid SHA-256 hex (64 lowercase hex chars): "${s}"`,
        );
    }
    return s as AuditEventHash;
}

/**
 * toAuditAction — AuditAction brand type factory function
 *
 * Guard: the sole valid path to obtain an AuditAction; validates length [1, 256] at runtime.
 *
 * @throws Error AUDIT_ACTION_INVALID if the length is violated (empty OR > 256)
 */
export function toAuditAction(s: string): AuditAction {
    if (s.length === 0 || s.length > ATP_AUDIT_ACTION_MAX_LENGTH) {
        throw new Error(
            `AUDIT_ACTION_INVALID: action length out of range [1, ${ATP_AUDIT_ACTION_MAX_LENGTH}]: "${s.length}"`,
        );
    }
    return s as AuditAction;
}

/**
 * toAuditClass — AuditClass brand type factory function (runtime enum validation)
 *
 * Guard: the sole valid path to obtain an AuditClass; validates ∈ {"L1", "L2", "L3"} at runtime.
 *
 * @throws Error AUDIT_SCHEMA_VIOLATION if the value is not in the valid set
 */
export function toAuditClass(s: string): AuditClass {
    if (s !== 'L1' && s !== 'L2' && s !== 'L3') {
        throw new Error(
            `AUDIT_SCHEMA_VIOLATION: auditClass must be one of L1/L2/L3, got "${s}"`,
        );
    }
    return s;
}

// ─── AuditError (standalone class; does not extend the ProtocolError main union) ──────────────────

/**
 * AuditError — atp's own error class
 *
 * Decision rationale:
 *   - in the existing ProtocolError(code, detail, requestId?) constructor signature the 3rd argument is requestId, not severity;
 *   - writing `super(code, message, 'ERROR')` is not aligned with the existing SSOT;
 *   - modifying the L0 ProtocolErrorCode main union to add 17 AUDIT_* items would trigger wire-format breaking + cross-module impact;
 *   - take the standalone AuditError extends Error path; severity is stored in its own field (atp's own union is closed);
 *   - namespace isolation is a natural benefit: a consumer inside the atp pipeline catching AuditError immediately knows the atp boundary;
 *   - coexists with the existing audit-access 13 AUDIT_* items (ProtocolError code) with 0 literal collision.
 *
 * fail-closed enforcement:
 *   atp is a verification primitive that only admits verified paths; partial-PASS is forbidden;
 *   any AuditError throw path = audit write reject + business transaction ROLLBACK.
 */
export class AuditError extends Error {
    public override readonly name = 'AuditError';

    public constructor(
        public readonly code: AuditErrorCode,
        public readonly detail: string,
        public readonly context?: Record<string, unknown>,
    ) {
        super(`[${code}] ${detail}`);
    }
}

// ─── assertNever exhaustive (AuditErrorCode 17 cases) ─────────────────────────

/**
 * assertNeverAuditError — AuditErrorCode exhaustive switch fallback
 *
 * Used in the default branch of the handleAuditError switch statement;
 * if a newly added AuditErrorCode value is not handled in the switch → compile-time error.
 *
 * @throws Error unreachable at runtime; if triggered, it means the type system was bypassed
 */
export function assertNeverAuditError(code: never): never {
    throw new Error(
        `Unreachable: unhandled AuditErrorCode "${String(code)}"`,
    );
}

// ─── handleAuditError — switch N case + assertNever exhaustive ───────────────

/**
 * AuditErrorContext — handleAuditError processing result
 *
 * Every atp error is fatal: true (fail-closed; partial-PASS not allowed);
 * httpStatus maps to 4xx/5xx (a stub 200 is not allowed even for 5xx).
 */
export interface AuditErrorContext {
    /** error code*/
    code: AuditErrorCode;
    /** HTTP status code (fail-closed; atp v0.1 freeze range)*/
    httpStatus: 400 | 401 | 403 | 409 | 422 | 500 | 503;
    /** error message*/
    message: string;
    /** whether the error is fatal (all AUDIT_* errors are ERROR)*/
    fatal: boolean;
}

/**
 * handleAuditError — AuditErrorCode switch full coverage of 17 cases + assertNever exhaustive
 *
 * Every AuditErrorCode value must have a corresponding case;
 * assertNeverAuditError(code) in the default branch ensures a compile-time exhaustive check.
 *
 * fail-closed principle: all errors map to 4xx/5xx; a stub 200 is not allowed.
 * Severity: all 17 items are ERROR (atp v0.1 freeze).
 */
export function handleAuditError(code: AuditErrorCode): AuditErrorContext {
    switch (code) {
        case 'AUDIT_VERSION_UNSUPPORTED':
            return {
                code,
                httpStatus: 422,
                message:
                    'atp atpVersion is not in the supported set or not valid semver',
                fatal: true,
            };
        case 'AUDIT_SCHEMA_VIOLATION':
            return {
                code,
                httpStatus: 400,
                message:
                    'atp JSON Schema validation failed (format / additionalProperties / required / enum)',
                fatal: true,
            };
        case 'AUDIT_TENANT_SCOPE_VIOLATION':
            return {
                code,
                httpStatus: 403,
                message:
                    'atp tenantId mismatch caller principal or cross-tenant write attempted or DB role mismatch audit_class',
                fatal: true,
            };
        case 'AUDIT_CANONICALIZE_BYPASS_DETECTED':
            return {
                code,
                httpStatus: 400,
                message:
                    'atp canonicalize failed or caller bypassed JCS via JSON.stringify',
                fatal: true,
            };
        case 'AUDIT_CANONICALIZE_MISMATCH':
            return {
                code,
                httpStatus: 400,
                message:
                    'atp verifier re-canonicalize(payload) does not match event.canonicalPayload',
                fatal: true,
            };
        case 'AUDIT_HASH_CHAIN_BROKEN':
            return {
                code,
                httpStatus: 409,
                message:
                    'atp previousHash mismatch previous same-class event tamperProofHash or invalid SHA-256 hex format',
                fatal: true,
            };
        case 'AUDIT_TAMPER_DETECTED':
            return {
                code,
                httpStatus: 409,
                message:
                    'atp reverse hash chain replay detected: recomputed tamperProofHash does not match stored value (DBA tampering or hash input asymmetry)',
                fatal: true,
            };
        case 'AUDIT_FAIL_CLOSED':
            return {
                code,
                httpStatus: 500,
                message:
                    'atp write reject and business transaction ROLLBACK (canonicalize / INSERT / schema validate failure)',
                fatal: true,
            };
        case 'AUDIT_ATOMICITY_VIOLATED':
            return {
                code,
                httpStatus: 500,
                message:
                    'atp audit write and business transaction not in same SERIALIZABLE transaction',
                fatal: true,
            };
        case 'AUDIT_GENESIS_VIOLATION':
            return {
                code,
                httpStatus: 409,
                message:
                    'atp per-audit_class chain GENESIS invariant violated (i===0 requires previousHash===null;i>0 requires previousHash!==null)',
                fatal: true,
            };
        case 'AUDIT_TIMESTAMP_INVALID':
            return {
                code,
                httpStatus: 400,
                message:
                    'atp timestamp not ISO 8601 UTC or client-side forged (server-side NOW() only)',
                fatal: true,
            };
        case 'AUDIT_EVENT_SIGNATURE_INVALID':
            return {
                code,
                httpStatus: 401,
                message:
                    'atp event.signature !== null and Ed25519 verify failed (audit event signature;distinct from audit-access query signature)',
                fatal: true,
            };
        case 'AUDIT_ACTOR_DID_INVALID':
            return {
                code,
                httpStatus: 400,
                message:
                    'atp actorDid does not start with did: prefix or brand cast failed',
                fatal: true,
            };
        case 'AUDIT_ACTION_INVALID':
            return {
                code,
                httpStatus: 400,
                message:
                    'atp action is empty string or length > 256',
                fatal: true,
            };
        case 'AUDIT_ADVISORY_LOCK_FAILED':
            return {
                code,
                httpStatus: 503,
                message:
                    'atp per-(tenantId, audit_class) advisory lock acquire failed',
                fatal: true,
            };
        case 'AUDIT_FETCH_LAST_HASH_FAILED':
            return {
                code,
                httpStatus: 503,
                message:
                    'atp fetchLastTamperProofHash query failed (DB unreachable or query timeout;scope (tenantId, audit_class))',
                fatal: true,
            };
        case 'AUDIT_REVERSE_REPLAY_FAILED':
            return {
                code,
                httpStatus: 503,
                message:
                    'atp verifier reverse hash chain replay DB query failed or canonicalize failed',
                fatal: true,
            };
        default:
            // assertNever exhaustive: if a newly added AuditErrorCode value is not handled in this switch → compile-time error
            /* v8 ignore next*/
            return assertNeverAuditError(code);
    }
}

// ─── 5 anti-pattern defenses (preventing the same root cause) ───────

/**
 * 5 anti-pattern defenses (enforced in this file):
 *   1. No stub default success → any AuditError throw path must be fail-closed; does not return a success fallback
 *   2. No brand cast `as <X>` → every brand must go through a to*() factory + runtime validation
 *   3. No dynamic import of canonicalize → the L3 writer uses a top-level import block
 *   4. No cross-module modification → AuditError does not extend ProtocolError and does not modify the L0 main union
 *   5. No partial-PASS for an auth/verification primitive → atp v0.1 is fail-closed and only admits verified paths
 *
 * DelegatedAuditKey real-verifier boundary:
 *   This atp v0.1 implementation is decoupled from DelegatedAuditKey; DelegatedAuditKey verification is the responsibility of the audit-access pipeline
 *   (the events.signature field is optional; Ed25519 verify is scheduled by the L3 writer/verifier side);
 *   atp v0.1 does not provide a DelegatedAuditKey resolve / verify interface (strict scope isolation);
 *   it does not introduce a new phantom verifier (the anti-pattern defenses are strictly observed).
 */
