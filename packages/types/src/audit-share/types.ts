/**
 * audit-share v0.2 — L0 type definitions
 *
 * Triple defense (same pattern as da v0.1 / ccr v0.1 / hcc v0.1):
 *   Layer 1 (this file): TypeScript brand type — compile-time guard; brand cast strictly forbidden
 *   Layer 2 (audit-share-v0.2.schema.json): JSON Schema — runtime schema layer
 *   Layer 3 (audit-share-validation.ts): AJV strict mode 4 flags — runtime schema engine layer
 *
 * Naming convention (to avoid colliding with existing audit-access v0.2 types):
 *   The literal name `VerifiedAuditRequest` is already taken by audit-access v0.2 (a union type)
 *   in packages/types/src/audit.ts; this sub-protocol still keeps the literal
 *   `VerifiedAuditRequest` type internally as a type alias; it exports the public alias `AuditShareVerifiedRequest`
 *   to disambiguate. The two sub-protocols are fully orthogonal:
 *     - audit-access v0.2 = principal/governor lane single-domain audit query protocol
 *     - audit-share v0.2 = cross-domain audit event sharing sub-protocol (token-based delegation;
 *       DelegatedAuditKey cross-domain delegation + AuditShareRequest cross-domain request)
 *
 * cross-protocol integration anchors:
 *   - atp v0.1 — multi-tenant isolation fail-closed reject (AUDIT_SHARE_CROSS_TENANT_REJECT)
 *   - hcc v0.1 — verifyHashChain primitive (AUDIT_SHARE_HASH_CHAIN_INVALID)
 *   - csp v0.1 — 5-field invariant (audience/notAfter/challenge/disclosedClaims/auditShareVersion)
 *   - tb v0.1 — delegator → delegatedTo cross-trust-boundary delegation (one-way delegation acknowledged)
 *   - sd-capability-token v0.2 — ParentWitness (hash chain witness semantics; not Merkle)
 *
 * Key architectural decisions:
 *   #1 DelegatedAuditKey upgraded from a placeholder stub to a real implementation
 *   #2 SQL migration 028 — implemented (sequence number locked)
 *   #3 tenant_audit_share_policy UI — deferred (out of scope at the current stage)
 *   #4 v0.3 full-stack cryptographic enforcement — deferred (v0.2 is procedural at the current stage)
 *   #5 sd-capability-token v0.2 witness — reuses existing semantics
 */

import type { DID, Signature, Timestamp } from '../base.js';

// ─── Brand Types (defense layer 1; brand cast forbidden) ─────────────────────────────────────

/**
 * AuditKeyId — DelegatedAuditKey primary key brand type
 *
 * Compile-time enforcement: the token field (VerifiedAuditRequest.token = DelegatedAuditKey.auditKeyId)
 * must be constructed via the toAuditKeyId() factory; `s as AuditKeyId` is not allowed.
 *
 * Format: UUID v4 (same format as csp UuidV4String; a separate brand namespace avoids type confusion)
 */
export type AuditKeyId = string & { readonly __brand: 'AuditKeyId' };

/**
 * AuditShareVersion — audit-share protocol version brand type
 *
 * v0.2 sole valid value: "1.0.0" (csp pattern; separate cspVersion / auditShareVersion namespace)
 *
 * Note: the literal value '0.2.0' is the documentation version number,
 * while the protocol runtime version brand uses the same csp pattern semver "1.0.0" form (locked at v0.1).
 * The public field name is still auditShareVersion (consistent with the csp naming style).
 */
export type AuditShareVersion = string & {
    readonly __brand: 'AuditShareVersion';
};

/**
 * AuditShareScope — L3 manager fetch-by-scope brand type
 *
 * Reuses brand types from atp v0.1 + hcc v0.1 ChainIdentity (atp/hcc brand types are being implemented in parallel;
 * internally this sub-protocol uses string + factory guards,
 * to be consolidated via cross-protocol alignment once the atp/hcc brand types land).
 *
 * The factory toAuditShareScope() guard rejects the following enumerated sentinel values:
 *   undefined / null / empty string / "_DELETED_" / "_PLACEHOLDER_" / "_SENTINEL_" / "_TBD_" /
 *   "_NULL_" / "TODO" / "FIXME" / "XXX"
 */
export type AuditShareScope = {
    readonly tenantId: string;
    readonly auditClass: 'L1' | 'L2' | 'L3';
    readonly chainNamespace?: string;
} & { readonly __brand: 'AuditShareScope' };

/**
 * AuditEventField — enum of allowed disclosedClaims values
 *
 * Selective disclosure projection field set
 * (a subset of the audit-access v0.2 AuditEventRecord fields + the audit-tamper-proof v0.1 atp_* fields).
 */
export const AUDIT_EVENT_FIELDS = [
    'id',
    'eventType',
    'actorDid',
    'targetAgentDid',
    'timestamp',
    'correlationId',
    'outcome',
    'denyReason',
    'prevHash',
    'signature',
    'tenantId',
    'auditClass',
    'chainNamespace',
    'chainPosition',
    'canonicalPayloadHash',
] as const;

export type AuditEventField = (typeof AUDIT_EVENT_FIELDS)[number];

// ─── Constants (factory function dependencies; must be defined before the factories) ──────────────────────────

/**
 * AuditShare supported version set (v0.2 sole value "1.0.0"; csp pattern)
 */
export const AUDIT_SHARE_SUPPORTED_VERSIONS: readonly string[] = [
    '1.0.0',
] as const;

/**
 * AuditShare v0.2 current version (factory function default value)
 */
export const AUDIT_SHARE_VERSION_1_0_0 = '1.0.0' as const;

/**
 * notAfter minimum validity window (milliseconds; reuses the csp pattern)
 *
 * Verifier-side check: notAfter > now + AUDIT_SHARE_MIN_VALIDITY_WINDOW_MS
 * Guards against boundary rejects caused by clock skew.
 */
export const AUDIT_SHARE_MIN_VALIDITY_WINDOW_MS = 1000;

/**
 * sentinel value enumeration
 *
 * Values the toAuditShareScope() factory guard rejects:
 *   undefined / null / empty string / "_DELETED_" / "_PLACEHOLDER_" / "_SENTINEL_" /
 *   "_TBD_" / "_NULL_" / "TODO" / "FIXME" / "XXX"
 */
const SENTINEL_VALUES: ReadonlySet<string> = new Set([
    '',
    '_DELETED_',
    '_PLACEHOLDER_',
    '_SENTINEL_',
    '_TBD_',
    '_NULL_',
    'TODO',
    'FIXME',
    'XXX',
]);

// ─── Error code union (v0.2 14 items + v0.3 3 new items = 17 items frozen) ──────────

/**
 * AuditShareErrorCode — audit-share error code namespace (AUDIT_SHARE_* prefix)
 *
 * Frozen (frozen union; no rename / remove / severity changes allowed):
 *
 * v0.2 14 items:
 *   1. AUDIT_SHARE_TOKEN_INVALID — DelegatedAuditKey not found / revoked
 *   2. AUDIT_SHARE_TOKEN_EXPIRED — now > validUntil OR now < validFrom
 *   3. AUDIT_SHARE_AUDIENCE_MISMATCH — request.audience !== expectedAudience
 *   4. AUDIT_SHARE_CHALLENGE_INVALID — challenge not among the verifier-issued ones
 *   5. AUDIT_SHARE_NOT_AFTER_EXPIRED — request.notAfter < now
 *   6. AUDIT_SHARE_REQUESTER_SIGNATURE_INVALID — Ed25519 verify fail
 *   7. AUDIT_SHARE_DELEGATOR_SIGNATURE_INVALID — DelegatedAuditKey.proof verify fail
 *   8. AUDIT_SHARE_DELEGATOR_AUDIENCE_MISMATCH — key.delegatedTo !== request.requesterDid
 *   9. AUDIT_SHARE_SCOPE_INVALID — toAuditShareScope factory guard fail
 *   10. AUDIT_SHARE_CROSS_TENANT_REJECT — atp multi-tenant fail-closed
 *   11. AUDIT_SHARE_HASH_CHAIN_INVALID — hcc verifyHashChain primitive fail
 *   12. AUDIT_SHARE_DISCLOSED_CLAIMS_INVALID — disclosedClaims contains a value not in the AuditEventField enum
 *   13. AUDIT_SHARE_VERSION_UNSUPPORTED — auditShareVersion not in the supported set
 *   14. AUDIT_SHARE_SCHEMA_INVALID — AJV schema validate fail (triple defense layer 3)
 *
 * v0.3 3 new items (audit-share v0.3 real-consumption closure):
 *   15. AUDIT_SHARE_VERIFIER_REQUIRED — sdk verifier factory not injected OR transportEvidence missing
 *                                            (raw transport evidence is mandatory)
 *   16. AUDIT_SHARE_BOUNDARY_CHECK_FAILED — sdk boundary check fails on one of 4 dimensions
 *                                            (assertTrustedDidIsKindAndFresh /
 *                                             assertCrossCheckMappingConsistent /
 *                                             L4 sub-protocol cross-check)
 *   17. AUDIT_SHARE_CHAIN_IDENTITY_TAMPERED — hcc v0.2 chainIdentity preimage tampering
 *                                             (carries over hcc v0.2 HC_CHAIN_IDENTITY_PREIMAGE_FAILED /
 *                                              HC_CHAIN_IDENTITY_SCHEMA_BREAKING / HC_HASH_MISMATCH)
 *
 * Namespace isolation: does not collide with CSP_* / TB_* / RFP_* / AUDIT_* (atp) / HC_*
 */
export type AuditShareErrorCode =
    | 'AUDIT_SHARE_TOKEN_INVALID'
    | 'AUDIT_SHARE_TOKEN_EXPIRED'
    | 'AUDIT_SHARE_AUDIENCE_MISMATCH'
    | 'AUDIT_SHARE_CHALLENGE_INVALID'
    | 'AUDIT_SHARE_NOT_AFTER_EXPIRED'
    | 'AUDIT_SHARE_REQUESTER_SIGNATURE_INVALID'
    | 'AUDIT_SHARE_DELEGATOR_SIGNATURE_INVALID'
    | 'AUDIT_SHARE_DELEGATOR_AUDIENCE_MISMATCH'
    | 'AUDIT_SHARE_SCOPE_INVALID'
    | 'AUDIT_SHARE_CROSS_TENANT_REJECT'
    | 'AUDIT_SHARE_HASH_CHAIN_INVALID'
    | 'AUDIT_SHARE_DISCLOSED_CLAIMS_INVALID'
    | 'AUDIT_SHARE_VERSION_UNSUPPORTED'
    | 'AUDIT_SHARE_SCHEMA_INVALID'
    // v0.3 3 new items
    | 'AUDIT_SHARE_VERIFIER_REQUIRED'
    | 'AUDIT_SHARE_BOUNDARY_CHECK_FAILED'
    | 'AUDIT_SHARE_CHAIN_IDENTITY_TAMPERED';

/**
 * AuditShareError — audit-share fail-closed error class
 *
 * Carries fail-closed semantics; any invariant violation = reject by default.
 * fail-degraded / fail-open / partial-PASS are not allowed (an auth primitive only admits verified paths).
 *
 * Implementation notes:
 *   AuditEvaluatorNotImplemented fully removed (the placeholder-stub throw path no longer exists);
 *   verifyDelegatedAuditKey is really implemented as 5 fail-closed steps;
 *   L3 AuditShareManager does an 11-step fail-closed verify.
 *
 * extends Error (sr/da/cr/hcc/ms baseline pattern; the ProtocolError frozen union is not extensible)
 */
export class AuditShareError extends Error {
    public readonly code: AuditShareErrorCode;
    public readonly invariant?: string;

    constructor(
        code: AuditShareErrorCode,
        message: string,
        invariant?: string,
    ) {
        super(`[${code}] ${message}`);
        this.name = 'AuditShareError';
        this.code = code;
        this.invariant = invariant;
    }
}

// ─── HashChainEntry / AuditEvent placeholder types ────────────

/**
 * HashChainEntry — hcc v0.1 chain primitive entry (reference)
 *
 * An internal placeholder for this sub-protocol; to be consolidated and replaced via
 * cross-protocol alignment once the hcc v0.1 L0 brand types land. The minimal field set carries over
 * the hcc v0.1 chain primitive's 7 fields + the audit-share v0.2 wrapper-layer extensions.
 */
export interface HashChainEntry {
    readonly tenantId: string;
    readonly auditClass: 'L1' | 'L2' | 'L3';
    readonly chainNamespace: string;
    readonly chainPosition: number;
    readonly previousHash: string | null;
    readonly canonicalPayloadHash: string;
    readonly entryAt: Timestamp;
}

/**
 * AuditEvent — atp v0.1 audit event (reference)
 *
 * An internal placeholder for this sub-protocol; to be consolidated and replaced via
 * cross-protocol alignment once the atp v0.1 L0 brand types land. The minimal field set carries over
 * audit-access v0.2 AuditEventRecord (packages/types/src/audit.ts) + atp extensions.
 */
export interface AuditEvent {
    readonly id: string;
    readonly eventType: string;
    readonly actorDid: DID;
    readonly targetAgentDid: DID;
    readonly timestamp: Timestamp;
    readonly correlationId?: string;
    readonly outcome: 'ALLOWED' | 'DENIED';
    readonly denyReason?: string;
    readonly prevHash: string | null;
    readonly signature: Signature;
    /** atp v0.1 multi-tenant isolation field*/
    readonly tenantId: string;
    readonly auditClass: 'L1' | 'L2' | 'L3';
    readonly chainNamespace?: string;
    readonly chainPosition?: number;
    readonly canonicalPayloadHash?: string;
}

/**
 * ParentWitness — hash chain witness
 *
 * Design acknowledgment:
 *   - This ParentWitness has hash chain witness semantics (parentChainPosition +
 *     parentCanonicalPayloadHash + issuerSignature + signedAt);
 *   - sd-capability-token v0.2 SDDisclosureProof.parentCommitmentWitness has
 *     Merkle inclusion proof witness semantics — the two witness concepts differ
 *   - This type does not serve sd-capability-token v0.2 chain hop verify; sd-capability-token v0.2
 *     chain hop verify still goes through the caller's own `parentWitnessResolver` path
 */
export interface ParentWitness {
    readonly parentChainPosition: number;
    readonly parentCanonicalPayloadHash: string;
    readonly issuerSignature: Signature;
    readonly signedAt: Timestamp;
}

// ─── VerifiedAuditRequest — verify-time signed payload ─────────

/**
 * VerifiedAuditRequest — verify-time signed payload
 *
 * Fully compliant with the csp v0.1 5-field invariant:
 *   - audience (DID = target domain)
 *   - notAfter (ISO 8601 UTC)
 *   - challenge (UUID v4; verifier-side issued)
 *   - disclosedClaims (selective disclosure projection fields)
 *   - auditShareVersion (metadata; separate namespace = csp pattern)
 *
 * Naming ambiguity note (see the naming convention in the JSDoc at the top of this file):
 *   The literal name `VerifiedAuditRequest` collides with the same-named audit-access v0.2
 *   union type in audit.ts; this sub-protocol uses namespace isolation:
 *     - internal type name: `VerifiedAuditRequest` (keeps the literal name; not exported to the root index.ts)
 *     - public alias: `AuditShareVerifiedRequest` (exported to packages/types/src/index.ts)
 */
export interface VerifiedAuditRequest {
    /** csp v0.1 metadata field (AuditShareVersion brand; factory toAuditShareVersion)*/
    readonly auditShareVersion: AuditShareVersion;
    /** = DelegatedAuditKey.auditKeyId (AuditKeyId brand; factory toAuditKeyId)*/
    readonly token: AuditKeyId;
    /** selective disclosure projection field subset; every item must belong to the AuditEventField enum*/
    readonly disclosedClaims: readonly AuditEventField[];
    /** verifier-side issued nonce; UUID v4 format (same format as csp UuidV4String)*/
    readonly challenge: string;
    /** = target domain DID; strict audience binding*/
    readonly audience: DID;
    /** csp signed payload's own expiry window; ISO 8601 UTC*/
    readonly notAfter: Timestamp;
    /** L3 manager fetch-by-scope brand; toAuditShareScope() factory guard*/
    readonly requestedScope: AuditShareScope;
    /** = DelegatedAuditKey.delegatedTo; strict-equality verify*/
    readonly requesterDid: DID;
    /** Ed25519; requester private key signs canonicalize(request minus requesterSignature)*/
    readonly requesterSignature: Signature;
}

/**
 * AuditShareVerifiedRequest — public alias for VerifiedAuditRequest (to avoid colliding with the same-named audit-access v0.2 type)
 *
 * Equivalent to the literal `VerifiedAuditRequest`; external consumers of this sub-protocol use this alias.
 */
export type AuditShareVerifiedRequest = VerifiedAuditRequest;

/**
 * AuditShareEntryWithWitness — wrapper layer returned by L3 manager fetchByChainIdentity
 *
 * Does not modify the hcc v0.1 HashChainEntry 7 fields; the audit-share v0.2 wrapper layer adds:
 *   - witness?: ParentWitness — hash chain witness (audit event chain prefetch)
 *   - auditEvent: AuditEvent — atp v0.1 audit event
 *   - disclosedFields: Partial<AuditEvent> — after selective disclosure projection
 */
export interface AuditShareEntryWithWitness {
    readonly entry: HashChainEntry;
    readonly witness?: ParentWitness;
    readonly auditEvent: AuditEvent;
    readonly disclosedFields: Partial<AuditEvent>;
}

/**
 * AuditShareVerifyResult — discriminated union (csp v0.1 pattern)
 *
 * selective disclosure projection:
 *   The auditEvents type goes from `readonly AuditEvent[]` → `readonly Partial<AuditEvent>[]`;
 *   it must go through project() projection and return only the disclosedClaims subset;
 *   a cross-domain caller will not obtain unauthorized fields.
 */
export type AuditShareVerifyResult =
    | {
          readonly ok: true;
          readonly entries: readonly HashChainEntry[];
          readonly auditEvents: readonly Partial<AuditEvent>[];
      }
    | {
          readonly ok: false;
          readonly code: AuditShareErrorCode;
          readonly reason: string;
      };

// ─── Factory Functions (brand cast guards; the sole valid path) ──────────────────

/**
 * toAuditKeyId — AuditKeyId brand type factory function
 *
 * Guard: the sole valid path to obtain an AuditKeyId; validates UUID v4 format at runtime.
 * The caller is not allowed to do `s as AuditKeyId` directly.
 *
 * @throws AuditShareError AUDIT_SHARE_TOKEN_INVALID if the format is non-compliant
 */
export function toAuditKeyId(s: string): AuditKeyId {
    if (typeof s !== 'string' || s.length === 0) {
        throw new AuditShareError(
            'AUDIT_SHARE_TOKEN_INVALID',
            `auditKeyId must be a non-empty string, got: ${JSON.stringify(s)}`,
            'token-format',
        );
    }
    if (
        !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
            s,
        )
    ) {
        throw new AuditShareError(
            'AUDIT_SHARE_TOKEN_INVALID',
            `auditKeyId must be a valid UUID v4: "${s}"`,
            'token-format',
        );
    }
    return s as AuditKeyId;
}

/**
 * toAuditShareVersion — AuditShareVersion brand type factory function
 *
 * Guard: the sole valid path to obtain an AuditShareVersion; validates semver + the valid value set at runtime.
 * v0.2 sole valid value: "1.0.0"
 *
 * @throws AuditShareError AUDIT_SHARE_VERSION_UNSUPPORTED if the format or version is non-compliant
 */
export function toAuditShareVersion(s: string): AuditShareVersion {
    if (typeof s !== 'string' || !/^[0-9]+\.[0-9]+\.[0-9]+$/.test(s)) {
        throw new AuditShareError(
            'AUDIT_SHARE_VERSION_UNSUPPORTED',
            `auditShareVersion must be valid semver (X.Y.Z): "${s}"`,
            'version-format',
        );
    }
    if (!AUDIT_SHARE_SUPPORTED_VERSIONS.includes(s)) {
        throw new AuditShareError(
            'AUDIT_SHARE_VERSION_UNSUPPORTED',
            `unsupported auditShareVersion "${s}"; supported: ${AUDIT_SHARE_SUPPORTED_VERSIONS.join(', ')}`,
            'version-set',
        );
    }
    return s as AuditShareVersion;
}

/**
 * toAuditShareScope — AuditShareScope brand type factory function
 *
 * Guard: the sole valid path to obtain an AuditShareScope;
 * sentinel values + empty values are fail-closed rejected.
 *
 * Rejected enumeration:
 *   undefined / null / empty string / "_DELETED_" / "_PLACEHOLDER_" / "_SENTINEL_" /
 *   "_TBD_" / "_NULL_" / "TODO" / "FIXME" / "XXX"
 *
 * auditClass must be ∈ {L1, L2, L3} (atp v0.1 three-level isolation)
 *
 * @throws AuditShareError AUDIT_SHARE_SCOPE_INVALID if any field is non-compliant
 */
export function toAuditShareScope(raw: {
    tenantId: string;
    auditClass: string;
    chainNamespace?: string;
}): AuditShareScope {
    // tenantId non-empty + non-sentinel
    if (typeof raw.tenantId !== 'string' || SENTINEL_VALUES.has(raw.tenantId)) {
        throw new AuditShareError(
            'AUDIT_SHARE_SCOPE_INVALID',
            `tenantId is null/sentinel: ${JSON.stringify(raw.tenantId)}`,
            'scope-tenant-id',
        );
    }
    // auditClass enum check
    if (
        raw.auditClass !== 'L1' &&
        raw.auditClass !== 'L2' &&
        raw.auditClass !== 'L3'
    ) {
        throw new AuditShareError(
            'AUDIT_SHARE_SCOPE_INVALID',
            `auditClass must be L1/L2/L3, got: ${JSON.stringify(raw.auditClass)}`,
            'scope-audit-class',
        );
    }
    // chainNamespace is optional; if provided it must be non-empty and non-sentinel
    if (raw.chainNamespace !== undefined) {
        if (
            typeof raw.chainNamespace !== 'string' ||
            SENTINEL_VALUES.has(raw.chainNamespace)
        ) {
            throw new AuditShareError(
                'AUDIT_SHARE_SCOPE_INVALID',
                `chainNamespace is sentinel: ${JSON.stringify(raw.chainNamespace)}`,
                'scope-chain-namespace',
            );
        }
    }

    const scope: {
        tenantId: string;
        auditClass: 'L1' | 'L2' | 'L3';
        chainNamespace?: string;
    } = {
        tenantId: raw.tenantId,
        auditClass: raw.auditClass,
    };
    if (raw.chainNamespace !== undefined) {
        scope.chainNamespace = raw.chainNamespace;
    }
    return scope as AuditShareScope;
}

// ─── assertNever exhaustive + handleAuditShareError switch 14 cases ─────────

/**
 * assertNeverAuditShareCode — AuditShareErrorCode exhaustive switch fallback
 *
 * Used in the default branch of the handleAuditShareError switch statement;
 * if a newly added AuditShareErrorCode value is not handled in the switch → compile-time error.
 *
 * @throws Error unreachable at runtime; if triggered, it means the type system was bypassed
 */
export function assertNeverAuditShareCode(code: never): never {
    throw new Error(
        `Unreachable: unhandled AuditShareErrorCode "${String(code)}"`,
    );
}

/**
 * AuditShareErrorContext — handleAuditShareError processing result
 *
 * httpStatus aligns with the csp/sr/da/hcc baseline pattern (fail-closed; does not return a stub 200):
 *   400 — schema / disclosed claims / format violations
 *   401 — challenge / signature / expiry category
 *   403 — audience / cross-tenant / delegator audience category
 *   422 — version unsupported
 *   503 — not used yet (reserved, same category as csp REVOCATION_QUERY_UNAVAILABLE)
 */
export interface AuditShareErrorContext {
    readonly code: AuditShareErrorCode;
    readonly httpStatus: 400 | 401 | 403 | 422 | 503;
    readonly message: string;
    readonly fatal: boolean;
}

/**
 * handleAuditShareError — AuditShareErrorCode switch full coverage of 17 cases + assertNever exhaustive
 *
 * v0.2 14 cases + v0.3 3 new cases (AUDIT_SHARE_VERIFIER_REQUIRED /
 * AUDIT_SHARE_BOUNDARY_CHECK_FAILED / AUDIT_SHARE_CHAIN_IDENTITY_TAMPERED).
 *
 * Every AuditShareErrorCode value must have a corresponding case;
 * assertNeverAuditShareCode(code) in the default branch ensures a compile-time exhaustive check.
 *
 * fail-closed principle: all errors map to 4xx/5xx; a stub 200 is not allowed.
 */
export function handleAuditShareError(
    code: AuditShareErrorCode,
): AuditShareErrorContext {
    switch (code) {
        case 'AUDIT_SHARE_TOKEN_INVALID':
            return {
                code,
                httpStatus: 401,
                message:
                    'audit-share token (DelegatedAuditKey.auditKeyId) is invalid, revoked, or not found',
                fatal: true,
            };
        case 'AUDIT_SHARE_TOKEN_EXPIRED':
            return {
                code,
                httpStatus: 401,
                message:
                    'audit-share DelegatedAuditKey is outside its validity window (validFrom <= now <= validUntil)',
                fatal: true,
            };
        case 'AUDIT_SHARE_AUDIENCE_MISMATCH':
            return {
                code,
                httpStatus: 403,
                message:
                    'audit-share request.audience does not strictly equal expectedAudience (csp F2 binding)',
                fatal: true,
            };
        case 'AUDIT_SHARE_CHALLENGE_INVALID':
            return {
                code,
                httpStatus: 401,
                message:
                    'audit-share challenge is not a valid UUID v4 or not in verifier-issued challenges (csp C1 reverse semantic)',
                fatal: true,
            };
        case 'AUDIT_SHARE_NOT_AFTER_EXPIRED':
            return {
                code,
                httpStatus: 401,
                message:
                    'audit-share request.notAfter is expired (csp I5 stale-replay defense)',
                fatal: true,
            };
        case 'AUDIT_SHARE_REQUESTER_SIGNATURE_INVALID':
            return {
                code,
                httpStatus: 401,
                message:
                    'audit-share request.requesterSignature Ed25519 verification failed',
                fatal: true,
            };
        case 'AUDIT_SHARE_DELEGATOR_SIGNATURE_INVALID':
            return {
                code,
                httpStatus: 401,
                message:
                    'audit-share DelegatedAuditKey.proof.signature Ed25519 verification failed (or signedBy !== delegatedFrom)',
                fatal: true,
            };
        case 'AUDIT_SHARE_DELEGATOR_AUDIENCE_MISMATCH':
            return {
                code,
                httpStatus: 403,
                message:
                    'audit-share DelegatedAuditKey.delegatedTo does not match request.requesterDid',
                fatal: true,
            };
        case 'AUDIT_SHARE_SCOPE_INVALID':
            return {
                code,
                httpStatus: 400,
                message:
                    'audit-share requestedScope is null/sentinel or auditClass not in {L1,L2,L3} (factory guard fail)',
                fatal: true,
            };
        case 'AUDIT_SHARE_CROSS_TENANT_REJECT':
            return {
                code,
                httpStatus: 403,
                message:
                    'audit-share cross-tenant query rejected (multi-tenant isolation fail-closed)',
                fatal: true,
            };
        case 'AUDIT_SHARE_HASH_CHAIN_INVALID':
            return {
                code,
                httpStatus: 401,
                message:
                    'audit-share hash chain verification failed (hcc v0.1 verifyHashChain primitive)',
                fatal: true,
            };
        case 'AUDIT_SHARE_DISCLOSED_CLAIMS_INVALID':
            return {
                code,
                httpStatus: 400,
                message:
                    'audit-share disclosedClaims contains values not in AuditEventField enum',
                fatal: true,
            };
        case 'AUDIT_SHARE_VERSION_UNSUPPORTED':
            return {
                code,
                httpStatus: 422,
                message:
                    'audit-share auditShareVersion is not valid semver or not in supported set',
                fatal: true,
            };
        case 'AUDIT_SHARE_SCHEMA_INVALID':
            return {
                code,
                httpStatus: 400,
                message:
                    'audit-share request JSON Schema validation failed (AJV strict mode)',
                fatal: true,
            };
        // v0.3 3 new cases
        case 'AUDIT_SHARE_VERIFIER_REQUIRED':
            // sdk verifier factory not injected OR raw transport evidence missing
            // 401 (same level as SIGNATURE_INVALID / CHALLENGE_INVALID — cryptographic identity derivation fail)
            return {
                code,
                httpStatus: 401,
                message:
                    'audit-share cryptographic verifier factory not invoked or raw transport evidence missing (caller must provide raw transport evidence)',
                fatal: true,
            };
        case 'AUDIT_SHARE_BOUNDARY_CHECK_FAILED':
            // sdk boundary check fails on one of 4 dimensions
            // (trustedDid not equal OR verifierKind not in expected OR verifiedAt stale OR sdkVersion downgrade)
            // 401 (cryptographic identity boundary guard fail)
            return {
                code,
                httpStatus: 401,
                message:
                    'audit-share boundary check failed (4 dimensions: trustedDid / verifierKind / verifiedAt freshness / sdkVersion downgrade)',
                fatal: true,
            };
        case 'AUDIT_SHARE_CHAIN_IDENTITY_TAMPERED':
            // hcc v0.2 chainIdentity preimage cryptographic enforce fail
            // 401 (same level as HASH_CHAIN_INVALID — hash chain primitive integrity fail)
            return {
                code,
                httpStatus: 401,
                message:
                    'audit-share chainIdentity preimage cryptographic enforce failed (any entry chainIdentity field OR canonicalPayload tampered → SHA-256 digest mismatch)',
                fatal: true,
            };
        default:
            /* v8 ignore next*/
            return assertNeverAuditShareCode(code);
    }
}
