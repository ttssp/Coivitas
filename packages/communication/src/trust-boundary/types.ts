/**
 * trust-boundary primitive v0.1 — L4 communication layer type definitions
 *
 * Implementation notes:
 * - `packages/types/src/trust-boundary.ts` is the L0 primary declaration
 * - This file holds the L4 communication channel's local types (needed for handshake / envelope integration)
 * - Once the L0 primary declaration is complete, the imports here will be replaced with L0 types (in a follow-up cleanup PR)
 *
 * Covers:
 * - brand types (TrustBoundaryId / TbVersionString)
 * - the TrustBoundary interface + 5-state discriminated union + 6 lifecycle events
 * - 12 invariants (I_tb_ver / I1-I10 + I_tb_audit_src)
 * - 8 legal transitions (T1-T8)
 * - the 17-entry TB_* error code namespace
 *
 * brand cast guard:
 * - direct casts `as TrustBoundaryId` / `as TbVersionString` are forbidden
 * - the factories are the only legal path (toTrustBoundaryId / toTbVersionString)
 */

import type { DID, Timestamp } from '@coivitas/types';

// ─── brand type hardening (csp triple defense line, layer 1) ──────────────────────────────

/** trust-boundary's own unique id brand type (UUID v4; boundary-id semantics; bare casts forbidden) */
export type TrustBoundaryId = string & { readonly __brand: 'TrustBoundaryId' };

/** trust-boundary protocol version brand type (a namespace independent of csp.cspVersion) */
export type TbVersionString = string & { readonly __brand: 'TbVersionString' };

/**
 * binding proof audit event id brand type (inherits the generic csp UuidV4String semantics)
 *
 * Local placeholder — to be replaced with import { UuidV4String } from '@coivitas/types' once the L0 csp implementation is complete.
 * Semantics: an audit event id (not the boundary's own id); type-level incompatible with TrustBoundaryId (to prevent the two kinds of id from being mixed up).
 */
export type UuidV4String = string & { readonly __brand: 'UuidV4String' };

const UUID_V4_REGEX =
    /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

const SEMVER_REGEX = /^[0-9]+\.[0-9]+\.[0-9]+$/;

/**
 * TrustBoundaryId factory function (the only legal path for the brand cast)
 * Strict UUID v4 format validation
 */
export function toTrustBoundaryId(s: string): TrustBoundaryId {
    if (!UUID_V4_REGEX.test(s)) {
        throw new Error('TB_ID_INVALID: not valid UUID v4');
    }
    return s as TrustBoundaryId;
}

/**
 * TbVersionString factory function (v0.1 has the single value '1.0.0'; independent tbVersion namespace)
 */
export function toTbVersionString(s: string): TbVersionString {
    if (!SEMVER_REGEX.test(s)) {
        throw new Error('TB_VERSION_UNSUPPORTED: not valid semver (X.Y.Z)');
    }
    return s as TbVersionString;
}

/**
 * UuidV4String factory function (placeholder; the import will be replaced once the L0 csp implementation is complete)
 */
export function toUuidV4String(s: string): UuidV4String {
    if (!UUID_V4_REGEX.test(s)) {
        throw new Error('TB_BINDING_PROOF_INVALID_UUID: not valid UUID v4');
    }
    return s as UuidV4String;
}

// ─── TrustBoundary interface + 5 state discriminated union ────────────

/**
 * TrustBoundary state machine — 5 states
 *
 * State-machine breaking-change firewall: emergency_suspended state is a v0.1 placeholder + the multisig rule is not implemented.
 * Full implementation is deferred to the integrated multisig + arbitration stage.
 */
export type TrustBoundaryState =
    | 'pending'
    | 'active'
    | 'suspended'
    | 'revoked'
    | 'expired';

/**
 * State-machine breaking-change firewall emergency state (v0.1 placeholder; not part of the 5 states)
 * The 5 states are the baseline; emergency_suspended is a separate state.
 */
export type TrustBoundaryEmergencyState = 'emergency_suspended';

/** the 6 kinds of lifecycle event (state-transition triggers) */
export type TrustBoundaryLifecycleEvent =
    | 'onTrustEstablished'
    | 'onLeaseExtended'
    | 'onSuspended'
    | 'onResumed'
    | 'onRevoked'
    | 'onExpired';

/** emergency-suspend lifecycle event (state-machine breaking-change firewall; v0.1 placeholder, declaration only) */
export type TrustBoundaryEmergencyEvent = 'onEmergencySuspended';

/**
 * audit event transitionSource three-state enum (I_tb_audit_src invariant)
 *
 * - 'client': triggered actively by principalSide + signed payload verify passes
 * - 'system': triggered automatically server-side (upstream token revocation cascade / parent delegation chain head revoked cascade)
 * - 'sweeper': triggered by the server-side background daemon when it detects lifecycleWindow.notAfter ≤ now (the independent audit source for T7)
 */
export type TransitionSource = 'client' | 'system' | 'sweeper';

/**
 * TrustBoundary v0.1 primary interface
 *
 * Field semantics:
 * - tbVersion = '1.0.0' (v0.1's single value)
 * - principalSide / boundedSide must not be equal (I2 no self-referential trust)
 * - state ∈ one of the 5 TrustBoundaryState states (I3)
 * - bindingProofId: undefined while pending; required for active/suspended/revoked/expired (I6)
 */
export interface TrustBoundary {
    /** tb protocol version metadata (independent namespace; v0.1 = '1.0.0') */
    tbVersion: TbVersionString;
    /** boundary unique id (UUID v4 brand) */
    id: TrustBoundaryId;
    /** one end of the boundary — principal-side (human / agent / system DID) */
    principalSide: DID;
    /** one end of the boundary — bounded-side (agent / resource DID) */
    boundedSide: DID;
    /** boundary scope (reuses the existing Capability union; introduces no new type; simplified here to string[]) */
    boundaryScope: readonly string[];
    /** boundary lifecycle window (creation time + expiry time; invariant I5) */
    lifecycleWindow: {
        readonly notBefore: Timestamp;
        readonly notAfter: Timestamp;
    };
    /** current state (5 states; invariant I3) */
    state: TrustBoundaryState;
    /** time the state was entered (written on each transition; used for auditing) */
    stateEnteredAt: Timestamp;
    /**
     * boundary binding proof id (the signature anchor for the trust-establishment event; nullable, corresponding to the pending state)
     * The actual binding proof payload uses the csp 5 fields + cspVersion (referencing the audit event by id).
     */
    bindingProofId?: UuidV4String;
    /** the associated current active token id (optional; used in the active-subset scenario) */
    boundedTokenId?: string;
    /** the associated delegation chain head (optional; referenced when establishing agent ↔ principal trust) */
    delegationChainHead?: string;
    /** the multisig authorization id associated with the emergency_suspended state (v0.1 placeholder + not enforced) */
    emergencyAuthorizationId?: string;
}

/**
 * BoundaryBindingProof — the anchor payload for the onTrustEstablished transition
 *
 * Implements the csp mandatory-5-fields SOP (token / disclosedClaims / challenge / audience / notAfter).
 * This type is the L4 transit-layer wrapper; the actual csp signed payload fields are defined by L0 csp.
 * The local placeholder fields ensure the csp mandatory-5-fields SOP guard can verify at the L4 layer.
 */
export interface BoundaryBindingProof {
    /** csp version metadata (v0.1 = '1.0.0'; csp mandatory-5-fields SOP) */
    cspVersion: string;
    /** the csp `token` field (binding proof token; not a CapabilityToken) */
    token: string;
    /** the csp `disclosedClaims` field (mode A = []; mode B selective disclosure) */
    disclosedClaims: readonly string[];
    /** the csp `challenge` field (server-issued nonce; replay protection) */
    challenge: string;
    /** the csp `audience` field (server-side trust-boundary registry URL; I7 strict equality) */
    audience: string;
    /** the csp `notAfter` field (server-enforced lifecycleWindow.notAfter; I8 strict equality) */
    notAfter: Timestamp;
    /** Ed25519 signature (signed by the principal cold key; I9 PoP) */
    proofValue: string;
    /** the associated boundary id */
    boundaryId: TrustBoundaryId;
}

/**
 * LeaseExtensionProof — the anchor payload for the onLeaseExtended transition (T2)
 *
 * Implements the lease-only renewal model; field structure is the same as BoundaryBindingProof.
 * I8 server-enforced expiry — newNotAfter ≤ now + maxLifecycleWindow (default 6 months).
 */
export interface LeaseExtensionProof {
    cspVersion: string;
    token: string;
    disclosedClaims: readonly string[];
    challenge: string;
    audience: string;
    /** server-enforced new notAfter (I8; the client is not allowed to sign an expiry too far in the future) */
    notAfter: Timestamp;
    proofValue: string;
    boundaryId: TrustBoundaryId;
}

/**
 * TrustBoundaryAuditEvent — lifecycle event audit payload
 *
 * transitionSource is mandatory and enforced (I_tb_audit_src invariant).
 * Uses csp JCS canonicalization (the canonicalize npm package by Erdtman); JSON.stringify fallback is forbidden.
 */
export interface TrustBoundaryAuditEvent {
    /** lifecycle event name (6 kinds) */
    type: TrustBoundaryLifecycleEvent;
    /** the associated trust boundary id */
    boundaryId: TrustBoundaryId;
    /** state before the transition (pending is the initial state; one of the 5 states) */
    transitionBefore: TrustBoundaryState;
    /** state after the transition (one of the 5 states) */
    transitionAfter: TrustBoundaryState;
    /** the transition trigger source (mandatory; I_tb_audit_src invariant) */
    transitionSource: TransitionSource;
    /** the DID that triggered the transition (client transition = principalSide; sweeper = system DID) */
    actorDID: DID;
    /** the time the transition was written (server-side trusted clock) */
    timestamp: Timestamp;
    /** binding proof audit event id (T6/T7 expired inherits it; no new signing event) */
    bindingProofId?: UuidV4String;
}

// ─── TB_* error code namespace (17 entries) ────────────────────────

/**
 * tb error code strict union
 *
 * The TB_* prefix is an independent namespace; fully orthogonal to the csp / token / delegation / scope error codes.
 * The error code namespace is frozen (after v0.1, renaming / removing / changing severity is not allowed).
 */
export type TbErrorCode =
    | 'TB_VERSION_UNSUPPORTED'
    | 'TB_ID_INVALID'
    | 'TB_PARTY_INVALID'
    | 'TB_PARTY_SELF_REFERENTIAL'
    | 'TB_STATE_INVALID'
    | 'TB_INVALID_TRANSITION'
    | 'TB_LIFECYCLE_INVALID'
    | 'TB_BOUNDARY_EXPIRED'
    | 'TB_BINDING_PROOF_MISSING'
    | 'TB_BINDING_PROOF_UNEXPECTED'
    | 'TB_PAYLOAD_COVERAGE_INSUFFICIENT'
    | 'TB_EXPIRY_CLIENT_CONTROLLED'
    | 'TB_PRINCIPAL_POP_MISSING'
    | 'TB_EMERGENCY_NOT_IMPLEMENTED'
    | 'TB_AUDIT_CANONICALIZE_FAILED'
    | 'TB_SCHEMA_VIOLATION'
    | 'TB_AUDIT_TRANSITION_SOURCE_INVALID'
    | 'TB_SUSPENDED_OPERATION_DENIED'
    | 'TB_BOUNDARY_NOT_FOUND'
    | 'TB_BOUNDARY_PROOF_VERIFY_FAILED';

/**
 * TbProtocolError — fail-closed error class
 *
 * fail-closed; any invariant violation = deny by default.
 * fail-degraded / fail-open / partial-PASS are not allowed (strict for an auth/verification primitive).
 */
export class TbProtocolError extends Error {
    public readonly code: TbErrorCode;
    public readonly invariant?: string;

    constructor(code: TbErrorCode, message: string, invariant?: string) {
        super(`[${code}] ${message}`);
        this.name = 'TbProtocolError';
        this.code = code;
        this.invariant = invariant;
    }
}

// ─── transition allowlist (8 legal transitions) ─────────────────────────

/**
 * legal transition allowlist (T1-T8; enforces invariant I4)
 *
 * Each transition tuple = [from state, event, to state].
 * Any from-event-to combination not in this allowlist = TB_INVALID_TRANSITION fail-closed reject.
 *
 * Anti-phantom design: the state transition allowlist is actively invoked across all 8 paths
 * of the transitionState switch case.
 */
export const LEGAL_TRANSITIONS: ReadonlyArray<{
    readonly id: 'T1' | 'T2' | 'T3' | 'T4' | 'T5' | 'T6' | 'T7' | 'T8';
    readonly from: TrustBoundaryState;
    readonly event: TrustBoundaryLifecycleEvent | TrustBoundaryEmergencyEvent;
    readonly to: TrustBoundaryState | TrustBoundaryEmergencyState;
    readonly description: string;
}> = [
    {
        id: 'T1',
        from: 'pending',
        event: 'onTrustEstablished',
        to: 'active',
        description: 'tb lifecycle entry point; binding proof verify + I9 PoP',
    },
    {
        id: 'T2',
        from: 'active',
        event: 'onLeaseExtended',
        to: 'active',
        description: 'lease renewal; active self-loop; server-enforced expiry',
    },
    {
        id: 'T3',
        from: 'active',
        event: 'onSuspended',
        to: 'suspended',
        description: 'principal actively shortens the lease / withdraws trust',
    },
    {
        id: 'T4',
        from: 'suspended',
        event: 'onResumed',
        to: 'active',
        description: 'resume a suspended boundary before it expires; I5',
    },
    {
        id: 'T5',
        from: 'active',
        event: 'onRevoked',
        to: 'revoked',
        description: 'active → revoked terminal state; irreversible',
    },
    {
        id: 'T5',
        from: 'suspended',
        event: 'onRevoked',
        to: 'revoked',
        description: 'suspended → revoked terminal state; irreversible',
    },
    {
        id: 'T6',
        from: 'active',
        event: 'onExpired',
        to: 'expired',
        description: 'active → expired natural expiry; declared actively by client/system',
    },
    {
        id: 'T6',
        from: 'suspended',
        event: 'onExpired',
        to: 'expired',
        description: 'suspended → expired natural expiry; declared actively by client/system',
    },
    {
        id: 'T7',
        from: 'active',
        event: 'onExpired',
        to: 'expired',
        description: 'active → expired auto-sweep;server-side sweeper detect',
    },
    {
        id: 'T7',
        from: 'suspended',
        event: 'onExpired',
        to: 'expired',
        description: 'suspended → expired auto-sweep;server-side sweeper detect',
    },
    {
        id: 'T8',
        from: 'active',
        event: 'onEmergencySuspended',
        to: 'emergency_suspended',
        description: 'fail-closed placeholder in v0.1; returns TB_EMERGENCY_NOT_IMPLEMENTED',
    },
] as const;

/**
 * default lifecycle window bounds (the lease-only renewal model)
 *
 * - minWindow: 1 second (clock skew protection; I5 enforces lifecycleWindow.notAfter > now + minWindow)
 * - maxLifecycleWindow: 6 months (I8 server-enforced expiry)
 */
export const TB_DEFAULT_BOUNDS = {
    minWindowMs: 1_000,
    maxLifecycleWindowMs: 6 * 30 * 24 * 60 * 60 * 1_000,
} as const;
