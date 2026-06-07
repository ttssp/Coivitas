import type { DID, Signature, Timestamp } from './base.js';

export interface AllowlistScope {
    type: 'allowlist';
    field: string;
    values: string[];
}

export interface NumericLimitScope {
    type: 'numeric_limit';
    field: string;
    max: number;
    currency?: string;
}

/**
 * Recurring time window
 *
 * timezone must be an IANA identifier (e.g. 'Asia/Shanghai').
 * startTime > endTime indicates it crosses midnight (e.g. 22:00 → 06:00).
 */
export interface RecurringWindow {
    /** daily start time, 'HH:MM' 24-hour format*/
    startTime: string;
    /** daily end time, 'HH:MM' 24-hour format*/
    endTime: string;
    /** ISO 8601 day of week (1=Monday, 7=Sunday); omitted = available every day*/
    daysOfWeek?: number[];
    /** IANA timezone identifier; required when recurringWindow is present*/
    timezone: string;
}

/**
 * TemporalScope — added
 *
 * Constrains the available time range of a Capability.
 * notBefore/notAfter use UTC; recurringWindow uses the local timezone specified by timezone.
 */
export interface TemporalScope {
    type: 'temporal_scope';
    notBefore: Timestamp;
    notAfter: Timestamp;
    recurringWindow?: RecurringWindow;
}

/**
 * MeterFieldRef.source tri-state enum
 *
 * - 'action_record' : implemented, reads metering values from the ActionRecord ledger
 * - 'external_witness' : only the type lands, the evaluator throws METRIC_SOURCE_NOT_IMPLEMENTED (fail-closed)
 * - 'consensus_meter' : only the type lands, the evaluator throws METRIC_SOURCE_NOT_IMPLEMENTED (fail-closed)
 *
 * @frozen frozen
 */
export type MeterFieldRefSource =
    | 'action_record'
    | 'external_witness'
    | 'consensus_meter';

/**
 * Metering field reference (v0.2 source tri-state extension)
 *
 * metric is an opaque registry key, not a field path.
 * source is extended to a tri-state; only the 'action_record' evaluator is implemented.
 *
 * @breaking no (v0.1 validator fail-closes on an unknown source)
 * @frozen frozen
 */
export interface MeterFieldRef {
    /**
     * Metering data source (v0.2 extended to a tri-state)
     *
     * - 'action_record': aggregated from the local ActionRecord ledger (implemented)
     * - 'external_witness': obtains a signed-endorsed value from an external witness (only type + interface)
     * - 'consensus_meter': obtains a multi-sig-endorsed value from a multi-party consensus metering protocol (only type + interface)
     */
    source: MeterFieldRefSource;
    /** must belong to METER_FIELD_REGISTRY*/
    metric: string;
    unit?: string;
    precision?: number;
}

/**
 * CumulativeLimitScope — added (conditional delivery)
 *
 * A stateful cumulative metering constraint based on the ActionRecord ledger.
 */
export interface CumulativeLimitScope {
    type: 'cumulative_limit';
    meterField: MeterFieldRef;
    max: number;
    /** fixed/calendar window (UTC boundaries), not a rolling window*/
    window: 'hour' | 'day' | 'week' | 'month';
    currency?: string;
}

/**
 * Scope union type — breaking-format-change #2
 *
 * Extended from 2 kinds to 4. A 0.2.0 Token may use all of them; a 0.1.0 Token is limited to the first two.
 */
export type Scope =
    | AllowlistScope
    | NumericLimitScope
    | TemporalScope
    | CumulativeLimitScope;

export interface Capability {
    action: string;
    scope: Scope;
}

export interface TokenProof {
    type: 'Ed25519Signature2026';
    created: Timestamp;
    /**
     * specVersion 0.1.0: did:key:...#key-1 only
     * specVersion 0.2.0: did:key:...#key-1 or did:agent:...#key-1 (a child Token that includes a delegationChain)
     */
    verificationMethod: string;
    value: Signature;
}

/**
 * delegation-chain sub-protocol version number (separate namespace)
 *
 * Aligned with the separate-namespace pattern of the 6 sub-protocols csp/tb/RFP/atp/hcc/ms
 * (cspVersion/tbVersion/rfpVersion/atpVersion/hccVersion/msVersion).
 *
 * Design intent:
 *   - a local dc revision does not trigger a global specVersion breaking change
 *   - backward compatible: when DelegationProof.dcVersion is absent the validator falls back to token.specVersion
 *   - an independent future evolution path
 *
 * @since v0.3.0
 */
export const DC_VERSION = '0.3.0' as const;

/**
 * A single link in the delegation chain
 *
 * Records one permission delegation from delegatorDid to delegateeDid,
 * protected by the delegator's signature.
 *
 * Note: DelegationProof.proof is an issuance-time signature (not verify-time) —
 *   the csp v0.1 5-field invariant does not apply.
 */
export interface DelegationProof {
    parentTokenId: string;
    delegatorDid: DID;
    delegateeDid: DID;
    /** snapshot of the parent Token's capabilities, protected by the delegator's signature*/
    parentCapabilities: Capability[];
    /** snapshot of the parent Token's expiresAt*/
    parentExpiresAt: Timestamp;
    attenuatedCapabilities: Capability[];
    proof: TokenProof;
    /**
     * delegation-chain sub-protocol version
     *
     * Optional field; when absent the validator falls back to token.specVersion (v0.1 compatibility path).
     * When this field is present, the validator uses this value to identify the dc sub-protocol contract version.
     *
     * @since v0.3.0
     */
    dcVersion?: string;
}

/**
 * DelegationProof signature payload
 *
 * Note: the dcVersion field is included in the signature payload (if present), ensuring the version metadata is
 * protected by the delegator's signature against verify-time tampering. Omit only excludes the proof field itself (self-reference).
 */
export type DelegationProofSignedPayload = Omit<DelegationProof, 'proof'>;

/** maximum delegation chain depth*/
export const MAX_DELEGATION_DEPTH = 5;

/**
 * delegation-chain error code namespace (separate union; L0 single source of truth)
 *
 * Mandatorily extracted as a standalone exported union:
 *   - L0 = single source of truth; cannot be redefined inline or as a partial subset in L2
 *   - L2 must `import type { DcErrorCode } from '@coivitas/types'`
 *   - L2+ callers use handleDcError for an exhaustive switch (compile-time enforcement of full code coverage)
 *
 * Namespace constraint: this union contains only delegation chain's own error codes; borrowing cross-spec
 * namespaces such as CSP_* / TB_* is forbidden.
 *
 * @since v0.3.0
 */
export type DcErrorCode =
    | 'DEPTH_EXCEEDED'
    | 'ATTENUATION_VIOLATED'
    | 'DELEGATION_CHAIN_INVALID'
    | 'SIGNATURE_INVALID'
    | 'PARENT_TOKEN_REVOKED'
    | 'PARENT_TOKEN_NOT_FOUND'
    | 'PARENT_TOKEN_EXPIRED'
    | 'EXPIRY_EXCEEDED'
    | 'DELEGATOR_MISMATCH'
    | 'CYCLE_DETECTED'
    | 'ROOT_NOT_PRINCIPAL'
    | 'INVALID_TOKEN_FORMAT'
    | 'ROTATION_NOT_SUPPORTED';

/**
 * CapabilityToken — breaking-format-change #3
 *
 * Adds the optional field delegationChain.
 * Without this field the behavior is identical to specVersion 0.1.0; with this field specVersion must be 0.2.0.
 */
export interface CapabilityToken {
    id: string;
    specVersion: string;
    issuerDid: DID;
    principalDid: DID;
    issuedTo: DID;
    issuedAt: Timestamp;
    expiresAt: Timestamp;
    capabilities: Capability[];
    revocationUrl: string;
    proof: TokenProof;
    /**
     * Added — ordered delegation chain.
     * Index 0 is the earliest, the end is the most recent. Absent = single-hop Token.
     * length ≤ MAX_DELEGATION_DEPTH.
     */
    delegationChain?: DelegationProof[];
}

/**
 * Structured detail of attenuation validation
 */
export type AttenuationDetail =
    | { rule: '2a'; missingDimension: string }
    | { rule: '2c'; introducedDimension: string }
    | {
          rule: 'temporal_subset';
          reason: 'notBefore' | 'notAfter' | 'recurringWindow';
      }
    | {
          rule: 'cumulative_subset';
          reason: 'max' | 'window' | 'meterField' | 'currency';
      }
    | { rule: 'scope_type_unknown'; scopeType: string }
    | { rule: 'allowlist_violation'; field: string }
    | { rule: 'numeric_limit_violation'; field: string }
    | {
          rule: 'capabilities_mismatch';
          at: 'parentCapabilities' | 'continuity' | 'leaf';
      }
    /**
     * Two scopes with the same scopeMatchKey appear under the same action (e.g. the parent Token
     * contains two `allowlist:category` entries); rejected outright by the fail-closed rule — to avoid
     * Map.set silently overwriting and letting a loose scope replace the strictest scope.
     */
    | {
          rule: 'duplicate_dimension';
          side: 'parent' | 'child';
          action: string;
          dimension: string;
      }
    /**
     * An allowlist scope's values array is empty — authorizes zero items, a dead
     * token on issuance, rejected by the fail-fast rule.
     */
    | {
          rule: 'empty_allowlist';
          side: 'parent' | 'child';
          action: string;
          field: string;
      };

/**
 * Extended signature return value of validateAttenuation
 *
 * within the same version the legacy boolean return can be used; mixed-version scenarios must use this structure.
 */
export type AttenuationResult =
    | { ok: true }
    | { ok: false; mixedVersion: boolean; detail: AttenuationDetail };

/**
 * Delegation chain validation result
 *
 * The reason field uses the standalone DcErrorCode union (L0 single source of truth).
 * Error codes are no longer inlined here — L2+ callers are forced to import DcErrorCode and do an exhaustive switch.
 */
export interface DelegationChainValidationResult {
    valid: boolean;
    depth: number;
    /**
     * Validation failure reason (only when valid === false)
     * @see DcErrorCode — L0 single source of truth; cannot be redefined inline by the caller
     */
    reason?: DcErrorCode;
    brokenAtIndex?: number;
    revokedTokenId?: string;
    detail?: AttenuationDetail;
}

/**
 * Revocation reason (versioned extension)
 */
export type RevocationReason =
    | 'MANUAL_REVOCATION'
    | 'KEY_COMPROMISE'
    | 'EXPIRED_EARLY'
    | 'AGENT_DEACTIVATED'
    /** Added — cascading invalidation because an upstream delegation was revoked*/
    | 'DELEGATION_REVOKED';
