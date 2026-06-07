/**
 * Dispute Arbitration L0 type definitions
 *
 * dispute-arbitration v0.1 sub-protocol
 *
 * Brand-cast guard: every brand type can only be obtained through a to*() factory function;
 * direct casts such as `as DisputeId` are forbidden (a single cast inside the factory is compliant).
 *
 * Design baseline — csp dual-class:
 *   DisputeFilingSignedPayload: csp constraint 1 FULL (verify-time; issuance-time uses DisputeFiling)
 *   ArbitrationDecision: NOT-APPLICABLE (not a CSP-constrained object)
 *
 * Design baseline — 2-transition freeze:
 *   the only legal transitions: FILED→RESOLVED + FILED→EXPIRED
 *   any other transition → DA_STATE_TRANSITION_INVALID
 */

import type { DID } from '../base.js';
import type { CspVersionString } from '../canonical-signed-payload/types.js';
import {
    DA_DISPUTE_TYPE_VALUES,
    DA_STATE_VALUES,
    DA_VERDICT_VALUES,
} from './constants.js';

// ─── Brand Types (brand-cast guard; compile-time enforced) ───────────────────────────────────────

type Brand<T extends string> = { readonly __brand: T };

/**
 * Dispute case UUID brand type
 *
 * Constructed only via the toDisputeId() factory.
 */
export type DisputeId = string & Brand<'DisputeId'>;

/**
 * DA protocol version brand type
 *
 * Constructed only via the toDaVersion() factory (daVersion field).
 */
export type DaVersion = string & Brand<'DaVersion'>;

/**
 * Settlement operation ID brand type (optional association field)
 *
 * Constructed only via the toSettlementOperationId() factory.
 */
export type SettlementOperationId = string & Brand<'SettlementOperationId'>;

/**
 * Arbitration canonical hash hex brand type (SHA-256/JCS)
 *
 * Constructed only via the toCanonicalHashHex() factory.
 */
export type CanonicalHashHex = string & Brand<'CanonicalHashHex'>;

// ─── Enum union types ────────────────────────────────────────────────────────

/**
 * Dispute state (3-state reduction)
 *
 * Design baseline: 2-transition freeze (FILED→RESOLVED + FILED→EXPIRED).
 * FILED = in progress; RESOLVED = terminal (has a verdict); EXPIRED = terminal (timed out).
 */
export type DisputeState = (typeof DA_STATE_VALUES)[number];

/**
 * Dispute type (5 categories frozen)
 */
export type DisputeType = (typeof DA_DISPUTE_TYPE_VALUES)[number];

/**
 * Verdict (3 categories frozen)
 */
export type DaVerdict = (typeof DA_VERDICT_VALUES)[number];

// ─── State transition constants (2-transition freeze) ─────────────────────────────────────

/**
 * Legal state transition pairs (design baseline)
 *
 * Strict 2-transition freeze; any additional transition is blocked.
 */
export const DISPUTE_STATE_TRANSITIONS: ReadonlyArray<
    readonly [DisputeState, DisputeState]
> = [
    ['FILED', 'RESOLVED'],
    ['FILED', 'EXPIRED'],
] as const;

// ─── Interface definitions ─────────────────────────────────────────────────────────────────

/**
 * Arbitrator identity information
 */
export interface Arbitrator {
    readonly did: DID;
    readonly publicKey: string;
    readonly isActive: boolean;
}

/**
 * Dispute filing (issuance-time internal object; not CSP-constrained)
 *
 * Design baseline: this interface is used at issuance-time;
 * verify-time goes through DisputeFilingSignedPayload (CSP constraint 1 FULL).
 */
export interface DisputeFiling {
    readonly disputeId: DisputeId;
    readonly claimantDid: DID;
    readonly respondentDid: DID;
    readonly disputeType: DisputeType;
    readonly evidenceUris: readonly string[];
    readonly settlementOperationRef?: SettlementOperationId;
    readonly cspVersion: CspVersionString;
    readonly token: string;
    readonly disclosedClaims: Record<string, unknown>;
    readonly challenge: string;
    readonly audience: string;
    readonly notAfter: string;
    readonly filedAt: string;
    readonly daVersion: DaVersion;
}

/**
 * Dispute filing signed payload (verify-time; CSP constraint 1 FULL)
 *
 * Design baseline: csp dual-class — this type is a CSP-constrained object (verify-time).
 * 13 fields enter the canonical hash; ordering is fixed by JCS RFC 8785.
 */
export interface DisputeFilingSignedPayload {
    readonly disputeId: DisputeId;
    readonly claimantDid: DID;
    readonly respondentDid: DID;
    readonly disputeType: DisputeType;
    readonly evidenceUris: readonly string[];
    readonly settlementOperationRef?: SettlementOperationId;
    readonly cspVersion: CspVersionString;
    /**
     * daVersion — DA protocol version metadata
     *
     * schemas.ts DISPUTE_FILING_SIGNED_PAYLOAD_SCHEMA.required includes 'daVersion';
     * the interface must keep this field in sync, otherwise any payload constructed through the TypeScript type system will necessarily fail AJV;
     * the triple defense line requires bidirectional schema/interface consistency.
     */
    readonly daVersion: DaVersion;
    readonly token: string;
    readonly disclosedClaims: Record<string, unknown>;
    readonly challenge: string;
    readonly audience: string;
    readonly notAfter: string;
    readonly filedAt: string;
    /** SHA-256(JCS(14 fields; including daVersion))*/
    readonly canonicalHash: CanonicalHashHex;
    /** CSP claimant signature*/
    readonly claimantSignature: string;
}

/**
 * Arbitration decision (ArbitrationDecision)
 *
 * Design baseline: NOT-APPLICABLE — not CSP-constrained (no csp constraint at issuance-time).
 * multisigPoolSize is subject to the three-layer enforcement constraint.
 */
export interface ArbitrationDecision {
    readonly decisionId: string;
    readonly disputeId: DisputeId;
    readonly verdict: DaVerdict;
    /** multisig threshold = computeThreshold(poolSize)*/
    readonly multisigThreshold: number;
    /** arbitrator pool size [MIN_ARBITRATOR_COUNT, MAX_ARBITRATOR_COUNT]*/
    readonly multisigPoolSize: number;
    readonly decisionCanonicalHash: CanonicalHashHex;
    readonly arbitratorSignatures: readonly ArbitratorSignature[];
    readonly decidedAt: string;
}

/**
 * Single arbitrator signature (arbitratorSignatures element)
 */
export interface ArbitratorSignature {
    readonly arbitratorDid: DID;
    readonly signature: string;
}

/**
 * Dispute state record (ledger entity)
 */
export interface Dispute {
    readonly disputeId: DisputeId;
    readonly tenantId: string;
    readonly currentState: DisputeState;
    readonly disputeType: DisputeType;
    readonly claimantDid: DID;
    readonly respondentDid: DID;
    readonly disputeFilingCanonicalHash: CanonicalHashHex;
    readonly settlementOperationRef?: SettlementOperationId;
    readonly evidenceUris: readonly string[];
    readonly cspVersion: CspVersionString;
    readonly daVersion: DaVersion;
    readonly filedAt: string;
    readonly resolvedAt?: string;
    readonly expiredAt?: string;
    readonly attemptedAt: string;
    readonly createdAt: string;
}

/**
 * Dispute state transition event (audit linkage; atp audit event)
 */
export interface DisputeStateTransitionEvent {
    readonly disputeId: DisputeId;
    readonly fromState: DisputeState;
    readonly toState: DisputeState;
    readonly transitionedAt: string;
    readonly triggeredBy: 'ARBITRATION_DECISION' | 'PC3_TIMEOUT_EXPIRY';
    /** atp audit class fixed at L2 (atp v0.1 frozen; 'dispute_event' forbidden)*/
    readonly auditClass: 'L2';
    /**
     * reviewQueue — manual review queue flag for the EXPIRED state
     *
     * Invariant: the EXPIRED terminal state triggers enqueue into the manual review queue = true;
     * non-EXPIRED states (RESOLVED / FILED) → undefined (optional)
     */
    readonly reviewQueue?: boolean;
}

// ─── Type constraint constants (runtime-available) ─────────────────────────────────────────────

// Re-exported for runtime validation
export {
    MIN_ARBITRATOR_COUNT,
    MAX_ARBITRATOR_COUNT,
    DA_VERSION_CURRENT,
} from './constants.js';
