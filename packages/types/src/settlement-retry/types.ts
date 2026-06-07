/**
 * Settlement Retry (SR) sub-protocol v0.1 — core type definitions
 *
 * Core types:
 *   SettlementRetryState — 5-state union
 *   SETTLEMENT_RETRY_STATE_TRANSITIONS — allowlist of 6 legal transitions
 *   RetryAttempt — structure of a single retry record
 *   IdempotencyRecord — idempotency record
 *   SettlementType — settlement type enum (v0.1 only fiat_transfer + digital_wallet)
 *   RetryAttemptFailureReason— union of 6 failure reasons (named separately from SrErrorCode)
 *   SettlementOperationSignedPayload — csp 5-field invariant FULL (csp v0.1 constraint 1)
 *   SettlementOperation — core settlement operation interface
 *
 * csp 5-field invariant (FULL; csp v0.1 constraint 1):
 *   token / disclosedClaims / challenge / audience / notAfter + cspVersion + srVersion metadata FULL
 *
 * Guard: SettlementType values are validated via validateSettlementType();
 *           direct `s as SettlementType` casts are not allowed.
 */

import type { DID, Signature, Timestamp } from '../base.js';
import type {
    CanonicalSignedPayload,
    CspVersionString,
} from '../canonical-signed-payload/types.js';
import type {
    Amount,
    Currency,
    IdempotencyKey,
    OperationId,
    RetryAttemptId,
    SrTenantId,
    SrVersion,
} from './brands.js';
import { SrError } from './errors.js';

// ─── SettlementRetryState (5-state union) ──────────────────────────

/**
 * SettlementRetryState — the 5 states of the settlement retry state machine
 *
 * Strict allowlist:
 *   PENDING — initial state; operation created and awaiting processing
 *   IN_PROGRESS — retry executing (intermediate state)
 *   SUCCEEDED — terminal state; settlement succeeded (not retryable)
 *   FAILED — intermediate failure state; can be retried again (attempt_count < MAX_RETRY_ATTEMPTS)
 *   DEAD_LETTER — terminal state; retry limit exceeded or non-retryable error (requires manual review)
 *
 * Terminal states: SUCCEEDED + DEAD_LETTER (cannot transition again)
 * Intermediate states: PENDING / IN_PROGRESS / FAILED
 */
export type SettlementRetryState =
    | 'PENDING'
    | 'IN_PROGRESS'
    | 'SUCCEEDED'
    | 'FAILED'
    | 'DEAD_LETTER';

/**
 * SETTLEMENT_RETRY_STATE_TRANSITIONS — allowlist of legal state transitions (ReadonlyArray)
 *
 * Strict allowlist finite state machine:
 *   list of [from, to] tuples; any transition not in this list → SR_STATE_TRANSITION_INVALID.
 *
 * 6 legal transitions:
 *   PENDING → IN_PROGRESS (start executing)
 *   IN_PROGRESS → SUCCEEDED (completed successfully)
 *   IN_PROGRESS → FAILED (this attempt failed; retryable)
 *   IN_PROGRESS → DEAD_LETTER (unrecoverable; straight to terminal state)
 *   FAILED → IN_PROGRESS (continue retrying; attempt_count < MAX)
 *   FAILED → DEAD_LETTER (retry limit reached; transition to terminal state)
 */
export const SETTLEMENT_RETRY_STATE_TRANSITIONS: ReadonlyArray<
    readonly [SettlementRetryState, SettlementRetryState]
> = [
    ['PENDING', 'IN_PROGRESS'],
    ['IN_PROGRESS', 'SUCCEEDED'],
    ['IN_PROGRESS', 'FAILED'],
    ['IN_PROGRESS', 'DEAD_LETTER'],
    ['FAILED', 'IN_PROGRESS'],
    ['FAILED', 'DEAD_LETTER'],
] as const;

/**
 * TERMINAL_STATES — set of terminal states (cannot transition again)
 */
export const TERMINAL_STATES: ReadonlySet<SettlementRetryState> = new Set([
    'SUCCEEDED',
    'DEAD_LETTER',
] as const);

// ─── SettlementType (v0.1 only fiat_transfer + digital_wallet) ───────

/**
 * SettlementType — settlement type
 *
 * v0.1 supports only:
 *   fiat_transfer — fiat-currency transfer
 *   digital_wallet — digital wallet
 *
 * Other types → SR_VERSION_UNSUPPORTED.
 * Note: implemented as a string literal union rather than a TypeScript enum; consistent with the existing codebase pattern.
 */
export type SettlementType = 'fiat_transfer' | 'digital_wallet';

/**
 * SR_SUPPORTED_SETTLEMENT_TYPES — set of settlement types supported in v0.1
 */
export const SR_SUPPORTED_SETTLEMENT_TYPES: readonly SettlementType[] = [
    'fiat_transfer',
    'digital_wallet',
] as const;

/**
 * validateSettlementType — runtime validation of SettlementType
 *
 * The only legal path to validate a SettlementType.
 *
 * @throws SrError SR_VERSION_UNSUPPORTED if the settlement type is not supported
 */
export function validateSettlementType(s: string): SettlementType {
    if (s === 'fiat_transfer' || s === 'digital_wallet') {
        return s;
    }
    throw new SrError('SR_VERSION_UNSUPPORTED', {
        settlementType: s,
        supported: SR_SUPPORTED_SETTLEMENT_TYPES,
    });
}

// ─── RetryAttemptFailureReason (6 items; named separately from SrErrorCode) ────────────────

/**
 * RetryAttemptFailureReason — failure reason for a single retry (6 items)
 *
 * Note: named separately from SrErrorCode; RetryAttemptFailureReason is the business reason at the RetryAttempt record layer;
 *     SrErrorCode is the error code thrown at the protocol layer. The two differ semantically but have a mapping relationship.
 *
 * The SQL DDL settlement_retries.failure_reason CHECK corresponds to these 6 items.
 */
export type RetryAttemptFailureReason =
    | 'SR_PROVIDER_UNAVAILABLE'
    | 'SR_PROVIDER_TIMEOUT'
    | 'SR_PROVIDER_DECLINED'
    | 'SR_INSUFFICIENT_FUNDS'
    | 'SR_REGULATORY_REJECTED'
    | 'SR_INTERNAL_ERROR';

// ─── RetryAttempt (single retry record) ───────────────────────────────────

/**
 * RetryAttempt — execution record of a single retry
 *
 * Each executeSettlementRetry call writes one record.
 *
 * Invariants:
 *   attemptNumber ≥ 1 and ≤ MAX_RETRY_ATTEMPTS
 *   fromState → toState must be in SETTLEMENT_RETRY_STATE_TRANSITIONS
 *   failureReason is non-null if and only if toState = FAILED or an IN_PROGRESS failure occurs
 *   backoffDelayMs ≥ 0 and ≤ 60000 (60s upper bound)
 */
export interface RetryAttempt {
    readonly id: RetryAttemptId;
    readonly operationId: OperationId;
    readonly attemptNumber: number;
    readonly fromState: SettlementRetryState;
    readonly toState: SettlementRetryState;
    readonly attemptedAt: Timestamp;
    readonly completedAt: Timestamp | null;
    readonly resultSummary: string | null;
    readonly failureReason: RetryAttemptFailureReason | null;
    readonly backoffDelayMs: number;
    readonly auditEventId: string;
}

// ─── IdempotencyRecord ─────────────────────────────────────────────

/**
 * IdempotencyRecord — idempotency record
 *
 * key = SHA-256(JCS({operationId, principalDid, settlementType, amount, currency, cspVersion}))
 * Prevents concurrent duplicate submissions with the same business semantics.
 */
export interface IdempotencyRecord {
    readonly key: IdempotencyKey;
    readonly tenantId: SrTenantId;
    readonly operationId: OperationId;
    readonly currentState: SettlementRetryState;
    readonly createdAt: Timestamp;
    readonly finalizedAt: Timestamp | null;
}

// ─── SettlementOperationSignedPayload (csp 5-field invariant FULL) ──

/**
 * SettlementOperationSignedPayload — signed payload of a settlement operation
 *
 * csp 5-field invariant FULL (csp v0.1 constraint 1):
 *   token / disclosedClaims / challenge / audience / notAfter (inherits the 5 CanonicalSignedPayload fields)
 *   cspVersion metadata (CspVersionString brand; constructed via the toCspVersionString() factory)
 *   srVersion metadata (SrVersion brand; constructed via the toSrVersion() factory)
 *
 * `'1.0.0' as CspVersionString` casts are not allowed — must go through the toCspVersionString() factory.
 * `'1.0.0' as SrVersion` casts are not allowed — must go through the toSrVersion() factory.
 *
 * Association: on the producer side (L3 buildSettlementOperationSignedPayload), signFn must be non-empty at construction;
 *       otherwise throw SR_SIGNATURE_INVALID (producer-side fail-closed enforcement).
 */
export interface SettlementOperationSignedPayload extends CanonicalSignedPayload {
    /**
     * CSP protocol version metadata (csp v0.1 constraint 1 FULL)
     *
     * Must be constructed via the toCspVersionString() factory; v0.1 only value "1.0.0".
     * Inherited from CanonicalSignedPayload; explicitly declared here to improve documentation visibility.
     */
    readonly cspVersion: CspVersionString;

    /**
     * SR protocol version metadata (independent namespace)
     *
     * Must be constructed via the toSrVersion() factory; v0.1 only value "1.0.0".
     */
    readonly srVersion: SrVersion;

    /**
     * payloadSignature — settlement operation signature (Ed25519; after JCS canonicalize)
     *
     * L3 verifyResult uses a typed field;
     * never bypass via a `signedPayload.token as Signature` cast.
     */
    readonly payloadSignature: Signature;

    /**
     * principalDid — the principal DID that initiated the settlement operation
     *
     * With this added field, L3 signatureVerifier.verify can use a typed field.
     */
    readonly principalDid: DID;
}

// ─── SettlementOperation (core settlement operation interface) ────────────────────────

/**
 * SettlementOperation — core settlement operation interface
 *
 * The primary input to L3 executeSettlementRetry.
 *
 * Invariants:
 *   id unique; corresponds to settlement_operations.id (UUID v4)
 *   srVersion ∈ SR_SUPPORTED_VERSIONS (="1.0.0")
 *   settlementType ∈ SR_SUPPORTED_SETTLEMENT_TYPES
 *   amount ≥ 1
 *   currency three-letter uppercase ISO 4217
 *   principalDid starts with "did:"
 *   counterpartyDid starts with "did:"
 *   signedPayload carries the csp 5 fields + cspVersion + srVersion
 *   idempotencyKey = SHA-256(JCS({operationId, principalDid, settlementType, amount, currency, cspVersion}))
 *   attemptCount ≥ 0 and ≤ DEAD_LETTER_THRESHOLD
 */
export interface SettlementOperation {
    readonly id: OperationId;
    readonly srVersion: SrVersion;
    readonly tenantId: SrTenantId;
    readonly idempotencyKey: IdempotencyKey;
    readonly settlementType: SettlementType;
    readonly principalDid: string;
    readonly counterpartyDid: string;
    readonly amount: Amount;
    readonly currency: Currency;
    readonly signedPayload: SettlementOperationSignedPayload;
    readonly currentState: SettlementRetryState;
    readonly attemptCount: number;
    readonly revoked: boolean;
    readonly createdAt: Timestamp;
    readonly updatedAt: Timestamp;
    readonly finalizedAt: Timestamp | null;
}

// ─── ExecuteRetryResult — L3 executeSettlementRetry return type ─────────────────

/**
 * ExecuteRetryResult — return value of the executeSettlementRetry success path
 *
 * newState: the state after transition
 * attempt: this retry record (written to settlement_retries)
 * nextRetryAt: if newState=FAILED, the recommended next retry time (ms from now)
 */
export interface ExecuteRetryResult {
    readonly newState: SettlementRetryState;
    readonly attempt: RetryAttempt;
    readonly nextRetryAt: number | null;
}
