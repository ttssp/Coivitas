/**
 * Settlement Retry (SR) sub-protocol v0.1 — Port interface definitions
 *
 *
 * Port interface design principles (hexagonal architecture):
 *   - LedgerPort: settlement provider gateway (single method submitSettlement)
 *   - IdempotencyStore: idempotency record + advisory lock (guards against concurrent races)
 *   - RetryScheduler: backoff delay computation (single method computeBackoffDelay)
 *   - RevocationChecker: fail-closed revocation lookup (step 5; operationId granularity)
 *   - SignatureVerifier: Ed25519 signature verification + audience binding
 *   - AtpRecorder: ATP audit event recording (step 8; audit_class='L2' linkage)
 *
 * Anti-phantom defense: every port interface method must be actively invoked in L3 executeSettlementRetry.
 * Violation → compile-time phantom detection (covered by grep verify).
 *
 * Note: the SrDeps aggregate interface has been removed; individual parameter injection is used instead.
 */

import type { DID, Signature } from '../base.js';
import type { IdempotencyKey, OperationId, SrTenantId } from './brands.js';
import type {
    IdempotencyRecord,
    SettlementOperation,
    SettlementOperationSignedPayload,
    SettlementRetryState,
} from './types.js';

// ─── LedgerPort — settlement provider gateway interface ────────────────────────────────

/**
 * LedgerPort — minimal contract for the settlement provider gateway interface
 *
 * Behavioral constraints (fail-closed):
 *   - provider upstream unreachable → throw SR_PROVIDER_UNAVAILABLE (no silent downgrade to SUCCEEDED)
 *   - provider timeout → throw SR_PROVIDER_TIMEOUT
 *   - provider decline → throw SR_PROVIDER_DECLINED (PSP risk-control decline)
 *   - provider returns an invalid finalState → throw SR_PROVIDER_RESPONSE_INVALID
 *   - never return null as a fallback that silently marks SUCCEEDED (violates the fail-closed principle)
 *
 * Minimal contract: single method submitSettlement.
 * CRUD methods (getOperation/saveOperation/updateOperationState/saveRetryAttempt) belong to L3 internal implementation;
 * never expose them through this interface (it would couple L0 to the DB schema).
 */
export interface LedgerPort {
    /**
     * submitSettlement — submit the settlement to the provider gateway (e.g. Stripe / Adyen / Web3 wallet)
     *
     * @param operation settlement operation (includes signedPayload + business fields)
     * @returns provider response (includes provider tx ID + terminal state); success = SUCCEEDED; failure = throw 1 of SR_PROVIDER_*
     * @throws SrError SR_PROVIDER_UNAVAILABLE if the provider is unreachable
     * @throws SrError SR_PROVIDER_TIMEOUT if the provider times out
     * @throws SrError SR_PROVIDER_DECLINED if the provider declines via risk control
     * @throws SrError SR_PROVIDER_RESPONSE_INVALID if the provider returns an invalid finalState
     */
    submitSettlement(operation: SettlementOperation): Promise<{
        readonly providerTxId: string;
        readonly finalState: 'SUCCEEDED' | 'FAILED';
        readonly responseCode?: string;
        readonly responseMessage?: string;
    }>;
}

// ─── IdempotencyStore — idempotency record + advisory lock ────────────────────────────

/**
 * IdempotencyStore — idempotency_key persistence + UNIQUE constraint lookup
 *
 * The idempotency key is SHA-256(JCS).
 *
 * advisory lock semantics (concurrent-retry race protection):
 *   acquireAdvisoryLock — PostgreSQL pg_advisory_xact_lock(hashtext(tenantId), hashtext(key))
 *   transaction-level lock: released automatically after commit/rollback (no explicit releaseAdvisoryLock needed)
 *
 * Behavioral constraints (fail-closed):
 *   - DB unreachable → throw (caller maps to SR_PROVIDER_UNAVAILABLE)
 *   - UNIQUE constraint conflict (PostgreSQL 23505) → throws naturally + caller catches and maps to SR_IDEMPOTENCY_VIOLATION
 *   - never return false to silently bypass the idempotency check
 */
export interface IdempotencyStore {
    /**
     * acquireAdvisoryLock — acquire a per-(tenantId, idempotencyKey) advisory lock
     *
     * The implementation layer uses a PostgreSQL pg_advisory_xact_lock transaction-level lock (released automatically after commit).
     * Serializes concurrent retries from multiple workers on the same (tenantId, key) (anti-double-spend race).
     *
     * @throws if the DB is unreachable (caller maps to SR_PROVIDER_UNAVAILABLE)
     */
    acquireAdvisoryLock(
        tenantId: SrTenantId,
        key: IdempotencyKey,
    ): Promise<void>;

    /**
     * findByKey — look up an IdempotencyRecord by idempotency_key
     *
     * @returns IdempotencyRecord | null
     *   null = first call; non-null = already exists → return finalState directly and skip retry
     */
    findByKey(
        tenantId: SrTenantId,
        key: IdempotencyKey,
    ): Promise<IdempotencyRecord | null>;

    /**
     * insertRecord — insert a new IdempotencyRecord (guarded by the UNIQUE constraint)
     *
     * Concurrent scenario: catch 23505 → findByKey again.
     *
     * @throws SR_IDEMPOTENCY_VIOLATION (PostgreSQL 23505 unique_violation)
     */
    insertRecord(record: IdempotencyRecord): Promise<void>;

    /**
     * updateState — update IdempotencyRecord.currentState
     *
     * The state-machine transition allowlist check is already done in the caller layer (executeSettlementRetry step 7);
     * the store layer no longer re-validates transition legality (defense-in-depth is owned by the caller).
     *
     * @param finalizedAt terminal-state timestamp (set on SUCCEEDED/DEAD_LETTER; undefined for intermediate states)
     */
    updateState(
        tenantId: SrTenantId,
        key: IdempotencyKey,
        newState: SettlementRetryState,
        finalizedAt?: string,
    ): Promise<void>;
}

// ─── RetryScheduler — exponential backoff computation ────────────────────────────

/**
 * RetryScheduler — exponential backoff retry scheduling
 *
 * Minimal contract: single method computeBackoffDelay.
 * The scheduleRetry method has been removed (0 invocations = dead port method).
 * When the retry-queue abstraction is added in a future release, a separate RetrySchedulerV2 will extend scheduleRetry (deferred).
 *
 * Behavioral constraints (fail-closed):
 *   - never return a 0 ms delay that silently bypasses backoff (except the first attempt, attemptNumber=0)
 *   - the result must be within the [0, 60000] range; out of range → SR_BACKOFF_INVALID (validated by the L3 caller)
 */
export interface RetryScheduler {
    /**
     * computeBackoffDelay — exponential backoff + jitter
     *
     * Formula:
     *   delay_ms = min(base_ms * 2^attempt + jitter, max_delay_ms)
     *   base_ms = 1000, jitter = randomInt(0, 500), max_delay_ms = 60000
     *
     * @param attemptNumber number of retries already completed (0 = first attempt; 1 = after the first retry...)
     * @returns backoff delay in milliseconds (≥ 0, ≤ 60000)
     */
    computeBackoffDelay(attemptNumber: number): number;
}

// ─── RevocationChecker — settlement_operation revocation lookup ──────────────────────

/**
 * RevocationChecker — real-time revocation check for settlement_operation
 *
 * Behavioral constraints (fail-closed):
 *   network failure → throw OR return true (treat as revoked); never return false on a network error.
 *
 * step 5 execution position: BEFORE step 6 (provider call)
 * Consistent with dc v0.3 step 6 / CCR v0.1 step 6 / CR v0.1 step 6 (cross-spec align).
 */
export interface RevocationChecker {
    /**
     * isOperationRevoked — check whether the operation has been revoked
     *
     * @param operationId settlement operation ID
     * @returns true if revoked (caller should throw SR_OPERATION_REVOKED); false if not revoked
     * @throws rethrows on network / DB errors (caller catches and fail-closed maps to SR_OPERATION_REVOKED)
     */
    isOperationRevoked(operationId: OperationId): Promise<boolean>;
}

// ─── SignatureVerifyResult — verification result ─────────────────────────────────────────

/**
 * SignatureVerifyResult — SignatureVerifier.verify return type
 *
 * valid=false + reason field: the caller throws SR_SIGNED_PAYLOAD_INVALID (tracked via the reason field).
 */
export interface SignatureVerifyResult {
    readonly valid: boolean;
    readonly reason?: string;
}

// ─── SignatureVerifier — Ed25519 signature verification + audience binding ─────────────────

/**
 * SignatureVerifier — Ed25519 payloadSignature verification port
 *
 * The protocol-layer contract guarantees the csp 5-field auth primitive is mandatorily actively invoked.
 *
 * Design intent:
 *   active invocation at step 4; the authenticate primitive must be enforced at the protocol layer.
 *   The implementation layer injects a concrete implementation (obtains the public key via the @coivitas/crypto ed25519 primitive + DID resolver).
 *
 * Behavioral constraints (fail-closed):
 *   - signature mismatch / parse failure → return { valid: false, reason }
 *   - DID resolve failure / public-key retrieval failure → throw (do not silently return false)
 *   - the audience field is a mandatory binding verify:
 *     expectedAudience must be passed in by the caller from a runtime trusted context
 * (never from the same-origin untrusted payload; protects against tautological audience binding)
 *   - the verifier internally cross-checks signedPayload.audience === expectedAudience again (guards against bypass risk)
 */
export interface SignatureVerifier {
    /**
     * verify — Ed25519 signature verify + audience binding
     *
     * @param input.signature payloadSignature (Ed25519 sig over canonicalized signedPayload)
     * @param input.signedPayload SettlementOperationSignedPayload (csp 5 fields + business fields;
     *   the verifier JCS-canonicalizes internally before verifying; never let the caller pre-canonicalize as a bypass)
     * @param input.expectedAudience settler DID (injected from a runtime trusted context; not same-origin with the payload;
     * audience binding guards against audience hijack)
     * @returns SignatureVerifyResult; valid=false → SR step 4 throws SR_SIGNED_PAYLOAD_INVALID
     */
    verify(input: {
        readonly signature: Signature;
        readonly signedPayload: SettlementOperationSignedPayload;
        readonly expectedAudience: DID;
    }): Promise<SignatureVerifyResult>;
}

// ─── AtpRecorder — ATP audit event recording ──────────────────────────────────────────

/**
 * AtpRecorder — Audit Tamper-Proof event recording interface
 *
 * The protocol-layer contract guarantees the audit recorder is mandatorily actively invoked.
 *
 * Design intent: active invocation at step 8, atpRecorder.recordEvent(...)
 * The implementation layer injects a concrete AtpRecorder (atp v0.1 recorder primitive; hcc v0.1 hash chain linkage).
 *
 * Behavioral constraints (fail-closed):
 *   - atp recorder write failure → throw ATP_* (atp v0.1 error codes); the SR caller propagates without rewrapping as SR_*
 *   - audit_class is mandatorily 'L2' (reuses the atp 026 enum; never unilaterally extend with 'settlement_event')
 *   - the payload field is an object (not a string); the atp recorder JCS-canonicalizes internally
 *     (never let the caller JSON.stringify as a bypass; csp v0.1 constraint 3 mandates RFC 8785 JCS)
 *   - the atpRecorder internally fills: atpVersion + eventId + previousHash + timestamp + tamperProofHash + signature
 */
export interface AtpRecorder {
    /**
     * recordEvent — record an SR audit event (audit_class='L2'; tamper-proof linkage)
     *
     * @param input.auditClass existing atp 026 enum (CHECK ['L1','L2','L3']); SR uses 'L2'
     * @param input.tenantId tenant ID
     * @param input.actorDid actor DID
     * @param input.action event type (e.g. 'SETTLEMENT_STATE_TRANSITION')
     * @param input.target operation target (e.g. operation.id)
     * @param input.payload audit event payload (object; atp internally RFC 8785 JCS canonicalizes)
     * @returns eventId (UUID v4; written to settlement_retries.audit_event_id)
     */
    recordEvent(input: {
        readonly auditClass: 'L1' | 'L2' | 'L3';
        readonly tenantId: SrTenantId;
        readonly actorDid: DID;
        readonly action: string;
        readonly target: string;
        readonly payload: Readonly<Record<string, unknown>>;
    }): Promise<string>;
}
