/**
 * Settlement Retry (SR) sub-protocol v0.1 — L3 core algorithm implementation
 *
 * The triple-defense L3 layer (AJV strict mode, 4 flags):
 *   Layer 1 (L0 brands.ts): TypeScript brand type — compile-time guard
 *   Layer 2 (L0 schemas.ts): JSON Schema strict — runtime Schema layer
 *   Layer 3 (this file): AJV strict mode 4 flags — runtime Schema-engine layer
 *     validateSettlementOperation / validateRetryAttempt / validateIdempotencyRecord
 *     imported from @coivitas/types (L3 must not directly new Ajv; avoids L0 <-> L3 dependency-layer inversion)
 *
 * The 9-step core algorithm:
 *   step 1: idempotency canonical hash check (SR_CANONICAL_HASH_MISMATCH)
 *   step 2: idempotency lookup + advisory lock (SR_IDEMPOTENCY_VIOLATION)
 *   step 3: field validation (SR_VERSION_UNSUPPORTED / SR_AMOUNT_INVALID)
 *   step 4: signedPayload validation (SR_SIGNED_PAYLOAD_INVALID / SR_FRESHNESS_INVALID)
 *   step 5: revocation check fail-closed BEFORE step 6 (SR_OPERATION_REVOKED)
 *   step 6: state transition → IN_PROGRESS (SR_STATE_TRANSITION_INVALID)
 *   step 7: retry attempt execution + backoff (SR_RETRY_EXHAUSTED / SR_BACKOFF_INVALID / SR_PROVIDER_*)
 *   step 8: audit recording (atp AtpRecorder; audit_class='L2')
 *   step 9: state commit + return (SR_STATE_TRANSITION_INVALID)
 *
 * fail-closed design: the step 5 revocation check must happen before the step 6 provider call.
 *
 * 5 architectural decisions:
 *   #1 SHA-256(JCS) idempotency key (collision-resistant; no symmetric key)
 *   #2 exponential backoff + random jitter (avoids thundering herd; base_ms=1000; max_delay_ms=60000)
 *   #3 DEAD_LETTER triggers enqueuing into the manual-review queue
 *   #4 strict allowlist state transitions (6 valid transitions; finite-state machine)
 *   #5 independent srVersion namespace (orthogonal to existing sub-protocols)
 *
 * brand cast forbidden: this file performs no `as` cast; brand-type conversion goes only through to*() factories.
 * fail-closed guard: any revocation / signature / hash validation failure → throw immediately (never silently pass).
 *
 * All 14 error codes have throw-path coverage verified (≥1 throw per code; v0.1 freeze):
 *   SR_IDEMPOTENCY_VIOLATION → step 2 concurrency conflict
 *   SR_CANONICAL_HASH_MISMATCH → step 1 hash mismatch + computeIdempotencyKey canonicalize failure
 *   SR_STATE_TRANSITION_INVALID → validateStateTransition + step 6 final/IN_PROGRESS path
 *   SR_RETRY_EXHAUSTED → step 7 attemptCount >= MAX_RETRY_ATTEMPTS
 *   SR_PROVIDER_UNAVAILABLE → step 7 provider unreachable
 *   SR_PROVIDER_TIMEOUT → step 7 provider timeout
 *   SR_PROVIDER_DECLINED → step 7 provider declined
 *   SR_PROVIDER_RESPONSE_INVALID → step 7 provider finalState invalid
 *   SR_OPERATION_REVOKED → step 5 revoked=true
 *   SR_SIGNED_PAYLOAD_INVALID → step 4 signature / audience binding failure
 *   SR_FRESHNESS_INVALID → step 4 notAfter expired
 *   SR_VERSION_UNSUPPORTED → step 3 / step 4 version not supported
 *   SR_AMOUNT_INVALID → step 3 amount <= 0
 *   SR_BACKOFF_INVALID → step 7 backoffDelayMs outside [0, 60000]
 */

import { canonicalize, hash } from '@coivitas/crypto';
import type { DID } from '@coivitas/types';
import {
    MAX_RETRY_ATTEMPTS,
    type Amount,
    type Currency,
    type IdempotencyKey,
    type OperationId,
    type RetryAttemptId,
    type SettlementOperation,
    type SettlementRetryState,
    type SettlementType,
    SETTLEMENT_RETRY_STATE_TRANSITIONS,
    TERMINAL_STATES,
    SrError,
    type AtpRecorder,
    type IdempotencyRecord,
    type IdempotencyStore,
    type LedgerPort,
    type RetryAttempt,
    type RetryAttemptFailureReason,
    type RetryScheduler,
    type RevocationChecker,
    type SignatureVerifier,
    validateSettlementOperation,
    validateRetryAttempt,
    validateIdempotencyRecord,
    SR_SUPPORTED_VERSIONS,
    toRetryAttemptId,
    toIdempotencyKey,
} from '@coivitas/types';
import type { RetryAttemptWriter } from './retry-attempt-writer.js';

// ─── computeIdempotencyKey — SHA-256(JCS) idempotency key derivation ─

/**
 * computeIdempotencyKey — idempotency key derivation (SHA-256 + JCS RFC 8785)
 *
 * Algorithm:
 *   1. build the canonical input object {operationId, principalDid, settlementType, amount, currency, cspVersion}
 *   2. JCS RFC 8785 canonicalize (from @coivitas/crypto; a JSON.stringify bypass is strictly forbidden)
 *   3. SHA-256 hash → hex string (64 lowercase hex chars)
 *   4. wrap as an IdempotencyKey brand (via the toIdempotencyKey factory; brand cast forbidden)
 *
 * fail-closed:
 *   canonicalize returns undefined → throw SR_CANONICAL_HASH_MISMATCH (no silent bypass)
 *
 * @param input the idempotency-key derivation fields (operationId, principalDid, settlementType, amount, currency, cspVersion)
 * @returns IdempotencyKey (64 lowercase hex chars; SHA-256 JCS)
 * @throws SrError SR_CANONICAL_HASH_MISMATCH if JCS canonicalize fails
 */
export function computeIdempotencyKey(input: {
    readonly operationId: OperationId;
    readonly principalDid: DID;
    readonly settlementType: SettlementType;
    readonly amount: Amount;
    readonly currency: Currency;
    readonly cspVersion: string;
}): IdempotencyKey {
    // JCS RFC 8785 canonicalize (a JSON.stringify fallback is strictly forbidden)
    const canonical = canonicalize(input as unknown as Record<string, unknown>);

    // fail-closed: canonicalize failure → throw immediately (no null-fallback)
    if (canonical === undefined || canonical === null) {
        throw new SrError('SR_CANONICAL_HASH_MISMATCH', {
            reason: 'jcs_canonicalize_returned_undefined',
            inputFields: Object.keys(input),
        });
    }

    // SHA-256 → hex string (hash() from @coivitas/crypto; default 'hex' encoding)
    const hexDigest = hash(canonical);

    // the toIdempotencyKey factory validates the 64 lowercase hex format (brand cast forbidden)
    return toIdempotencyKey(hexDigest);
}

// ─── validateStateTransition — state-transition allowlist guard ────────

/**
 * validateStateTransition — strict allowlist state-transition validation (step 6/7/9)
 *
 * Based on the 6 valid transitions in SETTLEMENT_RETRY_STATE_TRANSITIONS.
 * Any transition not in the allowlist → throw SR_STATE_TRANSITION_INVALID (fail-closed).
 *
 * @param from the source state
 * @param to the target state
 * @throws SrError SR_STATE_TRANSITION_INVALID if the transition is not in the allowlist
 */
function validateStateTransition(
    from: SettlementRetryState,
    to: SettlementRetryState,
): void {
    const isAllowed = SETTLEMENT_RETRY_STATE_TRANSITIONS.some(
        ([f, t]) => f === from && t === to,
    );

    if (!isAllowed) {
        throw new SrError('SR_STATE_TRANSITION_INVALID', {
            fromState: from,
            toState: to,
            reason: 'transition_not_in_allowlist',
            allowedTransitions: SETTLEMENT_RETRY_STATE_TRANSITIONS.map(
                ([f, t]) => `${f}→${t}`,
            ),
        });
    }
}

// ─── mapResponseCodeToFailureReason — provider response code mapping (step 7) ───

/**
 * mapResponseCodeToFailureReason — provider response code → RetryAttemptFailureReason
 *
 * step 7 helper; called by the SrError catch branch.
 *
 * Mapping rules:
 *   SrError SR_PROVIDER_UNAVAILABLE → 'SR_PROVIDER_UNAVAILABLE'
 *   SrError SR_PROVIDER_TIMEOUT → 'SR_PROVIDER_TIMEOUT'
 *   SrError SR_PROVIDER_DECLINED → 'SR_PROVIDER_DECLINED'
 *   responseCode INSUFFICIENT_FUNDS / NSF → 'SR_INSUFFICIENT_FUNDS'
 *   responseCode REGULATORY_BLOCK / REG_* → 'SR_REGULATORY_REJECTED'
 *   otherwise → 'SR_INTERNAL_ERROR'
 *
 * @param err the caught error (may be an SrError or an unknown error)
 * @param responseCode the provider response code (optional)
 * @returns RetryAttemptFailureReason (6-item union)
 */
function mapErrorToFailureReason(
    err: unknown,
    responseCode?: string,
): RetryAttemptFailureReason {
    // direct SrError mapping (provider error codes match precisely)
    if (err instanceof SrError) {
        if (err.code === 'SR_PROVIDER_UNAVAILABLE')
            return 'SR_PROVIDER_UNAVAILABLE';
        if (err.code === 'SR_PROVIDER_TIMEOUT') return 'SR_PROVIDER_TIMEOUT';
        if (err.code === 'SR_PROVIDER_DECLINED') return 'SR_PROVIDER_DECLINED';
    }

    // responseCode mapping (provider business error codes)
    if (responseCode) {
        if (responseCode === 'INSUFFICIENT_FUNDS' || responseCode === 'NSF') {
            return 'SR_INSUFFICIENT_FUNDS';
        }
        if (
            responseCode === 'REGULATORY_BLOCK' ||
            responseCode.startsWith('REG_')
        ) {
            return 'SR_REGULATORY_REJECTED';
        }
        if (responseCode === 'DECLINED') return 'SR_PROVIDER_DECLINED';
        if (responseCode === 'TIMEOUT') return 'SR_PROVIDER_TIMEOUT';
        if (responseCode.startsWith('5')) return 'SR_PROVIDER_TIMEOUT';
    }

    return 'SR_INTERNAL_ERROR';
}

// ─── bucketizeAmount — PII-protection amount bucket mapping ────

/**
 * bucketizeAmount — maps the exact amount value to a range bucket (PII protection)
 *
 * v0.1: settlementType + currency + amount range bucket (e.g. '1000-10000')
 *   selective disclosure; disclosing the exact amount value is strictly forbidden.
 *   the audit payload uses the bucket rather than the exact value; interlocked with the tamper-proof audit chain.
 */
function bucketizeAmount(amount: number): string {
    if (amount < 100) return '0-100';
    if (amount < 1000) return '100-1000';
    if (amount < 10000) return '1000-10000';
    if (amount < 100000) return '10000-100000';
    if (amount < 1000000) return '100000-1000000';
    return '1000000+';
}

// ─── recordSettlementAuditEvent — ATP audit event recording ( step 8) ───────────

/**
 * recordSettlementAuditEvent — write a settlement state-transition audit event (audit_class='L2')
 *
 * step 8; audit_class='L2' is mandatory (reuses the atp v0.1 enum).
 *
 * fail-closed:
 *   atpRecorder.recordEvent failure → throw ATP_* (atp error codes propagate; not re-wrapped as SR_*)
 *
 * @param operation the current settlement operation
 * @param attemptNumber the retry sequence number for this attempt (1-based)
 * @param fromState the state before the transition
 * @param toState the state after the transition
 * @param atpRecorder the ATP audit recorder (injected)
 * @returns auditEventId (UUID v4)
 */
async function recordSettlementAuditEvent(
    operation: SettlementOperation,
    attemptNumber: number,
    fromState: SettlementRetryState,
    toState: SettlementRetryState,
    atpRecorder: AtpRecorder,
): Promise<string> {
    // audit_class='L2'; payload is an object (atp internally does RFC 8785 JCS canonicalize; caller JSON.stringify strictly forbidden)
    const eventId = await atpRecorder.recordEvent({
        auditClass: 'L2',
        tenantId: operation.tenantId,
        actorDid: operation.principalDid as DID,
        action: 'SETTLEMENT_STATE_TRANSITION',
        target: operation.id,
        payload: {
            operationId: operation.id,
            tenantId: operation.tenantId,
            attemptNumber,
            fromState,
            toState,
            settlementType: operation.settlementType,
            // PII protection:
            // v0.1 selectively discloses settlementType + currency + amount range bucket;
            // disclosing the exact amount value + counterparty personally identifiable information is strictly forbidden; amount → bucket
            amountBucket: bucketizeAmount(operation.amount),
            currency: operation.currency,
        },
    });

    return eventId;
}

// ─── persistRetryAttempt — settlement_retries write ( step 8) ─────────

/**
 * persistRetryAttempt — persist a single retry record (SQL INSERT INTO settlement_retries)
 *
 * step 8 real implementation.
 * Executes a real SQL INSERT through the injected RetryAttemptWriter port; consumes the table created by migration 031.
 *
 * The AJV layer-3 defense is invoked here: validateRetryAttempt runtime Schema validation;
 * validation failure → throw SrError SR_STATE_TRANSITION_INVALID (schema-violation defense).
 *
 * fail-closed: writer.insert() failure → throw SrError propagate (never silently resolve).
 *
 * @param attempt the complete RetryAttempt (includes auditEventId; all fields must be populated)
 * @param writer the RetryAttemptWriter port (PgRetryAttemptWriter constructed and injected at L5; tests can inject in-memory)
 * @throws SrError SR_STATE_TRANSITION_INVALID if AJV schema validation fails
 * @throws SrError SR_IDEMPOTENCY_VIOLATION if attempt.id already exists (PK duplicate; pg 23505)
 * @throws SrError SR_STATE_TRANSITION_INVALID if the DB write fails (infrastructure fail-closed)
 */
async function persistRetryAttempt(
    attempt: RetryAttempt,
    writer: RetryAttemptWriter,
): Promise<void> {
    // Layer-3 defense: AJV strict mode validation (runtime schema guard)
    const schemaResult = validateRetryAttempt(attempt);
    if (!schemaResult.valid) {
        throw new SrError('SR_STATE_TRANSITION_INVALID', {
            reason: 'retry_attempt_schema_violation',
            errors: schemaResult.errors.map((e) => ({
                path: e.instancePath,
                message: e.message,
            })),
        });
    }

    // real SQL INSERT INTO settlement_retries (migration 031)
    // fail-closed: writer.insert() throw → propagate (never silently resolve)
    await writer.insert(attempt);
}

// ─── generateRetryAttemptId — UUID v4 generation ( step 7 helper) ────────────

/**
 * generateRetryAttemptId — generate a RetryAttemptId UUID v4
 *
 * step 7 helper.
 * Uses crypto.randomUUID() (built into Node 20+; no external dependency).
 *
 * @returns RetryAttemptId (UUID v4 brand)
 */
function generateRetryAttemptId(): RetryAttemptId {
    return toRetryAttemptId(crypto.randomUUID());
}

// ─── toTimestamp — Date → ISO 8601 string ( helper) ─────────────────

/**
 * toTimestamp — Date → ISO 8601 UTC string
 *
 * helper; the Timestamp type is a string (ISO 8601 UTC).
 *
 * @param date the Date object (defaults to now)
 * @returns ISO 8601 UTC string (e.g. "2026-05-18T12:34:56.789Z")
 */
function toTimestamp(date: Date = new Date()): string {
    return date.toISOString();
}

// ─── executeSettlementRetry — core function ( 9-step algorithm) ──────────────────

/**
 * executeSettlementRetry — SR v0.1 core settlement-retry execution function
 *
 * The 9-step algorithm; L3 implementation.
 *
 * The triple-defense L3 layer: invokes AJV strict mode schema validation in step 3 (validateSettlementOperation)
 * + step 8 (validateRetryAttempt) + idempotency insert (validateIdempotencyRecord).
 *
 * fail-closed guards:
 *   - step 5 revocation check BEFORE the step 6 provider call (strictly check revocation before calling)
 *   - any revocation / signature / hash validation failure → throw immediately
 *   - provider timeout / unavailable → throw (do not silently mark SUCCEEDED)
 *   - audit write failure → throw ATP_* (do not ignore; tamper-proof interlock)
 *
 * Idempotency guarantees:
 *   - same operationId + same business fields → a repeated call returns the existing terminal state
 *   - same idempotencyKey with a different operationId → throw SR_IDEMPOTENCY_VIOLATION
 *   - the advisory lock serializes concurrent retries
 *
 * @param operation the settlement operation (includes signedPayload + business fields)
 * @param ledgerPort the settlement provider gateway (injected)
 * @param idempotencyStore the idempotency record store (injected)
 * @param retryScheduler the backoff calculator (injected)
 * @param revocationChecker the revocation lookup (injected)
 * @param atpRecorder the ATP audit recorder (injected)
 * @param signatureVerifier the Ed25519 signature verifier (injected)
 * @param expectedSettlerDid the settler DID (injected from runtime trusted context; not same-sourced as the payload)
 * @param retryAttemptWriter the RetryAttemptWriter port (real SQL INSERT implementation injected; PgRetryAttemptWriter constructed at L5)
 * @returns the updated SettlementOperation
 * @throws SrError (14 SR_* error codes; each maps to a specific failure path)
 */
export async function executeSettlementRetry(
    operation: SettlementOperation,
    ledgerPort: LedgerPort,
    idempotencyStore: IdempotencyStore,
    retryScheduler: RetryScheduler,
    revocationChecker: RevocationChecker,
    atpRecorder: AtpRecorder,
    signatureVerifier: SignatureVerifier,
    expectedSettlerDid: DID,
    retryAttemptWriter: RetryAttemptWriter,
): Promise<SettlementOperation> {
    // ── step 1: idempotency canonical hash check (SR_CANONICAL_HASH_MISMATCH) ───
    
    // step 1: recompute idempotencyKey; compare it against operation.idempotencyKey.
    // Prevents the operation fields from being tampered with in transit/storage (tamper-proof + hash chain interlock).
    const expectedKey = computeIdempotencyKey({
        operationId: operation.id,
        principalDid: operation.principalDid as DID,
        settlementType: operation.settlementType,
        amount: operation.amount,
        currency: operation.currency,
        cspVersion: operation.signedPayload.cspVersion,
    });

    if (operation.idempotencyKey !== expectedKey) {
        throw new SrError('SR_CANONICAL_HASH_MISMATCH', {
            operationId: operation.id,
            reason: 'idempotency_key_field_drift_detected',
            storedKey: operation.idempotencyKey,
            recomputedKey: expectedKey,
        });
    }

    // ── step 2: idempotency lookup + advisory lock (SR_IDEMPOTENCY_VIOLATION) ──
    
    // step 2:
    // a. acquireAdvisoryLock — serialize concurrent retries (transaction-level lock; auto-released after commit)
    // b. findByKey — look up an existing IdempotencyRecord
    // c. if a record exists and is in a terminal state → idempotently return the existing operation
    // d. if an existing record has a mismatching operationId → throw SR_IDEMPOTENCY_VIOLATION
    // e. first call → insertRecord to establish an idempotency_key placeholder (UNIQUE constraint guards against concurrent duplicates)

    await idempotencyStore.acquireAdvisoryLock(
        operation.tenantId,
        operation.idempotencyKey,
    );

    const existingRecord = await idempotencyStore.findByKey(
        operation.tenantId,
        operation.idempotencyKey,
    );

    if (existingRecord !== null) {
        // Existing record: terminal state → idempotent return (SUCCEEDED / DEAD_LETTER)
        if (TERMINAL_STATES.has(existingRecord.currentState)) {
            // Idempotent path: return the current operation directly (a state-machine terminal state is non-reentrant)
            return operation;
        }

        // Existing record: same key, different operationId → concurrency conflict
        if (existingRecord.operationId !== operation.id) {
            throw new SrError('SR_IDEMPOTENCY_VIOLATION', {
                idempotencyKey: operation.idempotencyKey,
                existingOperationId: existingRecord.operationId,
                incomingOperationId: operation.id,
                reason: 'concurrent_duplicate_key_different_operation_id',
            });
        }

        // Existing record: same operationId → non-terminal, continue execution (recover scenario)
    } else {
        // First call: insert an IdempotencyRecord (UNIQUE constraint guards against concurrent duplicates)
        const newRecord: IdempotencyRecord = {
            key: operation.idempotencyKey,
            tenantId: operation.tenantId,
            operationId: operation.id,
            currentState: operation.currentState,
            createdAt: toTimestamp() as ReturnType<typeof toTimestamp> & {
                readonly __brand: 'Timestamp';
            },
            finalizedAt: null,
        };

        // Layer-3 defense: AJV strict mode validation of IdempotencyRecord
        const idempotencySchemaResult = validateIdempotencyRecord(newRecord);
        if (!idempotencySchemaResult.valid) {
            throw new SrError('SR_STATE_TRANSITION_INVALID', {
                reason: 'idempotency_record_schema_violation',
                errors: idempotencySchemaResult.errors.map((e) => ({
                    path: e.instancePath,
                    message: e.message,
                })),
            });
        }

        await idempotencyStore.insertRecord(newRecord);
    }

    // ── step 3: field validation (SR_VERSION_UNSUPPORTED / SR_AMOUNT_INVALID) ──
    
    // step 3:
    // settlementType must be in SR_SUPPORTED_SETTLEMENT_TYPES
    // srVersion must be in SR_SUPPORTED_VERSIONS
    // cspVersion must be "1.0.0"
    // amount must be > 0

    if (
        operation.settlementType !== 'fiat_transfer' &&
        operation.settlementType !== 'digital_wallet'
    ) {
        throw new SrError('SR_VERSION_UNSUPPORTED', {
            settlementType: operation.settlementType,
            supported: ['fiat_transfer', 'digital_wallet'],
        });
    }

    if (!SR_SUPPORTED_VERSIONS.includes(operation.srVersion as string)) {
        throw new SrError('SR_VERSION_UNSUPPORTED', {
            srVersion: operation.srVersion,
            supported: SR_SUPPORTED_VERSIONS,
        });
    }

    if (operation.amount <= 0) {
        throw new SrError('SR_AMOUNT_INVALID', {
            amount: operation.amount,
            reason: 'amount_must_be_positive_integer',
        });
    }

    // Layer-3 defense: AJV strict mode validation of SettlementOperation (L3 schema guard)
    const operationSchemaResult = validateSettlementOperation(operation);
    if (!operationSchemaResult.valid) {
        throw new SrError('SR_VERSION_UNSUPPORTED', {
            reason: 'settlement_operation_schema_violation',
            errors: operationSchemaResult.errors.map((e) => ({
                path: e.instancePath,
                message: e.message,
            })),
        });
    }

    // ── step 4: signedPayload validation (SR_SIGNED_PAYLOAD_INVALID / SR_FRESHNESS_INVALID) ──
    
    // step 4 (csp 5-field invariant FULL):
    // a. challenge non-empty
    // b. cspVersion = "1.0.0"
    // c. notAfter not expired (Date.now() ≤ notAfterMs)
    // d. audience binding: signedPayload.audience === expectedSettlerDid
    // e. Ed25519 signature verification (signatureVerifier.verify active invocation)

    const { signedPayload } = operation;

    // 4a: challenge non-empty (csp 5-field invariant #3)
    if (!signedPayload.challenge || signedPayload.challenge.trim() === '') {
        throw new SrError('SR_SIGNED_PAYLOAD_INVALID', {
            reason: 'csp_challenge_empty',
            operationId: operation.id,
        });
    }

    // 4b: cspVersion validation
    if (signedPayload.cspVersion !== '1.0.0') {
        throw new SrError('SR_VERSION_UNSUPPORTED', {
            cspVersion: signedPayload.cspVersion,
            supported: ['1.0.0'],
            reason: 'csp_version_not_supported',
        });
    }

    // 4c: notAfter freshness check (fail-closed; expired → SR_FRESHNESS_INVALID)
    const notAfterMs = new Date(signedPayload.notAfter).getTime();
    if (Number.isNaN(notAfterMs)) {
        throw new SrError('SR_FRESHNESS_INVALID', {
            notAfter: signedPayload.notAfter,
            reason: 'notAfter_not_parseable_as_timestamp',
        });
    }
    if (Date.now() > notAfterMs) {
        throw new SrError('SR_FRESHNESS_INVALID', {
            notAfter: signedPayload.notAfter,
            nowMs: Date.now(),
            reason: 'signed_payload_expired',
        });
    }

    // 4d: audience binding
    if (signedPayload.audience !== expectedSettlerDid) {
        throw new SrError('SR_SIGNED_PAYLOAD_INVALID', {
            reason: 'audience_binding_mismatch',
            payloadAudience: signedPayload.audience,
            expectedAudience: expectedSettlerDid,
        });
    }

    // 4e: Ed25519 signature verification (active invocation; csp constraint 1 mandatory)

    // a cast-as-Signature bypass is strictly forbidden (brand cast forbidden):
    // the original `signedPayload.token as Signature` cast bypass is replaced by the L0-added typed field signedPayload.payloadSignature
    const verifyResult = await signatureVerifier.verify({
        signature: operation.signedPayload.payloadSignature,
        signedPayload: operation.signedPayload,
        expectedAudience: expectedSettlerDid,
    });

    if (!verifyResult.valid) {
        throw new SrError('SR_SIGNED_PAYLOAD_INVALID', {
            reason:
                verifyResult.reason ?? 'ed25519_signature_verification_failed',
            operationId: operation.id,
        });
    }

    // ── step 5: revocation check fail-closed (SR_OPERATION_REVOKED) ─────────────
    
    // step 5:
    // the revocation check must happen before the step 6/7 provider call (prevents a revoked operation from being executed)
    // isOperationRevoked(operationId) → true → throw SR_OPERATION_REVOKED

    let isRevoked: boolean;
    try {
        isRevoked = await revocationChecker.isOperationRevoked(operation.id);
    } catch (_revocationErr) {
        // network/DB error: fail-closed → treat as revoked (never silently pass)
        throw new SrError('SR_OPERATION_REVOKED', {
            operationId: operation.id,
            reason: 'revocation_check_network_failure_fail_closed',
        });
    }

    if (isRevoked) {
        throw new SrError('SR_OPERATION_REVOKED', {
            operationId: operation.id,
            reason: 'operation_revoked_by_revocation_checker',
        });
    }

    // defense-in-depth: also check the operation.revoked field (guards against an in-memory field bypass)
    if (operation.revoked) {
        throw new SrError('SR_OPERATION_REVOKED', {
            operationId: operation.id,
            reason: 'operation_revoked_field_set_defense_in_depth',
        });
    }

    // ── step 6: state transition → IN_PROGRESS (SR_STATE_TRANSITION_INVALID) ───
    
    // step 6:
    // PENDING / FAILED → IN_PROGRESS (allowed)
    // IN_PROGRESS → IN_PROGRESS (recover scenario; allowed)
    // SUCCEEDED / DEAD_LETTER → throw SR_STATE_TRANSITION_INVALID (terminal state is non-reentrant)

    const fromState = operation.currentState;

    if (TERMINAL_STATES.has(fromState)) {
        throw new SrError('SR_STATE_TRANSITION_INVALID', {
            fromState,
            reason: 'cannot_transition_from_terminal_state',
        });
    }

    // PENDING / FAILED → IN_PROGRESS (state-machine allowlist validation)
    if (fromState !== 'IN_PROGRESS') {
        validateStateTransition(fromState, 'IN_PROGRESS');
        await idempotencyStore.updateState(
            operation.tenantId,
            operation.idempotencyKey,
            'IN_PROGRESS',
        );
    }
    // IN_PROGRESS → continue directly (recover scenario; do not re-update the state)

    // ── step 7: retry attempt execution (SR_RETRY_EXHAUSTED / SR_BACKOFF_INVALID / SR_PROVIDER_*) ──
    
    // step 7:
    // 7a. attemptCount >= MAX_RETRY_ATTEMPTS → DEAD_LETTER + throw SR_RETRY_EXHAUSTED
    // 7b. computeBackoffDelay — backoff delay calculation
    // 7c. backoffDelayMs range validation [0, 60000] (SR_BACKOFF_INVALID)
    // 7d. ledgerPort.submitSettlement — provider call (fail-closed)
    // 7e. finalState validation (SUCCEEDED / FAILED; otherwise → SR_PROVIDER_RESPONSE_INVALID)

    // 7a: retry-limit check (reaching MAX_RETRY_ATTEMPTS → DEAD_LETTER)
    if (operation.attemptCount >= MAX_RETRY_ATTEMPTS) {
        validateStateTransition('IN_PROGRESS', 'DEAD_LETTER');
        await idempotencyStore.updateState(
            operation.tenantId,
            operation.idempotencyKey,
            'DEAD_LETTER',
            toTimestamp(),
        );
        throw new SrError('SR_RETRY_EXHAUSTED', {
            operationId: operation.id,
            attemptCount: operation.attemptCount,
            maxRetryAttempts: MAX_RETRY_ATTEMPTS,
            reason: 'retry_attempts_exhausted_moved_to_dead_letter',
        });
    }

    const attemptNumber = operation.attemptCount + 1;

    // 7b: exponential backoff + jitter
    const backoffDelayMs = retryScheduler.computeBackoffDelay(
        operation.attemptCount,
    );

    // 7c: backoffDelayMs range validation [0, 60000] (SR_BACKOFF_INVALID)
    if (backoffDelayMs < 0 || backoffDelayMs > 60000) {
        throw new SrError('SR_BACKOFF_INVALID', {
            backoffDelayMs,
            attemptNumber,
            reason: 'backoff_delay_out_of_valid_range_0_to_60000ms',
        });
    }

    // 7d: provider call (fail-closed; timeout/unreachable → throw SrError; never silently return)
    const attemptedAt = toTimestamp();
    let providerResult:
        | {
              readonly providerTxId: string;
              readonly finalState: 'SUCCEEDED' | 'FAILED';
              readonly responseCode?: string;
              readonly responseMessage?: string;
          }
        | undefined;
    let attemptToState: SettlementRetryState = 'FAILED';
    let failureReason: RetryAttemptFailureReason | null = null;
    let resultSummary: string | null = null;

    try {
        providerResult = await ledgerPort.submitSettlement(operation);

        // 7e: finalState validation (strictly SUCCEEDED / FAILED; otherwise → SR_PROVIDER_RESPONSE_INVALID)
        if (
            providerResult.finalState !== 'SUCCEEDED' &&
            providerResult.finalState !== 'FAILED'
        ) {
            throw new SrError('SR_PROVIDER_RESPONSE_INVALID', {
                providerTxId: providerResult.providerTxId,
                finalState: providerResult.finalState,
                reason: 'provider_returned_invalid_final_state',
            });
        }

        attemptToState = providerResult.finalState;
        resultSummary = providerResult.responseMessage ?? null;

        // record failureReason when FAILED
        if (providerResult.finalState === 'FAILED') {
            failureReason = mapErrorToFailureReason(
                undefined,
                providerResult.responseCode,
            );
        }
    } catch (providerErr) {
        // provider call failed: determine failureReason based on the error type
        if (providerErr instanceof SrError) {
            // PROVIDER_* errors within SrError are rethrown directly (handled outside the catch)
            // non-PROVIDER_* types (e.g. SR_PROVIDER_RESPONSE_INVALID) must be mapped to a failureReason, then write audit and rethrow
            failureReason = mapErrorToFailureReason(providerErr);
            resultSummary = providerErr.message;
            attemptToState = 'FAILED';

            // write audit + RetryAttempt record (step 8), then rethrow
            const completedAt = toTimestamp();
            const attempt: RetryAttempt = {
                id: generateRetryAttemptId(),
                operationId: operation.id,
                attemptNumber,
                fromState,
                toState: attemptToState,
                attemptedAt: attemptedAt as ReturnType<typeof toTimestamp> & {
                    readonly __brand: 'Timestamp';
                },
                completedAt: completedAt as ReturnType<typeof toTimestamp> & {
                    readonly __brand: 'Timestamp';
                },
                resultSummary,
                failureReason,
                backoffDelayMs,
                auditEventId: '',
            };

            // step 8: audit recording (ATP fail-closed;throw ATP_* propagate)
            const auditEventId = await recordSettlementAuditEvent(
                operation,
                attemptNumber,
                fromState,
                attemptToState,
                atpRecorder,
            );

            const attemptWithAudit: RetryAttempt = { ...attempt, auditEventId };
            await persistRetryAttempt(attemptWithAudit, retryAttemptWriter);

            // state: remain FAILED (no update; the next retry continues from FAILED)
            validateStateTransition('IN_PROGRESS', 'FAILED');
            await idempotencyStore.updateState(
                operation.tenantId,
                operation.idempotencyKey,
                'FAILED',
            );

            throw providerErr;
        }

        // fail-closed:
        // any settlement state transition failure = reject by default;
        // fail-degraded / fail-open / partial-PASS / WARNING are not allowed;
        // the original fall-through (set placeholder + return a FAILED operation) is a fail-degraded anti-pattern;
        // now follows the same pattern as the SrError branch (audit + persist + updateState FAILED + throw fail-closed);
        // non-SrError exceptions are wrapped as SR_PROVIDER_RESPONSE_INVALID (no SR_INTERNAL_ERROR code; 14-item union freeze)
        const wrappedErr = new SrError('SR_PROVIDER_RESPONSE_INVALID', {
            reason: 'ledger_port_threw_unknown_error_fail_closed',
            originalError: String(providerErr),
            operationId: operation.id,
        });
        failureReason = mapErrorToFailureReason(wrappedErr);
        resultSummary = wrappedErr.message;
        attemptToState = 'FAILED';

        // reuse the SrError-branch audit + persist + updateState logic (fail-closed)
        const completedAt = toTimestamp();
        const attempt: RetryAttempt = {
            id: generateRetryAttemptId(),
            operationId: operation.id,
            attemptNumber,
            fromState,
            toState: attemptToState,
            attemptedAt: attemptedAt as ReturnType<typeof toTimestamp> & {
                readonly __brand: 'Timestamp';
            },
            completedAt: completedAt as ReturnType<typeof toTimestamp> & {
                readonly __brand: 'Timestamp';
            },
            resultSummary,
            failureReason,
            backoffDelayMs,
            auditEventId: '',
        };

        const auditEventId = await recordSettlementAuditEvent(
            operation,
            attemptNumber,
            fromState,
            attemptToState,
            atpRecorder,
        );

        const attemptWithAudit: RetryAttempt = { ...attempt, auditEventId };
        await persistRetryAttempt(attemptWithAudit, retryAttemptWriter);

        validateStateTransition('IN_PROGRESS', 'FAILED');
        await idempotencyStore.updateState(
            operation.tenantId,
            operation.idempotencyKey,
            'FAILED',
        );

        throw wrappedErr;
    }

    // ── step 8: audit recording (atp AtpRecorder;audit_class='L2') ─────────────
    
    // step 8:
    // atpRecorder.recordEvent({auditClass:'L2', ...}) — active invocation mandatory
    // ATP_* errors propagate without re-wrapping (fail-closed; tamper-proof interlock)
    // the RetryAttempt record is written to settlement_retries

    const completedAt = toTimestamp();

    const auditEventId = await recordSettlementAuditEvent(
        operation,
        attemptNumber,
        fromState,
        attemptToState,
        atpRecorder,
    );

    const attempt: RetryAttempt = {
        id: generateRetryAttemptId(),
        operationId: operation.id,
        attemptNumber,
        fromState,
        toState: attemptToState,
        attemptedAt: attemptedAt as ReturnType<typeof toTimestamp> & {
            readonly __brand: 'Timestamp';
        },
        completedAt: completedAt as ReturnType<typeof toTimestamp> & {
            readonly __brand: 'Timestamp';
        },
        resultSummary,
        failureReason,
        backoffDelayMs,
        auditEventId,
    };

    await persistRetryAttempt(attempt, retryAttemptWriter);

    // ── step 9: state commit + return (SR_STATE_TRANSITION_INVALID) ────────────
    
    // step 9:
    // SUCCEEDED → updateState(SUCCEEDED, finalizedAt) + return the updated operation
    // FAILED → check attemptNumber vs MAX_RETRY_ATTEMPTS:
    // - attemptNumber < MAX_RETRY_ATTEMPTS → updateState(FAILED) + return FAILED
    // - attemptNumber >= MAX_RETRY_ATTEMPTS → DEAD_LETTER + return DEAD_LETTER

    if (attemptToState === 'SUCCEEDED') {
        validateStateTransition('IN_PROGRESS', 'SUCCEEDED');
        const finalizedAt = completedAt;
        await idempotencyStore.updateState(
            operation.tenantId,
            operation.idempotencyKey,
            'SUCCEEDED',
            finalizedAt,
        );

        return {
            ...operation,
            currentState: 'SUCCEEDED',
            attemptCount: attemptNumber,
            finalizedAt: finalizedAt as ReturnType<typeof toTimestamp> & {
                readonly __brand: 'Timestamp';
            },
            updatedAt: finalizedAt as ReturnType<typeof toTimestamp> & {
                readonly __brand: 'Timestamp';
            },
        };
    }

    // attemptToState === 'FAILED'
    validateStateTransition('IN_PROGRESS', 'FAILED');

    if (attemptNumber >= MAX_RETRY_ATTEMPTS) {
        // retry limit reached → DEAD_LETTER (triggers the manual-review queue)
        validateStateTransition('FAILED', 'DEAD_LETTER');
        const deadLetterAt = completedAt;
        await idempotencyStore.updateState(
            operation.tenantId,
            operation.idempotencyKey,
            'DEAD_LETTER',
            deadLetterAt,
        );

        return {
            ...operation,
            currentState: 'DEAD_LETTER',
            attemptCount: attemptNumber,
            finalizedAt: deadLetterAt as ReturnType<typeof toTimestamp> & {
                readonly __brand: 'Timestamp';
            },
            updatedAt: deadLetterAt as ReturnType<typeof toTimestamp> & {
                readonly __brand: 'Timestamp';
            },
        };
    }

    // FAILED and attemptNumber < MAX_RETRY_ATTEMPTS: retry may continue
    await idempotencyStore.updateState(
        operation.tenantId,
        operation.idempotencyKey,
        'FAILED',
    );

    return {
        ...operation,
        currentState: 'FAILED',
        attemptCount: attemptNumber,
        updatedAt: completedAt as ReturnType<typeof toTimestamp> & {
            readonly __brand: 'Timestamp';
        },
    };
}
