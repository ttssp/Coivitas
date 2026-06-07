/**
 * RetryAttemptWriter — the settlement_retries row write port (defined internally at L3)
 *
 * The persistRetryAttempt real-implementation SQL INSERT injection path; defined internally at L3 (not in L0 types scope).
 *
 * Design:
 *   - single method insert(attempt): inserts a settlement_retries row
 *   - idempotency semantics: the same attempt.id -> throw SR_DUPLICATE_ATTEMPT (UNIQUE PK conflict)
 *   - DB unreachable -> throw SrError SR_PERSIST_FAILED (fail-closed)
 *
 * The implementation layer (PgRetryAttemptWriter) lives in the same directory; tests can inject InMemoryRetryAttemptWriter.
 * L5 sdk v0.2 DI path: construct PgRetryAttemptWriter at L5 and inject it into executeSettlementRetry.
 */

import type { RetryAttempt } from '@coivitas/types';

// ─── RetryAttemptWriter — L3 internal port interface ──────────────────────────────────

/**
 * RetryAttemptWriter — the settlement_retries row write interface
 *
 * Single responsibility: INSERT a single RetryAttempt record.
 * Idempotency: PK = attempt.id (UUID); a duplicate insert -> throw SrError SR_DUPLICATE_ATTEMPT.
 * fail-closed: DB unreachable -> throw SrError SR_PERSIST_FAILED (never silently resolve).
 */
export interface RetryAttemptWriter {
    /**
     * insert — write a single RetryAttempt row (settlement_retries INSERT)
     *
     * @param attempt the complete RetryAttempt object (id + operationId + all fields populated)
     * @throws SrError SR_IDEMPOTENCY_VIOLATION if attempt.id already exists (PK unique conflict;
     *   PgRetryAttemptWriter implementation; detail.reason='retry_attempt_id_pk_unique_violation_duplicate_persist')
     * @throws SrError SR_STATE_TRANSITION_INVALID if the DB write fails (connection drop / timeout / other constraint;
     *   SrErrorCode 14-item v0.1 freeze; SR_PERSIST_FAILED is not in the union;
     *   detail.reason='retry_attempt_db_insert_failed' distinguishes the call-path)
     */
    insert(attempt: RetryAttempt): Promise<void>;
}
