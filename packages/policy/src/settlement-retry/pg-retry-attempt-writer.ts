/**
 * PgRetryAttemptWriter — PostgreSQL implementation of RetryAttemptWriter
 *
 * Real SQL INSERT INTO settlement_retries.
 * Consumes the table created by migration 031 (packages/sdk/sql/031_settlement_retry.sql).
 *
 * Field mapping (A42 three-way reconciliation: types RetryAttempt <-> JSON Schema <-> SQL DDL):
 *   attempt.id -> id UUID NOT NULL PRIMARY KEY
 *   attempt.operationId -> operation_id UUID NOT NULL REFERENCES settlement_operations(id)
 *   attempt.attemptNumber -> attempt_number INTEGER NOT NULL
 *   attempt.fromState -> from_state TEXT NOT NULL
 *   attempt.toState -> to_state TEXT NOT NULL
 *   attempt.attemptedAt -> attempted_at TIMESTAMPTZ NOT NULL
 *   attempt.completedAt -> completed_at TIMESTAMPTZ NULL
 *   attempt.resultSummary -> result_summary TEXT NULL
 *   attempt.failureReason -> failure_reason TEXT NULL
 *   attempt.backoffDelayMs -> backoff_delay_ms INTEGER NOT NULL
 *   attempt.auditEventId -> audit_event_id UUID NOT NULL
 *
 * Error handling (fail-closed):
 *   PostgreSQL error code 23505 (unique_violation) -> throw SrError SR_DUPLICATE_ATTEMPT
 *   any other DB error -> throw SrError SR_PERSIST_FAILED
 */

import type { DatabasePool } from '@coivitas/shared';
import { SrError, type RetryAttempt } from '@coivitas/types';

import type { RetryAttemptWriter } from './retry-attempt-writer.js';

// ─── PgRetryAttemptWriter ─────────────────────────────────────────────────────

/**
 * PgRetryAttemptWriter — pg Pool implementation of RetryAttemptWriter
 *
 * Constructor: takes a pool (DatabasePool) and executes the INSERT.
 * fail-closed: any DB error -> throw SrError (never silently resolve).
 */
export class PgRetryAttemptWriter implements RetryAttemptWriter {
    private readonly pool: DatabasePool;

    constructor(pool: DatabasePool) {
        this.pool = pool;
    }

    /**
     * insert — real SQL INSERT INTO settlement_retries
     *
     * @param attempt the complete RetryAttempt (all fields must be populated; auditEventId non-empty)
     * @throws SrError SR_DUPLICATE_ATTEMPT if attempt.id already exists (PK conflict; pg 23505)
     * @throws SrError SR_PERSIST_FAILED if the DB write fails (connection drop / timeout / other constraint)
     */
    async insert(attempt: RetryAttempt): Promise<void> {
        const sql = `
            INSERT INTO settlement_retries (
                id,
                operation_id,
                attempt_number,
                from_state,
                to_state,
                attempted_at,
                completed_at,
                result_summary,
                failure_reason,
                backoff_delay_ms,
                audit_event_id
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11
            )
        `;

        const params = [
            attempt.id,
            attempt.operationId,
            attempt.attemptNumber,
            attempt.fromState,
            attempt.toState,
            attempt.attemptedAt,
            attempt.completedAt ?? null,
            attempt.resultSummary ?? null,
            attempt.failureReason ?? null,
            attempt.backoffDelayMs,
            attempt.auditEventId,
        ];

        try {
            await this.pool.query(sql, params);
        } catch (err: unknown) {
            // PostgreSQL 23505: unique_violation -> PK duplicate (attempt.id already exists)
            // Semantics: a duplicate write of the same retryAttemptId = idempotency conflict -> SR_IDEMPOTENCY_VIOLATION
            // (SrErrorCode 14-item v0.1 freeze; SR_DUPLICATE_ATTEMPT is not in the union;
            // SR_IDEMPOTENCY_VIOLATION is the closest in semantics: "concurrent duplicate key" covers a PK duplicate)
            if (isPgError(err) && err.code === '23505') {
                throw new SrError('SR_IDEMPOTENCY_VIOLATION', {
                    retryAttemptId: attempt.id,
                    operationId: attempt.operationId,
                    attemptNumber: attempt.attemptNumber,
                    reason: 'retry_attempt_id_pk_unique_violation_duplicate_persist',
                });
            }

            // Any other DB error -> SR_STATE_TRANSITION_INVALID (infrastructure fail-closed)
            // (SrErrorCode 14-item v0.1 freeze; SR_PERSIST_FAILED is not in the union;
            // SR_STATE_TRANSITION_INVALID is used in the existing L3 pattern for infrastructure-layer violations;
            // detail.reason = 'retry_attempt_db_insert_failed' distinguishes the call-path)
            throw new SrError('SR_STATE_TRANSITION_INVALID', {
                retryAttemptId: attempt.id,
                operationId: attempt.operationId,
                reason: 'retry_attempt_db_insert_failed',
                originalError: err instanceof Error ? err.message : String(err),
            });
        }
    }
}

// ─── isPgError — pg DatabaseError type guard ───────────────────────────────────

/**
 * isPgError — pg DatabaseError detection
 *
 * The Error thrown by the pg driver carries a `code` field (PostgreSQL error code string).
 * Uses duck typing rather than importing pg (avoids a circular import + reduces type-only dependencies).
 */
function isPgError(err: unknown): err is { code: string; message: string } {
    return (
        typeof err === 'object' &&
        err !== null &&
        'code' in err &&
        typeof (err as Record<string, unknown>)['code'] === 'string'
    );
}
