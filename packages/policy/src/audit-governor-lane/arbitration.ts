/**
 * arbitration.ts -- operator arbitration state machine implementation.
 *
 * Provides two implementations:
 *   - InMemoryOperatorArbitrationStateMachine: in-memory stub, for test fixtures only (@internal)
 *   - PostgresOperatorArbitrationStateMachine: durable implementation
 *
 * State transitions:
 *   (initial) -> ARBITRATED_PENDING_OPERATOR (requestArbitration)
 *   ARBITRATED_PENDING_OPERATOR -> ARBITRATED (submitVerdict)
 *
 * Illegal transitions -> throw fail-closed.
 *
 * half-committed defense:
 *   - DB layer: 011_arbitration_records.sql UNIQUE INDEX (first-line)
 *   - Application layer: ON CONFLICT DO NOTHING + RETURNING check (second-line)
 *
 */

import { randomUUID } from 'node:crypto';

import { ProtocolError, type Timestamp } from '@coivitas/types';
import type { DatabasePool } from '@coivitas/shared';

import type {
    ArbitrationRequest,
    ArbitrationResult,
    ArbitrationVerdict,
    ArbitratedState,
    OperatorArbitrationStateMachine,
} from './types.js';

// ---------------------------------------------------------------------------
// Legal state transition table
// ---------------------------------------------------------------------------

/** Set of legal transitions from the current state to the next state. */
const VALID_TRANSITIONS: ReadonlyMap<
    ArbitratedState | 'INITIAL',
    ReadonlySet<ArbitratedState>
> = new Map([
    ['INITIAL', new Set<ArbitratedState>(['ARBITRATED_PENDING_OPERATOR'])],
    ['ARBITRATED_PENDING_OPERATOR', new Set<ArbitratedState>(['ARBITRATED'])],
    // ARBITRATED is the terminal state, with no legal successor
    ['ARBITRATED', new Set<ArbitratedState>()],
]);

// ---------------------------------------------------------------------------
// Internal arbitration record structure
// ---------------------------------------------------------------------------

interface ArbitrationRecord {
    id: string;
    relatedRecordId: string;
    state: ArbitratedState;
    reason: string;
    createdAt: Timestamp;
    verdict?: ArbitrationVerdict;
    updatedAt?: Timestamp;
}

// ---------------------------------------------------------------------------
// InMemoryOperatorArbitrationStateMachine
// ---------------------------------------------------------------------------

/**
 * In-memory operator arbitration state machine.
 *
 * @internal Minimal viable implementation for use in test fixtures only.
 * Production environments must replace it with PostgresOperatorArbitrationStateMachine
 * (the durable version), persisting to the policy.arbitration_records table
 * (pre-allocated by migration 011).
 *
 * fail-closed guarantee: all illegal transitions throw ProtocolError.
 */
export class InMemoryOperatorArbitrationStateMachine implements OperatorArbitrationStateMachine {
    private readonly records = new Map<string, ArbitrationRecord>();

    /**
     * Request operator arbitration -- transitions from INITIAL to ARBITRATED_PENDING_OPERATOR.
     */
    public requestArbitration(
        params: ArbitrationRequest,
    ): Promise<ArbitrationResult> {
        const id = randomUUID();

        // Check whether relatedRecordId already has an in-progress arbitration
        for (const record of this.records.values()) {
            if (
                record.relatedRecordId === params.relatedRecordId &&
                record.state === 'ARBITRATED_PENDING_OPERATOR'
            ) {
                return Promise.reject(
                    new ProtocolError(
                        'INTERNAL_ERROR',
                        `ARBITRATION_HALF_COMMITTED: relatedRecordId '${params.relatedRecordId}' ` +
                            `already has a pending arbitration (id='${record.id}'). ` +
                            `Cannot create duplicate arbitration request.`,
                    ),
                );
            }
        }

        const record: ArbitrationRecord = {
            id,
            relatedRecordId: params.relatedRecordId,
            state: 'ARBITRATED_PENDING_OPERATOR',
            reason: params.reason,
            createdAt: params.timestamp,
        };

        this.records.set(id, record);

        return Promise.resolve({
            arbitrationId: id,
            state: 'ARBITRATED_PENDING_OPERATOR' as const,
        });
    }

    /**
     * Operator submits an arbitration verdict -- transitions from ARBITRATED_PENDING_OPERATOR to ARBITRATED.
     */
    public submitVerdict(
        arbitrationId: string,
        verdict: ArbitrationVerdict,
    ): Promise<ArbitrationResult> {
        const record = this.records.get(arbitrationId);

        if (record === undefined) {
            return Promise.reject(
                new ProtocolError(
                    'INTERNAL_ERROR',
                    `ARBITRATION_CHAIN_MALFORMED: arbitrationId '${arbitrationId}' not found. ` +
                        `Cannot submit verdict for non-existent arbitration.`,
                ),
            );
        }

        // Validate legality of the state transition
        const validNextStates = VALID_TRANSITIONS.get(record.state);
        if (!validNextStates?.has('ARBITRATED')) {
            return Promise.reject(
                new ProtocolError(
                    'INTERNAL_ERROR',
                    `ARBITRATION_CHAIN_MALFORMED: illegal state transition ` +
                        `${record.state} -> ARBITRATED for arbitrationId '${arbitrationId}'. ` +
                        `Only ARBITRATED_PENDING_OPERATOR -> ARBITRATED is legal.`,
                ),
            );
        }

        record.state = 'ARBITRATED';
        record.verdict = verdict;
        record.updatedAt = verdict.timestamp;

        return Promise.resolve({
            arbitrationId,
            state: 'ARBITRATED' as const,
        });
    }

    /**
     * Query arbitration state. Returns null when arbitrationId does not exist.
     */
    public getState(arbitrationId: string): Promise<ArbitratedState | null> {
        return Promise.resolve(this.records.get(arbitrationId)?.state ?? null);
    }

    /** Internal: get the current record count (for tests). */
    public get size(): number {
        return this.records.size;
    }

    /** Internal: clear the store (for tests). */
    public clear(): void {
        this.records.clear();
    }
}

// ---------------------------------------------------------------------------
// PostgresOperatorArbitrationStateMachine
// ---------------------------------------------------------------------------

/** DB row structure (internal, corresponds to policy.arbitration_records). */
interface ArbitrationDbRow {
    id: string;
    related_record_id: string;
    state: string;
    reason: string;
    created_at: string;
    verdict: unknown;
    updated_at: string | null;
}

/**
 * Postgres durable operator arbitration state machine.
 *
 * Implementation notes:
 *   - State transition legality: atomic UPDATE with SQL WHERE state = 'ARBITRATED_PENDING_OPERATOR' (first-line)
 *   - half-committed defense: INSERT ... ON CONFLICT DO NOTHING + RETURNING check (second-line),
 *     combined with the 011_arbitration_records.sql UNIQUE INDEX (first-line DB constraint)
 *   - Duplicate PENDING relatedRecordId -> reject ARBITRATION_HALF_COMMITTED
 *   - Illegal state transition (submitVerdict again after ARBITRATED) -> reject
 *
 */
export class PostgresOperatorArbitrationStateMachine implements OperatorArbitrationStateMachine {
    constructor(private readonly pool: DatabasePool) {}

    /**
     * Request operator arbitration -- transitions from INITIAL to ARBITRATED_PENDING_OPERATOR.
     *
     * half-committed defense:
     *   - INSERT ... ON CONFLICT DO NOTHING (second-line; the DB UNIQUE INDEX is first-line)
     *   - RETURNING id check: if no row is returned, the UNIQUE INDEX triggered a conflict -> ARBITRATION_HALF_COMMITTED
     *
     * @throws ProtocolError('INTERNAL_ERROR') ARBITRATION_HALF_COMMITTED on a duplicate pending request
     */
    public async requestArbitration(
        params: ArbitrationRequest,
    ): Promise<ArbitrationResult> {
        const id = randomUUID();
        const createdAt = params.timestamp as string;

        // INSERT ... ON CONFLICT DO NOTHING (application-layer second-line defense)
        // The DB UNIQUE INDEX uniq_arbitration_pending_per_record is the first-line defense
        const result = await this.pool.query<{ id: string }>(
            `INSERT INTO policy.arbitration_records
                (id, related_record_id, state, reason, created_at)
             VALUES ($1, $2, 'ARBITRATED_PENDING_OPERATOR', $3, $4)
             ON CONFLICT DO NOTHING
             RETURNING id`,
            [id, params.relatedRecordId, params.reason, createdAt],
        );

        if (result.rows.length === 0) {
            // UNIQUE INDEX conflict: a PENDING request already exists
            throw new ProtocolError(
                'INTERNAL_ERROR',
                `ARBITRATION_HALF_COMMITTED: relatedRecordId '${params.relatedRecordId}' ` +
                    `already has a pending arbitration (state=ARBITRATED_PENDING_OPERATOR). ` +
                    `Cannot create duplicate arbitration request. ` +
                    `[half-committed defense via UNIQUE INDEX on relatedRecordId]`,
            );
        }

        return {
            arbitrationId: result.rows[0]!.id,
            state: 'ARBITRATED_PENDING_OPERATOR' as const,
        };
    }

    /**
     * Operator submits an arbitration verdict -- transitions from ARBITRATED_PENDING_OPERATOR to ARBITRATED.
     *
     * State transition legality: atomic execution via SQL WHERE state = 'ARBITRATED_PENDING_OPERATOR' (first-line).
     * The application layer acts as the second-line: RETURNING checks whether any row was updated.
     *
     * @throws ProtocolError('INTERNAL_ERROR') on an illegal state transition or a nonexistent arbitrationId
     */
    public async submitVerdict(
        arbitrationId: string,
        verdict: ArbitrationVerdict,
    ): Promise<ArbitrationResult> {
        // An arbitrationId with an invalid UUID format is treated as not-found
        // (PG raises 22P02 invalid_text_representation; wrapped as ARBITRATION_CHAIN_MALFORMED)
        if (!isValidUuid(arbitrationId)) {
            throw new ProtocolError(
                'INTERNAL_ERROR',
                `ARBITRATION_CHAIN_MALFORMED: arbitrationId '${arbitrationId}' not found. ` +
                    `Cannot submit verdict for non-existent arbitration.`,
            );
        }

        const updatedAt = verdict.timestamp as string;
        const verdictJson = JSON.stringify({
            operatorDid: verdict.operatorDid,
            decision: verdict.decision,
            rationale: verdict.rationale,
            timestamp: verdict.timestamp,
        });

        // Atomic UPDATE: WHERE state = 'ARBITRATED_PENDING_OPERATOR' ensures the state transition is legal
        // RETURNING id check: no row returned = illegal state or nonexistent id
        const result = await this.pool.query<{ id: string }>(
            `UPDATE policy.arbitration_records
             SET state = 'ARBITRATED',
                 verdict = $2::jsonb,
                 updated_at = $3
             WHERE id = $1
               AND state = 'ARBITRATED_PENDING_OPERATOR'
             RETURNING id`,
            [arbitrationId, verdictJson, updatedAt],
        );

        if (result.rows.length === 0) {
            // No row updated: either the id does not exist, or the state is not ARBITRATED_PENDING_OPERATOR
            // Disambiguate further (application-layer second-line diagnostics)
            const existResult = await this.pool.query<{ state: string }>(
                `SELECT state FROM policy.arbitration_records WHERE id = $1`,
                [arbitrationId],
            );

            if (existResult.rows.length === 0) {
                throw new ProtocolError(
                    'INTERNAL_ERROR',
                    `ARBITRATION_CHAIN_MALFORMED: arbitrationId '${arbitrationId}' not found. ` +
                        `Cannot submit verdict for non-existent arbitration.`,
                );
            }

            const currentState = existResult.rows[0]!.state;
            throw new ProtocolError(
                'INTERNAL_ERROR',
                `ARBITRATION_CHAIN_MALFORMED: illegal state transition ` +
                    `${currentState} -> ARBITRATED for arbitrationId '${arbitrationId}'. ` +
                    `Only ARBITRATED_PENDING_OPERATOR -> ARBITRATED is legal.`,
            );
        }

        return {
            arbitrationId,
            state: 'ARBITRATED' as const,
        };
    }

    /**
     * Query arbitration state. Returns null when arbitrationId does not exist.
     */
    public async getState(
        arbitrationId: string,
    ): Promise<ArbitratedState | null> {
        // An invalid UUID format is treated as not-found (symmetric with submitVerdict behavior)
        if (!isValidUuid(arbitrationId)) {
            return null;
        }

        const result = await this.pool.query<ArbitrationDbRow>(
            `SELECT state FROM policy.arbitration_records WHERE id = $1`,
            [arbitrationId],
        );

        if (result.rows.length === 0) {
            return null;
        }

        const state = result.rows[0]!.state;
        // Runtime type validation (avoids a brand cast)
        if (state !== 'ARBITRATED_PENDING_OPERATOR' && state !== 'ARBITRATED') {
            throw new ProtocolError(
                'INTERNAL_ERROR',
                `ARBITRATION_CHAIN_MALFORMED: unexpected state '${state}' for arbitrationId '${arbitrationId}'. ` +
                    `Valid states: ARBITRATED_PENDING_OPERATOR, ARBITRATED.`,
            );
        }

        return state as ArbitratedState;
    }
}

// UUID format validation helper (prevents the PG 22P02 error from leaking to the caller)
const UUID_PATTERN =
    /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
function isValidUuid(value: string): boolean {
    return UUID_PATTERN.test(value);
}
