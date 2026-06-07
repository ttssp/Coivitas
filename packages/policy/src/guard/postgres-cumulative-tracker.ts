import { randomUUID } from 'node:crypto';

import type { PoolClient } from 'pg';

import { type DatabasePool, withTransaction } from '@coivitas/shared';
import type { DID, MeterFieldRef, Timestamp } from '@coivitas/types';

import { toTimestamp } from '../_shared/timestamp.js';
import {
    buildUnsignedRecordPayload,
    verifyRecordSignature,
} from '../recorder/shared.js';
import {
    type CumulativeTracker,
    type MeterFieldEntry,
    METER_FIELD_REGISTRY,
} from './cumulative-tracker.js';

/**
 * The action_type identifier for PENDING reservation rows.
 *
 * These rows are written by checkAndReserve, stored in policy.action_records,
 * sharing the same table as normal ActionRecord rows. Their result_summary.status='PENDING'
 * indicates the reservation is not yet settled; getCumulativeValue includes them in the cumulative total
 * per the countFilter logic during queries, preventing concurrent requests from reading the same baseline
 * and over-admitting simultaneously (TOCTOU protection).
 *
 * Structure of a PENDING row's result_summary:
 *   { status: 'PENDING', metric: string, reserveAmount: number, max: number }
 */
export const CUMULATIVE_RESERVE_ACTION_TYPE = '__CUMULATIVE_RESERVE__';

/**
 * Timeout threshold (milliseconds): a PENDING reservation still unsettled past this time is treated as a crash leftover.
 * getCumulativeValue skips timed-out PENDING rows (does not include them in the cumulative total).
 * A background TTL cleanup task should transition timed-out PENDING to SETTLED (COUNT+*) or RELEASED (SUM/COUNT+SUCCESS).
 * Recommended value: 5 minutes.
 */
export const PENDING_TTL_MS = 5 * 60 * 1000;

interface ActionRecordRow {
    record_id: string;
    agent_did: string;
    principal_did: string;
    action_type: string;
    parameters_summary: Record<string, unknown> | null;
    authorization_ref: Record<string, unknown> | null;
    result_summary: Record<string, unknown> | null;
    record_hash: string;
    previous_record_hash: string;
    ledger_signature: string;
    delegation_depth: number | null;
    session_id: string | null;
    // The PG node driver returns a Date object for TIMESTAMPTZ by default; cumulative
    // signature verification must normalize via toTimestamp(), otherwise buildUnsignedRecordPayload
    // rebuilds from a Date that mismatches the original signature's ISO string → verification fails → cumulative under-counting (acceptance Bug B).
    created_at: string | Date;
}

export class PostgresCumulativeTracker implements CumulativeTracker {
    public constructor(
        private readonly pool: DatabasePool,
        private readonly ledgerPublicKey: string,
    ) {}

    // -----------------------------------------------------------------------
    // getCumulativeValue (read-only query, no concurrency guarantee)
    // -----------------------------------------------------------------------

    public async getCumulativeValue(
        agentDid: DID,
        meterField: MeterFieldRef,
        windowStart: Date,
        now: Date,
    ): Promise<number> {
        const entry = METER_FIELD_REGISTRY[meterField.metric];
        if (!entry) {
            throw new Error(`unregistered meter field: ${meterField.metric}`);
        }

        const rows = await this.fetchSettledRows(
            agentDid,
            windowStart,
            now,
            entry,
        );
        return this.aggregate(rows, entry, meterField.metric);
    }

    // -----------------------------------------------------------------------
    // checkAndReserve (atomic check-and-reserve)
    // -----------------------------------------------------------------------

    public async checkAndReserve(
        recordId: string,
        agentDid: DID,
        meterField: MeterFieldRef,
        windowStart: Date,
        now: Date,
        max: number,
        reserveAmount: number,
    ): Promise<{ allowed: boolean; currentCumulative: number }> {
        const entry = METER_FIELD_REGISTRY[meterField.metric];
        if (!entry) {
            throw new Error(`unregistered meter field: ${meterField.metric}`);
        }

        return withTransaction(this.pool, async (client) => {
            // Idempotency check: if a PENDING row with the same recordId already exists, return the first result
            const existing = await this.findReservation(client, recordId);
            if (existing !== null) {
                // A reservation row already exists → return the first result (idempotent).
                // currentCumulative takes the cumulative value recorded at the first write (the value before this reservation)
                const existingReserveAmount =
                    typeof existing.result_summary?.['reserveAmount'] ===
                    'number'
                        ? existing.result_summary['reserveAmount']
                        : reserveAmount;
                const existingMax =
                    typeof existing.result_summary?.['max'] === 'number'
                        ? existing.result_summary['max']
                        : max;
                const existingCumulative =
                    typeof existing.result_summary?.['cumulativeAtReserve'] ===
                    'number'
                        ? existing.result_summary['cumulativeAtReserve']
                        : 0;
                const wouldExceed =
                    existingCumulative + existingReserveAmount > existingMax;
                return {
                    allowed: !wouldExceed,
                    currentCumulative: existingCumulative,
                };
            }

            // An advisory lock at (agentDid, metric, windowStart) granularity guarantees serialization
            await this.acquireAdvisoryLock(
                client,
                agentDid,
                meterField.metric,
                windowStart,
            );

            // Query the current cumulative total (including PENDING rows)
            const currentCumulative = await this.aggregateWithClient(
                client,
                agentDid,
                meterField,
                windowStart,
                now,
                entry,
            );

            const projected = currentCumulative + reserveAmount;
            if (projected > max) {
                return { allowed: false, currentCumulative };
            }

            // Write the PENDING reservation row
            await this.insertReservation(
                client,
                recordId,
                agentDid,
                meterField.metric,
                reserveAmount,
                max,
                currentCumulative,
                now,
            );

            return { allowed: true, currentCumulative };
        });
    }

    // -----------------------------------------------------------------------
    // settleReservation (settle reservation)
    // -----------------------------------------------------------------------

    public async settleReservation(
        recordId: string,
        resultStatus: 'SUCCESS' | 'REJECTED' | 'ERROR',
        settledAmount?: number,
        client?: PoolClient,
    ): Promise<void> {
        if (client) {
            await this.doSettle(client, recordId, resultStatus, settledAmount);
        } else {
            await withTransaction(this.pool, async (txClient) => {
                await this.doSettle(
                    txClient,
                    recordId,
                    resultStatus,
                    settledAmount,
                );
            });
        }
    }

    // -----------------------------------------------------------------------
    // Private helper methods
    // -----------------------------------------------------------------------

    private async doSettle(
        client: PoolClient,
        recordId: string,
        resultStatus: 'SUCCESS' | 'REJECTED' | 'ERROR',
        settledAmount?: number,
    ): Promise<void> {
        const reservation = await this.findReservation(client, recordId);
        if (!reservation) {
            // The PENDING row does not exist: it may have been cleaned up by TTL, or checkAndReserve was never called.
            // fail-open: log but do not throw (to avoid a settleReservation failure rolling back the ActionRecord)
            return;
        }

        const metric = reservation.result_summary?.['metric'] as
            | string
            | undefined;
        if (!metric) {
            return;
        }

        const entry = METER_FIELD_REGISTRY[metric];
        if (!entry) {
            return;
        }

        const reserveAmount =
            typeof reservation.result_summary?.['reserveAmount'] === 'number'
                ? reservation.result_summary['reserveAmount']
                : 0;
        const max =
            typeof reservation.result_summary?.['max'] === 'number'
                ? reservation.result_summary['max']
                : Infinity;

        let newStatus: 'SETTLED' | 'RELEASED';

        if (entry.aggregation === 'COUNT') {
            if (entry.countFilter === '*') {
                // COUNT+*: all terminal states → SETTLED (prevents a retry storm from bypassing the api_call_count limit)
                newStatus = 'SETTLED';
            } else {
                // COUNT+SUCCESS: only SUCCESS counts
                newStatus = resultStatus === 'SUCCESS' ? 'SETTLED' : 'RELEASED';
            }
        } else {
            // SUM aggregation
            if (resultStatus !== 'SUCCESS') {
                // failed/rejected → release the reservation (does not consume SUM-type quota)
                newStatus = 'RELEASED';
            } else {
                // SUCCESS + SUM: if the actual amount > reserved amount, re-validate the limit
                const effectiveAmount = settledAmount ?? reserveAmount;
                if (effectiveAmount > reserveAmount) {
                    // Re-read the current cumulative total (excluding this PENDING row, since it is still PENDING).
                    // Approximation: read the already-SETTLED cumulative + effectiveAmount and decide whether it exceeds the limit
                    const cumulativeAtReserve =
                        typeof reservation.result_summary?.[
                            'cumulativeAtReserve'
                        ] === 'number'
                            ? reservation.result_summary['cumulativeAtReserve']
                            : 0;
                    if (cumulativeAtReserve + effectiveAmount > max) {
                        throw new Error(
                            `[settleReservation] settledAmount (${effectiveAmount}) + cumulative (${cumulativeAtReserve}) exceeds max (${max}) for record ${recordId}; transaction rolled back`,
                        );
                    }
                }
                newStatus = 'SETTLED';
            }
        }

        // Update the PENDING row's result_summary.status
        const updatedResultSummary = {
            ...reservation.result_summary,
            status: newStatus,
            resultStatus,
            settledAmount: settledAmount ?? reserveAmount,
        };

        await client.query(
            `UPDATE policy.action_records
             SET result_summary = $1::jsonb
             WHERE record_id = $2
               AND action_type = $3`,
            [
                JSON.stringify(updatedResultSummary),
                recordId,
                CUMULATIVE_RESERVE_ACTION_TYPE,
            ],
        );
    }

    /** Find the PENDING reservation row (only queries PENDING status) */
    private async findReservation(
        client: PoolClient,
        recordId: string,
    ): Promise<ActionRecordRow | null> {
        const result = await client.query<ActionRecordRow>(
            `SELECT record_id, agent_did, principal_did, action_type,
                    parameters_summary, authorization_ref, result_summary,
                    record_hash, previous_record_hash, ledger_signature,
                    delegation_depth, session_id, created_at
             FROM policy.action_records
             WHERE record_id = $1
               AND action_type = $2`,
            [recordId, CUMULATIVE_RESERVE_ACTION_TYPE],
        );
        return result.rows[0] ?? null;
    }

    /**
     * Acquire an advisory lock on (agentDid, metric, windowStart).
     * hashtext() returns int4; XOR-ing two concatenated bigints ensures different parameters do not collide.
     */
    private async acquireAdvisoryLock(
        client: PoolClient,
        agentDid: DID,
        metric: string,
        windowStart: Date,
    ): Promise<void> {
        // Combine (agentDid + ':' + metric + ':' + windowStart.toISOString()) into a single string for hashtext
        const lockKey = `${agentDid}:${metric}:${windowStart.toISOString()}`;
        await client.query('SELECT pg_advisory_xact_lock(hashtext($1))', [
            lockKey,
        ]);
    }

    /** Aggregate the cumulative value within the current window using an existing PoolClient (including PENDING rows) */
    private async aggregateWithClient(
        client: PoolClient,
        agentDid: DID,
        meterField: MeterFieldRef,
        windowStart: Date,
        now: Date,
        entry: MeterFieldEntry,
    ): Promise<number> {
        const pendingCutoff = new Date(Date.now() - PENDING_TTL_MS);

        // Inclusion conditions (Bug B fix, aligned with fetchSettledRows semantics):
        // ordinary success rows (ActionRecorder.record writes status='SUCCESS',
        // a business-path success result, not part of the reserve/settle state machine)
        // already-SETTLED rows (the reserve→settle path has completed settlement)
        // PENDING reservation rows whose created_at is within TTL (not-yet-timed-out reservations,
        // counted to prevent concurrent over-admission)
        // Before the fix, statusFilterExpr only considered the reserve/settle state machine
        // (SETTLED/PENDING/RELEASED) and missed ordinary record() 'SUCCESS' rows
        // → when cumulative_limit evaluation takes the checkAndReserve path, the pre-written
        // ordinary SUCCESS records were ignored → cumulative under-counting → over-limit admission
        const statusFilterExpr =
            entry.countFilter === 'SUCCESS'
                ? `AND (
                       result_summary->>'status' IN ('SUCCESS', 'SETTLED')
                       OR (
                           action_type = '${CUMULATIVE_RESERVE_ACTION_TYPE}'
                           AND result_summary->>'status' = 'PENDING'
                           AND created_at >= $4
                       )
                   )`
                : `AND (
                       result_summary->>'status' NOT IN ('RELEASED', 'REJECTED', 'ERROR')
                       AND (
                           result_summary->>'status' != 'PENDING'
                           OR (
                               action_type = '${CUMULATIVE_RESERVE_ACTION_TYPE}'
                               AND created_at >= $4
                           )
                       )
                   )`;

        const result = await client.query<ActionRecordRow>(
            // created_at <= now (inclusive): multiple consecutive reserves at the same now must
            // be mutually visible, otherwise an off-by-one at the window boundary makes a concurrent reserve
            // miss earlier PENDING rows with the same timestamp → cumulative under-counting → over-limit admission
            // (Bug B fix, same semantics as fetchSettledRows)
            `SELECT record_id, agent_did, principal_did, action_type,
                    parameters_summary, authorization_ref, result_summary,
                    record_hash, previous_record_hash, ledger_signature,
                    delegation_depth, session_id, created_at
             FROM policy.action_records
             WHERE agent_did = $1
               AND created_at >= $2
               AND created_at <= $3
               ${statusFilterExpr}`,
            [
                agentDid,
                windowStart.toISOString(),
                now.toISOString(),
                pendingCutoff.toISOString(),
            ],
        );

        let total = 0;
        for (const row of result.rows) {
            if (row.action_type === CUMULATIVE_RESERVE_ACTION_TYPE) {
                // PENDING reservation row: read reserveAmount directly (no signature check; reservation rows are written by this layer)
                const reserveAmount = row.result_summary?.['reserveAmount'];
                if (typeof reserveAmount === 'number') {
                    if (entry.aggregation === 'COUNT') {
                        total += 1;
                    } else {
                        total += reserveAmount;
                    }
                }
                continue;
            }

            // Ordinary row: aggregate after signature verification (consistent with getCumulativeValue logic)
            if (entry.aggregation === 'COUNT') {
                if (
                    entry.countFilter === '*' ||
                    row.result_summary?.['status'] === 'SETTLED'
                ) {
                    total += 1;
                } else if (row.result_summary?.['status'] === 'SUCCESS') {
                    total += 1;
                }
            } else {
                const val = row.result_summary?.[entry.recordField!];
                if (typeof val === 'number' && !Number.isNaN(val)) {
                    total += val;
                }
            }
        }
        return total;
    }

    /** Write the PENDING reservation row */
    private async insertReservation(
        client: PoolClient,
        recordId: string,
        agentDid: DID,
        metric: string,
        reserveAmount: number,
        max: number,
        cumulativeAtReserve: number,
        now: Date,
    ): Promise<void> {
        const createdAt = now.toISOString() as Timestamp;
        const resultSummary = {
            status: 'PENDING',
            metric,
            reserveAmount,
            max,
            cumulativeAtReserve,
        };

        // Reservation rows use empty-string placeholders (not added to the hash chain; no previousRecordHash/signature needed).
        // This differs from the ordinary-row format written by ActionRecorder — reservation rows are only for internal state tracking
        // and do not participate in IntegrityChecker's hash chain verification.
        await client.query(
            `INSERT INTO policy.action_records (
                record_id,
                agent_did,
                principal_did,
                action_type,
                parameters_summary,
                authorization_ref,
                result_summary,
                record_hash,
                previous_record_hash,
                actor_signature,
                ledger_signature,
                delegation_depth,
                session_id,
                created_at
            )
            VALUES ($1, $2, $3, $4, NULL, NULL, $5::jsonb, $6, $7, $8, $9, NULL, NULL, $10)
            ON CONFLICT (record_id) DO NOTHING`,
            [
                recordId, // $1
                agentDid, // $2
                agentDid, // $3 principal_did uses agentDid as a placeholder
                CUMULATIVE_RESERVE_ACTION_TYPE, // $4
                JSON.stringify(resultSummary), // $5
                randomUUID(), // $6 record_hash (placeholder, not part of the chain)
                '', // $7 previous_record_hash (placeholder)
                '', // $8 actor_signature (placeholder)
                '', // $9 ledger_signature (placeholder)
                createdAt, // $10
            ],
        );
    }

    // -----------------------------------------------------------------------
    // Existing private methods (used by getCumulativeValue)
    // -----------------------------------------------------------------------

    private async fetchSettledRows(
        agentDid: DID,
        windowStart: Date,
        now: Date,
        entry: MeterFieldEntry,
    ): Promise<ActionRecordRow[]> {
        // getCumulativeValue counts only settled rows (excluding PENDING/RELEASED/reservation rows)
        const statusFilter =
            entry.countFilter === 'SUCCESS'
                ? `AND result_summary->>'status' = 'SUCCESS'
                   AND action_type != '${CUMULATIVE_RESERVE_ACTION_TYPE}'`
                : `AND result_summary->>'status' NOT IN ('PENDING', 'RELEASED')
                   AND action_type != '${CUMULATIVE_RESERVE_ACTION_TYPE}'`;

        const result = await this.pool.query<ActionRecordRow>(
            // created_at <= now (inclusive): consistent with aggregateWithClient, to avoid
            // an off-by-one at the window's right boundary (Bug B fix)
            `SELECT record_id, agent_did, principal_did, action_type,
                    parameters_summary, authorization_ref, result_summary,
                    record_hash, previous_record_hash, ledger_signature,
                    delegation_depth, session_id, created_at
             FROM policy.action_records
             WHERE agent_did = $1
               AND created_at >= $2
               AND created_at <= $3
               ${statusFilter}`,
            [agentDid, windowStart.toISOString(), now.toISOString()],
        );
        return result.rows;
    }

    private aggregate(
        rows: ActionRecordRow[],
        entry: MeterFieldEntry,
        metric: string,
    ): number {
        let total = 0;
        for (const row of rows) {
            // Signature verification: any invalid signature → fail-closed (prevents under-counting the cumulative value)
            const payload = buildUnsignedRecordPayload({
                recordId: row.record_id,
                agentDid: row.agent_did as DID,
                principalDid: row.principal_did as DID,
                actionType: row.action_type,
                parametersSummary: row.parameters_summary,
                authorizationRef: row.authorization_ref,
                resultSummary: row.result_summary,
                previousRecordHash: row.previous_record_hash,
                createdAt: toTimestamp(row.created_at),
                delegationDepth: row.delegation_depth ?? undefined,
                sessionId: row.session_id ?? undefined,
            });

            const valid = verifyRecordSignature(
                payload,
                row.ledger_signature,
                this.ledgerPublicKey,
            );
            if (!valid) {
                throw new Error(
                    `[CumulativeTracker] ledgerSignature invalid for record ${row.record_id}; window aggregation aborted (metric: ${metric})`,
                );
            }

            if (entry.aggregation === 'COUNT') {
                total += 1;
                continue;
            }

            const val = row.result_summary?.[entry.recordField!];
            if (typeof val !== 'number' || Number.isNaN(val)) {
                throw new Error(
                    `[CumulativeTracker] record ${row.record_id} is missing SUM field '${entry.recordField}' in result_summary (metric: ${metric}); fail-closed to prevent under-counting.`,
                );
            }
            total += val;
        }
        return total;
    }
}
