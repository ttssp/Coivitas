import type { PoolClient } from 'pg';

import type { DID, MeterFieldRef } from '@coivitas/types';

/**
 * Cumulative metering Tracker (the scope-extensions spec)
 *
 * Adds the two-phase checkAndReserve / settleReservation interface,
 * upgrading the original "read-then-decide" (which has a TOCTOU race) to a Reservation scheme:
 *
 * 1. checkAndReserve: atomically writes a PENDING reservation record; PENDING rows count toward the cumulative total,
 *    so subsequent concurrent requests read a cumulative total that already includes this reservation, avoiding over-admission.
 * 2. settleReservation: transitions the PENDING row to SETTLED / RELEASED,
 *    and must execute in the same database transaction as ActionRecorder.record() (pass PoolClient).
 */
export interface CumulativeTracker {
    getCumulativeValue(
        agentDid: DID,
        meterField: MeterFieldRef,
        windowStart: Date,
        now: Date,
    ): Promise<number>;

    /**
     * Atomic check-and-reserve.
     *
     * Performed within a single transaction:
     *   - acquire a pg_advisory_xact_lock on (agentDid, metric, windowStart)
     *   - query the current cumulative value (including existing PENDING reservations)
     *   - decide cumulative + reserveAmount > max → denied
     *   - write a PENDING reservation record (action_type='__CUMULATIVE_RESERVE__')
     *
     * Idempotent: calling again with the same recordId returns the first result and does not deduct twice.
     *
     * @param recordId pre-generated ActionRecord UUID (idempotency key)
     * @param agentDid agent DID
     * @param meterField metering field reference
     * @param windowStart window start time
     * @param now current time
     * @param max upper limit (used to decide whether the limit is exceeded)
     * @param reserveAmount COUNT→1; SUM→the request value extracted from params
     */
    checkAndReserve(
        recordId: string,
        agentDid: DID,
        meterField: MeterFieldRef,
        windowStart: Date,
        now: Date,
        max: number,
        reserveAmount: number,
    ): Promise<{ allowed: boolean; currentCumulative: number }>;

    /**
     * Settle reservation.
     *
     * Decides the final fate of the PENDING row based on resultStatus and countFilter:
     * - COUNT + countFilter='*': all terminal states → SETTLED (prevents retries from bypassing the limit)
     * - COUNT + countFilter='SUCCESS': SUCCESS → SETTLED; others → RELEASED
     * - SUM + SUCCESS: SETTLED, replacing reserveAmount with settledAmount;
     *   if settledAmount > reserveAmount, re-validate and throw when over the limit (the whole transaction rolls back)
     * - SUM + REJECTED/ERROR: RELEASED (failed transactions do not consume SUM quota)
     *
     * Must execute in the same database transaction as ActionRecorder.record(): pass in a PoolClient.
     *
     * @param recordId the ActionRecord UUID matching checkAndReserve
     * @param resultStatus execution result status
     * @param settledAmount required for the SUM type; ignored for the COUNT type
     * @param client PoolClient — shares the same transaction as ActionRecorder.record()
     */
    settleReservation(
        recordId: string,
        resultStatus: 'SUCCESS' | 'REJECTED' | 'ERROR',
        settledAmount?: number,
        client?: PoolClient,
    ): Promise<void>;
}

export type MeterAggregation = 'SUM' | 'COUNT';

export interface MeterFieldEntry {
    aggregation: MeterAggregation;
    /** valid only for SUM: the field name to extract from result_summary */
    recordField?: string;
    /** valid only for SUM: the field name to extract the current request value from params */
    requestField?: string;
    /** which result_summary.status values participate in aggregation */
    countFilter: 'SUCCESS' | '*';
}

/** Meter-field registry (the scope-extensions spec) */
export const METER_FIELD_REGISTRY: Record<string, MeterFieldEntry> = {
    transaction_amount: {
        aggregation: 'SUM',
        recordField: 'amount',
        requestField: 'amount',
        countFilter: 'SUCCESS',
    },
    api_call_count: {
        aggregation: 'COUNT',
        countFilter: '*',
    },
} as const;

/**
 * Compute the UTC calendar window start time per the window enum (the scope-extensions spec)
 */
export function computeWindowStart(
    window: 'hour' | 'day' | 'week' | 'month',
    now: Date,
): Date {
    const utc = new Date(now);
    switch (window) {
        case 'hour':
            utc.setUTCMinutes(0, 0, 0);
            return utc;
        case 'day':
            utc.setUTCHours(0, 0, 0, 0);
            return utc;
        case 'week': {
            // ISO 8601: Monday is the first day
            const dayOfWeek = utc.getUTCDay(); // 0=Sun, 1=Mon, ...6=Sat
            const daysToMonday = dayOfWeek === 0 ? 6 : dayOfWeek - 1;
            utc.setUTCDate(utc.getUTCDate() - daysToMonday);
            utc.setUTCHours(0, 0, 0, 0);
            return utc;
        }
        case 'month':
            utc.setUTCDate(1);
            utc.setUTCHours(0, 0, 0, 0);
            return utc;
    }
}
