/**
 * Package-private timestamp utilities (shared across policy-layer submodules)
 *
 * Background:
 *   The PG node driver returns JavaScript Date objects by default for
 *   TIMESTAMPTZ / TIMESTAMP, whereas row types such as ActionRecordRow /
 *   TokenStoreRow / CumulativeTrackerRow declare those fields as string, so the
 *   declared type and the runtime value disagree. Downstream code that casts
 *   with `as Timestamp` and then calls `.localeCompare()` / string comparison
 *   will throw a TypeError.
 *
 *   cross-domain-settle/payload.ts already fixed that submodule via toISOString;
 *   recorder / guard still have several cast lies of the same origin:
 *     - recorder/action-recorder.ts
 *     - recorder/action-record-routes.ts
 *     - guard/postgres-cumulative-tracker.ts
 *
 * Fix strategy: extract a package-level shared helper, call it uniformly, and
 * change cross-domain-settle/payload.ts toISOString into a re-export so that
 * existing call sites keep working.
 */

import type { Timestamp } from '@coivitas/types';

/**
 * Safely normalizes a PG TIMESTAMPTZ / TIMESTAMP column value (string | Date)
 * to an ISO 8601 string.
 *
 * Use cases: fromRow mapping plus any place that needs string output after
 * obtaining a PG timestamp.
 */
export function toISOString(value: string | Date): string {
    if (value instanceof Date) {
        return value.toISOString();
    }
    return value;
}

/**
 * Normalizes a PG timestamp column value to a Timestamp brand string.
 * Equivalent to `toISOString(value) as Timestamp`, but more explicit in intent.
 */
export function toTimestamp(value: string | Date): Timestamp {
    return toISOString(value) as Timestamp;
}
