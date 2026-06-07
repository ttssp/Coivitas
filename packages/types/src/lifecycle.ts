// Precise result types for asynchronous shutdown operations (pure L0 types).
// Design rationale: same origin as the IntegrityChecker DU refactor — type-layer defense > runtime silent failure.
// At compile time, forces every caller to destructure and distinguish completed vs timed_out vs error vs noop.

import type { Timestamp } from './base.js';

/**
 * ShutdownStatus — the precise result of an asynchronous shutdown operation.
 *
 * 4 variants:
 *   - completed: completed normally, with duration
 *   - timed_out: a hard timeout was hit; the underlying resource may still be running in the background
 *   - error: a non-timeout exception
 *   - noop: no operation needed (already shut down or never started)
 *
 * @breaking no (new type; existing Promise<void> callers must adapt, but behavior is unchanged)
 */
export type ShutdownStatus =
    | { readonly status: 'completed'; readonly durationMs: number }
    | {
          readonly status: 'timed_out';
          readonly durationMs: number;
          readonly reason: 'hard_timeout';
      }
    | {
          readonly status: 'error';
          readonly durationMs: number;
          readonly error: Error;
      }
    | {
          readonly status: 'noop';
          readonly reason: 'already_shutdown' | 'never_started';
      };

/**
 * ShutdownAware — marks a component as supporting typed shutdown.
 *
 * After shutdown, a component should return a ShutdownStatus to inform the caller of the precise result,
 * which the caller uses to decide whether to retry, the log level, or further cleanup.
 *
 */
export interface ShutdownAware {
    shutdown(): Promise<ShutdownStatus>;
}

// Re-export the imported Timestamp (so lifecycle.ts users do not need a separate import from base)
export type { Timestamp };
