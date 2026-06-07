/**
 * PendingReaper — background reaping job for TTL-expired PENDING records
 *
 * Background: under the intra-org-only trust model, the sender-domain tracker uses pull-mode reconciliation.
 * If the sender does not reconcile for a long time, PENDING records accumulate but never transition to SETTLED.
 * PendingReaper periodically scans expired PENDING records and marks them RELEASED to prevent leakage.
 *
 * Design constraint: because the recipient cannot directly access the sender's DB connection,
 * the TTL + reaping job is a mandatory fallback.
 *
 * Usage:
 *   const reaper = new PendingReaper(recipientHandler);
 *   reaper.start(); // start the background setInterval
 *   // ...
 *   reaper.stop(); // stop (call on shutdown)
 */

import type { RecipientSettleHandler } from './settle-handler.js';
import { DEFAULT_CONFIG } from './types.js';

export class PendingReaper {
    private timer: ReturnType<typeof setInterval> | null = null;

    public constructor(
        private readonly handler: RecipientSettleHandler,
        private readonly intervalMs: number = DEFAULT_CONFIG.reapIntervalMs,
    ) {}

    /**
     * Start the background reaping job (idempotent: ignored if already started).
     */
    public start(): void {
        if (this.timer) return;
        this.timer = setInterval(() => {
            void this.handler.reapExpiredPending();
        }, this.intervalMs);
    }

    /**
     * Stop the background reaping job (idempotent: ignored if not started).
     * Should be called on service shutdown to prevent the timer from blocking process exit.
     */
    public stop(): void {
        if (this.timer) {
            clearInterval(this.timer);
            this.timer = null;
        }
    }

    /**
     * Trigger a single reaping pass manually (for tests / manual ops triggering).
     * @returns the number of records reaped
     */
    public async reapOnce(): Promise<number> {
        return this.handler.reapExpiredPending();
    }
}
