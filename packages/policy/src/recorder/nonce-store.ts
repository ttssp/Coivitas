/**
 * AuditNonceStore — nonce replay-protection store
 *
 * Default implementation: InMemoryAuditNonceStore — single-process Map + periodic cleanup.
 * Multi-instance deployments require the deployer to replace it with a Redis/PostgreSQL implementation (a standard reference implementation is provided separately).
 */

// nonce rolling window TTL (seconds), aligned with the timestamp skew window.
// TTL = 300s; out-of-window requests are already rejected by step 8 (timestamp validation),
// so the nonce only needs to remain unique within the window.
const NONCE_TTL_MS = 300_000; // 300s = 5min

/**
 * nonce replay-protection interface.
 *
 */
export interface AuditNonceStore {
    /**
     * Check whether the nonce already exists and store it.
     *
     * Returns true = nonce already exists (replay) -> 401 AUDIT_NONCE_REPLAY
     * Returns false = nonce seen for the first time, written to the rolling window (TTL = 300s)
     */
    checkAndStore(nonce: string): Promise<boolean>;
}

/**
 * In-memory nonce store (default implementation).
 *
 * Single-process safe. Multi-instance deployments must replace it with a shared-storage implementation.
 * Periodic cleanup: scans for expired entries every 60s to prevent unbounded memory growth.
 *
 */
export class InMemoryAuditNonceStore implements AuditNonceStore {
    // nonce -> expiry timestamp (ms)
    private readonly store = new Map<string, number>();

    // Periodic cleanup handle, allowing an external dispose() call to stop it
    private readonly cleanupTimer: ReturnType<typeof setInterval>;

    public constructor(
        private readonly ttlMs: number = NONCE_TTL_MS,
        // Allow injecting a clock so unit tests can control time
        private readonly now: () => number = Date.now,
        cleanupIntervalMs: number = 60_000,
    ) {
        this.cleanupTimer = setInterval(
            () => this._cleanup(),
            cleanupIntervalMs,
        );
        // unref prevents cleanupTimer from keeping the process from exiting
        if (typeof this.cleanupTimer.unref === 'function') {
            this.cleanupTimer.unref();
        }
    }

    public checkAndStore(nonce: string): Promise<boolean> {
        const nowMs = this.now();
        const existing = this.store.get(nonce);
        if (existing !== undefined && existing > nowMs) {
            // nonce already exists within the window -> replay
            return Promise.resolve(true);
        }
        // First occurrence or expired -> write/overwrite
        this.store.set(nonce, nowMs + this.ttlMs);
        return Promise.resolve(false);
    }

    /** Clean up expired entries. */
    private _cleanup(): void {
        const nowMs = this.now();
        for (const [nonce, expiresAt] of this.store) {
            if (expiresAt <= nowMs) {
                this.store.delete(nonce);
            }
        }
    }

    /** Stop the periodic cleanup (for tests/shutdown). */
    public dispose(): void {
        clearInterval(this.cleanupTimer);
    }
}
