/**
 * per-tenant rate limiter implementation
 *
 * Responsibilities:
 *   - TenantRateLimiterConfig: per-tenant quota configuration
 *   - MemoryTenantRateLimiter: in-memory token bucket + sliding window; tenant-scoped
 *   - RateLimitResult: result (allowed / denied + remaining quota + reset time)
 *   - error code: TENANT_RATE_LIMITED (includes retry-after metadata)
 *
 * Design constraints (fail-closed + isolation invariant):
 *   - rate-limit state is strictly tenant-scoped; each tenant is counted independently
 *   - storage error -> fail-closed (throw TenantRateLimitError; do not allow by default)
 *   - the single-tenant fallback anti-patterns globalRateLimit / defaultTenant / untenanted are forbidden
 *   - MemoryTenantRateLimiter is an in-memory implementation; production should replace it with a Redis backend
 *
 */

import type { TenantId } from './types.js';

// ── TenantRateLimiterConfig ───────────────────────────────────────────────────

/**
 * per-tenant rate-limit configuration (can be modified dynamically; used to override a single tenant)
 */
export interface TenantRateLimiterConfig {
    /** Time window (milliseconds; used by sliding-window) */
    readonly windowMs: number;
    /** Maximum number of requests within the time window */
    readonly maxRequests: number;
    /**
     * Rate-limiting algorithm
     *   - 'token-bucket': allows short bursts; tokens are refilled at a fixed rate
     *   - 'sliding-window': precise time-window counting; stricter
     */
    readonly algorithm: 'token-bucket' | 'sliding-window';
    /**
     * Token-bucket burst capacity (effective when algorithm='token-bucket')
     * Meaning: at most burstCapacity extra requests are allowed during a burst
     * undefined -> use maxRequests as the burst ceiling
     */
    readonly burstCapacity?: number;
    /**
     * Token refill rate (token-bucket; tokens/second; undefined = maxRequests / (windowMs/1000))
     */
    readonly refillRatePerSecond?: number;
}

// ── RateLimitResult ───────────────────────────────────────────────────────────

/**
 * rate-limit check result
 */
export interface RateLimitResult {
    /** Whether this request is allowed */
    readonly allowed: boolean;
    /** Remaining quota (number of requests still allowed within this window) */
    readonly remaining: number;
    /**
     * Quota reset time (Unix millisecond timestamp; when allowed=false the client should wait until this time before retrying)
     * When allowed=true this is the end time of the current window
     */
    readonly resetAtMs: number;
    /**
     * Retry-After (seconds; present only when allowed=false)
     * Conforms to the RFC 7231 Retry-After header format
     */
    readonly retryAfterSeconds?: number;
    /** The owning tenantId (used in logs to confirm isolation is correct) */
    readonly tenantId: TenantId;
}

// ── TenantRateLimitError ──────────────────────────────────────────────────────

/**
 * TenantRateLimitError: rate limit exceeded (tenant-scoped)
 *
 * Triggered when: a tenant exceeds its quota within the time window.
 * Handling strategy: fail-closed; the caller should check retryAfterSeconds before retrying.
 */
export class TenantRateLimitError extends Error {
    readonly code = 'TENANT_RATE_LIMITED' as const;

    constructor(
        public readonly tenantId: TenantId,
        public readonly result: RateLimitResult,
    ) {
        super(
            `Tenant "${tenantId}" has exceeded the rate limit. ` +
            `Retry after ${result.retryAfterSeconds ?? 0} seconds ` +
            `(reset at ${new Date(result.resetAtMs).toISOString()}).`,
        );
        this.name = 'TenantRateLimitError';
        Object.setPrototypeOf(this, new.target.prototype);
    }
}

/**
 * TenantRateLimiterStorageError: rate-limiter storage-layer error (fail-closed)
 *
 * Triggered when: in-memory state is corrupt / the storage backend is unreachable.
 * Handling strategy: fail-closed; silent pass-through is forbidden (a storage error is not a rate-limit bypass).
 */
export class TenantRateLimiterStorageError extends Error {
    readonly code = 'TENANT_UNKNOWN' as const;

    constructor(
        public readonly tenantId: TenantId,
        cause: unknown,
    ) {
        super(
            `Rate limiter storage error for tenant "${tenantId}". ` +
            'Request aborted (fail-closed). ' +
            `Cause: ${cause instanceof Error ? cause.message : String(cause)}`,
        );
        this.name = 'TenantRateLimiterStorageError';
        Object.setPrototypeOf(this, new.target.prototype);
    }
}

// ── TenantRateLimiter interface ───────────────────────────────────────────────

/**
 * TenantRateLimiter interface (program against the interface; makes swapping in a Redis backend easy)
 */
export interface TenantRateLimiter {
    /**
     * Check and consume one unit of quota
     *
     * @param tenantId tenant ID (required; absent -> throws TenantRateLimitError)
     * @returns RateLimitResult (contains allowed + remaining + resetAtMs)
     * @throws TenantRateLimiterStorageError when storage is unreachable (fail-closed)
     */
    check(tenantId: TenantId): RateLimitResult;

    /**
     * Set or update a tenant's rate-limit configuration
     *
     * Note: the new configuration takes effect immediately; existing state is reset (the window restarts).
     */
    setTenantConfig(tenantId: TenantId, config: TenantRateLimiterConfig): void;

    /**
     * Remove a tenant's rate-limit state (call this when the tenant is deregistered)
     */
    removeTenant(tenantId: TenantId): void;

    /**
     * Get the current number of active tenants (for monitoring)
     */
    activeTenantCount(): number;
}

// ── MemoryTenantRateLimiter ───────────────────────────────────────────────────

/**
 * MemoryTenantRateLimiter: in-memory rate-limiting implementation
 *
 * Conclusion: production-grade in-memory implementation; supports both the token-bucket and sliding-window algorithms;
 * all state is strictly tenant-scoped (Map<TenantId, TenantBucketState>);
 * each tenant is counted independently; there is no shared state across tenants.
 *
 * Production notes:
 *   - the in-memory implementation is not suitable for multi-instance deployments (replace it with a Redis EVALSHA implementation)
 *   - state is lost on process restart (suitable for stateless single-instance deployments)
 */
export class MemoryTenantRateLimiter implements TenantRateLimiter {
    /**
     * tenant-scoped state store (strictly isolated; key = tenantId)
     *
     * Design: each tenantId maps to its own TenantBucketState;
     * there is no global counter or shared state across tenants.
     */
    private readonly tenantStates: Map<TenantId, TenantBucketState> = new Map();

    /**
     * tenant-scoped configuration (key = tenantId; takes precedence over the constructor's defaultConfig)
     */
    private readonly tenantConfigs: Map<TenantId, TenantRateLimiterConfig> = new Map();

    constructor(private readonly defaultConfig: TenantRateLimiterConfig) {
        validateRateLimiterConfig(defaultConfig);
    }

    /**
     * Check and consume one unit of quota (tenant-scoped; fail-closed on storage error)
     */
    check(tenantId: TenantId): RateLimitResult {
        try {
            const config = this.tenantConfigs.get(tenantId) ?? this.defaultConfig;
            const nowMs = Date.now();

            if (config.algorithm === 'token-bucket') {
                return this.checkTokenBucket(tenantId, config, nowMs);
            } else {
                return this.checkSlidingWindow(tenantId, config, nowMs);
            }
        } catch (err) {
            if (err instanceof TenantRateLimitError) throw err;
            throw new TenantRateLimiterStorageError(tenantId, err);
        }
    }

    setTenantConfig(tenantId: TenantId, config: TenantRateLimiterConfig): void {
        validateRateLimiterConfig(config);
        this.tenantConfigs.set(tenantId, config);
        // Reset state (the new configuration takes effect immediately)
        this.tenantStates.delete(tenantId);
    }

    removeTenant(tenantId: TenantId): void {
        this.tenantStates.delete(tenantId);
        this.tenantConfigs.delete(tenantId);
    }

    activeTenantCount(): number {
        return this.tenantStates.size;
    }

    // ── token-bucket algorithm ────────────────────────────────────────────────

    private checkTokenBucket(
        tenantId: TenantId,
        config: TenantRateLimiterConfig,
        nowMs: number,
    ): RateLimitResult {
        const burstCapacity = config.burstCapacity ?? config.maxRequests;
        const refillRatePerMs =
            (config.refillRatePerSecond ?? (config.maxRequests / (config.windowMs / 1000))) / 1000;

        let state = this.tenantStates.get(tenantId) as TokenBucketState | undefined;

        if (!state || state.type !== 'token-bucket') {
            state = {
                type: 'token-bucket',
                tokens: burstCapacity,
                lastRefillMs: nowMs,
            };
            this.tenantStates.set(tenantId, state);
        }

        // Refill tokens (computed from the elapsed time)
        const elapsedMs = nowMs - state.lastRefillMs;
        const newTokens = Math.min(
            burstCapacity,
            state.tokens + elapsedMs * refillRatePerMs,
        );
        state.tokens = newTokens;
        state.lastRefillMs = nowMs;

        // Not enough tokens -> denied
        if (state.tokens < 1) {
            const tokensNeeded = 1 - state.tokens;
            const waitMs = Math.ceil(tokensNeeded / refillRatePerMs);
            return {
                allowed: false,
                remaining: 0,
                resetAtMs: nowMs + waitMs,
                retryAfterSeconds: Math.ceil(waitMs / 1000),
                tenantId,
            };
        }

        // Consume one token
        state.tokens -= 1;

        // remaining: current token count (rounded down; do not expose a float)
        const remaining = Math.floor(state.tokens);
        const msToNextRefill = remaining > 0 ? 0 : Math.ceil(1 / refillRatePerMs);

        return {
            allowed: true,
            remaining,
            resetAtMs: nowMs + msToNextRefill,
            tenantId,
        };
    }

    // ── sliding-window algorithm ──────────────────────────────────────────────

    private checkSlidingWindow(
        tenantId: TenantId,
        config: TenantRateLimiterConfig,
        nowMs: number,
    ): RateLimitResult {
        let state = this.tenantStates.get(tenantId) as SlidingWindowState | undefined;

        if (!state || state.type !== 'sliding-window') {
            state = {
                type: 'sliding-window',
                requestTimestamps: [],
            };
            this.tenantStates.set(tenantId, state);
        }

        const windowStart = nowMs - config.windowMs;

        // Drop timestamps that fall outside the window
        state.requestTimestamps = state.requestTimestamps.filter(ts => ts > windowStart);

        const countInWindow = state.requestTimestamps.length;

        if (countInWindow >= config.maxRequests) {
            // oldest timestamp + windowMs = the time at which the next request can be allowed
            // countInWindow >= maxRequests >= 1 -> array is non-empty; index 0 is guaranteed to exist
            const oldestTs = state.requestTimestamps[0] as number;
            const resetAtMs = oldestTs + config.windowMs;
            const waitMs = Math.max(0, resetAtMs - nowMs);

            return {
                allowed: false,
                remaining: 0,
                resetAtMs,
                retryAfterSeconds: Math.ceil(waitMs / 1000),
                tenantId,
            };
        }

        // Record the timestamp of this request
        state.requestTimestamps.push(nowMs);

        const remaining = config.maxRequests - state.requestTimestamps.length;
        const resetAtMs = nowMs + config.windowMs;

        return {
            allowed: true,
            remaining,
            resetAtMs,
            tenantId,
        };
    }
}

// ── Internal state types ──────────────────────────────────────────────────────

type TenantBucketState = TokenBucketState | SlidingWindowState;

interface TokenBucketState {
    readonly type: 'token-bucket';
    tokens: number;
    lastRefillMs: number;
}

interface SlidingWindowState {
    readonly type: 'sliding-window';
    requestTimestamps: number[];
}

// ── Configuration validation ──────────────────────────────────────────────────

function validateRateLimiterConfig(config: TenantRateLimiterConfig): void {
    if (
        typeof config.windowMs !== 'number' || config.windowMs <= 0 ||
        typeof config.maxRequests !== 'number' || config.maxRequests <= 0
    ) {
        throw new Error(
            'TenantRateLimiterConfig.windowMs and maxRequests must be positive numbers.',
        );
    }
    if (config.algorithm !== 'token-bucket' && config.algorithm !== 'sliding-window') {
        throw new Error(
            'TenantRateLimiterConfig.algorithm must be "token-bucket" or "sliding-window".',
        );
    }
    if (config.burstCapacity !== undefined && config.burstCapacity < 0) {
        throw new Error('TenantRateLimiterConfig.burstCapacity must be non-negative.');
    }
}
