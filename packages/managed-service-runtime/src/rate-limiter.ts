/**
 * Rate limiter: in-memory token bucket, switching the key by tier (IP / api_key_id).
 *
 * Design notes (conclusion first, details after):
 * 1. No Redis introduced: single-instance deployment is sufficient for the alpha stage (when scaling horizontally,
 *    use sticky sessions or migrate to Redis; see the scale-up path in SLO.md). In-memory limiting fully covers
 *    the single-pod scenario.
 * 2. Token bucket algorithm:
 *    - initialize max tokens = quota.max
 *    - each request consumes 1 token; if insufficient -> 429 + Retry-After header
 *    - refill rate = quota.max / quota.windowMs, replenished lazily based on elapsed time
 * 3. FREE tier limiting key = client IP (auth has injected req.auth.clientIp);
 *    PRO tier limiting key = api_key.id (prevents multiple keys of the same tenant from sharing one bucket).
 * 4. bucket map size cap = 10000: when exceeded, drop the least-recently-accessed bucket (a simplified LRU,
 *    preventing a DDoS from blowing up the map and causing OOM). Sufficient for the alpha stage; switch to Redis when scaling in production.
 * 5. fail-closed: when the rate limit is hit, respond with **429 immediately** and do not let next() through.
 *
 */

import type { Response, NextFunction } from 'express';

import type { AuthenticatedRequest, RateLimitQuota, Tier } from './types.js';

/** Default quotas */
export const DEFAULT_QUOTAS: Record<Tier, RateLimitQuota> = {
    FREE: { windowMs: 60_000, max: 100 },
    PRO: { windowMs: 60_000, max: 10_000 },
};

/** Bucket map size cap (prevents DDoS OOM) */
const DEFAULT_MAX_BUCKETS = 10_000;

interface Bucket {
    tokens: number;
    /** Time of the last refill (ms) */
    lastRefill: number;
    /** Time of the last access (ms), used for LRU eviction */
    lastAccess: number;
}

/** rate-limiter configuration */
export interface RateLimiterConfig {
    /** Custom quotas; defaults to DEFAULT_QUOTAS */
    quotas?: Partial<Record<Tier, RateLimitQuota>>;
    /** Inject a clock for testing; defaults to => Date.now() */
    now?: () => number;
    /** Bucket cap; defaults to 10_000 */
    maxBuckets?: number;
    /**
     * Force the PRO tier to be downgraded to FREE.
     *
     * Defaults to true: the limiter is mounted before auth → a real PRO API key
     * always hits the pre-auth IP/FREE bucket; without the downgrade, the "PRO quota 10000/min"
     * promise would not match actual behavior. Until a true two-stage limiter is implemented
     * (distributed Redis + a post-auth PRO bucket), forcing forceFreeTierOnly=true keeps the
     * promise consistent with reality.
     *
     * Upgrade path: once a true PRO tier is implemented, change the default to false and allow callers
     * to explicitly opt in to the PRO tier based on their deployment topology (reverse proxy in place / Redis enabled).
     */
    forceFreeTierOnly?: boolean;
}

/**
 * Create the rate-limit middleware.
 *
 * **Mounting order**:
 * - A single limiter is mounted **before** the auth-middleware (anti-token-DDoS: avoids invalid Bearer tokens hitting the DB lookup)
 * - The quota is computed by IP (pre-auth path); after auth injects req.auth the bucket key switches to
 *   `pro:${apiKey.id}` or `free:${clientIp}`, but because this middleware runs before auth,
 *   in practice every request takes the pre-auth path and is metered by IP+FREE
 *
 * **Single-limiter design trade-off**:
 * - Does not use a `postAuthProOnly` two-limiter chain
 * - Reason: a two-chain setup would still trap a PRO tenant at the first FREE 100/min gate (the NAT-shared-IP scenario)
 * - Perfect tier-aware distributed rate limiting is deferred to a later stage (requires Redis + a reverse proxy in place)
 *
 * Degradation strategy (auth missing):
 * - req.auth does not exist (pre-auth call) → default FREE tier
 * - limiting key = `pre-auth:${client_ip}`
 * - prevents an attacker with invalid tokens from breaking through the limit by rotating the Bearer (the key is determined by IP)
 *
 * When the limit is hit, returns:
 * - HTTP 429
 * - body: { error: { code: 'RATE_LIMIT_EXCEEDED', message } }
 * - header: Retry-After (seconds, rounded up)
 */
export function createRateLimiter(config: RateLimiterConfig = {}) {
    const quotas: Record<Tier, RateLimitQuota> = {
        FREE: config.quotas?.FREE ?? DEFAULT_QUOTAS.FREE,
        PRO: config.quotas?.PRO ?? DEFAULT_QUOTAS.PRO,
    };
    const now = config.now ?? (() => Date.now());
    const maxBuckets = config.maxBuckets ?? DEFAULT_MAX_BUCKETS;
    // Force PRO down to FREE by default, keeping the promise consistent with reality
    const forceFreeTierOnly = config.forceFreeTierOnly ?? true;

    // Shared bucket map (rate-limit state is shared within the middleware instance)
    const buckets = new Map<string, Bucket>();

    return function rateLimitMiddleware(
        req: AuthenticatedRequest,
        res: Response,
        next: NextFunction,
    ): void {
        const auth = req.auth;

        // When auth is missing (pre-auth call), rate-limit using the IP+FREE quota
        // Prevents an attacker with invalid tokens from bypassing the FREE limit via random Bearer tokens
        // When forceFreeTierOnly=true, force PRO down to FREE
        // (the limiter being mounted before auth causes a PRO key to always hit the pre-auth FREE bucket, so the promise would not match reality)
        const requestedTier: Tier = auth?.tier ?? 'FREE';
        const tier: Tier = forceFreeTierOnly ? 'FREE' : requestedTier;
        const quota = quotas[tier];
        const key = buildBucketKey(auth, req);

        const currentMs = now();
        const bucket = getOrCreateBucket(
            buckets,
            key,
            quota,
            currentMs,
            maxBuckets,
        );

        // Lazy refill
        refillBucket(bucket, quota, currentMs);
        bucket.lastAccess = currentMs;

        if (bucket.tokens < 1) {
            const retryAfterSec = computeRetryAfter(bucket, quota, currentMs);
            res.setHeader('Retry-After', retryAfterSec.toString());
            res.status(429).json({
                error: {
                    code: 'RATE_LIMIT_EXCEEDED',
                    message: `Rate limit exceeded for tier ${tier} (${quota.max} req / ${quota.windowMs}ms).`,
                },
            });
            return;
        }

        bucket.tokens -= 1;
        next();
    };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function buildBucketKey(
    auth: AuthenticatedRequest['auth'],
    req: AuthenticatedRequest,
): string {
    // PRO tier is rate-limited by api_key.id; FREE tier is rate-limited by IP
    if (auth?.tier === 'PRO' && auth.apiKey) {
        return `pro:${auth.apiKey.id}`;
    }
    if (auth?.clientIp) {
        return `free:${auth.clientIp}`;
    }
    // Pre-auth path (auth does not exist): take the IP from req.ip
    // Express's req.ip defaults to connection.remoteAddress or X-Forwarded-For (once trust proxy is configured)
    const ip = req.ip ?? req.socket?.remoteAddress ?? 'unknown';
    return `pre-auth:${ip}`;
}

function getOrCreateBucket(
    buckets: Map<string, Bucket>,
    key: string,
    quota: RateLimitQuota,
    nowMs: number,
    maxBuckets: number,
): Bucket {
    const existing = buckets.get(key);
    if (existing) {
        return existing;
    }

    // map full -> evict the least-recently-accessed (a simplified O(n) version; sufficient for the alpha stage)
    if (buckets.size >= maxBuckets) {
        evictOldest(buckets);
    }

    const fresh: Bucket = {
        tokens: quota.max,
        lastRefill: nowMs,
        lastAccess: nowMs,
    };
    buckets.set(key, fresh);
    return fresh;
}

function evictOldest(buckets: Map<string, Bucket>): void {
    let oldestKey: string | null = null;
    let oldestAccess = Infinity;
    for (const [k, v] of buckets) {
        if (v.lastAccess < oldestAccess) {
            oldestAccess = v.lastAccess;
            oldestKey = k;
        }
    }
    if (oldestKey !== null) {
        buckets.delete(oldestKey);
    }
}

function refillBucket(
    bucket: Bucket,
    quota: RateLimitQuota,
    nowMs: number,
): void {
    const elapsed = nowMs - bucket.lastRefill;
    if (elapsed <= 0) {
        return;
    }

    // Refill to a full bucket each window; replenish linearly in proportion to elapsed time
    const refillAmount = (elapsed / quota.windowMs) * quota.max;
    bucket.tokens = Math.min(quota.max, bucket.tokens + refillAmount);
    bucket.lastRefill = nowMs;
}

function computeRetryAfter(
    bucket: Bucket,
    quota: RateLimitQuota,
    nowMs: number,
): number {
    // Compute the milliseconds needed to replenish 1 token
    const refillRatePerMs = quota.max / quota.windowMs;
    const tokensNeeded = 1 - bucket.tokens;
    if (tokensNeeded <= 0) {
        return 0;
    }
    const msNeeded = tokensNeeded / refillRatePerMs;
    // Round up to seconds
    void nowMs;
    return Math.max(1, Math.ceil(msNeeded / 1000));
}

/**
 * For testing / debugging: export the current bucket state.
 *
 * **Test-only**; the production path should not depend on this interface (rate-limit state is an implementation detail).
 */
export function snapshotBuckets(
    middleware: ReturnType<typeof createRateLimiter>,
): unknown {
    // The middleware closure does not expose buckets; this function is reserved as a future hook and currently returns 'opaque'.
    void middleware;
    return 'opaque';
}
