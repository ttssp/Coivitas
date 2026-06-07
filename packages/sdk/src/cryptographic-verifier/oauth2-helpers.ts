/**
 * OAuth2 introspection helpers
 *
 * Summary: three classes — OAuth2IntrospectionCache + OAuth2CircuitBreaker + OAuth2RateLimiter —
 *          covering RFC 7662 recommendations + DoS-dimension mitigation.
 *
 * Design notes:
 * - cache: TTL ≤ 60s (RFC 7662 recommends 30-300s; conservatively 60s)
 *   cache key = SHA-256(accessToken) (does not store the token plaintext)
 *   cache expiry = min(now + ttl, response.exp)
 * - circuit breaker: CLOSED → OPEN (after failureThreshold consecutive failures) → HALF_OPEN (probe after cooldown)
 * - rate limiter: token bucket (capacity + refill rate)
 */

import * as oauth from 'openid-client';

import { SdkError } from './errors.js';

type IntrospectionResponse = oauth.IntrospectionResponse;

/**
 * OAuth2IntrospectionCache — introspection response cache with TTL
 *
 * Design intent:
 * - cache TTL ≤ 60s (within the RFC 7662 recommended range; conservative upper bound)
 * - cache key = SHA-256(accessToken) → hex string (does not store the token plaintext)
 * - cache hit → skip the introspection RTT; miss → real introspection call
 * - cache expiry = min(now + cacheTtl, response.exp); if response.exp < now, do not cache
 */
export class OAuth2IntrospectionCache {
    private readonly cache = new Map<
        string,
        { response: IntrospectionResponse; expiresAt: number }
    >();
    private readonly cacheTtlMs: number;

    public constructor(cacheTtlSeconds = 60) {
        this.cacheTtlMs = cacheTtlSeconds * 1000;
    }

    /**
     * getOrIntrospect — return directly on cache hit; on miss invoke the introspect callback
     *
     * @param accessToken OAuth2 access token (Bearer)
     * @param introspect the real introspection call (injected by the caller)
     */
    public async getOrIntrospect(
        accessToken: string,
        introspect: (token: string) => Promise<IntrospectionResponse>,
    ): Promise<IntrospectionResponse> {
        const cacheKey = await this.computeCacheKey(accessToken);
        const cached = this.cache.get(cacheKey);

        if (cached && cached.expiresAt > Date.now()) {
            return cached.response;
        }

        const response = await introspect(accessToken);

        // only cache when active === true
        if (response.active === true) {
            const respExpMs =
                typeof response.exp === 'number'
                    ? response.exp * 1000
                    : Number.POSITIVE_INFINITY;
            const expiresAt = Math.min(Date.now() + this.cacheTtlMs, respExpMs);
            if (expiresAt > Date.now()) {
                this.cache.set(cacheKey, { response, expiresAt });
            }
        }

        return response;
    }

    /** invalidate a single entry (token revoke event handler)*/
    public async invalidate(accessToken: string): Promise<void> {
        const key = await this.computeCacheKey(accessToken);
        this.cache.delete(key);
    }

    /** invalidate the entire cache (testing / forced refresh)*/
    public clear(): void {
        this.cache.clear();
    }

    private async computeCacheKey(accessToken: string): Promise<string> {
        const bytes = new TextEncoder().encode(accessToken);
        const hashBytes = await crypto.subtle.digest('SHA-256', bytes);
        return Buffer.from(hashBytes).toString('hex');
    }
}

/** circuit breaker state (CLOSED → OPEN → HALF_OPEN → CLOSED loop)*/
export type CircuitState = 'CLOSED' | 'OPEN' | 'HALF_OPEN';

/**
 * OAuth2CircuitBreaker — introspection endpoint circuit breaker (DoS mitigation)
 *
 * State machine:
 * - CLOSED: normal calls; fail count = 0
 * - OPEN: after failureThreshold (default 5) consecutive failures → open the circuit for 60s + fail-closed
 *   (the caller throws SDK_OAUTH2_VERIFY_FAILED without calling upstream)
 * - HALF_OPEN: allow 1 probe after cooldown; success → CLOSED; failure → OPEN with the cooldown reset
 */
export class OAuth2CircuitBreaker {
    private state: CircuitState = 'CLOSED';
    private failCount = 0;
    private openedAt = 0;
    private readonly failureThreshold: number;
    private readonly cooldownMs: number;

    public constructor(failureThreshold = 5, cooldownSeconds = 60) {
        this.failureThreshold = failureThreshold;
        this.cooldownMs = cooldownSeconds * 1000;
    }

    /**
     * execute — run the operation under circuit-breaker protection
     *
     * @throws SdkError 'SDK_OAUTH2_VERIFY_FAILED' on OPEN state
     */
    public async execute<T>(operation: () => Promise<T>): Promise<T> {
        // Step 1: state machine transition (OPEN → HALF_OPEN once the cooldown has elapsed)
        if (this.state === 'OPEN') {
            if (Date.now() - this.openedAt >= this.cooldownMs) {
                this.state = 'HALF_OPEN';
            } else {
                throw new SdkError(
                    'SDK_OAUTH2_VERIFY_FAILED',
                    'OAuth2 introspection circuit breaker OPEN (fail-closed; upstream may be down)',
                );
            }
        }

        // Step 2: execute operation + transition by outcome
        try {
            const result = await operation();
            // Success → CLOSED state + reset count
            this.state = 'CLOSED';
            this.failCount = 0;
            return result;
        } catch (err) {
            // Failure → increment + state transition
            this.failCount++;
            if (this.failCount >= this.failureThreshold) {
                this.state = 'OPEN';
                this.openedAt = Date.now();
            } else if (this.state === 'HALF_OPEN') {
                this.state = 'OPEN';
                this.openedAt = Date.now();
            }
            throw err;
        }
    }

    public getState(): {
        state: CircuitState;
        failCount: number;
        openedAt: number;
    } {
        return {
            state: this.state,
            failCount: this.failCount,
            openedAt: this.openedAt,
        };
    }
}

/**
 * OAuth2RateLimiter — token bucket rate limiter (introspection endpoint DoS mitigation)
 *
 * Design:
 * - capacity = bucket capacity (default 100); refillPerSec = tokens replenished per second (default 100)
 * - consume() takes 1 token per call; if insufficient → throw SDK_OAUTH2_VERIFY_FAILED
 * - continuous refill over the time window (elapsed * refillPerSec), capped at capacity
 */
export class OAuth2RateLimiter {
    private tokens: number;
    private lastRefill: number;
    private readonly capacity: number;
    private readonly refillPerSec: number;

    public constructor(capacity = 100, refillPerSec = 100) {
        this.capacity = capacity;
        this.refillPerSec = refillPerSec;
        this.tokens = capacity;
        this.lastRefill = Date.now();
    }

    /**
     * consume — take 1 token (before an introspection call)
     *
     * @throws SdkError 'SDK_OAUTH2_VERIFY_FAILED' on rate limit exceeded
     */
    public consume(): void {
        const now = Date.now();
        const elapsed = (now - this.lastRefill) / 1000;
        this.tokens = Math.min(
            this.capacity,
            this.tokens + elapsed * this.refillPerSec,
        );
        this.lastRefill = now;

        if (this.tokens < 1) {
            throw new SdkError(
                'SDK_OAUTH2_VERIFY_FAILED',
                `OAuth2 introspection rate limit exceeded (capacity=${this.capacity}, refill=${this.refillPerSec}/s)`,
            );
        }
        this.tokens -= 1;
    }

    public getAvailableTokens(): number {
        return this.tokens;
    }
}
