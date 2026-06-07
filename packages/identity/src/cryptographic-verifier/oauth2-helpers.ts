/**
 * oauth2-helpers — OAuth2 introspection cache + circuit breaker + rate limiter
 *
 * Summary: three helper classes wrap the latency / resilience / anti-abuse logic of the OAuth2 introspection endpoint,
 * for verifyOAuth2AndDeriveDid to call.
 *
 * Basis:
 *   - sdk v0.2 (aligned cache + circuit breaker + rate limiter)
 *   - PKI threat model STRIDE DoS dimension (circuit breaker + rate limiter)
 *   - default parameters: 60s TTL cache + 5-failure circuit breaker + 100 req/s token bucket
 *
 * Security constraints:
 *   - OAuth2IntrospectionCache: cache key = SHA-256(trust-authority ‖ accessToken) — does not store token plaintext
 *     + bound to the trust authority (endpoint origin + client id + expected audience), preventing cross-authority reuse
 *   - OAuth2IntrospectionCache: cache expiry = min(now + cacheTtl, response.exp) — prevents stale active tokens
 *   - OAuth2CircuitBreaker: when OPEN, fail-closed throw SDK_OAUTH2_VERIFY_FAILED — no upstream-timeout degradation allowed
 *   - OAuth2RateLimiter: token bucket — on exceed, fail-closed throw SDK_OAUTH2_VERIFY_FAILED
 */

import type * as oauth from 'openid-client';
import { SdkError } from '@coivitas/types';

// ─── OAuth2IntrospectionCache ─────────────────────────────────────────────────

/**
 * OAuth2IntrospectionCache — introspection response cache with SHA-256 key + TTL expiry
 *
 * Summary: cache key = SHA-256(trust-authority ‖ accessToken), preventing token plaintext from lingering in memory
 * and binding to the trust authority.
 * cache expiry = min(now + cacheTtlMs, response.exp * 1000), preventing an expired active=true token from hitting the cache.
 * Inactive tokens (active !== true) do not enter the cache — every call goes to a real introspection.
 *
 * @example
 * const cache = new OAuth2IntrospectionCache(60); // 60s TTL
 * const response = await cache.getOrIntrospect(authority, accessToken, (token) => introspectRPC(token));
 */
/**
 * OAuth2TrustAuthority — trust-domain binding for the introspection cache key
 *
 * A cache hit must share the same trust authority; otherwise an attacker could introspect a token against a self-controlled endpoint
 * and then reuse the cache hit in another verifier context to skip the real endpoint.
 */
export interface OAuth2TrustAuthority {
    /** OIDC issuer URL — the real network authority (discovery entry point); the primary key for cross-issuer reuse protection*/
    readonly issuerUrl: string;
    /** introspection endpoint URL (origin determines the trust domain)*/
    readonly introspectionEndpoint: string;
    /** introspection client id (RS identity)*/
    readonly introspectionClientId: string;
    /** expected audience (the resource the token is bound to)*/
    readonly expectedAudience: string;
}

export class OAuth2IntrospectionCache {
    private readonly cache = new Map<
        string,
        { response: oauth.IntrospectionResponse; expiresAt: number }
    >();
    private readonly cacheTtlMs: number;

    constructor(cacheTtlSeconds = 60) {
        this.cacheTtlMs = cacheTtlSeconds * 1000;
    }

    /**
     * getOrIntrospect — on cache hit returns the cached response; on miss calls the introspect callback + writes the cache
     *
     * Summary: the cache key is a SHA-256(trust-authority ‖ token) hex string; on a hit that has not expired, return directly;
     * on a miss, call introspect, and if response.active === true write the cache with expiry = min(cacheTtl, token.exp).
     * The cache key is bound to the trust authority, preventing cross-endpoint/audience reuse.
     *
     * @param authority trust authority binding (endpoint + client id + expected audience)
     * @param accessToken the raw access token string
     * @param introspect the real introspection call callback
     */
    async getOrIntrospect(
        authority: OAuth2TrustAuthority,
        accessToken: string,
        introspect: (token: string) => Promise<oauth.IntrospectionResponse>,
    ): Promise<oauth.IntrospectionResponse> {
        const cacheKey = await this.computeCacheKey(authority, accessToken);
        const cached = this.cache.get(cacheKey);

        // cache hit and not expired -> return directly (latency reduction)
        if (cached && cached.expiresAt > Date.now()) {
            return cached.response;
        }

        // cache miss / expired -> call the real introspection
        const response = await introspect(accessToken);

        // Only write the cache for active=true tokens; inactive tokens are not cached (anti stale trust)
        if (response.active === true) {
            const respExpMs = response.exp ? response.exp * 1000 : Infinity;
            const expiresAt = Math.min(Date.now() + this.cacheTtlMs, respExpMs);
            // Only store responses that have not yet expired (prevents caching a token with exp < now)
            if (expiresAt > Date.now()) {
                this.cache.set(cacheKey, { response, expiresAt });
            }
        }

        return response;
    }

    /**
     * invalidate — forcibly clear the cache entry for a given token (token revoke event handler)
     *
     * Summary: called when an external revoke event arrives, ensuring the next introspect call goes to the real network.
     * Asynchronously computes the SHA-256 key and then deletes it; no-op if the key does not exist.
     */
    invalidate(authority: OAuth2TrustAuthority, accessToken: string): void {
        // Asynchronously compute the key + delete (the revoke event handler does not need to await)
        void this.computeCacheKey(authority, accessToken).then((key) =>
            this.cache.delete(key),
        );
    }

    /**
     * computeCacheKey — SHA-256(authority-binding ‖ accessToken) hex string
     *
     * Summary: uses the Web Crypto API (crypto.subtle built into Node 20+); does not store token plaintext.
     * The key prefix includes the trust authority (issuer + endpoint + client id + audience),
     * separated by \x1f (unit separator) to avoid field-concatenation ambiguity; the same token under different authorities yields different keys.
     * issuerUrl is the real network authority (discovery entry point); without it, issuer A's cache could be reused by issuer B.
     */
    private async computeCacheKey(
        authority: OAuth2TrustAuthority,
        accessToken: string,
    ): Promise<string> {
        const SEP = '\x1f';
        const keyMaterial =
            authority.issuerUrl +
            SEP +
            authority.introspectionEndpoint +
            SEP +
            authority.introspectionClientId +
            SEP +
            authority.expectedAudience +
            SEP +
            accessToken;
        const bytes = new TextEncoder().encode(keyMaterial);
        const hashBytes = await crypto.subtle.digest('SHA-256', bytes);
        return Buffer.from(hashBytes).toString('hex');
    }
}

// ─── OAuth2CircuitBreaker ──────────────────────────────────────────────────────

/**
 * CircuitState — circuit breaker state machine
 *
 * - CLOSED: normal calls; consecutive failure count accumulates
 * - OPEN: consecutive failures exceeded the threshold; within cooldown, fail-closed and do not call upstream
 * - HALF_OPEN: entered after cooldown ends; allows 1 probe call; success -> CLOSED; failure -> OPEN
 */
type CircuitState = 'CLOSED' | 'OPEN' | 'HALF_OPEN';

/**
 * OAuth2CircuitBreaker — introspection endpoint circuit breaker (STRIDE DoS mitigation)
 *
 * Summary: failureThreshold consecutive failures -> OPEN state + fail-closed; HALF_OPEN probe after cooldown.
 * State machine transitions:
 *   CLOSED -> OPEN: failCount >= failureThreshold
 *   OPEN -> HALF_OPEN: cooldown elapsed (Date.now() - openedAt >= cooldownMs)
 *   HALF_OPEN -> CLOSED: probe succeeded
 *   HALF_OPEN -> OPEN: probe failed + cooldown reset
 *
 * Security constraint: when OPEN, execute() throws SDK_OAUTH2_VERIFY_FAILED without calling the operation callback — fail-closed.
 *
 * @example
 * const cb = new OAuth2CircuitBreaker(5, 60);
 * const result = await cb.execute(() => introspectRPC(token));
 */
export class OAuth2CircuitBreaker {
    private state: CircuitState = 'CLOSED';
    private failCount = 0;
    private openedAt = 0;
    private readonly failureThreshold: number;
    private readonly cooldownMs: number;

    constructor(failureThreshold = 5, cooldownSeconds = 60) {
        this.failureThreshold = failureThreshold;
        this.cooldownMs = cooldownSeconds * 1000;
    }

    /**
     * execute — run the operation under the circuit breaker state machine
     *
     * Summary:
     *   - OPEN and cooldown not yet elapsed -> immediately throw SDK_OAUTH2_VERIFY_FAILED (operation not called)
     *   - OPEN and cooldown elapsed -> transition to HALF_OPEN + run the operation
     *   - run succeeds -> CLOSED + failCount reset to zero
     *   - run fails -> failCount++ + if >= threshold transition to OPEN; a HALF_OPEN failure also transitions to OPEN
     */
    async execute<T>(operation: () => Promise<T>): Promise<T> {
        // Step 1: state machine — cooldown check when OPEN
        if (this.state === 'OPEN') {
            if (Date.now() - this.openedAt >= this.cooldownMs) {
                // cooldown elapsed -> allow 1 HALF_OPEN probe
                this.state = 'HALF_OPEN';
            } else {
                // cooldown not elapsed -> fail-closed (do not call upstream)
                throw new SdkError(
                    'SDK_OAUTH2_VERIFY_FAILED',
                    `OAuth2 introspection circuit breaker OPEN — fail-closed (failCount=${this.failCount}; cooldownMs=${this.cooldownMs}; upstream may be down)`,
                );
            }
        }

        // Step 2: run the operation
        try {
            const result = await operation();
            // success -> CLOSED + failCount reset to zero
            this.state = 'CLOSED';
            this.failCount = 0;
            return result;
        } catch (err) {
            // failure -> failCount++ + state transition
            this.failCount++;

            if (this.state === 'HALF_OPEN') {
                // HALF_OPEN probe failed -> back to OPEN + cooldown reset
                this.state = 'OPEN';
                this.openedAt = Date.now();
            } else if (this.failCount >= this.failureThreshold) {
                // CLOSED -> OPEN threshold triggered
                this.state = 'OPEN';
                this.openedAt = Date.now();
            }

            throw err;
        }
    }

    /**
     * getState — query the current circuit breaker state (for external monitoring / alerting)
     */
    getState(): { state: CircuitState; failCount: number; openedAt: number } {
        return {
            state: this.state,
            failCount: this.failCount,
            openedAt: this.openedAt,
        };
    }
}

// ─── OAuth2RateLimiter ────────────────────────────────────────────────────────

/**
 * OAuth2RateLimiter — token bucket rate limiter (introspection endpoint anti-abuse)
 *
 * Summary: token bucket algorithm; capacity = maximum burst; refillPerSec = steady fill rate.
 * Each consume() call consumes 1 token; when insufficient, throw SDK_OAUTH2_VERIFY_FAILED (fail-closed).
 * Refill is computed dynamically from the time delta (not an interval setInterval; no timer leak).
 *
 * @example
 * const limiter = new OAuth2RateLimiter(100, 100); // 100 req/s burst + refill
 * limiter.consume(); // throws if rate exceeded
 */
export class OAuth2RateLimiter {
    private tokens: number;
    private lastRefill: number;
    private readonly capacity: number;
    private readonly refillPerSec: number;

    constructor(capacity = 100, refillPerSec = 100) {
        this.capacity = capacity;
        this.refillPerSec = refillPerSec;
        this.tokens = capacity;
        this.lastRefill = Date.now();
    }

    /**
     * consume — consume 1 token; when insufficient, throw SDK_OAUTH2_VERIFY_FAILED
     *
     * Summary: refill first (replenish tokens by the time delta), then consume 1; fail-closed when tokens < 1.
     * Refill is capped at capacity (preventing tokens from accumulating unbounded after a long idle period).
     */
    consume(): void {
        const now = Date.now();
        const elapsedSec = (now - this.lastRefill) / 1000;

        // refill tokens (capped at capacity; anti-overflow)
        this.tokens = Math.min(
            this.capacity,
            this.tokens + elapsedSec * this.refillPerSec,
        );
        this.lastRefill = now;

        if (this.tokens < 1) {
            throw new SdkError(
                'SDK_OAUTH2_VERIFY_FAILED',
                `OAuth2 introspection rate limit exceeded (capacity=${this.capacity} refill=${this.refillPerSec}/s)`,
            );
        }

        this.tokens -= 1;
    }
}
