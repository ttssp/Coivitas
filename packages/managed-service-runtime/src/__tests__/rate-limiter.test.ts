/**
 * rate-limiter.test.ts
 *
 * Test target: rate-limiter (packages/managed-service-runtime/src/rate-limiter.ts)
 *
 * Coverage strategy:
 * - token bucket behavior (consume + refill)
 * - FREE / PRO rate-limit key difference (IP vs api_key.id)
 * - over limit -> 429 + Retry-After header
 * - LRU eviction
 * - defensive fail-closed (missing auth)
 */

import { describe, expect, it, vi } from 'vitest';

import {
    createRateLimiter,
    DEFAULT_QUOTAS,
    snapshotBuckets,
} from '../rate-limiter.js';
import type { AuthenticatedRequest } from '../types.js';

import type { Response, NextFunction } from 'express';

function makeRes(): Response & {
    statusCode: number;
    body: unknown;
    headers: Record<string, string>;
} {
    let statusCode = 200;
    let body: unknown = null;
    const headers: Record<string, string> = {};
    const res = {
        statusCode,
        body,
        headers,
        status(code: number) {
            statusCode = code;
            (res as unknown as { statusCode: number }).statusCode = code;
            return res;
        },
        json(payload: unknown) {
            body = payload;
            (res as unknown as { body: unknown }).body = payload;
            return res;
        },
        setHeader(name: string, value: string) {
            headers[name] = value;
        },
    } as unknown as Response & {
        statusCode: number;
        body: unknown;
        headers: Record<string, string>;
    };
    return res;
}

function makeReq(
    overrides: Partial<AuthenticatedRequest> = {},
): AuthenticatedRequest {
    return {
        ip: '1.2.3.4',
        socket: { remoteAddress: '1.2.3.4' },
        ...overrides,
    } as AuthenticatedRequest;
}

describe('rate-limiter', () => {
    describe('FREE tier', () => {
        it('should allow up to quota.max consecutive requests then 429', () => {
            const middleware = createRateLimiter({
                quotas: { FREE: { windowMs: 60_000, max: 3 } },
            });
            const req = makeReq({
                auth: {
                    tier: 'FREE',
                    tenant: null,
                    apiKey: null,
                    clientIp: '1.2.3.4',
                },
            });
            const next = vi.fn() as NextFunction;

            // 3 requests should pass
            for (let i = 0; i < 3; i++) {
                const res = makeRes();
                middleware(req, res, next);
            }
            expect(next).toHaveBeenCalledTimes(3);

            // the 4th should return 429
            const res4 = makeRes();
            middleware(req, res4, next);
            expect(next).toHaveBeenCalledTimes(3); // not advanced
            expect(res4.statusCode).toBe(429);
            expect((res4.body as { error: { code: string } }).error.code).toBe(
                'RATE_LIMIT_EXCEEDED',
            );
            expect(res4.headers['Retry-After']).toBeDefined();
        });

        it('should isolate buckets across different IPs', () => {
            const middleware = createRateLimiter({
                quotas: { FREE: { windowMs: 60_000, max: 1 } },
            });
            const next = vi.fn() as NextFunction;

            const reqA = makeReq({
                auth: {
                    tier: 'FREE',
                    tenant: null,
                    apiKey: null,
                    clientIp: '1.1.1.1',
                },
            });
            const reqB = makeReq({
                auth: {
                    tier: 'FREE',
                    tenant: null,
                    apiKey: null,
                    clientIp: '2.2.2.2',
                },
            });

            const res1 = makeRes();
            middleware(reqA, res1, next);
            const res2 = makeRes();
            middleware(reqB, res2, next);

            expect(next).toHaveBeenCalledTimes(2);
            // A's second request is limited
            const res3 = makeRes();
            middleware(reqA, res3, next);
            expect(res3.statusCode).toBe(429);
        });
    });

    describe('PRO tier', () => {
        it('should use api_key.id as bucket key (not IP)', () => {
            // default forceFreeTierOnly=true downgrades PRO to FREE;
            // this test verifies real PRO bucket-key behavior, which requires explicit opt-in
            const middleware = createRateLimiter({
                quotas: { PRO: { windowMs: 60_000, max: 1 } },
                forceFreeTierOnly: false,
            });
            const next = vi.fn() as NextFunction;

            const apiKey = {
                id: 'key-1',
                tenantId: 't1',
                keyHash: 'h',
                keyPrefix: 'p',
                description: null,
                expiresAt: null,
                lastUsedAt: null,
                status: 'ACTIVE',
            } as const;
            const tenant = {
                id: 't1',
                tenantDid: 'did:agent:1',
                tier: 'PRO',
                displayName: 'T',
                contactEmail: null,
                status: 'ACTIVE',
            } as const;

            // two different keys on the same IP
            const reqA = makeReq({
                auth: {
                    tier: 'PRO',
                    tenant,
                    apiKey,
                    clientIp: '1.1.1.1',
                },
            });
            const reqB = makeReq({
                auth: {
                    tier: 'PRO',
                    tenant,
                    apiKey: { ...apiKey, id: 'key-2' },
                    clientIp: '1.1.1.1',
                },
            });

            const res1 = makeRes();
            middleware(reqA, res1, next);
            const res2 = makeRes();
            middleware(reqB, res2, next);

            expect(next).toHaveBeenCalledTimes(2);
            // the second request for the same key is limited
            const res3 = makeRes();
            middleware(reqA, res3, next);
            expect(res3.statusCode).toBe(429);
        });
    });

    describe('refill behavior', () => {
        it('should refill tokens proportionally to elapsed time', () => {
            let nowMs = 1_000_000;
            const middleware = createRateLimiter({
                quotas: { FREE: { windowMs: 60_000, max: 6 } },
                now: () => nowMs,
            });
            const req = makeReq({
                auth: {
                    tier: 'FREE',
                    tenant: null,
                    apiKey: null,
                    clientIp: '9.9.9.9',
                },
            });
            const next = vi.fn() as NextFunction;

            // consume all 6
            for (let i = 0; i < 6; i++) {
                middleware(req, makeRes(), next);
            }
            expect(next).toHaveBeenCalledTimes(6);

            // immediately the 7th -> 429
            const res7 = makeRes();
            middleware(req, res7, next);
            expect(res7.statusCode).toBe(429);

            // after 30s (half a window) -> should refill ~3 tokens
            nowMs += 30_000;
            const res8 = makeRes();
            middleware(req, res8, next);
            expect(next).toHaveBeenCalledTimes(7);
        });

        it('should cap refill at max tokens (no overflow)', () => {
            let nowMs = 1_000_000;
            const middleware = createRateLimiter({
                quotas: { FREE: { windowMs: 60_000, max: 2 } },
                now: () => nowMs,
            });
            const req = makeReq({
                auth: {
                    tier: 'FREE',
                    tenant: null,
                    apiKey: null,
                    clientIp: '8.8.8.8',
                },
            });
            const next = vi.fn() as NextFunction;

            // consume 1
            middleware(req, makeRes(), next);
            // after 10 windows (theoretically refill 20 tokens, but should cap at max=2)
            nowMs += 60_000 * 10;
            // still only 2 consumptions allowed (existing 1 + refill 1 = 2)
            middleware(req, makeRes(), next);
            middleware(req, makeRes(), next);
            const res4 = makeRes();
            middleware(req, res4, next);
            expect(res4.statusCode).toBe(429);
        });
    });

    describe('Retry-After header', () => {
        it('should set Retry-After to integer seconds when limited', () => {
            const middleware = createRateLimiter({
                quotas: { FREE: { windowMs: 60_000, max: 1 } },
            });
            const req = makeReq({
                auth: {
                    tier: 'FREE',
                    tenant: null,
                    apiKey: null,
                    clientIp: '7.7.7.7',
                },
            });
            const next = vi.fn() as NextFunction;

            middleware(req, makeRes(), next);
            const res2 = makeRes();
            middleware(req, res2, next);

            expect(res2.headers['Retry-After']).toMatch(/^\d+$/);
            const seconds = parseInt(res2.headers['Retry-After']!, 10);
            expect(seconds).toBeGreaterThan(0);
        });
    });

    describe('LRU eviction', () => {
        it('should evict oldest bucket when maxBuckets exceeded', () => {
            let nowMs = 1_000_000;
            const middleware = createRateLimiter({
                quotas: { FREE: { windowMs: 60_000, max: 1 } },
                now: () => nowMs,
                maxBuckets: 2,
            });
            const next = vi.fn() as NextFunction;

            // three different IPs fill it up + trigger eviction
            const ips = ['ip-1', 'ip-2', 'ip-3'];
            for (const ip of ips) {
                nowMs += 1;
                middleware(
                    makeReq({
                        auth: {
                            tier: 'FREE',
                            tenant: null,
                            apiKey: null,
                            clientIp: ip,
                        },
                    }),
                    makeRes(),
                    next,
                );
            }
            // all three pass next(); ip-1 should be evicted, and revisiting ip-1 resets its bucket
            expect(next).toHaveBeenCalledTimes(3);

            const res4 = makeRes();
            nowMs += 1;
            middleware(
                makeReq({
                    auth: {
                        tier: 'FREE',
                        tenant: null,
                        apiKey: null,
                        clientIp: 'ip-1',
                    },
                }),
                res4,
                next,
            );
            // the bucket is reset (full bucket, max=1), so it should pass
            expect(next).toHaveBeenCalledTimes(4);
        });
    });

    describe('pre-auth', () => {
        it('should rate-limit by IP when req.auth is missing (FREE tier defaults)', () => {
            // rate-limiter runs before auth; missing auth degrades to IP+FREE rate limiting
            const middleware = createRateLimiter({
                quotas: { FREE: { windowMs: 60_000, max: 2 } },
            });
            const req = makeReq(); // no auth, IP=1.2.3.4
            const next = vi.fn() as NextFunction;

            // 2 requests should pass
            middleware(req, makeRes(), next);
            middleware(req, makeRes(), next);
            expect(next).toHaveBeenCalledTimes(2);

            // the 3rd → 429
            const res3 = makeRes();
            middleware(req, res3, next);
            expect(next).toHaveBeenCalledTimes(2);
            expect(res3.statusCode).toBe(429);
        });

        it('should isolate pre-auth buckets across different IPs', () => {
            // an attacker rotates the token (i.e. a random Bearer) but the same IP is still rate-limited
            const middleware = createRateLimiter({
                quotas: { FREE: { windowMs: 60_000, max: 1 } },
            });
            const next = vi.fn() as NextFunction;

            const reqA = makeReq({
                ip: '10.0.0.1',
                socket: { remoteAddress: '10.0.0.1' },
            } as unknown as Partial<AuthenticatedRequest>);
            const reqB = makeReq({
                ip: '10.0.0.2',
                socket: { remoteAddress: '10.0.0.2' },
            } as unknown as Partial<AuthenticatedRequest>);

            middleware(reqA, makeRes(), next);
            middleware(reqB, makeRes(), next);
            expect(next).toHaveBeenCalledTimes(2);

            // reqA second time → 429 (same IP, quota exhausted)
            const resA2 = makeRes();
            middleware(reqA, resA2, next);
            expect(resA2.statusCode).toBe(429);

            // reqB second time → also 429 (different IP but quota=1)
            const resB2 = makeRes();
            middleware(reqB, resB2, next);
            expect(resB2.statusCode).toBe(429);
        });

        it('should fall back to remoteAddress when req.ip is undefined', () => {
            const middleware = createRateLimiter({
                quotas: { FREE: { windowMs: 60_000, max: 1 } },
            });
            const next = vi.fn() as NextFunction;
            // when ip is unavailable, fall back to socket.remoteAddress
            const req = {
                socket: { remoteAddress: '192.168.1.1' },
            } as unknown as AuthenticatedRequest;

            middleware(req, makeRes(), next);
            expect(next).toHaveBeenCalledOnce();

            const res2 = makeRes();
            middleware(req, res2, next);
            expect(res2.statusCode).toBe(429);
        });

        it('should use "unknown" key when both req.ip and remoteAddress missing', () => {
            const middleware = createRateLimiter({
                quotas: { FREE: { windowMs: 60_000, max: 1 } },
            });
            const next = vi.fn() as NextFunction;
            const req = {} as unknown as AuthenticatedRequest;

            middleware(req, makeRes(), next);
            expect(next).toHaveBeenCalledOnce();
        });
    });

    // the postAuthProOnly test was withdrawn (single-limiter design; fully tier-aware rate limiting is deferred to a later phase)

    describe('default quotas', () => {
        it('should expose DEFAULT_QUOTAS with FREE 100/min and PRO 10000/min', () => {
            expect(DEFAULT_QUOTAS.FREE).toEqual({ windowMs: 60_000, max: 100 });
            expect(DEFAULT_QUOTAS.PRO).toEqual({
                windowMs: 60_000,
                max: 10_000,
            });
        });

        it('should fall back to DEFAULT_QUOTAS when partial config provided', () => {
            // only override FREE; PRO should keep the default 10000
            // testing real PRO quota behavior requires opt-in forceFreeTierOnly=false
            const middleware = createRateLimiter({
                quotas: { FREE: { windowMs: 60_000, max: 1 } },
                forceFreeTierOnly: false,
            });
            const next = vi.fn() as NextFunction;

            const apiKey = {
                id: 'key-99',
                tenantId: 't1',
                keyHash: 'h',
                keyPrefix: 'p',
                description: null,
                expiresAt: null,
                lastUsedAt: null,
                status: 'ACTIVE',
            } as const;
            const tenant = {
                id: 't1',
                tenantDid: 'did:agent:1',
                tier: 'PRO',
                displayName: 'T',
                contactEmail: null,
                status: 'ACTIVE',
            } as const;
            const req = makeReq({
                auth: {
                    tier: 'PRO',
                    tenant,
                    apiKey,
                    clientIp: '1.1.1.1',
                },
            });

            // should be allowed through (PRO max=10000 default)
            middleware(req, makeRes(), next);
            expect(next).toHaveBeenCalledOnce();
        });
    });

    describe('snapshotBuckets', () => {
        it('should return opaque marker (test-only API)', () => {
            const middleware = createRateLimiter();
            expect(snapshotBuckets(middleware)).toBe('opaque');
        });
    });

    describe('forceFreeTierOnly default', () => {
        it('should downgrade PRO to FREE when forceFreeTierOnly defaults to true', () => {
            // default forceFreeTierOnly=true: PRO requests are forced through the FREE bucket
            // config: FREE max=1 (far below the PRO default 10000)
            const middleware = createRateLimiter({
                quotas: { FREE: { windowMs: 60_000, max: 1 } },
                // do not pass forceFreeTierOnly; verify the default is true
            });
            const next = vi.fn() as NextFunction;

            const apiKey = {
                id: 'pro-key',
                tenantId: 't1',
                keyHash: 'h',
                keyPrefix: 'p',
                description: null,
                expiresAt: null,
                lastUsedAt: null,
                status: 'ACTIVE',
            } as const;
            const tenant = {
                id: 't1',
                tenantDid: 'did:agent:1',
                tier: 'PRO',
                displayName: 'T',
                contactEmail: null,
                status: 'ACTIVE',
            } as const;
            const proReq = makeReq({
                auth: {
                    tier: 'PRO',
                    tenant,
                    apiKey,
                    clientIp: '1.1.1.1',
                },
            });

            // first time: PRO is downgraded to FREE, FREE max=1, should pass
            middleware(proReq, makeRes(), next);
            expect(next).toHaveBeenCalledOnce();

            // second time: the FREE bucket is exhausted, should 429 (even though PRO max=10000 default)
            const res2 = makeRes();
            middleware(proReq, res2, next);
            expect(res2.statusCode).toBe(429);
        });

        it('should respect real PRO quota when forceFreeTierOnly=false', () => {
            // forceFreeTierOnly=false: PRO uses its real PRO bucket (an upgrade-path rehearsal)
            const middleware = createRateLimiter({
                quotas: {
                    FREE: { windowMs: 60_000, max: 1 },
                    PRO: { windowMs: 60_000, max: 5 },
                },
                forceFreeTierOnly: false,
            });
            const next = vi.fn() as NextFunction;

            const apiKey = {
                id: 'pro-key',
                tenantId: 't1',
                keyHash: 'h',
                keyPrefix: 'p',
                description: null,
                expiresAt: null,
                lastUsedAt: null,
                status: 'ACTIVE',
            } as const;
            const tenant = {
                id: 't1',
                tenantDid: 'did:agent:1',
                tier: 'PRO',
                displayName: 'T',
                contactEmail: null,
                status: 'ACTIVE',
            } as const;
            const proReq = makeReq({
                auth: {
                    tier: 'PRO',
                    tenant,
                    apiKey,
                    clientIp: '1.1.1.1',
                },
            });

            // PRO max=5: 5 consecutive requests should pass
            for (let i = 0; i < 5; i++) {
                middleware(proReq, makeRes(), next);
            }
            expect(next).toHaveBeenCalledTimes(5);

            // the 6th should 429
            const res6 = makeRes();
            middleware(proReq, res6, next);
            expect(res6.statusCode).toBe(429);
        });
    });
});
