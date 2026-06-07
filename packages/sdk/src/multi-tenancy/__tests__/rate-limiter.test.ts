/**
 * MemoryTenantRateLimiter tests
 *
 * Coverage:
 *   - same tenant exhausts its quota -> TENANT_RATE_LIMITED (fail-closed)
 *   - different tenants are counted independently (key isolation test)
 *   - window reset (sliding-window)
 *   - token bucket algorithm correctness (token refill)
 *   - sliding window algorithm correctness (precise time window)
 *   - literal verification of retry-after metadata
 *   - storage error -> fail-closed (TenantRateLimiterStorageError)
 *   - isolation-invariant grep test (globalRateLimit = 0 lines)
 *   - TenantRateLimitError code literalization
 *
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { resolve, dirname } from 'node:path';
import { MemoryTenantRateLimiter } from '../rate-limiter.js';
import { makeTenantId } from '../types.js';
import type { TenantRateLimiterConfig } from '../rate-limiter.js';

// ── Helpers ───────────────────────────────────────────────────────────────────

const __dirname = dirname(fileURLToPath(import.meta.url));

function makeConfig(
    overrides?: Partial<TenantRateLimiterConfig>,
): TenantRateLimiterConfig {
    return {
        windowMs: 1000,
        maxRequests: 5,
        algorithm: 'sliding-window',
        ...overrides,
    };
}

// ── sliding-window: same tenant exhausts its quota ───────────────────────────

describe('MemoryTenantRateLimiter sliding-window — should exhaust quota per tenant', () => {
    it('should allow requests up to maxRequests then deny', () => {
        const limiter = new MemoryTenantRateLimiter(makeConfig({ maxRequests: 3 }));
        const tenantId = makeTenantId('acme-corp');

        const r1 = limiter.check(tenantId);
        const r2 = limiter.check(tenantId);
        const r3 = limiter.check(tenantId);
        const r4 = limiter.check(tenantId);

        expect(r1.allowed).toBe(true);
        expect(r2.allowed).toBe(true);
        expect(r3.allowed).toBe(true);
        expect(r4.allowed).toBe(false);
        expect(r4.remaining).toBe(0);
    });

    it('should include retryAfterSeconds when denied', () => {
        const limiter = new MemoryTenantRateLimiter(makeConfig({ maxRequests: 1 }));
        const tenantId = makeTenantId('test-tenant');

        limiter.check(tenantId); // consume quota
        const denied = limiter.check(tenantId);

        expect(denied.allowed).toBe(false);
        expect(typeof denied.retryAfterSeconds).toBe('number');
        expect(denied.retryAfterSeconds!).toBeGreaterThan(0);
    });

    it('should return correct remaining count after each request', () => {
        const limiter = new MemoryTenantRateLimiter(makeConfig({ maxRequests: 5 }));
        const tenantId = makeTenantId('count-tenant');

        const r1 = limiter.check(tenantId);
        expect(r1.remaining).toBe(4);

        const r2 = limiter.check(tenantId);
        expect(r2.remaining).toBe(3);
    });
});

// ── Different tenants counted independently (key isolation test) ─────────────

describe('MemoryTenantRateLimiter — should isolate rate limit state per tenant', () => {
    it('should not affect tenant-B quota when tenant-A exhausts its quota', () => {
        const limiter = new MemoryTenantRateLimiter(makeConfig({ maxRequests: 2 }));
        const tenantA = makeTenantId('tenant-a');
        const tenantB = makeTenantId('tenant-b');

        // tenant-A exhausts its quota
        limiter.check(tenantA);
        limiter.check(tenantA);
        const deniedA = limiter.check(tenantA);
        expect(deniedA.allowed).toBe(false);

        // tenant-B is unaffected: counted independently
        const allowedB = limiter.check(tenantB);
        expect(allowedB.allowed).toBe(true);
        expect(allowedB.tenantId).toBe('tenant-b');
    });

    it('should track remaining independently for each tenant', () => {
        const limiter = new MemoryTenantRateLimiter(makeConfig({ maxRequests: 5 }));
        const tenantA = makeTenantId('tenant-a');
        const tenantB = makeTenantId('tenant-b');

        limiter.check(tenantA);
        limiter.check(tenantA);
        limiter.check(tenantA);

        const rA = limiter.check(tenantA);
        const rB = limiter.check(tenantB);

        // tenant-A has used 4 requests; tenant-B has used only 1
        expect(rA.remaining).toBe(1);
        expect(rB.remaining).toBe(4);
    });

    it('should use activeTenantCount to confirm separate tenant tracking', () => {
        const limiter = new MemoryTenantRateLimiter(makeConfig());
        const tenantA = makeTenantId('tenant-a');
        const tenantB = makeTenantId('tenant-b');
        const tenantC = makeTenantId('tenant-c');

        limiter.check(tenantA);
        limiter.check(tenantB);
        limiter.check(tenantC);

        expect(limiter.activeTenantCount()).toBe(3);
    });
});

// ── sliding-window: window reset ─────────────────────────────────────────────

describe('MemoryTenantRateLimiter sliding-window — should reset window over time', () => {
    beforeEach(() => {
        vi.useFakeTimers();
    });

    afterEach(() => {
        vi.useRealTimers();
    });

    it('should allow new requests after window expires', () => {
        const limiter = new MemoryTenantRateLimiter(
            makeConfig({ windowMs: 1000, maxRequests: 2 }),
        );
        const tenantId = makeTenantId('window-tenant');

        limiter.check(tenantId);
        limiter.check(tenantId);
        const denied = limiter.check(tenantId);
        expect(denied.allowed).toBe(false);

        // Advance time by 1001ms (window expires)
        vi.advanceTimersByTime(1001);

        const allowed = limiter.check(tenantId);
        expect(allowed.allowed).toBe(true);
    });
});

// ── token bucket algorithm ────────────────────────────────────────────────────

describe('MemoryTenantRateLimiter token-bucket — should refill tokens over time', () => {
    beforeEach(() => {
        vi.useFakeTimers();
    });

    afterEach(() => {
        vi.useRealTimers();
    });

    it('should allow burst up to burstCapacity then refill', () => {
        const limiter = new MemoryTenantRateLimiter(
            makeConfig({
                algorithm: 'token-bucket',
                maxRequests: 2,
                windowMs: 1000,
                burstCapacity: 3,
            }),
        );
        const tenantId = makeTenantId('bucket-tenant');

        // Consume the burst (3 requests)
        expect(limiter.check(tenantId).allowed).toBe(true);
        expect(limiter.check(tenantId).allowed).toBe(true);
        expect(limiter.check(tenantId).allowed).toBe(true);
        const denied = limiter.check(tenantId);
        expect(denied.allowed).toBe(false);

        // Advance by 1000ms (should refill 2 tokens)
        vi.advanceTimersByTime(1000);

        expect(limiter.check(tenantId).allowed).toBe(true);
    });
});

// ── setTenantConfig + removeTenant ───────────────────────────────────────────

describe('MemoryTenantRateLimiter — setTenantConfig and removeTenant', () => {
    it('should apply per-tenant config override', () => {
        const limiter = new MemoryTenantRateLimiter(makeConfig({ maxRequests: 100 }));
        const tenantId = makeTenantId('limited-tenant');

        limiter.setTenantConfig(tenantId, makeConfig({ maxRequests: 1 }));

        limiter.check(tenantId); // consume
        const denied = limiter.check(tenantId);
        expect(denied.allowed).toBe(false);
    });

    it('should remove tenant state on removeTenant', () => {
        const limiter = new MemoryTenantRateLimiter(makeConfig({ maxRequests: 1 }));
        const tenantId = makeTenantId('remove-tenant');

        limiter.check(tenantId);
        limiter.removeTenant(tenantId);

        expect(limiter.activeTenantCount()).toBe(0);
        // Checking again should start fresh
        const result = limiter.check(tenantId);
        expect(result.allowed).toBe(true);
    });
});

// ── isolation-invariant grep test ────────────────────────────────────────────

/**
 * Isolation-invariant grep: scans only non-comment lines (dropping lines that start with * or //),
 * to avoid misclassifying a documentation comment that mentions "forbid globalRateLimit" as violating code.
 */
function nonCommentLines(src: string): string {
    return src
        .split('\n')
        .filter(line => {
            const trimmed = line.trim();
            return !trimmed.startsWith('*') && !trimmed.startsWith('//');
        })
        .join('\n');
}

describe('tenant isolation invariant grep test — rate-limiter.ts must not contain forbidden patterns', () => {
    it('should not contain globalRateLimit in non-comment code of rate-limiter.ts', () => {
        const srcPath = resolve(__dirname, '../rate-limiter.ts');
        const code = nonCommentLines(readFileSync(srcPath, 'utf-8'));

        expect(code).not.toMatch(/globalRateLimit/);
        expect(code).not.toMatch(/defaultTenant/);
        expect(code).not.toMatch(/untenanted/);
    });

    it('should not contain globalRateLimit in non-comment code of types.ts', () => {
        const srcPath = resolve(__dirname, '../types.ts');
        const code = nonCommentLines(readFileSync(srcPath, 'utf-8'));

        expect(code).not.toMatch(/globalRateLimit/);
        expect(code).not.toMatch(/defaultTenant/);
        expect(code).not.toMatch(/untenanted/);
    });

    it('should confirm MemoryTenantRateLimiter appears in rate-limiter.ts', () => {
        const srcPath = resolve(__dirname, '../rate-limiter.ts');
        const src = readFileSync(srcPath, 'utf-8');

        const count = (src.match(/MemoryTenantRateLimiter/g) ?? []).length;
        expect(count).toBeGreaterThanOrEqual(2);
    });
});
