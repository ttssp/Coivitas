/**
 * revocation-cache.test.ts -- RevocationCache unit tests
 *
 * Coverage:
 *   - cache get / set / invalidate basic paths
 *   - TTL expiration (virtual time)
 *   - LRU eviction (evict the oldest entry when maxSize is exceeded)
 *   - tenant isolation (keys of different tenantIds do not interfere with each other)
 *   - invalidateTenant clears all entries under a tenant
 *   - invalidateAll clears everything
 *
 */

import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest';
import { RevocationCache } from '../revocation-cache.js';

describe('RevocationCache', () => {
    beforeEach(() => {
        vi.useFakeTimers();
    });

    afterEach(() => {
        vi.useRealTimers();
    });

    // -------------------------------------------------------------------------
    // Basic get / set / invalidate
    // -------------------------------------------------------------------------

    describe('get / set / invalidate', () => {
        it('should return undefined for cache miss', () => {
            const cache = new RevocationCache();
            expect(cache.get('tenant-a', 'token-1')).toBeUndefined();
        });

        it('should return cached value on cache hit', () => {
            const cache = new RevocationCache({ ttlMs: 60_000 });
            cache.set('tenant-a', 'token-1', true);
            expect(cache.get('tenant-a', 'token-1')).toBe(true);
        });

        it('should cache false (not revoked) value', () => {
            const cache = new RevocationCache({ ttlMs: 60_000 });
            cache.set('tenant-a', 'token-2', false);
            expect(cache.get('tenant-a', 'token-2')).toBe(false);
        });

        it('should return undefined after invalidateToken', () => {
            const cache = new RevocationCache({ ttlMs: 60_000 });
            cache.set('tenant-a', 'token-1', true);
            cache.invalidateToken('tenant-a', 'token-1');
            expect(cache.get('tenant-a', 'token-1')).toBeUndefined();
        });

        it('should update existing cached value on set', () => {
            const cache = new RevocationCache({ ttlMs: 60_000 });
            cache.set('tenant-a', 'token-1', false);
            cache.set('tenant-a', 'token-1', true);
            expect(cache.get('tenant-a', 'token-1')).toBe(true);
        });
    });

    // -------------------------------------------------------------------------
    // TTL expiration
    // -------------------------------------------------------------------------

    describe('TTL expiration', () => {
        it('should return undefined after TTL expires', () => {
            const cache = new RevocationCache({ ttlMs: 1_000 }); // 1s TTL
            cache.set('tenant-a', 'token-1', true);

            vi.advanceTimersByTime(999);
            expect(cache.get('tenant-a', 'token-1')).toBe(true);

            vi.advanceTimersByTime(2); // 1001ms in total, exceeding the TTL
            expect(cache.get('tenant-a', 'token-1')).toBeUndefined();
        });

        it('should remove expired entry from size count', () => {
            const cache = new RevocationCache({ ttlMs: 500, maxSize: 10 });
            cache.set('tenant-a', 'token-1', true);
            expect(cache.size).toBe(1);

            vi.advanceTimersByTime(600);
            cache.get('tenant-a', 'token-1'); // triggers the TTL check and deletion
            expect(cache.size).toBe(0);
        });
    });

    // -------------------------------------------------------------------------
    // LRU eviction (when maxSize is exceeded)
    // -------------------------------------------------------------------------

    describe('LRU eviction', () => {
        it('should evict the least recently used entry when maxSize exceeded', () => {
            const cache = new RevocationCache({ maxSize: 3, ttlMs: 60_000 });
            cache.set('t', 'a', true); // insertion order: a → b → c
            cache.set('t', 'b', true);
            cache.set('t', 'c', true);

            // Access a, making b the oldest
            cache.get('t', 'a');

            // Write the 4th entry, which should evict the oldest (at this point b is the oldest not accessed)
            cache.set('t', 'd', true);
            expect(cache.size).toBe(3);

            // b should be evicted
            expect(cache.get('t', 'b')).toBeUndefined();
            // a, c, d should still be in the cache
            expect(cache.get('t', 'a')).toBe(true);
            expect(cache.get('t', 'c')).toBe(true);
            expect(cache.get('t', 'd')).toBe(true);
        });

        it('should evict the oldest entry when maxSize is 1', () => {
            const cache = new RevocationCache({ maxSize: 1, ttlMs: 60_000 });
            cache.set('t', 'token-1', true);
            cache.set('t', 'token-2', false);

            expect(cache.get('t', 'token-1')).toBeUndefined();
            expect(cache.get('t', 'token-2')).toBe(false);
        });
    });

    // -------------------------------------------------------------------------
    // tenant isolation
    // -------------------------------------------------------------------------

    describe('tenant isolation', () => {
        it('should not share cache entries between different tenants', () => {
            const cache = new RevocationCache({ ttlMs: 60_000 });
            cache.set('tenant-a', 'token-shared', true);
            cache.set('tenant-b', 'token-shared', false);

            expect(cache.get('tenant-a', 'token-shared')).toBe(true);
            expect(cache.get('tenant-b', 'token-shared')).toBe(false);
        });

        it('should not invalidate other tenant entries when invalidateToken called', () => {
            const cache = new RevocationCache({ ttlMs: 60_000 });
            cache.set('tenant-a', 'token-1', true);
            cache.set('tenant-b', 'token-1', true);

            cache.invalidateToken('tenant-a', 'token-1');

            expect(cache.get('tenant-a', 'token-1')).toBeUndefined();
            expect(cache.get('tenant-b', 'token-1')).toBe(true);
        });
    });

    // -------------------------------------------------------------------------
    // invalidateTenant
    // -------------------------------------------------------------------------

    describe('invalidateTenant', () => {
        it('should remove all entries for a specific tenant', () => {
            const cache = new RevocationCache({ ttlMs: 60_000 });
            cache.set('tenant-a', 'token-1', true);
            cache.set('tenant-a', 'token-2', false);
            cache.set('tenant-b', 'token-3', true);

            cache.invalidateTenant('tenant-a');

            expect(cache.get('tenant-a', 'token-1')).toBeUndefined();
            expect(cache.get('tenant-a', 'token-2')).toBeUndefined();
            // tenant-b is unaffected
            expect(cache.get('tenant-b', 'token-3')).toBe(true);
        });
    });

    // -------------------------------------------------------------------------
    // invalidateAll
    // -------------------------------------------------------------------------

    describe('invalidateAll', () => {
        it('should clear all cache entries', () => {
            const cache = new RevocationCache({ ttlMs: 60_000 });
            cache.set('tenant-a', 'token-1', true);
            cache.set('tenant-b', 'token-2', false);

            cache.invalidateAll();

            expect(cache.size).toBe(0);
            expect(cache.get('tenant-a', 'token-1')).toBeUndefined();
            expect(cache.get('tenant-b', 'token-2')).toBeUndefined();
        });
    });

    // -------------------------------------------------------------------------
    // revoke → invalidate → verifier reject flow (e2e semantics)
    // -------------------------------------------------------------------------

    describe('revoke → cache invalidation semantics', () => {
        it('should return undefined immediately after invalidateToken (revoke path)', () => {
            const cache = new RevocationCache({ ttlMs: 60_000 });

            // Simulate isRevoked() backfilling the cache (token not revoked)
            cache.set('tenant-a', 'token-1', false);
            expect(cache.get('tenant-a', 'token-1')).toBe(false);

            // revoke() invalidates before writing to the DB (revocation-api semantics)
            cache.invalidateToken('tenant-a', 'token-1');

            // At this point cache miss → the next isRevoked() goes to the DB
            expect(cache.get('tenant-a', 'token-1')).toBeUndefined();

            // After revoke() writes to the DB successfully, set true
            cache.set('tenant-a', 'token-1', true);
            expect(cache.get('tenant-a', 'token-1')).toBe(true);
        });
    });

    // -------------------------------------------------------------------------
    // size tracking
    // -------------------------------------------------------------------------

    describe('size', () => {
        it('should track the number of cached entries', () => {
            const cache = new RevocationCache({ ttlMs: 60_000 });
            expect(cache.size).toBe(0);
            cache.set('t', 'a', true);
            expect(cache.size).toBe(1);
            cache.set('t', 'b', false);
            expect(cache.size).toBe(2);
            cache.invalidateToken('t', 'a');
            expect(cache.size).toBe(1);
        });
    });
});
