/**
 * revocation-cache.ts -- RevocationList LRU + TTL cache layer
 *
 * Caching strategy:
 *   - LRU (Least Recently Used) eviction: evict the least recently accessed entry when maxSize is exceeded
 *   - TTL (Time-To-Live) expiry: an entry older than ttlMs is treated as expired (get returns undefined)
 *   - invalidate the cache immediately after a revoke write (guarantees the revoke -> cache evict -> verifier reject e2e chain)
 *   - cache key format: `${tenantId}:${tokenId}` (tenant isolation prefix)
 *
 * Performance target: revocation lookup < 10ms p99 (cache-hit path: O(1) Map operation)
 *
 * Design constraints:
 *   - fail-closed degradation: on a cache get failure, do not swallow the error; return undefined so the caller falls back to DB
 *   - not persisted (pure in-memory; the cache cold-starts after restart, DB is the source of truth)
 *   - thread safety: Node.js single-threaded model, no extra locking needed
 *
 */

// ---------------------------------------------------------------------------
// CacheEntry -- internal cache entry
// ---------------------------------------------------------------------------

/** Cache entry (internal use). */
interface CacheEntry<V> {
    value: V;
    /** Entry expiry timestamp (Unix ms). */
    expiresAt: number;
    /** LRU linked-list pointers (prev/next). */
    prev: string | null;
    next: string | null;
}

// ---------------------------------------------------------------------------
// LruTtlCache -- generic LRU + TTL cache (internal base class)
// ---------------------------------------------------------------------------

/**
 * Generic LRU + TTL cache.
 *
 * Uses a Map (insertion order) + doubly linked-list head/tail pointers for O(1) LRU eviction.
 * The actual LRU order is maintained via the prev/next fields of each Map entry (lightweight implementation).
 */
class LruTtlCache<V> {
    private readonly maxSize: number;
    private readonly ttlMs: number;
    private readonly store = new Map<string, CacheEntry<V>>();
    private head: string | null = null; // most recently accessed (newest)
    private tail: string | null = null; // least recently accessed (oldest, eviction candidate)

    constructor(maxSize: number, ttlMs: number) {
        if (maxSize < 1) throw new Error('LruTtlCache: maxSize must be >= 1');
        if (ttlMs < 0) throw new Error('LruTtlCache: ttlMs must be >= 0');
        this.maxSize = maxSize;
        this.ttlMs = ttlMs;
    }

    /**
     * Get a cache value.
     *
     * @returns the cached value, or undefined (cache miss / expired)
     */
    get(key: string): V | undefined {
        const entry = this.store.get(key);
        if (!entry) return undefined;

        // TTL check: if expired, delete and return undefined
        if (Date.now() > entry.expiresAt) {
            this.delete(key);
            return undefined;
        }

        // LRU update: move to the head of the list (most recently accessed)
        this._moveToHead(key, entry);
        return entry.value;
    }

    /**
     * Write a cache value.
     *
     * If the same key already exists, update the value and move it to the head of the list.
     * When maxSize is exceeded, evict the tail of the list (least recently accessed).
     */
    set(key: string, value: V): void {
        const existingEntry = this.store.get(key);
        if (existingEntry) {
            existingEntry.value = value;
            existingEntry.expiresAt = Date.now() + this.ttlMs;
            this._moveToHead(key, existingEntry);
            return;
        }

        // Evict the oldest entry (when over capacity)
        if (this.store.size >= this.maxSize) {
            this._evictTail();
        }

        const entry: CacheEntry<V> = {
            value,
            expiresAt: Date.now() + this.ttlMs,
            prev: null,
            next: this.head,
        };

        if (this.head) {
            const headEntry = this.store.get(this.head);
            if (headEntry) headEntry.prev = key;
        }
        this.head = key;
        if (this.tail === null) this.tail = key;
        this.store.set(key, entry);
    }

    /**
     * Delete a cache entry (cache invalidation).
     */
    delete(key: string): boolean {
        const entry = this.store.get(key);
        if (!entry) return false;
        this._unlink(key, entry);
        this.store.delete(key);
        return true;
    }

    /**
     * Clear the cache (single-tenant clear or full clear).
     *
     * When prefix is non-null, only keys matching the prefix are cleared (used for tenant-level invalidation).
     */
    clear(prefix: string | null = null): void {
        if (prefix === null) {
            this.store.clear();
            this.head = null;
            this.tail = null;
            return;
        }
        for (const key of this.store.keys()) {
            if (key.startsWith(prefix)) {
                this.delete(key);
            }
        }
    }

    /** Current cache size (includes non-expired entries). */
    get size(): number {
        return this.store.size;
    }

    // ---- Internal linked-list operations --------------------------------------------------------

    private _moveToHead(key: string, entry: CacheEntry<V>): void {
        if (this.head === key) return;
        this._unlink(key, entry);
        entry.prev = null;
        entry.next = this.head;
        if (this.head) {
            const headEntry = this.store.get(this.head);
            if (headEntry) headEntry.prev = key;
        }
        this.head = key;
        if (this.tail === null) this.tail = key;
    }

    private _unlink(key: string, entry: CacheEntry<V>): void {
        if (entry.prev) {
            const prevEntry = this.store.get(entry.prev);
            if (prevEntry) prevEntry.next = entry.next;
        } else {
            // is the head
            this.head = entry.next;
        }
        if (entry.next) {
            const nextEntry = this.store.get(entry.next);
            if (nextEntry) nextEntry.prev = entry.prev;
        } else {
            // is the tail
            this.tail = entry.prev;
        }
        entry.prev = null;
        entry.next = null;
    }

    private _evictTail(): void {
        if (!this.tail) return;
        const tailKey = this.tail;
        const tailEntry = this.store.get(tailKey);
        if (tailEntry) {
            this._unlink(tailKey, tailEntry);
        }
        this.store.delete(tailKey);
    }
}

// ---------------------------------------------------------------------------
// RevocationCache -- revocation-lookup cache (LRU + TTL; tenant-key isolation)
// ---------------------------------------------------------------------------

/** RevocationCache constructor options. */
export interface RevocationCacheOptions {
    /**
     * Maximum number of cache entries (LRU eviction ceiling).
     * Default 10_000 entries (roughly ~5MB per-instance memory).
     */
    maxSize?: number;
    /**
     * Cache TTL (ms).
     * Default 30_000ms (30s).
     *
     * Revocation timeliness requirement: cache invalidation is triggered immediately after a revoke; TTL only guards against long-term staleness.
     */
    ttlMs?: number;
}

/**
 * Revocation-lookup LRU + TTL cache.
 *
 * cache key format: `${tenantId}:${tokenId}` (tenant isolation).
 *
 * Typical usage scenarios:
 *   1. revocation-api revoke() -> DB write -> invalidateToken(tenantId, tokenId)
 *   2. revocation-api isRevoked() -> cache.get() -> cache miss -> DB -> cache.set()
 */
export class RevocationCache {
    private readonly cache: LruTtlCache<boolean>;

    constructor(opts: RevocationCacheOptions = {}) {
        this.cache = new LruTtlCache<boolean>(
            opts.maxSize ?? 10_000,
            opts.ttlMs ?? 30_000,
        );
    }

    /**
     * Build the cache key (tenant isolation).
     */
    private cacheKey(tenantId: string, tokenId: string): string {
        return `${tenantId}:${tokenId}`;
    }

    /**
     * Check whether a token is revoked according to the cache.
     *
     * @returns
     *   - true: cache hit, token is revoked
     *   - false: cache hit, token is not revoked
     *   - undefined: cache miss (caller falls back to DB)
     */
    get(tenantId: string, tokenId: string): boolean | undefined {
        return this.cache.get(this.cacheKey(tenantId, tokenId));
    }

    /**
     * Write the revocation status into the cache.
     *
     * @param tenantId tenant ID
     * @param tokenId token ID
     * @param revoked whether it is revoked
     */
    set(tenantId: string, tokenId: string, revoked: boolean): void {
        this.cache.set(this.cacheKey(tenantId, tokenId), revoked);
    }

    /**
     * Invalidate the cache for a single token (call immediately after revoke).
     *
     * Keeps the revoke -> cache evict -> verifier reject e2e chain correct.
     */
    invalidateToken(tenantId: string, tokenId: string): void {
        this.cache.delete(this.cacheKey(tenantId, tokenId));
    }

    /**
     * Clear all cache entries under a given tenant (tenant-level invalidation).
     *
     * Scenario: tenant bulk revoke or policy reset.
     */
    invalidateTenant(tenantId: string): void {
        this.cache.clear(`${tenantId}:`);
    }

    /**
     * Clear all cache entries (global invalidation; use with caution).
     */
    invalidateAll(): void {
        this.cache.clear(null);
    }

    /** Current number of cache entries. */
    get size(): number {
        return this.cache.size;
    }
}
