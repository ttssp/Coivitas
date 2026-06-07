/**
 * revocation-api.ts -- RevocationList revoke API + query API
 *
 * Responsibilities:
 *   - revoke(): revoke a token (DB write + cache invalidation)
 *   - isRevoked(): check whether a token has been revoked (cache-first + DB fallback)
 *   - getRevocation(): exact single-record lookup
 *   - getRevocations(): batch query
 *   - getNextListVersion(): query the next listVersion for a list
 *
 * Caching strategy:
 *   - isRevoked() path: cache get -> DB -> cache set (cache miss falls back to DB)
 *   - revoke() path: DB write -> cache invalidateToken (evict immediately after write)
 *   - cache failure: does not interrupt the operation; logs the error and degrades to DB (REVOCATION_CACHE_ERROR log)
 *
 * Design constraints:
 *   - fail-closed: isRevoked throws directly on DB error (never returns false)
 *   - no stub default 200 (a real errorCode is mandatory)
 *   - no partial-PASS
 *   - multi-tenant: every method MUST receive tenantId
 *
 */

import type {
    RevocationCheckResult,
    RevocationQueryFilters,
    RevocationRecord,
    RevocationWriteInput,
    RevocationWriteResult,
} from './revocation-record.js';
import {
    RevocationListStore,
    type RevocationListStoreOptions,
} from './revocation-list-store.js';
import {
    RevocationCache,
    type RevocationCacheOptions,
} from './revocation-cache.js';

// ---------------------------------------------------------------------------
// RevocationApiOptions
// ---------------------------------------------------------------------------

/** RevocationApi constructor options. */
export interface RevocationApiOptions {
    /** PostgreSQL connection pool config (passed to RevocationListStore). */
    store: RevocationListStoreOptions;
    /**
     * Cache config (optional; defaults to maxSize=10_000, ttlMs=30_000 when omitted).
     */
    cache?: RevocationCacheOptions;
}

// ---------------------------------------------------------------------------
// RevocationApi
// ---------------------------------------------------------------------------

/**
 * RevocationList API layer (cache + persistence coordination).
 *
 * RevocationList full implementation -- closes out the deferred stub.
 *
 * SDK GA integration interface reserved (implemented server-side, called by SDK clients):
 *   - the RevocationApi instance is injected into a RevocationChecker adapter by managed-service-runtime
 *   - see the replacement point comment in packages/managed-service-runtime/src/revocation-server.ts for the adapter
 */
export class RevocationApi {
    private readonly store: RevocationListStore;
    private readonly cache: RevocationCache;

    constructor(opts: RevocationApiOptions) {
        this.store = new RevocationListStore(opts.store);
        this.cache = new RevocationCache(opts.cache);
    }

    // -------------------------------------------------------------------------
    // revoke() -- revoke a token
    // -------------------------------------------------------------------------

    /**
     * Revoke a token.
     *
     * Flow: DB write -> cache invalidation (invalidate first regardless of DB success, to prevent staleness)
     *
     * Idempotent: a duplicate revoke returns REVOCATION_DUPLICATE (no throw).
     *
     * @param input revoke write parameters
     */
    async revoke(input: RevocationWriteInput): Promise<RevocationWriteResult> {
        // Invalidate the cache first (so a stale false value does not linger after the DB write)
        this._safeCacheInvalidate(input.tenantId, input.tokenId);

        const result = await this.store.revoke(input);

        if (result.ok) {
            // Write succeeded: set the cache to true (revoked)
            this._safeCacheSet(input.tenantId, input.tokenId, true);
        }

        return result;
    }

    // -------------------------------------------------------------------------
    // isRevoked() -- query revocation status (cache-first + DB fallback)
    // -------------------------------------------------------------------------

    /**
     * Check whether a token has been revoked.
     *
     * Cache path (p99 < 10ms target):
     *   1. cache.get() -> hit: return directly
     *   2. cache miss -> DB isRevoked() -> cache.set() -> return
     *
     * fail-closed: throws directly on DB error; never swallows the error and returns false.
     *
     * @throws Error when the DB query fails (cache-miss fallback path)
     */
    async isRevoked(tenantId: string, tokenId: string): Promise<boolean> {
        // 1. Cache lookup (O(1); hit path < 1ms)
        const cached = this.cache.get(tenantId, tokenId);
        if (cached !== undefined) {
            return cached;
        }

        // 2. DB fallback (cache miss; fail-closed: throw on DB error)
        const revoked = await this.store.isRevoked(tenantId, tokenId);

        // 3. Backfill the cache (a cache error does not interrupt the flow)
        this._safeCacheSet(tenantId, tokenId, revoked);

        return revoked;
    }

    // -------------------------------------------------------------------------
    // getRevocation() -- exact single-record lookup
    // -------------------------------------------------------------------------

    /**
     * Look up a single revocation record by tenantId + tokenId.
     *
     * Bypasses the cache (the full record is needed); queries the DB directly.
     *
     * @throws Error when the DB query fails
     */
    async getRevocation(
        tenantId: string,
        tokenId: string,
    ): Promise<RevocationCheckResult> {
        return this.store.getRevocation(tenantId, tokenId);
    }

    // -------------------------------------------------------------------------
    // getRevocations() -- batch query
    // -------------------------------------------------------------------------

    /**
     * Batch query revocation records (filtering + pagination).
     *
     * @throws Error when the DB query fails
     */
    async getRevocations(
        filters: RevocationQueryFilters,
    ): Promise<RevocationRecord[]> {
        return this.store.getRevocations(filters);
    }

    // -------------------------------------------------------------------------
    // getNextListVersion() -- query the next listVersion for a list
    // -------------------------------------------------------------------------

    /**
     * Query the next listVersion for a listId (MAX + 1, no lock).
     *
     * @throws Error when the DB query fails
     */
    async getNextListVersion(
        tenantId: string,
        listId: string,
    ): Promise<number> {
        return this.store.getNextListVersion(tenantId, listId);
    }

    // -------------------------------------------------------------------------
    // Cache management (explicit invalidation interface)
    // -------------------------------------------------------------------------

    /**
     * Invalidate the cache for a single token (called by the managed-service-runtime adapter).
     */
    invalidateCacheToken(tenantId: string, tokenId: string): void {
        this._safeCacheInvalidate(tenantId, tokenId);
    }

    /**
     * Clear all cache entries under a tenant (used after a bulk revoke).
     */
    invalidateCacheTenant(tenantId: string): void {
        this.cache.invalidateTenant(tenantId);
    }

    // ---- Internal cache operations (never throw; log the error and degrade) --------------------------

    private _safeCacheSet(
        tenantId: string,
        tokenId: string,
        revoked: boolean,
    ): void {
        try {
            this.cache.set(tenantId, tokenId, revoked);
        } catch (err) {
            // Cache write failed: do not interrupt the main flow (the DB fallback path still works)
            // In production this is captured by monitoring via the REVOCATION_CACHE_ERROR log
            console.error(
                '[RevocationApi] cache.set failed (degraded to DB):',
                err,
            );
        }
    }

    private _safeCacheInvalidate(tenantId: string, tokenId: string): void {
        try {
            this.cache.invalidateToken(tenantId, tokenId);
        } catch (err) {
            // Cache invalidation failed: do not interrupt the main flow
            console.error('[RevocationApi] cache.invalidateToken failed:', err);
        }
    }
}

// ---------------------------------------------------------------------------
// createRevocationApi -- factory function (simplified construction; for managed-service-runtime)
// ---------------------------------------------------------------------------

/**
 * Create a RevocationApi instance (factory function).
 *
 * Replaces the STUB_REVOCATION_NOT_FOR_PRODUCTION stub in
 * managed-service-runtime revocation-server.ts.
 *
 * @example
 * ```ts
 * import pg from 'pg';
 * import { createRevocationApi } from '@coivitas/policy';
 *
 * const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL });
 * const revocationApi = createRevocationApi({ store: { pool } });
 *
 * // Inject RevocationChecker
 * const checker = (credentialId: string) =>
 *   revocationApi.isRevoked(tenantId, credentialId)
 *     .then(revoked => ({ revoked }));
 * ```
 */
export function createRevocationApi(opts: RevocationApiOptions): RevocationApi {
    return new RevocationApi(opts);
}
