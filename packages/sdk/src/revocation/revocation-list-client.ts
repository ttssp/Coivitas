/**
 * revocation-list-client.ts -- RevocationList SDK Client
 *
 * Responsibilities:
 *   - RevocationListClient: the entry point for RevocationList operations by SDK GA consumers
 *     - checkRevoked: query whether a token has been revoked (LRU cache first + backend fallback)
 *     - revokeCredential: revoke a credential (write to the backend)
 *     - listRevocations: batch query revocation records (with pagination)
 *   - InMemoryRevocationPort: an in-memory mock implementation for tests (RevocationListPort)
 *
 * Caching strategy (client-side LRU):
 *   - maxSize: 100 entries (fixed; guards against memory blowup)
 *   - ttlMs: 60_000ms (60s TTL; reduces backend queries on the hot path)
 *   - checkRevoked path: cache get → hit returns / cache miss → backend → cache set
 *   - revokeCredential path: backend write → cache invalidate (evict the cached false value)
 *   - cache entry format: key = `${tenantId}:${tokenId}` / value = { revoked: boolean, expiresAt: number }
 *
 * Security P0 guards (fail-closed + literally forbidden):
 *   - checkRevoked backend failure → throw RevocationClientError(REVOCATION_CLIENT_CHECK_FAILED)
 *     (do not return false / do not return 'unknown'; the caller must handle the throw)
 *   - No stub default 200; no partial-PASS
 *   - empty tenantId / tokenId → throw REVOCATION_CLIENT_INVALID_TENANT / INVALID_TOKEN_ID immediately
 *
 */

import type {
    RevocationCheckResult,
    RevocationQueryFilters,
    RevocationRecord,
    RevocationWriteInput,
    RevocationWriteResult,
} from '@coivitas/policy';
import { isRevocationReason } from '@coivitas/policy';

import type { RevocationListPort } from './types.js';
import {
    RevocationClientError,
} from './types.js';
import type {
    CheckRevokedRequest,
    CheckRevokedResult,
    ListRevocationsRequest,
    ListRevocationsResult,
    RevokeCredentialRequest,
    RevokeCredentialResult,
} from './types.js';

// ---------------------------------------------------------------------------
// Internal LRU Cache implementation (simple Map + doubly-linked list; no external dependency)
// ---------------------------------------------------------------------------

interface CacheEntry {
    revoked: boolean;
    expiresAt: number;
}

/**
 * Lightweight LRU Cache (maxSize entries + per-entry TTL).
 *
 * Bottom line: no external lru-cache dependency; LRU is emulated via Map ordering (most recently accessed moved to the end).
 * Time complexity: get/set/delete = O(1) amortized (Map ordering preserves insertion order).
 * Eviction policy: on set, when size > maxSize → delete the oldest entry (Map.keys().next()).
 */
class RevocationLruCache {
    private readonly cache: Map<string, CacheEntry>;
    private readonly maxSize: number;
    private readonly ttlMs: number;

    constructor(maxSize: number, ttlMs: number) {
        this.cache = new Map();
        this.maxSize = maxSize;
        this.ttlMs = ttlMs;
    }

    /** Look up a cache entry; on TTL expiry, delete it and return undefined. */
    get(tenantId: string, tokenId: string): boolean | undefined {
        const key = this._key(tenantId, tokenId);
        const entry = this.cache.get(key);
        if (entry === undefined) return undefined;

        if (Date.now() > entry.expiresAt) {
            // TTL expired: delete + return undefined (force a backend query)
            this.cache.delete(key);
            return undefined;
        }

        // Emulate LRU: delete then re-insert (move to the end)
        this.cache.delete(key);
        this.cache.set(key, entry);
        return entry.revoked;
    }

    /** Write a cache entry; evict the oldest entry when maxSize is exceeded. */
    set(tenantId: string, tokenId: string, revoked: boolean): void {
        // maxSize <= 0 means caching is disabled (strong-consistency mode); skip the write
        if (this.maxSize <= 0) return;

        const key = this._key(tenantId, tokenId);

        // If it already exists: delete then insert (update + move to the end)
        if (this.cache.has(key)) {
            this.cache.delete(key);
        } else if (this.cache.size >= this.maxSize) {
            // Evict the oldest entry (Map.keys() returns insertion order)
            const oldest = this.cache.keys().next().value;
            if (oldest !== undefined) {
                this.cache.delete(oldest);
            }
        }

        this.cache.set(key, {
            revoked,
            expiresAt: Date.now() + this.ttlMs,
        });
    }

    /** Delete the cache entry for a single token. */
    invalidate(tenantId: string, tokenId: string): void {
        this.cache.delete(this._key(tenantId, tokenId));
    }

    /** Delete all cache entries under a tenant (O(n); used after a bulk revocation). */
    invalidateTenant(tenantId: string): void {
        const prefix = `${tenantId}:`;
        for (const key of this.cache.keys()) {
            if (key.startsWith(prefix)) {
                this.cache.delete(key);
            }
        }
    }

    /** Current cache size (for tests). */
    get size(): number {
        return this.cache.size;
    }

    private _key(tenantId: string, tokenId: string): string {
        return `${tenantId}:${tokenId}`;
    }
}

// ---------------------------------------------------------------------------
// RevocationListClientConfig
// ---------------------------------------------------------------------------

/** RevocationListClient construction config. */
export interface RevocationListClientConfig {
    /**
     * The DI-injected backend Port (tests pass InMemoryRevocationPort; production passes the RevocationApi adapter).
     *
     * Bare `as RevocationListPort` casts are forbidden; the caller injects by implementing the interface.
     */
    port: RevocationListPort;
    /**
     * Client-side LRU cache maxSize (default 100).
     * Set to 0 to disable the cache (tests or scenarios that explicitly require strong consistency).
     */
    cacheMaxSize?: number;
    /**
     * Client-side LRU cache TTL in milliseconds (default 60_000 = 60s).
     */
    cacheTtlMs?: number;
}

// ---------------------------------------------------------------------------
// RevocationListClient
// ---------------------------------------------------------------------------

/**
 * RevocationList SDK Client.
 *
 * SDK GA consumers operate on the RevocationList through this class, which hides backend DB details.
 *
 * Usage example (production):
 * ```ts
 * import { RevocationApi } from '@coivitas/policy';
 * import { RevocationListClient } from '@coivitas/sdk';
 *
 * const api = createRevocationApi({ store: { pool } });
 * const client = new RevocationListClient({ port: api });
 *
 * // fail-closed query (DB failure → throw; does not return false)
 * const { revoked } = await client.checkRevoked({ tenantId, tokenId });
 * if (revoked) throw new Error('credential revoked');
 * ```
 *
 * Security constraints (literally forbidden — verified by grep test):
 *   - No `return false` when unknown (fail-closed; any unknown state → throw)
 *   - No `return { revoked: false }` on error (same)
 *   - No `catch` + `return false` (fail-closed)
 *   - No stub default 200
 */
export class RevocationListClient {
    private readonly port: RevocationListPort;
    private readonly cache: RevocationLruCache;

    constructor(config: RevocationListClientConfig) {
        this.port = config.port;
        const maxSize =
            config.cacheMaxSize !== undefined ? config.cacheMaxSize : 100;
        const ttlMs =
            config.cacheTtlMs !== undefined ? config.cacheTtlMs : 60_000;
        this.cache = new RevocationLruCache(maxSize, ttlMs);
    }

    // -------------------------------------------------------------------------
    // checkRevoked -- query whether a token has been revoked (LRU cache first + backend fallback)
    // -------------------------------------------------------------------------

    /**
     * Query whether a token has been revoked.
     *
     * Cache path (LRU; 100 entries / 60s TTL):
     *   1. cache.get() → hit: return { revoked, fromCache: true }
     *   2. cache miss → port.isRevoked() → cache.set() → return { revoked, fromCache: false }
     *
     * fail-closed: port.isRevoked() failure → throw RevocationClientError(CHECK_FAILED).
     * No catch + return false (any unknown state must throw).
     *
     * @throws RevocationClientError(REVOCATION_CLIENT_INVALID_TENANT) tenantId is empty
     * @throws RevocationClientError(REVOCATION_CLIENT_INVALID_TOKEN_ID) tokenId is empty
     * @throws RevocationClientError(REVOCATION_CLIENT_CHECK_FAILED) backend query failed
     */
    async checkRevoked(req: CheckRevokedRequest): Promise<CheckRevokedResult> {
        this._validateTenant(req.tenantId);
        this._validateTokenId(req.tokenId);

        // 1. Cache lookup
        const cached = this.cache.get(req.tenantId, req.tokenId);
        if (cached !== undefined) {
            return { revoked: cached, fromCache: true };
        }

        // 2. Backend query (fail-closed: failure → throw, do not return false)
        let revoked: boolean;
        try {
            revoked = await this.port.isRevoked(req.tenantId, req.tokenId);
        } catch (err) {
            throw new RevocationClientError(
                `checkRevoked failed for tenant=${req.tenantId} token=${req.tokenId}: ${String(err)}`,
                'REVOCATION_CLIENT_CHECK_FAILED',
                err,
            );
        }

        // 3. Populate the cache
        this.cache.set(req.tenantId, req.tokenId, revoked);

        return { revoked, fromCache: false };
    }

    // -------------------------------------------------------------------------
    // revokeCredential -- revoke a credential (write to backend + cache invalidation)
    // -------------------------------------------------------------------------

    /**
     * Revoke a credential.
     *
     * Flow: cache invalidate → port.revoke() → branch on the result:
     *   - ok: true → cache.set(true); return { ok: true, record }
     *   - ok: false + REVOCATION_DUPLICATE → return { ok: false, duplicate: true, message }
     *   - ok: false + other → throw RevocationClientError(REVOKE_FAILED)
     *
     * @throws RevocationClientError(REVOCATION_CLIENT_INVALID_TENANT) tenantId is empty
     * @throws RevocationClientError(REVOCATION_CLIENT_INVALID_TOKEN_ID) tokenId is empty
     * @throws RevocationClientError(REVOCATION_CLIENT_REVOKE_FAILED) write failure (non-duplicate)
     */
    async revokeCredential(
        req: RevokeCredentialRequest,
    ): Promise<RevokeCredentialResult> {
        this._validateTenant(req.tenantId);
        this._validateTokenId(req.tokenId);

        // Invalidate first (prevent a stale cached false value from still hitting after the write)
        this.cache.invalidate(req.tenantId, req.tokenId);

        const input: RevocationWriteInput = {
            tenantId: req.tenantId,
            tokenId: req.tokenId,
            revokedBy: req.revokedBy,
            reason: req.reason !== undefined && isRevocationReason(req.reason)
                ? req.reason
                : 'UNSPECIFIED',
            listId: req.listId,
        };

        let result: RevocationWriteResult;
        try {
            result = await this.port.revoke(input);
        } catch (err) {
            throw new RevocationClientError(
                `revokeCredential failed for tenant=${req.tenantId} token=${req.tokenId}: ${String(err)}`,
                'REVOCATION_CLIENT_REVOKE_FAILED',
                err,
            );
        }

        if (result.ok) {
            // Write succeeded: set the cache to revoked (reduce backend pressure on subsequent queries)
            this.cache.set(req.tenantId, req.tokenId, true);
            return { ok: true, record: result.record };
        }

        // ok: false branch
        if (result.code === 'REVOCATION_DUPLICATE') {
            // Idempotent: already revoked; populate the cache
            this.cache.set(req.tenantId, req.tokenId, true);
            return { ok: false, duplicate: true, message: result.message };
        }

        // Other failures (STORE_ERROR, etc.) → throw fail-closed
        throw new RevocationClientError(
            `revokeCredential store error for tenant=${req.tenantId} token=${req.tokenId}: ${result.message}`,
            'REVOCATION_CLIENT_REVOKE_FAILED',
        );
    }

    // -------------------------------------------------------------------------
    // listRevocations -- batch query revocation records
    // -------------------------------------------------------------------------

    /**
     * Batch query revocation records (pagination + filtering).
     *
     * Does not use the cache (a full RevocationRecord list is required); queries the backend directly.
     *
     * @throws RevocationClientError(REVOCATION_CLIENT_INVALID_TENANT) tenantId is empty
     * @throws RevocationClientError(REVOCATION_CLIENT_LIST_FAILED) query failed
     */
    async listRevocations(
        req: ListRevocationsRequest,
    ): Promise<ListRevocationsResult> {
        this._validateTenant(req.tenantId);

        const filters: RevocationQueryFilters = {
            tenantId: req.tenantId,
            tokenId: req.tokenId,
            listId: req.listId,
            limit: req.limit,
            offset: req.offset,
        };

        let records: RevocationRecord[];
        try {
            records = await this.port.getRevocations(filters);
        } catch (err) {
            throw new RevocationClientError(
                `listRevocations failed for tenant=${req.tenantId}: ${String(err)}`,
                'REVOCATION_CLIENT_LIST_FAILED',
                err,
            );
        }

        return { records, total: records.length };
    }

    // -------------------------------------------------------------------------
    // Cache management (explicit invalidation; for tests + bulk-revocation scenarios)
    // -------------------------------------------------------------------------

    /**
     * Invalidate the client-side cache for a single token exactly.
     */
    invalidateCacheEntry(tenantId: string, tokenId: string): void {
        this.cache.invalidate(tenantId, tokenId);
    }

    /**
     * Clear all client-side cache entries under a tenant.
     */
    invalidateCacheTenant(tenantId: string): void {
        this.cache.invalidateTenant(tenantId);
    }

    /** Current cache size (for tests). */
    get cacheSize(): number {
        return this.cache.size;
    }

    // -------------------------------------------------------------------------
    // Parameter validation (fail-closed)
    // -------------------------------------------------------------------------

    private _validateTenant(tenantId: string): void {
        if (typeof tenantId !== 'string' || tenantId.trim() === '') {
            throw new RevocationClientError(
                `tenantId must be a non-empty string, got: ${JSON.stringify(tenantId)}`,
                'REVOCATION_CLIENT_INVALID_TENANT',
            );
        }
    }

    private _validateTokenId(tokenId: string): void {
        if (typeof tokenId !== 'string' || tokenId.trim() === '') {
            throw new RevocationClientError(
                `tokenId must be a non-empty string, got: ${JSON.stringify(tokenId)}`,
                'REVOCATION_CLIENT_INVALID_TOKEN_ID',
            );
        }
    }
}

// ---------------------------------------------------------------------------
// InMemoryRevocationPort -- in-memory mock implementation for tests
// ---------------------------------------------------------------------------

/**
 * In-memory RevocationListPort implementation for tests.
 *
 * Features:
 *   - In-memory storage (Map); no dependency on PostgreSQL / RevocationApi
 *   - Supports simulateError() to simulate backend failures (fail-closed tests)
 *   - Supports seed() to pre-populate revocation data
 *
 * No brand cast; implements RevocationListPort directly.
 */
export class InMemoryRevocationPort implements RevocationListPort {
    /** key = `${tenantId}:${tokenId}` → RevocationRecord */
    private readonly records: Map<string, RevocationRecord> = new Map();

    /** Simulated-backend-failure flag (for fail-closed tests). */
    private _shouldError = false;
    private _errorMessage = 'simulated backend error';

    /**
     * Pre-populate a revocation record (for test setup).
     */
    seed(record: RevocationRecord): void {
        const key = `${record.tenantId}:${record.tokenId}`;
        this.records.set(key, record);
    }

    /**
     * Set whether the next operation throws (fail-closed test).
     */
    simulateError(shouldError: boolean, message = 'simulated backend error'): void {
        this._shouldError = shouldError;
        this._errorMessage = message;
    }

    isRevoked(tenantId: string, tokenId: string): Promise<boolean> {
        if (this._shouldError) {
            return Promise.reject(new Error(this._errorMessage));
        }
        return Promise.resolve(this.records.has(`${tenantId}:${tokenId}`));
    }

    getRevocation(
        tenantId: string,
        tokenId: string,
    ): Promise<RevocationCheckResult> {
        if (this._shouldError) {
            return Promise.reject(new Error(this._errorMessage));
        }
        const record = this.records.get(`${tenantId}:${tokenId}`);
        if (record !== undefined) {
            return Promise.resolve({ found: true, record });
        }
        return Promise.resolve({ found: false });
    }

    revoke(input: RevocationWriteInput): Promise<RevocationWriteResult> {
        if (this._shouldError) {
            return Promise.reject(new Error(this._errorMessage));
        }
        const key = `${input.tenantId}:${input.tokenId}`;
        if (this.records.has(key)) {
            return Promise.resolve({
                ok: false,
                code: 'REVOCATION_DUPLICATE',
                message: `token ${input.tokenId} already revoked in tenant ${input.tenantId}`,
            });
        }
        const record: RevocationRecord = {
            id: `mock-${input.tenantId}-${input.tokenId}`,
            tenantId: input.tenantId,
            tokenId: input.tokenId,
            revokedBy: input.revokedBy,
            revokedAt: new Date(),
            reason: input.reason ?? 'UNSPECIFIED',
            listId: input.listId,
            listVersion: 1,
            issuerSignaturePayload: input.issuerSignaturePayload ?? null,
        };
        this.records.set(key, record);
        return Promise.resolve({ ok: true, record });
    }

    getRevocations(filters: RevocationQueryFilters): Promise<RevocationRecord[]> {
        if (this._shouldError) {
            return Promise.reject(new Error(this._errorMessage));
        }
        let results = Array.from(this.records.values()).filter(
            (r) => r.tenantId === filters.tenantId,
        );
        if (filters.tokenId !== undefined) {
            results = results.filter((r) => r.tokenId === filters.tokenId);
        }
        if (filters.listId !== undefined) {
            results = results.filter((r) => r.listId === filters.listId);
        }
        const offset = filters.offset ?? 0;
        const limit = filters.limit ?? 100;
        return Promise.resolve(results.slice(offset, offset + limit));
    }

    /** Current number of stored records (for test assertions). */
    get size(): number {
        return this.records.size;
    }
}
