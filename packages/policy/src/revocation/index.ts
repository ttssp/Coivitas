/**
 * revocation/index.ts -- RevocationList module entry point
 *
 * RevocationList full implementation.
 * Closes out the deferred stub (STUB_REVOCATION_NOT_FOR_PRODUCTION).
 *
 * Module layout:
 *   - revocation-record.ts: L3 persistence-layer types + error codes (REVOCATION_*)
 *   - revocation-list-store.ts: PostgreSQL persistence layer (policy.revocation_records)
 *   - revocation-cache.ts: LRU + TTL cache (p99 < 10ms)
 *   - revocation-api.ts: revoke API + query API (cache coordination layer)
 *
 */

// Type exports
export type {
    IssuerSignaturePayload,
    RevocationCheckResult,
    RevocationErrorCode,
    RevocationFound,
    RevocationNotFound,
    RevocationQueryFilters,
    RevocationReason,
    RevocationRecord,
    RevocationWriteFailure,
    RevocationWriteInput,
    RevocationWriteResult,
    RevocationWriteSuccess,
} from './revocation-record.js';

// Runtime validation utilities (no brand cast)
export {
    REVOCATION_REASONS,
    isRevocationReason,
    parseRevocationReason,
} from './revocation-record.js';

// Persistence layer
export {
    RevocationListStore,
    type RevocationListStoreOptions,
} from './revocation-list-store.js';

// Cache layer
export {
    RevocationCache,
    type RevocationCacheOptions,
} from './revocation-cache.js';

// API layer (main entry point)
export {
    RevocationApi,
    createRevocationApi,
    type RevocationApiOptions,
} from './revocation-api.js';
