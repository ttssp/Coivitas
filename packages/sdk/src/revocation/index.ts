/**
 * revocation/index.ts -- RevocationList SDK Client module entry point
 *
 * SDK API: the public consumer-facing interface of the RevocationList SDK Client.
 *
 * Module layout:
 *   - types.ts: RevocationListPort (DI interface) + DTO types + RevocationClientError
 *   - revocation-list-client.ts: RevocationListClient implementation + InMemoryRevocationPort (test mock)
 *
 * Design constraints (fail-closed + no brand cast):
 *   - Do not export any helper that bypasses fail-closed (e.g. checkedRevoked = false)
 *   - Do not export any function that bypasses tenantId validation
 *   - RevocationListPort is injected via the interface; bare `as RevocationListPort` casts are forbidden
 */

// ── Types + errors ───────────────────────────────────────────────────────────

export type {
    RevocationListPort,
    RevocationClientErrorCode,
    CheckRevokedRequest,
    CheckRevokedResult,
    RevokeCredentialRequest,
    RevokeCredentialResult,
    ListRevocationsRequest,
    ListRevocationsResult,
} from './types.js';

export { RevocationClientError } from './types.js';

// ── RevocationListClient + InMemoryRevocationPort ────────────────────────────

export type { RevocationListClientConfig } from './revocation-list-client.js';

export {
    RevocationListClient,
    InMemoryRevocationPort,
} from './revocation-list-client.js';
