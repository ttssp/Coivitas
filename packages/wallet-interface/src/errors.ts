/**
 * WalletErrorCode — union type of wallet operation error codes
 *
 * Design conventions (fail-closed):
 * - This package only produces interface definitions + a stub-only fail-closed implementation.
 * - All stub operations return WALLET_STUB_NOT_FOR_PRODUCTION.
 * - The full implementation is deferred to a later release.
 *
 * New error codes:
 * - WALLET_STUB_NOT_FOR_PRODUCTION: stub-implementation sentinel -- returned whenever any stub method
 *   is called, so the SDK's fail-unknown handling takes the retry / fallback path (fail-closed guard).
 * - WALLET_RECOVERY_VERSION_UNVERIFIED: rejects recovery when currentShardVersion is omitted
 *   (the production implementation closes the loop by externalizing version provenance).
 * - WALLET_RECOVERY_DID_MISMATCH: hard-fail; aborts before writing to disk when candidateDid !== expectedDid.
 */
export type WalletErrorCode =
    // ── Runtime state ──────────────────────────────────────────────────────────
    | 'WALLET_LOCKED'
    | 'WALLET_KEY_NOT_FOUND'
    | 'WALLET_HARDWARE_UNAVAILABLE'
    | 'WALLET_USER_CANCELLED'
    | 'WALLET_INTERNAL_ERROR'
    // ── Signing / encryption ─────────────────────────────────────────────────────────
    | 'WALLET_SIGNATURE_FAILED'
    | 'WALLET_DECRYPT_FAILED'
    // ── Recovery ────────────────────────────────────────────────────────────────
    | 'WALLET_RECOVERY_INSUFFICIENT_SHARES'
    | 'WALLET_RECOVERY_INVALID_SHARE'
    | 'WALLET_RECOVERY_STALE_SHARE'
    | 'WALLET_RECOVERY_VERSION_UNVERIFIED'
    | 'WALLET_RECOVERY_DID_MISMATCH'
    // ── Topology ────────────────────────────────────────────────────────────────
    | 'WALLET_INVALID_TOPOLOGY'
    // ── Stub guard (stub-only fail-closed) ──────────────────
    | 'WALLET_STUB_NOT_FOR_PRODUCTION';
