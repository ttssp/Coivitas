/**
 * revocation/types.ts -- RevocationList SDK Client type definitions
 *
 * Responsibilities:
 *   - RevocationListPort: an interface abstracting backend RevocationApi behavior
 *     (DI injection; test mock + production RevocationApi implementation)
 *   - Client DTOs: CheckRevokedRequest / CheckRevokedResult / RevokeRequest / RevokeResult
 *     / ListRevocationsRequest / ListRevocationsResult
 *   - SDK-layer error types: RevocationClientError + RevocationClientErrorCode
 *
 * Design constraints (fail-closed + no brand cast):
 *   - fail-closed: an isRevoked query failure → throw, never return false;
 *     unknown revocation status → reject (do not treat as not revoked)
 *   - No bare `as RevocationListPort` cast; SDK consumers inject via the interface + factory
 *   - No stub default 200; every error must be 5xx + RevocationClientErrorCode
 *   - No partial-PASS: isRevoked must not return a partial verification result
 *
 */

import type {
    RevocationCheckResult,
    RevocationQueryFilters,
    RevocationRecord,
    RevocationWriteInput,
    RevocationWriteResult,
} from '@coivitas/policy';

// ---------------------------------------------------------------------------
// RevocationListPort -- abstracts backend RevocationApi behavior
// ---------------------------------------------------------------------------

/**
 * RevocationListPort: an interface abstracting RevocationApi backend behavior.
 *
 * Bottom line: inject via the interface to isolate the backend DB dependency.
 *   - Tests inject InMemoryRevocationPort (in-memory mock)
 *   - Production injects the RevocationApi adapter (packages/policy)
 *
 * Security constraints (fail-closed):
 *   - isRevoked: DB failure → throw (do not swallow the error and return false)
 *   - revoke: write failure → return a RevocationWriteResult with ok: false (do not throw)
 *   - getRevocations: DB failure → throw
 */
export interface RevocationListPort {
    /**
     * Query whether a token has been revoked.
     *
     * fail-closed: the implementation layer must throw on a DB failure; the caller
     * (RevocationListClient) catches it and converts it to
     * RevocationClientError(REVOCATION_CLIENT_CHECK_FAILED).
     *
     * @param tenantId tenant ID (multi-tenant isolation; required)
     * @param tokenId the credential/token ID being queried
     * @returns true = revoked / false = not revoked
     * @throws on an implementation-layer DB failure
     */
    isRevoked(tenantId: string, tokenId: string): Promise<boolean>;

    /**
     * Query a single revocation record exactly (with full RevocationRecord details).
     *
     * @throws on an implementation-layer DB failure
     */
    getRevocation(
        tenantId: string,
        tokenId: string,
    ): Promise<RevocationCheckResult>;

    /**
     * Revoke a token (write to the persistence layer).
     *
     * Idempotent: a duplicate revocation returns ok: false + REVOCATION_DUPLICATE (does not throw).
     *
     * @param input revocation write parameters
     * @returns RevocationWriteResult (discriminated union)
     */
    revoke(input: RevocationWriteInput): Promise<RevocationWriteResult>;

    /**
     * Batch query revocation records (pagination + filtering).
     *
     * @throws on an implementation-layer DB failure
     */
    getRevocations(filters: RevocationQueryFilters): Promise<RevocationRecord[]>;
}

// ---------------------------------------------------------------------------
// RevocationClientErrorCode -- SDK client error code namespace
// ---------------------------------------------------------------------------

/**
 * RevocationListClient SDK-layer error codes.
 *
 * Strictly separated from RevocationErrorCode (the SDK layer does not pass backend error codes through directly).
 * fail-closed: any unexpected state → REVOCATION_CLIENT_UNKNOWN_ERROR (never swallowed).
 */
export type RevocationClientErrorCode =
    /** isRevoked query failed (network error / backend DB error). */
    | 'REVOCATION_CLIENT_CHECK_FAILED'
    /** revoke operation failed (write failure; non-duplicate case). */
    | 'REVOCATION_CLIENT_REVOKE_FAILED'
    /** listRevocations query failed. */
    | 'REVOCATION_CLIENT_LIST_FAILED'
    /** tenantId is empty or malformed. */
    | 'REVOCATION_CLIENT_INVALID_TENANT'
    /** tokenId is empty or malformed. */
    | 'REVOCATION_CLIENT_INVALID_TOKEN_ID'
    /** Unexpected error (fail-closed: never swallowed). */
    | 'REVOCATION_CLIENT_UNKNOWN_ERROR';

// ---------------------------------------------------------------------------
// RevocationClientError -- SDK-layer error class
// ---------------------------------------------------------------------------

/**
 * RevocationListClient SDK-layer error.
 *
 * Carries an error code (machine-readable) + message (human-readable) + optional cause (original error chain).
 * fail-closed: every error must carry a RevocationClientErrorCode;
 * throwing a code-less Error('unknown') is forbidden.
 */
export class RevocationClientError extends Error {
    readonly code: RevocationClientErrorCode;

    constructor(
        message: string,
        code: RevocationClientErrorCode,
        cause?: unknown,
    ) {
        super(message);
        this.name = 'RevocationClientError';
        this.code = code;
        if (cause !== undefined) {
            (this as { cause?: unknown }).cause = cause;
        }
    }
}

// ---------------------------------------------------------------------------
// Client DTOs (used by SDK consumers; aligned with the backend RevocationRecord but simplified)
// ---------------------------------------------------------------------------

/**
 * checkRevoked() request parameters.
 */
export interface CheckRevokedRequest {
    /** tenant ID (required; multi-tenant isolation). */
    tenantId: string;
    /** the credential/token ID being queried. */
    tokenId: string;
}

/**
 * checkRevoked() result.
 *
 * fail-closed: the revoked field is strictly a boolean;
 * no 'unknown' extension (in contrast to ManagedServiceClient's degraded semantics).
 * An SDK client query failure → throw RevocationClientError (does not return unknown).
 */
export interface CheckRevokedResult {
    /** true = revoked / false = not revoked. */
    readonly revoked: boolean;
    /** cache-hit flag (true = LRU cache hit; false = backend query). */
    readonly fromCache: boolean;
}

/**
 * revokeCredential() request parameters.
 */
export interface RevokeCredentialRequest {
    /** tenant ID (required). */
    tenantId: string;
    /** the credential/token ID being revoked. */
    tokenId: string;
    /** the principal DID performing the revocation (audit accountability). */
    revokedBy: string;
    /** revocation reason (defaults to UNSPECIFIED). */
    reason?: string;
    /** the ID of the owning revocation list. */
    listId: string;
}

/**
 * revokeCredential() result (discriminated union).
 *
 * ok: true = a new revocation record was created; ok: false + duplicate = revocation already existed (idempotent).
 */
export type RevokeCredentialResult =
    | { readonly ok: true; readonly record: RevocationRecord }
    | { readonly ok: false; readonly duplicate: boolean; readonly message: string };

/**
 * listRevocations() request parameters.
 */
export interface ListRevocationsRequest {
    /** tenant ID (required). */
    tenantId: string;
    /** optional: filter exactly by token_id. */
    tokenId?: string;
    /** optional: filter by list_id. */
    listId?: string;
    /** optional: pagination limit (default 100; max 1000). */
    limit?: number;
    /** optional: pagination offset. */
    offset?: number;
}

/**
 * listRevocations() result.
 */
export interface ListRevocationsResult {
    readonly records: RevocationRecord[];
    readonly total: number;
}
