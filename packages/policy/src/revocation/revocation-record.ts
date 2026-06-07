/**
 * revocation-record.ts -- RevocationList L3 persistence-layer type definitions
 *
 * Corresponds to the v0.4.0 wire format:
 *   RevocationList.listVersion: Integer (monotonic)
 *   issuerSignature payload redefined to include listVersion
 *
 * Design constraints:
 *   - This file defines the L3 persistence-layer view (RevocationRecord), strictly separated from the L0 wire type.
 *   - The L0 wire type (packages/types/src/credentials/revocation-list.ts) is maintained separately;
 *     this layer does not redefine wire fields, only the persistence row view.
 *   - All raw DB strings must be validated at runtime; brand cast is forbidden.
 *   - fail-closed primitive; partial-PASS is forbidden.
 *   - stub default 200 is forbidden.
 *
 */

// ---------------------------------------------------------------------------
// RevocationReason -- revocation reason enum
// ---------------------------------------------------------------------------

/**
 * The set of valid revocation reason values.
 *
 * fail-closed: DB-stored values must be validated through parseRevocationReason.
 */
export const REVOCATION_REASONS = [
    'KEY_COMPROMISE',
    'AFFILIATION_CHANGED',
    'SUPERSEDED',
    'CESSATION_OF_OPERATION',
    'PRIVILEGE_WITHDRAWN',
    'UNSPECIFIED',
] as const;

/** Revocation reason type (discriminant). */
export type RevocationReason = (typeof REVOCATION_REASONS)[number];

/**
 * Runtime type guard: verifies whether a value is a valid RevocationReason.
 * Use this function instead of a brand cast (brand coercion is forbidden).
 */
export function isRevocationReason(value: unknown): value is RevocationReason {
    return (
        typeof value === 'string' &&
        (REVOCATION_REASONS as readonly string[]).includes(value)
    );
}

/**
 * Parse a RevocationReason from a raw DB string; throws when invalid (fail-closed).
 *
 * @throws Error if value is not a valid RevocationReason
 */
export function parseRevocationReason(value: unknown): RevocationReason {
    if (!isRevocationReason(value)) {
        throw new Error(
            `RevocationRecord: invalid reason value from DB: ${JSON.stringify(value)}. ` +
                `Expected one of: ${REVOCATION_REASONS.join(', ')}`,
        );
    }
    return value;
}

// ---------------------------------------------------------------------------
// IssuerSignaturePayload -- the signed payload of issuerSignature (v0.4.0)
// ---------------------------------------------------------------------------

/**
 * The signed payload of issuerSignature.
 *
 * v0.4.0 redefinition: the payload must include listVersion (monotonic Integer).
 * The signature uses JCS RFC 8785 canonical serialization over the entire payload object (excluding the signature itself).
 *
 */
export interface IssuerSignaturePayload {
    /** Issuer DID (the signer's identity anchor). */
    readonly issuerDid: string;
    /** List identifier (unique within a single tenantId). */
    readonly listId: string;
    /** Monotonically increasing version number (added in v0.4.0; incremented on each revocation write). */
    readonly listVersion: number;
    /** Tenant ID (multi-tenant isolation). */
    readonly tenantId: string;
    /** Payload generation timestamp (ISO 8601). */
    readonly issuedAt: string;
}

/**
 * Validate at runtime that a raw DB JSONB value is a valid IssuerSignaturePayload (brand coercion forbidden).
 *
 * Replaces a bare `as IssuerSignaturePayload` cast; performs presence + basic-type checks on all required fields.
 * fail-closed: throws directly on any missing field or wrong type.
 *
 * @param raw the raw JSONB value read back from the DB (unknown)
 * @returns the validated IssuerSignaturePayload
 * @throws Error on a missing field / wrong type
 */
export function validateIssuerSignaturePayload(
    raw: unknown,
): IssuerSignaturePayload {
    if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
        throw new Error(
            `RevocationRecord: IssuerSignaturePayload must be a non-null object, got: ${JSON.stringify(raw)}`,
        );
    }
    const obj = raw as Record<string, unknown>;

    if (typeof obj['issuerDid'] !== 'string' || obj['issuerDid'] === '') {
        throw new Error(
            `RevocationRecord: IssuerSignaturePayload.issuerDid must be a non-empty string, got: ${JSON.stringify(obj['issuerDid'])}`,
        );
    }
    if (typeof obj['listId'] !== 'string' || obj['listId'] === '') {
        throw new Error(
            `RevocationRecord: IssuerSignaturePayload.listId must be a non-empty string, got: ${JSON.stringify(obj['listId'])}`,
        );
    }
    if (typeof obj['listVersion'] !== 'number' || obj['listVersion'] < 1 || !Number.isInteger(obj['listVersion'])) {
        throw new Error(
            `RevocationRecord: IssuerSignaturePayload.listVersion must be a positive integer >= 1, got: ${JSON.stringify(obj['listVersion'])}`,
        );
    }
    if (typeof obj['tenantId'] !== 'string' || obj['tenantId'] === '') {
        throw new Error(
            `RevocationRecord: IssuerSignaturePayload.tenantId must be a non-empty string, got: ${JSON.stringify(obj['tenantId'])}`,
        );
    }
    if (typeof obj['issuedAt'] !== 'string' || obj['issuedAt'] === '') {
        throw new Error(
            `RevocationRecord: IssuerSignaturePayload.issuedAt must be a non-empty string, got: ${JSON.stringify(obj['issuedAt'])}`,
        );
    }

    return {
        issuerDid: obj['issuerDid'],
        listId: obj['listId'],
        listVersion: obj['listVersion'],
        tenantId: obj['tenantId'],
        issuedAt: obj['issuedAt'],
    };
}

// ---------------------------------------------------------------------------
// RevocationRecord -- L3 persistence-layer row view (policy.revocation_records)
// ---------------------------------------------------------------------------

/**
 * L3 persistence-layer row view (policy.revocation_records).
 *
 * Field mapping (snake_case -> camelCase):
 *   id -> id
 *   tenant_id -> tenantId
 *   token_id -> tokenId
 *   revoked_by -> revokedBy
 *   revoked_at -> revokedAt
 *   reason -> reason
 *   list_id -> listId
 *   list_version -> listVersion (v0.4.0)
 *   issuer_signature_payload -> issuerSignaturePayload (JSONB)
 */
export interface RevocationRecord {
    /** DB UUID primary key (generated at the application layer). */
    readonly id: string;
    /** Tenant ID (multi-tenant isolation; non-empty). */
    readonly tenantId: string;
    /** The revoked credential/token ID. */
    readonly tokenId: string;
    /** DID of the subject that performed the revocation (audit accountability). */
    readonly revokedBy: string;
    /** Revocation timestamp (DB server-side time). */
    readonly revokedAt: Date;
    /** Revocation reason (fail-closed enum; UNSPECIFIED = not specified). */
    readonly reason: RevocationReason;
    /** Owning revocation list ID (uniquely identifies one RevocationList within a single tenantId). */
    readonly listId: string;
    /**
     * Monotonically increasing revocation-list version number (v0.4.0).
     *
     * Incremented (+1) on each revocation record written to the list.
     * Initial value is 1 (listVersion = 1 when the first record is written).
     */
    readonly listVersion: number;
    /**
     * The signed payload of issuerSignature (stored as JSONB).
     *
     * Includes listVersion; the signature uses JCS RFC 8785 canonical serialization.
     * null = not yet signed (populated by revocation-api at write time).
     */
    readonly issuerSignaturePayload: IssuerSignaturePayload | null;
}

// ---------------------------------------------------------------------------
// RevocationErrorCode -- REVOCATION_* error code namespace
// ---------------------------------------------------------------------------

/**
 * REVOCATION_* error code namespace.
 *
 * Does not collide with existing error codes:
 *   - STUB_REVOCATION_NOT_FOR_PRODUCTION (managed-service-runtime; not in this namespace)
 *   - REVOCATION_CHECK_FAILED (managed-service-runtime; not in this namespace)
 *
 * Constraint: prefer reusing an existing error code before considering a new one.
 *
 */
export type RevocationErrorCode =
    /** token_id already has a revocation record under this tenant (idempotent dedup; a duplicate operation returns this code). */
    | 'REVOCATION_DUPLICATE'
    /** tenant_id or token_id is missing or malformed. */
    | 'REVOCATION_INVALID_PARAMS'
    /** listVersion does not satisfy the monotonic increase constraint (concurrent write conflict). */
    | 'REVOCATION_LIST_VERSION_CONFLICT'
    /** An internal error occurred during a DB query or write (must not be surfaced to end users). */
    | 'REVOCATION_STORE_ERROR'
    /** Cache operation failed (degrade: go straight to DB; non-terminal error). */
    | 'REVOCATION_CACHE_ERROR';

// ---------------------------------------------------------------------------
// RevocationQueryFilters -- query filter parameters
// ---------------------------------------------------------------------------

/**
 * Revocation record query filter parameters.
 *
 * Every query MUST provide tenantId (multi-tenant isolation precondition).
 */
export interface RevocationQueryFilters {
    /** Required: tenant ID (isolation boundary). */
    tenantId: string;
    /** Optional: exact lookup by token_id. */
    tokenId?: string;
    /** Optional: filter by list_id. */
    listId?: string;
    /** Optional: filter by revocation time range (closed interval). */
    revokedAfter?: Date;
    revokedBefore?: Date;
    /** Optional: pagination limit (default 100; max 1000). */
    limit?: number;
    /** Optional: offset (for cursor-based pagination). */
    offset?: number;
}

// ---------------------------------------------------------------------------
// RevocationWriteInput -- revoke write input
// ---------------------------------------------------------------------------

/**
 * Revoke write input (revoke() parameters).
 *
 * listVersion is auto-incremented internally by the store and is not supplied by the caller.
 */
export interface RevocationWriteInput {
    /** Tenant ID (multi-tenant isolation). */
    tenantId: string;
    /** The revoked credential/token ID. */
    tokenId: string;
    /** DID of the subject that performed the revocation. */
    revokedBy: string;
    /** Revocation reason (default UNSPECIFIED). */
    reason?: RevocationReason;
    /** Owning revocation list ID (a single tenant may have multiple lists). */
    listId: string;
    /** The signed payload of issuerSignature (optional; populated by the API layer). */
    issuerSignaturePayload?: IssuerSignaturePayload;
}

// ---------------------------------------------------------------------------
// RevocationWriteResult -- revoke write result (discriminated union)
// ---------------------------------------------------------------------------

/** Revoke write success result. */
export interface RevocationWriteSuccess {
    readonly ok: true;
    readonly record: RevocationRecord;
}

/** Revoke write failure (duplicate revoke or internal error). */
export interface RevocationWriteFailure {
    readonly ok: false;
    readonly code: RevocationErrorCode;
    readonly message: string;
}

/** Revoke write result (discriminated union). */
export type RevocationWriteResult =
    | RevocationWriteSuccess
    | RevocationWriteFailure;

// ---------------------------------------------------------------------------
// RevocationCheckResult -- revocation query result (discriminated union)
// ---------------------------------------------------------------------------

/** Token has been revoked. */
export interface RevocationFound {
    readonly found: true;
    readonly record: RevocationRecord;
}

/** Token has not been revoked (no revocation record under this tenant). */
export interface RevocationNotFound {
    readonly found: false;
}

/** Revocation query result (discriminated union). */
export type RevocationCheckResult = RevocationFound | RevocationNotFound;
