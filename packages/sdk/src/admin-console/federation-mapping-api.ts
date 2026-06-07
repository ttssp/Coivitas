/**
 * federation-mapping-api.ts -- IdpMapping CRUD Admin API
 *
 * Responsibilities:
 *   - FederationMappingAdminClient: admin-only entry point for IdpMapping CRUD operations
 *     - listMappings: list all IdpMappings (admin, or tenant-admin scoped to its own tenant)
 *     - getMapping: fetch a single IdpMapping
 *     - createMapping: create an IdpMapping (admin only; writes security-sensitive fields)
 *     - updateMapping: update an IdpMapping (admin only; supports updating signing cert / JWKS URI)
 *     - deleteMapping: delete an IdpMapping (admin only)
 *
 * Design motivation:
 *   SSO admins need an RBAC-protected CRUD management API for IdpMapping.
 *   The original TenantFederationAdapter.findIdpMapping is read-only;
 *   this module adds admin-only write operations, injected via FederationMappingPort (no brand cast).
 *
 * Caller bypass-prevention design (callerTenantId=null sentinel bypass -> Caller discriminated union):
 *   The original `callerTenantId: string | null` design let an attacker explicitly pass null to bypass the cross-tenant guard.
 *   Fix: introduce a Caller discriminated union (kind: 'global-admin' | 'tenant-scoped').
 *   Enforced by the type system: a tenant-scoped caller must carry a tenantId; the guard cannot be bypassed at runtime.
 *
 * Design constraints (fail-closed + no brand cast + security guards):
 *   - fail-closed: every Port exception -> throw FederationMappingError (no swallowing)
 *   - FederationMappingPort is injected via the interface (no bare instantiation or `as FederationMappingPort`)
 *   - the Caller union is constructed only via the globalAdminCaller() / tenantScopedCaller() factories (no bare cast)
 *   - security constraint: modifying idpSigningCert / idpJwksUri -> admin role required (tenant-admin may not write)
 *   - no partial-PASS: get/list failure -> throw (never return partial results)
 *   - RBAC fail-closed: no role / unknown role -> AdminRbacError (no bypass)
 *   - no stub default 200; every error -> FederationMappingError with errorCode
 *
 */

import { createHash } from 'node:crypto';

import type { IdpMapping } from '../sso/tenant-federation.js';
import type { AdminRole } from './types.js';
import { parseAdminRole, AdminRbacError } from './types.js';
import { hasPermission } from './rbac.js';

// ---------------------------------------------------------------------------
// Caller discriminated union
// ---------------------------------------------------------------------------

/**
 * Caller: discriminated union for the caller's identity.
 *
 * Conclusion: replaces the original `callerTenantId: string | null` design;
 * the null sentinel let an attacker explicitly pass null to bypass the cross-tenant guard.
 * The discriminated union makes that attack vector inexpressible at the type level:
 *   - global-admin: global admin, no tenant restriction (no tenantId field)
 *   - tenant-scoped: tenant admin, carries tenantId (cannot be omitted / cannot be null)
 *
 * Anti brand-cast: constructed only via the globalAdminCaller() / tenantScopedCaller() factories;
 * a bare `as Caller` cast is forbidden.
 */
export type Caller =
    | { readonly kind: 'global-admin' }
    | { readonly kind: 'tenant-scoped'; readonly tenantId: string };

/**
 * globalAdminCaller: construct a global-admin Caller (the only legal construction path; no brand cast).
 *
 * Use case: invocations by a global admin role (no tenant restriction).
 */
export function globalAdminCaller(): Caller {
    return { kind: 'global-admin' };
}

/**
 * tenantScopedCaller: construct a tenant-scoped Caller (the only legal construction path; no brand cast).
 *
 * Note: throws a runtime Error when tenantId is empty (not FederationMappingError, since that class is not yet defined at construction time).
 * In practice the caller (the middleware layer) never reaches here with an empty tenantId (the auth layer intercepts it first).
 *
 * @param tenantId the caller's tenant ID (from the auth context; must not be an empty string)
 * @throws Error if tenantId is empty (caller responsibility: ensure tenantId is non-empty before calling)
 */
export function tenantScopedCaller(tenantId: string): Caller {
    if (!tenantId || tenantId.trim() === '') {
        throw new Error('tenantScopedCaller: tenantId must be a non-empty string');
    }
    return { kind: 'tenant-scoped', tenantId };
}

// ---------------------------------------------------------------------------
// FederationMappingAuditEvent -- audit event for CUD operations
// ---------------------------------------------------------------------------

/**
 * FederationMappingAuditEvent: audit event for CUD operations on the federation_mapping table.
 *
 * Security constraint (P0): idpSigningCert / idpJwksUri are trust-chain entry points and must not be written to the audit log in cleartext;
 * only the first 16 bytes (32 hex chars) of sha256(cert/uri) are written as a fingerprint, so security audits can track changes.
 */
export interface FederationMappingAuditEvent {
    /** Operation type. */
    readonly eventType:
        | 'federation_mapping.created'
        | 'federation_mapping.updated'
        | 'federation_mapping.deleted';
    /** The IdpMapping id involved in the operation. */
    readonly mappingId: string;
    /** The IdpMapping's idpIdentifier. */
    readonly idpIdentifier: string;
    /** The tenant context of the admin user performing the operation (global admin = 'system'). */
    readonly actorTenantId: string;
    /** Timestamp (ISO 8601). */
    readonly timestamp: string;
    /**
     * sha256 hash prefix of a security-sensitive field (first 16 bytes only, 32 hex chars).
     *
     * Conclusion: the cleartext cert / uri is never recorded; only the hash fingerprint is written so security audits can track trust-chain changes.
     * Written on create / update only (not needed for delete).
     */
    readonly certHashPrefix?: string;
    readonly jwksUriHashPrefix?: string;
}

// ---------------------------------------------------------------------------
// FederationMappingPort -- abstracts IdpMapping persistence-layer behavior
// ---------------------------------------------------------------------------

/**
 * FederationMappingPort: interface abstracting CRUD behavior over the federation_mapping table.
 *
 * Conclusion: injected via the interface to isolate the DB dependency (no brand cast):
 *   - tests inject InMemoryFederationMappingPort (in-memory mock)
 *   - production injects TenantFederationAdapter (or a dedicated adapter)
 *
 * Security constraint (P0 signing cert / JWKS URI fields):
 *   - create / update: the caller (FederationMappingAdminClient) is responsible for verifying the admin role
 *   - delete: the caller is responsible for verifying the admin role
 *   - Port implementations do not perform RBAC (RBAC lives in the client layer; the Port only does persistence-layer work)
 */
export interface FederationMappingPort {
    /**
     * List all IdpMappings (supports filtering by tenantId).
     *
     * @param filter optional filter criteria
     * @throws on an implementation-layer DB exception
     */
    listMappings(filter?: {
        tenantId?: string;
        idpType?: 'saml' | 'oidc';
        offset?: number;
        limit?: number;
    }): Promise<IdpMapping[]>;

    /**
     * Fetch a single IdpMapping by id.
     *
     * @returns the IdpMapping, or null if it does not exist
     * @throws on an implementation-layer DB exception
     */
    getMapping(id: string): Promise<IdpMapping | null>;

    /**
     * Create an IdpMapping.
     *
     * @throws on an implementation-layer DB exception (including a duplicate idpIdentifier conflict)
     */
    createMapping(input: FederationMappingCreateInput): Promise<IdpMapping>;

    /**
     * Update an IdpMapping (partial update; undefined fields are left unchanged).
     *
     * @returns the updated IdpMapping; null if the id does not exist
     * @throws on an implementation-layer DB exception
     */
    updateMapping(id: string, patch: FederationMappingPatch): Promise<IdpMapping | null>;

    /**
     * Delete an IdpMapping.
     *
     * @returns true = deleted successfully; false = record does not exist (idempotent)
     * @throws on an implementation-layer DB exception
     */
    deleteMapping(id: string): Promise<boolean>;

    /**
     * Write a federation_mapping CUD audit event.
     *
     * Conclusion: the audit is written asynchronously after the CUD operation; a failure does not block the main operation (safeWriteAuditEvent degrades gracefully).
     *
     * @throws on an implementation-layer write failure (caught and degraded by safeWriteAuditEvent)
     */
    writeAuditEvent(event: FederationMappingAuditEvent): Promise<void>;
}

// ---------------------------------------------------------------------------
// FederationMappingCreateInput / Patch
// ---------------------------------------------------------------------------

/**
 * Input parameters for creating an IdpMapping.
 *
 * Security constraint (P0): idpSigningCert / idpJwksUri are SSO trust-chain entry points;
 * only the admin role may write them (FederationMappingAdminClient verifies this before calling the Port).
 */
export interface FederationMappingCreateInput {
    /** IDP identifier (SAML EntityID or OIDC issuer; unique). */
    readonly idpIdentifier: string;
    /** IDP type. */
    readonly idpType: 'saml' | 'oidc';
    /**
     * Set of allowed tenant_ids (array of UUIDs).
     *
     * Security invariant: this field is the core defense against cross-tenant assertion substitution attacks;
     * it must be non-empty (at least 1 tenantId).
     */
    readonly allowedTenantIds: readonly string[];
    /**
     * IDP signing certificate (SAML; PEM format; optional).
     *
     * Security warning: this field is a SAML verification trust-chain entry point; only the admin role may write it.
     */
    readonly idpSigningCert?: string;
    /**
     * IDP JWKS URI (OIDC; optional).
     *
     * Security warning: this field is an OIDC verification trust-chain entry point; only the admin role may write it.
     */
    readonly idpJwksUri?: string;
}

/**
 * Partial fields for updating an IdpMapping (undefined = unchanged).
 *
 * Security constraint (P0): modifying idpSigningCert / idpJwksUri -> admin role required.
 */
export interface FederationMappingPatch {
    readonly allowedTenantIds?: readonly string[];
    /** Security warning: modifying this field is a trust-chain change; only the admin role may write it. */
    readonly idpSigningCert?: string;
    /** Security warning: modifying this field is a trust-chain change; only the admin role may write it. */
    readonly idpJwksUri?: string;
}

// ---------------------------------------------------------------------------
// FederationMappingErrorCode / FederationMappingError
// ---------------------------------------------------------------------------

/**
 * FederationMappingAdminClient error codes.
 *
 * fail-closed: every unexpected state -> FEDERATION_MAPPING_UNKNOWN_ERROR (no swallowing).
 */
export type FederationMappingErrorCode =
    /** RBAC role missing. */
    | 'FEDERATION_MAPPING_ROLE_MISSING'
    /** Insufficient RBAC permission (not admin). */
    | 'FEDERATION_MAPPING_PERMISSION_DENIED'
    /** Target IdpMapping does not exist. */
    | 'FEDERATION_MAPPING_NOT_FOUND'
    /** Invalid request parameters (empty idpIdentifier / empty allowedTenantIds, etc.). */
    | 'FEDERATION_MAPPING_INVALID_INPUT'
    /** List operation failed (DB exception). */
    | 'FEDERATION_MAPPING_LIST_FAILED'
    /** Get operation failed (DB exception). */
    | 'FEDERATION_MAPPING_GET_FAILED'
    /** Create operation failed (DB exception / duplicate). */
    | 'FEDERATION_MAPPING_CREATE_FAILED'
    /** Update operation failed (DB exception). */
    | 'FEDERATION_MAPPING_UPDATE_FAILED'
    /** Delete operation failed (DB exception). */
    | 'FEDERATION_MAPPING_DELETE_FAILED'
    /** Cross-tenant access denied (tenant-admin accessing a mapping outside its own tenant). */
    | 'FEDERATION_MAPPING_TENANT_MISMATCH'
    /** Caller type mismatch (a global-admin caller passed to a tenant-admin path, or vice versa). */
    | 'FEDERATION_MAPPING_CALLER_INCONSISTENT'
    /** Operation requires a global-admin caller (a tenant-scoped caller is not accepted). */
    | 'FEDERATION_MAPPING_ADMIN_REQUIRED'
    /** Unexpected error (fail-closed; no swallowing). */
    | 'FEDERATION_MAPPING_UNKNOWN_ERROR';

/**
 * FederationMappingAdminClient SDK-layer error.
 *
 * fail-closed: every error must carry a FederationMappingErrorCode;
 * throwing a bare Error('unknown') without a code is forbidden.
 */
export class FederationMappingError extends Error {
    readonly code: FederationMappingErrorCode;

    constructor(
        message: string,
        code: FederationMappingErrorCode,
        cause?: unknown,
    ) {
        super(message);
        this.name = 'FederationMappingError';
        this.code = code;
        if (cause !== undefined) {
            (this as { cause?: unknown }).cause = cause;
        }
    }
}

// ---------------------------------------------------------------------------
// FederationMappingAdminClientConfig
// ---------------------------------------------------------------------------

/**
 * FederationMappingAdminClient construction config.
 *
 * FederationMappingPort is injected via the interface (no bare cast).
 */
export interface FederationMappingAdminClientConfig {
    /**
     * FederationMappingPort (required; IdpMapping persistence-layer operations).
     * Injected via the FederationMappingPort interface; a bare `as FederationMappingPort` cast is not allowed.
     */
    readonly port: FederationMappingPort;
}

// ---------------------------------------------------------------------------
// Request / Response DTO
// ---------------------------------------------------------------------------

export interface ListMappingsRequest {
    /** Caller's role (RBAC check; from the X-Role header or a JWT claim). */
    readonly role: string;
    /**
     * Caller's identity (from the auth context; injected by middleware).
     *
     * The original `callerTenantId: string | null` let an attacker pass null to bypass the cross-tenant guard;
     * fixed to a Caller discriminated union:
     *   - global-admin: no tenant restriction (no tenantId field; the type system forbids passing null)
     *   - tenant-scoped: must carry tenantId (cannot be omitted)
     *
     * Constructed only via the globalAdminCaller() / tenantScopedCaller() factories.
     */
    readonly caller: Caller;
    /** Optional: filter by tenantId (a tenant-admin may only query its own tenant). */
    readonly tenantId?: string;
    /** Optional: filter by idpType. */
    readonly idpType?: 'saml' | 'oidc';
    readonly offset?: number;
    readonly limit?: number;
}

export interface ListMappingsResult {
    readonly mappings: IdpMapping[];
    readonly total: number;
}

export interface GetMappingRequest {
    readonly role: string;
    /**
     * Caller's identity (from the auth context; injected by middleware).
     *
     * The original `callerTenantId: string | null` let an attacker pass null to bypass the cross-tenant guard;
     * fixed to a Caller discriminated union (same as ListMappingsRequest).
     *
     * Constructed only via the globalAdminCaller() / tenantScopedCaller() factories.
     */
    readonly caller: Caller;
    /** IdpMapping id (UUID). */
    readonly id: string;
}

export interface CreateMappingRequest {
    /** Caller's role (must be admin; P0 security constraint). */
    readonly role: string;
    readonly input: FederationMappingCreateInput;
}

export interface UpdateMappingRequest {
    /** Caller's role (must be admin; P0 security constraint). */
    readonly role: string;
    readonly id: string;
    readonly patch: FederationMappingPatch;
}

export interface DeleteMappingRequest {
    /** Caller's role (must be admin; P0 security constraint). */
    readonly role: string;
    readonly id: string;
    /** Confirmation string (guards against accidental deletion; must equal id). */
    readonly confirmId: string;
}

// ---------------------------------------------------------------------------
// InMemoryFederationMappingPort -- in-memory mock for tests
// ---------------------------------------------------------------------------

/**
 * InMemoryFederationMappingPort: in-memory implementation of FederationMappingPort (for tests).
 *
 * No brand cast: implements the FederationMappingPort interface; does not expose the internal store field (injected via the interface).
 * fail-closed: after fault injection (injectError), all operations throw.
 */
export class InMemoryFederationMappingPort implements FederationMappingPort {
    private readonly store: Map<string, IdpMapping> = new Map();
    private readonly auditLog: FederationMappingAuditEvent[] = [];
    private _error: Error | undefined;

    /** For tests: inject an error (all subsequent operations throw). */
    injectError(err: Error): void {
        this._error = err;
    }

    /** For tests: clear the injected error. */
    clearError(): void {
        this._error = undefined;
    }

    /** For tests: preseed an IdpMapping (bypasses RBAC; writes directly to the store). */
    seed(mapping: IdpMapping): void {
        this.store.set(mapping.id, mapping);
    }

    /** For tests: get the list of written audit events (to verify audit calls). */
    getAuditEvents(): readonly FederationMappingAuditEvent[] {
        return this.auditLog;
    }

    listMappings(filter?: {
        tenantId?: string;
        idpType?: 'saml' | 'oidc';
        offset?: number;
        limit?: number;
    }): Promise<IdpMapping[]> {
        if (this._error !== undefined) return Promise.reject(this._error);
        let results = Array.from(this.store.values());
        if (filter?.tenantId !== undefined) {
            const t = filter.tenantId;
            results = results.filter(m => m.allowedTenantIds.includes(t));
        }
        if (filter?.idpType !== undefined) {
            const tp = filter.idpType;
            results = results.filter(m => m.idpType === tp);
        }
        const offset = filter?.offset ?? 0;
        const limit = filter?.limit ?? 100;
        return Promise.resolve(results.slice(offset, offset + limit));
    }

    getMapping(id: string): Promise<IdpMapping | null> {
        if (this._error !== undefined) return Promise.reject(this._error);
        return Promise.resolve(this.store.get(id) ?? null);
    }

    createMapping(input: FederationMappingCreateInput): Promise<IdpMapping> {
        if (this._error !== undefined) return Promise.reject(this._error);
        // Duplicate idpIdentifier check (mock)
        for (const m of this.store.values()) {
            if (m.idpIdentifier === input.idpIdentifier) {
                return Promise.reject(new Error(`Duplicate idpIdentifier: ${input.idpIdentifier}`));
            }
        }
        const now = new Date().toISOString();
        const id = `mock-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
        const mapping: IdpMapping = {
            id,
            idpIdentifier: input.idpIdentifier,
            idpType: input.idpType,
            allowedTenantIds: input.allowedTenantIds,
            idpSigningCert: input.idpSigningCert,
            idpJwksUri: input.idpJwksUri,
            createdAt: now,
            updatedAt: now,
        };
        this.store.set(id, mapping);
        return Promise.resolve(mapping);
    }

    updateMapping(id: string, patch: FederationMappingPatch): Promise<IdpMapping | null> {
        if (this._error !== undefined) return Promise.reject(this._error);
        const existing = this.store.get(id);
        if (existing === undefined) return Promise.resolve(null);
        const updated: IdpMapping = {
            ...existing,
            allowedTenantIds: patch.allowedTenantIds ?? existing.allowedTenantIds,
            idpSigningCert: patch.idpSigningCert !== undefined ? patch.idpSigningCert : existing.idpSigningCert,
            idpJwksUri: patch.idpJwksUri !== undefined ? patch.idpJwksUri : existing.idpJwksUri,
            updatedAt: new Date().toISOString(),
        };
        this.store.set(id, updated);
        return Promise.resolve(updated);
    }

    deleteMapping(id: string): Promise<boolean> {
        if (this._error !== undefined) return Promise.reject(this._error);
        return Promise.resolve(this.store.delete(id));
    }

    writeAuditEvent(event: FederationMappingAuditEvent): Promise<void> {
        if (this._error !== undefined) return Promise.reject(this._error);
        this.auditLog.push(event);
        return Promise.resolve();
    }
}

// ---------------------------------------------------------------------------
// FederationMappingAdminClient
// ---------------------------------------------------------------------------

/**
 * FederationMappingAdminClient: RBAC-protected, admin-only entry point for IdpMapping CRUD operations.
 *
 * Security constraints (P0 — trust-chain protection):
 *   - createMapping / updateMapping (including idpSigningCert / idpJwksUri) / deleteMapping:
 *     require the admin role (tenant-admin or viewer may not write)
 *   - listMappings / getMapping: admin or tenant-admin may query (tenant-admin is restricted by the tenantId filter)
 *
 * fail-closed: every Port exception -> throw FederationMappingError with a code;
 * no swallowing + no stub default 200;
 * no partial-PASS.
 *
 * Usage example:
 * ```ts
 * const client = new FederationMappingAdminClient({ port: new InMemoryFederationMappingPort() });
 *
 * // List mappings (admin sees all; tenant-admin is filtered to its own tenant)
 * const { mappings } = await client.listMappings({ role: 'admin' });
 *
 * // Create a mapping (admin only)
 * const mapping = await client.createMapping({
 *   role: 'admin',
 *   input: {
 *     idpIdentifier: 'https://idp.example.com',
 *     idpType: 'oidc',
 *     allowedTenantIds: ['tenant-1'],
 *     idpJwksUri: 'https://idp.example.com/.well-known/jwks.json',
 *   },
 * });
 * ```
 */
export class FederationMappingAdminClient {
    private readonly port: FederationMappingPort;

    constructor(config: FederationMappingAdminClientConfig) {
        this.port = config.port;
    }

    // -------------------------------------------------------------------------
    // listMappings -- list IdpMappings
    // -------------------------------------------------------------------------

    /**
     * List all IdpMappings.
     *
     * RBAC: admin / tenant-admin may access (viewer has no permission).
     * A tenant-admin may only query mappings whose allowedTenantIds include its own tenantId (a tenantId filter must be supplied).
     *
     * fail-closed: Port exception -> throw FederationMappingError(FEDERATION_MAPPING_LIST_FAILED).
     *
     * @throws FederationMappingError(FEDERATION_MAPPING_ROLE_MISSING) role missing
     * @throws FederationMappingError(FEDERATION_MAPPING_PERMISSION_DENIED) insufficient permission
     * @throws FederationMappingError(FEDERATION_MAPPING_LIST_FAILED) DB exception
     */
    async listMappings(req: ListMappingsRequest): Promise<ListMappingsResult> {
        // IdpMapping contains SSO trust-chain data (idpSigningCert / idpJwksUri);
        // the viewer role only holds the generic tenant:list permission but must not access IdpMapping (P0 trust-chain protection).
        // Only admin / tenant-admin may access the federation mapping list.
        const role = this._requireFederationReadRole(req.role);

        // A tenant-admin may only query mappings within its own tenant (P0 isolation).
        const tenantIdFilter = req.tenantId;
        if (role === 'tenant-admin' && tenantIdFilter === undefined) {
            throw new FederationMappingError(
                'FederationMappingAdminClient: tenant-admin must specify tenantId for listMappings',
                'FEDERATION_MAPPING_INVALID_INPUT',
            );
        }

        // Use the Caller discriminated union;
        // global-admin has no cross-tenant restriction; tenant-scoped must match the tenantId filter.
        // The original `callerTenantId !== null` guard short-circuited when an attacker passed null (bypass vulnerability);
        // new design: a tenant-scoped caller's tenantId field is never null/undefined (guaranteed by the type system).
        if (role === 'tenant-admin' && req.caller.kind === 'tenant-scoped') {
            // A tenant-admin must use a tenant-scoped caller, and tenantId must match caller.tenantId.
            if (tenantIdFilter !== undefined && tenantIdFilter !== req.caller.tenantId) {
                throw new FederationMappingError(
                    `FederationMappingAdminClient: tenant-admin caller tenantId "${req.caller.tenantId}" does not match requested tenantId "${tenantIdFilter}"`,
                    'FEDERATION_MAPPING_TENANT_MISMATCH',
                );
            }
        } else if (role === 'tenant-admin' && req.caller.kind === 'global-admin') {
            // tenant-admin role passed a global-admin caller -> inconsistent caller context (fail-closed)
            throw new FederationMappingError(
                'FederationMappingAdminClient: role is "tenant-admin" but caller is global-admin; use tenantScopedCaller(tenantId)',
                'FEDERATION_MAPPING_CALLER_INCONSISTENT',
            );
        }

        let mappings: IdpMapping[];
        try {
            mappings = await this.port.listMappings({
                tenantId: tenantIdFilter,
                idpType: req.idpType,
                offset: req.offset,
                limit: req.limit,
            });
        } catch (err) {
            throw new FederationMappingError(
                `FederationMappingAdminClient: listMappings failed: ${String(err)}`,
                'FEDERATION_MAPPING_LIST_FAILED',
                err,
            );
        }
        return { mappings, total: mappings.length };
    }

    // -------------------------------------------------------------------------
    // getMapping -- fetch a single IdpMapping
    // -------------------------------------------------------------------------

    /**
     * Fetch a single IdpMapping.
     *
     * RBAC: admin / tenant-admin / viewer may all access (read-only).
     * fail-closed: Port exception -> throw FederationMappingError(FEDERATION_MAPPING_GET_FAILED).
     *
     * @throws FederationMappingError(FEDERATION_MAPPING_ROLE_MISSING) role missing
     * @throws FederationMappingError(FEDERATION_MAPPING_NOT_FOUND) record does not exist
     * @throws FederationMappingError(FEDERATION_MAPPING_GET_FAILED) DB exception
     */
    async getMapping(req: GetMappingRequest): Promise<IdpMapping> {
        const role = this._requireFederationReadRole(req.role);
        if (!req.id || req.id.trim() === '') {
            throw new FederationMappingError(
                'FederationMappingAdminClient: id is required for getMapping',
                'FEDERATION_MAPPING_INVALID_INPUT',
            );
        }
        let mapping: IdpMapping | null;
        try {
            mapping = await this.port.getMapping(req.id);
        } catch (err) {
            throw new FederationMappingError(
                `FederationMappingAdminClient: getMapping failed: ${String(err)}`,
                'FEDERATION_MAPPING_GET_FAILED',
                err,
            );
        }
        if (mapping === null) {
            throw new FederationMappingError(
                `FederationMappingAdminClient: IdpMapping not found: id="${req.id}"`,
                'FEDERATION_MAPPING_NOT_FOUND',
            );
        }
        // Use the Caller discriminated union;
        // a tenant-scoped caller's tenantId must be present in mapping.allowedTenantIds.
        // The original `callerTenantId !== null` guard short-circuited when an attacker passed null (bypass vulnerability).
        if (role === 'tenant-admin' && req.caller.kind === 'tenant-scoped') {
            if (!mapping.allowedTenantIds.includes(req.caller.tenantId)) {
                throw new FederationMappingError(
                    `FederationMappingAdminClient: tenant-admin caller tenantId "${req.caller.tenantId}" is not in allowedTenantIds for mapping id="${req.id}"`,
                    'FEDERATION_MAPPING_TENANT_MISMATCH',
                );
            }
        } else if (role === 'tenant-admin' && req.caller.kind === 'global-admin') {
            // tenant-admin role passed a global-admin caller -> inconsistent caller context (fail-closed)
            throw new FederationMappingError(
                'FederationMappingAdminClient: role is "tenant-admin" but caller is global-admin; use tenantScopedCaller(tenantId)',
                'FEDERATION_MAPPING_CALLER_INCONSISTENT',
            );
        }
        return mapping;
    }

    // -------------------------------------------------------------------------
    // createMapping -- create an IdpMapping (admin only)
    // -------------------------------------------------------------------------

    /**
     * Create an IdpMapping.
     *
     * RBAC (P0 security constraint): only the admin role may create (idpSigningCert / idpJwksUri are trust-chain entry points).
     * Input validation: idpIdentifier non-empty / idpType valid / allowedTenantIds non-empty.
     * fail-closed: Port exception -> throw FederationMappingError(FEDERATION_MAPPING_CREATE_FAILED).
     *
     * @throws FederationMappingError(FEDERATION_MAPPING_ROLE_MISSING) role missing
     * @throws FederationMappingError(FEDERATION_MAPPING_PERMISSION_DENIED) not admin
     * @throws FederationMappingError(FEDERATION_MAPPING_INVALID_INPUT) invalid input
     * @throws FederationMappingError(FEDERATION_MAPPING_CREATE_FAILED) DB exception
     */
    async createMapping(req: CreateMappingRequest): Promise<IdpMapping> {
        // P0 security constraint: only admin may create an IdpMapping (trust-chain entry-point protection)
        this._requireAdminOnly(req.role, 'createMapping');
        this._validateCreateInput(req.input);

        let mapping: IdpMapping;
        try {
            mapping = await this.port.createMapping(req.input);
        } catch (err) {
            throw new FederationMappingError(
                `FederationMappingAdminClient: createMapping failed: ${String(err)}`,
                'FEDERATION_MAPPING_CREATE_FAILED',
                err,
            );
        }
        // audit: write the audit event after a successful CUD operation (a failure does not block the main operation)
        await this._safeWriteAuditEvent({
            eventType: 'federation_mapping.created',
            mappingId: mapping.id,
            idpIdentifier: mapping.idpIdentifier,
            actorTenantId: 'system',
            timestamp: new Date().toISOString(),
            certHashPrefix: mapping.idpSigningCert !== undefined
                ? this._sha256Prefix16(mapping.idpSigningCert)
                : undefined,
            jwksUriHashPrefix: mapping.idpJwksUri !== undefined
                ? this._sha256Prefix16(mapping.idpJwksUri)
                : undefined,
        });
        return mapping;
    }

    // -------------------------------------------------------------------------
    // updateMapping -- update an IdpMapping (admin only)
    // -------------------------------------------------------------------------

    /**
     * Update an IdpMapping (partial update).
     *
     * RBAC (P0 security constraint): only the admin role may update (including the idpSigningCert / idpJwksUri trust-chain fields).
     * fail-closed: Port exception -> throw FederationMappingError(FEDERATION_MAPPING_UPDATE_FAILED).
     *
     * @throws FederationMappingError(FEDERATION_MAPPING_ROLE_MISSING) role missing
     * @throws FederationMappingError(FEDERATION_MAPPING_PERMISSION_DENIED) not admin
     * @throws FederationMappingError(FEDERATION_MAPPING_INVALID_INPUT) invalid id
     * @throws FederationMappingError(FEDERATION_MAPPING_NOT_FOUND) record does not exist
     * @throws FederationMappingError(FEDERATION_MAPPING_UPDATE_FAILED) DB exception
     */
    async updateMapping(req: UpdateMappingRequest): Promise<IdpMapping> {
        // P0 security constraint: only admin may update an IdpMapping (trust-chain entry-point protection)
        this._requireAdminOnly(req.role, 'updateMapping');
        if (!req.id || req.id.trim() === '') {
            throw new FederationMappingError(
                'FederationMappingAdminClient: id is required for updateMapping',
                'FEDERATION_MAPPING_INVALID_INPUT',
            );
        }
        // allowedTenantIds patch validation: if provided, it must be non-empty
        if (req.patch.allowedTenantIds !== undefined && req.patch.allowedTenantIds.length === 0) {
            throw new FederationMappingError(
                'FederationMappingAdminClient: allowedTenantIds patch must not be empty',
                'FEDERATION_MAPPING_INVALID_INPUT',
            );
        }

        let result: IdpMapping | null;
        try {
            result = await this.port.updateMapping(req.id, req.patch);
        } catch (err) {
            throw new FederationMappingError(
                `FederationMappingAdminClient: updateMapping failed: ${String(err)}`,
                'FEDERATION_MAPPING_UPDATE_FAILED',
                err,
            );
        }
        if (result === null) {
            throw new FederationMappingError(
                `FederationMappingAdminClient: IdpMapping not found for update: id="${req.id}"`,
                'FEDERATION_MAPPING_NOT_FOUND',
            );
        }
        // audit: write the audit event after a successful CUD operation (a failure does not block the main operation)
        await this._safeWriteAuditEvent({
            eventType: 'federation_mapping.updated',
            mappingId: result.id,
            idpIdentifier: result.idpIdentifier,
            actorTenantId: 'system',
            timestamp: new Date().toISOString(),
            certHashPrefix: req.patch.idpSigningCert !== undefined
                ? this._sha256Prefix16(req.patch.idpSigningCert)
                : undefined,
            jwksUriHashPrefix: req.patch.idpJwksUri !== undefined
                ? this._sha256Prefix16(req.patch.idpJwksUri)
                : undefined,
        });
        return result;
    }

    // -------------------------------------------------------------------------
    // deleteMapping -- delete an IdpMapping (admin only)
    // -------------------------------------------------------------------------

    /**
     * Delete an IdpMapping.
     *
     * RBAC (P0 security constraint): only the admin role may delete.
     * Requires confirmId to equal id (guards against accidental deletion).
     * fail-closed: Port exception -> throw FederationMappingError(FEDERATION_MAPPING_DELETE_FAILED).
     *
     * @throws FederationMappingError(FEDERATION_MAPPING_ROLE_MISSING) role missing
     * @throws FederationMappingError(FEDERATION_MAPPING_PERMISSION_DENIED) not admin
     * @throws FederationMappingError(FEDERATION_MAPPING_INVALID_INPUT) confirmId mismatch
     * @throws FederationMappingError(FEDERATION_MAPPING_NOT_FOUND) record does not exist
     * @throws FederationMappingError(FEDERATION_MAPPING_DELETE_FAILED) DB exception
     */
    async deleteMapping(req: DeleteMappingRequest): Promise<void> {
        // P0 security constraint: only admin may delete an IdpMapping
        this._requireAdminOnly(req.role, 'deleteMapping');
        if (!req.id || req.id.trim() === '') {
            throw new FederationMappingError(
                'FederationMappingAdminClient: id is required for deleteMapping',
                'FEDERATION_MAPPING_INVALID_INPUT',
            );
        }
        if (req.confirmId !== req.id) {
            throw new FederationMappingError(
                `FederationMappingAdminClient: confirmId "${req.confirmId}" does not match id "${req.id}"; deletion aborted`,
                'FEDERATION_MAPPING_INVALID_INPUT',
            );
        }
        // Pre-fetch idpIdentifier for the audit (it cannot be queried once deleted)
        let idpIdentifier = req.id;
        try {
            const existing = await this.port.getMapping(req.id);
            if (existing !== null) {
                idpIdentifier = existing.idpIdentifier;
            }
        } catch {
            // A pre-fetch failure does not block the deletion (the audit degrades to using id as idpIdentifier)
        }
        let deleted: boolean;
        try {
            deleted = await this.port.deleteMapping(req.id);
        } catch (err) {
            throw new FederationMappingError(
                `FederationMappingAdminClient: deleteMapping failed: ${String(err)}`,
                'FEDERATION_MAPPING_DELETE_FAILED',
                err,
            );
        }
        if (!deleted) {
            throw new FederationMappingError(
                `FederationMappingAdminClient: IdpMapping not found for deletion: id="${req.id}"`,
                'FEDERATION_MAPPING_NOT_FOUND',
            );
        }
        // audit: write the audit event after a successful CUD operation (a failure does not block the main operation)
        await this._safeWriteAuditEvent({
            eventType: 'federation_mapping.deleted',
            mappingId: req.id,
            idpIdentifier,
            actorTenantId: 'system',
            timestamp: new Date().toISOString(),
        });
    }

    // -------------------------------------------------------------------------
    // Internal helper methods
    // -------------------------------------------------------------------------

    /**
     * _requireRole: parse the role and verify it holds the required permission (fail-closed).
     *
     * @returns the parsed AdminRole (so callers can branch on tenant-admin)
     * @throws FederationMappingError wrapping an AdminRbacError (role missing / insufficient permission)
     */
    private _requireRole(
        rawRole: string,
        permission: import('./types.js').AdminPermission,
        _failCode: FederationMappingErrorCode,
    ): AdminRole {
        let role: AdminRole;
        try {
            role = parseAdminRole(rawRole);
        } catch (err) {
            if (err instanceof AdminRbacError && err.code === 'ADMIN_ROLE_MISSING') {
                throw new FederationMappingError(
                    `FederationMappingAdminClient: role missing: ${String(err)}`,
                    'FEDERATION_MAPPING_ROLE_MISSING',
                    err,
                );
            }
            throw new FederationMappingError(
                `FederationMappingAdminClient: invalid role: ${String(err)}`,
                'FEDERATION_MAPPING_PERMISSION_DENIED',
                err,
            );
        }
        if (!hasPermission(role, permission)) {
            throw new FederationMappingError(
                `FederationMappingAdminClient: role "${role}" lacks permission "${permission}"`,
                'FEDERATION_MAPPING_PERMISSION_DENIED',
            );
        }
        return role;
    }

    /**
     * _requireAdminOnly: strictly verify the admin role (P0 trust-chain-protected write operations).
     *
     * @throws FederationMappingError(FEDERATION_MAPPING_ROLE_MISSING) role missing
     * @throws FederationMappingError(FEDERATION_MAPPING_PERMISSION_DENIED) not the admin role
     */
    private _requireAdminOnly(rawRole: string, operation: string): void {
        let role: AdminRole;
        try {
            role = parseAdminRole(rawRole);
        } catch (err) {
            if (err instanceof AdminRbacError && err.code === 'ADMIN_ROLE_MISSING') {
                throw new FederationMappingError(
                    `FederationMappingAdminClient: role missing for ${operation}`,
                    'FEDERATION_MAPPING_ROLE_MISSING',
                    err,
                );
            }
            throw new FederationMappingError(
                `FederationMappingAdminClient: invalid role for ${operation}: ${String(err)}`,
                'FEDERATION_MAPPING_PERMISSION_DENIED',
                err,
            );
        }
        if (role !== 'admin') {
            throw new FederationMappingError(
                `FederationMappingAdminClient: only "admin" role may perform "${operation}"; got "${role}"`,
                'FEDERATION_MAPPING_PERMISSION_DENIED',
            );
        }
    }

    /**
     * _requireFederationReadRole: verify the role is allowed to access the federation mapping list/detail.
     *
     * Conclusion: IdpMapping contains SSO trust-chain fields (idpSigningCert / idpJwksUri);
     * although viewer holds the generic tenant:list permission, it must not access IdpMapping (P0 trust-chain protection);
     * therefore listMappings / getMapping allow only admin / tenant-admin.
     *
     * @returns the parsed AdminRole (so callers can branch on tenant-admin)
     * @throws FederationMappingError(FEDERATION_MAPPING_ROLE_MISSING) role is empty
     * @throws FederationMappingError(FEDERATION_MAPPING_PERMISSION_DENIED) role is viewer or unknown
     */
    private _requireFederationReadRole(rawRole: string): AdminRole {
        let role: AdminRole;
        try {
            role = parseAdminRole(rawRole);
        } catch (err) {
            if (err instanceof AdminRbacError && err.code === 'ADMIN_ROLE_MISSING') {
                throw new FederationMappingError(
                    `FederationMappingAdminClient: role missing`,
                    'FEDERATION_MAPPING_ROLE_MISSING',
                    err,
                );
            }
            throw new FederationMappingError(
                `FederationMappingAdminClient: invalid role: ${String(err)}`,
                'FEDERATION_MAPPING_PERMISSION_DENIED',
                err,
            );
        }
        // P0 trust-chain protection: viewer is not allowed to access IdpMapping (which contains idpSigningCert / idpJwksUri)
        if (role === 'viewer') {
            throw new FederationMappingError(
                `FederationMappingAdminClient: role "viewer" is not permitted to access federation mappings (SSO trust chain protection)`,
                'FEDERATION_MAPPING_PERMISSION_DENIED',
            );
        }
        return role;
    }

    /**
     * _validateCreateInput: validate the input parameters for creating an IdpMapping.
     *
     * @throws FederationMappingError(FEDERATION_MAPPING_INVALID_INPUT) invalid parameters
     */
    private _validateCreateInput(input: FederationMappingCreateInput): void {
        if (!input.idpIdentifier || input.idpIdentifier.trim() === '') {
            throw new FederationMappingError(
                'FederationMappingAdminClient: idpIdentifier is required',
                'FEDERATION_MAPPING_INVALID_INPUT',
            );
        }
        if (input.idpType !== 'saml' && input.idpType !== 'oidc') {
            throw new FederationMappingError(
                `FederationMappingAdminClient: idpType must be "saml" or "oidc"; got "${String(input.idpType)}"`,
                'FEDERATION_MAPPING_INVALID_INPUT',
            );
        }
        if (!Array.isArray(input.allowedTenantIds) || input.allowedTenantIds.length === 0) {
            throw new FederationMappingError(
                'FederationMappingAdminClient: allowedTenantIds must be a non-empty array',
                'FEDERATION_MAPPING_INVALID_INPUT',
            );
        }
    }

    /**
     * _sha256Prefix16: compute the first 16 bytes (32 hex chars) of a string's sha256 hash.
     *
     * Security constraint (P0): idpSigningCert / idpJwksUri are trust-chain entry points and must not be written to the audit log in cleartext;
     * only the hash fingerprint (first 16 bytes) is written so security audits can track trust-chain changes.
     */
    private _sha256Prefix16(value: string): string {
        return createHash('sha256').update(value).digest('hex').slice(0, 32);
    }

    /**
     * _safeWriteAuditEvent: safely write a federation_mapping CUD audit event.
     *
     * An audit write failure does not interrupt the main flow (degrade: console.error only).
     */
    private async _safeWriteAuditEvent(event: FederationMappingAuditEvent): Promise<void> {
        try {
            await this.port.writeAuditEvent(event);
        } catch (err) {
            console.error('[FederationMappingAdminClient] audit write failed (degraded):', err);
        }
    }
}
