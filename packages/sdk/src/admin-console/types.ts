/**
 * Admin Console common type definitions
 *
 * Responsibilities:
 *   - AdminRole: the three RBAC roles (admin / tenant-admin / viewer)
 *   - TenantAdminRequest: tenant CRUD request bodies
 *   - PolicyAdminRequest: policy CRUD request bodies
 *   - AdminAuditEntry: audit entry for an admin operation
 *   - error-code system (fail-closed; unknown role / no role -> AdminRbacError)
 *
 * Design constraints (fail-closed):
 *   - RBAC must be fail-closed: no role / unknown role -> reject (no default-allow)
 *   - every admin operation must go through the audit hook (preCall + postCall)
 *   - the admin API must pass through tenantContextMiddleware (no bypassTenant / skipAuth)
 *   - no `as AdminRole` brand cast; use the parseAdminRole() factory function
 *
 */

import type { TenantId } from '../multi-tenancy/types.js';

// ── AdminRole ─────────────────────────────────────────────────────────────────

/**
 * Admin Console RBAC roles (three-role system)
 *
 * Conclusion: tiered control across three roles; admin holds all permissions; viewer is read-only;
 * unknown role / no role -> fail-closed (AdminRbacError).
 *
 * Permission matrix:
 *   - admin: all operations (list/get/update/delete tenant + policy)
 *   - tenant-admin: read/write within the current tenant (may not delete a tenant / may not cross tenants)
 *   - viewer: read-only (list/get; may not write/delete)
 */
export type AdminRole = 'admin' | 'tenant-admin' | 'viewer';

/** Set of all valid AdminRoles (used for validation) */
const VALID_ADMIN_ROLES: ReadonlySet<string> = new Set<AdminRole>([
    'admin',
    'tenant-admin',
    'viewer',
]);

/**
 * Parse an AdminRole (the only legal way to create an AdminRole; no brand cast)
 *
 * @param raw the raw string (from the X-Role header or a JWT claim)
 * @throws AdminRbacError if raw is not a valid AdminRole (fail-closed)
 */
export function parseAdminRole(raw: string | undefined): AdminRole {
    if (raw === undefined || raw === null || raw.trim() === '') {
        throw new AdminRbacError(
            'X-Role header is missing or empty. Admin API requires an explicit role.',
            'ADMIN_ROLE_MISSING',
        );
    }
    const trimmed = raw.trim().toLowerCase();
    if (!VALID_ADMIN_ROLES.has(trimmed)) {
        throw new AdminRbacError(
            `Unknown role "${raw.slice(0, 64)}". Valid roles: admin, tenant-admin, viewer.`,
            'ADMIN_ROLE_UNKNOWN',
        );
    }
    return trimmed as AdminRole;
}

// ── Permission enum ───────────────────────────────────────────────────────────

/**
 * Admin operation permission enum
 *
 * Conclusion: every admin API handler explicitly checks the required permission;
 * insufficient permission -> fail-closed (AdminRbacError; 403 response).
 */
export type AdminPermission =
    | 'tenant:list'
    | 'tenant:get'
    | 'tenant:update'
    | 'tenant:delete'
    | 'policy:list'
    | 'policy:get'
    | 'policy:update'
    | 'policy:delete';

/**
 * Role -> permission matrix (role-to-permissions mapping)
 *
 * Invariant:
 *   - admin: all permissions
 *   - tenant-admin: tenant read/write + policy read/write (excludes delete tenant)
 *   - viewer: read-only (list/get)
 */
export const ROLE_PERMISSIONS: Readonly<Record<AdminRole, ReadonlySet<AdminPermission>>> = {
    admin: new Set<AdminPermission>([
        'tenant:list',
        'tenant:get',
        'tenant:update',
        'tenant:delete',
        'policy:list',
        'policy:get',
        'policy:update',
        'policy:delete',
    ]),
    'tenant-admin': new Set<AdminPermission>([
        'tenant:list',
        'tenant:get',
        'tenant:update',
        'policy:list',
        'policy:get',
        'policy:update',
    ]),
    viewer: new Set<AdminPermission>([
        'tenant:list',
        'tenant:get',
        'policy:list',
        'policy:get',
    ]),
};

// ── TenantAdminRequest ────────────────────────────────────────────────────────

/**
 * Tenant admin CRUD request bodies (list / get / update / delete)
 */
export interface TenantListRequest {
    /** Pagination offset (0-based; default 0) */
    readonly offset?: number;
    /** Pagination limit (max 100; default 20) */
    readonly limit?: number;
}

export interface TenantGetRequest {
    /** Target tenant ID */
    readonly tenantId: TenantId;
}

export interface TenantUpdateRequest {
    /** Target tenant ID */
    readonly tenantId: TenantId;
    /** Fields to update (partial update; undefined = not updated) */
    readonly displayName?: string;
    readonly metadata?: Record<string, string>;
    readonly rateLimitOverride?: TenantRateLimitPatch;
}

export interface TenantDeleteRequest {
    /** Target tenant ID */
    readonly tenantId: TenantId;
    /** Confirmation string (guards against accidental deletion; must equal tenantId) */
    readonly confirmTenantId: TenantId;
}

/**
 * Tenant rate-limit partial update
 */
export interface TenantRateLimitPatch {
    readonly requestsPerSecond?: number;
    readonly requestsPerMinute?: number;
    readonly burstCapacity?: number;
}

// ── PolicyAdminRequest ────────────────────────────────────────────────────────

/**
 * Policy admin CRUD request bodies
 */
export interface PolicyListRequest {
    /** Scope tenant ID (a tenant-admin may only query its own tenant) */
    readonly tenantId: TenantId;
    readonly offset?: number;
    readonly limit?: number;
}

export interface PolicyGetRequest {
    readonly tenantId: TenantId;
    readonly policyId: string;
}

export interface PolicyUpdateRequest {
    readonly tenantId: TenantId;
    readonly policyId: string;
    /** Policy rule content (JSON-serializable) */
    readonly rules?: PolicyRuleSet;
    /** Whether enabled (undefined = unchanged) */
    readonly enabled?: boolean;
    /** key rotation policy integration (placeholder interface; integrates with a KMS key rotation policy) */
    readonly keyRotationPolicyId?: string;
}

export interface PolicyDeleteRequest {
    readonly tenantId: TenantId;
    readonly policyId: string;
}

/**
 * Policy rule set (simplified; for the admin console; the full rule set lives in packages/policy)
 */
export interface PolicyRuleSet {
    /** List of allowed operations */
    readonly allow?: readonly string[];
    /** List of denied operations (takes precedence over allow) */
    readonly deny?: readonly string[];
    /** Condition expressions (key = condition name; value = condition value) */
    readonly conditions?: Readonly<Record<string, string>>;
}

// ── Tenant + Policy record types ──────────────────────────────────────────────────

/**
 * Tenant record (admin console view)
 */
export interface TenantRecord {
    readonly tenantId: TenantId;
    readonly displayName?: string;
    readonly metadata?: Record<string, string>;
    readonly rateLimitOverride?: TenantRateLimitPatch;
    readonly createdAt: string;
    readonly updatedAt?: string;
}

/**
 * Policy record (admin console view)
 */
export interface PolicyRecord {
    readonly policyId: string;
    readonly tenantId: TenantId;
    readonly rules: PolicyRuleSet;
    readonly enabled: boolean;
    readonly keyRotationPolicyId?: string;
    readonly createdAt: string;
    readonly updatedAt?: string;
}

// ── AdminAuditEntry ───────────────────────────────────────────────────────────

/**
 * Audit entry for an admin operation (the format the admin console writes to TenantAuditHook)
 *
 * Conclusion: every admin write operation must produce one AdminAuditEntry;
 * injected via TenantAuditHook.preCall + postCall.
 */
export interface AdminAuditEntry {
    /** Admin operation type (prefixed with "admin.") */
    readonly action: string;
    /** Role of the operation initiator */
    readonly role: AdminRole;
    /** Operation target (tenant ID / policy ID) */
    readonly resource: string;
    /** Operation outcome */
    readonly outcome: 'success' | 'denied' | 'error';
    /** Additional context */
    readonly context?: Record<string, string>;
}

// ── Error-code system ────────────────────────────────────────────────────────────────

/**
 * Admin RBAC error codes
 */
export type AdminErrorCode =
    | 'ADMIN_ROLE_MISSING'
    | 'ADMIN_ROLE_UNKNOWN'
    | 'ADMIN_PERMISSION_DENIED'
    | 'ADMIN_TENANT_CONTEXT_MISSING'
    | 'ADMIN_RESOURCE_NOT_FOUND'
    | 'ADMIN_REQUEST_INVALID'
    | 'ADMIN_AUDIT_FAILED';

/**
 * AdminRbacError: role missing / unknown / insufficient permission
 *
 * Trigger scenarios:
 *   - X-Role header missing -> ADMIN_ROLE_MISSING (fail-closed)
 *   - unknown role -> ADMIN_ROLE_UNKNOWN (fail-closed)
 *   - insufficient permission -> ADMIN_PERMISSION_DENIED (fail-closed)
 */
export class AdminRbacError extends Error {
    readonly code: AdminErrorCode;

    constructor(message: string, code: AdminErrorCode = 'ADMIN_PERMISSION_DENIED') {
        super(message);
        this.name = 'AdminRbacError';
        this.code = code;
        Object.setPrototypeOf(this, new.target.prototype);
    }
}

/**
 * AdminResourceNotFoundError: the target resource does not exist
 */
export class AdminResourceNotFoundError extends Error {
    readonly code = 'ADMIN_RESOURCE_NOT_FOUND' as const;

    constructor(resource: string, id: string) {
        super(`Admin resource not found: ${resource} "${id}".`);
        this.name = 'AdminResourceNotFoundError';
        Object.setPrototypeOf(this, new.target.prototype);
    }
}

/**
 * AdminRequestInvalidError: invalid request parameters
 */
export class AdminRequestInvalidError extends Error {
    readonly code = 'ADMIN_REQUEST_INVALID' as const;

    constructor(message: string) {
        super(message);
        this.name = 'AdminRequestInvalidError';
        Object.setPrototypeOf(this, new.target.prototype);
    }
}
