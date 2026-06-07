/**
 * Admin Console Tenant Admin API
 *
 * Responsibilities:
 *   - listTenants: list all tenants (admin only; paginated)
 *   - getTenant: fetch a single tenant's details
 *   - updateTenant: update tenant attributes (tenantId must not be changed)
 *   - deleteTenant: delete a tenant (admin only; requires a confirmation string)
 *
 * Design constraints (fail-closed):
 *   - every handler must pass through tenantContextMiddleware (no bypassTenant / skipAuth)
 *   - RBAC fail-closed: requirePermission is called at the entry of every handler
 *   - every write operation must go through auditHook.preCall + postCall (wrapped by withAdminAudit)
 *   - read-only operations must go through withAdminAuditReadOnly
 *   - decoupled via the TenantResolver interface (no direct DB access)
 *
 * Note: this implementation uses an in-memory TenantRegistry;
 * production should replace it with a DB implementation (migration 022).
 *
 */

import { getTenantContextFromLocals } from '../multi-tenancy/tenant-resolver.js';
import type { TenantAuditHook } from '../multi-tenancy/audit-hook.js';
import type { TenantId } from '../multi-tenancy/types.js';
import { makeTenantId, TenantNotFoundError } from '../multi-tenancy/types.js';
import {
    AdminRbacError,
    AdminResourceNotFoundError,
    AdminRequestInvalidError,
} from './types.js';
import type {
    TenantUpdateRequest,
    TenantDeleteRequest,
    TenantRecord,
} from './types.js';
import { getRoleFromRequest, requirePermission } from './rbac.js';
import { withAdminAudit, withAdminAuditReadOnly } from './audit-integration.js';

// ── TenantRegistry (in-memory; replaced by DB in production) ─────────────────────────

/**
 * TenantRegistry: tenant storage interface (decoupled from the DB implementation)
 *
 * Conclusion: decoupled via the interface, supporting in-memory testing + DB production;
 * keeps a decoupling style consistent with the KMS TenantResolver interface.
 */
export interface TenantRegistry {
    list(offset: number, limit: number): Promise<readonly TenantRecord[]>;
    get(tenantId: TenantId): Promise<TenantRecord | undefined>;
    update(tenantId: TenantId, patch: Partial<TenantRecord>): Promise<TenantRecord>;
    delete(tenantId: TenantId): Promise<void>;
    count(): Promise<number>;
}

/**
 * InMemoryTenantRegistry: in-memory implementation (test + development environments)
 *
 * Conclusion: implements the TenantRegistry interface directly; production replaces it with PostgreSQL migration 022.
 */
export class InMemoryTenantRegistry implements TenantRegistry {
    private readonly store: Map<TenantId, TenantRecord> = new Map();

    constructor(initial?: readonly TenantRecord[]) {
        if (initial) {
            for (const record of initial) {
                this.store.set(record.tenantId, record);
            }
        }
    }

    list(offset: number, limit: number): Promise<readonly TenantRecord[]> {
        const all = Array.from(this.store.values());
        return Promise.resolve(all.slice(offset, offset + limit));
    }

    get(tenantId: TenantId): Promise<TenantRecord | undefined> {
        return Promise.resolve(this.store.get(tenantId));
    }

    update(tenantId: TenantId, patch: Partial<TenantRecord>): Promise<TenantRecord> {
        const existing = this.store.get(tenantId);
        if (!existing) {
            return Promise.reject(new TenantNotFoundError(`Tenant "${tenantId}" not found.`, tenantId));
        }
        const updated: TenantRecord = {
            ...existing,
            ...patch,
            tenantId,  // tenantId must not be changed
            updatedAt: new Date().toISOString(),
        };
        this.store.set(tenantId, updated);
        return Promise.resolve(updated);
    }

    delete(tenantId: TenantId): Promise<void> {
        if (!this.store.has(tenantId)) {
            return Promise.reject(new TenantNotFoundError(`Tenant "${tenantId}" not found.`, tenantId));
        }
        this.store.delete(tenantId);
        return Promise.resolve();
    }

    count(): Promise<number> {
        return Promise.resolve(this.store.size);
    }

    /** Internal: add a tenant (test use only) */
    seed(record: TenantRecord): void {
        this.store.set(record.tenantId, record);
    }
}

// ── Minimal Express type declarations ───────────────────────────────────────────────────────

interface AdminRequest extends MinimalReq {
    readonly body?: unknown;
    readonly params?: Record<string, string>;
    readonly query?: Record<string, string | string[] | undefined>;
}

interface MinimalReq {
    readonly headers: Record<string, string | string[] | undefined>;
}

interface AdminResponse {
    status(code: number): AdminResponse;
    json(body: unknown): AdminResponse;
    locals: Record<string, unknown>;
}

type AdminNextFn = (err?: unknown) => void;

// ── TenantAdminApiConfig ──────────────────────────────────────────────────────

/**
 * TenantAdminApi config (dependency injection)
 */
export interface TenantAdminApiConfig {
    readonly registry: TenantRegistry;
    readonly auditHook: TenantAuditHook;
}

// ── listTenants ───────────────────────────────────────────────────────────────

/**
 * listTenants: list all tenants (admin only; paginated)
 *
 * Endpoint: GET /admin/tenants
 * Permission: admin (tenant-admin / viewer may not list across tenants)
 * audit: withAdminAuditReadOnly (read-only operation)
 */
export function createListTenantsHandler(config: TenantAdminApiConfig) {
    return async (req: AdminRequest, res: AdminResponse, _next: AdminNextFn): Promise<void> => {
        try {
            // RBAC fail-closed: parse the role first, then check the permission
            const role = getRoleFromRequest(req);
            requirePermission(role, 'tenant:list');

            // tenantContextMiddleware has already injected it; missing -> TenantContextMissingError (fail-closed)
            const tenantContext = getTenantContextFromLocals(res, 'admin.tenant.list');

            const offset = parseIntParam(req.query?.['offset'], 0);
            const limit = Math.min(parseIntParam(req.query?.['limit'], 20), 100);

            const tenants = await withAdminAuditReadOnly(
                {
                    tenantContext,
                    auditHook: config.auditHook,
                    action: 'admin.tenant.list',
                    resource: 'tenants',
                    role,
                },
                () => config.registry.list(offset, limit),
            );

            const total = await config.registry.count();

            res.status(200).json({ tenants, total, offset, limit });
        } catch (err) {
            handleAdminError(err, res);
        }
    };
}

// ── getTenant ─────────────────────────────────────────────────────────────────

/**
 * getTenant: fetch a single tenant's details
 *
 * Endpoint: GET /admin/tenants/:tenantId
 * Permission: admin / tenant-admin (tenant-admin may only query its own tenant) / viewer
 * audit: withAdminAuditReadOnly
 */
export function createGetTenantHandler(config: TenantAdminApiConfig) {
    return async (req: AdminRequest, res: AdminResponse, _next: AdminNextFn): Promise<void> => {
        try {
            const role = getRoleFromRequest(req);
            requirePermission(role, 'tenant:get');

            const tenantContext = getTenantContextFromLocals(res, 'admin.tenant.get');

            const rawTenantId = req.params?.['tenantId'];
            if (!rawTenantId) {
                throw new AdminRequestInvalidError('Missing tenantId path parameter.');
            }
            const tenantId = makeTenantId(rawTenantId);

            // A tenant-admin may only query its own tenant
            if (role === 'tenant-admin' && tenantId !== tenantContext.tenantId) {
                throw new AdminRbacError(
                    `Role "tenant-admin" can only access its own tenant "${tenantContext.tenantId}", ` +
                    `not "${tenantId}".`,
                    'ADMIN_PERMISSION_DENIED',
                );
            }

            const tenant = await withAdminAuditReadOnly(
                {
                    tenantContext,
                    auditHook: config.auditHook,
                    action: 'admin.tenant.get',
                    resource: tenantId,
                    role,
                },
                () => config.registry.get(tenantId),
            );

            if (!tenant) {
                throw new AdminResourceNotFoundError('tenant', tenantId);
            }

            res.status(200).json({ tenant });
        } catch (err) {
            handleAdminError(err, res);
        }
    };
}

// ── updateTenant ──────────────────────────────────────────────────────────────

/**
 * updateTenant: update tenant attributes
 *
 * Endpoint: PATCH /admin/tenants/:tenantId
 * Permission: admin / tenant-admin (tenant-admin may only modify its own)
 * audit: withAdminAudit (write operation; preCall + postCall)
 */
export function createUpdateTenantHandler(config: TenantAdminApiConfig) {
    return async (req: AdminRequest, res: AdminResponse, _next: AdminNextFn): Promise<void> => {
        try {
            const role = getRoleFromRequest(req);
            requirePermission(role, 'tenant:update');

            // Literal constraint: admin operations must pass through tenantContextMiddleware (no bypassTenant / skipAuth)
            const tenantContext = getTenantContextFromLocals(res, 'admin.tenant.update');

            const rawTenantId = req.params?.['tenantId'];
            if (!rawTenantId) {
                throw new AdminRequestInvalidError('Missing tenantId path parameter.');
            }
            const tenantId = makeTenantId(rawTenantId);

            if (role === 'tenant-admin' && tenantId !== tenantContext.tenantId) {
                throw new AdminRbacError(
                    `Role "tenant-admin" can only update its own tenant "${tenantContext.tenantId}".`,
                    'ADMIN_PERMISSION_DENIED',
                );
            }

            const body = req.body as Partial<TenantUpdateRequest> | undefined;
            // TenantRecord fields are readonly; accumulate the patch in a mutable object, then cast back to Partial<TenantRecord>
            const patchMutable: {
                -readonly [K in keyof TenantRecord]?: TenantRecord[K];
            } = {};
            if (body?.displayName !== undefined) patchMutable.displayName = body.displayName;
            if (body?.metadata !== undefined) patchMutable.metadata = body.metadata;
            if (body?.rateLimitOverride !== undefined) patchMutable.rateLimitOverride = body.rateLimitOverride;
            const patch: Partial<TenantRecord> = patchMutable;

            // Literal constraint: admin write operations must go through auditHook.preCall + postCall (withAdminAudit)
            const updated = await withAdminAudit(
                {
                    tenantContext,
                    auditHook: config.auditHook,
                    action: 'admin.tenant.update',
                    resource: tenantId,
                    role,
                },
                () => config.registry.update(tenantId, patch),
            );

            res.status(200).json({ tenant: updated });
        } catch (err) {
            handleAdminError(err, res);
        }
    };
}

// ── deleteTenant ──────────────────────────────────────────────────────────────

/**
 * deleteTenant: delete a tenant (admin only; requires a confirmation string)
 *
 * Endpoint: DELETE /admin/tenants/:tenantId
 * Permission: admin only
 * Security: body.confirmTenantId must equal tenantId (guards against accidental deletion)
 * audit: withAdminAudit (write operation; preCall + postCall)
 */
export function createDeleteTenantHandler(config: TenantAdminApiConfig) {
    return async (req: AdminRequest, res: AdminResponse, _next: AdminNextFn): Promise<void> => {
        try {
            const role = getRoleFromRequest(req);
            requirePermission(role, 'tenant:delete');

            const tenantContext = getTenantContextFromLocals(res, 'admin.tenant.delete');

            const rawTenantId = req.params?.['tenantId'];
            if (!rawTenantId) {
                throw new AdminRequestInvalidError('Missing tenantId path parameter.');
            }
            const tenantId = makeTenantId(rawTenantId);

            const body = req.body as Partial<TenantDeleteRequest> | undefined;
            if (!body?.confirmTenantId || body.confirmTenantId !== tenantId) {
                throw new AdminRequestInvalidError(
                    `Delete confirmation mismatch. body.confirmTenantId must equal "${tenantId}".`,
                );
            }

            await withAdminAudit(
                {
                    tenantContext,
                    auditHook: config.auditHook,
                    action: 'admin.tenant.delete',
                    resource: tenantId,
                    role,
                },
                () => config.registry.delete(tenantId),
            );

            res.status(204).json({});
        } catch (err) {
            handleAdminError(err, res);
        }
    };
}

// ── Error handling ──────────────────────────────────────────────────────────────────

/**
 * handleAdminError: unified error response for the admin API (fail-closed)
 *
 * Conclusion: called from the catch block of every admin handler;
 * different error types map to different HTTP status codes;
 * no stub default 200.
 */
export function handleAdminError(err: unknown, res: AdminResponse): void {
    if (err instanceof AdminRbacError) {
        const status = err.code === 'ADMIN_ROLE_MISSING' || err.code === 'ADMIN_ROLE_UNKNOWN'
            ? 401
            : 403;
        res.status(status).json({ error: err.code, message: err.message });
        return;
    }
    if (err instanceof AdminResourceNotFoundError) {
        res.status(404).json({ error: err.code, message: err.message });
        return;
    }
    if (err instanceof AdminRequestInvalidError) {
        res.status(400).json({ error: err.code, message: err.message });
        return;
    }
    if (err instanceof TenantNotFoundError) {
        res.status(404).json({ error: 'TENANT_NOT_FOUND', message: (err as Error).message });
        return;
    }
    // Unknown error -> fail-closed 500 (no stub default 200)
    res.status(500).json({
        error: 'ADMIN_INTERNAL_ERROR',
        message: 'Internal server error. Request aborted.',
    });
}

// ── Helper functions ──────────────────────────────────────────────────────────────────

function parseIntParam(
    val: string | string[] | undefined,
    defaultVal: number,
): number {
    if (val === undefined) return defaultVal;
    const str = Array.isArray(val) ? val[0] ?? '' : val;
    const n = parseInt(str, 10);
    return Number.isFinite(n) && n >= 0 ? n : defaultVal;
}
