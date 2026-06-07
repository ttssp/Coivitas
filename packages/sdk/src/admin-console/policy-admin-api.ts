/**
 * Admin Console Policy Admin API
 *
 * Responsibilities:
 *   - listPolicies: list all policies under a tenant (paginated)
 *   - getPolicy: fetch a single policy's details
 *   - updatePolicy: update policy rules (includes the keyRotationPolicyId placeholder interface)
 *   - deletePolicy: delete a policy (admin only)
 *
 * Design constraints (fail-closed):
 *   - every handler must pass through tenantContextMiddleware (no bypassTenant / skipAuth)
 *   - RBAC fail-closed: requirePermission is called at the entry of every handler
 *   - every write operation must go through auditHook.preCall + postCall (wrapped by withAdminAudit)
 *   - tenant-admin may only operate on its own tenant's policies (tenant isolation)
 *   - keyRotationPolicyId: integration with a KMS key rotation policy (placeholder interface; literal constraint)
 */

import { getTenantContextFromLocals } from '../multi-tenancy/tenant-resolver.js';
import type { TenantAuditHook } from '../multi-tenancy/audit-hook.js';
import type { TenantId } from '../multi-tenancy/types.js';
import { makeTenantId } from '../multi-tenancy/types.js';
import {
    AdminRbacError,
    AdminResourceNotFoundError,
    AdminRequestInvalidError,
} from './types.js';
import type {
    PolicyUpdateRequest,
    PolicyRecord,
} from './types.js';
import { getRoleFromRequest, requirePermission } from './rbac.js';
import { withAdminAudit, withAdminAuditReadOnly } from './audit-integration.js';
import { handleAdminError } from './tenant-admin-api.js';

// ── PolicyRegistry (in-memory; replaced by DB migration 022 in production) ─────────────

/**
 * PolicyRegistry: policy storage interface (decoupled from the DB implementation)
 *
 * Conclusion: keeps an interface style consistent with TenantRegistry;
 * supports in-memory testing + DB production.
 * The keyRotationPolicyId field is reserved for integration with a KMS key rotation policy.
 */
export interface PolicyRegistry {
    list(tenantId: TenantId, offset: number, limit: number): Promise<readonly PolicyRecord[]>;
    get(tenantId: TenantId, policyId: string): Promise<PolicyRecord | undefined>;
    update(tenantId: TenantId, policyId: string, patch: Partial<PolicyRecord>): Promise<PolicyRecord>;
    delete(tenantId: TenantId, policyId: string): Promise<void>;
    count(tenantId: TenantId): Promise<number>;
}

/**
 * InMemoryPolicyRegistry: in-memory implementation (test + development environments)
 *
 * Conclusion: stored keyed by `${tenantId}::${policyId}`;
 * ensures tenant isolation (policyIds from different tenants do not collide).
 */
export class InMemoryPolicyRegistry implements PolicyRegistry {
    private readonly store: Map<string, PolicyRecord> = new Map();

    private key(tenantId: TenantId, policyId: string): string {
        return `${tenantId}::${policyId}`;
    }

    list(tenantId: TenantId, offset: number, limit: number): Promise<readonly PolicyRecord[]> {
        const all = Array.from(this.store.values()).filter(r => r.tenantId === tenantId);
        return Promise.resolve(all.slice(offset, offset + limit));
    }

    get(tenantId: TenantId, policyId: string): Promise<PolicyRecord | undefined> {
        return Promise.resolve(this.store.get(this.key(tenantId, policyId)));
    }

    update(tenantId: TenantId, policyId: string, patch: Partial<PolicyRecord>): Promise<PolicyRecord> {
        const k = this.key(tenantId, policyId);
        const existing = this.store.get(k);
        if (!existing) {
            return Promise.reject(new AdminResourceNotFoundError('policy', `${tenantId}/${policyId}`));
        }
        const updated: PolicyRecord = {
            ...existing,
            ...patch,
            tenantId,     // tenantId must not be changed
            policyId,     // policyId must not be changed
            updatedAt: new Date().toISOString(),
        };
        this.store.set(k, updated);
        return Promise.resolve(updated);
    }

    delete(tenantId: TenantId, policyId: string): Promise<void> {
        const k = this.key(tenantId, policyId);
        if (!this.store.has(k)) {
            return Promise.reject(new AdminResourceNotFoundError('policy', `${tenantId}/${policyId}`));
        }
        this.store.delete(k);
        return Promise.resolve();
    }

    count(tenantId: TenantId): Promise<number> {
        return Promise.resolve(Array.from(this.store.values()).filter(r => r.tenantId === tenantId).length);
    }

    /** Internal: add a policy (test use only) */
    seed(record: PolicyRecord): void {
        this.store.set(this.key(record.tenantId, record.policyId), record);
    }
}

// ── Minimal Express type declarations ───────────────────────────────────────────────────────

interface AdminRequest {
    readonly headers: Record<string, string | string[] | undefined>;
    readonly body?: unknown;
    readonly params?: Record<string, string>;
    readonly query?: Record<string, string | string[] | undefined>;
}

interface AdminResponse {
    status(code: number): AdminResponse;
    json(body: unknown): AdminResponse;
    locals: Record<string, unknown>;
}

type AdminNextFn = (err?: unknown) => void;

// ── PolicyAdminApiConfig ──────────────────────────────────────────────────────

/**
 * PolicyAdminApi config (dependency injection)
 */
export interface PolicyAdminApiConfig {
    readonly registry: PolicyRegistry;
    readonly auditHook: TenantAuditHook;
}

// ── listPolicies ──────────────────────────────────────────────────────────────

/**
 * listPolicies: list all policies under a tenant
 *
 * Endpoint: GET /admin/tenants/:tenantId/policies
 * Permission: admin / tenant-admin (tenant-admin may only query its own) / viewer
 * audit: withAdminAuditReadOnly
 */
export function createListPoliciesHandler(config: PolicyAdminApiConfig) {
    return async (req: AdminRequest, res: AdminResponse, _next: AdminNextFn): Promise<void> => {
        try {
            const role = getRoleFromRequest(req);
            requirePermission(role, 'policy:list');

            const tenantContext = getTenantContextFromLocals(res, 'admin.policy.list');

            const rawTenantId = req.params?.['tenantId'];
            if (!rawTenantId) {
                throw new AdminRequestInvalidError('Missing tenantId path parameter.');
            }
            const tenantId = makeTenantId(rawTenantId);

            // A tenant-admin may only query its own tenant's policies (tenant isolation)
            if (role === 'tenant-admin' && tenantId !== tenantContext.tenantId) {
                throw new AdminRbacError(
                    `Role "tenant-admin" can only list policies for its own tenant "${tenantContext.tenantId}".`,
                    'ADMIN_PERMISSION_DENIED',
                );
            }

            const offset = parseIntParam(req.query?.['offset'], 0);
            const limit = Math.min(parseIntParam(req.query?.['limit'], 20), 100);

            const policies = await withAdminAuditReadOnly(
                {
                    tenantContext,
                    auditHook: config.auditHook,
                    action: 'admin.policy.list',
                    resource: `tenant:${tenantId}`,
                    role,
                },
                () => config.registry.list(tenantId, offset, limit),
            );

            const total = await config.registry.count(tenantId);

            res.status(200).json({ policies, total, offset, limit });
        } catch (err) {
            handleAdminError(err, res);
        }
    };
}

// ── getPolicy ─────────────────────────────────────────────────────────────────

/**
 * getPolicy: fetch a single policy's details
 *
 * Endpoint: GET /admin/tenants/:tenantId/policies/:policyId
 * Permission: admin / tenant-admin (own tenant) / viewer
 * audit: withAdminAuditReadOnly
 */
export function createGetPolicyHandler(config: PolicyAdminApiConfig) {
    return async (req: AdminRequest, res: AdminResponse, _next: AdminNextFn): Promise<void> => {
        try {
            const role = getRoleFromRequest(req);
            requirePermission(role, 'policy:get');

            const tenantContext = getTenantContextFromLocals(res, 'admin.policy.get');

            const rawTenantId = req.params?.['tenantId'];
            const policyId = req.params?.['policyId'];
            if (!rawTenantId) throw new AdminRequestInvalidError('Missing tenantId path parameter.');
            if (!policyId) throw new AdminRequestInvalidError('Missing policyId path parameter.');

            const tenantId = makeTenantId(rawTenantId);

            if (role === 'tenant-admin' && tenantId !== tenantContext.tenantId) {
                throw new AdminRbacError(
                    `Role "tenant-admin" can only access policies for its own tenant.`,
                    'ADMIN_PERMISSION_DENIED',
                );
            }

            const policy = await withAdminAuditReadOnly(
                {
                    tenantContext,
                    auditHook: config.auditHook,
                    action: 'admin.policy.get',
                    resource: `tenant:${tenantId}/policy:${policyId}`,
                    role,
                },
                () => config.registry.get(tenantId, policyId),
            );

            if (!policy) {
                throw new AdminResourceNotFoundError('policy', `${tenantId}/${policyId}`);
            }

            res.status(200).json({ policy });
        } catch (err) {
            handleAdminError(err, res);
        }
    };
}

// ── updatePolicy ──────────────────────────────────────────────────────────────

/**
 * updatePolicy: update policy rules (includes the keyRotationPolicyId placeholder interface)
 *
 * Endpoint: PATCH /admin/tenants/:tenantId/policies/:policyId
 * Permission: admin / tenant-admin (own tenant)
 * audit: withAdminAudit (write operation; preCall + postCall)
 *
 * keyRotationPolicyId interface:
 *   - reserved for integration with a KMS key rotation policy
 *   - the production implementation will complete KMS integration in the SSO segment or a later release
 */
export function createUpdatePolicyHandler(config: PolicyAdminApiConfig) {
    return async (req: AdminRequest, res: AdminResponse, _next: AdminNextFn): Promise<void> => {
        try {
            const role = getRoleFromRequest(req);
            requirePermission(role, 'policy:update');

            // Literal constraint: admin operations must pass through tenantContextMiddleware (no bypassTenant / skipAuth)
            const tenantContext = getTenantContextFromLocals(res, 'admin.policy.update');

            const rawTenantId = req.params?.['tenantId'];
            const policyId = req.params?.['policyId'];
            if (!rawTenantId) throw new AdminRequestInvalidError('Missing tenantId path parameter.');
            if (!policyId) throw new AdminRequestInvalidError('Missing policyId path parameter.');

            const tenantId = makeTenantId(rawTenantId);

            if (role === 'tenant-admin' && tenantId !== tenantContext.tenantId) {
                throw new AdminRbacError(
                    `Role "tenant-admin" can only update policies for its own tenant.`,
                    'ADMIN_PERMISSION_DENIED',
                );
            }

            const body = req.body as Partial<PolicyUpdateRequest> | undefined;
            // PolicyRecord fields are readonly; accumulate the patch in a mutable object, then cast back to Partial<PolicyRecord>
            const patchMutable: {
                -readonly [K in keyof PolicyRecord]?: PolicyRecord[K];
            } = {};
            if (body?.rules !== undefined) patchMutable.rules = body.rules;
            if (body?.enabled !== undefined) patchMutable.enabled = body.enabled;
            if (body?.keyRotationPolicyId !== undefined) {
                // Reserved: integration with a KMS key rotation policy (production implementation in a later segment)
                patchMutable.keyRotationPolicyId = body.keyRotationPolicyId;
            }
            const patch: Partial<PolicyRecord> = patchMutable;

            // Literal constraint: admin write operations must go through auditHook.preCall + postCall (withAdminAudit)
            const updated = await withAdminAudit(
                {
                    tenantContext,
                    auditHook: config.auditHook,
                    action: 'admin.policy.update',
                    resource: `tenant:${tenantId}/policy:${policyId}`,
                    role,
                },
                () => config.registry.update(tenantId, policyId, patch),
            );

            res.status(200).json({ policy: updated });
        } catch (err) {
            handleAdminError(err, res);
        }
    };
}

// ── deletePolicy ──────────────────────────────────────────────────────────────

/**
 * deletePolicy: delete a policy (admin only)
 *
 * Endpoint: DELETE /admin/tenants/:tenantId/policies/:policyId
 * Permission: admin only
 * audit: withAdminAudit (write operation; preCall + postCall)
 */
export function createDeletePolicyHandler(config: PolicyAdminApiConfig) {
    return async (req: AdminRequest, res: AdminResponse, _next: AdminNextFn): Promise<void> => {
        try {
            const role = getRoleFromRequest(req);
            requirePermission(role, 'policy:delete');

            const tenantContext = getTenantContextFromLocals(res, 'admin.policy.delete');

            const rawTenantId = req.params?.['tenantId'];
            const policyId = req.params?.['policyId'];
            if (!rawTenantId) throw new AdminRequestInvalidError('Missing tenantId path parameter.');
            if (!policyId) throw new AdminRequestInvalidError('Missing policyId path parameter.');

            const tenantId = makeTenantId(rawTenantId);

            await withAdminAudit(
                {
                    tenantContext,
                    auditHook: config.auditHook,
                    action: 'admin.policy.delete',
                    resource: `tenant:${tenantId}/policy:${policyId}`,
                    role,
                },
                () => config.registry.delete(tenantId, policyId),
            );

            res.status(204).json({});
        } catch (err) {
            handleAdminError(err, res);
        }
    };
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
