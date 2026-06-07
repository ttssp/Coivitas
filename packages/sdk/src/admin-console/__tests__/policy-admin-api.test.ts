/**
 * Admin Console Policy Admin API tests
 *
 * Coverage:
 *   - InMemoryPolicyRegistry: CRUD operations (list/get/update/delete/count/seed)
 *   - createListPoliciesHandler: RBAC / tenant-admin isolation / audit
 *   - createGetPolicyHandler: RBAC / tenant-admin isolation / 404
 *   - createUpdatePolicyHandler: RBAC / tenant-admin isolation / audit preCall+postCall / keyRotationPolicyId reservation
 *   - createDeletePolicyHandler: admin only / audit
 *   - fail-closed invariant grep test: policy-admin-api.ts does not contain bypassTenant / skipAuth / adminGlobalAccess
 *
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { resolve, dirname } from 'node:path';
import {
    InMemoryPolicyRegistry,
    createListPoliciesHandler,
    createGetPolicyHandler,
    createUpdatePolicyHandler,
    createDeletePolicyHandler,
} from '../policy-admin-api.js';
import { AdminResourceNotFoundError } from '../types.js';
import type { PolicyRecord } from '../types.js';
import { makeTenantId } from '../../multi-tenancy/types.js';
import type { TenantAuditHook } from '../../multi-tenancy/audit-hook.js';
import type { TenantContext } from '../../multi-tenancy/types.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

// ── Test factory functions ──────────────────────────────────────────────────────────────

function makeTenantContext(tenantIdRaw: string): TenantContext {
    return {
        tenantId: makeTenantId(tenantIdRaw),
        tenantName: `Tenant ${tenantIdRaw}`,
        createdAt: new Date().toISOString() as never,
    };
}

type PolicyPreCallInvocation = { ctx: unknown; action: string; resource: string };
type PolicyPostCallInvocation = { ctx: unknown; action: string; outcome: string; resource: string; additionalContext: unknown };

function makeAuditHook(): TenantAuditHook & {
    preCallInvocations: PolicyPreCallInvocation[];
    postCallInvocations: PolicyPostCallInvocation[];
} {
    const preCallInvocations: PolicyPreCallInvocation[] = [];
    const postCallInvocations: PolicyPostCallInvocation[] = [];
    const hook = {
        preCallInvocations,
        postCallInvocations,
        preCall(ctx: unknown, action: string, resource: string): Promise<void> {
            preCallInvocations.push({ ctx, action, resource });
            return Promise.resolve();
        },
        postCall(ctx: unknown, action: string, outcome: string, resource: string, additionalContext: unknown): Promise<void> {
            postCallInvocations.push({ ctx, action, outcome, resource, additionalContext });
            return Promise.resolve();
        },
        getEvents() { return []; },
    };
    return hook as unknown as TenantAuditHook & {
        preCallInvocations: PolicyPreCallInvocation[];
        postCallInvocations: PolicyPostCallInvocation[];
    };
}

function makeResponse(tenantContext?: TenantContext) {
    const capturedStatus = { code: 0 };
    const capturedBody: unknown[] = [];
    const locals: Record<string, unknown> = {};
    if (tenantContext) {
        locals['tenantContext'] = tenantContext;
    }
    const res = {
        locals,
        status(code: number) {
            capturedStatus.code = code;
            return res;
        },
        json(body: unknown) {
            capturedBody.push(body);
            return res;
        },
        _status: capturedStatus,
        _body: capturedBody,
    };
    return res;
}

function makeRequest(opts: {
    role?: string;
    params?: Record<string, string>;
    query?: Record<string, string>;
    body?: unknown;
}) {
    return {
        headers: opts.role !== undefined ? { 'x-role': opts.role } : {},
        params: opts.params ?? {},
        query: opts.query ?? {},
        body: opts.body,
    };
}

function makePolicyRecord(tenantIdRaw: string, policyId: string): PolicyRecord {
    return {
        policyId,
        tenantId: makeTenantId(tenantIdRaw),
        rules: { allow: ['read'], deny: [] },
        enabled: true,
        createdAt: '2026-01-01T00:00:00.000Z',
    };
}

// ── InMemoryPolicyRegistry ────────────────────────────────────────────────────

describe('InMemoryPolicyRegistry — CRUD operations', () => {
    it('should return empty list for unknown tenant', async () => {
        const reg = new InMemoryPolicyRegistry();
        const list = await reg.list(makeTenantId('t1'), 0, 10);
        expect(list).toHaveLength(0);
    });

    it('should count 0 for unknown tenant', async () => {
        const reg = new InMemoryPolicyRegistry();
        expect(await reg.count(makeTenantId('t1'))).toBe(0);
    });

    it('should seed a policy and retrieve it', async () => {
        const reg = new InMemoryPolicyRegistry();
        reg.seed(makePolicyRecord('t1', 'policy-001'));
        const got = await reg.get(makeTenantId('t1'), 'policy-001');
        expect(got).toBeDefined();
        expect(got?.policyId).toBe('policy-001');
    });

    it('should return undefined for non-existent policy', async () => {
        const reg = new InMemoryPolicyRegistry();
        const got = await reg.get(makeTenantId('t1'), 'no-policy');
        expect(got).toBeUndefined();
    });

    it('should list only policies belonging to the given tenant', async () => {
        const reg = new InMemoryPolicyRegistry();
        reg.seed(makePolicyRecord('t1', 'p1'));
        reg.seed(makePolicyRecord('t1', 'p2'));
        reg.seed(makePolicyRecord('t2', 'p3'));
        const list = await reg.list(makeTenantId('t1'), 0, 10);
        expect(list).toHaveLength(2);
        expect(list.every(r => r.tenantId === 't1')).toBe(true);
    });

    it('should respect pagination for policy list', async () => {
        const reg = new InMemoryPolicyRegistry();
        for (let i = 1; i <= 5; i++) reg.seed(makePolicyRecord('t1', `p${i}`));
        const page = await reg.list(makeTenantId('t1'), 2, 2);
        expect(page).toHaveLength(2);
    });

    it('should update policy rules and set updatedAt', async () => {
        const reg = new InMemoryPolicyRegistry();
        reg.seed(makePolicyRecord('t1', 'p-update'));
        const updated = await reg.update(makeTenantId('t1'), 'p-update', {
            rules: { allow: ['write'] },
        });
        expect(updated.rules.allow).toContain('write');
        expect(updated.policyId).toBe('p-update');
        expect(updated.tenantId).toBe('t1');
        expect(updated.updatedAt).toBeDefined();
    });

    it('should throw AdminResourceNotFoundError when updating non-existent policy', async () => {
        const reg = new InMemoryPolicyRegistry();
        await expect(reg.update(makeTenantId('t1'), 'ghost', {})).rejects.toThrow(AdminResourceNotFoundError);
    });

    it('should delete an existing policy', async () => {
        const reg = new InMemoryPolicyRegistry();
        reg.seed(makePolicyRecord('t1', 'p-del'));
        await reg.delete(makeTenantId('t1'), 'p-del');
        expect(await reg.get(makeTenantId('t1'), 'p-del')).toBeUndefined();
    });

    it('should throw AdminResourceNotFoundError when deleting non-existent policy', async () => {
        const reg = new InMemoryPolicyRegistry();
        await expect(reg.delete(makeTenantId('t1'), 'ghost')).rejects.toThrow(AdminResourceNotFoundError);
    });

    it('should count correctly after seed and delete', async () => {
        const reg = new InMemoryPolicyRegistry();
        reg.seed(makePolicyRecord('t1', 'p1'));
        reg.seed(makePolicyRecord('t1', 'p2'));
        expect(await reg.count(makeTenantId('t1'))).toBe(2);
        await reg.delete(makeTenantId('t1'), 'p1');
        expect(await reg.count(makeTenantId('t1'))).toBe(1);
    });

    it('should isolate policies between tenants (different tenantId, same policyId)', async () => {
        const reg = new InMemoryPolicyRegistry();
        reg.seed(makePolicyRecord('t1', 'shared-id'));
        reg.seed(makePolicyRecord('t2', 'shared-id'));
        const p1 = await reg.get(makeTenantId('t1'), 'shared-id');
        const p2 = await reg.get(makeTenantId('t2'), 'shared-id');
        expect(p1?.tenantId).toBe('t1');
        expect(p2?.tenantId).toBe('t2');
    });
});

// ── createListPoliciesHandler ─────────────────────────────────────────────────

describe('createListPoliciesHandler — RBAC + tenant isolation', () => {
    it('should return 200 with policies list for admin', async () => {
        const registry = new InMemoryPolicyRegistry();
        registry.seed(makePolicyRecord('t1', 'p1'));
        const auditHook = makeAuditHook();
        const handler = createListPoliciesHandler({ registry, auditHook });

        const ctx = makeTenantContext('t1');
        const req = makeRequest({ role: 'admin', params: { tenantId: 't1' } });
        const res = makeResponse(ctx);

        await handler(req as never, res as never, () => {});
        expect(res._status.code).toBe(200);
        const body = res._body[0] as Record<string, unknown>;
        expect(Array.isArray(body['policies'])).toBe(true);
    });

    it('should return 200 for viewer listing policies', async () => {
        const registry = new InMemoryPolicyRegistry();
        const auditHook = makeAuditHook();
        const handler = createListPoliciesHandler({ registry, auditHook });

        const ctx = makeTenantContext('t1');
        const req = makeRequest({ role: 'viewer', params: { tenantId: 't1' } });
        const res = makeResponse(ctx);

        await handler(req as never, res as never, () => {});
        expect(res._status.code).toBe(200);
    });

    it('should call only postCall for list (read-only)', async () => {
        const registry = new InMemoryPolicyRegistry();
        const auditHook = makeAuditHook();
        const handler = createListPoliciesHandler({ registry, auditHook });

        const ctx = makeTenantContext('t1');
        const req = makeRequest({ role: 'admin', params: { tenantId: 't1' } });
        const res = makeResponse(ctx);

        await handler(req as never, res as never, () => {});
        expect(auditHook.preCallInvocations).toHaveLength(0);
        expect(auditHook.postCallInvocations).toHaveLength(1);
    });

    it('should deny tenant-admin from listing another tenant policies (403)', async () => {
        const registry = new InMemoryPolicyRegistry();
        const auditHook = makeAuditHook();
        const handler = createListPoliciesHandler({ registry, auditHook });

        const ctx = makeTenantContext('my-tenant');
        const req = makeRequest({ role: 'tenant-admin', params: { tenantId: 'other-tenant' } });
        const res = makeResponse(ctx);

        await handler(req as never, res as never, () => {});
        expect(res._status.code).toBe(403);
    });

    it('should allow tenant-admin to list own tenant policies', async () => {
        const registry = new InMemoryPolicyRegistry();
        registry.seed(makePolicyRecord('my-tenant', 'p1'));
        const auditHook = makeAuditHook();
        const handler = createListPoliciesHandler({ registry, auditHook });

        const ctx = makeTenantContext('my-tenant');
        const req = makeRequest({ role: 'tenant-admin', params: { tenantId: 'my-tenant' } });
        const res = makeResponse(ctx);

        await handler(req as never, res as never, () => {});
        expect(res._status.code).toBe(200);
    });

    it('should return 401 when role is missing', async () => {
        const registry = new InMemoryPolicyRegistry();
        const auditHook = makeAuditHook();
        const handler = createListPoliciesHandler({ registry, auditHook });

        const ctx = makeTenantContext('t1');
        const req = makeRequest({ params: { tenantId: 't1' } });
        const res = makeResponse(ctx);

        await handler(req as never, res as never, () => {});
        expect(res._status.code).toBe(401);
    });

    it('should return 400 when tenantId param is missing', async () => {
        const registry = new InMemoryPolicyRegistry();
        const auditHook = makeAuditHook();
        const handler = createListPoliciesHandler({ registry, auditHook });

        const ctx = makeTenantContext('t1');
        const req = makeRequest({ role: 'admin' });
        const res = makeResponse(ctx);

        await handler(req as never, res as never, () => {});
        expect(res._status.code).toBe(400);
    });
});

// ── createGetPolicyHandler ────────────────────────────────────────────────────

describe('createGetPolicyHandler — RBAC + tenant isolation + 404', () => {
    it('should return 200 with policy for admin', async () => {
        const registry = new InMemoryPolicyRegistry();
        registry.seed(makePolicyRecord('t1', 'p-get'));
        const auditHook = makeAuditHook();
        const handler = createGetPolicyHandler({ registry, auditHook });

        const ctx = makeTenantContext('t1');
        const req = makeRequest({ role: 'admin', params: { tenantId: 't1', policyId: 'p-get' } });
        const res = makeResponse(ctx);

        await handler(req as never, res as never, () => {});
        expect(res._status.code).toBe(200);
        const body = res._body[0] as Record<string, unknown>;
        expect(body['policy']).toBeDefined();
    });

    it('should return 404 for non-existent policy', async () => {
        const registry = new InMemoryPolicyRegistry();
        const auditHook = makeAuditHook();
        const handler = createGetPolicyHandler({ registry, auditHook });

        const ctx = makeTenantContext('t1');
        const req = makeRequest({ role: 'admin', params: { tenantId: 't1', policyId: 'nope' } });
        const res = makeResponse(ctx);

        await handler(req as never, res as never, () => {});
        expect(res._status.code).toBe(404);
    });

    it('should deny tenant-admin from getting another tenant policy (403)', async () => {
        const registry = new InMemoryPolicyRegistry();
        registry.seed(makePolicyRecord('other', 'p1'));
        const auditHook = makeAuditHook();
        const handler = createGetPolicyHandler({ registry, auditHook });

        const ctx = makeTenantContext('my-tenant');
        const req = makeRequest({ role: 'tenant-admin', params: { tenantId: 'other', policyId: 'p1' } });
        const res = makeResponse(ctx);

        await handler(req as never, res as never, () => {});
        expect(res._status.code).toBe(403);
    });

    it('should return 400 when policyId param is missing', async () => {
        const registry = new InMemoryPolicyRegistry();
        const auditHook = makeAuditHook();
        const handler = createGetPolicyHandler({ registry, auditHook });

        const ctx = makeTenantContext('t1');
        const req = makeRequest({ role: 'admin', params: { tenantId: 't1' } });
        const res = makeResponse(ctx);

        await handler(req as never, res as never, () => {});
        expect(res._status.code).toBe(400);
    });
});

// ── createUpdatePolicyHandler ─────────────────────────────────────────────────

describe('createUpdatePolicyHandler — write audit + keyRotationPolicyId + RBAC', () => {
    it('should return 200 with updated policy for admin', async () => {
        const registry = new InMemoryPolicyRegistry();
        registry.seed(makePolicyRecord('t1', 'p-upd'));
        const auditHook = makeAuditHook();
        const handler = createUpdatePolicyHandler({ registry, auditHook });

        const ctx = makeTenantContext('t1');
        const req = makeRequest({
            role: 'admin',
            params: { tenantId: 't1', policyId: 'p-upd' },
            body: { rules: { allow: ['write', 'read'] } },
        });
        const res = makeResponse(ctx);

        await handler(req as never, res as never, () => {});
        expect(res._status.code).toBe(200);
        const body = res._body[0] as Record<string, unknown>;
        expect(body['policy']).toBeDefined();
    });

    it('should call auditHook.preCall and postCall for update', async () => {
        const registry = new InMemoryPolicyRegistry();
        registry.seed(makePolicyRecord('t1', 'p-audit'));
        const auditHook = makeAuditHook();
        const handler = createUpdatePolicyHandler({ registry, auditHook });

        const ctx = makeTenantContext('t1');
        const req = makeRequest({
            role: 'admin',
            params: { tenantId: 't1', policyId: 'p-audit' },
            body: { enabled: false },
        });
        const res = makeResponse(ctx);

        await handler(req as never, res as never, () => {});
        expect(auditHook.preCallInvocations).toHaveLength(1);
        expect(auditHook.postCallInvocations).toHaveLength(1);
    });

    it('should update keyRotationPolicyId (KMS reserved interface)', async () => {
        const registry = new InMemoryPolicyRegistry();
        registry.seed(makePolicyRecord('t1', 'p-kms'));
        const auditHook = makeAuditHook();
        const handler = createUpdatePolicyHandler({ registry, auditHook });

        const ctx = makeTenantContext('t1');
        const req = makeRequest({
            role: 'admin',
            params: { tenantId: 't1', policyId: 'p-kms' },
            body: { keyRotationPolicyId: 'kms-key-001' },
        });
        const res = makeResponse(ctx);

        await handler(req as never, res as never, () => {});
        expect(res._status.code).toBe(200);
        const body = res._body[0] as Record<string, unknown>;
        const policy = body['policy'] as Record<string, unknown>;
        expect(policy['keyRotationPolicyId']).toBe('kms-key-001');
    });

    it('should return 403 when viewer attempts policy update', async () => {
        const registry = new InMemoryPolicyRegistry();
        registry.seed(makePolicyRecord('t1', 'p1'));
        const auditHook = makeAuditHook();
        const handler = createUpdatePolicyHandler({ registry, auditHook });

        const ctx = makeTenantContext('t1');
        const req = makeRequest({
            role: 'viewer',
            params: { tenantId: 't1', policyId: 'p1' },
            body: { enabled: false },
        });
        const res = makeResponse(ctx);

        await handler(req as never, res as never, () => {});
        expect(res._status.code).toBe(403);
    });

    it('should deny tenant-admin from updating another tenant policy', async () => {
        const registry = new InMemoryPolicyRegistry();
        registry.seed(makePolicyRecord('other', 'p1'));
        const auditHook = makeAuditHook();
        const handler = createUpdatePolicyHandler({ registry, auditHook });

        const ctx = makeTenantContext('my-tenant');
        const req = makeRequest({
            role: 'tenant-admin',
            params: { tenantId: 'other', policyId: 'p1' },
            body: { enabled: false },
        });
        const res = makeResponse(ctx);

        await handler(req as never, res as never, () => {});
        expect(res._status.code).toBe(403);
    });

    it('should allow tenant-admin to update own tenant policy', async () => {
        const registry = new InMemoryPolicyRegistry();
        registry.seed(makePolicyRecord('my-tenant', 'p-own'));
        const auditHook = makeAuditHook();
        const handler = createUpdatePolicyHandler({ registry, auditHook });

        const ctx = makeTenantContext('my-tenant');
        const req = makeRequest({
            role: 'tenant-admin',
            params: { tenantId: 'my-tenant', policyId: 'p-own' },
            body: { enabled: false },
        });
        const res = makeResponse(ctx);

        await handler(req as never, res as never, () => {});
        expect(res._status.code).toBe(200);
    });

    it('should return 404 when updating non-existent policy', async () => {
        const registry = new InMemoryPolicyRegistry();
        const auditHook = makeAuditHook();
        const handler = createUpdatePolicyHandler({ registry, auditHook });

        const ctx = makeTenantContext('t1');
        const req = makeRequest({
            role: 'admin',
            params: { tenantId: 't1', policyId: 'ghost' },
            body: {},
        });
        const res = makeResponse(ctx);

        await handler(req as never, res as never, () => {});
        expect(res._status.code).toBe(404);
    });
});

// ── createDeletePolicyHandler ─────────────────────────────────────────────────

describe('createDeletePolicyHandler — admin only + audit', () => {
    it('should return 204 for admin deleting existing policy', async () => {
        const registry = new InMemoryPolicyRegistry();
        registry.seed(makePolicyRecord('t1', 'p-del'));
        const auditHook = makeAuditHook();
        const handler = createDeletePolicyHandler({ registry, auditHook });

        const ctx = makeTenantContext('t1');
        const req = makeRequest({ role: 'admin', params: { tenantId: 't1', policyId: 'p-del' } });
        const res = makeResponse(ctx);

        await handler(req as never, res as never, () => {});
        expect(res._status.code).toBe(204);
    });

    it('should call auditHook.preCall and postCall for delete', async () => {
        const registry = new InMemoryPolicyRegistry();
        registry.seed(makePolicyRecord('t1', 'p-del-audit'));
        const auditHook = makeAuditHook();
        const handler = createDeletePolicyHandler({ registry, auditHook });

        const ctx = makeTenantContext('t1');
        const req = makeRequest({ role: 'admin', params: { tenantId: 't1', policyId: 'p-del-audit' } });
        const res = makeResponse(ctx);

        await handler(req as never, res as never, () => {});
        expect(auditHook.preCallInvocations).toHaveLength(1);
        expect(auditHook.postCallInvocations).toHaveLength(1);
    });

    it('should return 403 when tenant-admin attempts policy delete', async () => {
        const registry = new InMemoryPolicyRegistry();
        registry.seed(makePolicyRecord('t1', 'p1'));
        const auditHook = makeAuditHook();
        const handler = createDeletePolicyHandler({ registry, auditHook });

        const ctx = makeTenantContext('t1');
        const req = makeRequest({ role: 'tenant-admin', params: { tenantId: 't1', policyId: 'p1' } });
        const res = makeResponse(ctx);

        await handler(req as never, res as never, () => {});
        expect(res._status.code).toBe(403);
    });

    it('should return 403 when viewer attempts policy delete', async () => {
        const registry = new InMemoryPolicyRegistry();
        registry.seed(makePolicyRecord('t1', 'p1'));
        const auditHook = makeAuditHook();
        const handler = createDeletePolicyHandler({ registry, auditHook });

        const ctx = makeTenantContext('t1');
        const req = makeRequest({ role: 'viewer', params: { tenantId: 't1', policyId: 'p1' } });
        const res = makeResponse(ctx);

        await handler(req as never, res as never, () => {});
        expect(res._status.code).toBe(403);
    });

    it('should return 404 when deleting non-existent policy', async () => {
        const registry = new InMemoryPolicyRegistry();
        const auditHook = makeAuditHook();
        const handler = createDeletePolicyHandler({ registry, auditHook });

        const ctx = makeTenantContext('t1');
        const req = makeRequest({ role: 'admin', params: { tenantId: 't1', policyId: 'ghost' } });
        const res = makeResponse(ctx);

        await handler(req as never, res as never, () => {});
        expect(res._status.code).toBe(404);
    });
});

// ── fail-closed invariant grep test ──────────────────────────────────────────

describe('fail-closed invariant grep test — policy-admin-api.ts must not contain bypass patterns', () => {
    function nonCommentLines(src: string): string[] {
        return src
            .split('\n')
            .filter(line => !line.trim().startsWith('//') && !line.trim().startsWith('*'));
    }

    it('should not contain bypassTenant in policy-admin-api.ts', () => {
        const src = readFileSync(resolve(__dirname, '../policy-admin-api.ts'), 'utf-8');
        expect(nonCommentLines(src).join('\n')).not.toMatch(/bypassTenant/);
    });

    it('should not contain skipAuth in policy-admin-api.ts', () => {
        const src = readFileSync(resolve(__dirname, '../policy-admin-api.ts'), 'utf-8');
        expect(nonCommentLines(src).join('\n')).not.toMatch(/skipAuth/);
    });

    it('should not contain adminGlobalAccess in policy-admin-api.ts', () => {
        const src = readFileSync(resolve(__dirname, '../policy-admin-api.ts'), 'utf-8');
        expect(nonCommentLines(src).join('\n')).not.toMatch(/adminGlobalAccess/);
    });

    it('should contain requirePermission in policy-admin-api.ts (fail-closed)', () => {
        const src = readFileSync(resolve(__dirname, '../policy-admin-api.ts'), 'utf-8');
        expect(src).toMatch(/requirePermission/);
    });

    it('should contain withAdminAudit in policy-admin-api.ts (audit write)', () => {
        const src = readFileSync(resolve(__dirname, '../policy-admin-api.ts'), 'utf-8');
        expect(src).toMatch(/withAdminAudit/);
    });

    it('should contain keyRotationPolicyId in policy-admin-api.ts (KMS reserved)', () => {
        const src = readFileSync(resolve(__dirname, '../policy-admin-api.ts'), 'utf-8');
        expect(src).toMatch(/keyRotationPolicyId/);
    });

    it('should contain tenant isolation check (tenant-admin check) in policy-admin-api.ts', () => {
        const src = readFileSync(resolve(__dirname, '../policy-admin-api.ts'), 'utf-8');
        expect(src).toMatch(/tenant-admin/);
    });
});
