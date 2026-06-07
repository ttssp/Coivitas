/**
 * Admin Console Tenant Admin API tests
 *
 * Coverage:
 *   - InMemoryTenantRegistry: CRUD operations (list/get/update/delete/count/seed)
 *   - createListTenantsHandler: RBAC restriction / audit invocation / pagination
 *   - createGetTenantHandler: RBAC / tenant-admin isolation / 404
 *   - createUpdateTenantHandler: RBAC / tenant-admin isolation / audit preCall+postCall / 404
 *   - createDeleteTenantHandler: admin only / confirmTenantId check / audit
 *   - handleAdminError: error code → HTTP status code mapping (fail-closed)
 *   - fail-closed invariant grep test: tenant-admin-api.ts does not contain bypassTenant / skipAuth / adminGlobalAccess
 *
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { resolve, dirname } from 'node:path';
import {
    InMemoryTenantRegistry,
    createListTenantsHandler,
    createGetTenantHandler,
    createUpdateTenantHandler,
    createDeleteTenantHandler,
    handleAdminError,
} from '../tenant-admin-api.js';
import { AdminRbacError, AdminResourceNotFoundError, AdminRequestInvalidError } from '../types.js';
import type { TenantRecord } from '../types.js';
import { makeTenantId, TenantNotFoundError } from '../../multi-tenancy/types.js';
import type { TenantAuditHook } from '../../multi-tenancy/audit-hook.js';
import type { TenantContext } from '../../multi-tenancy/types.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

// ── Test factory functions ──────────────────────────────────────────────────────────────

/** Build a minimal TenantContext*/
function makeTenantContext(tenantIdRaw: string): TenantContext {
    return {
        tenantId: makeTenantId(tenantIdRaw),
        tenantName: `Tenant ${tenantIdRaw}`,
        createdAt: new Date().toISOString() as never,
    };
}

type PreCallInvocation = { ctx: unknown; action: string; resource: string };
type PostCallInvocation = { ctx: unknown; action: string; outcome: string; resource: string; additionalContext: unknown };

/** Build a mock TenantAuditHook*/
function makeAuditHook(): TenantAuditHook & {
    preCallInvocations: PreCallInvocation[];
    postCallInvocations: PostCallInvocation[];
} {
    const preCallInvocations: PreCallInvocation[] = [];
    const postCallInvocations: PostCallInvocation[] = [];
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
        preCallInvocations: PreCallInvocation[];
        postCallInvocations: PostCallInvocation[];
    };
}

/** Build a mock AdminResponse*/
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

/** Build a mock AdminRequest*/
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

/** Build a TenantRecord for tests*/
function makeTenantRecord(tenantIdRaw: string): TenantRecord {
    return {
        tenantId: makeTenantId(tenantIdRaw),
        displayName: `Display ${tenantIdRaw}`,
        createdAt: '2026-01-01T00:00:00.000Z',
    };
}

// ── InMemoryTenantRegistry ────────────────────────────────────────────────────

describe('InMemoryTenantRegistry — CRUD operations', () => {
    it('should return empty list when no tenants seeded', async () => {
        const reg = new InMemoryTenantRegistry();
        const list = await reg.list(0, 10);
        expect(list).toHaveLength(0);
    });

    it('should count 0 when empty', async () => {
        const reg = new InMemoryTenantRegistry();
        expect(await reg.count()).toBe(0);
    });

    it('should seed a tenant and retrieve it', async () => {
        const reg = new InMemoryTenantRegistry();
        const record = makeTenantRecord('tenant-alpha');
        reg.seed(record);
        const got = await reg.get(makeTenantId('tenant-alpha'));
        expect(got).toBeDefined();
        expect(got?.tenantId).toBe('tenant-alpha');
    });

    it('should return undefined for non-existent tenant', async () => {
        const reg = new InMemoryTenantRegistry();
        const got = await reg.get(makeTenantId('not-exist'));
        expect(got).toBeUndefined();
    });

    it('should list all seeded tenants with offset=0 limit=10', async () => {
        const reg = new InMemoryTenantRegistry();
        reg.seed(makeTenantRecord('t1'));
        reg.seed(makeTenantRecord('t2'));
        reg.seed(makeTenantRecord('t3'));
        const list = await reg.list(0, 10);
        expect(list).toHaveLength(3);
    });

    it('should respect pagination offset and limit', async () => {
        const reg = new InMemoryTenantRegistry();
        for (let i = 1; i <= 5; i++) reg.seed(makeTenantRecord(`t${i}`));
        const page1 = await reg.list(0, 2);
        const page2 = await reg.list(2, 2);
        expect(page1).toHaveLength(2);
        expect(page2).toHaveLength(2);
    });

    it('should update displayName and set updatedAt', async () => {
        const reg = new InMemoryTenantRegistry();
        reg.seed(makeTenantRecord('t-update'));
        const updated = await reg.update(makeTenantId('t-update'), { displayName: 'New Name' });
        expect(updated.displayName).toBe('New Name');
        expect(updated.tenantId).toBe('t-update'); // tenantId unchanged
        expect(updated.updatedAt).toBeDefined();
    });

    it('should throw TenantNotFoundError when updating non-existent tenant', async () => {
        const reg = new InMemoryTenantRegistry();
        await expect(reg.update(makeTenantId('ghost'), {})).rejects.toThrow(TenantNotFoundError);
    });

    it('should delete an existing tenant', async () => {
        const reg = new InMemoryTenantRegistry();
        reg.seed(makeTenantRecord('t-delete'));
        await reg.delete(makeTenantId('t-delete'));
        expect(await reg.get(makeTenantId('t-delete'))).toBeUndefined();
    });

    it('should throw TenantNotFoundError when deleting non-existent tenant', async () => {
        const reg = new InMemoryTenantRegistry();
        await expect(reg.delete(makeTenantId('ghost'))).rejects.toThrow(TenantNotFoundError);
    });

    it('should count correctly after seed and delete', async () => {
        const reg = new InMemoryTenantRegistry();
        reg.seed(makeTenantRecord('t1'));
        reg.seed(makeTenantRecord('t2'));
        expect(await reg.count()).toBe(2);
        await reg.delete(makeTenantId('t1'));
        expect(await reg.count()).toBe(1);
    });

    it('should accept initial records in constructor', async () => {
        const reg = new InMemoryTenantRegistry([makeTenantRecord('init1'), makeTenantRecord('init2')]);
        expect(await reg.count()).toBe(2);
    });
});

// ── createListTenantsHandler ──────────────────────────────────────────────────

describe('createListTenantsHandler — admin can list tenants', () => {
    it('should return 200 with tenants list when admin role', async () => {
        const registry = new InMemoryTenantRegistry();
        registry.seed(makeTenantRecord('t1'));
        registry.seed(makeTenantRecord('t2'));
        const auditHook = makeAuditHook();
        const handler = createListTenantsHandler({ registry, auditHook });

        const ctx = makeTenantContext('t1');
        const req = makeRequest({ role: 'admin' });
        const res = makeResponse(ctx);

        await handler(req as never, res as never, () => {});
        expect(res._status.code).toBe(200);
        const body = res._body[0] as Record<string, unknown>;
        expect(Array.isArray(body['tenants'])).toBe(true);
        expect(body['total']).toBe(2);
    });

    it('should call auditHook.postCall once for list (read-only)', async () => {
        const registry = new InMemoryTenantRegistry();
        const auditHook = makeAuditHook();
        const handler = createListTenantsHandler({ registry, auditHook });

        const ctx = makeTenantContext('t1');
        const req = makeRequest({ role: 'admin' });
        const res = makeResponse(ctx);

        await handler(req as never, res as never, () => {});
        // withAdminAuditReadOnly: only postCall
        expect(auditHook.postCallInvocations).toHaveLength(1);
        expect(auditHook.preCallInvocations).toHaveLength(0);
    });

    it('should return 403 when viewer role tries to list (viewer has tenant:list; but let us verify 200)', async () => {
        // viewer has policy:list and tenant:list so 200 is expected
        const registry = new InMemoryTenantRegistry();
        const auditHook = makeAuditHook();
        const handler = createListTenantsHandler({ registry, auditHook });

        const ctx = makeTenantContext('t1');
        const req = makeRequest({ role: 'viewer' });
        const res = makeResponse(ctx);

        await handler(req as never, res as never, () => {});
        expect(res._status.code).toBe(200);
    });

    it('should return 401 when no X-Role header', async () => {
        const registry = new InMemoryTenantRegistry();
        const auditHook = makeAuditHook();
        const handler = createListTenantsHandler({ registry, auditHook });

        const ctx = makeTenantContext('t1');
        const req = makeRequest({});
        const res = makeResponse(ctx);

        await handler(req as never, res as never, () => {});
        expect(res._status.code).toBe(401);
        const body = res._body[0] as Record<string, unknown>;
        expect(body['error']).toBe('ADMIN_ROLE_MISSING');
    });

    it('should return 401 when unknown role', async () => {
        const registry = new InMemoryTenantRegistry();
        const auditHook = makeAuditHook();
        const handler = createListTenantsHandler({ registry, auditHook });

        const ctx = makeTenantContext('t1');
        const req = makeRequest({ role: 'god-mode' });
        const res = makeResponse(ctx);

        await handler(req as never, res as never, () => {});
        expect(res._status.code).toBe(401);
        const body = res._body[0] as Record<string, unknown>;
        expect(body['error']).toBe('ADMIN_ROLE_UNKNOWN');
    });

    it('should apply default limit=20 when not specified', async () => {
        const registry = new InMemoryTenantRegistry();
        const auditHook = makeAuditHook();
        const handler = createListTenantsHandler({ registry, auditHook });

        const ctx = makeTenantContext('t1');
        const req = makeRequest({ role: 'admin' });
        const res = makeResponse(ctx);

        await handler(req as never, res as never, () => {});
        const body = res._body[0] as Record<string, unknown>;
        expect(body['limit']).toBe(20);
    });
});

// ── createGetTenantHandler ────────────────────────────────────────────────────

describe('createGetTenantHandler — RBAC + tenant isolation', () => {
    it('should return 200 with tenant for admin role', async () => {
        const registry = new InMemoryTenantRegistry();
        registry.seed(makeTenantRecord('t-get'));
        const auditHook = makeAuditHook();
        const handler = createGetTenantHandler({ registry, auditHook });

        const ctx = makeTenantContext('t-get');
        const req = makeRequest({ role: 'admin', params: { tenantId: 't-get' } });
        const res = makeResponse(ctx);

        await handler(req as never, res as never, () => {});
        expect(res._status.code).toBe(200);
        const body = res._body[0] as Record<string, unknown>;
        expect(body['tenant']).toBeDefined();
    });

    it('should return 404 for non-existent tenant', async () => {
        const registry = new InMemoryTenantRegistry();
        const auditHook = makeAuditHook();
        const handler = createGetTenantHandler({ registry, auditHook });

        const ctx = makeTenantContext('t-any');
        const req = makeRequest({ role: 'admin', params: { tenantId: 't-any' } });
        const res = makeResponse(ctx);

        await handler(req as never, res as never, () => {});
        expect(res._status.code).toBe(404);
    });

    it('should allow tenant-admin to get its own tenant', async () => {
        const registry = new InMemoryTenantRegistry();
        registry.seed(makeTenantRecord('my-tenant'));
        const auditHook = makeAuditHook();
        const handler = createGetTenantHandler({ registry, auditHook });

        const ctx = makeTenantContext('my-tenant');
        const req = makeRequest({ role: 'tenant-admin', params: { tenantId: 'my-tenant' } });
        const res = makeResponse(ctx);

        await handler(req as never, res as never, () => {});
        expect(res._status.code).toBe(200);
    });

    it('should deny tenant-admin access to another tenant (403)', async () => {
        const registry = new InMemoryTenantRegistry();
        registry.seed(makeTenantRecord('other-tenant'));
        const auditHook = makeAuditHook();
        const handler = createGetTenantHandler({ registry, auditHook });

        const ctx = makeTenantContext('my-tenant');
        const req = makeRequest({ role: 'tenant-admin', params: { tenantId: 'other-tenant' } });
        const res = makeResponse(ctx);

        await handler(req as never, res as never, () => {});
        expect(res._status.code).toBe(403);
        const body = res._body[0] as Record<string, unknown>;
        expect(body['error']).toBe('ADMIN_PERMISSION_DENIED');
    });

    it('should return 400 when tenantId param is missing', async () => {
        const registry = new InMemoryTenantRegistry();
        const auditHook = makeAuditHook();
        const handler = createGetTenantHandler({ registry, auditHook });

        const ctx = makeTenantContext('t1');
        const req = makeRequest({ role: 'admin', params: {} });
        const res = makeResponse(ctx);

        await handler(req as never, res as never, () => {});
        expect(res._status.code).toBe(400);
    });

    it('should call auditHook.postCall once (read-only)', async () => {
        const registry = new InMemoryTenantRegistry();
        registry.seed(makeTenantRecord('t-audit'));
        const auditHook = makeAuditHook();
        const handler = createGetTenantHandler({ registry, auditHook });

        const ctx = makeTenantContext('t-audit');
        const req = makeRequest({ role: 'admin', params: { tenantId: 't-audit' } });
        const res = makeResponse(ctx);

        await handler(req as never, res as never, () => {});
        expect(auditHook.postCallInvocations).toHaveLength(1);
        expect(auditHook.preCallInvocations).toHaveLength(0);
    });
});

// ── createUpdateTenantHandler ─────────────────────────────────────────────────

describe('createUpdateTenantHandler — write audit + RBAC + tenant isolation', () => {
    it('should return 200 with updated tenant for admin', async () => {
        const registry = new InMemoryTenantRegistry();
        registry.seed(makeTenantRecord('t-update'));
        const auditHook = makeAuditHook();
        const handler = createUpdateTenantHandler({ registry, auditHook });

        const ctx = makeTenantContext('t-update');
        const req = makeRequest({
            role: 'admin',
            params: { tenantId: 't-update' },
            body: { displayName: 'Updated Name' },
        });
        const res = makeResponse(ctx);

        await handler(req as never, res as never, () => {});
        expect(res._status.code).toBe(200);
        const body = res._body[0] as Record<string, unknown>;
        expect((body['tenant'] as Record<string, unknown>)['displayName']).toBe('Updated Name');
    });

    it('should call auditHook.preCall and postCall for write operation', async () => {
        const registry = new InMemoryTenantRegistry();
        registry.seed(makeTenantRecord('t-audit-write'));
        const auditHook = makeAuditHook();
        const handler = createUpdateTenantHandler({ registry, auditHook });

        const ctx = makeTenantContext('t-audit-write');
        const req = makeRequest({
            role: 'admin',
            params: { tenantId: 't-audit-write' },
            body: { displayName: 'New' },
        });
        const res = makeResponse(ctx);

        await handler(req as never, res as never, () => {});
        // withAdminAudit: both preCall and postCall
        expect(auditHook.preCallInvocations).toHaveLength(1);
        expect(auditHook.postCallInvocations).toHaveLength(1);
    });

    it('should return 403 when viewer attempts update', async () => {
        const registry = new InMemoryTenantRegistry();
        registry.seed(makeTenantRecord('t1'));
        const auditHook = makeAuditHook();
        const handler = createUpdateTenantHandler({ registry, auditHook });

        const ctx = makeTenantContext('t1');
        const req = makeRequest({ role: 'viewer', params: { tenantId: 't1' }, body: {} });
        const res = makeResponse(ctx);

        await handler(req as never, res as never, () => {});
        expect(res._status.code).toBe(403);
    });

    it('should deny tenant-admin from updating another tenant', async () => {
        const registry = new InMemoryTenantRegistry();
        registry.seed(makeTenantRecord('other'));
        const auditHook = makeAuditHook();
        const handler = createUpdateTenantHandler({ registry, auditHook });

        const ctx = makeTenantContext('my-tenant');
        const req = makeRequest({
            role: 'tenant-admin',
            params: { tenantId: 'other' },
            body: { displayName: 'Hack' },
        });
        const res = makeResponse(ctx);

        await handler(req as never, res as never, () => {});
        expect(res._status.code).toBe(403);
        const body = res._body[0] as Record<string, unknown>;
        expect(body['error']).toBe('ADMIN_PERMISSION_DENIED');
    });

    it('should allow tenant-admin to update its own tenant', async () => {
        const registry = new InMemoryTenantRegistry();
        registry.seed(makeTenantRecord('my-tenant'));
        const auditHook = makeAuditHook();
        const handler = createUpdateTenantHandler({ registry, auditHook });

        const ctx = makeTenantContext('my-tenant');
        const req = makeRequest({
            role: 'tenant-admin',
            params: { tenantId: 'my-tenant' },
            body: { displayName: 'Self Update' },
        });
        const res = makeResponse(ctx);

        await handler(req as never, res as never, () => {});
        expect(res._status.code).toBe(200);
    });

    it('should return 404 when updating non-existent tenant', async () => {
        const registry = new InMemoryTenantRegistry();
        const auditHook = makeAuditHook();
        const handler = createUpdateTenantHandler({ registry, auditHook });

        const ctx = makeTenantContext('ghost');
        const req = makeRequest({
            role: 'admin',
            params: { tenantId: 'ghost' },
            body: { displayName: 'X' },
        });
        const res = makeResponse(ctx);

        await handler(req as never, res as never, () => {});
        expect(res._status.code).toBe(404);
    });
});

// ── createDeleteTenantHandler ─────────────────────────────────────────────────

describe('createDeleteTenantHandler — admin only + confirmTenantId check', () => {
    it('should return 204 when admin deletes with correct confirmTenantId', async () => {
        const registry = new InMemoryTenantRegistry();
        registry.seed(makeTenantRecord('t-del'));
        const auditHook = makeAuditHook();
        const handler = createDeleteTenantHandler({ registry, auditHook });

        const ctx = makeTenantContext('t-del');
        const req = makeRequest({
            role: 'admin',
            params: { tenantId: 't-del' },
            body: { confirmTenantId: 't-del' },
        });
        const res = makeResponse(ctx);

        await handler(req as never, res as never, () => {});
        expect(res._status.code).toBe(204);
    });

    it('should call auditHook.preCall and postCall for delete', async () => {
        const registry = new InMemoryTenantRegistry();
        registry.seed(makeTenantRecord('t-del-audit'));
        const auditHook = makeAuditHook();
        const handler = createDeleteTenantHandler({ registry, auditHook });

        const ctx = makeTenantContext('t-del-audit');
        const req = makeRequest({
            role: 'admin',
            params: { tenantId: 't-del-audit' },
            body: { confirmTenantId: 't-del-audit' },
        });
        const res = makeResponse(ctx);

        await handler(req as never, res as never, () => {});
        expect(auditHook.preCallInvocations).toHaveLength(1);
        expect(auditHook.postCallInvocations).toHaveLength(1);
    });

    it('should return 400 when confirmTenantId does not match', async () => {
        const registry = new InMemoryTenantRegistry();
        registry.seed(makeTenantRecord('t-real'));
        const auditHook = makeAuditHook();
        const handler = createDeleteTenantHandler({ registry, auditHook });

        const ctx = makeTenantContext('t-real');
        const req = makeRequest({
            role: 'admin',
            params: { tenantId: 't-real' },
            body: { confirmTenantId: 'wrong-id' },
        });
        const res = makeResponse(ctx);

        await handler(req as never, res as never, () => {});
        expect(res._status.code).toBe(400);
        const body = res._body[0] as Record<string, unknown>;
        expect(body['error']).toBe('ADMIN_REQUEST_INVALID');
    });

    it('should return 403 when tenant-admin tries to delete (permission denied)', async () => {
        const registry = new InMemoryTenantRegistry();
        registry.seed(makeTenantRecord('t1'));
        const auditHook = makeAuditHook();
        const handler = createDeleteTenantHandler({ registry, auditHook });

        const ctx = makeTenantContext('t1');
        const req = makeRequest({
            role: 'tenant-admin',
            params: { tenantId: 't1' },
            body: { confirmTenantId: 't1' },
        });
        const res = makeResponse(ctx);

        await handler(req as never, res as never, () => {});
        expect(res._status.code).toBe(403);
    });

    it('should return 403 when viewer tries to delete', async () => {
        const registry = new InMemoryTenantRegistry();
        registry.seed(makeTenantRecord('t1'));
        const auditHook = makeAuditHook();
        const handler = createDeleteTenantHandler({ registry, auditHook });

        const ctx = makeTenantContext('t1');
        const req = makeRequest({
            role: 'viewer',
            params: { tenantId: 't1' },
            body: { confirmTenantId: 't1' },
        });
        const res = makeResponse(ctx);

        await handler(req as never, res as never, () => {});
        expect(res._status.code).toBe(403);
    });

    it('should return 400 when confirmTenantId is absent', async () => {
        const registry = new InMemoryTenantRegistry();
        registry.seed(makeTenantRecord('t-no-confirm'));
        const auditHook = makeAuditHook();
        const handler = createDeleteTenantHandler({ registry, auditHook });

        const ctx = makeTenantContext('t-no-confirm');
        const req = makeRequest({
            role: 'admin',
            params: { tenantId: 't-no-confirm' },
            body: {},
        });
        const res = makeResponse(ctx);

        await handler(req as never, res as never, () => {});
        expect(res._status.code).toBe(400);
    });
});

// ── handleAdminError (error → HTTP status mapping) ───────────────────────────────

describe('handleAdminError — should map error types to correct HTTP status codes', () => {
    function makeMinimalRes() {
        let capturedStatus = 0;
        const capturedBody: unknown[] = [];
        const res = {
            status(code: number) { capturedStatus = code; return res; },
            json(body: unknown) { capturedBody.push(body); return res; },
            get _status() { return capturedStatus; },
            _body: capturedBody,
            locals: {} as Record<string, unknown>,
        };
        return res;
    }

    it('should return 401 for ADMIN_ROLE_MISSING', () => {
        const res = makeMinimalRes();
        handleAdminError(new AdminRbacError('missing', 'ADMIN_ROLE_MISSING'), res as never);
        expect(res._status).toBe(401);
    });

    it('should return 401 for ADMIN_ROLE_UNKNOWN', () => {
        const res = makeMinimalRes();
        handleAdminError(new AdminRbacError('unknown', 'ADMIN_ROLE_UNKNOWN'), res as never);
        expect(res._status).toBe(401);
    });

    it('should return 403 for ADMIN_PERMISSION_DENIED', () => {
        const res = makeMinimalRes();
        handleAdminError(new AdminRbacError('denied', 'ADMIN_PERMISSION_DENIED'), res as never);
        expect(res._status).toBe(403);
    });

    it('should return 404 for AdminResourceNotFoundError', () => {
        const res = makeMinimalRes();
        handleAdminError(new AdminResourceNotFoundError('tenant', 'id-1'), res as never);
        expect(res._status).toBe(404);
    });

    it('should return 400 for AdminRequestInvalidError', () => {
        const res = makeMinimalRes();
        handleAdminError(new AdminRequestInvalidError('bad input'), res as never);
        expect(res._status).toBe(400);
    });

    it('should return 404 for TenantNotFoundError', () => {
        const res = makeMinimalRes();
        handleAdminError(
            new TenantNotFoundError('not found', makeTenantId('t1')),
            res as never,
        );
        expect(res._status).toBe(404);
    });

    it('should return 500 for unknown error (fail-closed)', () => {
        const res = makeMinimalRes();
        handleAdminError(new Error('something unexpected'), res as never);
        expect(res._status).toBe(500);
        const body = res._body[0] as Record<string, unknown>;
        expect(body['error']).toBe('ADMIN_INTERNAL_ERROR');
    });

    it('should return 500 for non-Error thrown value (fail-closed)', () => {
        const res = makeMinimalRes();
        handleAdminError('string error', res as never);
        expect(res._status).toBe(500);
    });
});

// ── fail-closed invariant grep test ──────────────────────────────────────────

describe('fail-closed invariant grep test — tenant-admin-api.ts must not contain bypass patterns', () => {
    function nonCommentLines(src: string): string[] {
        return src
            .split('\n')
            .filter(line => !line.trim().startsWith('//') && !line.trim().startsWith('*'));
    }

    it('should not contain bypassTenant in tenant-admin-api.ts', () => {
        const src = readFileSync(resolve(__dirname, '../tenant-admin-api.ts'), 'utf-8');
        expect(nonCommentLines(src).join('\n')).not.toMatch(/bypassTenant/);
    });

    it('should not contain skipAuth in tenant-admin-api.ts', () => {
        const src = readFileSync(resolve(__dirname, '../tenant-admin-api.ts'), 'utf-8');
        expect(nonCommentLines(src).join('\n')).not.toMatch(/skipAuth/);
    });

    it('should not contain adminGlobalAccess in tenant-admin-api.ts', () => {
        const src = readFileSync(resolve(__dirname, '../tenant-admin-api.ts'), 'utf-8');
        expect(nonCommentLines(src).join('\n')).not.toMatch(/adminGlobalAccess/);
    });

    it('should contain requirePermission in tenant-admin-api.ts (fail-closed)', () => {
        const src = readFileSync(resolve(__dirname, '../tenant-admin-api.ts'), 'utf-8');
        expect(src).toMatch(/requirePermission/);
    });

    it('should contain withAdminAudit in tenant-admin-api.ts (audit write)', () => {
        const src = readFileSync(resolve(__dirname, '../tenant-admin-api.ts'), 'utf-8');
        expect(src).toMatch(/withAdminAudit/);
    });

    it('should contain handleAdminError in tenant-admin-api.ts (fail-closed 5xx)', () => {
        const src = readFileSync(resolve(__dirname, '../tenant-admin-api.ts'), 'utf-8');
        expect(src).toMatch(/handleAdminError/);
    });

    it('should contain ADMIN_INTERNAL_ERROR 500 in tenant-admin-api.ts (fail-closed)', () => {
        const src = readFileSync(resolve(__dirname, '../tenant-admin-api.ts'), 'utf-8');
        expect(src).toMatch(/ADMIN_INTERNAL_ERROR/);
    });
});
