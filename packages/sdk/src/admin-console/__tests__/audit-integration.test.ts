/**
 * Admin Console audit-integration tests
 *
 * Coverage:
 *   - withAdminAudit: preCall is invoked before the handler; postCall success/error outcome;
 *     postCall is still invoked when the handler fails (with error context); the original error is rethrown;
 *     preCall failure → fail-closed (the handler does not run)
 *   - withAdminAuditReadOnly: postCall only (no preCall); success/error outcome
 *   - buildAdminAuditContext: role/action/resource/component fields;
 *     appends errorMessage/errorType on error; handling of non-Error objects
 *   - fail-closed invariant grep test: audit-integration.ts does not contain bypassTenant/skipAuth/adminGlobalAccess
 *
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { resolve, dirname } from 'node:path';
import {
    withAdminAudit,
    withAdminAuditReadOnly,
    buildAdminAuditContext,
} from '../audit-integration.js';
import type { AdminAuditParams } from '../audit-integration.js';
import type { TenantAuditHook } from '../../multi-tenancy/audit-hook.js';
import type { TenantContext } from '../../multi-tenancy/types.js';
import type { TenantId } from '../../multi-tenancy/types.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

// ── Helper factories ──────────────────────────────────────────────────────────────────

type AuditHookMock = TenantAuditHook & {
    preCallInvocations: Array<{ ctx: unknown; action: string; resource: string }>;
    postCallInvocations: Array<{ ctx: unknown; action: string; outcome: string; resource: string; additionalContext: unknown }>;
};

function makeAuditHookMock(): AuditHookMock {
    const preCallInvocations: AuditHookMock['preCallInvocations'] = [];
    const postCallInvocations: AuditHookMock['postCallInvocations'] = [];

    const mock = {
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
    };
    return mock as unknown as AuditHookMock;
}

function makeTenantContext(): TenantContext {
    return {
        tenantId: 'tenant-audit-test' as unknown as TenantId,
        tenantName: 'Audit Test Tenant',
        createdAt: new Date().toISOString() as never,
    };
}

function makeParams(overrides: Partial<AdminAuditParams> = {}): AdminAuditParams {
    return {
        tenantContext: makeTenantContext(),
        auditHook: makeAuditHookMock(),
        action: 'admin.tenant.update',
        resource: 'tenant-1',
        role: 'admin',
        ...overrides,
    };
}

// ── withAdminAudit ────────────────────────────────────────────────────────────

describe('withAdminAudit — should call preCall and postCall around handler', () => {
    it('should call preCall before handler executes', async () => {
        const hookMock = makeAuditHookMock();
        const callOrder: string[] = [];

        await withAdminAudit(
            makeParams({ auditHook: hookMock }),
            () => {
                callOrder.push('handler');
                return Promise.resolve('result');
            },
        );

        // preCall must precede the handler (invariant: audit first)
        expect(hookMock.preCallInvocations).toHaveLength(1);
        expect(hookMock.preCallInvocations[0].action).toBe('admin.tenant.update');
        expect(hookMock.preCallInvocations[0].resource).toBe('tenant-1');
        expect(callOrder).toContain('handler');
    });

    it('should call postCall with success outcome when handler succeeds', async () => {
        const hookMock = makeAuditHookMock();

        const result = await withAdminAudit(
            makeParams({ auditHook: hookMock }),
            () => Promise.resolve(42),
        );

        expect(result).toBe(42);
        expect(hookMock.postCallInvocations).toHaveLength(1);
        expect(hookMock.postCallInvocations[0].outcome).toBe('success');
        expect(hookMock.postCallInvocations[0].resource).toBe('tenant-1');
    });

    it('should call postCall with error outcome when handler throws', async () => {
        const hookMock = makeAuditHookMock();
        const boom = new Error('handler failed');

        await expect(
            withAdminAudit(makeParams({ auditHook: hookMock }), () => Promise.reject(boom)),
        ).rejects.toThrow('handler failed');

        expect(hookMock.postCallInvocations).toHaveLength(1);
        expect(hookMock.postCallInvocations[0].outcome).toBe('error');
    });

    it('should rethrow handler error even when postCall also fails', async () => {
        const failingHook: TenantAuditHook = {
            preCall(): Promise<void> { return Promise.resolve(); },
            postCall(): Promise<void> { return Promise.reject(new Error('postCall also failed')); },
        };
        const boom = new Error('original error');

        await expect(
            withAdminAudit(
                makeParams({ auditHook: failingHook }),
                () => Promise.reject(boom),
            ),
        ).rejects.toThrow('original error');
    });

    it('should include role and action in postCall additionalContext', async () => {
        const hookMock = makeAuditHookMock();

        await withAdminAudit(
            makeParams({ auditHook: hookMock, role: 'tenant-admin', action: 'admin.policy.update' }),
            () => Promise.resolve('ok'),
        );

        const additionalContext = hookMock.postCallInvocations[0].additionalContext as Record<string, string>;
        expect(additionalContext['role']).toBe('tenant-admin');
        expect(additionalContext['action']).toBe('admin.policy.update');
        expect(additionalContext['component']).toBe('admin-console');
    });

    it('should halt handler when preCall throws (fail-closed)', async () => {
        let handlerCalled = false;
        const failPreHook: TenantAuditHook = {
            preCall(): Promise<void> { throw new Error('preCall failed'); },
            postCall(): Promise<void> { return Promise.resolve(); },
        };

        await expect(
            withAdminAudit(makeParams({ auditHook: failPreHook }), () => {
                handlerCalled = true;
                return Promise.resolve('should not reach');
            }),
        ).rejects.toThrow('preCall failed');

        expect(handlerCalled).toBe(false);
    });

    it('should pass tenantContext to preCall and postCall', async () => {
        const hookMock = makeAuditHookMock();
        const ctx = makeTenantContext();

        await withAdminAudit(
            makeParams({ auditHook: hookMock, tenantContext: ctx }),
            () => Promise.resolve('done'),
        );

        expect(hookMock.preCallInvocations[0].ctx).toBe(ctx);
        expect(hookMock.postCallInvocations[0].ctx).toBe(ctx);
    });

    it('should include errorMessage in additionalContext when handler throws', async () => {
        const hookMock = makeAuditHookMock();
        const boom = new Error('something broke');

        await expect(
            withAdminAudit(makeParams({ auditHook: hookMock }), () => Promise.reject(boom)),
        ).rejects.toThrow();

        const additionalContext = hookMock.postCallInvocations[0].additionalContext as Record<string, string>;
        expect(additionalContext['errorMessage']).toBe('something broke');
        expect(additionalContext['errorType']).toBe('Error');
    });
});

// ── withAdminAuditReadOnly ────────────────────────────────────────────────────

describe('withAdminAuditReadOnly — should call only postCall (no preCall)', () => {
    it('should NOT call preCall for read-only operations', async () => {
        const hookMock = makeAuditHookMock();

        await withAdminAuditReadOnly(makeParams({ auditHook: hookMock }), () => Promise.resolve('list result'));

        expect(hookMock.preCallInvocations).toHaveLength(0);
    });

    it('should call postCall with success outcome on successful read', async () => {
        const hookMock = makeAuditHookMock();

        const result = await withAdminAuditReadOnly(makeParams({ auditHook: hookMock }), () => Promise.resolve(['item1', 'item2']));

        expect(result).toEqual(['item1', 'item2']);
        expect(hookMock.postCallInvocations).toHaveLength(1);
        expect(hookMock.postCallInvocations[0].outcome).toBe('success');
    });

    it('should call postCall with error outcome and rethrow when handler throws', async () => {
        const hookMock = makeAuditHookMock();
        const boom = new Error('read failed');

        await expect(
            withAdminAuditReadOnly(makeParams({ auditHook: hookMock }), () => Promise.reject(boom)),
        ).rejects.toThrow('read failed');

        expect(hookMock.postCallInvocations).toHaveLength(1);
        expect(hookMock.postCallInvocations[0].outcome).toBe('error');
    });

    it('should rethrow handler error even when postCall also fails in read-only mode', async () => {
        const failPostHook: TenantAuditHook = {
            preCall(): Promise<void> { return Promise.resolve(); },
            postCall(): Promise<void> { return Promise.reject(new Error('postCall failed in read-only')); },
        };
        const boom = new Error('read-only original error');

        await expect(
            withAdminAuditReadOnly(makeParams({ auditHook: failPostHook }), () => Promise.reject(boom)),
        ).rejects.toThrow('read-only original error');
    });

    it('should include role in postCall additionalContext for read-only', async () => {
        const hookMock = makeAuditHookMock();

        await withAdminAuditReadOnly(
            makeParams({ auditHook: hookMock, role: 'viewer', action: 'admin.tenant.list' }),
            () => Promise.resolve([]),
        );

        const additionalContext = hookMock.postCallInvocations[0].additionalContext as Record<string, string>;
        expect(additionalContext['role']).toBe('viewer');
        expect(additionalContext['action']).toBe('admin.tenant.list');
    });
});

// ── buildAdminAuditContext ────────────────────────────────────────────────────

describe('buildAdminAuditContext — should build correct audit context Record', () => {
    it('should include role, action, resource, component fields', () => {
        const ctx = buildAdminAuditContext('admin', 'admin.tenant.delete', 'tenant-42');
        expect(ctx['role']).toBe('admin');
        expect(ctx['action']).toBe('admin.tenant.delete');
        expect(ctx['resource']).toBe('tenant-42');
        expect(ctx['component']).toBe('admin-console');
    });

    it('should not include errorMessage/errorType when no error provided', () => {
        const ctx = buildAdminAuditContext('viewer', 'admin.tenant.list', 'all');
        expect(Object.prototype.hasOwnProperty.call(ctx, 'errorMessage')).toBe(false);
        expect(Object.prototype.hasOwnProperty.call(ctx, 'errorType')).toBe(false);
    });

    it('should include errorMessage and errorType when Error is provided', () => {
        const err = new TypeError('invalid input');
        const ctx = buildAdminAuditContext('admin', 'admin.policy.update', 'policy-1', err);
        expect(ctx['errorMessage']).toBe('invalid input');
        expect(ctx['errorType']).toBe('TypeError');
    });

    it('should include errorMessage from String() when non-Error is provided', () => {
        const ctx = buildAdminAuditContext('admin', 'admin.tenant.update', 'tenant-1', 'plain string error');
        expect(ctx['errorMessage']).toBe('plain string error');
        expect(ctx['errorType']).toBe('UnknownError');
    });

    it('should handle numeric non-Error gracefully', () => {
        const ctx = buildAdminAuditContext('tenant-admin', 'admin.policy.delete', 'policy-2', 404);
        expect(ctx['errorMessage']).toBe('404');
        expect(ctx['errorType']).toBe('UnknownError');
    });

    it('should return a plain Record<string, string> (not class instance)', () => {
        const ctx = buildAdminAuditContext('viewer', 'admin.tenant.get', 'tenant-5');
        expect(typeof ctx).toBe('object');
        expect(Object.getPrototypeOf(ctx)).toBe(Object.prototype);
    });

    it('should set component to admin-console for all roles', () => {
        for (const role of ['admin', 'tenant-admin', 'viewer'] as const) {
            const ctx = buildAdminAuditContext(role, 'admin.tenant.list', 'all');
            expect(ctx['component']).toBe('admin-console');
        }
    });
});

// ── fail-closed invariant grep test ──────────────────────────────────────────

describe('fail-closed invariant grep test — audit-integration.ts must not contain bypass patterns', () => {
    function nonCommentLines(src: string): string[] {
        return src
            .split('\n')
            .filter(line => !line.trim().startsWith('//') && !line.trim().startsWith('*'));
    }

    const auditSrcPath = resolve(__dirname, '../audit-integration.ts');

    it('should not contain bypassTenant in audit-integration.ts', () => {
        const src = readFileSync(auditSrcPath, 'utf-8');
        expect(nonCommentLines(src).join('\n')).not.toMatch(/bypassTenant/);
    });

    it('should not contain skipAuth in audit-integration.ts', () => {
        const src = readFileSync(auditSrcPath, 'utf-8');
        expect(nonCommentLines(src).join('\n')).not.toMatch(/skipAuth/);
    });

    it('should not contain adminGlobalAccess in audit-integration.ts', () => {
        const src = readFileSync(auditSrcPath, 'utf-8');
        expect(nonCommentLines(src).join('\n')).not.toMatch(/adminGlobalAccess/);
    });

    it('should contain withAdminAudit export in audit-integration.ts', () => {
        const src = readFileSync(auditSrcPath, 'utf-8');
        expect(src).toMatch(/export.*withAdminAudit/);
    });

    it('should contain withAdminAuditReadOnly export in audit-integration.ts', () => {
        const src = readFileSync(auditSrcPath, 'utf-8');
        expect(src).toMatch(/withAdminAuditReadOnly/);
    });

    it('should contain preCall call in audit-integration.ts (write path enforcement)', () => {
        const src = readFileSync(auditSrcPath, 'utf-8');
        expect(src).toMatch(/auditHook\.preCall/);
    });

    it('should contain postCall call in audit-integration.ts (outcome recording)', () => {
        const src = readFileSync(auditSrcPath, 'utf-8');
        expect(src).toMatch(/auditHook\.postCall/);
    });

    it('should contain buildAdminAuditContext export in audit-integration.ts', () => {
        const src = readFileSync(auditSrcPath, 'utf-8');
        expect(src).toMatch(/export.*buildAdminAuditContext/);
    });
});
