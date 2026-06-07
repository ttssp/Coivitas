/**
 * Admin Console audit integration
 *
 * Responsibilities:
 *   - withAdminAudit: a higher-order function; wraps an admin handler and injects the preCall + postCall audit hook
 *   - buildAdminAuditContext: builds the audit additional context (role + resource + operation type)
 *
 * Design constraints (fail-closed + literal coupling with the audit hook):
 *   - every admin write operation must go through auditHook.preCall + postCall (literal constraint)
 *   - TenantContext missing → fail-closed (TenantContextMissingError; tenant-less audit is not permitted)
 *   - audit hook failure → fail-closed (TenantAuditFailedError; the operation aborts)
 *   - this module depends only on the multi-tenancy/audit-hook TenantAuditHook interface; it does not modify that code
 *
 * Literal coupling relationship with multi-tenancy/audit-hook:
 *   - uses TenantAuditHook directly (the InMemoryTenantAuditHook interface)
 *   - audit event action is prefixed with "admin." (to distinguish it)
 *   - TenantContext comes from res.locals (already injected by tenantContextMiddleware)
 *
 */

import type { TenantAuditHook } from '../multi-tenancy/audit-hook.js';
import type { TenantContext } from '../multi-tenancy/types.js';
import type { AdminRole } from './types.js';

// ── withAdminAudit ────────────────────────────────────────────────────────────

/**
 * withAdminAudit parameters
 */
export interface AdminAuditParams {
    /** TenantContext (from tenantContextMiddleware; missing → fail-closed)*/
    readonly tenantContext: TenantContext | undefined;
    /** audit hook instance (from InMemoryTenantAuditHook)*/
    readonly auditHook: TenantAuditHook;
    /** admin operation type (e.g. "admin.tenant.update" / "admin.policy.delete")*/
    readonly action: string;
    /** the target resource of the operation (e.g. tenant ID / policy ID)*/
    readonly resource: string;
    /** the initiator's role*/
    readonly role: AdminRole;
}

/**
 * withAdminAudit: inject the audit hook around an admin operation (fail-closed)
 *
 * Conclusion: every admin write operation must be wrapped by this function;
 * it ensures both preCall and postCall are invoked, and injects the role information into the audit context.
 *
 * Execution flow:
 *   1. auditHook.preCall (fail-closed; TenantContext missing → abort)
 *   2. run the admin operation (handler())
 *   3. auditHook.postCall (record the outcome: success / error)
 *   4. return the handler result
 *
 * @param params AdminAuditParams
 * @param handler the actual operation (async function)
 * @throws TenantContextMissingError if tenantContext is undefined
 * @throws TenantAuditFailedError if the audit write fails
 */
export async function withAdminAudit<T>(
    params: AdminAuditParams,
    handler: () => Promise<T>,
): Promise<T> {
    const { tenantContext, auditHook, action, resource, role } = params;

    // Literal constraint: every admin write operation must go through auditHook.preCall (fail-closed invariant)
    await auditHook.preCall(tenantContext, action, resource);

    let outcome: 'success' | 'error' = 'success';
    try {
        const result = await handler();
        outcome = 'success';
        // Literal constraint: every admin write operation must go through auditHook.postCall (fail-closed invariant)
        await auditHook.postCall(
            tenantContext,
            action,
            outcome,
            resource,
            buildAdminAuditContext(role, action, resource),
        );
        return result;
    } catch (err) {
        outcome = 'error';
        // Try to record the failure audit (without swallowing the original error, even if this fails too)
        try {
            await auditHook.postCall(
                tenantContext,
                action,
                'error',
                resource,
                buildAdminAuditContext(role, action, resource, err),
            );
        } catch {
            // When the audit itself fails: preserve the original error (do not double-throw the audit error)
        }
        throw err;
    }
}

/**
 * withAdminAuditReadOnly: audit for read-only admin operations (does not require preCall; postCall only)
 *
 * Conclusion: read-only operations such as list/get use this wrapper;
 * it reduces the number of audit events while still recording an access log.
 */
export async function withAdminAuditReadOnly<T>(
    params: AdminAuditParams,
    handler: () => Promise<T>,
): Promise<T> {
    const { tenantContext, auditHook, action, resource, role } = params;

    try {
        const result = await handler();
        await auditHook.postCall(
            tenantContext,
            action,
            'success',
            resource,
            buildAdminAuditContext(role, action, resource),
        );
        return result;
    } catch (err) {
        await auditHook.postCall(
            tenantContext,
            action,
            'error',
            resource,
            buildAdminAuditContext(role, action, resource, err),
        ).catch(() => {
            // an audit failure does not affect rethrowing the primary error
        });
        throw err;
    }
}

// ── buildAdminAuditContext ────────────────────────────────────────────────────

/**
 * Build the admin audit additional context
 *
 * Conclusion: serialize role / action / resource into a string record;
 * injected into the additionalContext parameter of TenantAuditHook.postCall.
 */
export function buildAdminAuditContext(
    role: AdminRole,
    action: string,
    resource: string,
    error?: unknown,
): Record<string, string> {
    const ctx: Record<string, string> = {
        role,
        action,
        resource,
        component: 'admin-console',
    };
    if (error !== undefined) {
        ctx['errorMessage'] = error instanceof Error
            ? error.message
            : (typeof error === 'string' || typeof error === 'number' || typeof error === 'boolean')
                ? String(error)
                : 'non-Error thrown';
        ctx['errorType'] = error instanceof Error ? error.constructor.name : 'UnknownError';
    }
    return ctx;
}
