/**
 * audit-tamper-proof v0.1 L3 multi-tenant isolation interface
 *
 * fail-closed verification primitive:
 *   - caller principal → tenant mapping failure → AUDIT_TENANT_SCOPE_VIOLATION (fail-closed reject);
 *   - no default tenant fallback allowed;
 *   - cross-tenant writes forbidden (input AuditEvent.tenantId !== resolved tenantId → reject).
 *
 * Mandatory steps (1-6):
 *   1. caller principal (DID OR session token) + AuditEvent candidate
 *   2. resolveCallerTenant(callerPrincipal) → tenantId (throws AUDIT_TENANT_SCOPE_VIOLATION on failure)
 *   3. verify input.tenantId === resolved tenantId (mismatch throws AUDIT_TENANT_SCOPE_VIOLATION)
 *   4. DB role check (caller DB role ∈ {audit_writer_l1, audit_writer_l2}; throws if role does not match audit_class)
 *   5. SQL CHECK constraint (DB-layer backstop; 026 migration row-level security policy)
 *   6. all checks pass → proceed to step 3 advisory lock
 */

import type { DID } from '@coivitas/types';
import { AuditError, type AuditClass, type TenantId } from '@coivitas/types';

/**
 * CallerPrincipal — caller identity (DID or session token; injected by application-layer RBAC)
 */
export interface CallerPrincipal {
    /** caller DID (typical scenario; envelope sender / session owner)*/
    readonly actorDid: DID;
    /** Optional session token id (audit-share recorder scenario)*/
    readonly sessionId?: string;
    /** Optional caller DB role (audit_writer_l1 / audit_writer_l2)*/
    readonly dbRole?: 'audit_writer_l1' | 'audit_writer_l2';
}

/**
 * TenantResolver — caller principal → tenant mapping interface
 *
 * Implementation is injected at the application layer (taking a path equivalent to the SSO tenant-federation parseRole guard).
 *
 * fail-closed enforcement:
 *   - mapping failure → throw AuditError(AUDIT_TENANT_SCOPE_VIOLATION) — must not return undefined / null;
 *   - no default tenant fallback allowed.
 */
export interface TenantResolver {
    /**
     * resolveCallerTenant — caller principal → tenant mapping
     *
     * @param caller caller principal (DID + optional session + optional DB role)
     * @returns the resolved TenantId
     * @throws AuditError(AUDIT_TENANT_SCOPE_VIOLATION) if mapping fails
     */
    resolveCallerTenant(caller: CallerPrincipal): Promise<TenantId>;
}

/**
 * assertTenantScope — multi-tenant isolation enforcement guard (step 3)
 *
 * verify input AuditEvent.tenantId === resolved tenantId;
 * mismatch → AuditError(AUDIT_TENANT_SCOPE_VIOLATION) (cross-tenant writes forbidden).
 *
 * @param inputTenantId the tenantId carried by the AuditEvent candidate
 * @param resolvedTenantId the tenantId returned by resolveCallerTenant
 * @throws AuditError(AUDIT_TENANT_SCOPE_VIOLATION) if they do not match
 */
export function assertTenantScope(
    inputTenantId: TenantId,
    resolvedTenantId: TenantId,
): void {
    if (inputTenantId !== resolvedTenantId) {
        throw new AuditError(
            'AUDIT_TENANT_SCOPE_VIOLATION',
            `cross-tenant write attempted: input.tenantId="${inputTenantId}" !== resolved tenantId="${resolvedTenantId}" (multi-tenant audit isolation)`,
            { inputTenantId, resolvedTenantId },
        );
    }
}

/**
 * assertDbRoleMatchesAuditClass — guard that DB role matches audit_class (step 4)
 *
 * audit_writer_l1 → audit_class = "L1"
 * audit_writer_l2 → audit_class ∈ {"L2", "L3"}
 *
 * role does not match audit_class → AuditError(AUDIT_TENANT_SCOPE_VIOLATION)
 * (v0.1 only declares DB role separation; the actual GRANT is implemented in the 026 migration; this guard provides the application-layer enforcement path).
 *
 * @param dbRole caller DB role (optional; skipped if undefined — flagged as v0.1 backlog)
 * @param auditClass the audit class declared by the audit event
 * @throws AuditError(AUDIT_TENANT_SCOPE_VIOLATION) if they do not match
 */
export function assertDbRoleMatchesAuditClass(
    dbRole: CallerPrincipal['dbRole'],
    auditClass: AuditClass,
): void {
    // v0.1 allows dbRole to be undefined (to be implemented later; landed in the 026 migration);
    // undefined is not treated as a violation (this guard is skipped when the application layer has not enabled DB role separation)
    if (dbRole === undefined) {
        return;
    }

    if (dbRole === 'audit_writer_l1' && auditClass !== 'L1') {
        throw new AuditError(
            'AUDIT_TENANT_SCOPE_VIOLATION',
            `DB role mismatch audit_class: audit_writer_l1 may only write L1 events, got "${auditClass}"`,
            { dbRole, auditClass },
        );
    }
    if (dbRole === 'audit_writer_l2' && auditClass === 'L1') {
        throw new AuditError(
            'AUDIT_TENANT_SCOPE_VIOLATION',
            `DB role mismatch audit_class: audit_writer_l2 may not write L1 events, got "${auditClass}" (L1 reserved for audit_writer_l1)`,
            { dbRole, auditClass },
        );
    }
}

// ─── In-Memory TenantResolver (test-only;@internal stub) ─────────────────────

/**
 * InMemoryTenantResolver — @internal test stub
 *
 * For tests / offline dev mode only;
 * production callers must implement a standalone TenantResolver (e.g. PostgresTenantResolver).
 *
 * Strict fail-closed: this stub throws AuditError on mapping failure; no fallback default tenant allowed.
 */
export class InMemoryTenantResolver implements TenantResolver {
    private readonly mappings = new Map<string, TenantId>();

    /**
     * Register a caller DID → tenant mapping (test setup);
     * re-registering the same DID overwrites the previous mapping (test convenience).
     */
    public register(actorDid: DID, tenantId: TenantId): void {
        this.mappings.set(actorDid, tenantId);
    }

    /**
     * resolveCallerTenant — caller DID → tenant mapping;
     * throws AuditError(AUDIT_TENANT_SCOPE_VIOLATION) when not registered.
     *
     * @throws AuditError(AUDIT_TENANT_SCOPE_VIOLATION) if the DID is not registered
     */
    // eslint-disable-next-line @typescript-eslint/require-await
    public async resolveCallerTenant(
        caller: CallerPrincipal,
    ): Promise<TenantId> {
        const tenant = this.mappings.get(caller.actorDid);
        if (tenant === undefined) {
            throw new AuditError(
                'AUDIT_TENANT_SCOPE_VIOLATION',
                `caller principal not mapped to any tenant: actorDid="${caller.actorDid}" (InMemoryTenantResolver stub; production must implement; no default tenant fallback allowed)`,
                { actorDid: caller.actorDid },
            );
        }
        return tenant;
    }
}
