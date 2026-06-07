/**
 * audit-share-tenant-resolver — L2 multi-tenant audit isolation integration
 *
 * Integration: multi-tenant isolation enforcement + scope isolation declaration
 *
 * Responsibilities:
 *   - verifyCrossTenantAccess: verifies whether a cross-tenant audit-share request is authorized
 *     same tenant (same tenant_id): ACCEPT (single-tenant internal access needs no delegated key)
 *     cross-tenant: requires DelegatedAuditKey.tenant_id === requesterTenantId (delegator authority)
 *                   AND scope contains the target tenant_id binding (policy whitelist check)
 *                   otherwise throw AUDIT_SHARE_CROSS_TENANT_REJECT (fail-closed)
 *
 * Key design constraints (trinity + partial enforce declaration):
 *   - **procedural enforce**: tenant_audit_share_policy table SQL WHERE clause (not a cryptographic enforce)
 *   - **cryptographic enforce**: DelegatedAuditKey.proof.signature Ed25519 verify (handled elsewhere)
 *   - **fail-closed**: any cross-tenant check failure → throw AUDIT_SHARE_CROSS_TENANT_REJECT (does not return ok=false)
 *
 * Note: this file is the L2 sso/audit-share-tenant-resolver.
 *       The real DelegatedAuditKey verifier is implemented in delegated-audit-key.ts.
 */

// ── Error class ────────────────────────────────────────────────────────────────────

/**
 * AUDIT_SHARE_CROSS_TENANT_REJECT — cross-tenant access rejected error.
 *
 * Trigger conditions:
 *   1. cross-tenant access without DelegatedAuditKey authorization
 *   2. DelegatedAuditKey.tenant_id !== requesterTenantId (delegator authority mismatch)
 *   3. scope binding does not contain targetTenantId (not covered by the whitelist policy)
 *
 * fail-closed: any cross-tenant authorization failure throws this error (no silent fail).
 */
export class AuditShareCrossTenantRejectError extends Error {
    public override readonly name = 'AuditShareCrossTenantRejectError';
    public readonly code = 'AUDIT_SHARE_CROSS_TENANT_REJECT' as const;

    public constructor(
        public readonly requesterTenantId: string,
        public readonly targetTenantId: string,
        public readonly auditKeyId: string | null,
        reason: string,
    ) {
        super(
            `[AUDIT_SHARE_CROSS_TENANT_REJECT] ${reason} ` +
            `(requesterTenantId=${requesterTenantId}, targetTenantId=${targetTenantId}, ` +
            `auditKeyId=${auditKeyId ?? 'null'})`,
        );
    }
}

// ── Port interface ─────────────────────────────────────────────────────────────

/**
 * DelegatedAuditKeyRecord — SQL query result (delegated_audit_keys table row snapshot).
 *
 * Corresponds to the managed_service.delegated_audit_keys table column set (migration 028).
 * This file does not depend on an ORM; the caller injects the DB query logic via AuditKeyLookupPort.
 */
export interface DelegatedAuditKeyRecord {
    /** Delegated key business primary key (UUID v4; VerifiedAuditRequest.token references this value)*/
    readonly auditKeyId: string;
    /** Tenant the delegated key belongs to (multi-tenant FK corresponding to the tenant_id column)*/
    readonly tenantId: string;
    /** Delegator DID (delegated_from column)*/
    readonly delegatedFrom: string;
    /** Delegatee DID (delegated_to column)*/
    readonly delegatedTo: string;
    /** Authorized scope (scope JSONB column; contains the targetTenantId binding)*/
    readonly scope: AuditShareScopeRecord;
    /** Whether it has been revoked*/
    readonly revoked: boolean;
    /** Validity period start*/
    readonly validFrom: string;
    /** Validity period end*/
    readonly validUntil: string;
}

/**
 * AuditShareScopeRecord — scope JSONB deserialized structure.
 *
 * Corresponds to AuditShareScope.
 * Note: this layer performs no brand type conversion; the caller is responsible for the category guard.
 */
export interface AuditShareScopeRecord {
    /** Target tenantId (scope boundary)*/
    readonly tenantId: string;
    /** audit class boundary (L1/L2/L3)*/
    readonly auditClass: string;
    /** chain namespace boundary (optional; hcc v0.1 ChainIdentity)*/
    readonly chainNamespace?: string;
}

/**
 * PolicyRecord — tenant_audit_share_policy table row snapshot.
 *
 * Corresponds to the managed_service.tenant_audit_share_policy table column set (migration 028).
 */
export interface PolicyRecord {
    readonly principalDid: string;
    readonly allowedTenantId: string;
    readonly auditClass: string;
    readonly grantedBy: string;
}

/**
 * AuditKeyLookupPort — DelegatedAuditKey DB query port (dependency injection).
 *
 * The L3 AuditShareManager injects the DB query through this port;
 * this file defines the port interface.
 */
export interface AuditKeyLookupPort {
    /**
     * Queries a delegated key by auditKeyId (managed_service.delegated_audit_keys table).
     * @returns the record if found; null if not found (does not throw)
     */
    findByAuditKeyId(auditKeyId: string): Promise<DelegatedAuditKeyRecord | null>;
}

/**
 * PolicyLookupPort — tenant_audit_share_policy DB query port (dependency injection).
 *
 * Data source for the atp v0.1 multi-tenant isolation enforcement integration.
 */
export interface PolicyLookupPort {
    /**
     * Queries the cross-tenant whitelist (tenant_audit_share_policy table).
     * @returns the record if a matching policy is found; null if not authorized
     */
    findPolicy(
        principalDid: string,
        allowedTenantId: string,
        auditClass: string,
    ): Promise<PolicyRecord | null>;
}

// ── AuditShareTenantResolver interface (port — for injection) ─────────────

/**
 * AuditShareTenantResolver — L2 tenant isolation resolver port interface.
 *
 * The L3 manager injects this port;
 * this file provides the implementation (returned by the createAuditShareTenantResolver factory).
 *
 * Design constraints (fail-closed):
 *   - verifyCrossTenantAccess failure → throw AUDIT_SHARE_CROSS_TENANT_REJECT (not ok=false)
 *   - same tenant → ACCEPT (no DB query needed)
 *   - cross-tenant → DelegatedAuditKey tenant_id verify + scope binding verify
 */
export interface AuditShareTenantResolver {
    /**
     * Verifies cross-tenant audit-share access authorization.
     *
     * @param requesterTenantId tenant the requester belongs to (VerifiedAuditRequest.requestedScope.tenantId)
     * @param targetTenantId tenant the target data belongs to (DelegatedAuditKey.scope.tenantId)
     * @param auditKeyId delegated key ID (VerifiedAuditRequest.token)
     * @param auditClass the requested audit class (L1/L2/L3)
     *
     * @returns void (ACCEPT)
     * @throws AuditShareCrossTenantRejectError (REJECT fail-closed)
     */
    verifyCrossTenantAccess(
        requesterTenantId: string,
        targetTenantId: string,
        auditKeyId: string,
        auditClass: string,
    ): Promise<void>;
}

// ── Implementation ──────────────────────────────────────────────────────────────────────

/**
 * AuditShareTenantResolverDeps — createAuditShareTenantResolver dependency injection set.
 */
export interface AuditShareTenantResolverDeps {
    readonly auditKeyLookup: AuditKeyLookupPort;
    readonly policyLookup: PolicyLookupPort;
    /** now() provider (injected in tests; defaults to => new Date())*/
    readonly getNow?: () => Date;
}

/**
 * createAuditShareTenantResolver — AuditShareTenantResolver factory.
 *
 * Returns an object implementing the AuditShareTenantResolver port.
 * Dependency-injects auditKeyLookup + policyLookup (DB layer decoupling).
 *
 * Algorithm (cross-tenant path):
 *   1. same tenant fast ACCEPT
 *   2. fetch DelegatedAuditKey by auditKeyId (key not found → REJECT)
 *   3. key.tenantId === requesterTenantId (delegator authority check → mismatch REJECT)
 *   4. key.scope.tenantId === targetTenantId (scope binding check → mismatch REJECT)
 *   5. key.revoked (revoked → REJECT)
 *   6. key.validUntil ≥ now (expired → REJECT; time window check)
 *   7. policyLookup.findPolicy(delegatedFrom, targetTenantId, auditClass) (whitelist check → none REJECT)
 *
 * Note: signature verify is handled by the real DelegatedAuditKey verifier (this layer does not verify again).
 */
export function createAuditShareTenantResolver(
    deps: AuditShareTenantResolverDeps,
): AuditShareTenantResolver {
    const { auditKeyLookup, policyLookup, getNow = () => new Date() } = deps;

    return {
        async verifyCrossTenantAccess(
            requesterTenantId: string,
            targetTenantId: string,
            auditKeyId: string,
            auditClass: string,
        ): Promise<void> {
            // ── Step 1: same tenant fast ACCEPT ─────────────────────────────
            // Same-tenant internal access needs no DelegatedAuditKey delegation; within the atp v0.1 isolation scope
            if (requesterTenantId === targetTenantId) {
                return; // ACCEPT
            }

            // ── Step 2: cross-tenant — fetch DelegatedAuditKey ──────────────
            // Data source: managed_service.delegated_audit_keys (migration 028)
            const key = await auditKeyLookup.findByAuditKeyId(auditKeyId);
            if (key === null) {
                throw new AuditShareCrossTenantRejectError(
                    requesterTenantId,
                    targetTenantId,
                    auditKeyId,
                    'DelegatedAuditKey not found (auditKeyId lookup miss)',
                );
            }

            // ── Step 3: delegator authority check ────────────────────────────
            // key.tenantId must === requesterTenantId
            // Meaning: the delegated key must be issued by a principal in the requester's tenant
            // (a tenant A delegated key must not be used by a tenant B requester)
            if (key.tenantId !== requesterTenantId) {
                throw new AuditShareCrossTenantRejectError(
                    requesterTenantId,
                    targetTenantId,
                    auditKeyId,
                    `DelegatedAuditKey.tenantId (${key.tenantId}) !== requesterTenantId (${requesterTenantId})`,
                );
            }

            // ── Step 4: scope binding check ──────────────────────────────────
            // key.scope.tenantId must === targetTenantId
            // Meaning: the delegated key's scope must explicitly bind the target tenant
            if (key.scope.tenantId !== targetTenantId) {
                throw new AuditShareCrossTenantRejectError(
                    requesterTenantId,
                    targetTenantId,
                    auditKeyId,
                    `DelegatedAuditKey.scope.tenantId (${key.scope.tenantId}) !== targetTenantId (${targetTenantId})`,
                );
            }

            // ── Step 5: revoked check ─────────────────────────────────────────
            if (key.revoked) {
                throw new AuditShareCrossTenantRejectError(
                    requesterTenantId,
                    targetTenantId,
                    auditKeyId,
                    'DelegatedAuditKey is revoked',
                );
            }

            // ── Step 6: validity window check ──────────────────────────────────────
            const now = getNow();
            const validUntil = new Date(key.validUntil);
            const validFrom = new Date(key.validFrom);
            if (now < validFrom || now > validUntil) {
                throw new AuditShareCrossTenantRejectError(
                    requesterTenantId,
                    targetTenantId,
                    auditKeyId,
                    `DelegatedAuditKey not in validity window (validFrom=${key.validFrom}, validUntil=${key.validUntil}, now=${now.toISOString()})`,
                );
            }

            // ── Step 7: tenant_audit_share_policy whitelist check ────────────
            // Data source: managed_service.tenant_audit_share_policy (migration 028)
            // multi-tenant isolation enforcement integration
            const policy = await policyLookup.findPolicy(
                key.delegatedFrom,
                targetTenantId,
                auditClass,
            );
            if (policy === null) {
                throw new AuditShareCrossTenantRejectError(
                    requesterTenantId,
                    targetTenantId,
                    auditKeyId,
                    `No tenant_audit_share_policy found for principalDid=${key.delegatedFrom}, ` +
                    `allowedTenantId=${targetTenantId}, auditClass=${auditClass}`,
                );
            }

            // ── ACCEPT ───────────────────────────────────────────────────────
            // All checks passed: cross-tenant DelegatedAuditKey authorization within the same scope is verified
            return;
        },
    };
}
