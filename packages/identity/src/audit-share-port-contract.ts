/**
 * audit-share-port-contract — L2 AuditShareTenantResolver port interface
 *
 * Interplay: multi-tenant isolation enforcement (scope-boundary injection port)
 *
 * Responsibilities:
 *   - Provide the L2 resolver injection port definition for the L3 AuditShareManager
 *   - This file only exports the port interface (the implementation lives in sso/audit-share-tenant-resolver.ts)
 *   - Unify the port interface namespace via re-export, avoiding direct imports of sso/ subpaths
 *
 * Design constraints (partial-enforce declaration):
 *   - procedural enforce: the tenant_audit_share_policy table's SQL WHERE (not cryptographic)
 *   - cryptographic enforce: Ed25519 signature verify (the real verifier scope of DelegatedAuditKey)
 *   - fail-closed: any cross-tenant check failure → throw AUDIT_SHARE_CROSS_TENANT_REJECT
 *
 *   multi-tenant audit isolation:
 *   - This port is the L2 port definition for multi-tenant isolation
 *   - The L3 AuditShareManager injects the L2 resolver implementation through this port
 */

export type {
    AuditShareTenantResolver,
    AuditKeyLookupPort,
    PolicyLookupPort,
    DelegatedAuditKeyRecord,
    AuditShareScopeRecord,
    PolicyRecord,
    AuditShareTenantResolverDeps,
} from './sso/audit-share-tenant-resolver.js';

export { AuditShareCrossTenantRejectError } from './sso/audit-share-tenant-resolver.js';
