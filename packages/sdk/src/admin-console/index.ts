/**
 * Admin Console module public exports
 *
 * Export scope (admin console):
 *   - types.ts: AdminRole / error types / CRUD request/response types
 *   - rbac.ts: getRoleFromRequest / hasPermission / requirePermission
 *   - audit-integration.ts: withAdminAudit / withAdminAuditReadOnly / buildAdminAuditContext
 *   - tenant-admin-api.ts: CRUD handler factories + InMemoryTenantRegistry
 *   - policy-admin-api.ts: CRUD handler factories + InMemoryPolicyRegistry
 *
 * Not exported in this round (to be added in the SSO segment):
 *   - SSO SAML/OIDC integration (security-sensitive)
 *
 */

// ── types.ts ──────────────────────────────────────────────────────────────────

export type {
    AdminRole,
    AdminPermission,
    AdminErrorCode,
    TenantListRequest,
    TenantGetRequest,
    TenantUpdateRequest,
    TenantDeleteRequest,
    TenantRateLimitPatch,
    TenantRecord,
    PolicyListRequest,
    PolicyGetRequest,
    PolicyUpdateRequest,
    PolicyDeleteRequest,
    PolicyRuleSet,
    PolicyRecord,
    AdminAuditEntry,
} from './types.js';

export {
    parseAdminRole,
    ROLE_PERMISSIONS,
    AdminRbacError,
    AdminResourceNotFoundError,
    AdminRequestInvalidError,
} from './types.js';

// ── rbac.ts ───────────────────────────────────────────────────────────────────

export type { MinimalRequest } from './rbac.js';

export {
    getRoleFromRequest,
    hasPermission,
    requirePermission,
} from './rbac.js';

// ── audit-integration.ts ──────────────────────────────────────────────────────

export type { AdminAuditParams } from './audit-integration.js';

export {
    withAdminAudit,
    withAdminAuditReadOnly,
    buildAdminAuditContext,
} from './audit-integration.js';

// ── tenant-admin-api.ts ───────────────────────────────────────────────────────

export type {
    TenantRegistry,
    TenantAdminApiConfig,
} from './tenant-admin-api.js';

export {
    InMemoryTenantRegistry,
    createListTenantsHandler,
    createGetTenantHandler,
    createUpdateTenantHandler,
    createDeleteTenantHandler,
    handleAdminError,
} from './tenant-admin-api.js';

// ── policy-admin-api.ts ───────────────────────────────────────────────────────

export type {
    PolicyRegistry,
    PolicyAdminApiConfig,
} from './policy-admin-api.js';

export {
    InMemoryPolicyRegistry,
    createListPoliciesHandler,
    createGetPolicyHandler,
    createUpdatePolicyHandler,
    createDeletePolicyHandler,
} from './policy-admin-api.js';

// ── federation-mapping-api.ts ─────────────────────────────────────────

export type {
    Caller,
    FederationMappingPort,
    FederationMappingCreateInput,
    FederationMappingPatch,
    FederationMappingErrorCode,
    FederationMappingAdminClientConfig,
    ListMappingsRequest,
    ListMappingsResult,
    GetMappingRequest,
    CreateMappingRequest,
    UpdateMappingRequest,
    DeleteMappingRequest,
} from './federation-mapping-api.js';

export {
    globalAdminCaller,
    tenantScopedCaller,
    FederationMappingError,
    InMemoryFederationMappingPort,
    FederationMappingAdminClient,
} from './federation-mapping-api.js';
