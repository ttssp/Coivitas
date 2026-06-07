/**
 * Public exports of the multi-tenancy module (barrel export)
 *
 * Export surface (multi-tenancy):
 *   - TenantId + makeTenantId (branded type; brand cast forbidden)
 *   - TenantContext + MultiTenantSDKConfig + TenantResolver + TenantResolverRequest
 *   - Error-code taxonomy: TenantError + subclasses + TenantErrorCode
 *   - createDefaultTenantResolver + validateTenantContext + tenantContextMiddleware
 *   - MemoryTenantRateLimiter + TenantRateLimiterConfig + RateLimitResult + TenantRateLimitError
 *   - InMemoryTenantAuditHook + InMemoryTenantAuditFilter
 *   - TenantAuditEvent + TenantAuditHook + TenantAuditFilter + AuditQuery
 *
 * Not exported this round (to be added later):
 *   - admin console UI
 *   - SSO SAML/OIDC
 *
 */

// ── types.ts ─────────────────────────────────────────────────────────────────

export type {
    TenantId,
    TenantContext,
    TenantRateLimitOverride,
    MultiTenantSDKConfig,
    DefaultRateLimitConfig,
    TenantAuditConfig,
    TenantResolver,
    TenantResolverRequest,
    TenantErrorCode,
} from './types.js';

export {
    makeTenantId,
    TenantError,
    TenantNotFoundError,
    TenantUnauthorizedError,
    TenantContextMissingError,
    TenantConfigInvalidError,
    validateMultiTenantSDKConfig,
} from './types.js';

// ── tenant-resolver.ts ────────────────────────────────────────────────────────

export type { DefaultTenantResolverOptions } from './tenant-resolver.js';

export {
    createDefaultTenantResolver,
    validateTenantContext,
    tenantContextMiddleware,
    getTenantContextFromLocals,
} from './tenant-resolver.js';

// ── rate-limiter.ts ───────────────────────────────────────────────────────────

export type {
    TenantRateLimiterConfig,
    RateLimitResult,
    TenantRateLimiter,
} from './rate-limiter.js';

export {
    MemoryTenantRateLimiter,
    TenantRateLimitError,
    TenantRateLimiterStorageError,
} from './rate-limiter.js';

// ── audit-hook.ts ─────────────────────────────────────────────────────────────

export type {
    TenantAuditEvent,
    TenantAuditHook,
    TenantAuditFilter,
    AuditQuery,
} from './audit-hook.js';

export {
    InMemoryTenantAuditHook,
    InMemoryTenantAuditFilter,
    TenantAuditFailedError,
    TenantAuditCrossLeakError,
} from './audit-hook.js';
