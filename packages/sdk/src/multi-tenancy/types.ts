/**
 * Multi-tenant SDK public type definitions
 *
 * Responsibilities:
 *   - TenantId branded type
 *   - TenantContext: must be carried by every tenant-scoped operation
 *   - MultiTenantSDKConfig: enterprise SDK multi-tenancy configuration
 *   - TenantResolver: async function type that resolves a TenantId from a request
 *   - Error-code taxonomy (fail-closed; missing TenantContext -> TenantNotFoundError)
 *
 * Design constraints (fail-closed):
 *   - Every tenant-scoped operation MUST carry a TenantContext
 *   - missing TenantContext -> fail-closed (throw TenantNotFoundError; never fall back to a default tenant)
 *   - The single-tenant fallback anti-patterns globalRateLimit / defaultTenant / untenanted are forbidden
 *   - The `as TenantId` brand cast is forbidden; use the makeTenantId() factory function
 *
 */

import type { DID, Timestamp } from '@coivitas/types';

// ── TenantId branded type ─────────────────────────────────────────────────────

/**
 * TenantId branded type (prevents a bare string from being passed in by mistake)
 *
 * Conclusion: the branded type guarantees compile-time tenant isolation;
 * it must be constructed via makeTenantId(); the `as TenantId` cast is forbidden.
 *
 * Valid format: `^[a-zA-Z0-9_-]{1,128}$`
 */
export type TenantId = string & { readonly __brand: 'TenantId' };

/**
 * Construct a TenantId (the only legal way to create a TenantId; brand cast forbidden)
 *
 * Rules:
 *   - length 1-128 bytes
 *   - only a-z A-Z 0-9 _ -
 *   - empty string / too long / invalid characters -> throw TenantUnauthorizedError
 */
export function makeTenantId(raw: string): TenantId {
    if (!TENANT_ID_PATTERN.test(raw)) {
        throw new TenantUnauthorizedError(
            `Invalid tenantId format: "${raw.slice(0, 64)}"`,
            'TENANT_ID_INVALID_FORMAT',
        );
    }
    return raw as TenantId;
}

/** Regex for the valid TenantId format */
const TENANT_ID_PATTERN = /^[a-zA-Z0-9_-]{1,128}$/;

// ── TenantContext ─────────────────────────────────────────────────────────────

/**
 * Context carrier for every tenant-scoped operation
 *
 * Conclusion: TenantContext is the core data structure for multi-tenant isolation;
 * every tenant-scoped API must accept and propagate this context;
 * missing TenantContext -> fail-closed (throw TenantNotFoundError).
 */
export interface TenantContext {
    /** Unique tenant identifier */
    readonly tenantId: TenantId;

    /** Tenant display name (for logging / auditing; not used for authentication) */
    readonly tenantName?: string;

    /** DID of the actor that initiated the operation (used for the audit event; may be undefined only for internal system operations) */
    readonly actorDid?: DID;

    /**
     * Tenant-level rate-limit configuration override
     * undefined -> use MultiTenantSDKConfig.defaultRateLimitConfig
     */
    readonly rateLimitOverride?: TenantRateLimitOverride;

    /**
     * Context metadata (passed through transparently; supplementary info for the audit hook)
     * Do not store security-sensitive data such as credentials / tokens / passwords in this field
     */
    readonly metadata?: Record<string, string>;

    /** Context creation time (ISO 8601; used to correct audit timestamps) */
    readonly createdAt: Timestamp;
}

/**
 * Tenant rate-limit configuration override
 */
export interface TenantRateLimitOverride {
    /** Per-second request quota (overrides the global default) */
    readonly requestsPerSecond?: number;
    /** Per-minute request quota (overrides the global default) */
    readonly requestsPerMinute?: number;
    /** Extra requests allowed during a burst (token bucket) */
    readonly burstCapacity?: number;
}

// ── MultiTenantSDKConfig ──────────────────────────────────────────────────────

/**
 * Enterprise SDK multi-tenancy configuration (MultiTenantSDKConfig)
 *
 * Conclusion: adds a multi-tenancy section on top of EnterpriseSDKConfig;
 * tenantResolver is required, and a missing value fails closed at construction time.
 */
export interface MultiTenantSDKConfig {
    /**
     * TenantResolver (required): async function that resolves a TenantId from a request
     * missing / undefined -> MultiTenantSDKConfigError (fail-closed at construction time)
     */
    readonly tenantResolver: TenantResolver;

    /**
     * Default rate-limit configuration (applies to tenants that do not override it via TenantContext.rateLimitOverride)
     */
    readonly defaultRateLimitConfig: DefaultRateLimitConfig;

    /**
     * Audit hook configuration
     */
    readonly auditConfig?: TenantAuditConfig;

}

/**
 * Default rate-limit configuration
 */
export interface DefaultRateLimitConfig {
    /** Per-second request quota */
    readonly requestsPerSecond: number;
    /** Per-minute request quota */
    readonly requestsPerMinute: number;
    /** Extra requests allowed during a burst */
    readonly burstCapacity: number;
    /** Rate-limiting algorithm */
    readonly algorithm: 'token-bucket' | 'sliding-window';
}

/**
 * Tenant audit configuration
 */
export interface TenantAuditConfig {
    /** Whether to fire the pre-call audit hook on every API call (default true) */
    readonly enablePreCallHook?: boolean;
    /** Whether to fire the post-call audit hook on every API call (default true) */
    readonly enablePostCallHook?: boolean;
    /**
     * Signing key ID for audit events (from the key-custody KMS)
     * undefined -> audit events are not signed (development environments only)
     */
    readonly auditSigningKeyId?: string;
}

// ── TenantResolver ────────────────────────────────────────────────────────────

/**
 * TenantResolver: async function type that resolves a TenantId from a request
 *
 * Conclusion: supports three sources — HTTP header / API key / JWT claim;
 * if resolution fails it must throw TenantNotFoundError (fail-closed);
 * returning null / undefined / a default value is forbidden.
 *
 * Parameters:
 *   - request: TenantResolverRequest (contains headers / apiKey / jwtToken)
 * Returns:
 *   - a validated TenantContext (with tenantId + actorDid, etc.)
 * Throws:
 *   - TenantNotFoundError: tenantId cannot be resolved
 *   - TenantUnauthorizedError: tenantId has an invalid format or insufficient permissions
 */
export type TenantResolver = (request: TenantResolverRequest) => Promise<TenantContext>;

/**
 * Request parameter for TenantResolver (multiple optional sources; at least one must be non-empty)
 */
export interface TenantResolverRequest {
    /** HTTP headers (includes X-Tenant-Id / Authorization, etc.) */
    readonly headers?: Record<string, string | string[] | undefined>;
    /** API key (from the Authorization header or a query param) */
    readonly apiKey?: string;
    /** JWT token (from Authorization: Bearer <token>) */
    readonly jwtToken?: string;
    /** tenantId passed in directly (trusted source; internal calls only) */
    readonly tenantId?: string;
}

// ── Error-code taxonomy ───────────────────────────────────────────────────────

/**
 * Multi-tenancy error codes (fail-closed; missing TenantContext -> TenantNotFoundError)
 *
 * Design principle: every error must fail closed; silent degradation or fallback is forbidden.
 */
export type TenantErrorCode =
    /** tenantId could not be resolved from the request */
    | 'TENANT_NOT_FOUND'
    /** tenantId has an invalid format (does not match ^[a-zA-Z0-9_-]{1,128}$) */
    | 'TENANT_ID_INVALID_FORMAT'
    /** the tenant associated with the API key / JWT token has insufficient permissions */
    | 'TENANT_UNAUTHORIZED'
    /** TenantContext missing (the operation was called without a TenantContext) */
    | 'TENANT_CONTEXT_MISSING'
    /** MultiTenantSDKConfig configuration error (construction phase) */
    | 'TENANT_CONFIG_INVALID'
    /** rate limit exceeded (tenant-scoped) */
    | 'TENANT_RATE_LIMITED'
    /** audit hook failed (fail-closed; operation aborted) */
    | 'TENANT_AUDIT_FAILED'
    /** unknown tenant error (catch-all; must not be treated as success) */
    | 'TENANT_UNKNOWN';

/**
 * Base multi-tenancy error (parent class of all tenant errors)
 */
export abstract class TenantError extends Error {
    abstract readonly code: TenantErrorCode;

    constructor(
        message: string,
        public readonly tenantId?: TenantId,
    ) {
        super(message);
        this.name = this.constructor.name;
        // Ensure instanceof still works correctly after the TypeScript transpile
        Object.setPrototypeOf(this, new.target.prototype);
    }
}

/**
 * TenantNotFoundError: tenantId cannot be resolved from the request
 *
 * Triggered when: none of the HTTP header / API key / JWT claim carries a recognizable tenantId.
 * Handling strategy: fail-closed; execution must not continue.
 */
export class TenantNotFoundError extends TenantError {
    readonly code = 'TENANT_NOT_FOUND' as const;

    constructor(message: string, tenantId?: TenantId) {
        super(message, tenantId);
    }
}

/**
 * TenantUnauthorizedError: tenantId has an invalid format or insufficient permissions
 *
 * Triggered when:
 *   - tenantId does not match the ^[a-zA-Z0-9_-]{1,128}$ format
 *   - the tenant associated with the API key / JWT is not authorized to access the target resource
 * Handling strategy: fail-closed; execution must not continue.
 */
export class TenantUnauthorizedError extends TenantError {
    readonly code: TenantErrorCode;

    constructor(
        message: string,
        code: Extract<TenantErrorCode, 'TENANT_UNAUTHORIZED' | 'TENANT_ID_INVALID_FORMAT'> = 'TENANT_UNAUTHORIZED',
        tenantId?: TenantId,
    ) {
        super(message, tenantId);
        this.code = code;
    }
}

/**
 * TenantContextMissingError: the operation was called without a TenantContext
 *
 * Triggered when: a tenant-scoped operation does not carry a TenantContext.
 * Handling strategy: fail-closed; abort the operation immediately.
 */
export class TenantContextMissingError extends TenantError {
    readonly code = 'TENANT_CONTEXT_MISSING' as const;

    constructor(operationName: string) {
        super(
            `TenantContext is required for operation "${operationName}" but was not provided. ` +
            'All tenant-scoped operations must carry a TenantContext. ' +
            'Ensure tenantContextMiddleware is applied before this handler.',
        );
    }
}

/**
 * TenantConfigInvalidError: MultiTenantSDKConfig configuration error
 *
 * Triggered when: tenantResolver is missing or the configuration is invalid while constructing MultiTenantSDKConfig.
 * Handling strategy: fail-closed; SDK initialization is aborted.
 */
export class TenantConfigInvalidError extends TenantError {
    readonly code = 'TENANT_CONFIG_INVALID' as const;

    constructor(message: string) {
        super(message);
    }
}

// ── Utility types ─────────────────────────────────────────────────────────────

/**
 * Validate MultiTenantSDKConfig (fail-closed at construction time)
 *
 * Conclusion: called during SDK initialization; missing tenantResolver -> TenantConfigInvalidError.
 */
export function validateMultiTenantSDKConfig(config: MultiTenantSDKConfig): void {
    if (typeof config.tenantResolver !== 'function') {
        throw new TenantConfigInvalidError(
            'MultiTenantSDKConfig.tenantResolver must be a function. ' +
            'Provide a TenantResolver implementation (e.g., createDefaultTenantResolver).',
        );
    }
    const rl = config.defaultRateLimitConfig;
    if (
        typeof rl.requestsPerSecond !== 'number' || rl.requestsPerSecond <= 0 ||
        typeof rl.requestsPerMinute !== 'number' || rl.requestsPerMinute <= 0 ||
        typeof rl.burstCapacity !== 'number' || rl.burstCapacity < 0
    ) {
        throw new TenantConfigInvalidError(
            'MultiTenantSDKConfig.defaultRateLimitConfig must have positive requestsPerSecond, ' +
            'requestsPerMinute, and non-negative burstCapacity.',
        );
    }
    if (rl.algorithm !== 'token-bucket' && rl.algorithm !== 'sliding-window') {
        throw new TenantConfigInvalidError(
            'MultiTenantSDKConfig.defaultRateLimitConfig.algorithm must be "token-bucket" or "sliding-window".',
        );
    }
}
