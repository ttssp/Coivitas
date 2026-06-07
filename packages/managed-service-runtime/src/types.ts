/**
 * Shared type definitions for the managed service runtime.
 *
 * Design notes (conclusions first, details after):
 * - Introduces no wire format breaking: the API JSON reuses the already-frozen @coivitas/types types.
 * - tier = 'FREE' | 'PRO' maps to a SQL CHECK constraint and is strongly typed at runtime.
 * - request.tenant is attached state injected by auth-middleware; it may be null (the FREE tier has no key).
 *
 */

import type { Request } from 'express';

/** Billing tier (matches the SQL 008 CHECK constraint). */
export type Tier = 'FREE' | 'PRO';

/** Endpoint type (matches the SQL usage_log.endpoint CHECK constraint). */
export type Endpoint = 'resolver' | 'revocation';

/** Tenant record (DB row projection). */
export interface TenantRecord {
    id: string;
    tenantDid: string;
    tier: Tier;
    displayName: string;
    contactEmail: string | null;
    status: 'ACTIVE' | 'SUSPENDED' | 'DELETED';
}

/** API key record (DB row projection). */
export interface ApiKeyRecord {
    id: string;
    tenantId: string;
    keyHash: string;
    keyPrefix: string;
    description: string | null;
    expiresAt: Date | null;
    lastUsedAt: Date | null;
    status: 'ACTIVE' | 'REVOKED' | 'EXPIRED';
}

/**
 * Auth context (injected by auth-middleware into req.tenant).
 *
 * - PRO tier: both tenant and apiKey are present.
 * - FREE tier anonymous: both are null (rate-limited by IP / usage aggregated by tenant_id IS NULL).
 */
export interface AuthContext {
    tier: Tier;
    tenant: TenantRecord | null;
    apiKey: ApiKeyRecord | null;
    /** Client IP (FREE tier rate-limit key; extracted from req.ip / X-Forwarded-For). */
    clientIp: string;
}

/** Express Request extension (attached state). */
export interface AuthenticatedRequest extends Request {
    auth?: AuthContext;
}

/** auth-middleware error codes (introduces no new wire format; HTTP layer only). */
export type AuthErrorCode =
    | 'INVALID_API_KEY'
    | 'API_KEY_REVOKED'
    | 'API_KEY_EXPIRED'
    | 'TENANT_SUSPENDED';

/** Rate-limit quota. */
export interface RateLimitQuota {
    /** Time window (milliseconds). */
    windowMs: number;
    /** Maximum number of requests within the window. */
    max: number;
}
