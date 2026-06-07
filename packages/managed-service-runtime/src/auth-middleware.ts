/**
 * Auth middleware: parse `Authorization: Bearer <key>` -> SHA-256 hash -> DB lookup.
 *
 * Design notes (conclusion first, details after):
 * 1. fail-closed: any lookup failure / status other than ACTIVE / expiry -> 401,
 *    no silent downgrade to the FREE tier (prevents a leaked PRO key from abusing the free quota).
 * 2. Missing Authorization header -> FREE tier anonymous access (rate-limited by IP; rate-limiter takes over).
 * 3. SHA-256 via @noble/hashes (an existing project dependency; no crypto polyfill introduced);
 *    the key is only hashed and compared in memory, never logged (prevents accidentally dumping the plaintext key to stdout).
 * 4. last_used_at is updated asynchronously (fire-and-forget): unblocks the request hot path;
 *    an update failure only triggers console.warn and does not block the request (auth already passed).
 * 5. expires_at is compared at the app layer (the DB does not enforce expiry via a trigger); together with
 *    the rate-limiter's periodic sweep, ACTIVE -> EXPIRED. This passive-expire mode is consistent with envelope-ledger.
 *
 */

import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '@noble/hashes/utils';
import type { Response, NextFunction } from 'express';

import type { DatabasePool } from '@coivitas/shared';

import type {
    ApiKeyRecord,
    AuthContext,
    AuthenticatedRequest,
    AuthErrorCode,
    TenantRecord,
} from './types.js';

/** auth-middleware configuration */
export interface AuthMiddlewareConfig {
    pool: DatabasePool;
    /** Inject a clock to make expiry checks testable; defaults to => new Date() */
    now?: () => Date;
    /** Callback invoked when the last_used_at update fails; defaults to console.warn */
    onUpdateError?: (error: unknown) => void;
}

/**
 * Create the auth-middleware.
 *
 * Behavior matrix:
 * | Authorization header | Result |
 * | --------------------------- | --------------------------------------- |
 * | Missing / non-Bearer | req.auth = FREE tier anonymous (continue) |
 * | Bearer + valid key + ACTIVE | req.auth = PRO tier + tenant + apiKey |
 * | Bearer + unknown key | 401 INVALID_API_KEY |
 * | Bearer + REVOKED key | 401 API_KEY_REVOKED |
 * | Bearer + expired key | 401 API_KEY_EXPIRED |
 * | Bearer + tenant SUSPENDED | 401 TENANT_SUSPENDED |
 */
export function createAuthMiddleware(config: AuthMiddlewareConfig) {
    const { pool } = config;
    const now = config.now ?? (() => new Date());
    const onUpdateError =
        config.onUpdateError ??
        ((error: unknown) =>
            console.warn(
                '[auth-middleware] last_used_at update failed:',
                error,
            ));

    return async function authMiddleware(
        req: AuthenticatedRequest,
        res: Response,
        next: NextFunction,
    ): Promise<void> {
        const clientIp = extractClientIp(req);

        // 1. Parse the Authorization header
        const headerValue = req.header('authorization');
        const bearerToken = parseBearerToken(headerValue);

        if (!bearerToken) {
            // No token -> FREE tier anonymous (rate-limiter takes over IP-based limiting)
            req.auth = buildAnonymousContext(clientIp);
            next();
            return;
        }

        // 2. SHA-256 hash, then query the DB
        const keyHash = computeKeyHash(bearerToken);
        const lookup = await lookupApiKey(pool, keyHash);

        if (!lookup) {
            sendAuthError(res, 'INVALID_API_KEY', 'API key not recognized.');
            return;
        }

        const { apiKey, tenant } = lookup;

        // 3. Status validation (fail-closed order: apiKey REVOKED -> apiKey expired -> tenant SUSPENDED)
        if (apiKey.status === 'REVOKED') {
            sendAuthError(res, 'API_KEY_REVOKED', 'API key has been revoked.');
            return;
        }

        if (apiKey.status === 'EXPIRED' || isExpired(apiKey, now())) {
            sendAuthError(res, 'API_KEY_EXPIRED', 'API key has expired.');
            return;
        }

        if (tenant.status === 'SUSPENDED' || tenant.status === 'DELETED') {
            sendAuthError(
                res,
                'TENANT_SUSPENDED',
                `Tenant is ${tenant.status.toLowerCase()}.`,
            );
            return;
        }

        // 4. Inject the auth context
        req.auth = {
            tier: tenant.tier,
            tenant,
            apiKey,
            clientIp,
        };

        // 5. Update last_used_at asynchronously (fire-and-forget; does not block the hot path)
        void touchLastUsed(pool, apiKey.id, now()).catch(onUpdateError);

        next();
    };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Compute the SHA-256 hex hash of an API key (lowercase, 64 characters).
 * Exported for use by admin tooling and tests.
 */
export function computeKeyHash(rawKey: string): string {
    const bytes = sha256(new TextEncoder().encode(rawKey));
    return bytesToHex(bytes);
}

function parseBearerToken(headerValue: string | undefined): string | null {
    if (!headerValue) {
        return null;
    }
    const trimmed = headerValue.trim();
    const match = /^Bearer\s+(.+)$/i.exec(trimmed);
    if (!match) {
        return null;
    }
    const token = match[1]?.trim() ?? '';
    return token.length > 0 ? token : null;
}

function extractClientIp(req: AuthenticatedRequest): string {
    // Express req.ip is taken from the socket by default; when trust proxy is enabled it is parsed from X-Forwarded-For.
    // We do not parse X-Forwarded-For ourselves to prevent spoofing (the deployment should configure trust proxy).
    return req.ip ?? req.socket.remoteAddress ?? 'unknown';
}

function buildAnonymousContext(clientIp: string): AuthContext {
    return {
        tier: 'FREE',
        tenant: null,
        apiKey: null,
        clientIp,
    };
}

interface LookupRow {
    api_key_id: string;
    api_key_tenant_id: string;
    api_key_key_hash: string;
    api_key_key_prefix: string;
    api_key_description: string | null;
    api_key_expires_at: Date | null;
    api_key_last_used_at: Date | null;
    api_key_status: 'ACTIVE' | 'REVOKED' | 'EXPIRED';
    tenant_id: string;
    tenant_tenant_did: string;
    tenant_tier: 'FREE' | 'PRO';
    tenant_display_name: string;
    tenant_contact_email: string | null;
    tenant_status: 'ACTIVE' | 'SUSPENDED' | 'DELETED';
}

async function lookupApiKey(
    pool: DatabasePool,
    keyHash: string,
): Promise<{ apiKey: ApiKeyRecord; tenant: TenantRecord } | null> {
    const result = await pool.query<LookupRow>(
        `
        SELECT
            ak.id              AS api_key_id,
            ak.tenant_id       AS api_key_tenant_id,
            ak.key_hash        AS api_key_key_hash,
            ak.key_prefix      AS api_key_key_prefix,
            ak.description     AS api_key_description,
            ak.expires_at      AS api_key_expires_at,
            ak.last_used_at    AS api_key_last_used_at,
            ak.status          AS api_key_status,
            t.id               AS tenant_id,
            t.tenant_did       AS tenant_tenant_did,
            t.tier             AS tenant_tier,
            t.display_name     AS tenant_display_name,
            t.contact_email    AS tenant_contact_email,
            t.status           AS tenant_status
        FROM managed_service.api_keys ak
        JOIN managed_service.tenants t ON t.id = ak.tenant_id
        WHERE ak.key_hash = $1
        LIMIT 1
        `,
        [keyHash],
    );

    const row = result.rows[0];
    if (!row) {
        return null;
    }

    const apiKey: ApiKeyRecord = {
        id: row.api_key_id,
        tenantId: row.api_key_tenant_id,
        keyHash: row.api_key_key_hash,
        keyPrefix: row.api_key_key_prefix,
        description: row.api_key_description,
        expiresAt: row.api_key_expires_at,
        lastUsedAt: row.api_key_last_used_at,
        status: row.api_key_status,
    };

    const tenant: TenantRecord = {
        id: row.tenant_id,
        tenantDid: row.tenant_tenant_did,
        tier: row.tenant_tier,
        displayName: row.tenant_display_name,
        contactEmail: row.tenant_contact_email,
        status: row.tenant_status,
    };

    return { apiKey, tenant };
}

function isExpired(apiKey: ApiKeyRecord, now: Date): boolean {
    if (apiKey.expiresAt === null) {
        return false;
    }
    return apiKey.expiresAt.getTime() <= now.getTime();
}

async function touchLastUsed(
    pool: DatabasePool,
    apiKeyId: string,
    now: Date,
): Promise<void> {
    await pool.query(
        `UPDATE managed_service.api_keys SET last_used_at = $1 WHERE id = $2`,
        [now, apiKeyId],
    );
}

function sendAuthError(
    res: Response,
    code: AuthErrorCode,
    message: string,
): void {
    res.status(401).json({
        error: { code, message },
    });
}
