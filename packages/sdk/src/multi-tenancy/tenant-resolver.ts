/**
 * TenantResolver implementation
 *
 * Responsibilities:
 *   - createDefaultTenantResolver: supports three sources — HTTP header / API key / JWT claim
 *   - validateTenantContext: runtime validation (brand cast forbidden)
 *   - tenantContextMiddleware: Express middleware; missing TenantContext -> 401 fail-closed
 *
 * Design constraints (fail-closed):
 *   - cannot resolve tenantId -> fail-closed (TenantNotFoundError; never fall back to a default tenant)
 *   - empty tenantId / invalid format -> TenantUnauthorizedError (fail-closed)
 *   - JWT: only the claim is parsed; no signature verification is done at this layer (verification is the upper-layer SSO's responsibility)
 *   - Express middleware: missing TenantContext -> 401 JSON response (does not call next())
 *
 */

import type { DID, Timestamp } from '@coivitas/types';
import type {
    TenantContext,
    TenantResolver,
    TenantResolverRequest,
} from './types.js';
import {
    TenantId,
    makeTenantId,
    TenantNotFoundError,
    TenantUnauthorizedError,
    TenantContextMissingError,
} from './types.js';

// ── Constants ─────────────────────────────────────────────────────────────────

/** HTTP header: tenantId passed in directly (trusted source; internal systems only) */
const HEADER_TENANT_ID = 'x-tenant-id';

/** HTTP header: Authorization Bearer JWT (the tenant claim is parsed from the payload) */
const HEADER_AUTHORIZATION = 'authorization';

/** HTTP header: API key (e.g. `tenantId.secretKey` or a custom mapping) */
const HEADER_API_KEY = 'x-api-key';

/** JWT payload claim field names */
const JWT_CLAIM_TENANT_ID = 'tenant_id';
const JWT_CLAIM_SUB = 'sub';

// ── DefaultTenantResolverOptions ──────────────────────────────────────────────

/**
 * Options for createDefaultTenantResolver
 */
export interface DefaultTenantResolverOptions {
    /**
     * API key -> TenantId mapping table (for production use; key = API key prefix or full value)
     *
     * Conclusion: stores only the tenantId mapping; does not store the API key in cleartext (the caller is responsible for secure storage).
     * Test environments may use an in-memory map; production should load it from a secrets manager.
     */
    readonly apiKeyTenantMap?: Map<string, TenantId>;

    /**
     * List of trusted sources (controls which sources may serve as the authoritative source of the tenantId)
     *
     * Default priority (high -> low):
     *   1. 'header' (X-Tenant-Id; trusts internal systems)
     *   2. 'jwt' (Authorization Bearer JWT payload.tenant_id)
     *   3. 'api-key' (X-Api-Key mapping)
     *
     * Note: the 'header' source is the most trusted and should be used only for internal microservices (requests routed through a gateway).
     */
    readonly trustedSources?: Array<'header' | 'jwt' | 'api-key'>;

    /**
     * Set of allowed tenantIds (allowlist; undefined = no restriction)
     *
     * If an allowlist is set, an unknown tenantId -> TenantNotFoundError (fail-closed).
     * Setting an allowlist is recommended in production (load known tenants from the DB).
     */
    readonly allowedTenantIds?: ReadonlySet<TenantId>;

    /**
     * Whether to extract actorDid from the JWT sub claim (default true)
     */
    readonly extractActorDidFromJwt?: boolean;
}

// ── createDefaultTenantResolver ───────────────────────────────────────────────

/**
 * Create the default TenantResolver (supports the header / jwt / api-key sources)
 *
 * Conclusion: production-grade TenantResolver implementation; tries each source by priority;
 * if all fail -> TenantNotFoundError (fail-closed).
 *
 * Example:
 *   ```ts
 *   const resolver = createDefaultTenantResolver({
 *     apiKeyTenantMap: new Map([['sk_prod_xxxx', makeTenantId('acme-corp')]]),
 *     allowedTenantIds: new Set([makeTenantId('acme-corp'), makeTenantId('beta-inc')]),
 *   });
 *   ```
 */
export function createDefaultTenantResolver(
    options: DefaultTenantResolverOptions = {},
): TenantResolver {
    const {
        apiKeyTenantMap,
        trustedSources = ['header', 'jwt', 'api-key'],
        allowedTenantIds,
        extractActorDidFromJwt = true,
    } = options;

    return (request: TenantResolverRequest): Promise<TenantContext> => {
        try {
            let resolvedTenantId: TenantId | undefined;
            let resolvedActorDid: DID | undefined;

            // Try each source by priority
            for (const source of trustedSources) {
                if (source === 'header') {
                    const result = tryResolveFromHeader(request);
                    if (result) {
                        resolvedTenantId = result.tenantId;
                        break;
                    }
                } else if (source === 'jwt') {
                    const result = tryResolveFromJwt(request, extractActorDidFromJwt);
                    if (result) {
                        resolvedTenantId = result.tenantId;
                        resolvedActorDid = result.actorDid;
                        break;
                    }
                } else if (source === 'api-key') {
                    const result = tryResolveFromApiKey(request, apiKeyTenantMap);
                    if (result) {
                        resolvedTenantId = result.tenantId;
                        break;
                    }
                }
            }

            // tenantId passed in directly (highest trust; internal calls)
            if (!resolvedTenantId && request.tenantId !== undefined) {
                resolvedTenantId = makeTenantId(request.tenantId);
            }

            // No source resolved a tenantId -> fail-closed
            if (resolvedTenantId === undefined) {
                return Promise.reject(new TenantNotFoundError(
                    'Unable to resolve tenantId from request. ' +
                    'Expected one of: X-Tenant-Id header, Authorization Bearer JWT with tenant_id claim, ' +
                    'or X-Api-Key with registered tenant mapping. ' +
                    'Ensure the request includes a valid tenant identifier.',
                ));
            }

            // Allowlist check (if an allowed list was set)
            if (allowedTenantIds !== undefined && !allowedTenantIds.has(resolvedTenantId)) {
                return Promise.reject(new TenantNotFoundError(
                    `TenantId "${resolvedTenantId}" is not in the allowed tenant list.`,
                    resolvedTenantId,
                ));
            }

            return Promise.resolve({
                tenantId: resolvedTenantId,
                actorDid: resolvedActorDid,
                createdAt: new Date().toISOString() as Timestamp,
            });
        } catch (err) {
            return Promise.reject(err as Error);
        }
    };
}

// ── Internal resolution helpers ───────────────────────────────────────────────

/**
 * Resolve the tenantId from the X-Tenant-Id header
 */
function tryResolveFromHeader(
    request: TenantResolverRequest,
): { tenantId: TenantId } | undefined {
    const headers = request.headers;
    if (!headers) return undefined;

    const raw = getHeaderValue(headers, HEADER_TENANT_ID);
    if (!raw) return undefined;

    return { tenantId: makeTenantId(raw) };
}

/**
 * Resolve the tenant_id claim + sub (actorDid) from the Authorization Bearer JWT
 *
 * Note: this function only parses the JWT payload (base64url decode); it does not verify the signature.
 * JWT signature verification is the responsibility of the upper-layer SSO stage (SAML/OIDC);
 * this layer only extracts the tenant_id claim for request routing.
 */
function tryResolveFromJwt(
    request: TenantResolverRequest,
    extractActorDid: boolean,
): { tenantId: TenantId; actorDid?: DID } | undefined {
    const jwtToken = extractBearerToken(request);
    if (!jwtToken) return undefined;

    const payload = decodeJwtPayload(jwtToken);
    if (!payload) return undefined;

    const rawTenantId = payload[JWT_CLAIM_TENANT_ID];
    if (typeof rawTenantId !== 'string' || !rawTenantId) return undefined;

    const tenantId = makeTenantId(rawTenantId);

    let actorDid: DID | undefined;
    if (extractActorDid) {
        const sub = payload[JWT_CLAIM_SUB];
        if (typeof sub === 'string' && sub.startsWith('did:')) {
            actorDid = sub as DID;
        }
    }

    return { tenantId, actorDid };
}

/**
 * Resolve the tenantId from the X-Api-Key header (via the mapping table)
 */
function tryResolveFromApiKey(
    request: TenantResolverRequest,
    apiKeyTenantMap: Map<string, TenantId> | undefined,
): { tenantId: TenantId } | undefined {
    if (!apiKeyTenantMap || apiKeyTenantMap.size === 0) return undefined;

    const apiKey = request.apiKey ?? (
        request.headers ? getHeaderValue(request.headers, HEADER_API_KEY) : undefined
    );
    if (!apiKey) return undefined;

    const tenantId = apiKeyTenantMap.get(apiKey);
    if (!tenantId) return undefined;

    return { tenantId };
}

/**
 * Extract the Bearer token from the headers or request.jwtToken
 */
function extractBearerToken(request: TenantResolverRequest): string | undefined {
    if (request.jwtToken) return request.jwtToken;

    const headers = request.headers;
    if (!headers) return undefined;

    const authHeader = getHeaderValue(headers, HEADER_AUTHORIZATION);
    if (!authHeader) return undefined;

    const match = /^[Bb]earer\s+(.+)$/.exec(authHeader);
    return match ? match[1] : undefined;
}

/**
 * Decode the JWT payload (base64url decode only; no signature verification)
 */
function decodeJwtPayload(token: string): Record<string, unknown> | undefined {
    const parts = token.split('.');
    if (parts.length !== 3) return undefined;

    try {
        // parts.length === 3 confirmed above; index 1 is always defined
        const payloadB64 = (parts[1] as string).replace(/-/g, '+').replace(/_/g, '/');
        const padded = payloadB64 + '='.repeat((4 - (payloadB64.length % 4)) % 4);
        const decoded = Buffer.from(padded, 'base64').toString('utf8');
        const parsed: unknown = JSON.parse(decoded);
        if (typeof parsed === 'object' && parsed !== null) {
            return parsed as Record<string, unknown>;
        }
        return undefined;
    } catch {
        return undefined;
    }
}

/**
 * Get a header value from the headers (case-insensitive)
 */
function getHeaderValue(
    headers: Record<string, string | string[] | undefined>,
    name: string,
): string | undefined {
    const lower = name.toLowerCase();
    for (const [key, value] of Object.entries(headers)) {
        if (key.toLowerCase() === lower) {
            if (Array.isArray(value)) return value[0];
            return value;
        }
    }
    return undefined;
}

// ── validateTenantContext ─────────────────────────────────────────────────────

/**
 * validateTenantContext: runtime validation (brand cast forbidden)
 *
 * Conclusion: call this at the entry of every tenant-scoped operation;
 * TenantContext missing / empty tenantId -> fail-closed (throw the corresponding TenantError).
 *
 * @param ctx the TenantContext to validate (undefined is allowed; undefined -> TenantContextMissingError)
 * @param operationName operation name (used in the error message)
 * @throws TenantContextMissingError if ctx is undefined
 * @throws TenantUnauthorizedError if ctx.tenantId is empty
 */
export function validateTenantContext(
    ctx: TenantContext | undefined,
    operationName: string,
): asserts ctx is TenantContext {
    if (ctx === undefined || ctx === null) {
        throw new TenantContextMissingError(operationName);
    }
    if (!ctx.tenantId || typeof ctx.tenantId !== 'string' || ctx.tenantId.length === 0) {
        throw new TenantUnauthorizedError(
            `TenantContext.tenantId is empty for operation "${operationName}". ` +
            'TenantContext must contain a valid non-empty tenantId.',
            'TENANT_UNAUTHORIZED',
        );
    }
}

// ── tenantContextMiddleware ───────────────────────────────────────────────────

/**
 * Express middleware: resolve the TenantContext from the request and inject it into res.locals
 *
 * Conclusion: every tenant-scoped route must pass through this middleware first;
 * missing TenantContext -> 401 JSON response (fail-closed; does not call next()).
 *
 * Example:
 *   ```ts
 *   app.use('/api/tenant', tenantContextMiddleware(resolver));
 *   app.get('/api/tenant/resource', (req, res) => {
 *     const ctx = getTenantContextFromLocals(res);
 *     // ctx is already validated as non-undefined
 *   });
 *   ```
 */
export function tenantContextMiddleware(resolver: TenantResolver): ExpressMiddleware {
    return async (req: ExpressRequest, res: ExpressResponse, next: ExpressNextFunction): Promise<void> => {
        try {
            const tenantResolverRequest: TenantResolverRequest = {
                headers: req.headers,
                apiKey: undefined,
                jwtToken: undefined,
                tenantId: undefined,
            };

            const tenantContext = await resolver(tenantResolverRequest);
            res.locals['tenantContext'] = tenantContext;
            next();
        } catch (err) {
            if (err instanceof TenantNotFoundError) {
                res.status(401).json({
                    error: 'TENANT_NOT_FOUND',
                    message: 'Unable to identify tenant from request. ' +
                        'Provide a valid X-Tenant-Id header, Authorization Bearer JWT, or X-Api-Key.',
                });
                return;
            }
            if (err instanceof TenantUnauthorizedError) {
                res.status(403).json({
                    error: err.code,
                    message: err.message,
                });
                return;
            }
            // Unknown error -> fail-closed 500
            res.status(500).json({
                error: 'TENANT_UNKNOWN',
                message: 'Internal error during tenant resolution. Request aborted.',
            });
        }
    };
}

/**
 * Extract the TenantContext from Express res.locals (type-safe)
 *
 * @throws TenantContextMissingError if there is no tenantContext in locals
 */
export function getTenantContextFromLocals(
    res: { locals: Record<string, unknown> },
    operationName = 'unknown',
): TenantContext {
    // unknown → TenantContext; validateTenantContext handles missing/null via fail-closed
    const raw: unknown = res.locals['tenantContext'];
    const ctx = raw as TenantContext;
    validateTenantContext(ctx, operationName);
    return ctx;
}

// ── Minimal Express type declarations (avoids depending on @types/express) ────

interface ExpressRequest {
    readonly headers: Record<string, string | string[] | undefined>;
}

interface ExpressResponse {
    status(code: number): ExpressResponse;
    json(body: unknown): ExpressResponse;
    locals: Record<string, unknown>;
}

type ExpressNextFunction = (err?: unknown) => void;

type ExpressMiddleware = (
    req: ExpressRequest,
    res: ExpressResponse,
    next: ExpressNextFunction,
) => Promise<void> | void;
