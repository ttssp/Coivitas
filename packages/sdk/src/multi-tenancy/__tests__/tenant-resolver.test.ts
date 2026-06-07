/**
 * TenantResolver + validateTenantContext + tenantContextMiddleware tests
 *
 * Coverage:
 *   - HTTP header resolution (X-Tenant-Id)
 *   - API key mapping resolution (X-Api-Key)
 *   - JWT claim resolution (Authorization Bearer)
 *   - missing tenantId -> TenantNotFoundError (fail-closed)
 *   - malformed tenantId -> TenantUnauthorizedError (fail-closed)
 *   - middleware reject when no TenantContext (401 response)
 *   - validateTenantContext (runtime validation; brand cast forbidden)
 *   - abnormal tenantId (empty / too long / invalid characters)
 *   - middleware 500 unknown error -> fail-closed
 *   - isolation-invariant grep test (tenant-resolver.ts has no globalRateLimit / defaultTenant / untenanted)
 *
 */

import { describe, it, expect, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { resolve, dirname } from 'node:path';
import {
    createDefaultTenantResolver,
    validateTenantContext,
    tenantContextMiddleware,
} from '../tenant-resolver.js';
import {
    makeTenantId,
    TenantNotFoundError,
    TenantUnauthorizedError,
    TenantContextMissingError,
} from '../types.js';
import type { TenantId, TenantResolver } from '../types.js';
import type { Timestamp } from '@coivitas/types';

// ── isolation-invariant grep test helpers ────────────────────────────────────

const __dirname = dirname(fileURLToPath(import.meta.url));

/**
 * Filter out comment lines (starting with * or //); avoids misclassifying documentation prose as a code violation.
 */
function nonCommentLines(src: string): string {
    return src
        .split('\n')
        .filter(line => {
            const trimmed = line.trim();
            return !trimmed.startsWith('*') && !trimmed.startsWith('//');
        })
        .join('\n');
}

// Local Express types (structurally compatible with the internal declarations in tenant-resolver.ts; tests only)
type ReqLike = { readonly headers?: Record<string, string | string[] | undefined>; apiKey?: string; jwtToken?: string };
type ResLike = { locals: Record<string, unknown>; status(c: number): ResLike; json(b: unknown): ResLike };
type NextLike = (err?: unknown) => void;

// ── Helper: generate a JWT (unsigned; tests only) ─────────────────────────────

function makeJwt(payload: Record<string, unknown>): string {
    const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
    const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
    return `${header}.${body}.`;
}

// ── Helper: mock Express res ──────────────────────────────────────────────────

function makeMockRes(): ResLike & { getStatusCode(): number; getResponseBody(): unknown } {
    const locals: Record<string, unknown> = {};
    let statusCode = 200;
    let responseBody: unknown;
    const res = {
        locals,
        status(code: number) {
            statusCode = code;
            return res;
        },
        json(body: unknown) {
            responseBody = body;
            return res;
        },
        getStatusCode: () => statusCode,
        getResponseBody: () => responseBody,
    };
    return res;
}

// ── HTTP header resolution ────────────────────────────────────────────────────

describe('createDefaultTenantResolver — HTTP header source', () => {
    it('should resolve tenantId from X-Tenant-Id header', async () => {
        const resolver = createDefaultTenantResolver({ trustedSources: ['header'] });
        const ctx = await resolver({ headers: { 'x-tenant-id': 'acme-corp' } });
        expect(ctx.tenantId).toBe('acme-corp');
    });

    it('should resolve tenantId case-insensitively from header', async () => {
        const resolver = createDefaultTenantResolver({ trustedSources: ['header'] });
        const ctx = await resolver({ headers: { 'X-Tenant-Id': 'beta-inc' } });
        expect(ctx.tenantId).toBe('beta-inc');
    });
});

// ── API key resolution ───────────────────────────────────────────────────────

describe('createDefaultTenantResolver — API key source', () => {
    it('should resolve tenantId from X-Api-Key header via mapping', async () => {
        const apiKeyTenantMap = new Map<string, TenantId>([
            ['sk_prod_abc123', makeTenantId('acme-corp')],
        ]);
        const resolver = createDefaultTenantResolver({
            trustedSources: ['api-key'],
            apiKeyTenantMap,
        });
        const ctx = await resolver({ headers: { 'x-api-key': 'sk_prod_abc123' } });
        expect(ctx.tenantId).toBe('acme-corp');
    });

    it('should resolve tenantId from request.apiKey field', async () => {
        const apiKeyTenantMap = new Map<string, TenantId>([
            ['sk_test_xyz', makeTenantId('test-tenant')],
        ]);
        const resolver = createDefaultTenantResolver({
            trustedSources: ['api-key'],
            apiKeyTenantMap,
        });
        const ctx = await resolver({ apiKey: 'sk_test_xyz' });
        expect(ctx.tenantId).toBe('test-tenant');
    });
});

// ── JWT claim resolution ──────────────────────────────────────────────────────

describe('createDefaultTenantResolver — JWT claim source', () => {
    it('should resolve tenantId from Authorization Bearer JWT tenant_id claim', async () => {
        const jwt = makeJwt({ tenant_id: 'jwt-tenant', sub: 'did:example:alice' });
        const resolver = createDefaultTenantResolver({ trustedSources: ['jwt'] });
        const ctx = await resolver({ headers: { authorization: `Bearer ${jwt}` } });
        expect(ctx.tenantId).toBe('jwt-tenant');
    });

    it('should extract actorDid from JWT sub claim when it is a DID', async () => {
        const jwt = makeJwt({ tenant_id: 'jwt-tenant', sub: 'did:example:alice' });
        const resolver = createDefaultTenantResolver({
            trustedSources: ['jwt'],
            extractActorDidFromJwt: true,
        });
        const ctx = await resolver({ headers: { authorization: `Bearer ${jwt}` } });
        expect(ctx.actorDid).toBe('did:example:alice');
    });

    it('should resolve from request.jwtToken field directly', async () => {
        const jwt = makeJwt({ tenant_id: 'direct-jwt-tenant' });
        const resolver = createDefaultTenantResolver({ trustedSources: ['jwt'] });
        const ctx = await resolver({ jwtToken: jwt });
        expect(ctx.tenantId).toBe('direct-jwt-tenant');
    });
});

// ── missing tenantId -> fail-closed ──────────────────────────────────────────

describe('createDefaultTenantResolver — missing tenantId', () => {
    it('should throw TenantNotFoundError when no source provides tenantId', async () => {
        const resolver = createDefaultTenantResolver({
            trustedSources: ['header', 'jwt', 'api-key'],
        });
        await expect(resolver({})).rejects.toThrowError(TenantNotFoundError);
    });

    it('should throw TenantNotFoundError when headers are empty', async () => {
        const resolver = createDefaultTenantResolver({ trustedSources: ['header'] });
        await expect(resolver({ headers: {} })).rejects.toThrowError(TenantNotFoundError);
    });

    it('should throw TenantNotFoundError when tenantId not in allowedTenantIds whitelist', async () => {
        const allowedTenantIds = new Set<TenantId>([makeTenantId('allowed-tenant')]);
        const resolver = createDefaultTenantResolver({
            trustedSources: ['header'],
            allowedTenantIds,
        });
        await expect(
            resolver({ headers: { 'x-tenant-id': 'unknown-tenant' } }),
        ).rejects.toThrowError(TenantNotFoundError);
    });
});

// ── malformed tenantId -> fail-closed ────────────────────────────────────────

describe('createDefaultTenantResolver — malformed tenantId', () => {
    it('should throw TenantUnauthorizedError when tenantId in header has invalid characters', async () => {
        const resolver = createDefaultTenantResolver({ trustedSources: ['header'] });
        await expect(
            resolver({ headers: { 'x-tenant-id': 'invalid tenant@id!' } }),
        ).rejects.toThrowError(TenantUnauthorizedError);
    });

    it('should throw TenantUnauthorizedError when tenantId exceeds 128 chars', async () => {
        const resolver = createDefaultTenantResolver({ trustedSources: ['header'] });
        await expect(
            resolver({ headers: { 'x-tenant-id': 'a'.repeat(129) } }),
        ).rejects.toThrowError(TenantUnauthorizedError);
    });
});

// ── validateTenantContext ─────────────────────────────────────────────────────

describe('validateTenantContext — runtime validation', () => {
    it('should not throw when TenantContext is valid', () => {
        const ctx = {
            tenantId: makeTenantId('valid-tenant'),
            createdAt: new Date().toISOString() as Timestamp,
        };
        expect(() => validateTenantContext(ctx, 'my-op')).not.toThrow();
    });

    it('should throw TenantContextMissingError when ctx is undefined', () => {
        expect(() => validateTenantContext(undefined, 'my-op')).toThrowError(
            TenantContextMissingError,
        );
    });

    it('should throw TenantContextMissingError when ctx is null', () => {
        expect(() => validateTenantContext(null as unknown as undefined, 'my-op')).toThrowError(
            TenantContextMissingError,
        );
    });

    it('should throw TenantUnauthorizedError when ctx.tenantId is empty', () => {
        const ctx = {
            tenantId: '' as TenantId,
            createdAt: new Date().toISOString() as Timestamp,
        };
        expect(() => validateTenantContext(ctx, 'my-op')).toThrowError(TenantUnauthorizedError);
    });
});

// ── tenantContextMiddleware ───────────────────────────────────────────────────

describe('tenantContextMiddleware — should reject when TenantContext cannot be resolved', () => {
    it('should call next() with TenantContext in res.locals when resolution succeeds', async () => {
        const resolver = createDefaultTenantResolver({ trustedSources: ['header'] });
        const middleware = tenantContextMiddleware(resolver);

        const req: ReqLike = { headers: { 'x-tenant-id': 'acme-corp' } };
        const res = makeMockRes();
        const next: NextLike = vi.fn();

        await middleware(req as Parameters<typeof middleware>[0], res as Parameters<typeof middleware>[1], next);

        expect(next).toHaveBeenCalledOnce();
        expect(res.locals['tenantContext']).toBeDefined();
        const ctx = res.locals['tenantContext'] as { tenantId: string };
        expect(ctx.tenantId).toBe('acme-corp');
    });

    it('should return 401 when tenantId cannot be resolved (TenantNotFoundError)', async () => {
        const resolver = createDefaultTenantResolver({ trustedSources: ['header'] });
        const middleware = tenantContextMiddleware(resolver);

        const req: ReqLike = { headers: {} };
        const res = makeMockRes();
        const next: NextLike = vi.fn();

        await middleware(req as Parameters<typeof middleware>[0], res as Parameters<typeof middleware>[1], next);

        expect(next).not.toHaveBeenCalled();
        expect(res.getStatusCode()).toBe(401);
        const body = res.getResponseBody() as { error: string };
        expect(body.error).toBe('TENANT_NOT_FOUND');
    });

    it('should return 403 when tenantId is unauthorized (TenantUnauthorizedError)', async () => {
        const resolver = createDefaultTenantResolver({ trustedSources: ['header'] });
        const middleware = tenantContextMiddleware(resolver);

        const req: ReqLike = { headers: { 'x-tenant-id': 'invalid tenant@!' } };
        const res = makeMockRes();
        const next: NextLike = vi.fn();

        await middleware(req as Parameters<typeof middleware>[0], res as Parameters<typeof middleware>[1], next);

        expect(next).not.toHaveBeenCalled();
        expect(res.getStatusCode()).toBe(403);
    });

    it('should return 500 when resolver throws an unknown non-Tenant error (fail-closed)', async () => {
        // Covers the tenantContextMiddleware 500 unknown-error branch:
        // the resolver throws a plain Error that is not TenantNotFoundError / TenantUnauthorizedError
        const failingResolver: TenantResolver = () => Promise.reject(new Error('unexpected internal failure'));
        const middleware = tenantContextMiddleware(failingResolver);

        const req: ReqLike = { headers: {} };
        const res = makeMockRes();
        const next: NextLike = vi.fn();

        await middleware(req as Parameters<typeof middleware>[0], res as Parameters<typeof middleware>[1], next);

        expect(next).not.toHaveBeenCalled();
        expect(res.getStatusCode()).toBe(500);
        const body = res.getResponseBody() as { error: string; message: string };
        expect(body.error).toBe('TENANT_UNKNOWN');
        expect(body.message).toContain('Internal error');
    });
});

// ── isolation-invariant grep test ────────────────────────────────────────────

/**
 * Isolation-invariant grep: verifies that the non-comment code lines of tenant-resolver.ts
 * contain none of the single-tenant fallback anti-patterns globalRateLimit / defaultTenant / untenanted.
 *
 * This grep test is extended to tenant-resolver.ts (rate-limiter.test.ts only covers
 * rate-limiter.ts + types.ts; tenant-resolver.ts was not covered before).
 */
describe('tenant isolation invariant grep test — tenant-resolver.ts must not contain forbidden patterns', () => {
    it('should not contain globalRateLimit / defaultTenant / untenanted in non-comment code of tenant-resolver.ts', () => {
        const srcPath = resolve(__dirname, '../tenant-resolver.ts');
        const code = nonCommentLines(readFileSync(srcPath, 'utf-8'));

        expect(code).not.toMatch(/globalRateLimit/);
        expect(code).not.toMatch(/defaultTenant/);
        expect(code).not.toMatch(/untenanted/);
    });

    it('should not contain globalTenant / defaultTenantContext / noTenantFallback camelCase variants in tenant-resolver.ts', () => {
        const srcPath = resolve(__dirname, '../tenant-resolver.ts');
        const code = nonCommentLines(readFileSync(srcPath, 'utf-8'));

        expect(code).not.toMatch(/globalTenant/);
        expect(code).not.toMatch(/defaultTenantContext/);
        expect(code).not.toMatch(/noTenantFallback/);
    });
});
