/**
 * auth-middleware.test.ts
 *
 * Test target: auth-middleware (packages/managed-service-runtime/src/auth-middleware.ts)
 *
 * Coverage strategy:
 * - Unit tests (mock DB Pool): cover 8 path categories
 *   1. missing Authorization -> FREE tier anonymous
 *   2. non-Bearer scheme -> FREE tier anonymous
 *   3. valid PRO key -> inject tenant + apiKey
 *   4. nonexistent key -> 401 INVALID_API_KEY
 *   5. status=REVOKED -> 401 API_KEY_REVOKED
 *   6. status=EXPIRED -> 401 API_KEY_EXPIRED
 *   7. expires_at past -> 401 API_KEY_EXPIRED
 *   8. tenant SUSPENDED -> 401 TENANT_SUSPENDED
 *   9. last_used_at async update failure callback
 */

import { describe, expect, it, vi, beforeEach } from 'vitest';

import {
    computeKeyHash,
    createAuthMiddleware,
} from '../auth-middleware.js';
import type { AuthenticatedRequest } from '../types.js';

import type { Response, NextFunction } from 'express';
import type { DatabasePool } from '@coivitas/shared';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeRes(): Response & {
    statusCode: number;
    body: unknown;
} {
    let statusCode = 200;
    let body: unknown = null;
    const res = {
        statusCode,
        body,
        status(code: number) {
            statusCode = code;
            (res as unknown as { statusCode: number }).statusCode = code;
            return res;
        },
        json(payload: unknown) {
            body = payload;
            (res as unknown as { body: unknown }).body = payload;
            return res;
        },
    } as unknown as Response & { statusCode: number; body: unknown };
    return res;
}

function makeReq(headers: Record<string, string | undefined> = {}, ip = '1.2.3.4'): AuthenticatedRequest {
    return {
        ip,
        socket: { remoteAddress: ip } as unknown,
        header(name: string) {
            return headers[name.toLowerCase()];
        },
    } as unknown as AuthenticatedRequest;
}

interface QueryRow {
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

function makeRow(overrides: Partial<QueryRow> = {}): QueryRow {
    return {
        api_key_id: 'key-uuid-1',
        api_key_tenant_id: 'tenant-uuid-1',
        api_key_key_hash: computeKeyHash('test-key-123'),
        api_key_key_prefix: 'ap_test_',
        api_key_description: 'unit test key',
        api_key_expires_at: null,
        api_key_last_used_at: null,
        api_key_status: 'ACTIVE',
        tenant_id: 'tenant-uuid-1',
        tenant_tenant_did: 'did:agent:test-pro',
        tenant_tier: 'PRO',
        tenant_display_name: 'Test Tenant',
        tenant_contact_email: 'admin@example.com',
        tenant_status: 'ACTIVE',
        ...overrides,
    };
}

function makePool(rows: QueryRow[] = []): DatabasePool {
    return {
        query: vi.fn().mockResolvedValue({ rows }),
    } as unknown as DatabasePool;
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

describe('auth-middleware', () => {
    describe('computeKeyHash', () => {
        it('should produce deterministic SHA-256 hex when called twice with same input', () => {
            const h1 = computeKeyHash('hello');
            const h2 = computeKeyHash('hello');
            expect(h1).toBe(h2);
            expect(h1).toMatch(/^[0-9a-f]{64}$/);
        });

        it('should produce different hashes when inputs differ', () => {
            expect(computeKeyHash('a')).not.toBe(computeKeyHash('b'));
        });
    });

    describe('FREE tier anonymous path', () => {
        it('should attach FREE tier auth context when Authorization header is missing', async () => {
            const pool = makePool();
            const middleware = createAuthMiddleware({ pool });
            const req = makeReq();
            const res = makeRes();
            const next = vi.fn() as NextFunction;

            await middleware(req, res, next);

            expect(next).toHaveBeenCalledOnce();
            expect(req.auth).toMatchObject({
                tier: 'FREE',
                tenant: null,
                apiKey: null,
                clientIp: '1.2.3.4',
            });
        });

        it('should attach FREE tier when Authorization header is non-Bearer scheme', async () => {
            const pool = makePool();
            const middleware = createAuthMiddleware({ pool });
            const req = makeReq({ authorization: 'Basic somecreds' });
            const res = makeRes();
            const next = vi.fn() as NextFunction;

            await middleware(req, res, next);

            expect(next).toHaveBeenCalledOnce();
            expect(req.auth?.tier).toBe('FREE');
        });

        it('should attach FREE tier when Bearer token is empty', async () => {
            const pool = makePool();
            const middleware = createAuthMiddleware({ pool });
            const req = makeReq({ authorization: 'Bearer    ' });
            const res = makeRes();
            const next = vi.fn() as NextFunction;

            await middleware(req, res, next);

            expect(next).toHaveBeenCalledOnce();
            expect(req.auth?.tier).toBe('FREE');
        });

        it('should fall back to socket.remoteAddress when req.ip is missing', async () => {
            const pool = makePool();
            const middleware = createAuthMiddleware({ pool });
            const req = {
                socket: { remoteAddress: '5.6.7.8' },
                header: () => undefined,
            } as unknown as AuthenticatedRequest;
            const res = makeRes();
            const next = vi.fn() as NextFunction;

            await middleware(req, res, next);

            expect(req.auth?.clientIp).toBe('5.6.7.8');
        });

        it('should use "unknown" when both req.ip and socket.remoteAddress are missing', async () => {
            const pool = makePool();
            const middleware = createAuthMiddleware({ pool });
            const req = {
                socket: {},
                header: () => undefined,
            } as unknown as AuthenticatedRequest;
            const res = makeRes();
            const next = vi.fn() as NextFunction;

            await middleware(req, res, next);

            expect(req.auth?.clientIp).toBe('unknown');
        });
    });

    describe('PRO tier authenticated path', () => {
        it('should inject tenant + apiKey context when Bearer key is valid ACTIVE', async () => {
            const row = makeRow();
            const pool = makePool([row]);
            const middleware = createAuthMiddleware({ pool });
            const req = makeReq({ authorization: 'Bearer test-key-123' });
            const res = makeRes();
            const next = vi.fn() as NextFunction;

            await middleware(req, res, next);

            expect(next).toHaveBeenCalledOnce();
            expect(req.auth?.tier).toBe('PRO');
            expect(req.auth?.tenant?.tenantDid).toBe('did:agent:test-pro');
            expect(req.auth?.apiKey?.keyPrefix).toBe('ap_test_');
        });

        it('should fire-and-forget last_used_at update on success', async () => {
            const row = makeRow();
            const queryFn = vi
                .fn()
                .mockResolvedValueOnce({ rows: [row] })  // lookup
                .mockResolvedValueOnce({ rows: [] });    // touchLastUsed
            const pool = { query: queryFn } as unknown as DatabasePool;
            const middleware = createAuthMiddleware({ pool });
            const req = makeReq({ authorization: 'Bearer test-key-123' });
            const res = makeRes();
            const next = vi.fn() as NextFunction;

            await middleware(req, res, next);

            // wait for microtask flush
            await new Promise((r) => setImmediate(r));
            expect(queryFn).toHaveBeenCalledTimes(2);
            const updateCall = queryFn.mock.calls[1] as unknown as [
                string,
                unknown[],
            ];
            expect(updateCall[0]).toContain('UPDATE managed_service.api_keys');
        });

        it('should call onUpdateError when last_used_at update fails', async () => {
            const row = makeRow();
            const queryFn = vi
                .fn()
                .mockResolvedValueOnce({ rows: [row] })
                .mockRejectedValueOnce(new Error('db down'));
            const pool = { query: queryFn } as unknown as DatabasePool;
            const onUpdateError = vi.fn();
            const middleware = createAuthMiddleware({ pool, onUpdateError });
            const req = makeReq({ authorization: 'Bearer test-key-123' });
            const res = makeRes();
            const next = vi.fn() as NextFunction;

            await middleware(req, res, next);

            await new Promise((r) => setImmediate(r));
            expect(onUpdateError).toHaveBeenCalledOnce();
            const errArg = onUpdateError.mock.calls[0]?.[0] as unknown;
            expect(errArg).toBeInstanceOf(Error);
        });

        it('should default to console.warn for last_used_at update error when no callback provided', async () => {
            const row = makeRow();
            const queryFn = vi
                .fn()
                .mockResolvedValueOnce({ rows: [row] })
                .mockRejectedValueOnce(new Error('db down'));
            const pool = { query: queryFn } as unknown as DatabasePool;
            const warnSpy = vi
                .spyOn(console, 'warn')
                .mockImplementation(() => undefined);
            const middleware = createAuthMiddleware({ pool });
            const req = makeReq({ authorization: 'Bearer test-key-123' });
            const res = makeRes();
            const next = vi.fn() as NextFunction;

            await middleware(req, res, next);
            await new Promise((r) => setImmediate(r));

            expect(warnSpy).toHaveBeenCalled();
            warnSpy.mockRestore();
        });
    });

    describe('fail-closed paths', () => {
        it('should respond 401 INVALID_API_KEY when key is not in DB', async () => {
            const pool = makePool([]);
            const middleware = createAuthMiddleware({ pool });
            const req = makeReq({ authorization: 'Bearer unknown' });
            const res = makeRes();
            const next = vi.fn() as NextFunction;

            await middleware(req, res, next);

            expect(next).not.toHaveBeenCalled();
            expect(res.statusCode).toBe(401);
            expect((res.body as { error: { code: string } }).error.code).toBe(
                'INVALID_API_KEY',
            );
        });

        it('should respond 401 API_KEY_REVOKED when status=REVOKED', async () => {
            const pool = makePool([makeRow({ api_key_status: 'REVOKED' })]);
            const middleware = createAuthMiddleware({ pool });
            const req = makeReq({ authorization: 'Bearer test-key-123' });
            const res = makeRes();
            const next = vi.fn() as NextFunction;

            await middleware(req, res, next);

            expect(next).not.toHaveBeenCalled();
            expect(res.statusCode).toBe(401);
            expect((res.body as { error: { code: string } }).error.code).toBe(
                'API_KEY_REVOKED',
            );
        });

        it('should respond 401 API_KEY_EXPIRED when status=EXPIRED', async () => {
            const pool = makePool([makeRow({ api_key_status: 'EXPIRED' })]);
            const middleware = createAuthMiddleware({ pool });
            const req = makeReq({ authorization: 'Bearer test-key-123' });
            const res = makeRes();
            const next = vi.fn() as NextFunction;

            await middleware(req, res, next);

            expect(res.statusCode).toBe(401);
            expect((res.body as { error: { code: string } }).error.code).toBe(
                'API_KEY_EXPIRED',
            );
        });

        it('should respond 401 API_KEY_EXPIRED when expires_at < now (passive expire)', async () => {
            const pool = makePool([
                makeRow({
                    api_key_status: 'ACTIVE',
                    api_key_expires_at: new Date('2020-01-01'),
                }),
            ]);
            const fakeNow = new Date('2026-01-01');
            const middleware = createAuthMiddleware({
                pool,
                now: () => fakeNow,
            });
            const req = makeReq({ authorization: 'Bearer test-key-123' });
            const res = makeRes();
            const next = vi.fn() as NextFunction;

            await middleware(req, res, next);

            expect(res.statusCode).toBe(401);
            expect((res.body as { error: { code: string } }).error.code).toBe(
                'API_KEY_EXPIRED',
            );
        });

        it('should NOT mark expired when expires_at is null', async () => {
            const pool = makePool([
                makeRow({ api_key_expires_at: null }),
            ]);
            const middleware = createAuthMiddleware({ pool });
            const req = makeReq({ authorization: 'Bearer test-key-123' });
            const res = makeRes();
            const next = vi.fn() as NextFunction;

            await middleware(req, res, next);

            expect(next).toHaveBeenCalledOnce();
            expect(req.auth?.tier).toBe('PRO');
        });

        it('should respond 401 TENANT_SUSPENDED when tenant.status=SUSPENDED', async () => {
            const pool = makePool([
                makeRow({ tenant_status: 'SUSPENDED' }),
            ]);
            const middleware = createAuthMiddleware({ pool });
            const req = makeReq({ authorization: 'Bearer test-key-123' });
            const res = makeRes();
            const next = vi.fn() as NextFunction;

            await middleware(req, res, next);

            expect(res.statusCode).toBe(401);
            expect((res.body as { error: { code: string } }).error.code).toBe(
                'TENANT_SUSPENDED',
            );
        });

        it('should respond 401 TENANT_SUSPENDED when tenant.status=DELETED', async () => {
            const pool = makePool([makeRow({ tenant_status: 'DELETED' })]);
            const middleware = createAuthMiddleware({ pool });
            const req = makeReq({ authorization: 'Bearer test-key-123' });
            const res = makeRes();
            const next = vi.fn() as NextFunction;

            await middleware(req, res, next);

            expect(res.statusCode).toBe(401);
            expect((res.body as { error: { code: string } }).error.code).toBe(
                'TENANT_SUSPENDED',
            );
        });

        it('should prefer REVOKED over EXPIRED check when both could apply', async () => {
            // status=REVOKED + expires_at past → should return REVOKED rather than EXPIRED
            const pool = makePool([
                makeRow({
                    api_key_status: 'REVOKED',
                    api_key_expires_at: new Date('2020-01-01'),
                }),
            ]);
            const middleware = createAuthMiddleware({ pool });
            const req = makeReq({ authorization: 'Bearer test-key-123' });
            const res = makeRes();
            const next = vi.fn() as NextFunction;

            await middleware(req, res, next);

            expect((res.body as { error: { code: string } }).error.code).toBe(
                'API_KEY_REVOKED',
            );
        });
    });

    describe('Bearer parsing edge cases', () => {
        beforeEach(() => {
            vi.clearAllMocks();
        });

        it('should accept lowercase bearer scheme', async () => {
            const row = makeRow();
            const pool = makePool([row]);
            const middleware = createAuthMiddleware({ pool });
            const req = makeReq({ authorization: 'bearer test-key-123' });
            const res = makeRes();
            const next = vi.fn() as NextFunction;

            await middleware(req, res, next);

            expect(req.auth?.tier).toBe('PRO');
        });

        it('should treat header with leading/trailing whitespace correctly', async () => {
            const row = makeRow();
            const pool = makePool([row]);
            const middleware = createAuthMiddleware({ pool });
            const req = makeReq({
                authorization: '   Bearer test-key-123   ',
            });
            const res = makeRes();
            const next = vi.fn() as NextFunction;

            await middleware(req, res, next);

            expect(req.auth?.tier).toBe('PRO');
        });
    });
});
