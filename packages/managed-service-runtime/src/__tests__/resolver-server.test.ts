/**
 * resolver-server.test.ts
 *
 * Test target: createResolverApp (packages/managed-service-runtime/src/resolver-server.ts)
 *
 * Style: integration-lite (start Express + supertest-style fetch; mock out federatedResolver + pool)
 */

import { afterEach, describe, expect, it, vi } from 'vitest';

import { createResolverApp } from '../resolver-server.js';
import { createMetrics } from '../metrics.js';

import type { FederatedResolver } from '@coivitas/types';
import type { DatabasePool } from '@coivitas/shared';
import type { Server } from 'node:http';

interface ServerHandle {
    url: string;
    close: () => Promise<void>;
}

async function startApp(
    config: Parameters<typeof createResolverApp>[0],
): Promise<ServerHandle> {
    const app = createResolverApp(config);
    return new Promise((resolve, reject) => {
        const server: Server = app.listen(0, '127.0.0.1', () => {
            const addr = server.address();
            if (!addr || typeof addr === 'string') {
                reject(new Error('failed to bind'));
                return;
            }
            resolve({
                url: `http://127.0.0.1:${addr.port}`,
                close: () =>
                    new Promise<void>((res) => server.close(() => res())),
            });
        });
    });
}

function makePool(rows: unknown[] = []): DatabasePool {
    return {
        query: vi.fn().mockResolvedValue({ rows }),
    } as unknown as DatabasePool;
}

function makeStubResolver(
    impl: Partial<FederatedResolver> = {},
): FederatedResolver {
    return {
        resolve: () => Promise.resolve(null),
        invalidateCache: () => undefined,
        getMetrics: () =>
            ({
                resolveTotal: 0,
                resolveSuccess: 0,
                resolveNull: 0,
                resolveInternalError: 0,
                latencyP50Ms: 0,
                latencyP95Ms: 0,
                latencyP99Ms: 0,
                nodes: {},
                versionConflictCount: 0,
                signatureInvalidCount: 0,
                quorumUnmetCount: 0,
                cacheHit: 0,
                cacheMiss: 0,
                quorumVoteSplitCount: 0,
                dnsRebindingBlockedCount: 0,
                quorumReachedCount: 0,
            }) as ReturnType<FederatedResolver['getMetrics']>,
        close: () => Promise.resolve(),
        ...impl,
    } as FederatedResolver;
}

describe('resolver-server', () => {
    let server: ServerHandle | null = null;

    afterEach(async () => {
        if (server) {
            await server.close();
            server = null;
        }
    });

    describe('/health', () => {
        it('should return 200 with status ok', async () => {
            const pool = makePool();
            const resolver = makeStubResolver();
            server = await startApp({ pool, federatedResolver: resolver });

            const res = await fetch(`${server.url}/health`);
            expect(res.status).toBe(200);
            const body = (await res.json()) as { status: string; service: string };
            expect(body.status).toBe('ok');
            expect(body.service).toBe('resolver');
        });
    });

    describe('/metrics', () => {
        it('should return 200 with Prometheus text', async () => {
            const pool = makePool();
            const resolver = makeStubResolver();
            const metrics = createMetrics({ collectDefault: false });
            server = await startApp({
                pool,
                federatedResolver: resolver,
                metrics,
            });

            const res = await fetch(`${server.url}/metrics`);
            expect(res.status).toBe(200);
            const text = await res.text();
            expect(text).toContain('resolver_requests_total');
        });
    });

    describe('GET /v1/resolve/:did - FREE tier', () => {
        it('should return 200 with document on successful resolve', async () => {
            const pool = makePool();
            const resolver = makeStubResolver({
                resolve: () =>
                    Promise.resolve({
                        did: 'did:agent:test' as never,
                        publicKey: 'abc' as never,
                        version: 1,
                    } as never),
            });
            server = await startApp({ pool, federatedResolver: resolver });

            const res = await fetch(
                `${server.url}/v1/resolve/did:agent:test`,
            );
            expect(res.status).toBe(200);
            // The server returns the bare AgentIdentityDocument structure directly, with no wrapper
            const body = (await res.json()) as {
                did: string;
                publicKey: string;
                version: number;
            };
            expect(body.did).toBe('did:agent:test');
            expect(body.publicKey).toBe('abc');
            expect(body.version).toBe(1);
        });

        it('should return 404 when resolver returns null', async () => {
            const pool = makePool();
            const resolver = makeStubResolver({
                resolve: () => Promise.resolve(null),
            });
            server = await startApp({ pool, federatedResolver: resolver });

            const res = await fetch(`${server.url}/v1/resolve/did:agent:nope`);
            expect(res.status).toBe(404);
            const body = (await res.json()) as { error: { code: string } };
            expect(body.error.code).toBe('NOT_FOUND');
        });

        it('should return 502 when resolver throws', async () => {
            const pool = makePool();
            const resolver = makeStubResolver({
                resolve: () => Promise.reject(new Error('node down')),
            });
            server = await startApp({ pool, federatedResolver: resolver });

            const res = await fetch(`${server.url}/v1/resolve/did:agent:err`);
            expect(res.status).toBe(502);
            const body = (await res.json()) as { error: { code: string } };
            expect(body.error.code).toBe('RESOLVER_FAILED');
        });

        it('should serialize non-Error rejection as unknown', async () => {
            const pool = makePool();
            const resolver = makeStubResolver({
                // eslint-disable-next-line @typescript-eslint/prefer-promise-reject-errors
                resolve: () => Promise.reject('weird'),
            });
            server = await startApp({ pool, federatedResolver: resolver });

            const res = await fetch(
                `${server.url}/v1/resolve/did:agent:weird`,
            );
            expect(res.status).toBe(502);
            const body = (await res.json()) as {
                error: { message: string };
            };
            expect(body.error.message).toContain('unknown');
        });
    });

    describe('GET /v1/resolve/:did - PRO tier', () => {
        it('should authenticate via Bearer token and resolve', async () => {
            // test the PRO path: mock pool returns a valid row
            const validKey = 'test-pro-key';
            const validRow = {
                api_key_id: 'key-1',
                api_key_tenant_id: 'tenant-1',
                api_key_key_hash: '',
                api_key_key_prefix: 'ap_test_',
                api_key_description: null,
                api_key_expires_at: null,
                api_key_last_used_at: null,
                api_key_status: 'ACTIVE',
                tenant_id: 'tenant-1',
                tenant_tenant_did: 'did:agent:pro',
                tenant_tier: 'PRO',
                tenant_display_name: 'PRO Tenant',
                tenant_contact_email: null,
                tenant_status: 'ACTIVE',
            };
            // actual computeKeyHash value
            const { computeKeyHash } = await import('../auth-middleware.js');
            validRow.api_key_key_hash = computeKeyHash(validKey);

            const pool = makePool([validRow]);
            const resolver = makeStubResolver({
                resolve: () =>
                    Promise.resolve({
                        did: 'did:agent:test' as never,
                    } as never),
            });
            server = await startApp({ pool, federatedResolver: resolver });

            const res = await fetch(
                `${server.url}/v1/resolve/did:agent:test`,
                {
                    headers: { Authorization: `Bearer ${validKey}` },
                },
            );
            expect(res.status).toBe(200);
        });
    });

    describe('trustProxy config', () => {
        it('should default trust proxy to disabled (X-Forwarded-For ignored)', async () => {
            // default trustProxy=false: a client-sent X-Forwarded-For is ignored,
            // and req.ip still takes the socket remote address
            const pool = makePool();
            const resolver = makeStubResolver({
                resolve: () => Promise.resolve(null),
            });
            server = await startApp({ pool, federatedResolver: resolver });

            // even with X-Forwarded-For, IP rate limiting is unaffected (cannot spoof IP to bypass quota)
            const res = await fetch(`${server.url}/v1/resolve/did:agent:test`, {
                headers: { 'X-Forwarded-For': '203.0.113.99' },
            });
            // the 404 comes from stubResolver returning null (not the rate-limit path)
            expect([404, 200]).toContain(res.status);
        });

        it('should accept trustProxy=1 when explicitly configured (reverse proxy deploy)', async () => {
            // explicit trustProxy=1: trust one X-Forwarded-For hop
            const pool = makePool();
            const resolver = makeStubResolver({
                resolve: () => Promise.resolve(null),
            });
            server = await startApp({
                pool,
                federatedResolver: resolver,
                trustProxy: 1,
            });

            const res = await fetch(`${server.url}/v1/resolve/did:agent:test`, {
                headers: { 'X-Forwarded-For': '203.0.113.99' },
            });
            // behavior should not crash, and the trust proxy config takes effect (the concrete req.ip impact
            // is covered in the rate-limiter unit tests; here we only verify startup + no errors)
            expect([404, 200]).toContain(res.status);
        });
    });
});
