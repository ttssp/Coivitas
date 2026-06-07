/**
 * revocation-server.test.ts
 *
 * Test target: createRevocationApp (packages/managed-service-runtime/src/revocation-server.ts)
 */

import { afterEach, describe, expect, it, vi } from 'vitest';

import { createRevocationApp } from '../revocation-server.js';
import { createMetrics } from '../metrics.js';

import type { DatabasePool } from '@coivitas/shared';
import type { Server } from 'node:http';
import type { RevocationChecker } from '../revocation-server.js';

interface ServerHandle {
    url: string;
    close: () => Promise<void>;
}

async function startApp(
    config: Parameters<typeof createRevocationApp>[0],
): Promise<ServerHandle> {
    const app = createRevocationApp(config);
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

describe('revocation-server', () => {
    let server: ServerHandle | null = null;

    afterEach(async () => {
        if (server) {
            await server.close();
            server = null;
        }
    });

    describe('/health', () => {
        it('should return 200', async () => {
            server = await startApp({ pool: makePool() });
            const res = await fetch(`${server.url}/health`);
            expect(res.status).toBe(200);
            const body = (await res.json()) as {
                status: string;
                service: string;
            };
            expect(body.service).toBe('revocation');
        });
    });

    describe('/metrics', () => {
        it('should expose Prometheus text', async () => {
            const metrics = createMetrics({ collectDefault: false });
            server = await startApp({ pool: makePool(), metrics });
            const res = await fetch(`${server.url}/metrics`);
            expect(res.status).toBe(200);
            const text = await res.text();
            expect(text.length).toBeGreaterThan(0);
        });
    });

    describe('GET /v1/revocation/:credentialId - stub default fail-closed', () => {
        it('should return 503 + STUB_REVOCATION_NOT_FOR_PRODUCTION when no checker injected', async () => {
            server = await startApp({ pool: makePool() });
            const res = await fetch(
                `${server.url}/v1/revocation/test-credential-1`,
            );
            expect(res.status).toBe(503);
            const body = (await res.json()) as {
                error: { code: string; message: string };
            };
            expect(body.error.code).toBe('STUB_REVOCATION_NOT_FOR_PRODUCTION');
            expect(body.error.message).toContain(
                'inject a real RevocationChecker',
            );
        });

        it('should not return 200 + revoked:false for any credentialId (silent false negative guard)', async () => {
            server = await startApp({ pool: makePool() });
            const res = await fetch(
                `${server.url}/v1/revocation/should-be-revoked`,
            );
            // key invariant: the default stub must not produce 200 + body (avoids a trust hole)
            expect(res.status).not.toBe(200);
        });
    });

    describe('GET /v1/revocation/:credentialId - custom checker', () => {
        it('should return revoked=true with metadata when checker says so', async () => {
            const checker: RevocationChecker = (id) =>
                Promise.resolve({
                    revoked: true,
                    revokedAt: '2026-05-01T00:00:00Z',
                    reason: `compromised:${id}`,
                });
            server = await startApp({ pool: makePool(), checker });

            const res = await fetch(`${server.url}/v1/revocation/cred-99`);
            expect(res.status).toBe(200);
            const body = (await res.json()) as {
                credentialId: string;
                revoked: boolean;
                reason: string;
            };
            expect(body.revoked).toBe(true);
            expect(body.reason).toBe('compromised:cred-99');
        });

        it('should return 502 when checker throws', async () => {
            const checker: RevocationChecker = () =>
                Promise.reject(new Error('backend down'));
            server = await startApp({ pool: makePool(), checker });

            const res = await fetch(`${server.url}/v1/revocation/cred-x`);
            expect(res.status).toBe(502);
            const body = (await res.json()) as {
                error: { code: string };
            };
            expect(body.error.code).toBe('REVOCATION_CHECK_FAILED');
        });

        it('should serialize non-Error rejection as "unknown"', async () => {
            // eslint-disable-next-line @typescript-eslint/prefer-promise-reject-errors
            const checker: RevocationChecker = () => Promise.reject('strange');
            server = await startApp({ pool: makePool(), checker });

            const res = await fetch(`${server.url}/v1/revocation/cred-x`);
            expect(res.status).toBe(502);
            const body = (await res.json()) as {
                error: { message: string };
            };
            expect(body.error.message).toContain('unknown');
        });
    });

    describe('PRO tier path', () => {
        it('should authenticate via Bearer and call checker', async () => {
            const validKey = 'test-pro-key';
            const { computeKeyHash } = await import('../auth-middleware.js');
            const row = {
                api_key_id: 'k1',
                api_key_tenant_id: 't1',
                api_key_key_hash: computeKeyHash(validKey),
                api_key_key_prefix: 'ap_',
                api_key_description: null,
                api_key_expires_at: null,
                api_key_last_used_at: null,
                api_key_status: 'ACTIVE',
                tenant_id: 't1',
                tenant_tenant_did: 'did:agent:pro',
                tenant_tier: 'PRO',
                tenant_display_name: 'PRO',
                tenant_contact_email: null,
                tenant_status: 'ACTIVE',
            };
            const checker: RevocationChecker = vi
                .fn()
                .mockResolvedValue({ revoked: false });
            server = await startApp({
                pool: makePool([row]),
                checker,
            });

            const res = await fetch(`${server.url}/v1/revocation/c1`, {
                headers: { Authorization: `Bearer ${validKey}` },
            });
            expect(res.status).toBe(200);
            expect(checker).toHaveBeenCalledWith('c1');
        });
    });
});
