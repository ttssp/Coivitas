import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';

import {
    createTestDatabase,
    createTestServer,
    makeRequest,
} from '@coivitas/shared';
import { generateKeyPair } from '@coivitas/crypto';
import type { AgentIdentityDocument } from '@coivitas/types';

import {
    broadcastToNodes,
    type FederationBroadcastOptions,
    registerIdentityRoutes,
} from '../routes.js';
import {
    createAgentIdentity,
    didKeyFromPublicKey,
    IdentityRegistry,
} from '../index.js';

// Minimal valid document (only the id field is needed; broadcastToNodes does not validate content)
const fakeDoc = { id: 'did:agent:abc123' } as AgentIdentityDocument;

// Run HTTP integration tests only when a database is available
const describeIfDatabase = process.env.DATABASE_URL ? describe : describe.skip;

// ---- Pure-function tests (no database needed) ----

describe('broadcastToNodes', () => {
    it('should return ok:true for each node when fetch succeeds', async () => {
        const mockFetch = vi.fn().mockResolvedValue({ ok: true });
        const options: FederationBroadcastOptions = {
            nodes: [
                { id: 'node-1', url: 'http://node1.example.com' },
                { id: 'node-2', url: 'http://node2.example.com' },
            ],
            fetch: mockFetch,
        };

        const results = await broadcastToNodes(fakeDoc, options);

        expect(results).toHaveLength(2);
        expect(results[0]).toEqual({ nodeId: 'node-1', ok: true });
        expect(results[1]).toEqual({ nodeId: 'node-2', ok: true });
        expect(mockFetch).toHaveBeenCalledTimes(2);
        expect(mockFetch).toHaveBeenCalledWith(
            'http://node1.example.com/federation/sync',
            expect.objectContaining({
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(fakeDoc),
            }),
        );
    });

    it('should return ok:false with error when fetch throws', async () => {
        const mockFetch = vi
            .fn()
            .mockRejectedValue(new Error('network timeout'));
        const options: FederationBroadcastOptions = {
            nodes: [{ id: 'node-1', url: 'http://node1.example.com' }],
            fetch: mockFetch,
        };

        const results = await broadcastToNodes(fakeDoc, options);

        expect(results).toHaveLength(1);
        expect(results[0]).toMatchObject({ nodeId: 'node-1', ok: false });
        expect(results[0]?.error).toContain('network timeout');
    });

    it('should return ok:false when remote returns non-2xx status', async () => {
        const mockFetch = vi.fn().mockResolvedValue({ ok: false });
        const options: FederationBroadcastOptions = {
            nodes: [{ id: 'node-1', url: 'http://node1.example.com' }],
            fetch: mockFetch,
        };

        const results = await broadcastToNodes(fakeDoc, options);

        expect(results[0]).toEqual({ nodeId: 'node-1', ok: false });
    });

    it('should not throw when nodes list is empty', async () => {
        const mockFetch = vi.fn();
        const options: FederationBroadcastOptions = {
            nodes: [],
            fetch: mockFetch,
        };

        const results = await broadcastToNodes(fakeDoc, options);

        expect(results).toHaveLength(0);
        expect(mockFetch).not.toHaveBeenCalled();
    });
});

// ---- HTTP integration tests (database required) ----

describeIfDatabase('POST /api/v1/identities broadcast (05b)', () => {
    let closeServer: (() => Promise<void>) | undefined;
    let cleanup: (() => Promise<void>) | undefined;
    let serverUrl = '';
    let broadcastCalled = false;

    beforeAll(async () => {
        const database = await createTestDatabase();
        cleanup = database.cleanup;
        const registry = new IdentityRegistry(database.pool);
        const mockFetch = vi.fn().mockImplementation(() => {
            broadcastCalled = true;
            return Promise.resolve({ ok: true });
        });

        const server = await createTestServer((app) => {
            registerIdentityRoutes(app, registry, {
                nodes: [{ id: 'peer', url: 'http://peer.example.com' }],
                fetch: mockFetch,
            });
        });
        serverUrl = server.url;
        closeServer = server.close;
    });

    afterAll(async () => {
        await closeServer?.();
        await cleanup?.();
    });

    it('should trigger broadcast after successful register', async () => {
        const principal = generateKeyPair();
        const principalDid = didKeyFromPublicKey(
            Buffer.from(principal.publicKey, 'hex'),
        );
        const identity = createAgentIdentity({
            principalDid,
            principalPrivateKey: principal.privateKey,
        });

        const res = await makeRequest(
            serverUrl,
            'POST',
            '/api/v1/identities',
            identity.document,
        );
        expect(res.status).toBe(201);

        // fire-and-forget: wait for the microtask queue to drain
        await new Promise((resolve) => setTimeout(resolve, 10));
        expect(broadcastCalled).toBe(true);
    });
});

describeIfDatabase('POST /federation/sync (05a)', () => {
    let closeServer: (() => Promise<void>) | undefined;
    let cleanup: (() => Promise<void>) | undefined;
    let serverUrl = '';
    let validIdentity: ReturnType<typeof createAgentIdentity>;

    beforeAll(async () => {
        const database = await createTestDatabase();
        cleanup = database.cleanup;
        const registry = new IdentityRegistry(database.pool);

        const server = await createTestServer((app) => {
            registerIdentityRoutes(app, registry);
        });
        serverUrl = server.url;
        closeServer = server.close;

        const principal = generateKeyPair();
        const principalDid = didKeyFromPublicKey(
            Buffer.from(principal.publicKey, 'hex'),
        );
        validIdentity = createAgentIdentity({
            principalDid,
            principalPrivateKey: principal.privateKey,
        });
    });

    afterAll(async () => {
        await closeServer?.();
        await cleanup?.();
    });

    it('should return 200 and store a valid document', async () => {
        const res = await makeRequest(
            serverUrl,
            'POST',
            '/federation/sync',
            validIdentity.document,
        );
        expect(res.status).toBe(200);
        expect(res.body).toEqual({ ok: true });
    });

    it('should return 200 idempotently when document already exists', async () => {
        const res = await makeRequest(
            serverUrl,
            'POST',
            '/federation/sync',
            validIdentity.document,
        );
        expect(res.status).toBe(200);
    });

    it('should return 400 when document.id is missing', async () => {
        const docWithoutId = Object.fromEntries(
            Object.entries(validIdentity.document).filter(([k]) => k !== 'id'),
        );
        const res = await makeRequest(
            serverUrl,
            'POST',
            '/federation/sync',
            docWithoutId,
        );
        expect(res.status).toBe(400);
        expect((res.body as { error: { code: string } }).error.code).toBe(
            'INVALID_DOCUMENT',
        );
    });

    it('should return 400 when bindingProof is missing', async () => {
        const docWithoutProof = Object.fromEntries(
            Object.entries(validIdentity.document).filter(
                ([k]) => k !== 'bindingProof',
            ),
        );
        const res = await makeRequest(
            serverUrl,
            'POST',
            '/federation/sync',
            docWithoutProof,
        );
        expect(res.status).toBe(400);
        expect((res.body as { error: { code: string } }).error.code).toBe(
            'INVALID_DOCUMENT',
        );
    });

    it('should return 400 when bindingProof.agentDid does not match document.id', async () => {
        // Construct an attack document whose proof comes from a different agent
        const otherPrincipal = generateKeyPair();
        const otherDid = didKeyFromPublicKey(
            Buffer.from(otherPrincipal.publicKey, 'hex'),
        );
        const otherIdentity = createAgentIdentity({
            principalDid: otherDid,
            principalPrivateKey: otherPrincipal.privateKey,
        });

        // Attach validIdentity's bindingProof to the otherIdentity document
        const tamperedDoc = {
            ...otherIdentity.document,
            bindingProof: validIdentity.document.bindingProof,
        };
        const res = await makeRequest(
            serverUrl,
            'POST',
            '/federation/sync',
            tamperedDoc,
        );
        expect(res.status).toBe(400);
        expect((res.body as { error: { code: string } }).error.code).toBe(
            'SIGNATURE_INVALID',
        );
    });

    it('should return 400 when DID does not match publicKey (v=1 self-certification)', async () => {
        // Replace with another identity's publicKey so the DID no longer matches the publicKey
        const otherPrincipal = generateKeyPair();
        const otherDid = didKeyFromPublicKey(
            Buffer.from(otherPrincipal.publicKey, 'hex'),
        );
        const otherIdentity = createAgentIdentity({
            principalDid: otherDid,
            principalPrivateKey: otherPrincipal.privateKey,
        });
        // Keep id/bindingProof from validIdentity, but replace publicKey with a different agent's
        const tamperedDoc = {
            ...validIdentity.document,
            publicKey: otherIdentity.document.publicKey,
        };
        const res = await makeRequest(
            serverUrl,
            'POST',
            '/federation/sync',
            tamperedDoc,
        );
        expect(res.status).toBe(400);
        expect((res.body as { error: { code: string } }).error.code).toBe(
            'SIGNATURE_INVALID',
        );
    });

    it('should return 400 when bindingProof signature is invalid', async () => {
        // Tamper with the signature bytes so signature verification fails
        const tamperedDoc = {
            ...validIdentity.document,
            bindingProof: {
                ...validIdentity.document.bindingProof,
                signature: 'deadbeef'.repeat(16),
            },
        };
        const res = await makeRequest(
            serverUrl,
            'POST',
            '/federation/sync',
            tamperedDoc,
        );
        expect(res.status).toBe(400);
        expect((res.body as { error: { code: string } }).error.code).toBe(
            'SIGNATURE_INVALID',
        );
    });
});

describeIfDatabase('GET /federation/health (05c)', () => {
    let closeServer: (() => Promise<void>) | undefined;
    let cleanup: (() => Promise<void>) | undefined;
    let serverUrl = '';

    beforeAll(async () => {
        const database = await createTestDatabase();
        cleanup = database.cleanup;
        const registry = new IdentityRegistry(database.pool);

        const server = await createTestServer((app) => {
            registerIdentityRoutes(app, registry, {
                nodes: [
                    { id: 'node-1', url: 'http://node1.example.com' },
                    { id: 'node-2', url: 'http://node2.example.com' },
                ],
            });
        });
        serverUrl = server.url;
        closeServer = server.close;
    });

    afterAll(async () => {
        await closeServer?.();
        await cleanup?.();
    });

    it('should return status ok with knownNodes count', async () => {
        const res = await makeRequest(serverUrl, 'GET', '/federation/health');
        expect(res.status).toBe(200);
        expect(res.body).toMatchObject({
            status: 'ok',
            knownNodes: 2,
        });
        expect(typeof (res.body as { version: string }).version).toBe('string');
        // lastSyncAt may be null (no sync has happened yet)
        expect('lastSyncAt' in (res.body as object)).toBe(true);
    });
});
