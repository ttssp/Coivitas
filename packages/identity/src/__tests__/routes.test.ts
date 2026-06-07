import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import {
    createApp,
    createTestDatabase,
    createTestServer,
    makeRequest,
} from '@coivitas/shared';
import { generateKeyPair } from '@coivitas/crypto';

import {
    createAgentIdentity,
    didKeyFromPublicKey,
    IdentityRegistry,
    registerIdentityRoutes,
} from '../index.js';

const describeIfDatabase = process.env.DATABASE_URL ? describe : describe.skip;

describeIfDatabase('identity routes', () => {
    let cleanup: (() => Promise<void>) | undefined;
    let closeServer: (() => Promise<void>) | undefined;
    let serverUrl = '';

    beforeAll(async () => {
        const database = await createTestDatabase();
        cleanup = database.cleanup;
        const registry = new IdentityRegistry(database.pool);
        const app = createApp();
        registerIdentityRoutes(app, registry);
        const server = await createTestServer((testApp) => {
            registerIdentityRoutes(testApp, registry);
        });
        serverUrl = server.url;
        closeServer = server.close;
    });

    afterAll(async () => {
        await closeServer?.();
        await cleanup?.();
    });

    it('supports register, query, and deactivate over HTTP', async () => {
        const principal = generateKeyPair();
        const principalDid = didKeyFromPublicKey(
            Buffer.from(principal.publicKey, 'hex'),
        );
        const identity = createAgentIdentity({
            principalDid,
            principalPrivateKey: principal.privateKey,
        });

        const createResponse = await makeRequest(
            serverUrl,
            'POST',
            '/api/v1/identities',
            identity.document,
        );
        expect(createResponse.status).toBe(201);

        const getResponse = await makeRequest(
            serverUrl,
            'GET',
            `/api/v1/identities/${encodeURIComponent(identity.document.id)}`,
        );
        expect(getResponse.status).toBe(200);
        expect(getResponse.body).toEqual(identity.document);

        const deleteResponse = await makeRequest(
            serverUrl,
            'DELETE',
            `/api/v1/identities/${encodeURIComponent(identity.document.id)}`,
        );
        expect(deleteResponse.status).toBe(204);

        const missingResponse = await makeRequest(
            serverUrl,
            'GET',
            `/api/v1/identities/${encodeURIComponent(identity.document.id)}`,
        );
        expect(missingResponse.status).toBe(404);
        expect(missingResponse.body).toEqual({
            error: {
                code: 'IDENTITY_NOT_FOUND',
                message: `Identity ${identity.document.id} was not found.`,
            },
        });
    });
});
