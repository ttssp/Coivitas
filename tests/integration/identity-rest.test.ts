import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { generateKeyPair } from '../../packages/crypto/src/index.js';
import {
    createAgentIdentity,
    didKeyFromPublicKey,
    IdentityRegistry,
    registerIdentityRoutes,
    registerRevocationRoutes,
    RevocationList,
} from '../../packages/identity/src/index.js';
import {
    createTestDatabase,
    createTestServer,
    makeRequest,
} from '../../packages/shared/src/index.js';
import type { DID } from '../../packages/types/src/index.js';

const describeIfDatabase = process.env.DATABASE_URL ? describe : describe.skip;

describeIfDatabase('identity and revocation REST integration', () => {
    let cleanup: (() => Promise<void>) | undefined;
    let closeServer: (() => Promise<void>) | undefined;
    let serverUrl = '';

    beforeAll(async () => {
        const database = await createTestDatabase();
        cleanup = database.cleanup;

        const identityRegistry = new IdentityRegistry(database.pool);
        const revocationList = new RevocationList(database.pool);
        const server = await createTestServer((app) => {
            registerIdentityRoutes(app, identityRegistry);
            registerRevocationRoutes(app, revocationList);
        });

        serverUrl = server.url;
        closeServer = server.close;
    });

    afterAll(async () => {
        await closeServer?.();
        await cleanup?.();
    });

    it('covers register, query, deactivate, and missing identity responses over HTTP', async () => {
        const principal = generateKeyPair();
        const principalDid = didKeyFromPublicKey(
            Buffer.from(principal.publicKey, 'hex'),
        );
        const identity = createAgentIdentity({
            principalDid,
            principalPrivateKey: principal.privateKey,
            capabilities: ['INQUIRY', 'QUOTE'],
        });

        const registerResponse = await makeRequest(
            serverUrl,
            'POST',
            '/api/v1/identities',
            identity.document,
        );
        expect(registerResponse.status).toBe(201);
        expect(registerResponse.body).toEqual({ did: identity.document.id });

        const queryResponse = await makeRequest(
            serverUrl,
            'GET',
            `/api/v1/identities/${encodeURIComponent(identity.document.id)}`,
        );
        expect(queryResponse.status).toBe(200);
        expect(queryResponse.body).toEqual(identity.document);

        const deactivateResponse = await makeRequest(
            serverUrl,
            'DELETE',
            `/api/v1/identities/${encodeURIComponent(identity.document.id)}`,
        );
        expect(deactivateResponse.status).toBe(204);
        expect(deactivateResponse.body).toBeNull();

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

    it('covers revoke, query status, list, and invalid request responses over HTTP', async () => {
        const revokedBy =
            'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK' as DID;
        const tokenId = 'urn:cap:550e8400-e29b-41d4-a716-446655440000';

        const invalidResponse = await makeRequest(
            serverUrl,
            'POST',
            '/api/v1/revocations',
            {
                tokenId,
            },
        );
        expect(invalidResponse.status).toBe(400);
        expect(invalidResponse.body).toEqual({
            error: {
                code: 'INVALID_REQUEST',
                message: 'tokenId and revokedBy are required.',
            },
        });

        const revokeResponse = await makeRequest(
            serverUrl,
            'POST',
            '/api/v1/revocations',
            {
                tokenId,
                revokedBy,
                reason: 'MANUAL_REVOCATION',
            },
        );
        expect(revokeResponse.status).toBe(201);
        expect(revokeResponse.body).toMatchObject({
            token_id: tokenId,
            revoked_by: revokedBy,
            reason: 'MANUAL_REVOCATION',
        });

        const statusResponse = await makeRequest(
            serverUrl,
            'GET',
            `/api/v1/revocations/${encodeURIComponent(tokenId)}`,
        );
        expect(statusResponse.status).toBe(200);
        expect(statusResponse.body).toMatchObject({
            revoked: true,
            reason: 'MANUAL_REVOCATION',
        });

        const missingStatusResponse = await makeRequest(
            serverUrl,
            'GET',
            '/api/v1/revocations/urn%3Acap%3Amissing',
        );
        expect(missingStatusResponse.status).toBe(200);
        expect(missingStatusResponse.body).toEqual({ revoked: false });

        const listResponse = await makeRequest(
            serverUrl,
            'GET',
            '/api/v1/revocations',
        );
        expect(listResponse.status).toBe(200);
        expect(listResponse.body).toMatchObject({
            revocations: [
                {
                    token_id: tokenId,
                    revoked_by: revokedBy,
                    reason: 'MANUAL_REVOCATION',
                },
            ],
        });
    });
});
