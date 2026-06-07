import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import {
    createTestDatabase,
    createTestServer,
    makeRequest,
} from '@coivitas/shared';
import type { DID } from '@coivitas/types';

import { registerRevocationRoutes, RevocationList } from '../index.js';

const describeIfDatabase = process.env.DATABASE_URL ? describe : describe.skip;

describeIfDatabase('revocation routes', () => {
    let cleanup: (() => Promise<void>) | undefined;
    let closeServer: (() => Promise<void>) | undefined;
    let serverUrl = '';

    beforeAll(async () => {
        const database = await createTestDatabase();
        cleanup = database.cleanup;
        const revocations = new RevocationList(database.pool);
        const server = await createTestServer((app) => {
            registerRevocationRoutes(app, revocations);
        });
        serverUrl = server.url;
        closeServer = server.close;
    });

    afterAll(async () => {
        await closeServer?.();
        await cleanup?.();
    });

    it('supports creating and querying revocations over HTTP', async () => {
        const revokedBy =
            'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK' as DID;
        const createResponse = await makeRequest(
            serverUrl,
            'POST',
            '/api/v1/revocations',
            {
                tokenId: 'urn:cap:550e8400-e29b-41d4-a716-446655440000',
                revokedBy,
                reason: 'MANUAL_REVOCATION',
            },
        );

        expect(createResponse.status).toBe(201);
        expect(createResponse.body).toMatchObject({
            token_id: 'urn:cap:550e8400-e29b-41d4-a716-446655440000',
            revoked_by: revokedBy,
            reason: 'MANUAL_REVOCATION',
        });

        const getResponse = await makeRequest(
            serverUrl,
            'GET',
            '/api/v1/revocations/urn%3Acap%3A550e8400-e29b-41d4-a716-446655440000',
        );
        expect(getResponse.status).toBe(200);
        expect(getResponse.body).toMatchObject({
            revoked: true,
            reason: 'MANUAL_REVOCATION',
        });

        const listResponse = await makeRequest(
            serverUrl,
            'GET',
            '/api/v1/revocations',
        );
        expect(listResponse.status).toBe(200);
        expect(listResponse.body).toMatchObject({
            revocations: [
                {
                    token_id: 'urn:cap:550e8400-e29b-41d4-a716-446655440000',
                    revoked_by: revokedBy,
                    reason: 'MANUAL_REVOCATION',
                },
            ],
        });

        const missingResponse = await makeRequest(
            serverUrl,
            'GET',
            '/api/v1/revocations/urn%3Acap%3Amissing',
        );
        expect(missingResponse.status).toBe(200);
        expect(missingResponse.body).toEqual({ revoked: false });
    });
});
