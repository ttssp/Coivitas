import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { generateKeyPair } from '../../packages/crypto/src/index.js';
import {
    createAgentIdentity,
    didKeyFromPublicKey,
    IdentityRegistry,
    issueCapabilityToken,
    registerIdentityRoutes,
    registerRevocationRoutes,
    resolveAgentDID,
    RevocationList,
    verifyBinding,
    verifyCapabilityToken,
} from '../../packages/identity/src/index.js';
import {
    createTestDatabase,
    createTestServer,
    makeRequest,
} from '../../packages/shared/src/index.js';
import type { Timestamp } from '../../packages/types/src/index.js';

const describeIfIdentityE2E =
    process.env.DATABASE_URL && process.env.ENABLE_SOCKET_TESTS === '1'
        ? describe
        : describe.skip;

describeIfIdentityE2E('identity e2e', () => {
    let cleanup: (() => Promise<void>) | undefined;
    let closeServer: (() => Promise<void>) | undefined;
    let serverUrl = '';

    beforeAll(async () => {
        const database = await createTestDatabase();
        cleanup = database.cleanup;
        const identities = new IdentityRegistry(database.pool);
        const revocations = new RevocationList(database.pool);

        const server = await createTestServer((app) => {
            registerIdentityRoutes(app, identities);
            registerRevocationRoutes(app, revocations);
        });

        serverUrl = server.url;
        closeServer = server.close;
    });

    afterAll(async () => {
        await closeServer?.();
        await cleanup?.();
    });

    it('covers principal keys, identity registration, resolution, token issuance, and revocation over real HTTP', async () => {
        const alice = generateKeyPair();
        const bob = generateKeyPair();
        const aliceDid = didKeyFromPublicKey(
            Buffer.from(alice.publicKey, 'hex'),
        );
        const bobDid = didKeyFromPublicKey(Buffer.from(bob.publicKey, 'hex'));

        const agentA = createAgentIdentity({
            principalDid: aliceDid,
            principalPrivateKey: alice.privateKey,
            capabilities: ['INQUIRY', 'CONFIRM'],
            serviceEndpoints: [
                {
                    id: 'negotiation',
                    type: 'NegotiationEndpoint',
                    // the schema enforces ^https:// (identity.schema.json, frozen format).
                    // This case does not actually request the endpoint; it is only here to satisfy the Ajv pattern check.
                    url: 'https://example.test/agents/a',
                },
            ],
        });
        const agentB = createAgentIdentity({
            principalDid: bobDid,
            principalPrivateKey: bob.privateKey,
            capabilities: ['QUOTE', 'RECORD'],
            serviceEndpoints: [
                {
                    id: 'negotiation',
                    type: 'NegotiationEndpoint',
                    url: 'https://example.test/agents/b',
                },
            ],
        });

        expect(verifyBinding(agentA.document.bindingProof)).toBe(true);
        expect(verifyBinding(agentB.document.bindingProof)).toBe(true);

        await expect(
            makeRequest(
                serverUrl,
                'POST',
                '/api/v1/identities',
                agentA.document,
            ),
        ).resolves.toMatchObject({
            status: 201,
            body: { did: agentA.document.id },
        });
        await expect(
            makeRequest(
                serverUrl,
                'POST',
                '/api/v1/identities',
                agentB.document,
            ),
        ).resolves.toMatchObject({
            status: 201,
            body: { did: agentB.document.id },
        });

        await expect(
            resolveAgentDID(agentA.document.id, serverUrl),
        ).resolves.toEqual(agentA.document);
        await expect(
            resolveAgentDID(agentB.document.id, serverUrl),
        ).resolves.toEqual(agentB.document);

        const token = issueCapabilityToken({
            issuerDid: aliceDid,
            issuedTo: agentA.document.id,
            capabilities: [
                {
                    action: 'INQUIRY',
                    scope: {
                        type: 'allowlist',
                        field: 'sku',
                        values: ['SKU-001'],
                    },
                },
            ],
            expiresAt: '2026-04-04T08:00:00.000Z' as Timestamp,
            // token-issuer requires revocationUrl to start with https:// (token-issuer.ts:91).
            // This URL is only embedded in the token itself and does not affect the actual HTTP request path of the subsequent makeRequest().
            revocationUrl: 'https://example.test/api/v1/revocations/{id}',
            issuerPrivateKey: alice.privateKey,
            issuedAt: '2026-04-03T08:00:00.000Z' as Timestamp,
        });

        expect(
            verifyCapabilityToken(
                token,
                '2026-04-03T08:00:01.000Z' as Timestamp,
            ),
        ).toEqual({ valid: true });

        const revokeResponse = await makeRequest(
            serverUrl,
            'POST',
            '/api/v1/revocations',
            {
                tokenId: token.id,
                revokedBy: aliceDid,
                reason: 'MANUAL_REVOCATION',
            },
        );
        expect(revokeResponse.status).toBe(201);

        const statusResponse = await makeRequest(
            serverUrl,
            'GET',
            `/api/v1/revocations/${encodeURIComponent(token.id)}`,
        );
        expect(statusResponse.status).toBe(200);
        expect(statusResponse.body).toMatchObject({
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
                    token_id: token.id,
                    revoked_by: aliceDid,
                    reason: 'MANUAL_REVOCATION',
                },
            ],
        });
    });
});
