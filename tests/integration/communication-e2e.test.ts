import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { generateKeyPair } from '../../packages/crypto/src/index.js';
import {
    createAgentIdentity,
    didKeyFromPublicKey,
    IdentityRegistry,
    registerIdentityRoutes,
} from '../../packages/identity/src/index.js';
import {
    createTestDatabase,
    createTestServer,
    makeRequest,
} from '../../packages/shared/src/index.js';
import {
    buildEnvelope,
    HandshakeInitiator,
    HandshakeResponder,
    HttpTransport,
    verifyEnvelope,
} from '../../packages/communication/src/index.js';
import type {
    AgentIdentityDocument,
    DID,
} from '../../packages/types/src/index.js';

const describeIfE2E =
    process.env.DATABASE_URL && process.env.ENABLE_SOCKET_TESTS === '1'
        ? describe
        : describe.skip;

describeIfE2E('communication e2e', () => {
    let cleanup: (() => Promise<void>) | undefined;
    let closeIdentityServer: (() => Promise<void>) | undefined;
    let identityServerUrl = '';
    let registry: IdentityRegistry;

    const transports: HttpTransport[] = [];

    beforeAll(async () => {
        const database = await createTestDatabase();
        cleanup = database.cleanup;
        registry = new IdentityRegistry(database.pool);
        const identityServer = await createTestServer((app) => {
            registerIdentityRoutes(app, registry);
        });
        closeIdentityServer = identityServer.close;
        identityServerUrl = identityServer.url;
    });

    afterAll(async () => {
        await Promise.all(
            transports.splice(0).map(async (transport) => transport.close()),
        );
        await closeIdentityServer?.();
        await cleanup?.();
    });

    it('registers identities, completes handshake, and verifies envelope exchange', async () => {
        const principal = generateKeyPair();
        const principalDid = didKeyFromPublicKey(
            Buffer.from(principal.publicKey, 'hex'),
        );
        const initiatorIdentity = createAgentIdentity({
            principalDid,
            principalPrivateKey: principal.privateKey,
            capabilities: ['INQUIRY', 'QUOTE'],
        });
        const responderIdentity = createAgentIdentity({
            principalDid,
            principalPrivateKey: principal.privateKey,
            capabilities: ['QUOTE', 'CONFIRM'],
        });

        await expect(
            makeRequest(
                identityServerUrl,
                'POST',
                '/api/v1/identities',
                initiatorIdentity.document,
            ),
        ).resolves.toMatchObject({
            status: 201,
            body: { did: initiatorIdentity.document.id },
        });
        await expect(
            makeRequest(
                identityServerUrl,
                'POST',
                '/api/v1/identities',
                responderIdentity.document,
            ),
        ).resolves.toMatchObject({
            status: 201,
            body: { did: responderIdentity.document.id },
        });

        const resolvePublicKey = async (did: DID) => {
            const response = await makeRequest(
                identityServerUrl,
                'GET',
                `/api/v1/identities/${encodeURIComponent(did)}`,
            );

            if (response.status !== 200) {
                return null;
            }

            const document = response.body as AgentIdentityDocument;
            return document.publicKey;
        };

        const serverTransport = new HttpTransport();
        transports.push(serverTransport);
        const responder = new HandshakeResponder({
            responderDid: responderIdentity.document.id,
            responderPrivateKey: responderIdentity.privateKey,
            verifyInitiator: () => Promise.resolve(true),
            resolvePublicKey,
            capabilities: ['QUOTE', 'CONFIRM'],
        });
        const port = await serverTransport.listen(0, async (incoming) => {
            if (incoming.messageType === 'HANDSHAKE_INIT') {
                return await responder.respond(incoming);
            }

            const verified = await verifyEnvelope(incoming, {
                resolvePublicKey,
                now: () => new Date(incoming.timestamp).getTime(),
            });
            if (!verified.valid) {
                throw new Error(
                    `incoming verification failed: ${verified.reason}`,
                );
            }

            return buildEnvelope({
                senderDid: responderIdentity.document.id,
                senderPrivateKey: responderIdentity.privateKey,
                recipientDid: initiatorIdentity.document.id,
                sessionId: incoming.header.sessionId,
                messageType: 'NEGOTIATION_RESPONSE',
                body: {
                    requestId: 'req-001',
                    status: 'SUCCESS',
                    data: { accepted: true },
                },
                sequenceNumber: 2,
            });
        });

        const clientTransport = new HttpTransport();
        const initiator = new HandshakeInitiator({
            initiatorDid: initiatorIdentity.document.id,
            initiatorPrivateKey: initiatorIdentity.privateKey,
            transport: clientTransport,
            resolvePublicKey,
            capabilities: ['INQUIRY', 'QUOTE'],
        });

        const handshake = await initiator.initiate({
            responderDid: responderIdentity.document.id,
            responderEndpoint: `http://127.0.0.1:${port}`,
        });

        const outbound = buildEnvelope({
            senderDid: initiatorIdentity.document.id,
            senderPrivateKey: initiatorIdentity.privateKey,
            recipientDid: responderIdentity.document.id,
            sessionId: handshake.sessionId,
            messageType: 'NEGOTIATION_REQUEST',
            body: {
                action: 'INQUIRY',
                params: { sku: 'SKU-001' },
                requestId: 'req-001',
            },
            sequenceNumber: 1,
        });

        const response = await clientTransport.send(
            outbound,
            `http://127.0.0.1:${port}`,
        );

        expect(handshake.negotiatedCapabilities).toEqual(['QUOTE']);
        expect(response).not.toBeNull();
        await expect(
            verifyEnvelope(response!, {
                resolvePublicKey,
                now: () => new Date(response!.timestamp).getTime(),
            }),
        ).resolves.toEqual({ valid: true });
        expect(response).toMatchObject({
            header: {
                sessionId: handshake.sessionId,
            },
            messageType: 'NEGOTIATION_RESPONSE',
        });
        await expect(
            registry.query(initiatorIdentity.document.id),
        ).resolves.toMatchObject({
            id: initiatorIdentity.document.id,
        });
    });
});
