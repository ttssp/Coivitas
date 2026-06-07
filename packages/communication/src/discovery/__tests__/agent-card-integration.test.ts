import { createServer } from 'node:http';
import { EventEmitter } from 'node:events';
import { afterEach, describe, expect, it } from 'vitest';
import express from 'express';
import { generateKeyPair } from '@coivitas/crypto';
import type {
    AgentIdentityDocument,
    DID,
    DocumentUpdatedEvent,
    Signature,
    Timestamp,
} from '@coivitas/types';
import { buildAgentCard, verifyAgentCard } from '../agent-card.js';
import { AgentCardService } from '../agent-card-service.js';
import { createAgentCardRoute } from '../agent-card-routes.js';

const describeIfSockets =
    process.env.ENABLE_SOCKET_TESTS === '1' ? describe : describe.skip;

function makeDoc(publicKey: string, version: number): AgentIdentityDocument {
    return {
        id: 'did:agent:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0' as DID,
        specVersion: '0.1.0',
        principalDid: 'did:key:z6Mkf5rGMoatrSj1f4CyvuHBeXJELe9y84QbdU6D' as DID,
        publicKey,
        bindingProof: {
            principalDid:
                'did:key:z6Mkf5rGMoatrSj1f4CyvuHBeXJELe9y84QbdU6D' as DID,
            agentDid:
                'did:agent:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0' as DID,
            issuedAt: '2026-04-01T00:00:00.000Z' as Timestamp,
            expiresAt: null,
            signature: 'a'.repeat(128) as unknown as Signature,
        },
        capabilities: ['INQUIRY'],
        serviceEndpoints: [
            {
                id: 'main',
                type: 'NegotiationEndpoint',
                url: 'https://agent.example.com',
            },
        ],
        createdAt: '2026-04-01T00:00:00.000Z' as Timestamp,
        updatedAt: '2026-04-15T10:00:00.000Z' as Timestamp,
        version,
    };
}

async function fetchJson(url: string): Promise<unknown> {
    const res = await fetch(url);
    return res.json();
}

describeIfSockets('AgentCard integration: GET /.well-known/agent.json', () => {
    let serverClose: (() => Promise<void>) | null = null;

    afterEach(async () => {
        if (serverClose) {
            await serverClose();
            serverClose = null;
        }
    });

    it('should return a valid signed AgentCard and verify it successfully', async () => {
        const { privateKey, publicKey } = generateKeyPair();
        const doc = makeDoc(publicKey, 1);
        const emitter = new EventEmitter();
        const service = new AgentCardService({
            agentDid: doc.id,
            buildCard: () => buildAgentCard({ doc, privateKey }),
            eventEmitter: emitter,
        });

        const app = express();
        app.get('/.well-known/agent.json', createAgentCardRoute(service));
        const httpServer = createServer(app);

        const port = await new Promise<number>((resolve) => {
            httpServer.listen(0, '127.0.0.1', () => {
                resolve((httpServer.address() as { port: number }).port);
            });
        });
        serverClose = () =>
            new Promise<void>((resolve) => httpServer.close(() => resolve()));

        const card = (await fetchJson(
            `http://127.0.0.1:${port}/.well-known/agent.json`,
        )) as AgentIdentityDocument;

        expect((card as unknown as { did: string }).did).toBe(doc.id);
        expect(
            (card as unknown as { documentVersion: number }).documentVersion,
        ).toBe(1);

        const valid = await verifyAgentCard(
            card as unknown as Parameters<typeof verifyAgentCard>[0],
            () => Promise.resolve(doc),
        );
        expect(valid).toBe(true);
    });

    it('should return updated AgentCard after key rotation (documentVersion incremented)', async () => {
        const { privateKey: pk1, publicKey: pubKey1 } = generateKeyPair();
        const { privateKey: pk2, publicKey: pubKey2 } = generateKeyPair();

        let currentDoc = makeDoc(pubKey1, 1);
        let currentPrivateKey = pk1;

        const emitter = new EventEmitter();
        const service = new AgentCardService({
            agentDid: currentDoc.id,
            buildCard: () =>
                buildAgentCard({
                    doc: currentDoc,
                    privateKey: currentPrivateKey,
                }),
            eventEmitter: emitter,
        });

        const app = express();
        app.get('/.well-known/agent.json', createAgentCardRoute(service));
        const httpServer = createServer(app);

        const port = await new Promise<number>((resolve) => {
            httpServer.listen(0, '127.0.0.1', () => {
                resolve((httpServer.address() as { port: number }).port);
            });
        });
        serverClose = () =>
            new Promise<void>((resolve) => httpServer.close(() => resolve()));

        const card1 = (await fetchJson(
            `http://127.0.0.1:${port}/.well-known/agent.json`,
        )) as Record<string, unknown>;
        expect(card1['documentVersion']).toBe(1);
        expect(card1['publicKey']).toBe(pubKey1);

        currentDoc = makeDoc(pubKey2, 2);
        currentPrivateKey = pk2;
        const event: DocumentUpdatedEvent = {
            did: currentDoc.id,
            newVersion: 2,
            changeType: 'key_rotation',
        };
        emitter.emit('documentUpdated', event);

        const card2 = (await fetchJson(
            `http://127.0.0.1:${port}/.well-known/agent.json`,
        )) as Record<string, unknown>;
        expect(card2['documentVersion']).toBe(2);
        expect(card2['publicKey']).toBe(pubKey2);

        const valid = await verifyAgentCard(
            card2 as unknown as Parameters<typeof verifyAgentCard>[0],
            () => Promise.resolve(currentDoc),
        );
        expect(valid).toBe(true);
    });
});
