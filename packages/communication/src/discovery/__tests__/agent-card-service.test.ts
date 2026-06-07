import { describe, expect, it, vi } from 'vitest';
import { EventEmitter } from 'node:events';
import { generateKeyPair } from '@coivitas/crypto';
import type {
    AgentIdentityDocument,
    DID,
    DocumentUpdatedEvent,
    Signature,
    Timestamp,
} from '@coivitas/types';
import { buildAgentCard } from '../agent-card.js';
import { AgentCardService } from '../agent-card-service.js';

interface DocWithKey extends AgentIdentityDocument {
    _privateKey: string;
}

function makeDoc(version = 1): DocWithKey {
    const { privateKey, publicKey } = generateKeyPair();
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
        serviceEndpoints: [],
        createdAt: '2026-04-01T00:00:00.000Z' as Timestamp,
        updatedAt: '2026-04-15T10:00:00.000Z' as Timestamp,
        version,
        _privateKey: privateKey,
    };
}

describe('AgentCardService', () => {
    it('should return the cached AgentCard on second call without rebuilding', async () => {
        const doc = makeDoc();
        const buildSpy = vi.fn(() =>
            buildAgentCard({ doc, privateKey: doc._privateKey }),
        );
        const emitter = new EventEmitter();
        const service = new AgentCardService({
            agentDid: doc.id,
            buildCard: buildSpy,
            eventEmitter: emitter,
        });

        const card1 = await service.getCard();
        const card2 = await service.getCard();

        expect(buildSpy).toHaveBeenCalledTimes(1);
        expect(card1).toBe(card2);
    });

    it('should rebuild the AgentCard when a DocumentUpdatedEvent is emitted for the agent DID', async () => {
        const doc1 = makeDoc(1);
        let currentDoc = doc1;
        const buildSpy = vi.fn(() =>
            buildAgentCard({
                doc: currentDoc,
                privateKey: currentDoc._privateKey,
            }),
        );
        const emitter = new EventEmitter();
        const service = new AgentCardService({
            agentDid: doc1.id,
            buildCard: buildSpy,
            eventEmitter: emitter,
        });

        await service.getCard();
        expect(buildSpy).toHaveBeenCalledTimes(1);

        const doc2 = makeDoc(2);
        currentDoc = doc2;
        const event: DocumentUpdatedEvent = {
            did: doc1.id,
            newVersion: 2,
            changeType: 'key_rotation',
        };
        emitter.emit('documentUpdated', event);

        const card2 = await service.getCard();
        expect(buildSpy).toHaveBeenCalledTimes(2);
        expect(card2.documentVersion).toBe(2);
    });

    it('should NOT invalidate cache when DocumentUpdatedEvent is for a different DID', async () => {
        const doc = makeDoc();
        const buildSpy = vi.fn(() =>
            buildAgentCard({ doc, privateKey: doc._privateKey }),
        );
        const emitter = new EventEmitter();
        const service = new AgentCardService({
            agentDid: doc.id,
            buildCard: buildSpy,
            eventEmitter: emitter,
        });

        await service.getCard();
        expect(buildSpy).toHaveBeenCalledTimes(1);

        const otherEvent: DocumentUpdatedEvent = {
            did: ('did:agent:' + 'f'.repeat(40)) as DID,
            newVersion: 3,
            changeType: 'field_update',
        };
        emitter.emit('documentUpdated', otherEvent);

        await service.getCard();
        expect(buildSpy).toHaveBeenCalledTimes(1);
    });

    it('should invalidate cache manually via invalidate()', async () => {
        const doc = makeDoc();
        const buildSpy = vi.fn(() =>
            buildAgentCard({ doc, privateKey: doc._privateKey }),
        );
        const emitter = new EventEmitter();
        const service = new AgentCardService({
            agentDid: doc.id,
            buildCard: buildSpy,
            eventEmitter: emitter,
        });

        await service.getCard();
        service.invalidate();
        await service.getCard();

        expect(buildSpy).toHaveBeenCalledTimes(2);
    });
});
