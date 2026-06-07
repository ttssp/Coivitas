import { describe, expect, it } from 'vitest';
import { canonicalize, generateKeyPair, verify } from '@coivitas/crypto';
import type { AgentIdentityDocument, DID, Signature, Timestamp } from '@coivitas/types';
import { buildAgentCard, verifyAgentCard } from '../agent-card.js';

function makeDoc(overrides?: Partial<AgentIdentityDocument>): AgentIdentityDocument {
    const { publicKey } = generateKeyPair();
    return {
        id: 'did:agent:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0' as DID,
        specVersion: '0.1.0',
        principalDid: 'did:key:z6Mkf5rGMoatrSj1f4CyvuHBeXJELe9y84QbdU6D' as DID,
        publicKey,
        bindingProof: {
            principalDid: 'did:key:z6Mkf5rGMoatrSj1f4CyvuHBeXJELe9y84QbdU6D' as DID,
            agentDid: 'did:agent:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0' as DID,
            issuedAt: '2026-04-01T00:00:00.000Z' as Timestamp,
            expiresAt: null,
            signature: 'a'.repeat(128) as unknown as Signature,
        },
        capabilities: ['INQUIRY', 'QUOTE'],
        serviceEndpoints: [{ id: 'main', type: 'NegotiationEndpoint', url: 'https://agent.example.com/negotiate' }],
        createdAt: '2026-04-01T00:00:00.000Z' as Timestamp,
        updatedAt: '2026-04-15T10:00:00.000Z' as Timestamp,
        version: 1,
        ...overrides,
    };
}

describe('buildAgentCard', () => {
    it('should build a valid AgentCard with correct fields when all required fields are provided', () => {
        const { privateKey, publicKey } = generateKeyPair();
        const doc = makeDoc({ publicKey });

        const card = buildAgentCard({ doc, privateKey, displayName: 'Test Agent', description: 'desc' });

        expect(card.did).toBe(doc.id);
        expect(card.specVersion).toBe(doc.specVersion);
        expect(card.publicKey).toBe(doc.publicKey);
        expect(card.documentVersion).toBe(1);
        expect(card.capabilitiesDeclared).toEqual(['INQUIRY', 'QUOTE']);
        expect(card.serviceEndpoints).toEqual(doc.serviceEndpoints);
        expect(card.displayName).toBe('Test Agent');
        expect(card.description).toBe('desc');
        expect(card.signature).toMatch(/^[a-f0-9]{128}$/);
    });

    it('should build AgentCard without optional fields when displayName and description are omitted', () => {
        const { privateKey, publicKey } = generateKeyPair();
        const doc = makeDoc({ publicKey });

        const card = buildAgentCard({ doc, privateKey });

        expect(card.displayName).toBeUndefined();
        expect(card.description).toBeUndefined();
    });

    it('should default documentVersion to 1 when doc.version is undefined', () => {
        const { privateKey, publicKey } = generateKeyPair();
        const doc = makeDoc({ publicKey, version: undefined });

        const card = buildAgentCard({ doc, privateKey });

        expect(card.documentVersion).toBe(1);
    });

    it('should produce a valid Ed25519 signature verifiable by the corresponding public key', () => {
        const { privateKey, publicKey } = generateKeyPair();
        const doc = makeDoc({ publicKey });

        const card = buildAgentCard({ doc, privateKey });

        const { signature, ...payload } = card;
        const canonical = canonicalize(payload as Record<string, unknown>);
        const bytes = new TextEncoder().encode(canonical);
        const valid = verify(bytes, signature, publicKey);
        expect(valid).toBe(true);
    });

    it('should use empty arrays for capabilities and serviceEndpoints when doc fields are undefined', () => {
        const { privateKey, publicKey } = generateKeyPair();
        const doc = makeDoc({ publicKey, capabilities: undefined, serviceEndpoints: undefined });

        const card = buildAgentCard({ doc, privateKey });

        expect(card.capabilitiesDeclared).toEqual([]);
        expect(card.serviceEndpoints).toEqual([]);
    });
});

describe('verifyAgentCard', () => {
    it('should return true when signature and all derived fields match the authority document', async () => {
        const { privateKey, publicKey } = generateKeyPair();
        const doc = makeDoc({ publicKey });
        const card = buildAgentCard({ doc, privateKey });

        const result = await verifyAgentCard(card, () => Promise.resolve(doc));
        expect(result).toBe(true);
    });

    it('should return false when signature is tampered', async () => {
        const { privateKey, publicKey } = generateKeyPair();
        const doc = makeDoc({ publicKey });
        const card = buildAgentCard({ doc, privateKey });
        const tampered = { ...card, signature: 'b'.repeat(128) as unknown as Signature };

        const result = await verifyAgentCard(tampered, () => Promise.resolve(doc));
        expect(result).toBe(false);
    });

    it('should return false when publicKey in card differs from authority document', async () => {
        const { privateKey, publicKey } = generateKeyPair();
        const { publicKey: otherPublicKey } = generateKeyPair();
        const doc = makeDoc({ publicKey });
        const card = buildAgentCard({ doc, privateKey });
        const attacked = { ...card, publicKey: otherPublicKey };

        const result = await verifyAgentCard(attacked, () => Promise.resolve(doc));
        expect(result).toBe(false);
    });

    it('should return false when documentVersion in card differs from authority document', async () => {
        const { privateKey, publicKey } = generateKeyPair();
        const doc = makeDoc({ publicKey, version: 2 });
        const oldDoc = makeDoc({ publicKey, version: 1 });
        const card = buildAgentCard({ doc: oldDoc, privateKey });

        const result = await verifyAgentCard(card, () => Promise.resolve(doc));
        expect(result).toBe(false);
    });

    it('should return false when DID in card does not match authority document', async () => {
        const { privateKey, publicKey } = generateKeyPair();
        const doc = makeDoc({ publicKey });
        const card = buildAgentCard({ doc, privateKey });
        const wrongDid = { ...card, did: ('did:agent:' + '0'.repeat(40)) as DID };

        const result = await verifyAgentCard(wrongDid, () => Promise.resolve(doc));
        expect(result).toBe(false);
    });

    it('should return false when resolveDocument returns null (identity not found)', async () => {
        const { privateKey, publicKey } = generateKeyPair();
        const doc = makeDoc({ publicKey });
        const card = buildAgentCard({ doc, privateKey });

        const result = await verifyAgentCard(card, () => Promise.resolve(null));
        expect(result).toBe(false);
    });

    it('should return false when expectedDid is provided and card.did does not match', async () => {
        const { privateKey, publicKey } = generateKeyPair();
        const doc = makeDoc({ publicKey });
        const card = buildAgentCard({ doc, privateKey });

        const result = await verifyAgentCard(
            card,
            () => Promise.resolve(doc),
            ('did:agent:' + '1'.repeat(40)) as DID,
        );
        expect(result).toBe(false);
    });

    it('should return false when card.capabilitiesDeclared is a superset of doc.capabilities', async () => {
        const { privateKey, publicKey } = generateKeyPair();
        const restrictedDoc = makeDoc({ publicKey, capabilities: ['INQUIRY'] });
        const cardWithExtra = buildAgentCard({
            doc: { ...restrictedDoc, capabilities: ['INQUIRY', 'QUOTE'] },
            privateKey,
        });

        const result = await verifyAgentCard(cardWithExtra, () => Promise.resolve(restrictedDoc));
        expect(result).toBe(false);
    });

    it('should return false when publicKey in card is malformed causing verify to throw', async () => {
        const { privateKey, publicKey } = generateKeyPair();
        const doc = makeDoc({ publicKey });
        const card = buildAgentCard({ doc, privateKey });
        const badCard = { ...card, publicKey: 'not-a-valid-key' };

        const result = await verifyAgentCard(badCard, () => Promise.resolve(doc));
        expect(result).toBe(false);
    });

    it('should return false when card.did is not in valid did:agent format', async () => {
        const { privateKey, publicKey } = generateKeyPair();
        const doc = makeDoc({ publicKey });
        const card = buildAgentCard({ doc, privateKey });
        const badDid = { ...card, did: 'did:key:z6MkBadFormat' as DID };

        const result = await verifyAgentCard(badDid, () => Promise.resolve(doc));
        expect(result).toBe(false);
    });

    it('should return false when card.signature is not valid hex format', async () => {
        const { privateKey, publicKey } = generateKeyPair();
        const doc = makeDoc({ publicKey });
        const card = buildAgentCard({ doc, privateKey });
        const badSig = { ...card, signature: 'Z'.repeat(128) as unknown as Signature };

        const result = await verifyAgentCard(badSig, () => Promise.resolve(doc));
        expect(result).toBe(false);
    });

    it('should return true when doc has undefined version/capabilities/serviceEndpoints (uses defaults)', async () => {
        const { privateKey, publicKey } = generateKeyPair();
        const doc = makeDoc({ publicKey, version: undefined, capabilities: undefined, serviceEndpoints: undefined });
        const card = buildAgentCard({ doc, privateKey });

        const result = await verifyAgentCard(card, () => Promise.resolve(doc));
        expect(result).toBe(true);
    });

    it('should return false when card.specVersion differs from authority document', async () => {
        const { privateKey, publicKey } = generateKeyPair();
        const doc = makeDoc({ publicKey });
        const card = buildAgentCard({ doc, privateKey });
        const upgradedDoc = { ...doc, specVersion: '0.2.0' };

        const result = await verifyAgentCard(card, () => Promise.resolve(upgradedDoc));
        expect(result).toBe(false);
    });
});
