import { describe, expect, it, vi, beforeEach } from 'vitest';
import { generateKeyPair } from '@coivitas/crypto';
import { buildAgentCard } from '../agent-card.js';
import { DefaultDiscoveryService, InMemoryAgentCardCache } from '../discovery-service.js';
import type {
    AgentCard,
    AgentIdentityDocument,
    DID,
    FederatedResolver,
    FederatedResolverMetrics,
    Signature,
    Timestamp,
} from '@coivitas/types';

// ── test fixture helpers ────────────────────────────────────────────────────

interface DocWithKey extends AgentIdentityDocument {
    _privateKey: string;
}

function makeDoc(overrides: Partial<AgentIdentityDocument> = {}): DocWithKey {
    const { privateKey, publicKey } = generateKeyPair();
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
        capabilities: ['INQUIRY'],
        serviceEndpoints: [{ id: 'ep1', type: 'NegotiationEndpoint', url: 'https://agent.example.com' }],
        createdAt: '2026-04-01T00:00:00.000Z' as Timestamp,
        updatedAt: '2026-04-15T10:00:00.000Z' as Timestamp,
        version: 1,
        _privateKey: privateKey,
        ...overrides,
    };
}

function makeFederatedResolver(doc: AgentIdentityDocument | null): {
    resolver: FederatedResolver;
    resolveSpy: ReturnType<typeof vi.fn>;
} {
    const resolveSpy = vi.fn().mockResolvedValue(doc);
    const resolver = {
        resolve: resolveSpy,
        invalidateCache: vi.fn(),
        getMetrics: vi.fn().mockReturnValue({} as FederatedResolverMetrics),
        close: vi.fn().mockResolvedValue(undefined),
    } as FederatedResolver;
    return { resolver, resolveSpy };
}

// ── tests: DefaultDiscoveryService.discoverFromEndpoint ──────────────────────

describe('DefaultDiscoveryService.discoverFromEndpoint', () => {
    beforeEach(() => vi.unstubAllGlobals());

    it('should fetch, verify, and return AgentCard when endpoint responds with valid card', async () => {
        const doc = makeDoc();
        const card = buildAgentCard({ doc, privateKey: doc._privateKey });
        const { resolver } = makeFederatedResolver(doc);

        vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
            ok: true,
            json: () => Promise.resolve(card),
        }));

        const service = new DefaultDiscoveryService({ resolver });
        const result = await service.discoverFromEndpoint('https://agent.example.com', doc.id);

        expect(result).toMatchObject({ did: doc.id });
    });

    it('should throw when endpoint returns non-ok HTTP status', async () => {
        const doc = makeDoc();
        const { resolver } = makeFederatedResolver(doc);

        vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: false, status: 404 }));

        const service = new DefaultDiscoveryService({ resolver });
        await expect(
            service.discoverFromEndpoint('https://agent.example.com')
        ).rejects.toThrow('404');
    });

    it('should throw when endpoint is unreachable (network error)', async () => {
        const doc = makeDoc();
        const { resolver } = makeFederatedResolver(doc);

        vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('ECONNREFUSED')));

        const service = new DefaultDiscoveryService({ resolver });
        await expect(
            service.discoverFromEndpoint('https://dead.example.com')
        ).rejects.toThrow('unreachable');
    });

    it('should throw when AgentCard signature is invalid', async () => {
        const doc = makeDoc();
        const card = buildAgentCard({ doc, privateKey: doc._privateKey });
        const tampered = { ...card, signature: 'f'.repeat(128) as unknown as typeof card.signature };
        const { resolver } = makeFederatedResolver(doc);

        vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, json: () => Promise.resolve(tampered) }));

        const service = new DefaultDiscoveryService({ resolver });
        await expect(
            service.discoverFromEndpoint('https://agent.example.com')
        ).rejects.toThrow('verification failed');
    });
});

// ── tests: InMemoryAgentCardCache ────────────────────────────────────────────

describe('InMemoryAgentCardCache', () => {
    it('should return null when cache is empty', () => {
        const cache = new InMemoryAgentCardCache();
        expect(cache.get('did:agent:' + 'a'.repeat(40) as DID)).toBeNull();
    });

    it('should return cached card before TTL expires', () => {
        const cache = new InMemoryAgentCardCache(5000);
        const did = 'did:agent:' + 'a'.repeat(40) as DID;
        const card = { did } as AgentCard;
        cache.set(did, card);
        expect(cache.get(did)).toBe(card);
    });

    it('should return null after TTL expires', async () => {
        const cache = new InMemoryAgentCardCache(50);
        const did = 'did:agent:' + 'b'.repeat(40) as DID;
        cache.set(did, { did } as AgentCard);
        await new Promise(r => setTimeout(r, 100));
        expect(cache.get(did)).toBeNull();
    });

    it('should invalidate specific DID', () => {
        const cache = new InMemoryAgentCardCache();
        const did = 'did:agent:' + 'c'.repeat(40) as DID;
        cache.set(did, { did } as AgentCard);
        cache.invalidate(did);
        expect(cache.get(did)).toBeNull();
    });

    it('should clear all entries', () => {
        const cache = new InMemoryAgentCardCache();
        const did1 = 'did:agent:' + 'a'.repeat(40) as DID;
        const did2 = 'did:agent:' + 'b'.repeat(40) as DID;
        cache.set(did1, { did: did1 } as AgentCard);
        cache.set(did2, { did: did2 } as AgentCard);
        cache.clear();
        expect(cache.get(did1)).toBeNull();
        expect(cache.get(did2)).toBeNull();
    });

    it('should respect per-entry custom ttlMs override', async () => {
        const cache = new InMemoryAgentCardCache(5000);
        const did = 'did:agent:' + 'd'.repeat(40) as DID;
        cache.set(did, { did } as AgentCard, 50);
        await new Promise(r => setTimeout(r, 100));
        expect(cache.get(did)).toBeNull();
    });
});

// ── tests: DefaultDiscoveryService.discover ──────────────────────────────────

describe('DefaultDiscoveryService.discover', () => {
    beforeEach(() => vi.unstubAllGlobals());

    it('should discover AgentCard by DID via first valid endpoint', async () => {
        const doc = makeDoc();
        const card = buildAgentCard({ doc, privateKey: doc._privateKey });
        const { resolver, resolveSpy } = makeFederatedResolver(doc);

        vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, json: () => Promise.resolve(card) }));

        const service = new DefaultDiscoveryService({ resolver });
        const result = await service.discover(doc.id);

        expect(result.did).toBe(doc.id);
        expect(resolveSpy).toHaveBeenCalledWith(doc.id);
    });

    it('should throw when DID not found in identity registry', async () => {
        const { resolver } = makeFederatedResolver(null);
        const service = new DefaultDiscoveryService({ resolver });
        await expect(
            service.discover('did:agent:' + '0'.repeat(40) as DID)
        ).rejects.toThrow('Identity not found');
    });

    it('should throw when no serviceEndpoints exist on identity document', async () => {
        const doc = makeDoc({ serviceEndpoints: [] });
        const { resolver } = makeFederatedResolver(doc);
        const service = new DefaultDiscoveryService({ resolver });
        await expect(service.discover(doc.id)).rejects.toThrow('No service endpoints');
    });

    it('should try next endpoint when first endpoint is unreachable', async () => {
        const doc = makeDoc({
            serviceEndpoints: [
                { id: 'ep1', type: 'NegotiationEndpoint', url: 'https://dead.example.com' },
                { id: 'ep2', type: 'NegotiationEndpoint', url: 'https://alive.example.com' },
            ],
        });
        const card = buildAgentCard({ doc, privateKey: doc._privateKey });
        const { resolver } = makeFederatedResolver(doc);

        let callCount = 0;
        const fetchImpl = (): Promise<{ ok: boolean; json: () => Promise<typeof card> }> => {
            callCount++;
            if (callCount === 1) throw new Error('ECONNREFUSED');
            return Promise.resolve({ ok: true, json: () => Promise.resolve(card) });
        };
        vi.stubGlobal('fetch', vi.fn().mockImplementation(fetchImpl));

        const service = new DefaultDiscoveryService({ resolver });
        const result = await service.discover(doc.id);
        expect(result.did).toBe(doc.id);
        expect(callCount).toBe(2);
    });

    it('should throw when all endpoints fail', async () => {
        const doc = makeDoc({
            serviceEndpoints: [{ id: 'ep1', type: 'NegotiationEndpoint', url: 'https://dead.example.com' }],
        });
        const { resolver } = makeFederatedResolver(doc);
        vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('ECONNREFUSED')));

        const service = new DefaultDiscoveryService({ resolver });
        await expect(service.discover(doc.id)).rejects.toThrow('All endpoints failed');
    });

    it('should reject card whose did does not match requested DID', async () => {
        const doc = makeDoc();
        const attackerDoc = makeDoc({
            id: 'did:agent:' + 'f'.repeat(40) as DID,
            serviceEndpoints: [{ id: 'ep1', type: 'NegotiationEndpoint', url: 'https://attacker.example.com' }],
        });
        const spoofedCard = buildAgentCard({ doc: attackerDoc, privateKey: attackerDoc._privateKey });
        const { resolver } = makeFederatedResolver(doc);

        vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, json: () => Promise.resolve(spoofedCard) }));

        const service = new DefaultDiscoveryService({ resolver });
        await expect(service.discover(doc.id)).rejects.toThrow('All endpoints failed');
    });

    it('should return cached card without calling resolver on second call', async () => {
        const doc = makeDoc();
        const card = buildAgentCard({ doc, privateKey: doc._privateKey });
        const { resolver, resolveSpy } = makeFederatedResolver(doc);
        const fetchMock = vi.fn().mockResolvedValue({ ok: true, json: () => Promise.resolve(card) });
        vi.stubGlobal('fetch', fetchMock);

        const service = new DefaultDiscoveryService({ resolver, cacheTtlMs: 10000 });
        const first = await service.discover(doc.id);
        // first call: resolve x2 (once to fetch endpoints, once inside verifyAgentCard to fetch the doc)
        const callsAfterFirst = resolveSpy.mock.calls.length;
        const second = await service.discover(doc.id);

        // cache hit: the second call no longer triggers any resolve
        expect(resolveSpy.mock.calls.length).toBe(callsAfterFirst);
        expect(second).toBe(first);
    });

    it('should re-fetch after invalidateCache', async () => {
        const doc = makeDoc();
        const card = buildAgentCard({ doc, privateKey: doc._privateKey });
        const { resolver, resolveSpy } = makeFederatedResolver(doc);
        vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, json: () => Promise.resolve(card) }));

        const service = new DefaultDiscoveryService({ resolver, cacheTtlMs: 10000 });
        await service.discover(doc.id);
        // first time: resolve x2 (endpoints + verifyAgentCard)
        const callsAfterFirst = resolveSpy.mock.calls.length;
        service.invalidateCache(doc.id);
        await service.discover(doc.id);

        // discovering again after invalidate: triggers the same number of resolves again
        expect(resolveSpy.mock.calls.length).toBe(callsAfterFirst * 2);
    });
});
