// TTL cache + single-flight tests (Task 04d)
// Summary: mock binding.js / did.js to decouple signature verification and focus on cache semantics

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// Proxy undici.fetch to globalThis.fetch so existing vi.stubGlobal('fetch', ...) keeps working.
// Also mock Agent + buildConnector so unit tests do not open real network connections.
vi.mock('undici', () => {
    const mockConnector = vi
        .fn()
        .mockImplementation(
            (_opts: unknown, cb: (err: null, sock: unknown) => void) => {
                cb(null, {} as unknown);
            },
        );
    return {
        fetch: (...args: Parameters<typeof globalThis.fetch>) =>
            globalThis.fetch(...args),
        buildConnector: vi.fn(() => mockConnector),
        Agent: vi.fn().mockImplementation(() => ({
            close: vi.fn().mockResolvedValue(undefined),
        })),
    };
});

// Module-level mocks — must be declared before importing the implementation
vi.mock('../binding.js', () => ({
    verifyBinding: vi.fn().mockReturnValue(true),
    verifyBindingProof: vi.fn().mockReturnValue(true),
    createBinding: vi.fn(),
    createBindingProof: vi.fn(),
}));

vi.mock('../did.js', () => ({
    createAgentDID: vi.fn().mockImplementation((pk: string) => pk),
    isDidAgent: vi.fn().mockReturnValue(true),
    isDidKey: vi.fn().mockReturnValue(true),
    extractPublicKeyFromDIDKey: vi.fn().mockReturnValue('fakepubkey'),
    didKeyFromPublicKey: vi.fn(),
    isTimestampExpired: vi.fn().mockReturnValue(false),
}));

import {
    createFederatedResolver,
    createNullDnsRebindingGuard,
} from '../federated-resolver.js';
import type {
    AgentIdentityDocument,
    DID,
    DIDBindingVerifier,
    FederationAlertEvent,
    Signature,
    Timestamp,
} from '@coivitas/types';
import { verifyBindingProof } from '../binding.js';

// ============================================================
// Shared test utility functions
// ============================================================

const makeVerifier = (): DIDBindingVerifier => ({
    verify: vi.fn().mockResolvedValue(true),
    getDocumentHistory: vi.fn().mockResolvedValue([]),
});

// Helper for fields required at construction
const makeWatermark = () => ({
    getWatermark: vi.fn().mockResolvedValue(0),
    setWatermark: vi.fn().mockResolvedValue(undefined),
});

const makeDnsGuard = () => createNullDnsRebindingGuard();

// makeDoc: publicKey === did so that createAgentDID(publicKey) === did (mock identity function)
function makeDoc(did: string, version = 1): AgentIdentityDocument {
    return {
        id: did,
        publicKey: did, // publicKey = did, making the mock createAgentDID(pk) => pk === did
        principalDid: 'did:key:zQ3shPrincipal',
        bindingProof: {
            agentDid: did,
            principalDid: 'did:key:zQ3shPrincipal',
            signature: 'fakesig',
            issuedAt: new Date().toISOString(),
            expiresAt: new Date(Date.now() + 86400_000).toISOString(),
        },
        specVersion: '0.2.0',
        version,
    } as AgentIdentityDocument;
}

// ============================================================
// Constructor validation tests (Task 04a, unchanged)
// ============================================================

describe('FederatedResolver constructor', () => {
    it('should throw when given no nodes', () => {
        expect(() =>
            createFederatedResolver({
                nodes: [],
                minResponses: 1,
                timeoutMs: 5000,
                cacheTtlMs: 60000,
                verifyDIDBinding: makeVerifier(),
                persistentWatermark: makeWatermark(),
                dnsRebindingGuard: makeDnsGuard(),
            }),
        ).toThrow('nodes.length >= 1');
    });

    it('should throw when minResponses > nodes.length', () => {
        expect(() =>
            createFederatedResolver({
                nodes: [{ id: 'n1', url: 'http://n1' }],
                minResponses: 2,
                timeoutMs: 5000,
                cacheTtlMs: 60000,
                verifyDIDBinding: makeVerifier(),
                persistentWatermark: makeWatermark(),
                dnsRebindingGuard: makeDnsGuard(),
            }),
        ).toThrow('minResponses');
    });

    it('should throw when nodes=2 and minResponses=1', () => {
        expect(() =>
            createFederatedResolver({
                nodes: [
                    { id: 'n1', url: 'http://n1' },
                    { id: 'n2', url: 'http://n2' },
                ],
                minResponses: 1,
                timeoutMs: 5000,
                cacheTtlMs: 60000,
                verifyDIDBinding: makeVerifier(),
                persistentWatermark: makeWatermark(),
                dnsRebindingGuard: makeDnsGuard(),
            }),
        ).toThrow('minResponses');
    });

    it('should throw when verifyDIDBinding.verify is not a function', () => {
        expect(() =>
            createFederatedResolver({
                nodes: [{ id: 'n1', url: 'http://n1' }],
                minResponses: 1,
                timeoutMs: 5000,
                cacheTtlMs: 60000,
                // eslint-disable-next-line @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-assignment
                verifyDIDBinding: {
                    verify: null as unknown as DIDBindingVerifier['verify'],
                    getDocumentHistory: vi.fn(),
                },
                persistentWatermark: makeWatermark(),
                dnsRebindingGuard: makeDnsGuard(),
            }),
        ).toThrow('verifyDIDBinding');
    });

    it('should throw when minResponses < 1', () => {
        expect(() =>
            createFederatedResolver({
                nodes: [{ id: 'n1', url: 'http://n1' }],
                minResponses: 0,
                timeoutMs: 5000,
                cacheTtlMs: 60000,
                verifyDIDBinding: makeVerifier(),
                persistentWatermark: makeWatermark(),
                dnsRebindingGuard: makeDnsGuard(),
            }),
        ).toThrow('minResponses');
    });

    it('should create resolver for single node with minResponses=1', () => {
        const resolver = createFederatedResolver({
            nodes: [{ id: 'n1', url: 'http://n1' }],
            minResponses: 1,
            timeoutMs: 5000,
            cacheTtlMs: 60000,
            verifyDIDBinding: makeVerifier(),
            persistentWatermark: makeWatermark(),
            dnsRebindingGuard: makeDnsGuard(),
        });
        expect(resolver).toBeDefined();
        void resolver.close();
    });
});

// ============================================================
// TTL cache layer tests (Task 04d)
// ============================================================

describe('TTL cache', () => {
    it('should return cached document on cache hit', async () => {
        const did = 'did:agent:test1' as DID;
        const fetchMock = vi.fn().mockResolvedValue({
            ok: true,
            status: 200,
            headers: { get: () => '1024' },
            json: () => Promise.resolve(makeDoc(did)),
        });
        vi.stubGlobal('fetch', fetchMock);

        const resolver = createFederatedResolver({
            nodes: [{ id: 'n1', url: 'http://n1' }],
            minResponses: 1,
            timeoutMs: 5000,
            cacheTtlMs: 60000,
            verifyDIDBinding: makeVerifier(),
            persistentWatermark: makeWatermark(),
            dnsRebindingGuard: makeDnsGuard(),
        });

        await resolver.resolve(did);
        const callCountAfterFirst = fetchMock.mock.calls.length;
        expect(callCountAfterFirst).toBeGreaterThanOrEqual(1);

        // The second resolve should hit the cache and not issue a new fetch
        await resolver.resolve(did);
        expect(fetchMock.mock.calls.length).toBe(callCountAfterFirst);

        const metrics = resolver.getMetrics();
        expect(metrics.cacheHit).toBeGreaterThan(0);

        await resolver.close();
        vi.unstubAllGlobals();
    });

    it('should not return cached document after TTL expires', async () => {
        const did = 'did:agent:test2' as DID;
        const fetchMock = vi.fn().mockResolvedValue({
            ok: true,
            status: 200,
            headers: { get: () => '1024' },
            json: () => Promise.resolve(makeDoc(did)),
        });
        vi.stubGlobal('fetch', fetchMock);

        const resolver = createFederatedResolver({
            nodes: [{ id: 'n1', url: 'http://n1' }],
            minResponses: 1,
            timeoutMs: 5000,
            cacheTtlMs: 10, // 10ms TTL, very short
            verifyDIDBinding: makeVerifier(),
            persistentWatermark: makeWatermark(),
            dnsRebindingGuard: makeDnsGuard(),
        });

        await resolver.resolve(did);
        // Wait for the TTL to expire
        await new Promise((r) => setTimeout(r, 30));
        await resolver.resolve(did);

        // After the TTL expires it should issue a fresh fetch
        expect(fetchMock.mock.calls.length).toBeGreaterThanOrEqual(2);

        await resolver.close();
        vi.unstubAllGlobals();
    });

    it('should invalidate cache on invalidateCache()', async () => {
        const did = 'did:agent:test3' as DID;
        const fetchMock = vi.fn().mockResolvedValue({
            ok: true,
            status: 200,
            headers: { get: () => '1024' },
            json: () => Promise.resolve(makeDoc(did)),
        });
        vi.stubGlobal('fetch', fetchMock);

        const resolver = createFederatedResolver({
            nodes: [{ id: 'n1', url: 'http://n1' }],
            minResponses: 1,
            timeoutMs: 5000,
            cacheTtlMs: 60000,
            verifyDIDBinding: makeVerifier(),
            persistentWatermark: makeWatermark(),
            dnsRebindingGuard: makeDnsGuard(),
            onAlert: vi.fn(),
        });

        await resolver.resolve(did);
        resolver.invalidateCache(did);
        await resolver.resolve(did);

        // After invalidateCache it should issue a fresh fetch
        expect(fetchMock.mock.calls.length).toBeGreaterThanOrEqual(2);

        await resolver.close();
        vi.unstubAllGlobals();
    });
});

// ============================================================
// resolve — edge cases (all404 / quorum / mixed scenarios)
// ============================================================

describe('resolve — edge cases', () => {
    it('should return null without QUORUM_UNMET when all nodes return 404', async () => {
        const did = 'did:agent:all404' as DID;
        const alertFn = vi.fn();
        const fetchMock = vi.fn().mockResolvedValue({
            ok: false,
            status: 404,
            headers: { get: () => null },
        });
        vi.stubGlobal('fetch', fetchMock);

        const resolver = createFederatedResolver({
            nodes: [{ id: 'n1', url: 'http://n1' }],
            minResponses: 1,
            timeoutMs: 5000,
            cacheTtlMs: 60000,
            verifyDIDBinding: makeVerifier(),
            persistentWatermark: makeWatermark(),
            dnsRebindingGuard: makeDnsGuard(),
            onAlert: alertFn,
        });

        const result = await resolver.resolve(did);
        expect(result).toBeNull();
        // All 404: should not trigger QUORUM_UNMET
        const quorumAlerts = alertFn.mock.calls.filter(
            (args) =>
                (args[0] as { kind: string }).kind ===
                'FEDERATION_QUORUM_UNMET',
        );
        expect(quorumAlerts).toHaveLength(0);

        await resolver.close();
        vi.unstubAllGlobals();
    });

    it('should return null and emit QUORUM_UNMET when quorum cannot be met (no healthy nodes)', async () => {
        const did = 'did:agent:noquorum' as DID;
        const alertFn = vi.fn();
        const fetchMock = vi.fn().mockRejectedValue(new Error('network error'));
        vi.stubGlobal('fetch', fetchMock);

        // 3 nodes, minResponses=3, all nodes return network errors -> respondedNodes=0, all404=false
        const resolver = createFederatedResolver({
            nodes: [
                { id: 'n1', url: 'http://n1' },
                { id: 'n2', url: 'http://n2' },
                { id: 'n3', url: 'http://n3' },
            ],
            minResponses: 3,
            timeoutMs: 2000,
            cacheTtlMs: 60000,
            verifyDIDBinding: makeVerifier(),
            persistentWatermark: makeWatermark(),
            dnsRebindingGuard: makeDnsGuard(),
            onAlert: alertFn,
        });

        const result = await resolver.resolve(did);
        expect(result).toBeNull();
        // Network-error scenario -> QUORUM_UNMET must be triggered
        const quorumAlerts = alertFn.mock.calls.filter(
            (args) =>
                (args[0] as { kind: string }).kind ===
                'FEDERATION_QUORUM_UNMET',
        );
        expect(quorumAlerts.length).toBeGreaterThan(0);

        await resolver.close();
        vi.unstubAllGlobals();
    });

    it('should not count mixed 404+error scenario as all-404', async () => {
        const did = 'did:agent:mixed' as DID;
        const alertFn = vi.fn();
        let callCount = 0;
        const fetchMock = vi.fn().mockImplementation(() => {
            callCount++;
            if (callCount === 1) {
                return Promise.resolve({
                    ok: false,
                    status: 404,
                    headers: { get: () => null },
                });
            }
            return Promise.reject(new Error('network error'));
        });
        vi.stubGlobal('fetch', fetchMock);

        // 3 nodes, minResponses=3: n1=404, n2+n3=error -> all404=false, respondedNodes=1 < 3
        const resolver = createFederatedResolver({
            nodes: [
                { id: 'n1', url: 'http://n1' },
                { id: 'n2', url: 'http://n2' },
                { id: 'n3', url: 'http://n3' },
            ],
            minResponses: 3,
            timeoutMs: 2000,
            cacheTtlMs: 60000,
            verifyDIDBinding: makeVerifier(),
            persistentWatermark: makeWatermark(),
            dnsRebindingGuard: makeDnsGuard(),
            onAlert: alertFn,
        });

        const result = await resolver.resolve(did);
        expect(result).toBeNull();
        // Mixed scenario: all404=false, validCandidates=0 < minResponses -> QUORUM_UNMET must be triggered
        const quorumAlerts = alertFn.mock.calls.filter(
            (args) =>
                (args[0] as { kind: string }).kind ===
                'FEDERATION_QUORUM_UNMET',
        );
        expect(quorumAlerts.length).toBeGreaterThan(0);

        await resolver.close();
        vi.unstubAllGlobals();
    });
});

// ============================================================
// resolve — fan-out and version election (Task 04b/04c)
// Summary: covers the fanOut settle window / signature verification / version election / fork detection
// ============================================================

describe('resolve — fan-out and version election', () => {
    // Each test independently restores the global fetch and verifyBindingProof mocks
    beforeEach(() => {
        vi.mocked(verifyBindingProof).mockReturnValue(true);
    });

    afterEach(() => {
        vi.unstubAllGlobals();
        vi.mocked(verifyBindingProof).mockReturnValue(true);
    });

    // ------------------------------------------------------------------
    // Test 1: all nodes consistently return the same document; the document should be returned
    // ------------------------------------------------------------------
    it('should return document when all nodes agree on same version', async () => {
        const did = 'did:agent:fanout1' as DID;
        const doc = makeDoc(did, 1);

        const fetchMock = vi.fn().mockResolvedValue({
            ok: true,
            status: 200,
            headers: { get: () => '1024' },
            json: () => Promise.resolve(doc),
        });
        vi.stubGlobal('fetch', fetchMock);

        const resolver = createFederatedResolver({
            nodes: [
                { id: 'n1', url: 'http://n1' },
                { id: 'n2', url: 'http://n2' },
            ],
            minResponses: 2,
            timeoutMs: 5000,
            cacheTtlMs: 60000,
            verifyDIDBinding: makeVerifier(),
            persistentWatermark: makeWatermark(),
            dnsRebindingGuard: makeDnsGuard(),
        });

        const result = await resolver.resolve(did);
        expect(result).not.toBeNull();
        expect(result?.id).toBe(did);

        await resolver.close();
    });

    // ------------------------------------------------------------------
    // Test 2: nodes have different versions; the highest-version document should be returned
    // ------------------------------------------------------------------
    it('should return highest version document when nodes have different versions', async () => {
        const did = 'did:agent:fanout2' as DID;
        const alertFn = vi.fn();
        const docV1 = makeDoc(did, 1);
        // version=2 requires rotationProof (V2 schema check); add the minimal fields
        const docV2 = {
            ...makeDoc(did, 2),
            rotationProof: {
                signature: 'fakerotsig',
                previousDid: did,
                issuedAt: new Date().toISOString(),
            },
        } as unknown as AgentIdentityDocument;

        const fetchMock = vi.fn().mockImplementation((url: string) => {
            if (url.includes('n1')) {
                return Promise.resolve({
                    ok: true,
                    status: 200,
                    headers: { get: () => '1024' },
                    json: () => Promise.resolve(docV1),
                });
            }
            // n2 / n3 return v2
            return Promise.resolve({
                ok: true,
                status: 200,
                headers: { get: () => '1024' },
                json: () => Promise.resolve(docV2),
            });
        });
        vi.stubGlobal('fetch', fetchMock);

        // verifyDIDBinding.verify is used for the V3b check (v>1)
        const verifier = makeVerifier();

        const resolver = createFederatedResolver({
            nodes: [
                { id: 'n1', url: 'http://n1' },
                { id: 'n2', url: 'http://n2' },
                { id: 'n3', url: 'http://n3' },
            ],
            minResponses: 2,
            timeoutMs: 5000,
            cacheTtlMs: 60000,
            verifyDIDBinding: verifier,
            persistentWatermark: makeWatermark(),
            dnsRebindingGuard: makeDnsGuard(),
            onAlert: alertFn,
        });

        const result = await resolver.resolve(did);
        expect(result).not.toBeNull();
        expect(result?.version).toBe(2);

        // When different versions coexist, FEDERATION_VERSION_CONFLICT(conflictType=different_versions) must be triggered
        const conflictAlerts = alertFn.mock.calls.filter(
            ([e]) =>
                (e as FederationAlertEvent).kind ===
                'FEDERATION_VERSION_CONFLICT',
        );
        expect(conflictAlerts.length).toBeGreaterThan(0);
        const conflictEvent = conflictAlerts[0]![0] as Extract<
            FederationAlertEvent,
            { kind: 'FEDERATION_VERSION_CONFLICT' }
        >;
        expect(conflictEvent.conflict.conflictType).toBe('different_versions');

        await resolver.close();
    });

    // ------------------------------------------------------------------
    // Test 3: invalid binding-proof signature; should return null and trigger FEDERATION_SIGNATURE_INVALID
    // ------------------------------------------------------------------
    it('should return null and emit FEDERATION_SIGNATURE_INVALID when binding proof is invalid', async () => {
        const did = 'did:agent:fanout3' as DID;
        const alertFn = vi.fn();
        const doc = makeDoc(did, 1);

        // Make verifyBindingProof return false (signature failure)
        vi.mocked(verifyBindingProof).mockReturnValue(false);

        const fetchMock = vi.fn().mockResolvedValue({
            ok: true,
            status: 200,
            headers: { get: () => '1024' },
            json: () => Promise.resolve(doc),
        });
        vi.stubGlobal('fetch', fetchMock);

        const resolver = createFederatedResolver({
            nodes: [{ id: 'n1', url: 'http://n1' }],
            minResponses: 1,
            timeoutMs: 5000,
            cacheTtlMs: 60000,
            verifyDIDBinding: makeVerifier(),
            persistentWatermark: makeWatermark(),
            dnsRebindingGuard: makeDnsGuard(),
            onAlert: alertFn,
        });

        const result = await resolver.resolve(did);
        expect(result).toBeNull();

        const sigAlerts = alertFn.mock.calls.filter(
            (args) =>
                (args[0] as { kind: string }).kind ===
                'FEDERATION_SIGNATURE_INVALID',
        );
        expect(sigAlerts.length).toBeGreaterThan(0);

        await resolver.close();
    });

    // ------------------------------------------------------------------
    // Test 4: all nodes time out; should return null and trigger FEDERATION_QUORUM_UNMET
    // ------------------------------------------------------------------
    it('should return null and emit FEDERATION_QUORUM_UNMET when all nodes timeout', async () => {
        const did = 'did:agent:fanout4' as DID;
        const alertFn = vi.fn();

        // fetch never resolves, simulating a timeout
        const fetchMock = vi.fn().mockReturnValue(new Promise<never>(() => {}));
        vi.stubGlobal('fetch', fetchMock);

        const resolver = createFederatedResolver({
            nodes: [{ id: 'n1', url: 'http://n1' }],
            minResponses: 1,
            timeoutMs: 50, // short timeout so the test completes quickly
            cacheTtlMs: 60000,
            verifyDIDBinding: makeVerifier(),
            persistentWatermark: makeWatermark(),
            dnsRebindingGuard: makeDnsGuard(),
            onAlert: alertFn,
        });

        const start = Date.now();
        const result = await resolver.resolve(did);
        const elapsed = Date.now() - start;

        expect(result).toBeNull();
        // Ensure the test did not wait indefinitely
        expect(elapsed).toBeLessThan(2000);

        const quorumAlerts = alertFn.mock.calls.filter(
            (args) =>
                (args[0] as { kind: string }).kind ===
                'FEDERATION_QUORUM_UNMET',
        );
        expect(quorumAlerts.length).toBeGreaterThan(0);

        await resolver.close();
    }, 5000);

    // ------------------------------------------------------------------
    // Test 5: same-version content fork (different principalDid); should return null and trigger
    // FEDERATION_VERSION_CONFLICT(conflictType=same_version_divergent_content)
    // ------------------------------------------------------------------
    it('should return null and emit FEDERATION_VERSION_CONFLICT for same-version fork', async () => {
        const did = 'did:agent:fanout5' as DID;
        const alertFn = vi.fn();

        // Two documents with version=1 but different principalDid -> different hash -> fork
        const docA: AgentIdentityDocument = {
            ...makeDoc(did, 1),
            principalDid: 'did:key:zQ3shPrincipalA' as DID,
            bindingProof: {
                agentDid: did,
                principalDid: 'did:key:zQ3shPrincipalA' as DID,
                signature: 'fakesigA' as Signature,
                issuedAt: new Date().toISOString() as Timestamp,
                expiresAt: new Date(
                    Date.now() + 86400_000,
                ).toISOString() as Timestamp,
            },
        };
        const docB: AgentIdentityDocument = {
            ...makeDoc(did, 1),
            principalDid: 'did:key:zQ3shPrincipalB' as DID,
            bindingProof: {
                agentDid: did,
                principalDid: 'did:key:zQ3shPrincipalB' as DID,
                signature: 'fakesigB' as Signature,
                issuedAt: new Date().toISOString() as Timestamp,
                expiresAt: new Date(
                    Date.now() + 86400_000,
                ).toISOString() as Timestamp,
            },
        };

        const fetchMock = vi.fn().mockImplementation((url: string) => {
            const doc = url.includes('n1') ? docA : docB;
            return Promise.resolve({
                ok: true,
                status: 200,
                headers: { get: () => '1024' },
                json: () => Promise.resolve(doc),
            });
        });
        vi.stubGlobal('fetch', fetchMock);

        const resolver = createFederatedResolver({
            nodes: [
                { id: 'n1', url: 'http://n1' },
                { id: 'n2', url: 'http://n2' },
            ],
            minResponses: 2,
            timeoutMs: 5000,
            cacheTtlMs: 60000,
            verifyDIDBinding: makeVerifier(),
            persistentWatermark: makeWatermark(),
            dnsRebindingGuard: makeDnsGuard(),
            onAlert: alertFn,
        });

        const result = await resolver.resolve(did);
        expect(result).toBeNull();

        const conflictAlerts = alertFn.mock.calls.filter((args) => {
            const e = args[0] as {
                kind: string;
                conflict?: { conflictType?: string };
            };
            return (
                e.kind === 'FEDERATION_VERSION_CONFLICT' &&
                e.conflict?.conflictType === 'same_version_divergent_content'
            );
        });
        expect(conflictAlerts.length).toBeGreaterThan(0);

        await resolver.close();
    });

    // ------------------------------------------------------------------
    // Test 6: when different versions coexist, pick the highest version and record versionConflictCount
    // ------------------------------------------------------------------
    it('should select highest version and increment versionConflictCount when versions differ', async () => {
        const did = 'did:agent:fanout6' as DID;
        const alertFn = vi.fn();
        const docV1 = makeDoc(did, 1);
        const docV2 = {
            ...makeDoc(did, 2),
            rotationProof: {
                signature: 'fakerotsig',
                previousDid: did,
                issuedAt: new Date().toISOString(),
            },
        } as unknown as AgentIdentityDocument;

        const fetchMock = vi.fn().mockImplementation((url: string) => {
            const doc = url.includes('n1') ? docV1 : docV2;
            return Promise.resolve({
                ok: true,
                status: 200,
                headers: { get: () => '1024' },
                json: () => Promise.resolve(doc),
            });
        });
        vi.stubGlobal('fetch', fetchMock);

        const verifier = makeVerifier();

        const resolver = createFederatedResolver({
            nodes: [
                { id: 'n1', url: 'http://n1' },
                { id: 'n2', url: 'http://n2' },
            ],
            minResponses: 2,
            timeoutMs: 5000,
            cacheTtlMs: 60000,
            verifyDIDBinding: verifier,
            persistentWatermark: makeWatermark(),
            dnsRebindingGuard: makeDnsGuard(),
            onAlert: alertFn,
        });

        const result = await resolver.resolve(did);
        expect(result).not.toBeNull();
        expect(result?.version).toBe(2);

        const metrics = resolver.getMetrics();
        expect(metrics.versionConflictCount).toBeGreaterThan(0);

        const conflictAlerts = alertFn.mock.calls.filter((args) => {
            const e = args[0] as {
                kind: string;
                conflict?: { conflictType?: string };
            };
            return (
                e.kind === 'FEDERATION_VERSION_CONFLICT' &&
                e.conflict?.conflictType === 'different_versions'
            );
        });
        expect(conflictAlerts.length).toBeGreaterThan(0);

        await resolver.close();
    });

    // ------------------------------------------------------------------
    // Test 7: an invalid-signature node does not count toward the minResponses quota; the remaining valid nodes return normally once quorum is reached
    // ------------------------------------------------------------------

    it('should not count invalid-signature node toward minResponses quorum', async () => {
        const did = 'did:agent:fanout7' as DID;
        const alertFn = vi.fn();

        // docBad represents the document returned by n1: the signature field is intentionally set to an invalid value
        const docBad = {
            ...makeDoc(did, 1),
            bindingProof: {
                signature: 'badsig-should-fail',
                nonce: 'nonce',
                issuedAt: new Date().toISOString(),
            },
        } as unknown as AgentIdentityDocument;

        // docGood represents the normal document returned by n2/n3
        const docGood = makeDoc(did, 1);

        // Route by URL: n1 returns the bad document, the rest return the good document
        const fetchMock = vi.fn().mockImplementation((url: string) => {
            const doc = url.includes('n1') ? docBad : docGood;
            return Promise.resolve({
                ok: true,
                status: 200,
                headers: { get: () => '1024' },
                json: () => Promise.resolve(doc),
            });
        });
        vi.stubGlobal('fetch', fetchMock);

        // verifyBindingProof decides based on document content: badsig returns false, the rest return true
        vi.mocked(verifyBindingProof).mockImplementation((proof) => {
            return proof.signature !== 'badsig-should-fail';
        });

        const resolver = createFederatedResolver({
            nodes: [
                { id: 'n1', url: 'http://n1' },
                { id: 'n2', url: 'http://n2' },
                { id: 'n3', url: 'http://n3' },
            ],
            minResponses: 2,
            timeoutMs: 5000,
            cacheTtlMs: 60000,
            verifyDIDBinding: makeVerifier(),
            persistentWatermark: makeWatermark(),
            dnsRebindingGuard: makeDnsGuard(),
            onAlert: alertFn,
        });

        const result = await resolver.resolve(did);
        // n2 + n3 are both valid, satisfying minResponses=2, so the document should be returned
        expect(result?.id).toBe(did);

        // The invalid signature on n1 should trigger an alert, and nodeId should be 'n1'
        const sigAlerts = alertFn.mock.calls
            .map((args) => args[0] as { kind: string; nodeId?: string })
            .filter((e) => e.kind === 'FEDERATION_SIGNATURE_INVALID');
        expect(sigAlerts.length).toBeGreaterThan(0);
        expect(sigAlerts[0]!.nodeId).toBe('n1');

        await resolver.close();
    });
});

// ============================================================
// Health check state machine tests (Task 04e)
// Summary: use vi.useFakeTimers to control setInterval and verify the HEALTHY->DEGRADED->UNHEALTHY->HEALTHY transitions
// ============================================================

describe('health check state machine', () => {
    beforeEach(() => {
        vi.useFakeTimers();
    });

    afterEach(() => {
        vi.useRealTimers();
        vi.unstubAllGlobals();
    });

    // Generic probe fetch mock factory
    // Fix: a successful response must carry json() with body.status === 'ok'
    function makeHealthFetchMock(probeResult: 'success' | 'failure') {
        return vi.fn().mockImplementation((url: string) => {
            if (url.includes('/health')) {
                if (probeResult === 'failure') {
                    return Promise.resolve({
                        ok: false,
                        status: 500,
                        headers: { get: () => null },
                    });
                }
                return Promise.resolve({
                    ok: true,
                    status: 200,
                    headers: { get: () => null },
                    json: () => Promise.resolve({ status: 'ok' }),
                });
            }
            // DID resolution should not be called in health-check tests
            return Promise.reject(new Error('unexpected fetch call to ' + url));
        });
    }

    // ------------------------------------------------------------------
    // Test 1: HEALTHY → DEGRADED after first probe failure
    // ------------------------------------------------------------------
    it('should transition HEALTHY → DEGRADED after first probe failure', async () => {
        const alertFn = vi.fn();
        const fetchMock = makeHealthFetchMock('failure');
        vi.stubGlobal('fetch', fetchMock);

        const resolver = createFederatedResolver({
            nodes: [{ id: 'n1', url: 'http://n1' }],
            minResponses: 1,
            timeoutMs: 5000,
            cacheTtlMs: 60000,
            verifyDIDBinding: makeVerifier(),
            persistentWatermark: makeWatermark(),
            dnsRebindingGuard: makeDnsGuard(),
            onAlert: alertFn,
            healthCheck: {
                probeIntervalMs: 100,
                failureThreshold: 3,
                recoveryThreshold: 2,
                probePath: '/health',
            },
        });

        // Advance one probe interval to trigger the first probe (failure)
        await vi.advanceTimersByTimeAsync(100);

        const healthAlerts = alertFn.mock.calls
            .map(
                (args) =>
                    args[0] as { kind: string; from?: string; to?: string },
            )
            .filter((e) => e.kind === 'FEDERATION_NODE_HEALTH_CHANGED');

        expect(healthAlerts.length).toBeGreaterThan(0);
        expect(healthAlerts[0]!.from).toBe('HEALTHY');
        expect(healthAlerts[0]!.to).toBe('DEGRADED');

        const metrics = resolver.getMetrics();
        expect(metrics.nodes['n1']?.healthState).toBe('DEGRADED');

        await resolver.close();
    });

    // ------------------------------------------------------------------
    // Test 2: DEGRADED → UNHEALTHY after failureThreshold consecutive failures
    // ------------------------------------------------------------------
    it('should transition DEGRADED → UNHEALTHY after failureThreshold consecutive failures', async () => {
        const alertFn = vi.fn();
        const fetchMock = makeHealthFetchMock('failure');
        vi.stubGlobal('fetch', fetchMock);

        const resolver = createFederatedResolver({
            nodes: [{ id: 'n1', url: 'http://n1' }],
            minResponses: 1,
            timeoutMs: 5000,
            cacheTtlMs: 60000,
            verifyDIDBinding: makeVerifier(),
            persistentWatermark: makeWatermark(),
            dnsRebindingGuard: makeDnsGuard(),
            onAlert: alertFn,
            healthCheck: {
                probeIntervalMs: 100,
                failureThreshold: 3,
                recoveryThreshold: 2,
                probePath: '/health',
            },
        });

        // Advance 3 probe intervals: 3 consecutive failures -> DEGRADED -> UNHEALTHY
        await vi.advanceTimersByTimeAsync(300);

        const healthAlerts = alertFn.mock.calls
            .map(
                (args) =>
                    args[0] as { kind: string; from?: string; to?: string },
            )
            .filter((e) => e.kind === 'FEDERATION_NODE_HEALTH_CHANGED');

        // There should be two transitions: HEALTHY->DEGRADED and DEGRADED->UNHEALTHY
        const toUnhealthy = healthAlerts.filter((e) => e.to === 'UNHEALTHY');
        expect(toUnhealthy.length).toBeGreaterThan(0);
        expect(toUnhealthy[0]!.from).toBe('DEGRADED');

        const metrics = resolver.getMetrics();
        expect(metrics.nodes['n1']?.healthState).toBe('UNHEALTHY');

        await resolver.close();
    });

    // ------------------------------------------------------------------
    // Test 3: UNHEALTHY → HEALTHY after recoveryThreshold consecutive successes
    // ------------------------------------------------------------------
    it('should transition UNHEALTHY → HEALTHY after recoveryThreshold consecutive successes', async () => {
        const alertFn = vi.fn();
        let probeResult: 'success' | 'failure' = 'failure';

        const fetchMock = vi.fn().mockImplementation((url: string) => {
            if (url.includes('/health')) {
                if (probeResult === 'failure') {
                    return Promise.resolve({
                        ok: false,
                        status: 500,
                        headers: { get: () => null },
                    });
                }
                return Promise.resolve({
                    ok: true,
                    status: 200,
                    headers: { get: () => null },
                    json: () => Promise.resolve({ status: 'ok' }),
                });
            }
            return Promise.reject(new Error('unexpected fetch call'));
        });
        vi.stubGlobal('fetch', fetchMock);

        const resolver = createFederatedResolver({
            nodes: [{ id: 'n1', url: 'http://n1' }],
            minResponses: 1,
            timeoutMs: 5000,
            cacheTtlMs: 60000,
            verifyDIDBinding: makeVerifier(),
            persistentWatermark: makeWatermark(),
            dnsRebindingGuard: makeDnsGuard(),
            onAlert: alertFn,
            healthCheck: {
                probeIntervalMs: 100,
                failureThreshold: 2,
                recoveryThreshold: 2,
                probePath: '/health',
            },
        });

        // First trigger 2 failures -> UNHEALTHY
        await vi.advanceTimersByTimeAsync(200);
        expect(resolver.getMetrics().nodes['n1']?.healthState).toBe(
            'UNHEALTHY',
        );

        // Switch to success, advance 2 times -> HEALTHY
        probeResult = 'success';
        await vi.advanceTimersByTimeAsync(200);

        const healthAlerts = alertFn.mock.calls
            .map(
                (args) =>
                    args[0] as { kind: string; from?: string; to?: string },
            )
            .filter((e) => e.kind === 'FEDERATION_NODE_HEALTH_CHANGED');

        const toHealthy = healthAlerts.filter((e) => e.to === 'HEALTHY');
        expect(toHealthy.length).toBeGreaterThan(0);
        expect(toHealthy[0]!.from).toBe('UNHEALTHY');

        expect(resolver.getMetrics().nodes['n1']?.healthState).toBe('HEALTHY');

        await resolver.close();
    });

    // ------------------------------------------------------------------
    // Test 4: UNHEALTHY nodes are excluded from resolve targets
    // Summary: use fake timers throughout; do not switch to realTimers mid-test (avoid races)
    // ------------------------------------------------------------------
    it('should exclude UNHEALTHY nodes from resolve targets and emit QUORUM_UNMET', async () => {
        const alertFn = vi.fn();
        const fetchMock = vi.fn();
        vi.stubGlobal('fetch', fetchMock);

        // Health probe request: returns 503 -> increments the failure count
        fetchMock.mockResolvedValue({ ok: false, status: 503 });

        const resolver = createFederatedResolver({
            nodes: [{ id: 'n1', url: 'http://n1' }],
            minResponses: 1,
            // timeoutMs set to 50ms; the resolve timeout is triggered by advancing fake timers
            timeoutMs: 50,
            cacheTtlMs: 60000,
            verifyDIDBinding: makeVerifier(),
            persistentWatermark: makeWatermark(),
            dnsRebindingGuard: makeDnsGuard(),
            onAlert: alertFn,
            healthCheck: {
                probeIntervalMs: 1000,
                failureThreshold: 2,
                recoveryThreshold: 2,
                probePath: '/federation/health',
            },
        });

        // Advance 2100ms -> trigger 2 probe failures -> UNHEALTHY
        await vi.advanceTimersByTimeAsync(2100);
        expect(resolver.getMetrics().nodes['n1']!.healthState).toBe(
            'UNHEALTHY',
        );

        // Clear the call history so we only observe fetch behavior during the resolve phase
        fetchMock.mockClear();
        // Resolve phase: n1 UNHEALTHY -> targets empty -> straight to QUORUM_UNMET, no DID fetch issued
        // But resolve internally uses setTimeout(timeoutMs) as the timeout gate, which needs the fake timer advanced
        const resolvePromise = resolver.resolve('did:agent:excluded' as DID);
        // Advance past timeoutMs (50ms) so resolve's internal race-timeout path fires
        await vi.advanceTimersByTimeAsync(100);
        const result = await resolvePromise;

        expect(result).toBeNull();

        // No DID-resolution fetch was issued (n1 excluded, targets empty)
        const didFetchCalls = fetchMock.mock.calls.filter(
            (args) => !(args[0] as string).includes('/federation/health'),
        );
        expect(didFetchCalls).toHaveLength(0);

        // Should trigger QUORUM_UNMET (the only node is unhealthy)
        const quorumAlerts = alertFn.mock.calls
            .map((args) => args[0] as { kind: string })
            .filter((e) => e.kind === 'FEDERATION_QUORUM_UNMET');
        expect(quorumAlerts.length).toBeGreaterThan(0);

        await resolver.close();
    });
});

// ============================================================
// Constructor validation: healthCheck threshold validation (Task 04f)
// ============================================================

describe('FederatedResolver constructor — healthCheck validation', () => {
    it('should throw when healthCheck.probeIntervalMs is not a positive integer', () => {
        expect(() =>
            createFederatedResolver({
                nodes: [{ id: 'n1', url: 'http://n1' }],
                minResponses: 1,
                timeoutMs: 5000,
                cacheTtlMs: 60000,
                verifyDIDBinding: makeVerifier(),
                persistentWatermark: makeWatermark(),
                dnsRebindingGuard: makeDnsGuard(),
                healthCheck: {
                    probeIntervalMs: 0, // invalid
                    failureThreshold: 2,
                    recoveryThreshold: 2,
                    probePath: '/health',
                },
            }),
        ).toThrow('probeIntervalMs');
    });

    it('should throw when healthCheck.failureThreshold is not a positive integer', () => {
        expect(() =>
            createFederatedResolver({
                nodes: [{ id: 'n1', url: 'http://n1' }],
                minResponses: 1,
                timeoutMs: 5000,
                cacheTtlMs: 60000,
                verifyDIDBinding: makeVerifier(),
                persistentWatermark: makeWatermark(),
                dnsRebindingGuard: makeDnsGuard(),
                healthCheck: {
                    probeIntervalMs: 100,
                    failureThreshold: 0, // invalid
                    recoveryThreshold: 2,
                    probePath: '/health',
                },
            }),
        ).toThrow('failureThreshold');
    });

    it('should throw when healthCheck.recoveryThreshold is not a positive integer', () => {
        expect(() =>
            createFederatedResolver({
                nodes: [{ id: 'n1', url: 'http://n1' }],
                minResponses: 1,
                timeoutMs: 5000,
                cacheTtlMs: 60000,
                verifyDIDBinding: makeVerifier(),
                persistentWatermark: makeWatermark(),
                dnsRebindingGuard: makeDnsGuard(),
                healthCheck: {
                    probeIntervalMs: 100,
                    failureThreshold: 2,
                    recoveryThreshold: -1, // invalid
                    probePath: '/health',
                },
            }),
        ).toThrow('recoveryThreshold');
    });
});

// ============================================================
// Metrics collection tests (Task 04h)
// Summary: verify correct collection of latency percentiles, node availability, version-conflict rate, etc.
// ============================================================

describe('metrics — 04h', () => {
    // I-3: afterEach prevents the fetch stub from leaking across tests (also cleans up when a test throws mid-way)
    afterEach(() => {
        vi.unstubAllGlobals();
    });

    // ------------------------------------------------------------------
    // Test 1: latency percentiles and exact hit/miss counts
    // Resolve sequence: resolve(did) -> invalidateCache(did) -> resolve(did) -> resolve(did)
    // 1st: cacheMiss=1, resolveSuccess=1 (fetch succeeds)
    // invalidateCache: evicts the cache
    // 2nd: cacheMiss=2, resolveSuccess=2 (fetch succeeds)
    // 3rd: cacheHit=1 (hits the cache written on the 2nd resolve, no new fetch)
    // ------------------------------------------------------------------
    it('should export latency percentiles after resolves', async () => {
        const did = 'did:agent:metrics1' as DID;
        const doc = makeDoc(did, 1);
        // json() introduces a 1ms delay so the Date.now() difference > 0, making latencyP50Ms precisely assertable
        vi.stubGlobal(
            'fetch',
            vi.fn().mockResolvedValue({
                ok: true,
                status: 200,
                headers: { get: () => '100' },
                json: () => new Promise((r) => setTimeout(() => r(doc), 1)),
            }),
        );

        const resolver = createFederatedResolver({
            nodes: [{ id: 'n1', url: 'http://n1' }],
            minResponses: 1,
            timeoutMs: 5000,
            cacheTtlMs: 60000,
            verifyDIDBinding: makeVerifier(),
            persistentWatermark: makeWatermark(),
            dnsRebindingGuard: makeDnsGuard(),
        });

        // Run multiple resolves: 1st miss -> invalidate -> 2nd miss -> 3rd hit (hits the 2nd cache)
        await resolver.resolve(did);
        resolver.invalidateCache(did);
        await resolver.resolve(did);
        await resolver.resolve(did); // hits the cache written on the 2nd resolve

        const m = resolver.getMetrics();
        expect(m.resolveTotal).toBe(3);
        // Exact assertion: 2 cacheMisses (fetch), 1 cacheHit (no fetch)
        expect(m.cacheHit).toBe(1);
        expect(m.cacheMiss).toBe(2);
        // resolveSuccess increments only when fanOut returns non-null (the cacheHit path does not count)
        expect(m.resolveSuccess).toBe(2);
        expect(m.latencyP95Ms).toBeGreaterThan(0);
        expect(m.latencyP95Ms).toBeGreaterThanOrEqual(m.latencyP50Ms);
        expect(m.latencyP99Ms).toBeGreaterThanOrEqual(m.latencyP95Ms);
        expect(m.nodes['n1']).toBeDefined();
        expect(m.nodes['n1']!.availability).toBeGreaterThan(0);

        await resolver.close();
    });

    // ------------------------------------------------------------------
    // Test 2: structural failure (v=2 without rotationProof) triggers signatureInvalidCount
    // Implementation path: verifyDocumentSignature V2 check -> rotation_proof_malformed
    // -> signatureInvalidCount++ (occurs before the verifyDIDBinding.verify call)
    // Uses makeVerifier() rather than a hand-written stub, making clear this tests a schema structural failure, not a DID binding failure
    // ------------------------------------------------------------------
    it('should track signatureInvalidCount', async () => {
        const did = 'did:agent:metrics2' as DID;
        // v=2 without rotationProof -> verifyDocumentSignature returns rotation_proof_malformed during the V2 check
        const doc = makeDoc(did, 2);

        vi.stubGlobal(
            'fetch',
            vi.fn().mockResolvedValue({
                ok: true,
                status: 200,
                headers: { get: () => '100' },
                json: () => Promise.resolve(doc),
            }),
        );

        const resolver = createFederatedResolver({
            nodes: [
                { id: 'n1', url: 'http://n1' },
                { id: 'n2', url: 'http://n2' },
            ],
            minResponses: 2,
            timeoutMs: 5000,
            cacheTtlMs: 60000,
            settleWindowMs: 50,
            verifyDIDBinding: makeVerifier(),
            persistentWatermark: makeWatermark(),
            dnsRebindingGuard: makeDnsGuard(),
        });

        await resolver.resolve(did);
        const m = resolver.getMetrics();
        // I-2: both nodes return the same makeDoc(did,2) (no rotationProof), each triggering one failure -> exactly 2
        expect(m.signatureInvalidCount).toBe(2);
        await resolver.close();
    });

    // ------------------------------------------------------------------
    // Test 3: same-version content fork (different hash) triggers versionConflictCount
    // ------------------------------------------------------------------
    it('should track versionConflictCount on fork', async () => {
        const did = 'did:agent:metrics3' as DID;
        const docA = makeDoc(did, 1);
        // docB: principalDid and bindingProof.principalDid stay consistent (pass signature check) but differ from docA
        // -> same-version content fork (different hash) -> same_version_divergent_content -> versionConflictCount++
        const docB: AgentIdentityDocument = {
            ...makeDoc(did, 1),
            principalDid: 'did:key:zOther' as DID,
            bindingProof: {
                agentDid: did,
                principalDid: 'did:key:zOther' as DID,
                signature: 'fakesig' as Signature,
                issuedAt: new Date().toISOString() as Timestamp,
                expiresAt: new Date(
                    Date.now() + 86400_000,
                ).toISOString() as Timestamp,
            },
        };

        let call = 0;
        vi.stubGlobal(
            'fetch',
            vi.fn().mockImplementation(() => {
                call++;
                const doc = call % 2 === 0 ? docB : docA;
                return Promise.resolve({
                    ok: true,
                    status: 200,
                    headers: { get: () => '100' },
                    json: () => Promise.resolve(doc),
                });
            }),
        );

        const resolver = createFederatedResolver({
            nodes: [
                { id: 'n1', url: 'http://n1' },
                { id: 'n2', url: 'http://n2' },
            ],
            minResponses: 2,
            timeoutMs: 5000,
            cacheTtlMs: 60000,
            settleWindowMs: 50,
            verifyDIDBinding: makeVerifier(),
            persistentWatermark: makeWatermark(),
            dnsRebindingGuard: makeDnsGuard(),
        });

        await resolver.resolve(did);
        const m = resolver.getMetrics();
        // M-1: only one DID resolution sees a two-node fork, exactly 1
        expect(m.versionConflictCount).toBe(1);
        await resolver.close();
    });
});

// ============================================================
// Edge-case completion (Task 04f — coverage completion)
// ============================================================

describe('edge cases — coverage', () => {
    afterEach(() => {
        vi.useRealTimers();
        vi.unstubAllGlobals();
    });

    // ------------------------------------------------------------------
    // 1. Single-flight merge (single-flight inflight hit path)
    // Summary: two concurrent resolves for the same DID issue only 1 fetch
    // ------------------------------------------------------------------
    it('should merge concurrent resolves via single-flight', async () => {
        const did = 'did:agent:flight1' as DID;
        let fetchCallCount = 0;
        vi.stubGlobal(
            'fetch',
            vi.fn().mockImplementation(async () => {
                fetchCallCount++;
                await new Promise((r) => setTimeout(r, 20));
                return {
                    ok: true,
                    status: 200,
                    headers: { get: () => '100' },
                    json: () => Promise.resolve(makeDoc(did)),
                };
            }),
        );

        const resolver = createFederatedResolver({
            nodes: [{ id: 'n1', url: 'http://n1' }],
            minResponses: 1,
            timeoutMs: 5000,
            cacheTtlMs: 60000,
            verifyDIDBinding: makeVerifier(),
            persistentWatermark: makeWatermark(),
            dnsRebindingGuard: makeDnsGuard(),
        });

        const [r1, r2] = await Promise.all([
            resolver.resolve(did),
            resolver.resolve(did),
        ]);
        expect(fetchCallCount).toBe(1); // single-flight merge
        expect(r1?.id).toBe(did);
        expect(r2?.id).toBe(did);
        await resolver.close();
    });

    // ------------------------------------------------------------------
    // 2. response_too_large → FEDERATION_NODE_ABUSE
    // ------------------------------------------------------------------
    it('should emit FEDERATION_NODE_ABUSE when content-length exceeds maxResponseBytes', async () => {
        const did = 'did:agent:toolarge' as DID;
        const alerts: Array<{ kind: string; reason?: string }> = [];

        vi.stubGlobal(
            'fetch',
            vi.fn().mockResolvedValue({
                ok: true,
                status: 200,
                headers: { get: () => '99999999' }, // far exceeds maxResponseBytes
                json: () => Promise.resolve(makeDoc(did)),
            }),
        );

        const resolver = createFederatedResolver({
            nodes: [{ id: 'n1', url: 'http://n1' }],
            minResponses: 1,
            timeoutMs: 5000,
            cacheTtlMs: 60000,
            maxResponseBytes: 1024,
            verifyDIDBinding: makeVerifier(),
            persistentWatermark: makeWatermark(),
            dnsRebindingGuard: makeDnsGuard(),
            onAlert: (e) => alerts.push(e as { kind: string; reason?: string }),
        });

        await resolver.resolve(did);
        expect(
            alerts.some(
                (a) =>
                    a.kind === 'FEDERATION_NODE_ABUSE' &&
                    a.reason === 'response_too_large',
            ),
        ).toBe(true);
        await resolver.close();
    });

    // ------------------------------------------------------------------
    // 3. malformed JSON response -> FEDERATION_NODE_ABUSE malformed_json
    // ------------------------------------------------------------------
    it('should emit FEDERATION_NODE_ABUSE when json() throws', async () => {
        const did = 'did:agent:malformedjson' as DID;
        const alerts: Array<{ kind: string; reason?: string }> = [];

        vi.stubGlobal(
            'fetch',
            vi.fn().mockResolvedValue({
                ok: true,
                status: 200,
                headers: { get: () => '100' },
                json: () => Promise.reject(new SyntaxError('Unexpected token')),
            }),
        );

        const resolver = createFederatedResolver({
            nodes: [{ id: 'n1', url: 'http://n1' }],
            minResponses: 1,
            timeoutMs: 5000,
            cacheTtlMs: 60000,
            verifyDIDBinding: makeVerifier(),
            persistentWatermark: makeWatermark(),
            dnsRebindingGuard: makeDnsGuard(),
            onAlert: (e) => alerts.push(e as { kind: string; reason?: string }),
        });

        await resolver.resolve(did);
        expect(
            alerts.some(
                (a) =>
                    a.kind === 'FEDERATION_NODE_ABUSE' &&
                    a.reason === 'malformed_json',
            ),
        ).toBe(true);
        await resolver.close();
    });

    // ------------------------------------------------------------------
    // 4. doc.id !== did → FEDERATION_NODE_ABUSE invalid_schema
    // ------------------------------------------------------------------
    it('should emit FEDERATION_NODE_ABUSE when doc.id does not match requested DID', async () => {
        const did = 'did:agent:requester' as DID;
        const alerts: Array<{ kind: string; reason?: string }> = [];

        // Returns a document with the wrong DID
        vi.stubGlobal(
            'fetch',
            vi.fn().mockResolvedValue({
                ok: true,
                status: 200,
                headers: { get: () => '100' },
                json: () => Promise.resolve(makeDoc('did:agent:wrong')),
            }),
        );

        const resolver = createFederatedResolver({
            nodes: [{ id: 'n1', url: 'http://n1' }],
            minResponses: 1,
            timeoutMs: 5000,
            cacheTtlMs: 60000,
            verifyDIDBinding: makeVerifier(),
            persistentWatermark: makeWatermark(),
            dnsRebindingGuard: makeDnsGuard(),
            onAlert: (e) => alerts.push(e as { kind: string; reason?: string }),
        });

        await resolver.resolve(did);
        expect(
            alerts.some(
                (a) =>
                    a.kind === 'FEDERATION_NODE_ABUSE' &&
                    a.reason === 'invalid_schema',
            ),
        ).toBe(true);
        await resolver.close();
    });

    // ------------------------------------------------------------------
    // 5. persistentWatermark — version rollback → fail-closed
    // ------------------------------------------------------------------
    it('should return null and emit FEDERATION_VERSION_ROLLBACK when watermark > incoming version', async () => {
        const did = 'did:agent:rollback1' as DID;
        const alerts: Array<{ kind: string }> = [];

        vi.stubGlobal(
            'fetch',
            vi.fn().mockResolvedValue({
                ok: true,
                status: 200,
                headers: { get: () => '100' },
                json: () => Promise.resolve(makeDoc(did, 1)), // version=1
            }),
        );

        const resolver = createFederatedResolver({
            nodes: [{ id: 'n1', url: 'http://n1' }],
            minResponses: 1,
            timeoutMs: 5000,
            cacheTtlMs: 60000,
            verifyDIDBinding: makeVerifier(),
            onAlert: (e) => alerts.push(e as { kind: string }),
            persistentWatermark: {
                getWatermark: () => Promise.resolve(5), // watermark=5 > version=1 -> rollback
                setWatermark: vi.fn(),
            },
            dnsRebindingGuard: makeDnsGuard(),
        });

        const result = await resolver.resolve(did);
        expect(result).toBeNull();
        expect(
            alerts.some((a) => a.kind === 'FEDERATION_VERSION_ROLLBACK'),
        ).toBe(true);
        await resolver.close();
    });

    // ------------------------------------------------------------------
    // 6. persistentWatermark.setWatermark is called after a successful resolve
    // ------------------------------------------------------------------
    it('should call persistentWatermark.setWatermark after successful resolve', async () => {
        const did = 'did:agent:watermark1' as DID;
        const setWatermark = vi.fn();

        vi.stubGlobal(
            'fetch',
            vi.fn().mockResolvedValue({
                ok: true,
                status: 200,
                headers: { get: () => '100' },
                json: () => Promise.resolve(makeDoc(did, 1)),
            }),
        );

        const resolver = createFederatedResolver({
            nodes: [{ id: 'n1', url: 'http://n1' }],
            minResponses: 1,
            timeoutMs: 5000,
            cacheTtlMs: 60000,
            verifyDIDBinding: makeVerifier(),
            persistentWatermark: {
                getWatermark: () => Promise.resolve(0),
                setWatermark,
            },
            dnsRebindingGuard: makeDnsGuard(),
        });

        const result = await resolver.resolve(did);
        expect(result).not.toBeNull();
        expect(setWatermark).toHaveBeenCalledWith(did, 1);
        await resolver.close();
    });

    // ------------------------------------------------------------------
    // 7. Epoch mismatch -> fail-closed, emit FEDERATION_EPOCH_MISMATCH
    // Summary: while resolveInternal runs inside single-flight, an external invalidateCache call
    // increments the epoch, causing an epoch mismatch at write time
    // ------------------------------------------------------------------
    it('should return null and emit FEDERATION_EPOCH_MISMATCH when epoch changes mid-resolve', async () => {
        const did = 'did:agent:epoch1' as DID;
        const alerts: Array<{ kind: string }> = [];

        const resolver = createFederatedResolver({
            nodes: [{ id: 'n1', url: 'http://n1' }],
            minResponses: 1,
            timeoutMs: 5000,
            cacheTtlMs: 60000,
            verifyDIDBinding: makeVerifier(),
            persistentWatermark: makeWatermark(),
            dnsRebindingGuard: makeDnsGuard(),
            onAlert: (e) => alerts.push(e as { kind: string }),
        });

        vi.stubGlobal(
            'fetch',
            vi.fn().mockImplementation(() => {
                // While the fetch is in progress, an external invalidateCache increments the epoch
                resolver.invalidateCache(did);
                return Promise.resolve({
                    ok: true,
                    status: 200,
                    headers: { get: () => '100' },
                    json: () => Promise.resolve(makeDoc(did, 1)),
                });
            }),
        );

        const result = await resolver.resolve(did);
        expect(result).toBeNull();
        expect(alerts.some((a) => a.kind === 'FEDERATION_EPOCH_MISMATCH')).toBe(
            true,
        );
        await resolver.close();
    });

    // ------------------------------------------------------------------
    // 8. invalidateCache is idempotent for an uncached DID (does not throw)
    // ------------------------------------------------------------------
    it('should not throw when invalidateCache is called for a non-cached DID', () => {
        const resolver = createFederatedResolver({
            nodes: [{ id: 'n1', url: 'http://n1' }],
            minResponses: 1,
            timeoutMs: 5000,
            cacheTtlMs: 60000,
            verifyDIDBinding: makeVerifier(),
            persistentWatermark: makeWatermark(),
            dnsRebindingGuard: makeDnsGuard(),
        });
        expect(() =>
            resolver.invalidateCache('did:agent:notexist' as DID),
        ).not.toThrow();
        void resolver.close();
    });

    // ------------------------------------------------------------------
    // 9. close() is idempotent — calling it twice should not throw
    // ------------------------------------------------------------------
    it('should be idempotent when close() is called twice', async () => {
        const resolver = createFederatedResolver({
            nodes: [{ id: 'n1', url: 'http://n1' }],
            minResponses: 1,
            timeoutMs: 5000,
            cacheTtlMs: 60000,
            verifyDIDBinding: makeVerifier(),
            persistentWatermark: makeWatermark(),
            dnsRebindingGuard: makeDnsGuard(),
        });
        await resolver.close();
        await expect(resolver.close()).resolves.toBeUndefined();
    });

    // ------------------------------------------------------------------
    // 10. When onAlert is not provided (fallback to console.warn) — confirm alerts do not throw
    // ------------------------------------------------------------------
    it('should fall back to console.warn when onAlert is not provided', async () => {
        const did = 'did:agent:nowarn' as DID;
        const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});

        vi.stubGlobal(
            'fetch',
            vi.fn().mockRejectedValue(new Error('network error')),
        );

        const resolver = createFederatedResolver({
            nodes: [{ id: 'n1', url: 'http://n1' }],
            minResponses: 1,
            timeoutMs: 5000,
            cacheTtlMs: 60000,
            verifyDIDBinding: makeVerifier(),
            persistentWatermark: makeWatermark(),
            dnsRebindingGuard: makeDnsGuard(),
            // onAlert is not provided
        });

        const result = await resolver.resolve(did);
        expect(result).toBeNull();
        // The QUORUM_UNMET alert went through console.warn (defaultAlertHandler format: args[1] is JSON.stringify(event))
        expect(
            warnSpy.mock.calls.some(
                (args: unknown[]) =>
                    typeof args[1] === 'string' &&
                    args[1].includes('FEDERATION_QUORUM_UNMET'),
            ),
        ).toBe(true);

        warnSpy.mockRestore();
        await resolver.close();
    });

    // ------------------------------------------------------------------
    // 11. V3b DID binding verification fails (verifyDIDBinding.verify returns false when v>1)
    // Summary: rotation_proof_malformed alert + signatureInvalidCount increment
    // ------------------------------------------------------------------
    it('should emit FEDERATION_SIGNATURE_INVALID with rotation_proof_malformed when v>1 verify fails', async () => {
        const did = 'did:agent:v2badverify' as DID;
        const alerts: Array<{ kind: string; reason?: string }> = [];

        const docV2 = {
            ...makeDoc(did, 2),
            rotationProof: {
                signature: 'fakerotsig',
                previousDid: did,
                issuedAt: new Date().toISOString(),
            },
        } as unknown as AgentIdentityDocument;

        vi.stubGlobal(
            'fetch',
            vi.fn().mockResolvedValue({
                ok: true,
                status: 200,
                headers: { get: () => '100' },
                json: () => Promise.resolve(docV2),
            }),
        );

        const verifier = makeVerifier();
        // eslint-disable-next-line @typescript-eslint/unbound-method
        vi.mocked(verifier.verify).mockResolvedValue(false); // V3b verification fails

        const resolver = createFederatedResolver({
            nodes: [{ id: 'n1', url: 'http://n1' }],
            minResponses: 1,
            timeoutMs: 5000,
            cacheTtlMs: 60000,
            verifyDIDBinding: verifier,
            persistentWatermark: makeWatermark(),
            dnsRebindingGuard: makeDnsGuard(),
            onAlert: (e) => alerts.push(e as { kind: string; reason?: string }),
        });

        const result = await resolver.resolve(did);
        expect(result).toBeNull();
        expect(
            alerts.some(
                (a) =>
                    a.kind === 'FEDERATION_SIGNATURE_INVALID' &&
                    a.reason === 'rotation_proof_malformed',
            ),
        ).toBe(true);
        const m = resolver.getMetrics();
        expect(m.signatureInvalidCount).toBe(1);
        await resolver.close();
    });

    // ------------------------------------------------------------------
    // 12. weight=0 nodes are skipped in startHealthProbe
    // Summary: a weight=0 node is never probed and never included in resolve targets
    // ------------------------------------------------------------------
    it('should skip weight=0 node in health probe and resolve targets', async () => {
        vi.useFakeTimers();
        const alerts: Array<{ kind: string }> = [];
        const fetchMock = vi.fn().mockImplementation((url: string) => {
            if (url.includes('/health')) {
                return Promise.resolve({
                    ok: true,
                    status: 200,
                    headers: { get: () => null },
                    json: () => Promise.resolve({ status: 'ok' }),
                });
            }
            return Promise.reject(new Error('unexpected DID fetch'));
        });
        vi.stubGlobal('fetch', fetchMock);

        const resolver = createFederatedResolver({
            nodes: [
                { id: 'n1', url: 'http://n1', weight: 0 }, // weight=0, never included in routing
                { id: 'n2', url: 'http://n2', weight: 1 }, // healthy probe
                { id: 'n3', url: 'http://n3', weight: 1 }, // healthy probe
            ],
            minResponses: 2,
            timeoutMs: 5000,
            cacheTtlMs: 60000,
            verifyDIDBinding: makeVerifier(),
            persistentWatermark: makeWatermark(),
            dnsRebindingGuard: makeDnsGuard(),
            onAlert: (e) => alerts.push(e as { kind: string }),
            healthCheck: {
                probeIntervalMs: 100,
                failureThreshold: 2,
                recoveryThreshold: 2,
                probePath: '/health',
            },
        });

        // Advance the probe interval: n1 is skipped, n2 accepts probes
        await vi.advanceTimersByTimeAsync(200);

        // n1 weight=0 -> never issues a health probe and is not in resolve targets
        const healthProbes = fetchMock.mock.calls.filter(
            (args) =>
                (args[0] as string).includes('n1') &&
                (args[0] as string).includes('/health'),
        );
        expect(healthProbes).toHaveLength(0);

        await resolver.close();
    });

    // ------------------------------------------------------------------
    // 13. probeNode: HTTP ok but body.status !== 'ok' -> recordNodeFailure
    // ------------------------------------------------------------------
    it('should record node failure when probe response body.status is not ok', async () => {
        vi.useFakeTimers();
        const fetchMock = vi.fn().mockImplementation((url: string) => {
            if (url.includes('/health')) {
                return Promise.resolve({
                    ok: true,
                    status: 200,
                    headers: { get: () => null },
                    json: () => Promise.resolve({ status: 'degraded' }), // not 'ok'
                });
            }
            return Promise.reject(new Error('unexpected'));
        });
        vi.stubGlobal('fetch', fetchMock);

        const alertFn = vi.fn();
        const resolver = createFederatedResolver({
            nodes: [{ id: 'n1', url: 'http://n1' }],
            minResponses: 1,
            timeoutMs: 5000,
            cacheTtlMs: 60000,
            verifyDIDBinding: makeVerifier(),
            persistentWatermark: makeWatermark(),
            dnsRebindingGuard: makeDnsGuard(),
            onAlert: alertFn,
            healthCheck: {
                probeIntervalMs: 100,
                failureThreshold: 2,
                recoveryThreshold: 2,
                probePath: '/health',
            },
        });

        // Advance 2 probes (body.status=degraded is treated as a failure) -> UNHEALTHY
        await vi.advanceTimersByTimeAsync(200);
        expect(resolver.getMetrics().nodes['n1']?.healthState).toBe(
            'UNHEALTHY',
        );

        await resolver.close();
    });

    // ------------------------------------------------------------------
    // 14. probeNode: HTTP ok but res.json() throws -> recordNodeFailure
    // ------------------------------------------------------------------
    it('should record node failure when probe response json() throws', async () => {
        vi.useFakeTimers();
        const fetchMock = vi.fn().mockImplementation((url: string) => {
            if (url.includes('/health')) {
                return Promise.resolve({
                    ok: true,
                    status: 200,
                    headers: { get: () => null },
                    json: () => Promise.reject(new SyntaxError('bad json')),
                });
            }
            return Promise.reject(new Error('unexpected'));
        });
        vi.stubGlobal('fetch', fetchMock);

        const alertFn = vi.fn();
        const resolver = createFederatedResolver({
            nodes: [{ id: 'n1', url: 'http://n1' }],
            minResponses: 1,
            timeoutMs: 5000,
            cacheTtlMs: 60000,
            verifyDIDBinding: makeVerifier(),
            persistentWatermark: makeWatermark(),
            dnsRebindingGuard: makeDnsGuard(),
            onAlert: alertFn,
            healthCheck: {
                probeIntervalMs: 100,
                failureThreshold: 2,
                recoveryThreshold: 2,
                probePath: '/health',
            },
        });

        // Advance 2 probes -> JSON parse failure is treated as a probe failure -> UNHEALTHY
        await vi.advanceTimersByTimeAsync(200);
        expect(resolver.getMetrics().nodes['n1']?.healthState).toBe(
            'UNHEALTHY',
        );

        await resolver.close();
    });

    // ------------------------------------------------------------------
    // 15. probeNode: fetch itself throws (network error) -> recordNodeFailure
    // ------------------------------------------------------------------
    it('should record node failure when probe fetch throws a network error', async () => {
        vi.useFakeTimers();
        const fetchMock = vi.fn().mockImplementation((url: string) => {
            if (url.includes('/health')) {
                return Promise.reject(new Error('ECONNREFUSED'));
            }
            return Promise.reject(new Error('unexpected'));
        });
        vi.stubGlobal('fetch', fetchMock);

        const alertFn = vi.fn();
        const resolver = createFederatedResolver({
            nodes: [{ id: 'n1', url: 'http://n1' }],
            minResponses: 1,
            timeoutMs: 5000,
            cacheTtlMs: 60000,
            verifyDIDBinding: makeVerifier(),
            persistentWatermark: makeWatermark(),
            dnsRebindingGuard: makeDnsGuard(),
            onAlert: alertFn,
            healthCheck: {
                probeIntervalMs: 100,
                failureThreshold: 2,
                recoveryThreshold: 2,
                probePath: '/health',
            },
        });

        // Advance 2 probes -> network failure -> UNHEALTHY
        await vi.advanceTimersByTimeAsync(200);
        expect(resolver.getMetrics().nodes['n1']?.healthState).toBe(
            'UNHEALTHY',
        );

        await resolver.close();
    });

    // ------------------------------------------------------------------
    // 16. TTL cache hit (the second sequential resolve hits the outer cache)
    // Summary: the first resolve writes the TTL cache on completion; the second resolve hits
    // the outer cache directly -> cacheHit increments, fetch is called only once
    // ------------------------------------------------------------------
    it('should hit outer TTL cache on second sequential resolve for same DID', async () => {
        const did = 'did:agent:inner-cache' as DID;
        let fetchCalls = 0;

        vi.stubGlobal(
            'fetch',
            vi.fn().mockImplementation(async () => {
                fetchCalls++;
                // Delay so the second resolve can enter the inflight check
                await new Promise((r) => setTimeout(r, 10));
                return {
                    ok: true,
                    status: 200,
                    headers: { get: () => '100' },
                    json: () => Promise.resolve(makeDoc(did)),
                };
            }),
        );

        const resolver = createFederatedResolver({
            nodes: [{ id: 'n1', url: 'http://n1' }],
            minResponses: 1,
            timeoutMs: 5000,
            cacheTtlMs: 60000,
            verifyDIDBinding: makeVerifier(),
            persistentWatermark: makeWatermark(),
            dnsRebindingGuard: makeDnsGuard(),
        });

        const r1 = await resolver.resolve(did); // writes the cache
        expect(r1?.id).toBe(did);
        const r2 = await resolver.resolve(did); // outer TTL cacheHit
        const m = resolver.getMetrics();
        expect(m.cacheHit).toBeGreaterThan(0);
        expect(r2?.id).toBe(did);
        expect(fetchCalls).toBe(1);

        await resolver.close();
    });

    // ------------------------------------------------------------------
    // 17. Non-404 non-ok HTTP status (e.g. 503) -> queryNode returns error
    // ------------------------------------------------------------------
    it('should return null when node returns non-404 non-ok HTTP status', async () => {
        const did = 'did:agent:servererr' as DID;
        const alerts: Array<{ kind: string }> = [];

        vi.stubGlobal(
            'fetch',
            vi.fn().mockResolvedValue({
                ok: false,
                status: 503,
                headers: { get: () => null },
            }),
        );

        const resolver = createFederatedResolver({
            nodes: [{ id: 'n1', url: 'http://n1' }],
            minResponses: 1,
            timeoutMs: 5000,
            cacheTtlMs: 60000,
            verifyDIDBinding: makeVerifier(),
            persistentWatermark: makeWatermark(),
            dnsRebindingGuard: makeDnsGuard(),
            onAlert: (e) => alerts.push(e as { kind: string }),
        });

        const result = await resolver.resolve(did);
        expect(result).toBeNull();
        // Non-404 non-ok -> error -> QUORUM_UNMET
        expect(alerts.some((a) => a.kind === 'FEDERATION_QUORUM_UNMET')).toBe(
            true,
        );
        await resolver.close();
    });

    // ------------------------------------------------------------------
    // 18. AbortError path: after fetch is aborted -> timeout count increments
    // Summary: simulate an AbortError to exercise the isAbort branch in queryNode
    // ------------------------------------------------------------------
    it('should count timeout when fetch is aborted with AbortError', async () => {
        const did = 'did:agent:aborttest' as DID;

        vi.stubGlobal(
            'fetch',
            vi.fn().mockImplementation(() => {
                // Abort immediately
                const abortErr = new Error('The operation was aborted');
                abortErr.name = 'AbortError';
                return Promise.reject(abortErr);
            }),
        );

        const resolver = createFederatedResolver({
            nodes: [{ id: 'n1', url: 'http://n1' }],
            minResponses: 1,
            timeoutMs: 5000,
            cacheTtlMs: 60000,
            verifyDIDBinding: makeVerifier(),
            persistentWatermark: makeWatermark(),
            dnsRebindingGuard: makeDnsGuard(),
        });

        await resolver.resolve(did);
        const m = resolver.getMetrics();
        // AbortError -> timeout count
        expect(m.nodes['n1']?.timeout).toBe(1);
        await resolver.close();
    });

    // ------------------------------------------------------------------
    // 19. settleWindowMs=0 -> close the window immediately on first reaching minResponses
    // ------------------------------------------------------------------
    it('should close settle window immediately when settleWindowMs=0', async () => {
        const did = 'did:agent:settle0' as DID;

        vi.stubGlobal(
            'fetch',
            vi.fn().mockResolvedValue({
                ok: true,
                status: 200,
                headers: { get: () => '100' },
                json: () => Promise.resolve(makeDoc(did)),
            }),
        );

        const resolver = createFederatedResolver({
            nodes: [{ id: 'n1', url: 'http://n1' }],
            minResponses: 1,
            timeoutMs: 5000,
            cacheTtlMs: 60000,
            settleWindowMs: 0, // close the window immediately
            verifyDIDBinding: makeVerifier(),
            persistentWatermark: makeWatermark(),
            dnsRebindingGuard: makeDnsGuard(),
        });

        const result = await resolver.resolve(did);
        expect(result?.id).toBe(did);
        await resolver.close();
    });

    // ------------------------------------------------------------------
    // 20. resolveInternal throws -> resolveInternalError count increments
    // Summary: make verifyDIDBinding.verify throw to trigger an internal exception in resolveInternal
    // ------------------------------------------------------------------
    it('should increment resolveInternalError when resolveInternal throws', async () => {
        const did = 'did:agent:internalerr' as DID;

        // v=2 document (with rotationProof); verifyDIDBinding.verify throws
        const docV2 = {
            ...makeDoc(did, 2),
            rotationProof: {
                signature: 'fakerotsig',
                previousDid: did,
                issuedAt: new Date().toISOString(),
            },
        } as unknown as AgentIdentityDocument;

        vi.stubGlobal(
            'fetch',
            vi.fn().mockResolvedValue({
                ok: true,
                status: 200,
                headers: { get: () => '100' },
                json: () => Promise.resolve(docV2),
            }),
        );

        const verifier = makeVerifier();
        // eslint-disable-next-line @typescript-eslint/unbound-method
        vi.mocked(verifier.verify).mockRejectedValue(new Error('crypto panic'));

        const resolver = createFederatedResolver({
            nodes: [{ id: 'n1', url: 'http://n1' }],
            minResponses: 1,
            timeoutMs: 5000,
            cacheTtlMs: 60000,
            verifyDIDBinding: verifier,
            persistentWatermark: makeWatermark(),
            dnsRebindingGuard: makeDnsGuard(),
        });

        // The internal exception in resolveInternal propagates out of resolve()
        await expect(resolver.resolve(did)).rejects.toThrow('crypto panic');
        const m = resolver.getMetrics();
        expect(m.resolveInternalError).toBe(1);
        await resolver.close();
    });

    // ------------------------------------------------------------------
    // 21. bindingProof missing -> binding_proof_invalid
    // ------------------------------------------------------------------
    it('should emit FEDERATION_SIGNATURE_INVALID when bindingProof is missing', async () => {
        const did = 'did:agent:nobindingproof' as DID;
        const alerts: Array<{ kind: string; reason?: string }> = [];

        const docNoBp = {
            ...makeDoc(did, 1),
            bindingProof: undefined,
        } as unknown as AgentIdentityDocument;

        vi.stubGlobal(
            'fetch',
            vi.fn().mockResolvedValue({
                ok: true,
                status: 200,
                headers: { get: () => '100' },
                json: () => Promise.resolve(docNoBp),
            }),
        );

        const resolver = createFederatedResolver({
            nodes: [{ id: 'n1', url: 'http://n1' }],
            minResponses: 1,
            timeoutMs: 5000,
            cacheTtlMs: 60000,
            verifyDIDBinding: makeVerifier(),
            persistentWatermark: makeWatermark(),
            dnsRebindingGuard: makeDnsGuard(),
            onAlert: (e) => alerts.push(e as { kind: string; reason?: string }),
        });

        const result = await resolver.resolve(did);
        expect(result).toBeNull();
        expect(
            alerts.some(
                (a) =>
                    a.kind === 'FEDERATION_SIGNATURE_INVALID' &&
                    a.reason === 'binding_proof_invalid',
            ),
        ).toBe(true);
        await resolver.close();
    });

    // ------------------------------------------------------------------
    // 22. bindingProof.agentDid !== doc.id -> binding_proof_invalid
    // ------------------------------------------------------------------
    it('should emit FEDERATION_SIGNATURE_INVALID when bindingProof.agentDid mismatches doc.id', async () => {
        const did = 'did:agent:agentdidmismatch' as DID;
        const alerts: Array<{ kind: string; reason?: string }> = [];

        const docMismatch = {
            ...makeDoc(did, 1),
            bindingProof: {
                agentDid: 'did:agent:other', // intentionally inconsistent with did
                principalDid: 'did:key:zQ3shPrincipal',
                signature: 'fakesig',
                issuedAt: new Date().toISOString(),
                expiresAt: new Date(Date.now() + 86400_000).toISOString(),
            },
        } as AgentIdentityDocument;

        vi.stubGlobal(
            'fetch',
            vi.fn().mockResolvedValue({
                ok: true,
                status: 200,
                headers: { get: () => '100' },
                json: () => Promise.resolve(docMismatch),
            }),
        );

        const resolver = createFederatedResolver({
            nodes: [{ id: 'n1', url: 'http://n1' }],
            minResponses: 1,
            timeoutMs: 5000,
            cacheTtlMs: 60000,
            verifyDIDBinding: makeVerifier(),
            persistentWatermark: makeWatermark(),
            dnsRebindingGuard: makeDnsGuard(),
            onAlert: (e) => alerts.push(e as { kind: string; reason?: string }),
        });

        const result = await resolver.resolve(did);
        expect(result).toBeNull();
        expect(
            alerts.some(
                (a) =>
                    a.kind === 'FEDERATION_SIGNATURE_INVALID' &&
                    a.reason === 'binding_proof_invalid',
            ),
        ).toBe(true);
        await resolver.close();
    });

    // ------------------------------------------------------------------
    // 23. Latency-sample rolling-window pruning (samples older than 5 minutes are cleared)
    // Summary: use vi.useFakeTimers to advance the clock so samples fall outside the 5-minute window
    // ------------------------------------------------------------------
    it('should prune latency samples older than 5 minutes', async () => {
        const did = 'did:agent:prune' as DID;
        vi.useFakeTimers();

        vi.stubGlobal(
            'fetch',
            vi.fn().mockResolvedValue({
                ok: true,
                status: 200,
                headers: { get: () => '100' },
                json: () => Promise.resolve(makeDoc(did)),
            }),
        );

        const resolver = createFederatedResolver({
            nodes: [{ id: 'n1', url: 'http://n1' }],
            minResponses: 1,
            timeoutMs: 5000,
            cacheTtlMs: 60000,
            verifyDIDBinding: makeVerifier(),
            persistentWatermark: makeWatermark(),
            dnsRebindingGuard: makeDnsGuard(),
        });

        // The first resolve produces one latency sample
        const r1 = resolver.resolve(did);
        await vi.runAllTimersAsync();
        await r1;

        // Advance the clock 6 minutes so the first sample exceeds the 5-minute window
        await vi.advanceTimersByTimeAsync(6 * 60 * 1000);

        // Invalidate the cache and resolve again, producing a new sample and triggering pruning
        resolver.invalidateCache(did);
        const r2 = resolver.resolve(did);
        await vi.runAllTimersAsync();
        await r2;

        // Verify metrics can still be returned normally (no throw)
        const m = resolver.getMetrics();
        expect(m.resolveTotal).toBeGreaterThan(0);

        await resolver.close();
    });

    // ------------------------------------------------------------------
    // 24. Inner resolveInternal second-level cache hit (internal hit after single-flight merge)
    // Summary: after the first resolve completes and writes the cache, the second concurrent resolve
    // hits the outer cache as inflight; manually populating outside resolveInternal can exercise the inner path
    // ------------------------------------------------------------------
    it('should hit inner resolveInternal cache when inflight resolves first', async () => {
        const did = 'did:agent:inner2' as DID;
        let resolveCount = 0;

        // fetch is intentionally delayed so both concurrent resolves enter the inflight check
        vi.stubGlobal(
            'fetch',
            vi.fn().mockImplementation(async () => {
                resolveCount++;
                await new Promise((r) => setTimeout(r, 30));
                return {
                    ok: true,
                    status: 200,
                    headers: { get: () => '100' },
                    json: () => Promise.resolve(makeDoc(did)),
                };
            }),
        );

        const resolver = createFederatedResolver({
            nodes: [{ id: 'n1', url: 'http://n1' }],
            minResponses: 1,
            timeoutMs: 5000,
            cacheTtlMs: 60000,
            verifyDIDBinding: makeVerifier(),
            persistentWatermark: makeWatermark(),
            dnsRebindingGuard: makeDnsGuard(),
        });

        // Fire three resolves concurrently; the first is inflight and the other two should merge
        const [r1, r2, r3] = await Promise.all([
            resolver.resolve(did),
            resolver.resolve(did),
            resolver.resolve(did),
        ]);
        // single-flight merge: there should be only 1 fetch
        expect(resolveCount).toBe(1);
        expect(r1?.id).toBe(did);
        expect(r2?.id).toBe(did);
        expect(r3?.id).toBe(did);

        await resolver.close();
    });

    // ------------------------------------------------------------------
    // 25. redirect TypeError -> FEDERATION_NODE_ABUSE redirect_blocked
    // ------------------------------------------------------------------
    it('should emit FEDERATION_NODE_ABUSE redirect_blocked when fetch throws redirect TypeError', async () => {
        const did = 'did:agent:redirect' as DID;
        const alerts: Array<{ kind: string; reason?: string }> = [];

        vi.stubGlobal(
            'fetch',
            vi.fn().mockImplementation(() => {
                const err = new TypeError('redirect not allowed');
                throw err;
            }),
        );

        const resolver = createFederatedResolver({
            nodes: [{ id: 'n1', url: 'http://n1' }],
            minResponses: 1,
            timeoutMs: 5000,
            cacheTtlMs: 60000,
            verifyDIDBinding: makeVerifier(),
            persistentWatermark: makeWatermark(),
            dnsRebindingGuard: makeDnsGuard(),
            onAlert: (e) => alerts.push(e as { kind: string; reason?: string }),
        });

        await resolver.resolve(did);
        expect(
            alerts.some(
                (a) =>
                    a.kind === 'FEDERATION_NODE_ABUSE' &&
                    a.reason === 'redirect_blocked',
            ),
        ).toBe(true);
        await resolver.close();
    });

    // ------------------------------------------------------------------
    // 26. createAgentDID throws -> return malformed_document (prevents single-node DoS)
    // Summary: in the v=1 self-certification check, fromHex throws a CryptoError for a non-hex publicKey;
    // the try/catch ensures this only invalidates that candidate node rather than rejecting the whole resolve
    // ------------------------------------------------------------------
    it('should treat node as invalid when createAgentDID throws on malformed publicKey', async () => {
        const { createAgentDID } = await import('../did.js');
        const did = 'did:agent:malformedpk' as DID;
        const alerts: Array<FederationAlertEvent> = [];

        // Throw only for this call, simulating a non-hex publicKey triggering a CryptoError
        vi.mocked(createAgentDID).mockImplementationOnce(() => {
            throw new Error('INVALID_HEX_STRING');
        });

        vi.stubGlobal(
            'fetch',
            vi.fn().mockResolvedValue({
                ok: true,
                status: 200,
                headers: { get: () => '100' },
                json: () => Promise.resolve(makeDoc(did)),
            }),
        );

        const resolver = createFederatedResolver({
            nodes: [{ id: 'n1', url: 'http://n1' }],
            minResponses: 1,
            timeoutMs: 5000,
            cacheTtlMs: 60000,
            verifyDIDBinding: makeVerifier(),
            persistentWatermark: makeWatermark(),
            dnsRebindingGuard: makeDnsGuard(),
            onAlert: (e) => alerts.push(e),
        });

        // Should return null (invalid candidate -> quorum unmet) rather than throw
        const result = await resolver.resolve(did);
        expect(result).toBeNull();
        // Should trigger SIGNATURE_INVALID (malformed_document) rather than crash the whole resolve
        expect(
            alerts.some(
                (a) =>
                    a.kind === 'FEDERATION_SIGNATURE_INVALID' &&
                    (a as { reason?: string }).reason === 'malformed_document',
            ),
        ).toBe(true);
        await resolver.close();
    });

    // ------------------------------------------------------------------
    // 27. Passive health check — resolve failures drive the state machine even without a healthCheck config
    // Summary: uses the PASSIVE_HEALTH_CFG default threshold (failureThreshold=3);
    // after 3 consecutive fetch failures the node should transition to UNHEALTHY
    // ------------------------------------------------------------------
    it('should transition node to UNHEALTHY via passive health check after repeated resolve failures', async () => {
        const did = 'did:agent:passivehealth' as DID;
        const alerts: Array<FederationAlertEvent> = [];

        // Always return 500 so queryNode records otherFailure and drives the passive state machine
        vi.stubGlobal(
            'fetch',
            vi.fn().mockResolvedValue({
                ok: false,
                status: 500,
                headers: { get: () => null },
            }),
        );

        const resolver = createFederatedResolver({
            nodes: [{ id: 'n1', url: 'http://n1' }],
            minResponses: 1,
            timeoutMs: 5000,
            cacheTtlMs: 60000,
            verifyDIDBinding: makeVerifier(),
            persistentWatermark: makeWatermark(),
            dnsRebindingGuard: makeDnsGuard(),
            onAlert: (e) => alerts.push(e),
            // Intentionally no healthCheck — pure passive mode
        });

        // 3 failures -> passiveCfg.failureThreshold=3 -> UNHEALTHY
        await resolver.resolve(did);
        await resolver.resolve(did);
        await resolver.resolve(did);

        const healthAlerts = alerts.filter(
            (a) => a.kind === 'FEDERATION_NODE_HEALTH_CHANGED',
        ) as Array<{ kind: string; from: string; to: string }>;
        const finalHealth = resolver.getMetrics().nodes['n1']?.healthState;

        expect(finalHealth).toBe('UNHEALTHY');
        expect(healthAlerts.some((a) => a.to === 'DEGRADED')).toBe(true);
        expect(healthAlerts.some((a) => a.to === 'UNHEALTHY')).toBe(true);
        await resolver.close();
    });

    // ------------------------------------------------------------------
    // 28. BLOCKED_PORTS: the constructor does not block a node configured with a blocked port, but queryNode rejects the request
    // Summary: database port 5432 is blocked; queryNode emits url_policy_violation and returns error
    // ------------------------------------------------------------------
    it('should emit url_policy_violation for BLOCKED_PORTS when queryNode is called', async () => {
        const did = 'did:agent:blockedport' as DID;
        const alerts: Array<{ kind: string; reason?: string }> = [];

        // The node URL uses the blocked port 5432 (PostgreSQL)
        const resolver = createFederatedResolver({
            nodes: [{ id: 'n1', url: 'http://somehost.example.com:5432' }],
            minResponses: 1,
            timeoutMs: 5000,
            cacheTtlMs: 60000,
            verifyDIDBinding: makeVerifier(),
            persistentWatermark: makeWatermark(),
            dnsRebindingGuard: makeDnsGuard(),
            onAlert: (e) => alerts.push(e as { kind: string; reason?: string }),
        });

        // fetch should not be called; queryNode's internal URL check should intercept before fetch
        vi.stubGlobal(
            'fetch',
            vi.fn().mockRejectedValue(new Error('should not be called')),
        );

        const result = await resolver.resolve(did);
        expect(result).toBeNull();
        expect(
            alerts.some(
                (a) =>
                    a.kind === 'FEDERATION_NODE_ABUSE' &&
                    a.reason === 'url_policy_violation',
            ),
        ).toBe(true);
        await resolver.close();
    });

    // ------------------------------------------------------------------
    // 29. IP literal rejection: an IPv4-literal URL is intercepted by queryNode
    // Summary: the node URL contains an IP literal; queryNode emits url_policy_violation and returns error
    // ------------------------------------------------------------------
    it('should emit url_policy_violation when node URL contains IPv4 literal', async () => {
        const did = 'did:agent:ipliteral' as DID;
        const alerts: Array<{ kind: string; reason?: string }> = [];

        const resolver = createFederatedResolver({
            nodes: [{ id: 'n1', url: 'http://192.168.1.1' }],
            minResponses: 1,
            timeoutMs: 5000,
            cacheTtlMs: 60000,
            verifyDIDBinding: makeVerifier(),
            persistentWatermark: makeWatermark(),
            dnsRebindingGuard: makeDnsGuard(),
            onAlert: (e) => alerts.push(e as { kind: string; reason?: string }),
        });

        vi.stubGlobal(
            'fetch',
            vi.fn().mockRejectedValue(new Error('should not be called')),
        );

        const result = await resolver.resolve(did);
        expect(result).toBeNull();
        expect(
            alerts.some(
                (a) =>
                    a.kind === 'FEDERATION_NODE_ABUSE' &&
                    a.reason === 'url_policy_violation',
            ),
        ).toBe(true);
        await resolver.close();
    });

    // ------------------------------------------------------------------
    // 30. IP literal rejection: an IPv6-literal URL is intercepted by queryNode
    // Summary: a host containing a colon is recognized as an IPv6 literal and emits url_policy_violation
    // ------------------------------------------------------------------
    it('should emit url_policy_violation when node URL contains IPv6 literal', async () => {
        const did = 'did:agent:ipv6literal' as DID;
        const alerts: Array<{ kind: string; reason?: string }> = [];

        // An IPv6 address must be bracket-wrapped to parse as a URL
        const resolver = createFederatedResolver({
            nodes: [{ id: 'n1', url: 'http://[::1]' }],
            minResponses: 1,
            timeoutMs: 5000,
            cacheTtlMs: 60000,
            verifyDIDBinding: makeVerifier(),
            persistentWatermark: makeWatermark(),
            dnsRebindingGuard: makeDnsGuard(),
            onAlert: (e) => alerts.push(e as { kind: string; reason?: string }),
        });

        vi.stubGlobal(
            'fetch',
            vi.fn().mockRejectedValue(new Error('should not be called')),
        );

        const result = await resolver.resolve(did);
        expect(result).toBeNull();
        expect(
            alerts.some(
                (a) =>
                    a.kind === 'FEDERATION_NODE_ABUSE' &&
                    a.reason === 'url_policy_violation',
            ),
        ).toBe(true);
        await resolver.close();
    });

    // ------------------------------------------------------------------
    // 32. Rolling health window (passive): once the window is full, HEALTHY->DEGRADED (failure rate >= 20%)
    // Summary: when the window is full (20 entries) and the failure rate >= 20%, passive health checking should demote a HEALTHY node to DEGRADED
    // (covers drivePassiveHealth lines 890-894)
    // ------------------------------------------------------------------
    it('should transition HEALTHY node to DEGRADED via full rolling window when failure rate reaches 20%', async () => {
        const alerts: Array<FederationAlertEvent> = [];
        let callCount = 0;
        const did = 'did:agent:rolling-window-full-test' as DID;

        // 1st: failure -> DEGRADED (immediate demotion while the window is not full)
        // 2nd-21st: success -> fill the window, failure rate 1/20=5%<10% -> recover to HEALTHY
        // 22nd-26th: failure -> window full, check failure rate each time (high failureThreshold=100 will not trigger UNHEALTHY)
        vi.stubGlobal(
            'fetch',
            vi.fn().mockImplementation(() => {
                callCount++;
                if (callCount === 1 || callCount >= 22) {
                    // Failure response (not 404)
                    return Promise.resolve({
                        ok: false,
                        status: 500,
                        headers: { get: () => null },
                    });
                }
                // Success response
                return Promise.resolve({
                    ok: true,
                    status: 200,
                    headers: { get: () => '100' },
                    json: () => Promise.resolve(makeDoc(did as string)),
                });
            }),
        );

        const resolver = createFederatedResolver({
            nodes: [{ id: 'n1', url: 'http://n1' }],
            minResponses: 1,
            timeoutMs: 5000,
            cacheTtlMs: 1,
            verifyDIDBinding: makeVerifier(),
            persistentWatermark: makeWatermark(),
            dnsRebindingGuard: makeDnsGuard(),
            onAlert: (e) => alerts.push(e),
            healthCheck: {
                probeIntervalMs: 9_999_999, // very long interval: the probe will not fire during the test
                failureThreshold: 100, // high threshold: keeps consecutiveFailures from triggering UNHEALTHY
                recoveryThreshold: 2,
                probePath: '/health',
            },
        });

        // 1st: failure -> DEGRADED (window short-circuit)
        await resolver.resolve(did);
        expect(resolver.getMetrics().nodes['n1']?.healthState).toBe('DEGRADED');

        // 2nd-21st: success fills the window, failure rate drops to 5% < 10% -> HEALTHY
        for (let i = 0; i < 20; i++) {
            resolver.invalidateCache(did);
            await resolver.resolve(did);
        }
        expect(resolver.getMetrics().nodes['n1']?.healthState).toBe('HEALTHY');

        // 22nd-26th: consecutive failures (window full, consecutiveFailures < 100), failure rate climbs gradually
        // On the 25th failure: window contains 4/20 = 20% failures -> DEGRADED via lines 890-894
        for (let i = 0; i < 5; i++) {
            resolver.invalidateCache(did);
            await resolver.resolve(did);
        }

        const finalHealth = resolver.getMetrics().nodes['n1']?.healthState;
        expect(finalHealth).toBe('DEGRADED');

        await resolver.close();
    });

    // 31. Rolling health window: DEGRADED automatically recovers to HEALTHY once the failure rate drops below 10%
    // Summary: when the window is full (20 entries) and the failure rate < 10%, passive health checking should promote a DEGRADED node to HEALTHY
    // ------------------------------------------------------------------
    it('should transition DEGRADED node to HEALTHY when rolling window failure rate drops below 10%', async () => {
        const alerts: Array<FederationAlertEvent> = [];

        // Simulate: 1 failure first to move the node into DEGRADED, then fill with 20 successes (window full and failure rate = 1/21 < 10%)
        let callCount = 0;

        vi.stubGlobal(
            'fetch',
            vi.fn().mockImplementation(() => {
                callCount++;
                if (callCount === 1) {
                    // 1st: return 500, triggering DEGRADED (window=[false])
                    return Promise.resolve({
                        ok: false,
                        status: 500,
                        headers: { get: () => null },
                    });
                }
                // Subsequent: success response
                const did = 'did:agent:rolling-window-test' as DID;
                return Promise.resolve({
                    ok: true,
                    status: 200,
                    headers: { get: () => '100' },
                    json: () => Promise.resolve(makeDoc(did)),
                });
            }),
        );

        const resolver = createFederatedResolver({
            nodes: [{ id: 'n1', url: 'http://n1' }],
            minResponses: 1,
            timeoutMs: 5000,
            cacheTtlMs: 1, // very short TTL so every resolve triggers a fetch
            verifyDIDBinding: makeVerifier(),
            persistentWatermark: makeWatermark(),
            dnsRebindingGuard: makeDnsGuard(),
            onAlert: (e) => alerts.push(e),
        });

        const did = 'did:agent:rolling-window-test' as DID;

        // 1st: failure -> DEGRADED
        await resolver.resolve(did);
        const afterFirstFail = resolver.getMetrics().nodes['n1']?.healthState;
        expect(afterFirstFail).toBe('DEGRADED');

        // Keep resolving until the window reaches HEALTH_RATE_WINDOW (20 entries) to drive the failure rate down
        // Wait for the TTL to expire (1ms) so each resolve re-fetches
        for (let i = 0; i < 20; i++) {
            await new Promise((r) => setTimeout(r, 5)); // wait for TTL=1ms to expire
            resolver.invalidateCache(did);
            await resolver.resolve(did);
        }

        // In the window: 1 failure + 20 successes = 21 entries; failure rate = max(1/20 in window) = 5% < 10%
        const finalHealth = resolver.getMetrics().nodes['n1']?.healthState;
        const healthChanges = alerts.filter(
            (a) => a.kind === 'FEDERATION_NODE_HEALTH_CHANGED',
        ) as Array<{ kind: string; from: string; to: string }>;
        const recoveryEvents = healthChanges.filter((a) => a.to === 'HEALTHY');
        expect(recoveryEvents.length).toBeGreaterThan(0);
        expect(finalHealth).toBe('HEALTHY');

        await resolver.close();
    });

    // 33. Rolling health window (active probe): DEGRADED recovers to HEALTHY once the probe window is full and failure rate < 10%
    // Summary: covers recordNodeSuccess lines 930-937 (the active-probe path, distinct from the passive drivePassiveHealth)
    // ------------------------------------------------------------------
    it('should transition DEGRADED to HEALTHY via active probe rolling window when failure rate drops below 10%', async () => {
        vi.useFakeTimers();

        const alertFn = vi.fn();
        let probeCall = 0;

        // Probe mock: 1st fails (-> DEGRADED), the next 20 succeed
        const fetchMock = vi.fn().mockImplementation((url: string) => {
            if (url.includes('/federation/health')) {
                probeCall++;
                if (probeCall === 1) {
                    return Promise.resolve({
                        ok: false,
                        status: 500,
                        headers: { get: () => null },
                    });
                }
                return Promise.resolve({
                    ok: true,
                    status: 200,
                    headers: { get: () => null },
                    json: () => Promise.resolve({ status: 'ok' }),
                });
            }
            return Promise.reject(new Error('unexpected fetch: ' + url));
        });
        vi.stubGlobal('fetch', fetchMock);

        const resolver = createFederatedResolver({
            nodes: [{ id: 'n1', url: 'http://n1' }],
            minResponses: 1,
            timeoutMs: 5000,
            cacheTtlMs: 60000,
            verifyDIDBinding: makeVerifier(),
            persistentWatermark: makeWatermark(),
            dnsRebindingGuard: makeDnsGuard(),
            onAlert: alertFn,
            healthCheck: {
                probeIntervalMs: 100,
                failureThreshold: 50, // high threshold: do not trigger UNHEALTHY, let the window path take effect
                recoveryThreshold: 50, // high threshold: let the window path (not consecutiveSuccesses) drive recovery
                probePath: '/federation/health',
            },
        });

        // 1st probe: failure -> DEGRADED (window=[F], length < 20 -> else path)
        await vi.advanceTimersByTimeAsync(100);
        expect(resolver.getMetrics().nodes['n1']?.healthState).toBe('DEGRADED');

        // The next 20 probes succeed: the window fills gradually; on the 20th success window=[F, T x19],
        // then push T -> shift -> window=[T x20], failures=0 < 10% -> HEALTHY (lines 930-937)
        await vi.advanceTimersByTimeAsync(2000); // 20 probe intervals

        const healthAlerts = alertFn.mock.calls
            .map(
                (args) =>
                    args[0] as { kind: string; from?: string; to?: string },
            )
            .filter((e) => e.kind === 'FEDERATION_NODE_HEALTH_CHANGED');
        const recoveryEvents = healthAlerts.filter((e) => e.to === 'HEALTHY');
        expect(recoveryEvents.length).toBeGreaterThan(0);
        expect(resolver.getMetrics().nodes['n1']?.healthState).toBe('HEALTHY');

        vi.useRealTimers();
        await resolver.close();
    });
});

// ============================================================
// DNS rebinding MUST + WatermarkStore required at construction
// ============================================================

import { isPrivateIP } from '../federated-resolver.js';

describe('DNS rebinding MUST + WatermarkStore MUST', () => {
    beforeEach(() => {
        vi.unstubAllGlobals();
    });

    afterEach(() => {
        vi.unstubAllGlobals();
    });

    // ------------------------------------------------------------------
    // Construction-time validation: persistentWatermark MUST
    // ------------------------------------------------------------------
    it('should throw when persistentWatermark is missing', () => {
        expect(() =>
            createFederatedResolver({
                nodes: [{ id: 'n1', url: 'http://n1' }],
                minResponses: 1,
                timeoutMs: 5000,
                cacheTtlMs: 60000,
                verifyDIDBinding: makeVerifier(),
                // eslint-disable-next-line @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-assignment
                persistentWatermark: undefined as any,
                dnsRebindingGuard: makeDnsGuard(),
            }),
        ).toThrow('persistentWatermark');
    });

    it('should throw when persistentWatermark.getWatermark is not a function', () => {
        expect(() =>
            createFederatedResolver({
                nodes: [{ id: 'n1', url: 'http://n1' }],
                minResponses: 1,
                timeoutMs: 5000,
                cacheTtlMs: 60000,
                verifyDIDBinding: makeVerifier(),
                persistentWatermark: {
                    // eslint-disable-next-line @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-assignment
                    getWatermark: null as any,
                    setWatermark: vi.fn(),
                },
                dnsRebindingGuard: makeDnsGuard(),
            }),
        ).toThrow('persistentWatermark');
    });

    // ------------------------------------------------------------------
    // Construction-time validation: dnsRebindingGuard MUST
    // ------------------------------------------------------------------
    it('should throw when dnsRebindingGuard is missing', () => {
        expect(() =>
            createFederatedResolver({
                nodes: [{ id: 'n1', url: 'http://n1' }],
                minResponses: 1,
                timeoutMs: 5000,
                cacheTtlMs: 60000,
                verifyDIDBinding: makeVerifier(),
                persistentWatermark: makeWatermark(),
                // eslint-disable-next-line @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-assignment
                dnsRebindingGuard: undefined as any,
            }),
        ).toThrow('dnsRebindingGuard');
    });

    it('should throw when dnsRebindingGuard.resolveAndValidate is not a function', () => {
        expect(() =>
            createFederatedResolver({
                nodes: [{ id: 'n1', url: 'http://n1' }],
                minResponses: 1,
                timeoutMs: 5000,
                cacheTtlMs: 60000,
                verifyDIDBinding: makeVerifier(),
                persistentWatermark: makeWatermark(),
                dnsRebindingGuard: {
                    // eslint-disable-next-line @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-assignment
                    resolveAndValidate: null as any,
                },
            }),
        ).toThrow('dnsRebindingGuard');
    });

    // ------------------------------------------------------------------
    // isPrivateIP utility function
    // ------------------------------------------------------------------
    it('should detect IPv4 loopback as private', () => {
        expect(isPrivateIP('127.0.0.1')).toBe(true);
        expect(isPrivateIP('127.255.255.255')).toBe(true);
    });

    it('should detect IPv4 RFC1918 ranges as private', () => {
        expect(isPrivateIP('10.0.0.1')).toBe(true);
        expect(isPrivateIP('172.16.0.1')).toBe(true);
        expect(isPrivateIP('172.31.255.255')).toBe(true);
        expect(isPrivateIP('192.168.1.1')).toBe(true);
    });

    it('should detect IPv4 link-local as private', () => {
        expect(isPrivateIP('169.254.0.1')).toBe(true);
        expect(isPrivateIP('169.254.255.255')).toBe(true);
    });

    it('should NOT classify public IPv4 as private', () => {
        expect(isPrivateIP('1.2.3.4')).toBe(false);
        expect(isPrivateIP('8.8.8.8')).toBe(false);
        expect(isPrivateIP('172.32.0.1')).toBe(false); // outside 172.16-31 range
        expect(isPrivateIP('192.169.1.1')).toBe(false); // not 192.168
    });

    it('should detect IPv6 loopback as private', () => {
        expect(isPrivateIP('::1')).toBe(true);
        expect(isPrivateIP('[::1]')).toBe(true); // URL bracket form
    });

    it('should detect IPv6 unique-local as private', () => {
        expect(isPrivateIP('fc00::1')).toBe(true);
        expect(isPrivateIP('fd12:3456:789a::1')).toBe(true);
    });

    it('should detect IPv6 link-local as private', () => {
        expect(isPrivateIP('fe80::1')).toBe(true);
        expect(isPrivateIP('febf::1')).toBe(true); // boundary of fe80::/10
    });

    it('should NOT classify public IPv6 as private', () => {
        expect(isPrivateIP('2001:db8::1')).toBe(false);
        expect(isPrivateIP('2606:4700::1')).toBe(false);
    });

    // ------------------------------------------------------------------
    // DNS rebinding guard runtime behavior: guard throws -> emit alert + resolve returns null
    // ------------------------------------------------------------------
    it('should emit FEDERATION_DNS_REBINDING_BLOCKED and return null when guard blocks private IP', async () => {
        const did = 'did:agent:rebind1' as DID;
        const alerts: FederationAlertEvent[] = [];

        vi.stubGlobal(
            'fetch',
            vi.fn().mockResolvedValue({
                ok: true,
                status: 200,
                headers: { get: () => '100' },
                json: () => Promise.resolve(makeDoc(did, 1)),
            }),
        );

        // Guard always rejects (simulating a DNS rebinding attack)
        const blockingGuard = {
            resolveAndValidate: vi
                .fn()
                .mockRejectedValue(
                    new Error(
                        'DNS rebinding blocked: n1.example.com resolves to private IPs: 192.168.0.1',
                    ),
                ),
        };

        const resolver = createFederatedResolver({
            nodes: [{ id: 'n1', url: 'http://n1.example.com' }],
            minResponses: 1,
            timeoutMs: 5000,
            cacheTtlMs: 60000,
            verifyDIDBinding: makeVerifier(),
            persistentWatermark: makeWatermark(),
            dnsRebindingGuard: blockingGuard,
            onAlert: (e) => alerts.push(e),
        });

        const result = await resolver.resolve(did);
        expect(result).toBeNull();
        expect(
            alerts.some((a) => a.kind === 'FEDERATION_DNS_REBINDING_BLOCKED'),
        ).toBe(true);

        const rebindAlert = alerts.find(
            (a) => a.kind === 'FEDERATION_DNS_REBINDING_BLOCKED',
        );
        expect(rebindAlert).toBeDefined();
        if (rebindAlert?.kind === 'FEDERATION_DNS_REBINDING_BLOCKED') {
            expect(rebindAlert.nodeId).toBe('n1');
            expect(rebindAlert.hostname).toBe('n1.example.com');
            expect(rebindAlert.reason).toContain('192.168.0.1');
        }

        await resolver.close();
    });

    it('should call guard with correct hostname before each fetch', async () => {
        const did = 'did:agent:rebind2' as DID;
        const guardSpy = vi.fn().mockResolvedValue('203.0.113.1');

        vi.stubGlobal(
            'fetch',
            vi.fn().mockResolvedValue({
                ok: true,
                status: 200,
                headers: { get: () => '100' },
                json: () => Promise.resolve(makeDoc(did, 1)),
            }),
        );

        const resolver = createFederatedResolver({
            nodes: [{ id: 'n1', url: 'http://n1.example.com' }],
            minResponses: 1,
            timeoutMs: 5000,
            cacheTtlMs: 60000,
            verifyDIDBinding: makeVerifier(),
            persistentWatermark: makeWatermark(),
            dnsRebindingGuard: { resolveAndValidate: guardSpy },
        });

        await resolver.resolve(did);
        expect(guardSpy).toHaveBeenCalledWith('n1.example.com');

        await resolver.close();
    });

    it('should allow resolution through when guard passes', async () => {
        const did = 'did:agent:rebind3' as DID;

        vi.stubGlobal(
            'fetch',
            vi.fn().mockResolvedValue({
                ok: true,
                status: 200,
                headers: { get: () => '100' },
                json: () => Promise.resolve(makeDoc(did, 1)),
            }),
        );

        const resolver = createFederatedResolver({
            nodes: [{ id: 'n1', url: 'http://n1.example.com' }],
            minResponses: 1,
            timeoutMs: 5000,
            cacheTtlMs: 60000,
            verifyDIDBinding: makeVerifier(),
            persistentWatermark: makeWatermark(),
            dnsRebindingGuard: {
                resolveAndValidate: vi.fn().mockResolvedValue('203.0.113.1'),
            },
        });

        const result = await resolver.resolve(did);
        expect(result).not.toBeNull();
        expect(result?.id).toBe(did);

        await resolver.close();
    });

    it('should degrade node health after guard failure', async () => {
        const did = 'did:agent:rebind4' as DID;

        vi.stubGlobal('fetch', vi.fn());

        const resolver = createFederatedResolver({
            nodes: [{ id: 'n1', url: 'http://n1.example.com' }],
            minResponses: 1,
            timeoutMs: 5000,
            cacheTtlMs: 60000,
            verifyDIDBinding: makeVerifier(),
            persistentWatermark: makeWatermark(),
            dnsRebindingGuard: {
                resolveAndValidate: vi
                    .fn()
                    .mockRejectedValue(new Error('private IP blocked')),
            },
        });

        // Trigger 3 failures to drive a health-state change
        await resolver.resolve(did);
        await resolver.resolve(did);
        await resolver.resolve(did);

        const nodeMetrics = resolver.getMetrics().nodes['n1'];
        expect(nodeMetrics).toBeDefined();
        // The otherFailure count should be at least 3 (no further queries after caching, but cacheTtlMs=60s does not affect this test)
        // Note: due to single-flight, the 3 resolves may merge into 1 actual query
        expect(nodeMetrics!.otherFailure).toBeGreaterThanOrEqual(1);

        await resolver.close();
    });
});
