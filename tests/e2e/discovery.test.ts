/**
 * Discovery flow E2E test
 *
 * Scenario:
 *   1. Agent A (HTTP server @ 127.0.0.1:3001)
 *      - registers its identity (into the in-memory registry)
 *      - publishes its AgentCard: GET /.well-known/agent.json
 *      - hosts a Handshake responder: POST /handshake
 *   2. Agent B (HTTP server @ 127.0.0.1:3002)
 *      - registers its identity (in the same in-memory registry, so peers can resolve each other)
 *      - also publishes its own AgentCard (symmetric), but in this test acts only as the initiator
 *      - discovers Agent A via DefaultDiscoveryService.discoverFromEndpoint
 *          ("discoverAgent(url)" maps to the public entry point discoverFromEndpoint;
 *           the discoverAgent() top-level function is an internal private implementation in discovery-service.ts)
 *      - verifies the returned AgentCard signature is valid
 *      - initiates a Handshake (via HttpTransport POST to http://127.0.0.1:3001/handshake)
 *      - verifies HandshakeResult.negotiatedCapabilities
 *   3. End-to-end < 10s (vitest testTimeout=10_000, with an explicit assertion)
 *
 * Design decisions:
 *   - No PostgreSQL dependency: uses Map<DID, AgentIdentityDocument> as the in-memory
 *     FederatedResolver adapter, avoiding a DB dependency to keep gating simpler.
 *   - No express dependency in root package.json: starts a Server directly with node:http,
 *     manually routing /.well-known/agent.json and /handshake; the effect is equivalent to an
 *     "Express server", but keeps root dev deps clean.
 *   - Uses InMemorySessionStore injected into HandshakeResponder.sessionStore,
 *     ensuring session.state === 'ACTIVE' is persisted after a successful handshake.
 *   - Ports 3001/3002 are hardcoded (aligned with the task description); if occupied the test fails immediately with a clear error.
 *   - HandshakeInitiator's transport uses HttpTransport directly (endpoint pointing to
 *     http://127.0.0.1:3001/handshake); the POST response body is the ACK envelope.
 *
 * Pass conditions (per task requirements):
 *   - AgentCard.documentVersion === AgentIdentityDocument.version
 *   - AgentCard signature verification passes (verifyAgentCard() === true)
 *   - Handshake session created successfully (sessionId is a non-empty UUID)
 *   - session.state === 'ACTIVE'
 */

import {
    createServer,
    type IncomingMessage,
    type Server as HttpServer,
    type ServerResponse,
} from 'node:http';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { generateKeyPair } from '../../packages/crypto/src/index.js';
import {
    createAgentIdentity,
    didKeyFromPublicKey,
} from '../../packages/identity/src/index.js';
import {
    buildAgentCard,
    DefaultDiscoveryService,
    HandshakeInitiator,
    HandshakeResponder,
    HttpTransport,
    InMemorySessionStore,
    verifyAgentCard,
} from '../../packages/communication/src/index.js';
import type {
    AgentCard,
    AgentIdentityDocument,
    DID,
    FederatedResolver,
    FederatedResolverMetrics,
    NegotiationEnvelope,
} from '../../packages/types/src/index.js';

// ─── Test gating ────────────────────────────────────────────────────────────────
// Aligned with the other e2e tests: only runs when ENABLE_SOCKET_TESTS=1, to avoid
// occupying ports inside the pure unit suite.
// This test does not depend on DATABASE_URL (fully in-memory).
const describeIfSockets =
    process.env.ENABLE_SOCKET_TESTS === '1' ? describe : describe.skip;

// ─── In-memory resolver (minimal FederatedResolver implementation) ───────────────────────────────
class InMemoryResolver implements FederatedResolver {
    private readonly store = new Map<DID, AgentIdentityDocument>();

    register(doc: AgentIdentityDocument): void {
        this.store.set(doc.id, doc);
    }

    resolve(did: DID): Promise<AgentIdentityDocument | null> {
        return Promise.resolve(this.store.get(did) ?? null);
    }

    invalidateCache(): void {
        // no cache layer — return directly
    }

    getMetrics(): FederatedResolverMetrics {
        return {
            resolveTotal: 0,
            resolveSuccess: 0,
            resolveNull: 0,
            resolveInternalError: 0,
            versionConflictCount: 0,
            signatureInvalidCount: 0,
            quorumUnmetCount: 0,
            cacheHit: 0,
            cacheMiss: 0,
            latencyP50Ms: 0,
            latencyP95Ms: 0,
            latencyP99Ms: 0,
            nodes: {},
        };
    }

    close(): Promise<void> {
        return Promise.resolve();
    }
}

// ─── Start a minimal HTTP server: expose AgentCard + optional handshake POST ─────────────
interface AgentServer {
    url: string;
    port: number;
    close: () => Promise<void>;
}

/**
 * Read the request body as a utf8 string.
 */
async function readBody(req: IncomingMessage): Promise<string> {
    const chunks: Buffer[] = [];
    for await (const chunk of req as AsyncIterable<string | Buffer>) {
        chunks.push(typeof chunk === 'string' ? Buffer.from(chunk) : chunk);
    }
    return Buffer.concat(chunks).toString('utf8');
}

function writeJson(res: ServerResponse, status: number, body: unknown): void {
    res.statusCode = status;
    res.setHeader('content-type', 'application/json; charset=utf-8');
    res.end(JSON.stringify(body));
}

async function startAgentServer(params: {
    port: number;
    agentCard: AgentCard;
    // optional: handshake response handler; if not provided, POST /handshake is not mounted
    handshake?: (envelope: NegotiationEnvelope) => Promise<NegotiationEnvelope>;
}): Promise<AgentServer> {
    const server = createServer((req, res) => {
        void (async () => {
            try {
                const method = req.method ?? '';
                const url = req.url ?? '';

                if (method === 'GET' && url === '/.well-known/agent.json') {
                    res.setHeader('cache-control', 'public, max-age=300');
                    writeJson(res, 200, params.agentCard);
                    return;
                }

                if (
                    method === 'POST' &&
                    url === '/handshake' &&
                    params.handshake
                ) {
                    const raw = await readBody(req);
                    const envelope = JSON.parse(raw) as NegotiationEnvelope;
                    const ack = await params.handshake(envelope);
                    writeJson(res, 200, ack);
                    return;
                }

                writeJson(res, 404, {
                    code: 'NOT_FOUND',
                    message: `${method} ${url}`,
                });
            } catch (err) {
                const message =
                    err instanceof Error ? err.message : 'handler error';
                writeJson(res, 500, { code: 'INTERNAL_ERROR', message });
            }
        })();
    });

    await new Promise<void>((resolve, reject) => {
        server.once('listening', () => resolve());
        server.once('error', (err) =>
            reject(
                new Error(
                    `Failed to bind HTTP server on 127.0.0.1:${params.port}: ${err.message}`,
                ),
            ),
        );
        server.listen(params.port, '127.0.0.1');
    });

    const address = server.address();
    if (!address || typeof address === 'string') {
        throw new Error(
            `Server failed to bind TCP port on 127.0.0.1:${params.port}`,
        );
    }

    const httpServer: HttpServer = server;
    return {
        port: address.port,
        url: `http://127.0.0.1:${address.port}`,
        close: () =>
            new Promise<void>((resolve, reject) => {
                httpServer.closeAllConnections?.();
                httpServer.close((err) => {
                    if (err) reject(err);
                    else resolve();
                });
            }),
    };
}

// ─── Tests ────────────────────────────────────────────────────────────────────

describeIfSockets('discovery e2e', () => {
    const AGENT_A_PORT = 3001;
    const AGENT_B_PORT = 3002;

    let agentAServer: AgentServer | undefined;
    let agentBServer: AgentServer | undefined;
    let clientTransport: HttpTransport | undefined;

    // top-level resources (constructed once in beforeAll, assertions made inside it)
    let resolver: InMemoryResolver;
    let agentADoc: AgentIdentityDocument;
    let agentAPrivateKey: string;
    let agentACard: AgentCard;
    let agentBDoc: AgentIdentityDocument;
    let agentBPrivateKey: string;
    let agentBCard: AgentCard;
    let sessionStore: InMemorySessionStore;

    beforeAll(async () => {
        resolver = new InMemoryResolver();

        // 1. Alice (principal) -> Agent A; Bob (principal) -> Agent B
        const alice = generateKeyPair();
        const aliceDid = didKeyFromPublicKey(
            Buffer.from(alice.publicKey, 'hex'),
        );

        const agentA = createAgentIdentity({
            principalDid: aliceDid,
            principalPrivateKey: alice.privateKey,
            capabilities: ['INQUIRY', 'QUOTE'],
            // a valid https URL is only to pass the Ajv pattern check; real requests go to http://127.0.0.1
            serviceEndpoints: [
                {
                    id: 'main',
                    type: 'NegotiationEndpoint',
                    url: 'https://agent-a.example.test',
                },
            ],
        });
        agentADoc = agentA.document;
        agentAPrivateKey = agentA.privateKey;
        resolver.register(agentADoc);

        const bob = generateKeyPair();
        const bobDid = didKeyFromPublicKey(Buffer.from(bob.publicKey, 'hex'));
        const agentB = createAgentIdentity({
            principalDid: bobDid,
            principalPrivateKey: bob.privateKey,
            capabilities: ['QUOTE', 'CONFIRM'],
            serviceEndpoints: [
                {
                    id: 'main',
                    type: 'NegotiationEndpoint',
                    url: 'https://agent-b.example.test',
                },
            ],
        });
        agentBDoc = agentB.document;
        agentBPrivateKey = agentB.privateKey;
        resolver.register(agentBDoc);

        // 2. Build AgentCards (A publishes; B publishes too, to satisfy the "both are HTTP servers" description)
        agentACard = buildAgentCard({
            doc: agentADoc,
            privateKey: agentAPrivateKey,
            displayName: 'Agent A (discovery e2e)',
        });
        agentBCard = buildAgentCard({
            doc: agentBDoc,
            privateKey: agentBPrivateKey,
            displayName: 'Agent B (discovery e2e)',
        });

        // 3. Agent A's handshake responder: inject InMemorySessionStore, state=ACTIVE after responding
        sessionStore = new InMemorySessionStore();
        const responder = new HandshakeResponder({
            responderDid: agentADoc.id,
            responderPrivateKey: agentAPrivateKey,
            verifyInitiator: () => Promise.resolve(true),
            resolvePublicKey: async (did: DID) => {
                const doc = await resolver.resolve(did);
                return doc?.publicKey ?? null;
            },
            capabilities: agentADoc.capabilities ?? [],
            sessionStore,
        });

        // 4. Start two HTTP servers; Agent A mounts the handshake POST, Agent B only publishes its own AgentCard
        agentAServer = await startAgentServer({
            port: AGENT_A_PORT,
            agentCard: agentACard,
            handshake: (envelope) => responder.respond(envelope),
        });
        agentBServer = await startAgentServer({
            port: AGENT_B_PORT,
            agentCard: agentBCard,
        });
    });

    afterAll(async () => {
        await clientTransport?.close();
        await agentAServer?.close();
        await agentBServer?.close();
    });

    it('Agent B discovers Agent A, verifies the card, and completes handshake with an ACTIVE session', async () => {
        const startedAt = Date.now();

        // Basic precondition: both servers must have bound successfully in beforeAll
        expect(
            agentAServer,
            'Agent A HTTP server should be initialised by beforeAll',
        ).toBeDefined();
        expect(
            agentAServer!.port,
            `Agent A must bind to task-specified port ${AGENT_A_PORT}`,
        ).toBe(AGENT_A_PORT);
        expect(
            agentBServer!.port,
            `Agent B must bind to task-specified port ${AGENT_B_PORT}`,
        ).toBe(AGENT_B_PORT);

        // ── 1. Agent B discovers Agent A via DefaultDiscoveryService.discoverFromEndpoint ──
        // "discoverAgent(url)" maps to the public entry point discoverFromEndpoint.
        // Passing expectedDid forces card.did === agentADoc.id, preventing cross-identity endpoint theft.
        const discovery = new DefaultDiscoveryService({ resolver });
        const discoveredCard = await discovery.discoverFromEndpoint(
            agentAServer!.url,
            agentADoc.id,
        );

        // ── 2. Key assertion: documentVersion === AgentIdentityDocument.version ──
        expect(
            discoveredCard.documentVersion,
            `AgentCard.documentVersion (${discoveredCard.documentVersion}) must equal AgentIdentityDocument.version (${String(agentADoc.version)})`,
        ).toBe(agentADoc.version ?? 1);
        expect(
            discoveredCard.did,
            `Discovered card DID (${discoveredCard.did}) must equal registered Agent A DID (${agentADoc.id})`,
        ).toBe(agentADoc.id);

        // ── 3. Key assertion: AgentCard signature verification passes (re-verified independently of discoveryService) ──
        // verifyAgentCard re-canonicalizes the payload, performs ed25519 signature verification,
        // and cross-checks field consistency against the authoritative document in the resolver
        // (publicKey / version / specVersion equal, endpoints / capabilities are subsets).
        const valid = await verifyAgentCard(
            discoveredCard,
            (did) => resolver.resolve(did),
            agentADoc.id,
        );
        expect(
            valid,
            `AgentCard signature/content verification against resolver failed; card=${JSON.stringify(
                {
                    did: discoveredCard.did,
                    documentVersion: discoveredCard.documentVersion,
                    publicKey: discoveredCard.publicKey,
                    signaturePrefix: discoveredCard.signature.slice(0, 16),
                },
            )}`,
        ).toBe(true);

        // ── 4. Agent B initiates a Handshake (HttpTransport -> POST /handshake) ──
        clientTransport = new HttpTransport();
        const initiator = new HandshakeInitiator({
            initiatorDid: agentBDoc.id,
            initiatorPrivateKey: agentBPrivateKey,
            transport: clientTransport,
            resolvePublicKey: async (did: DID) => {
                const doc = await resolver.resolve(did);
                return doc?.publicKey ?? null;
            },
            capabilities: agentBDoc.capabilities ?? [],
        });

        const handshakeResult = await initiator.initiate({
            responderDid: agentADoc.id,
            responderEndpoint: `${agentAServer!.url}/handshake`,
        });

        // ── 5. Key assertion: negotiatedCapabilities = A.cap ∩ B.cap ──
        // A declares ['INQUIRY','QUOTE'], B declares ['QUOTE','CONFIRM'];
        // HandshakeResponder first computes challenge.initiatorCapabilities ∩ A.cap -> responderCapabilities;
        // HandshakeInitiator returns responderCapabilities ∩ B.cap; the overall result equals ['QUOTE'].
        expect(
            handshakeResult.negotiatedCapabilities,
            `negotiatedCapabilities expected to be A (${(agentADoc.capabilities ?? []).join(',')}) ∩ B (${(agentBDoc.capabilities ?? []).join(',')}) = ['QUOTE']; got [${handshakeResult.negotiatedCapabilities.join(',')}]`,
        ).toEqual(['QUOTE']);

        expect(
            handshakeResult.sessionId,
            `Handshake session id must be a non-empty UUID; got "${handshakeResult.sessionId}"`,
        ).toMatch(
            /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,
        );

        // ── 6. Key assertion: session.state === 'ACTIVE' ──
        const persistedSession = await sessionStore.get(
            handshakeResult.sessionId,
        );
        expect(
            persistedSession,
            `Session ${handshakeResult.sessionId} should have been persisted by HandshakeResponder but was not found in sessionStore`,
        ).not.toBeNull();
        expect(
            persistedSession!.state,
            `Persisted session state should be 'ACTIVE' after successful handshake; got '${persistedSession!.state}'`,
        ).toBe('ACTIVE');
        expect(
            persistedSession!.initiatorDid,
            `Persisted session.initiatorDid mismatch: expected ${agentBDoc.id}, got ${persistedSession!.initiatorDid}`,
        ).toBe(agentBDoc.id);
        expect(
            persistedSession!.responderDid,
            `Persisted session.responderDid mismatch: expected ${agentADoc.id}, got ${persistedSession!.responderDid}`,
        ).toBe(agentADoc.id);
        expect(
            persistedSession!.negotiatedCapabilities,
            `Persisted session.negotiatedCapabilities mismatch; got [${persistedSession!.negotiatedCapabilities.join(',')}]`,
        ).toEqual(['QUOTE']);

        // ── 7. Time-limit assertion: full flow < 10s ──
        const elapsedMs = Date.now() - startedAt;
        expect(
            elapsedMs,
            `Discovery + handshake flow must finish under 10s; took ${elapsedMs}ms`,
        ).toBeLessThan(10_000);
    });
});
