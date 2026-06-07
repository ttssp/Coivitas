/**
 * Full-chain E2E test
 *
 * This test is the comprehensive regression for the "communication + recording core"; it threads
 * all six layers L0-L5 into an end-to-end closed loop in a single test case, confirming that each layer's
 * contracts remain self-consistent under a real PostgreSQL + real HTTP (127.0.0.1) environment.
 * Splitting it into smaller files would weaken the "cross-layer contract" signal — this case must run
 * all at once to catch the long-tail bug of "all unit packages green / the full chain still broken".
 *
 * ── Scenario (step by step, aligned with the task description) ─────────────────────────────────────────────
 *   1. Agent A registers its identity (did:agent) + publishes its AgentCard (documentVersion=1).
 *   2. Agent B discovers Agent A via DefaultDiscoveryService.discoverFromEndpoint
 *      -> retrieves the AgentCard -> independently runs verifyAgentCard() for signature + document consistency re-verification.
 *   3. Agent B -> Agent A initiates a handshake; sessionStore persists the B<->A Session with state='ACTIVE'.
 *   4. The Principal manually issues a (specVersion=0.2.0) root CapabilityToken to
 *      Agent B, with capabilities declaring both allowlist + temporal_scope (a 1-hour window).
 *      Why manual issuance: issueCapabilityToken() always produces 0.1.0 and does not accept temporal_scope.
 *   5. Agent B sub-delegates the token to Agent C via delegateCapabilityToken(),
 *      attenuating the allowlist ([medical_records, billing_records] -> [medical_records]),
 *      keeping the temporal_scope's 1-hour window (still within the root window).
 *   6. Agent C independently completes a handshake with Agent A -> C<->A Session; then uses its own private key
 *      to build a NegotiationEnvelope (messageType=NEGOTIATION_REQUEST, carrying
 *      capabilityTokenRef=hop1Token.id and sessionId=<C<->A>).
 *      Why have C handshake independently first: task step 6 requires "Agent C builds a NegotiationEnvelope",
 *      the envelope's senderDid must match the signing private key; envelope.header.sessionId should point
 *      to a valid session where C is the sender — C is not a participant in the B<->A session, so reusing it
 *      would violate session-participant semantics. Hence the C<->A session is a required additional step.
 *   7. Agent A receives the envelope -> parseEnvelope -> verifyEnvelope (signature + clock)
 *      -> retrieves the Token corresponding to capabilityTokenRef from tokenStore -> calls RuntimeGuard.check():
 *         - verifies it is within the temporal_scope window (NOW ∈ [notBefore, notAfter))
 *         - the delegation chain is valid (validateDelegationChain -> valid, depth=1)
 *   8. After RuntimeGuard allows it, PolicyEngine calls the executor (INQUIRY action) and calls
 *      recorder.record() to write an ActionRecord. PolicyEngine does not pass sessionId through,
 *      so here we manually orchestrate RuntimeGuard + recorder.record() to faithfully carry
 *      delegationDepth=1 / sessionId=<C<->A> / actorSignature (signed by Agent C's private key).
 *   9. IntegrityChecker.verifyIntegrity() verifies that Agent C's action_records hash
 *      chain is intact (each previous_record_hash aligns with the prior record_hash, and each
 *      record_hash recomputes consistently from the canonicalized form).
 *  10. Mount the GET /records route on a temporary Express app via registerActionRecordRoutes;
 *      the Principal requests with a signed audit request (X-Audit-* headers), and asserts the
 *      response body contains the recordId we wrote.
 *
 * ── Time budget ──────────────────────────────────────────────────────────────
 *   vitest default testTimeout=10_000ms; the task requires the full flow < 10s. Inside it() we
 *   timestamp with Date.now() and at the end make a hard assertion with explicit
 *   expect(elapsedMs).toBeLessThan(10_000), to avoid vitest counting setup time too.
 *
 * ── Gate conditions ─────────────────────────────────────────────────────────────
 *   DATABASE_URL + ENABLE_SOCKET_TESTS=1: requires both a real PostgreSQL ledger table and
 *   a real TCP loopback. Aligned with golden-path.test.ts, ensuring this test does not
 *   sporadically occupy ports / start a DB in the ordinary unit suite.
 */

import {
    createServer,
    type IncomingMessage,
    type Server as HttpServer,
    type ServerResponse,
} from 'node:http';
import { randomUUID } from 'node:crypto';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import {
    canonicalize,
    generateKeyPair,
    sign,
} from '../../packages/crypto/src/index.js';
import {
    createAgentIdentity,
    delegateCapabilityToken,
    didKeyFromPublicKey,
    extractPublicKeyFromDIDKey,
    IdentityRegistry,
    RevocationList,
    validateDelegationChain,
} from '../../packages/identity/src/index.js';
import {
    buildAgentCard,
    buildEnvelope,
    DefaultDiscoveryService,
    HandshakeInitiator,
    HandshakeResponder,
    HttpTransport,
    InMemorySessionStore,
    parseEnvelope,
    verifyAgentCard,
    verifyEnvelope,
} from '../../packages/communication/src/index.js';
import {
    ActionRecorder,
    IntegrityChecker,
    RuntimeGuard,
    TokenStore,
    registerActionRecordRoutes,
} from '../../packages/policy/src/index.js';
import {
    createTestDatabase,
    createTestServer,
} from '../../packages/shared/src/index.js';
import type {
    AgentCard,
    AgentIdentityDocument,
    Capability,
    CapabilityToken,
    DID,
    FederatedResolver,
    FederatedResolverMetrics,
    NegotiationEnvelope,
    ResolvedPublicKeys,
    Timestamp,
} from '../../packages/types/src/index.js';
import { SPEC_VERSION_0_2_0 } from '../../packages/types/src/index.js';

// ─── Test gating ────────────────────────────────────────────────────────────────
// DATABASE_URL: the account/record tables + policy-related migrations must be genuinely available.
// ENABLE_SOCKET_TESTS=1: requires binding a TCP port on 127.0.0.1 to host AgentCard + handshake.
// Skips the test when either environment variable is missing, aligned with golden-path.test.ts / discovery.test.ts.
const describeIfE2E =
    process.env.DATABASE_URL && process.env.ENABLE_SOCKET_TESTS === '1'
        ? describe
        : describe.skip;

// ─── Time anchors (the temporal_scope 1-hour window covers NOW) ─────────────────────────────
// T0 = root token notBefore; ONE_HOUR_LATER = notAfter; NOW falls within the window.
// The specVersion 0.2.0 scope extension requires the root to first declare the temporal_scope dimension before
// a delegator is allowed to introduce / narrow it; here the root token directly declares a 1h window, without further narrowing.
const T0 = '2026-04-24T10:00:00.000Z' as Timestamp;
const NOW = '2026-04-24T10:15:00.000Z' as Timestamp;
const ONE_HOUR_LATER = '2026-04-24T11:00:00.000Z' as Timestamp;
const ROOT_EXPIRES = '2026-04-24T11:00:00.000Z' as Timestamp;
const HOP1_EXPIRES = '2026-04-24T10:55:00.000Z' as Timestamp;

/**
 * Manually issue a specVersion=0.2.0 root Token.
 *
 * Why not use issueCapabilityToken(): it always produces 0.1.0, and
 * token-verifier.ts rejects a 0.1.0 containing temporal_scope with INVALID_TOKEN_FORMAT.
 * We need the capability to declare both allowlist + temporal_scope, which requires 0.2.0.
 *
 * The signing payload remains equivalent to createCapabilityTokenPayload (no delegationChain field;
 * the canonicalized payload of a 0.2.0 root token does not write that key).
 */
function buildPhase2RootToken(params: {
    principalDid: DID;
    principalPrivateKey: string;
    issuedTo: DID;
    capabilities: Capability[];
    issuedAt: Timestamp;
    expiresAt: Timestamp;
    revocationUrl: string;
}): CapabilityToken {
    const payload = {
        id: `urn:cap:${randomUUID()}`,
        specVersion: SPEC_VERSION_0_2_0,
        issuerDid: params.principalDid,
        principalDid: params.principalDid,
        issuedTo: params.issuedTo,
        issuedAt: params.issuedAt,
        expiresAt: params.expiresAt,
        capabilities: params.capabilities,
        revocationUrl: params.revocationUrl,
    };
    const payloadBytes = new TextEncoder().encode(
        canonicalize(payload as unknown as Record<string, unknown>),
    );
    return {
        ...payload,
        proof: {
            type: 'Ed25519Signature2026',
            created: params.issuedAt,
            verificationMethod: `${params.principalDid}#key-1`,
            value: sign(
                payloadBytes,
                params.principalPrivateKey,
            ) as CapabilityToken['proof']['value'],
        },
    } as CapabilityToken;
}

// ─── In-memory FederatedResolver (shared by discovery / AgentCard signature verification) ────────────────
// The discovery layer's verifyAgentCard needs to fetch the authoritative AgentIdentityDocument via
// FederatedResolver to perform publicKey / version / spec / subset consistency comparison; while the
// delegation chain and envelope signature verification also need to resolve the principal public key via did:key.
// A minimal Map implementation suffices, without introducing DB-cache complexity.
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

// ─── Lightweight HTTP server (GET /.well-known/agent.json + POST /handshake) ────────
// No express/koa dependency: node:http is sufficient and does not pollute root dev-deps. port=0 lets the OS
// assign a port, avoiding conflicts with discovery.test.ts's 3001/3002.
interface AgentHttpServer {
    url: string;
    port: number;
    close: () => Promise<void>;
}

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
    agentCard: AgentCard;
    handshake?: (envelope: NegotiationEnvelope) => Promise<NegotiationEnvelope>;
}): Promise<AgentHttpServer> {
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
        server.once('error', reject);
        server.listen(0, '127.0.0.1');
    });

    const address = server.address();
    if (!address || typeof address === 'string') {
        throw new Error('Agent HTTP server failed to bind 127.0.0.1');
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

describeIfE2E('full flow e2e', () => {
    // ─── Top-level resources ────────────────────────────────────────────────────────────
    let cleanup: (() => Promise<void>) | undefined;
    let pool: Awaited<ReturnType<typeof createTestDatabase>>['pool'];
    let identityRegistry: IdentityRegistry;
    let tokenStore: TokenStore;
    let revocations: RevocationList;
    let recorder: ActionRecorder;
    let ledgerPrivateKey: string; // passed into IntegrityChecker's constructor (to avoid reflecting recorder's private field)

    // in-memory DID resolver: used by AgentCard verify / envelope verify / delegation chain
    let resolver: InMemoryResolver;

    // Principal / three Agents
    let principalDid: DID;
    let principalPrivateKey: string;
    let agentA: { did: DID; privateKey: string; doc: AgentIdentityDocument };
    let agentB: { did: DID; privateKey: string; doc: AgentIdentityDocument };
    let agentC: { did: DID; privateKey: string; doc: AgentIdentityDocument };

    // AgentCard + HTTP server (Agent A acts as the discovery + handshake server)
    let agentACard: AgentCard;
    let agentAServer: AgentHttpServer | undefined;
    let clientTransport: HttpTransport | undefined;

    // Token chain
    let rootToken: CapabilityToken;
    let hop1Token: CapabilityToken; // the token after attenuating the Principal -> B root via B -> C

    // session store (one store carries both the B<->A and C<->A sessions)
    let sessionStore: InMemorySessionStore;

    // audit route server
    let auditApiServer: { url: string; close: () => Promise<void> } | undefined;

    beforeAll(async () => {
        const database = await createTestDatabase();
        cleanup = database.cleanup;
        pool = database.pool;

        identityRegistry = new IdentityRegistry(pool);
        tokenStore = new TokenStore(pool);
        // revocation cache TTL=0: this test does not revoke, so the default would also be fine; but explicitly
        // zeroing it avoids a pitfall if someone later adds cascading-revocation assertions.
        revocations = new RevocationList(pool, { cacheTtlMs: 0 });

        // ledger signing key: ActionRecorder requires it to be non-empty; a random keypair suffices (closed test loop).
        // slice(0, 64): an Ed25519 seed is 32 bytes = 64 hex chars; the seed is retained for
        // IntegrityChecker to do ledger signature verification (avoiding reflecting recorder.ledgerPrivateKey).
        const ledger = generateKeyPair();
        ledgerPrivateKey = ledger.privateKey.slice(0, 64);
        recorder = new ActionRecorder(pool, {
            kind: 'standard',
            ledgerPrivateKey,
        });

        resolver = new InMemoryResolver();

        // ── Step 1: create the Principal + three Agent identities ────────────────────────
        const principal = generateKeyPair();
        principalDid = didKeyFromPublicKey(
            Buffer.from(principal.publicKey, 'hex'),
        );
        principalPrivateKey = principal.privateKey;

        // Agent A acts as the discovery target + handshake responder; declares a NegotiationEndpoint.
        // The endpoint url must pass the Ajv https pattern check, but actual requests go to http://127.0.0.1.
        const createdA = createAgentIdentity({
            principalDid,
            principalPrivateKey,
            capabilities: ['INQUIRY', 'QUOTE'],
            serviceEndpoints: [
                {
                    id: 'main',
                    type: 'NegotiationEndpoint',
                    url: 'https://agent-a.example.test',
                },
            ],
        });
        agentA = {
            did: createdA.document.id,
            privateKey: createdA.privateKey,
            doc: createdA.document,
        };

        const createdB = createAgentIdentity({
            principalDid,
            principalPrivateKey,
            capabilities: ['INQUIRY', 'QUOTE'],
        });
        agentB = {
            did: createdB.document.id,
            privateKey: createdB.privateKey,
            doc: createdB.document,
        };

        const createdC = createAgentIdentity({
            principalDid,
            principalPrivateKey,
            capabilities: ['INQUIRY'],
        });
        agentC = {
            did: createdC.document.id,
            privateKey: createdC.privateKey,
            doc: createdC.document,
        };

        // Register in both the DB registry + the in-memory resolver (the former is for the audit API/token
        // chain verification, the latter for envelope verify / discovery — the two paths consume separately).
        await identityRegistry.register(agentA.doc);
        await identityRegistry.register(agentB.doc);
        await identityRegistry.register(agentC.doc);
        resolver.register(agentA.doc);
        resolver.register(agentB.doc);
        resolver.register(agentC.doc);

        // ── Step 1 cont'd: publish Agent A's AgentCard (with documentVersion) ────────
        agentACard = buildAgentCard({
            doc: agentA.doc,
            privateKey: agentA.privateKey,
            displayName: 'Agent A (full-flow e2e)',
        });

        // ── Step 3 precondition: start Agent A's HTTP server (hosting both /.well-known/agent.json + /handshake)
        sessionStore = new InMemorySessionStore();
        const responder = new HandshakeResponder({
            responderDid: agentA.did,
            responderPrivateKey: agentA.privateKey,
            // allowlist: both B + C are allowed (they each handshake with A)
            verifyInitiator: () => Promise.resolve(true),
            resolvePublicKey: async (did: DID) => {
                const doc = await resolver.resolve(did);
                return doc?.publicKey ?? null;
            },
            capabilities: agentA.doc.capabilities ?? [],
            sessionStore,
        });

        agentAServer = await startAgentServer({
            agentCard: agentACard,
            handshake: (envelope) => responder.respond(envelope),
        });
    });

    afterAll(async () => {
        await clientTransport?.close();
        await agentAServer?.close();
        await auditApiServer?.close();
        await cleanup?.();
    });

    it('runs the full 10-step flow within 10s', async () => {
        const startedAt = Date.now();
        expect(agentAServer).toBeDefined();

        // ─── Step 2: Agent B discovers Agent A ────────────────────────────────────
        // DefaultDiscoveryService.discoverFromEndpoint comes with verifyAgentCard (+
        // binding against the resolver's authoritative document); then independently call verifyAgentCard()
        // for cross re-verification, triggering field-level consistency checks such as
        // "documentVersion === doc.version" / "endpoints ⊆ doc.endpoints".
        const discovery = new DefaultDiscoveryService({ resolver });
        const discoveredCard = await discovery.discoverFromEndpoint(
            agentAServer!.url,
            agentA.did,
        );
        expect(discoveredCard.did).toBe(agentA.did);
        expect(discoveredCard.documentVersion).toBe(agentA.doc.version ?? 1);
        const cardValid = await verifyAgentCard(
            discoveredCard,
            (did) => resolver.resolve(did),
            agentA.did,
        );
        expect(
            cardValid,
            'AgentCard signature + authoritative doc cross-check must succeed',
        ).toBe(true);

        // ─── Step 3: Agent B -> Agent A handshake ───────────────────────────────────
        clientTransport = new HttpTransport();
        const initiatorBA = new HandshakeInitiator({
            initiatorDid: agentB.did,
            initiatorPrivateKey: agentB.privateKey,
            transport: clientTransport,
            resolvePublicKey: async (did: DID) => {
                const doc = await resolver.resolve(did);
                return doc?.publicKey ?? null;
            },
            capabilities: agentB.doc.capabilities ?? [],
        });
        const handshakeBA = await initiatorBA.initiate({
            responderDid: agentA.did,
            responderEndpoint: `${agentAServer!.url}/handshake`,
        });
        // negotiatedCapabilities = the A ∩ B capabilities of both sides (['INQUIRY','QUOTE'])
        expect(
            new Set(handshakeBA.negotiatedCapabilities),
            'B↔A negotiated capabilities should be A∩B',
        ).toEqual(new Set(['INQUIRY', 'QUOTE']));

        // persisted session assertion: state === 'ACTIVE'
        const sessionBA = await sessionStore.get(handshakeBA.sessionId);
        expect(sessionBA).not.toBeNull();
        expect(sessionBA!.state).toBe('ACTIVE');
        expect(sessionBA!.initiatorDid).toBe(agentB.did);
        expect(sessionBA!.responderDid).toBe(agentA.did);

        // ─── Step 4: Principal issues a Root Token to Agent B ─────────────────────
        // Two capabilities: the allowlist dimension + the temporal_scope dimension (1h window).
        // scope extension constraint: a delegator cannot introduce a scope dimension the parent did not declare;
        // the root must have both dimensions present for the subsequent B->C to legitimately carry temporal_scope.
        rootToken = buildPhase2RootToken({
            principalDid,
            principalPrivateKey,
            issuedTo: agentB.did,
            capabilities: [
                {
                    action: 'INQUIRY',
                    scope: {
                        type: 'allowlist',
                        field: 'resource_type',
                        values: ['medical_records', 'billing_records'],
                    },
                },
                {
                    action: 'INQUIRY',
                    scope: {
                        type: 'temporal_scope',
                        notBefore: T0,
                        notAfter: ONE_HOUR_LATER,
                    },
                },
            ],
            issuedAt: T0,
            expiresAt: ROOT_EXPIRES,
            revocationUrl: 'https://revocation.example.com/v1/{id}',
        });
        await tokenStore.store(agentB.did, rootToken);

        // ─── Step 5: Agent B -> Agent C sub-delegation (allowlist attenuation) ──────────────
        // the allowlist narrows from [medical_records, billing_records] to [medical_records];
        // the temporal_scope keeps its 1h window (root = child, still a valid subset).
        hop1Token = delegateCapabilityToken({
            parentToken: rootToken,
            delegatorPrivateKey: agentB.privateKey,
            delegateeDid: agentC.did,
            attenuatedCapabilities: [
                {
                    action: 'INQUIRY',
                    scope: {
                        type: 'allowlist',
                        field: 'resource_type',
                        values: ['medical_records'],
                    },
                },
                {
                    action: 'INQUIRY',
                    scope: {
                        type: 'temporal_scope',
                        notBefore: T0,
                        notAfter: ONE_HOUR_LATER,
                    },
                },
            ],
            expiresAt: HOP1_EXPIRES,
            revocationUrl: 'https://revocation.example.com/v1/{id}',
            issuedAt: T0,
        });
        await tokenStore.store(agentC.did, hop1Token);

        // ── Step 6 precondition: C handshakes independently with A (to obtain the C<->A sessionId for the envelope to carry) ──
        const initiatorCA = new HandshakeInitiator({
            initiatorDid: agentC.did,
            initiatorPrivateKey: agentC.privateKey,
            transport: clientTransport,
            resolvePublicKey: async (did: DID) => {
                const doc = await resolver.resolve(did);
                return doc?.publicKey ?? null;
            },
            capabilities: agentC.doc.capabilities ?? [],
        });
        const handshakeCA = await initiatorCA.initiate({
            responderDid: agentA.did,
            responderEndpoint: `${agentAServer!.url}/handshake`,
        });
        // C declares only ['INQUIRY']; intersected with A's ['INQUIRY','QUOTE'] = ['INQUIRY']
        expect(handshakeCA.negotiatedCapabilities).toEqual(['INQUIRY']);
        const sessionCA = await sessionStore.get(handshakeCA.sessionId);
        expect(sessionCA?.state).toBe('ACTIVE');

        // ─── Step 6: Agent C builds a NegotiationEnvelope (with capabilityTokenRef) ──
        // When capabilityTokenRef enters the header, envelope.specVersion is automatically promoted to 0.2.0
        // (envelope.ts line 72-76). The signing private key must be C's — otherwise envelope verify
        // would fail because senderDid does not match the signature.
        const envelope = buildEnvelope({
            senderDid: agentC.did,
            senderPrivateKey: agentC.privateKey,
            recipientDid: agentA.did,
            sessionId: handshakeCA.sessionId,
            messageType: 'NEGOTIATION_REQUEST',
            body: {
                action: 'INQUIRY',
                params: { resource_type: 'medical_records' },
            },
            capabilityTokenRef: hop1Token.id,
        });
        expect(envelope.specVersion).toBe(SPEC_VERSION_0_2_0);
        expect(envelope.header.capabilityTokenRef).toBe(hop1Token.id);
        expect(envelope.header.sessionId).toBe(handshakeCA.sessionId);

        // ─── Step 7: Agent A receives -> parse/verify -> guard.check() ──────────────
        // Serialize and deserialize once, simulating real HTTP transmission (ensuring canonicalization closes the loop).
        const onWire = JSON.parse(
            JSON.stringify(envelope),
        ) as NegotiationEnvelope;
        const received = parseEnvelope(onWire);
        const envelopeVerify = await verifyEnvelope(received, {
            resolvePublicKey: async (did: DID) => {
                const doc = await resolver.resolve(did);
                return doc?.publicKey ?? null;
            },
            // the real-time now() participates in verifyEnvelope's ±300s clock check; envelope.timestamp
            // is written by buildEnvelope as new Date().toISOString(), guaranteeing freshness.
            now: () => Date.now(),
        });
        expect(
            envelopeVerify.valid,
            `envelope verification failed: ${envelopeVerify.reason}`,
        ).toBe(true);

        // fetch the actual token from tokenStore by ref; RuntimeGuard will do another
        // store query inside check(), this is just contract verification of "envelope.capabilityTokenRef -> resolvable token".
        const fetchedToken = await tokenStore.getToken(
            received.header.capabilityTokenRef!,
        );
        expect(fetchedToken).not.toBeNull();
        expect(fetchedToken!.id).toBe(hop1Token.id);

        // RuntimeGuard.check(): within the temporal_scope window + valid delegation chain -> allowed.
        // resolvePublicKeys handles both did:key (root signature verification) and did:agent (delegator
        // signature verification); the same dual-mode resolver as in delegation.test.ts.
        // The field is named resolvePublicKeys (dual-key version);
        // the e2e does not involve rotation, so it is wrapped as a STABLE single key.
        const guard = new RuntimeGuard({
            tokenStore,
            revocationChecker: (id) => revocations.isRevoked(id),
            now: () => NOW,
            delegationChainValidator: validateDelegationChain,
            resolvePublicKeys: async (
                did: DID,
            ): Promise<ResolvedPublicKeys | null> => {
                let key: string | null;
                if (did.startsWith('did:key:')) {
                    key = extractPublicKeyFromDIDKey(did);
                } else {
                    const doc = await resolver.resolve(did);
                    key = doc?.publicKey ?? null;
                }
                return key === null
                    ? null
                    : { current: key, rotationState: 'STABLE' };
            },
        });
        const guardResult = await guard.check(
            'INQUIRY',
            { resource_type: 'medical_records' },
            agentC.did,
            received.header.capabilityTokenRef,
        );
        expect(
            guardResult.allowed,
            `guard should allow: reason=${guardResult.reason ?? ''}`,
        ).toBe(true);
        expect(guardResult.tokenId).toBe(hop1Token.id);
        // Step 7 assertion: delegation chain depth = 1 (C delegated from B in a single hop)
        expect(guardResult.delegationDepth).toBe(1);

        // independently run validateDelegationChain again as a contract assertion (confirming Step 7 semantics)
        // the 2nd argument is ResolvedPublicKeys (dual-key version); the e2e does not involve
        // rotation, so it is wrapped as a STABLE single key.
        const chainResult = await validateDelegationChain(
            hop1Token,
            async (did: DID): Promise<ResolvedPublicKeys | null> => {
                let key: string | null;
                if (did.startsWith('did:key:')) {
                    key = extractPublicKeyFromDIDKey(did);
                } else {
                    const doc = await resolver.resolve(did);
                    key = doc?.publicKey ?? null;
                }
                return key === null
                    ? null
                    : { current: key, rotationState: 'STABLE' };
            },
            (id) => revocations.isRevoked(id),
            NOW,
            (tokenId) => tokenStore.getToken(tokenId),
        );
        expect(chainResult.valid).toBe(true);
        expect(chainResult.depth).toBe(1);

        // ─── Step 8: execute INQUIRY + write ActionRecord (with delegationDepth/sessionId/actorSignature)
        // PolicyEngine.executeWithPolicy does not pass sessionId through to the recorder (engine.ts:
        // line 147-215's parameters do not include sessionId). The task requires the record to carry sessionId, so
        // here we bypass the engine and orchestrate directly: the guard has allowed -> executor run -> recorder.record.
        // This manual orchestration is equivalent to the orchestrator step3.5-step4 logic.
        const executor = (): Promise<{ ok: boolean }> =>
            Promise.resolve({ ok: true });
        const executorResult = await executor();
        expect(executorResult.ok).toBe(true);

        const recordWriteResult = await recorder.record({
            agentDid: agentC.did,
            principalDid,
            actionType: 'INQUIRY',
            parametersSummary: { resource_type: 'medical_records' },
            authorizationRef: {
                tokenId: guardResult.tokenId ?? hop1Token.id,
            },
            resultSummary: { status: 'SUCCESS' },
            actorPrivateKey: agentC.privateKey,
            delegationDepth: guardResult.delegationDepth,
            sessionId: handshakeCA.sessionId,
        });
        expect(recordWriteResult.recordId).toBeDefined();
        expect(recordWriteResult.hash.length).toBeGreaterThan(0);

        // read back and make field-level assertions: delegationDepth=1 / sessionId matches / actorSignature non-empty
        const { records } = await recorder.query({
            agentDid: agentC.did,
            limit: 10,
        });
        const persisted = records.find(
            (r) => r.recordId === recordWriteResult.recordId,
        );
        expect(persisted, 'persisted record must be queryable').toBeDefined();
        expect(persisted!.delegationDepth).toBe(1);
        expect(persisted!.sessionId).toBe(handshakeCA.sessionId);
        expect(
            persisted!.actorSignature,
            'actor signature must be non-empty (Agent C signed)',
        ).toBeTruthy();
        expect(persisted!.actorSignature.length).toBeGreaterThan(0);
        expect(
            persisted!.ledgerSignature,
            'ledger signature must be non-empty (ActionRecorder signed)',
        ).toBeTruthy();

        // ─── Step 9: IntegrityChecker verifies the hash chain ─────────────────────────────
        // Use standard mode (business-chain verification).
        // This e2e scenario produces no SESSION_SUPERSEDED record, so governor DID fail-closed does not affect the business path.
        const integrity = new IntegrityChecker(pool, {
            kind: 'standard',
            ledgerPrivateKey,
            ledgerPublicKey: recorder.ledgerPublicKey,
            resolveIdentity: async (did: DID) => {
                const doc = await resolver.resolve(did);
                return doc?.publicKey ?? null;
            },
        });
        const integrityResult = await integrity.verifyIntegrity(agentC.did);
        expect(
            integrityResult.valid,
            `integrity check failed at ${integrityResult.brokenAt ?? 'unknown'}: ${integrityResult.reason ?? ''}`,
        ).toBe(true);

        // ─── Step 10: start the GET /records audit API + signed request ────────────────────
        // Use @coivitas/shared's createTestServer: internally createApp has already mounted
        // express.json + helmet + cors + rate-limit + errorHandler, and passes the Express
        // Application to the callback; registerActionRecordRoutes registers routes on this app.
        // This avoids importing express directly into root package.json (keeping the dependency surface clean,
        // consistent with discovery.test.ts's "manually starting a server with node:http" design).

        // createApp redirects `app.get()` to the internal apiRouter; registerActionRecordRoutes
        // registers /records* and /ledger/head all as get routes, so the behavior here is identical.
        const server = await createTestServer((app) => {
            registerActionRecordRoutes(app, {
                dbPool: pool,
                identityRegistry,
                ledgerPublicKey: recorder.ledgerPublicKey,
            });
        });
        const apiUrl = server.url;
        auditApiServer = { url: apiUrl, close: server.close };

        // query /ledger/head to get the snapshot boundary;
        // an unsigned auxiliary endpoint, requiring only the agent_did query.
        const headResp = await fetch(
            `${apiUrl}/ledger/head?agent_did=${encodeURIComponent(agentC.did)}`,
        );
        expect(headResp.status).toBe(200);
        const head = (await headResp.json()) as {
            agentDid: string;
            headRecordId: string;
            headCreatedAt: string;
            headRecordHash: string;
        };
        expect(head.headRecordId).toBe(recordWriteResult.recordId);

        // construct the signed audit request: the payload structure is fully aligned with
        // action-record-routes.integration.test.ts's makeHeaders()
        // (camelCase fields, resourceBinding, snapshotBoundary, timestamp).
        const requestTimestamp = new Date().toISOString();
        const signaturePayload = {
            requesterDid: principalDid,
            targetAgentDid: agentC.did,
            httpMethod: 'GET' as const,
            resourceBinding: { route: 'records.list', recordId: null },
            queryParams: { agentDid: agentC.did },
            snapshotBoundary: {
                headCreatedAt: head.headCreatedAt,
                headRecordId: head.headRecordId,
                headRecordHash: head.headRecordHash,
            },
            timestamp: requestTimestamp,
        };
        const signatureBytes = new TextEncoder().encode(
            canonicalize(signaturePayload),
        );
        const auditSignature = sign(signatureBytes, principalPrivateKey);

        const listResp = await fetch(
            `${apiUrl}/records?agent_did=${encodeURIComponent(agentC.did)}`,
            {
                method: 'GET',
                headers: {
                    'x-audit-requester': principalDid,
                    'x-audit-signature': auditSignature,
                    'x-audit-timestamp': requestTimestamp,
                    'x-audit-snapshot-headcreatedat': head.headCreatedAt,
                    'x-audit-snapshot-headrecordid': head.headRecordId,
                    'x-audit-snapshot-headrecordhash': head.headRecordHash,
                },
            },
        );
        expect(
            listResp.status,
            `GET /records expected 200, got ${listResp.status}: ${await listResp.clone().text()}`,
        ).toBe(200);
        const listBody = (await listResp.json()) as {
            records: Array<{ recordId: string; agentDid: string }>;
        };
        expect(listBody.records.length).toBeGreaterThanOrEqual(1);
        const queried = listBody.records.find(
            (r) => r.recordId === recordWriteResult.recordId,
        );
        expect(
            queried,
            `recordId ${recordWriteResult.recordId} should be queryable via GET /records; got [${listBody.records
                .map((r) => r.recordId)
                .join(',')}]`,
        ).toBeDefined();
        expect(queried!.agentDid).toBe(agentC.did);

        // ─── Time-limit assertion: full flow < 10s ─────────────────────────────────────────
        const elapsedMs = Date.now() - startedAt;
        expect(
            elapsedMs,
            `Full flow must complete under 10s; took ${elapsedMs}ms`,
        ).toBeLessThan(10_000);
    }, 10_000);
});
