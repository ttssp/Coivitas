/**
 * Federated resolution E2E test
 *
 * Scenario:
 *   1. Start 3 Express nodes to simulate a federation (ports 4001/4002/4003)
 *   2. Node 1 registers Agent A -> broadcasts sync to nodes 2/3
 *   3. FederatedResolver.resolve(agentA.did) -> succeeds (all 3 nodes consistent)
 *   4. Shut down node 3
 *   5. FederatedResolver.resolve(agentA.did) -> still succeeds (minResponses=2)
 *   6. Node 1 updates Agent A (version=2) -> syncs to node 2
 *   7. Node 3 recovers (still at version=1)
 *   8. FederatedResolver.resolve -> returns version=2 (highest version wins)
 *   9. Verify getMetrics(): resolution latency, cache hit rate, version conflict frequency
 *
 * Design decisions:
 *   - No PostgreSQL dependency: each node holds a Map<DID, AgentIdentityDocument> as
 *     in-memory storage, avoiding a DB barrier for the E2E. FederatedResolver only consumes
 *     the HTTP response of /api/v1/identities/:did, not caring whether the backend is SQL.
 *   - Uses Express nodes: aligned with the task description; reuses the existing middleware stack
 *     (CORS/Helmet/RateLimit/ErrorHandler) via @coivitas/shared's createApp.
 *   - Ports hardcoded to 4001/4002/4003 (task requirement); if occupied the test fails immediately with a clear error.
 *   - The version 2 document is generated with a real initiateKeyRotation triple signature,
 *     with a DIDBindingVerifier stub injected to return true (to avoid reconstructing the full history chain).
 *   - Federation sync goes through the original broadcastToNodes helper: node 1's POST
 *     /api/v1/identities/:did route, after receiving, POSTs /federation/sync to the other nodes.
 *   - Node 3 is still at v1 when it recovers: requests broadcastToNodes sends to it during the
 *     downtime window fail (the node is not listening); this is a faithful reproduction of a "sync miss".
 */

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import type { Application } from 'express';
import { once } from 'node:events';
import type { Server } from 'node:http';

import {
    canonicalize,
    generateKeyPair,
    sign,
} from '../../packages/crypto/src/index.js';
import {
    completeKeyRotation,
    createAgentIdentity,
    createFederatedResolver,
    createNullDnsRebindingGuard,
    didKeyFromPublicKey,
    initiateKeyRotation,
} from '../../packages/identity/src/index.js';

// FederatedResolverConfig.persistentWatermark / dnsRebindingGuard are promoted to MUST.
// The E2E test uses in-memory + a null guard to satisfy the construction-time validation.
const makeMemWatermark = () => {
    let value = 0;
    return {
        getWatermark: () => Promise.resolve(value),
        setWatermark: (v: number) => {
            value = v;
            return Promise.resolve();
        },
    };
};
const makeNullGuard = () => createNullDnsRebindingGuard();
import { createApp } from '../../packages/shared/src/index.js';
import type {
    AgentIdentityDocument,
    DID,
    DIDBindingVerifier,
    Signature,
    Timestamp,
} from '../../packages/types/src/index.js';

// ─── Test gating ────────────────────────────────────────────────────────────────
// Aligned with discovery.test.ts: only runs when ENABLE_SOCKET_TESTS=1, to avoid occupying ports.
// This test is fully in-memory and does not need DATABASE_URL.
const describeIfSockets =
    process.env.ENABLE_SOCKET_TESTS === '1' ? describe : describe.skip;

// ─── Node definitions ────────────────────────────────────────────────────────────────

interface FederationPeer {
    id: string;
    url: string;
}

interface FederationNode {
    id: string;
    port: number;
    url: string; // external URL (used by resolver): uses localhost to bypass federated-resolver SSRF rejection of IP literals
    store: Map<DID, AgentIdentityDocument>;
    peers: FederationPeer[];
    start: () => Promise<void>;
    stop: () => Promise<void>;
    isRunning: () => boolean;
}

// Node factory: each Express app exposes 4 routes
// GET /api/v1/identities/:did — resolver query entry point
// POST /api/v1/identities — register + actively broadcast /federation/sync
// POST /federation/sync — receive peer-node sync
// GET /federation/health — optionally used by FederatedResolver's health probe
function createFederationNode(params: {
    id: string;
    port: number;
    peers: FederationPeer[];
}): FederationNode {
    const store = new Map<DID, AgentIdentityDocument>();
    let server: Server | undefined;

    // Build the Express app and mount routes. createApp comes with an errorHandler,
    // so we only need to add the 4 business endpoints.
    function buildApp(): Application {
        const app = createApp();

        app.get('/api/v1/identities/:did', (req, res) => {
            const did = decodeURIComponent(req.params.did) as DID;
            const doc = store.get(did);
            if (!doc) {
                res.status(404).json({
                    error: { code: 'IDENTITY_NOT_FOUND', message: did },
                });
                return;
            }
            res.status(200).json(doc);
        });

        // register + broadcast (does not reuse registerIdentityRoutes, to avoid a DB dependency)
        app.post('/api/v1/identities', (req, res) => {
            const doc = req.body as AgentIdentityDocument;
            if (!doc?.id) {
                res.status(400).json({
                    error: { code: 'INVALID_DOCUMENT', message: 'id required' },
                });
                return;
            }
            // version/conflict policy: pick the higher version to overwrite (simulating node 1's write-source semantics)
            const existing = store.get(doc.id);
            const incomingVersion = doc.version ?? 1;
            const existingVersion = existing?.version ?? 0;
            if (!existing || incomingVersion >= existingVersion) {
                store.set(doc.id, doc);
            }
            res.status(201).json({ did: doc.id });

            // fire-and-forget broadcast to the other nodes
            for (const peer of params.peers) {
                void fetch(`${peer.url}/federation/sync`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(doc),
                    signal: AbortSignal.timeout(2000),
                }).catch(() => {
                    // silent: the node may already be down, retry deferred
                });
            }
        });

        app.post('/federation/sync', (req, res) => {
            const doc = req.body as AgentIdentityDocument;
            if (!doc?.id) {
                res.status(400).json({
                    error: { code: 'INVALID_DOCUMENT', message: 'id required' },
                });
                return;
            }
            const existing = store.get(doc.id);
            const incomingVersion = doc.version ?? 1;
            const existingVersion = existing?.version ?? 0;
            if (!existing || incomingVersion >= existingVersion) {
                store.set(doc.id, doc);
            }
            res.status(200).json({ ok: true });
        });

        app.get('/federation/health', (_req, res) => {
            res.status(200).json({ status: 'ok' });
        });

        return app;
    }

    return {
        id: params.id,
        port: params.port,
        // the resolver consumes this URL: uses localhost to avoid SSRF (rejecting IP literals)
        url: `http://localhost:${params.port}`,
        store,
        peers: params.peers,
        isRunning: () => server !== undefined,
        start: async () => {
            if (server) return;
            const app = buildApp();
            // Must match the URL's `localhost` resolution: if we only listen on 127.0.0.1, under an
            // IPv6-first Node/OS resolution order (Node 18+ defaults to verbatim, getaddrinfo returns ::1 first)
            // the resolver would hit an unlistened ::1, causing ECONNREFUSED. Listening on localhost lets Node
            // bind both the IPv4 loopback + IPv6 loopback, matching all loopback resolution paths.
            const newServer = app.listen(params.port, 'localhost');
            await once(newServer, 'listening');
            server = newServer;
        },
        stop: async () => {
            const s = server;
            if (!s) return;
            server = undefined;
            s.closeAllConnections?.();
            await new Promise<void>((resolve, reject) => {
                s.close((err) => (err ? reject(err) : resolve()));
            });
        },
    };
}

// ─── Helper: wait for broadcast convergence ──────────────────────────────────────────────────────
// Node 1's POST /api/v1/identities is fire-and-forget;
// we must poll the other nodes until their store contains the target DID, or error on timeout.
async function waitForReplication(
    nodes: FederationNode[],
    did: DID,
    expectedVersion: number,
    timeoutMs = 5000,
): Promise<void> {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
        const allHave = nodes.every((n) => {
            if (!n.isRunning()) return true; // shut-down nodes are not required
            const doc = n.store.get(did);
            return doc !== undefined && (doc.version ?? 1) >= expectedVersion;
        });
        if (allHave) return;
        await new Promise((r) => setTimeout(r, 50));
    }
    const snapshot = nodes.map((n) => ({
        id: n.id,
        running: n.isRunning(),
        version: n.store.get(did)?.version ?? null,
    }));
    throw new Error(
        `Replication timed out; expected v>=${expectedVersion} on all running nodes; snapshot=${JSON.stringify(snapshot)}`,
    );
}

// ─── Helper: triple-signature RotationProof payload ───────────────────────────────────────
function signRotationPayload(
    payload: {
        agentDid: DID;
        newPublicKey: string;
        oldPublicKey: string;
        rotatedAt: Timestamp;
    },
    privateKey: string,
): Signature {
    const bytes = new TextEncoder().encode(
        canonicalize({
            agentDid: payload.agentDid,
            newPublicKey: payload.newPublicKey,
            oldPublicKey: payload.oldPublicKey,
            rotatedAt: payload.rotatedAt,
        }),
    );
    return sign(bytes, privateKey) as Signature;
}

// ─── Helper: DIDBindingVerifier stub ───────────────────────────────────────────
// FederatedResolver only calls verify() when doc.version > 1. This test accepts any document that
// passes the local rotationProof field validation — the resolver's internal V1a/V1b/V2/V3 layers
// have already verified the fields and bindingProof; the verifier here is only responsible for the
// cross-document history-chain assertion, returning true to mean "the history chain is trusted".
function makeTrustedVerifier(): DIDBindingVerifier {
    return {
        verify: () => Promise.resolve(true),
        getDocumentHistory: () => Promise.resolve([]),
    };
}

// ─── Test suite ────────────────────────────────────────────────────────────────

describeIfSockets('federation e2e', () => {
    const NODE1_PORT = 4001;
    const NODE2_PORT = 4002;
    const NODE3_PORT = 4003;

    let node1: FederationNode;
    let node2: FederationNode;
    let node3: FederationNode;
    let nodes: FederationNode[];
    let agentADid: DID;
    let agentAV1Doc: AgentIdentityDocument;
    let principalPrivateKey: string;
    let agentAV1PrivateKey: string;

    beforeAll(async () => {
        // 1. Create and start 3 nodes. peers point at each other, so each node's broadcast notifies the other two.
        node1 = createFederationNode({
            id: 'node-1',
            port: NODE1_PORT,
            peers: [
                { id: 'node-2', url: `http://localhost:${NODE2_PORT}` },
                { id: 'node-3', url: `http://localhost:${NODE3_PORT}` },
            ],
        });
        node2 = createFederationNode({
            id: 'node-2',
            port: NODE2_PORT,
            peers: [
                { id: 'node-1', url: `http://localhost:${NODE1_PORT}` },
                { id: 'node-3', url: `http://localhost:${NODE3_PORT}` },
            ],
        });
        node3 = createFederationNode({
            id: 'node-3',
            port: NODE3_PORT,
            peers: [
                { id: 'node-1', url: `http://localhost:${NODE1_PORT}` },
                { id: 'node-2', url: `http://localhost:${NODE2_PORT}` },
            ],
        });
        nodes = [node1, node2, node3];

        await Promise.all(nodes.map((n) => n.start()));

        // 2. Construct Agent A v1: Alice principal -> agent identity
        const alice = generateKeyPair();
        principalPrivateKey = alice.privateKey;
        const aliceDid = didKeyFromPublicKey(
            Buffer.from(alice.publicKey, 'hex'),
        );
        const agentA = createAgentIdentity({
            principalDid: aliceDid,
            principalPrivateKey: alice.privateKey,
            capabilities: ['INQUIRY'],
        });
        agentAV1Doc = agentA.document;
        agentADid = agentA.document.id;
        agentAV1PrivateKey = agentA.privateKey;
    });

    afterAll(async () => {
        await Promise.all(nodes.map((n) => n.stop().catch(() => {})));
    });

    it('resolves through 3 nodes, tolerates node outage, and selects highest version', async () => {
        // ── Scenario 2: register on node 1 and broadcast ──
        const registerRes = await fetch(`${node1.url}/api/v1/identities`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(agentAV1Doc),
        });
        expect(
            registerRes.status,
            `Register on node-1 should return 201; got ${registerRes.status}`,
        ).toBe(201);

        // wait for nodes 2/3's /federation/sync to take effect
        await waitForReplication(nodes, agentADid, 1);

        // all three nodes should hold the v1 document with consistent hashes
        for (const n of nodes) {
            const doc = n.store.get(agentADid);
            expect(
                doc,
                `Node ${n.id} should hold agent A v1 after replication`,
            ).toBeDefined();
            expect(doc!.version ?? 1).toBe(1);
            expect(doc!.publicKey).toBe(agentAV1Doc.publicKey);
        }

        // ── Scenario 3: FederatedResolver resolves successfully ──
        const resolverV1 = createFederatedResolver({
            nodes: [
                { id: 'node-1', url: node1.url },
                { id: 'node-2', url: node2.url },
                { id: 'node-3', url: node3.url },
            ],
            minResponses: 2,
            timeoutMs: 5000,
            cacheTtlMs: 60_000,
            settleWindowMs: 200,
            verifyDIDBinding: makeTrustedVerifier(),
            persistentWatermark: makeMemWatermark(),
            dnsRebindingGuard: makeNullGuard(),
        });

        const resolvedV1 = await resolverV1.resolve(agentADid);
        expect(
            resolvedV1,
            `resolve() should succeed with all 3 healthy nodes`,
        ).not.toBeNull();
        expect(resolvedV1!.id).toBe(agentADid);
        expect(resolvedV1!.version ?? 1).toBe(1);
        expect(resolvedV1!.publicKey).toBe(agentAV1Doc.publicKey);

        // a second resolution should hit the cache
        const resolvedCached = await resolverV1.resolve(agentADid);
        expect(resolvedCached).not.toBeNull();
        const metricsAfterCache = resolverV1.getMetrics();
        expect(
            metricsAfterCache.cacheHit,
            `second resolve should hit cache; metrics=${JSON.stringify(metricsAfterCache)}`,
        ).toBeGreaterThanOrEqual(1);

        await resolverV1.close();

        // ── Scenario 4: shut down node 3 ──
        await node3.stop();
        expect(node3.isRunning()).toBe(false);

        // ── Scenario 5: 2-of-3 quorum still succeeds (minResponses=2) ──
        const resolverDown = createFederatedResolver({
            nodes: [
                { id: 'node-1', url: node1.url },
                { id: 'node-2', url: node2.url },
                { id: 'node-3', url: node3.url }, // shut down
            ],
            minResponses: 2,
            timeoutMs: 5000,
            cacheTtlMs: 60_000,
            settleWindowMs: 200,
            verifyDIDBinding: makeTrustedVerifier(),
            persistentWatermark: makeMemWatermark(),
            dnsRebindingGuard: makeNullGuard(),
        });

        const resolvedWithOutage = await resolverDown.resolve(agentADid);
        expect(
            resolvedWithOutage,
            `resolve() should succeed with minResponses=2 when 1 node is down`,
        ).not.toBeNull();
        expect(resolvedWithOutage!.id).toBe(agentADid);
        expect(resolvedWithOutage!.version ?? 1).toBe(1);
        await resolverDown.close();

        // ── Scenario 6: node 1 updates Agent A to version=2, syncs only to node 2 (node 3 still down) ──
        const newKeyPair = generateKeyPair();
        const rotatedAt = new Date().toISOString() as Timestamp;
        const principalApproval = signRotationPayload(
            {
                agentDid: agentADid,
                newPublicKey: newKeyPair.publicKey,
                oldPublicKey: agentAV1Doc.publicKey,
                rotatedAt,
            },
            principalPrivateKey,
        );
        const rotating = initiateKeyRotation({
            currentDoc: agentAV1Doc,
            currentPrivateKey: agentAV1PrivateKey,
            newKeyPair,
            principalApproval,
            rotatedAt,
        });
        const agentAV2Doc = completeKeyRotation(rotating);
        expect(agentAV2Doc.version).toBe(2);
        expect(agentAV2Doc.publicKey).toBe(newKeyPair.publicKey);

        // push the v2 document to node 1 (via the same register route, POST /api/v1/identities)
        // Note: node1's route is lenient about version semantics, directly overwriting the store and broadcasting.
        const updateRes = await fetch(`${node1.url}/api/v1/identities`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(agentAV2Doc),
        });
        expect(updateRes.status).toBe(201);

        // wait for node2 to receive v2 (node3 is down, so the broadcast request to it silently fails)
        await waitForReplication([node1, node2], agentADid, 2);

        expect(node1.store.get(agentADid)?.version ?? 1).toBe(2);
        expect(node2.store.get(agentADid)?.version ?? 1).toBe(2);

        // ── Scenario 7: node 3 recovers (still at version=1) ──
        // Key point: the store Map is cleared during shutdown; it must be re-seeded with v1, then started.
        // createFederationNode rebuilds the app on every start, but the store is externally held,
        // so the store itself is never cleaned up — after reconnecting it still holds v1.
        // Verification: stop did not clear the store.
        expect(node3.store.get(agentADid)?.version ?? 1).toBe(1);

        await node3.start();
        expect(node3.isRunning()).toBe(true);

        // verify node 3 still holds only v1 at this point (it missed node 1's v2 broadcast during the downtime)
        expect(node3.store.get(agentADid)!.version ?? 1).toBe(1);

        // verify node 3, after recovery, still returns v1 externally (HTTP-layer assertion, to guard against a pre-store-mutation ghost)
        const node3Response = await fetch(
            `${node3.url}/api/v1/identities/${encodeURIComponent(agentADid)}`,
        );
        expect(node3Response.status).toBe(200);
        const node3Body = (await node3Response.json()) as AgentIdentityDocument;
        expect(
            node3Body.version ?? 1,
            `node-3 should still serve v1 after recovery (missed v2 broadcast)`,
        ).toBe(1);

        // ── Scenario 8: FederatedResolver returns version=2 (highest version wins) ──
        // create a new resolver (independent counters, convenient for asserting versionConflictCount)
        const resolverV2 = createFederatedResolver({
            nodes: [
                { id: 'node-1', url: node1.url },
                { id: 'node-2', url: node2.url },
                { id: 'node-3', url: node3.url },
            ],
            minResponses: 2,
            timeoutMs: 5000,
            cacheTtlMs: 60_000,
            settleWindowMs: 500, // relax settle so all 3 nodes arrive as much as possible, exposing version divergence
            verifyDIDBinding: makeTrustedVerifier(),
            persistentWatermark: makeMemWatermark(),
            dnsRebindingGuard: makeNullGuard(),
        });

        const resolvedV2 = await resolverV2.resolve(agentADid);
        expect(
            resolvedV2,
            `resolve() should select the higher version when nodes diverge`,
        ).not.toBeNull();
        expect(
            resolvedV2!.version ?? 1,
            `highest version should win: expected v2, got v${resolvedV2!.version ?? 1}`,
        ).toBe(2);
        expect(resolvedV2!.publicKey).toBe(newKeyPair.publicKey);

        // ── Scenario 9: getMetrics outputs resolution latency / cache hit rate / version conflict frequency ──
        // do another resolve to trigger cacheHit, ensuring each metrics dimension is non-zero.
        await resolverV2.resolve(agentADid);
        const finalMetrics = resolverV2.getMetrics();

        // resolution latency fields: p50/p95/p99 must all be non-negative and in a reasonable range
        expect(finalMetrics.latencyP50Ms).toBeGreaterThanOrEqual(0);
        expect(finalMetrics.latencyP95Ms).toBeGreaterThanOrEqual(
            finalMetrics.latencyP50Ms,
        );
        expect(finalMetrics.latencyP99Ms).toBeGreaterThanOrEqual(
            finalMetrics.latencyP95Ms,
        );
        expect(finalMetrics.latencyP99Ms).toBeLessThan(10_000);

        // cache hit rate: at least one successful hit (the second resolve)
        expect(
            finalMetrics.cacheHit,
            `cacheHit should be >= 1 after second resolve; metrics=${JSON.stringify(finalMetrics)}`,
        ).toBeGreaterThanOrEqual(1);
        expect(finalMetrics.cacheMiss).toBeGreaterThanOrEqual(1);
        expect(finalMetrics.resolveSuccess).toBeGreaterThanOrEqual(1);

        // version conflict frequency: nodes 1/2 give v2, node 3 gives v1 -> different_versions
        // should record at least 1 (the exact count depends on whether the settle window captures v1, but >= 1 must hold).
        expect(
            finalMetrics.versionConflictCount,
            `versionConflictCount should be >= 1 when nodes diverge (v2 vs v1); metrics=${JSON.stringify(finalMetrics)}`,
        ).toBeGreaterThanOrEqual(1);

        // node-level metrics: all 3 nodes should have been counted as having received requests
        expect(Object.keys(finalMetrics.nodes).sort()).toEqual([
            'node-1',
            'node-2',
            'node-3',
        ]);
        for (const n of ['node-1', 'node-2', 'node-3'] as const) {
            expect(
                finalMetrics.nodes[n]!.requestTotal,
                `node ${n} should have been queried at least once`,
            ).toBeGreaterThanOrEqual(1);
        }

        await resolverV2.close();
    });
});
