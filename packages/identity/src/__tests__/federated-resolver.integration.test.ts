/**
 * Integration test: 3 simulated HTTP federation nodes
 *
 * Uses the real createAgentIdentity to generate an AgentIdentityDocument with valid cryptographic proofs,
 * starts 3 Node http.Server instances (ports 19301/19302/19303), and verifies the federated resolver's core flow.
 * Uses Node's built-in http module to avoid pulling a new express dependency into the identity package.
 *
 * Covered scenarios:
 *   1. Successful resolution when all 3 nodes are healthy
 *   2. Successful resolution when 1 node is down (2-of-3 quorum)
 *   3. Unknown DID returns null
 *   4. Second resolve hits the cache
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import http from 'http';
import type { Server } from 'http';
import type {
    DID,
    AgentIdentityDocument,
    DIDBindingVerifier,
} from '@coivitas/types';
import { generateKeyPair } from '@coivitas/crypto';
import {
    createFederatedResolver,
    createNullDnsRebindingGuard,
} from '../federated-resolver.js';
import { createAgentIdentity } from '../did-agent.js';
import { didKeyFromPublicKey } from '../did.js';

// ============================================================
// Helpers: start/stop HTTP federation nodes
// ============================================================

// DID URL prefix; the federated resolver sends GET /api/v1/identities/:did
const IDENTITY_PATH_PREFIX = '/api/v1/identities/';
const HEALTH_PATH = '/federation/health';

/**
 * Start a simulated federation node (plain Node http) exposing two endpoints:
 *   GET /api/v1/identities/:did — returns the document or 404
 *   GET /federation/health — returns { status: 'ok' }
 */
function startFederatedNode(
    port: number,
    documents: Map<string, AgentIdentityDocument>,
): Promise<Server> {
    const srv = http.createServer((req, res) => {
        const url = req.url ?? '/';

        if (url === HEALTH_PATH) {
            const body = JSON.stringify({ status: 'ok' });
            res.writeHead(200, {
                'Content-Type': 'application/json',
                'Content-Length': Buffer.byteLength(body),
            });
            res.end(body);
            return;
        }

        if (url.startsWith(IDENTITY_PATH_PREFIX)) {
            // The DID in the path was encodeURIComponent'd by the client, so decode it back
            const encodedDid = url.slice(IDENTITY_PATH_PREFIX.length);
            const did = decodeURIComponent(encodedDid);
            const doc = documents.get(did);
            if (!doc) {
                const body = JSON.stringify({ error: 'not found' });
                res.writeHead(404, {
                    'Content-Type': 'application/json',
                    'Content-Length': Buffer.byteLength(body),
                });
                res.end(body);
                return;
            }
            const body = JSON.stringify(doc);
            res.writeHead(200, {
                'Content-Type': 'application/json',
                'Content-Length': Buffer.byteLength(body),
            });
            res.end(body);
            return;
        }

        res.writeHead(404);
        res.end();
    });

    return new Promise((resolve, reject) => {
        srv.listen(port, '127.0.0.1', () => resolve(srv));
        srv.on('error', reject);
    });
}

function stopServer(srv: Server): Promise<void> {
    return new Promise((resolve) => srv.close(() => resolve()));
}

// ============================================================
// Helper: build a DIDBindingVerifier that always returns true
// ============================================================
function makeIntegVerifier(): DIDBindingVerifier {
    return {
        verify: () => Promise.resolve(true),
        getDocumentHistory: () => Promise.resolve([]),
    };
}

// Helpers for fields required at construction
const makeIntegWatermark = () => ({
    getWatermark: () => Promise.resolve(0 as number | undefined),
    setWatermark: () => Promise.resolve(),
});

// ============================================================
// Test suite
// ============================================================

describe('FederatedResolver integration — 3 nodes', () => {
    let srv1: Server | undefined;
    let srv2: Server | undefined;
    let srv3: Server | undefined;
    let did: DID;
    const docs = new Map<string, AgentIdentityDocument>();

    beforeAll(async () => {
        // Use real cryptography to generate the principal key pair, then create the agent identity
        // so bindingProof contains a valid signature that passes the V1a/V1b/V3a three-layer checks
        const principal = generateKeyPair();
        const principalDid = didKeyFromPublicKey(
            // generateKeyPair().publicKey is hex and must be converted to Uint8Array
            // didKeyFromPublicKey accepts a Uint8Array
            // the crypto package exports fromHex; use it directly
            Uint8Array.from(Buffer.from(principal.publicKey, 'hex')),
        );

        const { document } = createAgentIdentity({
            principalDid,
            principalPrivateKey: principal.privateKey,
        });

        did = document.id;
        docs.set(did, document);

        [srv1, srv2, srv3] = await Promise.all([
            startFederatedNode(19301, docs),
            startFederatedNode(19302, docs),
            startFederatedNode(19303, docs),
        ]);
    });

    afterAll(async () => {
        await Promise.all(
            [srv1, srv2, srv3]
                .filter((s): s is Server => s !== undefined)
                .map((srv) => stopServer(srv)),
        );
    });

    // ----------------------------------------------------------
    // Scenario 1: all 3 nodes healthy, first resolve succeeds, metrics correct
    // ----------------------------------------------------------
    it('should resolve DID successfully when 3 nodes are healthy', async () => {
        const resolver = createFederatedResolver({
            nodes: [
                { id: 'n1', url: 'http://localhost:19301' },
                { id: 'n2', url: 'http://localhost:19302' },
                { id: 'n3', url: 'http://localhost:19303' },
            ],
            minResponses: 2,
            timeoutMs: 5000,
            cacheTtlMs: 60000,
            settleWindowMs: 200,
            verifyDIDBinding: makeIntegVerifier(),
            persistentWatermark: makeIntegWatermark(),
            dnsRebindingGuard: createNullDnsRebindingGuard(),
        });

        const result = await resolver.resolve(did);
        expect(result).not.toBeNull();
        expect(result?.id).toBe(did);

        const m = resolver.getMetrics();
        expect(m.resolveSuccess).toBe(1);
        expect(m.cacheMiss).toBe(1);

        await resolver.close();
    });

    // ----------------------------------------------------------
    // Scenario 2: 1 node down (port 19399 does not exist), 2-of-3 quorum still succeeds
    // ----------------------------------------------------------
    it('should resolve when one node is down (2-of-3 quorum)', async () => {
        const resolver = createFederatedResolver({
            nodes: [
                { id: 'n1', url: 'http://localhost:19301' },
                { id: 'n2', url: 'http://localhost:19302' },
                { id: 'n_down', url: 'http://localhost:19399' },
            ],
            minResponses: 2,
            timeoutMs: 5000,
            cacheTtlMs: 60000,
            settleWindowMs: 200,
            verifyDIDBinding: makeIntegVerifier(),
            persistentWatermark: makeIntegWatermark(),
            dnsRebindingGuard: createNullDnsRebindingGuard(),
        });

        const result = await resolver.resolve(did);
        expect(result).not.toBeNull();
        expect(result?.id).toBe(did);

        await resolver.close();
    });

    // ----------------------------------------------------------
    // Scenario 3: unknown DID, all nodes return 404, resolution result is null
    // ----------------------------------------------------------
    it('should return null for unknown DID', async () => {
        const resolver = createFederatedResolver({
            nodes: [
                { id: 'n1', url: 'http://localhost:19301' },
                { id: 'n2', url: 'http://localhost:19302' },
                { id: 'n3', url: 'http://localhost:19303' },
            ],
            minResponses: 2,
            timeoutMs: 5000,
            cacheTtlMs: 60000,
            settleWindowMs: 200,
            verifyDIDBinding: makeIntegVerifier(),
            persistentWatermark: makeIntegWatermark(),
            dnsRebindingGuard: createNullDnsRebindingGuard(),
        });

        const result = await resolver.resolve(
            'did:agent:0000000000000000000000000000000000000099' as DID,
        );
        expect(result).toBeNull();

        await resolver.close();
    });

    // ----------------------------------------------------------
    // Scenario 4: second resolve hits the cache, cacheHit+1, resolveTotal+1
    // ----------------------------------------------------------
    it('should hit cache on second resolve', async () => {
        const resolver = createFederatedResolver({
            nodes: [
                { id: 'n1', url: 'http://localhost:19301' },
                { id: 'n2', url: 'http://localhost:19302' },
                { id: 'n3', url: 'http://localhost:19303' },
            ],
            minResponses: 2,
            timeoutMs: 5000,
            cacheTtlMs: 60000,
            settleWindowMs: 200,
            verifyDIDBinding: makeIntegVerifier(),
            persistentWatermark: makeIntegWatermark(),
            dnsRebindingGuard: createNullDnsRebindingGuard(),
        });

        // First resolve (cache miss)
        await resolver.resolve(did);
        const m1 = resolver.getMetrics();

        // Second resolve (cache hit)
        await resolver.resolve(did);
        const m2 = resolver.getMetrics();

        expect(m2.cacheHit).toBe(m1.cacheHit + 1);
        expect(m2.resolveTotal).toBe(m1.resolveTotal + 1);

        await resolver.close();
    });
});
