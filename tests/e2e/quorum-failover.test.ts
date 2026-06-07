/**
 * E2E federation quorum failover test
 *
 * Coverage:
 *   1. 1 node forges a document (invalid schema) + 1 node times out + 1 node healthy -> quorum met (minResponses=2)
 *   2. 1 node forges a document + 1 node times out -> quorum unmet (minResponses=2), FEDERATION_QUORUM_UNMET fires
 *   3. all 3 nodes network error -> FEDERATION_QUORUM_UNMET fires
 *   4. all 3 nodes 404 -> silently returns null, does not fire QUORUM_UNMET
 *   5. node 1 forges (signature verification fails) + nodes 2-3 healthy -> quorum met (minResponses=2)
 *
 * Design decisions:
 *   - Uses vi.mock('undici') to intercept undici.fetch (production code switched to undiciFetch,
 *     no longer going through globalThis.fetch; vi.stubGlobal cannot intercept).
 *   - "forgery" = returning JSON with an invalid schema (null values / missing required fields); the federated resolver
 *     counts it as signatureInvalid due to signature verification failure, and does not include it in validCandidates.
 *   - "timeout" = fetch rejection (network error); the federated resolver counts it as otherFailure.
 *   - Module-level vi.mock ensures binding.js / did.js / undici do not touch the real logic.
 *
 *  Fix: vi.stubGlobal('fetch') -> vi.mock('undici')
 *   Root cause: after fed-resolver switched to undici.fetch (pinIp dispatcher),
 *   this file's mock was not synced, causing the mock to be ineffective -> all quorum unmet -> 4 failures.
 *
 */

import { afterEach, describe, expect, it, vi } from 'vitest';

// ============================================================
// Module-level mocks — must be declared before importing the implementation (vitest hoisting)
// ============================================================

vi.mock('../../packages/identity/src/binding.js', () => ({
    verifyBinding: vi.fn().mockReturnValue(true),
    verifyBindingProof: vi.fn().mockReturnValue(true),
    createBinding: vi.fn(),
    createBindingProof: vi.fn(),
}));

vi.mock('../../packages/identity/src/did.js', () => ({
    createAgentDID: vi.fn().mockImplementation((pk: string) => pk),
    isDidAgent: vi.fn().mockReturnValue(true),
    isDidKey: vi.fn().mockReturnValue(true),
    extractPublicKeyFromDIDKey: vi.fn().mockReturnValue('fakepubkey'),
    didKeyFromPublicKey: vi.fn(),
    isTimestampExpired: vi.fn().mockReturnValue(false),
}));

// Intercept the undici module (production code does import { fetch as undiciFetch } from 'undici')
// pnpm strict hoisting: undici is only installed in packages/identity/node_modules/,
// tests/e2e/ cannot resolve a bare 'undici'; the module must be located via the relative path inside the identity package.
// Simplified version: only a fetch spy + a minimal Agent/buildConnector stub is needed (no connector capture required)
vi.mock('../../packages/identity/node_modules/undici', () => {
    // buildConnector returns a no-op connector (the test does not check the pinIp path)
    const connectorStub = vi
        .fn()
        .mockImplementation(
            (_opts: unknown, cb: (err: null, sock: unknown) => void) => {
                cb(null, {} as unknown);
            },
        );
    const buildConnectorMock = vi.fn(() => connectorStub);

    // Agent mock: constructs the pinnedDispatcher object (production code does new UndiciAgent({ connect }))
    const AgentMock = vi
        .fn()
        .mockImplementation(
            (agentOpts: { connect: (opts: unknown, cb: unknown) => void }) => ({
                _connectFactory: agentOpts.connect,
                close: vi.fn().mockResolvedValue(undefined),
            }),
        );

    // fetch spy: each test overrides the behavior via mockImplementation
    const fetchMock = vi.fn();

    return {
        fetch: fetchMock,
        buildConnector: buildConnectorMock,
        Agent: AgentMock,
    };
});

import {
    createFederatedResolver,
    createNullDnsRebindingGuard,
} from '../../packages/identity/src/federated-resolver.js';
import type {
    AgentIdentityDocument,
    DID,
    DIDBindingVerifier,
    FederationAlertEvent,
} from '@coivitas/types';
import { fetch as _undiciFetch } from '../../packages/identity/node_modules/undici';

// vi.mocked provides type-safe mock access
const mockedFetch = vi.mocked(_undiciFetch);

// ─── Test helper functions ────────────────────────────────────────────────────────────

/** Construct a DIDBindingVerifier stub (verify always true, getDocumentHistory empty) */
function makeVerifier(): DIDBindingVerifier {
    return {
        verify: vi.fn().mockResolvedValue(true),
        getDocumentHistory: vi.fn().mockResolvedValue([]),
    };
}

/** WatermarkStore stub */
function makeWatermark() {
    return {
        getWatermark: vi.fn().mockResolvedValue(0),
        setWatermark: vi.fn().mockResolvedValue(undefined),
    };
}

/**
 * Construct a valid AgentIdentityDocument stub (consistent with federated-resolver.test.ts's makeDoc).
 * publicKey === did, ensuring the mock createAgentDID(pk) => pk === did.
 */
function makeDoc(did: string, version = 1): AgentIdentityDocument {
    return {
        id: did,
        publicKey: did,
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

/** A normal 200 response (valid document) */
function makeOkResponse(doc: AgentIdentityDocument) {
    return {
        ok: true,
        status: 200,
        headers: { get: () => '2048' },
        json: () => Promise.resolve(doc),
    };
}

/** Forgery: invalid schema (id is null, required fields missing), which will trigger binding verification failure */
function makeForgeryResponse() {
    return {
        ok: true,
        status: 200,
        headers: { get: () => '512' },
        // id=null will trigger schema validation failure or signature invalid
        json: () =>
            Promise.resolve({
                id: null,
                publicKey: 'evil_key',
                version: 1,
                specVersion: '0.2.0',
            }),
    };
}

/** Timeout / network error: fetch reject */
function makeNetworkError() {
    return Promise.reject(new Error('ETIMEDOUT: network error'));
}

/** 404: does not fire QUORUM_UNMET */
function make404Response() {
    return {
        ok: false,
        status: 404,
        headers: { get: () => null },
    };
}

// ─── Test suite ─────────────────────────────────────────────────────────────────

describe('quorum failover — FEDERATION_QUORUM_UNMET', () => {
    afterEach(() => {
        // reset the undici fetch mock (vi.unstubAllGlobals is no longer needed, fetch now goes through the module mock)
        mockedFetch.mockReset();
    });

    // -------------------------------------------------------------------------
    // Scenario 1: 1 forgery + 1 timeout + 1 healthy -> minResponses=2, quorum met
    // -------------------------------------------------------------------------
    it('should resolve successfully when 1 valid node among 3 satisfies minResponses=1', async () => {
        // 3 nodes, minResponses=1: just 1 valid is enough
        const did = 'did:agent:' + 'a'.repeat(40);
        const doc = makeDoc(did, 1);
        const alertFn = vi.fn();

        // url-based switch (concurrent fetch callIdx is not stable): use vi.mock('undici')
        // to intercept undiciFetch
        mockedFetch.mockImplementation((url: unknown) => {
            const u = String(url);
            if (u.includes('//n1'))
                return Promise.resolve(makeForgeryResponse()) as never;
            if (u.includes('//n2')) return makeNetworkError() as never;
            return Promise.resolve(makeOkResponse(doc)) as never;
        });

        const resolver = createFederatedResolver({
            nodes: [
                { id: 'n1', url: 'http://n1' },
                { id: 'n2', url: 'http://n2' },
                { id: 'n3', url: 'http://n3' },
            ],
            minResponses: 1,
            timeoutMs: 3000,
            cacheTtlMs: 60000,
            verifyDIDBinding: makeVerifier(),
            persistentWatermark: makeWatermark(),
            dnsRebindingGuard: createNullDnsRebindingGuard(),
            onAlert: alertFn,
        });

        const result = await resolver.resolve(did as DID);
        // n3 is healthy, minResponses=1 -> resolution succeeds
        expect(result).not.toBeNull();
        expect(result?.id).toBe(did);

        // should not fire QUORUM_UNMET
        const quorumAlerts = alertFn.mock.calls.filter(
            (args) =>
                (args[0] as FederationAlertEvent).kind ===
                'FEDERATION_QUORUM_UNMET',
        );
        expect(quorumAlerts).toHaveLength(0);

        await resolver.close();
    });

    // -------------------------------------------------------------------------
    // Scenario 2: 1 forgery + 1 timeout + 1 healthy -> minResponses=2, quorum unmet -> QUORUM_UNMET
    // -------------------------------------------------------------------------
    it('should emit FEDERATION_QUORUM_UNMET when only 1 valid node but minResponses=2', async () => {
        const did = 'did:agent:' + 'b'.repeat(40);
        const doc = makeDoc(did, 1);
        const alertFn = vi.fn();

        // use vi.mock('undici') + url-based switch
        // (scenario 2: 1 forgery + 1 network error + 1 valid -> quorum unmet)
        // switched to url-based deterministic routing (aligned with scenario 1)
        mockedFetch.mockImplementation((url: unknown) => {
            const u = String(url);
            if (u.includes('//n1'))
                return Promise.resolve(makeForgeryResponse()) as never;
            if (u.includes('//n2')) return makeNetworkError() as never;
            return Promise.resolve(makeOkResponse(doc)) as never;
        });

        const resolver = createFederatedResolver({
            nodes: [
                { id: 'n1', url: 'http://n1' },
                { id: 'n2', url: 'http://n2' },
                { id: 'n3', url: 'http://n3' },
            ],
            minResponses: 2,
            timeoutMs: 3000,
            cacheTtlMs: 60000,
            verifyDIDBinding: makeVerifier(),
            persistentWatermark: makeWatermark(),
            dnsRebindingGuard: createNullDnsRebindingGuard(),
            onAlert: alertFn,
        });

        const result = await resolver.resolve(did as DID);
        expect(result).toBeNull();

        // validCandidates=1 < minResponses=2 -> QUORUM_UNMET must fire
        const quorumAlerts = alertFn.mock.calls.filter(
            (args) =>
                (args[0] as FederationAlertEvent).kind ===
                'FEDERATION_QUORUM_UNMET',
        );
        expect(quorumAlerts.length).toBeGreaterThan(0);

        // verify the alert field structure
        const alert = quorumAlerts[0]?.[0] as Extract<
            FederationAlertEvent,
            { kind: 'FEDERATION_QUORUM_UNMET' }
        >;
        expect(alert.did).toBe(did);
        expect(alert.required).toBeGreaterThanOrEqual(2);
        expect(alert.observedAt).toBeTruthy();

        await resolver.close();
    });

    // -------------------------------------------------------------------------
    // Scenario 3: all 3 nodes network error -> QUORUM_UNMET fires
    // -------------------------------------------------------------------------
    it('should emit FEDERATION_QUORUM_UNMET when all nodes fail with network error', async () => {
        const did = 'did:agent:' + 'c'.repeat(40);
        const alertFn = vi.fn();

        // intercept with vi.mock('undici')
        mockedFetch.mockRejectedValue(new Error('network error'));

        const resolver = createFederatedResolver({
            nodes: [
                { id: 'n1', url: 'http://n1' },
                { id: 'n2', url: 'http://n2' },
                { id: 'n3', url: 'http://n3' },
            ],
            minResponses: 2,
            timeoutMs: 3000,
            cacheTtlMs: 60000,
            verifyDIDBinding: makeVerifier(),
            persistentWatermark: makeWatermark(),
            dnsRebindingGuard: createNullDnsRebindingGuard(),
            onAlert: alertFn,
        });

        const result = await resolver.resolve(did as DID);
        expect(result).toBeNull();

        const quorumAlerts = alertFn.mock.calls.filter(
            (args) =>
                (args[0] as FederationAlertEvent).kind ===
                'FEDERATION_QUORUM_UNMET',
        );
        expect(quorumAlerts.length).toBeGreaterThan(0);

        await resolver.close();
    });

    // -------------------------------------------------------------------------
    // Scenario 4: all nodes 404 -> silent null, does not fire QUORUM_UNMET
    // -------------------------------------------------------------------------
    it('should return null without QUORUM_UNMET when all nodes return 404', async () => {
        const did = 'did:agent:' + 'd'.repeat(40);
        const alertFn = vi.fn();

        // intercept with vi.mock('undici')
        mockedFetch.mockResolvedValue(make404Response() as never);

        const resolver = createFederatedResolver({
            nodes: [
                { id: 'n1', url: 'http://n1' },
                { id: 'n2', url: 'http://n2' },
                { id: 'n3', url: 'http://n3' },
            ],
            minResponses: 1,
            timeoutMs: 3000,
            cacheTtlMs: 60000,
            verifyDIDBinding: makeVerifier(),
            persistentWatermark: makeWatermark(),
            dnsRebindingGuard: createNullDnsRebindingGuard(),
            onAlert: alertFn,
        });

        const result = await resolver.resolve(did as DID);
        expect(result).toBeNull();

        // all-404 scenario: should not fire QUORUM_UNMET
        const quorumAlerts = alertFn.mock.calls.filter(
            (args) =>
                (args[0] as FederationAlertEvent).kind ===
                'FEDERATION_QUORUM_UNMET',
        );
        expect(quorumAlerts).toHaveLength(0);

        await resolver.close();
    });

    // -------------------------------------------------------------------------
    // Scenario 5: node 1 forgery + nodes 2-3 healthy -> minResponses=2, quorum met
    // -------------------------------------------------------------------------
    it('should resolve when majority nodes agree (1 forgery, 2 valid, minResponses=2)', async () => {
        const did = 'did:agent:' + 'e'.repeat(40);
        const doc = makeDoc(did, 1);
        const alertFn = vi.fn();

        // url-based switch (concurrent fetch callIdx is not stable): use vi.mock('undici')
        // to intercept undiciFetch
        mockedFetch.mockImplementation((url: unknown) => {
            const u = String(url);
            if (u.includes('//n1'))
                return Promise.resolve(makeForgeryResponse()) as never;
            return Promise.resolve(makeOkResponse(doc)) as never;
        });

        const resolver = createFederatedResolver({
            nodes: [
                { id: 'n1', url: 'http://n1' },
                { id: 'n2', url: 'http://n2' },
                { id: 'n3', url: 'http://n3' },
            ],
            minResponses: 2,
            timeoutMs: 3000,
            cacheTtlMs: 60000,
            verifyDIDBinding: makeVerifier(),
            persistentWatermark: makeWatermark(),
            dnsRebindingGuard: createNullDnsRebindingGuard(),
            onAlert: alertFn,
        });

        const result = await resolver.resolve(did as DID);
        expect(result).not.toBeNull();
        expect(result?.id).toBe(did);

        // quorum reached, should not fire QUORUM_UNMET
        const quorumAlerts = alertFn.mock.calls.filter(
            (args) =>
                (args[0] as FederationAlertEvent).kind ===
                'FEDERATION_QUORUM_UNMET',
        );
        expect(quorumAlerts).toHaveLength(0);

        await resolver.close();
    });

    // -------------------------------------------------------------------------
    // Scenario 6: metrics verification — quorumUnmetCount increments after a QUORUM_UNMET scenario
    // -------------------------------------------------------------------------
    it('should increment quorumUnmetCount in metrics when quorum is not met', async () => {
        const did = 'did:agent:' + 'f'.repeat(40);

        // intercept with vi.mock('undici')
        mockedFetch.mockRejectedValue(new Error('all down'));

        const resolver = createFederatedResolver({
            nodes: [
                { id: 'n1', url: 'http://n1' },
                { id: 'n2', url: 'http://n2' },
            ],
            minResponses: 2,
            timeoutMs: 3000,
            cacheTtlMs: 60000,
            verifyDIDBinding: makeVerifier(),
            persistentWatermark: makeWatermark(),
            dnsRebindingGuard: createNullDnsRebindingGuard(),
        });

        await resolver.resolve(did as DID);

        const metrics = resolver.getMetrics();
        expect(metrics.quorumUnmetCount).toBeGreaterThanOrEqual(1);
        expect(metrics.resolveNull).toBeGreaterThanOrEqual(1);

        await resolver.close();
    });
});
