// D3 DNS rebinding TOCTOU race-free fix unit tests
// Verification goals:
// 1. the pinIP returned by resolveAndValidate is passed into the undici Agent connector (not a second DNS resolution)
// 2. if an attacker switches DNS between step 1 (validate) and step 2 (connect), the request still connects to pinIP
// 3. when buildConnector is called, hostname is replaced with pinIP, and servername keeps the original hostname (TLS SNI)
// 4. when resolveAndValidate fails the alert path is correct: returns null, fetch is not called

// Test naming follows the should ... when ... style

import { describe, it, expect, vi, beforeEach } from 'vitest';

// ============================================================
// D3-specific mock: control undici's Agent + buildConnector + fetch
// must use factory functions inside vi.mock so the spies are accessible after vitest hoisting
// Note: do not call vi.clearAllMocks() / vi.restoreAllMocks() in beforeEach/afterEach,
// because they would reset the mockImplementation of the vi.fn() inside the vi.mock factory.
// ============================================================

// record the hostname argument of connector calls (verifies the pinIp-pinned path)
// use a module-level mutable array, manually cleared in each test's beforeEach
const capturedConnectOpts: Array<{ hostname: string; servername?: string }> =
    [];

vi.mock('undici', () => {
    // connectorSpy: simulates the low-level connect function returned by buildConnector
    // records opts.hostname / opts.servername at call time into the module-level array
    const connectorSpy = vi
        .fn()
        .mockImplementation(
            (
                opts: { hostname: string; servername?: string },
                cb: (err: null, sock: unknown) => void,
            ) => {
                capturedConnectOpts.push({
                    hostname: opts.hostname,
                    servername: opts.servername,
                });
                cb(null, {} as unknown);
            },
        );

    // buildConnector: returns connectorSpy (simulates undici.buildConnector behavior)
    const buildConnectorSpy = vi.fn(() => connectorSpy);

    // Agent mock:
    // - implements construction behavior similar to undici.Agent
    // - captures agentOpts.connect and invokes it during fetch (simulating undici's internal connection flow)
    // - exposes _connectFactory for fetchSpy to use
    const AgentMock = vi
        .fn()
        .mockImplementation(
            (agentOpts: { connect: (opts: unknown, cb: unknown) => void }) => {
                return {
                    _connectFactory: agentOpts.connect,
                    close: vi.fn().mockResolvedValue(undefined),
                };
            },
        );

    // fetchSpy:
    // - accepts a dispatcher (i.e. the pinnedDispatcher instance)
    // - triggers the connection via dispatcher._connectFactory, simulating undici taking the connector path internally
    // - returns a success response with id fixed to 'did:agent:test-d3' (all tests use the same DID)
    const fetchSpy = vi
        .fn()
        .mockImplementation(
            async (
                _url: string,
                opts: {
                    dispatcher?: {
                        _connectFactory?: (opts: unknown, cb: unknown) => void;
                    };
                    signal?: AbortSignal;
                },
            ) => {
                // simulate undici internals: establish the connection via dispatcher.connect (triggers the pinIp path)
                if (opts?.dispatcher?._connectFactory) {
                    await new Promise<void>((resolve) => {
                        opts.dispatcher!._connectFactory!(
                            // pass the original opts; the connect callback replaces them internally with pinIP
                            {
                                hostname: 'will-be-overridden',
                                servername: undefined,
                                protocol: 'https:',
                                port: '443',
                            },
                            (_err: unknown, _sock: unknown) => {
                                resolve();
                            },
                        );
                    });
                }
                return {
                    ok: true,
                    status: 200,
                    // valid content-length (smaller than the default maxResponseBytes=512KB)
                    headers: { get: (_name: string) => '256' },
                    json: () =>
                        Promise.resolve({
                            // id must match the DID passed to resolve(), otherwise document validation fails
                            id: 'did:agent:test-d3',
                            publicKey: 'did:agent:test-d3',
                            principalDid: 'did:key:zPrincipal',
                            bindingProof: {
                                agentDid: 'did:agent:test-d3',
                                principalDid: 'did:key:zPrincipal',
                                signature: 'fakesig',
                                issuedAt: new Date().toISOString(),
                                expiresAt: new Date(
                                    Date.now() + 86400_000,
                                ).toISOString(),
                            },
                            specVersion: '0.2.0',
                            version: 1,
                        }),
                };
            },
        );

    return {
        fetch: fetchSpy,
        buildConnector: buildConnectorSpy,
        Agent: AgentMock,
    };
});

// module-level mock — decouple binding/did (to prevent real crypto logic from interfering with the D3 path test)
vi.mock('../binding.js', () => ({
    verifyBinding: vi.fn().mockReturnValue(true),
    verifyBindingProof: vi.fn().mockReturnValue(true),
    createBinding: vi.fn(),
    createBindingProof: vi.fn(),
}));

vi.mock('../did.js', () => ({
    // treat publicKey directly as the DID (consistent with publicKey: 'did:agent:test-d3' in the fetch mock)
    createAgentDID: vi.fn().mockImplementation((pk: string) => pk),
    isDidAgent: vi.fn().mockReturnValue(true),
    isDidKey: vi.fn().mockReturnValue(true),
    extractPublicKeyFromDIDKey: vi.fn().mockReturnValue('fakepubkey'),
    didKeyFromPublicKey: vi.fn(),
    isTimestampExpired: vi.fn().mockReturnValue(false),
}));

import { createFederatedResolver } from '../federated-resolver.js';
import type {
    DID,
    AgentIdentityDocument,
    FederationAlertEvent,
} from '@coivitas/types';
import {
    Agent as _AgentMockClass,
    buildConnector as _buildConnectorMock,
    fetch as _fetchMock,
} from 'undici';

// vi.mocked provides type-safe mock access (avoids the unsafe-member-access lint from direct casting)
const AgentMockClass = vi.mocked(_AgentMockClass);
const buildConnectorMock = vi.mocked(_buildConnectorMock);
const fetchMock = vi.mocked(_fetchMock);

// ============================================================
// test helpers
// ============================================================

function makeWatermark() {
    return {
        getWatermark: vi.fn().mockResolvedValue(0),
        setWatermark: vi.fn().mockResolvedValue(undefined),
    };
}

function makeVerifier() {
    return {
        verify: vi.fn().mockResolvedValue(true),
        getDocumentHistory: vi.fn().mockResolvedValue([]),
    };
}

// ============================================================
// D3 TOCTOU test group
// ============================================================

describe('D3 DNS rebinding TOCTOU race-free fix', () => {
    beforeEach(() => {
        // clear the connector call records (module-level mutable array)
        capturedConnectOpts.length = 0;
        // clear the mock call history (call counts) to prevent cross-test pollution
        // Note: vi.clearAllMocks() only clears history, it does not reset mockImplementation
        // vi.resetAllMocks() / vi.restoreAllMocks() would break the vi.mock factory implementation, so they cannot be used
        vi.clearAllMocks();
    });

    it('should pin IP from resolveAndValidate to undici Agent connector when resolving DID', async () => {
        // Scenario: DNS step 1 returns the public IP 1.2.3.4 (which is validated); if step 2 resolves DNS again
        // it could return 192.168.x.x (an attack); the race-free approach ensures the connector uses 1.2.3.4

        const pinnedIP = '1.2.3.4';
        const originalHostname = 'federation-node.example.com';
        const targetDID = 'did:agent:test-d3' as DID;

        const dnsRebindingGuard = {
            resolveAndValidate: vi.fn().mockResolvedValue(pinnedIP),
        };

        // record each mock's call count at the start of the test (to prevent cross-state pollution with other tests)
        const fetchCallsBefore = fetchMock.mock.calls.length;
        const agentInstBefore = AgentMockClass.mock.calls.length;
        const buildConnBefore = buildConnectorMock.mock.calls.length;

        const dns_alerts: FederationAlertEvent[] = [];
        const resolver = createFederatedResolver({
            nodes: [{ id: 'n1', url: `https://${originalHostname}` }],
            minResponses: 1,
            timeoutMs: 5000,
            cacheTtlMs: 0, // disable caching to ensure an actual request is made every time
            verifyDIDBinding: makeVerifier(),
            persistentWatermark: makeWatermark(),
            dnsRebindingGuard,
            onAlert: (e) => dns_alerts.push(e),
        });

        const result = await resolver.resolve(targetDID);

        // verify: resolve succeeds and returns an AgentIdentityDocument (not null)
        // resolve()'s return type is AgentIdentityDocument | null; on success it is the document object
        expect(result).not.toBeNull();
        expect((result as AgentIdentityDocument).id).toBe(targetDID);

        // verify: no DNS-rebinding alert (success path; the QUORUM_UNMET fallback is expected behavior)
        // Note: a single-node configuration (< 3 nodes) triggers the selectByQuorum downgrade, which necessarily emits a QUORUM_UNMET fallback alert
        const rebindAlerts = dns_alerts.filter(
            (a) => a.kind === 'FEDERATION_DNS_REBINDING_BLOCKED',
        );
        expect(rebindAlerts).toHaveLength(0);

        // verify: dnsRebindingGuard.resolveAndValidate is called with the original hostname as argument
        expect(dnsRebindingGuard.resolveAndValidate).toHaveBeenCalledWith(
            originalHostname,
        );

        // verify: undici.Agent is instantiated (the pinIp dispatcher path), exactly 1 time in this test
        expect(AgentMockClass.mock.calls.length - agentInstBefore).toBe(1);

        // verify: buildConnector is called (to construct the low-level pinIp connector), exactly 1 time in this test
        expect(buildConnectorMock.mock.calls.length - buildConnBefore).toBe(1);

        // verify: undici.fetch is called (not globalThis.fetch), exactly 1 time in this test
        expect(fetchMock.mock.calls.length - fetchCallsBefore).toBe(1);

        // core verification: when the connector is called, hostname is pinIP (not the original hostname, not an RFC1918 attack IP)
        expect(capturedConnectOpts.length).toBeGreaterThanOrEqual(1);
        const connectCall = capturedConnectOpts[0]!;
        expect(connectCall.hostname).toBe(pinnedIP);

        // TLS SNI verification: servername should be the original hostname to ensure correct certificate validation
        expect(connectCall.servername).toBe(originalHostname);

        await resolver.close();
    });

    it('should block request and return null when resolveAndValidate throws (TOCTOU attack scenario)', async () => {
        // simulate a TOCTOU attack scenario: resolveAndValidate detects a private IP and throws
        // expected: fetch is not called, resolve() returns null, and a DNS rebinding alert is emitted

        // record the call counts before the test starts (to prevent cross-test history pollution)
        const fetchCallsBefore = fetchMock.mock.calls.length;
        const agentInstBefore = AgentMockClass.mock.calls.length;

        const dnsRebindingGuard = {
            resolveAndValidate: vi
                .fn()
                .mockRejectedValue(
                    new Error(
                        'DNS rebinding blocked: node.attacker.com resolves to private IPs: 192.168.1.1',
                    ),
                ),
        };

        const alerts: FederationAlertEvent[] = [];
        const resolver = createFederatedResolver({
            nodes: [{ id: 'n1', url: 'https://node.attacker.com' }],
            minResponses: 1,
            timeoutMs: 5000,
            cacheTtlMs: 0,
            verifyDIDBinding: makeVerifier(),
            persistentWatermark: makeWatermark(),
            dnsRebindingGuard,
            onAlert: (e) => alerts.push(e),
        });

        // the resolve() public API returns null to indicate failure (not a discriminated union)
        const result = await resolver.resolve('did:agent:victim' as DID);
        expect(result).toBeNull();

        // a DNS rebinding alert should be emitted
        const rebindAlerts = alerts.filter(
            (a) => a.kind === 'FEDERATION_DNS_REBINDING_BLOCKED',
        );
        expect(rebindAlerts).toHaveLength(1);
        expect(rebindAlerts[0]!.kind).toBe('FEDERATION_DNS_REBINDING_BLOCKED');

        // fetch should not be called (the TOCTOU window is closed at the resolveAndValidate stage)
        // use a delta check to avoid cross-test history pollution
        expect(fetchMock.mock.calls.length - fetchCallsBefore).toBe(0);

        // Agent should not be instantiated (after resolveAndValidate throws, it short-circuits to an error without entering the fetch path)
        expect(AgentMockClass.mock.calls.length - agentInstBefore).toBe(0);

        await resolver.close();
    });

    it('should use pinIP not hostname when connector is invoked (direct pinIp path hit)', async () => {
        // direct verification: when the connector is called, hostname is exactly resolveAndValidate's return value
        // and not the hostname in the original node URL (if it were the hostname, TOCTOU would not be fixed)

        const EXPECTED_PIN_IP = '203.0.113.42'; // TEST-NET-3 (RFC 5737, non-private)
        const NODE_HOSTNAME = 'did-federation.example.org';
        const targetDID = 'did:agent:test-d3' as DID;

        const dnsRebindingGuard = {
            resolveAndValidate: vi.fn().mockResolvedValue(EXPECTED_PIN_IP),
        };

        const resolver = createFederatedResolver({
            nodes: [{ id: 'n1', url: `https://${NODE_HOSTNAME}` }],
            minResponses: 1,
            timeoutMs: 5000,
            cacheTtlMs: 0,
            verifyDIDBinding: makeVerifier(),
            persistentWatermark: makeWatermark(),
            dnsRebindingGuard,
        });

        await resolver.resolve(targetDID);

        // core assertion: hostname in the connector must be pinIp (the validated IP),
        // not NODE_HOSTNAME (if it were NODE_HOSTNAME, TOCTOU would not be fixed and the attacker could switch DNS a second time)
        expect(capturedConnectOpts.length).toBeGreaterThanOrEqual(1);
        const call = capturedConnectOpts[0]!;
        expect(call.hostname).toBe(EXPECTED_PIN_IP);
        expect(call.hostname).not.toBe(NODE_HOSTNAME);

        await resolver.close();
    });

    it('should preserve original hostname as TLS servername when pinning IP', async () => {
        // verify that the TLS SNI (servername) is still the original hostname to ensure correct TLS certificate validation
        // Background: after replacing the TCP hostname with an IP, the TLS handshake needs servername=original hostname
        // in order to correctly match the server certificate's CN/SAN

        const PIN_IP = '198.51.100.5'; // TEST-NET-2 (RFC 5737, non-private)
        const ORIGINAL_HOST = 'secure-federation.example.net';
        const targetDID = 'did:agent:test-d3' as DID;

        const dnsRebindingGuard = {
            resolveAndValidate: vi.fn().mockResolvedValue(PIN_IP),
        };

        const resolver = createFederatedResolver({
            nodes: [{ id: 'n1', url: `https://${ORIGINAL_HOST}/` }],
            minResponses: 1,
            timeoutMs: 5000,
            cacheTtlMs: 0,
            verifyDIDBinding: makeVerifier(),
            persistentWatermark: makeWatermark(),
            dnsRebindingGuard,
        });

        await resolver.resolve(targetDID);

        expect(capturedConnectOpts.length).toBeGreaterThanOrEqual(1);
        const call = capturedConnectOpts[0]!;

        // TCP/TLS connection target: pinIP (the validated public IP)
        expect(call.hostname).toBe(PIN_IP);

        // TLS SNI: the original hostname (certificate domain validation stays correct, unaffected by IP pinning)
        expect(call.servername).toBe(ORIGINAL_HOST);

        await resolver.close();
    });
});
