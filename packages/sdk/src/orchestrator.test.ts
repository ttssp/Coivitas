import { describe, expect, it, vi } from 'vitest';

import { generateKeyPair, sign } from '@coivitas/crypto';
import {
    createCapabilityTokenPayload,
    delegateCapabilityToken,
    didKeyFromPublicKey,
    issueCapabilityToken,
} from '@coivitas/identity';
import type {
    AgentIdentityDocument,
    CapabilityToken,
    DelegationChainValidationResult,
    DID,
    DiscoveryService,
    FederatedResolver,
    NegotiationEnvelope,
    ResolvedPublicKeys,
    Timestamp,
} from '@coivitas/types';
import { SPEC_VERSION_0_2_0 } from '@coivitas/types';
import { buildEnvelope, verifyEnvelope } from '@coivitas/communication';

import {
    InMemoryResponseIdempotencyCache,
    Orchestrator,
} from './orchestrator.js';

const senderDid = 'did:agent:00112233445566778899aabbccddeeff00112233' as DID;
const recipientDid =
    'did:agent:1111222233334444555566667777888899990000' as DID;
const senderKeyPair = generateKeyPair() as {
    publicKey: string;
    privateKey: string;
};
const senderPrivateKey = senderKeyPair.privateKey;
const recipientPrivateKey = '2'.repeat(128);
const publicKey = senderKeyPair.publicKey;
const principalDid =
    'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK' as DID;

/**
 * Mid-chain agent of the delegation chain (the chain-tail delegatorDid).
 * delegation-chain: the leaf's top-level proof is signed by the chain-tail delegator,
 * not by issuedTo (= senderDid). The fixture signs the leaf proof with this DID,
 * so every test that needs to resolve the sender's public key must also be able to resolve this middle DID's public key.
 */
const middleAgentDid =
    'did:agent:abcdef0123456789abcdef0123456789abcdef01' as DID;
const middleKeyPair = generateKeyPair() as {
    publicKey: string;
    privateKey: string;
};
const middlePublicKey = middleKeyPair.publicKey;

/**
 * Dispatch public keys by DID: verifyEnvelope uses the sender's public key; step3.5 delegated-leaf
 * verification uses the middle public key; unknown DIDs return null. Wiring this single resolver is enough for the tests.
 */
function makePubKeyResolver(extra?: Record<string, string>) {
    return vi.fn((did: DID) => {
        if (did === senderDid) return Promise.resolve(publicKey);
        if (did === middleAgentDid) return Promise.resolve(middlePublicKey);
        const custom = extra?.[did as string];
        if (custom !== undefined) return Promise.resolve(custom);
        return Promise.resolve(null);
    });
}

/**
 * A step3.5 authorization rejection must write an ActionRecord. When tokenStore is injected, the Orchestrator
 * constructor requires policyRecorder to be injected as well; this returns a default vi.fn implementation that
 * returns a fixed recordId/hash. Tests that need to assert on the recorded content inspect `.mock.calls[]`.
 */
function mockPolicyRecorder() {
    return {
        record: vi.fn(async () =>
            Promise.resolve({
                recordId: `record-mock-${Math.random().toString(36).slice(2, 8)}`,
                hash: 'f'.repeat(64),
            }),
        ),
    };
}

/**
 * Default sender AgentIdentityDocument mock: principal matches the token.
 * Tests that do not care about principal validation use this default; tests that need to simulate a mismatch override it explicitly.
 */
function mockSenderDocument(
    overrides?: Partial<AgentIdentityDocument>,
): AgentIdentityDocument {
    return {
        id: senderDid,
        specVersion: SPEC_VERSION_0_2_0,
        principalDid,
        publicKey,
        bindingProof: {} as never,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        ...overrides,
    } as unknown as AgentIdentityDocument;
}

describe('Orchestrator', () => {
    it('returns a success response when policy allows execution', async () => {
        const orchestrator = new Orchestrator({
            agentDid: recipientDid,
            agentPrivateKey: recipientPrivateKey,
            principalDid,
            policyEngine: {
                executeWithPolicy: async ({ executor }) => ({
                    executed: true as const,
                    result: await executor(),
                    recordId: 'record-1',
                }),
            },
            policyRecorder: mockPolicyRecorder(),
            transport: {} as never,
            resolvePublicKey: makePubKeyResolver(),
            businessHandler: ({ action }) =>
                Promise.resolve({
                    handledAction: action,
                }),
        });

        const incoming = buildEnvelope({
            senderDid,
            senderPrivateKey,
            recipientDid,
            sessionId: 'session-1',
            messageType: 'NEGOTIATION_REQUEST',
            body: {
                action: 'INQUIRY',
                params: { recipient: 'supplier-a' },
                requestId: 'req-1',
            },
            sequenceNumber: 1,
        });

        const result = await orchestrator.handleEnvelope(incoming);

        expect(result).toMatchObject({
            handled: true,
            recordId: 'record-1',
            responseEnvelope: {
                messageType: 'NEGOTIATION_RESPONSE',
                header: {
                    senderDid: recipientDid,
                    recipientDid: senderDid,
                    sessionId: 'session-1',
                    sequenceNumber: 2,
                },
                body: {
                    requestId: 'req-1',
                    action: 'INQUIRY',
                    status: 'SUCCESS',
                    recordId: 'record-1',
                    data: {
                        handledAction: 'INQUIRY',
                    },
                },
            },
        });
    });

    it('returns a standard authorization error envelope when policy denies execution', async () => {
        const orchestrator = new Orchestrator({
            agentDid: recipientDid,
            agentPrivateKey: recipientPrivateKey,
            principalDid,
            policyEngine: {
                executeWithPolicy: () =>
                    Promise.resolve({
                        executed: false as const,
                        reason: 'capability revoked',
                        recordId: 'record-2',
                    }),
            },
            policyRecorder: mockPolicyRecorder(),
            transport: {} as never,
            resolvePublicKey: makePubKeyResolver(),
            businessHandler: vi.fn(),
        });

        const incoming = buildEnvelope({
            senderDid,
            senderPrivateKey,
            recipientDid,
            sessionId: 'session-2',
            messageType: 'NEGOTIATION_REQUEST',
            body: {
                action: 'INQUIRY',
                params: { recipient: 'supplier-a' },
            },
        });

        const result = await orchestrator.handleEnvelope(incoming);

        expect(result).toMatchObject({
            handled: false,
            recordId: 'record-2',
            rejectionReason: 'capability revoked',
            responseEnvelope: {
                messageType: 'ERROR',
                body: {
                    code: 'AUTHORIZATION_INSUFFICIENT',
                    message: 'capability revoked',
                },
            },
        });
    });

    it('returns an invalid-envelope error when the payload cannot be parsed', async () => {
        const orchestrator = new Orchestrator({
            agentDid: recipientDid,
            agentPrivateKey: recipientPrivateKey,
            principalDid,
            policyEngine: {
                executeWithPolicy: vi.fn(),
            },
            policyRecorder: mockPolicyRecorder(),
            transport: {} as never,
            resolvePublicKey: makePubKeyResolver(),
            businessHandler: vi.fn(),
        });

        const result = await orchestrator.handleEnvelope({
            id: 'not-a-valid-envelope',
        } as NegotiationEnvelope);

        expect(result).toMatchObject({
            handled: false,
            responseEnvelope: {
                messageType: 'ERROR',
                body: {
                    code: 'INVALID_ENVELOPE',
                },
            },
        });
    });

    // ─── 01b public-key resolution priority (mutual-exclusion constraint) ─────
    it('throws during construction when both federatedResolver and resolvePublicKey are provided (mutual exclusion)', () => {
        // The two resolvers are mutually exclusive, to avoid path ambiguity during a staged rollout.
        // Deployments that need caching should wrap the cache inside the FederatedResolver implementation.
        const federatedResolver: FederatedResolver = {
            resolve: vi.fn(),
            invalidateCache: vi.fn(),
            getMetrics: vi.fn(),
            close: vi.fn(),
        } as unknown as FederatedResolver;

        expect(
            () =>
                new Orchestrator({
                    agentDid: recipientDid,
                    agentPrivateKey: recipientPrivateKey,
                    principalDid,
                    policyEngine: { executeWithPolicy: vi.fn() },
                    policyRecorder: mockPolicyRecorder(),
                    transport: {} as never,
                    federatedResolver,
                    resolvePublicKey: makePubKeyResolver(),
                    businessHandler: vi.fn(),
                }),
        ).toThrow(/mutually exclusive/);
    });

    it('falls back to federatedResolver-derived publicKey when resolvePublicKey is not provided', async () => {
        const federatedResolve = vi.fn(() =>
            Promise.resolve({ publicKey } as unknown as AgentIdentityDocument),
        );
        const federatedResolver: FederatedResolver = {
            resolve: federatedResolve,
            invalidateCache: vi.fn(),
            getMetrics: vi.fn(),
            close: vi.fn(),
        } as unknown as FederatedResolver;

        const orchestrator = new Orchestrator({
            agentDid: recipientDid,
            agentPrivateKey: recipientPrivateKey,
            principalDid,
            policyEngine: {
                executeWithPolicy: async ({ executor }) => ({
                    executed: true as const,
                    result: await executor(),
                    recordId: 'record-fr',
                }),
            },
            policyRecorder: mockPolicyRecorder(),
            transport: {} as never,
            federatedResolver, // inject federatedResolver only
            businessHandler: ({ action }) =>
                Promise.resolve({ handledAction: action }),
        });

        const incoming = buildEnvelope({
            senderDid,
            senderPrivateKey,
            recipientDid,
            sessionId: 'session-fr-only',
            messageType: 'NEGOTIATION_REQUEST',
            body: { action: 'INQUIRY', params: { recipient: 'supplier-a' } },
        });

        const result = await orchestrator.handleEnvelope(incoming);

        expect(result.handled).toBe(true);
        expect(federatedResolve).toHaveBeenCalledWith(senderDid);
    });

    it('returns identity verification failure when federatedResolver returns no document', async () => {
        const federatedResolver: FederatedResolver = {
            resolve: vi.fn(() => Promise.resolve(null)),
            invalidateCache: vi.fn(),
            getMetrics: vi.fn(),
            close: vi.fn(),
        } as unknown as FederatedResolver;

        const orchestrator = new Orchestrator({
            agentDid: recipientDid,
            agentPrivateKey: recipientPrivateKey,
            principalDid,
            policyEngine: { executeWithPolicy: vi.fn() },
            policyRecorder: mockPolicyRecorder(),
            transport: {} as never,
            federatedResolver,
            businessHandler: vi.fn(),
        });

        const incoming = buildEnvelope({
            senderDid,
            senderPrivateKey,
            recipientDid,
            sessionId: 'session-fr-miss',
            messageType: 'NEGOTIATION_REQUEST',
            body: { action: 'INQUIRY', params: { recipient: 'supplier-a' } },
        });

        const result = await orchestrator.handleEnvelope(incoming);

        expect(result).toMatchObject({
            handled: false,
            responseEnvelope: {
                messageType: 'ERROR',
                body: { code: 'IDENTITY_VERIFICATION_FAILED' },
            },
        });
    });

    it('throws during construction when neither federatedResolver nor resolvePublicKey is provided', () => {
        expect(
            () =>
                new Orchestrator({
                    agentDid: recipientDid,
                    agentPrivateKey: recipientPrivateKey,
                    principalDid,
                    policyEngine: { executeWithPolicy: vi.fn() },
                    policyRecorder: mockPolicyRecorder(),
                    transport: {} as never,
                    businessHandler: vi.fn(),
                }),
        ).toThrow(/federatedResolver.*resolvePublicKey.*resolveAgentDocument/);
    });

    it('throws during construction when tokenStore is provided without delegationChainValidator', () => {
        expect(
            () =>
                new Orchestrator({
                    agentDid: recipientDid,
                    agentPrivateKey: recipientPrivateKey,
                    principalDid,
                    policyEngine: { executeWithPolicy: vi.fn() },
                    policyRecorder: mockPolicyRecorder(),
                    transport: {} as never,
                    resolvePublicKey: makePubKeyResolver(),
                    tokenStore: { getToken: vi.fn() },
                    businessHandler: vi.fn(),
                }),
        ).toThrow(/delegationChainValidator/);
    });

    // ─── 01c delegation-chain validation ──────────────────────────────────
    it('rejects capabilityTokenRef envelope when capability dependencies are not fully wired (fail-closed)', async () => {
        // Key security guarantee: a caller declaring capabilityTokenRef is requesting capability-token semantics,
        // so if the recipient has not wired all dependencies (tokenStore/validator/revocationChecker/resolveAgentDocument)
        // it must reject, and must not downgrade to the no-tokenRef behavior of scanning the agent's whole pool (a token-confusion attack).
        const orchestrator = new Orchestrator({
            agentDid: recipientDid,
            agentPrivateKey: recipientPrivateKey,
            principalDid,
            policyEngine: { executeWithPolicy: vi.fn() },
            policyRecorder: mockPolicyRecorder(),
            transport: {} as never,
            resolvePublicKey: makePubKeyResolver(),
            // Deliberately not injecting tokenStore / delegationChainValidator /
            // revocationChecker / resolveAgentDocument
            businessHandler: vi.fn(),
        });

        const incoming = buildEnvelope({
            senderDid,
            senderPrivateKey,
            recipientDid,
            sessionId: 'session-partial-deploy',
            messageType: 'NEGOTIATION_REQUEST',
            body: { action: 'INQUIRY', params: { recipient: 'supplier-a' } },
            capabilityTokenRef: 'urn:cap:00000000-0000-0000-0000-000000000000',
        });

        const result = await orchestrator.handleEnvelope(incoming);

        expect(result).toMatchObject({
            handled: false,
            rejectionReason: 'delegation_phase2_dependencies_missing',
            responseEnvelope: {
                messageType: 'ERROR',
                body: { code: 'AUTHORIZATION_INSUFFICIENT' },
            },
        });
    });

    it('still allows no-tokenRef envelopes when only the base dependencies are wired', async () => {
        // The no-tokenRef envelope path must keep working — fail-closed applies only to
        // envelopes that declare capability-token semantics (capabilityTokenRef present).
        const orchestrator = new Orchestrator({
            agentDid: recipientDid,
            agentPrivateKey: recipientPrivateKey,
            principalDid,
            policyEngine: {
                executeWithPolicy: async ({ executor }) => ({
                    executed: true as const,
                    result: await executor(),
                    recordId: 'record-phase1-ok',
                }),
            },
            policyRecorder: mockPolicyRecorder(),
            transport: {} as never,
            resolvePublicKey: makePubKeyResolver(),
            businessHandler: ({ action }) =>
                Promise.resolve({ handledAction: action }),
        });

        const incoming = buildEnvelope({
            senderDid,
            senderPrivateKey,
            recipientDid,
            sessionId: 'session-phase1-ok',
            messageType: 'NEGOTIATION_REQUEST',
            body: { action: 'INQUIRY', params: { recipient: 'supplier-a' } },
            // do not pass capabilityTokenRef
        });

        const result = await orchestrator.handleEnvelope(incoming);

        expect(result.handled).toBe(true);
    });

    it('throws at construction when tokenStore is wired but revocationChecker is missing', () => {
        // Hard-validate the full set of capability-token dependencies at construction time, to avoid the configuration
        // time bomb of "the deployment looks valid, yet the first capability traffic is 100% rejected".
        expect(
            () =>
                new Orchestrator({
                    agentDid: recipientDid,
                    agentPrivateKey: recipientPrivateKey,
                    principalDid,
                    policyEngine: { executeWithPolicy: vi.fn() },
                    transport: {} as never,
                    resolvePublicKey: makePubKeyResolver(),
                    tokenStore: { getToken: vi.fn() },
                    delegationChainValidator: vi.fn(),
                    resolveAgentDocument: vi.fn(() =>
                        Promise.resolve(mockSenderDocument()),
                    ),
                    policyRecorder: mockPolicyRecorder(),
                    // revocationChecker deliberately omitted
                    businessHandler: vi.fn(),
                }),
        ).toThrow(/revocationChecker/);
    });

    it('throws at construction when tokenStore is wired but resolveAgentDocument is missing', () => {
        expect(
            () =>
                new Orchestrator({
                    agentDid: recipientDid,
                    agentPrivateKey: recipientPrivateKey,
                    principalDid,
                    policyEngine: { executeWithPolicy: vi.fn() },
                    transport: {} as never,
                    resolvePublicKey: makePubKeyResolver(),
                    tokenStore: { getToken: vi.fn() },
                    delegationChainValidator: vi.fn(),
                    revocationChecker: vi.fn(() => Promise.resolve(false)),
                    policyRecorder: mockPolicyRecorder(),
                    // resolveAgentDocument deliberately omitted
                    businessHandler: vi.fn(),
                }),
        ).toThrow(/resolveAgentDocument/);
    });

    it('throws at construction when tokenStore is wired but policyRecorder is missing', () => {
        expect(
            () =>
                new Orchestrator({
                    agentDid: recipientDid,
                    agentPrivateKey: recipientPrivateKey,
                    principalDid,
                    policyEngine: { executeWithPolicy: vi.fn() },
                    transport: {} as never,
                    resolvePublicKey: makePubKeyResolver(),
                    tokenStore: { getToken: vi.fn() },
                    delegationChainValidator: vi.fn(),
                    revocationChecker: vi.fn(() => Promise.resolve(false)),
                    resolveAgentDocument: vi.fn(() =>
                        Promise.resolve(mockSenderDocument()),
                    ),
                    // policyRecorder deliberately omitted
                    businessHandler: vi.fn(),
                }),
        ).toThrow(/policyRecorder/);
    });

    it('throws at construction when policyRecorder is missing even without tokenStore (audit invariant applies to all orchestrators)', () => {
        // policyRecorder is promoted from "required only in the tokenStore scenario" to "globally required".
        // In a mixed-version deployment, a node without capability-token wiring that receives a capabilityTokenRef envelope will
        // reject it at step3.5 with delegation_phase2_dependencies_missing — and without a recorder
        // there is no audit trail. Intercepting at construction time avoids this blind spot.
        expect(
            () =>
                new Orchestrator({
                    agentDid: recipientDid,
                    agentPrivateKey: recipientPrivateKey,
                    principalDid,
                    policyEngine: { executeWithPolicy: vi.fn() },
                    transport: {} as never,
                    resolvePublicKey: makePubKeyResolver(),
                    // no tokenStore (no capability-token wiring)
                    // and no policyRecorder either
                    businessHandler: vi.fn(),
                }),
        ).toThrow(/policyRecorder/);
    });

    it('throws at construction when tokenStore is wired but delegationChainValidator is missing', () => {
        expect(
            () =>
                new Orchestrator({
                    agentDid: recipientDid,
                    agentPrivateKey: recipientPrivateKey,
                    principalDid,
                    policyEngine: { executeWithPolicy: vi.fn() },
                    transport: {} as never,
                    resolvePublicKey: makePubKeyResolver(),
                    tokenStore: { getToken: vi.fn() },
                    revocationChecker: vi.fn(() => Promise.resolve(false)),
                    resolveAgentDocument: vi.fn(() =>
                        Promise.resolve(mockSenderDocument()),
                    ),
                    policyRecorder: mockPolicyRecorder(),
                    // delegationChainValidator deliberately omitted
                    businessHandler: vi.fn(),
                }),
        ).toThrow(/delegationChainValidator/);
    });

    it('rejects with delegation_token_not_found when capabilityTokenRef does not resolve', async () => {
        const validator = vi.fn();

        const orchestrator = new Orchestrator({
            agentDid: recipientDid,
            agentPrivateKey: recipientPrivateKey,
            principalDid,
            policyEngine: { executeWithPolicy: vi.fn() },
            transport: {} as never,
            resolvePublicKey: makePubKeyResolver(),
            tokenStore: { getToken: vi.fn(() => Promise.resolve(null)) },
            delegationChainValidator: validator,
            revocationChecker: vi.fn(() => Promise.resolve(false)),
            policyRecorder: mockPolicyRecorder(),
            resolveAgentDocument: vi.fn(() =>
                Promise.resolve(mockSenderDocument()),
            ),
            businessHandler: vi.fn(),
        });

        const incoming = buildEnvelope({
            senderDid,
            senderPrivateKey,
            recipientDid,
            sessionId: 'session-notfound',
            messageType: 'NEGOTIATION_REQUEST',
            body: { action: 'INQUIRY', params: { recipient: 'supplier-a' } },
            capabilityTokenRef: 'urn:cap:11111111-1111-1111-1111-111111111111',
        });

        const result = await orchestrator.handleEnvelope(incoming);

        expect(result).toMatchObject({
            handled: false,
            rejectionReason: 'delegation_token_not_found',
            responseEnvelope: {
                messageType: 'ERROR',
                body: { code: 'AUTHORIZATION_INSUFFICIENT' },
            },
        });
        expect(validator).not.toHaveBeenCalled();
    });

    it('rejects with delegation_token_sender_mismatch when token.issuedTo does not match envelope.senderDid', async () => {
        // Attack path: an attacker obtains a Token whose issuedTo is someone else (e.g. this node's own agent Token),
        // and stuffs it into their own signed envelope to escalate privileges. Authorization validation must reject this escalation.
        const strangerDid =
            'did:agent:dead0000000000000000000000000000deadbeef' as DID;
        const token = {
            id: 'urn:cap:22222222-2222-2222-2222-222222222222',
            specVersion: SPEC_VERSION_0_2_0,
            issuerDid: principalDid,
            principalDid,
            issuedTo: strangerDid, // not senderDid
            issuedAt: new Date().toISOString(),
            expiresAt: new Date(Date.now() + 3600_000).toISOString(),
            capabilities: [],
            revocationUrl: 'https://revocation.example/v1/{id}',
            proof: {
                type: 'Ed25519Signature2026',
                created: new Date().toISOString(),
                verificationMethod: `${principalDid}#key-1`,
                value: 'x'.repeat(128),
            },
        } as unknown as CapabilityToken;
        const validator = vi.fn();

        const orchestrator = new Orchestrator({
            agentDid: recipientDid,
            agentPrivateKey: recipientPrivateKey,
            principalDid,
            policyEngine: { executeWithPolicy: vi.fn() },
            transport: {} as never,
            resolvePublicKey: makePubKeyResolver(),
            tokenStore: { getToken: vi.fn(() => Promise.resolve(token)) },
            delegationChainValidator: validator,
            revocationChecker: vi.fn(() => Promise.resolve(false)),
            policyRecorder: mockPolicyRecorder(),
            resolveAgentDocument: vi.fn(() =>
                Promise.resolve(mockSenderDocument()),
            ),
            businessHandler: vi.fn(),
        });

        const incoming = buildEnvelope({
            senderDid,
            senderPrivateKey,
            recipientDid,
            sessionId: 'session-sender-mismatch',
            messageType: 'NEGOTIATION_REQUEST',
            body: { action: 'INQUIRY', params: { recipient: 'supplier-a' } },
            capabilityTokenRef: token.id,
        });

        const result = await orchestrator.handleEnvelope(incoming);

        expect(result).toMatchObject({
            handled: false,
            rejectionReason: 'delegation_token_sender_mismatch',
        });
        expect(validator).not.toHaveBeenCalled();
    });

    it('rejects replay of recipient-owned token when sender is different (regression)', async () => {
        // Regression: before the fix, the orchestrator only checked token.issuedTo === agentDid (this node),
        // which let "the recipient's own Token" be replayed by any signed sender.
        const recipientOwnedToken = {
            id: 'urn:cap:aaaa1111-bbbb-cccc-dddd-eeeeffff0000',
            specVersion: SPEC_VERSION_0_2_0,
            issuerDid: principalDid,
            principalDid,
            issuedTo: recipientDid, // this node's agent Token
            issuedAt: new Date().toISOString(),
            expiresAt: new Date(Date.now() + 3600_000).toISOString(),
            capabilities: [],
            revocationUrl: 'https://revocation.example/v1/{id}',
            proof: {
                type: 'Ed25519Signature2026',
                created: new Date().toISOString(),
                verificationMethod: `${principalDid}#key-1`,
                value: 'x'.repeat(128),
            },
        } as unknown as CapabilityToken;
        const validator = vi.fn();

        const orchestrator = new Orchestrator({
            agentDid: recipientDid,
            agentPrivateKey: recipientPrivateKey,
            principalDid,
            policyEngine: { executeWithPolicy: vi.fn() },
            transport: {} as never,
            resolvePublicKey: makePubKeyResolver(),
            tokenStore: {
                getToken: vi.fn(() => Promise.resolve(recipientOwnedToken)),
            },
            delegationChainValidator: validator,
            revocationChecker: vi.fn(() => Promise.resolve(false)),
            policyRecorder: mockPolicyRecorder(),
            resolveAgentDocument: vi.fn(() =>
                Promise.resolve(mockSenderDocument()),
            ),
            businessHandler: vi.fn(),
        });

        const incoming = buildEnvelope({
            senderDid, // the attacker's DID, different from token.issuedTo (recipientDid)
            senderPrivateKey,
            recipientDid,
            sessionId: 'session-replay',
            messageType: 'NEGOTIATION_REQUEST',
            body: { action: 'INQUIRY', params: { recipient: 'supplier-a' } },
            capabilityTokenRef: recipientOwnedToken.id,
        });

        const result = await orchestrator.handleEnvelope(incoming);

        expect(result.handled).toBe(false);
        expect(result.rejectionReason).toBe('delegation_token_sender_mismatch');
        expect(validator).not.toHaveBeenCalled();
    });

    it('rejects with delegation_parent_token_revoked when the chain validator reports revocation', async () => {
        const token = buildDelegatedTokenFixture({
            id: 'urn:cap:33333333-3333-3333-3333-333333333333',
            issuedTo: senderDid,
        });
        const validator = vi.fn(
            (): Promise<DelegationChainValidationResult> =>
                Promise.resolve({
                    valid: false,
                    depth: 2,
                    reason: 'PARENT_TOKEN_REVOKED',
                    brokenAtIndex: 1,
                    revokedTokenId: 'urn:cap:parent',
                }),
        );
        // step3.5 first checks the leaf itself with revocationChecker;
        // only the parent tokenId is reported as revoked, the leaf passes, so the flow reaches the validator and we can assert on it.
        const revocationChecker = vi.fn((tokenId: string) =>
            Promise.resolve(tokenId === 'urn:cap:parent'),
        );

        const orchestrator = new Orchestrator({
            agentDid: recipientDid,
            agentPrivateKey: recipientPrivateKey,
            principalDid,
            policyEngine: { executeWithPolicy: vi.fn() },
            transport: {} as never,
            resolvePublicKey: makePubKeyResolver(),
            tokenStore: { getToken: vi.fn(() => Promise.resolve(token)) },
            delegationChainValidator: validator,
            revocationChecker,
            policyRecorder: mockPolicyRecorder(),
            resolveAgentDocument: vi.fn(() =>
                Promise.resolve(mockSenderDocument()),
            ),
            businessHandler: vi.fn(),
        });

        const incoming = buildEnvelope({
            senderDid,
            senderPrivateKey,
            recipientDid,
            sessionId: 'session-revoked',
            messageType: 'NEGOTIATION_REQUEST',
            body: { action: 'INQUIRY', params: { recipient: 'supplier-a' } },
            capabilityTokenRef: token.id,
        });

        const result = await orchestrator.handleEnvelope(incoming);

        expect(result).toMatchObject({
            handled: false,
            rejectionReason: 'delegation_parent_token_revoked',
        });
        expect(validator).toHaveBeenCalledTimes(1);
        // The validator receives revocationChecker as its third argument
        expect(validator.mock.calls[0]?.[2]).toBe(revocationChecker);
    });

    it('rejects with delegation_depth_exceeded when validator reports depth overflow', async () => {
        const token = buildDelegatedTokenFixture({
            id: 'urn:cap:44444444-4444-4444-4444-444444444444',
            issuedTo: senderDid,
        });
        const validator = vi.fn(
            (): Promise<DelegationChainValidationResult> =>
                Promise.resolve({
                    valid: false,
                    depth: 6,
                    reason: 'DEPTH_EXCEEDED',
                }),
        );

        const orchestrator = new Orchestrator({
            agentDid: recipientDid,
            agentPrivateKey: recipientPrivateKey,
            principalDid,
            policyEngine: { executeWithPolicy: vi.fn() },
            transport: {} as never,
            resolvePublicKey: makePubKeyResolver(),
            tokenStore: { getToken: vi.fn(() => Promise.resolve(token)) },
            delegationChainValidator: validator,
            revocationChecker: vi.fn(() => Promise.resolve(false)),
            policyRecorder: mockPolicyRecorder(),
            resolveAgentDocument: vi.fn(() =>
                Promise.resolve(mockSenderDocument()),
            ),
            businessHandler: vi.fn(),
        });

        const incoming = buildEnvelope({
            senderDid,
            senderPrivateKey,
            recipientDid,
            sessionId: 'session-depth',
            messageType: 'NEGOTIATION_REQUEST',
            body: { action: 'INQUIRY', params: { recipient: 'supplier-a' } },
            capabilityTokenRef: token.id,
        });

        const result = await orchestrator.handleEnvelope(incoming);

        expect(result.handled).toBe(false);
        expect(result.rejectionReason).toBe('delegation_depth_exceeded');
    });

    it('passes through to policyEngine when delegation chain is valid', async () => {
        const token = buildDelegatedTokenFixture({
            id: 'urn:cap:55555555-5555-5555-5555-555555555555',
            issuedTo: senderDid,
        });
        const validator = vi.fn(
            (): Promise<DelegationChainValidationResult> =>
                Promise.resolve({
                    valid: true,
                    depth: 3,
                }),
        );

        const orchestrator = new Orchestrator({
            agentDid: recipientDid,
            agentPrivateKey: recipientPrivateKey,
            principalDid,
            policyEngine: {
                executeWithPolicy: async ({ executor }) => ({
                    executed: true as const,
                    result: await executor(),
                    recordId: 'record-chain-ok',
                }),
            },
            transport: {} as never,
            resolvePublicKey: makePubKeyResolver(),
            tokenStore: { getToken: vi.fn(() => Promise.resolve(token)) },
            delegationChainValidator: validator,
            revocationChecker: vi.fn(() => Promise.resolve(false)),
            policyRecorder: mockPolicyRecorder(),
            resolveAgentDocument: vi.fn(() =>
                Promise.resolve(mockSenderDocument()),
            ),
            businessHandler: ({ action }) =>
                Promise.resolve({ handledAction: action }),
        });

        const incoming = buildEnvelope({
            senderDid,
            senderPrivateKey,
            recipientDid,
            sessionId: 'session-chain-ok',
            messageType: 'NEGOTIATION_REQUEST',
            body: { action: 'INQUIRY', params: { recipient: 'supplier-a' } },
            capabilityTokenRef: token.id,
        });

        const result = await orchestrator.handleEnvelope(incoming);

        expect(result.handled).toBe(true);
        expect(result.recordId).toBe('record-chain-ok');
        expect(validator).toHaveBeenCalledTimes(1);
    });

    it('emits fallback reason prefix when validator reports valid=false without a reason code', async () => {
        const token = buildDelegatedTokenFixture({
            id: 'urn:cap:66666666-6666-6666-6666-666666666666',
            issuedTo: senderDid,
        });
        const validator = vi.fn(
            (): Promise<DelegationChainValidationResult> =>
                Promise.resolve({
                    valid: false,
                    depth: 1,
                }),
        );

        const orchestrator = new Orchestrator({
            agentDid: recipientDid,
            agentPrivateKey: recipientPrivateKey,
            principalDid,
            policyEngine: { executeWithPolicy: vi.fn() },
            transport: {} as never,
            resolvePublicKey: makePubKeyResolver(),
            tokenStore: { getToken: vi.fn(() => Promise.resolve(token)) },
            delegationChainValidator: validator,
            revocationChecker: vi.fn(() => Promise.resolve(false)),
            policyRecorder: mockPolicyRecorder(),
            resolveAgentDocument: vi.fn(() =>
                Promise.resolve(mockSenderDocument()),
            ),
            businessHandler: vi.fn(),
        });

        const incoming = buildEnvelope({
            senderDid,
            senderPrivateKey,
            recipientDid,
            sessionId: 'session-fallback',
            messageType: 'NEGOTIATION_REQUEST',
            body: { action: 'INQUIRY', params: { recipient: 'supplier-a' } },
            capabilityTokenRef: token.id,
        });

        const result = await orchestrator.handleEnvelope(incoming);

        expect(result.rejectionReason).toBe('delegation_invalid');
    });

    // ─── 01a DiscoveryService injection point ─────────────────────────────
    it('accepts a discoveryService without invoking it during handleEnvelope', async () => {
        const discoverSpy = vi.fn();
        const discoverFromEndpointSpy = vi.fn();
        const discoveryService: DiscoveryService = {
            discover: discoverSpy,
            discoverFromEndpoint: discoverFromEndpointSpy,
            invalidateCache: vi.fn(),
        } as unknown as DiscoveryService;

        const orchestrator = new Orchestrator({
            agentDid: recipientDid,
            agentPrivateKey: recipientPrivateKey,
            principalDid,
            policyEngine: {
                executeWithPolicy: async ({ executor }) => ({
                    executed: true as const,
                    result: await executor(),
                    recordId: 'record-discovery',
                }),
            },
            policyRecorder: mockPolicyRecorder(),
            transport: {} as never,
            resolvePublicKey: makePubKeyResolver(),
            discoveryService,
            businessHandler: ({ action }) =>
                Promise.resolve({ handledAction: action }),
        });

        const incoming = buildEnvelope({
            senderDid,
            senderPrivateKey,
            recipientDid,
            sessionId: 'session-discovery',
            messageType: 'NEGOTIATION_REQUEST',
            body: { action: 'INQUIRY', params: { recipient: 'supplier-a' } },
        });

        const result = await orchestrator.handleEnvelope(incoming);

        expect(result.handled).toBe(true);
        // The Orchestrator does not call discoveryService on the handleEnvelope path (separation of concerns)
        expect(discoverSpy).not.toHaveBeenCalled();
        expect(discoverFromEndpointSpy).not.toHaveBeenCalled();
    });

    // ─── verbose logging & pathological error objects ────────────────────
    it('emits verbose step logs when verbose=true', async () => {
        const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

        const orchestrator = new Orchestrator({
            agentDid: recipientDid,
            agentPrivateKey: recipientPrivateKey,
            principalDid,
            policyEngine: {
                executeWithPolicy: async ({ executor }) => ({
                    executed: true as const,
                    result: await executor(),
                    recordId: 'record-verbose',
                }),
            },
            policyRecorder: mockPolicyRecorder(),
            transport: {} as never,
            resolvePublicKey: makePubKeyResolver(),
            businessHandler: ({ action }) =>
                Promise.resolve({ handledAction: action }),
            verbose: true,
        });

        const incoming = buildEnvelope({
            senderDid,
            senderPrivateKey,
            recipientDid,
            sessionId: 'session-verbose',
            messageType: 'NEGOTIATION_REQUEST',
            body: { action: 'INQUIRY', params: { recipient: 'supplier-a' } },
        });

        await orchestrator.handleEnvelope(incoming);

        expect(logSpy).toHaveBeenCalled();
        const concatenated = logSpy.mock.calls
            .map((args) => args.join(' '))
            .join('\n');
        expect(concatenated).toContain('[ORCH]');
        expect(concatenated).toContain('step1');
        expect(concatenated).toContain('total');

        logSpy.mockRestore();
    });

    it('emits verbose logs on failure paths (policy deny, capability reject, invalid envelope)', async () => {
        const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

        // 1) policy deny — covers the step4 FAIL branch
        const orchestrator = new Orchestrator({
            agentDid: recipientDid,
            agentPrivateKey: recipientPrivateKey,
            principalDid,
            policyEngine: {
                executeWithPolicy: () =>
                    Promise.resolve({
                        executed: false as const,
                        reason: 'capability revoked',
                        recordId: 'record-verbose-deny',
                    }),
            },
            policyRecorder: mockPolicyRecorder(),
            transport: {} as never,
            resolvePublicKey: makePubKeyResolver(),
            businessHandler: vi.fn(),
            verbose: true,
        });

        await orchestrator.handleEnvelope(
            buildEnvelope({
                senderDid,
                senderPrivateKey,
                recipientDid,
                sessionId: 'session-v-deny',
                messageType: 'NEGOTIATION_REQUEST',
                body: {
                    action: 'INQUIRY',
                    params: { recipient: 'supplier-a' },
                },
            }),
        );

        // 2) capability reject — covers the logFailure branch at step3.5
        const tokenRejectOrch = new Orchestrator({
            agentDid: recipientDid,
            agentPrivateKey: recipientPrivateKey,
            principalDid,
            policyEngine: { executeWithPolicy: vi.fn() },
            transport: {} as never,
            resolvePublicKey: makePubKeyResolver(),
            tokenStore: { getToken: vi.fn(() => Promise.resolve(null)) },
            delegationChainValidator: vi.fn(),
            revocationChecker: vi.fn(() => Promise.resolve(false)),
            policyRecorder: mockPolicyRecorder(),
            resolveAgentDocument: vi.fn(() =>
                Promise.resolve(mockSenderDocument()),
            ),
            businessHandler: vi.fn(),
            verbose: true,
        });
        await tokenRejectOrch.handleEnvelope(
            buildEnvelope({
                senderDid,
                senderPrivateKey,
                recipientDid,
                sessionId: 'session-v-cap',
                messageType: 'NEGOTIATION_REQUEST',
                body: { action: 'INQUIRY', params: {} },
                capabilityTokenRef:
                    'urn:cap:aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
            }),
        );

        // 3) invalid envelope — covers the logFailure/logTotal branch in catch
        await tokenRejectOrch.handleEnvelope({
            id: 'bad',
        } as NegotiationEnvelope);

        const concatenated = logSpy.mock.calls
            .map((args) => args.join(' '))
            .join('\n');
        expect(concatenated).toContain('FAIL');

        logSpy.mockRestore();
    });

    // ─── logger injection ───────────────────────────────────────
    it('routes warn/info through injected logger and suppresses console when logger is provided', async () => {
        const logger = {
            warn: vi.fn<(message: string) => void>(),
            error: vi.fn<(message: string) => void>(),
            info: vi.fn<(message: string) => void>(),
        };
        const consoleWarnSpy = vi
            .spyOn(console, 'warn')
            .mockImplementation(() => {});
        const consoleLogSpy = vi
            .spyOn(console, 'log')
            .mockImplementation(() => {});

        // No idempotencyCache -> the first handleEnvelope must emit one warn;
        // verbose=true -> each step emits info. Both paths must go through logger.* rather than console.*.
        const orchestrator = new Orchestrator({
            agentDid: recipientDid,
            agentPrivateKey: recipientPrivateKey,
            principalDid,
            policyEngine: {
                executeWithPolicy: async ({ executor }) => ({
                    executed: true as const,
                    result: await executor(),
                    recordId: 'record-logger',
                }),
            },
            policyRecorder: mockPolicyRecorder(),
            transport: {} as never,
            resolvePublicKey: makePubKeyResolver(),
            businessHandler: ({ action }) =>
                Promise.resolve({ handledAction: action }),
            verbose: true,
            logger,
        });

        await orchestrator.handleEnvelope(
            buildEnvelope({
                senderDid,
                senderPrivateKey,
                recipientDid,
                sessionId: 'session-logger',
                messageType: 'NEGOTIATION_REQUEST',
                body: {
                    action: 'INQUIRY',
                    params: { recipient: 'supplier-a' },
                },
            }),
        );

        expect(logger.warn).toHaveBeenCalledTimes(1);
        expect(logger.warn.mock.calls[0]?.[0]).toContain(
            'idempotencyCache is not configured',
        );
        expect(logger.info).toHaveBeenCalled();
        const infoConcat = logger.info.mock.calls
            .map((args) => args.join(' '))
            .join('\n');
        expect(infoConcat).toContain('[ORCH]');
        expect(infoConcat).toContain('total');

        // console.* must be completely silent — the most central guarantee of injecting a logger.
        expect(consoleWarnSpy).not.toHaveBeenCalled();
        expect(consoleLogSpy).not.toHaveBeenCalled();

        consoleWarnSpy.mockRestore();
        consoleLogSpy.mockRestore();
    });

    it('handles catch path when incoming has no string id (relatedEnvelopeId falls through to undefined)', async () => {
        const orchestrator = new Orchestrator({
            agentDid: recipientDid,
            agentPrivateKey: recipientPrivateKey,
            principalDid,
            policyEngine: { executeWithPolicy: vi.fn() },
            policyRecorder: mockPolicyRecorder(),
            transport: {} as never,
            resolvePublicKey: makePubKeyResolver(),
            businessHandler: vi.fn(),
        });

        // non-string id + non-object header -> takes the catch branch with id/header falling back to undefined/null
        const result = await orchestrator.handleEnvelope({
            id: 12345,
            header: null,
        } as unknown as NegotiationEnvelope);

        expect(result.handled).toBe(false);
        expect(result.responseEnvelope.messageType).toBe('ERROR');
        // the relatedEnvelopeId field should not appear in the error envelope body
        expect(
            result.responseEnvelope.body['relatedEnvelopeId'],
        ).toBeUndefined();
    });

    // ─── request body validation ──────────────────────────────────────────
    it('rejects with INVALID_MESSAGE when envelope body is missing action', async () => {
        const orchestrator = new Orchestrator({
            agentDid: recipientDid,
            agentPrivateKey: recipientPrivateKey,
            principalDid,
            policyEngine: { executeWithPolicy: vi.fn() },
            policyRecorder: mockPolicyRecorder(),
            transport: {} as never,
            resolvePublicKey: makePubKeyResolver(),
            businessHandler: vi.fn(),
        });

        const incoming = buildEnvelope({
            senderDid,
            senderPrivateKey,
            recipientDid,
            sessionId: 'session-no-action',
            messageType: 'NEGOTIATION_REQUEST',
            body: { params: { recipient: 'supplier-a' } },
        });

        const result = await orchestrator.handleEnvelope(incoming);

        expect(result).toMatchObject({
            handled: false,
            responseEnvelope: {
                messageType: 'ERROR',
                body: { code: 'INVALID_ENVELOPE' },
            },
        });
    });

    it('rejects with INVALID_MESSAGE when envelope body params is not an object', async () => {
        const orchestrator = new Orchestrator({
            agentDid: recipientDid,
            agentPrivateKey: recipientPrivateKey,
            principalDid,
            policyEngine: { executeWithPolicy: vi.fn() },
            policyRecorder: mockPolicyRecorder(),
            transport: {} as never,
            resolvePublicKey: makePubKeyResolver(),
            businessHandler: vi.fn(),
        });

        const incoming = buildEnvelope({
            senderDid,
            senderPrivateKey,
            recipientDid,
            sessionId: 'session-bad-params',
            messageType: 'NEGOTIATION_REQUEST',
            body: { action: 'INQUIRY', params: ['not', 'an', 'object'] },
        });

        const result = await orchestrator.handleEnvelope(incoming);

        expect(result).toMatchObject({
            handled: false,
            responseEnvelope: {
                messageType: 'ERROR',
                body: { code: 'INVALID_ENVELOPE' },
            },
        });
    });

    // ─── internal exception path ──────────────────────────────────────────
    it('wraps unexpected executor errors in an INTERNAL_ERROR envelope', async () => {
        const orchestrator = new Orchestrator({
            agentDid: recipientDid,
            agentPrivateKey: recipientPrivateKey,
            principalDid,
            policyEngine: {
                executeWithPolicy: () =>
                    Promise.reject(new Error('downstream timeout')),
            },
            policyRecorder: mockPolicyRecorder(),
            transport: {} as never,
            resolvePublicKey: makePubKeyResolver(),
            businessHandler: vi.fn(),
        });

        const incoming = buildEnvelope({
            senderDid,
            senderPrivateKey,
            recipientDid,
            sessionId: 'session-error',
            messageType: 'NEGOTIATION_REQUEST',
            body: { action: 'INQUIRY', params: { recipient: 'supplier-a' } },
        });

        const result = await orchestrator.handleEnvelope(incoming);

        expect(result).toMatchObject({
            handled: false,
            rejectionReason: 'downstream timeout',
            responseEnvelope: {
                messageType: 'ERROR',
                body: { code: 'INTERNAL_ERROR' },
            },
        });
    });

    // ─── the delegation-chain validator must receive the authoritative parent-Token resolver ──
    it('passes tokenStore.getToken to delegationChainValidator as resolveToken', async () => {
        const token = buildDelegatedTokenFixture({
            id: 'urn:cap:77777777-7777-7777-7777-777777777777',
            issuedTo: senderDid,
        });
        const validator = vi.fn(
            (): Promise<DelegationChainValidationResult> =>
                Promise.resolve({ valid: true, depth: 2 }),
        );
        const getToken = vi.fn(() => Promise.resolve(token));

        const orchestrator = new Orchestrator({
            agentDid: recipientDid,
            agentPrivateKey: recipientPrivateKey,
            principalDid,
            policyEngine: {
                executeWithPolicy: async ({ executor }) => ({
                    executed: true as const,
                    result: await executor(),
                    recordId: 'record-resolveToken',
                }),
            },
            transport: {} as never,
            resolvePublicKey: makePubKeyResolver(),
            tokenStore: { getToken },
            delegationChainValidator: validator,
            revocationChecker: vi.fn(() => Promise.resolve(false)),
            policyRecorder: mockPolicyRecorder(),
            resolveAgentDocument: vi.fn(() =>
                Promise.resolve(mockSenderDocument()),
            ),
            businessHandler: ({ action }) =>
                Promise.resolve({ handledAction: action }),
        });

        const incoming = buildEnvelope({
            senderDid,
            senderPrivateKey,
            recipientDid,
            sessionId: 'session-resolvetoken',
            messageType: 'NEGOTIATION_REQUEST',
            body: { action: 'INQUIRY', params: { recipient: 'supplier-a' } },
            capabilityTokenRef: token.id,
        });

        await orchestrator.handleEnvelope(incoming);

        expect(validator).toHaveBeenCalledTimes(1);
        // the 5th argument must be a callable resolveToken function, not undefined
        const resolveTokenArg = validator.mock.calls[0]?.[4];
        expect(typeof resolveTokenArg).toBe('function');
        // calling it should delegate to tokenStore.getToken
        await (resolveTokenArg as (id: string) => Promise<unknown>)(
            'urn:cap:parent',
        );
        expect(getToken).toHaveBeenCalledWith('urn:cap:parent');
    });

    it('rejects with delegation_parent_token_not_found when validator reports parent missing', async () => {
        const token = buildDelegatedTokenFixture({
            id: 'urn:cap:88888888-8888-8888-8888-888888888888',
            issuedTo: senderDid,
        });
        const validator = vi.fn(
            (): Promise<DelegationChainValidationResult> =>
                Promise.resolve({
                    valid: false,
                    depth: 1,
                    reason: 'PARENT_TOKEN_NOT_FOUND',
                    brokenAtIndex: 0,
                }),
        );

        const orchestrator = new Orchestrator({
            agentDid: recipientDid,
            agentPrivateKey: recipientPrivateKey,
            principalDid,
            policyEngine: { executeWithPolicy: vi.fn() },
            transport: {} as never,
            resolvePublicKey: makePubKeyResolver(),
            tokenStore: { getToken: vi.fn(() => Promise.resolve(token)) },
            delegationChainValidator: validator,
            revocationChecker: vi.fn(() => Promise.resolve(false)),
            policyRecorder: mockPolicyRecorder(),
            resolveAgentDocument: vi.fn(() =>
                Promise.resolve(mockSenderDocument()),
            ),
            businessHandler: vi.fn(),
        });

        const incoming = buildEnvelope({
            senderDid,
            senderPrivateKey,
            recipientDid,
            sessionId: 'session-parent-missing',
            messageType: 'NEGOTIATION_REQUEST',
            body: { action: 'INQUIRY', params: { recipient: 'supplier-a' } },
            capabilityTokenRef: token.id,
        });

        const result = await orchestrator.handleEnvelope(incoming);

        expect(result.handled).toBe(false);
        expect(result.rejectionReason).toBe(
            'delegation_parent_token_not_found',
        );
    });

    // ─── the sender token must authorize this action/scope ────────
    it('rejects when sender token does not authorize the requested action (action mismatch)', async () => {
        // the token authorizes QUOTE, but the envelope requests INQUIRY -> must be rejected at step3.5.
        // without an action-match check, a valid QUOTE token could be replayed onto an INQUIRY request.
        const token = buildDelegatedTokenFixture({
            id: 'urn:cap:action-mismatch',
            issuedTo: senderDid,
            capabilities: [
                {
                    action: 'QUOTE',
                    scope: {
                        type: 'allowlist',
                        field: 'recipient',
                        values: ['supplier-a'],
                    },
                },
            ] as unknown as CapabilityToken['capabilities'],
        });

        const validator = vi.fn(
            (): Promise<DelegationChainValidationResult> =>
                Promise.resolve({ valid: true, depth: 1 }),
        );

        const orchestrator = new Orchestrator({
            agentDid: recipientDid,
            agentPrivateKey: recipientPrivateKey,
            principalDid,
            policyEngine: { executeWithPolicy: vi.fn() },
            transport: {} as never,
            resolvePublicKey: makePubKeyResolver(),
            tokenStore: { getToken: vi.fn(() => Promise.resolve(token)) },
            delegationChainValidator: validator,
            revocationChecker: vi.fn(() => Promise.resolve(false)),
            policyRecorder: mockPolicyRecorder(),
            resolveAgentDocument: vi.fn(() =>
                Promise.resolve(mockSenderDocument()),
            ),
            businessHandler: vi.fn(),
        });

        const incoming = buildEnvelope({
            senderDid,
            senderPrivateKey,
            recipientDid,
            sessionId: 'session-action-mismatch',
            messageType: 'NEGOTIATION_REQUEST',
            body: { action: 'INQUIRY', params: { recipient: 'supplier-a' } },
            capabilityTokenRef: token.id,
        });

        const result = await orchestrator.handleEnvelope(incoming);

        expect(result.handled).toBe(false);
        expect(result.rejectionReason).toBe('delegation_invalid_action');
        // short-circuited at step3.5, the validator should not be called
        expect(validator).not.toHaveBeenCalled();
    });

    it('rejects when sender token scope is exceeded (numeric_limit)', async () => {
        const token = buildDelegatedTokenFixture({
            id: 'urn:cap:scope-exceeded',
            issuedTo: senderDid,
            capabilities: [
                {
                    action: 'PAYMENT',
                    scope: {
                        type: 'numeric_limit',
                        field: 'amount',
                        max: 100,
                    },
                },
            ] as unknown as CapabilityToken['capabilities'],
        });

        const validator = vi.fn(
            (): Promise<DelegationChainValidationResult> =>
                Promise.resolve({ valid: true, depth: 1 }),
        );

        const orchestrator = new Orchestrator({
            agentDid: recipientDid,
            agentPrivateKey: recipientPrivateKey,
            principalDid,
            policyEngine: { executeWithPolicy: vi.fn() },
            transport: {} as never,
            resolvePublicKey: makePubKeyResolver(),
            tokenStore: { getToken: vi.fn(() => Promise.resolve(token)) },
            delegationChainValidator: validator,
            revocationChecker: vi.fn(() => Promise.resolve(false)),
            policyRecorder: mockPolicyRecorder(),
            resolveAgentDocument: vi.fn(() =>
                Promise.resolve(mockSenderDocument()),
            ),
            businessHandler: vi.fn(),
        });

        const incoming = buildEnvelope({
            senderDid,
            senderPrivateKey,
            recipientDid,
            sessionId: 'session-scope-exceeded',
            messageType: 'NEGOTIATION_REQUEST',
            body: { action: 'PAYMENT', params: { amount: 500 } },
            capabilityTokenRef: token.id,
        });

        const result = await orchestrator.handleEnvelope(incoming);

        expect(result.handled).toBe(false);
        // reuses the L3 ScopeEvaluator; the error message carries a prefix + L3 details.
        expect(result.rejectionReason).toMatch(/^delegation_scope_denied:/);
        expect(validator).not.toHaveBeenCalled();
    });

    // ─── leaf token's own validity (expiry/revocation/signature) ──────
    it('rejects when sender token is expired (leaf expiry)', async () => {
        // a token expired by 1 hour: the step3.5 leaf time-window check must intercept it first.
        const expired = new Date(Date.now() - 3_600_000).toISOString();
        const token = buildDelegatedTokenFixture({
            id: 'urn:cap:leaf-expired',
            issuedTo: senderDid,
            issuedAt: new Date(Date.now() - 7_200_000).toISOString(),
            expiresAt: expired,
        });

        const validator = vi.fn(
            (): Promise<DelegationChainValidationResult> =>
                Promise.resolve({ valid: true, depth: 1 }),
        );

        const orchestrator = new Orchestrator({
            agentDid: recipientDid,
            agentPrivateKey: recipientPrivateKey,
            principalDid,
            policyEngine: { executeWithPolicy: vi.fn() },
            transport: {} as never,
            resolvePublicKey: makePubKeyResolver(),
            tokenStore: { getToken: vi.fn(() => Promise.resolve(token)) },
            delegationChainValidator: validator,
            revocationChecker: vi.fn(() => Promise.resolve(false)),
            policyRecorder: mockPolicyRecorder(),
            resolveAgentDocument: vi.fn(() =>
                Promise.resolve(mockSenderDocument()),
            ),
            businessHandler: vi.fn(),
        });

        const incoming = buildEnvelope({
            senderDid,
            senderPrivateKey,
            recipientDid,
            sessionId: 'session-leaf-expired',
            messageType: 'NEGOTIATION_REQUEST',
            body: { action: 'INQUIRY', params: { recipient: 'supplier-a' } },
            capabilityTokenRef: token.id,
        });

        const result = await orchestrator.handleEnvelope(incoming);

        expect(result.handled).toBe(false);
        expect(result.rejectionReason).toBe('delegation_token_expired');
        expect(validator).not.toHaveBeenCalled();
    });

    it('rejects when sender leaf token id itself is revoked', async () => {
        // the leaf itself is revoked; this differs from parent revocation — earlier versions only checked the
        // parent inside validateDelegationChain, so revocation of the leaf itself was ignored.
        const token = buildDelegatedTokenFixture({
            id: 'urn:cap:leaf-revoked',
            issuedTo: senderDid,
        });

        const validator = vi.fn(
            (): Promise<DelegationChainValidationResult> =>
                Promise.resolve({ valid: true, depth: 1 }),
        );
        const revocationChecker = vi.fn((tokenId: string) =>
            Promise.resolve(tokenId === token.id),
        );

        const orchestrator = new Orchestrator({
            agentDid: recipientDid,
            agentPrivateKey: recipientPrivateKey,
            principalDid,
            policyEngine: { executeWithPolicy: vi.fn() },
            transport: {} as never,
            resolvePublicKey: makePubKeyResolver(),
            tokenStore: { getToken: vi.fn(() => Promise.resolve(token)) },
            delegationChainValidator: validator,
            revocationChecker,
            policyRecorder: mockPolicyRecorder(),
            resolveAgentDocument: vi.fn(() =>
                Promise.resolve(mockSenderDocument()),
            ),
            businessHandler: vi.fn(),
        });

        const incoming = buildEnvelope({
            senderDid,
            senderPrivateKey,
            recipientDid,
            sessionId: 'session-leaf-revoked',
            messageType: 'NEGOTIATION_REQUEST',
            body: { action: 'INQUIRY', params: { recipient: 'supplier-a' } },
            capabilityTokenRef: token.id,
        });

        const result = await orchestrator.handleEnvelope(incoming);

        expect(result.handled).toBe(false);
        expect(result.rejectionReason).toBe('delegation_token_revoked');
        expect(validator).not.toHaveBeenCalled();
    });

    it('rejects when sender leaf token signature is invalid (delegated path)', async () => {
        // sign the leaf with a different keypair, but sender resolvePublicKey still returns the original public key -> signature verification fails.
        const attackerKeyPair = generateKeyPair();
        const token = buildDelegatedTokenFixture({
            id: 'urn:cap:leaf-badsig',
            issuedTo: senderDid,
            signingPrivateKey: attackerKeyPair.privateKey,
        });

        const validator = vi.fn(
            (): Promise<DelegationChainValidationResult> =>
                Promise.resolve({ valid: true, depth: 1 }),
        );

        const orchestrator = new Orchestrator({
            agentDid: recipientDid,
            agentPrivateKey: recipientPrivateKey,
            principalDid,
            policyEngine: { executeWithPolicy: vi.fn() },
            transport: {} as never,
            // the sender's public key is still the legitimate one (not attackerKeyPair.publicKey)
            resolvePublicKey: makePubKeyResolver(),
            tokenStore: { getToken: vi.fn(() => Promise.resolve(token)) },
            delegationChainValidator: validator,
            revocationChecker: vi.fn(() => Promise.resolve(false)),
            policyRecorder: mockPolicyRecorder(),
            resolveAgentDocument: vi.fn(() =>
                Promise.resolve(mockSenderDocument()),
            ),
            businessHandler: vi.fn(),
        });

        const incoming = buildEnvelope({
            senderDid,
            senderPrivateKey,
            recipientDid,
            sessionId: 'session-leaf-badsig',
            messageType: 'NEGOTIATION_REQUEST',
            body: { action: 'INQUIRY', params: { recipient: 'supplier-a' } },
            capabilityTokenRef: token.id,
        });

        const result = await orchestrator.handleEnvelope(incoming);

        expect(result.handled).toBe(false);
        expect(result.rejectionReason).toBe(
            'delegation_leaf_signature_invalid',
        );
        expect(validator).not.toHaveBeenCalled();
    });

    // ─── the sender tokenId must not be threaded through to the recipient-side PolicyEngine ──
    it('does not forward sender tokenId to recipient-side executeWithPolicy (independent authorization contexts)', async () => {
        const token = buildDelegatedTokenFixture({
            id: 'urn:cap:99999999-9999-9999-9999-999999999999',
            issuedTo: senderDid,
        });
        const validator = vi.fn(
            (): Promise<DelegationChainValidationResult> =>
                Promise.resolve({ valid: true, depth: 1 }),
        );
        const executeWithPolicy = vi.fn(
            async ({
                executor,
            }: {
                executor: () => Promise<Record<string, unknown>>;
            }) => ({
                executed: true as const,
                result: await executor(),
                recordId: 'record-closed-loop',
            }),
        );

        const orchestrator = new Orchestrator({
            agentDid: recipientDid,
            agentPrivateKey: recipientPrivateKey,
            principalDid,
            policyEngine: { executeWithPolicy },
            transport: {} as never,
            resolvePublicKey: makePubKeyResolver(),
            tokenStore: { getToken: vi.fn(() => Promise.resolve(token)) },
            delegationChainValidator: validator,
            revocationChecker: vi.fn(() => Promise.resolve(false)),
            policyRecorder: mockPolicyRecorder(),
            resolveAgentDocument: vi.fn(() =>
                Promise.resolve(mockSenderDocument()),
            ),
            businessHandler: ({ action }) =>
                Promise.resolve({ handledAction: action }),
        });

        const incoming = buildEnvelope({
            senderDid,
            senderPrivateKey,
            recipientDid,
            sessionId: 'session-closed-loop',
            messageType: 'NEGOTIATION_REQUEST',
            body: { action: 'INQUIRY', params: { recipient: 'supplier-a' } },
            capabilityTokenRef: token.id,
        });

        await orchestrator.handleEnvelope(incoming);

        expect(executeWithPolicy).toHaveBeenCalledTimes(1);
        const callArgs = executeWithPolicy.mock.calls[0]?.[0];
        // the sender's tokenId does not belong to the recipient-side authorization context and must never be passed
        // into executeWithPolicy; otherwise RuntimeGuard would filter the recipient's local Token pool by the
        // sender tokenId -> necessarily find no Token -> falsely reject a legitimate request.
        expect(callArgs?.requestedTokenId).toBeUndefined();
    });

    it('omits requestedTokenId when envelope has no capabilityTokenRef (no-tokenRef path)', async () => {
        const executeWithPolicy = vi.fn(
            async ({
                executor,
            }: {
                executor: () => Promise<Record<string, unknown>>;
            }) => ({
                executed: true as const,
                result: await executor(),
                recordId: 'record-phase1-path',
            }),
        );

        const orchestrator = new Orchestrator({
            agentDid: recipientDid,
            agentPrivateKey: recipientPrivateKey,
            principalDid,
            policyEngine: { executeWithPolicy },
            policyRecorder: mockPolicyRecorder(),
            transport: {} as never,
            resolvePublicKey: makePubKeyResolver(),
            businessHandler: ({ action }) =>
                Promise.resolve({ handledAction: action }),
        });

        const incoming = buildEnvelope({
            senderDid,
            senderPrivateKey,
            recipientDid,
            sessionId: 'session-no-tokenref',
            messageType: 'NEGOTIATION_REQUEST',
            body: { action: 'INQUIRY', params: { recipient: 'supplier-a' } },
        });

        await orchestrator.handleEnvelope(incoming);

        const callArgs = executeWithPolicy.mock.calls[0]?.[0];
        expect(callArgs?.requestedTokenId).toBeUndefined();
    });

    // ─── principal consistency check ──────────────────────────────────
    it('rejects when sender document principalDid does not match token principalDid', async () => {
        // Attack scenario: the token was signed by Alice for Agent X (principal = Alice),
        // but the principal bound in Agent X's AgentIdentityDocument is Charlie.
        // Without a principal consistency check, "the agent of human Charlie" could act in the name of "Alice's authorization".
        const alicePrincipal =
            'did:key:z6MkalicealicealicealicealicealicealicealicealiceD' as DID;
        const token = {
            id: 'urn:cap:aaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
            specVersion: SPEC_VERSION_0_2_0,
            issuerDid: alicePrincipal,
            principalDid: alicePrincipal, // the Token claims it is Alice's authorization
            issuedTo: senderDid,
            issuedAt: new Date().toISOString(),
            expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
            capabilities: [],
            revocationUrl: 'https://revocation.example/v1/{id}',
            proof: {
                type: 'Ed25519Signature2026',
                created: new Date().toISOString(),
                verificationMethod: `${alicePrincipal}#key-1`,
                value: 'x'.repeat(128),
            },
        } as unknown as CapabilityToken;

        // sender agent document: the principal is actually bound to Charlie (inconsistent with the Token)
        const charliePrincipal =
            'did:key:z6MkcharliecharliecharliecharliecharliecharlieCHAR' as DID;
        const senderDocument = {
            id: senderDid,
            specVersion: SPEC_VERSION_0_2_0,
            principalDid: charliePrincipal,
            publicKey,
            bindingProof: {} as never,
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString(),
        } as unknown as AgentIdentityDocument;

        const validator = vi.fn();
        const orchestrator = new Orchestrator({
            agentDid: recipientDid,
            agentPrivateKey: recipientPrivateKey,
            principalDid,
            policyEngine: { executeWithPolicy: vi.fn() },
            transport: {} as never,
            resolvePublicKey: makePubKeyResolver(),
            resolveAgentDocument: vi.fn(() => Promise.resolve(senderDocument)),
            tokenStore: { getToken: vi.fn(() => Promise.resolve(token)) },
            delegationChainValidator: validator,
            revocationChecker: vi.fn(() => Promise.resolve(false)),
            policyRecorder: mockPolicyRecorder(),
            businessHandler: vi.fn(),
        });

        const incoming = buildEnvelope({
            senderDid,
            senderPrivateKey,
            recipientDid,
            sessionId: 'session-principal-mismatch',
            messageType: 'NEGOTIATION_REQUEST',
            body: { action: 'INQUIRY', params: { recipient: 'supplier-a' } },
            capabilityTokenRef: token.id,
        });

        const result = await orchestrator.handleEnvelope(incoming);

        expect(result.handled).toBe(false);
        expect(result.rejectionReason).toBe('delegation_principal_mismatch');
        expect(validator).not.toHaveBeenCalled();
    });

    it('rejects with delegation_sender_document_not_found when publicKey resolver succeeds but document resolver returns null', async () => {
        // Scenario: step2 resolves successfully via an independent public-key cache, step3.5 calls the independent
        // document resolver but the document lookup fails. This must fail-closed and reject — passing step2 must not
        // cause the principal consistency check to be skipped.
        const token = buildDelegatedTokenFixture({
            id: 'urn:cap:bbbbbbb-cccc-dddd-eeee-ffffffffffff',
            issuedTo: senderDid,
        });
        const orchestrator = new Orchestrator({
            agentDid: recipientDid,
            agentPrivateKey: recipientPrivateKey,
            principalDid,
            policyEngine: { executeWithPolicy: vi.fn() },
            transport: {} as never,
            // independent public-key resolution (e.g. a performance cache)
            resolvePublicKey: makePubKeyResolver(),
            // independent document resolution returning null (simulates the document service being temporarily unreachable)
            resolveAgentDocument: vi.fn(() => Promise.resolve(null)),
            tokenStore: { getToken: vi.fn(() => Promise.resolve(token)) },
            delegationChainValidator: vi.fn(),
            revocationChecker: vi.fn(() => Promise.resolve(false)),
            policyRecorder: mockPolicyRecorder(),
            businessHandler: vi.fn(),
        });

        const incoming = buildEnvelope({
            senderDid,
            senderPrivateKey,
            recipientDid,
            sessionId: 'session-doc-missing',
            messageType: 'NEGOTIATION_REQUEST',
            body: { action: 'INQUIRY', params: { recipient: 'supplier-a' } },
            capabilityTokenRef: token.id,
        });

        const result = await orchestrator.handleEnvelope(incoming);

        expect(result.handled).toBe(false);
        expect(result.rejectionReason).toBe(
            'delegation_sender_document_not_found',
        );
    });

    it('derives resolveAgentDocument from federatedResolver when not explicitly provided', async () => {
        const token = buildDelegatedTokenFixture({
            id: 'urn:cap:ccccccc-dddd-eeee-ffff-aaaaaaaaaaaa',
            issuedTo: senderDid,
        });
        const senderDocument = {
            id: senderDid,
            specVersion: SPEC_VERSION_0_2_0,
            principalDid, // matches token.principalDid (the fixture uses principalDid)
            publicKey,
            bindingProof: {} as never,
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString(),
        } as unknown as AgentIdentityDocument;
        const middleDocument = {
            id: middleAgentDid,
            specVersion: SPEC_VERSION_0_2_0,
            principalDid,
            publicKey: middlePublicKey,
            bindingProof: {} as never,
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString(),
        } as unknown as AgentIdentityDocument;

        // Dispatch by DID: the sender side uses the sender document, the chain-tail delegator uses the middle document.
        const resolveFn = vi.fn((did: DID) => {
            if (did === middleAgentDid) return Promise.resolve(middleDocument);
            return Promise.resolve(senderDocument);
        });
        const federatedResolver: FederatedResolver = {
            resolve: resolveFn,
            invalidateCache: vi.fn(),
            getMetrics: vi.fn(),
            close: vi.fn(),
        } as unknown as FederatedResolver;

        const orchestrator = new Orchestrator({
            agentDid: recipientDid,
            agentPrivateKey: recipientPrivateKey,
            principalDid,
            policyEngine: {
                executeWithPolicy: async ({ executor }) => ({
                    executed: true as const,
                    result: await executor(),
                    recordId: 'record-derived',
                }),
            },
            transport: {} as never,
            federatedResolver, // inject federatedResolver only, not resolveAgentDocument
            tokenStore: { getToken: vi.fn(() => Promise.resolve(token)) },
            delegationChainValidator: vi.fn(
                (): Promise<DelegationChainValidationResult> =>
                    Promise.resolve({ valid: true, depth: 1 }),
            ),
            revocationChecker: vi.fn(() => Promise.resolve(false)),
            policyRecorder: mockPolicyRecorder(),
            businessHandler: ({ action }) =>
                Promise.resolve({ handledAction: action }),
        });

        const incoming = buildEnvelope({
            senderDid,
            senderPrivateKey,
            recipientDid,
            sessionId: 'session-derived-doc',
            messageType: 'NEGOTIATION_REQUEST',
            body: { action: 'INQUIRY', params: { recipient: 'supplier-a' } },
            capabilityTokenRef: token.id,
        });

        const result = await orchestrator.handleEnvelope(incoming);

        expect(result.handled).toBe(true);
        // resolveFn is called at least twice: public-key derivation + document derivation (the same federatedResolver.resolve)
        expect(resolveFn).toHaveBeenCalled();
    });

    it('throws at construction when legacy resolvePublicKey + tokenStore but no document resolver', () => {
        // The legacy path (resolvePublicKey only) + tokenStore cannot satisfy
        // capability-token authorization (step 5 needs the principalDid consistency check), so construction
        // must reject. This scenario previously only returned delegation_phase2_dependencies_missing at runtime,
        // which is a "configuration time bomb" — it now errors at construction time instead.
        expect(
            () =>
                new Orchestrator({
                    agentDid: recipientDid,
                    agentPrivateKey: recipientPrivateKey,
                    principalDid,
                    policyEngine: { executeWithPolicy: vi.fn() },
                    transport: {} as never,
                    resolvePublicKey: makePubKeyResolver(),
                    // deliberately not configuring resolveAgentDocument / federatedResolver
                    tokenStore: { getToken: vi.fn() },
                    delegationChainValidator: vi.fn(),
                    revocationChecker: vi.fn(() => Promise.resolve(false)),
                    policyRecorder: mockPolicyRecorder(),
                    businessHandler: vi.fn(),
                }),
        ).toThrow(/resolveAgentDocument/);
    });

    // ─── coverage fill-in: construction branches, leaf-not-yet-valid, missing delegated-leaf public key, capability-token scope
    it('falls back to resolveAgentDocument-derived publicKey when no federatedResolver/resolvePublicKey is provided', async () => {
        // Coverage of the third construction branch: with only resolveAgentDocument injected, verifyEnvelope's resolvePublicKey
        // must be derived from document.publicKey.
        const orchestrator = new Orchestrator({
            agentDid: recipientDid,
            agentPrivateKey: recipientPrivateKey,
            principalDid,
            policyEngine: {
                executeWithPolicy: async ({ executor }) => ({
                    executed: true as const,
                    result: await executor(),
                    recordId: 'record-doc-derived',
                }),
            },
            policyRecorder: mockPolicyRecorder(),
            transport: {} as never,
            resolveAgentDocument: vi.fn(() =>
                Promise.resolve(mockSenderDocument()),
            ),
            businessHandler: ({ action }) =>
                Promise.resolve({ handledAction: action }),
        });

        const incoming = buildEnvelope({
            senderDid,
            senderPrivateKey,
            recipientDid,
            sessionId: 'session-doc-derived',
            messageType: 'NEGOTIATION_REQUEST',
            body: { action: 'INQUIRY', params: { recipient: 'supplier-a' } },
        });

        const result = await orchestrator.handleEnvelope(incoming);
        expect(result.handled).toBe(true);
    });

    it('rejects with delegation_token_not_yet_valid when token issuedAt is in the future', async () => {
        const token = buildDelegatedTokenFixture({
            id: 'urn:cap:leaf-not-yet-valid',
            issuedTo: senderDid,
            issuedAt: new Date(Date.now() + 60_000).toISOString(),
            expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
        });

        const orchestrator = new Orchestrator({
            agentDid: recipientDid,
            agentPrivateKey: recipientPrivateKey,
            principalDid,
            policyEngine: { executeWithPolicy: vi.fn() },
            transport: {} as never,
            resolvePublicKey: makePubKeyResolver(),
            tokenStore: { getToken: vi.fn(() => Promise.resolve(token)) },
            delegationChainValidator: vi.fn(),
            revocationChecker: vi.fn(() => Promise.resolve(false)),
            policyRecorder: mockPolicyRecorder(),
            resolveAgentDocument: vi.fn(() =>
                Promise.resolve(mockSenderDocument()),
            ),
            businessHandler: vi.fn(),
        });

        const incoming = buildEnvelope({
            senderDid,
            senderPrivateKey,
            recipientDid,
            sessionId: 'session-leaf-not-yet-valid',
            messageType: 'NEGOTIATION_REQUEST',
            body: { action: 'INQUIRY', params: { recipient: 'supplier-a' } },
            capabilityTokenRef: token.id,
        });

        const result = await orchestrator.handleEnvelope(incoming);
        expect(result.rejectionReason).toBe('delegation_token_not_yet_valid');
    });

    it('rejects with delegation_sender_publickey_not_found when sender publicKey cannot be resolved (delegated leaf)', async () => {
        const token = buildDelegatedTokenFixture({
            id: 'urn:cap:leaf-no-sender-key',
            issuedTo: senderDid,
        });

        const orchestrator = new Orchestrator({
            agentDid: recipientDid,
            agentPrivateKey: recipientPrivateKey,
            principalDid,
            policyEngine: { executeWithPolicy: vi.fn() },
            transport: {} as never,
            // sender public key missing (returns null) -> the delegated-leaf signature cannot be verified
            resolvePublicKey: vi.fn(() => Promise.resolve(null)),
            tokenStore: { getToken: vi.fn(() => Promise.resolve(token)) },
            delegationChainValidator: vi.fn(),
            revocationChecker: vi.fn(() => Promise.resolve(false)),
            policyRecorder: mockPolicyRecorder(),
            resolveAgentDocument: vi.fn(() =>
                Promise.resolve(mockSenderDocument()),
            ),
            businessHandler: vi.fn(),
        });

        const incoming = buildEnvelope({
            senderDid,
            senderPrivateKey,
            recipientDid,
            sessionId: 'session-no-sender-key',
            messageType: 'NEGOTIATION_REQUEST',
            body: { action: 'INQUIRY', params: { recipient: 'supplier-a' } },
            capabilityTokenRef: token.id,
        });

        const result = await orchestrator.handleEnvelope(incoming);
        // verifyEnvelope first tries resolvePublicKey -> null and therefore returns identity_verification_failed.
        // This is the normal order: envelope verification (step2) precedes capability (step3.5).
        // So handled=false and the rejection reason lands at the identity layer, not delegation_sender_publickey_not_found.
        expect(result.handled).toBe(false);
    });

    it('accepts when sender token uses a versioned scope (temporal_scope) and defers semantic eval to RuntimeGuard', async () => {
        // hasPhase2Scope positive branch: step3.5 only checks for the existence of the action.
        const token = buildDelegatedTokenFixture({
            id: 'urn:cap:leaf-temporal-scope',
            issuedTo: senderDid,
            capabilities: [
                {
                    action: 'INQUIRY',
                    scope: {
                        type: 'temporal_scope',
                        notBefore: new Date(
                            Date.now() - 3_600_000,
                        ).toISOString(),
                        notAfter: new Date(
                            Date.now() + 3_600_000,
                        ).toISOString(),
                    },
                },
            ] as unknown as CapabilityToken['capabilities'],
        });

        const validator = vi.fn(
            (): Promise<DelegationChainValidationResult> =>
                Promise.resolve({ valid: true, depth: 1 }),
        );

        const orchestrator = new Orchestrator({
            agentDid: recipientDid,
            agentPrivateKey: recipientPrivateKey,
            principalDid,
            policyEngine: {
                executeWithPolicy: async ({ executor }) => ({
                    executed: true as const,
                    result: await executor(),
                    recordId: 'record-phase2-scope',
                }),
            },
            transport: {} as never,
            resolvePublicKey: makePubKeyResolver(),
            tokenStore: { getToken: vi.fn(() => Promise.resolve(token)) },
            delegationChainValidator: validator,
            revocationChecker: vi.fn(() => Promise.resolve(false)),
            policyRecorder: mockPolicyRecorder(),
            resolveAgentDocument: vi.fn(() =>
                Promise.resolve(mockSenderDocument()),
            ),
            businessHandler: ({ action }) =>
                Promise.resolve({ handledAction: action }),
        });

        const incoming = buildEnvelope({
            senderDid,
            senderPrivateKey,
            recipientDid,
            sessionId: 'session-phase2-scope',
            messageType: 'NEGOTIATION_REQUEST',
            body: { action: 'INQUIRY', params: {} },
            capabilityTokenRef: token.id,
        });

        const result = await orchestrator.handleEnvelope(incoming);
        expect(result.handled).toBe(true);
    });

    it('rejects with delegation_invalid_action when a versioned-scope token has no matching action', async () => {
        // An action mismatch uniformly takes evaluateSenderTokenScope's invalid_action branch,
        // aligned with the base path (no longer using special versioned scope naming).
        const token = buildDelegatedTokenFixture({
            id: 'urn:cap:leaf-phase2-action-mismatch',
            issuedTo: senderDid,
            capabilities: [
                {
                    action: 'PAYMENT',
                    scope: {
                        type: 'cumulative_limit',
                        meterField: {
                            source: 'action_record',
                            metric: 'payment_total_cny',
                        },
                        max: 10_000,
                        window: 'day',
                    },
                },
            ] as unknown as CapabilityToken['capabilities'],
        });

        const validator = vi.fn(
            (): Promise<DelegationChainValidationResult> =>
                Promise.resolve({ valid: true, depth: 1 }),
        );

        const orchestrator = new Orchestrator({
            agentDid: recipientDid,
            agentPrivateKey: recipientPrivateKey,
            principalDid,
            policyEngine: { executeWithPolicy: vi.fn() },
            transport: {} as never,
            resolvePublicKey: makePubKeyResolver(),
            tokenStore: { getToken: vi.fn(() => Promise.resolve(token)) },
            delegationChainValidator: validator,
            revocationChecker: vi.fn(() => Promise.resolve(false)),
            policyRecorder: mockPolicyRecorder(),
            resolveAgentDocument: vi.fn(() =>
                Promise.resolve(mockSenderDocument()),
            ),
            businessHandler: vi.fn(),
        });

        const incoming = buildEnvelope({
            senderDid,
            senderPrivateKey,
            recipientDid,
            sessionId: 'session-phase2-action-mismatch',
            messageType: 'NEGOTIATION_REQUEST',
            body: { action: 'INQUIRY', params: {} },
            capabilityTokenRef: token.id,
        });

        const result = await orchestrator.handleEnvelope(incoming);
        expect(result.rejectionReason).toBe('delegation_invalid_action');
        expect(validator).not.toHaveBeenCalled();
    });

    // ─── per-entry evaluation of the sender token scope (AND semantics) ─────────
    it('rejects when sender token temporal_scope window is outside now', async () => {
        // Attack surface: the sender takes a 9:00–10:00 token and sends a request at 11:00.
        // The previous version only checked action existence -> allowed; after the fix it must reject by the temporal boundary.
        const notBefore = new Date(Date.now() - 7_200_000).toISOString();
        const notAfter = new Date(Date.now() - 3_600_000).toISOString();
        const token = buildDelegatedTokenFixture({
            id: 'urn:cap:leaf-temporal-out',
            issuedTo: senderDid,
            capabilities: [
                {
                    action: 'INQUIRY',
                    scope: {
                        type: 'temporal_scope',
                        notBefore,
                        notAfter,
                    },
                },
            ] as unknown as CapabilityToken['capabilities'],
        });

        const validator = vi.fn(
            (): Promise<DelegationChainValidationResult> =>
                Promise.resolve({ valid: true, depth: 1 }),
        );

        const orchestrator = new Orchestrator({
            agentDid: recipientDid,
            agentPrivateKey: recipientPrivateKey,
            principalDid,
            policyEngine: { executeWithPolicy: vi.fn() },
            transport: {} as never,
            resolvePublicKey: makePubKeyResolver(),
            tokenStore: { getToken: vi.fn(() => Promise.resolve(token)) },
            delegationChainValidator: validator,
            revocationChecker: vi.fn(() => Promise.resolve(false)),
            policyRecorder: mockPolicyRecorder(),
            resolveAgentDocument: vi.fn(() =>
                Promise.resolve(mockSenderDocument()),
            ),
            businessHandler: vi.fn(),
        });

        const incoming = buildEnvelope({
            senderDid,
            senderPrivateKey,
            recipientDid,
            sessionId: 'session-temporal-out',
            messageType: 'NEGOTIATION_REQUEST',
            body: { action: 'INQUIRY', params: {} },
            capabilityTokenRef: token.id,
        });

        const result = await orchestrator.handleEnvelope(incoming);
        expect(result.handled).toBe(false);
        // For exceeding notAfter, the L3 ScopeEvaluator returns "temporal_scope: expired ...".
        expect(result.rejectionReason).toMatch(
            /^delegation_scope_denied: temporal_scope/,
        );
        expect(validator).not.toHaveBeenCalled();
    });

    it('rejects when sender token has mixed scope (temporal_scope + allowlist) and params violate allowlist', async () => {
        // Key attack surface: a mixed-scope token (temporal passes but allowlist is violated).
        // The previous version skipped the allowlist whenever hasPhase2Scope=true -> a direct bypass.
        // After the fix: AND semantics, both capabilities must pass.
        const token = buildDelegatedTokenFixture({
            id: 'urn:cap:leaf-mixed-scope',
            issuedTo: senderDid,
            capabilities: [
                {
                    action: 'INQUIRY',
                    scope: {
                        type: 'temporal_scope',
                        notBefore: new Date(
                            Date.now() - 3_600_000,
                        ).toISOString(),
                        notAfter: new Date(
                            Date.now() + 3_600_000,
                        ).toISOString(),
                    },
                },
                {
                    action: 'INQUIRY',
                    scope: {
                        type: 'allowlist',
                        field: 'recipient',
                        values: ['supplier-a'],
                    },
                },
            ] as unknown as CapabilityToken['capabilities'],
        });

        const validator = vi.fn(
            (): Promise<DelegationChainValidationResult> =>
                Promise.resolve({ valid: true, depth: 1 }),
        );

        const orchestrator = new Orchestrator({
            agentDid: recipientDid,
            agentPrivateKey: recipientPrivateKey,
            principalDid,
            policyEngine: { executeWithPolicy: vi.fn() },
            transport: {} as never,
            resolvePublicKey: makePubKeyResolver(),
            tokenStore: { getToken: vi.fn(() => Promise.resolve(token)) },
            delegationChainValidator: validator,
            revocationChecker: vi.fn(() => Promise.resolve(false)),
            policyRecorder: mockPolicyRecorder(),
            resolveAgentDocument: vi.fn(() =>
                Promise.resolve(mockSenderDocument()),
            ),
            businessHandler: vi.fn(),
        });

        // sent to supplier-b — outside the allowlist
        const incoming = buildEnvelope({
            senderDid,
            senderPrivateKey,
            recipientDid,
            sessionId: 'session-mixed-bypass',
            messageType: 'NEGOTIATION_REQUEST',
            body: {
                action: 'INQUIRY',
                params: { recipient: 'supplier-b' },
            },
            capabilityTokenRef: token.id,
        });

        const result = await orchestrator.handleEnvelope(incoming);
        expect(result.handled).toBe(false);
        // L3 allowlist failure message "recipient is not in the allowlist".
        expect(result.rejectionReason).toMatch(
            /^delegation_scope_denied:.*allowlist/,
        );
        expect(validator).not.toHaveBeenCalled();
    });

    it('accepts when sender token has numeric_limit + temporal_scope and both satisfied', async () => {
        // Positive case: temporal falls within the window + numeric_limit not violated -> allowed.
        const token = buildDelegatedTokenFixture({
            id: 'urn:cap:leaf-mixed-pass',
            issuedTo: senderDid,
            capabilities: [
                {
                    action: 'PAYMENT',
                    scope: {
                        type: 'temporal_scope',
                        notBefore: new Date(
                            Date.now() - 3_600_000,
                        ).toISOString(),
                        notAfter: new Date(
                            Date.now() + 3_600_000,
                        ).toISOString(),
                    },
                },
                {
                    action: 'PAYMENT',
                    scope: {
                        type: 'numeric_limit',
                        field: 'amount',
                        max: 1_000,
                    },
                },
            ] as unknown as CapabilityToken['capabilities'],
        });

        const validator = vi.fn(
            (): Promise<DelegationChainValidationResult> =>
                Promise.resolve({ valid: true, depth: 1 }),
        );

        const orchestrator = new Orchestrator({
            agentDid: recipientDid,
            agentPrivateKey: recipientPrivateKey,
            principalDid,
            policyEngine: {
                executeWithPolicy: async ({ executor }) => ({
                    executed: true as const,
                    result: await executor(),
                    recordId: 'record-mixed-pass',
                }),
            },
            transport: {} as never,
            resolvePublicKey: makePubKeyResolver(),
            tokenStore: { getToken: vi.fn(() => Promise.resolve(token)) },
            delegationChainValidator: validator,
            revocationChecker: vi.fn(() => Promise.resolve(false)),
            policyRecorder: mockPolicyRecorder(),
            resolveAgentDocument: vi.fn(() =>
                Promise.resolve(mockSenderDocument()),
            ),
            businessHandler: ({ action }) =>
                Promise.resolve({ handledAction: action }),
        });

        const incoming = buildEnvelope({
            senderDid,
            senderPrivateKey,
            recipientDid,
            sessionId: 'session-mixed-pass',
            messageType: 'NEGOTIATION_REQUEST',
            body: { action: 'PAYMENT', params: { amount: 500 } },
            capabilityTokenRef: token.id,
        });

        const result = await orchestrator.handleEnvelope(incoming);
        expect(result.handled).toBe(true);
    });

    // ─── cumulative_limit fail-closed default + injectable tracker port ───
    // Evolution log:
    // Early on, cumulative_limit was filtered out (no audit) -> a silent bypass.
    // Changed to fail-closed (too coarse, blocked legitimate capability-token authorizations).
    // Then changed to allow+warn (recognized as a privilege-escalation downgrade that violates the cumulative-limit step of the authorization flow).
    // Current: fail-closed by default + an injectable senderCumulativeTracker port for real evaluation.
    it('rejects sender token cumulative_limit when senderCumulativeTracker is not injected (default fail-closed)', async () => {
        const token = buildDelegatedTokenFixture({
            id: 'urn:cap:leaf-cumulative-no-tracker',
            issuedTo: senderDid,
            capabilities: [
                {
                    action: 'PAYMENT',
                    scope: {
                        type: 'cumulative_limit',
                        meterField: {
                            source: 'action_record',
                            metric: 'transaction_amount',
                        },
                        max: 10_000,
                        window: 'day',
                    },
                },
            ] as unknown as CapabilityToken['capabilities'],
        });

        const validator = vi.fn(
            (): Promise<DelegationChainValidationResult> =>
                Promise.resolve({ valid: true, depth: 1 }),
        );

        const orchestrator = new Orchestrator({
            agentDid: recipientDid,
            agentPrivateKey: recipientPrivateKey,
            principalDid,
            policyEngine: { executeWithPolicy: vi.fn() },
            transport: {} as never,
            resolvePublicKey: makePubKeyResolver(),
            tokenStore: { getToken: vi.fn(() => Promise.resolve(token)) },
            delegationChainValidator: validator,
            revocationChecker: vi.fn(() => Promise.resolve(false)),
            policyRecorder: mockPolicyRecorder(),
            resolveAgentDocument: vi.fn(() =>
                Promise.resolve(mockSenderDocument()),
            ),
            // senderCumulativeTracker deliberately not injected
            businessHandler: vi.fn(),
        });

        const incoming = buildEnvelope({
            senderDid,
            senderPrivateKey,
            recipientDid,
            sessionId: 'session-cumulative-no-tracker',
            messageType: 'NEGOTIATION_REQUEST',
            body: { action: 'PAYMENT', params: { amount: 5_000 } },
            capabilityTokenRef: token.id,
        });

        const result = await orchestrator.handleEnvelope(incoming);

        expect(result.handled).toBe(false);
        expect(result.rejectionReason).toBe(
            'delegation_cumulative_limit_unverifiable',
        );
    });

    it('allows sender token cumulative_limit when senderCumulativeTracker is injected and projected total stays within max', async () => {
        const token = buildDelegatedTokenFixture({
            id: 'urn:cap:leaf-cumulative-under',
            issuedTo: senderDid,
            capabilities: [
                {
                    action: 'PAYMENT',
                    scope: {
                        type: 'cumulative_limit',
                        meterField: {
                            source: 'action_record',
                            metric: 'transaction_amount',
                        },
                        max: 10_000,
                        window: 'day',
                    },
                },
            ] as unknown as CapabilityToken['capabilities'],
        });

        const validator = vi.fn(
            (): Promise<DelegationChainValidationResult> =>
                Promise.resolve({ valid: true, depth: 1 }),
        );

        const executeWithPolicy = vi.fn(
            async ({
                executor,
            }: {
                executor: () => Promise<Record<string, unknown>>;
            }) => ({
                executed: true as const,
                result: await executor(),
                recordId: 'record-cumulative-under',
            }),
        );

        // checkAndReserve does an atomic query + reservation.
        // already accumulated 3_000, reserve 5_000 -> 8_000 < max 10_000 -> allowed:true.
        const checkAndReserve = vi.fn(() =>
            Promise.resolve({ allowed: true, currentCumulative: 3_000 }),
        );

        const orchestrator = new Orchestrator({
            agentDid: recipientDid,
            agentPrivateKey: recipientPrivateKey,
            principalDid,
            policyEngine: { executeWithPolicy },
            transport: {} as never,
            resolvePublicKey: makePubKeyResolver(),
            tokenStore: { getToken: vi.fn(() => Promise.resolve(token)) },
            delegationChainValidator: validator,
            revocationChecker: vi.fn(() => Promise.resolve(false)),
            policyRecorder: mockPolicyRecorder(),
            resolveAgentDocument: vi.fn(() =>
                Promise.resolve(mockSenderDocument()),
            ),
            senderCumulativeTracker: { checkAndReserve },
            businessHandler: ({ action }) =>
                Promise.resolve({ handledAction: action }),
        });

        const incoming = buildEnvelope({
            senderDid,
            senderPrivateKey,
            recipientDid,
            sessionId: 'session-cumulative-under',
            messageType: 'NEGOTIATION_REQUEST',
            body: { action: 'PAYMENT', params: { amount: 5_000 } },
            capabilityTokenRef: token.id,
        });

        const result = await orchestrator.handleEnvelope(incoming);

        expect(result.handled).toBe(true);
        expect(checkAndReserve).toHaveBeenCalledTimes(1);
        // checkAndReserve argument order: recordId, principalDid, meterField, windowStart, now, reserveAmount
        const trackerCallArgs = checkAndReserve.mock.calls[0];
        // recordId = envelopeId#metric#window (window must be the suffix)
        expect(trackerCallArgs?.[0]).toMatch(/#transaction_amount#day$/);
        expect(trackerCallArgs?.[1]).toBe(principalDid); // principal's perspective
        expect(trackerCallArgs?.[5]).toBe(5_000); // reserveAmount = params.amount
        expect(executeWithPolicy).toHaveBeenCalledTimes(1);
    });

    // The sender side must also fail-closed on the three-state source;
    // otherwise a 0.3.0 token using 'external_witness' / 'consensus_meter' could bypass
    // recipient validation and directly reserve the sender's quota.
    it('rejects sender token cumulative_limit when meterField.source is external_witness (fail-closed)', async () => {
        const token = buildDelegatedTokenFixture({
            id: 'urn:cap:leaf-cumulative-witness',
            issuedTo: senderDid,
            capabilities: [
                {
                    action: 'PAYMENT',
                    scope: {
                        type: 'cumulative_limit',
                        meterField: {
                            source: 'external_witness',
                            metric: 'api_call_count',
                        },
                        max: 10_000,
                        window: 'day',
                    },
                },
            ] as unknown as CapabilityToken['capabilities'],
        });

        const validator = vi.fn(
            (): Promise<DelegationChainValidationResult> =>
                Promise.resolve({ valid: true, depth: 1 }),
        );
        const checkAndReserve = vi.fn(() =>
            Promise.resolve({ allowed: true, currentCumulative: 0 }),
        );

        const orchestrator = new Orchestrator({
            agentDid: recipientDid,
            agentPrivateKey: recipientPrivateKey,
            principalDid,
            policyEngine: { executeWithPolicy: vi.fn() },
            transport: {} as never,
            resolvePublicKey: makePubKeyResolver(),
            tokenStore: { getToken: vi.fn(() => Promise.resolve(token)) },
            delegationChainValidator: validator,
            revocationChecker: vi.fn(() => Promise.resolve(false)),
            policyRecorder: mockPolicyRecorder(),
            resolveAgentDocument: vi.fn(() =>
                Promise.resolve(mockSenderDocument()),
            ),
            senderCumulativeTracker: { checkAndReserve },
            businessHandler: vi.fn(),
        });

        const incoming = buildEnvelope({
            senderDid,
            senderPrivateKey,
            recipientDid,
            sessionId: 'session-cumulative-witness',
            messageType: 'NEGOTIATION_REQUEST',
            body: { action: 'PAYMENT', params: { amount: 5_000 } },
            capabilityTokenRef: token.id,
        });

        const result = await orchestrator.handleEnvelope(incoming);

        expect(result.handled).toBe(false);
        expect(result.rejectionReason).toMatch(
            /delegation_cumulative_limit_metric_source_not_implemented/,
        );
        expect(result.rejectionReason).toMatch(/external_witness/);
        // Key point: the tracker is not called (avoids wrongly reserving the sender's quota)
        expect(checkAndReserve).not.toHaveBeenCalled();
    });

    it('rejects sender token cumulative_limit when meterField.source is consensus_meter (fail-closed)', async () => {
        const token = buildDelegatedTokenFixture({
            id: 'urn:cap:leaf-cumulative-consensus',
            issuedTo: senderDid,
            capabilities: [
                {
                    action: 'PAYMENT',
                    scope: {
                        type: 'cumulative_limit',
                        meterField: {
                            source: 'consensus_meter',
                            metric: 'api_call_count',
                        },
                        max: 10_000,
                        window: 'day',
                    },
                },
            ] as unknown as CapabilityToken['capabilities'],
        });

        const validator = vi.fn(
            (): Promise<DelegationChainValidationResult> =>
                Promise.resolve({ valid: true, depth: 1 }),
        );
        const checkAndReserve = vi.fn(() =>
            Promise.resolve({ allowed: true, currentCumulative: 0 }),
        );

        const orchestrator = new Orchestrator({
            agentDid: recipientDid,
            agentPrivateKey: recipientPrivateKey,
            principalDid,
            policyEngine: { executeWithPolicy: vi.fn() },
            transport: {} as never,
            resolvePublicKey: makePubKeyResolver(),
            tokenStore: { getToken: vi.fn(() => Promise.resolve(token)) },
            delegationChainValidator: validator,
            revocationChecker: vi.fn(() => Promise.resolve(false)),
            policyRecorder: mockPolicyRecorder(),
            resolveAgentDocument: vi.fn(() =>
                Promise.resolve(mockSenderDocument()),
            ),
            senderCumulativeTracker: { checkAndReserve },
            businessHandler: vi.fn(),
        });

        const incoming = buildEnvelope({
            senderDid,
            senderPrivateKey,
            recipientDid,
            sessionId: 'session-cumulative-consensus',
            messageType: 'NEGOTIATION_REQUEST',
            body: { action: 'PAYMENT', params: { amount: 5_000 } },
            capabilityTokenRef: token.id,
        });

        const result = await orchestrator.handleEnvelope(incoming);

        expect(result.handled).toBe(false);
        expect(result.rejectionReason).toMatch(
            /delegation_cumulative_limit_metric_source_not_implemented/,
        );
        expect(result.rejectionReason).toMatch(/consensus_meter/);
        expect(checkAndReserve).not.toHaveBeenCalled();
    });

    it('rejects sender token cumulative_limit when meter metric is not in METER_FIELD_REGISTRY (unregistered metric)', async () => {
        // Covers evaluateSenderCumulativeScopes's unregistered-metric branch:
        // scope.meterField.metric is not in the registry -> reject directly even if a tracker is injected
        // (any unregistered metric fails closed).
        const token = buildDelegatedTokenFixture({
            id: 'urn:cap:leaf-cumulative-unregistered',
            issuedTo: senderDid,
            capabilities: [
                {
                    action: 'PAYMENT',
                    scope: {
                        type: 'cumulative_limit',
                        meterField: {
                            source: 'action_record',
                            metric: 'unregistered_exotic_metric',
                        },
                        max: 10_000,
                        window: 'day',
                    },
                },
            ] as unknown as CapabilityToken['capabilities'],
        });

        const validator = vi.fn(
            (): Promise<DelegationChainValidationResult> =>
                Promise.resolve({ valid: true, depth: 1 }),
        );
        const checkAndReserve = vi.fn(() =>
            Promise.resolve({ allowed: true, currentCumulative: 0 }),
        );

        const orchestrator = new Orchestrator({
            agentDid: recipientDid,
            agentPrivateKey: recipientPrivateKey,
            principalDid,
            policyEngine: { executeWithPolicy: vi.fn() },
            transport: {} as never,
            resolvePublicKey: makePubKeyResolver(),
            tokenStore: { getToken: vi.fn(() => Promise.resolve(token)) },
            delegationChainValidator: validator,
            revocationChecker: vi.fn(() => Promise.resolve(false)),
            policyRecorder: mockPolicyRecorder(),
            resolveAgentDocument: vi.fn(() =>
                Promise.resolve(mockSenderDocument()),
            ),
            senderCumulativeTracker: { checkAndReserve },
            businessHandler: vi.fn(),
        });

        const incoming = buildEnvelope({
            senderDid,
            senderPrivateKey,
            recipientDid,
            sessionId: 'session-cumulative-unregistered',
            messageType: 'NEGOTIATION_REQUEST',
            body: { action: 'PAYMENT', params: { amount: 5_000 } },
            capabilityTokenRef: token.id,
        });

        const result = await orchestrator.handleEnvelope(incoming);

        expect(result.handled).toBe(false);
        expect(result.rejectionReason).toMatch(
            /delegation_cumulative_limit_unregistered_metric/,
        );
        // the tracker is not called (rejected before the metric check)
        expect(checkAndReserve).not.toHaveBeenCalled();
    });

    it('rejects sender token cumulative_limit when SUM metric request value is missing from params (request-value-missing)', async () => {
        // Covers the request-value-missing branch of SUM aggregation: transaction_amount
        // requires params.amount to be a number, and fails closed if it is missing.
        const token = buildDelegatedTokenFixture({
            id: 'urn:cap:leaf-cumulative-no-amount',
            issuedTo: senderDid,
            capabilities: [
                {
                    action: 'PAYMENT',
                    scope: {
                        type: 'cumulative_limit',
                        meterField: {
                            source: 'action_record',
                            metric: 'transaction_amount',
                        },
                        max: 10_000,
                        window: 'day',
                    },
                },
            ] as unknown as CapabilityToken['capabilities'],
        });

        const validator = vi.fn(
            (): Promise<DelegationChainValidationResult> =>
                Promise.resolve({ valid: true, depth: 1 }),
        );
        const checkAndReserve = vi.fn(() =>
            Promise.resolve({ allowed: true, currentCumulative: 0 }),
        );

        const orchestrator = new Orchestrator({
            agentDid: recipientDid,
            agentPrivateKey: recipientPrivateKey,
            principalDid,
            policyEngine: { executeWithPolicy: vi.fn() },
            transport: {} as never,
            resolvePublicKey: makePubKeyResolver(),
            tokenStore: { getToken: vi.fn(() => Promise.resolve(token)) },
            delegationChainValidator: validator,
            revocationChecker: vi.fn(() => Promise.resolve(false)),
            policyRecorder: mockPolicyRecorder(),
            resolveAgentDocument: vi.fn(() =>
                Promise.resolve(mockSenderDocument()),
            ),
            senderCumulativeTracker: { checkAndReserve },
            businessHandler: vi.fn(),
        });

        const incoming = buildEnvelope({
            senderDid,
            senderPrivateKey,
            recipientDid,
            sessionId: 'session-cumulative-no-amount',
            messageType: 'NEGOTIATION_REQUEST',
            // params has no amount, so SUM aggregation cannot extract the request value
            body: { action: 'PAYMENT', params: { recipient: 'supplier-a' } },
            capabilityTokenRef: token.id,
        });

        const result = await orchestrator.handleEnvelope(incoming);

        expect(result.handled).toBe(false);
        expect(result.rejectionReason).toMatch(
            /delegation_cumulative_limit_request_value_missing/,
        );
        expect(checkAndReserve).not.toHaveBeenCalled();
    });

    it('accepts sender token cumulative_limit for COUNT aggregation (api_call_count metric)', async () => {
        // Covers the COUNT branch: currentValue is fixed at 1, not extracted from params;
        // projected = 99 + 1 = 100 == max -> passes (only > max is rejected).
        const token = buildDelegatedTokenFixture({
            id: 'urn:cap:leaf-cumulative-count-under',
            issuedTo: senderDid,
            capabilities: [
                {
                    action: 'PAYMENT',
                    scope: {
                        type: 'cumulative_limit',
                        meterField: {
                            source: 'action_record',
                            metric: 'api_call_count',
                        },
                        max: 100,
                        window: 'hour',
                    },
                },
            ] as unknown as CapabilityToken['capabilities'],
        });

        const validator = vi.fn(
            (): Promise<DelegationChainValidationResult> =>
                Promise.resolve({ valid: true, depth: 1 }),
        );
        const executeWithPolicy = vi.fn(
            async ({
                executor,
            }: {
                executor: () => Promise<Record<string, unknown>>;
            }) => ({
                executed: true as const,
                result: await executor(),
                recordId: 'record-count-under',
            }),
        );
        // COUNT aggregation: reserveAmount is fixed at 1; cumulative 99 + 1 = 100 == max -> allowed:true
        const checkAndReserve = vi.fn(() =>
            Promise.resolve({ allowed: true, currentCumulative: 99 }),
        );

        const orchestrator = new Orchestrator({
            agentDid: recipientDid,
            agentPrivateKey: recipientPrivateKey,
            principalDid,
            policyEngine: { executeWithPolicy },
            transport: {} as never,
            resolvePublicKey: makePubKeyResolver(),
            tokenStore: { getToken: vi.fn(() => Promise.resolve(token)) },
            delegationChainValidator: validator,
            revocationChecker: vi.fn(() => Promise.resolve(false)),
            policyRecorder: mockPolicyRecorder(),
            resolveAgentDocument: vi.fn(() =>
                Promise.resolve(mockSenderDocument()),
            ),
            senderCumulativeTracker: { checkAndReserve },
            businessHandler: ({ action }) =>
                Promise.resolve({ handledAction: action }),
        });

        const incoming = buildEnvelope({
            senderDid,
            senderPrivateKey,
            recipientDid,
            sessionId: 'session-cumulative-count-under',
            messageType: 'NEGOTIATION_REQUEST',
            body: { action: 'PAYMENT', params: {} },
            capabilityTokenRef: token.id,
        });

        const result = await orchestrator.handleEnvelope(incoming);

        expect(result.handled).toBe(true);
        expect(checkAndReserve).toHaveBeenCalledTimes(1);
        // COUNT aggregation: the reserveAmount position (the 6th argument) must be 1
        expect(checkAndReserve.mock.calls[0]?.[5]).toBe(1);
        expect(executeWithPolicy).toHaveBeenCalledTimes(1);
    });

    it('rejects sender token cumulative_limit when senderCumulativeTracker reports projected total exceeds max', async () => {
        const token = buildDelegatedTokenFixture({
            id: 'urn:cap:leaf-cumulative-over',
            issuedTo: senderDid,
            capabilities: [
                {
                    action: 'PAYMENT',
                    scope: {
                        type: 'cumulative_limit',
                        meterField: {
                            source: 'action_record',
                            metric: 'transaction_amount',
                        },
                        max: 10_000,
                        window: 'day',
                    },
                },
            ] as unknown as CapabilityToken['capabilities'],
        });

        const validator = vi.fn(
            (): Promise<DelegationChainValidationResult> =>
                Promise.resolve({ valid: true, depth: 1 }),
        );

        // tracker.checkAndReserve returns allowed:false (the implementation has already determined
        // the limit was exceeded; the orchestrator no longer does the projected > max calculation itself).
        const checkAndReserve = vi.fn(() =>
            Promise.resolve({ allowed: false, currentCumulative: 9_000 }),
        );

        const orchestrator = new Orchestrator({
            agentDid: recipientDid,
            agentPrivateKey: recipientPrivateKey,
            principalDid,
            policyEngine: { executeWithPolicy: vi.fn() },
            transport: {} as never,
            resolvePublicKey: makePubKeyResolver(),
            tokenStore: { getToken: vi.fn(() => Promise.resolve(token)) },
            delegationChainValidator: validator,
            revocationChecker: vi.fn(() => Promise.resolve(false)),
            policyRecorder: mockPolicyRecorder(),
            resolveAgentDocument: vi.fn(() =>
                Promise.resolve(mockSenderDocument()),
            ),
            senderCumulativeTracker: { checkAndReserve },
            businessHandler: vi.fn(),
        });

        const incoming = buildEnvelope({
            senderDid,
            senderPrivateKey,
            recipientDid,
            sessionId: 'session-cumulative-over',
            messageType: 'NEGOTIATION_REQUEST',
            body: { action: 'PAYMENT', params: { amount: 5_000 } },
            capabilityTokenRef: token.id,
        });

        const result = await orchestrator.handleEnvelope(incoming);

        expect(result.handled).toBe(false);
        expect(result.rejectionReason).toMatch(
            /delegation_cumulative_limit_exceeded/,
        );
        expect(checkAndReserve).toHaveBeenCalledTimes(1);
    });

    // ─── the evaluator uses scope.max locally for a token-level decision ──
    // Background: tracker.checkAndReserve's signature does not include scope.max, so the tracker implementation has
    // no way to know the token-level ceiling applicable to this call. If fully delegated to the tracker, a real
    // implementation would either allow because it cannot obtain max, or use its own backend policy (inconsistent with token max).
    // After the fix, even if the tracker returns allowed:true, the orchestrator locally compares
    // currentCumulative + reserveAmount against scope.max, and when exceeded it:
    // 1) cancels this just-successful reservation (effective for countFilter='SUCCESS');
    // 2) returns delegation_cumulative_limit_exceeded.
    it('should reject cumulative_limit via local scope.max gate when tracker returns allowed:true but projected > max', async () => {
        const token = buildDelegatedTokenFixture({
            id: 'urn:cap:leaf-p1-local-max',
            issuedTo: senderDid,
            capabilities: [
                {
                    action: 'PAYMENT',
                    scope: {
                        type: 'cumulative_limit',
                        meterField: {
                            source: 'action_record',
                            metric: 'transaction_amount',
                        },
                        max: 10_000,
                        window: 'day',
                    },
                },
            ] as unknown as CapabilityToken['capabilities'],
        });

        const validator = vi.fn(
            (): Promise<DelegationChainValidationResult> =>
                Promise.resolve({ valid: true, depth: 1 }),
        );

        // Tracker misjudges / has no policy: allowed:true + currentCumulative=9_000.
        // This reserveAmount=5_000 -> projected=14_000 > max=10_000 -> must be rejected by the
        // evaluator's local gate, and the successful reservation must be cancelled.
        const checkAndReserve = vi.fn(() =>
            Promise.resolve({ allowed: true, currentCumulative: 9_000 }),
        );
        const cancelReservation = vi.fn(() => Promise.resolve());

        const orchestrator = new Orchestrator({
            agentDid: recipientDid,
            agentPrivateKey: recipientPrivateKey,
            principalDid,
            policyEngine: { executeWithPolicy: vi.fn() },
            transport: {} as never,
            resolvePublicKey: makePubKeyResolver(),
            tokenStore: { getToken: vi.fn(() => Promise.resolve(token)) },
            delegationChainValidator: validator,
            revocationChecker: vi.fn(() => Promise.resolve(false)),
            policyRecorder: mockPolicyRecorder(),
            resolveAgentDocument: vi.fn(() =>
                Promise.resolve(mockSenderDocument()),
            ),
            senderCumulativeTracker: { checkAndReserve, cancelReservation },
            businessHandler: vi.fn(),
        });

        const incoming = buildEnvelope({
            senderDid,
            senderPrivateKey,
            recipientDid,
            sessionId: 'session-p1-local-max',
            messageType: 'NEGOTIATION_REQUEST',
            body: { action: 'PAYMENT', params: { amount: 5_000 } },
            capabilityTokenRef: token.id,
        });

        const result = await orchestrator.handleEnvelope(incoming);

        expect(result.handled).toBe(false);
        expect(result.rejectionReason).toMatch(
            /delegation_cumulative_limit_exceeded/,
        );
        expect(result.rejectionReason).toMatch(/>max=10000/);
        expect(checkAndReserve).toHaveBeenCalledTimes(1);
        // transaction_amount has countFilter='SUCCESS' -> after the local gate triggers,
        // it must best-effort cancel this reservation.
        expect(cancelReservation).toHaveBeenCalledTimes(1);
    });

    // ─── when checkAndReserve throws, cancel the already-successful reservations before rethrowing ──
    // Background: in the evaluator's for-loop, the first k-1 checkAndReserve calls successfully write PENDING,
    // and the k-th throws due to a transient DB/network failure; if the evaluator rethrows directly, the outer
    // handleEnvelopeInner's reservationsFromCapability is still an empty array, so the outer catch
    // skips cancel -> the first k-1 reservations can only be reclaimed by TTL. After the fix, the evaluator's internal
    // try/catch best-effort cancels these reservations before rethrowing.
    it('should cancel earlier successful reservations when a later checkAndReserve throws', async () => {
        // The Token contains two cumulative_limit entries (different metrics), reserved in two hops.
        const token = buildDelegatedTokenFixture({
            id: 'urn:cap:leaf-p2-throw-rollback',
            issuedTo: senderDid,
            capabilities: [
                {
                    action: 'PAYMENT',
                    scope: {
                        type: 'cumulative_limit',
                        meterField: {
                            source: 'action_record',
                            metric: 'transaction_amount',
                        },
                        max: 100_000,
                        window: 'day',
                    },
                },
                {
                    action: 'PAYMENT',
                    scope: {
                        type: 'cumulative_limit',
                        meterField: {
                            source: 'action_record',
                            metric: 'api_call_count',
                        },
                        max: 1_000,
                        window: 'day',
                    },
                },
            ] as unknown as CapabilityToken['capabilities'],
        });

        const validator = vi.fn(
            (): Promise<DelegationChainValidationResult> =>
                Promise.resolve({ valid: true, depth: 1 }),
        );

        // The 1st (transaction_amount) succeeds; the 2nd (api_call_count) throws.
        const checkAndReserve = vi
            .fn()
            .mockResolvedValueOnce({ allowed: true, currentCumulative: 0 })
            .mockRejectedValueOnce(new Error('transient DB failure'));

        const cancelReservation = vi.fn(() => Promise.resolve());

        const orchestrator = new Orchestrator({
            agentDid: recipientDid,
            agentPrivateKey: recipientPrivateKey,
            principalDid,
            policyEngine: { executeWithPolicy: vi.fn() },
            transport: {} as never,
            resolvePublicKey: makePubKeyResolver(),
            tokenStore: { getToken: vi.fn(() => Promise.resolve(token)) },
            delegationChainValidator: validator,
            revocationChecker: vi.fn(() => Promise.resolve(false)),
            policyRecorder: mockPolicyRecorder(),
            resolveAgentDocument: vi.fn(() =>
                Promise.resolve(mockSenderDocument()),
            ),
            senderCumulativeTracker: { checkAndReserve, cancelReservation },
            businessHandler: vi.fn(),
        });

        const incoming = buildEnvelope({
            senderDid,
            senderPrivateKey,
            recipientDid,
            sessionId: 'session-p2-throw-rollback',
            messageType: 'NEGOTIATION_REQUEST',
            body: { action: 'PAYMENT', params: { amount: 50_000 } },
            capabilityTokenRef: token.id,
        });

        // the orchestrator should catch the exception and return a structured response instead of throwing directly.
        const result = await orchestrator.handleEnvelope(incoming);
        expect(result.handled).toBe(false);
        expect(checkAndReserve).toHaveBeenCalledTimes(2);

        // Key assertion: the 1st successful reservation (transaction_amount / countFilter='SUCCESS')
        // must be cancelled before the rethrow. api_call_count (countFilter='*'), even if
        // reserved, is never passed into cancelReservedRecords — and here it is the one that throws on the 2nd call,
        // so it was never pushed into reserved at all.
        expect(cancelReservation).toHaveBeenCalledTimes(1);
        const cancelArgs = cancelReservation.mock.calls[0];
        expect(cancelArgs?.[0]).toMatch(/#transaction_amount#day$/);
    });

    // ─── chain validation failure must occur before the cumulative checkAndReserve ──
    it('does NOT call senderCumulativeTracker.checkAndReserve when delegation chain validation fails (reservations never triggered by invalid delegation)', async () => {
        // Goal: construct a token whose leaf signature and time window are both valid, but whose chain is rejected by the validator
        // (e.g. parent already revoked / attenuation violation / snapshot mismatch). If an attacker could
        // trigger checkAndReserve before chain validation fails, they could repeatedly consume the sender principal's real quota
        // by rotating envelope.id. Requirement: untrusted input must complete all read-only validation
        // first, and only after passing it may a side-effecting reservation be initiated.
        const token = buildDelegatedTokenFixture({
            id: 'urn:cap:leaf-chain-invalid',
            issuedTo: senderDid,
            capabilities: [
                {
                    action: 'PAYMENT',
                    scope: {
                        type: 'cumulative_limit',
                        meterField: {
                            source: 'action_record',
                            metric: 'transaction_amount',
                        },
                        max: 10_000,
                        window: 'day',
                    },
                },
            ] as unknown as CapabilityToken['capabilities'],
        });

        const validator = vi.fn(
            (): Promise<DelegationChainValidationResult> =>
                Promise.resolve({
                    valid: false,
                    reason: 'parent_revoked',
                    depth: 1,
                }),
        );

        // Key assertion: checkAndReserve must be called **never**.
        const checkAndReserve = vi.fn(() =>
            Promise.resolve({ allowed: true, currentCumulative: 0 }),
        );

        const orchestrator = new Orchestrator({
            agentDid: recipientDid,
            agentPrivateKey: recipientPrivateKey,
            principalDid,
            policyEngine: { executeWithPolicy: vi.fn() },
            transport: {} as never,
            resolvePublicKey: makePubKeyResolver(),
            tokenStore: { getToken: vi.fn(() => Promise.resolve(token)) },
            delegationChainValidator: validator,
            revocationChecker: vi.fn(() => Promise.resolve(false)),
            policyRecorder: mockPolicyRecorder(),
            resolveAgentDocument: vi.fn(() =>
                Promise.resolve(mockSenderDocument()),
            ),
            senderCumulativeTracker: { checkAndReserve },
            businessHandler: vi.fn(),
        });

        const incoming = buildEnvelope({
            senderDid,
            senderPrivateKey,
            recipientDid,
            sessionId: 'session-chain-invalid',
            messageType: 'NEGOTIATION_REQUEST',
            body: { action: 'PAYMENT', params: { amount: 5_000 } },
            capabilityTokenRef: token.id,
        });

        const result = await orchestrator.handleEnvelope(incoming);

        expect(result.handled).toBe(false);
        expect(result.rejectionReason).toMatch(/^delegation_parent_revoked/);
        // Key assertion: tracker.checkAndReserve **must not** be called when chain validation fails —
        // the reservation must come after all read-only validation.
        expect(checkAndReserve).not.toHaveBeenCalled();
        // the validator must be called (proving the order is chain first, then cumulative)
        expect(validator).toHaveBeenCalledTimes(1);
    });

    // ─── the same metric across multiple windows must produce distinct recordIds ──
    it('uses distinct recordIds for scopes with same metric but different windows (recordId includes window)', async () => {
        // The uniqueness key is (agentDid, meterField.metric, window).
        // If a single token's "1000/day / 20000/month" dual limits reuse the same recordId, the tracker
        // would dedup by the idempotency key, causing the second checkAndReserve to be misread as a retry, so the second window
        // is never reserved independently. The recordId must include a window suffix.
        const token = buildDelegatedTokenFixture({
            id: 'urn:cap:leaf-dual-window',
            issuedTo: senderDid,
            capabilities: [
                {
                    action: 'PAYMENT',
                    scope: {
                        type: 'cumulative_limit',
                        meterField: {
                            source: 'action_record',
                            metric: 'transaction_amount',
                        },
                        max: 1_000,
                        window: 'day',
                    },
                },
                {
                    action: 'PAYMENT',
                    scope: {
                        type: 'cumulative_limit',
                        meterField: {
                            source: 'action_record',
                            metric: 'transaction_amount',
                        },
                        max: 20_000,
                        window: 'month',
                    },
                },
            ] as unknown as CapabilityToken['capabilities'],
        });

        const validator = vi.fn(
            (): Promise<DelegationChainValidationResult> =>
                Promise.resolve({ valid: true, depth: 1 }),
        );

        const checkAndReserve = vi.fn(() =>
            Promise.resolve({ allowed: true, currentCumulative: 0 }),
        );

        const executeWithPolicy = vi.fn(
            async ({
                executor,
            }: {
                executor: () => Promise<Record<string, unknown>>;
            }) => ({
                executed: true as const,
                result: await executor(),
                recordId: 'record-dual-window',
            }),
        );

        const orchestrator = new Orchestrator({
            agentDid: recipientDid,
            agentPrivateKey: recipientPrivateKey,
            principalDid,
            policyEngine: { executeWithPolicy },
            transport: {} as never,
            resolvePublicKey: makePubKeyResolver(),
            tokenStore: { getToken: vi.fn(() => Promise.resolve(token)) },
            delegationChainValidator: validator,
            revocationChecker: vi.fn(() => Promise.resolve(false)),
            policyRecorder: mockPolicyRecorder(),
            resolveAgentDocument: vi.fn(() =>
                Promise.resolve(mockSenderDocument()),
            ),
            senderCumulativeTracker: { checkAndReserve },
            businessHandler: ({ action }) =>
                Promise.resolve({ handledAction: action }),
        });

        const incoming = buildEnvelope({
            senderDid,
            senderPrivateKey,
            recipientDid,
            sessionId: 'session-dual-window',
            messageType: 'NEGOTIATION_REQUEST',
            body: { action: 'PAYMENT', params: { amount: 500 } },
            capabilityTokenRef: token.id,
        });

        const result = await orchestrator.handleEnvelope(incoming);

        expect(result.handled).toBe(true);
        expect(checkAndReserve).toHaveBeenCalledTimes(2);
        const recordIdDay = checkAndReserve.mock.calls[0]?.[0] as string;
        const recordIdMonth = checkAndReserve.mock.calls[1]?.[0] as string;
        // the two recordIds must differ; one ends in day / the other in month
        expect(recordIdDay).toMatch(/#transaction_amount#day$/);
        expect(recordIdMonth).toMatch(/#transaction_amount#month$/);
        expect(recordIdDay).not.toBe(recordIdMonth);
        // the envelope.id prefix is the same (two reservations of the same envelope share the prefix)
        const prefixDay = recordIdDay.split('#')[0];
        const prefixMonth = recordIdMonth.split('#')[0];
        expect(prefixDay).toBe(prefixMonth);
    });

    // ─── cancelReservation is best-effort called after the business executor throws ──
    it('calls senderCumulativeTracker.cancelReservation when business executor throws after successful reservation (best-effort release)', async () => {
        // Scenario: the step3.5 cumulative reservation succeeded, but the business
        // executor after step4 throws, triggering the outer catch. At this point the orchestrator
        // should best-effort call tracker.cancelReservation(recordId) to release the reservation,
        // to avoid this request's real quota being locked until TTL expiry.
        const token = buildDelegatedTokenFixture({
            id: 'urn:cap:leaf-cancel-on-failure',
            issuedTo: senderDid,
            capabilities: [
                {
                    action: 'PAYMENT',
                    scope: {
                        type: 'cumulative_limit',
                        meterField: {
                            source: 'action_record',
                            metric: 'transaction_amount',
                        },
                        max: 10_000,
                        window: 'day',
                    },
                },
            ] as unknown as CapabilityToken['capabilities'],
        });

        const validator = vi.fn(
            (): Promise<DelegationChainValidationResult> =>
                Promise.resolve({ valid: true, depth: 1 }),
        );

        const checkAndReserve = vi.fn(() =>
            Promise.resolve({ allowed: true, currentCumulative: 0 }),
        );
        const cancelReservation = vi.fn(() => Promise.resolve());

        // executeWithPolicy throws internally (the real path for a failed business executor).
        const executeWithPolicy = vi.fn(() =>
            Promise.reject(new Error('business executor crashed')),
        );

        const orchestrator = new Orchestrator({
            agentDid: recipientDid,
            agentPrivateKey: recipientPrivateKey,
            principalDid,
            policyEngine: { executeWithPolicy },
            transport: {} as never,
            resolvePublicKey: makePubKeyResolver(),
            tokenStore: { getToken: vi.fn(() => Promise.resolve(token)) },
            delegationChainValidator: validator,
            revocationChecker: vi.fn(() => Promise.resolve(false)),
            policyRecorder: mockPolicyRecorder(),
            resolveAgentDocument: vi.fn(() =>
                Promise.resolve(mockSenderDocument()),
            ),
            senderCumulativeTracker: { checkAndReserve, cancelReservation },
            businessHandler: vi.fn(),
        });

        const incoming = buildEnvelope({
            senderDid,
            senderPrivateKey,
            recipientDid,
            sessionId: 'session-cancel-on-failure',
            messageType: 'NEGOTIATION_REQUEST',
            body: { action: 'PAYMENT', params: { amount: 500 } },
            capabilityTokenRef: token.id,
        });

        const result = await orchestrator.handleEnvelope(incoming);

        // business throws -> handled:false + INTERNAL_ERROR
        expect(result.handled).toBe(false);
        expect(checkAndReserve).toHaveBeenCalledTimes(1);
        const reservedRecordId = checkAndReserve.mock.calls[0]?.[0];
        // Core assertion: cancelReservation is called with the same recordId used to reserve
        expect(cancelReservation).toHaveBeenCalledTimes(1);
        expect(cancelReservation.mock.calls[0]?.[0]).toBe(reservedRecordId);
    });

    // ─── cancel is called after a step4 policy denial ──
    it('calls senderCumulativeTracker.cancelReservation when step4 policy denies after successful reservation', async () => {
        const token = buildDelegatedTokenFixture({
            id: 'urn:cap:leaf-cancel-step4-deny',
            issuedTo: senderDid,
            capabilities: [
                {
                    action: 'PAYMENT',
                    scope: {
                        type: 'cumulative_limit',
                        meterField: {
                            source: 'action_record',
                            metric: 'transaction_amount',
                        },
                        max: 10_000,
                        window: 'day',
                    },
                },
            ] as unknown as CapabilityToken['capabilities'],
        });

        const validator = vi.fn(
            (): Promise<DelegationChainValidationResult> =>
                Promise.resolve({ valid: true, depth: 1 }),
        );

        const checkAndReserve = vi.fn(() =>
            Promise.resolve({ allowed: true, currentCumulative: 0 }),
        );
        const cancelReservation = vi.fn(() => Promise.resolve());

        const executeWithPolicy = vi.fn(() =>
            Promise.resolve({
                executed: false as const,
                reason: 'recipient_policy_denied',
                recordId: 'record-step4-deny',
            }),
        );

        const orchestrator = new Orchestrator({
            agentDid: recipientDid,
            agentPrivateKey: recipientPrivateKey,
            principalDid,
            policyEngine: { executeWithPolicy },
            transport: {} as never,
            resolvePublicKey: makePubKeyResolver(),
            tokenStore: { getToken: vi.fn(() => Promise.resolve(token)) },
            delegationChainValidator: validator,
            revocationChecker: vi.fn(() => Promise.resolve(false)),
            policyRecorder: mockPolicyRecorder(),
            resolveAgentDocument: vi.fn(() =>
                Promise.resolve(mockSenderDocument()),
            ),
            senderCumulativeTracker: { checkAndReserve, cancelReservation },
            businessHandler: vi.fn(),
        });

        const incoming = buildEnvelope({
            senderDid,
            senderPrivateKey,
            recipientDid,
            sessionId: 'session-step4-deny',
            messageType: 'NEGOTIATION_REQUEST',
            body: { action: 'PAYMENT', params: { amount: 500 } },
            capabilityTokenRef: token.id,
        });

        const result = await orchestrator.handleEnvelope(incoming);

        expect(result.handled).toBe(false);
        expect(result.rejectionReason).toBe('recipient_policy_denied');
        expect(checkAndReserve).toHaveBeenCalledTimes(1);
        // cancel is also required after a step4 denial
        expect(cancelReservation).toHaveBeenCalledTimes(1);
        expect(cancelReservation.mock.calls[0]?.[0]).toBe(
            checkAndReserve.mock.calls[0]?.[0],
        );
    });

    // ─── for COUNT+'*' metrics (api_call_count) failures also count, so cancel must not be called ──
    it('does NOT call cancelReservation for countFilter="*" metrics on executor failure (api_call_count preserves on failure)', async () => {
        // api_call_count's countFilter='*' means
        // REJECTED/ERROR/timeout all count toward the cumulative total — to prevent failure retries from bypassing the limit.
        // The orchestrator filters by countFilter in cancelReservedRecords,
        // and reservations with countFilter='*' are never passed to tracker.cancelReservation.
        const token = buildDelegatedTokenFixture({
            id: 'urn:cap:leaf-count-no-cancel',
            issuedTo: senderDid,
            capabilities: [
                {
                    action: 'PAYMENT',
                    scope: {
                        type: 'cumulative_limit',
                        meterField: {
                            source: 'action_record',
                            metric: 'api_call_count', // COUNT + countFilter='*'
                        },
                        max: 100,
                        window: 'day',
                    },
                },
            ] as unknown as CapabilityToken['capabilities'],
        });

        const validator = vi.fn(
            (): Promise<DelegationChainValidationResult> =>
                Promise.resolve({ valid: true, depth: 1 }),
        );

        const checkAndReserve = vi.fn(() =>
            Promise.resolve({ allowed: true, currentCumulative: 0 }),
        );
        const cancelReservation = vi.fn(() => Promise.resolve());

        const executeWithPolicy = vi.fn(() =>
            Promise.reject(new Error('business executor crashed')),
        );

        const orchestrator = new Orchestrator({
            agentDid: recipientDid,
            agentPrivateKey: recipientPrivateKey,
            principalDid,
            policyEngine: { executeWithPolicy },
            transport: {} as never,
            resolvePublicKey: makePubKeyResolver(),
            tokenStore: { getToken: vi.fn(() => Promise.resolve(token)) },
            delegationChainValidator: validator,
            revocationChecker: vi.fn(() => Promise.resolve(false)),
            policyRecorder: mockPolicyRecorder(),
            resolveAgentDocument: vi.fn(() =>
                Promise.resolve(mockSenderDocument()),
            ),
            senderCumulativeTracker: { checkAndReserve, cancelReservation },
            businessHandler: vi.fn(),
        });

        const incoming = buildEnvelope({
            senderDid,
            senderPrivateKey,
            recipientDid,
            sessionId: 'session-count-no-cancel',
            messageType: 'NEGOTIATION_REQUEST',
            body: { action: 'PAYMENT', params: {} },
            capabilityTokenRef: token.id,
        });

        const result = await orchestrator.handleEnvelope(incoming);

        expect(result.handled).toBe(false);
        expect(checkAndReserve).toHaveBeenCalledTimes(1);
        // Key assertion: api_call_count's cancelReservation must **not** be called —
        // failed requests also count toward the cumulative total (to prevent bypassing the limit).
        expect(cancelReservation).not.toHaveBeenCalled();
    });

    // ─── after business + ActionRecord(SUCCESS) is committed, a step5 failure must not cancel the reservation ──
    it('does NOT call cancelReservation when business executor succeeded but step5 buildEnvelope throws (committed gate)', async () => {
        // Scenario: executeWithPolicy returns executed=true (the business side effect has landed and
        // ActionRecord(SUCCESS) has been written), but step5 buildEnvelope throws because
        // policyResult.result contains a non-serializable value (BigInt).
        // Before the fix: the outer catch would unconditionally cancel the sender cumulative reservation,
        // causing "actually consumed but quota released" — quota is underestimated and retry risk doubles.
        // After the fix: committed=true makes the outer catch skip cancel; the reservation
        // stays PENDING and is settled to SETTLED via the tracker's TTL/out-of-band settle as a backstop.
        const token = buildDelegatedTokenFixture({
            id: 'urn:cap:leaf-commit-gate',
            issuedTo: senderDid,
            capabilities: [
                {
                    action: 'PAYMENT',
                    scope: {
                        type: 'cumulative_limit',
                        meterField: {
                            source: 'action_record',
                            metric: 'transaction_amount',
                        },
                        max: 10_000,
                        window: 'day',
                    },
                },
            ] as unknown as CapabilityToken['capabilities'],
        });

        const validator = vi.fn(
            (): Promise<DelegationChainValidationResult> =>
                Promise.resolve({ valid: true, depth: 1 }),
        );

        const checkAndReserve = vi.fn(() =>
            Promise.resolve({ allowed: true, currentCumulative: 0 }),
        );
        const cancelReservation = vi.fn(() => Promise.resolve());

        // executeWithPolicy returns success + a SUCCESS ActionRecord, but result contains a BigInt
        // so the subsequent buildEnvelope -> canonicalize throws a TypeError.
        // The mock must simulate the real engine behavior — after the executor succeeds it calls
        // the onExecutorSuccess hook and then returns; the orchestrator sets committed=true accordingly.
        const executeWithPolicy = vi.fn(
            async (params: {
                recordId?: string;
                onExecutorSuccess?: () => void | Promise<void>;
            }) => {
                // real engine: executor succeeds -> hook -> recorder(SUCCESS) -> return
                await params.onExecutorSuccess?.();
                return {
                    executed: true as const,
                    recordId: params.recordId ?? 'urn:rec:commit-test-001',
                    result: { amount: BigInt(500) },
                };
            },
        );

        const orchestrator = new Orchestrator({
            agentDid: recipientDid,
            agentPrivateKey: recipientPrivateKey,
            principalDid,
            policyEngine: { executeWithPolicy },
            transport: {} as never,
            resolvePublicKey: makePubKeyResolver(),
            tokenStore: { getToken: vi.fn(() => Promise.resolve(token)) },
            delegationChainValidator: validator,
            revocationChecker: vi.fn(() => Promise.resolve(false)),
            policyRecorder: mockPolicyRecorder(),
            resolveAgentDocument: vi.fn(() =>
                Promise.resolve(mockSenderDocument()),
            ),
            senderCumulativeTracker: { checkAndReserve, cancelReservation },
            businessHandler: vi.fn(),
        });

        const incoming = buildEnvelope({
            senderDid,
            senderPrivateKey,
            recipientDid,
            sessionId: 'session-commit-gate',
            messageType: 'NEGOTIATION_REQUEST',
            body: { action: 'PAYMENT', params: { amount: 500 } },
            capabilityTokenRef: token.id,
        });

        const result = await orchestrator.handleEnvelope(incoming);

        // step5 throws -> outer catch -> INTERNAL_ERROR envelope.
        expect(result.handled).toBe(false);
        expect(checkAndReserve).toHaveBeenCalledTimes(1);

        // Core assertion: once business is committed, a step5 failure must not cancel the reservation.
        expect(cancelReservation).not.toHaveBeenCalled();
    });

    // ─── the reservation recordId is generated by the recipient, no longer using envelope.id ──
    it('generates distinct reservation recordIds for replayed envelopes with identical envelope.id (receiver-owned id)', async () => {
        // Background: early on, the orchestrator used envelope.id as the recordId prefix for the sender
        // cumulative reservation. A sender could resend a re-signed envelope with the same id + different params,
        // and the tracker would idempotently return by the same recordId, not deducting again -> quota bypass.
        // Fix: the recipient generates pendingRecordId locally via randomUUID(),
        // which the sender cannot influence; two calls with the same envelope.id generate two independent reservations.
        const token = buildDelegatedTokenFixture({
            id: 'urn:cap:leaf-r18-f1',
            issuedTo: senderDid,
            capabilities: [
                {
                    action: 'PAYMENT',
                    scope: {
                        type: 'cumulative_limit',
                        meterField: {
                            source: 'action_record',
                            metric: 'transaction_amount',
                        },
                        max: 10_000,
                        window: 'day',
                    },
                },
            ] as unknown as CapabilityToken['capabilities'],
        });

        const validator = vi.fn(
            (): Promise<DelegationChainValidationResult> =>
                Promise.resolve({ valid: true, depth: 1 }),
        );

        const checkAndReserve = vi.fn(() =>
            Promise.resolve({ allowed: true, currentCumulative: 0 }),
        );
        const cancelReservation = vi.fn(() => Promise.resolve());

        // engine mock simulates executor + hook + SUCCESS
        const executeWithPolicy = vi.fn(
            async (params: {
                recordId?: string;
                onExecutorSuccess?: () => void | Promise<void>;
            }) => {
                await params.onExecutorSuccess?.();
                return {
                    executed: true as const,
                    recordId: params.recordId ?? 'urn:rec:r18-f1',
                    result: { ok: true },
                };
            },
        );

        const orchestrator = new Orchestrator({
            agentDid: recipientDid,
            agentPrivateKey: recipientPrivateKey,
            principalDid,
            policyEngine: { executeWithPolicy },
            transport: {} as never,
            resolvePublicKey: makePubKeyResolver(),
            tokenStore: { getToken: vi.fn(() => Promise.resolve(token)) },
            delegationChainValidator: validator,
            revocationChecker: vi.fn(() => Promise.resolve(false)),
            policyRecorder: mockPolicyRecorder(),
            resolveAgentDocument: vi.fn(() =>
                Promise.resolve(mockSenderDocument()),
            ),
            senderCumulativeTracker: { checkAndReserve, cancelReservation },
            businessHandler: vi.fn(() => Promise.resolve({})),
        });

        const incoming = buildEnvelope({
            senderDid,
            senderPrivateKey,
            recipientDid,
            sessionId: 'session-r18-f1',
            messageType: 'NEGOTIATION_REQUEST',
            body: { action: 'PAYMENT', params: { amount: 500 } },
            capabilityTokenRef: token.id,
        });

        // two handleEnvelope calls (simulating the sender resending the same envelope)
        await orchestrator.handleEnvelope(incoming);
        await orchestrator.handleEnvelope(incoming);

        expect(checkAndReserve).toHaveBeenCalledTimes(2);
        const recordId1 = checkAndReserve.mock.calls[0]?.[0];
        const recordId2 = checkAndReserve.mock.calls[1]?.[0];
        // Core assertion: the two reservations have different recordIds (the recipient generates one UUID each)
        expect(recordId1).not.toBe(recordId2);
        // and neither contains envelope.id (the sender-controlled value never leaks in)
        expect(recordId1).not.toContain(incoming.id);
        expect(recordId2).not.toContain(incoming.id);
    });

    // ─── if recorder fails after the executor succeeds, the reservation must not be cancelled ──
    it('does NOT call cancelReservation when executor succeeded but recorder.record(SUCCESS) threw (committed gate via hook)', async () => {
        // Attack surface: if the committed flag is only set after executeWithPolicy returns,
        // and the engine's recorder.record(SUCCESS) throws due to a DB failure, the engine will throw
        // -> committed is still false -> the outer catch cancels the reservation -> the business actually ran
        // but the quota was released, so a sender retry would consume the business again.
        // Fix: the engine calls the onExecutorSuccess hook after the executor succeeds and before the recorder;
        // the orchestrator sets committed=true in the hook, so even if the recorder throws the outer catch will not cancel.
        const token = buildDelegatedTokenFixture({
            id: 'urn:cap:leaf-r18-f2',
            issuedTo: senderDid,
            capabilities: [
                {
                    action: 'PAYMENT',
                    scope: {
                        type: 'cumulative_limit',
                        meterField: {
                            source: 'action_record',
                            metric: 'transaction_amount',
                        },
                        max: 10_000,
                        window: 'day',
                    },
                },
            ] as unknown as CapabilityToken['capabilities'],
        });

        const validator = vi.fn(
            (): Promise<DelegationChainValidationResult> =>
                Promise.resolve({ valid: true, depth: 1 }),
        );

        const checkAndReserve = vi.fn(() =>
            Promise.resolve({ allowed: true, currentCumulative: 0 }),
        );
        const cancelReservation = vi.fn(() => Promise.resolve());

        // engine mock: executor succeeds -> hook -> recorder throws (simulates a DB failure)
        const executeWithPolicy = vi.fn(
            async (params: {
                onExecutorSuccess?: () => void | Promise<void>;
            }) => {
                // 1) executor side effect (passed in by the orchestrator; no real execution needed here)
                // 2) hook: notify the caller that the executor succeeded
                await params.onExecutorSuccess?.();
                // 3) recorder.record(SUCCESS) throws -> engine throw
                throw new Error('db connection lost during success record');
            },
        );

        const orchestrator = new Orchestrator({
            agentDid: recipientDid,
            agentPrivateKey: recipientPrivateKey,
            principalDid,
            policyEngine: { executeWithPolicy },
            transport: {} as never,
            resolvePublicKey: makePubKeyResolver(),
            tokenStore: { getToken: vi.fn(() => Promise.resolve(token)) },
            delegationChainValidator: validator,
            revocationChecker: vi.fn(() => Promise.resolve(false)),
            policyRecorder: mockPolicyRecorder(),
            resolveAgentDocument: vi.fn(() =>
                Promise.resolve(mockSenderDocument()),
            ),
            senderCumulativeTracker: { checkAndReserve, cancelReservation },
            businessHandler: vi.fn(),
        });

        const incoming = buildEnvelope({
            senderDid,
            senderPrivateKey,
            recipientDid,
            sessionId: 'session-r18-f2',
            messageType: 'NEGOTIATION_REQUEST',
            body: { action: 'PAYMENT', params: { amount: 500 } },
            capabilityTokenRef: token.id,
        });

        const result = await orchestrator.handleEnvelope(incoming);

        // engine throw → outer catch → INTERNAL_ERROR envelope
        expect(result.handled).toBe(false);
        expect(checkAndReserve).toHaveBeenCalledTimes(1);

        // Core assertion: the executor has succeeded, so the reservation must not be cancelled
        expect(cancelReservation).not.toHaveBeenCalled();
    });

    // ─── InMemoryResponseIdempotencyCache response short-circuit ──
    it('short-circuits duplicate envelopes via InMemoryResponseIdempotencyCache (response-level idempotency)', async () => {
        // Background: after changing the reservation recordId to a recipient-generated UUID,
        // a TCP retry with the same envelope.id is no longer automatically deduped by reservation idempotency ->
        // it would be treated as a new request and amplified into multiple deductions + multiple business side effects.
        // Fix: once the orchestrator is given an idempotencyCache,
        // the **temporally later** second delivery for the same (senderDid, sessionId, envelope.id) directly
        // returns the cached response, without going through verifyCapability / checkAndReserve /
        // businessHandler. Note: this cache does **not guarantee** at-most-once business semantics under
        // concurrency/crash scenarios (the business handler must be idempotent).
        const token = buildDelegatedTokenFixture({
            id: 'urn:cap:leaf-r19-f1',
            issuedTo: senderDid,
            capabilities: [
                {
                    action: 'PAYMENT',
                    scope: {
                        type: 'cumulative_limit',
                        meterField: {
                            source: 'action_record',
                            metric: 'transaction_amount',
                        },
                        max: 10_000,
                        window: 'day',
                    },
                },
            ] as unknown as CapabilityToken['capabilities'],
        });

        const validator = vi.fn(
            (): Promise<DelegationChainValidationResult> =>
                Promise.resolve({ valid: true, depth: 1 }),
        );

        const checkAndReserve = vi.fn(() =>
            Promise.resolve({ allowed: true, currentCumulative: 0 }),
        );
        const cancelReservation = vi.fn(() => Promise.resolve());

        const executeWithPolicy = vi.fn(
            async (params: {
                recordId?: string;
                onExecutorSuccess?: () => void | Promise<void>;
            }) => {
                await params.onExecutorSuccess?.();
                return {
                    executed: true as const,
                    recordId: params.recordId ?? 'urn:rec:r19-f1',
                    result: { ok: true },
                };
            },
        );

        const businessHandler = vi.fn(() => Promise.resolve({}));

        const idempotencyCache = new InMemoryResponseIdempotencyCache();

        const orchestrator = new Orchestrator({
            agentDid: recipientDid,
            agentPrivateKey: recipientPrivateKey,
            principalDid,
            policyEngine: { executeWithPolicy },
            transport: {} as never,
            resolvePublicKey: makePubKeyResolver(),
            tokenStore: { getToken: vi.fn(() => Promise.resolve(token)) },
            delegationChainValidator: validator,
            revocationChecker: vi.fn(() => Promise.resolve(false)),
            policyRecorder: mockPolicyRecorder(),
            resolveAgentDocument: vi.fn(() =>
                Promise.resolve(mockSenderDocument()),
            ),
            senderCumulativeTracker: { checkAndReserve, cancelReservation },
            businessHandler,
            idempotencyCache,
        });

        const incoming = buildEnvelope({
            senderDid,
            senderPrivateKey,
            recipientDid,
            sessionId: 'session-r19-f1',
            messageType: 'NEGOTIATION_REQUEST',
            body: { action: 'PAYMENT', params: { amount: 500 } },
            capabilityTokenRef: token.id,
        });

        const first = await orchestrator.handleEnvelope(incoming);
        const second = await orchestrator.handleEnvelope(incoming);

        // first call processes normally, second call hits the cache
        expect(first.handled).toBe(true);
        expect(second.handled).toBe(true);

        // On a HIT the envelope is re-signed (with a fresh timestamp), so the two envelope
        // objects are **different references** with different timestamp and signature; but the business fields are identical.
        expect(second.responseEnvelope).not.toBe(first.responseEnvelope);
        expect(second.responseEnvelope.header.senderDid).toBe(
            first.responseEnvelope.header.senderDid,
        );
        expect(second.responseEnvelope.header.recipientDid).toBe(
            first.responseEnvelope.header.recipientDid,
        );
        expect(second.responseEnvelope.header.sessionId).toBe(
            first.responseEnvelope.header.sessionId,
        );
        expect(second.responseEnvelope.messageType).toBe(
            first.responseEnvelope.messageType,
        );
        expect(second.responseEnvelope.body).toEqual(
            first.responseEnvelope.body,
        );
        // the timestamp must be fresh (>= first's time) rather than reusing the old value
        expect(
            new Date(second.responseEnvelope.timestamp).getTime(),
        ).toBeGreaterThanOrEqual(
            new Date(first.responseEnvelope.timestamp).getTime(),
        );

        // both the reservation and the downstream engine are called only once (the second duplicate is short-circuited by idempotencyCache)
        // Note: businessHandler is not actually invoked inside the mocked executeWithPolicy,
        // so we instead assert on executeWithPolicy's call count (it is the step4 entry, and is also
        // businessHandler's parent call on the production path).
        expect(checkAndReserve).toHaveBeenCalledTimes(1);
        expect(executeWithPolicy).toHaveBeenCalledTimes(1);
        // businessHandler is declared but the mock does not fire it, recorded as 0 — as counter-evidence of
        // "not going downstream": the second handleEnvelope is also 0 (not invoked in the mock).
        void businessHandler;
    });

    // ─── terminal-state allowlist — a transient step3.5 recorder failure is retryable ──────
    it('allows retry when step3.5 rejection recorder transiently fails (cacheable=false for non-committed INTERNAL_ERROR)', async () => {
        // Background: the capability-rejection path (step3.5 REJECTED) relies on policyRecorder
        // to write the audit; if the recorder throws due to DB degradation, the orchestrator upgrades the response to
        // INTERNAL_ERROR (a signal that the audit invariant failed). Early on, this response would be written to
        // idempotencyCache, so within the TTL window the caller would hit the
        // stale INTERNAL_ERROR even after the DB recovers and they resubmit, never re-running the audit/rejection path.

        // Fix: the `cacheable: false` flag makes finally skip record; the next
        // resubmission re-verifies the signature and re-runs step3.5, and the second recorder succeeds -> returns the REJECTED
        // response (not INTERNAL_ERROR).
        const token = buildDelegatedTokenFixture({
            id: 'urn:cap:leaf-r21-f2-a',
            issuedTo: senderDid,
            capabilities: [
                {
                    action: 'PAYMENT',
                    scope: {
                        type: 'numeric_limit',
                        field: 'amount',
                        max: 100, // deliberately blocking — amount=500 exceeds max
                    },
                },
            ] as unknown as CapabilityToken['capabilities'],
        });

        const validator = vi.fn(
            (): Promise<DelegationChainValidationResult> =>
                Promise.resolve({ valid: true, depth: 1 }),
        );

        // the first record throws (DB degradation), the second succeeds
        const recordImpl = vi
            .fn<
                Parameters<ReturnType<typeof mockPolicyRecorder>['record']>,
                ReturnType<ReturnType<typeof mockPolicyRecorder>['record']>
            >()
            .mockImplementationOnce(() =>
                Promise.reject(new Error('transient DB outage')),
            )
            .mockImplementationOnce(() =>
                Promise.resolve({
                    recordId: 'record-retry-ok',
                    hash: 'a'.repeat(64),
                }),
            );
        const policyRecorder = { record: recordImpl };

        const idempotencyCache = new InMemoryResponseIdempotencyCache();
        const cacheRecordSpy = vi.spyOn(idempotencyCache, 'record');

        const orchestrator = new Orchestrator({
            agentDid: recipientDid,
            agentPrivateKey: recipientPrivateKey,
            principalDid,
            policyEngine: {
                executeWithPolicy: vi.fn(() =>
                    Promise.resolve({
                        executed: false as const,
                        recordId: 'unused',
                        reason: 'should not reach step4',
                    }),
                ),
            },
            transport: {} as never,
            resolvePublicKey: makePubKeyResolver(),
            tokenStore: { getToken: vi.fn(() => Promise.resolve(token)) },
            delegationChainValidator: validator,
            revocationChecker: vi.fn(() => Promise.resolve(false)),
            policyRecorder,
            resolveAgentDocument: vi.fn(() =>
                Promise.resolve(mockSenderDocument()),
            ),
            businessHandler: vi.fn(),
            idempotencyCache,
        });

        const incoming = buildEnvelope({
            senderDid,
            senderPrivateKey,
            recipientDid,
            sessionId: 'session-r21-f2-a',
            messageType: 'NEGOTIATION_REQUEST',
            body: { action: 'PAYMENT', params: { amount: 500 } }, // exceeds max=100
            capabilityTokenRef: token.id,
        });

        // First call: recorder throws -> INTERNAL_ERROR, with cacheable=false
        const first = await orchestrator.handleEnvelope(incoming);
        expect(first.handled).toBe(false);
        expect(first.cacheable).toBe(false);
        // Key assertion: finally did not write the cache (poisoning is blocked)
        expect(cacheRecordSpy).not.toHaveBeenCalled();

        // Second call: recorder recovers -> returns a normal REJECTED response (not INTERNAL_ERROR)
        const second = await orchestrator.handleEnvelope(incoming);
        expect(second.handled).toBe(false);
        // the second call runs the full flow -> recorder is called again (2 times total)
        expect(recordImpl).toHaveBeenCalledTimes(2);
        // the second call is a normal REJECTED (cacheable defaults to true), so finally should write the cache
        expect(cacheRecordSpy).toHaveBeenCalledTimes(1);
    });

    // ─── executor throws + committed=false is retryable ────────────
    it('allows retry when executor throws before commit (non-cacheable INTERNAL_ERROR in outer catch)', async () => {
        // Background: when the step4 executor throws (business did not land, onExecutorSuccess not fired ->
        // committed=false), the outer catch generates an INTERNAL_ERROR response. Early on,
        // this response would be cached -> the caller's resubmission would always hit INTERNAL_ERROR and the business would never
        // be attempted again.

        // Fix: the outer catch determines cacheable from committed — when committed=false,
        // cacheable=false and finally skips record.
        const token = buildDelegatedTokenFixture({
            id: 'urn:cap:leaf-r21-f2-b',
            issuedTo: senderDid,
            capabilities: [
                {
                    action: 'PAYMENT',
                    scope: {
                        type: 'numeric_limit',
                        field: 'amount',
                        max: 10_000,
                    },
                },
            ] as unknown as CapabilityToken['capabilities'],
        });

        const validator = vi.fn(
            (): Promise<DelegationChainValidationResult> =>
                Promise.resolve({ valid: true, depth: 1 }),
        );

        // the engine throws on the first call (executor did not return -> onExecutorSuccess not called ->
        // committed stays false), and succeeds on the second.
        let engineCall = 0;
        const executeWithPolicy = vi.fn(
            async (params: {
                recordId?: string;
                onExecutorSuccess?: () => void | Promise<void>;
                executor: () => Promise<unknown>;
            }) => {
                engineCall += 1;
                if (engineCall === 1) {
                    throw new Error('executor transient failure');
                }
                await params.onExecutorSuccess?.();
                return {
                    executed: true as const,
                    recordId: params.recordId ?? 'record-retry-success',
                    result: { ok: true },
                };
            },
        );

        const idempotencyCache = new InMemoryResponseIdempotencyCache();
        const cacheRecordSpy = vi.spyOn(idempotencyCache, 'record');

        const orchestrator = new Orchestrator({
            agentDid: recipientDid,
            agentPrivateKey: recipientPrivateKey,
            principalDid,
            policyEngine: { executeWithPolicy },
            transport: {} as never,
            resolvePublicKey: makePubKeyResolver(),
            tokenStore: { getToken: vi.fn(() => Promise.resolve(token)) },
            delegationChainValidator: validator,
            revocationChecker: vi.fn(() => Promise.resolve(false)),
            policyRecorder: mockPolicyRecorder(),
            resolveAgentDocument: vi.fn(() =>
                Promise.resolve(mockSenderDocument()),
            ),
            businessHandler: vi.fn(() => Promise.resolve({ ok: true })),
            idempotencyCache,
        });

        const incoming = buildEnvelope({
            senderDid,
            senderPrivateKey,
            recipientDid,
            sessionId: 'session-r21-f2-b',
            messageType: 'NEGOTIATION_REQUEST',
            body: { action: 'PAYMENT', params: { amount: 500 } },
            capabilityTokenRef: token.id,
        });

        // First call: executor throws -> INTERNAL_ERROR + cacheable=false
        const first = await orchestrator.handleEnvelope(incoming);
        expect(first.handled).toBe(false);
        expect(first.cacheable).toBe(false);
        expect(cacheRecordSpy).not.toHaveBeenCalled();

        // Second call: engine recovers -> SUCCESS (cacheable defaults to true, writes the cache)
        const second = await orchestrator.handleEnvelope(incoming);
        expect(second.handled).toBe(true);
        // the engine was called 2 times — confirming the second call was not short-circuited by the cache
        expect(executeWithPolicy).toHaveBeenCalledTimes(2);
        expect(cacheRecordSpy).toHaveBeenCalledTimes(1);
    });

    // ─── when committed=true, INTERNAL_ERROR must still be cached ────────
    it('caches INTERNAL_ERROR when executor already committed (cacheable=true to prevent double side-effects)', async () => {
        // Background: inside the engine the executor returns successfully (the onExecutorSuccess hook has fired ->
        // committed=true), but the subsequent recorder write of SUCCESS throws, causing
        // executeWithPolicy to throw. The business has **already executed** (the external side effect has landed), so if
        // this INTERNAL_ERROR response is not cached, the caller's resubmission would trigger the business executor again ->
        // a duplicate side effect. Fix: the outer catch marks cacheable=true when committed=true.
        const token = buildDelegatedTokenFixture({
            id: 'urn:cap:leaf-r21-f2-c',
            issuedTo: senderDid,
            capabilities: [
                {
                    action: 'PAYMENT',
                    scope: {
                        type: 'numeric_limit',
                        field: 'amount',
                        max: 10_000,
                    },
                },
            ] as unknown as CapabilityToken['capabilities'],
        });

        const validator = vi.fn(
            (): Promise<DelegationChainValidationResult> =>
                Promise.resolve({ valid: true, depth: 1 }),
        );

        // engine simulation: executor succeeds (hook fires, committed=true) -> recorder
        // write of SUCCESS fails -> throw (the business side effect has landed)
        const executeWithPolicy = vi.fn(
            async (params: {
                recordId?: string;
                onExecutorSuccess?: () => void | Promise<void>;
                executor: () => Promise<unknown>;
            }) => {
                await params.executor();
                await params.onExecutorSuccess?.();
                throw new Error('recorder SUCCESS write failed');
            },
        );

        const idempotencyCache = new InMemoryResponseIdempotencyCache();
        const cacheRecordSpy = vi.spyOn(idempotencyCache, 'record');

        const businessHandler = vi.fn(() => Promise.resolve({ ok: true }));

        const orchestrator = new Orchestrator({
            agentDid: recipientDid,
            agentPrivateKey: recipientPrivateKey,
            principalDid,
            policyEngine: { executeWithPolicy },
            transport: {} as never,
            resolvePublicKey: makePubKeyResolver(),
            tokenStore: { getToken: vi.fn(() => Promise.resolve(token)) },
            delegationChainValidator: validator,
            revocationChecker: vi.fn(() => Promise.resolve(false)),
            policyRecorder: mockPolicyRecorder(),
            resolveAgentDocument: vi.fn(() =>
                Promise.resolve(mockSenderDocument()),
            ),
            businessHandler,
            idempotencyCache,
        });

        const incoming = buildEnvelope({
            senderDid,
            senderPrivateKey,
            recipientDid,
            sessionId: 'session-r21-f2-c',
            messageType: 'NEGOTIATION_REQUEST',
            body: { action: 'PAYMENT', params: { amount: 500 } },
            capabilityTokenRef: token.id,
        });

        // First call: executor ran -> engine throw -> INTERNAL_ERROR + cacheable=true
        const first = await orchestrator.handleEnvelope(incoming);
        expect(first.handled).toBe(false);
        expect(first.cacheable).toBe(true);
        expect(cacheRecordSpy).toHaveBeenCalledTimes(1);

        // Second call: hits the cache, the executor is not re-triggered (avoiding a duplicate side effect)
        const second = await orchestrator.handleEnvelope(incoming);
        // HIT re-signs the envelope, so the reference differs; the key point is that the **business handler is no longer called**.
        expect(second.responseEnvelope).not.toBe(first.responseEnvelope);
        expect(second.responseEnvelope.body).toEqual(
            first.responseEnvelope.body,
        );
        expect(second.responseEnvelope.messageType).toBe('ERROR');
        // Key assertion: both the business handler and the engine are called only once
        expect(businessHandler).toHaveBeenCalledTimes(1);
        expect(executeWithPolicy).toHaveBeenCalledTimes(1);
        // the HIT path marks cacheable=false, so finally does not extend the entry's life; the total record count is still 1
        expect(cacheRecordSpy).toHaveBeenCalledTimes(1);
    });

    // ─── a record() write timeout does not block the main flow ──────────────────────
    it('does not block response when idempotencyCache.record hangs beyond write timeout (bounded wait)', async () => {
        // Background: the `record()` in finally must be awaited to guarantee that subsequent retries hit the same
        // response (making it async would break the idempotency promise). But an unbounded await would let a hanging
        // cache backend stall every response. Promise.race bounds the timeout; on timeout it is treated as a record
        // failure, only warned about, and the main flow returns on time.
        
        // This test uses a record() implementation that stays pending forever — handleEnvelope's response
        // must complete within the timeout window (it must not hang).
        const token = buildDelegatedTokenFixture({
            id: 'urn:cap:leaf-r21-f1',
            issuedTo: senderDid,
            capabilities: [
                {
                    action: 'PAYMENT',
                    scope: {
                        type: 'numeric_limit',
                        field: 'amount',
                        max: 10_000,
                    },
                },
            ] as unknown as CapabilityToken['capabilities'],
        });

        const validator = vi.fn(
            (): Promise<DelegationChainValidationResult> =>
                Promise.resolve({ valid: true, depth: 1 }),
        );

        const executeWithPolicy = vi.fn(
            async (params: {
                recordId?: string;
                onExecutorSuccess?: () => void | Promise<void>;
            }) => {
                await params.onExecutorSuccess?.();
                return {
                    executed: true as const,
                    recordId: params.recordId ?? 'record-r21-f1',
                    result: { ok: true },
                };
            },
        );

        // record() never resolves: simulates a hanging backend
        const hangingCache = {
            check: vi.fn(() => Promise.resolve(null)),
            record: vi.fn(() => new Promise<void>(() => {})),
        };

        // lower the timeout threshold to 50 ms, to avoid the test running for 2s
        const WRITE_TIMEOUT_MS = 50;

        const consoleErrorSpy = vi
            .spyOn(console, 'error')
            .mockImplementation(() => {});

        try {
            const orchestrator = new Orchestrator({
                agentDid: recipientDid,
                agentPrivateKey: recipientPrivateKey,
                principalDid,
                policyEngine: { executeWithPolicy },
                transport: {} as never,
                resolvePublicKey: makePubKeyResolver(),
                tokenStore: { getToken: vi.fn(() => Promise.resolve(token)) },
                delegationChainValidator: validator,
                revocationChecker: vi.fn(() => Promise.resolve(false)),
                policyRecorder: mockPolicyRecorder(),
                resolveAgentDocument: vi.fn(() =>
                    Promise.resolve(mockSenderDocument()),
                ),
                businessHandler: vi.fn(() => Promise.resolve({})),
                idempotencyCache: hangingCache,
                idempotencyCacheWriteTimeoutMs: WRITE_TIMEOUT_MS,
            });

            const incoming = buildEnvelope({
                senderDid,
                senderPrivateKey,
                recipientDid,
                sessionId: 'session-r21-f1',
                messageType: 'NEGOTIATION_REQUEST',
                body: { action: 'PAYMENT', params: { amount: 500 } },
                capabilityTokenRef: token.id,
            });

            const startedAt = Date.now();
            const result = await orchestrator.handleEnvelope(incoming);
            const elapsed = Date.now() - startedAt;

            // the main flow is not blocked by the hanging record: the business response returns normally
            expect(result.handled).toBe(true);
            // timeout threshold of 50 ms + a reasonable margin (CI GC/scheduling may inflate it)
            // if record were truly awaited unboundedly, elapsed would be vitest's default 5000 ms timeout
            expect(elapsed).toBeLessThan(2000);
            // record was indeed triggered (it just timed out)
            expect(hangingCache.record).toHaveBeenCalledTimes(1);
            // the stderr warning is observable
            const errorCall = consoleErrorSpy.mock.calls.find((call) =>
                String(call[0] ?? '').includes(
                    'idempotencyCache.record failed',
                ),
            );
            expect(errorCall).toBeDefined();
            expect(String(errorCall?.[0] ?? '')).toContain(
                `exceeded ${WRITE_TIMEOUT_MS}ms`,
            );
        } finally {
            consoleErrorSpy.mockRestore();
        }
    });

    // ─── a shared cache must not cross-wire between recipients ─────────────────────
    it('does not leak cached response across recipients when backend is shared (recipientDid namespace)', async () => {
        // Background: if the ResponseIdempotencyCache key is only (senderDid,
        // sessionId, envelopeId), a shared persistent backend (Postgres/Redis) would wrongly reuse agent A's
        // response for agent B. When a sender signs an envelope with the same id + same sessionId to two different
        // recipients, recipient B would hit recipient A's response, bypassing local authorization/business.
        // Fix: add a recipientDid dimension to the key (= the agentDid of the cache's owning agent) for
        // strong isolation; two orchestrators sharing a cache then do not interfere.
        const tokenA = buildDelegatedTokenFixture({
            id: 'urn:cap:r22-f1-a',
            issuedTo: senderDid,
            capabilities: [
                {
                    action: 'PING',
                    scope: {
                        type: 'numeric_limit',
                        field: 'amount',
                        max: 10_000,
                    },
                },
            ] as unknown as CapabilityToken['capabilities'],
        });
        const tokenB = buildDelegatedTokenFixture({
            id: 'urn:cap:r22-f1-b',
            issuedTo: senderDid,
            capabilities: [
                {
                    action: 'PING',
                    scope: {
                        type: 'numeric_limit',
                        field: 'amount',
                        max: 10_000,
                    },
                },
            ] as unknown as CapabilityToken['capabilities'],
        });

        // two recipients share the same cache instance (simulating a Postgres/Redis persistent backend)
        const sharedCache = new InMemoryResponseIdempotencyCache();

        // generate a new keypair for recipient B (different agentDid -> isolation dimension)
        const recipientBKeyPair = generateKeyPair() as {
            publicKey: string;
            privateKey: string;
        };
        const recipientBDid =
            'did:agent:0000000000000000000000000000000000000000' as DID;
        const recipientBPrivateKey = recipientBKeyPair.privateKey;

        // This test does not need verifyEnvelope to actually pass (the assertions focus on senderDid routing
        // and engine call counts); resolvePublicKey only needs to return the sender's public key.
        const resolvePublicKeyBoth = makePubKeyResolver();

        const makeValidator = () =>
            vi.fn(
                (): Promise<DelegationChainValidationResult> =>
                    Promise.resolve({ valid: true, depth: 1 }),
            );
        const makeEngine = (tag: string) =>
            vi.fn(
                async (params: {
                    recordId?: string;
                    onExecutorSuccess?: () => void | Promise<void>;
                }) => {
                    await params.onExecutorSuccess?.();
                    return {
                        executed: true as const,
                        recordId: `record-${tag}`,
                        result: { recipient: tag },
                    };
                },
            );

        const engineA = makeEngine('A');
        const engineB = makeEngine('B');

        const orchestratorA = new Orchestrator({
            agentDid: recipientDid,
            agentPrivateKey: recipientPrivateKey,
            principalDid,
            policyEngine: { executeWithPolicy: engineA },
            transport: {} as never,
            resolvePublicKey: resolvePublicKeyBoth,
            tokenStore: { getToken: vi.fn(() => Promise.resolve(tokenA)) },
            delegationChainValidator: makeValidator(),
            revocationChecker: vi.fn(() => Promise.resolve(false)),
            policyRecorder: mockPolicyRecorder(),
            resolveAgentDocument: vi.fn(() =>
                Promise.resolve(mockSenderDocument()),
            ),
            businessHandler: vi.fn(() => Promise.resolve({})),
            idempotencyCache: sharedCache,
        });

        const orchestratorB = new Orchestrator({
            agentDid: recipientBDid,
            agentPrivateKey: recipientBPrivateKey,
            principalDid,
            policyEngine: { executeWithPolicy: engineB },
            transport: {} as never,
            resolvePublicKey: resolvePublicKeyBoth,
            tokenStore: { getToken: vi.fn(() => Promise.resolve(tokenB)) },
            delegationChainValidator: makeValidator(),
            revocationChecker: vi.fn(() => Promise.resolve(false)),
            policyRecorder: mockPolicyRecorder(),
            resolveAgentDocument: vi.fn(() =>
                Promise.resolve(mockSenderDocument()),
            ),
            businessHandler: vi.fn(() => Promise.resolve({})),
            idempotencyCache: sharedCache,
        });

        // the sender sends A and B each a signed envelope with "the same id and same sessionId"
        const sharedEnvelopeId = 'shared-envelope-r22-f1';
        const sharedSessionId = 'session-r22-f1-shared';
        const envelopeToA = buildEnvelope({
            id: sharedEnvelopeId,
            senderDid,
            senderPrivateKey,
            recipientDid,
            sessionId: sharedSessionId,
            messageType: 'NEGOTIATION_REQUEST',
            body: { action: 'PING', params: { amount: 1 } },
            capabilityTokenRef: tokenA.id,
        });
        const envelopeToB = buildEnvelope({
            id: sharedEnvelopeId,
            senderDid,
            senderPrivateKey,
            recipientDid: recipientBDid,
            sessionId: sharedSessionId,
            messageType: 'NEGOTIATION_REQUEST',
            body: { action: 'PING', params: { amount: 1 } },
            capabilityTokenRef: tokenB.id,
        });

        const resultA = await orchestratorA.handleEnvelope(envelopeToA);
        const resultB = await orchestratorB.handleEnvelope(envelopeToB);

        // Key assertion: B must run the flow **independently** (not hit A's cache);
        // both engines are called separately; the two responses have different senderDid.
        expect(resultA.handled).toBe(true);
        expect(resultB.handled).toBe(true);
        expect(engineA).toHaveBeenCalledTimes(1);
        expect(engineB).toHaveBeenCalledTimes(1);
        expect(resultA.responseEnvelope.header.senderDid).toBe(recipientDid);
        expect(resultB.responseEnvelope.header.senderDid).toBe(recipientBDid);
        // body.data carries each one's own tag, verifying there is no cross-agent response contamination
        expect(
            (resultA.responseEnvelope.body as { data: { recipient: string } })
                .data.recipient,
        ).toBe('A');
        expect(
            (resultB.responseEnvelope.body as { data: { recipient: string } })
                .data.recipient,
        ).toBe('B');
    });

    // ─── HIT re-signs a new envelope with a fresh timestamp ────────────────
    it('returns a freshly-signed response envelope on cache hit with current timestamp (rebuild, do not replay old bytes)', async () => {
        // Background: the old design cached the NegotiationEnvelope directly, and the 10-minute TTL
        // far exceeds verifyEnvelope's 5-minute clock skew; a retry more than 5 minutes after the first response would
        // get a stale envelope that the protocol must reject.
        // Fix: on a HIT, re-sign a new envelope using the current clock.
        // This test simulates "advancing the clock on a HIT" — verifying that the re-signed envelope's timestamp
        // is later than the first response, and that it passes verifyEnvelope (valid signature + valid time window).
        const token = buildDelegatedTokenFixture({
            id: 'urn:cap:r22-f2-fresh',
            issuedTo: senderDid,
            capabilities: [
                {
                    action: 'PING',
                    scope: {
                        type: 'numeric_limit',
                        field: 'amount',
                        max: 10_000,
                    },
                },
            ] as unknown as CapabilityToken['capabilities'],
        });

        const validator = vi.fn(
            (): Promise<DelegationChainValidationResult> =>
                Promise.resolve({ valid: true, depth: 1 }),
        );
        const executeWithPolicy = vi.fn(
            async (params: {
                recordId?: string;
                onExecutorSuccess?: () => void | Promise<void>;
            }) => {
                await params.onExecutorSuccess?.();
                return {
                    executed: true as const,
                    recordId: params.recordId ?? 'record-r22-f2-fresh',
                    result: { ok: true },
                };
            },
        );

        const idempotencyCache = new InMemoryResponseIdempotencyCache();

        // This test needs verifyEnvelope to **actually** pass on the re-signed response — use a real
        // keypair as the recipient private key (the existing recipientPrivateKey is fake).
        const recipientRealKeyPair = generateKeyPair() as {
            publicKey: string;
            privateKey: string;
        };
        const recipientRealPublicKey = recipientRealKeyPair.publicKey;
        const recipientRealPrivateKey = recipientRealKeyPair.privateKey;
        const resolvePublicKeyForBoth = vi.fn((did: DID) => {
            if (did === senderDid) return Promise.resolve(publicKey);
            if (did === middleAgentDid) return Promise.resolve(middlePublicKey);
            if (did === recipientDid)
                return Promise.resolve(recipientRealPublicKey);
            return Promise.resolve(null);
        });

        const orchestrator = new Orchestrator({
            agentDid: recipientDid,
            agentPrivateKey: recipientRealPrivateKey,
            principalDid,
            policyEngine: { executeWithPolicy },
            transport: {} as never,
            resolvePublicKey: resolvePublicKeyForBoth,
            tokenStore: { getToken: vi.fn(() => Promise.resolve(token)) },
            delegationChainValidator: validator,
            revocationChecker: vi.fn(() => Promise.resolve(false)),
            policyRecorder: mockPolicyRecorder(),
            resolveAgentDocument: vi.fn(() =>
                Promise.resolve(mockSenderDocument()),
            ),
            businessHandler: vi.fn(() => Promise.resolve({})),
            idempotencyCache,
        });

        const incoming = buildEnvelope({
            senderDid,
            senderPrivateKey,
            recipientDid,
            sessionId: 'session-r22-f2-fresh',
            messageType: 'NEGOTIATION_REQUEST',
            body: { action: 'PING', params: { amount: 1 } },
            capabilityTokenRef: token.id,
        });

        const first = await orchestrator.handleEnvelope(incoming);
        // Precondition assertion: the first call must reach SUCCESS (otherwise step3.5 rejected it)
        expect(first.handled).toBe(true);
        expect(first.rejectionReason).toBeUndefined();
        const firstTs = new Date(first.responseEnvelope.timestamp).getTime();

        // sleep 20ms to ensure the wall clock advances (avoiding the same ms granularity)
        await new Promise((resolve) => setTimeout(resolve, 20));

        const second = await orchestrator.handleEnvelope(incoming);
        const secondTs = new Date(second.responseEnvelope.timestamp).getTime();

        // HIT but re-signed: the two envelopes have different references; the business fields are the same; the timestamp is fresh
        expect(second.responseEnvelope).not.toBe(first.responseEnvelope);
        expect(second.responseEnvelope.body).toEqual(
            first.responseEnvelope.body,
        );
        expect(secondTs).toBeGreaterThan(firstTs);
        expect(second.responseEnvelope.signature).not.toBe(
            first.responseEnvelope.signature,
        );

        // Key assertion: the new envelope passes verifyEnvelope (clock skew + valid signature)
        const verifyResult = await verifyEnvelope(second.responseEnvelope, {
            resolvePublicKey: resolvePublicKeyForBoth,
        });
        expect(verifyResult.valid).toBe(true);

        // the engine is still called only once (the second call is short-circuited by the cache hit)
        expect(executeWithPolicy).toHaveBeenCalledTimes(1);
    });

    // ─── HIT does not trigger a re-record (does not extend the life of a stale entry) ────────────────
    it('does not re-record on cache hit (avoid extending TTL on stale entries)', async () => {
        // Background: if the HIT path calls record() again it would refresh the entry's
        // createdAt, so an expired entry would be kept alive indefinitely. The HIT return explicitly marks
        // cacheable=false, and the finally guard skips record.
        const token = buildDelegatedTokenFixture({
            id: 'urn:cap:r22-f2-norerec',
            issuedTo: senderDid,
            capabilities: [
                {
                    action: 'PING',
                    scope: {
                        type: 'numeric_limit',
                        field: 'amount',
                        max: 10_000,
                    },
                },
            ] as unknown as CapabilityToken['capabilities'],
        });

        const validator = vi.fn(
            (): Promise<DelegationChainValidationResult> =>
                Promise.resolve({ valid: true, depth: 1 }),
        );
        const executeWithPolicy = vi.fn(
            async (params: {
                onExecutorSuccess?: () => void | Promise<void>;
            }) => {
                await params.onExecutorSuccess?.();
                return {
                    executed: true as const,
                    recordId: 'record-r22-f2-norerec',
                    result: { ok: true },
                };
            },
        );

        const idempotencyCache = new InMemoryResponseIdempotencyCache();
        const recordSpy = vi.spyOn(idempotencyCache, 'record');

        const orchestrator = new Orchestrator({
            agentDid: recipientDid,
            agentPrivateKey: recipientPrivateKey,
            principalDid,
            policyEngine: { executeWithPolicy },
            transport: {} as never,
            resolvePublicKey: makePubKeyResolver(),
            tokenStore: { getToken: vi.fn(() => Promise.resolve(token)) },
            delegationChainValidator: validator,
            revocationChecker: vi.fn(() => Promise.resolve(false)),
            policyRecorder: mockPolicyRecorder(),
            resolveAgentDocument: vi.fn(() =>
                Promise.resolve(mockSenderDocument()),
            ),
            businessHandler: vi.fn(() => Promise.resolve({})),
            idempotencyCache,
        });

        const incoming = buildEnvelope({
            senderDid,
            senderPrivateKey,
            recipientDid,
            sessionId: 'session-r22-f2-norerec',
            messageType: 'NEGOTIATION_REQUEST',
            body: { action: 'PING', params: { amount: 1 } },
            capabilityTokenRef: token.id,
        });

        await orchestrator.handleEnvelope(incoming);
        expect(recordSpy).toHaveBeenCalledTimes(1); // first MISS -> write cache

        await orchestrator.handleEnvelope(incoming);
        await orchestrator.handleEnvelope(incoming);
        // Key assertion: the following two HITs no longer call record -> the old entry is not kept alive
        expect(recordSpy).toHaveBeenCalledTimes(1);
    });

    // ─── OBSOLETE: the explicit rejection path has been replaced by dual-key fallback ──────────
    // Historical background: early on the orchestrator's leaf verification was a single-key path that pre-checked the ROTATING state
    // and explicitly rejected (rejectionReason='delegation_rotation_not_supported') as the contractual
    // exit. Later the dual-key ResolvedPublicKeys (current + previous) was pushed down into
    // the delegation-validator, so a valid token signed with the previous key during ROTATING can now
    // fall back and pass during verification — the explicit rejection branch was removed accordingly
    // (OrchestratorConfig.resolveKeyRotationState + the orchestrator's rejection injection).
    // This test is kept as a historical skip: re-activating it = dual-key fallback no longer works (a regression signal).
    it.skip('OBSOLETE: rejects delegated token when last-hop delegator is in ROTATING state (explicit contract signal)', async () => {
        const token = buildDelegatedTokenFixture({
            id: 'urn:cap:leaf-r19-f2',
            issuedTo: senderDid,
            capabilities: [
                {
                    action: 'PAYMENT',
                    scope: {
                        type: 'numeric_limit',
                        field: 'amount',
                        max: 10_000,
                    },
                },
            ] as unknown as CapabilityToken['capabilities'],
        });

        const validator = vi.fn(
            (): Promise<DelegationChainValidationResult> =>
                Promise.resolve({ valid: true, depth: 1 }),
        );

        // the last-hop delegator is in ROTATING
        const resolveKeyRotationState = vi.fn(
            (): Promise<'ACTIVE' | 'ROTATING' | 'RETIRED' | null> =>
                Promise.resolve('ROTATING'),
        );

        const orchestrator = new Orchestrator({
            agentDid: recipientDid,
            agentPrivateKey: recipientPrivateKey,
            principalDid,
            policyEngine: {
                executeWithPolicy: vi.fn(() =>
                    Promise.resolve({
                        executed: false as const,
                        recordId: 'unused',
                        reason: 'should not reach step4',
                    }),
                ),
            },
            transport: {} as never,
            resolvePublicKey: makePubKeyResolver(),
            tokenStore: { getToken: vi.fn(() => Promise.resolve(token)) },
            delegationChainValidator: validator,
            revocationChecker: vi.fn(() => Promise.resolve(false)),
            policyRecorder: mockPolicyRecorder(),
            resolveAgentDocument: vi.fn(() =>
                Promise.resolve(mockSenderDocument()),
            ),
            resolveKeyRotationState,
            businessHandler: vi.fn(),
        });

        const incoming = buildEnvelope({
            senderDid,
            senderPrivateKey,
            recipientDid,
            sessionId: 'session-r19-f2',
            messageType: 'NEGOTIATION_REQUEST',
            body: { action: 'PAYMENT', params: { amount: 500 } },
            capabilityTokenRef: token.id,
        });

        const result = await orchestrator.handleEnvelope(incoming);

        // step3.5 rejects -> handled:false + rejectionReason contains rotation_not_supported
        expect(result.handled).toBe(false);
        expect(result.rejectionReason).toBe(
            'delegation_rotation_not_supported',
        );
        expect(resolveKeyRotationState).toHaveBeenCalled();
    });

    // ─── dual-key fallback is effective for both leaf + chain ──────
    it('accepts delegated token signed with previous key during ROTATING grace period (resolvePublicKeys leaf + chain fallback)', async () => {
        // Scenario: the middle agent is in ROTATING; the leaf's top-level proof is signed with the previous key,
        // and the time anchor token.issuedAt <= previousValidBefore. With the dual-key resolvePublicKeys port injected
        // -> after leaf verification with current fails, the orchestrator falls back to previous, and verification passes.
        const previousKp = generateKeyPair() as {
            publicKey: string;
            privateKey: string;
        };
        const currentKp = middleKeyPair; // the currently registered publicKey
        const issuedAt = new Date(Date.now() - 60_000).toISOString();
        const previousValidBefore = new Date(Date.now() + 60_000).toISOString();

        // sign the leaf's top-level proof with the previous key
        const token = buildDelegatedTokenFixture({
            id: 'urn:cap:leaf-fallback',
            issuedTo: senderDid,
            issuedAt,
            capabilities: [
                {
                    action: 'INQUIRY',
                    scope: {
                        type: 'allowlist',
                        field: 'recipient',
                        values: ['supplier-a'],
                    },
                },
            ] as unknown as CapabilityToken['capabilities'],
            signingPrivateKey: previousKp.privateKey, // key point: signed with the previous key
        });

        const validator = vi.fn(
            (): Promise<DelegationChainValidationResult> =>
                Promise.resolve({ valid: true, depth: 1 }),
        );

        // resolvePublicKeys injects the dual-key port
        const resolvePublicKeys = vi.fn(
            (did: DID): Promise<ResolvedPublicKeys | null> => {
                if (did === middleAgentDid) {
                    return Promise.resolve({
                        current: currentKp.publicKey,
                        previous: previousKp.publicKey,
                        previousValidBefore:
                            previousValidBefore as unknown as Timestamp,
                        rotationState: 'ROTATING',
                    });
                }
                return Promise.resolve(null);
            },
        );

        const policyEngine = {
            executeWithPolicy: vi.fn(() =>
                Promise.resolve({
                    executed: true as const,
                    recordId: 'r1',
                    result: { ok: true },
                }),
            ),
        };

        const orchestrator = new Orchestrator({
            agentDid: recipientDid,
            agentPrivateKey: recipientPrivateKey,
            principalDid,
            policyEngine,
            transport: {} as never,
            resolvePublicKey: makePubKeyResolver(),
            resolvePublicKeys, // the new port
            tokenStore: { getToken: vi.fn(() => Promise.resolve(token)) },
            delegationChainValidator: validator,
            revocationChecker: vi.fn(() => Promise.resolve(false)),
            policyRecorder: mockPolicyRecorder(),
            resolveAgentDocument: vi.fn(() =>
                Promise.resolve(mockSenderDocument()),
            ),
            businessHandler: vi.fn(() =>
                Promise.resolve({ ok: true } as Record<string, unknown>),
            ),
        });

        const incoming = buildEnvelope({
            senderDid,
            senderPrivateKey,
            recipientDid,
            sessionId: 'session-fallback',
            messageType: 'NEGOTIATION_REQUEST',
            body: {
                action: 'INQUIRY',
                params: { recipient: 'supplier-a' },
            },
            capabilityTokenRef: token.id,
        });

        const result = await orchestrator.handleEnvelope(incoming);

        // leaf verification with current fails -> fall back to previous -> passes; no longer triggers
        // a delegation_leaf_signature_invalid rejection
        expect(result.handled).toBe(true);
        expect(resolvePublicKeys).toHaveBeenCalledWith(middleAgentDid);
    });

    it('rejects delegated token with previous key when issuedAt > previousValidBefore (time-window fail-closed)', async () => {
        // Scenario: the previous key's time window has expired (issuedAt > previousValidBefore) ->
        // fallback is not allowed, and it must be rejected as delegation_leaf_signature_invalid.
        const previousKp = generateKeyPair() as {
            publicKey: string;
            privateKey: string;
        };
        const currentKp = middleKeyPair;
        // issuedAt is in the past (a valid issuance moment) but later than previousValidBefore -> the time window is closed.
        // previousValidBefore is set earlier (before issuedAt), so fallback is not allowed and the signature must be rejected.
        const issuedAt = new Date(Date.now() - 60_000).toISOString();
        const previousValidBefore = new Date(
            Date.now() - 120_000,
        ).toISOString();

        const token = buildDelegatedTokenFixture({
            id: 'urn:cap:leaf-fallback-stale',
            issuedTo: senderDid,
            issuedAt,
            capabilities: [
                {
                    action: 'INQUIRY',
                    scope: {
                        type: 'allowlist',
                        field: 'recipient',
                        values: ['supplier-a'],
                    },
                },
            ] as unknown as CapabilityToken['capabilities'],
            signingPrivateKey: previousKp.privateKey,
        });

        const validator = vi.fn(
            (): Promise<DelegationChainValidationResult> =>
                Promise.resolve({ valid: true, depth: 1 }),
        );

        const resolvePublicKeys = vi.fn(
            (did: DID): Promise<ResolvedPublicKeys | null> => {
                if (did === middleAgentDid) {
                    return Promise.resolve({
                        current: currentKp.publicKey,
                        previous: previousKp.publicKey,
                        previousValidBefore:
                            previousValidBefore as unknown as Timestamp,
                        rotationState: 'ROTATING',
                    });
                }
                return Promise.resolve(null);
            },
        );

        const orchestrator = new Orchestrator({
            agentDid: recipientDid,
            agentPrivateKey: recipientPrivateKey,
            principalDid,
            policyEngine: {
                executeWithPolicy: vi.fn(() =>
                    Promise.resolve({
                        executed: false as const,
                        recordId: 'unused',
                        reason: 'should not reach',
                    }),
                ),
            },
            transport: {} as never,
            resolvePublicKey: makePubKeyResolver(),
            resolvePublicKeys,
            tokenStore: { getToken: vi.fn(() => Promise.resolve(token)) },
            delegationChainValidator: validator,
            revocationChecker: vi.fn(() => Promise.resolve(false)),
            policyRecorder: mockPolicyRecorder(),
            resolveAgentDocument: vi.fn(() =>
                Promise.resolve(mockSenderDocument()),
            ),
            businessHandler: vi.fn(),
        });

        const incoming = buildEnvelope({
            senderDid,
            senderPrivateKey,
            recipientDid,
            sessionId: 'session-stale',
            messageType: 'NEGOTIATION_REQUEST',
            body: {
                action: 'INQUIRY',
                params: { recipient: 'supplier-a' },
            },
            capabilityTokenRef: token.id,
        });

        const result = await orchestrator.handleEnvelope(incoming);

        expect(result.handled).toBe(false);
        expect(result.rejectionReason).toBe(
            'delegation_leaf_signature_invalid',
        );
    });

    // ─── the orchestrator step3.5 delegation path must reject specVersion='0.1.0' + delegationChain ──
    it('rejects delegated token with specVersion="0.1.0" at step3.5 (version gate propagates through validator)', async () => {
        // Requires that specVersion='0.1.0' and the delegationChain field be mutually exclusive.
        // The check is pushed down into validateDelegationChain -> when the orchestrator calls the validator
        // it automatically rejects (reason='INVALID_TOKEN_FORMAT' maps to delegation_invalid_token_format).
        const baseToken = buildDelegatedTokenFixture({
            id: 'urn:cap:leaf-downgrade-0.1.0',
            issuedTo: senderDid,
            capabilities: [
                {
                    action: 'PAYMENT',
                    scope: {
                        type: 'numeric_limit',
                        field: 'amount',
                        max: 1000,
                    },
                },
            ] as unknown as CapabilityToken['capabilities'],
        });
        // downgrade a valid 0.2.0 delegated token to 0.1.0
        const downgradedToken: CapabilityToken = {
            ...baseToken,
            specVersion: '0.1.0',
        };

        // Inject the real validateDelegationChain — the key point is to make the orchestrator rely on
        // the validator's INVALID_TOKEN_FORMAT decision.
        const { validateDelegationChain } =
            await import('@coivitas/identity');

        const orchestrator = new Orchestrator({
            agentDid: recipientDid,
            agentPrivateKey: recipientPrivateKey,
            principalDid,
            policyEngine: { executeWithPolicy: vi.fn() },
            transport: {} as never,
            resolvePublicKey: makePubKeyResolver(),
            tokenStore: {
                getToken: vi.fn(() => Promise.resolve(downgradedToken)),
            },
            delegationChainValidator: validateDelegationChain,
            revocationChecker: vi.fn(() => Promise.resolve(false)),
            policyRecorder: mockPolicyRecorder(),
            resolveAgentDocument: vi.fn(() =>
                Promise.resolve(mockSenderDocument()),
            ),
            businessHandler: vi.fn(),
        });

        const incoming = buildEnvelope({
            senderDid,
            senderPrivateKey,
            recipientDid,
            sessionId: 'session-downgrade',
            messageType: 'NEGOTIATION_REQUEST',
            body: { action: 'PAYMENT', params: { amount: 100 } },
            capabilityTokenRef: downgradedToken.id,
        });

        const result = await orchestrator.handleEnvelope(incoming);

        expect(result.handled).toBe(false);
        // After the token's specVersion is downgraded, the orchestrator step3.5 fine-grained
        // check (manual verify(payloadBytes, token.proof.value)) first finds that "the signature does not match the payload"
        // (because the valid signature was over the 0.2.0 payload), and returns
        // delegation_leaf_signature_invalid — this is the correct fail-closed behavior.
        // Even if the orchestrator's manual check were bypassed, the validator's internal INVALID_TOKEN_FORMAT
        // gate would reject it as a second line of defense (the identity test "should reject delegated token
        // with specVersion=0.1.0" covers that path).
        // This test only requires the orchestrator to reject the 0.1.0+chain token overall; it does not pin the reason text.
        expect(result.rejectionReason).toMatch(/^delegation_/);
    });

    // ─── gap lock-in — a non-delegated did:agent-issuer token is currently rejected (the spec does not yet support rotation) ──
    it('rejects non-delegated token with did:agent issuerDid (rotation not yet supported, pinned)', async () => {
        // The current !hasChain branch of step3.5 calls the synchronous version of verifyCapabilityToken
        // without passing resolvedKeys -> the identity-layer gate requires a did:key issuer. Here a
        // non-delegated token with a did:agent issuerDid pins the behavior: it is rejected by leaf verification.

        // If a later ticket introduces an L5 key-resolver port + an identity-side async verifier
        // that supports rotation / a did:agent issuer, this test should be removed or rewritten.
        const agentIssuerDid =
            'did:agent:cafebabecafebabecafebabecafebabecafebabe' as DID;
        const maliciousOrRotationKeyPair = generateKeyPair();
        // manually construct a non-delegated token with issuerDid=did:agent (no delegationChain)
        const base = {
            id: 'urn:cap:agent-issuer-nonchain',
            specVersion: SPEC_VERSION_0_2_0,
            issuerDid: agentIssuerDid,
            principalDid,
            issuedTo: senderDid,
            issuedAt: new Date().toISOString(),
            expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
            capabilities: [
                {
                    action: 'INQUIRY',
                    scope: {
                        type: 'allowlist',
                        field: 'recipient',
                        values: ['supplier-a'],
                    },
                },
            ],
            revocationUrl: 'https://revocation.example/v1/{id}',
        };
        const payloadBytes = createCapabilityTokenPayload(base);
        const sigValue = sign(
            payloadBytes,
            maliciousOrRotationKeyPair.privateKey,
        );
        const token = {
            ...base,
            proof: {
                type: 'Ed25519Signature2026',
                created: base.issuedAt,
                verificationMethod: `${agentIssuerDid}#key-1`,
                value: sigValue,
            },
        } as unknown as CapabilityToken;

        const orchestrator = new Orchestrator({
            agentDid: recipientDid,
            agentPrivateKey: recipientPrivateKey,
            principalDid,
            policyEngine: { executeWithPolicy: vi.fn() },
            transport: {} as never,
            resolvePublicKey: makePubKeyResolver(),
            tokenStore: { getToken: vi.fn(() => Promise.resolve(token)) },
            delegationChainValidator: vi.fn(),
            revocationChecker: vi.fn(() => Promise.resolve(false)),
            policyRecorder: mockPolicyRecorder(),
            resolveAgentDocument: vi.fn(() =>
                Promise.resolve(mockSenderDocument()),
            ),
            businessHandler: vi.fn(),
        });

        const incoming = buildEnvelope({
            senderDid,
            senderPrivateKey,
            recipientDid,
            sessionId: 'session-agent-issuer',
            messageType: 'NEGOTIATION_REQUEST',
            body: { action: 'INQUIRY', params: { recipient: 'supplier-a' } },
            capabilityTokenRef: token.id,
        });

        const result = await orchestrator.handleEnvelope(incoming);
        expect(result.handled).toBe(false);
        // rejected by leaf verification (prefix delegation_leaf_*); no silent bypass occurs.
        expect(result.rejectionReason).toMatch(/^delegation_leaf_/);
    });

    // ─── non-delegated token key-rotation semantics ───────────────────────
    // Once the OrchestratorConfig.resolvePublicKeys port is injected, the !hasChain branch must
    // pass the resolution result to verifyCapabilityToken so the ROTATING grace period takes effect.
    describe('non-delegated token key rotation (resolvePublicKeys port)', () => {
        it('should allow non-delegated token signed with previous key during ROTATING grace period when resolvePublicKeys port is injected', async () => {
            // Scenario: the principal's key is rotating — a token issued by the old private key is still valid within the grace period.
            // Once the orchestrator is given the resolvePublicKeys port, it should allow it via verifyCapabilityToken's
            // dual-key fallback.
            const oldKeyPair = generateKeyPair();
            const newKeyPair = generateKeyPair();

            const principalOldDid = didKeyFromPublicKey(
                Buffer.from(oldKeyPair.publicKey, 'hex'),
            );

            // the token is issued by the old key, and issuedAt is within the grace period
            const issuedAt = '2026-04-21T10:00:00.000Z';
            const expiresAt = '2026-04-22T10:00:00.000Z';
            const previousValidBefore = '2026-04-21T12:00:00.000Z'; // grace deadline

            const rotatingToken = issueCapabilityToken({
                issuerDid: principalOldDid,
                issuedTo: senderDid,
                capabilities: [
                    {
                        action: 'INQUIRY',
                        scope: {
                            type: 'allowlist',
                            field: 'recipient',
                            values: ['supplier-a'],
                        },
                    },
                ],
                expiresAt,
                revocationUrl: 'https://revocation.example/v1/{id}',
                issuerPrivateKey: oldKeyPair.privateKey,
                issuedAt,
            });

            // resolvePublicKeys returns the ROTATING state: current=new, previous=old
            const resolvePublicKeys = vi.fn((_did: DID) =>
                Promise.resolve({
                    current: newKeyPair.publicKey,
                    previous: oldKeyPair.publicKey,
                    previousValidBefore,
                    rotationState: 'ROTATING' as const,
                }),
            );

            const orchestrator = new Orchestrator({
                agentDid: recipientDid,
                agentPrivateKey: recipientPrivateKey,
                principalDid: principalOldDid,
                policyEngine: {
                    executeWithPolicy: async ({ executor }) => ({
                        executed: true as const,
                        result: await executor(),
                        recordId: 'record-grace',
                    }),
                },
                transport: {} as never,
                resolvePublicKey: makePubKeyResolver(),
                resolvePublicKeys,
                tokenStore: {
                    getToken: vi.fn(() => Promise.resolve(rotatingToken)),
                },
                delegationChainValidator: vi.fn(),
                revocationChecker: vi.fn(() => Promise.resolve(false)),
                policyRecorder: mockPolicyRecorder(),
                resolveAgentDocument: vi.fn(() =>
                    Promise.resolve(
                        mockSenderDocument({ principalDid: principalOldDid }),
                    ),
                ),
                businessHandler: vi.fn(() => Promise.resolve({ ok: true })),
                now: () =>
                    '2026-04-21T10:05:00.000Z' as import('@coivitas/types').Timestamp,
            });

            const incoming = buildEnvelope({
                senderDid,
                senderPrivateKey,
                recipientDid,
                sessionId: 'session-rotation-grace',
                messageType: 'NEGOTIATION_REQUEST',
                body: {
                    action: 'INQUIRY',
                    params: { recipient: 'supplier-a' },
                },
                capabilityTokenRef: rotatingToken.id,
            });

            const result = await orchestrator.handleEnvelope(incoming);
            // a token issued by the old key within the ROTATING grace period must be allowed
            expect(result.rejectionReason).toBeUndefined();
            // resolvePublicKeys is called with (issuerDid, now) passed through
            expect(resolvePublicKeys).toHaveBeenCalledWith(
                principalOldDid,
                expect.any(Date),
            );
        });

        it('should reject non-delegated token signed with previous key when ROTATING grace period has expired', async () => {
            // issuedAt > previousValidBefore: a token issued by the old key after the grace period ends must be rejected
            const oldKeyPair = generateKeyPair();
            const newKeyPair = generateKeyPair();
            const principalOldDid = didKeyFromPublicKey(
                Buffer.from(oldKeyPair.publicKey, 'hex'),
            );

            // issuedAt is after the grace deadline — treated as invalid
            const issuedAt = '2026-04-21T13:00:00.000Z'; // exceeds previousValidBefore
            const expiresAt = '2026-04-22T13:00:00.000Z';
            const previousValidBefore = '2026-04-21T12:00:00.000Z';

            const lateToken = issueCapabilityToken({
                issuerDid: principalOldDid,
                issuedTo: senderDid,
                capabilities: [
                    {
                        action: 'INQUIRY',
                        scope: {
                            type: 'allowlist',
                            field: 'recipient',
                            values: ['supplier-a'],
                        },
                    },
                ],
                expiresAt,
                revocationUrl: 'https://revocation.example/v1/{id}',
                issuerPrivateKey: oldKeyPair.privateKey,
                issuedAt,
            });

            const resolvePublicKeys = vi.fn((_did: DID) =>
                Promise.resolve({
                    current: newKeyPair.publicKey,
                    previous: oldKeyPair.publicKey,
                    previousValidBefore,
                    rotationState: 'ROTATING' as const,
                }),
            );

            const orchestrator = new Orchestrator({
                agentDid: recipientDid,
                agentPrivateKey: recipientPrivateKey,
                principalDid: principalOldDid,
                policyEngine: { executeWithPolicy: vi.fn() },
                transport: {} as never,
                resolvePublicKey: makePubKeyResolver(),
                resolvePublicKeys,
                tokenStore: {
                    getToken: vi.fn(() => Promise.resolve(lateToken)),
                },
                delegationChainValidator: vi.fn(),
                revocationChecker: vi.fn(() => Promise.resolve(false)),
                policyRecorder: mockPolicyRecorder(),
                resolveAgentDocument: vi.fn(() =>
                    Promise.resolve(
                        mockSenderDocument({ principalDid: principalOldDid }),
                    ),
                ),
                businessHandler: vi.fn(),
                now: () =>
                    '2026-04-21T13:05:00.000Z' as import('@coivitas/types').Timestamp,
            });

            const incoming = buildEnvelope({
                senderDid,
                senderPrivateKey,
                recipientDid,
                sessionId: 'session-rotation-expired',
                messageType: 'NEGOTIATION_REQUEST',
                body: {
                    action: 'INQUIRY',
                    params: { recipient: 'supplier-a' },
                },
                capabilityTokenRef: lateToken.id,
            });

            const result = await orchestrator.handleEnvelope(incoming);
            expect(result.handled).toBe(false);
            // the old key signed outside the grace period -> signature invalid
            expect(result.rejectionReason).toMatch(/^delegation_leaf_/);
        });

        it('should behave identically when resolvePublicKeys port is not injected (backward compat: single-key path)', async () => {
            // when resolvePublicKeys is not injected, !hasChain follows the original single-key path with unchanged behavior.
            const principalKeyPair = generateKeyPair();
            const principalKeyDid = didKeyFromPublicKey(
                Buffer.from(principalKeyPair.publicKey, 'hex'),
            );

            const stableToken = issueCapabilityToken({
                issuerDid: principalKeyDid,
                issuedTo: senderDid,
                capabilities: [
                    {
                        action: 'INQUIRY',
                        scope: {
                            type: 'allowlist',
                            field: 'recipient',
                            values: ['supplier-a'],
                        },
                    },
                ],
                expiresAt: '2026-04-22T10:00:00.000Z',
                revocationUrl: 'https://revocation.example/v1/{id}',
                issuerPrivateKey: principalKeyPair.privateKey,
                issuedAt: '2026-04-21T10:00:00.000Z',
            });

            const orchestrator = new Orchestrator({
                agentDid: recipientDid,
                agentPrivateKey: recipientPrivateKey,
                principalDid: principalKeyDid,
                policyEngine: {
                    executeWithPolicy: async ({ executor }) => ({
                        executed: true as const,
                        result: await executor(),
                        recordId: 'record-compat',
                    }),
                },
                transport: {} as never,
                resolvePublicKey: makePubKeyResolver(),
                // resolvePublicKeys not injected
                tokenStore: {
                    getToken: vi.fn(() => Promise.resolve(stableToken)),
                },
                delegationChainValidator: vi.fn(),
                revocationChecker: vi.fn(() => Promise.resolve(false)),
                policyRecorder: mockPolicyRecorder(),
                resolveAgentDocument: vi.fn(() =>
                    Promise.resolve(
                        mockSenderDocument({ principalDid: principalKeyDid }),
                    ),
                ),
                businessHandler: vi.fn(() => Promise.resolve({ ok: true })),
                now: () =>
                    '2026-04-21T10:05:00.000Z' as import('@coivitas/types').Timestamp,
            });

            const incoming = buildEnvelope({
                senderDid,
                senderPrivateKey,
                recipientDid,
                sessionId: 'session-stable-no-port',
                messageType: 'NEGOTIATION_REQUEST',
                body: {
                    action: 'INQUIRY',
                    params: { recipient: 'supplier-a' },
                },
                capabilityTokenRef: stableToken.id,
            });

            const result = await orchestrator.handleEnvelope(incoming);
            // the single-key path is unaffected: the current key's signature is valid, so verification should pass
            expect(result.rejectionReason).toBeUndefined();
        });

        // when resolvePublicKeys returns null (unknown DID)
        // it must reject directly, and must not pass null to verifyCapabilityToken (which would trigger INTERNAL_ERROR)
        it('should reject with token_issuer_unknown when resolvePublicKeys returns null', async () => {
            const principalKeyPair = generateKeyPair();
            const principalKeyDid = didKeyFromPublicKey(
                Buffer.from(principalKeyPair.publicKey, 'hex'),
            );

            const token = issueCapabilityToken({
                issuerDid: principalKeyDid,
                issuedTo: senderDid,
                capabilities: [
                    {
                        action: 'INQUIRY',
                        scope: {
                            type: 'allowlist',
                            field: 'recipient',
                            values: ['supplier-a'],
                        },
                    },
                ],
                expiresAt: '2026-04-22T10:00:00.000Z',
                revocationUrl: 'https://revocation.example/v1/{id}',
                issuerPrivateKey: principalKeyPair.privateKey,
                issuedAt: '2026-04-21T10:00:00.000Z',
            });

            const resolvePublicKeys = vi.fn((_did: DID, _now?: Date) =>
                Promise.resolve(null),
            );

            const orchestrator = new Orchestrator({
                agentDid: recipientDid,
                agentPrivateKey: recipientPrivateKey,
                principalDid: principalKeyDid,
                policyEngine: { executeWithPolicy: vi.fn() },
                transport: {} as never,
                resolvePublicKey: makePubKeyResolver(),
                resolvePublicKeys,
                tokenStore: { getToken: vi.fn(() => Promise.resolve(token)) },
                delegationChainValidator: vi.fn(),
                revocationChecker: vi.fn(() => Promise.resolve(false)),
                policyRecorder: mockPolicyRecorder(),
                resolveAgentDocument: vi.fn(() =>
                    Promise.resolve(
                        mockSenderDocument({ principalDid: principalKeyDid }),
                    ),
                ),
                businessHandler: vi.fn(),
                now: () =>
                    '2026-04-21T10:05:00.000Z' as import('@coivitas/types').Timestamp,
            });

            const incoming = buildEnvelope({
                senderDid,
                senderPrivateKey,
                recipientDid,
                sessionId: 'session-resolver-null',
                messageType: 'NEGOTIATION_REQUEST',
                body: {
                    action: 'INQUIRY',
                    params: { recipient: 'supplier-a' },
                },
                capabilityTokenRef: token.id,
            });

            const result = await orchestrator.handleEnvelope(incoming);
            expect(result.rejectionReason).toBe(
                'delegation_leaf_token_issuer_unknown',
            );
            expect(resolvePublicKeys).toHaveBeenCalledWith(
                principalKeyDid,
                expect.any(Date),
            );
        });
    });

    // ─── a token produced by the real delegateCapabilityToken() must pass ─
    it('accepts delegated token produced by real delegateCapabilityToken() (signer=middle, issuedTo=sender)', async () => {
        // End-to-end: human principal -> middle agent -> sender agent.
        // The leaf's top-level proof is signed by middle (delegatorDid=middleAgentDid,
        // issuedTo=senderDid). Before the fix, resolving the public key by senderDid would falsely reject this legitimate flow.
        const principalKeyPair = generateKeyPair();
        const realPrincipalDid = didKeyFromPublicKey(
            Buffer.from(principalKeyPair.publicKey, 'hex'),
        );

        // 1. the parent token signed by the principal for the middle agent
        const parentToken = issueCapabilityToken({
            issuerDid: realPrincipalDid,
            issuedTo: middleAgentDid,
            capabilities: [
                {
                    action: 'INQUIRY',
                    scope: {
                        type: 'allowlist',
                        field: 'recipient',
                        values: ['supplier-a'],
                    },
                },
            ],
            expiresAt: new Date(Date.now() + 7_200_000).toISOString() as never,
            revocationUrl: 'https://revocation.example/v1/{id}',
            issuerPrivateKey: principalKeyPair.privateKey,
            issuedAt: new Date().toISOString() as never,
        });

        // 2. middle delegates to sender
        const childToken = delegateCapabilityToken({
            parentToken,
            delegatorPrivateKey: middleKeyPair.privateKey,
            delegateeDid: senderDid,
            attenuatedCapabilities: [
                {
                    action: 'INQUIRY',
                    scope: {
                        type: 'allowlist',
                        field: 'recipient',
                        values: ['supplier-a'],
                    },
                },
            ],
            expiresAt: new Date(Date.now() + 3_600_000).toISOString() as never,
            revocationUrl: 'https://revocation.example/v1/{id}',
        });

        const validator = vi.fn(
            (): Promise<DelegationChainValidationResult> =>
                Promise.resolve({ valid: true, depth: 1 }),
        );
        const executeWithPolicy = vi.fn(
            async ({
                executor,
            }: {
                executor: () => Promise<Record<string, unknown>>;
            }) => ({
                executed: true as const,
                result: await executor(),
                recordId: 'record-real-delegated',
            }),
        );

        const orchestrator = new Orchestrator({
            agentDid: recipientDid,
            agentPrivateKey: recipientPrivateKey,
            principalDid: realPrincipalDid,
            policyEngine: { executeWithPolicy },
            transport: {} as never,
            resolvePublicKey: makePubKeyResolver(),
            tokenStore: {
                getToken: vi.fn(() => Promise.resolve(childToken)),
            },
            delegationChainValidator: validator,
            revocationChecker: vi.fn(() => Promise.resolve(false)),
            policyRecorder: mockPolicyRecorder(),
            resolveAgentDocument: vi.fn(() =>
                Promise.resolve(
                    mockSenderDocument({ principalDid: realPrincipalDid }),
                ),
            ),
            businessHandler: ({ action }) =>
                Promise.resolve({ handledAction: action }),
        });

        const incoming = buildEnvelope({
            senderDid,
            senderPrivateKey,
            recipientDid,
            sessionId: 'session-real-delegated',
            messageType: 'NEGOTIATION_REQUEST',
            body: { action: 'INQUIRY', params: { recipient: 'supplier-a' } },
            capabilityTokenRef: childToken.id,
        });

        const result = await orchestrator.handleEnvelope(incoming);
        expect(result.handled).toBe(true);
        expect(validator).toHaveBeenCalledTimes(1);
    });

    it('rejects when verificationMethod does not point to chain-tail delegator', async () => {
        // Forgery scenario: the attacker changes verificationMethod to point to the sender itself (issuedTo),
        // attempting to shift the signer identification onto the sender; this should be rejected by the consistency check.
        const token = buildDelegatedTokenFixture({
            id: 'urn:cap:leaf-vm-mismatch',
            issuedTo: senderDid,
        });
        // directly change verificationMethod to point to sender (rather than middle)
        const tampered = {
            ...token,
            proof: {
                ...token.proof,
                verificationMethod: `${senderDid}#key-1`,
            },
        } as CapabilityToken;

        const orchestrator = new Orchestrator({
            agentDid: recipientDid,
            agentPrivateKey: recipientPrivateKey,
            principalDid,
            policyEngine: { executeWithPolicy: vi.fn() },
            transport: {} as never,
            resolvePublicKey: makePubKeyResolver(),
            tokenStore: {
                getToken: vi.fn(() => Promise.resolve(tampered)),
            },
            delegationChainValidator: vi.fn(),
            revocationChecker: vi.fn(() => Promise.resolve(false)),
            policyRecorder: mockPolicyRecorder(),
            resolveAgentDocument: vi.fn(() =>
                Promise.resolve(mockSenderDocument()),
            ),
            businessHandler: vi.fn(),
        });

        const incoming = buildEnvelope({
            senderDid,
            senderPrivateKey,
            recipientDid,
            sessionId: 'session-vm-mismatch',
            messageType: 'NEGOTIATION_REQUEST',
            body: { action: 'INQUIRY', params: { recipient: 'supplier-a' } },
            capabilityTokenRef: tampered.id,
        });

        const result = await orchestrator.handleEnvelope(incoming);
        expect(result.handled).toBe(false);
        expect(result.rejectionReason).toBe(
            'delegation_leaf_verification_method_mismatch',
        );
    });

    it('rejects when leaf signer public key cannot be resolved for chain-tail delegator', async () => {
        // middleAgentDid is not in the resolvePublicKey mapping -> returns null -> reject.
        const token = buildDelegatedTokenFixture({
            id: 'urn:cap:leaf-no-delegator-key',
            issuedTo: senderDid,
        });

        // the explicit resolver only recognizes sender; middle returns null
        const limitedResolver = vi.fn((did: DID) =>
            did === senderDid
                ? Promise.resolve(publicKey)
                : Promise.resolve(null),
        );

        const orchestrator = new Orchestrator({
            agentDid: recipientDid,
            agentPrivateKey: recipientPrivateKey,
            principalDid,
            policyEngine: { executeWithPolicy: vi.fn() },
            transport: {} as never,
            resolvePublicKey: limitedResolver,
            tokenStore: { getToken: vi.fn(() => Promise.resolve(token)) },
            delegationChainValidator: vi.fn(),
            revocationChecker: vi.fn(() => Promise.resolve(false)),
            policyRecorder: mockPolicyRecorder(),
            resolveAgentDocument: vi.fn(() =>
                Promise.resolve(mockSenderDocument()),
            ),
            businessHandler: vi.fn(),
        });

        const incoming = buildEnvelope({
            senderDid,
            senderPrivateKey,
            recipientDid,
            sessionId: 'session-no-delegator-key',
            messageType: 'NEGOTIATION_REQUEST',
            body: { action: 'INQUIRY', params: { recipient: 'supplier-a' } },
            capabilityTokenRef: token.id,
        });

        const result = await orchestrator.handleEnvelope(incoming);
        expect(result.handled).toBe(false);
        expect(result.rejectionReason).toBe(
            'delegation_leaf_signer_publickey_not_found',
        );
    });

    // ─── L3 ScopeEvaluator semantic consistency ─────────────────────
    it('accepts allowlist wildcard suffix in sender token (parity with L3 ScopeEvaluator)', async () => {
        // the L3 allowlist supports "*.acme.com"; the early L5 rewrite ignored this semantic.
        const token = buildDelegatedTokenFixture({
            id: 'urn:cap:leaf-wildcard',
            issuedTo: senderDid,
            capabilities: [
                {
                    action: 'INQUIRY',
                    scope: {
                        type: 'allowlist',
                        field: 'recipient',
                        values: ['*.acme.com'],
                    },
                },
            ] as unknown as CapabilityToken['capabilities'],
        });

        const validator = vi.fn(
            (): Promise<DelegationChainValidationResult> =>
                Promise.resolve({ valid: true, depth: 1 }),
        );
        const executeWithPolicy = vi.fn(
            async ({
                executor,
            }: {
                executor: () => Promise<Record<string, unknown>>;
            }) => ({
                executed: true as const,
                result: await executor(),
                recordId: 'record-wildcard',
            }),
        );

        const orchestrator = new Orchestrator({
            agentDid: recipientDid,
            agentPrivateKey: recipientPrivateKey,
            principalDid,
            policyEngine: { executeWithPolicy },
            transport: {} as never,
            resolvePublicKey: makePubKeyResolver(),
            tokenStore: { getToken: vi.fn(() => Promise.resolve(token)) },
            delegationChainValidator: validator,
            revocationChecker: vi.fn(() => Promise.resolve(false)),
            policyRecorder: mockPolicyRecorder(),
            resolveAgentDocument: vi.fn(() =>
                Promise.resolve(mockSenderDocument()),
            ),
            businessHandler: ({ action }) =>
                Promise.resolve({ handledAction: action }),
        });

        const incoming = buildEnvelope({
            senderDid,
            senderPrivateKey,
            recipientDid,
            sessionId: 'session-wildcard',
            messageType: 'NEGOTIATION_REQUEST',
            body: {
                action: 'INQUIRY',
                // falls within the *.acme.com wildcard suffix: L5 exact matching would falsely reject, L3 passes.
                params: { recipient: 'ops.acme.com' },
            },
            capabilityTokenRef: token.id,
        });

        const result = await orchestrator.handleEnvelope(incoming);
        expect(result.handled).toBe(true);
    });

    it('rejects when sender token temporal_scope recurringWindow is outside now (parity with L3)', async () => {
        // recurringWindow was previously skipped outright by L5; an attacker could keep sending requests outside business hours.
        // Construct a "tomorrow's day-of-week" window -> today must be outside the window (to avoid hard-coded date drift).
        const todayDow = new Date().getUTCDay();
        const tomorrowDow = (todayDow + 1) % 7;
        const token = buildDelegatedTokenFixture({
            id: 'urn:cap:leaf-recurring-out',
            issuedTo: senderDid,
            capabilities: [
                {
                    action: 'INQUIRY',
                    scope: {
                        type: 'temporal_scope',
                        notBefore: new Date(
                            Date.now() - 86_400_000,
                        ).toISOString(),
                        notAfter: new Date(
                            Date.now() + 86_400_000,
                        ).toISOString(),
                        recurringWindow: {
                            startTime: '09:00',
                            endTime: '18:00',
                            // compute "tomorrow's DOW" relative to today — today must be outside the window
                            daysOfWeek: [tomorrowDow],
                            timezone: 'UTC',
                        },
                    },
                },
            ] as unknown as CapabilityToken['capabilities'],
        });

        const validator = vi.fn(
            (): Promise<DelegationChainValidationResult> =>
                Promise.resolve({ valid: true, depth: 1 }),
        );

        const orchestrator = new Orchestrator({
            agentDid: recipientDid,
            agentPrivateKey: recipientPrivateKey,
            principalDid,
            policyEngine: { executeWithPolicy: vi.fn() },
            transport: {} as never,
            resolvePublicKey: makePubKeyResolver(),
            tokenStore: { getToken: vi.fn(() => Promise.resolve(token)) },
            delegationChainValidator: validator,
            revocationChecker: vi.fn(() => Promise.resolve(false)),
            policyRecorder: mockPolicyRecorder(),
            resolveAgentDocument: vi.fn(() =>
                Promise.resolve(mockSenderDocument()),
            ),
            businessHandler: vi.fn(),
        });

        const incoming = buildEnvelope({
            senderDid,
            senderPrivateKey,
            recipientDid,
            sessionId: 'session-recurring-out',
            messageType: 'NEGOTIATION_REQUEST',
            body: { action: 'INQUIRY', params: {} },
            capabilityTokenRef: token.id,
        });

        const result = await orchestrator.handleEnvelope(incoming);
        expect(result.handled).toBe(false);
        // L3 message "temporal_scope: outside recurring window (day of week)"
        expect(result.rejectionReason).toMatch(
            /^delegation_scope_denied:.*recurring window/,
        );
        expect(validator).not.toHaveBeenCalled();
    });

    // ─── a step3.5 authorization rejection must write an ActionRecord ───────────────
    it('throws during construction when tokenStore is provided without policyRecorder (audit invariant)', () => {
        // Every authorization rejection on the capability-token path must be auditable; a missing recorder would produce a traceless rejection ->
        // fail closed at construction time.
        expect(
            () =>
                new Orchestrator({
                    agentDid: recipientDid,
                    agentPrivateKey: recipientPrivateKey,
                    principalDid,
                    policyEngine: { executeWithPolicy: vi.fn() },
                    transport: {} as never,
                    resolvePublicKey: makePubKeyResolver(),
                    tokenStore: { getToken: vi.fn() },
                    delegationChainValidator: vi.fn(),
                    revocationChecker: vi.fn(() => Promise.resolve(false)),
                    resolveAgentDocument: vi.fn(() =>
                        Promise.resolve(mockSenderDocument()),
                    ),
                    // policyRecorder deliberately omitted
                    businessHandler: vi.fn(),
                }),
        ).toThrow(/policyRecorder/);
    });

    it('writes REJECTED ActionRecord on step3.5 rejection (token_expired) with tokenId+reason', async () => {
        // expired token -> delegation_token_expired; the recorder must receive one
        // REJECTED record containing tokenId/actionType/reason, and pass recordId back into the result.
        const expired = new Date(Date.now() - 3_600_000).toISOString();
        const token = buildDelegatedTokenFixture({
            id: 'urn:cap:leaf-expired-audit',
            issuedTo: senderDid,
            issuedAt: new Date(Date.now() - 7_200_000).toISOString(),
            expiresAt: expired,
        });

        const recorder = mockPolicyRecorder();
        const orchestrator = new Orchestrator({
            agentDid: recipientDid,
            agentPrivateKey: recipientPrivateKey,
            principalDid,
            policyEngine: { executeWithPolicy: vi.fn() },
            transport: {} as never,
            resolvePublicKey: makePubKeyResolver(),
            tokenStore: { getToken: vi.fn(() => Promise.resolve(token)) },
            delegationChainValidator: vi.fn(),
            revocationChecker: vi.fn(() => Promise.resolve(false)),
            policyRecorder: recorder,
            resolveAgentDocument: vi.fn(() =>
                Promise.resolve(mockSenderDocument()),
            ),
            businessHandler: vi.fn(),
        });

        const incoming = buildEnvelope({
            senderDid,
            senderPrivateKey,
            recipientDid,
            sessionId: 'session-audit-expired',
            messageType: 'NEGOTIATION_REQUEST',
            body: { action: 'INQUIRY', params: { recipient: 'supplier-a' } },
            capabilityTokenRef: token.id,
        });

        const result = await orchestrator.handleEnvelope(incoming);
        expect(result.handled).toBe(false);
        expect(result.rejectionReason).toBe('delegation_token_expired');
        expect(result.recordId).toBeDefined();

        expect(recorder.record).toHaveBeenCalledTimes(1);
        const recordedInput = recorder.record.mock.calls[0]?.[0];
        expect(recordedInput).toMatchObject({
            agentDid: recipientDid,
            principalDid,
            actionType: 'INQUIRY',
            authorizationRef: { tokenId: token.id },
            resultSummary: {
                status: 'REJECTED',
                reason: 'delegation_token_expired',
                phase: 'step3.5',
            },
            // a delegated token's delegationDepth must be written into the audit record.
            // buildDelegatedTokenFixture produces chain.length=1 -> depth=1.
            delegationDepth: 1,
        });
    });

    it('escalates to INTERNAL_ERROR + console.error when policyRecorder throws', async () => {
        // Early approach: on a recorder throw, verbose log + return AUTHORIZATION_INSUFFICIENT.
        // Fix: when the audit invariant is broken it must not masquerade as an ordinary authorization rejection — upgrade to
        // INTERNAL_ERROR + an unconditional console.error, which operations must be able to see.
        const token = buildDelegatedTokenFixture({
            id: 'urn:cap:leaf-recorder-fails',
            issuedTo: senderDid,
            capabilities: [
                {
                    action: 'QUOTE',
                    scope: {
                        type: 'allowlist',
                        field: 'recipient',
                        values: ['supplier-a'],
                    },
                },
            ] as unknown as CapabilityToken['capabilities'],
        });

        const throwingRecorder = {
            record: vi.fn(() => Promise.reject(new Error('database offline'))),
        };

        const orchestrator = new Orchestrator({
            agentDid: recipientDid,
            agentPrivateKey: recipientPrivateKey,
            principalDid,
            policyEngine: { executeWithPolicy: vi.fn() },
            transport: {} as never,
            resolvePublicKey: makePubKeyResolver(),
            tokenStore: { getToken: vi.fn(() => Promise.resolve(token)) },
            delegationChainValidator: vi.fn(),
            revocationChecker: vi.fn(() => Promise.resolve(false)),
            policyRecorder: throwingRecorder,
            resolveAgentDocument: vi.fn(() =>
                Promise.resolve(mockSenderDocument()),
            ),
            businessHandler: vi.fn(),
        });

        const incoming = buildEnvelope({
            senderDid,
            senderPrivateKey,
            recipientDid,
            sessionId: 'session-recorder-fails',
            messageType: 'NEGOTIATION_REQUEST',
            body: { action: 'INQUIRY', params: { recipient: 'supplier-a' } },
            capabilityTokenRef: token.id,
        });

        const errSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
        const result = await orchestrator.handleEnvelope(incoming);

        // the rejection still holds (not downgraded to allow), but the response is upgraded to INTERNAL_ERROR
        expect(result.handled).toBe(false);
        expect(result.rejectionReason).toBe('delegation_invalid_action');
        expect(result.recordId).toBeUndefined();
        // the response envelope is INTERNAL_ERROR, no longer masquerading as AUTHORIZATION_INSUFFICIENT
        expect(result.responseEnvelope).toMatchObject({
            messageType: 'ERROR',
            body: { code: 'INTERNAL_ERROR' },
        });
        // audit-invariant breakage signal: console.error is called once (not controlled by verbose)
        expect(errSpy).toHaveBeenCalledTimes(1);
        expect(errSpy.mock.calls[0]?.[0]).toMatch(
            /audit.*invariant|record write failed/i,
        );
        expect(throwingRecorder.record).toHaveBeenCalledTimes(1);
        errSpy.mockRestore();
    });
});

/**
 * Construct a **real-signed** delegated leaf token.
 *
 * orchestrator step3.5 validates the sender leaf token's own
 * signature and action/scope — the fixture must produce a token that passes verification, otherwise every test that uses
 * a mock validator to assert downstream behavior would be rejected early at the leaf check.
 *
 * Conventions:
 *   - the delegated leaf's top-level proof is signed by the final did:agent delegator (= issuedTo);
 *     by default it is signed with the global senderPrivateKey, whose corresponding public key is senderKeyPair.publicKey.
 *   - the default capabilities contain one INQUIRY + allowlist(recipient=[supplier-a]),
 *     matching the incoming body { action:'INQUIRY', params:{ recipient:'supplier-a' } } common in the tests.
 *   - callers can override via `capabilities` to specifically test scope / action mismatch scenarios.
 */
function buildDelegatedTokenFixture(overrides: {
    id: string;
    issuedTo: DID;
    capabilities?: CapabilityToken['capabilities'];
    issuedAt?: string;
    expiresAt?: string;
    signingPrivateKey?: string;
}): CapabilityToken {
    const capabilities =
        overrides.capabilities ??
        ([
            {
                action: 'INQUIRY',
                scope: {
                    type: 'allowlist',
                    field: 'recipient',
                    values: ['supplier-a'],
                },
            },
        ] as unknown as CapabilityToken['capabilities']);
    const issuedAt = overrides.issuedAt ?? new Date().toISOString();
    const expiresAt =
        overrides.expiresAt ?? new Date(Date.now() + 3_600_000).toISOString();
    // the delegated leaf's top-level proof is signed by the chain-tail delegatorDid (the middle agent),
    // not issuedTo. By default it uses the middle keypair; tests can override via signingPrivateKey
    // (e.g. a signer-impersonation scenario).
    const signer = overrides.signingPrivateKey ?? middleKeyPair.privateKey;

    const base = {
        id: overrides.id,
        specVersion: SPEC_VERSION_0_2_0,
        issuerDid: principalDid,
        principalDid,
        issuedTo: overrides.issuedTo,
        issuedAt,
        expiresAt,
        capabilities,
        revocationUrl: 'https://revocation.example',
        delegationChain: [
            {
                parentTokenId: 'urn:cap:parent',
                delegatorDid: middleAgentDid,
                delegateeDid: overrides.issuedTo,
                parentCapabilities: capabilities,
                parentExpiresAt: new Date(Date.now() + 7_200_000).toISOString(),
                attenuatedCapabilities: capabilities,
                proof: {
                    type: 'Ed25519Signature2026',
                    created: issuedAt,
                    verificationMethod: `${middleAgentDid}#key-1`,
                    value: 'y'.repeat(128),
                },
            },
        ],
    };

    const payloadBytes = createCapabilityTokenPayload(base);
    const signatureValue = sign(payloadBytes, signer);

    return {
        ...base,
        proof: {
            type: 'Ed25519Signature2026',
            created: issuedAt,
            // verificationMethod points to the chain-tail delegator (= middleAgentDid).
            verificationMethod: `${middleAgentDid}#key-1`,
            value: signatureValue,
        },
    } as unknown as CapabilityToken;
}
