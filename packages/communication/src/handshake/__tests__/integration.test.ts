import { afterEach, describe, expect, it, vi } from 'vitest';

import { generateKeyPair } from '@coivitas/crypto';
import {
    createAgentIdentity,
    didKeyFromPublicKey,
} from '@coivitas/identity';

import { buildEnvelope } from '../../envelope.js';
import { InMemorySessionStore } from '../../session/in-memory-store.js';
import { SessionManager } from '../../session/session-manager.js';
import { HandshakeInitiator } from '../initiator.js';
import { HandshakeResponder } from '../responder.js';
import { HttpTransport } from '../../transport/http.js';
import type { HandshakeAckBody } from '../types.js';

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

function createParties() {
    const initiatorKey = generateKeyPair();
    const initiatorDid = didKeyFromPublicKey(
        Buffer.from(initiatorKey.publicKey, 'hex'),
    );
    const initiator = createAgentIdentity({
        principalDid: initiatorDid,
        principalPrivateKey: initiatorKey.privateKey,
        capabilities: ['INQUIRY', 'QUOTE'],
    });

    const responderKey = generateKeyPair();
    const responderDid = didKeyFromPublicKey(
        Buffer.from(responderKey.publicKey, 'hex'),
    );
    const responder = createAgentIdentity({
        principalDid: responderDid,
        principalPrivateKey: responderKey.privateKey,
        capabilities: ['QUOTE', 'CONFIRM'],
    });

    return { initiator, responder };
}

function buildChallengeEnvelope(
    initiator: ReturnType<typeof createParties>['initiator'],
    responderDid: string,
    initiatorCaps: string[],
) {
    return buildEnvelope({
        senderDid: initiator.document.id,
        senderPrivateKey: initiator.privateKey,
        recipientDid: responderDid,
        sessionId: null,
        messageType: 'HANDSHAKE_INIT',
        body: {
            challenge: {
                challengeId: crypto.randomUUID(),
                initiatorDid: initiator.document.id,
                responderDid,
                nonce:
                    crypto.randomUUID().replace(/-/g, '') +
                    crypto.randomUUID().replace(/-/g, ''),
                timestamp: new Date().toISOString(),
                expiresAt: new Date(Date.now() + 60_000).toISOString(),
                initiatorCapabilities: initiatorCaps,
            },
        },
    });
}

// ---------------------------------------------------------------------------
// Existing HTTP transport integration test (requires ENABLE_SOCKET_TESTS=1)
// ---------------------------------------------------------------------------

const describeIfSockets =
    process.env.ENABLE_SOCKET_TESTS === '1' ? describe : describe.skip;

describeIfSockets('handshake integration', () => {
    const transports: HttpTransport[] = [];

    afterEach(async () => {
        await Promise.all(
            transports.splice(0).map(async (transport) => transport.close()),
        );
    });

    it('completes a full HTTP handshake between two agents', async () => {
        const principal = generateKeyPair();
        const principalDid = didKeyFromPublicKey(
            Buffer.from(principal.publicKey, 'hex'),
        );
        const initiatorIdentity = createAgentIdentity({
            principalDid,
            principalPrivateKey: principal.privateKey,
            capabilities: ['INQUIRY', 'QUOTE'],
        });
        const responderIdentity = createAgentIdentity({
            principalDid,
            principalPrivateKey: principal.privateKey,
            capabilities: ['QUOTE', 'CONFIRM'],
        });

        const serverTransport = new HttpTransport();
        transports.push(serverTransport);
        const responder = new HandshakeResponder({
            responderDid: responderIdentity.document.id,
            responderPrivateKey: responderIdentity.privateKey,
            verifyInitiator: () => Promise.resolve(true),
            resolvePublicKey: (did) =>
                Promise.resolve(
                    did === initiatorIdentity.document.id
                        ? initiatorIdentity.document.publicKey
                        : did === responderIdentity.document.id
                          ? responderIdentity.document.publicKey
                          : null,
                ),
            capabilities: ['QUOTE', 'CONFIRM'],
        });

        const port = await serverTransport.listen(
            0,
            async (envelope) => await responder.respond(envelope),
        );

        const clientTransport = new HttpTransport();
        const initiator = new HandshakeInitiator({
            initiatorDid: initiatorIdentity.document.id,
            initiatorPrivateKey: initiatorIdentity.privateKey,
            transport: clientTransport,
            resolvePublicKey: (did) =>
                Promise.resolve(
                    did === responderIdentity.document.id
                        ? responderIdentity.document.publicKey
                        : did === initiatorIdentity.document.id
                          ? initiatorIdentity.document.publicKey
                          : null,
                ),
            capabilities: ['INQUIRY', 'QUOTE'],
        });

        const result = await initiator.initiate({
            responderDid: responderIdentity.document.id,
            responderEndpoint: `http://127.0.0.1:${port}`,
        });

        expect(result.negotiatedCapabilities).toEqual(['QUOTE']);
        expect(result.sessionId).toEqual(expect.any(String));
    });
});

// ---------------------------------------------------------------------------
// Test 1: Handshake → ACTIVE session persisted
// ---------------------------------------------------------------------------

describe('Integration: Handshake → ACTIVE session persisted', () => {
    it('should persist ACTIVE session with correct negotiatedCapabilities when handshake succeeds', async () => {
        const { initiator, responder } = createParties();
        const store = new InMemorySessionStore();

        const handshake = new HandshakeResponder({
            responderDid: responder.document.id,
            responderPrivateKey: responder.privateKey,
            verifyInitiator: () => Promise.resolve(true),
            resolvePublicKey: (did) =>
                Promise.resolve(
                    did === initiator.document.id
                        ? initiator.document.publicKey
                        : null,
                ),
            // initiator provides ['INQUIRY','QUOTE'], responder provides ['QUOTE','CONFIRM']
            // intersection = ['QUOTE']
            capabilities: ['QUOTE', 'CONFIRM'],
            sessionStore: store,
        });

        const challengeEnvelope = buildChallengeEnvelope(
            initiator,
            responder.document.id,
            ['INQUIRY', 'QUOTE'],
        );

        const ack = await handshake.respond(challengeEnvelope);
        const ackBody = ack.body as unknown as HandshakeAckBody;

        expect(ackBody.accepted).toBe(true);

        const sessionId = ackBody.response.sessionId;
        const session = await store.get(sessionId);

        expect(session).not.toBeNull();
        expect(session!.state).toBe('ACTIVE');
        expect(session!.initiatorDid).toBe(initiator.document.id);
        expect(session!.responderDid).toBe(responder.document.id);
        // Intersection: initiator=['INQUIRY','QUOTE'] ∩ responder=['QUOTE','CONFIRM'] = ['QUOTE']
        expect(session!.negotiatedCapabilities).toEqual(['QUOTE']);
    });
});

// ---------------------------------------------------------------------------
// Test 2: claimForDispatch → markAuthorized CAS chain
// ---------------------------------------------------------------------------

describe('Integration: claimForDispatch → markAuthorized CAS chain', () => {
    it('should increment revision on claim then authorize, and reject stale revision', async () => {
        const { initiator, responder } = createParties();
        const store = new InMemorySessionStore();

        // Create an ACTIVE session directly in the store, without going through the handshake flow
        const created = await store.create({
            sessionId: crypto.randomUUID(),
            initiatorDid: initiator.document.id,
            responderDid: responder.document.id,
            principalDid: initiator.document.id,
            negotiatedCapabilities: ['QUOTE'],
            initialState: 'ACTIVE',
        });

        expect(created.state).toBe('ACTIVE');
        const initialRevision = created.revision; // '1'

        // Step A: claimForDispatch → revision should increment from '1' to '2'
        const claimed = await store.claimForDispatch({
            sessionId: created.sessionId,
            senderDid: initiator.document.id,
            selfDid: responder.document.id,
        });

        expect(claimed.revision).toBe(String(parseInt(initialRevision, 10) + 1));
        const claimedRevision = claimed.revision; // '2'

        // Step B: markAuthorized with the correct expectedRevision → should succeed, revision increments to '3'
        const authorized = await store.markAuthorized({
            sessionId: created.sessionId,
            expectedRevision: claimedRevision,
        });

        expect(authorized.revision).toBe(String(parseInt(claimedRevision, 10) + 1));

        // Step C: call markAuthorized again with the stale revision (claimedRevision = '2') → should throw SESSION_STATE_INVALID
        await expect(
            store.markAuthorized({
                sessionId: created.sessionId,
                expectedRevision: claimedRevision, // stale revision
            }),
        ).rejects.toMatchObject({
            name: 'ProtocolError',
            code: 'SESSION_STATE_INVALID',
        });
    });
});

// ---------------------------------------------------------------------------
// Test 3: sweep → ACTIVE → IDLE → CLOSED
// ---------------------------------------------------------------------------

describe('Integration: sweep lifecycle ACTIVE → IDLE → CLOSED', () => {
    afterEach(() => {
        vi.useRealTimers();
    });

    it('should transition ACTIVE to IDLE after idleSoftMs and IDLE to CLOSED after idleHardMs', async () => {
        vi.useFakeTimers();

        const { initiator, responder } = createParties();
        const store = new InMemorySessionStore();
        const manager = new SessionManager({
            store,
            idleSoftMs: 1_000,
            idleHardMs: 5_000,
            createdTimeoutMs: 60_000,
        });

        // Create an ACTIVE session
        const session = await store.create({
            sessionId: crypto.randomUUID(),
            initiatorDid: initiator.document.id,
            responderDid: responder.document.id,
            principalDid: initiator.document.id,
            negotiatedCapabilities: ['QUOTE'],
            initialState: 'ACTIVE',
        });

        expect(session.state).toBe('ACTIVE');

        // Advance 1500ms (past idleSoftMs=1000ms)
        vi.advanceTimersByTime(1_500);

        // sweep: ACTIVE → IDLE
        const result1 = await manager.sweep();
        expect(result1.markedIdle).toBe(1);
        expect(result1.markedClosed).toBe(0);

        const afterIdle = await store.get(session.sessionId);
        expect(afterIdle!.state).toBe('IDLE');

        // Advance 6000ms (past idleHardMs=5000ms)
        vi.advanceTimersByTime(6_000);

        // sweep: IDLE → CLOSED (IDLE_TIMEOUT)
        const result2 = await manager.sweep();
        expect(result2.markedClosed).toBe(1);

        const afterClosed = await store.get(session.sessionId);
        expect(afterClosed!.state).toBe('CLOSED');
        expect(afterClosed!.closeReason).toBe('IDLE_TIMEOUT');
    });
});
