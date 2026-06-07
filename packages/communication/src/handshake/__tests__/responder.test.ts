import { randomUUID } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import { generateKeyPair } from '@coivitas/crypto';
import {
    createAgentIdentity,
    didKeyFromPublicKey,
} from '@coivitas/identity';
import type { DID, Signature } from '@coivitas/types';

import { buildEnvelope, verifyEnvelope } from '../../envelope.js';
import { InMemorySessionStore } from '../../session/in-memory-store.js';
import type { SessionStore } from '../../session/types.js';
import { HandshakeResponder } from '../responder.js';
import type { HandshakeAckBody, NonceStore } from '../types.js';

function createParties() {
    const principal = generateKeyPair();
    const principalDid = didKeyFromPublicKey(
        Buffer.from(principal.publicKey, 'hex'),
    );
    const initiator = createAgentIdentity({
        principalDid,
        principalPrivateKey: principal.privateKey,
        capabilities: ['INQUIRY', 'QUOTE'],
    });
    const responder = createAgentIdentity({
        principalDid,
        principalPrivateKey: principal.privateKey,
        capabilities: ['QUOTE', 'CONFIRM'],
    });

    return { initiator, responder };
}

describe('HandshakeResponder', () => {
    it('should return HANDSHAKE_ACK with accepted=true and record last result when init is valid', async () => {
        const { initiator, responder } = createParties();
        const challengeEnvelope = buildEnvelope({
            senderDid: initiator.document.id,
            senderPrivateKey: initiator.privateKey,
            recipientDid: responder.document.id,
            sessionId: null,
            messageType: 'HANDSHAKE_INIT',
            body: {
                challenge: {
                    challengeId: randomUUID(),
                    initiatorDid: initiator.document.id,
                    responderDid: responder.document.id,
                    nonce: 'a'.repeat(64),
                    timestamp: new Date().toISOString(),
                    expiresAt: new Date(Date.now() + 60_000).toISOString(),
                    initiatorCapabilities: ['INQUIRY', 'QUOTE'],
                },
            },
        });

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
            capabilities: ['QUOTE', 'CONFIRM'],
        });

        const ack = await handshake.respond(challengeEnvelope);
        const ackBody = ack.body as unknown as HandshakeAckBody;
        const response = ackBody.response;

        expect(ack.messageType).toBe('HANDSHAKE_ACK');
        expect(ack.header.sessionId).toBe(response.sessionId);
        expect(ackBody.accepted).toBe(true);
        expect(response.responderCapabilities).toEqual(['QUOTE']);
        expect(handshake.getLastHandshakeResult()).toEqual({
            sessionId: response.sessionId,
            negotiatedCapabilities: ['QUOTE'],
        });

        await expect(
            verifyEnvelope(ack, {
                resolvePublicKey: (did) =>
                    Promise.resolve(
                        did === responder.document.id
                            ? responder.document.publicKey
                            : null,
                    ),
                now: () => new Date(ack.timestamp).getTime(),
            }),
        ).resolves.toEqual({ valid: true });
    });

    it('should return accepted=false without throwing when challenge is expired or replayed', async () => {
        const { initiator, responder } = createParties();
        const handshake = new HandshakeResponder({
            responderDid: responder.document.id,
            responderPrivateKey: responder.privateKey,
            verifyInitiator: () => Promise.resolve(true),
            resolvePublicKey: () =>
                Promise.resolve(initiator.document.publicKey),
            capabilities: ['QUOTE'],
            nonceStore: {
                claim: (nonce: string) => Promise.resolve(nonce !== 'b'.repeat(64)),
            } satisfies NonceStore,
        });

        const expired = buildEnvelope({
            senderDid: initiator.document.id,
            senderPrivateKey: initiator.privateKey,
            recipientDid: responder.document.id,
            sessionId: null,
            messageType: 'HANDSHAKE_INIT',
            body: {
                challenge: {
                    challengeId: randomUUID(),
                    initiatorDid: initiator.document.id,
                    responderDid: responder.document.id,
                    nonce: 'c'.repeat(64),
                    timestamp: new Date(Date.now() - 120_000).toISOString(),
                    expiresAt: new Date(Date.now() - 60_000).toISOString(),
                    initiatorCapabilities: ['QUOTE'],
                },
            },
        });

        const replayed = buildEnvelope({
            senderDid: initiator.document.id,
            senderPrivateKey: initiator.privateKey,
            recipientDid: responder.document.id,
            sessionId: null,
            messageType: 'HANDSHAKE_INIT',
            body: {
                challenge: {
                    challengeId: randomUUID(),
                    initiatorDid: initiator.document.id,
                    responderDid: responder.document.id,
                    nonce: 'b'.repeat(64),
                    timestamp: new Date().toISOString(),
                    expiresAt: new Date(Date.now() + 60_000).toISOString(),
                    initiatorCapabilities: ['QUOTE'],
                },
            },
        });

        const expiredAck = await handshake.respond(expired);
        const expiredBody = expiredAck.body as unknown as HandshakeAckBody;
        expect(expiredAck.messageType).toBe('HANDSHAKE_ACK');
        expect(expiredBody.accepted).toBe(false);
        expect(expiredBody.reason).toBe('Challenge expired');

        const replayedAck = await handshake.respond(replayed);
        const replayedBody = replayedAck.body as unknown as HandshakeAckBody;
        expect(replayedAck.messageType).toBe('HANDSHAKE_ACK');
        expect(replayedBody.accepted).toBe(false);
        expect(replayedBody.reason).toBe('Duplicate nonce (suspected replay attack)');
    });

    it('should throw ProtocolError when signature is invalid or challenge metadata is inconsistent', async () => {
        const { initiator, responder } = createParties();
        const handshake = new HandshakeResponder({
            responderDid: responder.document.id,
            responderPrivateKey: responder.privateKey,
            verifyInitiator: () => Promise.resolve(true),
            resolvePublicKey: () =>
                Promise.resolve(initiator.document.publicKey),
            capabilities: ['QUOTE'],
        });

        const invalidSignature = {
            ...buildEnvelope({
                senderDid: initiator.document.id,
                senderPrivateKey: initiator.privateKey,
                recipientDid: responder.document.id,
                sessionId: null,
                messageType: 'HANDSHAKE_INIT',
                body: {
                    challenge: {
                        challengeId: randomUUID(),
                        initiatorDid: initiator.document.id,
                        responderDid: responder.document.id,
                        nonce: 'd'.repeat(64),
                        timestamp: new Date().toISOString(),
                        expiresAt: new Date(Date.now() + 60_000).toISOString(),
                        initiatorCapabilities: ['QUOTE'],
                    },
                },
            }),
            signature: 'f'.repeat(128) as Signature,
        };

        await expect(handshake.respond(invalidSignature)).rejects.toMatchObject(
            {
                name: 'ProtocolError',
                code: 'SIGNATURE_INVALID',
            },
        );

        const inconsistent = buildEnvelope({
            senderDid: initiator.document.id,
            senderPrivateKey: initiator.privateKey,
            recipientDid: responder.document.id,
            sessionId: null,
            messageType: 'HANDSHAKE_INIT',
            body: {
                challenge: {
                    challengeId: randomUUID(),
                    initiatorDid: responder.document.id,
                    responderDid: responder.document.id,
                    nonce: 'e'.repeat(64),
                    timestamp: new Date().toISOString(),
                    expiresAt: new Date(Date.now() + 60_000).toISOString(),
                    initiatorCapabilities: ['QUOTE'],
                },
            },
        });

        await expect(handshake.respond(inconsistent)).rejects.toMatchObject({
            name: 'ProtocolError',
            code: 'INVALID_HANDSHAKE',
        });
    });
});

function buildChallenge(
    initiator: ReturnType<typeof createParties>['initiator'],
    responderDid: DID,
    caps: string[],
) {
    return buildEnvelope({
        senderDid: initiator.document.id,
        senderPrivateKey: initiator.privateKey,
        recipientDid: responderDid,
        sessionId: null,
        messageType: 'HANDSHAKE_INIT',
        body: {
            challenge: {
                challengeId: randomUUID(),
                initiatorDid: initiator.document.id,
                responderDid,
                nonce:
                    crypto.randomUUID().replace(/-/g, '') +
                    crypto.randomUUID().replace(/-/g, ''),
                timestamp: new Date().toISOString(),
                expiresAt: new Date(Date.now() + 60_000).toISOString(),
                initiatorCapabilities: caps,
            },
        },
    });
}

describe('HandshakeResponder: sessionStore + authorizationValidator', () => {
    it('should persist ACTIVE session to store when sessionStore is injected and handshake succeeds', async () => {
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
            capabilities: ['QUOTE'],
            sessionStore: store,
        });

        const challengeEnvelope = buildChallenge(
            initiator,
            responder.document.id,
            ['QUOTE'],
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
        expect(session!.negotiatedCapabilities).toEqual(['QUOTE']);
    });

    it('should return accepted=false when authorizationValidator rejects', async () => {
        const { initiator, responder } = createParties();
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
            capabilities: ['QUOTE'],
            authorizationValidator: {
                validate: () => Promise.resolve({ accepted: false, reason: 'Token revoked' }),
            },
        });

        const challengeEnvelope = buildChallenge(
            initiator,
            responder.document.id,
            ['QUOTE'],
        );
        const ack = await handshake.respond(challengeEnvelope);
        const ackBody = ack.body as unknown as HandshakeAckBody;
        expect(ackBody.accepted).toBe(false);
        expect(ackBody.reason).toBe('Authorization validation failed');
    });

    it('should return accepted=false with persistence failure reason when store throws', async () => {
        const { initiator, responder } = createParties();
        const brokenStore = {
            create: () => Promise.reject(new Error('DB connection failed')),
            get: () => Promise.resolve(null),
            update: () => Promise.reject(new Error()),
            resume: () => Promise.reject(new Error()),
            supersedeAndCreate: () => Promise.reject(new Error()),
            claimForDispatch: () => Promise.reject(new Error()),
            markAuthorized: () => Promise.reject(new Error()),
            closeByToken: () => Promise.resolve([]),
            closeByPrincipal: () => Promise.resolve([]),
            listActive: () => Promise.resolve([]),
            cleanExpired: () => Promise.resolve({
                markedStale: 0,
                markedIdle: 0,
                markedClosed: 0,
            }),
        };
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
            capabilities: ['QUOTE'],
            sessionStore: brokenStore as unknown as SessionStore,
        });

        const challengeEnvelope = buildChallenge(
            initiator,
            responder.document.id,
            ['QUOTE'],
        );
        const ack = await handshake.respond(challengeEnvelope);
        const ackBody = ack.body as unknown as HandshakeAckBody;
        expect(ackBody.accepted).toBe(false);
        expect(ackBody.reason).toBe('Session persistence failed');
    });
});
