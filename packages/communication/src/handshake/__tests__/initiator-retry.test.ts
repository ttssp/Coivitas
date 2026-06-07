import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { generateKeyPair } from '@coivitas/crypto';
import {
    createAgentIdentity,
    didKeyFromPublicKey,
} from '@coivitas/identity';
import type { NegotiationEnvelope } from '@coivitas/types';

import { buildEnvelope } from '../../envelope.js';
import { HandshakeInitiator } from '../initiator.js';
import type { HandshakeChallenge } from '../types.js';

// Extract the challenge field from the INIT envelope and build a valid ACK for helper tests
function buildValidAck(
    initEnvelope: NegotiationEnvelope,
    responder: ReturnType<typeof createParties>['responder'],
    initiator: ReturnType<typeof createParties>['initiator'],
    sessionId = 'valid-session',
): NegotiationEnvelope {
    const challenge = initEnvelope.body['challenge'] as HandshakeChallenge;
    return buildEnvelope({
        senderDid: responder.document.id,
        senderPrivateKey: responder.privateKey,
        recipientDid: initiator.document.id,
        sessionId,
        messageType: 'HANDSHAKE_ACK',
        body: {
            accepted: true,
            response: {
                challengeId: challenge.challengeId,
                sessionId,
                responderDid: responder.document.id,
                responderCapabilities: ['INQUIRY'],
                nonce: challenge.nonce,
                timestamp: new Date().toISOString(),
            },
        },
    });
}

function createParties() {
    const kp = generateKeyPair();
    const did = didKeyFromPublicKey(Buffer.from(kp.publicKey, 'hex'));
    const initiator = createAgentIdentity({
        principalDid: did,
        principalPrivateKey: kp.privateKey,
        capabilities: ['INQUIRY'],
    });
    const responder = createAgentIdentity({
        principalDid: did,
        principalPrivateKey: kp.privateKey,
        capabilities: ['INQUIRY', 'QUOTE'],
    });
    return { initiator, responder };
}

describe('HandshakeInitiator — retry & cleanup', () => {
    beforeEach(() => {
        vi.useFakeTimers();
    });

    afterEach(() => {
        vi.useRealTimers();
    });

    it('should retry after timeout and succeed on second attempt', async () => {
        const { initiator, responder } = createParties();
        let callCount = 0;
        // Save the first INIT envelope so the second call can build the ACK
        let firstEnvelope: NegotiationEnvelope | undefined;

        const transport = {
            send: vi.fn().mockImplementation(async (envelope: NegotiationEnvelope) => {
                callCount++;
                if (callCount === 1) {
                    firstEnvelope = envelope;
                    // First call: return a never-resolving Promise so the initiator's timeout fires
                    return new Promise<NegotiationEnvelope | null>(() => {
                        // Deliberately never resolve — after the fake timer advances, the timeout wins the race
                    });
                }
                // Second call: immediately return a valid ACK
                return buildValidAck(envelope, responder, initiator, 'retry-session');
            }),
            listen: vi.fn(),
            close: vi.fn(),
        };

        const handshake = new HandshakeInitiator({
            initiatorDid: initiator.document.id,
            initiatorPrivateKey: initiator.privateKey,
            transport,
            resolvePublicKey: () => Promise.resolve(responder.document.publicKey),
            capabilities: ['INQUIRY'],
            maxRetries: 2,
        });

        const resultPromise = handshake.initiate({
            responderDid: responder.document.id,
            responderEndpoint: 'http://peer/handshake',
            timeoutMs: 30,
        });

        // Advance the fake clock past timeoutMs to trigger the first timeout
        await vi.advanceTimersByTimeAsync(31);
        // Drain the microtask queue so the second send completes
        await vi.advanceTimersByTimeAsync(0);

        const result = await resultPromise;
        expect(result.sessionId).toBe('retry-session');
        expect(transport.send).toHaveBeenCalledTimes(2);
        void firstEnvelope; // Explicitly mark as used
    });

    it('should throw HANDSHAKE_TIMEOUT when all retries exhausted', async () => {
        const { initiator, responder } = createParties();

        const transport = {
            send: vi.fn().mockImplementation(
                () => new Promise<NegotiationEnvelope | null>(() => {
                    // Never resolve
                }),
            ),
            listen: vi.fn(),
            close: vi.fn(),
        };

        const handshake = new HandshakeInitiator({
            initiatorDid: initiator.document.id,
            initiatorPrivateKey: initiator.privateKey,
            transport,
            resolvePublicKey: () => Promise.resolve(responder.document.publicKey),
            capabilities: [],
            maxRetries: 1,
        });

        // Attach the rejects expectation before advancing the clock, to avoid initiate() rejecting first and causing an UnhandledRejection
        const assertion = expect(
            handshake.initiate({
                responderDid: responder.document.id,
                responderEndpoint: 'http://peer/handshake',
                timeoutMs: 30,
            }),
        ).rejects.toMatchObject({
            name: 'ProtocolError',
            code: 'HANDSHAKE_TIMEOUT',
        });

        // First timeout
        await vi.advanceTimersByTimeAsync(31);
        // Second (retry) timeout
        await vi.advanceTimersByTimeAsync(31);

        await assertion;

        // 1 initial + 1 retry = 2 calls
        expect(transport.send).toHaveBeenCalledTimes(2);
    });

    it('should clean up pending challenges after each attempt', async () => {
        const { initiator, responder } = createParties();

        const transport = {
            send: vi.fn().mockImplementation(
                () => new Promise<NegotiationEnvelope | null>(() => {
                    // Never resolve
                }),
            ),
            listen: vi.fn(),
            close: vi.fn(),
        };

        const handshake = new HandshakeInitiator({
            initiatorDid: initiator.document.id,
            initiatorPrivateKey: initiator.privateKey,
            transport,
            resolvePublicKey: () => Promise.resolve(responder.document.publicKey),
            capabilities: [],
            maxRetries: 0,
        });

        // Attach the rejects expectation before advancing the clock, to avoid an UnhandledRejection
        const assertion = expect(
            handshake.initiate({
                responderDid: responder.document.id,
                responderEndpoint: 'http://peer/handshake',
                timeoutMs: 20,
            }),
        ).rejects.toMatchObject({ code: 'HANDSHAKE_TIMEOUT' });

        await vi.advanceTimersByTimeAsync(21);
        await assertion;

        // After the finally-block cleanup, pendingChallenges should be empty
        // @ts-expect-error accessing internal test state
        expect(handshake.pendingChallenges.size).toBe(0);
    });

    it('should not retry on HANDSHAKE_REJECTED', async () => {
        const { initiator, responder } = createParties();

        const transport = {
            send: vi.fn().mockImplementation((envelope: NegotiationEnvelope) => {
                const challenge = envelope.body['challenge'] as HandshakeChallenge;
                return Promise.resolve(buildEnvelope({
                    senderDid: responder.document.id,
                    senderPrivateKey: responder.privateKey,
                    recipientDid: initiator.document.id,
                    sessionId: null,
                    messageType: 'HANDSHAKE_ACK',
                    body: {
                        accepted: false,
                        reason: 'Unauthorized',
                        response: {
                            challengeId: challenge.challengeId,
                            sessionId: '',
                            responderDid: responder.document.id,
                            responderCapabilities: [],
                            nonce: challenge.nonce,
                            timestamp: new Date().toISOString(),
                        },
                    },
                }));
            }),
            listen: vi.fn(),
            close: vi.fn(),
        };

        const handshake = new HandshakeInitiator({
            initiatorDid: initiator.document.id,
            initiatorPrivateKey: initiator.privateKey,
            transport,
            resolvePublicKey: () => Promise.resolve(responder.document.publicKey),
            capabilities: [],
            maxRetries: 2,
        });

        await expect(
            handshake.initiate({
                responderDid: responder.document.id,
                responderEndpoint: 'http://peer/handshake',
            }),
        ).rejects.toMatchObject({ code: 'HANDSHAKE_REJECTED' });

        // Rejection does not retry; sent only once
        expect(transport.send).toHaveBeenCalledTimes(1);
    });

    it('should throw INVALID_HANDSHAKE when ACK challengeId does not match', async () => {
        const { initiator, responder } = createParties();

        const transport = {
            send: vi.fn().mockImplementation((envelope: NegotiationEnvelope) => {
                // Intercept the INIT envelope, extract the nonce, and build an ACK with a tampered challengeId
                const challenge = envelope.body['challenge'] as HandshakeChallenge;
                return Promise.resolve(buildEnvelope({
                    senderDid: responder.document.id,
                    senderPrivateKey: responder.privateKey,
                    recipientDid: initiator.document.id,
                    sessionId: 'fake-session',
                    messageType: 'HANDSHAKE_ACK',
                    body: {
                        response: {
                            // Wrong challengeId (still UUID-shaped so it passes schema validation,
                            // allowing it to reach initiator.ts's challengeId-mismatch business gate)
                            challengeId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
                            sessionId: 'fake-session',
                            responderDid: responder.document.id,
                            responderCapabilities: [],
                            nonce: challenge.nonce, // Correct nonce, to ensure it does not error at the nonce check
                            timestamp: new Date().toISOString(),
                        },
                        accepted: true,
                    },
                }));
            }),
            listen: vi.fn(),
            close: vi.fn(),
        };

        const handshake = new HandshakeInitiator({
            initiatorDid: initiator.document.id,
            initiatorPrivateKey: initiator.privateKey,
            transport,
            resolvePublicKey: () => Promise.resolve(responder.document.publicKey),
            capabilities: ['INQUIRY'],
            maxRetries: 0,
        });

        await expect(
            handshake.initiate({
                responderDid: responder.document.id,
                responderEndpoint: 'http://peer/handshake',
            }),
        ).rejects.toMatchObject({
            name: 'ProtocolError',
            code: 'INVALID_HANDSHAKE',
        });
    });

    it('should throw INVALID_HANDSHAKE when ACK responderDid does not match', async () => {
        const { initiator, responder } = createParties();

        // A second identity used to tamper with responderDid. It must be a valid did:agent shape to pass the schema's
        // didAgent pattern (v0.4 option W: schema validates first, business-level mismatch checked afterward).
        const altKp = generateKeyPair();
        const altPrincipalDid = didKeyFromPublicKey(
            Buffer.from(altKp.publicKey, 'hex'),
        );
        const altIdentity = createAgentIdentity({
            principalDid: altPrincipalDid,
            principalPrivateKey: altKp.privateKey,
            capabilities: ['INQUIRY'],
        });
        const altDid = altIdentity.document.id;

        const transport = {
            send: vi.fn().mockImplementation((envelope: NegotiationEnvelope) => {
                // Intercept the INIT envelope, extract the nonce, and build an ACK with a tampered responderDid
                const challenge = envelope.body['challenge'] as HandshakeChallenge;
                return Promise.resolve(buildEnvelope({
                    senderDid: responder.document.id,
                    senderPrivateKey: responder.privateKey,
                    recipientDid: initiator.document.id,
                    sessionId: 'fake-session',
                    messageType: 'HANDSHAKE_ACK',
                    body: {
                        response: {
                            challengeId: challenge.challengeId, // Correct challengeId
                            sessionId: 'fake-session',
                            responderDid: altDid, // Wrong responderDid
                            responderCapabilities: [],
                            nonce: challenge.nonce, // Correct nonce
                            timestamp: new Date().toISOString(),
                        },
                        accepted: true,
                    },
                }));
            }),
            listen: vi.fn(),
            close: vi.fn(),
        };

        const handshake = new HandshakeInitiator({
            initiatorDid: initiator.document.id,
            initiatorPrivateKey: initiator.privateKey,
            transport,
            resolvePublicKey: () => Promise.resolve(responder.document.publicKey),
            capabilities: ['INQUIRY'],
            maxRetries: 0,
        });

        await expect(
            handshake.initiate({
                responderDid: responder.document.id,
                responderEndpoint: 'http://peer/handshake',
            }),
        ).rejects.toMatchObject({
            name: 'ProtocolError',
            code: 'INVALID_HANDSHAKE',
        });
    });

    it('should throw HANDSHAKE_REJECTED with default message when reason is absent', async () => {
        const { initiator, responder } = createParties();

        // accepted: false with no reason field, triggering the `?? 'Peer rejected the handshake'` default branch
        const transport = {
            send: vi.fn().mockImplementation((envelope: NegotiationEnvelope) => {
                const challenge = envelope.body['challenge'] as HandshakeChallenge;
                return Promise.resolve(buildEnvelope({
                    senderDid: responder.document.id,
                    senderPrivateKey: responder.privateKey,
                    recipientDid: initiator.document.id,
                    sessionId: null,
                    messageType: 'HANDSHAKE_ACK',
                    body: {
                        accepted: false,
                        // reason field deliberately omitted
                        response: {
                            challengeId: challenge.challengeId,
                            sessionId: '',
                            responderDid: responder.document.id,
                            responderCapabilities: [],
                            nonce: challenge.nonce,
                            timestamp: new Date().toISOString(),
                        },
                    },
                }));
            }),
            listen: vi.fn(),
            close: vi.fn(),
        };

        const handshake = new HandshakeInitiator({
            initiatorDid: initiator.document.id,
            initiatorPrivateKey: initiator.privateKey,
            transport,
            resolvePublicKey: () => Promise.resolve(responder.document.publicKey),
            capabilities: [],
            maxRetries: 0,
        });

        const error = await handshake
            .initiate({
                responderDid: responder.document.id,
                responderEndpoint: 'http://peer/handshake',
            })
            .catch((e: unknown) => e);

        expect(error).toMatchObject({
            name: 'ProtocolError',
            code: 'HANDSHAKE_REJECTED',
        });
        // The default detail should be 'Peer rejected the handshake'
        expect((error as { detail?: string }).detail).toBe('Peer rejected the handshake');
    });
});
