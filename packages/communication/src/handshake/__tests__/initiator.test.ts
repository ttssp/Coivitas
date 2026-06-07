import { describe, expect, it, vi } from 'vitest';

import { generateKeyPair } from '@coivitas/crypto';
import {
    createAgentIdentity,
    didKeyFromPublicKey,
} from '@coivitas/identity';
import type { NegotiationEnvelope } from '@coivitas/types';

import { buildEnvelope } from '../../envelope.js';
import { HandshakeInitiator } from '../initiator.js';

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

describe('HandshakeInitiator', () => {
    it('should complete handshake and intersect capabilities when initiator and responder have overlapping capabilities', async () => {
        const { initiator, responder } = createParties();

        const transport = {
            send: vi.fn((envelope: NegotiationEnvelope) => {
                const challenge = envelope.body['challenge'] as Record<
                    string,
                    unknown
                >;
                return Promise.resolve(
                    buildEnvelope({
                        senderDid: responder.document.id,
                        senderPrivateKey: responder.privateKey,
                        recipientDid: initiator.document.id,
                        sessionId: 'session-001',
                        messageType: 'HANDSHAKE_ACK',
                        body: {
                            accepted: true,
                            response: {
                                challengeId: challenge['challengeId'],
                                sessionId: 'session-001',
                                responderDid: responder.document.id,
                                responderCapabilities: ['QUOTE', 'CONFIRM'],
                                nonce: challenge['nonce'],
                                timestamp: new Date().toISOString(),
                            },
                        },
                    }),
                );
            }),
            listen: vi.fn(),
            close: vi.fn(),
        };

        const handshake = new HandshakeInitiator({
            initiatorDid: initiator.document.id,
            initiatorPrivateKey: initiator.privateKey,
            transport,
            resolvePublicKey: (did) =>
                Promise.resolve(
                    did === responder.document.id
                        ? responder.document.publicKey
                        : null,
                ),
            capabilities: ['INQUIRY', 'QUOTE'],
        });

        await expect(
            handshake.initiate({
                responderDid: responder.document.id,
                responderEndpoint: 'http://peer.example/handshake',
            }),
        ).resolves.toEqual({
            sessionId: 'session-001',
            negotiatedCapabilities: ['QUOTE'],
        });
    });

    it('should throw HANDSHAKE_REJECTED when responder rejects and INVALID_HANDSHAKE when nonce mismatches', async () => {
        const { initiator, responder } = createParties();
        const handshake = new HandshakeInitiator({
            initiatorDid: initiator.document.id,
            initiatorPrivateKey: initiator.privateKey,
            transport: {
                send: vi
                    .fn()
                    .mockImplementationOnce((envelope: NegotiationEnvelope) => {
                        const challenge = envelope.body['challenge'] as Record<
                            string,
                            unknown
                        >;
                        return Promise.resolve(
                            buildEnvelope({
                                senderDid: responder.document.id,
                                senderPrivateKey: responder.privateKey,
                                recipientDid: initiator.document.id,
                                sessionId: null,
                                messageType: 'HANDSHAKE_ACK',
                                body: {
                                    accepted: false,
                                    reason: 'Rejected',
                                    response: {
                                        challengeId: challenge['challengeId'],
                                        sessionId: '',
                                        responderDid: responder.document.id,
                                        responderCapabilities: [],
                                        nonce: challenge['nonce'],
                                        timestamp: new Date().toISOString(),
                                    },
                                },
                            }),
                        );
                    })
                    .mockImplementationOnce((envelope: NegotiationEnvelope) => {
                        const challenge = envelope.body['challenge'] as Record<
                            string,
                            unknown
                        >;
                        return Promise.resolve(
                            buildEnvelope({
                                senderDid: responder.document.id,
                                senderPrivateKey: responder.privateKey,
                                recipientDid: initiator.document.id,
                                sessionId: 'session-002',
                                messageType: 'HANDSHAKE_ACK',
                                body: {
                                    accepted: true,
                                    response: {
                                        challengeId: challenge['challengeId'],
                                        sessionId: 'session-002',
                                        responderDid: responder.document.id,
                                        responderCapabilities: ['QUOTE'],
                                        nonce: 'f'.repeat(64),
                                        timestamp: new Date().toISOString(),
                                    },
                                },
                            }),
                        );
                    }),
                listen: vi.fn(),
                close: vi.fn(),
            },
            resolvePublicKey: () =>
                Promise.resolve(responder.document.publicKey),
            capabilities: ['QUOTE'],
        });

        await expect(
            handshake.initiate({
                responderDid: responder.document.id,
                responderEndpoint: 'http://peer.example/handshake',
            }),
        ).rejects.toMatchObject({
            name: 'ProtocolError',
            code: 'HANDSHAKE_REJECTED',
        });

        await expect(
            handshake.initiate({
                responderDid: responder.document.id,
                responderEndpoint: 'http://peer.example/handshake',
            }),
        ).rejects.toMatchObject({
            name: 'ProtocolError',
            code: 'INVALID_HANDSHAKE',
        });
    });

    it('should throw SIGNATURE_INVALID for bad ACK signature and HANDSHAKE_TIMEOUT when transport stalls', async () => {
        const { initiator, responder } = createParties();
        const handshake = new HandshakeInitiator({
            initiatorDid: initiator.document.id,
            initiatorPrivateKey: initiator.privateKey,
            maxRetries: 0,
            transport: {
                send: vi
                    .fn()
                    .mockImplementationOnce((envelope: NegotiationEnvelope) => {
                        const challenge = envelope.body['challenge'] as Record<
                            string,
                            unknown
                        >;
                        return Promise.resolve({
                            ...buildEnvelope({
                                senderDid: responder.document.id,
                                senderPrivateKey: responder.privateKey,
                                recipientDid: initiator.document.id,
                                sessionId: 'session-003',
                                messageType: 'HANDSHAKE_ACK',
                                body: {
                                    accepted: true,
                                    response: {
                                        challengeId: challenge['challengeId'],
                                        sessionId: 'session-003',
                                        responderDid: responder.document.id,
                                        responderCapabilities: ['QUOTE'],
                                        nonce: challenge['nonce'],
                                        timestamp: new Date().toISOString(),
                                    },
                                },
                            }),
                            signature: '0'.repeat(128),
                        });
                    })
                    .mockImplementationOnce(
                        () =>
                            new Promise<never>(() => {
                                return undefined;
                            }),
                    ),
                listen: vi.fn(),
                close: vi.fn(),
            },
            resolvePublicKey: () =>
                Promise.resolve(responder.document.publicKey),
            capabilities: ['QUOTE'],
        });

        await expect(
            handshake.initiate({
                responderDid: responder.document.id,
                responderEndpoint: 'http://peer.example/handshake',
            }),
        ).rejects.toMatchObject({
            name: 'ProtocolError',
            code: 'SIGNATURE_INVALID',
        });

        await expect(
            handshake.initiate({
                responderDid: responder.document.id,
                responderEndpoint: 'http://peer.example/handshake',
                timeoutMs: 5,
            }),
        ).rejects.toMatchObject({
            name: 'ProtocolError',
            code: 'HANDSHAKE_TIMEOUT',
        });
    });

    it('should throw INVALID_HANDSHAKE when response messageType is not HANDSHAKE_ACK', async () => {
        const { initiator, responder } = createParties();

        // Return a HANDSHAKE_INIT envelope instead of an ACK (messageType mismatch)
        const transport = {
            send: vi.fn((envelope: NegotiationEnvelope) => {
                const challenge = envelope.body['challenge'] as Record<
                    string,
                    unknown
                >;
                // Deliberately build a HANDSHAKE_INIT rather than a HANDSHAKE_ACK
                return Promise.resolve(
                    buildEnvelope({
                        senderDid: responder.document.id,
                        senderPrivateKey: responder.privateKey,
                        recipientDid: initiator.document.id,
                        sessionId: null,
                        messageType: 'HANDSHAKE_INIT',
                        body: { challenge: { ...challenge } },
                    }),
                );
            }),
            listen: vi.fn(),
            close: vi.fn(),
        };

        const handshake = new HandshakeInitiator({
            initiatorDid: initiator.document.id,
            initiatorPrivateKey: initiator.privateKey,
            transport,
            resolvePublicKey: () =>
                Promise.resolve(responder.document.publicKey),
            capabilities: [],
        });

        await expect(
            handshake.initiate({
                responderDid: responder.document.id,
                responderEndpoint: 'http://peer.example/handshake',
            }),
        ).rejects.toMatchObject({
            name: 'ProtocolError',
            code: 'INVALID_HANDSHAKE',
        });
    });

    it('should throw INVALID_HANDSHAKE when ACK header senderDid does not match responderDid', async () => {
        const { initiator, responder } = createParties();

        // Sign the ACK with a second independent identity so header.senderDid differs from params.responderDid
        const altPrincipal = generateKeyPair();
        const altDid = didKeyFromPublicKey(
            Buffer.from(altPrincipal.publicKey, 'hex'),
        );
        const altAgent = createAgentIdentity({
            principalDid: altDid,
            principalPrivateKey: altPrincipal.privateKey,
            capabilities: [],
        });

        const transport = {
            send: vi.fn((envelope: NegotiationEnvelope) => {
                const challenge = envelope.body['challenge'] as Record<
                    string,
                    unknown
                >;
                // Signed by altAgent, but resolvePublicKey resolves the responder's public key → signature verification would fail.
                // Instead, directly tamper with the header.senderDid field to create a mismatch, bypassing the signature check.
                const env = buildEnvelope({
                    senderDid: altAgent.document.id,
                    senderPrivateKey: altAgent.privateKey,
                    recipientDid: initiator.document.id,
                    sessionId: 'other-session',
                    messageType: 'HANDSHAKE_ACK',
                    body: {
                        accepted: true,
                        response: {
                            challengeId: challenge['challengeId'],
                            sessionId: 'other-session',
                            responderDid: responder.document.id,
                            responderCapabilities: [],
                            nonce: challenge['nonce'],
                            timestamp: new Date().toISOString(),
                        },
                    },
                });
                return Promise.resolve(env);
            }),
            listen: vi.fn(),
            close: vi.fn(),
        };

        const handshake = new HandshakeInitiator({
            initiatorDid: initiator.document.id,
            initiatorPrivateKey: initiator.privateKey,
            transport,
            // resolvePublicKey returns altAgent's public key so the signature passes, then triggers the senderDid mismatch
            resolvePublicKey: () =>
                Promise.resolve(altAgent.document.publicKey),
            capabilities: [],
        });

        await expect(
            handshake.initiate({
                responderDid: responder.document.id,
                responderEndpoint: 'http://peer.example/handshake',
            }),
        ).rejects.toMatchObject({
            name: 'ProtocolError',
            code: 'INVALID_HANDSHAKE',
        });
    });

    it('should throw HANDSHAKE_TIMEOUT when transport throws a non-ProtocolError', async () => {
        const { initiator, responder } = createParties();

        // transport.send throws a plain Error (not a ProtocolError); it should be wrapped as HANDSHAKE_TIMEOUT
        const transport = {
            send: vi.fn().mockRejectedValue(new Error('network failure')),
            listen: vi.fn(),
            close: vi.fn(),
        };

        const handshake = new HandshakeInitiator({
            initiatorDid: initiator.document.id,
            initiatorPrivateKey: initiator.privateKey,
            transport,
            resolvePublicKey: () =>
                Promise.resolve(responder.document.publicKey),
            capabilities: [],
            maxRetries: 0,
        });

        await expect(
            handshake.initiate({
                responderDid: responder.document.id,
                responderEndpoint: 'http://peer.example/handshake',
            }),
        ).rejects.toMatchObject({
            name: 'ProtocolError',
            code: 'HANDSHAKE_TIMEOUT',
        });
    });

    it('should throw INVALID_HANDSHAKE when transport returns null', async () => {
        const { initiator, responder } = createParties();

        // transport.send returns null (empty ACK)
        const transport = {
            send: vi.fn().mockResolvedValue(null),
            listen: vi.fn(),
            close: vi.fn(),
        };

        const handshake = new HandshakeInitiator({
            initiatorDid: initiator.document.id,
            initiatorPrivateKey: initiator.privateKey,
            transport,
            resolvePublicKey: () =>
                Promise.resolve(responder.document.publicKey),
            capabilities: [],
            maxRetries: 0,
        });

        await expect(
            handshake.initiate({
                responderDid: responder.document.id,
                responderEndpoint: 'http://peer.example/handshake',
            }),
        ).rejects.toMatchObject({
            name: 'ProtocolError',
            code: 'INVALID_HANDSHAKE',
        });
    });

    // ─── regression test ─────────────────────────────
    it('should thread principalDid and capabilityTokenId from InitiateParams into challenge', async () => {
        const { initiator, responder } = createParties();
        const expectedPrincipal = initiator.document.id;
        const expectedTokenId = 'urn:cap:11111111-2222-4333-8444-555555555555';

        let capturedChallenge: Record<string, unknown> | undefined;

        const transport = {
            send: vi.fn((envelope: NegotiationEnvelope) => {
                capturedChallenge = envelope.body['challenge'] as Record<
                    string,
                    unknown
                >;
                return Promise.resolve(
                    buildEnvelope({
                        senderDid: responder.document.id,
                        senderPrivateKey: responder.privateKey,
                        recipientDid: initiator.document.id,
                        sessionId: 'session-f4-001',
                        messageType: 'HANDSHAKE_ACK',
                        body: {
                            accepted: true,
                            response: {
                                challengeId: capturedChallenge['challengeId'],
                                sessionId: 'session-f4-001',
                                responderDid: responder.document.id,
                                responderCapabilities: ['QUOTE', 'CONFIRM'],
                                nonce: capturedChallenge['nonce'],
                                timestamp: new Date().toISOString(),
                            },
                        },
                    }),
                );
            }),
            listen: vi.fn(),
            close: vi.fn(),
        };

        const handshake = new HandshakeInitiator({
            initiatorDid: initiator.document.id,
            initiatorPrivateKey: initiator.privateKey,
            transport,
            resolvePublicKey: (did) =>
                Promise.resolve(
                    did === responder.document.id
                        ? responder.document.publicKey
                        : null,
                ),
            capabilities: ['INQUIRY', 'QUOTE'],
        });

        await handshake.initiate({
            responderDid: responder.document.id,
            responderEndpoint: 'http://peer.example/handshake',
            principalDid: expectedPrincipal,
            capabilityTokenId: expectedTokenId,
        });

        // Before the fix: InitiateParams had no principalDid/capabilityTokenId fields,
        // so both were always undefined → the responder's REQUIRED path would always throw
        // ENCRYPTION_REQUIRES_CAPABILITY_TOKEN
        expect(capturedChallenge).toBeDefined();
        expect(capturedChallenge!['principalDid']).toBe(expectedPrincipal);
        expect(capturedChallenge!['capabilityTokenId']).toBe(expectedTokenId);
    });
});
