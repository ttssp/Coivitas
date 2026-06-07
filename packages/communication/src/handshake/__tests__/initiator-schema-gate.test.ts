import { randomUUID } from 'node:crypto';

import { describe, expect, it, vi } from 'vitest';

import { generateKeyPair } from '@coivitas/crypto';
import {
    createAgentIdentity,
    didKeyFromPublicKey,
} from '@coivitas/identity';
import {
    HANDSHAKE_CAPABILITY_VOCABULARY,
    type NegotiationEnvelope,
} from '@coivitas/types';

import { buildEnvelope } from '../../envelope.js';
import { HandshakeInitiator } from '../initiator.js';

/**
 * After receiving a HANDSHAKE_ACK, HandshakeInitiator.initiate() must perform a vocabulary check
 * symmetric to responder.ts; otherwise a malicious responder carrying control-plane actions in
 * responderCapabilities (e.g. SESSION_SUPERSEDED) could let the handshake's negotiated state contain
 * out-of-set values, breaking one half of the trust boundary's bidirectional fail-closed guarantee.
 * Filtering to the intersection alone cannot reject out-of-set values and is no substitute for an explicit ban.
 *
 * Regression guard: an early initiator that skips the ACK schema/vocabulary
 * gate lets the responder smuggle control-plane actions such as SESSION_SUPERSEDED into the ACK.
 */

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
        capabilities: ['QUOTE'],
    });
    return { initiator, responder };
}

interface AckOverrides {
    responderCapabilities?: unknown;
    accepted?: boolean;
}

function makeAckTransport(
    parties: ReturnType<typeof createParties>,
    overrides: AckOverrides = {},
) {
    return {
        send: vi.fn((envelope: NegotiationEnvelope) => {
            const challenge = envelope.body['challenge'] as Record<
                string,
                unknown
            >;
            return Promise.resolve(
                buildEnvelope({
                    senderDid: parties.responder.document.id,
                    senderPrivateKey: parties.responder.privateKey,
                    recipientDid: parties.initiator.document.id,
                    sessionId: 'session-schema-gate',
                    messageType: 'HANDSHAKE_ACK',
                    body: {
                        accepted: overrides.accepted ?? true,
                        response: {
                            challengeId: challenge['challengeId'],
                            sessionId: 'session-schema-gate',
                            responderDid: parties.responder.document.id,
                            responderCapabilities:
                                overrides.responderCapabilities ?? ['QUOTE'],
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
}

function makeInitiator(
    parties: ReturnType<typeof createParties>,
    transport: ReturnType<typeof makeAckTransport>,
) {
    return new HandshakeInitiator({
        initiatorDid: parties.initiator.document.id,
        initiatorPrivateKey: parties.initiator.privateKey,
        transport,
        resolvePublicKey: (did) =>
            Promise.resolve(
                did === parties.responder.document.id
                    ? parties.responder.document.publicKey
                    : null,
            ),
        capabilities: ['INQUIRY', 'QUOTE'],
    });
}

describe('HandshakeInitiator schema gate', () => {
    describe('responderCapabilities vocabulary runtime mirror (symmetric with responder.ts)', () => {
        it('should reject HANDSHAKE_ACK when responderCapabilities contains SESSION_SUPERSEDED', async () => {
            const parties = createParties();
            const transport = makeAckTransport(parties, {
                responderCapabilities: ['SESSION_SUPERSEDED'],
            });
            const initiator = makeInitiator(parties, transport);

            await expect(
                initiator.initiate({
                    responderDid: parties.responder.document.id,
                    responderEndpoint: 'http://peer.example/handshake',
                }),
            ).rejects.toMatchObject({
                name: 'ProtocolError',
                code: 'INVALID_HANDSHAKE',
            });
            await expect(
                initiator.initiate({
                    responderDid: parties.responder.document.id,
                    responderEndpoint: 'http://peer.example/handshake',
                }),
            ).rejects.toThrow(/SESSION_SUPERSEDED/);
        });

        it('should reject HANDSHAKE_ACK when responderCapabilities mixes SESSION_SUPERSEDED with valid values', async () => {
            const parties = createParties();
            const transport = makeAckTransport(parties, {
                responderCapabilities: ['QUOTE', 'SESSION_SUPERSEDED'],
            });
            const initiator = makeInitiator(parties, transport);

            await expect(
                initiator.initiate({
                    responderDid: parties.responder.document.id,
                    responderEndpoint: 'http://peer.example/handshake',
                }),
            ).rejects.toMatchObject({
                name: 'ProtocolError',
                code: 'INVALID_HANDSHAKE',
            });
        });

        it('should reject HANDSHAKE_ACK when responderCapabilities contains arbitrary unknown value', async () => {
            const parties = createParties();
            const transport = makeAckTransport(parties, {
                responderCapabilities: ['QUOTE', 'TOTALLY_UNKNOWN_CAP'],
            });
            const initiator = makeInitiator(parties, transport);

            await expect(
                initiator.initiate({
                    responderDid: parties.responder.document.id,
                    responderEndpoint: 'http://peer.example/handshake',
                }),
            ).rejects.toMatchObject({
                name: 'ProtocolError',
                code: 'INVALID_HANDSHAKE',
            });
            await expect(
                initiator.initiate({
                    responderDid: parties.responder.document.id,
                    responderEndpoint: 'http://peer.example/handshake',
                }),
            ).rejects.toThrow(/TOTALLY_UNKNOWN_CAP/);
        });

        it('should reject HANDSHAKE_ACK when responderCapabilities is not an array (string injection)', async () => {
            const parties = createParties();
            const transport = makeAckTransport(parties, {
                // Deliberately inject a non-array shape — hits the Array.isArray guard, triggering INVALID_HANDSHAKE
                responderCapabilities: 'SESSION_SUPERSEDED',
            });
            const initiator = makeInitiator(parties, transport);

            await expect(
                initiator.initiate({
                    responderDid: parties.responder.document.id,
                    responderEndpoint: 'http://peer.example/handshake',
                }),
            ).rejects.toMatchObject({
                name: 'ProtocolError',
                code: 'INVALID_HANDSHAKE',
            });
        });

        it('should accept HANDSHAKE_ACK when all responderCapabilities are within HANDSHAKE_CAPABILITY_VOCABULARY', async () => {
            const parties = createParties();
            const transport = makeAckTransport(parties, {
                responderCapabilities: [...HANDSHAKE_CAPABILITY_VOCABULARY],
            });
            const initiator = makeInitiator(parties, transport);

            // All valid values — passes the vocabulary check; after filtering, takes the intersection with the initiator's capabilities
            const result = await initiator.initiate({
                responderDid: parties.responder.document.id,
                responderEndpoint: 'http://peer.example/handshake',
            });
            expect(result.sessionId).toBe('session-schema-gate');
            expect(result.negotiatedCapabilities.sort()).toEqual(
                ['INQUIRY', 'QUOTE'].sort(),
            );
        });

        it('should reject HANDSHAKE_ACK with vocabulary check BEFORE checking accepted=false', async () => {
            // Even when the ACK has accepted=false, out-of-set values should still be caught by the vocabulary gate first —
            // a malicious responder must not be able to use a "rejected ACK" as a carrier for control-plane action literals.
            const parties = createParties();
            const transport = makeAckTransport(parties, {
                accepted: false,
                responderCapabilities: ['SESSION_SUPERSEDED'],
            });
            const initiator = makeInitiator(parties, transport);

            await expect(
                initiator.initiate({
                    responderDid: parties.responder.document.id,
                    responderEndpoint: 'http://peer.example/handshake',
                }),
            ).rejects.toMatchObject({
                name: 'ProtocolError',
                code: 'INVALID_HANDSHAKE',
            });
        });

        it('should accept HANDSHAKE_ACK when responderCapabilities is empty array (degenerate but legal)', async () => {
            const parties = createParties();
            const transport = makeAckTransport(parties, {
                responderCapabilities: [],
            });
            const initiator = makeInitiator(parties, transport);

            const result = await initiator.initiate({
                responderDid: parties.responder.document.id,
                responderEndpoint: 'http://peer.example/handshake',
            });
            // An empty array does not trigger a vocabulary rejection; the intersection is empty but sessionId exists
            expect(result.sessionId).toBe('session-schema-gate');
            expect(result.negotiatedCapabilities).toEqual([]);
        });
    });

    describe('input integrity boundaries (DoS defense)', () => {
        // Important: construct an ACK envelope with a **valid signature but a malformed ackBody shape**.
        // The early implementation only checked when `ackBody?.response?.responderCapabilities !== undefined`;
        // a missing response object / missing responderCapabilities / non-object response
        // would all fall through to a downstream `ackBody.response.nonce` raw TypeError.
        // After the fix, all missing/malformed cases uniformly throw INVALID_HANDSHAKE.
        function makeAckTransportWithBody(
            parties: ReturnType<typeof createParties>,
            body: Record<string, unknown>,
        ) {
            return {
                send: vi.fn(() =>
                    Promise.resolve(
                        buildEnvelope({
                            senderDid: parties.responder.document.id,
                            senderPrivateKey: parties.responder.privateKey,
                            recipientDid: parties.initiator.document.id,
                            sessionId: 'session-malformed',
                            messageType: 'HANDSHAKE_ACK',
                            body,
                        }),
                    ),
                ),
                listen: vi.fn(),
                close: vi.fn(),
            };
        }

        it('should reject INVALID_HANDSHAKE when ackBody.response is missing entirely', async () => {
            const parties = createParties();
            // accepted=true but no response object at all — previously this would throw a raw
            // TypeError at ackBody.response.nonce
            const transport = makeAckTransportWithBody(parties, {
                accepted: true,
            });
            const initiator = makeInitiator(parties, transport);

            await expect(
                initiator.initiate({
                    responderDid: parties.responder.document.id,
                    responderEndpoint: 'http://peer.example/handshake',
                }),
            ).rejects.toMatchObject({
                name: 'ProtocolError',
                code: 'INVALID_HANDSHAKE',
            });
            await expect(
                initiator.initiate({
                    responderDid: parties.responder.document.id,
                    responderEndpoint: 'http://peer.example/handshake',
                }),
            ).rejects.toThrow(/response/);
        });

        it('should reject INVALID_HANDSHAKE when ackBody.response is null', async () => {
            const parties = createParties();
            const transport = makeAckTransportWithBody(parties, {
                accepted: true,
                response: null,
            });
            const initiator = makeInitiator(parties, transport);

            await expect(
                initiator.initiate({
                    responderDid: parties.responder.document.id,
                    responderEndpoint: 'http://peer.example/handshake',
                }),
            ).rejects.toMatchObject({
                name: 'ProtocolError',
                code: 'INVALID_HANDSHAKE',
            });
        });

        it('should reject INVALID_HANDSHAKE when ackBody.response is missing responderCapabilities', async () => {
            const parties = createParties();
            const transport = makeAckTransportWithBody(parties, {
                accepted: true,
                response: {
                    challengeId: randomUUID(),
                    sessionId: 'session-malformed',
                    responderDid: parties.responder.document.id,
                    nonce: 'a'.repeat(64),
                    timestamp: new Date().toISOString(),
                    // responderCapabilities deliberately missing
                },
            });
            const initiator = makeInitiator(parties, transport);

            await expect(
                initiator.initiate({
                    responderDid: parties.responder.document.id,
                    responderEndpoint: 'http://peer.example/handshake',
                }),
            ).rejects.toMatchObject({
                name: 'ProtocolError',
                code: 'INVALID_HANDSHAKE',
            });
            await expect(
                initiator.initiate({
                    responderDid: parties.responder.document.id,
                    responderEndpoint: 'http://peer.example/handshake',
                }),
            ).rejects.toThrow(/responderCapabilities/);
        });

        it('should reject INVALID_HANDSHAKE when ackBody.accepted is missing or non-boolean', async () => {
            const parties = createParties();
            const transport = makeAckTransportWithBody(parties, {
                // accepted deliberately omitted
                response: {
                    challengeId: randomUUID(),
                    sessionId: 'session-malformed',
                    responderDid: parties.responder.document.id,
                    responderCapabilities: ['QUOTE'],
                    nonce: 'a'.repeat(64),
                    timestamp: new Date().toISOString(),
                },
            });
            const initiator = makeInitiator(parties, transport);

            await expect(
                initiator.initiate({
                    responderDid: parties.responder.document.id,
                    responderEndpoint: 'http://peer.example/handshake',
                }),
            ).rejects.toMatchObject({
                name: 'ProtocolError',
                code: 'INVALID_HANDSHAKE',
            });
            await expect(
                initiator.initiate({
                    responderDid: parties.responder.document.id,
                    responderEndpoint: 'http://peer.example/handshake',
                }),
            ).rejects.toThrow(/accepted/);
        });

        it('should reject INVALID_HANDSHAKE when responderCapabilities contains non-string element', async () => {
            const parties = createParties();
            const transport = makeAckTransportWithBody(parties, {
                accepted: true,
                response: {
                    challengeId: randomUUID(),
                    sessionId: 'session-malformed',
                    responderDid: parties.responder.document.id,
                    responderCapabilities: ['QUOTE', 99, 'INQUIRY'],
                    nonce: 'a'.repeat(64),
                    timestamp: new Date().toISOString(),
                },
            });
            const initiator = makeInitiator(parties, transport);

            await expect(
                initiator.initiate({
                    responderDid: parties.responder.document.id,
                    responderEndpoint: 'http://peer.example/handshake',
                }),
            ).rejects.toMatchObject({
                name: 'ProtocolError',
                code: 'INVALID_HANDSHAKE',
            });
            // AJV schema "must be string" error (triggered at the array-element level).
            // Semantically equivalent to the inline guard "contains a non-string element".
            await expect(
                initiator.initiate({
                    responderDid: parties.responder.document.id,
                    responderEndpoint: 'http://peer.example/handshake',
                }),
            ).rejects.toThrow(/must be string/);
        });
    });

    describe("sessionId / scalar boundaries (schema if/then enforcement)", () => {
        // handshakeAckBody if/then conditional-branch constraints:
        // accepted=true → response.sessionId minLength≥1 (prevents a malicious responder from sending
        // sessionId='' on the accepted=true path to make the initiator believe a session was established)
        // accepted=false → response.sessionId may be empty (the reject path has a settled wire format)
        it("should reject HANDSHAKE_ACK when accepted=true but response.sessionId is empty string", async () => {
            const parties = createParties();
            const transport = {
                send: vi.fn((envelope: NegotiationEnvelope) => {
                    const challenge = envelope.body['challenge'] as Record<
                        string,
                        unknown
                    >;
                    return Promise.resolve(
                        buildEnvelope({
                            senderDid: parties.responder.document.id,
                            senderPrivateKey: parties.responder.privateKey,
                            recipientDid: parties.initiator.document.id,
                            sessionId: 'session-x',
                            messageType: 'HANDSHAKE_ACK',
                            body: {
                                accepted: true,
                                response: {
                                    challengeId: challenge['challengeId'],
                                    // Trigger point: accepted=true + sessionId=''
                                    // The inline guard does not validate sessionId minLength;
                                    // the schema if/then constraint triggers INVALID_HANDSHAKE here.
                                    sessionId: '',
                                    responderDid: parties.responder.document.id,
                                    responderCapabilities: ['QUOTE'],
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
            const initiator = makeInitiator(parties, transport);

            await expect(
                initiator.initiate({
                    responderDid: parties.responder.document.id,
                    responderEndpoint: 'http://peer.example/handshake',
                }),
            ).rejects.toMatchObject({
                name: 'ProtocolError',
                code: 'INVALID_HANDSHAKE',
            });
            await expect(
                initiator.initiate({
                    responderDid: parties.responder.document.id,
                    responderEndpoint: 'http://peer.example/handshake',
                }),
            ).rejects.toThrow(/sessionId/);
        });

        it("should accept HANDSHAKE_ACK when accepted=false even with sessionId='' (reject path wire-format)", async () => {
            // Regression guard: the settled sessionId='' wire format on the reject path must not be rejected by the schema,
            // otherwise the responder's reject-path envelope would be misclassified on the initiator side as a schema error
            // rather than the business-level HANDSHAKE_REJECTED.
            const parties = createParties();
            const transport = {
                send: vi.fn((envelope: NegotiationEnvelope) => {
                    const challenge = envelope.body['challenge'] as Record<
                        string,
                        unknown
                    >;
                    return Promise.resolve(
                        buildEnvelope({
                            senderDid: parties.responder.document.id,
                            senderPrivateKey: parties.responder.privateKey,
                            recipientDid: parties.initiator.document.id,
                            sessionId: null,
                            messageType: 'HANDSHAKE_ACK',
                            body: {
                                accepted: false,
                                reason: 'Rejected at the business level',
                                response: {
                                    challengeId: challenge['challengeId'],
                                    sessionId: '',
                                    responderDid: parties.responder.document.id,
                                    responderCapabilities: [],
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
            const initiator = makeInitiator(parties, transport);

            // Expect: business-level HANDSHAKE_REJECTED, **not** schema INVALID_HANDSHAKE
            await expect(
                initiator.initiate({
                    responderDid: parties.responder.document.id,
                    responderEndpoint: 'http://peer.example/handshake',
                }),
            ).rejects.toMatchObject({
                name: 'ProtocolError',
                code: 'HANDSHAKE_REJECTED',
            });
        });
    });
});
