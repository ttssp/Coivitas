import { randomUUID } from 'node:crypto';

import { describe, expect, it } from 'vitest';

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
import { HandshakeResponder } from '../responder.js';

/**
 * Regression test matrix: HandshakeResponder.respond() must reject two classes
 * of illegal envelope before verifyEnvelope:
 * 1. capabilityTokenRef specVersion gate (already present inside parseEnvelope)
 * 2. initiatorCapabilities vocabulary check (runtime mirror of the schema enum ban)
 *
 * Regression guard: if `respond` skips the schema gate early, a v0.3.0 envelope
 * carrying capabilityTokenRef passes the gate, and control-plane actions such as
 * SESSION_SUPERSEDED can bypass the handshake capability vocabulary and enter
 * negotiation.
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

function makeResponder(parties: ReturnType<typeof createParties>) {
    return new HandshakeResponder({
        responderDid: parties.responder.document.id,
        responderPrivateKey: parties.responder.privateKey,
        verifyInitiator: () => Promise.resolve(true),
        resolvePublicKey: (did) =>
            Promise.resolve(
                did === parties.initiator.document.id
                    ? parties.initiator.document.publicKey
                    : null,
            ),
        capabilities: ['QUOTE'],
    });
}

function buildBaseChallengeEnvelope(
    parties: ReturnType<typeof createParties>,
    overrides: {
        initiatorCapabilities?: readonly string[];
        capabilityTokenRef?: string;
    } = {},
) {
    return buildEnvelope({
        senderDid: parties.initiator.document.id,
        senderPrivateKey: parties.initiator.privateKey,
        recipientDid: parties.responder.document.id,
        sessionId: null,
        messageType: 'HANDSHAKE_INIT',
        body: {
            challenge: {
                challengeId: randomUUID(),
                initiatorDid: parties.initiator.document.id,
                responderDid: parties.responder.document.id,
                nonce: 'a'.repeat(64),
                timestamp: new Date().toISOString(),
                expiresAt: new Date(Date.now() + 60_000).toISOString(),
                initiatorCapabilities: overrides.initiatorCapabilities ?? [
                    'INQUIRY',
                    'QUOTE',
                ],
            },
        },
        ...(overrides.capabilityTokenRef !== undefined
            ? { capabilityTokenRef: overrides.capabilityTokenRef }
            : {}),
    });
}

/** Forcibly rewrites a built envelope's specVersion to something other than 0.2.0,
 * to trigger the SPEC_VERSION_MISMATCH path of the capabilityTokenRef gate. Note that
 * this change breaks the signature, but parseEnvelope does not verify signatures — it
 * runs before verifyEnvelope, which matches the test's intent.
*/
function rewriteSpecVersion(
    envelope: NegotiationEnvelope,
    specVersion: string,
): NegotiationEnvelope {
    return {
        ...envelope,
        specVersion,
    };
}

describe('HandshakeResponder schema gate', () => {
    describe('capabilityTokenRef specVersion gate (parseEnvelope)', () => {
        it('should reject HANDSHAKE_INIT when specVersion is 0.3.0 with capabilityTokenRef present', async () => {
            const parties = createParties();
            const responder = makeResponder(parties);

            const envelope = rewriteSpecVersion(
                buildBaseChallengeEnvelope(parties, {
                    capabilityTokenRef: 'cap-token-ref-001',
                }),
                '0.3.0',
            );

            await expect(responder.respond(envelope)).rejects.toMatchObject({
                name: 'ProtocolError',
                code: 'SPEC_VERSION_MISMATCH',
            });
        });

        it('should reject HANDSHAKE_INIT when specVersion is 0.1.0 with capabilityTokenRef present', async () => {
            const parties = createParties();
            const responder = makeResponder(parties);

            // buildEnvelope forces 0.2.0 when capabilityTokenRef is passed; explicitly override to 0.1.0
            const envelope = rewriteSpecVersion(
                buildBaseChallengeEnvelope(parties, {
                    capabilityTokenRef: 'cap-token-ref-002',
                }),
                '0.1.0',
            );

            await expect(responder.respond(envelope)).rejects.toMatchObject({
                name: 'ProtocolError',
                code: 'SPEC_VERSION_MISMATCH',
            });
        });

        it('should NOT reject HANDSHAKE_INIT when specVersion is 0.2.0 with capabilityTokenRef present (allowed combination)', async () => {
            const parties = createParties();
            const responder = makeResponder(parties);

            const envelope = buildBaseChallengeEnvelope(parties, {
                capabilityTokenRef: 'cap-token-ref-003',
            });
            // Existing valid path (0.2.0 + capabilityTokenRef), should not be blocked by the schema gate.
            // The subsequent verifyEnvelope passes; only assert the schema gate does not throw SPEC_VERSION_MISMATCH.
            const result = responder.respond(envelope);
            await expect(result).resolves.toBeDefined();
        });
    });

    describe('initiatorCapabilities vocabulary runtime mirror', () => {
        it('should reject HANDSHAKE_INIT when initiatorCapabilities contains SESSION_SUPERSEDED', async () => {
            const parties = createParties();
            const responder = makeResponder(parties);

            const envelope = buildBaseChallengeEnvelope(parties, {
                initiatorCapabilities: ['SESSION_SUPERSEDED'],
            });

            await expect(responder.respond(envelope)).rejects.toMatchObject({
                name: 'ProtocolError',
                code: 'INVALID_HANDSHAKE',
            });
            await expect(responder.respond(envelope)).rejects.toThrow(
                /SESSION_SUPERSEDED/,
            );
        });

        it('should reject HANDSHAKE_INIT when initiatorCapabilities mixes SESSION_SUPERSEDED with valid values', async () => {
            const parties = createParties();
            const responder = makeResponder(parties);

            const envelope = buildBaseChallengeEnvelope(parties, {
                initiatorCapabilities: [
                    'INQUIRY',
                    'SESSION_SUPERSEDED',
                    'QUOTE',
                ],
            });

            await expect(responder.respond(envelope)).rejects.toMatchObject({
                name: 'ProtocolError',
                code: 'INVALID_HANDSHAKE',
            });
        });

        it('should reject HANDSHAKE_INIT when initiatorCapabilities contains arbitrary unknown value', async () => {
            const parties = createParties();
            const responder = makeResponder(parties);

            const envelope = buildBaseChallengeEnvelope(parties, {
                initiatorCapabilities: ['INQUIRY', 'TOTALLY_UNKNOWN_CAP'],
            });

            await expect(responder.respond(envelope)).rejects.toMatchObject({
                name: 'ProtocolError',
                code: 'INVALID_HANDSHAKE',
            });
            await expect(responder.respond(envelope)).rejects.toThrow(
                /TOTALLY_UNKNOWN_CAP/,
            );
        });

        it('should accept HANDSHAKE_INIT when all initiatorCapabilities are within HANDSHAKE_CAPABILITY_VOCABULARY', async () => {
            const parties = createParties();
            const responder = makeResponder(parties);

            const envelope = buildBaseChallengeEnvelope(parties, {
                initiatorCapabilities: [...HANDSHAKE_CAPABILITY_VOCABULARY],
            });

            // All valid values — passes the schema gate into the existing verifyEnvelope path, should yield an ACK.
            const ack = await responder.respond(envelope);
            expect(ack.messageType).toBe('HANDSHAKE_ACK');
        });

        it('should reject HANDSHAKE_INIT with INVALID_HANDSHAKE when challenge field is null', async () => {
            const parties = createParties();
            const responder = makeResponder(parties);

            const envelope = buildEnvelope({
                senderDid: parties.initiator.document.id,
                senderPrivateKey: parties.initiator.privateKey,
                recipientDid: parties.responder.document.id,
                sessionId: null,
                messageType: 'HANDSHAKE_INIT',
                body: { challenge: null },
            });

            // Front guard throws INVALID_HANDSHAKE — when challenge is missing or not an object,
            // it no longer silently passes through to the downstream filter that throws a bare TypeError.
            await expect(responder.respond(envelope)).rejects.toMatchObject({
                name: 'ProtocolError',
                code: 'INVALID_HANDSHAKE',
            });
        });
    });

    describe('input integrity boundaries (DoS defense)', () => {
        // Important: the envelopes built by these cases are valid at the signature layer
        // (buildEnvelope signs the full body), but the body's challenge field is structurally
        // malformed. `parseEnvelope` does not deeply inspect the body's internal structure, so a
        // malformed envelope passes parseEnvelope; the responder entry shape guard must throw
        // INVALID_HANDSHAKE, otherwise the downstream `challenge.initiatorCapabilities.filter(...)`
        // throws a bare TypeError → 5xx → DoS on the handshake port.
        it('should reject INVALID_HANDSHAKE when challenge.initiatorCapabilities is missing', async () => {
            const parties = createParties();
            const responder = makeResponder(parties);

            const envelope = buildEnvelope({
                senderDid: parties.initiator.document.id,
                senderPrivateKey: parties.initiator.privateKey,
                recipientDid: parties.responder.document.id,
                sessionId: null,
                messageType: 'HANDSHAKE_INIT',
                body: {
                    challenge: {
                        challengeId: randomUUID(),
                        initiatorDid: parties.initiator.document.id,
                        responderDid: parties.responder.document.id,
                        nonce: 'a'.repeat(64),
                        timestamp: new Date().toISOString(),
                        expiresAt: new Date(Date.now() + 60_000).toISOString(),
                        // initiatorCapabilities intentionally omitted
                    },
                },
            });

            await expect(responder.respond(envelope)).rejects.toMatchObject({
                name: 'ProtocolError',
                code: 'INVALID_HANDSHAKE',
            });
            await expect(responder.respond(envelope)).rejects.toThrow(
                /initiatorCapabilities/,
            );
        });

        it('should reject INVALID_HANDSHAKE when challenge.initiatorCapabilities is non-array (string injection)', async () => {
            const parties = createParties();
            const responder = makeResponder(parties);

            const envelope = buildEnvelope({
                senderDid: parties.initiator.document.id,
                senderPrivateKey: parties.initiator.privateKey,
                recipientDid: parties.responder.document.id,
                sessionId: null,
                messageType: 'HANDSHAKE_INIT',
                body: {
                    challenge: {
                        challengeId: randomUUID(),
                        initiatorDid: parties.initiator.document.id,
                        responderDid: parties.responder.document.id,
                        nonce: 'a'.repeat(64),
                        timestamp: new Date().toISOString(),
                        expiresAt: new Date(Date.now() + 60_000).toISOString(),
                        initiatorCapabilities: 'INQUIRY,QUOTE', // string injection
                    },
                },
            });

            await expect(responder.respond(envelope)).rejects.toMatchObject({
                name: 'ProtocolError',
                code: 'INVALID_HANDSHAKE',
            });
            // AJV schema "must be array" error. Semantically equivalent to
            // the inline guard "must be an array".
            await expect(responder.respond(envelope)).rejects.toThrow(
                /must be array/,
            );
        });

        it('should reject INVALID_HANDSHAKE when initiatorCapabilities contains non-string element', async () => {
            const parties = createParties();
            const responder = makeResponder(parties);

            const envelope = buildEnvelope({
                senderDid: parties.initiator.document.id,
                senderPrivateKey: parties.initiator.privateKey,
                recipientDid: parties.responder.document.id,
                sessionId: null,
                messageType: 'HANDSHAKE_INIT',
                body: {
                    challenge: {
                        challengeId: randomUUID(),
                        initiatorDid: parties.initiator.document.id,
                        responderDid: parties.responder.document.id,
                        nonce: 'a'.repeat(64),
                        timestamp: new Date().toISOString(),
                        expiresAt: new Date(Date.now() + 60_000).toISOString(),
                        // A number mixed into the array elements — at the TypeScript level includes(cap)
                        // returns false due to type mismatch but still runs string operations. The front guard enforces string-only.
                        initiatorCapabilities: ['INQUIRY', 42, 'QUOTE'],
                    },
                },
            });

            await expect(responder.respond(envelope)).rejects.toMatchObject({
                name: 'ProtocolError',
                code: 'INVALID_HANDSHAKE',
            });
            // AJV schema "must be string" error (triggered at the array element level).
            // Semantically equivalent to the inline guard "contains a non-string element".
            await expect(responder.respond(envelope)).rejects.toThrow(
                /must be string/,
            );
        });
    });

    describe('scalar boundaries (schema enforcer all-field enforcement)', () => {
        // The AJV schema directly covers scalar-field
        // pattern / minLength / format validation — more exhaustive than the inline guards.
        it('should reject INVALID_HANDSHAKE when challenge.expiresAt is not ISO 8601 timestamp', async () => {
            const parties = createParties();
            const responder = makeResponder(parties);

            const envelope = buildEnvelope({
                senderDid: parties.initiator.document.id,
                senderPrivateKey: parties.initiator.privateKey,
                recipientDid: parties.responder.document.id,
                sessionId: null,
                messageType: 'HANDSHAKE_INIT',
                body: {
                    challenge: {
                        challengeId: randomUUID(),
                        initiatorDid: parties.initiator.document.id,
                        responderDid: parties.responder.document.id,
                        nonce: 'a'.repeat(64),
                        timestamp: new Date().toISOString(),
                        // Hit point: 'not-a-date' passes the inline guard's
                        // truthiness check → new Date(...).getTime() = NaN → the expiry
                        // check is bypassed. The schema timestamp pattern rejects it.
                        expiresAt: 'not-a-date',
                        initiatorCapabilities: ['INQUIRY'],
                    },
                },
            });

            await expect(responder.respond(envelope)).rejects.toMatchObject({
                name: 'ProtocolError',
                code: 'INVALID_HANDSHAKE',
            });
            await expect(responder.respond(envelope)).rejects.toThrow(
                /expiresAt/,
            );
        });

        it('should reject INVALID_HANDSHAKE when challenge.nonce is empty', async () => {
            const parties = createParties();
            const responder = makeResponder(parties);

            const envelope = buildEnvelope({
                senderDid: parties.initiator.document.id,
                senderPrivateKey: parties.initiator.privateKey,
                recipientDid: parties.responder.document.id,
                sessionId: null,
                messageType: 'HANDSHAKE_INIT',
                body: {
                    challenge: {
                        challengeId: randomUUID(),
                        initiatorDid: parties.initiator.document.id,
                        responderDid: parties.responder.document.id,
                        // Hit point: nonce='' relative to the inline guard's
                        // truthiness check (empty string is falsy → goes to fail), but the inline guard
                        // only rejects when `!nonce`; whitespace strings like ' ' slip through.
                        // The schema hash pattern (^[0-9a-f]{64}$) rejects anything that is not 64 hex chars.
                        nonce: '',
                        timestamp: new Date().toISOString(),
                        expiresAt: new Date(Date.now() + 60_000).toISOString(),
                        initiatorCapabilities: ['INQUIRY'],
                    },
                },
            });

            await expect(responder.respond(envelope)).rejects.toMatchObject({
                name: 'ProtocolError',
                code: 'INVALID_HANDSHAKE',
            });
            await expect(responder.respond(envelope)).rejects.toThrow(
                /nonce/,
            );
        });

        it('should reject INVALID_HANDSHAKE when challenge.challengeId is non-UUID format', async () => {
            const parties = createParties();
            const responder = makeResponder(parties);

            const envelope = buildEnvelope({
                senderDid: parties.initiator.document.id,
                senderPrivateKey: parties.initiator.privateKey,
                recipientDid: parties.responder.document.id,
                sessionId: null,
                messageType: 'HANDSHAKE_INIT',
                body: {
                    challenge: {
                        // Hit point: challengeId is an arbitrary string (not a valid UUID v4).
                        // The inline guard only checks truthiness; the schema enforces UUID format.
                        challengeId: 'arbitrary-string',
                        initiatorDid: parties.initiator.document.id,
                        responderDid: parties.responder.document.id,
                        nonce: 'a'.repeat(64),
                        timestamp: new Date().toISOString(),
                        expiresAt: new Date(Date.now() + 60_000).toISOString(),
                        initiatorCapabilities: ['INQUIRY'],
                    },
                },
            });

            await expect(responder.respond(envelope)).rejects.toMatchObject({
                name: 'ProtocolError',
                code: 'INVALID_HANDSHAKE',
            });
            await expect(responder.respond(envelope)).rejects.toThrow(
                /challengeId/,
            );
        });
    });
});
