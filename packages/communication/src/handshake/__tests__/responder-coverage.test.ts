/**
 * Coverage supplement tests for responder.ts
 *
 * Target branches (by line number):
 * - L72-77 : messageType !== 'HANDSHAKE_INIT'
 * - L93-100 : challenge field-missing validation
 * - L102-107: challenge.initiatorDid !== header.senderDid (already covered by existing tests)
 * - L109-114: challenge.responderDid !== this.responderDid
 * - L139-146: verifyInitiator() returns false → reject
 */
import { randomUUID } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import { generateKeyPair } from '@coivitas/crypto';
import {
    createAgentIdentity,
    didKeyFromPublicKey,
} from '@coivitas/identity';
import type { NegotiationEnvelope } from '@coivitas/types';

import { buildEnvelope } from '../../envelope.js';
import { HandshakeResponder } from '../responder.js';
import type { HandshakeAckBody } from '../types.js';

function makeAgent(caps: string[] = []) {
    const kp = generateKeyPair();
    const did = didKeyFromPublicKey(Buffer.from(kp.publicKey, 'hex'));
    return createAgentIdentity({
        principalDid: did,
        principalPrivateKey: kp.privateKey,
        capabilities: caps,
    });
}

/** Builds a valid HANDSHAKE_INIT envelope skeleton for partial tampering in tests*/
function buildValidInit(
    initiator: ReturnType<typeof makeAgent>,
    responder: ReturnType<typeof makeAgent>,
    challengeOverrides: Record<string, unknown> = {},
): NegotiationEnvelope {
    return buildEnvelope({
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
                initiatorCapabilities: [],
                ...challengeOverrides,
            },
        },
    });
}

describe('HandshakeResponder — coverage supplement', () => {
    it('should throw INVALID_HANDSHAKE when messageType is not HANDSHAKE_INIT', async () => {
        const initiator = makeAgent();
        const responder = makeAgent();

        const handshake = new HandshakeResponder({
            responderDid: responder.document.id,
            responderPrivateKey: responder.privateKey,
            verifyInitiator: () => Promise.resolve(true),
            resolvePublicKey: () =>
                Promise.resolve(initiator.document.publicKey),
        });

        // Build a HANDSHAKE_ACK envelope (wrong messageType) and pass it to respond()
        const wrongTypeEnvelope = buildEnvelope({
            senderDid: initiator.document.id,
            senderPrivateKey: initiator.privateKey,
            recipientDid: responder.document.id,
            sessionId: null,
            messageType: 'HANDSHAKE_ACK',
            body: {
                accepted: true,
                response: {
                    challengeId: randomUUID(),
                    sessionId: '',
                    responderDid: responder.document.id,
                    responderCapabilities: [],
                    nonce: 'a'.repeat(64),
                    timestamp: new Date().toISOString(),
                },
            },
        });

        await expect(
            handshake.respond(wrongTypeEnvelope),
        ).rejects.toMatchObject({
            name: 'ProtocolError',
            code: 'INVALID_HANDSHAKE',
        });
    });

    it('should throw INVALID_HANDSHAKE when challenge body is missing required fields', async () => {
        const initiator = makeAgent();
        const responder = makeAgent();

        const handshake = new HandshakeResponder({
            responderDid: responder.document.id,
            responderPrivateKey: responder.privateKey,
            verifyInitiator: () => Promise.resolve(true),
            resolvePublicKey: () =>
                Promise.resolve(initiator.document.publicKey),
        });

        // Build a HANDSHAKE_INIT but with challenge.nonce removed
        const missingNonce = buildEnvelope({
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
                    // nonce intentionally omitted
                    timestamp: new Date().toISOString(),
                    expiresAt: new Date(Date.now() + 60_000).toISOString(),
                    initiatorCapabilities: [],
                },
            },
        });

        await expect(handshake.respond(missingNonce)).rejects.toMatchObject({
            name: 'ProtocolError',
            code: 'INVALID_HANDSHAKE',
        });

        // Build a challenge with expiresAt missing
        const missingExpiresAt = buildEnvelope({
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
                    // expiresAt intentionally omitted
                    initiatorCapabilities: [],
                },
            },
        });

        await expect(
            handshake.respond(missingExpiresAt),
        ).rejects.toMatchObject({
            name: 'ProtocolError',
            code: 'INVALID_HANDSHAKE',
        });
    });

    it('should throw INVALID_HANDSHAKE when challenge.responderDid does not match this responderDid', async () => {
        const initiator = makeAgent();
        const responder = makeAgent();
        const otherResponder = makeAgent();

        const handshake = new HandshakeResponder({
            responderDid: responder.document.id,
            responderPrivateKey: responder.privateKey,
            verifyInitiator: () => Promise.resolve(true),
            resolvePublicKey: () =>
                Promise.resolve(initiator.document.publicKey),
        });

        // challenge.responderDid points to otherResponder, differing from this.responderDid
        const wrongResponderDid = buildEnvelope({
            senderDid: initiator.document.id,
            senderPrivateKey: initiator.privateKey,
            recipientDid: responder.document.id,
            sessionId: null,
            messageType: 'HANDSHAKE_INIT',
            body: {
                challenge: {
                    challengeId: randomUUID(),
                    initiatorDid: initiator.document.id,
                    responderDid: otherResponder.document.id, // mismatch
                    nonce: 'c'.repeat(64),
                    timestamp: new Date().toISOString(),
                    expiresAt: new Date(Date.now() + 60_000).toISOString(),
                    initiatorCapabilities: [],
                },
            },
        });

        await expect(handshake.respond(wrongResponderDid)).rejects.toMatchObject(
            {
                name: 'ProtocolError',
                code: 'INVALID_HANDSHAKE',
            },
        );
    });

    it('should return rejected ACK without throwing when verifyInitiator returns false', async () => {
        const initiator = makeAgent(['QUOTE']);
        const responder = makeAgent(['QUOTE']);

        const handshake = new HandshakeResponder({
            responderDid: responder.document.id,
            responderPrivateKey: responder.privateKey,
            // verifyInitiator returns false → reject the initiator
            verifyInitiator: () => Promise.resolve(false),
            resolvePublicKey: () =>
                Promise.resolve(initiator.document.publicKey),
            capabilities: ['QUOTE'],
        });

        const init = buildValidInit(initiator, responder);
        const ack = await handshake.respond(init);
        const ackBody = ack.body as unknown as HandshakeAckBody;

        expect(ack.messageType).toBe('HANDSHAKE_ACK');
        expect(ackBody.accepted).toBe(false);
        expect(ackBody.reason).toBe('Initiator not authorized');
        // After rejection, lastHandshakeResult should still be null
        expect(handshake.getLastHandshakeResult()).toBeNull();
    });
});
