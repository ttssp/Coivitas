import { describe, expect, it } from 'vitest';

import { generateKeyPair } from '@coivitas/crypto';
import {
    createAgentIdentity,
    didKeyFromPublicKey,
} from '@coivitas/identity';
import type { NegotiationEnvelope } from '@coivitas/types';

import { HandshakeInitiator } from '../initiator.js';
import { HandshakeResponder } from '../responder.js';

function makeAgent(caps: string[]) {
    const kp = generateKeyPair();
    const did = didKeyFromPublicKey(Buffer.from(kp.publicKey, 'hex'));
    return createAgentIdentity({
        principalDid: did,
        principalPrivateKey: kp.privateKey,
        capabilities: caps,
    });
}

function makeTransportPair(responder: HandshakeResponder) {
    return {
        send: async (envelope: NegotiationEnvelope): Promise<NegotiationEnvelope> => {
            return responder.respond(envelope);
        },
        listen: () => undefined,
        close: () => undefined,
    };
}

describe('HandshakeInitiator + HandshakeResponder — capability negotiation', () => {
    it('should return intersection of initiator and responder capabilities', async () => {
        const initiatorAgent = makeAgent(['INQUIRY', 'QUOTE', 'CONFIRM']);
        const responderAgent = makeAgent(['QUOTE', 'CONFIRM', 'ADMIN']);

        const responder = new HandshakeResponder({
            responderDid: responderAgent.document.id,
            responderPrivateKey: responderAgent.privateKey,
            verifyInitiator: () => Promise.resolve(true),
            resolvePublicKey: () =>
                Promise.resolve(initiatorAgent.document.publicKey),
            capabilities: ['QUOTE', 'CONFIRM', 'ADMIN'],
        });

        const initiator = new HandshakeInitiator({
            initiatorDid: initiatorAgent.document.id,
            initiatorPrivateKey: initiatorAgent.privateKey,
            transport: makeTransportPair(responder),
            resolvePublicKey: () =>
                Promise.resolve(responderAgent.document.publicKey),
            capabilities: ['INQUIRY', 'QUOTE', 'CONFIRM'],
        });

        const result = await initiator.initiate({
            responderDid: responderAgent.document.id,
            responderEndpoint: 'in-process',
        });

        // Initiator has INQUIRY, QUOTE, CONFIRM; Responder has QUOTE, CONFIRM, ADMIN
        // Intersection = QUOTE, CONFIRM (in initiator order)
        expect(result.negotiatedCapabilities).toEqual(['QUOTE', 'CONFIRM']);
    });

    it('should return empty array when no capabilities overlap', async () => {
        const initiatorAgent = makeAgent(['INQUIRY']);
        const responderAgent = makeAgent(['ADMIN']);

        const responder = new HandshakeResponder({
            responderDid: responderAgent.document.id,
            responderPrivateKey: responderAgent.privateKey,
            verifyInitiator: () => Promise.resolve(true),
            resolvePublicKey: () =>
                Promise.resolve(initiatorAgent.document.publicKey),
            capabilities: ['ADMIN'],
        });

        const initiator = new HandshakeInitiator({
            initiatorDid: initiatorAgent.document.id,
            initiatorPrivateKey: initiatorAgent.privateKey,
            transport: makeTransportPair(responder),
            resolvePublicKey: () =>
                Promise.resolve(responderAgent.document.publicKey),
            capabilities: ['INQUIRY'],
        });

        const result = await initiator.initiate({
            responderDid: responderAgent.document.id,
            responderEndpoint: 'in-process',
        });

        expect(result.negotiatedCapabilities).toEqual([]);
    });

    it('should handle empty capabilities on both sides', async () => {
        const initiatorAgent = makeAgent([]);
        const responderAgent = makeAgent([]);

        const responder = new HandshakeResponder({
            responderDid: responderAgent.document.id,
            responderPrivateKey: responderAgent.privateKey,
            verifyInitiator: () => Promise.resolve(true),
            resolvePublicKey: () =>
                Promise.resolve(initiatorAgent.document.publicKey),
            capabilities: [],
        });

        const initiator = new HandshakeInitiator({
            initiatorDid: initiatorAgent.document.id,
            initiatorPrivateKey: initiatorAgent.privateKey,
            transport: makeTransportPair(responder),
            resolvePublicKey: () =>
                Promise.resolve(responderAgent.document.publicKey),
            capabilities: [],
        });

        const result = await initiator.initiate({
            responderDid: responderAgent.document.id,
            responderEndpoint: 'in-process',
        });

        expect(result.negotiatedCapabilities).toEqual([]);
    });
});
