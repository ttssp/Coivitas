/**
 * Unit tests for the discover-envelope command
 *
 * Covered paths:
 * - Success path: runDiscoverEnvelope returns { requestEnvelope, response } via deps.postEnvelope
 * - Envelope structure validation: messageType='DISCOVERY_REQUEST', specVersion='0.3.0'
 * - Throws ProtocolError('INTERNAL_ERROR') when senderDid is missing
 * - Throws ProtocolError('INTERNAL_ERROR') when senderKey is missing
 */

import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest';

import { generateKeyPair } from '@coivitas/crypto';
import {
    createAgentIdentity,
    didKeyFromPublicKey,
} from '@coivitas/identity';
import { ProtocolError } from '@coivitas/types';

import { runDiscoverEnvelope } from './discover-envelope.js';

// Generate a sender identity for tests (a real Ed25519 key pair, so buildEnvelope can call sign())
function makeSender() {
    const kp = generateKeyPair();
    const principalDid = didKeyFromPublicKey(Buffer.from(kp.publicKey, 'hex'));
    const identity = createAgentIdentity({
        principalDid,
        principalPrivateKey: kp.privateKey,
    });
    return identity;
}

const TARGET_DID =
    'did:agent:aaaabbbbccccdddd0000111122223333444455556666' as const;
const RESPONDER_URL = 'https://agent.example.com/api/v1/envelopes';
const FAKE_RESPONSE = { status: 'ok', envelopeId: 'resp-env-001' };

describe('runDiscoverEnvelope', () => {
    let originalAgentDid: string | undefined;
    let originalAgentKey: string | undefined;

    beforeEach(() => {
        originalAgentDid = process.env.AGENT_DID;
        originalAgentKey = process.env.AGENT_PRIVATE_KEY;
        // Clear to prevent environment-variable interference between tests
        delete process.env.AGENT_DID;
        delete process.env.AGENT_PRIVATE_KEY;
    });

    afterEach(() => {
        if (originalAgentDid !== undefined) {
            process.env.AGENT_DID = originalAgentDid;
        } else {
            delete process.env.AGENT_DID;
        }
        if (originalAgentKey !== undefined) {
            process.env.AGENT_PRIVATE_KEY = originalAgentKey;
        } else {
            delete process.env.AGENT_PRIVATE_KEY;
        }
    });

    it('should return requestEnvelope and response when postEnvelope is injected', async () => {
        const sender = makeSender();
        const postEnvelope = vi.fn().mockResolvedValue(FAKE_RESPONSE);

        const result = await runDiscoverEnvelope(
            {
                target: TARGET_DID,
                responderUrl: RESPONDER_URL,
                senderDid: sender.document.id,
                senderKey: sender.privateKey,
            },
            { postEnvelope },
        );

        expect(result).toHaveProperty('requestEnvelope');
        expect(result).toHaveProperty('response', FAKE_RESPONSE);

        // postEnvelope should be called once, with responderUrl + the constructed envelope
        expect(postEnvelope).toHaveBeenCalledOnce();
        expect(postEnvelope).toHaveBeenCalledWith(
            RESPONDER_URL,
            expect.objectContaining({ messageType: 'DISCOVERY_REQUEST' }),
        );
    });

    it('should build envelope with messageType DISCOVERY_REQUEST and specVersion 0.3.0', async () => {
        const sender = makeSender();
        const postEnvelope = vi.fn().mockResolvedValue(FAKE_RESPONSE);

        const result = await runDiscoverEnvelope(
            {
                target: TARGET_DID,
                responderUrl: RESPONDER_URL,
                senderDid: sender.document.id,
                senderKey: sender.privateKey,
            },
            { postEnvelope },
        );

        const env = result.requestEnvelope;
        expect(env.messageType).toBe('DISCOVERY_REQUEST');
        expect(env.specVersion).toBe('0.3.0');
        expect(env.header.senderDid).toBe(sender.document.id);
        expect(env.header.recipientDid).toBe(TARGET_DID);

        // body contains targetDid and requestedAt
        expect(env.body).toMatchObject({ targetDid: TARGET_DID });
        expect(typeof env.body.requestedAt).toBe('string');
    });

    it('should throw INTERNAL_ERROR when senderDid is not provided and AGENT_DID is not set', async () => {
        const sender = makeSender();

        await expect(
            runDiscoverEnvelope(
                {
                    target: TARGET_DID,
                    responderUrl: RESPONDER_URL,
                    // senderDid omitted, no env var
                    senderKey: sender.privateKey,
                },
                {},
            ),
        ).rejects.toThrow(ProtocolError);

        await expect(
            runDiscoverEnvelope(
                {
                    target: TARGET_DID,
                    responderUrl: RESPONDER_URL,
                    senderKey: sender.privateKey,
                },
                {},
            ),
        ).rejects.toMatchObject({ code: 'INTERNAL_ERROR' });
    });

    it('should throw INTERNAL_ERROR when senderKey is not provided and AGENT_PRIVATE_KEY is not set', async () => {
        const sender = makeSender();

        await expect(
            runDiscoverEnvelope(
                {
                    target: TARGET_DID,
                    responderUrl: RESPONDER_URL,
                    senderDid: sender.document.id,
                    // senderKey omitted, no env var
                },
                {},
            ),
        ).rejects.toThrow(ProtocolError);

        await expect(
            runDiscoverEnvelope(
                {
                    target: TARGET_DID,
                    responderUrl: RESPONDER_URL,
                    senderDid: sender.document.id,
                },
                {},
            ),
        ).rejects.toMatchObject({ code: 'INTERNAL_ERROR' });
    });

    it('should read senderDid and senderKey from environment variables when not passed as options', async () => {
        const sender = makeSender();
        process.env.AGENT_DID = sender.document.id;
        process.env.AGENT_PRIVATE_KEY = sender.privateKey;

        const postEnvelope = vi.fn().mockResolvedValue(FAKE_RESPONSE);

        const result = await runDiscoverEnvelope(
            {
                target: TARGET_DID,
                responderUrl: RESPONDER_URL,
            },
            { postEnvelope },
        );

        expect(result.requestEnvelope.header.senderDid).toBe(
            sender.document.id,
        );
        expect(postEnvelope).toHaveBeenCalledOnce();
    });
});
