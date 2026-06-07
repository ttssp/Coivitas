import { describe, expect, it } from 'vitest';

import { generateKeyPair } from '@coivitas/crypto';
import {
    createAgentIdentity,
    didKeyFromPublicKey,
} from '@coivitas/identity';

import {
    buildAuthorizationInsufficientEnvelope,
    buildErrorEnvelope,
    buildIdentityVerificationFailedEnvelope,
    buildInternalErrorEnvelope,
    buildInvalidEnvelopeEnvelope,
    buildSessionNotFoundEnvelope,
    verifyEnvelope,
} from '../index.js';

describe('error-envelope', () => {
    const principal = generateKeyPair();
    const principalDid = didKeyFromPublicKey(
        Buffer.from(principal.publicKey, 'hex'),
    );
    const sender = createAgentIdentity({
        principalDid,
        principalPrivateKey: principal.privateKey,
    });
    const recipient = createAgentIdentity({
        principalDid,
        principalPrivateKey: principal.privateKey,
    });

    it('builds a signed standard error envelope without leaking internal detail', async () => {
        const envelope = buildErrorEnvelope({
            senderDid: sender.document.id,
            senderPrivateKey: sender.privateKey,
            recipientDid: recipient.document.id,
            sessionId: '770e8400-e29b-41d4-a716-446655440000',
            code: 'AUTHORIZATION_INSUFFICIENT',
            relatedEnvelopeId: '660e8400-e29b-41d4-a716-446655440001',
        });

        expect(envelope.messageType).toBe('ERROR');
        expect(envelope.body).toEqual({
            code: 'AUTHORIZATION_INSUFFICIENT',
            message: 'Authorization insufficient for the requested action.',
            relatedEnvelopeId: '660e8400-e29b-41d4-a716-446655440001',
        });
        // v0.1.0 envelopes default to hex (the frozen wire format baseline is unchanged), 64-byte signature → 128 hex chars
        expect(envelope.signature).toMatch(/^[0-9a-f]{128}$/);
        expect(envelope.body['detail']).toBeUndefined();

        await expect(
            verifyEnvelope(envelope, {
                resolvePublicKey(did) {
                    return Promise.resolve(
                        did === sender.document.id
                            ? sender.document.publicKey
                            : null,
                    );
                },
                now: () => new Date(envelope.timestamp).getTime(),
            }),
        ).resolves.toEqual({ valid: true });
    });

    it('provides dedicated builders for the five standard error codes', () => {
        const common = {
            senderDid: sender.document.id,
            senderPrivateKey: sender.privateKey,
            recipientDid: recipient.document.id,
            sessionId: null,
            relatedEnvelopeId: '660e8400-e29b-41d4-a716-446655440001',
        };

        expect(
            buildAuthorizationInsufficientEnvelope(common).body,
        ).toMatchObject({
            code: 'AUTHORIZATION_INSUFFICIENT',
        });
        expect(
            buildIdentityVerificationFailedEnvelope(common).body,
        ).toMatchObject({
            code: 'IDENTITY_VERIFICATION_FAILED',
        });
        expect(buildSessionNotFoundEnvelope(common).body).toMatchObject({
            code: 'SESSION_NOT_FOUND',
        });
        expect(buildInvalidEnvelopeEnvelope(common).body).toMatchObject({
            code: 'INVALID_ENVELOPE',
        });
        expect(buildInternalErrorEnvelope(common).body).toMatchObject({
            code: 'INTERNAL_ERROR',
        });
    });
});
