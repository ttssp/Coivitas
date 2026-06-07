import { describe, expect, it } from 'vitest';

import { generateKeyPair } from '@coivitas/crypto';

import {
    createAgentDID,
    createBinding,
    didKeyFromPublicKey,
    verifyBinding,
} from '../index.js';

describe('binding', () => {
    it('creates and verifies a binding proof', () => {
        const principal = generateKeyPair();
        const agent = generateKeyPair();
        const principalDid = didKeyFromPublicKey(
            Buffer.from(principal.publicKey, 'hex'),
        );
        const agentDid = createAgentDID(agent.publicKey);
        const proof = createBinding({
            principalDid,
            agentDid,
            principalPrivateKey: principal.privateKey,
        });

        expect(verifyBinding(proof)).toBe(true);
    });

    it('returns false when the proof is tampered', () => {
        const principal = generateKeyPair();
        const agent = generateKeyPair();
        const principalDid = didKeyFromPublicKey(
            Buffer.from(principal.publicKey, 'hex'),
        );
        const agentDid = createAgentDID(agent.publicKey);
        const proof = createBinding({
            principalDid,
            agentDid,
            principalPrivateKey: principal.privateKey,
        });

        expect(
            verifyBinding({
                ...proof,
                agentDid: createAgentDID(generateKeyPair().publicKey),
            }),
        ).toBe(false);
    });

    it('returns false when the proof has expired', () => {
        const principal = generateKeyPair();
        const agent = generateKeyPair();
        const principalDid = didKeyFromPublicKey(
            Buffer.from(principal.publicKey, 'hex'),
        );
        const agentDid = createAgentDID(agent.publicKey);
        const proof = createBinding({
            principalDid,
            agentDid,
            principalPrivateKey: principal.privateKey,
            issuedAt: '2026-04-01T00:00:00.000Z' as never,
            expiresAt: '2026-04-01T01:00:00.000Z' as never,
        });

        expect(verifyBinding(proof, '2026-04-01T01:00:00.000Z' as never)).toBe(
            false,
        );
    });
});
