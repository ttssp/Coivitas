import { describe, expect, it } from 'vitest';

import { generateKeyPair } from '@coivitas/crypto';

import {
    createAgentDID,
    createAgentIdentity,
    didKeyFromPublicKey,
    extractPublicKeyFromDIDKey,
    verifyAgentIdentityDocument,
} from '../index.js';

describe('did-agent', () => {
    it('derives a deterministic did:agent from the same public key', () => {
        const keyPair = generateKeyPair();

        expect(createAgentDID(keyPair.publicKey)).toBe(
            createAgentDID(keyPair.publicKey),
        );
    });

    it('creates a complete agent identity document', () => {
        const principal = generateKeyPair();
        const principalDid = didKeyFromPublicKey(
            Buffer.from(principal.publicKey, 'hex'),
        );
        const result = createAgentIdentity({
            principalDid,
            principalPrivateKey: principal.privateKey,
            capabilities: ['INQUIRY'],
        });

        expect(result.document.id).toMatch(/^did:agent:[a-f0-9]{40}$/);
        expect(result.document.principalDid).toBe(principalDid);
        expect(result.document.publicKey).toHaveLength(64);
        expect(verifyAgentIdentityDocument(result.document).valid).toBe(true);
    });

    it('extracts the original public key from did:key', () => {
        const principal = generateKeyPair();
        const didKey = didKeyFromPublicKey(
            Buffer.from(principal.publicKey, 'hex'),
        );

        expect(extractPublicKeyFromDIDKey(didKey)).toBe(principal.publicKey);
    });

    // Key-rotation update:
    // verifyAgentIdentityDocument allows 0.1.0 and 0.2.0-v=1; when v>1 it must carry a valid rotationProof.
    it('accepts a 0.2.0 document with version=1 (no rotation)', () => {
        const principal = generateKeyPair();
        const principalDid = didKeyFromPublicKey(
            Buffer.from(principal.publicKey, 'hex'),
        );
        const result = createAgentIdentity({
            principalDid,
            principalPrivateKey: principal.privateKey,
            capabilities: ['INQUIRY'],
        });

        const upgraded = {
            ...result.document,
            specVersion: '0.2.0',
            version: 1,
        };
        expect(verifyAgentIdentityDocument(upgraded).valid).toBe(true);
    });

    it('rejects a 0.2.0 document with version=2 and invalid rotationProof signatures', () => {
        const principal = generateKeyPair();
        const principalDid = didKeyFromPublicKey(
            Buffer.from(principal.publicKey, 'hex'),
        );
        const result = createAgentIdentity({
            principalDid,
            principalPrivateKey: principal.privateKey,
            capabilities: ['INQUIRY'],
        });

        const rotated = {
            ...result.document,
            specVersion: '0.2.0',
            version: 2,
            previousPublicKey: 'a'.repeat(64),
            rotationProof: {
                oldPublicKey: 'a'.repeat(64),
                newPublicKey: result.document.publicKey,
                oldKeySignature: 'b'.repeat(128) as unknown as string,
                newKeySignature: 'b'.repeat(128) as unknown as string,
                principalSignature: 'b'.repeat(128) as unknown as string,
                agentDid: result.document.id,
                rotatedAt: result.document.createdAt,
            },
        };
        const res = verifyAgentIdentityDocument(
            rotated as unknown as typeof result.document,
        );
        expect(res.valid).toBe(false);
        // for v>1, validate rotationProof's triple signature; a forged signature reports a rotationProof field error
        expect(res.errors.some((e) => e.field === 'rotationProof')).toBe(true);
    });

    it('rejects a 0.2.0 document with version=2 and missing rotationProof', () => {
        const principal = generateKeyPair();
        const principalDid = didKeyFromPublicKey(
            Buffer.from(principal.publicKey, 'hex'),
        );
        const result = createAgentIdentity({
            principalDid,
            principalPrivateKey: principal.privateKey,
            capabilities: ['INQUIRY'],
        });

        const noProof = {
            ...result.document,
            specVersion: '0.2.0',
            version: 2,
            previousPublicKey: 'a'.repeat(64),
            // rotationProof intentionally missing
        };
        const res = verifyAgentIdentityDocument(
            noProof as unknown as typeof result.document,
        );
        expect(res.valid).toBe(false);
        expect(res.errors.some((e) => e.field === 'rotationProof')).toBe(true);
    });
});
