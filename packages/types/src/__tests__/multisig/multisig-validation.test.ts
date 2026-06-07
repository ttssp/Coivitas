/**
 * multisig-validation.test.ts — Multisig L0 AJV strict-mode third-layer defense tests
 *
 * Triple defense: types-layer brand (L1) + JSON Schema layer (L2) + AJV strict (L3) — this test covers L2+L3
 */

import { describe, expect, it } from 'vitest';

import { validateMultisigToken } from '../../multisig/index.js';

function makeValidToken(): Record<string, unknown> {
    return {
        multisigVersion: '1.0.0',
        threshold: 2,
        signers: [
            {
                id: 'did:key:signer-001',
                role: 'human',
                publicKey:
                    'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a',
                signature:
                    'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b',
            },
            {
                id: 'did:key:signer-002',
                role: 'agent',
                publicKey:
                    'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511b',
                signature:
                    'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100c',
            },
            {
                id: 'did:key:signer-003',
                role: 'agent',
                publicKey:
                    'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511c',
                signature:
                    'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100d',
            },
        ],
        merkleRoot:
            'abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234',
        inclusionProofs: [
            { signerId: 'did:key:signer-001', path: 'AQID=' },
            { signerId: 'did:key:signer-002', path: 'BQYH=' },
            { signerId: 'did:key:signer-003', path: 'CAkK=' },
        ],
        csp: {
            cspVersion: '1.0.0',
            token: {
                id: 'token-test-001',
                issuerDid: 'did:key:test-issuer',
                principalDid: 'did:key:test-principal',
                issuedTo: 'did:key:test-agent',
                specVersion: '0.3.0',
                issuedAt: '2026-05-18T00:00:00.000Z',
                expiresAt: '2099-01-01T00:00:00.000Z',
                capabilities: [
                    {
                        action: 'read',
                        scope: { type: 'allowlist', field: 'res', values: [] },
                    },
                ],
                revocationUrl: 'https://issuer.example.com/revocation/token-test-001',
                proof: {
                    type: 'Ed25519Signature2026',
                    created: '2026-05-18T00:00:00.000Z',
                    verificationMethod: 'did:key:test-issuer#key-1',
                    value: 'sig-base64-stub',
                },
            },
            disclosedClaims: [],
            challenge: '550e8400-e29b-41d4-a716-446655440000',
            audience: 'did:example:verifier',
            notAfter: '2099-01-01T00:00:00.000Z',
        },
    };
}

describe('validateMultisigToken — happy path', () => {
    it('should accept full valid token (all 6 fields + csp 5 fields)', () => {
        const result = validateMultisigToken(makeValidToken());
        expect(result.valid).toBe(true);
    });
});

describe('validateMultisigToken — fail-closed schema enforce', () => {
    it('should reject token missing multisigVersion (required)', () => {
        const token = makeValidToken();
        delete token['multisigVersion'];
        const result = validateMultisigToken(token);
        expect(result.valid).toBe(false);
        if (!result.valid) {
            expect(
                result.errors.some(
                    (e) => e.keyword === 'required' && e.message?.includes('multisigVersion'),
                ),
            ).toBe(true);
        }
    });

    it('should reject token with multisigVersion !== "1.0.0" (const)', () => {
        const token = makeValidToken();
        token['multisigVersion'] = '2.0.0';
        const result = validateMultisigToken(token);
        expect(result.valid).toBe(false);
    });

    it('should reject token missing threshold (required)', () => {
        const token = makeValidToken();
        delete token['threshold'];
        const result = validateMultisigToken(token);
        expect(result.valid).toBe(false);
    });

    it('should reject non-integer threshold', () => {
        const token = makeValidToken();
        token['threshold'] = 1.5;
        const result = validateMultisigToken(token);
        expect(result.valid).toBe(false);
    });

    it('should reject threshold < 1', () => {
        const token = makeValidToken();
        token['threshold'] = 0;
        const result = validateMultisigToken(token);
        expect(result.valid).toBe(false);
    });

    it('should reject empty signers array (minItems: 1)', () => {
        const token = makeValidToken();
        token['signers'] = [];
        const result = validateMultisigToken(token);
        expect(result.valid).toBe(false);
    });

    it('should reject signer without required role field', () => {
        const token = makeValidToken();
        const signers = token['signers'] as Array<Record<string, unknown>>;
        delete signers[0]?.['role'];
        const result = validateMultisigToken(token);
        expect(result.valid).toBe(false);
    });

    it('should reject invalid signer role (not human/agent)', () => {
        const token = makeValidToken();
        const signers = token['signers'] as Array<Record<string, unknown>>;
        if (signers[0]) signers[0]['role'] = 'admin';
        const result = validateMultisigToken(token);
        expect(result.valid).toBe(false);
    });

    it('should reject inclusion proofs missing signerId', () => {
        const token = makeValidToken();
        const proofs = token['inclusionProofs'] as Array<Record<string, unknown>>;
        if (proofs[0]) delete proofs[0]['signerId'];
        const result = validateMultisigToken(token);
        expect(result.valid).toBe(false);
    });

    it('should reject path exceeding maxLength 8192', () => {
        const token = makeValidToken();
        const proofs = token['inclusionProofs'] as Array<Record<string, unknown>>;
        if (proofs[0]) proofs[0]['path'] = 'A'.repeat(8193);
        const result = validateMultisigToken(token);
        expect(result.valid).toBe(false);
    });

    it('should reject additionalProperties at top level', () => {
        const token = makeValidToken();
        token['extraField'] = 'should-be-rejected';
        const result = validateMultisigToken(token);
        expect(result.valid).toBe(false);
    });

    it('should reject additionalProperties in signer', () => {
        const token = makeValidToken();
        const signers = token['signers'] as Array<Record<string, unknown>>;
        if (signers[0]) signers[0]['extraSignerField'] = 'rejected';
        const result = validateMultisigToken(token);
        expect(result.valid).toBe(false);
    });

    it('should reject missing csp', () => {
        const token = makeValidToken();
        delete token['csp'];
        const result = validateMultisigToken(token);
        expect(result.valid).toBe(false);
    });
});
