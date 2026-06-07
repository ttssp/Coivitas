/**
 * CR L1 sign-verify-integrity-proof.test.ts — Ed25519 sign + verify primitive unit tests
 *
 * Coverage goals:
 *   - signResolvedCredentialIntegrityProof: signedPayload + privateKey -> hex signature (128 chars)
 *   - verifyResolvedCredentialIntegrityProofSignature: proof + publicKey -> { valid: true } OR throw
 *   - fail-closed: wrong publicKey / tampered payload / non-hex signature / invalid key length
 *   - round-trip: sign -> verify all PASS
 *   - anti-phantom: stubbing a return true is strictly forbidden (a failed verify must throw)
 */

import { describe, expect, it } from 'vitest';

import { ed25519 } from '@noble/curves/ed25519';

import {
    canonicalizeResolvedCredentialIntegrityProof,
    CrError,
    signResolvedCredentialIntegrityProof,
    verifyResolvedCredentialIntegrityProofSignature,
    type ResolvedCredentialIntegrityProofSignedPayload,
} from '../../credential-resolver/index.js';

import type { ResolvedCredentialIntegrityProof } from '@coivitas/types';

// ─── test helper ────────────────────────────────────────────────────────────

function makeKeyPair(): { publicKey: Uint8Array; privateKey: Uint8Array } {
    const privateKey = ed25519.utils.randomPrivateKey();
    const publicKey = ed25519.getPublicKey(privateKey);
    return { publicKey, privateKey };
}

function validSignedPayload(): ResolvedCredentialIntegrityProofSignedPayload {
    return {
        token: 'cr:550e8400-e29b-41d4-a716-446655440000:user=550e8400-e29b-41d4-a716-446655440001',
        disclosedClaims: [
            'issuer:https://oidc.example.com',
            'subject:user-001',
            'userId:550e8400-e29b-41d4-a716-446655440001',
        ],
        challenge: '550e8400-e29b-41d4-a716-446655440002',
        audience: 'did:example:verifier-001',
        notAfter: '2099-01-01T00:00:00.000Z',
        cspVersion: '1.0.0',
    };
}

function buildFullProof(
    signedPayload: ResolvedCredentialIntegrityProofSignedPayload,
    privateKey: Uint8Array,
    resolverDid = 'did:example:resolver-001',
): ResolvedCredentialIntegrityProof {
    const proofSignature = signResolvedCredentialIntegrityProof(
        signedPayload,
        privateKey,
    );
    return {
        ...signedPayload,
        proofSignature,
        resolverDid,
    };
}

// ─── signResolvedCredentialIntegrityProof ──────────────────────────────────

describe('signResolvedCredentialIntegrityProof — Ed25519 sign on JCS canonical bytes (issuer side)', () => {
    it('should produce 128-char lowercase hex signature for valid input', () => {
        const { privateKey } = makeKeyPair();
        const sig = signResolvedCredentialIntegrityProof(
            validSignedPayload(),
            privateKey,
        );
        expect(typeof sig).toBe('string');
        expect(sig.length).toBe(128);
        expect(sig).toMatch(/^[0-9a-f]{128}$/);
    });

    it('should reject non-Uint8Array privateKey (CR_PORT_CONTRACT_VIOLATION)', () => {
        expect(() =>
            signResolvedCredentialIntegrityProof(
                validSignedPayload(),
                'not-uint8array' as unknown as Uint8Array,
            ),
        ).toThrow(CrError);
        try {
            signResolvedCredentialIntegrityProof(
                validSignedPayload(),
                'not-uint8array' as unknown as Uint8Array,
            );
        } catch (err) {
            expect((err as CrError).code).toBe('CR_PORT_CONTRACT_VIOLATION');
            expect((err as CrError).detail?.['reason']).toBe(
                'private_key_not_uint8array',
            );
        }
    });

    it('should reject privateKey wrong length (CR_PORT_CONTRACT_VIOLATION)', () => {
        const shortKey = new Uint8Array(16); // wrong length
        expect(() =>
            signResolvedCredentialIntegrityProof(
                validSignedPayload(),
                shortKey,
            ),
        ).toThrow(CrError);
        try {
            signResolvedCredentialIntegrityProof(
                validSignedPayload(),
                shortKey,
            );
        } catch (err) {
            expect((err as CrError).code).toBe('CR_PORT_CONTRACT_VIOLATION');
            expect((err as CrError).detail?.['reason']).toBe(
                'private_key_invalid_length',
            );
        }
    });

    it('should produce deterministic signature for same input (Ed25519 deterministic)', () => {
        const { privateKey } = makeKeyPair();
        const sig1 = signResolvedCredentialIntegrityProof(
            validSignedPayload(),
            privateKey,
        );
        const sig2 = signResolvedCredentialIntegrityProof(
            validSignedPayload(),
            privateKey,
        );
        expect(sig1).toBe(sig2);
    });

    it('should produce different signatures for different private keys', () => {
        const kp1 = makeKeyPair();
        const kp2 = makeKeyPair();
        const sig1 = signResolvedCredentialIntegrityProof(
            validSignedPayload(),
            kp1.privateKey,
        );
        const sig2 = signResolvedCredentialIntegrityProof(
            validSignedPayload(),
            kp2.privateKey,
        );
        expect(sig1).not.toBe(sig2);
    });
});

// ─── verifyResolvedCredentialIntegrityProofSignature ───────────────────────

describe('verifyResolvedCredentialIntegrityProofSignature — Ed25519 verify (verifier side; fail-closed)', () => {
    it('should accept valid proof signed with corresponding privateKey (round-trip)', () => {
        const { publicKey, privateKey } = makeKeyPair();
        const proof = buildFullProof(validSignedPayload(), privateKey);
        const result = verifyResolvedCredentialIntegrityProofSignature(
            proof,
            publicKey,
        );
        expect(result.valid).toBe(true);
    });

    it('should reject proof with wrong publicKey (CR_INTEGRITY_PROOF_INVALID)', () => {
        const { privateKey } = makeKeyPair();
        const wrongKeyPair = makeKeyPair();
        const proof = buildFullProof(validSignedPayload(), privateKey);
        expect(() =>
            verifyResolvedCredentialIntegrityProofSignature(
                proof,
                wrongKeyPair.publicKey,
            ),
        ).toThrow(CrError);
        try {
            verifyResolvedCredentialIntegrityProofSignature(
                proof,
                wrongKeyPair.publicKey,
            );
        } catch (err) {
            expect((err as CrError).code).toBe('CR_INTEGRITY_PROOF_INVALID');
            expect((err as CrError).detail?.['reason']).toBe(
                'signature_verify_failed',
            );
        }
    });

    it('should reject proof with tampered token field (CR_INTEGRITY_PROOF_INVALID)', () => {
        const { publicKey, privateKey } = makeKeyPair();
        const proof = buildFullProof(validSignedPayload(), privateKey);
        const tampered: ResolvedCredentialIntegrityProof = {
            ...proof,
            token: 'cr:TAMPERED:user=BAD',
        };
        expect(() =>
            verifyResolvedCredentialIntegrityProofSignature(
                tampered,
                publicKey,
            ),
        ).toThrow(CrError);
    });

    it('should reject proof with tampered challenge field (replay defense)', () => {
        const { publicKey, privateKey } = makeKeyPair();
        const proof = buildFullProof(validSignedPayload(), privateKey);
        const tampered: ResolvedCredentialIntegrityProof = {
            ...proof,
            challenge: 'REPLAY-ATTACK-CHALLENGE',
        };
        expect(() =>
            verifyResolvedCredentialIntegrityProofSignature(
                tampered,
                publicKey,
            ),
        ).toThrow(CrError);
    });

    it('should reject proof with tampered audience field (hijack defense)', () => {
        const { publicKey, privateKey } = makeKeyPair();
        const proof = buildFullProof(validSignedPayload(), privateKey);
        const tampered: ResolvedCredentialIntegrityProof = {
            ...proof,
            audience: 'did:example:attacker-verifier',
        };
        expect(() =>
            verifyResolvedCredentialIntegrityProofSignature(
                tampered,
                publicKey,
            ),
        ).toThrow(CrError);
    });

    it('should reject proofSignature with wrong hex format (CR_INTEGRITY_PROOF_INVALID)', () => {
        const { publicKey, privateKey } = makeKeyPair();
        const proof = buildFullProof(validSignedPayload(), privateKey);
        const malformed: ResolvedCredentialIntegrityProof = {
            ...proof,
            proofSignature: 'not-hex-not-128-chars',
        };
        expect(() =>
            verifyResolvedCredentialIntegrityProofSignature(
                malformed,
                publicKey,
            ),
        ).toThrow(CrError);
        try {
            verifyResolvedCredentialIntegrityProofSignature(
                malformed,
                publicKey,
            );
        } catch (err) {
            expect((err as CrError).code).toBe('CR_INTEGRITY_PROOF_INVALID');
            expect((err as CrError).detail?.['reason']).toBe(
                'proof_signature_invalid_hex_format',
            );
        }
    });

    it('should reject proofSignature non-string (CR_INTEGRITY_PROOF_INVALID)', () => {
        const { publicKey, privateKey } = makeKeyPair();
        const proof = buildFullProof(validSignedPayload(), privateKey);
        const malformed = {
            ...proof,
            proofSignature: 12345 as unknown as string,
        };
        expect(() =>
            verifyResolvedCredentialIntegrityProofSignature(
                malformed as ResolvedCredentialIntegrityProof,
                publicKey,
            ),
        ).toThrow(CrError);
    });

    it('should reject non-Uint8Array publicKey (CR_PORT_CONTRACT_VIOLATION)', () => {
        const { privateKey } = makeKeyPair();
        const proof = buildFullProof(validSignedPayload(), privateKey);
        expect(() =>
            verifyResolvedCredentialIntegrityProofSignature(
                proof,
                'not-uint8array' as unknown as Uint8Array,
            ),
        ).toThrow(CrError);
        try {
            verifyResolvedCredentialIntegrityProofSignature(
                proof,
                'not-uint8array' as unknown as Uint8Array,
            );
        } catch (err) {
            expect((err as CrError).code).toBe('CR_PORT_CONTRACT_VIOLATION');
        }
    });

    it('should reject publicKey wrong length (CR_PORT_CONTRACT_VIOLATION)', () => {
        const { privateKey } = makeKeyPair();
        const proof = buildFullProof(validSignedPayload(), privateKey);
        const shortKey = new Uint8Array(16);
        expect(() =>
            verifyResolvedCredentialIntegrityProofSignature(proof, shortKey),
        ).toThrow(CrError);
    });

    it('should NOT silent-return-true on verify failure (anti-phantom; strict fail-closed)', () => {
        const { privateKey } = makeKeyPair();
        const wrongKeyPair = makeKeyPair();
        const proof = buildFullProof(validSignedPayload(), privateKey);
        // verify should throw, not return a { valid: false }-style value (auth/verification primitives are strictly fail-closed)
        let didThrow = false;
        try {
            verifyResolvedCredentialIntegrityProofSignature(
                proof,
                wrongKeyPair.publicKey,
            );
        } catch (err) {
            didThrow = true;
            expect(err).toBeInstanceOf(CrError);
        }
        expect(didThrow).toBe(true);
    });
});

// ─── canonicalize / sign / verify full-chain round-trip ───────────────────────────

describe('CR L1 full-chain round-trip: canonicalize -> sign -> verify', () => {
    it('should round-trip: canonicalize -> sign -> verify (PASS)', () => {
        const { publicKey, privateKey } = makeKeyPair();
        const signedPayload = validSignedPayload();

        // step 1: canonicalize
        const canonicalBytes =
            canonicalizeResolvedCredentialIntegrityProof(signedPayload);
        expect(canonicalBytes.length).toBeGreaterThan(0);

        // step 2: sign
        const sig = signResolvedCredentialIntegrityProof(
            signedPayload,
            privateKey,
        );
        expect(sig).toMatch(/^[0-9a-f]{128}$/);

        // step 3: verify (full proof construction)
        const fullProof: ResolvedCredentialIntegrityProof = {
            ...signedPayload,
            proofSignature: sig,
            resolverDid: 'did:example:resolver-001',
        };
        const result = verifyResolvedCredentialIntegrityProofSignature(
            fullProof,
            publicKey,
        );
        expect(result.valid).toBe(true);
    });

    it('should verify after multiple sign/verify cycles (deterministic)', () => {
        const { publicKey, privateKey } = makeKeyPair();
        const signedPayload = validSignedPayload();

        for (let i = 0; i < 3; i += 1) {
            const sig = signResolvedCredentialIntegrityProof(
                signedPayload,
                privateKey,
            );
            const proof: ResolvedCredentialIntegrityProof = {
                ...signedPayload,
                proofSignature: sig,
                resolverDid: 'did:example:resolver-001',
            };
            const result = verifyResolvedCredentialIntegrityProofSignature(
                proof,
                publicKey,
            );
            expect(result.valid).toBe(true);
        }
    });
});
