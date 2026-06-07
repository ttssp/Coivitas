/**
 * e2e-cross-package.test.ts — Multisig L0 (types) + L1 (crypto) + L2 (identity) cross-package end-to-end integration test
 *
 * Scope: ms v0.1 L2 identity + L0+L1 cross-package contract
 *
 * Placement:
 *   The identity (L2) package is the layer that depends on both @coivitas/types (L0) and @coivitas/crypto (L1);
 *   L1 is strictly forbidden from depending on L0 (anti-layering), so the e2e test spanning L0+L1+L2 must live in an L2+ package (identity chosen here).
 *
 * Coverage targets (>=3 cases):
 *   - case 1 (happy): L0 schema validate -> L1 generateMerkleLeaf -> L1 verifyMultisigProof -> L2 verifyMultisigToken
 *   - case 2 (schema reject): malformed MultisigToken -> L0 validateMultisigToken reject -> valid:false
 *   - case 3 (threshold fail): quorum not met -> L2 verifyMultisigToken throws MULTISIG_QUORUM_INSUFFICIENT
 *   - case 4 (challenge bind): challenge mismatch -> L2 verifyMultisigToken throws MULTISIG_CHALLENGE_INVALID
 *   - case 5 (audience mismatch): audience !== expected -> L2 throws MULTISIG_SCHEMA_VIOLATION
 *   - case 6 (notAfter expired): csp.notAfter <= now + minWindow -> L2 throws MULTISIG_SCHEMA_VIOLATION
 *
 * Cross-package contract (anti-phantom + anti cross-package drift):
 *   - L0 (@coivitas/types) schema + MultisigErrorCode union covering 14 codes;
 *   - L1 (@coivitas/crypto) generateMerkleLeaf + verifyMultisigProof throw the spec's 14 codes;
 *   - L2 (@coivitas/identity) issueMultisigToken + verifyMultisigToken implement the pipeline chaining L0+L1;
 *   - L0/L1/L2 bidirectional contract: schema reject <-> AJV 3rd defense layer; Merkle inclusion <-> leaf encoding consistency.
 */

import { describe, expect, it } from 'vitest';

import { ed25519 } from '@noble/curves/ed25519';
import {
    canonicalSerialize,
    generateMerkleLeaf,
    toHex,
    verifyMultisigProof,
    type MultisigTokenLike,
} from '@coivitas/crypto';
import {
    type CanonicalSignedPayload,
    type Hash,
    type Signature,
    validateMultisigToken,
} from '@coivitas/types';

import {
    issueMultisigToken,
    type SignerKeyMaterial,
    verifyMultisigToken,
} from '../../credentials/multisig/index.js';

// ─── helpers ────────────────────────────────────────────────────────────────

function makeKeyPair(): { publicKey: string; privateKey: string } {
    const privateBytes = ed25519.utils.randomPrivateKey();
    const publicBytes = ed25519.getPublicKey(privateBytes);
    return {
        publicKey: toHex(publicBytes),
        privateKey: toHex(privateBytes),
    };
}

function makeCsp(
    overrides: Partial<{ challenge: string; audience: string; notAfter: string }> = {},
): CanonicalSignedPayload {
    return {
        cspVersion: '1.0.0' as CanonicalSignedPayload['cspVersion'],
        token: {
            id: 'token-e2e-001',
            issuerDid: 'did:key:issuer' as CanonicalSignedPayload['token']['issuerDid'],
            principalDid: 'did:key:principal' as CanonicalSignedPayload['token']['principalDid'],
            issuedTo: 'did:key:agent' as CanonicalSignedPayload['token']['issuedTo'],
            specVersion: '0.3.0',
            issuedAt: '2026-05-18T00:00:00.000Z' as CanonicalSignedPayload['token']['issuedAt'],
            expiresAt: '2099-01-01T00:00:00.000Z' as CanonicalSignedPayload['token']['expiresAt'],
            capabilities: [
                {
                    action: 'read',
                    scope: { type: 'allowlist', field: 'res', values: [] },
                },
            ],
            revocationUrl: 'https://issuer.example.com/revocation/token-e2e-001',
            proof: {
                type: 'Ed25519Signature2026',
                created: '2026-05-18T00:00:00.000Z' as CanonicalSignedPayload['token']['proof']['created'],
                verificationMethod: 'did:key:issuer#key-1',
                value: 'sig-base64-stub' as CanonicalSignedPayload['token']['proof']['value'],
            },
        },
        disclosedClaims: [],
        challenge: (overrides.challenge ??
            '550e8400-e29b-41d4-a716-446655440000') as CanonicalSignedPayload['challenge'],
        audience: (overrides.audience ??
            'did:example:verifier') as CanonicalSignedPayload['audience'],
        notAfter: (overrides.notAfter ??
            '2099-01-01T00:00:00.000Z') as CanonicalSignedPayload['notAfter'],
    };
}

function makeSignerKeyMaterial(
    id: string,
    role: 'human' | 'agent' = 'agent',
): SignerKeyMaterial {
    const { publicKey, privateKey } = makeKeyPair();
    return { id, role, publicKey, privateKey };
}

// ─── case 1 (happy): L0+L1+L2 full closed loop ─────────────────────────────────────

describe('ms L0+L1+L2 cross-package e2e — Path A full closed loop', () => {
    /**
     * case 1 (happy):
     *   L2 issueMultisigToken (issuer side signs m signers + Merkle commitment)
     *   -> L0 validateMultisigToken AJV -> valid:true
     *   -> L1 verifyMultisigProof (Merkle inclusion + Ed25519 verify + quorum) -> valid:true
     *   -> L2 verifyMultisigToken (challenge + audience + notAfter + all of L1 pass) -> valid:true
     */
    it('case 1 (happy): issue -> schema validate -> L1 verify -> L2 verify (2-of-3 all PASS)', () => {
        const challenge = '550e8400-e29b-41d4-a716-446655440000';
        const audience = 'did:example:verifier';

        const signers: SignerKeyMaterial[] = [
            makeSignerKeyMaterial('did:key:signer-001', 'human'),
            makeSignerKeyMaterial('did:key:signer-002', 'agent'),
            makeSignerKeyMaterial('did:key:signer-003', 'agent'),
        ];

        const csp = makeCsp({ challenge, audience });

        // ── L2 issuer side ── coordinate m signers signing + Merkle commitment
        const token = issueMultisigToken({
            signers,
            threshold: 2,
            csp,
        });

        // ── L0 3rd defense layer: schema validate ──
        const schemaResult = validateMultisigToken(token);
        expect(schemaResult.valid).toBe(true);

        // ── L1 verifyMultisigProof (Merkle inclusion + Ed25519 verify + quorum) ──
        const l1Result = verifyMultisigProof(token);
        expect(l1Result.valid).toBe(true);
        expect(l1Result.validCount).toBe(3);
        expect(l1Result.threshold).toBe(2);

        // ── L2 verifyMultisigToken (challenge bind + audience + notAfter + all of L1 pass) ──
        const l2Result = verifyMultisigToken(token, {
            expectedAudience: audience,
            expectedChallenge: challenge,
        });
        expect(l2Result.valid).toBe(true);
        expect(l2Result.validCount).toBe(3);
        expect(l2Result.threshold).toBe(2);
    });

    /**
     * case 2 (schema reject):
     *   malformed MultisigToken → L0 validateMultisigToken AJV reject → valid:false
     */
    it('case 2 (schema reject): malformed token → L0 validateMultisigToken reject', () => {
        const malformed = {
            multisigVersion: '1.0.0',
            // missing threshold field
            signers: [],
            merkleRoot: 'abc',
            inclusionProofs: [],
            csp: {},
        };

        const schemaResult = validateMultisigToken(malformed);
        expect(schemaResult.valid).toBe(false);
        if (!schemaResult.valid) {
            expect(schemaResult.errors.length).toBeGreaterThan(0);
        }
    });

    /**
     * case 3 (threshold fail):
     *   tamper signer -> L1 verifyMultisigProof throws MULTISIG_QUORUM_INSUFFICIENT
     *   (design: changing one signer's signature makes Merkle inclusion fail -> throws
     *    MULTISIG_MERKLE_ROOT_INVALID at step 6.4 — short-circuits before the quorum computation)
     */
    it('case 3 (threshold/inclusion fail): tampered signer → throw at Merkle inclusion or quorum', () => {
        const challenge = '550e8400-e29b-41d4-a716-446655440000';
        const audience = 'did:example:verifier';

        const signers: SignerKeyMaterial[] = [
            makeSignerKeyMaterial('did:key:signer-001'),
            makeSignerKeyMaterial('did:key:signer-002'),
        ];

        const csp = makeCsp({ challenge, audience });
        const token = issueMultisigToken({ signers, threshold: 2, csp });

        // tamper: change signer[0]'s signature to a fake non-hex value
        const tamperedToken: MultisigTokenLike = {
            ...token,
            signers: token.signers.map((s, i) =>
                i === 0
                    ? { ...s, signature: '0'.repeat(128) } // all zeros — still valid 64-byte hex but does not correspond to a valid sig
                    : s,
            ),
        };

        // tampered signature -> recomputed leaf differs -> Merkle inclusion fails and throws first
        // (in the verify pipeline, Merkle inclusion comes before Ed25519 verify; and an Ed25519 failure also throws)
        expect(() =>
            verifyMultisigToken(tamperedToken, {
                expectedAudience: audience,
                expectedChallenge: challenge,
            }),
        ).toThrow(/MULTISIG_MERKLE_ROOT_INVALID|MULTISIG_SIGNATURE_INVALID|MULTISIG_QUORUM_INSUFFICIENT/);
    });

    /**
     * case 4 (challenge bind):
     *   csp.challenge !== verifier-issued -> L2 throws MULTISIG_CHALLENGE_INVALID
     */
    it('case 4 (challenge bind): csp.challenge !== verifier-issued -> throw MULTISIG_CHALLENGE_INVALID', () => {
        const issuanceChallenge = '550e8400-e29b-41d4-a716-446655440000';
        const verifierChallenge = '660e8400-e29b-41d4-a716-446655440001'; // different
        const audience = 'did:example:verifier';

        const signers: SignerKeyMaterial[] = [
            makeSignerKeyMaterial('did:key:signer-001'),
            makeSignerKeyMaterial('did:key:signer-002'),
        ];

        const csp = makeCsp({ challenge: issuanceChallenge, audience });
        const token = issueMultisigToken({ signers, threshold: 2, csp });

        // The verifier side uses a different challenge -> fail-closed reject
        expect(() =>
            verifyMultisigToken(token, {
                expectedAudience: audience,
                expectedChallenge: verifierChallenge,
            }),
        ).toThrow(/MULTISIG_CHALLENGE_INVALID/);
    });

    /**
     * case 5 (audience mismatch):
     *   csp.audience !== expected -> L2 throws MULTISIG_SCHEMA_VIOLATION (audience strict equality)
     */
    it('case 5 (audience mismatch): csp.audience !== expected -> throw MULTISIG_SCHEMA_VIOLATION', () => {
        const challenge = '550e8400-e29b-41d4-a716-446655440000';
        const issuanceAudience = 'did:example:verifier-A';
        const verifierAudience = 'did:example:verifier-B'; // different

        const signers: SignerKeyMaterial[] = [
            makeSignerKeyMaterial('did:key:signer-001'),
            makeSignerKeyMaterial('did:key:signer-002'),
        ];

        const csp = makeCsp({ challenge, audience: issuanceAudience });
        const token = issueMultisigToken({ signers, threshold: 2, csp });

        expect(() =>
            verifyMultisigToken(token, {
                expectedAudience: verifierAudience,
                expectedChallenge: challenge,
            }),
        ).toThrow(/MULTISIG_SCHEMA_VIOLATION.*audience/);
    });

    /**
     * case 6 (notAfter expired):
     *   csp.notAfter <= now + minWindow -> L2 throws MULTISIG_SCHEMA_VIOLATION (I5 guards against stale replay)
     */
    it('case 6 (notAfter expired): csp.notAfter in past -> throw MULTISIG_SCHEMA_VIOLATION', () => {
        const challenge = '550e8400-e29b-41d4-a716-446655440000';
        const audience = 'did:example:verifier';

        const signers: SignerKeyMaterial[] = [
            makeSignerKeyMaterial('did:key:signer-001'),
            makeSignerKeyMaterial('did:key:signer-002'),
        ];

        // Setting csp.notAfter to a past time (1 year ago) would be rejected first by L0 createCanonicalSignedPayload
        // Instead: construct the csp object directly, bypassing the factory (the e2e test simulates the expiry scenario internally)
        // Note: the csp factory already enforces notAfter > now at issuance; this e2e case is the verify-time check
        // Real scenario: an already-issued token + time elapsed -> notAfter has expired at verify time

        // We use the helper to set notAfter to a future time on the verifier side but < now + minWindow
        const csp = makeCsp({
            challenge,
            audience,
            notAfter: '2099-01-01T00:00:00.000Z', // far future
        });
        const token = issueMultisigToken({ signers, threshold: 2, csp });

        // The verifier side uses now = year 2200 (far past notAfter) -> throw
        expect(() =>
            verifyMultisigToken(token, {
                expectedAudience: audience,
                expectedChallenge: challenge,
                now: new Date('2200-01-01T00:00:00.000Z'),
            }),
        ).toThrow(/MULTISIG_SCHEMA_VIOLATION.*notAfter/);
    });
});

// ─── case 7 (cross-validation): L0 PASS ⊃ L1 PASS bidirectional reconciliation ────────────────

describe('ms L0/L1 cross-package reconciliation — schema PASS ⊃ verify PASS', () => {
    it('happy token: L0 schema PASS AND L1 verify PASS', () => {
        const signers: SignerKeyMaterial[] = [
            makeSignerKeyMaterial('did:key:signer-001'),
            makeSignerKeyMaterial('did:key:signer-002'),
            makeSignerKeyMaterial('did:key:signer-003'),
        ];

        const csp = makeCsp();
        const token = issueMultisigToken({ signers, threshold: 2, csp });

        const schemaResult = validateMultisigToken(token);
        const l1Result = verifyMultisigProof(token);

        expect(schemaResult.valid).toBe(true);
        expect(l1Result.valid).toBe(true);
    });
});
