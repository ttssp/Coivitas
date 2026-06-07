/**
 * CR L2 verify-resolved-credential.test.ts — verifyResolvedCredential unit tests
 *
 * Implements: cr v0.1 L2 identity
 *
 * Coverage goals:
 *   - verifyResolvedCredential 7-step validation (cspVersion / crVersion / notAfter / challenge /
 *     audience / link.userId / Ed25519 signature)
 *   - all fail-closed throw cases (CR_VERSION_UNSUPPORTED / CR_FRESHNESS_INVALID /
 *     CR_INTEGRITY_PROOF_INVALID / CR_PORT_CONTRACT_VIOLATION)
 *   - notAfter boundary cases (Date parse error / boundary value)
 */

import { describe, expect, it } from 'vitest';

import { ed25519 } from '@noble/curves/ed25519';

import {
    signResolvedCredentialIntegrityProof,
    type ResolvedCredentialIntegrityProofSignedPayload,
} from '@coivitas/crypto';
import {
    CR_VERSION_1_0_0,
    CrError,
    toFederationLinkId,
    toUserId,
    toTenantId,
    toNormalizedOidcClaims,
    type FederationIdentityLink,
    type ResolvedCredential,
} from '@coivitas/types';

import { verifyResolvedCredential } from '../../index.js';

const TEST_TENANT_ID = toTenantId('550e8400-e29b-41d4-a716-446655440000');
const TEST_USER_ID = toUserId('550e8400-e29b-41d4-a716-446655440001');
const TEST_LINK_ID = toFederationLinkId('550e8400-e29b-41d4-a716-446655440002');

const TEST_VERIFIER_DID = 'did:example:verifier-001';
const TEST_CHALLENGE = '550e8400-e29b-41d4-a716-446655440099';
const TEST_RESOLVER_DID = 'did:example:resolver-001';

function makeKeyPair(): { publicKey: Uint8Array; privateKey: Uint8Array } {
    const privateKey = ed25519.utils.randomPrivateKey();
    const publicKey = ed25519.getPublicKey(privateKey);
    return { publicKey, privateKey };
}

function makeLink(
    overrides: Partial<FederationIdentityLink> = {},
): FederationIdentityLink {
    return {
        id: TEST_LINK_ID,
        tenantId: TEST_TENANT_ID,
        source: 'oidc',
        issuer: 'https://oidc.example.com',
        federatedSubject: 'subject-001',
        userId: TEST_USER_ID,
        signature: 'a'.repeat(128),
        createdAt: '2026-05-18T00:00:00.000Z',
        revoked: false,
        ...overrides,
    };
}

function makeResolved(
    overrides: {
        signedPayload?: Partial<ResolvedCredentialIntegrityProofSignedPayload>;
        link?: Partial<FederationIdentityLink>;
        crVersion?: string;
        privateKey?: Uint8Array;
    } = {},
): ResolvedCredential {
    const privateKey = overrides.privateKey ?? makeKeyPair().privateKey;
    const signedPayload: ResolvedCredentialIntegrityProofSignedPayload = {
        token: `cr:${TEST_LINK_ID}:user=${TEST_USER_ID}`,
        disclosedClaims: [
            `issuer:https://oidc.example.com`,
            `subject:subject-001`,
            `userId:${TEST_USER_ID}`,
        ],
        challenge: TEST_CHALLENGE,
        audience: TEST_VERIFIER_DID,
        notAfter: '2099-01-01T00:00:00.000Z',
        cspVersion: '1.0.0',
        ...overrides.signedPayload,
    };
    const proofSignature = signResolvedCredentialIntegrityProof(
        signedPayload,
        privateKey,
    );
    return {
        crVersion: (overrides.crVersion ??
            CR_VERSION_1_0_0) as typeof CR_VERSION_1_0_0,
        link: makeLink(overrides.link),
        source: 'oidc',
        normalizedClaims: toNormalizedOidcClaims({
            source: 'oidc',
            issuer: 'https://oidc.example.com',
            subject: 'subject-001',
            audience: ['oidc-client-001'],
            expiresAt: new Date('2099-01-01T00:00:00.000Z'),
            issuedAt: new Date('2026-01-01T00:00:00.000Z'),
        }),
        notRevoked: true,
        integrityProof: {
            ...signedPayload,
            proofSignature,
            resolverDid: TEST_RESOLVER_DID,
        },
        resolvedAt: '2026-05-18T00:00:00.000Z',
    } as ResolvedCredential;
}

// ─── happy path ─────────────────────────────────────────────────────────────

describe('verifyResolvedCredential — happy path', () => {
    it('should PASS with correct publicKey + challenge + audience', () => {
        const { publicKey, privateKey } = makeKeyPair();
        const resolved = makeResolved({ privateKey });
        expect(() =>
            verifyResolvedCredential(
                resolved,
                publicKey,
                TEST_CHALLENGE,
                TEST_VERIFIER_DID,
            ),
        ).not.toThrow();
    });
});

// ─── cspVersion validation ────────────────────────────────────────────────────────

describe('verifyResolvedCredential — cspVersion check', () => {
    it('should throw CR_VERSION_UNSUPPORTED when cspVersion !== "1.0.0"', () => {
        const { publicKey, privateKey } = makeKeyPair();
        const resolved = makeResolved({
            signedPayload: { cspVersion: '2.0.0' },
            privateKey,
        });
        expect(() =>
            verifyResolvedCredential(
                resolved,
                publicKey,
                TEST_CHALLENGE,
                TEST_VERIFIER_DID,
            ),
        ).toThrow(CrError);
        try {
            verifyResolvedCredential(
                resolved,
                publicKey,
                TEST_CHALLENGE,
                TEST_VERIFIER_DID,
            );
        } catch (err) {
            expect((err as CrError).code).toBe('CR_VERSION_UNSUPPORTED');
            expect((err as CrError).detail?.['field']).toBe('cspVersion');
        }
    });
});

// ─── crVersion validation ─────────────────────────────────────────────────────────

describe('verifyResolvedCredential — crVersion check', () => {
    it('should throw CR_VERSION_UNSUPPORTED when crVersion !== "1.0.0"', () => {
        const { publicKey, privateKey } = makeKeyPair();
        const resolved = makeResolved({ privateKey });
        // manually tamper with crVersion (bypass brand factory)
        const tampered = {
            ...resolved,
            crVersion: '0.9.0' as unknown as typeof resolved.crVersion,
        };
        expect(() =>
            verifyResolvedCredential(
                tampered,
                publicKey,
                TEST_CHALLENGE,
                TEST_VERIFIER_DID,
            ),
        ).toThrow(CrError);
        try {
            verifyResolvedCredential(
                tampered,
                publicKey,
                TEST_CHALLENGE,
                TEST_VERIFIER_DID,
            );
        } catch (err) {
            expect((err as CrError).code).toBe('CR_VERSION_UNSUPPORTED');
            expect((err as CrError).detail?.['field']).toBe('crVersion');
        }
    });
});

// ─── notAfter validation ──────────────────────────────────────────────────────────

describe('verifyResolvedCredential — notAfter freshness check', () => {
    it('should throw CR_FRESHNESS_INVALID when notAfter is in the past', () => {
        const { publicKey, privateKey } = makeKeyPair();
        const resolved = makeResolved({
            signedPayload: { notAfter: '2020-01-01T00:00:00.000Z' },
            privateKey,
        });
        expect(() =>
            verifyResolvedCredential(
                resolved,
                publicKey,
                TEST_CHALLENGE,
                TEST_VERIFIER_DID,
            ),
        ).toThrow(CrError);
        try {
            verifyResolvedCredential(
                resolved,
                publicKey,
                TEST_CHALLENGE,
                TEST_VERIFIER_DID,
            );
        } catch (err) {
            expect((err as CrError).code).toBe('CR_FRESHNESS_INVALID');
            expect((err as CrError).detail?.['reason']).toBe(
                'integrity_proof_expired',
            );
        }
    });

    it('should throw CR_FRESHNESS_INVALID when notAfter is not parseable', () => {
        const { publicKey, privateKey } = makeKeyPair();
        const resolved = makeResolved({
            signedPayload: { notAfter: 'not-a-date' },
            privateKey,
        });
        expect(() =>
            verifyResolvedCredential(
                resolved,
                publicKey,
                TEST_CHALLENGE,
                TEST_VERIFIER_DID,
            ),
        ).toThrow(CrError);
        try {
            verifyResolvedCredential(
                resolved,
                publicKey,
                TEST_CHALLENGE,
                TEST_VERIFIER_DID,
            );
        } catch (err) {
            expect((err as CrError).code).toBe('CR_FRESHNESS_INVALID');
            expect((err as CrError).detail?.['reason']).toBe(
                'notAfter_not_parseable',
            );
        }
    });
});

// ─── challenge validation ─────────────────────────────────────────────────────────

describe('verifyResolvedCredential — challenge replay defense', () => {
    it('should throw CR_INTEGRITY_PROOF_INVALID when expectedChallenge !== proof.challenge', () => {
        const { publicKey, privateKey } = makeKeyPair();
        const resolved = makeResolved({ privateKey });
        expect(() =>
            verifyResolvedCredential(
                resolved,
                publicKey,
                'WRONG-CHALLENGE',
                TEST_VERIFIER_DID,
            ),
        ).toThrow(CrError);
        try {
            verifyResolvedCredential(
                resolved,
                publicKey,
                'WRONG-CHALLENGE',
                TEST_VERIFIER_DID,
            );
        } catch (err) {
            expect((err as CrError).code).toBe('CR_INTEGRITY_PROOF_INVALID');
            expect((err as CrError).detail?.['reason']).toBe(
                'challenge_mismatch',
            );
        }
    });
});

// ─── audience validation ──────────────────────────────────────────────────────────

describe('verifyResolvedCredential — audience hijack defense', () => {
    it('should throw CR_INTEGRITY_PROOF_INVALID when verifierDid !== proof.audience', () => {
        const { publicKey, privateKey } = makeKeyPair();
        const resolved = makeResolved({ privateKey });
        expect(() =>
            verifyResolvedCredential(
                resolved,
                publicKey,
                TEST_CHALLENGE,
                'did:example:attacker',
            ),
        ).toThrow(CrError);
        try {
            verifyResolvedCredential(
                resolved,
                publicKey,
                TEST_CHALLENGE,
                'did:example:attacker',
            );
        } catch (err) {
            expect((err as CrError).code).toBe('CR_INTEGRITY_PROOF_INVALID');
            expect((err as CrError).detail?.['reason']).toBe(
                'audience_mismatch',
            );
        }
    });
});

// ─── link.userId validation ──────────────────────────────────────────────────────

describe('verifyResolvedCredential — port contract violation (link.userId)', () => {
    it('should throw CR_PORT_CONTRACT_VIOLATION when link.userId is empty string', () => {
        const { publicKey, privateKey } = makeKeyPair();
        const resolved = makeResolved({ privateKey });
        const tampered = {
            ...resolved,
            link: {
                ...resolved.link,
                userId: '' as unknown as typeof resolved.link.userId,
            },
        };
        expect(() =>
            verifyResolvedCredential(
                tampered,
                publicKey,
                TEST_CHALLENGE,
                TEST_VERIFIER_DID,
            ),
        ).toThrow(CrError);
        try {
            verifyResolvedCredential(
                tampered,
                publicKey,
                TEST_CHALLENGE,
                TEST_VERIFIER_DID,
            );
        } catch (err) {
            expect((err as CrError).code).toBe('CR_PORT_CONTRACT_VIOLATION');
            expect((err as CrError).detail?.['reason']).toBe(
                'link_userId_invalid',
            );
        }
    });

    it('should throw CR_PORT_CONTRACT_VIOLATION when link.userId is non-string', () => {
        const { publicKey, privateKey } = makeKeyPair();
        const resolved = makeResolved({ privateKey });
        const tampered = {
            ...resolved,
            link: {
                ...resolved.link,
                userId: 123 as unknown as typeof resolved.link.userId,
            },
        };
        expect(() =>
            verifyResolvedCredential(
                tampered,
                publicKey,
                TEST_CHALLENGE,
                TEST_VERIFIER_DID,
            ),
        ).toThrow(CrError);
    });
});

// ─── Ed25519 signature verify (L1 propagate) ────────────────────────────────

describe('verifyResolvedCredential — signature verify (L1 propagate)', () => {
    it('should throw CR_INTEGRITY_PROOF_INVALID when wrong publicKey provided', () => {
        const { privateKey } = makeKeyPair();
        const wrongPubKey = makeKeyPair().publicKey;
        const resolved = makeResolved({ privateKey });
        expect(() =>
            verifyResolvedCredential(
                resolved,
                wrongPubKey,
                TEST_CHALLENGE,
                TEST_VERIFIER_DID,
            ),
        ).toThrow(CrError);
        try {
            verifyResolvedCredential(
                resolved,
                wrongPubKey,
                TEST_CHALLENGE,
                TEST_VERIFIER_DID,
            );
        } catch (err) {
            expect((err as CrError).code).toBe('CR_INTEGRITY_PROOF_INVALID');
            expect((err as CrError).detail?.['reason']).toBe(
                'signature_verify_failed',
            );
        }
    });
});
