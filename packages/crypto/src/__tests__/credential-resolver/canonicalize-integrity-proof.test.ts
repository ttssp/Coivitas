/**
 * CR L1 canonicalize-integrity-proof.test.ts — JCS canonicalize primitive unit tests
 *
 * Implements: cr v0.1 L1 crypto
 *            constraint 3 FULL RFC 8785 JCS canonicalize
 *
 * Coverage goals:
 *   - canonicalizeResolvedCredentialIntegrityProof: 6 fields -> Uint8Array
 *   - canonicalizeResolvedCredentialIntegrityProofToString: 6 fields -> string
 *   - extractIntegrityProofSignedPayload: full proof -> 6 fields (excluding proofSignature / resolverDid)
 *   - assertSerializable fail-closed: undefined / function / symbol / bigint / NaN / Infinity / circular
 *   - JCS lexicographic sort (RFC 8785 — field names token-sorted)
 *   - UTF-8 encoding consistency (canonical bytes can round-trip with the string form)
 */

import { describe, expect, it } from 'vitest';

import {
    canonicalizeResolvedCredentialIntegrityProof,
    canonicalizeResolvedCredentialIntegrityProofToString,
    CrError,
    extractIntegrityProofSignedPayload,
    type ResolvedCredentialIntegrityProofSignedPayload,
} from '../../credential-resolver/index.js';

// ─── test fixture ───────────────────────────────────────────────────────────

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

// ─── extractIntegrityProofSignedPayload ─────────────────────────────────────

describe('extractIntegrityProofSignedPayload — full proof -> 6-field signed payload', () => {
    it('should extract 6 fields (5 invariant + cspVersion) and exclude proofSignature/resolverDid', () => {
        const fullProof = {
            ...validSignedPayload(),
            proofSignature: 'a'.repeat(128),
            resolverDid: 'did:example:resolver-001',
        };
        const extracted = extractIntegrityProofSignedPayload(fullProof);
        expect(extracted.token).toBe(fullProof.token);
        expect(extracted.disclosedClaims).toEqual(fullProof.disclosedClaims);
        expect(extracted.challenge).toBe(fullProof.challenge);
        expect(extracted.audience).toBe(fullProof.audience);
        expect(extracted.notAfter).toBe(fullProof.notAfter);
        expect(extracted.cspVersion).toBe(fullProof.cspVersion);
        // Does not contain proofSignature / resolverDid
        expect(Object.keys(extracted).sort()).toEqual([
            'audience',
            'challenge',
            'cspVersion',
            'disclosedClaims',
            'notAfter',
            'token',
        ]);
    });
});

// ─── canonicalizeResolvedCredentialIntegrityProof (Uint8Array output) ─────────

describe('canonicalizeResolvedCredentialIntegrityProof — JCS canonical encode -> Uint8Array', () => {
    it('should produce non-empty Uint8Array for valid payload', () => {
        const bytes =
            canonicalizeResolvedCredentialIntegrityProof(validSignedPayload());
        expect(bytes).toBeInstanceOf(Uint8Array);
        expect(bytes.length).toBeGreaterThan(0);
    });

    it('should produce deterministic bytes (RFC 8785 lexicographic order; independent calls match)', () => {
        const bytes1 =
            canonicalizeResolvedCredentialIntegrityProof(validSignedPayload());
        const bytes2 =
            canonicalizeResolvedCredentialIntegrityProof(validSignedPayload());
        expect(bytes1).toEqual(bytes2);
    });

    it('should produce deterministic bytes for different field order (lexicographic sort)', () => {
        const payload1 = validSignedPayload();
        const payload2: ResolvedCredentialIntegrityProofSignedPayload = {
            cspVersion: payload1.cspVersion,
            notAfter: payload1.notAfter,
            audience: payload1.audience,
            challenge: payload1.challenge,
            disclosedClaims: payload1.disclosedClaims,
            token: payload1.token,
        };
        const bytes1 = canonicalizeResolvedCredentialIntegrityProof(payload1);
        const bytes2 = canonicalizeResolvedCredentialIntegrityProof(payload2);
        // JCS automatically sorts by field name lexicographically; both input orders produce identical canonical bytes
        expect(bytes1).toEqual(bytes2);
    });

    it('should be valid UTF-8 (decodable back to JSON)', () => {
        const bytes =
            canonicalizeResolvedCredentialIntegrityProof(validSignedPayload());
        const decoder = new TextDecoder();
        const text = decoder.decode(bytes);
        const parsed = JSON.parse(text) as Record<string, unknown>;
        expect(parsed['token']).toBe(validSignedPayload().token);
        expect(parsed['cspVersion']).toBe('1.0.0');
    });
});

// ─── canonicalizeResolvedCredentialIntegrityProofToString (string output) ─────

describe('canonicalizeResolvedCredentialIntegrityProofToString — JCS canonical encode -> string', () => {
    it('should produce non-empty string for valid payload', () => {
        const text =
            canonicalizeResolvedCredentialIntegrityProofToString(
                validSignedPayload(),
            );
        expect(typeof text).toBe('string');
        expect(text.length).toBeGreaterThan(0);
    });

    it('should produce JSON-parseable string', () => {
        const text =
            canonicalizeResolvedCredentialIntegrityProofToString(
                validSignedPayload(),
            );
        const parsed = JSON.parse(text) as Record<string, unknown>;
        expect(parsed['cspVersion']).toBe('1.0.0');
    });

    it('should produce strictly-sorted field names (lexicographic; RFC 8785 §3.2.3)', () => {
        const text =
            canonicalizeResolvedCredentialIntegrityProofToString(
                validSignedPayload(),
            );
        // JCS canonical output: audience < challenge < cspVersion < disclosedClaims < notAfter < token
        // (lexicographic; ASCII lowercase)
        const audienceIdx = text.indexOf('"audience"');
        const challengeIdx = text.indexOf('"challenge"');
        const cspVersionIdx = text.indexOf('"cspVersion"');
        const disclosedClaimsIdx = text.indexOf('"disclosedClaims"');
        const notAfterIdx = text.indexOf('"notAfter"');
        const tokenIdx = text.indexOf('"token"');
        expect(audienceIdx).toBeGreaterThanOrEqual(0);
        expect(challengeIdx).toBeGreaterThan(audienceIdx);
        expect(cspVersionIdx).toBeGreaterThan(challengeIdx);
        expect(disclosedClaimsIdx).toBeGreaterThan(cspVersionIdx);
        expect(notAfterIdx).toBeGreaterThan(disclosedClaimsIdx);
        expect(tokenIdx).toBeGreaterThan(notAfterIdx);
    });
});

// ─── assertSerializable fail-closed (CR_INTEGRITY_PROOF_INVALID anti-phantom) ─

describe('canonicalize assertSerializable — fail-closed reject of illegal JCS types', () => {
    it('should reject undefined value (CR_INTEGRITY_PROOF_INVALID)', () => {
        const bad = {
            ...validSignedPayload(),
            token: undefined as unknown as string,
        };
        expect(() => canonicalizeResolvedCredentialIntegrityProof(bad)).toThrow(
            CrError,
        );
        try {
            canonicalizeResolvedCredentialIntegrityProof(bad);
        } catch (err) {
            expect((err as CrError).code).toBe('CR_INTEGRITY_PROOF_INVALID');
        }
    });

    it('should reject function value (CR_INTEGRITY_PROOF_INVALID)', () => {
        const bad = {
            ...validSignedPayload(),
            token: (() => 'x') as unknown as string,
        };
        expect(() => canonicalizeResolvedCredentialIntegrityProof(bad)).toThrow(
            CrError,
        );
    });

    it('should reject symbol value', () => {
        const bad = {
            ...validSignedPayload(),
            token: Symbol('x') as unknown as string,
        };
        expect(() => canonicalizeResolvedCredentialIntegrityProof(bad)).toThrow(
            CrError,
        );
    });

    it('should reject bigint value', () => {
        const bad = {
            ...validSignedPayload(),
            token: 100n as unknown as string,
        };
        expect(() => canonicalizeResolvedCredentialIntegrityProof(bad)).toThrow(
            CrError,
        );
    });

    it('should reject NaN in disclosedClaims array element', () => {
        const bad = {
            ...validSignedPayload(),
            disclosedClaims: [NaN as unknown as string],
        };
        expect(() => canonicalizeResolvedCredentialIntegrityProof(bad)).toThrow(
            CrError,
        );
    });

    it('should reject Infinity', () => {
        const bad = {
            ...validSignedPayload(),
            challenge: Infinity as unknown as string,
        };
        expect(() => canonicalizeResolvedCredentialIntegrityProof(bad)).toThrow(
            CrError,
        );
    });

    it('should reject circular reference', () => {
        const circular: Record<string, unknown> = {
            ...validSignedPayload(),
        };
        circular['self'] = circular;
        expect(() =>
            canonicalizeResolvedCredentialIntegrityProof(
                circular as unknown as ResolvedCredentialIntegrityProofSignedPayload,
            ),
        ).toThrow(CrError);
    });

    it('toString variant should also reject non-JCS-serializable types', () => {
        const bad = {
            ...validSignedPayload(),
            audience: undefined as unknown as string,
        };
        expect(() =>
            canonicalizeResolvedCredentialIntegrityProofToString(bad),
        ).toThrow(CrError);
    });
});
