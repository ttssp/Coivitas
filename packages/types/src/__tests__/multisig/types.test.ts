/**
 * multisig L0 types.test.ts — Multisig sub-protocol L0 types unit tests
 *
 * (ms v0.1 L0 types)
 *
 * Coverage goals (≥95% coverage):
 *   - brand type factory: toSignerId / toMerklePath / toMultisigVersion
 *   - createMultisigToken factory: completeness of 6 fields + I1-I4 invariant validation + by-field uniqueness
 *   - 14 MultisigErrorCode, each with ≥1 throw-path (anti-phantom)
 *   - assertNeverMultisigError exhaustive switch guards compile-time
 *   - handleMultisigError all 14 cases PASS
 */

import { describe, expect, it } from 'vitest';

import type { CanonicalSignedPayload } from '../../canonical-signed-payload/types.js';
import {
    assertNeverMultisigError,
    createMultisigToken,
    handleMultisigError,
    MULTISIG_MERKLE_PATH_MAX_LENGTH,
    MULTISIG_SUPPORTED_VERSIONS,
    MULTISIG_THRESHOLD_MAX_SANITY,
    MULTISIG_VERSION_CURRENT,
    toMerklePath,
    toMultisigVersion,
    toSignerId,
    type MultisigErrorCode,
} from '../../multisig/index.js';
import type { Hash, Signature } from '../../base.js';

// ─── test fixture helper ──────────────────────────────────────────────────

function makeCsp(): CanonicalSignedPayload {
    return {
        cspVersion: '1.0.0' as CanonicalSignedPayload['cspVersion'],
        token: {
            id: 'token-test-001',
            issuerDid: 'did:key:test-issuer' as CanonicalSignedPayload['token']['issuerDid'],
            principalDid:
                'did:key:test-principal' as CanonicalSignedPayload['token']['principalDid'],
            issuedTo: 'did:key:test-agent' as CanonicalSignedPayload['token']['issuedTo'],
            specVersion: '0.3.0',
            issuedAt: '2026-05-18T00:00:00.000Z' as CanonicalSignedPayload['token']['issuedAt'],
            expiresAt: '2099-01-01T00:00:00.000Z' as CanonicalSignedPayload['token']['expiresAt'],
            capabilities: [
                {
                    action: 'read',
                    scope: { type: 'allowlist', field: 'res', values: [] },
                },
            ],
            revocationUrl: 'https://issuer.example.com/revocation/token-test-001',
            proof: {
                type: 'Ed25519Signature2026',
                created: '2026-05-18T00:00:00.000Z' as CanonicalSignedPayload['token']['proof']['created'],
                verificationMethod: 'did:key:test-issuer#key-1',
                value: 'sig-base64-stub',
            },
        },
        disclosedClaims: [],
        challenge:
            '550e8400-e29b-41d4-a716-446655440000' as CanonicalSignedPayload['challenge'],
        audience: 'did:example:verifier' as CanonicalSignedPayload['audience'],
        notAfter: '2099-01-01T00:00:00.000Z' as CanonicalSignedPayload['notAfter'],
    };
}

function makeValidSignerInput(
    overrides: Partial<{ id: string; role: 'human' | 'agent' }> = {},
) {
    return {
        id: overrides.id ?? 'did:key:signer-001',
        role: overrides.role ?? ('agent' as const),
        publicKey:
            'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a',
        signature:
            'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b' as Signature,
    };
}

// ─── toSignerId factory ────────────────────────────────────────────────────

describe('toSignerId — factory + validation', () => {
    it('should accept did:* DID', () => {
        const id = toSignerId('did:key:abc123');
        expect(id).toBe('did:key:abc123');
    });

    it('should accept UUID v4', () => {
        const uuid = '550e8400-e29b-41d4-a716-446655440000';
        const id = toSignerId(uuid);
        expect(id).toBe(uuid);
    });

    it('should reject non-string input (MULTISIG_SIGNER_ID_INVALID)', () => {
        expect(() => toSignerId(123 as unknown as string)).toThrow(
            /MULTISIG_SIGNER_ID_INVALID/,
        );
    });

    it('should reject bare "did:" without identifier (MULTISIG_SIGNER_ID_INVALID)', () => {
        expect(() => toSignerId('did:')).toThrow(/MULTISIG_SIGNER_ID_INVALID/);
    });

    it('should reject non-DID non-UUID strings (MULTISIG_SIGNER_ID_INVALID)', () => {
        expect(() => toSignerId('signer-001')).toThrow(/MULTISIG_SIGNER_ID_INVALID/);
        expect(() => toSignerId('http://example.com/signer')).toThrow(
            /MULTISIG_SIGNER_ID_INVALID/,
        );
    });

    it('should reject non-v4 UUID (e.g., v1)', () => {
        // v1 UUID: the 13th position is 1, not 4
        expect(() => toSignerId('550e8400-e29b-11d4-a716-446655440000')).toThrow(
            /MULTISIG_SIGNER_ID_INVALID/,
        );
    });
});

// ─── toMerklePath factory ──────────────────────────────────────────────────

describe('toMerklePath — factory + validation', () => {
    it('should accept valid base64url string', () => {
        const path = toMerklePath('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA');
        expect(path).toBeDefined();
    });

    it('should accept base64url with padding', () => {
        const path = toMerklePath('AQID=');
        expect(path).toBeDefined();
    });

    it('should reject non-string (MULTISIG_MERKLE_PATH_INVALID)', () => {
        expect(() => toMerklePath(null as unknown as string)).toThrow(
            /MULTISIG_MERKLE_PATH_INVALID/,
        );
    });

    it('should reject empty string', () => {
        expect(() => toMerklePath('')).toThrow(/MULTISIG_MERKLE_PATH_INVALID.*empty/);
    });

    it('should reject string exceeding MULTISIG_MERKLE_PATH_MAX_LENGTH', () => {
        const tooLong = 'A'.repeat(MULTISIG_MERKLE_PATH_MAX_LENGTH + 1);
        expect(() => toMerklePath(tooLong)).toThrow(
            /MULTISIG_MERKLE_PATH_INVALID.*exceeds max/,
        );
    });

    it('should reject non-base64url characters', () => {
        expect(() => toMerklePath('invalid!@#$%')).toThrow(
            /MULTISIG_MERKLE_PATH_INVALID.*not valid base64url/,
        );
    });
});

// ─── toMultisigVersion factory ─────────────────────────────────────────────

describe('toMultisigVersion — factory + validation', () => {
    it('should accept "1.0.0" (v0.1 only supported version)', () => {
        const version = toMultisigVersion('1.0.0');
        expect(version).toBe('1.0.0');
    });

    it('should reject non-semver format', () => {
        expect(() => toMultisigVersion('1.0')).toThrow(/MULTISIG_VERSION_UNSUPPORTED/);
        expect(() => toMultisigVersion('v1.0.0')).toThrow(
            /MULTISIG_VERSION_UNSUPPORTED/,
        );
    });

    it('should reject unsupported semver value', () => {
        expect(() => toMultisigVersion('2.0.0')).toThrow(/MULTISIG_VERSION_UNSUPPORTED/);
        expect(() => toMultisigVersion('1.0.1')).toThrow(/MULTISIG_VERSION_UNSUPPORTED/);
    });

    it('should reject non-string input', () => {
        expect(() => toMultisigVersion(100 as unknown as string)).toThrow(
            /MULTISIG_VERSION_UNSUPPORTED/,
        );
    });

    it('exposes MULTISIG_SUPPORTED_VERSIONS as readonly ["1.0.0"]', () => {
        expect(MULTISIG_SUPPORTED_VERSIONS).toEqual(['1.0.0']);
        expect(MULTISIG_VERSION_CURRENT).toBe('1.0.0');
    });
});

// ─── createMultisigToken factory ───────────────────────────────────────────

describe('createMultisigToken — factory + I1-I4 invariant validation', () => {
    const csp = makeCsp();

    function makeValidInput() {
        return {
            multisigVersion: '1.0.0',
            threshold: 2,
            signers: [
                makeValidSignerInput({ id: 'did:key:signer-001' }),
                makeValidSignerInput({ id: 'did:key:signer-002', role: 'human' as const }),
                makeValidSignerInput({ id: 'did:key:signer-003' }),
            ],
            merkleRoot: 'abcd1234'.repeat(8) as Hash, // 64-char hex
            inclusionProofs: [
                { signerId: 'did:key:signer-001', path: 'AQID=' },
                { signerId: 'did:key:signer-002', path: 'BQYH=' },
                { signerId: 'did:key:signer-003', path: 'CAkK=' },
            ],
            csp,
        };
    }

    it('should produce MultisigToken with all 6 fields when input is valid (happy path)', () => {
        const token = createMultisigToken(makeValidInput());
        // equivalent to MultisigTokenStruct; no __brand wrapper (JSON Schema friendly)
        expect(token.multisigVersion).toBe('1.0.0');
        expect(token.threshold).toBe(2);
        expect(token.signers).toHaveLength(3);
        expect(token.merkleRoot).toBeDefined();
        expect(token.inclusionProofs).toHaveLength(3);
        expect(token.csp).toEqual(csp);
    });

    it('should throw MULTISIG_VERSION_UNSUPPORTED for non-1.0.0 version', () => {
        const input = makeValidInput();
        input.multisigVersion = '2.0.0';
        expect(() => createMultisigToken(input)).toThrow(/MULTISIG_VERSION_UNSUPPORTED/);
    });

    it('should throw MULTISIG_THRESHOLD_INVALID for non-integer threshold (I1)', () => {
        const input = makeValidInput();
        input.threshold = 2.5;
        expect(() => createMultisigToken(input)).toThrow(/MULTISIG_THRESHOLD_INVALID/);
    });

    it('should throw MULTISIG_THRESHOLD_INVALID for threshold < 1 (I1)', () => {
        const input = makeValidInput();
        input.threshold = 0;
        expect(() => createMultisigToken(input)).toThrow(/MULTISIG_THRESHOLD_INVALID/);
    });

    it('should throw MULTISIG_THRESHOLD_INVALID for threshold > sanity max', () => {
        const input = makeValidInput();
        input.threshold = MULTISIG_THRESHOLD_MAX_SANITY + 1;
        expect(() => createMultisigToken(input)).toThrow(
            /MULTISIG_THRESHOLD_INVALID.*sanity max/,
        );
    });

    it('should throw MULTISIG_SIGNERS_INSUFFICIENT when signers.length < threshold (I2)', () => {
        const input = makeValidInput();
        input.threshold = 5; // > 3 signers
        expect(() => createMultisigToken(input)).toThrow(
            /MULTISIG_SIGNERS_INSUFFICIENT/,
        );
    });

    it('should throw MULTISIG_SIGNER_DUPLICATE for duplicated signer IDs (I2)', () => {
        const input = makeValidInput();
        input.signers[1] = { ...input.signers[1]!, id: 'did:key:signer-001' };
        expect(() => createMultisigToken(input)).toThrow(/MULTISIG_SIGNER_DUPLICATE/);
    });

    it('should throw MULTISIG_SIGNER_ID_INVALID for bad signer ID', () => {
        const input = makeValidInput();
        input.signers[0] = { ...input.signers[0]!, id: 'bad-format' };
        expect(() => createMultisigToken(input)).toThrow(/MULTISIG_SIGNER_ID_INVALID/);
    });

    it('should throw MULTISIG_SCHEMA_VIOLATION for invalid signer role', () => {
        const input = makeValidInput();
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        input.signers[0] = { ...input.signers[0]!, role: 'invalid' as any };
        expect(() => createMultisigToken(input)).toThrow(/MULTISIG_SCHEMA_VIOLATION/);
    });

    it('should throw MULTISIG_SCHEMA_VIOLATION for empty publicKey', () => {
        const input = makeValidInput();
        input.signers[0] = { ...input.signers[0]!, publicKey: '' };
        expect(() => createMultisigToken(input)).toThrow(
            /MULTISIG_SCHEMA_VIOLATION.*publicKey/,
        );
    });

    it('should throw MULTISIG_SCHEMA_VIOLATION for empty signature', () => {
        const input = makeValidInput();
        input.signers[0] = {
            ...input.signers[0]!,
            signature: '' as Signature,
        };
        expect(() => createMultisigToken(input)).toThrow(
            /MULTISIG_SCHEMA_VIOLATION.*signature/,
        );
    });

    it('should throw MULTISIG_MERKLE_ROOT_INVALID for empty merkleRoot', () => {
        const input = makeValidInput();
        input.merkleRoot = '' as Hash;
        expect(() => createMultisigToken(input)).toThrow(/MULTISIG_MERKLE_ROOT_INVALID/);
    });

    it('should throw MULTISIG_INCLUSION_PROOF_MISSING when inclusionProofs.length !== signers.length (I4)', () => {
        const input = makeValidInput();
        input.inclusionProofs = [{ signerId: 'did:key:signer-001', path: 'AQID=' }];
        expect(() => createMultisigToken(input)).toThrow(
            /MULTISIG_INCLUSION_PROOF_MISSING/,
        );
    });

    it('should throw MULTISIG_INCLUSION_PROOF_MISSING when inclusionProof signerId not in signers set', () => {
        const input = makeValidInput();
        input.inclusionProofs[1] = { signerId: 'did:key:other-signer', path: 'BQYH=' };
        expect(() => createMultisigToken(input)).toThrow(
            /MULTISIG_INCLUSION_PROOF_MISSING.*not in signers set/,
        );
    });

    it('should throw MULTISIG_INCLUSION_PROOF_MISSING for duplicate signerId in proofs', () => {
        const input = makeValidInput();
        input.inclusionProofs[1] = { signerId: 'did:key:signer-001', path: 'BQYH=' };
        expect(() => createMultisigToken(input)).toThrow(
            /MULTISIG_INCLUSION_PROOF_MISSING.*duplicates/,
        );
    });

    it('should throw MULTISIG_TOKEN_INCOMPLETE for null csp', () => {
        const input = makeValidInput();
        input.csp = null as unknown as CanonicalSignedPayload;
        expect(() => createMultisigToken(input)).toThrow(
            /MULTISIG_TOKEN_INCOMPLETE.*csp/,
        );
    });

    it('should throw MULTISIG_TOKEN_INCOMPLETE for non-object csp', () => {
        const input = makeValidInput();
        input.csp = 'string-csp' as unknown as CanonicalSignedPayload;
        expect(() => createMultisigToken(input)).toThrow(
            /MULTISIG_TOKEN_INCOMPLETE.*csp/,
        );
    });

    it('should throw MULTISIG_TOKEN_INCOMPLETE for non-array signers', () => {
        const input = makeValidInput();
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        input.signers = 'not-array' as any;
        expect(() => createMultisigToken(input)).toThrow(
            /MULTISIG_TOKEN_INCOMPLETE.*signers/,
        );
    });

    it('should throw MULTISIG_TOKEN_INCOMPLETE for non-array inclusionProofs', () => {
        const input = makeValidInput();
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        input.inclusionProofs = null as any;
        expect(() => createMultisigToken(input)).toThrow(
            /MULTISIG_TOKEN_INCOMPLETE.*inclusionProofs/,
        );
    });

    it('should throw MULTISIG_MERKLE_PATH_INVALID for bad path format', () => {
        const input = makeValidInput();
        input.inclusionProofs[0] = {
            signerId: 'did:key:signer-001',
            path: 'invalid!@#$',
        };
        expect(() => createMultisigToken(input)).toThrow(/MULTISIG_MERKLE_PATH_INVALID/);
    });

    it('should throw MULTISIG_TOKEN_INCOMPLETE for null signer entry', () => {
        const input = makeValidInput();
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        input.signers[0] = null as any;
        expect(() => createMultisigToken(input)).toThrow(
            /MULTISIG_TOKEN_INCOMPLETE.*signers\[0\]/,
        );
    });

    it('should throw MULTISIG_TOKEN_INCOMPLETE for null inclusionProof entry', () => {
        const input = makeValidInput();
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        input.inclusionProofs[0] = null as any;
        expect(() => createMultisigToken(input)).toThrow(
            /MULTISIG_TOKEN_INCOMPLETE.*inclusionProofs\[0\]/,
        );
    });
});

// ─── handleMultisigError full coverage of 14 cases ────────────────────────────────────

describe('handleMultisigError — 14 case exhaustive switch', () => {
    const cases: MultisigErrorCode[] = [
        'MULTISIG_TOKEN_INCOMPLETE',
        'MULTISIG_VERSION_UNSUPPORTED',
        'MULTISIG_THRESHOLD_INVALID',
        'MULTISIG_SIGNERS_INSUFFICIENT',
        'MULTISIG_SIGNER_DUPLICATE',
        'MULTISIG_SIGNER_ID_INVALID',
        'MULTISIG_MERKLE_ROOT_INVALID',
        'MULTISIG_MERKLE_PATH_INVALID',
        'MULTISIG_INCLUSION_PROOF_MISSING',
        'MULTISIG_SIGNATURE_INVALID',
        'MULTISIG_QUORUM_INSUFFICIENT',
        'MULTISIG_PARTIAL_SIGNED_REJECTED',
        'MULTISIG_CHALLENGE_INVALID',
        'MULTISIG_SCHEMA_VIOLATION',
    ];

    it('should have 14 active error codes (R2 frozen baseline)', () => {
        expect(cases).toHaveLength(14);
    });

    for (const code of cases) {
        it(`should map ${code} to MultisigErrorContext with valid httpStatus + fatal`, () => {
            const ctx = handleMultisigError(code);
            expect(ctx.code).toBe(code);
            expect([400, 401, 403, 422, 503]).toContain(ctx.httpStatus);
            expect(ctx.fatal).toBe(true);
            expect(typeof ctx.message).toBe('string');
            expect(ctx.message.length).toBeGreaterThan(0);
        });
    }

    it('should map MULTISIG_VERSION_UNSUPPORTED to 422 (MED severity)', () => {
        const ctx = handleMultisigError('MULTISIG_VERSION_UNSUPPORTED');
        expect(ctx.httpStatus).toBe(422);
    });

    it('should map MULTISIG_QUORUM_INSUFFICIENT to 401 (auth severity)', () => {
        const ctx = handleMultisigError('MULTISIG_QUORUM_INSUFFICIENT');
        expect(ctx.httpStatus).toBe(401);
    });
});

// ─── assertNeverMultisigError — exhaustive guard ──────────────────────────

describe('assertNeverMultisigError — exhaustive guard', () => {
    it('should throw when called at runtime (unreachable type guard)', () => {
        // simulate the scenario where the type system is bypassed at runtime
        expect(() => assertNeverMultisigError('FAKE_CODE' as never)).toThrow(
            /Unreachable.*FAKE_CODE/,
        );
    });
});
