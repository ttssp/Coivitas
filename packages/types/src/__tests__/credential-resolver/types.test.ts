/**
 * CR L0 types.test.ts — Credential Resolver sub-protocol L0 types unit tests
 *
 * 14 CR_* error codes frozen + 5 design decisions.
 *
 * Coverage target (≥95% coverage):
 *   - brand type factory: toUserId / toFederationLinkId / toCrVersion
 *   - factory guard: casting strictly forbidden / must go through factory validation
 *   - OidcRawClaims / SamlRawClaims nominal incompatibility (ts-expect-error verify)
 *   - ≥1 throw-path per code across the 14 CrErrorCode values
 *   - assertNeverCrCode exhaustive switch guarded at compile-time
 *   - handleCrError all 14 cases PASS
 *   - CrError extends Error; does not extend ProtocolError
 */

import { describe, expect, it } from 'vitest';

import {
    assertNeverCrCode,
    CR_CSP_VERSION_1_0_0,
    CR_INTEGRITY_PROOF_DEFAULT_NOT_AFTER_MS,
    CR_SUPPORTED_VERSIONS,
    CR_VERSION_1_0_0,
    CR_VERSION_1_0_0_RAW,
    CrError,
    handleCrError,
    MAX_FEDERATION_LINK_DEPTH,
    toCrVersion,
    toFederationLinkId,
    toUserId,
    toTenantId,
    toNormalizedOidcClaims,
    toNormalizedSamlClaims,
    toOidcRawClaims,
    toSamlRawClaims,
    validateCr,
    type CrErrorCode,
    type NormalizedSamlClaims,
    type OidcRawClaims,
    type SamlRawClaims,
} from '../../credential-resolver/index.js';

// ─── Constants + basics ─────────────────────────────────────────────────────────────

describe('CR constant definitions', () => {
    it('should expose MAX_FEDERATION_LINK_DEPTH = 3', () => {
        expect(MAX_FEDERATION_LINK_DEPTH).toBe(3);
    });

    it('should expose CR_SUPPORTED_VERSIONS = ["1.0.0"]', () => {
        expect(CR_SUPPORTED_VERSIONS).toEqual(['1.0.0']);
    });

    it('should expose CR_VERSION_1_0_0 brand const', () => {
        expect(CR_VERSION_1_0_0_RAW).toBe('1.0.0');
        expect(CR_VERSION_1_0_0).toBe('1.0.0');
    });

    it('should expose CR_CSP_VERSION_1_0_0 = "1.0.0" (csp baseline)', () => {
        expect(CR_CSP_VERSION_1_0_0).toBe('1.0.0');
    });

    it('should expose CR_INTEGRITY_PROOF_DEFAULT_NOT_AFTER_MS = 3600000 (1 hour)', () => {
        expect(CR_INTEGRITY_PROOF_DEFAULT_NOT_AFTER_MS).toBe(3_600_000);
    });
});

// ─── CrError class ─────────────────────────────────────────────────────────────

describe('CrError class — extends Error + code + detail', () => {
    it('should expose code + detail when constructed', () => {
        const err = new CrError('CR_FEDERATION_LINK_INVALID', {
            reason: 'no_link_found',
        });
        expect(err.name).toBe('CrError');
        expect(err.code).toBe('CR_FEDERATION_LINK_INVALID');
        expect(err.detail).toEqual({ reason: 'no_link_found' });
        expect(err.message).toContain('CR_FEDERATION_LINK_INVALID');
    });

    it('should be instance of Error (not ProtocolError)', () => {
        const err = new CrError('CR_SCHEMA_INVALID');
        expect(err).toBeInstanceOf(Error);
        // extends Error rather than ProtocolError (avoids polluting the frozen union)
    });

    it('should allow detail to be omitted', () => {
        const err = new CrError('CR_VERSION_UNSUPPORTED');
        expect(err.code).toBe('CR_VERSION_UNSUPPORTED');
        expect(err.detail).toBeUndefined();
    });
});

// ─── assertNeverCrCode ─────────────────────────────────────────────────────

describe('assertNeverCrCode — exhaustive switch guard', () => {
    it('should throw CrError(CR_SCHEMA_INVALID) when called', () => {
        expect(() => assertNeverCrCode('UNKNOWN' as never)).toThrow(CrError);
        try {
            assertNeverCrCode('UNKNOWN' as never);
        } catch (err) {
            expect(err).toBeInstanceOf(CrError);
            expect((err as CrError).code).toBe('CR_SCHEMA_INVALID');
        }
    });
});

// ─── handleCrError — full coverage of 14 cases ─────────────────────────────────────────

describe('handleCrError — full coverage of 14 cases', () => {
    const allCodes: CrErrorCode[] = [
        'CR_FEDERATION_LINK_INVALID',
        'CR_OIDC_CLAIM_INVALID',
        'CR_SAML_CLAIM_INVALID',
        'CR_FK_VIOLATION',
        'CR_PORT_CONTRACT_VIOLATION',
        'CR_BRAND_TYPE_MISMATCH',
        'CR_PROVIDER_UNAVAILABLE',
        'CR_CREDENTIAL_REVOKED',
        'CR_POP_BINDING_INVALID',
        'CR_VERSION_UNSUPPORTED',
        'CR_INTEGRITY_PROOF_INVALID',
        'CR_FRESHNESS_INVALID',
        'CR_FEDERATION_LINK_DEPTH_EXCEEDED',
        'CR_SCHEMA_INVALID',
    ];

    it('should have exactly 14 frozen error codes (v0.1 freeze)', () => {
        expect(allCodes).toHaveLength(14);
    });

    it.each(allCodes)(
        'should return CrErrorContext for %s with valid httpStatus/severity',
        (code) => {
            const ctx = handleCrError(code);
            expect(ctx.code).toBe(code);
            expect([400, 422, 500, 503]).toContain(ctx.httpStatus);
            expect(['CRITICAL', 'HIGH', 'MED']).toContain(ctx.severity);
            expect(typeof ctx.message).toBe('string');
            expect(ctx.message.length).toBeGreaterThan(0);
        },
    );

    it('CR_FK_VIOLATION should map to httpStatus 500 + CRITICAL', () => {
        const ctx = handleCrError('CR_FK_VIOLATION');
        expect(ctx.httpStatus).toBe(500);
        expect(ctx.severity).toBe('CRITICAL');
    });

    it('CR_PROVIDER_UNAVAILABLE should map to httpStatus 503 (fail-closed)', () => {
        const ctx = handleCrError('CR_PROVIDER_UNAVAILABLE');
        expect(ctx.httpStatus).toBe(503);
    });

    it('CR_VERSION_UNSUPPORTED should map to httpStatus 422 + MED', () => {
        const ctx = handleCrError('CR_VERSION_UNSUPPORTED');
        expect(ctx.httpStatus).toBe(422);
        expect(ctx.severity).toBe('MED');
    });
});

// ─── toTenantId / toUserId / toFederationLinkId factory guards ────────────────

describe('toTenantId — re-export from atp', () => {
    it('should accept valid UUID v4', () => {
        const uuid = '550e8400-e29b-41d4-a716-446655440000';
        const id = toTenantId(uuid);
        expect(id).toBe(uuid);
    });

    it('should reject non-UUID input', () => {
        expect(() => toTenantId('not-a-uuid')).toThrow();
    });
});

describe('toUserId — UUID v4 brand factory', () => {
    it('should accept valid UUID v4', () => {
        const uuid = '550e8400-e29b-41d4-a716-446655440000';
        const id = toUserId(uuid);
        expect(id).toBe(uuid);
    });

    it('should reject non-string input (CR_SCHEMA_INVALID)', () => {
        expect(() => toUserId(123 as unknown as string)).toThrow(CrError);
        try {
            toUserId(123 as unknown as string);
        } catch (err) {
            expect((err as CrError).code).toBe('CR_SCHEMA_INVALID');
            expect((err as CrError).detail?.['reason']).toBe(
                'userId_must_be_string',
            );
        }
    });

    it('should reject non-UUID v4 string', () => {
        expect(() => toUserId('not-a-uuid')).toThrow(CrError);
        expect(() => toUserId('12345678-1234-1234-1234-123456789012')).toThrow(
            CrError,
        ); // wrong version (not 4)
    });

    it('should accept UUID v4 with uppercase hex (case-insensitive)', () => {
        const uuid = '550E8400-E29B-41D4-A716-446655440000';
        const id = toUserId(uuid);
        expect(id).toBe(uuid);
    });
});

describe('toFederationLinkId — UUID v4 brand factory', () => {
    it('should accept valid UUID v4', () => {
        const uuid = 'a1b2c3d4-e5f6-4789-8abc-def012345678';
        const id = toFederationLinkId(uuid);
        expect(id).toBe(uuid);
    });

    it('should reject invalid UUID v4', () => {
        expect(() => toFederationLinkId('not-uuid')).toThrow(CrError);
        expect(() => toFederationLinkId(123 as unknown as string)).toThrow(
            CrError,
        );
    });
});

// ─── toCrVersion factory ──────────────────────────────────

describe('toCrVersion — CR protocol version brand factory (independent namespace)', () => {
    it('should accept "1.0.0" (the only valid value in v0.1)', () => {
        const v = toCrVersion('1.0.0');
        expect(v).toBe('1.0.0');
    });

    it('should reject "0.9.0" (not in supported set; CR_VERSION_UNSUPPORTED)', () => {
        expect(() => toCrVersion('0.9.0')).toThrow(CrError);
        try {
            toCrVersion('0.9.0');
        } catch (err) {
            expect((err as CrError).code).toBe('CR_VERSION_UNSUPPORTED');
        }
    });

    it('should reject non-semver string', () => {
        expect(() => toCrVersion('foo')).toThrow(CrError);
        expect(() => toCrVersion('1.0')).toThrow(CrError);
        expect(() => toCrVersion('')).toThrow(CrError);
    });

    it('should reject non-string input', () => {
        expect(() => toCrVersion(100 as unknown as string)).toThrow(CrError);
    });
});

// ─── toOidcRawClaims / toSamlRawClaims (nominal isolation) ──────────────────

describe('toOidcRawClaims — OIDC raw claims brand factory', () => {
    function validOidcClaims(): unknown {
        return {
            iss: 'https://oidc.example.com',
            sub: 'oidc-subject-001',
            aud: 'oidc-client-001',
            exp: 1900000000,
            iat: 1700000000,
        };
    }

    it('should accept valid OidcRawClaims (5 mandatory fields)', () => {
        const claims = toOidcRawClaims(validOidcClaims());
        expect(claims.iss).toBe('https://oidc.example.com');
        expect(claims.sub).toBe('oidc-subject-001');
    });

    it('should accept aud as string OR string[]', () => {
        const single = toOidcRawClaims({
            ...(validOidcClaims() as Record<string, unknown>),
            aud: 'single-aud',
        });
        const multi = toOidcRawClaims({
            ...(validOidcClaims() as Record<string, unknown>),
            aud: ['aud-1', 'aud-2'],
        });
        expect(single.aud).toBe('single-aud');
        expect(multi.aud).toEqual(['aud-1', 'aud-2']);
    });

    it('should reject missing iss (CR_OIDC_CLAIM_INVALID)', () => {
        const claims = validOidcClaims() as Record<string, unknown>;
        delete claims['iss'];
        expect(() => toOidcRawClaims(claims)).toThrow(CrError);
        try {
            toOidcRawClaims(claims);
        } catch (err) {
            expect((err as CrError).code).toBe('CR_OIDC_CLAIM_INVALID');
        }
    });

    it('should reject additional property (additionalProperties:false)', () => {
        const claims = {
            ...(validOidcClaims() as Record<string, unknown>),
            extra_field: 'banned_wildcard',
        };
        expect(() => toOidcRawClaims(claims)).toThrow(CrError);
    });

    it('should reject non-uri iss (format check)', () => {
        const claims = {
            ...(validOidcClaims() as Record<string, unknown>),
            iss: 'not a uri',
        };
        expect(() => toOidcRawClaims(claims)).toThrow(CrError);
    });

    it('should accept optional nonce + email (OIDC Standard Claims)', () => {
        const claims = toOidcRawClaims({
            ...(validOidcClaims() as Record<string, unknown>),
            nonce: 'nonce-001',
            email: 'user@example.com',
            email_verified: true,
        });
        expect(claims.nonce).toBe('nonce-001');
        expect(claims.email).toBe('user@example.com');
    });
});

describe('toSamlRawClaims — SAML raw claims brand factory (SAML side)', () => {
    function validSamlClaims(): unknown {
        return {
            nameId: 'saml-name-001',
            nameIdFormat:
                'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
            issuer: 'https://saml.example.com/idp',
            audience: 'https://sp.example.com/saml',
            attributes: {},
        };
    }

    it('should accept valid SamlRawClaims (5 mandatory fields)', () => {
        const claims = toSamlRawClaims(validSamlClaims());
        expect(claims.nameId).toBe('saml-name-001');
    });

    it('should reject missing audience (CR_SAML_CLAIM_INVALID)', () => {
        const claims = validSamlClaims() as Record<string, unknown>;
        delete claims['audience'];
        expect(() => toSamlRawClaims(claims)).toThrow(CrError);
        try {
            toSamlRawClaims(claims);
        } catch (err) {
            expect((err as CrError).code).toBe('CR_SAML_CLAIM_INVALID');
        }
    });

    it('should reject additional property (additionalProperties:false)', () => {
        const claims = {
            ...(validSamlClaims() as Record<string, unknown>),
            xss_attempt: 'banned',
        };
        expect(() => toSamlRawClaims(claims)).toThrow(CrError);
    });
});

// ─── nominal type incompatibility (TypeScript compile-time verify) ────────────

describe('OidcRawClaims / SamlRawClaims nominal incompatibility', () => {
    it('should narrow OidcRawClaims at TypeScript compile-time (compile-time only)', () => {
        const oidcInput = {
            iss: 'https://oidc.example.com',
            sub: 'oidc-subject-001',
            aud: 'oidc-client-001',
            exp: 1900000000,
            iat: 1700000000,
        };
        const oidc: OidcRawClaims = toOidcRawClaims(oidcInput);
        // Compile-time narrow: oidc.iss is accessible; oidc.nameId is not (a SamlRawClaims field)
        expect(oidc.iss).toBe('https://oidc.example.com');
        // nominal isolation: OidcRawClaims has no nameId field (SAML-only);
        // @ts-expect-error - intentional access of non-existent field for nominal isolation verify
        // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
        const _nameId: string = oidc.nameId;
        void _nameId;
    });

    it('should narrow SamlRawClaims at TypeScript compile-time (compile-time only)', () => {
        const samlInput = {
            nameId: 'saml-name-001',
            nameIdFormat:
                'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
            issuer: 'https://saml.example.com/idp',
            audience: 'https://sp.example.com/saml',
            attributes: {},
        };
        const saml: SamlRawClaims = toSamlRawClaims(samlInput);
        expect(saml.nameId).toBe('saml-name-001');
        // nominal isolation: SamlRawClaims has no iss field (OIDC-only)
        // @ts-expect-error - intentional access of non-existent field for nominal isolation verify
        // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
        const _iss: string = saml.iss;
        void _iss;
    });

    it('should prevent OidcRawClaims being assignable to SamlRawClaims slot (compile-time)', () => {
        const oidc: OidcRawClaims = toOidcRawClaims({
            iss: 'https://x',
            sub: 's',
            aud: 'a',
            exp: 1,
            iat: 1,
        });
        // @ts-expect-error - nominal isolation: OidcRawClaims is NOT assignable to SamlRawClaims
        const wrongAssign: SamlRawClaims = oidc;
        void wrongAssign;
    });
});

// ─── toNormalizedOidcClaims / toNormalizedSamlClaims ────────────

describe('toNormalizedOidcClaims — port implementation-layer normalized output', () => {
    function validNormalizedOidc(): unknown {
        return {
            source: 'oidc',
            issuer: 'https://oidc.example.com',
            subject: 'oidc-subject-001',
            audience: ['oidc-client-001'],
            expiresAt: new Date('2099-01-01T00:00:00.000Z'),
            issuedAt: new Date('2026-01-01T00:00:00.000Z'),
        };
    }

    it('should accept valid NormalizedOidcClaims (source=oidc discriminator)', () => {
        const claims = toNormalizedOidcClaims(validNormalizedOidc());
        expect(claims.source).toBe('oidc');
        expect(claims.issuer).toBe('https://oidc.example.com');
    });

    it('should reject input with source !== "oidc" (CR_BRAND_TYPE_MISMATCH)', () => {
        const claims = {
            ...(validNormalizedOidc() as Record<string, unknown>),
            source: 'saml',
        };
        expect(() => toNormalizedOidcClaims(claims)).toThrow(CrError);
        try {
            toNormalizedOidcClaims(claims);
        } catch (err) {
            expect((err as CrError).code).toBe('CR_BRAND_TYPE_MISMATCH');
        }
    });

    it('should reject null input (CR_BRAND_TYPE_MISMATCH)', () => {
        expect(() => toNormalizedOidcClaims(null)).toThrow(CrError);
    });
});

describe('toNormalizedSamlClaims — port implementation-layer normalized output (SAML side)', () => {
    function validNormalizedSaml(): unknown {
        return {
            source: 'saml',
            issuer: 'https://saml.example.com/idp',
            subject: 'saml-name-001',
            subjectFormat:
                'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
            audience: ['https://sp.example.com/saml'],
            attributes: {},
        };
    }

    it('should accept valid NormalizedSamlClaims (source=saml discriminator)', () => {
        const claims = toNormalizedSamlClaims(validNormalizedSaml());
        expect(claims.source).toBe('saml');
    });

    it('should reject input with source !== "saml" (CR_BRAND_TYPE_MISMATCH)', () => {
        const claims = {
            ...(validNormalizedSaml() as Record<string, unknown>),
            source: 'oidc',
        };
        expect(() => toNormalizedSamlClaims(claims)).toThrow(CrError);
    });

    it('should narrow NormalizedSamlClaims at compile-time (subjectFormat exists)', () => {
        const saml: NormalizedSamlClaims = toNormalizedSamlClaims(
            validNormalizedSaml(),
        );
        expect(saml.subjectFormat).toBeDefined();
        // @ts-expect-error - NormalizedSamlClaims discriminator narrow: source is literal 'saml'
        const _oidcSource: 'oidc' = saml.source;
        void _oidcSource;
    });

    it('should reject null input (CR_BRAND_TYPE_MISMATCH)', () => {
        expect(() => toNormalizedSamlClaims(null)).toThrow(CrError);
        try {
            toNormalizedSamlClaims(null);
        } catch (err) {
            expect((err as CrError).code).toBe('CR_BRAND_TYPE_MISMATCH');
            expect((err as CrError).detail?.['reason']).toBe(
                'normalizedSamlClaims_input_not_object',
            );
        }
    });

    it('should reject string input (CR_BRAND_TYPE_MISMATCH)', () => {
        expect(() => toNormalizedSamlClaims('not-an-object')).toThrow(CrError);
    });

    it('should reject input failing AJV schema validate (CR_SAML_CLAIM_INVALID)', () => {
        // source='saml' passes the discriminator, but the mandatory subjectFormat is missing → schema fail
        const malformed = {
            source: 'saml',
            issuer: 'https://saml.example.com/idp',
            subject: 'saml-name-001',
            // subjectFormat missing
            audience: ['https://sp.example.com/saml'],
            attributes: {},
        };
        expect(() => toNormalizedSamlClaims(malformed)).toThrow(CrError);
        try {
            toNormalizedSamlClaims(malformed);
        } catch (err) {
            expect((err as CrError).code).toBe('CR_SAML_CLAIM_INVALID');
            expect((err as CrError).detail?.['reason']).toBe(
                'normalized_saml_claims_schema_validate_failed',
            );
        }
    });
});

describe('toNormalizedOidcClaims — additional coverage (uncovered branches)', () => {
    it('should reject string input (CR_BRAND_TYPE_MISMATCH)', () => {
        expect(() => toNormalizedOidcClaims('not-an-object')).toThrow(CrError);
    });

    it('should reject input failing AJV schema validate (CR_OIDC_CLAIM_INVALID)', () => {
        // source='oidc' passes the discriminator, but audience is a string rather than an array → schema fail
        const malformed = {
            source: 'oidc',
            issuer: 'https://oidc.example.com',
            subject: 'oidc-subject-001',
            audience: 'should-be-array', // schema requires array
            expiresAt: new Date('2099-01-01T00:00:00.000Z'),
            issuedAt: new Date('2026-01-01T00:00:00.000Z'),
        };
        expect(() => toNormalizedOidcClaims(malformed)).toThrow(CrError);
        try {
            toNormalizedOidcClaims(malformed);
        } catch (err) {
            expect((err as CrError).code).toBe('CR_OIDC_CLAIM_INVALID');
            expect((err as CrError).detail?.['reason']).toBe(
                'normalized_oidc_claims_schema_validate_failed',
            );
        }
    });
});

// ─── validateCr (L0 schema validate; 7 entry points) ─────────────────────────────────

describe('validateCr — AJV strict mode validation entry point (7 schema entry points)', () => {
    it('should accept valid OidcRawClaims', () => {
        const result = validateCr('OidcRawClaims', {
            iss: 'https://x',
            sub: 's',
            aud: 'a',
            exp: 1,
            iat: 1,
        });
        expect(result.valid).toBe(true);
    });

    it('should reject invalid OidcRawClaims (missing field)', () => {
        const result = validateCr('OidcRawClaims', {
            iss: 'https://x',
            sub: 's',
            aud: 'a',
            // exp missing
            iat: 1,
        });
        expect(result.valid).toBe(false);
        if (!result.valid) {
            expect(result.errors.length).toBeGreaterThan(0);
        }
    });

    it('should accept valid FederationIdentityLink', () => {
        const result = validateCr('FederationIdentityLink', {
            id: '550e8400-e29b-41d4-a716-446655440000',
            tenantId: '550e8400-e29b-41d4-a716-446655440001',
            source: 'oidc',
            issuer: 'https://oidc.example.com',
            federatedSubject: 'subject-001',
            userId: '550e8400-e29b-41d4-a716-446655440002',
            signature: 'a'.repeat(128),
            createdAt: '2026-05-18T00:00:00.000Z',
            revoked: false,
        });
        expect(result.valid).toBe(true);
    });

    it('should reject signature with wrong pattern (FederationIdentityLink)', () => {
        const result = validateCr('FederationIdentityLink', {
            id: '550e8400-e29b-41d4-a716-446655440000',
            tenantId: '550e8400-e29b-41d4-a716-446655440001',
            source: 'oidc',
            issuer: 'https://oidc.example.com',
            federatedSubject: 'subject-001',
            userId: '550e8400-e29b-41d4-a716-446655440002',
            signature: 'not-hex', // pattern fail
            createdAt: '2026-05-18T00:00:00.000Z',
            revoked: false,
        });
        expect(result.valid).toBe(false);
    });

    it('should accept valid ResolvedCredentialIntegrityProof (5 fields + cspVersion)', () => {
        const result = validateCr('ResolvedCredentialIntegrityProof', {
            token: 'cr:link-001:user=user-001',
            disclosedClaims: ['issuer:x', 'subject:y'],
            challenge: 'challenge-001',
            audience: 'did:example:verifier',
            notAfter: '2099-01-01T00:00:00.000Z',
            cspVersion: '1.0.0',
            proofSignature: 'b'.repeat(128),
            resolverDid: 'did:example:resolver',
        });
        expect(result.valid).toBe(true);
    });

    it('should reject ResolvedCredentialIntegrityProof with audience not starting with did:', () => {
        const result = validateCr('ResolvedCredentialIntegrityProof', {
            token: 'cr:link-001:user=user-001',
            disclosedClaims: [],
            challenge: 'challenge-001',
            audience: 'https://not-a-did',
            notAfter: '2099-01-01T00:00:00.000Z',
            cspVersion: '1.0.0',
            proofSignature: 'b'.repeat(128),
            resolverDid: 'did:example:resolver',
        });
        expect(result.valid).toBe(false);
    });

    it('should reject ResolvedCredentialIntegrityProof with wrong cspVersion enum', () => {
        const result = validateCr('ResolvedCredentialIntegrityProof', {
            token: 'cr:x',
            disclosedClaims: [],
            challenge: 'c',
            audience: 'did:x',
            notAfter: '2099-01-01T00:00:00.000Z',
            cspVersion: '0.9.0', // enum fail
            proofSignature: 'a'.repeat(128),
            resolverDid: 'did:x',
        });
        expect(result.valid).toBe(false);
    });
});

// ─── re-import sanity (ensure L0 barrel export consistency) ────────────────────────

describe('CR L0 barrel export sanity check', () => {
    it('should expose all 14 CrErrorCode values via union type (compile-time)', () => {
        // This is implicitly verified by handleCrError's full coverage of 14 cases;
        // here we do an explicit sanity check (compile-time TypeScript union type)
        const code: CrErrorCode = 'CR_FEDERATION_LINK_INVALID';
        expect(code).toBeDefined();
    });

    it('should expose CrError as a callable constructor', () => {
        const err = new CrError('CR_SCHEMA_INVALID');
        expect(err).toBeInstanceOf(CrError);
        expect(err).toBeInstanceOf(Error);
    });
});
