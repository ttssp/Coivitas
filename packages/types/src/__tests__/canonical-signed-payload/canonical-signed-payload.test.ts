/**
 * CSP v0.1 L0 types + AJV strict mode validator tests
 *
 * priority 1 sub-protocol — canonical signed payload
 * coverage target: ≥95% lines/statements/functions; ≥90% branches
 *
 * Test scope:
 *   1. brand type factory functions (toUuidV4String / toHttpsUrl / toCspAudience / toCspVersionString)
 *   2. createCanonicalSignedPayload factory function + 6-field validation
 *   3. handleCspError full coverage of 13 error codes + assertNeverCspError exhaustive
 *   4. validateCspPayload AJV strict mode (3rd line of defense) — happy path + 4 fail-closed paths
 *   5. constant exports (CSP_SUPPORTED_VERSIONS / CSP_VERSION_CURRENT / CSP_MIN_VALIDITY_WINDOW_MS)
 */

import { describe, expect, it, beforeEach } from 'vitest';
import type { CapabilityToken } from '../../authorization.js';
import type { DID, Timestamp } from '../../base.js';
import {
    // Brand type factories
    toUuidV4String,
    toHttpsUrl,
    toCspAudience,
    toCspVersionString,
    // Main factory
    createCanonicalSignedPayload,
    // Error handling
    handleCspError,
    assertNeverCspError,
    // Validation
    validateCspPayload,
    // Constants
    CSP_SUPPORTED_VERSIONS,
    CSP_VERSION_CURRENT,
    CSP_MIN_VALIDITY_WINDOW_MS,
} from '../../canonical-signed-payload/index.js';
import type { CspErrorCode } from '../../canonical-signed-payload/types.js';

// ─── Test Fixtures ───────────────────────────────────────────────────────────

const VALID_UUID_V4 = '550e8400-e29b-41d4-a716-446655440000';
const VALID_HTTPS_URL = 'https://verifier.example.com/endpoint';
const VALID_DID = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';
const VALID_NOT_AFTER = new Date(Date.now() + 30_000).toISOString(); // expires in 30s

function makeValidToken(
    overrides: Partial<CapabilityToken> = {},
): CapabilityToken {
    return {
        id: 'token-id-001',
        specVersion: '0.3.0',
        issuerDid: 'did:key:issuer' as DID,
        principalDid: 'did:key:principal' as DID,
        issuedTo: 'did:key:issuedto' as DID,
        issuedAt: new Date(Date.now() - 1000).toISOString() as Timestamp,
        expiresAt: new Date(Date.now() + 3600_000).toISOString() as Timestamp,
        capabilities: [
            {
                action: 'read',
                scope: {
                    type: 'allowlist',
                    field: 'resource',
                    values: ['doc-1', 'doc-2'],
                },
            },
        ],
        revocationUrl: 'https://revocation.example.com/list',
        proof: {
            type: 'Ed25519Signature2026',
            created: new Date().toISOString() as Timestamp,
            verificationMethod: 'did:key:issuer#key-1',
            value: 'base64urlSig' as import('../../base.js').Signature,
        },
        ...overrides,
    };
}

// ─── 1. Brand Type Factory Functions ────────────────────────────────────────

describe('toUuidV4String', () => {
    it('should accept a valid UUID v4 string', () => {
        const result = toUuidV4String(VALID_UUID_V4);
        expect(result).toBe(VALID_UUID_V4);
    });

    it('should accept uppercase UUID v4', () => {
        const upper = VALID_UUID_V4.toUpperCase();
        const result = toUuidV4String(upper);
        expect(result).toBe(upper);
    });

    it('should throw CSP_CHALLENGE_INVALID when not valid UUID v4 format', () => {
        expect(() => toUuidV4String('not-a-uuid')).toThrow(
            'CSP_CHALLENGE_INVALID',
        );
    });

    it('should throw CSP_CHALLENGE_INVALID for UUID v1 (not v4)', () => {
        // UUID v1: third group starts with 1 instead of 4
        expect(() =>
            toUuidV4String('550e8400-e29b-11d4-a716-446655440000'),
        ).toThrow('CSP_CHALLENGE_INVALID');
    });

    it('should throw CSP_CHALLENGE_INVALID for empty string', () => {
        expect(() => toUuidV4String('')).toThrow('CSP_CHALLENGE_INVALID');
    });

    it('should throw CSP_CHALLENGE_INVALID for UUID with wrong variant bits', () => {
        // fourth group must start with [89ab]; 'c' is invalid
        expect(() =>
            toUuidV4String('550e8400-e29b-41d4-c716-446655440000'),
        ).toThrow('CSP_CHALLENGE_INVALID');
    });
});

describe('toHttpsUrl', () => {
    it('should accept a valid https URL', () => {
        const result = toHttpsUrl(VALID_HTTPS_URL);
        expect(result).toBe(VALID_HTTPS_URL);
    });

    it('should accept https URL with path and query', () => {
        const url = 'https://example.com/path?q=1#frag';
        const result = toHttpsUrl(url);
        expect(result).toBe(url);
    });

    it('should throw for http URL (not https)', () => {
        expect(() => toHttpsUrl('http://example.com')).toThrow(
            'CSP_AUDIENCE_INVALID',
        );
    });

    it('should throw for malformed URL', () => {
        expect(() => toHttpsUrl('not-a-url')).toThrow('CSP_AUDIENCE_INVALID');
    });

    it('should throw for empty string', () => {
        expect(() => toHttpsUrl('')).toThrow('CSP_AUDIENCE_INVALID');
    });

    it('should throw for ftp URL', () => {
        expect(() => toHttpsUrl('ftp://example.com/file')).toThrow(
            'CSP_AUDIENCE_INVALID',
        );
    });
});

describe('toCspAudience', () => {
    it('should accept a DID audience', () => {
        const result = toCspAudience(VALID_DID);
        expect(result).toBe(VALID_DID);
    });

    it('should accept a https URL audience', () => {
        const result = toCspAudience(VALID_HTTPS_URL);
        expect(result).toBe(VALID_HTTPS_URL);
    });

    it('should throw CSP_AUDIENCE_MISMATCH for neither DID nor https URL', () => {
        expect(() => toCspAudience('http://insecure.com')).toThrow(
            'CSP_AUDIENCE_MISMATCH',
        );
    });

    it('should throw CSP_AUDIENCE_MISMATCH for empty string', () => {
        expect(() => toCspAudience('')).toThrow('CSP_AUDIENCE_MISMATCH');
    });

    it('should throw CSP_AUDIENCE_MISMATCH for bare domain', () => {
        expect(() => toCspAudience('example.com')).toThrow(
            'CSP_AUDIENCE_MISMATCH',
        );
    });

    it('should propagate toHttpsUrl error for malformed https url', () => {
        // starts with https:// but URL constructor fails on this edge case — test valid path routing
        expect(() => toCspAudience('not-a-url')).toThrow(
            'CSP_AUDIENCE_MISMATCH',
        );
    });
});

describe('toCspVersionString', () => {
    it('should accept "1.0.0" (only supported version)', () => {
        const result = toCspVersionString('1.0.0');
        expect(result).toBe('1.0.0');
    });

    it('should throw CSP_VERSION_UNSUPPORTED for non-semver string', () => {
        expect(() => toCspVersionString('v1.0.0')).toThrow(
            'CSP_VERSION_UNSUPPORTED',
        );
    });

    it('should throw CSP_VERSION_UNSUPPORTED for unsupported semver "2.0.0"', () => {
        expect(() => toCspVersionString('2.0.0')).toThrow(
            'CSP_VERSION_UNSUPPORTED',
        );
    });

    it('should throw CSP_VERSION_UNSUPPORTED for empty string', () => {
        expect(() => toCspVersionString('')).toThrow('CSP_VERSION_UNSUPPORTED');
    });

    it('should throw CSP_VERSION_UNSUPPORTED for "0.1.0" (token specVersion, not cspVersion)', () => {
        expect(() => toCspVersionString('0.1.0')).toThrow(
            'CSP_VERSION_UNSUPPORTED',
        );
    });
});

// ─── 2. createCanonicalSignedPayload Factory ────────────────────────────────

describe('createCanonicalSignedPayload', () => {
    let validInput: Parameters<typeof createCanonicalSignedPayload>[0];

    beforeEach(() => {
        validInput = {
            cspVersion: '1.0.0',
            token: makeValidToken(),
            disclosedClaims: [],
            challenge: VALID_UUID_V4,
            audience: VALID_DID,
            notAfter: VALID_NOT_AFTER,
        };
    });

    it('should create a valid CanonicalSignedPayload (mode A, DID audience)', () => {
        const result = createCanonicalSignedPayload(validInput);
        expect(result.cspVersion).toBe('1.0.0');
        expect(result.challenge).toBe(VALID_UUID_V4);
        expect(result.audience).toBe(VALID_DID);
        expect(result.disclosedClaims).toEqual([]);
        expect(result.notAfter).toBe(VALID_NOT_AFTER);
    });

    it('should create a valid CanonicalSignedPayload (mode A, HTTPS URL audience)', () => {
        const result = createCanonicalSignedPayload({
            ...validInput,
            audience: VALID_HTTPS_URL,
        });
        expect(result.audience).toBe(VALID_HTTPS_URL);
    });

    it('should create a valid CanonicalSignedPayload (mode B, non-empty disclosedClaims)', () => {
        const claim = {
            action: 'read',
            scope: {
                type: 'allowlist' as const,
                field: 'resource',
                values: ['doc-1'],
            },
        };
        const result = createCanonicalSignedPayload({
            ...validInput,
            disclosedClaims: [claim],
        });
        expect(result.disclosedClaims).toHaveLength(1);
    });

    it('should throw CSP_VERSION_UNSUPPORTED for unsupported cspVersion', () => {
        expect(() =>
            createCanonicalSignedPayload({
                ...validInput,
                cspVersion: '2.0.0',
            }),
        ).toThrow('CSP_VERSION_UNSUPPORTED');
    });

    it('should throw CSP_TOKEN_MISSING when token is null', () => {
        expect(() =>
            createCanonicalSignedPayload({
                ...validInput,
                token: null as unknown as CapabilityToken,
            }),
        ).toThrow('CSP_TOKEN_MISSING');
    });

    it('should throw CSP_TOKEN_VERSION_UNSUPPORTED for unsupported token.specVersion', () => {
        const badToken = makeValidToken({ specVersion: '9.9.9' });
        expect(() =>
            createCanonicalSignedPayload({ ...validInput, token: badToken }),
        ).toThrow('CSP_TOKEN_VERSION_UNSUPPORTED');
    });

    it('should throw CSP_DISCLOSURE_INVALID when disclosedClaims is not an array', () => {
        expect(() =>
            createCanonicalSignedPayload({
                ...validInput,
                disclosedClaims: 'not-an-array' as unknown as [],
            }),
        ).toThrow('CSP_DISCLOSURE_INVALID');
    });

    it('should throw CSP_CHALLENGE_INVALID for invalid challenge format', () => {
        expect(() =>
            createCanonicalSignedPayload({
                ...validInput,
                challenge: 'not-a-uuid',
            }),
        ).toThrow('CSP_CHALLENGE_INVALID');
    });

    it('should throw CSP_AUDIENCE_MISMATCH for invalid audience', () => {
        expect(() =>
            createCanonicalSignedPayload({
                ...validInput,
                audience: 'invalid-audience',
            }),
        ).toThrow('CSP_AUDIENCE_MISMATCH');
    });

    it('should throw CSP_PAYLOAD_EXPIRED when notAfter is not valid ISO 8601', () => {
        expect(() =>
            createCanonicalSignedPayload({
                ...validInput,
                notAfter: 'not-a-date',
            }),
        ).toThrow('CSP_PAYLOAD_EXPIRED');
    });

    it('should throw CSP_PAYLOAD_EXPIRED when notAfter is in the past', () => {
        const pastDate = new Date(Date.now() - 5000).toISOString();
        expect(() =>
            createCanonicalSignedPayload({ ...validInput, notAfter: pastDate }),
        ).toThrow('CSP_PAYLOAD_EXPIRED');
    });

    it('should throw CSP_PAYLOAD_EXPIRED when notAfter is within minWindow (1s)', () => {
        // just within CSP_MIN_VALIDITY_WINDOW_MS = 1000ms
        const tooSoon = new Date(Date.now() + 500).toISOString();
        expect(() =>
            createCanonicalSignedPayload({ ...validInput, notAfter: tooSoon }),
        ).toThrow('CSP_PAYLOAD_EXPIRED');
    });
});

// ─── 3. handleCspError full coverage of 13 error codes ──────────────────────────────────────

describe('handleCspError', () => {
    const allErrorCodes: CspErrorCode[] = [
        'CSP_PAYLOAD_INCOMPLETE',
        'CSP_TOKEN_MISSING',
        'CSP_TOKEN_VERSION_UNSUPPORTED',
        'CSP_DISCLOSURE_INVALID',
        'CSP_CHALLENGE_INVALID',
        'CSP_CHALLENGE_EXPIRED',
        'CSP_AUDIENCE_MISMATCH',
        'CSP_PAYLOAD_EXPIRED',
        'CSP_CANONICALIZE_MISMATCH',
        'CSP_SIGNATURE_INVALID',
        'CSP_REVOCATION_QUERY_UNAVAILABLE',
        'CSP_SCHEMA_VIOLATION',
        'CSP_VERSION_UNSUPPORTED',
    ];

    it('should handle all 13 CspErrorCode values without throwing', () => {
        for (const code of allErrorCodes) {
            expect(() => handleCspError(code)).not.toThrow();
        }
    });

    it('should return valid CspErrorContext for each code', () => {
        for (const code of allErrorCodes) {
            const ctx = handleCspError(code);
            expect(ctx.code).toBe(code);
            expect([400, 401, 403, 422, 503]).toContain(ctx.httpStatus);
            expect(typeof ctx.message).toBe('string');
            expect(ctx.message.length).toBeGreaterThan(0);
            expect(ctx.fatal).toBe(true);
        }
    });

    it('should return 400 for CSP_PAYLOAD_INCOMPLETE', () => {
        const ctx = handleCspError('CSP_PAYLOAD_INCOMPLETE');
        expect(ctx.httpStatus).toBe(400);
    });

    it('should return 400 for CSP_TOKEN_MISSING', () => {
        const ctx = handleCspError('CSP_TOKEN_MISSING');
        expect(ctx.httpStatus).toBe(400);
    });

    it('should return 400 for CSP_TOKEN_VERSION_UNSUPPORTED', () => {
        const ctx = handleCspError('CSP_TOKEN_VERSION_UNSUPPORTED');
        expect(ctx.httpStatus).toBe(400);
    });

    it('should return 400 for CSP_DISCLOSURE_INVALID', () => {
        const ctx = handleCspError('CSP_DISCLOSURE_INVALID');
        expect(ctx.httpStatus).toBe(400);
    });

    it('should return 401 for CSP_CHALLENGE_INVALID', () => {
        const ctx = handleCspError('CSP_CHALLENGE_INVALID');
        expect(ctx.httpStatus).toBe(401);
    });

    it('should return 401 for CSP_CHALLENGE_EXPIRED', () => {
        const ctx = handleCspError('CSP_CHALLENGE_EXPIRED');
        expect(ctx.httpStatus).toBe(401);
    });

    it('should return 403 for CSP_AUDIENCE_MISMATCH', () => {
        const ctx = handleCspError('CSP_AUDIENCE_MISMATCH');
        expect(ctx.httpStatus).toBe(403);
    });

    it('should return 401 for CSP_PAYLOAD_EXPIRED', () => {
        const ctx = handleCspError('CSP_PAYLOAD_EXPIRED');
        expect(ctx.httpStatus).toBe(401);
    });

    it('should return 400 for CSP_CANONICALIZE_MISMATCH', () => {
        const ctx = handleCspError('CSP_CANONICALIZE_MISMATCH');
        expect(ctx.httpStatus).toBe(400);
    });

    it('should return 401 for CSP_SIGNATURE_INVALID', () => {
        const ctx = handleCspError('CSP_SIGNATURE_INVALID');
        expect(ctx.httpStatus).toBe(401);
    });

    it('should return 503 for CSP_REVOCATION_QUERY_UNAVAILABLE (fail-closed)', () => {
        const ctx = handleCspError('CSP_REVOCATION_QUERY_UNAVAILABLE');
        expect(ctx.httpStatus).toBe(503);
    });

    it('should return 400 for CSP_SCHEMA_VIOLATION', () => {
        const ctx = handleCspError('CSP_SCHEMA_VIOLATION');
        expect(ctx.httpStatus).toBe(400);
    });

    it('should return 422 for CSP_VERSION_UNSUPPORTED (MED severity)', () => {
        const ctx = handleCspError('CSP_VERSION_UNSUPPORTED');
        expect(ctx.httpStatus).toBe(422);
    });
});

describe('assertNeverCspError', () => {
    it('should throw at runtime when called with unknown code', () => {
        // Simulates the case where the type system is bypassed at runtime
        expect(() => assertNeverCspError('UNKNOWN_CODE' as never)).toThrow(
            'Unreachable: unhandled CspErrorCode',
        );
    });
});

// ─── 4. validateCspPayload AJV strict mode (3rd line of defense) ────────────────────

describe('validateCspPayload', () => {
    function makeValidPayload(
        overrides: Record<string, unknown> = {},
    ): unknown {
        // Fields aligned with all 10 schema required fields;
        // schema aligned with CapabilityToken in authorization.ts (incl. issuedAt/expiresAt/revocationUrl)
        return {
            cspVersion: '1.0.0',
            token: {
                id: 'token-001',
                issuerDid: 'did:key:issuer',
                principalDid: 'did:key:principal',
                issuedTo: 'did:key:agent',
                specVersion: '0.3.0',
                issuedAt: '2026-05-18T00:00:00.000Z',
                expiresAt: '2099-01-01T00:00:00.000Z',
                capabilities: [
                    {
                        action: 'read',
                        scope: { type: 'allowlist', field: 'res', values: [] },
                    },
                ],
                revocationUrl:
                    'https://issuer.example.com/revocation/token-001',
                proof: {
                    type: 'Ed25519Signature2026',
                    created: '2026-05-18T00:00:00.000Z',
                    verificationMethod: 'did:key:issuer#key-1',
                    value: 'sig-base64',
                },
            },
            disclosedClaims: [],
            challenge: VALID_UUID_V4,
            audience: VALID_DID,
            notAfter: VALID_NOT_AFTER,
            ...overrides,
        };
    }

    it('should return valid:true for a well-formed CSP payload', () => {
        const result = validateCspPayload(makeValidPayload());
        expect(result.valid).toBe(true);
    });

    it('should return valid:true for HTTPS URL audience', () => {
        const result = validateCspPayload(
            makeValidPayload({ audience: VALID_HTTPS_URL }),
        );
        expect(result.valid).toBe(true);
    });

    it('should return valid:false (CSP_CHALLENGE_INVALID path) when challenge is not UUID v4', () => {
        const result = validateCspPayload(
            makeValidPayload({ challenge: 'not-a-uuid' }),
        );
        expect(result.valid).toBe(false);
        if (!result.valid) {
            expect(result.errors.length).toBeGreaterThan(0);
        }
    });

    it('should return valid:false when cspVersion is wrong', () => {
        const result = validateCspPayload(
            makeValidPayload({ cspVersion: '2.0.0' }),
        );
        expect(result.valid).toBe(false);
    });

    it('should return valid:false when required field is missing (CSP_PAYLOAD_INCOMPLETE path)', () => {
        const { notAfter: _, ...payloadMissingNotAfter } =
            makeValidPayload() as Record<string, unknown>;
        const result = validateCspPayload(payloadMissingNotAfter);
        expect(result.valid).toBe(false);
    });

    it('should return valid:false when notAfter is not date-time format', () => {
        const result = validateCspPayload(
            makeValidPayload({ notAfter: 'not-a-date' }),
        );
        expect(result.valid).toBe(false);
    });

    it('should return valid:false when audience is neither DID nor https', () => {
        const result = validateCspPayload(
            makeValidPayload({ audience: 'http://insecure.com' }),
        );
        expect(result.valid).toBe(false);
    });

    it('should return valid:false when payload is not an object', () => {
        const result = validateCspPayload('string-payload');
        expect(result.valid).toBe(false);
    });

    it('should return valid:false when payload is null', () => {
        const result = validateCspPayload(null);
        expect(result.valid).toBe(false);
    });

    it('should return valid:false when additionalProperties present', () => {
        const result = validateCspPayload(
            makeValidPayload({ unknownField: 'extra' }),
        );
        expect(result.valid).toBe(false);
    });

    it('should return valid:false when challenge UUID has wrong version digit (v1 not v4)', () => {
        // UUID v1 — third group starts with 1 not 4
        const result = validateCspPayload(
            makeValidPayload({
                challenge: '550e8400-e29b-11d4-a716-446655440000',
            }),
        );
        expect(result.valid).toBe(false);
    });

    it('should return error with instancePath when validation fails', () => {
        const result = validateCspPayload(
            makeValidPayload({ challenge: 'bad' }),
        );
        if (!result.valid) {
            const hasPath = result.errors.some(
                (e) => typeof e.instancePath === 'string',
            );
            expect(hasPath).toBe(true);
        }
    });
});

// ─── 5. Constant exports ─────────────────────────────────────────────────────────────

describe('CSP constants', () => {
    it('should export CSP_SUPPORTED_VERSIONS as readonly array containing "1.0.0"', () => {
        expect(CSP_SUPPORTED_VERSIONS).toContain('1.0.0');
        expect(Array.isArray(CSP_SUPPORTED_VERSIONS)).toBe(true);
    });

    it('should export CSP_VERSION_CURRENT as "1.0.0"', () => {
        expect(CSP_VERSION_CURRENT).toBe('1.0.0');
    });

    it('should export CSP_MIN_VALIDITY_WINDOW_MS as 1000', () => {
        expect(CSP_MIN_VALIDITY_WINDOW_MS).toBe(1000);
    });

    it('CSP_SUPPORTED_VERSIONS should include CSP_VERSION_CURRENT', () => {
        expect(CSP_SUPPORTED_VERSIONS).toContain(CSP_VERSION_CURRENT);
    });
});
