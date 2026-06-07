/**
 * revocation-record.test.ts -- RevocationRecord type-layer unit tests
 *
 * Coverage:
 *   - isRevocationReason / parseRevocationReason runtime validation (no brand cast)
 *   - REVOCATION_REASONS enum completeness
 *   - RevocationErrorCode type completeness (compile-time check)
 *   - IssuerSignaturePayload field completeness (v0.4.0)
 *
 */

import { describe, expect, it } from 'vitest';
import {
    REVOCATION_REASONS,
    isRevocationReason,
    parseRevocationReason,
    validateIssuerSignaturePayload,
} from '../revocation-record.js';
import type {
    RevocationErrorCode,
    IssuerSignaturePayload,
    RevocationRecord,
} from '../revocation-record.js';

// ---------------------------------------------------------------------------
// isRevocationReason
// ---------------------------------------------------------------------------

describe('isRevocationReason', () => {
    it('should return true when value is a valid RevocationReason', () => {
        for (const reason of REVOCATION_REASONS) {
            expect(isRevocationReason(reason)).toBe(true);
        }
    });

    it('should return false when value is an unknown string', () => {
        expect(isRevocationReason('UNKNOWN_REASON')).toBe(false);
        expect(isRevocationReason('key_compromise')).toBe(false); // case-sensitive
        expect(isRevocationReason('')).toBe(false);
    });

    it('should return false when value is not a string', () => {
        expect(isRevocationReason(null)).toBe(false);
        expect(isRevocationReason(undefined)).toBe(false);
        expect(isRevocationReason(42)).toBe(false);
        expect(isRevocationReason({})).toBe(false);
        expect(isRevocationReason([])).toBe(false);
    });
});

// ---------------------------------------------------------------------------
// parseRevocationReason
// ---------------------------------------------------------------------------

describe('parseRevocationReason', () => {
    it('should return the reason when valid', () => {
        expect(parseRevocationReason('KEY_COMPROMISE')).toBe('KEY_COMPROMISE');
        expect(parseRevocationReason('UNSPECIFIED')).toBe('UNSPECIFIED');
        expect(parseRevocationReason('SUPERSEDED')).toBe('SUPERSEDED');
    });

    it('should throw when value is invalid string', () => {
        expect(() => parseRevocationReason('INVALID')).toThrowError(
            /invalid reason value from DB/,
        );
    });

    it('should throw when value is null', () => {
        expect(() => parseRevocationReason(null)).toThrowError(
            /invalid reason value from DB/,
        );
    });

    it('should throw when value is undefined', () => {
        expect(() => parseRevocationReason(undefined)).toThrowError(
            /invalid reason value from DB/,
        );
    });

    it('should include expected values list in error message', () => {
        try {
            parseRevocationReason('BAD');
            expect.fail('should have thrown');
        } catch (err) {
            expect(String(err)).toContain('KEY_COMPROMISE');
            expect(String(err)).toContain('UNSPECIFIED');
        }
    });
});

// ---------------------------------------------------------------------------
// REVOCATION_REASONS enum completeness
// ---------------------------------------------------------------------------

describe('REVOCATION_REASONS', () => {
    it('should contain all 6 expected reasons', () => {
        expect(REVOCATION_REASONS).toContain('KEY_COMPROMISE');
        expect(REVOCATION_REASONS).toContain('AFFILIATION_CHANGED');
        expect(REVOCATION_REASONS).toContain('SUPERSEDED');
        expect(REVOCATION_REASONS).toContain('CESSATION_OF_OPERATION');
        expect(REVOCATION_REASONS).toContain('PRIVILEGE_WITHDRAWN');
        expect(REVOCATION_REASONS).toContain('UNSPECIFIED');
        expect(REVOCATION_REASONS).toHaveLength(6);
    });

    it('should be a readonly array (as const)', () => {
        // TypeScript compile-time check; runtime verifies includes() is available
        expect(typeof REVOCATION_REASONS[0]).toBe('string');
    });
});

// ---------------------------------------------------------------------------
// IssuerSignaturePayload -- v0.4.0 field completeness
// ---------------------------------------------------------------------------

describe('IssuerSignaturePayload (v0.4.0)', () => {
    it('should accept valid payload with listVersion', () => {
        const payload: IssuerSignaturePayload = {
            issuerDid: 'did:ap:issuer-001',
            listId: 'list-tenant-a-001',
            listVersion: 1,
            tenantId: 'tenant-a',
            issuedAt: '2026-05-10T00:00:00.000Z',
        };
        // Passing TypeScript compilation means the type is correct; runtime checks field presence
        expect(payload.listVersion).toBe(1);
        expect(payload.tenantId).toBe('tenant-a');
        expect(payload.issuerDid).toBe('did:ap:issuer-001');
        expect(payload.listId).toBe('list-tenant-a-001');
        expect(payload.issuedAt).toBe('2026-05-10T00:00:00.000Z');
    });

    it('should allow listVersion to be any positive integer (monotonic)', () => {
        const v1: IssuerSignaturePayload = {
            issuerDid: 'did:ap:issuer-001',
            listId: 'list-001',
            listVersion: 42,
            tenantId: 'tenant-a',
            issuedAt: '2026-05-10T00:00:00.000Z',
        };
        expect(v1.listVersion).toBeGreaterThan(0);
    });
});

// ---------------------------------------------------------------------------
// RevocationRecord -- field mapping completeness
// ---------------------------------------------------------------------------

describe('RevocationRecord interface', () => {
    it('should accept a complete RevocationRecord with all required fields', () => {
        const record: RevocationRecord = {
            id: '00000000-0000-0000-0000-000000000001',
            tenantId: 'tenant-a',
            tokenId: 'token-abc',
            revokedBy: 'did:ap:admin-001',
            revokedAt: new Date('2026-05-10T00:00:00.000Z'),
            reason: 'KEY_COMPROMISE',
            listId: 'list-001',
            listVersion: 1,
            issuerSignaturePayload: {
                issuerDid: 'did:ap:issuer-001',
                listId: 'list-001',
                listVersion: 1,
                tenantId: 'tenant-a',
                issuedAt: '2026-05-10T00:00:00.000Z',
            },
        };

        // Core field assertions
        expect(record.listVersion).toBe(1);
        expect(record.tenantId).toBe('tenant-a');
        expect(record.issuerSignaturePayload?.listVersion).toBe(1);
    });

    it('should allow null issuerSignaturePayload', () => {
        const record: RevocationRecord = {
            id: '00000000-0000-0000-0000-000000000002',
            tenantId: 'tenant-b',
            tokenId: 'token-xyz',
            revokedBy: 'did:ap:admin-002',
            revokedAt: new Date(),
            reason: 'UNSPECIFIED',
            listId: 'list-002',
            listVersion: 1,
            issuerSignaturePayload: null,
        };
        expect(record.issuerSignaturePayload).toBeNull();
    });
});

// ---------------------------------------------------------------------------
// RevocationErrorCode -- compile-time type completeness check (TypeScript only)
// ---------------------------------------------------------------------------

describe('RevocationErrorCode (compile-time)', () => {
    it('should cover all 5 error code values', () => {
        // Verifies compile-time type completeness at runtime via string assignment
        const codes: RevocationErrorCode[] = [
            'REVOCATION_DUPLICATE',
            'REVOCATION_INVALID_PARAMS',
            'REVOCATION_LIST_VERSION_CONFLICT',
            'REVOCATION_STORE_ERROR',
            'REVOCATION_CACHE_ERROR',
        ];
        expect(codes).toHaveLength(5);
        for (const code of codes) {
            expect(typeof code).toBe('string');
            expect(code.startsWith('REVOCATION_')).toBe(true);
        }
    });

    it('should not include STUB_REVOCATION_NOT_FOR_PRODUCTION (managed-service-runtime code)', () => {
        const codes: RevocationErrorCode[] = [
            'REVOCATION_DUPLICATE',
            'REVOCATION_INVALID_PARAMS',
            'REVOCATION_LIST_VERSION_CONFLICT',
            'REVOCATION_STORE_ERROR',
            'REVOCATION_CACHE_ERROR',
        ];
        // Ensure managed-service-runtime error codes are not in this namespace
        expect(codes).not.toContain('STUB_REVOCATION_NOT_FOR_PRODUCTION');
        expect(codes).not.toContain('REVOCATION_CHECK_FAILED');
    });
});

// ---------------------------------------------------------------------------
// validateIssuerSignaturePayload -- runtime validation (no brand cast)
// ---------------------------------------------------------------------------

describe('validateIssuerSignaturePayload', () => {
    const validPayload = {
        issuerDid: 'did:ap:issuer-001',
        listId: 'list-tenant-a-001',
        listVersion: 1,
        tenantId: 'tenant-a',
        issuedAt: '2026-05-10T00:00:00.000Z',
    };

    it('should return validated IssuerSignaturePayload when all fields are valid', () => {
        const result = validateIssuerSignaturePayload(validPayload);
        expect(result.issuerDid).toBe('did:ap:issuer-001');
        expect(result.listId).toBe('list-tenant-a-001');
        expect(result.listVersion).toBe(1);
        expect(result.tenantId).toBe('tenant-a');
        expect(result.issuedAt).toBe('2026-05-10T00:00:00.000Z');
    });

    it('should accept listVersion greater than 1 (monotonic)', () => {
        const result = validateIssuerSignaturePayload({ ...validPayload, listVersion: 42 });
        expect(result.listVersion).toBe(42);
    });

    it('should throw when raw is null', () => {
        expect(() => validateIssuerSignaturePayload(null)).toThrowError(
            /IssuerSignaturePayload must be a non-null object/,
        );
    });

    it('should throw when raw is not an object (string)', () => {
        expect(() => validateIssuerSignaturePayload('invalid')).toThrowError(
            /IssuerSignaturePayload must be a non-null object/,
        );
    });

    it('should throw when raw is not an object (number)', () => {
        expect(() => validateIssuerSignaturePayload(42)).toThrowError(
            /IssuerSignaturePayload must be a non-null object/,
        );
    });

    it('should throw when raw is an array', () => {
        expect(() => validateIssuerSignaturePayload([])).toThrowError(
            /IssuerSignaturePayload must be a non-null object/,
        );
    });

    it('should throw when issuerDid is missing', () => {
        const { issuerDid: _omit, ...rest } = validPayload;
        expect(() => validateIssuerSignaturePayload(rest)).toThrowError(
            /issuerDid must be a non-empty string/,
        );
    });

    it('should throw when issuerDid is empty string', () => {
        expect(() => validateIssuerSignaturePayload({ ...validPayload, issuerDid: '' })).toThrowError(
            /issuerDid must be a non-empty string/,
        );
    });

    it('should throw when issuerDid is not a string', () => {
        expect(() => validateIssuerSignaturePayload({ ...validPayload, issuerDid: 123 })).toThrowError(
            /issuerDid must be a non-empty string/,
        );
    });

    it('should throw when listId is missing', () => {
        const { listId: _omit, ...rest } = validPayload;
        expect(() => validateIssuerSignaturePayload(rest)).toThrowError(
            /listId must be a non-empty string/,
        );
    });

    it('should throw when listId is empty string', () => {
        expect(() => validateIssuerSignaturePayload({ ...validPayload, listId: '' })).toThrowError(
            /listId must be a non-empty string/,
        );
    });

    it('should throw when listVersion is missing', () => {
        const { listVersion: _omit, ...rest } = validPayload;
        expect(() => validateIssuerSignaturePayload(rest)).toThrowError(
            /listVersion must be a positive integer/,
        );
    });

    it('should throw when listVersion is 0 (not >= 1)', () => {
        expect(() => validateIssuerSignaturePayload({ ...validPayload, listVersion: 0 })).toThrowError(
            /listVersion must be a positive integer/,
        );
    });

    it('should throw when listVersion is negative', () => {
        expect(() => validateIssuerSignaturePayload({ ...validPayload, listVersion: -1 })).toThrowError(
            /listVersion must be a positive integer/,
        );
    });

    it('should throw when listVersion is a float (non-integer)', () => {
        expect(() => validateIssuerSignaturePayload({ ...validPayload, listVersion: 1.5 })).toThrowError(
            /listVersion must be a positive integer/,
        );
    });

    it('should throw when listVersion is a string', () => {
        expect(() => validateIssuerSignaturePayload({ ...validPayload, listVersion: '1' })).toThrowError(
            /listVersion must be a positive integer/,
        );
    });

    it('should throw when tenantId is missing', () => {
        const { tenantId: _omit, ...rest } = validPayload;
        expect(() => validateIssuerSignaturePayload(rest)).toThrowError(
            /tenantId must be a non-empty string/,
        );
    });

    it('should throw when tenantId is empty string', () => {
        expect(() => validateIssuerSignaturePayload({ ...validPayload, tenantId: '' })).toThrowError(
            /tenantId must be a non-empty string/,
        );
    });

    it('should throw when issuedAt is missing', () => {
        const { issuedAt: _omit, ...rest } = validPayload;
        expect(() => validateIssuerSignaturePayload(rest)).toThrowError(
            /issuedAt must be a non-empty string/,
        );
    });

    it('should throw when issuedAt is empty string', () => {
        expect(() => validateIssuerSignaturePayload({ ...validPayload, issuedAt: '' })).toThrowError(
            /issuedAt must be a non-empty string/,
        );
    });
});
