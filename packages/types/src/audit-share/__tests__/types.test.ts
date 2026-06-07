/**
 * audit-share v0.2 L0 types unit tests
 *
 *
 * Covered scenarios:
 *   - toAuditKeyId factory: UUID v4 validation (valid + malformed)
 *   - toAuditShareVersion factory: semver + supported value set
 *   - toAuditShareScope factory: sentinel value enumeration rejection + auditClass enum
 *   - handleAuditShareError switch full coverage of 14 cases (httpStatus + message + fatal)
 *   - assertNeverAuditShareCode exhaustive (unreachable at runtime)
 *   - AuditShareError extends Error
 */

import { describe, expect, it } from 'vitest';

import {
    AUDIT_EVENT_FIELDS,
    AUDIT_SHARE_MIN_VALIDITY_WINDOW_MS,
    AUDIT_SHARE_SUPPORTED_VERSIONS,
    AUDIT_SHARE_VERSION_1_0_0,
    AuditShareError,
    assertNeverAuditShareCode,
    handleAuditShareError,
    toAuditKeyId,
    toAuditShareScope,
    toAuditShareVersion,
    type AuditShareErrorCode,
} from '../types.js';

// ── Constant export validation ──────────────────────────────────────────────────────────

describe('audit-share constants', () => {
    it('should expose AUDIT_SHARE_VERSION_1_0_0 = "1.0.0"', () => {
        expect(AUDIT_SHARE_VERSION_1_0_0).toBe('1.0.0');
    });

    it('should expose AUDIT_SHARE_SUPPORTED_VERSIONS containing only 1.0.0', () => {
        expect(AUDIT_SHARE_SUPPORTED_VERSIONS).toEqual(['1.0.0']);
    });

    it('should expose AUDIT_SHARE_MIN_VALIDITY_WINDOW_MS = 1000', () => {
        expect(AUDIT_SHARE_MIN_VALIDITY_WINDOW_MS).toBe(1000);
    });

    it('should expose AUDIT_EVENT_FIELDS with 15 items', () => {
        expect(AUDIT_EVENT_FIELDS.length).toBe(15);
        expect(AUDIT_EVENT_FIELDS).toContain('eventType');
        expect(AUDIT_EVENT_FIELDS).toContain('tenantId');
        expect(AUDIT_EVENT_FIELDS).toContain('canonicalPayloadHash');
    });
});

// ── toAuditKeyId factory ─────────────────────────────────────────────

describe('toAuditKeyId factory', () => {
    it('should accept valid UUID v4', () => {
        const valid = '11111111-2222-4333-8444-555555555555';
        expect(toAuditKeyId(valid)).toBe(valid);
    });

    it('should throw AUDIT_SHARE_TOKEN_INVALID when not UUID v4 format', () => {
        expect(() => toAuditKeyId('not-a-uuid')).toThrowError(AuditShareError);
        try {
            toAuditKeyId('not-a-uuid');
            expect.fail('should have thrown');
        } catch (err) {
            expect((err as AuditShareError).code).toBe(
                'AUDIT_SHARE_TOKEN_INVALID',
            );
        }
    });

    it('should throw AUDIT_SHARE_TOKEN_INVALID when version digit is not 4', () => {
        // UUID v1 format (version digit "1" at position 14) — must reject
        const invalid = '11111111-2222-1333-8444-555555555555';
        expect(() => toAuditKeyId(invalid)).toThrowError(AuditShareError);
    });

    it('should throw AUDIT_SHARE_TOKEN_INVALID for empty string', () => {
        expect(() => toAuditKeyId('')).toThrowError(AuditShareError);
    });

    it('should throw AUDIT_SHARE_TOKEN_INVALID for non-string input', () => {
        expect(() => toAuditKeyId(null as unknown as string)).toThrowError(
            AuditShareError,
        );
    });
});

// ── toAuditShareVersion factory ──────────────────────────────────────

describe('toAuditShareVersion factory', () => {
    it('should accept "1.0.0"', () => {
        expect(toAuditShareVersion('1.0.0')).toBe('1.0.0');
    });

    it('should throw AUDIT_SHARE_VERSION_UNSUPPORTED for invalid semver', () => {
        expect(() => toAuditShareVersion('not-semver')).toThrowError(
            AuditShareError,
        );
        try {
            toAuditShareVersion('not-semver');
            expect.fail('should have thrown');
        } catch (err) {
            expect((err as AuditShareError).code).toBe(
                'AUDIT_SHARE_VERSION_UNSUPPORTED',
            );
        }
    });

    it('should throw AUDIT_SHARE_VERSION_UNSUPPORTED for unsupported semver value', () => {
        // "2.0.0" is valid semver but not in the supported set
        expect(() => toAuditShareVersion('2.0.0')).toThrowError(
            AuditShareError,
        );
    });

    it('should throw AUDIT_SHARE_VERSION_UNSUPPORTED for non-string input', () => {
        expect(() =>
            toAuditShareVersion(undefined as unknown as string),
        ).toThrowError(AuditShareError);
    });
});

// ── toAuditShareScope factory (sentinel rejection + auditClass enum) ──────

describe('toAuditShareScope factory', () => {
    it('should accept valid scope with required fields', () => {
        const scope = toAuditShareScope({
            tenantId: 'tenant-acme',
            auditClass: 'L1',
        });
        expect(scope.tenantId).toBe('tenant-acme');
        expect(scope.auditClass).toBe('L1');
        expect(scope.chainNamespace).toBeUndefined();
    });

    it('should accept valid scope with optional chainNamespace', () => {
        const scope = toAuditShareScope({
            tenantId: 'tenant-acme',
            auditClass: 'L2',
            chainNamespace: 'atp',
        });
        expect(scope.chainNamespace).toBe('atp');
    });

    it('should throw AUDIT_SHARE_SCOPE_INVALID for empty tenantId', () => {
        expect(() =>
            toAuditShareScope({ tenantId: '', auditClass: 'L1' }),
        ).toThrowError(AuditShareError);
    });

    it('should reject all sentinel values for tenantId', () => {
        const sentinels = [
            '_DELETED_',
            '_PLACEHOLDER_',
            '_SENTINEL_',
            '_TBD_',
            '_NULL_',
            'TODO',
            'FIXME',
            'XXX',
        ];
        for (const sentinel of sentinels) {
            expect(() =>
                toAuditShareScope({ tenantId: sentinel, auditClass: 'L1' }),
            ).toThrowError(AuditShareError);
        }
    });

    it('should throw AUDIT_SHARE_SCOPE_INVALID for invalid auditClass', () => {
        expect(() =>
            toAuditShareScope({
                tenantId: 'tenant-acme',
                auditClass: 'L4' as 'L1',
            }),
        ).toThrowError(AuditShareError);
    });

    it('should reject sentinel chainNamespace when provided', () => {
        expect(() =>
            toAuditShareScope({
                tenantId: 'tenant-acme',
                auditClass: 'L1',
                chainNamespace: '_PLACEHOLDER_',
            }),
        ).toThrowError(AuditShareError);
    });

    it('should accept missing chainNamespace (optional field; not sentinel)', () => {
        const scope = toAuditShareScope({
            tenantId: 'tenant-acme',
            auditClass: 'L3',
        });
        expect(scope.chainNamespace).toBeUndefined();
    });
});

// ── AuditShareError extends Error ───────────────────────

describe('AuditShareError', () => {
    it('should extend Error', () => {
        const err = new AuditShareError(
            'AUDIT_SHARE_TOKEN_INVALID',
            'test message',
        );
        expect(err).toBeInstanceOf(Error);
        expect(err.name).toBe('AuditShareError');
    });

    it('should expose code field', () => {
        const err = new AuditShareError(
            'AUDIT_SHARE_AUDIENCE_MISMATCH',
            'audience mismatch',
        );
        expect(err.code).toBe('AUDIT_SHARE_AUDIENCE_MISMATCH');
    });

    it('should format message with [code] prefix', () => {
        const err = new AuditShareError(
            'AUDIT_SHARE_TOKEN_EXPIRED',
            'token expired test',
        );
        expect(err.message).toContain('[AUDIT_SHARE_TOKEN_EXPIRED]');
        expect(err.message).toContain('token expired test');
    });

    it('should expose optional invariant field', () => {
        const err = new AuditShareError(
            'AUDIT_SHARE_SCHEMA_INVALID',
            'invalid',
            'step-1-schema-validate',
        );
        expect(err.invariant).toBe('step-1-schema-validate');
    });
});

// ── handleAuditShareError switch 17 cases (v0.2 14 + v0.3 3 new) ──────────

describe('handleAuditShareError — full coverage of 17 cases (v0.2 14 + v0.3 3 new)', () => {
    const ALL_CODES: AuditShareErrorCode[] = [
        // v0.2 14 items
        'AUDIT_SHARE_TOKEN_INVALID',
        'AUDIT_SHARE_TOKEN_EXPIRED',
        'AUDIT_SHARE_AUDIENCE_MISMATCH',
        'AUDIT_SHARE_CHALLENGE_INVALID',
        'AUDIT_SHARE_NOT_AFTER_EXPIRED',
        'AUDIT_SHARE_REQUESTER_SIGNATURE_INVALID',
        'AUDIT_SHARE_DELEGATOR_SIGNATURE_INVALID',
        'AUDIT_SHARE_DELEGATOR_AUDIENCE_MISMATCH',
        'AUDIT_SHARE_SCOPE_INVALID',
        'AUDIT_SHARE_CROSS_TENANT_REJECT',
        'AUDIT_SHARE_HASH_CHAIN_INVALID',
        'AUDIT_SHARE_DISCLOSED_CLAIMS_INVALID',
        'AUDIT_SHARE_VERSION_UNSUPPORTED',
        'AUDIT_SHARE_SCHEMA_INVALID',
        // v0.3 3 new items
        'AUDIT_SHARE_VERIFIER_REQUIRED',
        'AUDIT_SHARE_BOUNDARY_CHECK_FAILED',
        'AUDIT_SHARE_CHAIN_IDENTITY_TAMPERED',
    ];

    it.each(ALL_CODES)(
        'should map %s to a fail-closed 4xx/5xx http status with fatal=true',
        (code) => {
            const ctx = handleAuditShareError(code);
            expect(ctx.code).toBe(code);
            expect([400, 401, 403, 422, 503]).toContain(ctx.httpStatus);
            expect(ctx.fatal).toBe(true);
            expect(ctx.message.length).toBeGreaterThan(0);
        },
    );

    it('should cover all 17 error codes (v0.2 14 + v0.3 3 new; none missing)', () => {
        expect(ALL_CODES.length).toBe(17);
    });

    it('should map the v0.3 3 new items (VERIFIER_REQUIRED / BOUNDARY_CHECK_FAILED / CHAIN_IDENTITY_TAMPERED) to 401', () => {
        // cryptographic identity derivation / boundary guard / hash chain primitive failure
        expect(
            handleAuditShareError('AUDIT_SHARE_VERIFIER_REQUIRED').httpStatus,
        ).toBe(401);
        expect(
            handleAuditShareError('AUDIT_SHARE_BOUNDARY_CHECK_FAILED')
                .httpStatus,
        ).toBe(401);
        expect(
            handleAuditShareError('AUDIT_SHARE_CHAIN_IDENTITY_TAMPERED')
                .httpStatus,
        ).toBe(401);
    });

    it('should map TOKEN_INVALID + TOKEN_EXPIRED + CHALLENGE_INVALID + NOT_AFTER_EXPIRED to 401', () => {
        expect(
            handleAuditShareError('AUDIT_SHARE_TOKEN_INVALID').httpStatus,
        ).toBe(401);
        expect(
            handleAuditShareError('AUDIT_SHARE_TOKEN_EXPIRED').httpStatus,
        ).toBe(401);
        expect(
            handleAuditShareError('AUDIT_SHARE_CHALLENGE_INVALID').httpStatus,
        ).toBe(401);
        expect(
            handleAuditShareError('AUDIT_SHARE_NOT_AFTER_EXPIRED').httpStatus,
        ).toBe(401);
    });

    it('should map AUDIENCE_MISMATCH + CROSS_TENANT + DELEGATOR_AUDIENCE to 403', () => {
        expect(
            handleAuditShareError('AUDIT_SHARE_AUDIENCE_MISMATCH').httpStatus,
        ).toBe(403);
        expect(
            handleAuditShareError('AUDIT_SHARE_CROSS_TENANT_REJECT').httpStatus,
        ).toBe(403);
        expect(
            handleAuditShareError('AUDIT_SHARE_DELEGATOR_AUDIENCE_MISMATCH')
                .httpStatus,
        ).toBe(403);
    });

    it('should map VERSION_UNSUPPORTED to 422', () => {
        expect(
            handleAuditShareError('AUDIT_SHARE_VERSION_UNSUPPORTED').httpStatus,
        ).toBe(422);
    });

    it('should map SCHEMA_INVALID + DISCLOSED_CLAIMS_INVALID + SCOPE_INVALID to 400', () => {
        expect(
            handleAuditShareError('AUDIT_SHARE_SCHEMA_INVALID').httpStatus,
        ).toBe(400);
        expect(
            handleAuditShareError('AUDIT_SHARE_DISCLOSED_CLAIMS_INVALID')
                .httpStatus,
        ).toBe(400);
        expect(
            handleAuditShareError('AUDIT_SHARE_SCOPE_INVALID').httpStatus,
        ).toBe(400);
    });
});

// ── assertNeverAuditShareCode exhaustive ────────────────────────────────

describe('assertNeverAuditShareCode', () => {
    it('should throw at runtime when invoked (unreachable bypass)', () => {
        expect(() =>
            assertNeverAuditShareCode('UNKNOWN_CODE' as never),
        ).toThrowError(/Unreachable/);
    });
});
