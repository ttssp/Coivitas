/**
 * audit-share v0.2 AJV strict mode validation unit tests
 *
 * Layer 3 of the triple defense
 *
 * Covered scenarios:
 *   - happy path (valid request with all fields → valid: true)
 *   - missing required field → valid: false + AUDIT_SHARE_SCHEMA_INVALID
 *   - additionalProperties: false enforce
 *   - format: uuid + date-time + pattern strict
 *   - audience must startsWith did:
 *   - auditClass enum L1/L2/L3
 *   - disclosedClaims enum check (15 AuditEventField)
 *   - auditShareVersion const "1.0.0"
 */

import { describe, expect, it } from 'vitest';

import { validateAuditShareRequestSchema } from '../audit-share-validation.js';

// ── Test helpers ──────────────────────────────────────────────────────────────

function buildValidRequest(
    overrides: Partial<Record<string, unknown>> = {},
): Record<string, unknown> {
    return {
        auditShareVersion: '1.0.0',
        token: '11111111-2222-4333-8444-555555555555',
        disclosedClaims: ['eventType', 'timestamp'],
        challenge: 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee',
        audience: 'did:key:target-domain',
        notAfter: '2027-01-01T00:00:00.000Z',
        requestedScope: {
            tenantId: 'tenant-acme',
            auditClass: 'L1',
        },
        requesterDid: 'did:key:auditor-001',
        requesterSignature:
            '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
        ...overrides,
    };
}

// ── Happy path ──────────────────────────────────────────────────────────

describe('validateAuditShareRequestSchema — happy path', () => {
    it('should accept valid request with all required fields', () => {
        const result = validateAuditShareRequestSchema(buildValidRequest());
        expect(result.valid).toBe(true);
    });

    it('should accept request with optional chainNamespace', () => {
        const request = buildValidRequest({
            requestedScope: {
                tenantId: 'tenant-acme',
                auditClass: 'L2',
                chainNamespace: 'atp',
            },
        });
        const result = validateAuditShareRequestSchema(request);
        expect(result.valid).toBe(true);
    });

    it('should accept empty disclosedClaims array (similar to mode A; zero projection is valid)', () => {
        const result = validateAuditShareRequestSchema(
            buildValidRequest({ disclosedClaims: [] }),
        );
        expect(result.valid).toBe(true);
    });

    it('should accept all 15 AuditEventField values in disclosedClaims', () => {
        const allFields = [
            'id',
            'eventType',
            'actorDid',
            'targetAgentDid',
            'timestamp',
            'correlationId',
            'outcome',
            'denyReason',
            'prevHash',
            'signature',
            'tenantId',
            'auditClass',
            'chainNamespace',
            'chainPosition',
            'canonicalPayloadHash',
        ];
        const result = validateAuditShareRequestSchema(
            buildValidRequest({ disclosedClaims: allFields }),
        );
        expect(result.valid).toBe(true);
    });
});

// ── Required fields enforce ─────────────────────────────────────────────

describe('validateAuditShareRequestSchema — required fields', () => {
    const REQUIRED_FIELDS = [
        'auditShareVersion',
        'token',
        'disclosedClaims',
        'challenge',
        'audience',
        'notAfter',
        'requestedScope',
        'requesterDid',
        'requesterSignature',
    ];

    it.each(REQUIRED_FIELDS)(
        'should reject when required field %s is missing',
        (field) => {
            const request = buildValidRequest();
            delete request[field];
            const result = validateAuditShareRequestSchema(request);
            expect(result.valid).toBe(false);
        },
    );
});

// ── additionalProperties: false ─────────────────────────────────────────

describe('validateAuditShareRequestSchema — additionalProperties false', () => {
    it('should reject request with unknown top-level field', () => {
        const request = buildValidRequest({ unknownField: 'evil' });
        const result = validateAuditShareRequestSchema(request);
        expect(result.valid).toBe(false);
    });

    it('should reject requestedScope with unknown field', () => {
        const request = buildValidRequest({
            requestedScope: {
                tenantId: 'tenant-acme',
                auditClass: 'L1',
                unknown: 'evil',
            },
        });
        const result = validateAuditShareRequestSchema(request);
        expect(result.valid).toBe(false);
    });
});

// ── auditShareVersion const "1.0.0" ─────────────────────────────────────

describe('validateAuditShareRequestSchema — auditShareVersion const', () => {
    it('should reject auditShareVersion "2.0.0"', () => {
        const request = buildValidRequest({ auditShareVersion: '2.0.0' });
        const result = validateAuditShareRequestSchema(request);
        expect(result.valid).toBe(false);
    });

    it('should reject non-semver auditShareVersion', () => {
        const request = buildValidRequest({ auditShareVersion: 'not-semver' });
        const result = validateAuditShareRequestSchema(request);
        expect(result.valid).toBe(false);
    });
});

// ── token format uuid v4 ────────────────────────────────────────────────

describe('validateAuditShareRequestSchema — token UUID v4 strict', () => {
    it('should reject token that is not UUID v4', () => {
        const request = buildValidRequest({ token: 'not-a-uuid' });
        const result = validateAuditShareRequestSchema(request);
        expect(result.valid).toBe(false);
    });

    it('should reject UUID v1 (version digit 1)', () => {
        const request = buildValidRequest({
            token: '11111111-2222-1333-8444-555555555555',
        });
        const result = validateAuditShareRequestSchema(request);
        expect(result.valid).toBe(false);
    });
});

// ── audience must startsWith did: ──────────────────────────────────────

describe('validateAuditShareRequestSchema — audience pattern', () => {
    it('should reject audience that does not start with did:', () => {
        const request = buildValidRequest({
            audience: 'https://example.com',
        });
        const result = validateAuditShareRequestSchema(request);
        expect(result.valid).toBe(false);
    });

    it('should reject empty audience', () => {
        const request = buildValidRequest({ audience: '' });
        const result = validateAuditShareRequestSchema(request);
        expect(result.valid).toBe(false);
    });
});

// ── auditClass enum L1/L2/L3 ───────────────────────────────────────────

describe('validateAuditShareRequestSchema — auditClass enum', () => {
    it('should reject auditClass not in {L1, L2, L3}', () => {
        const request = buildValidRequest({
            requestedScope: {
                tenantId: 'tenant-acme',
                auditClass: 'L4',
            },
        });
        const result = validateAuditShareRequestSchema(request);
        expect(result.valid).toBe(false);
    });

    it('should accept L1 L2 L3', () => {
        for (const lvl of ['L1', 'L2', 'L3']) {
            const request = buildValidRequest({
                requestedScope: { tenantId: 'tenant', auditClass: lvl },
            });
            const result = validateAuditShareRequestSchema(request);
            expect(result.valid).toBe(true);
        }
    });
});

// ── disclosedClaims enum + uniqueItems ─────────────────────────────────

describe('validateAuditShareRequestSchema — disclosedClaims', () => {
    it('should reject disclosedClaims containing unknown field', () => {
        const request = buildValidRequest({
            disclosedClaims: ['eventType', 'evil_field'],
        });
        const result = validateAuditShareRequestSchema(request);
        expect(result.valid).toBe(false);
    });

    it('should reject duplicate items (uniqueItems true)', () => {
        const request = buildValidRequest({
            disclosedClaims: ['eventType', 'eventType'],
        });
        const result = validateAuditShareRequestSchema(request);
        expect(result.valid).toBe(false);
    });
});

// ── notAfter format date-time ──────────────────────────────────────────

describe('validateAuditShareRequestSchema — notAfter date-time', () => {
    it('should reject notAfter not in ISO 8601 format', () => {
        const request = buildValidRequest({ notAfter: 'not-a-date' });
        const result = validateAuditShareRequestSchema(request);
        expect(result.valid).toBe(false);
    });
});

// ── error structure shape ──────────────────────────────────────────────

describe('validateAuditShareRequestSchema — error shape', () => {
    it('should return AuditShareValidationError[] with instancePath + message + keyword', () => {
        const request = buildValidRequest({ auditShareVersion: '9.9.9' });
        const result = validateAuditShareRequestSchema(request);
        expect(result.valid).toBe(false);
        if (!result.valid) {
            expect(result.errors.length).toBeGreaterThan(0);
            const firstErr = result.errors[0]!;
            expect(typeof firstErr.instancePath).toBe('string');
            expect(typeof firstErr.message).toBe('string');
            expect(typeof firstErr.keyword).toBe('string');
        }
    });
});
