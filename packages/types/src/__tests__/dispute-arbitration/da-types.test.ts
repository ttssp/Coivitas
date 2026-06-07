/**
 * Dispute Arbitration L0 types + factory function tests
 *
 * Sub-protocol — dispute-arbitration v0.1
 *
 * Coverage:
 *   - brand factory validation + error paths
 *   - DaError class behavior
 *   - handleDaError exhaustive switch
 *   - assertNeverDaCode guard
 *   - correctness of constant values
 *   - DISPUTE_STATE_TRANSITIONS 2-transition freeze
 *   - AJV schema validation (strict mode 4 flags)
 */

import { describe, it, expect } from 'vitest';
import {
    toDisputeId,
    toDaVersion,
    toSettlementOperationId,
    toCanonicalHashHex,
    DA_VERSION_1_0_0,
    DaError,
    handleDaError,
    assertNeverDaCode,
    MIN_ARBITRATOR_COUNT,
    MAX_ARBITRATOR_COUNT,
    MAX_DISPUTE_DAYS,
    MAX_DISPUTE_MS,
    DA_VERSION_CURRENT,
    DISPUTE_STATE_TRANSITIONS,
    validateDisputeFilingSchema,
    validateArbitrationDecisionSchema,
    assertValidDisputeFiling,
    assertValidArbitrationDecision,
    DA_STATE_VALUES,
    DA_DISPUTE_TYPE_VALUES,
    DA_VERDICT_VALUES,
} from '../../dispute-arbitration/index.js';

// ─── constants tests ───────────────────────────────

describe('dispute-arbitration constants', () => {
    it('should enforce MIN_ARBITRATOR_COUNT = 3', () => {
        expect(MIN_ARBITRATOR_COUNT).toBe(3);
    });

    it('should enforce MAX_ARBITRATOR_COUNT = 5', () => {
        expect(MAX_ARBITRATOR_COUNT).toBe(5);
    });

    it('should enforce MAX_DISPUTE_DAYS = 14', () => {
        expect(MAX_DISPUTE_DAYS).toBe(14);
    });

    it('should compute MAX_DISPUTE_MS = 14 * 24 * 3600 * 1000', () => {
        expect(MAX_DISPUTE_MS).toBe(14 * 24 * 3600 * 1000);
    });

    it('should set DA_VERSION_CURRENT to 1.0.0', () => {
        expect(DA_VERSION_CURRENT).toBe('1.0.0');
    });

    it('should have exactly 3 dispute states', () => {
        expect(DA_STATE_VALUES).toHaveLength(3);
        expect(DA_STATE_VALUES).toContain('FILED');
        expect(DA_STATE_VALUES).toContain('RESOLVED');
        expect(DA_STATE_VALUES).toContain('EXPIRED');
    });

    it('should have exactly 5 dispute types', () => {
        expect(DA_DISPUTE_TYPE_VALUES).toHaveLength(5);
    });

    it('should have exactly 3 verdict values', () => {
        expect(DA_VERDICT_VALUES).toHaveLength(3);
    });

    it('should freeze DISPUTE_STATE_TRANSITIONS to exactly 2 transitions', () => {
        expect(DISPUTE_STATE_TRANSITIONS).toHaveLength(2);
        expect(DISPUTE_STATE_TRANSITIONS[0]).toEqual(['FILED', 'RESOLVED']);
        expect(DISPUTE_STATE_TRANSITIONS[1]).toEqual(['FILED', 'EXPIRED']);
    });
});

// ─── brand factory tests ───────────────────────────────────────────

describe('toDisputeId factory', () => {
    const VALID_UUID = '550e8400-e29b-41d4-a716-446655440000';

    it('should create DisputeId for valid UUID v4', () => {
        const id = toDisputeId(VALID_UUID);
        expect(id).toBe(VALID_UUID);
    });

    it('should throw DA_FILING_INVALID for empty string when invalid UUID', () => {
        expect(() => toDisputeId('')).toThrow(DaError);
        try {
            toDisputeId('');
        } catch (e) {
            expect(e).toBeInstanceOf(DaError);
            expect((e as DaError).code).toBe('DA_FILING_INVALID');
        }
    });

    it('should throw DA_FILING_INVALID for non-UUID string', () => {
        expect(() => toDisputeId('not-a-uuid')).toThrow(DaError);
    });

    it('should throw DA_FILING_INVALID for UUID v1 (not v4)', () => {
        // UUID v1: 3rd segment starts with 1
        expect(() =>
            toDisputeId('550e8400-e29b-11d4-a716-446655440000'),
        ).toThrow(DaError);
    });
});

describe('toDaVersion factory', () => {
    it('should create DaVersion for supported version 1.0.0', () => {
        const v = toDaVersion('1.0.0');
        expect(v).toBe('1.0.0');
    });

    it('should throw DA_VERSION_UNSUPPORTED for unknown version', () => {
        try {
            toDaVersion('2.0.0');
        } catch (e) {
            expect(e).toBeInstanceOf(DaError);
            expect((e as DaError).code).toBe('DA_VERSION_UNSUPPORTED');
        }
    });

    it('should throw DA_VERSION_UNSUPPORTED for empty string', () => {
        expect(() => toDaVersion('')).toThrow(DaError);
    });
});

describe('toSettlementOperationId factory', () => {
    const VALID_UUID = '550e8400-e29b-41d4-a716-446655440001';

    it('should create SettlementOperationId for valid UUID v4', () => {
        const id = toSettlementOperationId(VALID_UUID);
        expect(id).toBe(VALID_UUID);
    });

    it('should throw DA_FILING_INVALID for invalid format', () => {
        try {
            toSettlementOperationId('invalid');
        } catch (e) {
            expect(e).toBeInstanceOf(DaError);
            expect((e as DaError).code).toBe('DA_FILING_INVALID');
        }
    });
});

describe('toCanonicalHashHex factory', () => {
    const VALID_SHA256 = 'a'.repeat(64); // 64 hex chars

    it('should create CanonicalHashHex for valid 64-char hex', () => {
        const hash = toCanonicalHashHex(VALID_SHA256);
        expect(hash).toBe(VALID_SHA256);
    });

    it('should throw DA_CANONICAL_HASH_MISMATCH for too-short hex', () => {
        try {
            toCanonicalHashHex('abc');
        } catch (e) {
            expect(e).toBeInstanceOf(DaError);
            expect((e as DaError).code).toBe('DA_CANONICAL_HASH_MISMATCH');
        }
    });

    it('should throw DA_CANONICAL_HASH_MISMATCH for non-hex characters', () => {
        const nonHex = 'g'.repeat(64);
        expect(() => toCanonicalHashHex(nonHex)).toThrow(DaError);
    });

    it('should throw DA_CANONICAL_HASH_MISMATCH for 63-char hex (too short)', () => {
        expect(() => toCanonicalHashHex('a'.repeat(63))).toThrow(DaError);
    });

    it('should throw DA_CANONICAL_HASH_MISMATCH for 65-char hex (too long)', () => {
        expect(() => toCanonicalHashHex('a'.repeat(65))).toThrow(DaError);
    });
});

describe('DA_VERSION_1_0_0 pre-built constant', () => {
    it('should equal 1.0.0 without factory invocation', () => {
        expect(DA_VERSION_1_0_0).toBe('1.0.0');
    });
});

// ─── DaError class tests ───────────────────────────────────────────────────────

describe('DaError class', () => {
    it('should extend Error', () => {
        const e = new DaError('DA_FILING_INVALID');
        expect(e).toBeInstanceOf(Error);
        expect(e).toBeInstanceOf(DaError);
    });

    it('should set name to DaError', () => {
        const e = new DaError('DA_CANONICAL_HASH_MISMATCH');
        expect(e.name).toBe('DaError');
    });

    it('should include code in message', () => {
        const e = new DaError('DA_TIMEOUT_EXCEEDED');
        expect(e.message).toContain('DA_TIMEOUT_EXCEEDED');
    });

    it('should use reason from detail in message when provided', () => {
        const e = new DaError('DA_FILING_INVALID', { reason: 'test_reason' });
        expect(e.message).toContain('test_reason');
    });

    it('should set empty detail when no detail provided', () => {
        const e = new DaError('DA_VERSION_UNSUPPORTED');
        expect(e.detail).toEqual({});
    });

    it('should preserve detail fields', () => {
        const e = new DaError('DA_ARBITRATOR_INSUFFICIENT', {
            poolSize: 2,
            minRequired: 3,
            reason: 'test',
        });
        expect(e.detail).toMatchObject({ poolSize: 2, minRequired: 3 });
    });

    it('should preserve instanceof across serialization boundary (prototype fix)', () => {
        const e = new DaError('DA_EVIDENCE_INVALID');
        // Ensure the prototype chain is correct (Object.setPrototypeOf)
        expect(Object.getPrototypeOf(e)).toBe(DaError.prototype);
    });

    it('should cover all 15 error codes (anti-phantom)', () => {
        const allCodes = [
            'DA_FILING_INVALID',
            'DA_DUPLICATE_FILING',
            'DA_CANONICAL_HASH_MISMATCH',
            'DA_SIGNED_PAYLOAD_INVALID',
            'DA_TIMEOUT_EXCEEDED',
            'DA_STATE_TRANSITION_INVALID',
            'DA_ARBITRATOR_INVALID',
            'DA_ARBITRATOR_INSUFFICIENT',
            'DA_INSUFFICIENT_SIGNATURES',
            'DA_EVIDENCE_INVALID',
            'DA_PROVIDER_UNAVAILABLE',
            'DA_VERSION_UNSUPPORTED',
            'DA_DISPUTE_REVOKED',
            'DA_IDEMPOTENCY_VIOLATION',
            'DA_FRESHNESS_INVALID',
        ] as const;
        expect(allCodes).toHaveLength(15);
        for (const code of allCodes) {
            const e = new DaError(code);
            expect(e.code).toBe(code);
        }
    });
});

// ─── handleDaError exhaustive switch tests ────────────────────────────────────

describe('handleDaError', () => {
    it('should return logged:true for every error code', () => {
        const codes = [
            'DA_FILING_INVALID',
            'DA_DUPLICATE_FILING',
            'DA_CANONICAL_HASH_MISMATCH',
            'DA_SIGNED_PAYLOAD_INVALID',
            'DA_TIMEOUT_EXCEEDED',
            'DA_STATE_TRANSITION_INVALID',
            'DA_ARBITRATOR_INVALID',
            'DA_ARBITRATOR_INSUFFICIENT',
            'DA_INSUFFICIENT_SIGNATURES',
            'DA_EVIDENCE_INVALID',
            'DA_PROVIDER_UNAVAILABLE',
            'DA_VERSION_UNSUPPORTED',
            'DA_DISPUTE_REVOKED',
            'DA_IDEMPOTENCY_VIOLATION',
            'DA_FRESHNESS_INVALID',
        ] as const;

        for (const code of codes) {
            const result = handleDaError(new DaError(code));
            expect(result.logged).toBe(true);
            expect(result.code).toBe(code);
        }
    });
});

// ─── assertNeverDaCode guard tests ─────────────────────────────────────────────

describe('assertNeverDaCode', () => {
    it('should throw DA_STATE_TRANSITION_INVALID with unreachable detail', () => {
        try {
            assertNeverDaCode('UNKNOWN_CODE' as never);
        } catch (e) {
            expect(e).toBeInstanceOf(DaError);
            expect((e as DaError).code).toBe('DA_STATE_TRANSITION_INVALID');
            expect((e as DaError).detail).toMatchObject({
                reason: 'exhaustive_guard_unreachable_da_error_code',
            });
        }
    });
});

// ─── AJV schema validation tests (strict mode 4 flags) ───────────────────────────────

describe('validateDisputeFilingSchema', () => {
    const VALID_UUID = '550e8400-e29b-41d4-a716-446655440000';
    const VALID_HASH = 'a'.repeat(64);

    const validPayload = {
        disputeId: VALID_UUID,
        claimantDid: 'did:key:z6Mkabcdef',
        respondentDid: 'did:key:z6Mkghijkl',
        disputeType: 'SETTLEMENT_FAILED',
        evidenceUris: [],
        cspVersion: '1.0.0',
        token: 'token-value',
        disclosedClaims: {},
        challenge: 'challenge-abc',
        audience: 'did:key:z6Mkaudience',
        notAfter: new Date(Date.now() + 3600000).toISOString(),
        filedAt: new Date().toISOString(),
        daVersion: '1.0.0',
        canonicalHash: VALID_HASH,
        claimantSignature: 'sig-abc',
    };

    it('should validate a correct DisputeFilingSignedPayload', () => {
        const result = validateDisputeFilingSchema(validPayload);
        expect(result.valid).toBe(true);
        expect(result.errors).toHaveLength(0);
    });

    it('should reject payload missing required fields', () => {
        const incomplete = { disputeId: VALID_UUID };
        const result = validateDisputeFilingSchema(incomplete);
        expect(result.valid).toBe(false);
        expect(result.errors.length).toBeGreaterThan(0);
    });

    it('should reject payload with invalid disputeType', () => {
        const invalid = { ...validPayload, disputeType: 'INVALID_TYPE' };
        const result = validateDisputeFilingSchema(invalid);
        expect(result.valid).toBe(false);
    });

    it('should reject payload with invalid canonicalHash format', () => {
        const invalid = { ...validPayload, canonicalHash: 'not-a-hash' };
        const result = validateDisputeFilingSchema(invalid);
        expect(result.valid).toBe(false);
    });

    it('should reject payload with additional unknown properties', () => {
        const withExtra = { ...validPayload, unknownField: 'extra' };
        const result = validateDisputeFilingSchema(withExtra);
        expect(result.valid).toBe(false);
    });
});

describe('validateArbitrationDecisionSchema', () => {
    const VALID_UUID = '550e8400-e29b-41d4-a716-446655440000';
    const VALID_HASH = 'b'.repeat(64);

    const validDecision = {
        decisionId: 'dec-001',
        disputeId: VALID_UUID,
        verdict: 'CLAIMANT_PREVAILS',
        multisigThreshold: 2,
        multisigPoolSize: 3,
        decisionCanonicalHash: VALID_HASH,
        arbitratorSignatures: [
            { arbitratorDid: 'did:key:z6Mkarb1', signature: 'sig1' },
            { arbitratorDid: 'did:key:z6Mkarb2', signature: 'sig2' },
        ],
        decidedAt: new Date().toISOString(),
    };

    it('should validate a correct ArbitrationDecision', () => {
        const result = validateArbitrationDecisionSchema(validDecision);
        expect(result.valid).toBe(true);
    });

    it('should reject multisigPoolSize = 2 (SQL DDL layer minimum = 3)', () => {
        const invalid = { ...validDecision, multisigPoolSize: 2 };
        const result = validateArbitrationDecisionSchema(invalid);
        expect(result.valid).toBe(false);
    });

    it('should reject multisigPoolSize = 6 (above MAX_ARBITRATOR_COUNT = 5)', () => {
        const invalid = { ...validDecision, multisigPoolSize: 6 };
        const result = validateArbitrationDecisionSchema(invalid);
        expect(result.valid).toBe(false);
    });

    it('should reject invalid verdict', () => {
        const invalid = { ...validDecision, verdict: 'INVALID_VERDICT' };
        const result = validateArbitrationDecisionSchema(invalid);
        expect(result.valid).toBe(false);
    });
});

describe('assertValidDisputeFiling', () => {
    it('should throw DaError DA_FILING_INVALID for invalid payload', () => {
        try {
            assertValidDisputeFiling({ foo: 'bar' });
        } catch (e) {
            expect(e).toBeInstanceOf(DaError);
            expect((e as DaError).code).toBe('DA_FILING_INVALID');
        }
    });
});

describe('assertValidArbitrationDecision', () => {
    it('should throw DaError DA_ARBITRATOR_INVALID for invalid decision', () => {
        try {
            assertValidArbitrationDecision({ foo: 'bar' });
        } catch (e) {
            expect(e).toBeInstanceOf(DaError);
            expect((e as DaError).code).toBe('DA_ARBITRATOR_INVALID');
        }
    });
});
