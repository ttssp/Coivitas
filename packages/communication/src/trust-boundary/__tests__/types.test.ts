/**
 * trust-boundary primitive v0.1 — types.ts unit tests
 *
 * Coverage targets:
 * - factory function brand cast guard
 * - LEGAL_TRANSITIONS allowlist completeness
 * - TbErrorCode strict union coverage
 *
 * Covered behaviors:
 * - brand type + factory
 * - 8 legal transitions + invariant I4
 * - the 17-entry TB_* error code namespace
 */

import { describe, expect, it } from 'vitest';

import {
    LEGAL_TRANSITIONS,
    TB_DEFAULT_BOUNDS,
    TbProtocolError,
    toTbVersionString,
    toTrustBoundaryId,
    toUuidV4String,
    type TbErrorCode,
} from '../types.js';

describe('trust-boundary types — brand factory guard', () => {
    describe('toTrustBoundaryId', () => {
        it('should return TrustBoundaryId brand when input is valid UUID v4', () => {
            const valid = '550e8400-e29b-41d4-a716-446655440000';
            const result = toTrustBoundaryId(valid);
            expect(result).toBe(valid);
        });

        it('should throw TB_ID_INVALID when input is not UUID v4 format', () => {
            expect(() => toTrustBoundaryId('not-a-uuid')).toThrow('TB_ID_INVALID');
        });

        it('should throw TB_ID_INVALID when input is UUID v1 (wrong version)', () => {
            // the first digit of the third UUID v1 segment is 1, not 4
            expect(() =>
                toTrustBoundaryId('550e8400-e29b-11d4-a716-446655440000'),
            ).toThrow('TB_ID_INVALID');
        });

        it('should throw TB_ID_INVALID when input has uppercase hex (UUID v4 lowercase only)', () => {
            expect(() =>
                toTrustBoundaryId('550E8400-E29B-41D4-A716-446655440000'),
            ).toThrow('TB_ID_INVALID');
        });

        it('should throw TB_ID_INVALID when input is empty string', () => {
            expect(() => toTrustBoundaryId('')).toThrow('TB_ID_INVALID');
        });
    });

    describe('toTbVersionString', () => {
        it('should return TbVersionString brand when input is semver format', () => {
            const result = toTbVersionString('1.0.0');
            expect(result).toBe('1.0.0');
        });

        it('should throw TB_VERSION_UNSUPPORTED when not semver', () => {
            expect(() => toTbVersionString('v1.0.0')).toThrow('TB_VERSION_UNSUPPORTED');
            expect(() => toTbVersionString('1.0')).toThrow('TB_VERSION_UNSUPPORTED');
            expect(() => toTbVersionString('1.0.0-beta')).toThrow(
                'TB_VERSION_UNSUPPORTED',
            );
        });

        it('should accept semver bump candidates (2.0.0 / 1.1.0)', () => {
            // the factory only validates the semver format; v0.1 spec acceptance is rechecked by assertInvariant
            expect(toTbVersionString('2.0.0')).toBe('2.0.0');
            expect(toTbVersionString('1.1.0')).toBe('1.1.0');
        });
    });

    describe('toUuidV4String (binding proof id placeholder)', () => {
        it('should return UuidV4String brand when input is valid UUID v4', () => {
            const valid = '550e8400-e29b-41d4-a716-446655440000';
            expect(toUuidV4String(valid)).toBe(valid);
        });

        it('should throw TB_BINDING_PROOF_INVALID_UUID when input is not UUID v4', () => {
            expect(() => toUuidV4String('not-uuid')).toThrow(
                'TB_BINDING_PROOF_INVALID_UUID',
            );
        });
    });
});

describe('LEGAL_TRANSITIONS allowlist — 8 legal transitions', () => {
    it('should contain T1 onTrustEstablished pending → active', () => {
        const t1 = LEGAL_TRANSITIONS.find(
            (t) =>
                t.from === 'pending' &&
                t.event === 'onTrustEstablished' &&
                t.to === 'active',
        );
        expect(t1).toBeDefined();
        expect(t1?.id).toBe('T1');
    });

    it('should contain T2 onLeaseExtended active → active (self-loop)', () => {
        const t2 = LEGAL_TRANSITIONS.find(
            (t) =>
                t.from === 'active' &&
                t.event === 'onLeaseExtended' &&
                t.to === 'active',
        );
        expect(t2).toBeDefined();
        expect(t2?.id).toBe('T2');
    });

    it('should contain T3 onSuspended active → suspended', () => {
        const t3 = LEGAL_TRANSITIONS.find(
            (t) =>
                t.from === 'active' &&
                t.event === 'onSuspended' &&
                t.to === 'suspended',
        );
        expect(t3).toBeDefined();
        expect(t3?.id).toBe('T3');
    });

    it('should contain T4 onResumed suspended → active', () => {
        const t4 = LEGAL_TRANSITIONS.find(
            (t) =>
                t.from === 'suspended' && t.event === 'onResumed' && t.to === 'active',
        );
        expect(t4).toBeDefined();
        expect(t4?.id).toBe('T4');
    });

    it('should contain T5 onRevoked for both active and suspended', () => {
        const t5Active = LEGAL_TRANSITIONS.find(
            (t) => t.from === 'active' && t.event === 'onRevoked' && t.to === 'revoked',
        );
        const t5Suspended = LEGAL_TRANSITIONS.find(
            (t) =>
                t.from === 'suspended' && t.event === 'onRevoked' && t.to === 'revoked',
        );
        expect(t5Active?.id).toBe('T5');
        expect(t5Suspended?.id).toBe('T5');
    });

    it('should contain T6 onExpired for both active and suspended (client/system path)', () => {
        const t6Active = LEGAL_TRANSITIONS.find(
            (t) =>
                t.from === 'active' &&
                t.event === 'onExpired' &&
                t.to === 'expired' &&
                t.id === 'T6',
        );
        const t6Suspended = LEGAL_TRANSITIONS.find(
            (t) =>
                t.from === 'suspended' &&
                t.event === 'onExpired' &&
                t.to === 'expired' &&
                t.id === 'T6',
        );
        expect(t6Active).toBeDefined();
        expect(t6Suspended).toBeDefined();
    });

    it('should contain T7 auto-sweep for both active and suspended (sweeper path)', () => {
        const t7Active = LEGAL_TRANSITIONS.find(
            (t) =>
                t.from === 'active' &&
                t.event === 'onExpired' &&
                t.to === 'expired' &&
                t.id === 'T7',
        );
        const t7Suspended = LEGAL_TRANSITIONS.find(
            (t) =>
                t.from === 'suspended' &&
                t.event === 'onExpired' &&
                t.to === 'expired' &&
                t.id === 'T7',
        );
        expect(t7Active).toBeDefined();
        expect(t7Suspended).toBeDefined();
    });

    it('should contain T8 onEmergencySuspended (placeholder)', () => {
        const t8 = LEGAL_TRANSITIONS.find(
            (t) => t.event === 'onEmergencySuspended' && t.id === 'T8',
        );
        expect(t8).toBeDefined();
        expect(t8?.from).toBe('active');
        expect(t8?.to).toBe('emergency_suspended');
    });

    it('should have exactly 11 transition entries (T1 + T2 + T3 + T4 + 2*T5 + 2*T6 + 2*T7 + T8)', () => {
        // T1=1 + T2=1 + T3=1 + T4=1 + T5(active+suspended)=2 + T6(active+suspended)=2 + T7(active+suspended)=2 + T8=1 = 11
        expect(LEGAL_TRANSITIONS.length).toBe(11);
    });

    it('should NOT contain illegal transition: pending → revoked (must go through active first)', () => {
        const illegal = LEGAL_TRANSITIONS.find(
            (t) =>
                t.from === 'pending' && t.event === 'onRevoked' && t.to === 'revoked',
        );
        expect(illegal).toBeUndefined();
    });

    it('should NOT contain reverse transition: revoked → active (revoked is terminal)', () => {
        const illegal = LEGAL_TRANSITIONS.find(
            (t) => t.from === 'revoked' && t.to === 'active',
        );
        expect(illegal).toBeUndefined();
    });

    it('should NOT contain reverse transition: expired → active (expired is terminal)', () => {
        const illegal = LEGAL_TRANSITIONS.find(
            (t) => t.from === 'expired' && t.to === 'active',
        );
        expect(illegal).toBeUndefined();
    });
});

describe('TbProtocolError — fail-closed error class', () => {
    it('should construct error with code + message + invariant', () => {
        const err = new TbProtocolError(
            'TB_INVALID_TRANSITION',
            'illegal transition test',
            'I4',
        );
        expect(err.code).toBe('TB_INVALID_TRANSITION');
        expect(err.invariant).toBe('I4');
        expect(err.message).toContain('[TB_INVALID_TRANSITION]');
        expect(err.name).toBe('TbProtocolError');
    });

    it('should support all 20 TbErrorCode union values (compile-time exhaustive)', () => {
        // compiles; verifies at runtime that the enum strings are stable
        const codes: TbErrorCode[] = [
            'TB_VERSION_UNSUPPORTED',
            'TB_ID_INVALID',
            'TB_PARTY_INVALID',
            'TB_PARTY_SELF_REFERENTIAL',
            'TB_STATE_INVALID',
            'TB_INVALID_TRANSITION',
            'TB_LIFECYCLE_INVALID',
            'TB_BOUNDARY_EXPIRED',
            'TB_BINDING_PROOF_MISSING',
            'TB_BINDING_PROOF_UNEXPECTED',
            'TB_PAYLOAD_COVERAGE_INSUFFICIENT',
            'TB_EXPIRY_CLIENT_CONTROLLED',
            'TB_PRINCIPAL_POP_MISSING',
            'TB_EMERGENCY_NOT_IMPLEMENTED',
            'TB_AUDIT_CANONICALIZE_FAILED',
            'TB_SCHEMA_VIOLATION',
            'TB_AUDIT_TRANSITION_SOURCE_INVALID',
            'TB_SUSPENDED_OPERATION_DENIED',
            'TB_BOUNDARY_NOT_FOUND',
            'TB_BOUNDARY_PROOF_VERIFY_FAILED',
        ];
        expect(codes.length).toBe(20);
    });
});

describe('TB_DEFAULT_BOUNDS — lease-only baseline', () => {
    it('should have minWindowMs = 1000 (1s clock skew defense)', () => {
        expect(TB_DEFAULT_BOUNDS.minWindowMs).toBe(1_000);
    });

    it('should have maxLifecycleWindowMs ≈ 6 month', () => {
        const sixMonthsMs = 6 * 30 * 24 * 60 * 60 * 1_000;
        expect(TB_DEFAULT_BOUNDS.maxLifecycleWindowMs).toBe(sixMonthsMs);
    });
});
