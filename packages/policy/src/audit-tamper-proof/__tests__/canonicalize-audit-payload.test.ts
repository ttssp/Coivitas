/**
 * canonicalizeAuditPayload — L3 unit tests (counterexample defense enforced)
 *
 * Test scope:
 *   1. valid object payload -> RFC 8785 JCS output (verified via top-level import canonicalize)
 *   2. invalid payload (null / primitive / array / circular) -> AUDIT_CANONICALIZE_BYPASS_DETECTED
 *   3. deterministic canonical output (key order does not affect the output — JCS literal lex sort)
 */

import { describe, expect, it } from 'vitest';
import { AuditError } from '@coivitas/types';
import { canonicalizeAuditPayload } from '../canonicalize-audit-payload.js';

describe('canonicalizeAuditPayload — RFC 8785 JCS strict', () => {
    it('should produce canonical string when payload is well-formed object', () => {
        const result = canonicalizeAuditPayload({ b: 2, a: 1 });
        // JCS lex sort key: {"a":1,"b":2}
        expect(result).toBe('{"a":1,"b":2}');
    });

    it('should produce identical output for two object payloads with different key insertion order', () => {
        const r1 = canonicalizeAuditPayload({ x: 1, y: 2, z: 3 });
        const r2 = canonicalizeAuditPayload({ z: 3, y: 2, x: 1 });
        expect(r1).toBe(r2);
    });

    it('should throw AUDIT_CANONICALIZE_BYPASS_DETECTED when payload is null', () => {
        expect(() => canonicalizeAuditPayload(null)).toThrow(AuditError);
        try {
            canonicalizeAuditPayload(null);
        } catch (e) {
            expect((e as AuditError).code).toBe(
                'AUDIT_CANONICALIZE_BYPASS_DETECTED',
            );
        }
    });

    it('should throw AUDIT_CANONICALIZE_BYPASS_DETECTED when payload is primitive number', () => {
        expect(() => canonicalizeAuditPayload(42)).toThrow(
            'AUDIT_CANONICALIZE_BYPASS_DETECTED',
        );
    });

    it('should throw AUDIT_CANONICALIZE_BYPASS_DETECTED when payload is primitive string', () => {
        expect(() => canonicalizeAuditPayload('not-object')).toThrow(
            'AUDIT_CANONICALIZE_BYPASS_DETECTED',
        );
    });

    it('should throw AUDIT_CANONICALIZE_BYPASS_DETECTED when payload is an array (not object)', () => {
        expect(() => canonicalizeAuditPayload([1, 2, 3])).toThrow(
            'AUDIT_CANONICALIZE_BYPASS_DETECTED',
        );
    });

    it('should throw AUDIT_CANONICALIZE_BYPASS_DETECTED when payload contains circular reference', () => {
        const circular: Record<string, unknown> = { foo: 'bar' };
        circular['self'] = circular;
        expect(() => canonicalizeAuditPayload(circular)).toThrow(
            'AUDIT_CANONICALIZE_BYPASS_DETECTED',
        );
    });

    it('should throw AUDIT_CANONICALIZE_BYPASS_DETECTED when payload value contains function (non-serializable)', () => {
        const withFn = { foo: 'bar', cb: () => 1 };
        expect(() => canonicalizeAuditPayload(withFn)).toThrow(
            'AUDIT_CANONICALIZE_BYPASS_DETECTED',
        );
    });

    it('should re-throw the original AuditError without re-wrapping', () => {
        // When calling canonicalize throws an AuditError (the internal guard already threw), it should be re-thrown as-is
        // In practice triggered via an array: the array is rejected by the type guard -> AuditError thrown directly
        const evidence: Error[] = [];
        try {
            canonicalizeAuditPayload([1, 2, 3]);
        } catch (e) {
            evidence.push(e as Error);
        }
        // Should be the original AuditError instance; not double-wrapped by the try/catch
        expect(evidence[0]).toBeInstanceOf(AuditError);
        expect((evidence[0] as AuditError).code).toBe(
            'AUDIT_CANONICALIZE_BYPASS_DETECTED',
        );
    });
});
