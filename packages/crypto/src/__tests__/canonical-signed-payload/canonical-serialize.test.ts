/**
 * canonical-serialize.test.ts — CSP L1 crypto primitive unit tests
 *
 * Implements: csp v0.1 L1 crypto
 *
 * Coverage goals (>=95% coverage):
 *   - JCS determinism (key-order independent + nested objects + arrays);
 *   - empty payload + single field;
 *   - number/string boundaries (integer vs float vs numeric string vs non-ASCII);
 *   - all 6 exception paths (undefined / function / symbol / bigint / NaN / Infinity / circular ref);
 *   - both surfaces: canonicalSerialize (Uint8Array) + canonicalSerializeToString (string).
 */

import { describe, expect, it } from 'vitest';

import {
    canonicalSerialize,
    canonicalSerializeToString,
    CspError,
} from '../../canonical-signed-payload/index.js';

const textDecoder = new TextDecoder();

describe('canonicalSerialize — JCS determinism', () => {
    it('should produce stable key ordering when input keys differ in order', () => {
        const bytesAB = canonicalSerialize({ a: 1, b: 2 });
        const bytesBA = canonicalSerialize({ b: 2, a: 1 });
        expect(textDecoder.decode(bytesAB)).toBe(textDecoder.decode(bytesBA));
    });

    it('should canonicalize nested objects recursively', () => {
        const bytes = canonicalSerialize({ z: { b: 1, a: 2 } });
        expect(textDecoder.decode(bytes)).toBe('{"z":{"a":2,"b":1}}');
    });

    it('should preserve array element order (arrays are sequence-significant per RFC 8785)', () => {
        const bytes = canonicalSerialize({ list: [3, 2, 1] });
        expect(textDecoder.decode(bytes)).toBe('{"list":[3,2,1]}');
    });

    it('should produce idempotent output after JSON.parse + canonicalSerialize roundtrip', () => {
        const original = canonicalSerializeToString({
            b: [3, 2, 1],
            a: { z: false, y: null },
        });
        const roundtrip = canonicalSerializeToString(
            JSON.parse(original) as Record<string, unknown>,
        );
        expect(roundtrip).toBe(original);
    });

    it('should normalize 1.0 and 1 to identical canonical form (JCS number normalization)', () => {
        const bytesFloat = canonicalSerialize({ value: 1.0 });
        const bytesInt = canonicalSerialize({ value: 1 });
        expect(textDecoder.decode(bytesFloat)).toBe(
            textDecoder.decode(bytesInt),
        );
    });
});

describe('canonicalSerialize — empty + boundary payload', () => {
    it('should serialize empty object to "{}"', () => {
        const bytes = canonicalSerialize({});
        expect(textDecoder.decode(bytes)).toBe('{}');
    });

    it('should serialize single field object', () => {
        const bytes = canonicalSerialize({ key: 'value' });
        expect(textDecoder.decode(bytes)).toBe('{"key":"value"}');
    });

    it('should serialize null value field', () => {
        const bytes = canonicalSerialize({ value: null });
        expect(textDecoder.decode(bytes)).toBe('{"value":null}');
    });

    it('should serialize boolean values', () => {
        const bytes = canonicalSerialize({ t: true, f: false });
        expect(textDecoder.decode(bytes)).toBe('{"f":false,"t":true}');
    });

    it('should serialize integer / negative / zero', () => {
        const bytes = canonicalSerialize({ a: 0, b: -1, c: 999 });
        expect(textDecoder.decode(bytes)).toBe('{"a":0,"b":-1,"c":999}');
    });

    it('should serialize Unicode strings (UTF-8 byte output)', () => {
        const bytes = canonicalSerialize({ msg: '你好' });
        // RFC 8785 JCS does not escape Unicode characters (it UTF-8 encodes them directly)
        expect(textDecoder.decode(bytes)).toBe('{"msg":"你好"}');
    });

    it('should escape special JSON chars (quote / backslash / newline)', () => {
        const bytes = canonicalSerialize({
            s: 'a"b\\c\nd',
        });
        expect(textDecoder.decode(bytes)).toBe('{"s":"a\\"b\\\\c\\nd"}');
    });

    it('should return Uint8Array (not string)', () => {
        const bytes = canonicalSerialize({ a: 1 });
        expect(bytes).toBeInstanceOf(Uint8Array);
        expect(bytes.length).toBeGreaterThan(0);
    });
});

describe('canonicalSerialize — csp signed payload 5-field scenario', () => {
    it('should serialize csp signed payload 5 fields + cspVersion deterministically', () => {
        const payload1 = {
            cspVersion: '1.0.0',
            token: { id: 'token-123', specVersion: '0.3.0' },
            disclosedClaims: [],
            challenge: '550e8400-e29b-41d4-a716-446655440000',
            audience: 'did:example:verifier',
            notAfter: '2026-05-20T10:00:00.000Z',
        };

        // same fields in different input order -> byte-identical (the key JCS property)
        const payload2 = {
            notAfter: '2026-05-20T10:00:00.000Z',
            audience: 'did:example:verifier',
            challenge: '550e8400-e29b-41d4-a716-446655440000',
            disclosedClaims: [],
            token: { specVersion: '0.3.0', id: 'token-123' },
            cspVersion: '1.0.0',
        };

        const bytes1 = canonicalSerialize(payload1);
        const bytes2 = canonicalSerialize(payload2);
        expect(textDecoder.decode(bytes1)).toBe(textDecoder.decode(bytes2));
    });

    it('should serialize mode B csp signed payload (disclosedClaims non-empty)', () => {
        const payload = {
            cspVersion: '1.0.0',
            token: { id: 'token-456' },
            disclosedClaims: [
                { action: 'INQUIRY', scope: { type: 'allowlist' } },
            ],
            challenge: '550e8400-e29b-41d4-a716-446655440001',
            audience: 'https://verifier.example.com',
            notAfter: '2026-05-20T11:00:00.000Z',
        };
        const bytes = canonicalSerialize(payload);
        const serialized = textDecoder.decode(bytes);
        expect(serialized).toContain('"cspVersion":"1.0.0"');
        expect(serialized).toContain('"disclosedClaims":');
    });
});

describe('canonicalSerialize — fail-closed throw paths (anti-phantom)', () => {
    it('should throw CspError(CSP_SCHEMA_VIOLATION) on undefined field value', () => {
        expect(() => canonicalSerialize({ value: undefined })).toThrowError(
            CspError,
        );
        try {
            canonicalSerialize({ value: undefined });
        } catch (e) {
            expect(e).toBeInstanceOf(CspError);
            expect((e as CspError).code).toBe('CSP_SCHEMA_VIOLATION');
        }
    });

    it('should throw CspError on function field value', () => {
        expect(() =>
            canonicalSerialize({ fn: () => 1 }),
        ).toThrowError(CspError);
    });

    it('should throw CspError on symbol field value', () => {
        expect(() =>
            canonicalSerialize({ sym: Symbol('x') }),
        ).toThrowError(CspError);
    });

    it('should throw CspError on bigint field value', () => {
        expect(() => canonicalSerialize({ big: BigInt(1) })).toThrowError(
            CspError,
        );
    });

    it('should throw CspError on NaN field value', () => {
        expect(() => canonicalSerialize({ value: Number.NaN })).toThrowError(
            CspError,
        );
    });

    it('should throw CspError on Infinity field value', () => {
        expect(() =>
            canonicalSerialize({ value: Number.POSITIVE_INFINITY }),
        ).toThrowError(CspError);
    });

    it('should throw CspError on -Infinity field value', () => {
        expect(() =>
            canonicalSerialize({ value: Number.NEGATIVE_INFINITY }),
        ).toThrowError(CspError);
    });

    it('should throw CspError on circular reference', () => {
        const obj: Record<string, unknown> = { a: 1 };
        obj.self = obj;
        expect(() => canonicalSerialize(obj)).toThrowError(CspError);
        try {
            canonicalSerialize(obj);
        } catch (e) {
            expect((e as CspError).code).toBe('CSP_SCHEMA_VIOLATION');
        }
    });

    it('should throw CspError on nested undefined field', () => {
        expect(() =>
            canonicalSerialize({ outer: { inner: undefined } }),
        ).toThrowError(CspError);
    });

    it('should throw CspError on array containing undefined', () => {
        expect(() =>
            canonicalSerialize({ list: [1, undefined, 3] }),
        ).toThrowError(CspError);
    });
});

describe('canonicalSerializeToString — string surface', () => {
    it('should return string (not Uint8Array)', () => {
        const result = canonicalSerializeToString({ a: 1, b: 2 });
        expect(typeof result).toBe('string');
        expect(result).toBe('{"a":1,"b":2}');
    });

    it('should produce identical content to canonicalSerialize (UTF-8 decoded)', () => {
        const obj = { z: 1, a: { c: 3, b: 2 } };
        const bytes = canonicalSerialize(obj);
        const str = canonicalSerializeToString(obj);
        expect(textDecoder.decode(bytes)).toBe(str);
    });

    it('should throw CspError on undefined field (parity with canonicalSerialize)', () => {
        expect(() =>
            canonicalSerializeToString({ value: undefined }),
        ).toThrowError(CspError);
    });

    it('should throw CspError on NaN (parity with canonicalSerialize)', () => {
        expect(() =>
            canonicalSerializeToString({ value: Number.NaN }),
        ).toThrowError(CspError);
    });

    it('should throw CspError on circular reference (parity)', () => {
        const obj: Record<string, unknown> = { x: 1 };
        obj.cycle = obj;
        expect(() => canonicalSerializeToString(obj)).toThrowError(CspError);
    });
});

describe('canonicalSerialize — defensive catch (npm dep behavior change protection)', () => {
    /**
     * Defensive test coverage: the canonicalize npm package internal throw / non-string return paths.
     *
     * These guard against the phantom pattern that has recurred 8 times — we do not allow
     * "this error condition is theoretically unreachable, so skip it".
     * Real-world scenario: a canonicalize npm upgrade may change behavior (e.g. TypeError on bigint),
     * so we must catch + translate to CspError(CSP_SCHEMA_VIOLATION) rather than let the npm exception propagate.
     *
     * vi.mock simulates a canonicalize package exception to ensure the fail-closed path has an active throw.
     */

    it('should catch npm canonicalize package internal throw and translate to CspError', async () => {
        // Replace the canonicalize npm package with vi.doMock -> simulate an internal throw
        const { vi } = await import('vitest');
        vi.resetModules();
        vi.doMock('canonicalize', () => ({
            default: () => {
                throw new TypeError('simulated npm internal throw');
            },
        }));

        const mod = await import('../../canonical-signed-payload/canonical-serialize.js');

        try {
            mod.canonicalSerialize({ a: 1 });
            expect.fail('should have thrown CspError');
        } catch (e) {
            // Note: dynamic import returns module instance with fresh CspError class;
            // instanceof check fails across module boundaries; use duck-type via .code
            expect((e as { code?: string; name?: string }).code).toBe(
                'CSP_SCHEMA_VIOLATION',
            );
            expect((e as { name?: string }).name).toBe('CspError');
            expect((e as Error).message).toContain('canonicalSerialize');
        }

        vi.doUnmock('canonicalize');
        vi.resetModules();
    });

    it('should catch npm canonicalize package non-string return and translate to CspError', async () => {
        const { vi } = await import('vitest');
        vi.resetModules();
        vi.doMock('canonicalize', () => ({
            default: () => undefined,
        }));

        const mod = await import('../../canonical-signed-payload/canonical-serialize.js');

        try {
            mod.canonicalSerialize({ a: 1 });
            expect.fail('should have thrown CspError');
        } catch (e) {
            expect((e as { code?: string }).code).toBe('CSP_SCHEMA_VIOLATION');
            expect((e as { name?: string }).name).toBe('CspError');
            expect((e as Error).message).toContain('non-string');
        }

        vi.doUnmock('canonicalize');
        vi.resetModules();
    });

    it('should catch npm canonicalize package throw in canonicalSerializeToString', async () => {
        const { vi } = await import('vitest');
        vi.resetModules();
        vi.doMock('canonicalize', () => ({
            default: () => {
                throw new TypeError('simulated npm internal throw (toString variant)');
            },
        }));

        const mod = await import('../../canonical-signed-payload/canonical-serialize.js');

        try {
            mod.canonicalSerializeToString({ a: 1 });
            expect.fail('should have thrown CspError');
        } catch (e) {
            expect((e as { code?: string }).code).toBe('CSP_SCHEMA_VIOLATION');
            expect((e as { name?: string }).name).toBe('CspError');
            expect((e as Error).message).toContain(
                'canonicalSerializeToString',
            );
        }

        vi.doUnmock('canonicalize');
        vi.resetModules();
    });

    it('should catch npm canonicalize package non-string return in canonicalSerializeToString', async () => {
        const { vi } = await import('vitest');
        vi.resetModules();
        vi.doMock('canonicalize', () => ({
            default: () => undefined,
        }));

        const mod = await import('../../canonical-signed-payload/canonical-serialize.js');

        try {
            mod.canonicalSerializeToString({ a: 1 });
            expect.fail('should have thrown CspError');
        } catch (e) {
            expect((e as { code?: string }).code).toBe('CSP_SCHEMA_VIOLATION');
            expect((e as { name?: string }).name).toBe('CspError');
            expect((e as Error).message).toContain('non-string');
        }

        vi.doUnmock('canonicalize');
        vi.resetModules();
    });
});

describe('canonicalSerialize — RFC 8785 reference vectors', () => {
    /**
     * RFC 8785 example — JSON canonical form:
     *   input: {"numbers":[333333333.3333333,1E30,4.50,2e-3,0.000000000000000000000000001]}
     *   output: {"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27]}
     *
     * We use a simplified version to verify the number normalization path (1.0 -> 1) + key ordering.
     */
    it('should match RFC 8785 number normalization (1.0 → 1)', () => {
        const bytes = canonicalSerialize({ n: 1.0 });
        expect(textDecoder.decode(bytes)).toBe('{"n":1}');
    });

    it('should match RFC 8785 string escape (forward slash NOT escaped)', () => {
        // RFC 8785 explicitly DOES NOT escape forward slash (/)
        const bytes = canonicalSerialize({ url: 'https://example.com' });
        expect(textDecoder.decode(bytes)).toBe(
            '{"url":"https://example.com"}',
        );
    });

    it('should match RFC 8785 nested object key sorting (lexicographic)', () => {
        const bytes = canonicalSerialize({
            outer: { z: 1, a: 2, m: 3 },
        });
        expect(textDecoder.decode(bytes)).toBe(
            '{"outer":{"a":2,"m":3,"z":1}}',
        );
    });
});
