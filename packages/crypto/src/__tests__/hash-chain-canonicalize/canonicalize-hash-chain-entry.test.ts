/**
 * canonicalize-hash-chain-entry.test.ts — HCC L1 crypto primitive unit tests
 *
 * Implements: hcc v0.1 L1 crypto
 *    top-level import block + constraint #3 FULL (canonicalize is the primary uniqueness carrier)
 *
 * Coverage goals (>=95% coverage; anti-phantom defense for the 6 error-code throw-paths):
 *   - JCS determinism (key-order independent + nested + array order significant);
 *   - empty payload + boundaries (empty object / single field / null value / boolean);
 *   - all exception paths (undefined / function / symbol / bigint / NaN / Infinity / circular ref);
 *   - both surfaces: canonicalizeHashChainEntry (Uint8Array) + canonicalizeHashChainEntryToString (string).
 */

import { describe, expect, it } from 'vitest';

import { HashChainError } from '@coivitas/types';

import {
    canonicalizeHashChainEntry,
    canonicalizeHashChainEntryToString,
} from '../../hash-chain-canonicalize/index.js';

const textDecoder = new TextDecoder();

describe('canonicalizeHashChainEntry — JCS determinism', () => {
    it('should produce stable key ordering regardless of input order', () => {
        const bytesAB = canonicalizeHashChainEntry({ a: 1, b: 2 });
        const bytesBA = canonicalizeHashChainEntry({ b: 2, a: 1 });
        expect(textDecoder.decode(bytesAB)).toBe(textDecoder.decode(bytesBA));
    });

    it('should canonicalize nested objects recursively', () => {
        const bytes = canonicalizeHashChainEntry({ z: { b: 1, a: 2 } });
        expect(textDecoder.decode(bytes)).toBe('{"z":{"a":2,"b":1}}');
    });

    it('should preserve array element order (arrays are sequence-significant per RFC 8785)', () => {
        const bytes = canonicalizeHashChainEntry({ list: [3, 2, 1] });
        expect(textDecoder.decode(bytes)).toBe('{"list":[3,2,1]}');
    });

    it('should produce idempotent output after JSON.parse + canonicalize roundtrip (I1 invariant)', () => {
        const original = canonicalizeHashChainEntryToString({
            b: [3, 2, 1],
            a: { z: false, y: null },
        });
        const roundtrip = canonicalizeHashChainEntryToString(
            JSON.parse(original) as Record<string, unknown>,
        );
        expect(roundtrip).toBe(original);
    });

    it('should normalize 1.0 and 1 to identical canonical form (JCS number normalization)', () => {
        const bytesFloat = canonicalizeHashChainEntry({ value: 1.0 });
        const bytesInt = canonicalizeHashChainEntry({ value: 1 });
        expect(textDecoder.decode(bytesFloat)).toBe(
            textDecoder.decode(bytesInt),
        );
    });
});

describe('canonicalizeHashChainEntry — empty + boundary payload', () => {
    it('should serialize empty object to "{}"', () => {
        const bytes = canonicalizeHashChainEntry({});
        expect(textDecoder.decode(bytes)).toBe('{}');
    });

    it('should serialize single field object', () => {
        const bytes = canonicalizeHashChainEntry({ key: 'value' });
        expect(textDecoder.decode(bytes)).toBe('{"key":"value"}');
    });

    it('should serialize null value field', () => {
        const bytes = canonicalizeHashChainEntry({ value: null });
        expect(textDecoder.decode(bytes)).toBe('{"value":null}');
    });

    it('should serialize boolean values', () => {
        const bytes = canonicalizeHashChainEntry({ t: true, f: false });
        expect(textDecoder.decode(bytes)).toBe('{"f":false,"t":true}');
    });

    it('should serialize UTF-8 characters (non-ASCII payload)', () => {
        const bytes = canonicalizeHashChainEntry({ text: '中文测试' });
        // canonicalize npm escapes non-ASCII as JSON literal in some versions;
        // this test only asserts the output is a valid string and can round-trip
        const decoded = textDecoder.decode(bytes);
        expect(JSON.parse(decoded)).toEqual({ text: '中文测试' });
    });
});

// ─── HC_CANONICALIZE_FAILED throw-path (anti-phantom defense, 6 cases) ────────────

describe('canonicalizeHashChainEntry — fail-closed throw HC_CANONICALIZE_FAILED', () => {
    it('should throw HC_CANONICALIZE_FAILED for undefined field value', () => {
        expect(() =>
            canonicalizeHashChainEntry({ x: undefined } as unknown as Record<
                string,
                unknown
            >),
        ).toThrow(HashChainError);
        expect(() =>
            canonicalizeHashChainEntry({ x: undefined } as unknown as Record<
                string,
                unknown
            >),
        ).toThrow(/HC_CANONICALIZE_FAILED/);
    });

    it('should throw HC_CANONICALIZE_FAILED for function field value', () => {
        expect(() =>
            canonicalizeHashChainEntry({ fn: () => 1 }),
        ).toThrow(HashChainError);
    });

    it('should throw HC_CANONICALIZE_FAILED for symbol field value', () => {
        expect(() =>
            canonicalizeHashChainEntry({ sym: Symbol('x') }),
        ).toThrow(HashChainError);
    });

    it('should throw HC_CANONICALIZE_FAILED for bigint field value', () => {
        expect(() =>
            canonicalizeHashChainEntry({ big: 123n }),
        ).toThrow(HashChainError);
    });

    it('should throw HC_CANONICALIZE_FAILED for NaN field value', () => {
        expect(() =>
            canonicalizeHashChainEntry({ n: NaN }),
        ).toThrow(HashChainError);
    });

    it('should throw HC_CANONICALIZE_FAILED for Infinity field value', () => {
        expect(() =>
            canonicalizeHashChainEntry({ inf: Infinity }),
        ).toThrow(HashChainError);
    });

    it('should throw HC_CANONICALIZE_FAILED for -Infinity field value', () => {
        expect(() =>
            canonicalizeHashChainEntry({ inf: -Infinity }),
        ).toThrow(HashChainError);
    });

    it('should throw HC_CANONICALIZE_FAILED for circular reference', () => {
        const obj: Record<string, unknown> = { a: 1 };
        obj.self = obj;
        expect(() => canonicalizeHashChainEntry(obj)).toThrow(HashChainError);
        expect(() => canonicalizeHashChainEntry(obj)).toThrow(
            /circular reference/,
        );
    });

    it('should throw HC_CANONICALIZE_FAILED for nested undefined', () => {
        expect(() =>
            canonicalizeHashChainEntry({
                nested: { deep: undefined } as unknown as Record<
                    string,
                    unknown
                >,
            }),
        ).toThrow(HashChainError);
    });

    it('should throw HC_CANONICALIZE_FAILED for array containing undefined', () => {
        expect(() =>
            canonicalizeHashChainEntry({
                list: [1, undefined, 3] as unknown as unknown[],
            }),
        ).toThrow(HashChainError);
    });

    it('should throw HC_CANONICALIZE_FAILED for circular array reference', () => {
        const arr: unknown[] = [1, 2];
        arr.push(arr);
        expect(() =>
            canonicalizeHashChainEntry({ list: arr }),
        ).toThrow(HashChainError);
    });
});

// ─── canonicalizeHashChainEntryToString — surface consistency ─────────────────────

describe('canonicalizeHashChainEntryToString — surface consistency', () => {
    it('should produce same string as Uint8Array decode', () => {
        const obj = { b: 2, a: 1 };
        const str = canonicalizeHashChainEntryToString(obj);
        const bytes = canonicalizeHashChainEntry(obj);
        expect(str).toBe(textDecoder.decode(bytes));
    });

    it('should also throw HC_CANONICALIZE_FAILED for undefined (string surface, same semantics)', () => {
        expect(() =>
            canonicalizeHashChainEntryToString({ x: undefined } as unknown as Record<
                string,
                unknown
            >),
        ).toThrow(HashChainError);
    });

    it('should throw HC_CANONICALIZE_FAILED for NaN (string surface)', () => {
        expect(() =>
            canonicalizeHashChainEntryToString({ n: NaN }),
        ).toThrow(HashChainError);
    });

    it('should throw HC_CANONICALIZE_FAILED for circular ref (string surface)', () => {
        const obj: Record<string, unknown> = { a: 1 };
        obj.self = obj;
        expect(() =>
            canonicalizeHashChainEntryToString(obj),
        ).toThrow(HashChainError);
    });

    it('should produce "{}" for empty object', () => {
        expect(canonicalizeHashChainEntryToString({})).toBe('{}');
    });

    it('should canonicalize stable across multiple calls (determinism)', () => {
        const obj = { b: 2, a: 1, c: { z: 3, y: 4 } };
        const r1 = canonicalizeHashChainEntryToString(obj);
        const r2 = canonicalizeHashChainEntryToString(obj);
        const r3 = canonicalizeHashChainEntryToString(obj);
        expect(r1).toBe(r2);
        expect(r2).toBe(r3);
    });
});
