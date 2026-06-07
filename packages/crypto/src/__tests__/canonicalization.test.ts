import { describe, expect, it } from 'vitest';

import { canonicalize, CryptoError } from '../index.js';

describe('canonicalize', () => {
    it('produces stable object key ordering', () => {
        expect(canonicalize({ b: 1, a: 2 })).toBe(canonicalize({ a: 2, b: 1 }));
    });

    it('canonicalizes nested objects recursively', () => {
        expect(canonicalize({ z: { b: 1, a: 2 } })).toBe('{"z":{"a":2,"b":1}}');
    });

    it('normalizes equivalent numeric values', () => {
        expect(canonicalize({ value: 1.0 })).toBe(canonicalize({ value: 1 }));
    });

    it('is idempotent after parse and canonicalize', () => {
        const original = canonicalize({
            b: [3, 2, 1],
            a: { z: false, y: null },
        });
        expect(
            canonicalize(JSON.parse(original) as Record<string, unknown>),
        ).toBe(original);
    });

    it('rejects unsupported values', () => {
        expect(() => canonicalize({ value: undefined })).toThrowError(
            CryptoError,
        );
        expect(() => canonicalize({ value: Number.NaN })).toThrowError(
            CryptoError,
        );
    });
});
