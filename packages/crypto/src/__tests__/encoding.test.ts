import { describe, expect, it } from 'vitest';

import {
    CryptoError,
    detectEncoding,
    fromBase64Url,
    fromHex,
    toBase64Url,
    toHex,
} from '../index.js';

describe('encoding - hex', () => {
    it('should convert bytes to lowercase hex when given standard bytes', () => {
        expect(toHex(new Uint8Array([0x0f, 0xff, 0xa0]))).toBe('0fffa0');
    });

    it('should return empty string when given empty bytes', () => {
        expect(toHex(new Uint8Array())).toBe('');
    });

    it('should accept uppercase input when decoding hex', () => {
        expect(Array.from(fromHex('0FFF'))).toEqual([0x0f, 0xff]);
    });

    it('should return empty Uint8Array when given empty hex string', () => {
        const result = fromHex('');
        expect(result).toBeInstanceOf(Uint8Array);
        expect(result.length).toBe(0);
    });

    it('should reject invalid hex input when string contains non-hex characters', () => {
        expect(() => fromHex('xyz')).toThrowError(CryptoError);
        expect(() => fromHex('abc')).toThrowError(CryptoError);
    });

    it('should reject odd-length hex string when given 3-char input', () => {
        expect(() => fromHex('0ff')).toThrowError(CryptoError);
    });

    it('should round-trip arbitrary bytes through hex when encoding then decoding', () => {
        const original = new Uint8Array([0x00, 0x01, 0x7f, 0x80, 0xfe, 0xff]);
        expect(Array.from(fromHex(toHex(original)))).toEqual(
            Array.from(original),
        );
    });
});

describe('encoding - toBase64Url', () => {
    it('should return empty string when given empty bytes', () => {
        expect(toBase64Url(new Uint8Array())).toBe('');
    });

    it('should encode single byte correctly when given 0x00', () => {
        // 0x00 → 000000 00 → "AA" (2 chars, no padding in output)
        expect(toBase64Url(new Uint8Array([0x00]))).toBe('AA');
    });

    it('should encode RFC 4648 test vector "Man" when given ASCII bytes', () => {
        // "Man" = 0x4d 0x61 0x6e → "TWFu"
        const bytes = new Uint8Array([0x4d, 0x61, 0x6e]);
        expect(toBase64Url(bytes)).toBe('TWFu');
    });

    it('should use - instead of + when encoding bytes with value 0xfb', () => {
        // 0xfb 0xff = 11111011 11111111 → 111110 111111 11xx → 62, 63 → "-_" prefix
        const bytes = new Uint8Array([0xfb, 0xff]);
        const result = toBase64Url(bytes);
        expect(result).toContain('-');
    });

    it('should use _ instead of / when encoding bytes that produce index 63', () => {
        // byte 0xff = 11111111, first 6 bits with next = 111111 = 63 → '_'
        const bytes = new Uint8Array([0x03, 0xff]);
        const result = toBase64Url(bytes);
        expect(result).not.toContain('/');
        expect(result).not.toContain('+');
    });

    it('should produce no padding characters when encoding', () => {
        const bytes = new Uint8Array([0x01]);
        expect(toBase64Url(bytes)).not.toContain('=');

        const bytes2 = new Uint8Array([0x01, 0x02]);
        expect(toBase64Url(bytes2)).not.toContain('=');
    });

    it('should handle 1-byte input producing 2-char output', () => {
        const result = toBase64Url(new Uint8Array([0x61])); // 'a' = 0x61
        expect(result.length).toBe(2);
    });

    it('should handle 2-byte input producing 3-char output', () => {
        const result = toBase64Url(new Uint8Array([0x61, 0x62]));
        expect(result.length).toBe(3);
    });

    it('should handle 3-byte input producing 4-char output', () => {
        const result = toBase64Url(new Uint8Array([0x61, 0x62, 0x63]));
        expect(result.length).toBe(4);
    });
});

describe('encoding - fromBase64Url', () => {
    it('should return empty Uint8Array when given empty string', () => {
        const result = fromBase64Url('');
        expect(result).toBeInstanceOf(Uint8Array);
        expect(result.length).toBe(0);
    });

    it('should decode RFC 4648 test vector "TWFu" when given standard base64url', () => {
        // "TWFu" → "Man" → 0x4d 0x61 0x6e
        const result = fromBase64Url('TWFu');
        expect(Array.from(result)).toEqual([0x4d, 0x61, 0x6e]);
    });

    it('should accept padded input when given base64url with == padding', () => {
        // 'AA==' is padded form of 0x00
        const result = fromBase64Url('AA==');
        expect(result.length).toBe(1);
        expect(result[0]).toBe(0x00);
    });

    it('should accept padded input when given base64url with = padding', () => {
        // 'YWI=' is padded form of "ab" = 0x61 0x62
        const result = fromBase64Url('YWI=');
        expect(Array.from(result)).toEqual([0x61, 0x62]);
    });

    it('should decode unpadded input when given base64url without padding', () => {
        // same as above without padding
        const result = fromBase64Url('YWI');
        expect(Array.from(result)).toEqual([0x61, 0x62]);
    });

    it('should throw CryptoError with ENCODING_ERROR when given illegal characters', () => {
        let thrown: unknown;
        try {
            fromBase64Url('abc!');
        } catch (e) {
            thrown = e;
        }
        expect(thrown).toBeInstanceOf(CryptoError);
        expect((thrown as CryptoError).code).toBe('ENCODING_ERROR');
    });

    it('should throw CryptoError when given base64 standard chars (+ and /)', () => {
        // standard base64 uses + and /, base64url uses - and _
        expect(() => fromBase64Url('ab+c')).toThrowError(CryptoError);
        expect(() => fromBase64Url('ab/c')).toThrowError(CryptoError);
    });

    it('should throw CryptoError when given whitespace in input', () => {
        expect(() => fromBase64Url('TW Fu')).toThrowError(CryptoError);
    });

    it('should round-trip arbitrary bytes through base64url when encoding then decoding', () => {
        const original = new Uint8Array([0x00, 0x01, 0x7f, 0x80, 0xfe, 0xff]);
        const encoded = toBase64Url(original);
        const decoded = fromBase64Url(encoded);
        expect(Array.from(decoded)).toEqual(Array.from(original));
    });

    it('should round-trip single byte when encoding then decoding', () => {
        for (const byte of [0x00, 0x01, 0x7e, 0x7f, 0x80, 0xff]) {
            const original = new Uint8Array([byte]);
            expect(Array.from(fromBase64Url(toBase64Url(original)))).toEqual(
                Array.from(original),
            );
        }
    });
});

describe('encoding - detectEncoding', () => {
    it('should return hex when given lowercase hex string with even length', () => {
        expect(detectEncoding('deadbeef')).toBe('hex');
    });

    it('should return hex when given uppercase hex string with even length', () => {
        expect(detectEncoding('DEADBEEF')).toBe('hex');
    });

    it('should return hex when given empty string', () => {
        expect(detectEncoding('')).toBe('hex');
    });

    it('should return base64url when given string with non-hex characters', () => {
        expect(detectEncoding('TWFu')).toBe('base64url');
    });

    it('should return base64url when given string with - character', () => {
        expect(detectEncoding('ab-cd')).toBe('base64url');
    });

    it('should return base64url when given string with _ character', () => {
        expect(detectEncoding('ab_cd')).toBe('base64url');
    });

    it('should return base64url when given hex-char-only string with odd length', () => {
        // odd-length strings cannot be hex
        expect(detectEncoding('abc')).toBe('base64url');
    });

    it('should return hex when given 64-char hex string (typical SHA-256 output)', () => {
        const sha256hex =
            'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
        expect(detectEncoding(sha256hex)).toBe('hex');
    });

    it('should return base64url when given base64url-encoded SHA-256', () => {
        // base64url of 32 zero bytes contains uppercase and potentially - or _
        const b64 = toBase64Url(new Uint8Array(32));
        expect(detectEncoding(b64)).toBe('base64url');
    });
});

describe('encoding - hex/base64url interoperability', () => {
    it('should produce identical bytes when decoding same data from hex and base64url', () => {
        const original = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
        const hexEncoded = toHex(original);
        const b64Encoded = toBase64Url(original);

        const fromHexResult = fromHex(hexEncoded);
        const fromB64Result = fromBase64Url(b64Encoded);

        expect(Array.from(fromHexResult)).toEqual(Array.from(fromB64Result));
    });

    it('should correctly identify and decode hex when detectEncoding is used', () => {
        const original = new Uint8Array([0xca, 0xfe, 0xba, 0xbe]);
        const hexStr = toHex(original);

        const detected = detectEncoding(hexStr);
        expect(detected).toBe('hex');

        const decoded =
            detected === 'hex' ? fromHex(hexStr) : fromBase64Url(hexStr);
        expect(Array.from(decoded)).toEqual(Array.from(original));
    });

    it('should correctly identify and decode base64url when detectEncoding is used', () => {
        // Use bytes that produce non-hex chars in base64url
        const original = new Uint8Array([0x01, 0x02, 0x03, 0x04, 0x05]);
        const b64Str = toBase64Url(original);

        const detected = detectEncoding(b64Str);
        // 'AQIDBA' contains uppercase and non-hex chars, should be base64url
        expect(detected).toBe('base64url');

        const decoded =
            detected === 'hex' ? fromHex(b64Str) : fromBase64Url(b64Str);
        expect(Array.from(decoded)).toEqual(Array.from(original));
    });
});
