import { describe, expect, it } from 'vitest';

import { fromBase64Url, fromHex } from '../encoding.js';
import { hash } from '../index.js';

describe('hash', () => {
    it('matches the SHA-256 test vector for empty input', () => {
        expect(hash('')).toBe(
            'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        );
    });

    it('matches the SHA-256 test vector for abc', () => {
        expect(hash('abc')).toBe(
            'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
        );
    });

    it('should return hex by default when encoding param is omitted', () => {
        // Omitting the encoding parameter behaves identically to explicitly passing hex
        expect(hash('hello')).toBe(hash('hello', 'hex'));
    });

    it('should return hex when encoding is explicitly hex', () => {
        const result = hash('abc', 'hex');
        expect(result).toBe(
            'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
        );
    });

    it('should return base64url when encoding is base64url', () => {
        const result = hash('abc', 'base64url');
        // The base64url charset contains only A-Z a-z 0-9 - _, with no padding character
        expect(result).toMatch(/^[A-Za-z0-9_-]+$/);
    });

    it('should produce consistent bytes for hex and base64url outputs of same input', () => {
        const input = 'hello world';
        const hexOut = hash(input, 'hex');
        const b64Out = hash(input, 'base64url');

        // The decoded bytes from both encodings should be identical
        const bytesFromHex = fromHex(hexOut);
        const bytesFromB64 = fromBase64Url(b64Out);

        expect(bytesFromHex).toEqual(bytesFromB64);
    });

    it('should produce consistent bytes for hex and base64url outputs of Uint8Array input', () => {
        const input = new Uint8Array([1, 2, 3, 4, 5]);
        const hexOut = hash(input, 'hex');
        const b64Out = hash(input, 'base64url');

        const bytesFromHex = fromHex(hexOut);
        const bytesFromB64 = fromBase64Url(b64Out);

        expect(bytesFromHex).toEqual(bytesFromB64);
    });

    it('should handle empty string with base64url encoding', () => {
        // SHA-256('') = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        const hexOut = hash('', 'hex');
        const b64Out = hash('', 'base64url');

        expect(fromHex(hexOut)).toEqual(fromBase64Url(b64Out));
    });
});
