import { CryptoError } from './types.js';

const HEX_PATTERN = /^[0-9a-f]+$/i;

// RFC 4648: base64url alphabet, + replaced by -, / replaced by _
const BASE64URL_CHARS =
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

// valid base64url alphabet (with optional padding)
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]*={0,2}$/;

export function toHex(bytes: Uint8Array): string {
    return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join(
        '',
    );
}

export function fromHex(hex: string): Uint8Array {
    if (hex.length === 0) {
        return new Uint8Array();
    }

    if (hex.length % 2 !== 0 || !HEX_PATTERN.test(hex)) {
        throw new CryptoError(
            'INVALID_HEX_STRING',
            'Hex string must have an even length and contain only hexadecimal characters.',
        );
    }

    const normalized = hex.toLowerCase();
    const bytes = new Uint8Array(normalized.length / 2);

    for (let index = 0; index < normalized.length; index += 2) {
        bytes[index / 2] = Number.parseInt(
            normalized.slice(index, index + 2),
            16,
        );
    }

    return bytes;
}

/**
 * Encodes a byte array as a base64url string (RFC 4648, no padding).
 * Conclusion: empty input returns an empty string; no external dependency, implemented with pure bit operations.
 */
export function toBase64Url(bytes: Uint8Array): string {
    if (bytes.length === 0) {
        return '';
    }

    let result = '';
    const len = bytes.length;

    // process in groups of 3 bytes, producing 4 base64url characters
    for (let i = 0; i < len; i += 3) {
        const b0 = bytes[i]!;
        const b1 = i + 1 < len ? bytes[i + 1]! : 0;
        const b2 = i + 2 < len ? bytes[i + 2]! : 0;

        result += BASE64URL_CHARS[b0 >> 2];
        result += BASE64URL_CHARS[((b0 & 0x03) << 4) | (b1 >> 4)];
        if (i + 1 < len) {
            result += BASE64URL_CHARS[((b1 & 0x0f) << 2) | (b2 >> 6)];
        }
        if (i + 2 < len) {
            result += BASE64URL_CHARS[b2 & 0x3f];
        }
    }

    return result;
}

/**
 * Decodes a base64url string into a byte array (RFC 4648).
 * Conclusion: accepts with/without padding; illegal characters throw CryptoError('ENCODING_ERROR').
 */
export function fromBase64Url(str: string): Uint8Array {
    if (str.length === 0) {
        return new Uint8Array();
    }

    // strip optional padding (= sign), then validate the remaining characters
    const stripped = str.replace(/=+$/, '');

    if (!BASE64URL_PATTERN.test(str)) {
        throw new CryptoError(
            'ENCODING_ERROR',
            'Invalid base64url string: contains illegal characters.',
        );
    }

    // len % 4 === 1 is an impossible valid base64url length (RFC 4648)
    if (stripped.length % 4 === 1) {
        throw new CryptoError(
            'ENCODING_ERROR',
            'Invalid base64url string: impossible length (length mod 4 must not be 1).',
        );
    }

    // build the decode lookup table
    const lookup = new Uint8Array(256).fill(255);
    for (let i = 0; i < BASE64URL_CHARS.length; i++) {
        lookup[BASE64URL_CHARS.charCodeAt(i)] = i;
    }

    const len = stripped.length;
    // compute the output byte count: every 4 base64 characters map to 3 bytes, with tail handling
    const outputLen = Math.floor((len * 3) / 4);
    const result = new Uint8Array(outputLen);
    let outIdx = 0;

    for (let i = 0; i < len; i += 4) {
        // the input has passed the BASE64URL_PATTERN check, so lookup will not return 255
        const c0 = lookup[stripped.charCodeAt(i)]!;
        const c1 = i + 1 < len ? lookup[stripped.charCodeAt(i + 1)]! : 0;
        const c2 = i + 2 < len ? lookup[stripped.charCodeAt(i + 2)]! : 0;
        const c3 = i + 3 < len ? lookup[stripped.charCodeAt(i + 3)]! : 0;

        result[outIdx++] = (c0 << 2) | (c1 >> 4);

        if (i + 2 < len) {
            result[outIdx++] = ((c1 & 0x0f) << 4) | (c2 >> 2);
        }

        if (i + 3 < len) {
            result[outIdx++] = ((c2 & 0x03) << 6) | c3;
        }
    }

    return result;
}

/**
 * Heuristically determines the string encoding format.
 * Conclusion:
 *   - all characters are [0-9a-fA-F] and the length is even → 'hex'
 *   - otherwise → 'base64url'
 * Edge case: pure hex characters with an even length are decided as hex first (consistent with the wire-format default).
 */
export function detectEncoding(str: string): 'hex' | 'base64url' {
    if (str.length === 0) {
        // an empty string can be represented by both formats, defaults to returning hex
        return 'hex';
    }

    if (str.length % 2 === 0 && HEX_PATTERN.test(str)) {
        return 'hex';
    }

    return 'base64url';
}
