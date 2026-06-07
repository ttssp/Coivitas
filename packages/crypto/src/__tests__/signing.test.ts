import { ed25519 } from '@noble/curves/ed25519';
import { describe, expect, it, vi } from 'vitest';

import {
    fromBase64Url,
    fromHex,
    toBase64Url,
    toHex,
} from '../encoding.js';
import { CryptoError, sign, verify } from '../index.js';

const textEncoder = new TextEncoder();

// RFC 8032 test vector (hex format)
const rfcPrivateKey =
    '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60' +
    'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a';
const rfcPublicKey =
    'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a';
const rfcSignature =
    'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155' +
    '5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b';

// Derive base64url-format test vectors
const rfcPrivateKeyBytes = fromHex(rfcPrivateKey);
const rfcPublicKeyBytes = fromHex(rfcPublicKey);
const rfcSignatureBytes = fromHex(rfcSignature);

// base64url of the 64-byte private key (86 chars)
const rfcPrivateKeyBase64 = toBase64Url(rfcPrivateKeyBytes);
// base64url of just the 32-byte seed (43 chars)
const rfcSeedBase64 = toBase64Url(rfcPrivateKeyBytes.subarray(0, 32));
// base64url of the 32-byte public key (43 chars)
const rfcPublicKeyBase64 = toBase64Url(rfcPublicKeyBytes);
// base64url of the 64-byte signature (86 chars)
const rfcSignatureBase64 = toBase64Url(rfcSignatureBytes);

describe('sign — hex private key (existing behavior)', () => {
    it('should produce deterministic signatures when using hex private key', () => {
        const message = textEncoder.encode('hello world');
        const first = sign(message, rfcPrivateKey);
        const second = sign(message, rfcPrivateKey);

        expect(first).toBe(second);
        expect(first).toHaveLength(128);
    });

    it('should match the RFC 8032 test vector when signing empty message', () => {
        expect(sign(new Uint8Array(), rfcPrivateKey)).toBe(rfcSignature);
    });

    it('should reject invalid private key lengths', () => {
        expect(() => sign(textEncoder.encode('hello'), 'abcd')).toThrowError(
            CryptoError,
        );
    });
});

describe('sign — base64url private key input (02a)', () => {
    it('should sign with 64-byte base64url private key and return hex by default', () => {
        const sig = sign(new Uint8Array(), rfcPrivateKeyBase64);
        expect(sig).toBe(rfcSignature);
        expect(sig).toHaveLength(128);
    });

    it('should sign with 32-byte seed base64url private key and return hex', () => {
        const sig = sign(new Uint8Array(), rfcSeedBase64);
        // The seed is identical, so the signature should match the full private key
        expect(sig).toBe(rfcSignature);
    });

    it('should return base64url signature when outputEncoding is base64url', () => {
        const sig = sign(new Uint8Array(), rfcPrivateKey, 'base64url');
        expect(sig).toBe(rfcSignatureBase64);
        // base64url has no padding; 64 bytes → 86 chars
        expect(sig.length).toBe(86);
    });

    it('should return hex signature when outputEncoding is hex explicitly', () => {
        const sig = sign(new Uint8Array(), rfcPrivateKey, 'hex');
        expect(sig).toBe(rfcSignature);
        expect(sig).toHaveLength(128);
    });

    it('should produce same bytes regardless of private key encoding', () => {
        const sigFromHex = sign(textEncoder.encode('test'), rfcPrivateKey);
        const sigFromBase64 = sign(
            textEncoder.encode('test'),
            rfcPrivateKeyBase64,
        );
        const sigFromSeed = sign(
            textEncoder.encode('test'),
            rfcSeedBase64,
        );

        expect(sigFromHex).toBe(sigFromBase64);
        expect(sigFromHex).toBe(sigFromSeed);
    });

    it('should reject private key with invalid byte length', () => {
        // 16 bytes → base64url 21 chars, not a valid private key length
        const shortKey = toBase64Url(new Uint8Array(16));
        expect(() => sign(textEncoder.encode('hello'), shortKey)).toThrowError(
            CryptoError,
        );
    });
});

describe('verify — existing behavior (hex)', () => {
    it('should accept the RFC 8032 test vector', () => {
        expect(verify(new Uint8Array(), rfcSignature, rfcPublicKey)).toBe(true);
    });

    it('should return false when message is tampered', () => {
        const message = textEncoder.encode('hello world');
        const signature = sign(message, rfcPrivateKey);
        const tamperedMessage = Uint8Array.from(message);
        tamperedMessage[0]! ^= 0xff;

        expect(verify(tamperedMessage, signature, rfcPublicKey)).toBe(false);
    });

    it('should return false when signature is tampered', () => {
        const message = textEncoder.encode('hello world');
        const signature = sign(message, rfcPrivateKey);
        const tamperedSignature = `${signature.slice(0, -2)}00`;

        expect(verify(message, tamperedSignature, rfcPublicKey)).toBe(false);
    });

    it('should return false when public key is tampered', () => {
        const message = textEncoder.encode('hello world');
        const signature = sign(message, rfcPrivateKey);
        const tamperedPublicKey = `${rfcPublicKey.slice(0, -2)}00`;

        expect(verify(message, signature, tamperedPublicKey)).toBe(false);
    });

    it('should reject malformed public keys', () => {
        expect(() =>
            verify(textEncoder.encode('hello'), rfcSignature, 'abcd'),
        ).toThrowError(CryptoError);
    });
});

describe('verify — dual-format support (02b)', () => {
    it('should verify when signature is base64url and public key is hex', () => {
        expect(verify(new Uint8Array(), rfcSignatureBase64, rfcPublicKey)).toBe(
            true,
        );
    });

    it('should verify when signature is hex and public key is base64url', () => {
        expect(verify(new Uint8Array(), rfcSignature, rfcPublicKeyBase64)).toBe(
            true,
        );
    });

    it('should verify when both signature and public key are base64url', () => {
        expect(
            verify(new Uint8Array(), rfcSignatureBase64, rfcPublicKeyBase64),
        ).toBe(true);
    });

    it('should return false for tampered base64url signature', () => {
        const message = textEncoder.encode('hello world');
        // Obtain the correct base64url signature
        const sigBase64 = sign(message, rfcPrivateKey, 'base64url');
        // Decode, tamper the first byte, re-encode
        const sigBytes = fromBase64Url(sigBase64);
        sigBytes[0]! ^= 0xff;
        const tamperedSigBase64 = toBase64Url(sigBytes);

        expect(verify(message, tamperedSigBase64, rfcPublicKey)).toBe(false);
    });

    it('should reject malformed base64url signature (wrong byte length)', () => {
        // 16 bytes → base64url 21 chars, wrong signature length
        const shortSig = toBase64Url(new Uint8Array(16));
        expect(() =>
            verify(textEncoder.encode('hello'), shortSig, rfcPublicKey),
        ).toThrowError(CryptoError);
    });

    it('should reject malformed base64url public key (wrong byte length)', () => {
        // 16 bytes → base64url 21 chars, wrong public key length
        const shortKey = toBase64Url(new Uint8Array(16));
        expect(() =>
            verify(textEncoder.encode('hello'), rfcSignature, shortKey),
        ).toThrowError(CryptoError);
    });
});

describe('mixed-format cross verification (02d)', () => {
    it('should verify hex-signed with base64url-encoded verification inputs', () => {
        const message = textEncoder.encode('cross-format test');
        // hex private key signing, default hex output
        const hexSig = sign(message, rfcPrivateKey);
        // Convert to base64url
        const b64Sig = toBase64Url(fromHex(hexSig));

        expect(verify(message, b64Sig, rfcPublicKeyBase64)).toBe(true);
    });

    it('should verify base64url-signed with hex verification inputs', () => {
        const message = textEncoder.encode('cross-format test');
        // base64url private key signing, base64url output
        const b64Sig = sign(message, rfcPrivateKeyBase64, 'base64url');
        // Convert to hex
        const hexSig = toHex(fromBase64Url(b64Sig));

        expect(verify(message, hexSig, rfcPublicKey)).toBe(true);
    });

    it('should produce identical bytes from sign regardless of private key format or output encoding', () => {
        const message = textEncoder.encode('encoding consistency');

        const hexSig = sign(message, rfcPrivateKey, 'hex');
        const b64Sig = sign(message, rfcPrivateKeyBase64, 'base64url');

        // The two output formats should be identical after decoding
        expect(fromHex(hexSig)).toEqual(fromBase64Url(b64Sig));
    });

    it('should verify across all four format combinations', () => {
        const message = textEncoder.encode('all combinations');
        const hexSig = sign(message, rfcPrivateKey, 'hex');
        const b64Sig = sign(message, rfcPrivateKey, 'base64url');

        // hex sig + hex key
        expect(verify(message, hexSig, rfcPublicKey)).toBe(true);
        // hex sig + base64url key
        expect(verify(message, hexSig, rfcPublicKeyBase64)).toBe(true);
        // base64url sig + hex key
        expect(verify(message, b64Sig, rfcPublicKey)).toBe(true);
        // base64url sig + base64url key
        expect(verify(message, b64Sig, rfcPublicKeyBase64)).toBe(true);
    });
});

describe('error-path coverage (assertMessage / catch blocks)', () => {
    it('should throw INTERNAL_CRYPTO_ERROR when message is not Uint8Array', () => {
        // assertMessage branch: non-Uint8Array input
        expect(() =>
            sign('not-a-uint8array' as unknown as Uint8Array, rfcPrivateKey),
        ).toThrowError(CryptoError);

        expect(() =>
            verify(
                'not-a-uint8array' as unknown as Uint8Array,
                rfcSignature,
                rfcPublicKey,
            ),
        ).toThrowError(CryptoError);
    });

    it('should throw INVALID_KEY_FORMAT when private key has invalid base64url chars', () => {
        // assertPrivateKey catch branch: a string with illegal characters is classified as base64url by detectEncoding but fromBase64Url throws
        // Construct a string with illegal characters (such as !) that does not look like hex
        const invalidKey = '!invalid!base64url!key!string!here!!!!!!!!!!';
        expect(() => sign(textEncoder.encode('hello'), invalidKey)).toThrowError(
            CryptoError,
        );
    });

    it('should throw INVALID_SIGNATURE_FORMAT when signature has invalid base64url chars', () => {
        // assertSignature catch branch
        const invalidSig = '!invalid!base64url!sig!here!!!!!!!!!!!!!!!!!!!!!!!!!!!!';
        expect(() =>
            verify(textEncoder.encode('hello'), invalidSig, rfcPublicKey),
        ).toThrowError(CryptoError);
    });

    it('should throw INVALID_KEY_FORMAT when public key has invalid base64url chars', () => {
        // assertPublicKey catch branch
        const invalidKey = '!invalid!base64url!pub!key!here!!!!!!!!!!!';
        expect(() =>
            verify(textEncoder.encode('hello'), rfcSignature, invalidKey),
        ).toThrowError(CryptoError);
    });

    it('should return false when ed25519.verify throws a non-CryptoError', () => {
        // verify catch branch: returns false when ed25519.verify throws a non-CryptoError
        // Use vi.spyOn to mock ed25519.verify throwing a plain Error
        vi.spyOn(ed25519, 'verify').mockImplementationOnce(() => {
            throw new Error('mock ed25519 error');
        });

        const result = verify(textEncoder.encode('test'), rfcSignature, rfcPublicKey);
        expect(result).toBe(false);

        vi.restoreAllMocks();
    });

    it('should re-throw CryptoError when ed25519.verify throws a CryptoError', () => {
        // verify catch branch: re-throws when ed25519.verify throws a CryptoError
        const cryptoErr = new CryptoError('INTERNAL_CRYPTO_ERROR', 'mock error');
        vi.spyOn(ed25519, 'verify').mockImplementationOnce(() => {
            throw cryptoErr;
        });

        expect(() =>
            verify(textEncoder.encode('test'), rfcSignature, rfcPublicKey),
        ).toThrow(cryptoErr);

        vi.restoreAllMocks();
    });

    it('should throw INTERNAL_CRYPTO_ERROR when ed25519.sign throws', () => {
        // sign catch branch: wraps a plain Error thrown by ed25519.sign as INTERNAL_CRYPTO_ERROR
        vi.spyOn(ed25519, 'sign').mockImplementationOnce(() => {
            throw new Error('mock ed25519 sign error');
        });

        expect(() =>
            sign(textEncoder.encode('test'), rfcPrivateKey),
        ).toThrowError(CryptoError);

        vi.restoreAllMocks();
    });

    it('should throw INTERNAL_CRYPTO_ERROR when ed25519.sign throws non-Error', () => {
        // sign catch branch: the case where error instanceof Error is false (undefined cause)
        vi.spyOn(ed25519, 'sign').mockImplementationOnce(() => {
            // eslint-disable-next-line @typescript-eslint/only-throw-error
            throw 'string error';
        });

        expect(() =>
            sign(textEncoder.encode('test'), rfcPrivateKey),
        ).toThrowError(CryptoError);

        vi.restoreAllMocks();
    });
});
