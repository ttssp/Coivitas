import { ed25519 } from '@noble/curves/ed25519';

import {
    detectEncoding,
    fromBase64Url,
    fromHex,
    toBase64Url,
    toHex,
} from './encoding.js';
import { CryptoError } from './types.js';

// Private helper: uniformly convert a hex or base64url string to raw bytes.
// Bottom line: use detectEncoding to determine the format first; not exported.
function normalizeKey(input: string): Uint8Array {
    const encoding = detectEncoding(input);

    if (encoding === 'hex') {
        return fromHex(input);
    }

    return fromBase64Url(input);
}

function assertMessage(message: Uint8Array): void {
    if (!(message instanceof Uint8Array)) {
        throw new CryptoError(
            'INTERNAL_CRYPTO_ERROR',
            'Message must be a Uint8Array.',
        );
    }
}

// Supported private-key formats:
// - 128-char hex (64 bytes: seed 32 + pubkey 32)
// - 86-char base64url (64 bytes, no padding)
// - 44-char base64url (32-byte seed, no padding, with 1 padding =)
// - 43-char base64url (32-byte seed, no padding)
// sign only takes the first 32 bytes as the seed, so both 32-byte and 64-byte private keys are accepted
function assertPrivateKey(privateKey: string): Uint8Array {
    let keyBytes: Uint8Array;

    try {
        keyBytes = normalizeKey(privateKey);
    } catch {
        throw new CryptoError(
            'INVALID_KEY_FORMAT',
            'Private key must be a valid hex or base64url encoded string.',
        );
    }

    // Accept either length: 32-byte seed or 64-byte (seed + pubkey)
    if (keyBytes.length !== 32 && keyBytes.length !== 64) {
        throw new CryptoError(
            'INVALID_KEY_FORMAT',
            'Private key must decode to 32 bytes (seed) or 64 bytes (seed + public key).',
        );
    }

    return keyBytes;
}

// Supported public-key formats:
// - 64-char hex (32 bytes)
// - 43-char base64url (32 bytes, no padding)
function assertPublicKey(publicKey: string): Uint8Array {
    let keyBytes: Uint8Array;

    try {
        keyBytes = normalizeKey(publicKey);
    } catch {
        throw new CryptoError(
            'INVALID_KEY_FORMAT',
            'Public key must be a valid hex or base64url encoded string.',
        );
    }

    if (keyBytes.length !== 32) {
        throw new CryptoError(
            'INVALID_KEY_FORMAT',
            'Public key must decode to 32 bytes.',
        );
    }

    return keyBytes;
}

// Supported signature formats:
// - 128-char hex (64 bytes)
// - 86-char base64url (64 bytes, no padding)
function assertSignature(signature: string): Uint8Array {
    let signatureBytes: Uint8Array;

    try {
        signatureBytes = normalizeKey(signature);
    } catch {
        throw new CryptoError(
            'INVALID_SIGNATURE_FORMAT',
            'Signature must be a valid hex or base64url encoded string.',
        );
    }

    if (signatureBytes.length !== 64) {
        throw new CryptoError(
            'INVALID_SIGNATURE_FORMAT',
            'Signature must decode to 64 bytes.',
        );
    }

    return signatureBytes;
}

/**
 * Ed25519-sign a message
 * - privateKey: accepts 128-char hex (64 bytes) or 43/44/86-char base64url (32/64 bytes seed)
 * - outputEncoding: defaults to 'hex' (consistent with wire-format-freeze), optionally 'base64url'
 */
export function sign(
    message: Uint8Array,
    privateKey: string,
    outputEncoding: 'hex' | 'base64url' = 'hex',
): string {
    assertMessage(message);
    const keyBytes = assertPrivateKey(privateKey);

    try {
        // Take the first 32 bytes as the seed; compatible with 32-byte and 64-byte private keys
        const signatureBytes = ed25519.sign(message, keyBytes.subarray(0, 32));

        return outputEncoding === 'base64url'
            ? toBase64Url(signatureBytes)
            : toHex(signatureBytes);
    } catch (error) {
        throw new CryptoError(
            'INTERNAL_CRYPTO_ERROR',
            'Failed to sign the message.',
            error instanceof Error ? error : undefined,
        );
    }
}

/**
 * Verify an Ed25519 signature
 * - signature: accepts 128-char hex or base64url
 * - publicKey: accepts 64-char hex or base64url
 * Bottom line: the verification result is independent of the encoding format
 */
export function verify(
    message: Uint8Array,
    signature: string,
    publicKey: string,
): boolean {
    assertMessage(message);
    const signatureBytes = assertSignature(signature);
    const publicKeyBytes = assertPublicKey(publicKey);

    try {
        return ed25519.verify(signatureBytes, message, publicKeyBytes);
    } catch (error) {
        if (error instanceof CryptoError) {
            throw error;
        }

        return false;
    }
}
