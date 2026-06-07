import { describe, expect, it } from 'vitest';

import { generateKeyPair, sign, verify } from '../index.js';

const message = new TextEncoder().encode('key generation roundtrip');

describe('generateKeyPair', () => {
    it('creates a 32-byte public key and a 64-byte private key', () => {
        const keyPair = generateKeyPair();

        expect(keyPair.publicKey).toHaveLength(64);
        expect(keyPair.privateKey).toHaveLength(128);
    });

    it('generates unique public keys across 100 pairs', () => {
        const publicKeys = new Set<string>();

        for (let index = 0; index < 100; index += 1) {
            publicKeys.add(generateKeyPair().publicKey);
        }

        expect(publicKeys.size).toBe(100);
    });

    it('supports sign and verify roundtrip', () => {
        const keyPair = generateKeyPair();
        const signature = sign(message, keyPair.privateKey);

        expect(verify(message, signature, keyPair.publicKey)).toBe(true);
    });
});
