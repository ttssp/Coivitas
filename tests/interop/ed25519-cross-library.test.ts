import { createPublicKey, verify as verifyWithNodeCrypto } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import interopVectors from '../fixtures/interop/ed25519-vectors.json';

interface InteropVector {
    id: string;
    message_hex: string;
    public_key_hex: string;
    signature_hex: string;
    expected: 'valid' | 'invalid';
}

const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

describe('ed25519 cross-library interoperability', () => {
    const vectors = interopVectors.vectors as InteropVector[];

    for (const vector of vectors) {
        it(`matches Node/OpenSSL verification for ${vector.id}`, () => {
            const publicKey = createPublicKey({
                key: Buffer.concat([
                    ED25519_SPKI_PREFIX,
                    Buffer.from(vector.public_key_hex, 'hex'),
                ]),
                format: 'der',
                type: 'spki',
            });

            const valid = verifyWithNodeCrypto(
                null,
                Buffer.from(vector.message_hex, 'hex'),
                publicKey,
                Buffer.from(vector.signature_hex, 'hex'),
            );

            expect(valid).toBe(vector.expected === 'valid');
        });
    }
});
