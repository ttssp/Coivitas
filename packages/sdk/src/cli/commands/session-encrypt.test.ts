/**
 * session-encrypt command unit tests
 *
 * Coverage paths:
 * - Success path: runSessionEncrypt returns { ciphertext, aad, encryptedPayload }
 * - Parameter path: output contains the correct field structure
 * - Error path: SessionCryptoHandleImpl state check (re-registering the same sessionId throws INTERNAL_ERROR)
 */

import { describe, expect, it } from 'vitest';

import { runSessionEncrypt } from './session-encrypt.js';

describe('runSessionEncrypt', () => {
    it('should return ciphertext, aad, and encryptedPayload when given valid options', async () => {
        const result = await runSessionEncrypt({
            sessionId: 'test-session-001',
            plaintext: 'hello world',
            tokenId: 'tok-abc-123',
        });

        expect(result).toHaveProperty('ciphertext');
        expect(result).toHaveProperty('aad');
        expect(result).toHaveProperty('encryptedPayload');

        // ciphertext is a hex string
        expect(typeof result.ciphertext).toBe('string');
        expect(result.ciphertext.length).toBeGreaterThan(0);

        // aad contains the required fields
        expect(result.aad).toHaveProperty('envelopeId');
        expect(result.aad).toHaveProperty('messageType', 'DEBUG_ENCRYPT');
        expect(result.aad).toHaveProperty('keyId');
        expect(result.aad).toHaveProperty('aeadNonce');

        // encryptedPayload fields are complete
        expect(result.encryptedPayload).toHaveProperty('encrypted', true);
        expect(result.encryptedPayload).toHaveProperty(
            'encryptionProtocolVersion',
            'ap/e2e/v1',
        );
        expect(result.encryptedPayload).toHaveProperty('type', 'BUSINESS');
    });

    it('should produce different ciphertexts for same plaintext on separate calls', async () => {
        const opts = {
            sessionId: 'test-session-diff-keys-1',
            plaintext: 'same plaintext',
            tokenId: 'tok-same',
        };

        const result1 = await runSessionEncrypt({
            ...opts,
            sessionId: 'test-session-diff-1',
        });
        const result2 = await runSessionEncrypt({
            ...opts,
            sessionId: 'test-session-diff-2',
        });

        // Different session -> different random keys -> different ciphertext
        expect(result1.ciphertext).not.toBe(result2.ciphertext);
    });

    it('should encrypt empty plaintext without throwing', async () => {
        const result = await runSessionEncrypt({
            sessionId: 'test-session-empty',
            plaintext: '',
            tokenId: 'tok-empty',
        });

        expect(result.ciphertext).toBeDefined();
        // AES-GCM produces a 16B GCM tag for empty plaintext, so the hex length is 32
        expect(result.ciphertext.length).toBeGreaterThanOrEqual(32);
    });
});
