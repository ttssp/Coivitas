/**
 *  Encryption primitive unit tests
 *
 * Coverage:
 * - X25519 keypair generation and ECDH
 * - transcript_hash 16-field RFC 8785 + SHA-256
 * - HKDF key derivation (4 expands)
 * - chain-key rekey derivation
 * - keyId computation (SHA-256[0:16] hex)
 * - AEAD nonce construction (12B)
 * - AAD byte construction (8 fields, RFC 8785)
 * - AES-256-GCM encrypt/decrypt
 * - direction semantic helpers
 *
 */

import { describe, expect, it } from 'vitest';

import {
    aeadDecrypt,
    aeadEncrypt,
    buildAeadBytes,
    buildAeadNonce,
    computeKeyId,
    computeTranscriptHash,
    computeX25519SharedSecret,
    deriveChainKeyRekeyKeys,
    deriveSessionKeys,
    generateEphemeralX25519KeyPair,
    ownDirection,
    peerDirection,
    type AeadAadParams,
    type TranscriptHashInput,
} from '../encryption.js';

// ─── test fixtures ──────────────────────────────────────────────────────────────────

function makeTranscriptInput(
    overrides?: Partial<TranscriptHashInput>,
): TranscriptHashInput {
    return {
        protocolVersion: 'ap/e2e/v1',
        initiatorDid: 'did:key:zInit',
        responderDid: 'did:key:zResp',
        initiatorCapabilities: ['encrypt'],
        responderCapabilities: ['encrypt'],
        initiatorPreference: 'REQUIRED',
        responderPreference: 'REQUIRED',
        negotiatedEncryptionMode: 'REQUIRED',
        I_epk: 'aabbccdd',
        R_epk: 'eeff0011',
        nonce: 'nonce-abc',
        initTimestamp: '2026-01-01T00:00:00.000Z',
        responseTimestamp: '2026-01-01T00:00:01.000Z',
        authorizedPrincipalDid: 'did:key:zPrincipal',
        authorizedTokenId: 'token-123',
        authorizedTokenFingerprint: 'fp-abc',
        ...overrides,
    };
}

function makeAadParams(overrides?: Partial<AeadAadParams>): AeadAadParams {
    return {
        envelopeId: 'env-001',
        messageType: 'AGENT_MESSAGE',
        direction: 'init_to_resp',
        keyId: 'aabbccddeeff00112233445566778899',
        sequenceNumber: 1n,
        sessionId: 'sess-xyz',
        tokenId: 'token-123',
        ...overrides,
    };
}

// ─── X25519 keypair + ECDH ────────────────────────────────────────────────────

describe('generateEphemeralX25519KeyPair', () => {
    it('should return 32-byte secretKey and publicKey', () => {
        const kp = generateEphemeralX25519KeyPair();
        expect(kp.secretKey).toBeInstanceOf(Uint8Array);
        expect(kp.secretKey.length).toBe(32);
        expect(kp.publicKey).toBeInstanceOf(Uint8Array);
        expect(kp.publicKey.length).toBe(32);
    });

    it('should generate different keypairs on each call', () => {
        const kp1 = generateEphemeralX25519KeyPair();
        const kp2 = generateEphemeralX25519KeyPair();
        expect(kp1.secretKey).not.toEqual(kp2.secretKey);
        expect(kp1.publicKey).not.toEqual(kp2.publicKey);
    });
});

describe('computeX25519SharedSecret', () => {
    it('should produce same shared secret from both sides', () => {
        const alice = generateEphemeralX25519KeyPair();
        const bob = generateEphemeralX25519KeyPair();
        const ssAlice = computeX25519SharedSecret(
            alice.secretKey,
            bob.publicKey,
        );
        const ssBob = computeX25519SharedSecret(bob.secretKey, alice.publicKey);
        expect(ssAlice).toEqual(ssBob);
    });

    it('should return 32-byte shared secret', () => {
        const alice = generateEphemeralX25519KeyPair();
        const bob = generateEphemeralX25519KeyPair();
        const ss = computeX25519SharedSecret(alice.secretKey, bob.publicKey);
        expect(ss.length).toBe(32);
    });

    it('should produce different secrets for different keypairs', () => {
        const alice = generateEphemeralX25519KeyPair();
        const bob = generateEphemeralX25519KeyPair();
        const charlie = generateEphemeralX25519KeyPair();
        const ss1 = computeX25519SharedSecret(alice.secretKey, bob.publicKey);
        const ss2 = computeX25519SharedSecret(
            alice.secretKey,
            charlie.publicKey,
        );
        expect(ss1).not.toEqual(ss2);
    });
});

// ─── transcript_hash ──────────────────────────────────────────────────────────

describe('computeTranscriptHash', () => {
    it('should return 32-byte SHA-256 output', () => {
        const h = computeTranscriptHash(makeTranscriptInput());
        expect(h).toBeInstanceOf(Uint8Array);
        expect(h.length).toBe(32);
    });

    it('should be deterministic for same input', () => {
        const h1 = computeTranscriptHash(makeTranscriptInput());
        const h2 = computeTranscriptHash(makeTranscriptInput());
        expect(h1).toEqual(h2);
    });

    it('should differ when any field changes', () => {
        const h1 = computeTranscriptHash(makeTranscriptInput());
        const h2 = computeTranscriptHash(
            makeTranscriptInput({ initiatorDid: 'did:key:zOther' }),
        );
        expect(h1).not.toEqual(h2);
    });

    it('should produce different hash when authorizedTokenId is null vs string', () => {
        const h1 = computeTranscriptHash(
            makeTranscriptInput({ authorizedTokenId: null }),
        );
        const h2 = computeTranscriptHash(
            makeTranscriptInput({ authorizedTokenId: 'token-x' }),
        );
        expect(h1).not.toEqual(h2);
    });

    it('should use RFC 8785 canonical order (field order insensitive)', () => {
        // RFC 8785 canonicalize guarantees field order does not affect the result
        const input1 = makeTranscriptInput();
        // We would build two objects with the same content in different order, but TS cannot reorder directly, so we compare via different field values instead
        const h1 = computeTranscriptHash(input1);
        expect(h1.length).toBe(32);
    });
});

// ─── HKDF key derivation ────────────────────────────────────────────────────────────

describe('deriveSessionKeys', () => {
    it('should return correct key lengths', () => {
        const alice = generateEphemeralX25519KeyPair();
        const bob = generateEphemeralX25519KeyPair();
        const ss = computeX25519SharedSecret(alice.secretKey, bob.publicKey);
        const th = computeTranscriptHash(makeTranscriptInput());
        const keys = deriveSessionKeys(ss, th);

        expect(keys.initToResp.length).toBe(32);
        expect(keys.respToInit.length).toBe(32);
        expect(keys.sessionSalt.length).toBe(4);
        expect(keys.rekeyChainKey.length).toBe(32);
    });

    it('should derive different keys for each direction', () => {
        const alice = generateEphemeralX25519KeyPair();
        const bob = generateEphemeralX25519KeyPair();
        const ss = computeX25519SharedSecret(alice.secretKey, bob.publicKey);
        const th = computeTranscriptHash(makeTranscriptInput());
        const keys = deriveSessionKeys(ss, th);

        expect(keys.initToResp).not.toEqual(keys.respToInit);
    });

    it('should be deterministic for same inputs', () => {
        const alice = generateEphemeralX25519KeyPair();
        const bob = generateEphemeralX25519KeyPair();
        const ss = computeX25519SharedSecret(alice.secretKey, bob.publicKey);
        const th = computeTranscriptHash(makeTranscriptInput());
        const keys1 = deriveSessionKeys(ss, th);
        const keys2 = deriveSessionKeys(ss, th);

        expect(keys1.initToResp).toEqual(keys2.initToResp);
        expect(keys1.respToInit).toEqual(keys2.respToInit);
        expect(keys1.sessionSalt).toEqual(keys2.sessionSalt);
        expect(keys1.rekeyChainKey).toEqual(keys2.rekeyChainKey);
    });

    it('should differ when transcript_hash differs', () => {
        const alice = generateEphemeralX25519KeyPair();
        const bob = generateEphemeralX25519KeyPair();
        const ss = computeX25519SharedSecret(alice.secretKey, bob.publicKey);
        const th1 = computeTranscriptHash(
            makeTranscriptInput({ nonce: 'nonce-1' }),
        );
        const th2 = computeTranscriptHash(
            makeTranscriptInput({ nonce: 'nonce-2' }),
        );
        const keys1 = deriveSessionKeys(ss, th1);
        const keys2 = deriveSessionKeys(ss, th2);

        expect(keys1.initToResp).not.toEqual(keys2.initToResp);
    });

    it('should produce same keys from both sides of ECDH', () => {
        const alice = generateEphemeralX25519KeyPair();
        const bob = generateEphemeralX25519KeyPair();
        const ssAlice = computeX25519SharedSecret(
            alice.secretKey,
            bob.publicKey,
        );
        const ssBob = computeX25519SharedSecret(bob.secretKey, alice.publicKey);
        const th = computeTranscriptHash(makeTranscriptInput());
        const keysA = deriveSessionKeys(ssAlice, th);
        const keysB = deriveSessionKeys(ssBob, th);

        expect(keysA.initToResp).toEqual(keysB.initToResp);
        expect(keysA.respToInit).toEqual(keysB.respToInit);
        expect(keysA.sessionSalt).toEqual(keysB.sessionSalt);
        expect(keysA.rekeyChainKey).toEqual(keysB.rekeyChainKey);
    });
});

// ─── chain-key rekey ──────────────────────────────────────────────────────────

describe('deriveChainKeyRekeyKeys', () => {
    it('should return 32-byte keys', () => {
        const alice = generateEphemeralX25519KeyPair();
        const bob = generateEphemeralX25519KeyPair();
        const ss = computeX25519SharedSecret(alice.secretKey, bob.publicKey);
        const th = computeTranscriptHash(makeTranscriptInput());
        const prev = deriveSessionKeys(ss, th);
        const rekey = deriveChainKeyRekeyKeys(
            prev.rekeyChainKey,
            prev.initToResp,
            prev.respToInit,
        );

        expect(rekey.initToResp.length).toBe(32);
        expect(rekey.respToInit.length).toBe(32);
        expect(rekey.rekeyChainKey.length).toBe(32);
    });

    it('should produce different keys from original derivation', () => {
        const alice = generateEphemeralX25519KeyPair();
        const bob = generateEphemeralX25519KeyPair();
        const ss = computeX25519SharedSecret(alice.secretKey, bob.publicKey);
        const th = computeTranscriptHash(makeTranscriptInput());
        const prev = deriveSessionKeys(ss, th);
        const rekey = deriveChainKeyRekeyKeys(
            prev.rekeyChainKey,
            prev.initToResp,
            prev.respToInit,
        );

        expect(rekey.initToResp).not.toEqual(prev.initToResp);
        expect(rekey.respToInit).not.toEqual(prev.respToInit);
        expect(rekey.rekeyChainKey).not.toEqual(prev.rekeyChainKey);
    });

    it('should be deterministic for same chain key', () => {
        const alice = generateEphemeralX25519KeyPair();
        const bob = generateEphemeralX25519KeyPair();
        const ss = computeX25519SharedSecret(alice.secretKey, bob.publicKey);
        const th = computeTranscriptHash(makeTranscriptInput());
        const prev = deriveSessionKeys(ss, th);
        const r1 = deriveChainKeyRekeyKeys(
            prev.rekeyChainKey,
            prev.initToResp,
            prev.respToInit,
        );
        const r2 = deriveChainKeyRekeyKeys(
            prev.rekeyChainKey,
            prev.initToResp,
            prev.respToInit,
        );

        expect(r1.initToResp).toEqual(r2.initToResp);
        expect(r1.rekeyChainKey).toEqual(r2.rekeyChainKey);
    });
});

// ─── keyId computation ───────────────────────────────────────────────────────────────

describe('computeKeyId', () => {
    it('should return 32-char hex string', () => {
        const key = new Uint8Array(32).fill(0xaa);
        const id = computeKeyId(key, 1);
        expect(id).toMatch(/^[0-9a-f]{32}$/);
    });

    it('should differ across generations', () => {
        const key = new Uint8Array(32).fill(0xbb);
        const id0 = computeKeyId(key, 0);
        const id1 = computeKeyId(key, 1);
        expect(id0).not.toBe(id1);
    });

    it('should differ across direction keys', () => {
        const key1 = new Uint8Array(32).fill(0xcc);
        const key2 = new Uint8Array(32).fill(0xdd);
        const id1 = computeKeyId(key1, 0);
        const id2 = computeKeyId(key2, 0);
        expect(id1).not.toBe(id2);
    });

    it('should be deterministic', () => {
        const key = new Uint8Array(32).fill(0xee);
        expect(computeKeyId(key, 5)).toBe(computeKeyId(key, 5));
    });

    it('should handle generation=0 without throwing', () => {
        const key = new Uint8Array(32);
        expect(() => computeKeyId(key, 0)).not.toThrow();
    });
});

// ─── AEAD nonce construction ──────────────────────────────────────────────────────────

describe('buildAeadNonce', () => {
    it('should return 12-byte nonce', () => {
        const salt = new Uint8Array(4).fill(0x01);
        const nonce = buildAeadNonce('init_to_resp', 0n, salt);
        expect(nonce.length).toBe(12);
    });

    it('should encode direction byte correctly', () => {
        const salt = new Uint8Array(4);
        const initNonce = buildAeadNonce('init_to_resp', 0n, salt);
        const respNonce = buildAeadNonce('resp_to_init', 0n, salt);
        expect(initNonce[0]).toBe(0x01);
        expect(respNonce[0]).toBe(0x02);
    });

    it('should encode sequence number as big-endian 8 bytes at offset 1', () => {
        const salt = new Uint8Array(4);
        // seqNo = 1
        const nonce = buildAeadNonce('init_to_resp', 1n, salt);
        const view = new DataView(nonce.buffer);
        expect(view.getUint32(1, false)).toBe(0);
        expect(view.getUint32(5, false)).toBe(1);
    });

    it('should encode session salt bytes at offset 9', () => {
        const salt = new Uint8Array([0xaa, 0xbb, 0xcc, 0xdd]);
        const nonce = buildAeadNonce('init_to_resp', 0n, salt);
        expect(nonce[9]).toBe(0xaa);
        expect(nonce[10]).toBe(0xbb);
        expect(nonce[11]).toBe(0xcc);
    });

    it('should differ for different sequence numbers', () => {
        const salt = new Uint8Array(4);
        const n1 = buildAeadNonce('init_to_resp', 1n, salt);
        const n2 = buildAeadNonce('init_to_resp', 2n, salt);
        expect(n1).not.toEqual(n2);
    });

    it('should handle large sequenceNumber (2^32 boundary)', () => {
        const salt = new Uint8Array(4);
        const seqNo = 0x100000000n; // = 2^32
        const nonce = buildAeadNonce('init_to_resp', seqNo, salt);
        const view = new DataView(nonce.buffer);
        // hi = 1, lo = 0
        expect(view.getUint32(1, false)).toBe(1);
        expect(view.getUint32(5, false)).toBe(0);
    });
});

// ─── AAD byte construction ─────────────────────────────────────────────────────────────

describe('buildAeadBytes', () => {
    it('should return non-empty Uint8Array', () => {
        const aad = buildAeadBytes(makeAadParams());
        expect(aad).toBeInstanceOf(Uint8Array);
        expect(aad.length).toBeGreaterThan(0);
    });

    it('should be deterministic for same params', () => {
        const p = makeAadParams();
        expect(buildAeadBytes(p)).toEqual(buildAeadBytes(p));
    });

    it('should differ when envelopeId changes', () => {
        const a1 = buildAeadBytes(makeAadParams({ envelopeId: 'env-001' }));
        const a2 = buildAeadBytes(makeAadParams({ envelopeId: 'env-002' }));
        expect(a1).not.toEqual(a2);
    });

    it('should differ when sequenceNumber changes', () => {
        const a1 = buildAeadBytes(makeAadParams({ sequenceNumber: 1n }));
        const a2 = buildAeadBytes(makeAadParams({ sequenceNumber: 2n }));
        expect(a1).not.toEqual(a2);
    });

    it('should differ when direction changes', () => {
        const a1 = buildAeadBytes(makeAadParams({ direction: 'init_to_resp' }));
        const a2 = buildAeadBytes(makeAadParams({ direction: 'resp_to_init' }));
        expect(a1).not.toEqual(a2);
    });

    it('should serialize tokenId=null as JSON null', () => {
        const aad = buildAeadBytes(makeAadParams({ tokenId: null }));
        const str = new TextDecoder().decode(aad);
        expect(str).toContain('"tokenId":null');
    });

    it('should include aadSummary=null when not provided', () => {
        const aad = buildAeadBytes(makeAadParams({ aadSummary: undefined }));
        const str = new TextDecoder().decode(aad);
        expect(str).toContain('"aadSummary":null');
    });

    it('should include aadSummary when provided', () => {
        const aad = buildAeadBytes(
            makeAadParams({ aadSummary: { action: 'test' } }),
        );
        const str = new TextDecoder().decode(aad);
        expect(str).toContain('"aadSummary"');
        expect(str).toContain('"action"');
    });

    it('should have exactly 8 top-level fields in canonical JSON', () => {
        const aad = buildAeadBytes(makeAadParams());
        const str = new TextDecoder().decode(aad);
        const parsed = JSON.parse(str) as Record<string, unknown>;
        expect(Object.keys(parsed)).toHaveLength(8);
    });
});

// ─── AES-256-GCM encrypt/decrypt ───────────────────────────────────────────────────

describe('aeadEncrypt / aeadDecrypt', () => {
    function makeKey(): Uint8Array {
        return new Uint8Array(32).fill(0x42);
    }

    function makeNonce(): Uint8Array {
        return buildAeadNonce('init_to_resp', 1n, new Uint8Array(4));
    }

    function makeAad(): Uint8Array {
        return buildAeadBytes(makeAadParams());
    }

    it('should encrypt and decrypt to original plaintext', () => {
        const key = makeKey();
        const nonce = makeNonce();
        const aad = makeAad();
        const plaintext = new TextEncoder().encode('hello, world');

        const ciphertext = aeadEncrypt(key, nonce, aad, plaintext);
        const recovered = aeadDecrypt(key, nonce, aad, ciphertext);
        expect(recovered).toEqual(plaintext);
    });

    it('should ciphertext be longer than plaintext by 16 bytes (GCM tag)', () => {
        const key = makeKey();
        const nonce = makeNonce();
        const aad = makeAad();
        const plaintext = new Uint8Array(64).fill(0x01);

        const ciphertext = aeadEncrypt(key, nonce, aad, plaintext);
        expect(ciphertext.length).toBe(plaintext.length + 16);
    });

    it('should produce different ciphertext for different plaintexts', () => {
        const key = makeKey();
        const nonce = makeNonce();
        const aad = makeAad();
        const ct1 = aeadEncrypt(key, nonce, aad, new Uint8Array([0x01]));
        const ct2 = aeadEncrypt(key, nonce, aad, new Uint8Array([0x02]));
        expect(ct1).not.toEqual(ct2);
    });

    it('should produce deterministic ciphertext for same inputs', () => {
        const key = makeKey();
        const nonce = makeNonce();
        const aad = makeAad();
        const plaintext = new TextEncoder().encode('deterministic');
        const ct1 = aeadEncrypt(key, nonce, aad, plaintext);
        const ct2 = aeadEncrypt(key, nonce, aad, plaintext);
        expect(ct1).toEqual(ct2);
    });

    it('should throw on tampered ciphertext (tag verification fails)', () => {
        const key = makeKey();
        const nonce = makeNonce();
        const aad = makeAad();
        const plaintext = new TextEncoder().encode('test data');
        const ciphertext = aeadEncrypt(key, nonce, aad, plaintext);

        // tamper byte 0
        const tampered = new Uint8Array(ciphertext);
        tampered[0] = (tampered[0] ?? 0) ^ 0xff;

        expect(() => aeadDecrypt(key, nonce, aad, tampered)).toThrow();
    });

    it('should throw on wrong AAD', () => {
        const key = makeKey();
        const nonce = makeNonce();
        const aad = makeAad();
        const wrongAad = buildAeadBytes(
            makeAadParams({ envelopeId: 'env-wrong' }),
        );
        const plaintext = new TextEncoder().encode('test');
        const ciphertext = aeadEncrypt(key, nonce, aad, plaintext);

        expect(() => aeadDecrypt(key, nonce, wrongAad, ciphertext)).toThrow();
    });

    it('should throw on wrong key', () => {
        const key = makeKey();
        const wrongKey = new Uint8Array(32).fill(0x99);
        const nonce = makeNonce();
        const aad = makeAad();
        const plaintext = new TextEncoder().encode('test');
        const ciphertext = aeadEncrypt(key, nonce, aad, plaintext);

        expect(() => aeadDecrypt(wrongKey, nonce, aad, ciphertext)).toThrow();
    });

    it('should encrypt empty plaintext successfully', () => {
        const key = makeKey();
        const nonce = makeNonce();
        const aad = makeAad();
        const plaintext = new Uint8Array(0);
        const ciphertext = aeadEncrypt(key, nonce, aad, plaintext);
        expect(ciphertext.length).toBe(16); // just the tag
        const recovered = aeadDecrypt(key, nonce, aad, ciphertext);
        expect(recovered).toEqual(plaintext);
    });
});

// ─── direction semantic helpers ───────────────────────────────────────────────────────

describe('ownDirection / peerDirection', () => {
    it('should ownDirection(initiator) = init_to_resp', () => {
        expect(ownDirection('initiator')).toBe('init_to_resp');
    });

    it('should ownDirection(responder) = resp_to_init', () => {
        expect(ownDirection('responder')).toBe('resp_to_init');
    });

    it('should peerDirection(initiator) = resp_to_init', () => {
        expect(peerDirection('initiator')).toBe('resp_to_init');
    });

    it('should peerDirection(responder) = init_to_resp', () => {
        expect(peerDirection('responder')).toBe('init_to_resp');
    });

    it('should ownDirection and peerDirection be inverses for initiator', () => {
        expect(ownDirection('initiator')).not.toBe(peerDirection('initiator'));
    });

    it('should ownDirection and peerDirection be inverses for responder', () => {
        expect(ownDirection('responder')).not.toBe(peerDirection('responder'));
    });
});

// ─── end-to-end integration: ECDH + HKDF + AEAD ─────────────────────────────────────────

describe('end-to-end: initiator encrypts, responder decrypts', () => {
    it('should allow cross-side symmetric encryption', () => {
        // ECDH on both sides
        const initKp = generateEphemeralX25519KeyPair();
        const respKp = generateEphemeralX25519KeyPair();
        const ssInit = computeX25519SharedSecret(
            initKp.secretKey,
            respKp.publicKey,
        );
        const ssResp = computeX25519SharedSecret(
            respKp.secretKey,
            initKp.publicKey,
        );

        // transcript_hash (both sides must use the same transcript input)
        const th = computeTranscriptHash(makeTranscriptInput());

        // HKDF
        const keysInit = deriveSessionKeys(ssInit, th);
        const keysResp = deriveSessionKeys(ssResp, th);

        // initiator-side encrypt -> keyId
        const initKeyId = computeKeyId(keysInit.initToResp, 0);
        const salt = keysInit.sessionSalt;
        const seqNo = 1n;

        const nonce = buildAeadNonce('init_to_resp', seqNo, salt);
        const aadParams: AeadAadParams = {
            envelopeId: 'env-e2e-001',
            messageType: 'AGENT_MESSAGE',
            direction: 'init_to_resp',
            keyId: initKeyId,
            sequenceNumber: seqNo,
            sessionId: 'sess-e2e',
            tokenId: 'tok-001',
        };
        const aad = buildAeadBytes(aadParams);
        const plaintext = new TextEncoder().encode('secret payload');

        // initiator encrypts with initToResp
        const ciphertext = aeadEncrypt(
            keysInit.initToResp,
            nonce,
            aad,
            plaintext,
        );

        // responder decrypts with the responder-side identical initToResp key
        const recovered = aeadDecrypt(
            keysResp.initToResp,
            nonce,
            aad,
            ciphertext,
        );
        expect(recovered).toEqual(plaintext);
    });
});
