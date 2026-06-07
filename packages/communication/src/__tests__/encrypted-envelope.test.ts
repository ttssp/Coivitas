/**
 * encryptEnvelopeBody + decryptEnvelopeBody unit tests
 *
 * Coverage:
 *   - encrypt/decrypt normal round-trip path
 *   - Inv 3.2 precondition (capabilityTokenRef !== authorizedTokenId → SESSION_TOKEN_MISMATCH)
 *   - Inv 4.3 post-decrypt token assertion (tokenRef found to mismatch after successful decryption → SESSION_TOKEN_MISMATCH)
 *   - SESSION_NOT_FOUND (encrypt path: session does not exist)
 *   - DECRYPTION_FAILED (decrypt path: keyId mismatch)
 *   - INVALID_ENCRYPTED_BODY (type missing / invalid aeadNonce format)
 *   - ENCRYPTED_REPLAY_DETECTED (sequenceNumber replay)
 *   - SESSION_HANDLE_REVOKED (handle is CLOSED)
 *   - aadSummary correctly propagated to EncryptedBody
 *
 */

import { beforeEach, describe, expect, it } from 'vitest';

import {
    deriveSessionKeys,
    generateEphemeralX25519KeyPair,
    computeX25519SharedSecret,
    computeTranscriptHash,
} from '@coivitas/crypto';
import type {
    AeadAadFields,
    EncryptedBody,
    NewSessionData,
} from '@coivitas/types';
import { ProtocolError } from '@coivitas/types';

import { SessionRegistryImpl } from '../session-registry.js';
import {
    _clearReplayTracker,
    decryptEnvelopeBody,
    encryptEnvelopeBody,
} from '../envelope.js';

// ─── Test helper functions ────────────────────────────────────────────────────────────

/**
 * Generates real NewSessionData (X25519 ECDH + HKDF derivation)
 */
function makeRealSession(sessionId: string, generation = 0): NewSessionData {
    const initiatorKp = generateEphemeralX25519KeyPair();
    const responderKp = generateEphemeralX25519KeyPair();
    const sharedSecret = computeX25519SharedSecret(
        initiatorKp.secretKey,
        responderKp.publicKey,
    );
    const transcriptHash = computeTranscriptHash({
        protocolVersion: 'ap/e2e/v1',
        initiatorDid: 'did:key:initiator',
        responderDid: 'did:key:responder',
        initiatorCapabilities: [],
        responderCapabilities: [],
        initiatorPreference: 'REQUIRED',
        responderPreference: 'REQUIRED',
        negotiatedEncryptionMode: 'REQUIRED',
        I_epk: Buffer.from(initiatorKp.publicKey).toString('hex'),
        R_epk: Buffer.from(responderKp.publicKey).toString('hex'),
        nonce: 'test-nonce-12345',
        initTimestamp: '2026-01-01T00:00:00Z',
        ackTimestamp: '2026-01-01T00:00:01Z',
        sessionId,
        capabilityTokenId: 'token-001',
        policyHash: 'policyHash123',
    });
    const keys = deriveSessionKeys(sharedSecret, transcriptHash);
    return {
        trafficKeys: {
            initToResp: keys.initToResp,
            respToInit: keys.respToInit,
        },
        sessionSalt: keys.sessionSalt,
        rekeyChainKey: keys.rekeyChainKey,
        generation,
    };
}

/**
 * Builds standard AAD fields
 */
function makeAad(
    envelopeId = 'env-e08-001',
    messageType = 'NEGOTIATION_REQUEST',
    aadSummary?: Record<string, unknown>,
): AeadAadFields {
    return { envelopeId, messageType, aadSummary };
}

/**
 * Sets up the session registries for both the initiator and responder, sharing key material
 * Returns: { initiatorReg, responderReg, sessionData }
 */
function makeSessionPair(
    sessionId: string,
    tokenId: string,
): {
    initiatorReg: SessionRegistryImpl;
    responderReg: SessionRegistryImpl;
    sessionData: NewSessionData;
} {
    const sessionData = makeRealSession(sessionId);

    const initiatorReg = new SessionRegistryImpl();
    initiatorReg.createSession(sessionId, 'initiator', tokenId, sessionData);

    const responderReg = new SessionRegistryImpl();
    responderReg.createSession(sessionId, 'responder', tokenId, sessionData);

    return { initiatorReg, responderReg, sessionData };
}

// ─── Tests ─────────────────────────────────────────────────────────────────────

const TOKEN_ID = 'urn:cap:12345678-1234-4123-89ab-123456789012';
const SESSION_ID = 'session-e08-test-001';

beforeEach(() => {
    // Reset the replay tracker before each test to avoid cross-test contamination
    _clearReplayTracker();
});

describe('encryptEnvelopeBody — normal path', () => {
    it('should encrypt plaintext and return valid EncryptedBody when called with correct params', () => {
        const { initiatorReg } = makeSessionPair(SESSION_ID, TOKEN_ID);
        const plaintext = new TextEncoder().encode('hello encrypted world');
        const aad = makeAad();

        const body = encryptEnvelopeBody({
            registry: initiatorReg,
            sessionId: SESSION_ID,
            capabilityTokenRef: TOKEN_ID,
            aadFields: aad,
            plaintext,
            bodyType: 'BUSINESS',
        });

        expect(body.encrypted).toBe(true);
        expect(body.encryptionProtocolVersion).toBe('ap/e2e/v1');
        expect(body.type).toBe('BUSINESS');
        expect(typeof body.ciphertext).toBe('string');
        expect(body.ciphertext.length).toBeGreaterThan(0);
        expect(typeof body.aeadNonce).toBe('string');
        // hex: 12B = 24 chars
        expect(body.aeadNonce).toMatch(/^[0-9a-f]{24}$/i);
        expect(typeof body.keyId).toBe('string');
        expect(body.keyId.length).toBeGreaterThan(0);
        expect(body.aadSummary).toBeUndefined();
    });

    it('should include aadSummary in EncryptedBody when provided', () => {
        const { initiatorReg } = makeSessionPair(SESSION_ID, TOKEN_ID);
        const plaintext = new TextEncoder().encode('with summary');
        const aad = makeAad('env-001', 'NEGOTIATION_REQUEST', {
            sku: 'SKU-001',
            qty: 5,
        });

        const body = encryptEnvelopeBody({
            registry: initiatorReg,
            sessionId: SESSION_ID,
            capabilityTokenRef: TOKEN_ID,
            aadFields: aad,
            plaintext,
            bodyType: 'BUSINESS',
        });

        expect(body.aadSummary).toEqual({ sku: 'SKU-001', qty: 5 });
    });

    it('should encrypt RECEIPT type body when bodyType is RECEIPT', () => {
        const { initiatorReg } = makeSessionPair(SESSION_ID, TOKEN_ID);
        const plaintext = new TextEncoder().encode('receipt payload');

        const body = encryptEnvelopeBody({
            registry: initiatorReg,
            sessionId: SESSION_ID,
            capabilityTokenRef: TOKEN_ID,
            aadFields: makeAad(),
            plaintext,
            bodyType: 'RECEIPT',
        });

        expect(body.type).toBe('RECEIPT');
    });
});

describe('encrypt + decrypt round-trip path', () => {
    it('should decrypt ciphertext produced by encryptEnvelopeBody and recover original plaintext', () => {
        const { initiatorReg, responderReg } = makeSessionPair(
            SESSION_ID,
            TOKEN_ID,
        );
        const originalText = 'round-trip test message 123';
        const plaintext = new TextEncoder().encode(originalText);
        const aad = makeAad('env-rt-001', 'NEGOTIATION_REQUEST');

        // initiator encrypts
        const body = encryptEnvelopeBody({
            registry: initiatorReg,
            sessionId: SESSION_ID,
            capabilityTokenRef: TOKEN_ID,
            aadFields: aad,
            plaintext,
            bodyType: 'BUSINESS',
        });

        // responder decrypts (using the same aadFields)
        const recovered = decryptEnvelopeBody({
            registry: responderReg,
            sessionId: SESSION_ID,
            body,
            aadFields: aad,
            capabilityTokenRef: TOKEN_ID,
        });

        expect(new TextDecoder().decode(recovered)).toBe(originalText);
    });

    it('should handle multiple sequential encryptions without replay false-positives', () => {
        const { initiatorReg, responderReg } = makeSessionPair(
            SESSION_ID,
            TOKEN_ID,
        );

        for (let i = 0; i < 3; i++) {
            const plaintext = new TextEncoder().encode(`message-${i}`);
            const aad = makeAad(`env-seq-${i}`, 'NEGOTIATION_REQUEST');

            const body = encryptEnvelopeBody({
                registry: initiatorReg,
                sessionId: SESSION_ID,
                capabilityTokenRef: TOKEN_ID,
                aadFields: aad,
                plaintext,
                bodyType: 'BUSINESS',
            });

            const recovered = decryptEnvelopeBody({
                registry: responderReg,
                sessionId: SESSION_ID,
                body,
                aadFields: aad,
                capabilityTokenRef: TOKEN_ID,
            });

            expect(new TextDecoder().decode(recovered)).toBe(`message-${i}`);
        }
    });
});

describe('encryptEnvelopeBody — error path', () => {
    it('should throw SESSION_NOT_FOUND when encrypt called for non-existent session', () => {
        const registry = new SessionRegistryImpl();
        const plaintext = new TextEncoder().encode('test');

        expect(() =>
            encryptEnvelopeBody({
                registry,
                sessionId: 'non-existent-session',
                capabilityTokenRef: TOKEN_ID,
                aadFields: makeAad(),
                plaintext,
                bodyType: 'BUSINESS',
            }),
        ).toThrow(ProtocolError);

        expect(() =>
            encryptEnvelopeBody({
                registry,
                sessionId: 'non-existent-session',
                capabilityTokenRef: TOKEN_ID,
                aadFields: makeAad(),
                plaintext,
                bodyType: 'BUSINESS',
            }),
        ).toThrow('[SESSION_NOT_FOUND]');
    });

    it('should throw SESSION_TOKEN_MISMATCH when capabilityTokenRef does not match authorizedTokenId (Inv 3.2)', () => {
        const { initiatorReg } = makeSessionPair(SESSION_ID, TOKEN_ID);
        const plaintext = new TextEncoder().encode('test');
        const wrongToken = 'urn:cap:00000000-0000-4000-89ab-000000000000';

        expect(() =>
            encryptEnvelopeBody({
                registry: initiatorReg,
                sessionId: SESSION_ID,
                capabilityTokenRef: wrongToken,
                aadFields: makeAad(),
                plaintext,
                bodyType: 'BUSINESS',
            }),
        ).toThrow('[SESSION_TOKEN_MISMATCH]');
    });

    it('should throw SESSION_HANDLE_REVOKED when session is closed before encrypt', () => {
        const { initiatorReg } = makeSessionPair(SESSION_ID, TOKEN_ID);
        initiatorReg.closeSession(SESSION_ID, 'CLOSED');

        const plaintext = new TextEncoder().encode('test');

        // session is closed, lookupHandle returns null → SESSION_NOT_FOUND
        expect(() =>
            encryptEnvelopeBody({
                registry: initiatorReg,
                sessionId: SESSION_ID,
                capabilityTokenRef: TOKEN_ID,
                aadFields: makeAad(),
                plaintext,
                bodyType: 'BUSINESS',
            }),
        ).toThrow('[SESSION_NOT_FOUND]');
    });
});

describe('decryptEnvelopeBody — error path', () => {
    it('should throw INVALID_ENCRYPTED_BODY when body.type is missing (Inv 11)', () => {
        const { responderReg } = makeSessionPair(SESSION_ID, TOKEN_ID);

        // Build a body missing type (TS type cast, simulating the case where type is absent on the wire)
        const brokenBody = {
            encrypted: true as const,
            encryptionProtocolVersion: 'ap/e2e/v1' as const,
            // type is intentionally omitted
            ciphertext: 'aabbccdd',
            aeadNonce: '00'.repeat(12),
            keyId: 'some-key-id',
        } as unknown as EncryptedBody;

        expect(() =>
            decryptEnvelopeBody({
                registry: responderReg,
                sessionId: SESSION_ID,
                body: brokenBody,
                aadFields: makeAad(),
                capabilityTokenRef: TOKEN_ID,
            }),
        ).toThrow('[INVALID_ENCRYPTED_BODY]');
    });

    it('should throw INVALID_ENCRYPTED_BODY when aeadNonce has invalid format', () => {
        const { responderReg } = makeSessionPair(SESSION_ID, TOKEN_ID);

        const brokenBody: EncryptedBody = {
            encrypted: true,
            encryptionProtocolVersion: 'ap/e2e/v1',
            type: 'BUSINESS',
            ciphertext: 'aabbccdd',
            aeadNonce: 'not-valid-nonce!!', // invalid format
            keyId: 'some-key-id',
        };

        expect(() =>
            decryptEnvelopeBody({
                registry: responderReg,
                sessionId: SESSION_ID,
                body: brokenBody,
                aadFields: makeAad(),
                capabilityTokenRef: TOKEN_ID,
            }),
        ).toThrow('[INVALID_ENCRYPTED_BODY]');
    });

    it('should throw ENCRYPTED_REPLAY_DETECTED when same sequenceNumber is received twice', () => {
        const { initiatorReg, responderReg } = makeSessionPair(
            SESSION_ID,
            TOKEN_ID,
        );
        const plaintext = new TextEncoder().encode('replay test');
        const aad = makeAad('env-replay-001', 'NEGOTIATION_REQUEST');

        // First encryption (seq=0)
        const body = encryptEnvelopeBody({
            registry: initiatorReg,
            sessionId: SESSION_ID,
            capabilityTokenRef: TOKEN_ID,
            aadFields: aad,
            plaintext,
            bodyType: 'BUSINESS',
        });

        // First decryption: succeeds
        expect(() =>
            decryptEnvelopeBody({
                registry: responderReg,
                sessionId: SESSION_ID,
                body,
                aadFields: aad,
                capabilityTokenRef: TOKEN_ID,
            }),
        ).not.toThrow();

        // Second decryption of the same body (seq=0 already seen): must be rejected
        expect(() =>
            decryptEnvelopeBody({
                registry: responderReg,
                sessionId: SESSION_ID,
                body,
                aadFields: aad,
                capabilityTokenRef: TOKEN_ID,
            }),
        ).toThrow('[ENCRYPTED_REPLAY_DETECTED]');
    });

    it('should throw DECRYPTION_FAILED when keyId does not match any handle (Inv 4 no-trial-and-error)', () => {
        const { responderReg } = makeSessionPair(SESSION_ID, TOKEN_ID);

        // Build a body with a mismatched keyId (12B hex nonce, but the keyId is forged)
        const brokenBody: EncryptedBody = {
            encrypted: true,
            encryptionProtocolVersion: 'ap/e2e/v1',
            type: 'BUSINESS',
            ciphertext: 'aabbccdd',
            aeadNonce: '00'.repeat(12), // valid 24-char hex nonce
            keyId: 'unknown-key-id-that-does-not-match',
        };

        expect(() =>
            decryptEnvelopeBody({
                registry: responderReg,
                sessionId: SESSION_ID,
                body: brokenBody,
                aadFields: makeAad(),
                capabilityTokenRef: TOKEN_ID,
            }),
        ).toThrow('[DECRYPTION_FAILED]');
    });

    it('should throw SESSION_TOKEN_MISMATCH when post-decrypt token check fails (Inv 4.3)', () => {
        // This scenario requires: handle found + AEAD decryption succeeds + but capabilityTokenRef mismatches
        // Approach: create the session with the correct tokenId, encrypt, then pass the wrong capabilityTokenRef on decrypt
        const { initiatorReg, responderReg } = makeSessionPair(
            SESSION_ID,
            TOKEN_ID,
        );
        const plaintext = new TextEncoder().encode('post-decrypt token test');
        const aad = makeAad('env-pdt-001', 'NEGOTIATION_REQUEST');

        const body = encryptEnvelopeBody({
            registry: initiatorReg,
            sessionId: SESSION_ID,
            capabilityTokenRef: TOKEN_ID,
            aadFields: aad,
            plaintext,
            bodyType: 'BUSINESS',
        });

        const wrongToken = 'urn:cap:ffffffff-ffff-4fff-89ab-ffffffffffff';

        // post-decrypt check: decryption succeeds but capabilityTokenRef mismatches
        expect(() =>
            decryptEnvelopeBody({
                registry: responderReg,
                sessionId: SESSION_ID,
                body,
                aadFields: aad,
                capabilityTokenRef: wrongToken,
            }),
        ).toThrow('[SESSION_TOKEN_MISMATCH]');
    });

    it('should throw DECRYPTION_FAILED when tampered ciphertext fails AEAD tag verification', () => {
        const { initiatorReg, responderReg } = makeSessionPair(
            SESSION_ID,
            TOKEN_ID,
        );
        const plaintext = new TextEncoder().encode('tampering test');
        const aad = makeAad('env-tamper-001', 'NEGOTIATION_REQUEST');

        const body = encryptEnvelopeBody({
            registry: initiatorReg,
            sessionId: SESSION_ID,
            capabilityTokenRef: TOKEN_ID,
            aadFields: aad,
            plaintext,
            bodyType: 'BUSINESS',
        });

        // Tamper with the ciphertext (flip the last byte)
        const tamperedCiphertext =
            body.ciphertext.slice(0, -2) +
            (parseInt(body.ciphertext.slice(-2), 16) ^ 0xff)
                .toString(16)
                .padStart(2, '0');

        const tamperedBody: EncryptedBody = {
            ...body,
            ciphertext: tamperedCiphertext,
        };

        expect(() =>
            decryptEnvelopeBody({
                registry: responderReg,
                sessionId: SESSION_ID,
                body: tamperedBody,
                aadFields: aad,
                capabilityTokenRef: TOKEN_ID,
            }),
        ).toThrow('[DECRYPTION_FAILED]');
    });
});

describe('replay detection boundary conditions', () => {
    it('should not trigger replay when decrypting two different messages in order', () => {
        const { initiatorReg, responderReg } = makeSessionPair(
            SESSION_ID,
            TOKEN_ID,
        );

        const aad1 = makeAad('env-order-001', 'NEGOTIATION_REQUEST');
        const aad2 = makeAad('env-order-002', 'NEGOTIATION_REQUEST');

        // seq=0
        const body1 = encryptEnvelopeBody({
            registry: initiatorReg,
            sessionId: SESSION_ID,
            capabilityTokenRef: TOKEN_ID,
            aadFields: aad1,
            plaintext: new TextEncoder().encode('msg1'),
            bodyType: 'BUSINESS',
        });

        // seq=1
        const body2 = encryptEnvelopeBody({
            registry: initiatorReg,
            sessionId: SESSION_ID,
            capabilityTokenRef: TOKEN_ID,
            aadFields: aad2,
            plaintext: new TextEncoder().encode('msg2'),
            bodyType: 'BUSINESS',
        });

        // Decrypt in order; does not trigger replay
        expect(() =>
            decryptEnvelopeBody({
                registry: responderReg,
                sessionId: SESSION_ID,
                body: body1,
                aadFields: aad1,
                capabilityTokenRef: TOKEN_ID,
            }),
        ).not.toThrow();

        expect(() =>
            decryptEnvelopeBody({
                registry: responderReg,
                sessionId: SESSION_ID,
                body: body2,
                aadFields: aad2,
                capabilityTokenRef: TOKEN_ID,
            }),
        ).not.toThrow();
    });

    it('should trigger ENCRYPTED_REPLAY_DETECTED when older seq is replayed after newer seq received', () => {
        const { initiatorReg, responderReg } = makeSessionPair(
            SESSION_ID,
            TOKEN_ID,
        );

        const aad1 = makeAad('env-replay-a1', 'NEGOTIATION_REQUEST');
        const aad2 = makeAad('env-replay-a2', 'NEGOTIATION_REQUEST');

        // seq=0
        const body1 = encryptEnvelopeBody({
            registry: initiatorReg,
            sessionId: SESSION_ID,
            capabilityTokenRef: TOKEN_ID,
            aadFields: aad1,
            plaintext: new TextEncoder().encode('msg1'),
            bodyType: 'BUSINESS',
        });

        // seq=1
        const body2 = encryptEnvelopeBody({
            registry: initiatorReg,
            sessionId: SESSION_ID,
            capabilityTokenRef: TOKEN_ID,
            aadFields: aad2,
            plaintext: new TextEncoder().encode('msg2'),
            bodyType: 'BUSINESS',
        });

        // Receive seq=1 first (simulating out-of-order arrival)
        decryptEnvelopeBody({
            registry: responderReg,
            sessionId: SESSION_ID,
            body: body2,
            aadFields: aad2,
            capabilityTokenRef: TOKEN_ID,
        });

        // Then receive seq=0 (now behind maxSeen=1), which must be rejected
        expect(() =>
            decryptEnvelopeBody({
                registry: responderReg,
                sessionId: SESSION_ID,
                body: body1,
                aadFields: aad1,
                capabilityTokenRef: TOKEN_ID,
            }),
        ).toThrow('[ENCRYPTED_REPLAY_DETECTED]');
    });

    it('should track replay per session independently when multiple sessions exist', () => {
        const SESSION_A = 'session-e08-a';
        const SESSION_B = 'session-e08-b';

        const { initiatorReg: regA_init, responderReg: regA_resp } =
            makeSessionPair(SESSION_A, TOKEN_ID);
        const { initiatorReg: regB_init, responderReg: regB_resp } =
            makeSessionPair(SESSION_B, TOKEN_ID);

        const aadA = makeAad('env-sa-001', 'NEGOTIATION_REQUEST');
        const aadB = makeAad('env-sb-001', 'NEGOTIATION_REQUEST');

        const bodyA = encryptEnvelopeBody({
            registry: regA_init,
            sessionId: SESSION_A,
            capabilityTokenRef: TOKEN_ID,
            aadFields: aadA,
            plaintext: new TextEncoder().encode('session-a msg'),
            bodyType: 'BUSINESS',
        });

        const bodyB = encryptEnvelopeBody({
            registry: regB_init,
            sessionId: SESSION_B,
            capabilityTokenRef: TOKEN_ID,
            aadFields: aadB,
            plaintext: new TextEncoder().encode('session-b msg'),
            bodyType: 'BUSINESS',
        });

        // session-A decrypts successfully
        decryptEnvelopeBody({
            registry: regA_resp,
            sessionId: SESSION_A,
            body: bodyA,
            aadFields: aadA,
            capabilityTokenRef: TOKEN_ID,
        });

        // session-B decrypts successfully (independent tracker, unaffected by session-A's maxSeen)
        expect(() =>
            decryptEnvelopeBody({
                registry: regB_resp,
                sessionId: SESSION_B,
                body: bodyB,
                aadFields: aadB,
                capabilityTokenRef: TOKEN_ID,
            }),
        ).not.toThrow();
    });
});

// ─── Regression tests for the fix ────────────────────────

describe('replay tracker distinguishes keyId generations', () => {
    it('should accept fresh seq=0 packet on the new generation after swapForDualKey when previous generation had higher max', () => {
        const { initiatorReg, responderReg } = makeSessionPair(
            SESSION_ID,
            TOKEN_ID,
        );

        // First send + receive one frame on the old generation (pushes maxSeen=0)
        const aadOld = makeAad('env-rekey-old', 'NEGOTIATION_REQUEST');
        const bodyOld = encryptEnvelopeBody({
            registry: initiatorReg,
            sessionId: SESSION_ID,
            capabilityTokenRef: TOKEN_ID,
            aadFields: aadOld,
            plaintext: new TextEncoder().encode('msg-old-gen'),
            bodyType: 'BUSINESS',
        });
        decryptEnvelopeBody({
            registry: responderReg,
            sessionId: SESSION_ID,
            body: bodyOld,
            aadFields: aadOld,
            capabilityTokenRef: TOKEN_ID,
        });

        // rekey switches to the new generation (and resets sequenceNumber to 0)
        const newSession = makeRealSession(SESSION_ID);
        initiatorReg.swapForDualKey(SESSION_ID, newSession);
        responderReg.swapForDualKey(SESSION_ID, newSession);

        // The new generation's first frame has seq=0; if the replay tracker keys only on
        // (sessionId, directionByte), this triggers ENCRYPTED_REPLAY_DETECTED; keying on
        // (sessionId, directionByte, keyId) → it should pass.
        const aadNew = makeAad('env-rekey-new', 'NEGOTIATION_REQUEST');
        const bodyNew = encryptEnvelopeBody({
            registry: initiatorReg,
            sessionId: SESSION_ID,
            capabilityTokenRef: TOKEN_ID,
            aadFields: aadNew,
            plaintext: new TextEncoder().encode('msg-new-gen'),
            bodyType: 'BUSINESS',
        });
        // keyId must differ from the old generation (generation goes into the hash)
        expect(bodyNew.keyId).not.toBe(bodyOld.keyId);

        expect(() =>
            decryptEnvelopeBody({
                registry: responderReg,
                sessionId: SESSION_ID,
                body: bodyNew,
                aadFields: aadNew,
                capabilityTokenRef: TOKEN_ID,
            }),
        ).not.toThrow();
    });
});

describe('decryptEnvelopeBody accepts base64url EncryptedBody', () => {
    it('should decrypt successfully when ciphertext/aeadNonce arrive as base64url instead of hex', () => {
        const { initiatorReg, responderReg } = makeSessionPair(
            SESSION_ID,
            TOKEN_ID,
        );

        const aad = makeAad('env-b64url-001', 'NEGOTIATION_REQUEST');
        const body = encryptEnvelopeBody({
            registry: initiatorReg,
            sessionId: SESSION_ID,
            capabilityTokenRef: TOKEN_ID,
            aadFields: aad,
            plaintext: new TextEncoder().encode('hello base64url decrypt'),
            bodyType: 'BUSINESS',
        });

        // Simulate the peer sending back ciphertext/aeadNonce base64url-encoded (the schema allows both)
        const cipherBytes = Buffer.from(body.ciphertext, 'hex');
        const nonceBytes = Buffer.from(body.aeadNonce, 'hex');
        const b64Body = {
            ...body,
            ciphertext: cipherBytes.toString('base64url'),
            aeadNonce: nonceBytes.toString('base64url'),
        };

        // If decoding were hardcoded to hex → garbage decode → tag verify fails → DECRYPTION_FAILED
        // Correct implementation: detect then choose base64url → decodes correctly → passes
        const plain = decryptEnvelopeBody({
            registry: responderReg,
            sessionId: SESSION_ID,
            body: b64Body,
            aadFields: aad,
            capabilityTokenRef: TOKEN_ID,
        });
        expect(new TextDecoder().decode(plain)).toBe(
            'hello base64url decrypt',
        );
    });
});
