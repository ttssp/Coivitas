/**
 * E2E encryption integration test
 *
 * Coverage:
 *   1. Compatibility matrix 10 rows (specVersion + encryptionMode combinations)
 *      - OFF+OFF, OFF+OPT_IN, OFF+REQUIRED (reject)
 *      - OPT_IN+OFF, OPT_IN+OPT_IN (downgrade to OFF), OPT_IN+REQUIRED+token (REQUIRED)
 *      - REQUIRED+OFF (reject), REQUIRED+OPT_IN+token (REQUIRED), REQUIRED+REQUIRED+token (REQUIRED)
 *      - REQUIRED+REQUIRED rejected when capabilityTokenId is missing
 *   2. transcript_hash mismatch detection (decrypting with the wrong session -> DECRYPTION_FAILED)
 *   3. 30s dual-key fallback window (injecting dualKeyFallbackMs=100 to speed up):
 *      - during PENDING_REKEY: new key encrypts, old key can still decrypt
 *      - after the window expires: old key invalidated, decrypting with old keyId -> DECRYPTION_FAILED
 *
 * Design decisions:
 *   - Pure in-memory test, no DB / Socket dependency (no gating).
 *   - Uses real X25519 ECDH + HKDF key derivation (not mocked).
 *   - Compatibility matrix rows are tested via simulated negotiation results: the actual handshake-layer
 *     negotiation is handled by L4 handshake; here we only verify the negotiatedEncryptionMode decision
 *     semantics, without running a full handshake.
 *   - dualKeyFallbackMs=100ms ensures the window expiry completes within 200ms in the test.
 *
 */

import { beforeEach, describe, expect, it } from 'vitest';

import {
    computeTranscriptHash,
    computeX25519SharedSecret,
    deriveSessionKeys,
    generateEphemeralX25519KeyPair,
} from '../../packages/crypto/src/index.js';
import type {
    AeadAadFields,
    NewSessionData,
} from '../../packages/types/src/index.js';
import {
    _clearReplayTracker,
    decryptEnvelopeBody,
    encryptEnvelopeBody,
} from '../../packages/communication/src/envelope.js';
import { SessionRegistryImpl } from '../../packages/communication/src/index.js';

// ─── Test helper functions ────────────────────────────────────────────────────────────

/**
 * Generate NewSessionData produced by a real X25519 ECDH negotiation.
 * Uses the same helper pattern as encrypted-envelope.test.ts.
 */
function makeRealSession(
    sessionId: string,
    opts: {
        generation?: number;
        initiatorPreference?: 'OFF' | 'OPT_IN' | 'REQUIRED';
        responderPreference?: 'OFF' | 'OPT_IN' | 'REQUIRED';
        negotiatedEncryptionMode?: 'OFF' | 'REQUIRED';
        tokenId?: string | null;
    } = {},
): NewSessionData {
    const {
        generation = 0,
        initiatorPreference = 'REQUIRED',
        responderPreference = 'REQUIRED',
        negotiatedEncryptionMode = 'REQUIRED',
        tokenId = 'token-001',
    } = opts;

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
        initiatorPreference,
        responderPreference,
        negotiatedEncryptionMode,
        I_epk: Buffer.from(initiatorKp.publicKey).toString('hex'),
        R_epk: Buffer.from(responderKp.publicKey).toString('hex'),
        nonce: 'test-nonce-12345',
        initTimestamp: '2026-01-01T00:00:00Z',
        responseTimestamp: '2026-01-01T00:00:01Z',
        authorizedPrincipalDid: 'did:key:principal',
        authorizedTokenId: tokenId,
        authorizedTokenFingerprint: 'fp-test-001',
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
 * Set up both the initiator and responder registries, sharing the key material.
 */
function makeSessionPair(
    sessionId: string,
    tokenId: string | null,
    opts: {
        dualKeyFallbackMs?: number;
        initiatorPreference?: 'OFF' | 'OPT_IN' | 'REQUIRED';
        responderPreference?: 'OFF' | 'OPT_IN' | 'REQUIRED';
        negotiatedEncryptionMode?: 'OFF' | 'REQUIRED';
    } = {},
): {
    initiatorReg: SessionRegistryImpl;
    responderReg: SessionRegistryImpl;
    sessionData: NewSessionData;
} {
    const sessionData = makeRealSession(sessionId, {
        tokenId,
        initiatorPreference: opts.initiatorPreference,
        responderPreference: opts.responderPreference,
        negotiatedEncryptionMode: opts.negotiatedEncryptionMode,
    });

    const regOpts =
        opts.dualKeyFallbackMs !== undefined
            ? { dualKeyFallbackMs: opts.dualKeyFallbackMs }
            : undefined;

    const initiatorReg = new SessionRegistryImpl(regOpts);
    initiatorReg.createSession(sessionId, 'initiator', tokenId, sessionData);

    const responderReg = new SessionRegistryImpl(regOpts);
    responderReg.createSession(sessionId, 'responder', tokenId, sessionData);

    return { initiatorReg, responderReg, sessionData };
}

function makeAad(envelopeId = 'env-enc-001'): AeadAadFields {
    return { envelopeId, messageType: 'NEGOTIATION_REQUEST' };
}

// ─── Compatibility matrix helper ────────────────────────────────────────────────────────────

/**
 * Negotiation compatibility matrix rules
 *
 * negotiatedEncryptionMode is decided by HandshakeResponder once the handshake layer completes.
 * This function simulates that decision, without running a real handshake.
 */
// Negotiation decision — fully aligned with
// packages/communication/src/handshake/responder.ts:297-306:
// negotiatedMode = (initiator==='REQUIRED' || responder==='REQUIRED') ? 'REQUIRED' : 'OFF'.
// The previous version's Row 6 "OPT_IN+OPT_IN+token -> REQUIRED" contradicted the production
// responder — the real code does not distinguish hasToken; as long as both are OPT_IN, the
// result is OFF. This helper only checks the REJECT boundary (when one side is REQUIRED the
// other must be >= OPT_IN and the token must be present).
function computeNegotiatedMode(
    initiator: 'OFF' | 'OPT_IN' | 'REQUIRED',
    responder: 'OFF' | 'OPT_IN' | 'REQUIRED',
    hasToken: boolean,
): 'OFF' | 'REQUIRED' | 'REJECT' {
    // REJECT boundary: one side REQUIRED + the other OFF (irreconcilable)
    if (initiator === 'OFF' && responder === 'REQUIRED') return 'REJECT';
    if (initiator === 'REQUIRED' && responder === 'OFF') return 'REJECT';
    // REJECT boundary: negotiated REQUIRED but no capabilityToken
    const wouldBeRequired =
        initiator === 'REQUIRED' || responder === 'REQUIRED';
    if (wouldBeRequired && !hasToken) return 'REJECT';
    // Otherwise follow the production responder logic: both REQUIRED / one-sided REQUIRED -> REQUIRED;
    // everything else (including OPT_IN+OPT_IN, regardless of hasToken) -> OFF.
    return wouldBeRequired ? 'REQUIRED' : 'OFF';
}

// ─── Constants ────────────────────────────────────────────────────────────────────

const TOKEN_ID = 'urn:cap:12345678-1234-4123-89ab-123456789012';
const SESSION_ID = 'session-enc-e2e-001';

beforeEach(() => {
    _clearReplayTracker();
});

// ─── Compatibility matrix tests ──────────────────────────────────────────────────────────

describe('encryption negotiation compatibility matrix (10 core rules)', () => {
    it('Row 1: OFF+OFF -> negotiatedMode=OFF, no encryption (encrypt/decrypt not applicable)', () => {
        const mode = computeNegotiatedMode('OFF', 'OFF', false);
        expect(mode).toBe('OFF');
        // When negotiatedMode=OFF, no EncryptedBody is established; the business layer does not call encryptEnvelopeBody.
        // This line verifies the decision semantics, with no actual encrypt call.
    });

    it('Row 2: OFF+OPT_IN -> negotiatedMode=OFF, responder downgrades and accepts plaintext', () => {
        const mode = computeNegotiatedMode('OFF', 'OPT_IN', false);
        expect(mode).toBe('OFF');
    });

    it('Row 3: OFF+REQUIRED -> REJECT (initiator does not support encryption)', () => {
        const mode = computeNegotiatedMode('OFF', 'REQUIRED', false);
        expect(mode).toBe('REJECT');
        // HandshakeResponder should return an ENCRYPTION_MODE_INCOMPATIBLE error.
        // This test verifies the decision-matrix semantics; the actual negotiation rejection is thrown by the handshake layer.
    });

    it('Row 4: OPT_IN+OFF -> negotiatedMode=OFF, initiator downgrades and accepts plaintext', () => {
        const mode = computeNegotiatedMode('OPT_IN', 'OFF', false);
        expect(mode).toBe('OFF');
    });

    it('Row 5: OPT_IN+OPT_IN, no token -> negotiatedMode=OFF (downgrade)', () => {
        const mode = computeNegotiatedMode('OPT_IN', 'OPT_IN', false);
        expect(mode).toBe('OFF');
    });

    it('Row 6: OPT_IN+OPT_IN, with token -> negotiatedMode=OFF (production responder does not distinguish token; dual OPT_IN always downgrades)', () => {
        // Revision rationale: the previous version asserting 'REQUIRED' contradicts the production responder contract —
        // packages/communication/src/handshake/responder.ts:297-306 negotiates REQUIRED only when
        // one side is REQUIRED; OPT_IN+OPT_IN (regardless of hasToken) always negotiates OFF.
        // The original test forced a session with negotiatedEncryptionMode:'REQUIRED' to make
        // encrypt/decrypt falsely green, but that path is unreachable on the real wire.
        // Real coverage of the encryption round-trip is guaranteed by Row 7/10/12 (one side REQUIRED).
        const mode = computeNegotiatedMode('OPT_IN', 'OPT_IN', true);
        expect(mode).toBe('OFF');
    });

    it('Row 7: OPT_IN+REQUIRED, with token -> negotiatedMode=REQUIRED', () => {
        const mode = computeNegotiatedMode('OPT_IN', 'REQUIRED', true);
        expect(mode).toBe('REQUIRED');

        const sid = 'session-matrix-row7';
        const { initiatorReg, responderReg } = makeSessionPair(sid, TOKEN_ID, {
            initiatorPreference: 'OPT_IN',
            responderPreference: 'REQUIRED',
            negotiatedEncryptionMode: 'REQUIRED',
        });
        const plaintext = new TextEncoder().encode('matrix row 7 payload');
        const body = encryptEnvelopeBody({
            registry: initiatorReg,
            sessionId: sid,
            capabilityTokenRef: TOKEN_ID,
            aadFields: makeAad('env-row7'),
            plaintext,
            bodyType: 'BUSINESS',
        });
        const decrypted = decryptEnvelopeBody({
            registry: responderReg,
            sessionId: sid,
            body,
            aadFields: makeAad('env-row7'),
            capabilityTokenRef: TOKEN_ID,
        });
        expect(decrypted).toEqual(plaintext);
    });

    it('Row 9: REQUIRED+OFF -> REJECT (responder does not support encryption)', () => {
        const mode = computeNegotiatedMode('REQUIRED', 'OFF', false);
        expect(mode).toBe('REJECT');
    });

    it('Row 10: REQUIRED+OPT_IN, with token -> negotiatedMode=REQUIRED', () => {
        const mode = computeNegotiatedMode('REQUIRED', 'OPT_IN', true);
        expect(mode).toBe('REQUIRED');

        const sid = 'session-matrix-row10';
        const { initiatorReg, responderReg } = makeSessionPair(sid, TOKEN_ID, {
            initiatorPreference: 'REQUIRED',
            responderPreference: 'OPT_IN',
            negotiatedEncryptionMode: 'REQUIRED',
        });
        const plaintext = new TextEncoder().encode('matrix row 10 payload');
        const body = encryptEnvelopeBody({
            registry: initiatorReg,
            sessionId: sid,
            capabilityTokenRef: TOKEN_ID,
            aadFields: makeAad('env-row10'),
            plaintext,
            bodyType: 'BUSINESS',
        });
        const decrypted = decryptEnvelopeBody({
            registry: responderReg,
            sessionId: sid,
            body,
            aadFields: makeAad('env-row10'),
            capabilityTokenRef: TOKEN_ID,
        });
        expect(decrypted).toEqual(plaintext);
    });

    it('Row 12: REQUIRED+REQUIRED, with token -> negotiatedMode=REQUIRED; full encryption round-trip', () => {
        const mode = computeNegotiatedMode('REQUIRED', 'REQUIRED', true);
        expect(mode).toBe('REQUIRED');

        const sid = 'session-matrix-row12';
        const { initiatorReg, responderReg } = makeSessionPair(sid, TOKEN_ID, {
            initiatorPreference: 'REQUIRED',
            responderPreference: 'REQUIRED',
            negotiatedEncryptionMode: 'REQUIRED',
        });
        const plaintext = new TextEncoder().encode(
            'matrix row 12 payload - fully encrypted session',
        );
        const body = encryptEnvelopeBody({
            registry: initiatorReg,
            sessionId: sid,
            capabilityTokenRef: TOKEN_ID,
            aadFields: makeAad('env-row12'),
            plaintext,
            bodyType: 'BUSINESS',
        });

        expect(body.encrypted).toBe(true);
        expect(body.encryptionProtocolVersion).toBe('ap/e2e/v1');
        expect(body.type).toBe('BUSINESS');
        expect(body.keyId).toBeTruthy();

        const decrypted = decryptEnvelopeBody({
            registry: responderReg,
            sessionId: sid,
            body,
            aadFields: makeAad('env-row12'),
            capabilityTokenRef: TOKEN_ID,
        });
        expect(decrypted).toEqual(plaintext);
    });

    it('Row 12b: REQUIRED+REQUIRED, no token -> REJECT (capabilityTokenId is required)', () => {
        const mode = computeNegotiatedMode('REQUIRED', 'REQUIRED', false);
        expect(mode).toBe('REJECT');
        // Note: even if a session is established (tokenId=null), a capabilityTokenRef mismatch would
        // cause SESSION_TOKEN_MISMATCH; this line verifies the matrix decision semantics.
    });
});

// ─── transcript_hash mismatch detection ──────────────────────────────────────────────

describe('transcript_hash mismatch detection', () => {
    it('should throw DECRYPTION_FAILED when initiator/responder derive keys from different transcript inputs (same sessionId, same sharedSecret)', () => {
        // The old version simulated a mismatch by changing sessionId / changing registry,
        // which actually triggered a lookupHandleForDecrypt failure (keyId can't find the session),
        // rather than a transcript binding regression. This test instead uses the same sessionId +
        // same sharedSecret, but the transcriptHash inputs to deriveSessionKeys on the two sides differ
        // in one field (such as nonce), thus deriving different trafficKeys; the keyId is found on both
        // sides, but AEAD fails to decrypt because the keys do not match. This is the real
        // transcript-binding regression detection: if someone later omits a field from transcriptHash,
        // this test will fail.
        const sid = 'session-transcript-binding';

        // shared ECDH (initiator/responder use the same ephemeral pair)
        const initiatorKp = generateEphemeralX25519KeyPair();
        const responderKp = generateEphemeralX25519KeyPair();
        const sharedSecret = computeX25519SharedSecret(
            initiatorKp.secretKey,
            responderKp.publicKey,
        );

        const baseTranscript = {
            protocolVersion: 'ap/e2e/v1' as const,
            initiatorDid: 'did:key:initiator',
            responderDid: 'did:key:responder',
            initiatorCapabilities: [],
            responderCapabilities: [],
            initiatorPreference: 'REQUIRED' as const,
            responderPreference: 'REQUIRED' as const,
            negotiatedEncryptionMode: 'REQUIRED' as const,
            I_epk: Buffer.from(initiatorKp.publicKey).toString('hex'),
            R_epk: Buffer.from(responderKp.publicKey).toString('hex'),
            initTimestamp: '2026-01-01T00:00:00Z',
            responseTimestamp: '2026-01-01T00:00:01Z',
            authorizedPrincipalDid: 'did:key:principal',
            authorizedTokenId: TOKEN_ID,
            authorizedTokenFingerprint: 'fp-test-001',
        };

        // initiator transcript: nonce='nonce-A'
        const transcriptHashA = computeTranscriptHash({
            ...baseTranscript,
            nonce: 'nonce-A',
        });
        const keysA = deriveSessionKeys(sharedSecret, transcriptHashA);

        // responder transcript: nonce='nonce-B' (any differing field suffices) -> different traffic key
        const transcriptHashB = computeTranscriptHash({
            ...baseTranscript,
            nonce: 'nonce-B',
        });
        const keysB = deriveSessionKeys(sharedSecret, transcriptHashB);

        // verify: same sharedSecret + different transcriptHash -> different trafficKey
        expect(keysA.initToResp).not.toEqual(keysB.initToResp);

        const sessionA: NewSessionData = {
            trafficKeys: keysA,
            sessionSalt: keysA.sessionSalt,
            rekeyChainKey: keysA.rekeyChainKey,
            generation: 0,
        };
        const sessionB: NewSessionData = {
            trafficKeys: keysB,
            sessionSalt: keysB.sessionSalt,
            rekeyChainKey: keysB.rekeyChainKey,
            generation: 0,
        };

        const initiatorReg = new SessionRegistryImpl();
        initiatorReg.createSession(sid, 'initiator', TOKEN_ID, sessionA);
        const responderReg = new SessionRegistryImpl();
        responderReg.createSession(sid, 'responder', TOKEN_ID, sessionB);

        const plaintext = new TextEncoder().encode('secret payload');
        const body = encryptEnvelopeBody({
            registry: initiatorReg,
            sessionId: sid,
            capabilityTokenRef: TOKEN_ID,
            aadFields: makeAad('env-mismatch'),
            plaintext,
            bodyType: 'BUSINESS',
        });

        // the responder keyId is findable in the registry (same sessionId), but decrypting with the mismatched trafficKey -> AEAD rejects
        expect(() => {
            decryptEnvelopeBody({
                registry: responderReg,
                sessionId: sid,
                body,
                aadFields: makeAad('env-mismatch'),
                capabilityTokenRef: TOKEN_ID,
            });
        }).toThrow('DECRYPTION_FAILED');
    });

    it('should throw DECRYPTION_FAILED when using wrong session registry for decryption', () => {
        const sid = 'session-wrong-registry';
        const emptyReg = new SessionRegistryImpl();
        // emptyReg has no session registered

        const { initiatorReg } = makeSessionPair(sid, TOKEN_ID);
        const plaintext = new TextEncoder().encode(
            'payload for wrong registry test',
        );
        const body = encryptEnvelopeBody({
            registry: initiatorReg,
            sessionId: sid,
            capabilityTokenRef: TOKEN_ID,
            aadFields: makeAad('env-wr'),
            plaintext,
            bodyType: 'BUSINESS',
        });

        expect(() => {
            decryptEnvelopeBody({
                registry: emptyReg,
                sessionId: sid,
                body,
                aadFields: makeAad('env-wr'),
                capabilityTokenRef: TOKEN_ID,
            });
        }).toThrow('DECRYPTION_FAILED');
    });
});

// ─── 30s dual-key fallback window (Inv 5) ────────────────────────────────────────────

describe('dual-key fallback window (PENDING_REKEY, dualKeyFallbackMs=100)', () => {
    it('should allow decryption with old key during PENDING_REKEY window', () => {
        const sid = 'session-dual-key-window';
        // inject a 100ms timeout (speeds up the test, avoiding the real 30s wait)
        const { initiatorReg, responderReg } = makeSessionPair(sid, TOKEN_ID, {
            dualKeyFallbackMs: 100,
        });

        // Step 1: encrypt a message with the old key
        const plaintextOld = new TextEncoder().encode('old key message');
        const bodyOld = encryptEnvelopeBody({
            registry: initiatorReg,
            sessionId: sid,
            capabilityTokenRef: TOKEN_ID,
            aadFields: makeAad('env-old'),
            plaintext: plaintextOld,
            bodyType: 'BUSINESS',
        });

        // Step 2: trigger a chain-key rekey (both sides derive the new key from the same chain key, staying in sync)
        // swapForDualKeyChainMode deterministically derives the new traffic key from the existing chain key, without external coordination
        initiatorReg.swapForDualKeyChainMode(sid);
        responderReg.swapForDualKeyChainMode(sid);

        // Step 3: during PENDING_REKEY, encrypt with the new key
        const plaintextNew = new TextEncoder().encode(
            'new key message during PENDING_REKEY',
        );
        const bodyNew = encryptEnvelopeBody({
            registry: initiatorReg,
            sessionId: sid,
            capabilityTokenRef: TOKEN_ID,
            aadFields: makeAad('env-new'),
            plaintext: plaintextNew,
            bodyType: 'BUSINESS',
        });

        // Inv 5 verification: within the window, the old-key body can still be decrypted (responderReg retains previousHandle)
        const decryptedOld = decryptEnvelopeBody({
            registry: responderReg,
            sessionId: sid,
            body: bodyOld,
            aadFields: makeAad('env-old'),
            capabilityTokenRef: TOKEN_ID,
        });
        expect(decryptedOld).toEqual(plaintextOld);

        // the new-key body can also be decrypted
        const decryptedNew = decryptEnvelopeBody({
            registry: responderReg,
            sessionId: sid,
            body: bodyNew,
            aadFields: makeAad('env-new'),
            capabilityTokenRef: TOKEN_ID,
        });
        expect(decryptedNew).toEqual(plaintextNew);
    });

    it('should fail DECRYPTION_FAILED for old keyId after dual-key window expires', async () => {
        const sid = 'session-dual-key-expire';
        const { initiatorReg, responderReg } = makeSessionPair(sid, TOKEN_ID, {
            dualKeyFallbackMs: 100,
        });

        // encrypt with the old key (before the window expires)
        const plaintextOld = new TextEncoder().encode('old key before expiry');
        const bodyOld = encryptEnvelopeBody({
            registry: initiatorReg,
            sessionId: sid,
            capabilityTokenRef: TOKEN_ID,
            aadFields: makeAad('env-expire-old'),
            plaintext: plaintextOld,
            bodyType: 'BUSINESS',
        });

        // trigger a chain-key rekey (100ms timeout)
        initiatorReg.swapForDualKeyChainMode(sid);
        responderReg.swapForDualKeyChainMode(sid);

        // wait 150ms to let the timer expire (100ms + 50ms buffer)
        await new Promise<void>((resolve) => setTimeout(resolve, 150));

        // after the window expires: the previousHandle for the old keyId has been zeroed and removed
        // lookupHandleForDecrypt cannot find the old keyId -> DECRYPTION_FAILED
        expect(() => {
            decryptEnvelopeBody({
                registry: responderReg,
                sessionId: sid,
                body: bodyOld,
                aadFields: makeAad('env-expire-old'),
                capabilityTokenRef: TOKEN_ID,
            });
        }).toThrow('DECRYPTION_FAILED');
    });

    it('should successfully encrypt/decrypt with new key after dual-key window expires', async () => {
        const sid = 'session-dual-key-new-active';
        const { initiatorReg, responderReg } = makeSessionPair(sid, TOKEN_ID, {
            dualKeyFallbackMs: 100,
        });

        // trigger a chain-key rekey -> wait for the window to expire
        initiatorReg.swapForDualKeyChainMode(sid);
        responderReg.swapForDualKeyChainMode(sid);

        await new Promise<void>((resolve) => setTimeout(resolve, 150));

        // after the window expires: encryption/decryption with the new key still works
        const plaintext = new TextEncoder().encode(
            'new key after window expires',
        );
        const body = encryptEnvelopeBody({
            registry: initiatorReg,
            sessionId: sid,
            capabilityTokenRef: TOKEN_ID,
            aadFields: makeAad('env-new-active'),
            plaintext,
            bodyType: 'BUSINESS',
        });

        const decrypted = decryptEnvelopeBody({
            registry: responderReg,
            sessionId: sid,
            body,
            aadFields: makeAad('env-new-active'),
            capabilityTokenRef: TOKEN_ID,
        });
        expect(decrypted).toEqual(plaintext);
    });
});

// ─── Basic error paths ─────────────────────────────────────────────────────────────

describe('encryption basic error paths', () => {
    it('should throw SESSION_NOT_FOUND when encrypting with non-existent session', () => {
        const emptyReg = new SessionRegistryImpl();
        expect(() => {
            encryptEnvelopeBody({
                registry: emptyReg,
                sessionId: 'non-existent',
                capabilityTokenRef: TOKEN_ID,
                aadFields: makeAad(),
                plaintext: new TextEncoder().encode('test'),
                bodyType: 'BUSINESS',
            });
        }).toThrow('SESSION_NOT_FOUND');
    });

    it('should throw SESSION_TOKEN_MISMATCH when capabilityTokenRef does not match authorizedTokenId', () => {
        const { initiatorReg } = makeSessionPair(SESSION_ID, TOKEN_ID);
        const wrongToken = 'urn:cap:wrong-token-id-0000000000000000000';
        expect(() => {
            encryptEnvelopeBody({
                registry: initiatorReg,
                sessionId: SESSION_ID,
                capabilityTokenRef: wrongToken,
                aadFields: makeAad(),
                plaintext: new TextEncoder().encode('test'),
                bodyType: 'BUSINESS',
            });
        }).toThrow('SESSION_TOKEN_MISMATCH');
    });

    it('should throw ENCRYPTED_REPLAY_DETECTED on sequenceNumber replay', () => {
        const sid = 'session-replay-test';
        const { initiatorReg, responderReg } = makeSessionPair(sid, TOKEN_ID);
        const plaintext = new TextEncoder().encode('replay test');

        const body = encryptEnvelopeBody({
            registry: initiatorReg,
            sessionId: sid,
            capabilityTokenRef: TOKEN_ID,
            aadFields: makeAad('env-replay'),
            plaintext,
            bodyType: 'BUSINESS',
        });

        // first decryption succeeds
        decryptEnvelopeBody({
            registry: responderReg,
            sessionId: sid,
            body,
            aadFields: makeAad('env-replay'),
            capabilityTokenRef: TOKEN_ID,
        });

        // second time with the same body -> replay detection
        expect(() => {
            decryptEnvelopeBody({
                registry: responderReg,
                sessionId: sid,
                body,
                aadFields: makeAad('env-replay'),
                capabilityTokenRef: TOKEN_ID,
            });
        }).toThrow('ENCRYPTED_REPLAY_DETECTED');
    });
});
