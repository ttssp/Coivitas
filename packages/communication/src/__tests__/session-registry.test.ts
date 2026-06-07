/**
 * SessionRegistry + SessionCryptoHandle 13-invariant unit tests
 *
 * Covers the following 13 end-to-end encryption invariants:
 *   Inv 1: SessionRegistry unique index
 *   Inv 2: callers do not cache the handle reference (transient brand type verification)
 *   Inv 3: encrypt precondition (state + token)
 *   Inv 4: the decrypt path must use lookupHandleForDecrypt; no trial-and-error
 *   Inv 5: dual-key fallback window of 30s (swapForDualKey is idempotent)
 *   Inv 6: closeSession atomic cleanup
 *   Inv 7: monotonic AEAD nonce increment + reset across rekey
 *   Inv 8: authorizedTokenId is immutable at runtime
 *   Inv 9: sender Receipt write timing (an architectural constraint; the registry does not participate)
 *   Inv 10: specVersion boundary (a caller responsibility)
 *   Inv 11: impossible wire state (a caller responsibility)
 *   Inv 12: no sessionTrustDomain field
 *   Inv 13: calling rekey again during PENDING_REKEY throws REKEY_FAILED
 *
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import {
    deriveSessionKeys,
    generateEphemeralX25519KeyPair,
    computeX25519SharedSecret,
    computeTranscriptHash,
} from '@coivitas/crypto';
import type { NewSessionData } from '@coivitas/types';
import { ProtocolError } from '@coivitas/types';

import { SessionRegistryImpl } from '../session-registry.js';
import { SessionCryptoHandleImpl } from '../session/crypto-state.js';

// ─── Test helper functions ────────────────────────────────────────────────────────────

/**
 * Generates real NewSessionData (X25519 + HKDF, for integration scenarios)
 */
function makeRealSession(generation = 0): NewSessionData {
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
        sessionId: 'test-session',
        capabilityTokenId: 'test-token',
        policyHash: 'abc123',
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
 * Generates pseudo-random NewSessionData (quick to build, for state-machine tests)
 */
function makeFakeSession(generation = 0, seed = 0): NewSessionData {
    const fill = (v: number) => new Uint8Array(32).fill(v);
    return {
        trafficKeys: {
            initToResp: fill(seed + 1),
            respToInit: fill(seed + 2),
        },
        sessionSalt: new Uint8Array(4).fill(seed + 3),
        rekeyChainKey: fill(seed + 4),
        generation,
    };
}

/**
 * Builds standard aadFields for tests (a valid envelopeId + messageType)
 */
const TEST_AAD = {
    envelopeId: 'env-test-001',
    messageType: 'NEGOTIATION_REQUEST',
};

const PLAINTEXT = new TextEncoder().encode('hello world');

// ─── Invariant 1: SessionRegistry unique index ──────────────────────────────────

describe('Invariant 1: SessionRegistry unique index', () => {
    it('should register a session successfully', () => {
        const registry = new SessionRegistryImpl();
        registry.createSession(
            'sid-1',
            'initiator',
            'token-1',
            makeFakeSession(),
        );
        expect(registry.size).toBe(1);
    });

    it('should throw INTERNAL_ERROR when registering duplicate sessionId', () => {
        const registry = new SessionRegistryImpl();
        registry.createSession(
            'sid-1',
            'initiator',
            'token-1',
            makeFakeSession(),
        );
        expect(() => {
            registry.createSession(
                'sid-1',
                'responder',
                'token-2',
                makeFakeSession(),
            );
        }).toThrow(ProtocolError);
        expect(() => {
            registry.createSession(
                'sid-1',
                'responder',
                'token-2',
                makeFakeSession(),
            );
        }).toThrowError('INTERNAL_ERROR');
    });

    it('should return same handle reference on consecutive lookups (unique index)', () => {
        const registry = new SessionRegistryImpl();
        registry.createSession(
            'sid-1',
            'initiator',
            'token-1',
            makeFakeSession(),
        );
        const h1 = registry.lookupHandle('sid-1');
        const h2 = registry.lookupHandle('sid-1');
        // Within the same registry state, the returned handle should be the same underlying handle
        expect(h1).not.toBeNull();
        expect(h2).not.toBeNull();
        expect(h1?.sessionId).toBe(h2?.sessionId);
        expect(h1?.generation).toBe(h2?.generation);
    });

    it('should allow different sessionIds to coexist', () => {
        const registry = new SessionRegistryImpl();
        registry.createSession(
            'sid-1',
            'initiator',
            'token-1',
            makeFakeSession(0, 0),
        );
        registry.createSession(
            'sid-2',
            'responder',
            'token-2',
            makeFakeSession(0, 10),
        );
        expect(registry.size).toBe(2);
        expect(registry.lookupHandle('sid-1')?.sessionId).toBe('sid-1');
        expect(registry.lookupHandle('sid-2')?.sessionId).toBe('sid-2');
    });
});

// ─── Invariant 2: transient brand (callers do not cache the reference) ────────────────────────────

describe('Invariant 2: lookupHandle returns a transient handle', () => {
    it('should return null for unknown sessionId', () => {
        const registry = new SessionRegistryImpl();
        expect(registry.lookupHandle('nonexistent')).toBeNull();
    });

    it('should return handle with correct sessionId and generation', () => {
        const registry = new SessionRegistryImpl();
        registry.createSession(
            'sid-1',
            'initiator',
            'token-1',
            makeFakeSession(3),
        );
        const handle = registry.lookupHandle('sid-1');
        expect(handle?.sessionId).toBe('sid-1');
        expect(handle?.generation).toBe(3);
        expect(handle?.role).toBe('initiator');
        expect(handle?.state).toBe('ACTIVE');
    });

    it('should return PENDING_REKEY handle after swap (encrypt path uses the new generation)', () => {
        vi.useFakeTimers();
        const registry = new SessionRegistryImpl({ dualKeyFallbackMs: 30_000 });
        registry.createSession(
            'sid-1',
            'initiator',
            'token-1',
            makeFakeSession(0),
        );
        registry.swapForDualKey('sid-1', makeFakeSession(1, 10));
        const handle = registry.lookupHandle('sid-1');
        expect(handle?.generation).toBe(1);
        expect(handle?.state).toBe('PENDING_REKEY');
        vi.useRealTimers();
    });
});

// ─── Invariant 3: encrypt precondition (state + token) ──────────────────────────

describe('Invariant 3: encrypt precondition', () => {
    it('should throw SESSION_HANDLE_REVOKED when encrypt on CLOSED handle', () => {
        const data = makeFakeSession();
        const handle = new SessionCryptoHandleImpl(
            'sid',
            0,
            'initiator',
            'token-1',
            data.trafficKeys,
            data.sessionSalt,
            data.rekeyChainKey,
            'CLOSED',
        );
        expect(() =>
            handle.encrypt({ aadFields: TEST_AAD, plaintext: PLAINTEXT }),
        ).toThrowError('SESSION_HANDLE_REVOKED');
    });

    it('should throw SESSION_HANDLE_REVOKED when encrypt on REVOKED handle', () => {
        const data = makeFakeSession();
        const handle = new SessionCryptoHandleImpl(
            'sid',
            0,
            'initiator',
            'token-1',
            data.trafficKeys,
            data.sessionSalt,
            data.rekeyChainKey,
            'REVOKED',
        );
        expect(() =>
            handle.encrypt({ aadFields: TEST_AAD, plaintext: PLAINTEXT }),
        ).toThrowError('SESSION_HANDLE_REVOKED');
    });

    it('should throw SESSION_HANDLE_REVOKED when authorizedTokenId is null', () => {
        const data = makeFakeSession();
        const handle = new SessionCryptoHandleImpl(
            'sid',
            0,
            'initiator',
            null, // null tokenId
            data.trafficKeys,
            data.sessionSalt,
            data.rekeyChainKey,
            'ACTIVE',
        );
        expect(() =>
            handle.encrypt({ aadFields: TEST_AAD, plaintext: PLAINTEXT }),
        ).toThrowError('SESSION_HANDLE_REVOKED');
    });

    it('should allow encrypt on ACTIVE handle', () => {
        const data = makeRealSession();
        const handle = new SessionCryptoHandleImpl(
            'sid',
            0,
            'initiator',
            'token-1',
            data.trafficKeys,
            data.sessionSalt,
            data.rekeyChainKey,
            'ACTIVE',
        );
        const result = handle.encrypt({
            aadFields: TEST_AAD,
            plaintext: PLAINTEXT,
        });
        expect(result.ciphertext).toBeInstanceOf(Uint8Array);
        expect(result.aeadNonce).toHaveLength(12);
        expect(result.keyId).toHaveLength(32); // 32 hex chars = 16 bytes
    });

    it('should allow encrypt on PENDING_REKEY handle (during the dual-key window)', () => {
        const data = makeRealSession();
        const handle = new SessionCryptoHandleImpl(
            'sid',
            1,
            'initiator',
            'token-1',
            data.trafficKeys,
            data.sessionSalt,
            data.rekeyChainKey,
            'PENDING_REKEY',
        );
        const result = handle.encrypt({
            aadFields: TEST_AAD,
            plaintext: PLAINTEXT,
        });
        expect(result.ciphertext).toBeInstanceOf(Uint8Array);
    });
});

// ─── Invariant 4: the decrypt path must use lookupHandleForDecrypt ──────────────────

describe('Invariant 4: decrypt precondition + lookupHandleForDecrypt exact routing', () => {
    it('should return null for unknown sessionId in lookupHandleForDecrypt', () => {
        const registry = new SessionRegistryImpl();
        expect(
            registry.lookupHandleForDecrypt('nonexistent', 'some-key-id'),
        ).toBeNull();
    });

    it('should return null when keyId does not match any handle', () => {
        const registry = new SessionRegistryImpl();
        registry.createSession(
            'sid-1',
            'initiator',
            'token-1',
            makeFakeSession(0),
        );
        const result = registry.lookupHandleForDecrypt(
            'sid-1',
            'invalid-key-id-xyz',
        );
        expect(result).toBeNull();
    });

    it('should throw SESSION_HANDLE_REVOKED when decrypt on CLOSED handle', () => {
        const data = makeRealSession();
        const handle = new SessionCryptoHandleImpl(
            'sid',
            0,
            'initiator',
            'token-1',
            data.trafficKeys,
            data.sessionSalt,
            data.rekeyChainKey,
            'CLOSED',
        );
        const dummyNonce = new Uint8Array(12);
        const dummyCiphertext = new Uint8Array(32);
        expect(() =>
            handle.decrypt({
                aadFields: TEST_AAD,
                ciphertext: dummyCiphertext,
                aeadNonce: dummyNonce,
            }),
        ).toThrowError('SESSION_HANDLE_REVOKED');
    });

    it('should throw DECRYPTION_FAILED when ciphertext is tampered', () => {
        const data = makeRealSession();
        const initiator = new SessionCryptoHandleImpl(
            'sid',
            0,
            'initiator',
            'token-1',
            data.trafficKeys,
            data.sessionSalt,
            data.rekeyChainKey,
            'ACTIVE',
        );
        const responder = new SessionCryptoHandleImpl(
            'sid',
            0,
            'responder',
            'token-1',
            data.trafficKeys,
            data.sessionSalt,
            data.rekeyChainKey,
            'ACTIVE',
        );

        const { ciphertext, aeadNonce } = initiator.encrypt({
            aadFields: TEST_AAD,
            plaintext: PLAINTEXT,
        });

        // Tamper with the ciphertext (modify the tag region)
        const tampered = new Uint8Array(ciphertext);
        tampered[0] = (tampered[0] ?? 0) ^ 0xff;

        expect(() =>
            responder.decrypt({
                aadFields: TEST_AAD,
                ciphertext: tampered,
                aeadNonce,
            }),
        ).toThrowError('DECRYPTION_FAILED');
    });

    it('should decrypt successfully with correct ciphertext', () => {
        const data = makeRealSession();
        const initiator = new SessionCryptoHandleImpl(
            'sid',
            0,
            'initiator',
            'token-1',
            data.trafficKeys,
            data.sessionSalt,
            data.rekeyChainKey,
            'ACTIVE',
        );
        const responder = new SessionCryptoHandleImpl(
            'sid',
            0,
            'responder',
            'token-1',
            data.trafficKeys,
            data.sessionSalt,
            data.rekeyChainKey,
            'ACTIVE',
        );

        const { ciphertext, aeadNonce } = initiator.encrypt({
            aadFields: TEST_AAD,
            plaintext: PLAINTEXT,
        });

        const plaintext = responder.decrypt({
            aadFields: TEST_AAD,
            ciphertext,
            aeadNonce,
        });

        expect(plaintext).toEqual(PLAINTEXT);
    });

    it('should route to currentHandle.peerKeyId when keyId matches', () => {
        const data = makeRealSession();
        const registry = new SessionRegistryImpl();
        registry.createSession('sid-1', 'initiator', 'token-1', data);

        // Get the peer (the responder's encrypt direction = the initiator's peerDirection)
        const currentHandle = registry._getCurrentHandle('sid-1')!;
        const peerKeyId = currentHandle.peerKeyId;

        const result = registry.lookupHandleForDecrypt('sid-1', peerKeyId);
        expect(result).not.toBeNull();
        expect(result?.sessionId).toBe('sid-1');
    });

    it('should not trial-and-error: lookupHandleForDecrypt returns null for unknown keyId', () => {
        // Inv 4: confirm it returns null rather than performing a fallback or trial-and-error
        const registry = new SessionRegistryImpl();
        registry.createSession(
            'sid-1',
            'initiator',
            'token-1',
            makeFakeSession(0),
        );
        // Use a keyId that definitely does not exist
        const result = registry.lookupHandleForDecrypt(
            'sid-1',
            'aaaa-bbbb-cccc-dddd-eeee',
        );
        expect(result).toBeNull();
        // registry.size is unchanged (no internal trial operation altered the state)
        expect(registry.size).toBe(1);
    });
});

// ─── Invariant 5: dual-key fallback window of 30s ─────────────────────────────────────

describe('Invariant 5: dual-key 30s fallback window', () => {
    beforeEach(() => {
        vi.useFakeTimers();
    });

    afterEach(() => {
        vi.useRealTimers();
    });

    it('should create new PENDING_REKEY handle after swapForDualKey', () => {
        const registry = new SessionRegistryImpl({ dualKeyFallbackMs: 30_000 });
        registry.createSession(
            'sid-1',
            'initiator',
            'token-1',
            makeFakeSession(0),
        );
        registry.swapForDualKey('sid-1', makeFakeSession(1, 10));

        const currentHandle = registry._getCurrentHandle('sid-1');
        const previousHandle = registry._getPreviousHandle('sid-1');

        expect(currentHandle?.generation).toBe(1);
        expect(currentHandle?.state).toBe('PENDING_REKEY');
        expect(previousHandle?.generation).toBe(0);
        expect(previousHandle?.state).toBe('ACTIVE'); // the old generation stays ACTIVE
    });

    it('should promote new handle to ACTIVE after 30s', () => {
        const registry = new SessionRegistryImpl({ dualKeyFallbackMs: 30_000 });
        registry.createSession(
            'sid-1',
            'initiator',
            'token-1',
            makeFakeSession(0),
        );
        registry.swapForDualKey('sid-1', makeFakeSession(1, 10));

        // The timer fires after 30s
        vi.advanceTimersByTime(30_001);

        const currentHandle = registry._getCurrentHandle('sid-1');
        const previousHandle = registry._getPreviousHandle('sid-1');

        expect(currentHandle?.state).toBe('ACTIVE');
        expect(previousHandle).toBeNull(); // the old generation has been zeroized + removed
    });

    it('should zeroize old handle after 30s window expires', () => {
        const registry = new SessionRegistryImpl({ dualKeyFallbackMs: 30_000 });
        registry.createSession(
            'sid-1',
            'initiator',
            'token-1',
            makeFakeSession(0),
        );
        registry.swapForDualKey('sid-1', makeFakeSession(1, 10));

        // Save a reference to the old-generation handle (test-only, violates Inv 2)
        const oldHandle = registry._getPreviousHandle('sid-1')!;
        expect(oldHandle).not.toBeNull();

        vi.advanceTimersByTime(30_001);

        // The old generation has been zeroized
        expect(oldHandle.isZeroized).toBe(true);
        expect(oldHandle.state).toBe('CLOSED');
    });

    it('should be idempotent: second swapForDualKey is no-op when PENDING_REKEY', () => {
        const registry = new SessionRegistryImpl({ dualKeyFallbackMs: 30_000 });
        registry.createSession(
            'sid-1',
            'initiator',
            'token-1',
            makeFakeSession(0),
        );
        registry.swapForDualKey('sid-1', makeFakeSession(1, 10));

        // Record the state after the first swap
        const firstCurrentHandle = registry._getCurrentHandle('sid-1');
        expect(firstCurrentHandle?.generation).toBe(1);

        // Second swap (idempotent: should be ignored)
        registry.swapForDualKey('sid-1', makeFakeSession(2, 20));

        // The current generation is still 1 (not overwritten by the second swap)
        const currentAfter = registry._getCurrentHandle('sid-1');
        expect(currentAfter?.generation).toBe(1);
    });

    it('should route old keyId to previousHandle during dual-key window', () => {
        const data = makeRealSession(0);
        const newData = makeRealSession(1);
        const registry = new SessionRegistryImpl({ dualKeyFallbackMs: 30_000 });
        registry.createSession('sid-1', 'initiator', 'token-1', data);

        // Record the old-generation peerKeyId
        const oldPeerKeyId = registry._getCurrentHandle('sid-1')!.peerKeyId;

        registry.swapForDualKey('sid-1', newData);

        // Within the 30s window, the old keyId matches previousHandle
        const result = registry.lookupHandleForDecrypt('sid-1', oldPeerKeyId);
        expect(result).not.toBeNull();
        expect(result?.generation).toBe(0); // old generation
    });

    it('should reject old keyId after 30s window expires', () => {
        const data = makeRealSession(0);
        const newData = makeRealSession(1);
        const registry = new SessionRegistryImpl({ dualKeyFallbackMs: 30_000 });
        registry.createSession('sid-1', 'initiator', 'token-1', data);

        const oldPeerKeyId = registry._getCurrentHandle('sid-1')!.peerKeyId;

        registry.swapForDualKey('sid-1', newData);

        // Wait for the 30s window to expire
        vi.advanceTimersByTime(30_001);

        // The old keyId no longer matches any handle
        const result = registry.lookupHandleForDecrypt('sid-1', oldPeerKeyId);
        expect(result).toBeNull();
    });

    it('should route new keyId to currentHandle during dual-key window', () => {
        const data = makeRealSession(0);
        const newData = makeRealSession(1);
        const registry = new SessionRegistryImpl({ dualKeyFallbackMs: 30_000 });
        registry.createSession('sid-1', 'initiator', 'token-1', data);
        registry.swapForDualKey('sid-1', newData);

        // New-generation peerKeyId
        const newPeerKeyId = registry._getCurrentHandle('sid-1')!.peerKeyId;
        const result = registry.lookupHandleForDecrypt('sid-1', newPeerKeyId);
        expect(result).not.toBeNull();
        expect(result?.generation).toBe(1); // new generation
    });

    it('should encrypt with new key only during dual-key window (lookupHandle = currentHandle)', () => {
        const registry = new SessionRegistryImpl({ dualKeyFallbackMs: 30_000 });
        registry.createSession(
            'sid-1',
            'initiator',
            'token-1',
            makeFakeSession(0),
        );
        registry.swapForDualKey('sid-1', makeFakeSession(1, 10));

        // The encrypt path should use the new generation (gen 1)
        const handle = registry.lookupHandle('sid-1');
        expect(handle?.generation).toBe(1);
        expect(handle?.state).toBe('PENDING_REKEY');
    });

    it('should throw INTERNAL_ERROR when swapForDualKey on nonexistent session', () => {
        const registry = new SessionRegistryImpl();
        expect(() => {
            registry.swapForDualKey('nonexistent', makeFakeSession(1));
        }).toThrowError('INTERNAL_ERROR');
    });
});

// ─── Invariant 6: closeSession atomic cleanup ─────────────────────────────────────

describe('Invariant 6: closeSession atomic cleanup', () => {
    beforeEach(() => {
        vi.useFakeTimers();
    });

    afterEach(() => {
        vi.useRealTimers();
    });

    it('should return null after closeSession (lookupHandle fail-fast)', () => {
        const registry = new SessionRegistryImpl();
        registry.createSession(
            'sid-1',
            'initiator',
            'token-1',
            makeFakeSession(0),
        );
        registry.closeSession('sid-1', 'CLOSED');
        expect(registry.lookupHandle('sid-1')).toBeNull();
        expect(
            registry.lookupHandleForDecrypt('sid-1', 'any-key-id'),
        ).toBeNull();
    });

    it('should zeroize currentHandle on closeSession', () => {
        const registry = new SessionRegistryImpl();
        registry.createSession(
            'sid-1',
            'initiator',
            'token-1',
            makeFakeSession(0),
        );
        const handle = registry._getCurrentHandle('sid-1')!;

        registry.closeSession('sid-1', 'CLOSED');

        expect(handle.isZeroized).toBe(true);
        expect(handle.state).toBe('CLOSED');
    });

    it('should cancel timer and zeroize previousHandle on closeSession during PENDING_REKEY', () => {
        const registry = new SessionRegistryImpl({ dualKeyFallbackMs: 30_000 });
        registry.createSession(
            'sid-1',
            'initiator',
            'token-1',
            makeFakeSession(0),
        );
        registry.swapForDualKey('sid-1', makeFakeSession(1, 10));

        const oldHandle = registry._getPreviousHandle('sid-1')!;
        const currentHandle = registry._getCurrentHandle('sid-1')!;

        registry.closeSession('sid-1', 'CLOSED');

        // Both handles should be zeroized
        expect(oldHandle.isZeroized).toBe(true);
        expect(currentHandle.isZeroized).toBe(true);
        // The timer is cancelled: after 30s _expireDualKeyWindow no longer fires (the session no longer exists)
        vi.advanceTimersByTime(30_001);
        // No crash; when the session does not exist, _expireDualKeyWindow gracefully no-ops
    });

    it('should be idempotent: closeSession on nonexistent session is no-op', () => {
        const registry = new SessionRegistryImpl();
        expect(() => {
            registry.closeSession('nonexistent', 'CLOSED');
        }).not.toThrow();
    });

    it('should remove session from registry (size decrements)', () => {
        const registry = new SessionRegistryImpl();
        registry.createSession(
            'sid-1',
            'initiator',
            'token-1',
            makeFakeSession(0),
        );
        registry.createSession(
            'sid-2',
            'responder',
            'token-2',
            makeFakeSession(0, 10),
        );
        expect(registry.size).toBe(2);
        registry.closeSession('sid-1', 'CLOSED');
        expect(registry.size).toBe(1);
    });

    it('should throw SESSION_HANDLE_REVOKED when using stale handle after closeSession', () => {
        const data = makeRealSession();
        const registry = new SessionRegistryImpl();
        registry.createSession('sid-1', 'initiator', 'token-1', data);
        const staleHandle = registry._getCurrentHandle('sid-1')!;

        registry.closeSession('sid-1', 'CLOSED');

        // Calling encrypt on the stale reference (violating Inv 2) should throw
        expect(() =>
            staleHandle.encrypt({ aadFields: TEST_AAD, plaintext: PLAINTEXT }),
        ).toThrowError('SESSION_HANDLE_REVOKED');
    });
});

// ─── Invariant 7: monotonic AEAD nonce increment + reset across rekey ───────────────────────

describe('Invariant 7: monotonic AEAD nonce increment', () => {
    it('should increment sequenceNumber monotonically', () => {
        const data = makeRealSession();
        const handle = new SessionCryptoHandleImpl(
            'sid',
            0,
            'initiator',
            'token-1',
            data.trafficKeys,
            data.sessionSalt,
            data.rekeyChainKey,
            'ACTIVE',
        );

        expect(handle.sequenceNumber).toBe(0n);
        handle.encrypt({ aadFields: TEST_AAD, plaintext: PLAINTEXT });
        expect(handle.sequenceNumber).toBe(1n);
        handle.encrypt({ aadFields: TEST_AAD, plaintext: PLAINTEXT });
        expect(handle.sequenceNumber).toBe(2n);
    });

    it('should produce unique nonces for each encrypt call', () => {
        const data = makeRealSession();
        const handle = new SessionCryptoHandleImpl(
            'sid',
            0,
            'initiator',
            'token-1',
            data.trafficKeys,
            data.sessionSalt,
            data.rekeyChainKey,
            'ACTIVE',
        );

        const nonces: string[] = [];
        for (let i = 0; i < 10; i++) {
            const { aeadNonce } = handle.encrypt({
                aadFields: TEST_AAD,
                plaintext: PLAINTEXT,
            });
            nonces.push(Buffer.from(aeadNonce).toString('hex'));
        }

        // All nonces are unique
        const unique = new Set(nonces);
        expect(unique.size).toBe(10);
    });

    it('should start sequenceNumber at 0 for new PENDING_REKEY handle after swap', () => {
        vi.useFakeTimers();
        const registry = new SessionRegistryImpl({ dualKeyFallbackMs: 30_000 });
        registry.createSession(
            'sid-1',
            'initiator',
            'token-1',
            makeFakeSession(0),
        );

        // First encrypt a few (the old generation's sequenceNumber increments)
        const oldHandle = registry._getCurrentHandle('sid-1')!;
        oldHandle.encrypt({
            aadFields: TEST_AAD,
            plaintext: new Uint8Array(0),
        });
        // Note: encrypt may DECRYPTION FAILED when ACTIVE with an all-zero key; makeRealSession would be more robust here.
        // But this only verifies sequenceNumber, and with fakeSession encrypt may fail due to AES-GCM,
        // so checking the property directly is sufficient.

        // After the swap, the new-generation handle's sequenceNumber should start at 0
        registry.swapForDualKey('sid-1', makeFakeSession(1, 10));
        const newHandle = registry._getCurrentHandle('sid-1')!;
        expect(newHandle.sequenceNumber).toBe(0n);
        vi.useRealTimers();
    });

    it('should produce distinct nonces for initiator and responder (direction byte differs)', () => {
        const data = makeRealSession();
        const initiator = new SessionCryptoHandleImpl(
            'sid',
            0,
            'initiator',
            'token-1',
            data.trafficKeys,
            data.sessionSalt,
            data.rekeyChainKey,
            'ACTIVE',
        );

        const { aeadNonce: n1 } = initiator.encrypt({
            aadFields: TEST_AAD,
            plaintext: PLAINTEXT,
        });
        // direction byte of initiator (init_to_resp = 0x01, per the DIRECTION_BYTE constant)
        // responder direction byte (resp_to_init = 0x02) is verified by the E2E test section
        expect(n1[0]).toBe(0x01); // initiator = init_to_resp = 0x01
    });
});

// ─── Invariant 8: authorizedTokenId is immutable at runtime ────────────────────────────

describe('Invariant 8: authorizedTokenId is immutable at runtime', () => {
    it('should not allow overwriting authorizedTokenId via direct assignment', () => {
        const data = makeFakeSession();
        const handle = new SessionCryptoHandleImpl(
            'sid',
            0,
            'initiator',
            'original-token',
            data.trafficKeys,
            data.sessionSalt,
            data.rekeyChainKey,
        );

        // TypeScript already blocks readonly at compile time; at runtime it is reinforced via Object.defineProperty writable:false
        expect(() => {
            // Cast to any to attempt a runtime modification
            (handle as unknown as Record<string, unknown>)[
                'authorizedTokenId'
            ] = 'hacked';
        }).toThrow(); // throws TypeError under strict mode

        expect(handle.authorizedTokenId).toBe('original-token');
    });

    it('should not allow overwriting authorizedTokenId via Object.defineProperty (configurable:false)', () => {
        const data = makeFakeSession();
        const handle = new SessionCryptoHandleImpl(
            'sid',
            0,
            'initiator',
            'original-token',
            data.trafficKeys,
            data.sessionSalt,
            data.rekeyChainKey,
        );

        expect(() => {
            Object.defineProperty(handle, 'authorizedTokenId', {
                value: 'hacked',
            });
        }).toThrow(TypeError);

        expect(handle.authorizedTokenId).toBe('original-token');
    });

    it('should not allow overwriting sessionId (configurable:false)', () => {
        const data = makeFakeSession();
        const handle = new SessionCryptoHandleImpl(
            'sid-original',
            0,
            'initiator',
            'token',
            data.trafficKeys,
            data.sessionSalt,
            data.rekeyChainKey,
        );

        expect(() => {
            Object.defineProperty(handle, 'sessionId', { value: 'hacked-id' });
        }).toThrow(TypeError);

        expect(handle.sessionId).toBe('sid-original');
    });

    it('should not allow overwriting generation (configurable:false)', () => {
        const data = makeFakeSession();
        const handle = new SessionCryptoHandleImpl(
            'sid',
            5,
            'initiator',
            'token',
            data.trafficKeys,
            data.sessionSalt,
            data.rekeyChainKey,
        );

        expect(() => {
            Object.defineProperty(handle, 'generation', { value: 999 });
        }).toThrow(TypeError);

        expect(handle.generation).toBe(5);
    });

    it('should not allow overwriting role (configurable:false)', () => {
        const data = makeFakeSession();
        const handle = new SessionCryptoHandleImpl(
            'sid',
            0,
            'initiator',
            'token',
            data.trafficKeys,
            data.sessionSalt,
            data.rekeyChainKey,
        );

        expect(() => {
            Object.defineProperty(handle, 'role', { value: 'responder' });
        }).toThrow(TypeError);

        expect(handle.role).toBe('initiator');
    });
});

// ─── Invariant 9/10/11: architectural constraints (caller responsibility; the registry does not participate) ───────────

describe('Invariant 9/10/11: architectural constraints (caller responsibility verification)', () => {
    it('Inv 9: registry does not write ActionRecord (no-op test — architecture constraint)', () => {
        // The registry contains no ActionRecord write logic
        // This test verifies that neither SessionRegistryImpl nor SessionCryptoHandleImpl has any ActionRecord-related methods
        const registry = new SessionRegistryImpl();
        expect(
            (registry as unknown as Record<string, unknown>)[
                'writeActionRecord'
            ],
        ).toBeUndefined();
        expect(
            (registry as unknown as Record<string, unknown>)['afterSend'],
        ).toBeUndefined();
    });

    it('Inv 10: handle does not carry specVersion (version boundary is caller responsibility)', () => {
        const data = makeFakeSession();
        const handle = new SessionCryptoHandleImpl(
            'sid',
            0,
            'initiator',
            'token',
            data.trafficKeys,
            data.sessionSalt,
            data.rekeyChainKey,
        );
        expect(
            (handle as unknown as Record<string, unknown>)['specVersion'],
        ).toBeUndefined();
    });
});

// ─── Invariant 12: no sessionTrustDomain field ────────────────────────────────

describe('Invariant 12: no sessionTrustDomain field', () => {
    it('should not have sessionTrustDomain on SessionCryptoHandleImpl', () => {
        const data = makeFakeSession();
        const handle = new SessionCryptoHandleImpl(
            'sid',
            0,
            'initiator',
            'token',
            data.trafficKeys,
            data.sessionSalt,
            data.rekeyChainKey,
        );
        // sessionTrustDomain does not exist
        expect(
            (handle as unknown as Record<string, unknown>)[
                'sessionTrustDomain'
            ],
        ).toBeUndefined();
    });

    it('should not have sessionTrustDomain on SessionRegistryImpl', () => {
        const registry = new SessionRegistryImpl();
        expect(
            (registry as unknown as Record<string, unknown>)[
                'sessionTrustDomain'
            ],
        ).toBeUndefined();
    });

    it('should not have sessionTrustDomain on registry entry (internal check)', () => {
        const registry = new SessionRegistryImpl();
        registry.createSession(
            'sid-1',
            'initiator',
            'token-1',
            makeFakeSession(0),
        );
        const handle = registry._getCurrentHandle('sid-1')!;
        expect(
            (handle as unknown as Record<string, unknown>)[
                'sessionTrustDomain'
            ],
        ).toBeUndefined();
    });
});

// ─── Invariant 13: concurrent rekey trigger handling ──────────────────────────────────────

describe('Invariant 13: calling rekey again during PENDING_REKEY throws REKEY_FAILED', () => {
    beforeEach(() => {
        vi.useFakeTimers();
    });

    afterEach(() => {
        vi.useRealTimers();
    });

    it('should throw REKEY_FAILED when rekey called on PENDING_REKEY handle', () => {
        const data = makeFakeSession();
        const handle = new SessionCryptoHandleImpl(
            'sid',
            1,
            'initiator',
            'token-1',
            data.trafficKeys,
            data.sessionSalt,
            data.rekeyChainKey,
            'PENDING_REKEY',
        );
        expect(() => handle.rekey('chain_key')).toThrowError('REKEY_FAILED');
        expect(() => handle.rekey('full_handshake_required')).toThrowError(
            'REKEY_FAILED',
        );
    });

    it('should throw SESSION_HANDLE_REVOKED when rekey called on CLOSED handle', () => {
        const data = makeFakeSession();
        const handle = new SessionCryptoHandleImpl(
            'sid',
            0,
            'initiator',
            'token-1',
            data.trafficKeys,
            data.sessionSalt,
            data.rekeyChainKey,
            'CLOSED',
        );
        expect(() => handle.rekey('chain_key')).toThrowError(
            'SESSION_HANDLE_REVOKED',
        );
    });

    it('should throw SESSION_HANDLE_REVOKED when rekey called on REVOKED handle', () => {
        const data = makeFakeSession();
        const handle = new SessionCryptoHandleImpl(
            'sid',
            0,
            'initiator',
            'token-1',
            data.trafficKeys,
            data.sessionSalt,
            data.rekeyChainKey,
            'REVOKED',
        );
        expect(() => handle.rekey('chain_key')).toThrowError(
            'SESSION_HANDLE_REVOKED',
        );
    });

    it('should not throw when rekey called on ACTIVE handle', () => {
        const data = makeFakeSession();
        const handle = new SessionCryptoHandleImpl(
            'sid',
            0,
            'initiator',
            'token-1',
            data.trafficKeys,
            data.sessionSalt,
            data.rekeyChainKey,
            'ACTIVE',
        );
        expect(() => handle.rekey('chain_key')).not.toThrow();
        expect(() => handle.rekey('full_handshake_required')).not.toThrow();
    });

    it('should remain in PENDING_REKEY after second swapForDualKey (idempotent = state unchanged)', () => {
        const registry = new SessionRegistryImpl({ dualKeyFallbackMs: 30_000 });
        registry.createSession(
            'sid-1',
            'initiator',
            'token-1',
            makeFakeSession(0),
        );
        registry.swapForDualKey('sid-1', makeFakeSession(1, 10));

        const firstNewHandle = registry._getCurrentHandle('sid-1')!;
        expect(firstNewHandle.generation).toBe(1);
        expect(firstNewHandle.state).toBe('PENDING_REKEY');

        // Second swapForDualKey (idempotent no-op)
        registry.swapForDualKey('sid-1', makeFakeSession(2, 20));

        const sameHandle = registry._getCurrentHandle('sid-1')!;
        // Still the handle from the first swap (generation 1)
        expect(sameHandle.generation).toBe(1);
        expect(sameHandle.state).toBe('PENDING_REKEY');
    });

    it('should allow rekey after 30s window expires (ACTIVE state restored)', () => {
        const registry = new SessionRegistryImpl({ dualKeyFallbackMs: 30_000 });
        registry.createSession(
            'sid-1',
            'initiator',
            'token-1',
            makeFakeSession(0),
        );
        registry.swapForDualKey('sid-1', makeFakeSession(1, 10));

        // The 30s window ends
        vi.advanceTimersByTime(30_001);

        const handle = registry._getCurrentHandle('sid-1')!;
        expect(handle.state).toBe('ACTIVE');

        // In the ACTIVE state, rekey can be called again (chain_key)
        expect(() => handle.rekey('chain_key')).not.toThrow();
    });
});

// ─── zeroize idempotence tests ─────────────────────────────────────────────────────────

describe('SessionCryptoHandleImpl.zeroize idempotence', () => {
    it('should be idempotent: multiple zeroize calls do not throw', () => {
        const data = makeFakeSession();
        const handle = new SessionCryptoHandleImpl(
            'sid',
            0,
            'initiator',
            'token',
            data.trafficKeys,
            data.sessionSalt,
            data.rekeyChainKey,
        );
        handle.zeroize();
        handle.zeroize(); // the second call should not throw
        expect(handle.isZeroized).toBe(true);
        expect(handle.state).toBe('CLOSED');
    });

    it('should set all key bytes to 0 after zeroize', () => {
        const data = makeFakeSession(0, 5); // non-zero values such as fill(6), fill(7)
        const handle = new SessionCryptoHandleImpl(
            'sid',
            0,
            'initiator',
            'token',
            data.trafficKeys,
            data.sessionSalt,
            data.rekeyChainKey,
        );

        // Verify the keys are initially non-zero
        const keys = handle.getTrafficKeys();
        expect(keys.initToResp[0]).toBe(6); // seed=5, fill(5+1)=6

        handle.zeroize();

        // After zeroize, the getTrafficKeys reference (captured before zeroize) should now be all zeros
        expect(keys.initToResp.every((b) => b === 0)).toBe(true);
        expect(keys.respToInit.every((b) => b === 0)).toBe(true);
    });
});

// ─── swapForDualKeyChainMode integration tests ───────────────────────────────────────

describe('swapForDualKeyChainMode: chain-key rekey derivation', () => {
    beforeEach(() => {
        vi.useFakeTimers();
    });

    afterEach(() => {
        vi.useRealTimers();
    });

    it('should derive new generation handle with different traffic keys', () => {
        const data = makeRealSession(0);
        const registry = new SessionRegistryImpl({ dualKeyFallbackMs: 30_000 });
        registry.createSession('sid-1', 'initiator', 'token-1', data);

        const oldKeys = registry._getCurrentHandle('sid-1')!.getTrafficKeys();
        const oldInitToResp = Buffer.from(oldKeys.initToResp).toString('hex');

        registry.swapForDualKeyChainMode('sid-1');

        const newHandle = registry._getCurrentHandle('sid-1')!;
        const newKeys = newHandle.getTrafficKeys();
        const newInitToResp = Buffer.from(newKeys.initToResp).toString('hex');

        // The new generation's traffic keys differ from the old generation's (HKDF derivation)
        expect(newInitToResp).not.toBe(oldInitToResp);
        // The new generation is 1
        expect(newHandle.generation).toBe(1);
    });

    it('should encrypt/decrypt correctly across chain-key rekey', () => {
        // After the Initiator and Responder each perform a chain-key rekey, they can communicate normally
        const data = makeRealSession(0);

        // Initiator-side registry
        const iRegistry = new SessionRegistryImpl({
            dualKeyFallbackMs: 30_000,
        });
        iRegistry.createSession('sid-1', 'initiator', 'token-1', data);

        // Responder-side registry (sharing the same key material)
        const rRegistry = new SessionRegistryImpl({
            dualKeyFallbackMs: 30_000,
        });
        rRegistry.createSession('sid-1', 'responder', 'token-1', data);

        // Both sides perform the chain-key rekey in sync
        iRegistry.swapForDualKeyChainMode('sid-1');
        rRegistry.swapForDualKeyChainMode('sid-1');

        // Wait for the 30s window
        vi.advanceTimersByTime(30_001);

        // Initiator encrypts with the new generation
        const iHandle = iRegistry.lookupHandle('sid-1')!;
        expect(iHandle.state).toBe('ACTIVE');
        const { ciphertext, aeadNonce, keyId } = iHandle.encrypt({
            aadFields: TEST_AAD,
            plaintext: PLAINTEXT,
        });

        // Responder routes by keyId and decrypts
        const rHandle = rRegistry.lookupHandleForDecrypt('sid-1', keyId)!;
        expect(rHandle).not.toBeNull();
        const decrypted = rHandle.decrypt({
            aadFields: TEST_AAD,
            ciphertext,
            aeadNonce,
        });

        expect(decrypted).toEqual(PLAINTEXT);
    });
});

// ─── keyId computation consistency tests ────────────────────────────────────────────────────

describe('keyId computation consistency', () => {
    it('should compute different keyIds for different directions (initiator vs responder)', () => {
        const data = makeRealSession(0);
        const initiator = new SessionCryptoHandleImpl(
            'sid',
            0,
            'initiator',
            'token-1',
            data.trafficKeys,
            data.sessionSalt,
            data.rekeyChainKey,
            'ACTIVE',
        );
        const responder = new SessionCryptoHandleImpl(
            'sid',
            0,
            'responder',
            'token-1',
            data.trafficKeys,
            data.sessionSalt,
            data.rekeyChainKey,
            'ACTIVE',
        );

        // initiator.keyId (own = init_to_resp key) should equal responder.peerKeyId (peer = init_to_resp key)
        expect(initiator.keyId).toBe(responder.peerKeyId);
        // responder.keyId (own = resp_to_init key) should equal initiator.peerKeyId (peer = resp_to_init key)
        expect(responder.keyId).toBe(initiator.peerKeyId);
    });

    it('should have 32 hex chars (16 bytes) keyId', () => {
        const data = makeRealSession(0);
        const handle = new SessionCryptoHandleImpl(
            'sid',
            0,
            'initiator',
            'token-1',
            data.trafficKeys,
            data.sessionSalt,
            data.rekeyChainKey,
        );
        expect(handle.keyId).toHaveLength(32);
        expect(handle.keyId).toMatch(/^[0-9a-f]{32}$/);
    });

    it('should compute different keyIds for different generations', () => {
        const data0 = makeRealSession(0);
        const data1 = makeRealSession(1);
        const h0 = new SessionCryptoHandleImpl(
            'sid',
            0,
            'initiator',
            'token',
            data0.trafficKeys,
            data0.sessionSalt,
            data0.rekeyChainKey,
        );
        const h1 = new SessionCryptoHandleImpl(
            'sid',
            1,
            'initiator',
            'token',
            data1.trafficKeys,
            data1.sessionSalt,
            data1.rekeyChainKey,
        );
        // Different keys produce different keyIds (note: even the same key at different generations differs, because generation is part of the computation)
        expect(h0.keyId).not.toBe(h1.keyId);
    });
});

// ─── Full encrypt → decrypt round-trip tests ────────────────────────────────────────

describe('end-to-end encrypt/decrypt round-trip', () => {
    it('should correctly encrypt and decrypt using registry', () => {
        const data = makeRealSession(0);
        const iRegistry = new SessionRegistryImpl();
        const rRegistry = new SessionRegistryImpl();

        iRegistry.createSession('sid-1', 'initiator', 'token-1', data);
        rRegistry.createSession('sid-1', 'responder', 'token-1', data);

        // Initiator encrypts
        const iHandle = iRegistry.lookupHandle('sid-1')!;
        const { ciphertext, aeadNonce, keyId } = iHandle.encrypt({
            aadFields: TEST_AAD,
            plaintext: PLAINTEXT,
        });

        // Responder routes by keyId and decrypts
        const rHandle = rRegistry.lookupHandleForDecrypt('sid-1', keyId)!;
        expect(rHandle).not.toBeNull();

        const decrypted = rHandle.decrypt({
            aadFields: TEST_AAD,
            ciphertext,
            aeadNonce,
        });

        expect(decrypted).toEqual(PLAINTEXT);
    });

    it('should reject decryption with wrong AAD', () => {
        const data = makeRealSession(0);
        const initiator = new SessionCryptoHandleImpl(
            'sid',
            0,
            'initiator',
            'token-1',
            data.trafficKeys,
            data.sessionSalt,
            data.rekeyChainKey,
        );
        const responder = new SessionCryptoHandleImpl(
            'sid',
            0,
            'responder',
            'token-1',
            data.trafficKeys,
            data.sessionSalt,
            data.rekeyChainKey,
        );

        const { ciphertext, aeadNonce } = initiator.encrypt({
            aadFields: TEST_AAD,
            plaintext: PLAINTEXT,
        });

        // Use a different envelopeId on decrypt (AAD mismatch)
        expect(() =>
            responder.decrypt({
                aadFields: { ...TEST_AAD, envelopeId: 'tampered-envelope-id' },
                ciphertext,
                aeadNonce,
            }),
        ).toThrowError('DECRYPTION_FAILED');
    });

    it('should encrypt/decrypt correctly for responder role (respToInit branch)', () => {
        // Covers crypto-state.ts:207 / 269 — the respToInit branch
        const data = makeRealSession(0);
        const responder = new SessionCryptoHandleImpl(
            'sid',
            0,
            'responder',
            'token-1',
            data.trafficKeys,
            data.sessionSalt,
            data.rekeyChainKey,
            'ACTIVE',
        );
        const initiator = new SessionCryptoHandleImpl(
            'sid',
            0,
            'initiator',
            'token-1',
            data.trafficKeys,
            data.sessionSalt,
            data.rekeyChainKey,
            'ACTIVE',
        );

        // responder encrypt (uses the respToInit key, direction 0x02)
        const { ciphertext, aeadNonce } = responder.encrypt({
            aadFields: TEST_AAD,
            plaintext: PLAINTEXT,
        });
        expect(aeadNonce[0]).toBe(0x02); // resp_to_init direction byte

        // initiator decrypt (receives a message in the respToInit direction)
        const plaintext = initiator.decrypt({
            aadFields: TEST_AAD,
            ciphertext,
            aeadNonce,
        });
        expect(plaintext).toEqual(PLAINTEXT);
    });
});

// ─── Supplementary coverage tests (swapForDualKeyChainMode + _isPendingRekey) ────────────────

describe('coverage supplement: swapForDualKeyChainMode idempotence + _isPendingRekey', () => {
    beforeEach(() => {
        vi.useFakeTimers();
    });

    afterEach(() => {
        vi.useRealTimers();
    });

    it('should be idempotent: swapForDualKeyChainMode no-op when PENDING_REKEY (line 251-252)', () => {
        const data = makeRealSession(0);
        const registry = new SessionRegistryImpl({ dualKeyFallbackMs: 30_000 });
        registry.createSession('sid-1', 'initiator', 'token-1', data);

        // First swap trigger
        registry.swapForDualKeyChainMode('sid-1');
        const firstGenHandle = registry._getCurrentHandle('sid-1')!;
        expect(firstGenHandle.generation).toBe(1);
        expect(firstGenHandle.state).toBe('PENDING_REKEY');

        // Second call: hits line 251-252 (PENDING_REKEY early return)
        registry.swapForDualKeyChainMode('sid-1');
        const stillSame = registry._getCurrentHandle('sid-1')!;
        expect(stillSame.generation).toBe(1); // did not become 2
    });

    it('should return true from _isPendingRekey when handle is in PENDING_REKEY (line 320-321)', () => {
        const registry = new SessionRegistryImpl({ dualKeyFallbackMs: 30_000 });
        registry.createSession(
            'sid-1',
            'initiator',
            'token-1',
            makeFakeSession(0),
        );

        expect(registry._isPendingRekey('sid-1')).toBe(false);

        registry.swapForDualKey('sid-1', makeFakeSession(1, 10));
        expect(registry._isPendingRekey('sid-1')).toBe(true); // covers line 320-321

        expect(registry._isPendingRekey('nonexistent')).toBe(false);
    });
});
