/**
 * E2E encryption primitives
 *
 * - X25519 ECDH key agreement (@noble/curves/ed25519 x25519)
 * - HKDF-SHA-256 key derivation (@noble/hashes/hkdf)
 * - AES-256-GCM encryption/decryption (@noble/ciphers/aes)
 * - transcript_hash computation (16-field RFC 8785 + SHA-256)
 * - keyId computation (hex of the first 16 bytes of SHA-256)
 *
 * @frozen
 */

import { gcm } from '@noble/ciphers/aes';
import { x25519 } from '@noble/curves/ed25519';
import { extract, expand } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';

import { canonicalize } from './canonicalization.js';
import { toHex } from './encoding.js';

// ─── HKDF Labels (full set) ────────────────────────────────────────────

const HKDF_LABELS = {
    INIT_TO_RESP_KEY: 'ap/e2e/v1/traffic/init->resp/key',
    RESP_TO_INIT_KEY: 'ap/e2e/v1/traffic/resp->init/key',
    SESSION_SALT: 'ap/e2e/v1/nonce/session-salt',
    REKEY_CHAIN: 'ap/e2e/v1/rekey/chain-key',
    TRANSCRIPT_BINDING: 'ap/e2e/v1/handshake/transcript-binding',
} as const;

const textEncoder = new TextEncoder();

// ─── X25519 key pair (per-session ephemeral) ──────────────────────────────────

/**
 * Generates an X25519 ephemeral key pair.
 * The private key must be kept in memory, persistence is forbidden.
 */
export function generateEphemeralX25519KeyPair(): {
    secretKey: Uint8Array;
    publicKey: Uint8Array;
} {
    const secretKey = x25519.utils.randomSecretKey();
    const publicKey = x25519.getPublicKey(secretKey);
    return { secretKey, publicKey };
}

/**
 * X25519 ECDH shared secret.
 *
 * All-zero public key (small-subgroup attack) check: the caller must verify R_epk is not all-zero
 * at the handshake layer; here only the low-level DH is performed, no security check is done
 * (the security check resides in the L4 handshake layer).
 */
export function computeX25519SharedSecret(
    mySecretKey: Uint8Array,
    theirPublicKey: Uint8Array,
): Uint8Array {
    return x25519.getSharedSecret(mySecretKey, theirPublicKey);
}

// ─── transcript_hash ────────────────────────────────────────────────

/**
 * transcript_hash 16-field object (canonical field set, order determined by RFC 8785 lexicographic sort)
 */
export interface TranscriptHashInput {
    protocolVersion: 'ap/e2e/v1';
    initiatorDid: string;
    responderDid: string;
    initiatorCapabilities: string[];
    responderCapabilities: string[];
    initiatorPreference: 'OFF' | 'OPT_IN' | 'REQUIRED';
    responderPreference: 'OFF' | 'OPT_IN' | 'REQUIRED';
    negotiatedEncryptionMode: 'OFF' | 'REQUIRED';
    I_epk: string; // hex or base64url
    R_epk: string; // hex or base64url
    nonce: string; // HandshakeChallenge.nonce
    initTimestamp: string;
    responseTimestamp: string;
    authorizedPrincipalDid: string;
    /** null → canonical JSON literal "null"*/
    authorizedTokenId: string | null;
    authorizedTokenFingerprint: string;
}

/**
 * Computes transcript_hash.
 * SHA-256(canonicalize(16-field object)); the result is used as the salt for HKDF-Extract.
 */
export function computeTranscriptHash(input: TranscriptHashInput): Uint8Array {
    // canonicalize implements RFC 8785 (lexicographic sort + normalization)
    const jsonStr = canonicalize(input as unknown as Record<string, unknown>);
    return sha256(textEncoder.encode(jsonStr));
}

// ─── HKDF key derivation ──────────────────────────────────────────────────

export interface DerivedSessionKeys {
    /** AES-256-GCM key for initiator → responder direction (32B)*/
    initToResp: Uint8Array;
    /** AES-256-GCM key for responder → initiator direction (32B)*/
    respToInit: Uint8Array;
    /** Session salt (4B) for nonce construction*/
    sessionSalt: Uint8Array;
    /** Rekey chain key (32B) for chain-key rekey path*/
    rekeyChainKey: Uint8Array;
}

/**
 * Derives all session keys from the ECDH shared secret + transcript_hash.
 *
 * Steps:
 *   PRK = HKDF-Extract(salt=transcript_hash, ikm=shared_secret)
 *   k_init_to_resp = HKDF-Expand(PRK, label=INIT_TO_RESP_KEY, L=32)
 *   k_resp_to_init = HKDF-Expand(PRK, label=RESP_TO_INIT_KEY, L=32)
 *   session_salt = HKDF-Expand(PRK, label=SESSION_SALT, L=4)
 *   rekey_chain = HKDF-Expand(PRK, label=REKEY_CHAIN, L=32)
 */
export function deriveSessionKeys(
    sharedSecret: Uint8Array,
    transcriptHash: Uint8Array,
): DerivedSessionKeys {
    const prk = extract(sha256, sharedSecret, transcriptHash);

    const initToResp = expand(
        sha256,
        prk,
        textEncoder.encode(HKDF_LABELS.INIT_TO_RESP_KEY),
        32,
    );
    const respToInit = expand(
        sha256,
        prk,
        textEncoder.encode(HKDF_LABELS.RESP_TO_INIT_KEY),
        32,
    );
    const sessionSalt = expand(
        sha256,
        prk,
        textEncoder.encode(HKDF_LABELS.SESSION_SALT),
        4,
    );
    const rekeyChainKey = expand(
        sha256,
        prk,
        textEncoder.encode(HKDF_LABELS.REKEY_CHAIN),
        32,
    );

    return { initToResp, respToInit, sessionSalt, rekeyChainKey };
}

/**
 * chain-key rekey derivation.
 * Only used for the sequenceNumber >= 2^63 scenario.
 * new key = HKDF-Expand(HKDF-Extract(salt=prevRekeyChainKey, ikm=prevRekeyChainKey), label=REKEY_CHAIN, L=32)
 *
 * Note: chain-key rekey does not provide post-compromise security and does not change session_salt.
 */
export function deriveChainKeyRekeyKeys(
    prevRekeyChainKey: Uint8Array,
    prevInitToResp: Uint8Array,
    prevRespToInit: Uint8Array,
): {
    initToResp: Uint8Array;
    respToInit: Uint8Array;
    rekeyChainKey: Uint8Array;
} {
    // run HKDF-Extract with the previous-generation chain key as both salt + ikm
    const prk = extract(sha256, prevRekeyChainKey, prevRekeyChainKey);

    const initToResp = expand(
        sha256,
        prk,
        textEncoder.encode(HKDF_LABELS.INIT_TO_RESP_KEY),
        32,
    );
    const respToInit = expand(
        sha256,
        prk,
        textEncoder.encode(HKDF_LABELS.RESP_TO_INIT_KEY),
        32,
    );
    const rekeyChainKey = expand(
        sha256,
        prk,
        textEncoder.encode(HKDF_LABELS.REKEY_CHAIN),
        32,
    );

    // prevent the caller from accidentally reusing previous-generation traffic keys (zeroize semantics are the caller's responsibility)
    void prevInitToResp;
    void prevRespToInit;

    return { initToResp, respToInit, rekeyChainKey };
}

// ─── keyId computation ────────────────────────────────────────────────────

/**
 * Computes keyId: SHA-256(k_direction || generation_BE_8B)[0:16] hex (32 hex chars).
 *
 * generation is serialized as 8 bytes big-endian (the uint64 range is sufficient; JS Number 53-bit precision is lossless at realistic generation counts).
 */
export function computeKeyId(
    directionKey: Uint8Array,
    generation: number,
): string {
    const genBytes = new Uint8Array(8);
    const view = new DataView(genBytes.buffer);
    // JS Number max safe integer is 2^53-1, so generation will not overflow
    view.setUint32(0, Math.floor(generation / 0x1_0000_0000), false);
    view.setUint32(4, generation >>> 0, false);

    const input = new Uint8Array(directionKey.length + 8);
    input.set(directionKey, 0);
    input.set(genBytes, directionKey.length);

    const digest = sha256(input);
    // take the first 16 bytes (128 bit), providing a 2^64 birthday-collision budget
    return toHex(digest.slice(0, 16));
}

// ─── AEAD Nonce construction ────────────────────────────────────────────────

/**
 * direction byte mapping: init_to_resp = 0x01, resp_to_init = 0x02.
 */
const DIRECTION_BYTE: Record<'init_to_resp' | 'resp_to_init', number> = {
    init_to_resp: 0x01,
    resp_to_init: 0x02,
};

/**
 * Constructs a 12B AEAD nonce (Invariant 7):
 *   directionByte (1B) || sequenceNumber (8B BE) || sessionSalt[0..2] (3B) = 12B
 */
export function buildAeadNonce(
    direction: 'init_to_resp' | 'resp_to_init',
    sequenceNumber: bigint,
    sessionSalt: Uint8Array,
): Uint8Array {
    const nonce = new Uint8Array(12);
    const view = new DataView(nonce.buffer);

    nonce[0] = DIRECTION_BYTE[direction];

    // sequenceNumber 8B BE
    const hi = Number(sequenceNumber >> 32n);
    const lo = Number(sequenceNumber & 0xffffffffn);
    view.setUint32(1, hi, false);
    view.setUint32(5, lo, false);

    // sessionSalt[0..2] 3B
    nonce[9] = sessionSalt[0] ?? 0;
    nonce[10] = sessionSalt[1] ?? 0;
    nonce[11] = sessionSalt[2] ?? 0;

    return nonce;
}

// ─── AAD field set (8 fields, non-expandable) ──────────────────────────────────

/**
 * AAD construction parameters used internally by the handle (does not expose tokenId/sessionId write access to the business layer).
 */
export interface AeadAadParams {
    /** from the business layer AeadAadFields*/
    envelopeId: string;
    messageType: string;
    aadSummary?: Record<string, unknown>;
    /** message direction (encrypt = ownDirection, decrypt = peerDirection)*/
    direction: 'init_to_resp' | 'resp_to_init';
    /** from inside the handle*/
    keyId: string;
    sequenceNumber: bigint;
    sessionId: string;
    tokenId: string | null;
}

/**
 * Constructs the AAD bytes (8 fields, RFC 8785 lexicographic canonicalize).
 * Note: any expansion is treated as a breaking-format-change.
 */
export function buildAeadBytes(params: AeadAadParams): Uint8Array {
    const aadObj: Record<string, unknown> = {
        aadSummary: params.aadSummary ?? null,
        direction: params.direction,
        envelopeId: params.envelopeId,
        keyId: params.keyId,
        messageType: params.messageType,
        sequenceNumber: params.sequenceNumber.toString(),
        sessionId: params.sessionId,
        tokenId: params.tokenId,
    };

    const jsonStr = canonicalize(aadObj);
    return textEncoder.encode(jsonStr);
}

// ─── AES-256-GCM encryption / decryption ──────────────────────────────────────────────────

/**
 * AES-256-GCM encryption (includes the GCM authentication tag, a 16B tag appended at the end of the ciphertext).
 */
export function aeadEncrypt(
    key: Uint8Array,
    nonce: Uint8Array,
    aad: Uint8Array,
    plaintext: Uint8Array,
): Uint8Array {
    const cipher = gcm(key, nonce, aad);
    return cipher.encrypt(plaintext);
}

/**
 * AES-256-GCM decryption.
 * When tag verification fails, @noble/ciphers throws an Error; the caller should catch it and convert it to DECRYPTION_FAILED.
 */
export function aeadDecrypt(
    key: Uint8Array,
    nonce: Uint8Array,
    aad: Uint8Array,
    ciphertext: Uint8Array,
): Uint8Array {
    const cipher = gcm(key, nonce, aad);
    return cipher.decrypt(ciphertext);
}

// ─── direction-semantics helpers ─────────────────────────────────────────────────────────

/**
 * Given handle.role, returns the direction used when encrypting (= own direction).
 */
export function ownDirection(
    role: 'initiator' | 'responder',
): 'init_to_resp' | 'resp_to_init' {
    return role === 'initiator' ? 'init_to_resp' : 'resp_to_init';
}

/**
 * Given handle.role, returns the direction used when decrypting (= peer direction).
 */
export function peerDirection(
    role: 'initiator' | 'responder',
): 'init_to_resp' | 'resp_to_init' {
    return role === 'initiator' ? 'resp_to_init' : 'init_to_resp';
}
