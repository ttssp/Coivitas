/**
 * wallet-interface type definitions
 *
 * Design conventions:
 * - WalletResult<T> = a fail-closed union type; all methods return this type and never throw.
 * - RecoverResult does not contain didMatch (R4 C1: on DID mismatch, abort before writing to disk and return WALLET_RECOVERY_DID_MISMATCH).
 * - When currentShardVersion is omitted, recoverFromShares returns WALLET_RECOVERY_VERSION_UNVERIFIED (stub behavior).
 */

import type { DID, Signature, Timestamp } from '@coivitas/types';

import type { WalletErrorCode } from './errors.js';

// ── Base types ────────────────────────────────────────────────────────────────

/** Wallet-internal key identifier (opaque branded string). */
export type WalletKeyId = string & { readonly __brand: 'WalletKeyId' };

/** Wallet operation result (fail-closed design; never throws). */
export type WalletResult<T> =
    | { ok: true; value: T }
    | { ok: false; error: WalletError };

/** Wallet error. */
export interface WalletError {
    code: WalletErrorCode;
    message: string;
    /** Optional: underlying platform error (WebAuthn DOMException, etc.). */
    cause?: unknown;
}

/** Wallet state. */
export type WalletState =
    | 'LOCKED'
    | 'UNLOCKED'
    | 'RECOVERING'
    | 'UNINITIALIZED';

// ── createKey ───────────────────────────────────────────────────────────────

export interface CreateKeyParams {
    /** Optional human-friendly label. */
    label?: string;
    /** Key storage-level hint. */
    storageHint?: 'platform' | 'roaming' | 'software';
}

export interface CreateKeyResult {
    keyId: WalletKeyId;
    publicKey: string; // 64-char hex Ed25519
    /** Creation time. */
    createdAt: Timestamp;
}

// ── getPublicKey ─────────────────────────────────────────────────────────────

export interface GetPublicKeyResult {
    keyId: WalletKeyId;
    publicKey: string; // 64-char hex Ed25519
}

// ── listKeys ─────────────────────────────────────────────────────────────────

export interface WalletKeyInfo {
    keyId: WalletKeyId;
    label?: string;
    createdAt: Timestamp;
    storageType: 'platform' | 'roaming' | 'software';
    /** Whether this key is the current default signing key. */
    isDefault: boolean;
}

// ── signSessionAuth (Hot Passkey path; R3 split) ────────────────────────────

export interface SignSessionAuthParams {
    payload: Uint8Array;
    keyId?: WalletKeyId;
}

/**
 * WebAuthn assertion triple — Hot Passkey path output.
 *
 * Key point: in the TypeScript type system this type is fully incompatible with Signature
 * (128-char hex Ed25519); attempting to assign a WebAuthnAssertionResult to a Signature field fails to compile.
 * This enforces the D1 "Hot/Cold path separation" design promise at compile time.
 */
export interface WebAuthnAssertionResult {
    /** Passkey credential ID. */
    credentialId: string;
    /** WebAuthn clientDataJSON (base64url). */
    clientDataJSON: string;
    /** WebAuthn authenticatorData (base64url). */
    authenticatorData: string;
    /** WebAuthn signature (base64url; may be ECDSA P-256 or Ed25519, depending on the platform authenticator). */
    signature: string;
    /** Key ID. */
    keyId: WalletKeyId;
    /** Signing moment. */
    signedAt: Timestamp;
}

// ── signCold (Cold Ed25519 path; R3 split) ──────────────────────────────────

/**
 * signCold operation type — the caller must explicitly declare its purpose.
 *
 * Purpose: the wallet UX presents different unlock prompts based on operationType; the adapter implementation can record audit entries.
 */
export type SignColdOperationType =
    | 'ROTATION_PROOF' // RotationProof.principalSignature
    | 'BINDING_PROOF' // BindingProof.signature
    | 'DEACTIVATION_PROOF'; // identity spec deactivation

export interface SignColdParams {
    payload: Uint8Array;
    operationType: SignColdOperationType;
    keyId?: WalletKeyId;
}

export interface SignColdResult {
    signature: Signature; // 128-char hex Ed25519 (matches what the key-rotation spec expects)
    keyId: WalletKeyId;
    signedAt: Timestamp;
    /** Echoes operationType (for the audit trail). */
    operationType: SignColdOperationType;
}

// ── encrypt / decrypt ────────────────────────────────────────────────────────

export interface EncryptParams {
    plaintext: Uint8Array;
    /** Optional: specify the encryption key ID; if omitted, the Passkey PRF-derived key is used. */
    keyId?: WalletKeyId;
}

export interface EncryptResult {
    ciphertext: Uint8Array;
    /** 24-byte nonce (required by XChaCha20). */
    nonce: Uint8Array;
    /** Algorithm identifier. */
    algorithm: 'xchacha20-poly1305';
}

export interface DecryptParams {
    ciphertext: Uint8Array;
    nonce: Uint8Array;
    keyId?: WalletKeyId;
}

export interface DecryptResult {
    plaintext: Uint8Array;
}

// ── Recovery ─────────────────────────────────────────────────────────────────

/**
 * RecipientShare — discriminated union of share recipients
 *
 * Topology design: a typical (2, 3) topology = 1 local Passkey + 1 hardware key + 1 Guardian.
 */
export type RecipientShare =
    | {
          kind: 'local';
          /** Local Passkey credential ID (used to derive the encryption key via the PRF extension). */
          credentialId: string;
      }
    | {
          kind: 'hardware';
          /** Hardware key identifier (e.g. a Yubikey serial or hardware token ID). */
          deviceId: string;
          /** The hardware key's wrapping public key (X25519, 64-char hex). */
          wrappingPublicKey: string;
      }
    | {
          kind: 'guardian';
          /** The Guardian's X25519 wrapping public key (64-char hex). */
          guardianPublicKey: string;
          /** Guardian identifier (a natural person or device alias; for UX display). */
          guardianLabel?: string;
      };

export interface CreateRecoverySharesParams {
    /** Minimum number of shares required to reconstruct (M); enforced >= 2. */
    threshold: number;
    /** Total number of shares (N); enforced >= 3 and >= threshold; must === recipients.length. */
    totalShares: number;
    /**
     * Share-recipient topology
     *
     * The length must === totalShares. recipients[i] determines the encryption method and ownership of share i.
     */
    recipients: RecipientShare[];
}

/** A single recovery share (already encrypted). */
export interface RecoveryShare {
    /** Share index (1-indexed). */
    index: number;
    /** Encrypted share data. */
    encryptedShare: Uint8Array;
    /** Nonce used for encryption. */
    nonce: Uint8Array;
    /** Corresponding recipient info (R3: copied from RecipientShare; identifies which recipient can decrypt). */
    recipient: RecipientShare;
    /** Share fingerprint (SHA-256 of the plaintext share, used for integrity checking). */
    shareFingerprint: string;
    /**
     * Share version number (incrementing) — added in R3
     *
     * Incremented by 1 after each rotateRecoverySecret() call.
     * The recovery flow only accepts shares with version >= currentVersion.
     */
    shardVersion: number;
}

export interface RecoverFromSharesParams {
    /** Collected decrypted shares (at least M). */
    shares: DecryptedShare[];
    /** The did:key expected to be recovered (used to validate the reconstruction result). */
    expectedDid: DID;
    /**
     * The latest known shardVersion.
     *
     * Stub behavior: when omitted, returns WALLET_RECOVERY_VERSION_UNVERIFIED (fail-closed).
     * Once the production implementation closes the loop by externalizing version provenance, this can adopt "omitted means 0" semantics.
     */
    currentShardVersion?: number;
}

/**
 * Decrypted share
 *
 * R3 adds shardVersion so the recovery flow can reject outdated share versions.
 */
export interface DecryptedShare {
    index: number;
    shareData: Uint8Array;
    /**
     * Share version number (aligned with RecoveryShare.shardVersion)
     *
     * recoverFromShares enforces min(shares.shardVersion) >= currentShardVersion,
     * otherwise WALLET_RECOVERY_STALE_SHARE (D2).
     */
    shardVersion: number;
}

/**
 * RecoverResult — the return value after a successful recovery (R4 C1: no didMatch field)
 *
 * R4 revision: removes the didMatch field (R3's soft-success violated fail-closed).
 * On DID mismatch, the implementation layer aborts before writing to disk and returns WALLET_RECOVERY_DID_MISMATCH.
 */
export interface RecoverResult {
    /** The new keyId generated after recovery (the private key is already in secure storage; returned only on DID match). */
    keyId: WalletKeyId;
    /** The recovered public key. */
    publicKey: string;
    /** The share version actually used for recovery (min(shares.shardVersion); R3 audit trail). */
    recoveredShardVersion: number;
}

// ── proveOwnership ───────────────────────────────────────────────────────────

export interface ProveOwnershipParams {
    keyId?: WalletKeyId;
    /** Optional challenge (provided by the verifier to prevent replay). */
    challenge?: Uint8Array;
}

/**
 * WalletStateProof — wallet ownership proof
 *
 * Proves the caller holds the signing capability for some key at this moment.
 * This proof is used only internally between wallet and identity; it does not enter the envelope/token wire format.
 */
export interface WalletStateProof {
    keyId: WalletKeyId;
    publicKey: string;
    /** Signing payload = canonicalize({ keyId, publicKey, timestamp, challenge? }). */
    signature: Signature;
    timestamp: Timestamp;
    challenge?: Uint8Array;
}

// ── rotateRecoverySecret ─────────────────────────────────────────────────────

export interface RotateRecoverySecretParams {
    /**
     * New share-recipient topology (R3: changed from guardianPublicKeys[] to a RecipientShare[] union)
     *
     * The length must === newTopology?.totalShares ?? currentTotalShares.
     */
    recipients: RecipientShare[];
    /** Optional: override the current (M, N) topology; if omitted, the existing configuration is reused. */
    newTopology?: { threshold: number; totalShares: number };
}

// ── setRecoveryTopology ──────────────────────────────────────────────────────

export interface SetRecoveryTopologyParams {
    /** Minimum number of shares required to reconstruct (M); enforced >= 2. */
    threshold: number;
    /** Total number of shares (N); enforced >= 3 and >= threshold. */
    totalShares: number;
}

// ── unlock ───────────────────────────────────────────────────────────────────

export interface UnlockParams {
    /** Unlock-method hint (the implementation chooses the UI accordingly). */
    method?: 'biometric' | 'pin' | 'passkey';
}

// ── Re-export DID for convenience (used internally by the interface layer; does not change the types package) ──────────
export type { DID, Signature, Timestamp };
