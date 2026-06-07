/**
 * WalletInterface — unified abstraction for Human Principal key management
 *
 * 15 methods: key management 3 + signing 2 (Hot/Cold split) + encrypt/decrypt 2 + recovery 3
 *            + topology configuration 1 + ownership proof 1 + lifecycle 3
 *
 * Interface conventions:
 * - All methods return Promise<WalletResult<T>> and never throw.
 * - Implementations must guarantee the private key never leaves the security boundary in plaintext.
 * - Calling convention:
 *     The Agent Runtime must never receive the principal's private key; the principal signs within their own secure environment.
 */

import type {
    CreateKeyParams,
    CreateKeyResult,
    CreateRecoverySharesParams,
    DecryptParams,
    DecryptResult,
    EncryptParams,
    EncryptResult,
    GetPublicKeyResult,
    ProveOwnershipParams,
    RecoverFromSharesParams,
    RecoverResult,
    RecoveryShare,
    RotateRecoverySecretParams,
    SetRecoveryTopologyParams,
    SignColdParams,
    SignColdResult,
    SignSessionAuthParams,
    UnlockParams,
    WalletKeyId,
    WalletKeyInfo,
    WalletResult,
    WalletState,
    WalletStateProof,
    WebAuthnAssertionResult,
} from './types.js';

export interface WalletInterface {
    // ═══ Key management ═══

    /**
     * Creates a new principal key pair (called on first registration)
     *
     * Internal flow: generate an Ed25519 key pair -> store in secure storage -> return the public key + keyId.
     * WebAuthn implementation: navigator.credentials.create() -> attestation -> extract the public key.
     */
    createKey(params: CreateKeyParams): Promise<WalletResult<CreateKeyResult>>;

    /**
     * Gets the current principal public key
     *
     * Purpose: compute the did:key, and provide the verifier's public key during signature verification.
     */
    getPublicKey(
        keyId?: WalletKeyId,
    ): Promise<WalletResult<GetPublicKeyResult>>;

    /**
     * Lists all available key IDs
     *
     * Purpose: multi-key scenarios (backup keys, migration intermediate states).
     */
    listKeys(): Promise<WalletResult<WalletKeyInfo[]>>;

    // ═══ Signing operations (R3 split: the Hot/Cold paths are separated at compile time) ═══

    /**
     * Hot Passkey path — session authentication signature (R3 split)
     *
     * Used only for browser session authentication / step-up re-verification.
     * The output is a WebAuthn assertion triple and cannot be used for RotationProof.principalSignature
     * / BindingProof.signature / deactivationProof.signature -- the latter are typed as Signature
     * (128-char hex Ed25519), which is incompatible with WebAuthnAssertionResult (enforced by TS at compile time).
     *
     * @param params.payload - the byte array to sign (becomes the WebAuthn challenge)
     * @param params.keyId - which Passkey credential to use; if omitted, the default Hot key is used
     */
    signSessionAuth(
        params: SignSessionAuthParams,
    ): Promise<WalletResult<WebAuthnAssertionResult>>;

    /**
     * Cold Ed25519 path — principal-endorsement signature (R3 split)
     *
     * The only method that can produce RotationProof.principalSignature / BindingProof.signature /
     * deactivationProof.signature. Output = Signature: 128-char hex Ed25519,
     * compatible with the key-rotation signing convention.
     *
     * The operationType field forces the caller to declare its purpose; the wallet UX presents different unlock prompts accordingly.
     *
     * @param params.payload - the byte array to sign (the caller is responsible for canonicalize)
     * @param params.operationType - 'ROTATION_PROOF' | 'BINDING_PROOF' | 'DEACTIVATION_PROOF'
     * @param params.keyId - which Cold key to use; if omitted, the default primary key is used
     */
    signCold(params: SignColdParams): Promise<WalletResult<SignColdResult>>;

    // ═══ Encrypt/decrypt (for share protection) ═══

    /**
     * Principal-level encryption (used to protect exported recovery shares)
     *
     * Algorithm: XChaCha20-Poly1305, with the key derived from the Passkey PRF extension.
     * Not E2E communication encryption -- only protects the wallet's own backup data.
     */
    encrypt(params: EncryptParams): Promise<WalletResult<EncryptResult>>;

    /**
     * Principal-level decryption
     */
    decrypt(params: DecryptParams): Promise<WalletResult<DecryptResult>>;

    // ═══ Recovery ═══

    /**
     * Generates M-of-N Shamir shares
     *
     * Splits the principal private key into N shares, any M of which can reconstruct it.
     * Each share is already encrypted with the corresponding Guardian's wrapping key before being returned.
     *
     * @param params.threshold - the M value (minimum number of shares required to reconstruct)
     * @param params.totalShares - the N value (total number of shares)
     * @param params.recipients - the topology of each recipient (discriminated union)
     */
    createRecoveryShares(
        params: CreateRecoverySharesParams,
    ): Promise<WalletResult<RecoveryShare[]>>;

    /**
     * Reconstructs the principal private key from M shares
     *
     * After reconstruction the private key is stored in the new device's secure storage and never returned in plaintext.
     * R4 C1: on DID mismatch, abort before writing to disk and return WALLET_RECOVERY_DID_MISMATCH.
     * Stub behavior: when currentShardVersion is omitted, return WALLET_RECOVERY_VERSION_UNVERIFIED.
     *
     * On success the caller should immediately call rotateRecoverySecret() to re-deal.
     */
    recoverFromShares(
        params: RecoverFromSharesParams,
    ): Promise<WalletResult<RecoverResult>>;

    /**
     * Re-dealing: generates a brand-new share set + increments shard_version
     *
     * Triggers: after a successful recovery / when a Guardian is replaced / when the user initiates a periodic rotation.
     */
    rotateRecoverySecret(
        params: RotateRecoverySecretParams,
    ): Promise<WalletResult<RecoveryShare[]>>;

    /**
     * Configures the (M, N) recovery topology
     *
     * Enforced constraints: M >= 2 and N >= 3 and M <= N.
     */
    setRecoveryTopology(
        params: SetRecoveryTopologyParams,
    ): Promise<WalletResult<void>>;

    // ═══ Ownership proof ═══

    /**
     * Generates a wallet ownership proof (WalletStateProof)
     *
     * Proves the caller holds the private key corresponding to some keyId and that the key is currently usable.
     * This proof is used only internally between wallet and identity; it does not enter the envelope/token wire format.
     */
    proveOwnership(
        params: ProveOwnershipParams,
    ): Promise<WalletResult<WalletStateProof>>;

    // ═══ Lifecycle ═══

    /**
     * Locks the wallet (user-initiated lock or timeout lock)
     *
     * After locking, all signing/decryption operations return the WALLET_LOCKED error.
     */
    lock(): Promise<WalletResult<void>>;

    /**
     * Unlocks the wallet (requires biometric/PIN confirmation)
     */
    unlock(params: UnlockParams): Promise<WalletResult<void>>;

    /**
     * Gets the wallet's current state
     */
    getState(): Promise<WalletResult<WalletState>>;
}
