/**
 * key-custody public type definitions
 *
 * Responsibility:
 *   - KMSClient interface: generateKey / sign / decrypt / getKeyMetadata
 *   - KMS error type system (fail-closed; no default 200 / stub allowed)
 *   - EnterpriseSDKConfig schema (including the revocationList placeholder)
 *
 * Design constraints:
 *   - This module is the key-custody segment; it does not include multi-tenancy / console / SSO
 *   - Every error must carry an explicit error code; silent degradation is forbidden
 *   - The RevocationListClient field is only a config placeholder and is not implemented (implemented in a later segment)
 *
 */

import type { Timestamp } from '@coivitas/types';

// ── KMS error codes ───────────────────────────────────────────────────────────

/**
 * KMS operation error codes (fail-closed; any error not in this list is treated as UNKNOWN)
 *
 * Design principles:
 *   - Every error must fail-closed (throw a KMSError; returning null or silently degrading is forbidden)
 *   - After catching, the caller decides whether to retry (idempotent operations) or raise an alert (non-idempotent operations)
 */
export type KMSErrorCode =
    /** The KMS key ID does not exist or has been disabled/deleted*/
    | 'KMS_KEY_NOT_FOUND'
    /** KMS credentials are invalid (access key expired / insufficient permissions)*/
    | 'KMS_AUTH_FAILED'
    /** KMS server-side timeout (network latency or service unavailable)*/
    | 'KMS_TIMEOUT'
    /** The KMS operation was throttled (TPS quota exceeded)*/
    | 'KMS_THROTTLED'
    /** Request parameter validation failed (caller error; no retry)*/
    | 'KMS_INVALID_PARAMETER'
    /** KMS returned an unparseable response (protocol error; no retry)*/
    | 'KMS_PROTOCOL_ERROR'
    /** Unknown KMS error (fallback; the caller must not treat it as success)*/
    | 'KMS_UNKNOWN';

/**
 * KMS operation error (always fail-closed; the caller is not allowed to downgrade it to success)
 *
 * Rationale: extends Error to ensure instanceof checks work;
 * the retryable field guides the retry strategy (THROTTLED / TIMEOUT = retryable; AUTH_FAILED = not retryable).
 */
export class KMSError extends Error {
    readonly code: KMSErrorCode;
    /** Whether it is safe to retry (idempotent operations; the caller owns the retry logic)*/
    readonly retryable: boolean;
    /** The underlying provider's raw error (for debugging; must not be exposed to end users)*/
    override readonly cause?: unknown;

    constructor(params: {
        code: KMSErrorCode;
        message: string;
        retryable: boolean;
        cause?: unknown;
    }) {
        super(params.message);
        this.name = 'KMSError';
        this.code = params.code;
        this.retryable = params.retryable;
        this.cause = params.cause;
    }
}

// ── KMS key metadata ──────────────────────────────────────────────────────────

/** KMS key state (aligned with the semantics of each provider's state field)*/
export type KMSKeyState =
    | 'ENABLED' // normally usable
    | 'DISABLED' // disabled (unusable; can be re-enabled)
    | 'PENDING_DELETION' // pending deletion (unusable; unrecoverable)
    | 'UNAVAILABLE' // provider-internal unavailability (temporary; retryable)
    | 'UNKNOWN'; // the provider did not return a state

/** Key algorithm type (currently only signing algorithms are supported; encryption algorithms reserve an extension slot)*/
export type KMSKeyAlgorithm =
    | 'ECDSA_P256' // AWS KMS ECC_NIST_P256 (used for signing)
    | 'RSA_4096_OAEP_SHA256' // AWS KMS RSA_4096 (used for decryption; key wrapping)
    | 'SYMMETRIC_256' // AES-256 (used for data encryption)
    | 'UNKNOWN';

/**
 * KMS key metadata (getKeyMetadata return value)
 *
 * Design: the fields align with the AWS KMS DescribeKey response but use provider-agnostic type names,
 * avoiding coupling the upper layers to a specific KMS provider.
 */
export interface KMSKeyMetadata {
    /** Unique key identifier (provider ARN or key ID)*/
    keyId: string;
    /** Current key state*/
    state: KMSKeyState;
    /** Key algorithm*/
    algorithm: KMSKeyAlgorithm;
    /** Key creation time (ISO 8601 UTC)*/
    createdAt: Timestamp;
    /** Key expiry time (null = never expires; ISO 8601 UTC)*/
    expiresAt: Timestamp | null;
    /** Key description label (for debugging / auditing; contains no secrets)*/
    description?: string;
    /** Provider-specific extra metadata (filled by the provider adapter; the caller must not depend on it)*/
    providerMetadata?: Record<string, string>;
}

// ── KMSClient interface ───────────────────────────────────────────────────────

/**
 * generateKey parameters
 *
 * Note: the KMS-side key never exports private key material; once generated it can only be used through the KMS API (HSM design).
 */
export interface GenerateKeyParams {
    /** Key algorithm*/
    algorithm: Exclude<KMSKeyAlgorithm, 'UNKNOWN'>;
    /**
     * Key description label (for audit tracing; contains no secrets)
     * Suggested format: `<tenant-id>/<purpose>/<version>` (once the multi-tenancy segment is introduced, the caller can fill in the tenant identifier)
     */
    description?: string;
    /**
     * Key expiry time (ISO 8601 UTC; null = never expires)
     * Per NIST SP 800-57: signing keys are recommended to last at most 2 years
     */
    expiresAt?: Timestamp;
}

/** generateKey return value*/
export interface GenerateKeyResult {
    /** Unique identifier of the new key (used by subsequent sign / decrypt / getKeyMetadata)*/
    keyId: string;
    /** Key creation time (ISO 8601 UTC)*/
    createdAt: Timestamp;
    /** Initial key metadata*/
    metadata: KMSKeyMetadata;
}

/**
 * sign parameters
 *
 * Security constraint: payload must be a digest of an application-layer message (or the raw message; the KMS side does the hashing);
 * passing unprocessed user input is forbidden (to prevent signing-oracle attacks).
 */
export interface SignParams {
    /** Target key ID*/
    keyId: string;
    /**
     * Message to sign (raw bytes; the KMS side signs after taking a SHA-256 / SHA-384 digest)
     * The caller is responsible for ensuring the payload is deterministic (canonicalized bytes).
     */
    payload: Uint8Array;
    /** Signing algorithm (must be compatible with the key algorithm; otherwise KMS_INVALID_PARAMETER)*/
    algorithm: 'ECDSA_SHA_256' | 'ECDSA_SHA_384';
}

/** sign return value*/
export interface SignResult {
    /** DER-encoded ECDSA signature (base64 encoded; AWS KMS native format)*/
    signature: string;
    /** The signing algorithm actually used (verifies the provider did not downgrade the algorithm)*/
    algorithm: string;
    /** Signing time (ISO 8601 UTC; for auditing)*/
    signedAt: Timestamp;
}

/**
 * decrypt parameters
 *
 * Scenario: use a KMS key to decrypt a data encryption key (DEK; the envelope encryption pattern).
 * The KMS key itself stores no data; the data is encrypted with the DEK, and the DEK is stored encrypted by the KMS CMK.
 */
export interface DecryptParams {
    /** Target key ID*/
    keyId: string;
    /** Ciphertext bytes encrypted by the KMS CMK (base64 encoded)*/
    ciphertextBlob: string;
    /** Decryption algorithm (must match the one used at encryption; otherwise KMS_INVALID_PARAMETER)*/
    algorithm: 'RSAES_OAEP_SHA_256' | 'SYMMETRIC_DEFAULT';
}

/** decrypt return value*/
export interface DecryptResult {
    /** Decrypted plaintext bytes (the caller is responsible for securely wiping memory)*/
    plaintext: Uint8Array;
    /** The key ID actually used (verifies the provider routed correctly)*/
    keyId: string;
}

/**
 * KMS client interface (provider-agnostic; see AwsKmsAdapter for the implementation)
 *
 * Design principles:
 *   1. All methods return a Promise; on failure they reject with a KMSError (fail-closed)
 *   2. No generateKeyPair is provided (the private key does not leave the KMS); keys are only created inside the KMS via generateKey
 *   3. getKeyMetadata is the only entry point for state checks (it does not expose dangerous operations like list / delete)
 *   4. The caller holds no private key material; it holds only the keyId
 */
export interface KMSClient {
    /**
     * Generate a new key inside the KMS (the private key material does not leave the KMS)
     *
     * @throws KMSError (code: KMS_AUTH_FAILED | KMS_INVALID_PARAMETER | KMS_UNKNOWN)
     */
    generateKey(params: GenerateKeyParams): Promise<GenerateKeyResult>;

    /**
     * Sign using a KMS key (the private key is never exposed)
     *
     * Security note: payload must be canonicalized deterministic bytes;
     * the KMS side signs after taking a SHA-256/SHA-384 digest, so the caller should not hash again.
     *
     * @throws KMSError (code: KMS_KEY_NOT_FOUND | KMS_THROTTLED | KMS_TIMEOUT | ...)
     */
    sign(params: SignParams): Promise<SignResult>;

    /**
     * Decrypt using a KMS key (envelope decryption; the private key is never exposed)
     *
     * @throws KMSError (code: KMS_KEY_NOT_FOUND | KMS_AUTH_FAILED | ...)
     */
    decrypt(params: DecryptParams): Promise<DecryptResult>;

    /**
     * Query key metadata (state / algorithm / expiry time)
     *
     * Commonly used for key rotation policy checks (triggering rotation before expiry).
     *
     * @throws KMSError (code: KMS_KEY_NOT_FOUND | KMS_AUTH_FAILED | ...)
     */
    getKeyMetadata(keyId: string): Promise<KMSKeyMetadata>;
}

// ── EnterpriseSDKConfig ──────────────────────────────────────────────────────

/**
 * RevocationListClient placeholder interface (a type reservation only; implemented in a later phase)
 *
 * This interface currently serves only as a type placeholder:
 *   - EnterpriseSDKConfig references this type to keep the config schema complete
 *   - The concrete methods will be filled in once the RevocationList API is wired up
 *
 * This round does not directly consume RevocationList; it only reserves the field.
 */
export interface RevocationListClient {
    /** Placeholder method (to be replaced once implemented later)*/
    checkRevocation(tokenId: string): Promise<{ revoked: boolean }>;
}

/**
 * Enterprise SDK config schema (made concrete for this segment)
 *
 * Includes all config items required by the key-custody segment. Additional config items are added in later segments;
 * this round does not cross segment boundaries (i.e. this schema contains no multi-tenancy fields / SSO fields).
 */
export interface EnterpriseSDKConfig {
    /**
     * KMS client instance (required)
     * The caller injects a concrete adapter (AwsKmsAdapter / GcpKmsAdapter / etc.)
     */
    kmsClient: KMSClient;

    /**
     * Key rotation policy config (optional; defaults to the NIST SP 800-57 baseline)
     * The key rotation policy is implemented in a later phase; the field shape is reserved here
     */
    keyRotationPolicy?: KeyRotationPolicyConfig;

    /**
     * RevocationList client placeholder (not implemented yet; injected once wired up later)
     *
     * This round does not directly consume RevocationList; it only reserves this field in the enterprise SDK config schema.
     */
    revocationList?: RevocationListClient;

    /**
     * Operation timeout (milliseconds; defaults to 10000ms)
     * Applies to all KMS API calls; on timeout, rejects with KMSError(KMS_TIMEOUT)
     */
    operationTimeoutMs?: number;
}

/**
 * Key rotation policy config (implemented in detail in a later phase; the shape is reserved here)
 *
 * Per NIST SP 800-57:
 *   - Signing keys: no more than 1-2 years
 *   - Symmetric keys: no more than 1 year
 *   - Old key retention period: at least 1 rotation cycle (to ensure historical signatures can be verified)
 */
export interface KeyRotationPolicyConfig {
    /** Rotation interval (days; corresponds to rotation_interval_days)*/
    rotationIntervalDays: number;
    /** Old key retention period (days; can be safely deleted after expiry; corresponds to retention_days)*/
    retentionDays: number;
    /**
     * Rotation trigger mode (corresponds to rotation_trigger)
     *   - 'scheduled': triggered periodically per rotationIntervalDays
     *   - 'expiry_threshold': triggered when the key's remaining validity < threshold
     */
    rotationTrigger: 'scheduled' | 'expiry_threshold';
    /** Lead time in days for the expiry-threshold trigger (only valid when rotation_trigger='expiry_threshold')*/
    expiryThresholdDays?: number;
}
