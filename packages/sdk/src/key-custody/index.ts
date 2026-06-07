/**
 * key-custody module public exports (barrel export)
 *
 * Export scope (key-custody segment):
 *   - KMSClient interface + all operation types
 *   - KMSError + KMSErrorCode
 *   - AwsKmsAdapter + AwsKmsClientPort + AwsKmsAdapterConfig
 *   - EnterpriseSDKConfig + KeyRotationPolicyConfig
 *   - RevocationListClient (placeholder interface)
 *
 * Not exported this round (added in later segments):
 *   - multi-tenancy tenantIsolator
 *   - management console tabA/tabB
 *   - SSO SAML/OIDC
 *
 */

// ── Type definitions ────────────────────────────────────────────────────────

export type {
    KMSErrorCode,
    KMSKeyState,
    KMSKeyAlgorithm,
    KMSKeyMetadata,
    GenerateKeyParams,
    GenerateKeyResult,
    SignParams,
    SignResult,
    DecryptParams,
    DecryptResult,
    KMSClient,
    RevocationListClient,
    EnterpriseSDKConfig,
    KeyRotationPolicyConfig,
} from './types.js';

export { KMSError } from './types.js';

// ── AWS KMS adapter ──────────────────────────────────────────────────────────

export type {
    AwsKmsClientPort,
    AwsKmsAdapterConfig,
    AwsKmsCommandFactoryPort,
} from './aws-kms-adapter.js';

export { AwsKmsAdapter, makeTestCommandFactory } from './aws-kms-adapter.js';
