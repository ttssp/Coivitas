/**
 * @coivitas/wallet-interface
 *
 * Human Principal key-management interface-definition package (types-only + stub-only fail-closed)
 *
 * Package positioning:
 * - Pure TypeScript interface + type exports, with zero runtime dependencies.
 * - L1.5 (above crypto, below identity).
 * - Implementations (Passkey adapter / HSM adapter / software wallet adapter) ship separately.
 */

// Error codes
export type { WalletErrorCode } from './errors.js';

// All Params / Result / Error / State types
export type {
    CreateKeyParams,
    CreateKeyResult,
    CreateRecoverySharesParams,
    DecryptParams,
    DecryptResult,
    DecryptedShare,
    DID,
    EncryptParams,
    EncryptResult,
    GetPublicKeyResult,
    ProveOwnershipParams,
    RecoverFromSharesParams,
    RecoverResult,
    RecipientShare,
    RecoveryShare,
    RotateRecoverySecretParams,
    SetRecoveryTopologyParams,
    Signature,
    SignColdOperationType,
    SignColdParams,
    SignColdResult,
    SignSessionAuthParams,
    Timestamp,
    UnlockParams,
    WalletError,
    WalletKeyId,
    WalletKeyInfo,
    WalletResult,
    WalletState,
    WalletStateProof,
    WebAuthnAssertionResult,
} from './types.js';

// Core interface
export type { WalletInterface } from './interface.js';

// Stub implementation (fail-closed; for testing)
export { createStubWallet } from './stub-wallet.js';
