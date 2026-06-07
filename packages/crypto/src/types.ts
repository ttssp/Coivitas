export const CRYPTO_ERROR_CODES = [
    'INVALID_KEY_FORMAT',
    'INVALID_SIGNATURE_FORMAT',
    'INVALID_HASH_FORMAT',
    'INVALID_HEX_STRING',
    'ENCODING_ERROR',
    'SIGNATURE_VERIFICATION_FAILED',
    'SERIALIZATION_FAILED',
    'HASH_CHAIN_BROKEN',
    'INTERNAL_CRYPTO_ERROR',
] as const;

export type CryptoErrorCode = (typeof CRYPTO_ERROR_CODES)[number];

export interface KeyPair {
    publicKey: string;
    privateKey: string;
}

export interface HashChainVerifyResult {
    valid: boolean;
    chainLength: number; // number of records verified successfully; equals brokenAtIndex when the chain is broken
    brokenAtIndex?: number; // renamed from the original brokenAt
    expectedHash?: string | null;
    actualHash?: string | null;
}

/**
 * @experimental Preparatory capability; not part of the stable specVersion 0.2.0 API.
 * Not exported from the package entry. The public API shape will be decided after the root anchor contract is designed.
 */
export interface MerkleProofNode {
    hash: string; // hex encoding (consistent with wire-format)
    position: 'left' | 'right';
}

/**
 * @experimental Preparatory capability. Return value of generateProof().
 * Not exported from the @coivitas/crypto package entry.
 */
export interface MerkleProof {
    recordIndex: number;
    recordHash: string; // hash of the target record (hex)
    siblings: MerkleProofNode[];
    root: string; // Merkle tree root hash (hex); the current release has no external anchor contract
}

export class CryptoError extends Error {
    public override readonly name = 'CryptoError';
    public readonly code: CryptoErrorCode;
    public override readonly cause?: Error;

    public constructor(code: CryptoErrorCode, message: string, cause?: Error) {
        super(message);
        this.code = code;
        this.cause = cause;
    }
}
