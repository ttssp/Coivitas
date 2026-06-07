/**
 * @coivitas/crypto multisig sub-protocol L1 barrel export
 *
 * Main L1 crypto primitives:
 *   - generateMerkleLeaf: SHA-256(JCS({id, role, signature})) leaf encoding;
 *   - buildMerkleTree: RFC 6962 Merkle tree construction (issuer side; returns root + audit paths);
 *   - verifyMerkleInclusion: RFC 6962 audit path verify (verifier side);
 *   - verifyMultisigProof: main entry (2-of-N threshold + Merkle inclusion + Ed25519 verify + quorum);
 *
 * The "single-source error codes + L1 import" template:
 *   - L0 (@coivitas/types) is the single source of the MultisigErrorCode 14-entry union
 *   - L1 imports the type from L0; no inline / partial-subset redefinition
 *   - L2 multisig-token-issuer / multisig-token-verifier consume them in sequence
 *
 * Error-code namespace (isolation contract):
 *   - MultisigError class extension + MultisigErrorCode union from @coivitas/types (single source, 14 codes)
 *   - orthogonal in namespace to the existing CryptoError class + CryptoErrorCode (9 codes)
 *   - orthogonal in namespace to the CspError class + CspErrorCode (13 codes)
 */

export {
    buildMerkleTree,
    decodeMerklePath,
    encodeMerklePath,
    generateMerkleLeaf,
    generateMerkleLeafHex,
    verifyMerkleInclusion,
    type SignerLeafInput,
} from './merkle-tree.js';
export {
    mapMultisigErrorCodeToMessage,
    verifyMultisigProof,
    type MultisigTokenLike,
    type VerifyMultisigProofOptions,
    type VerifyMultisigProofResult,
} from './verify-multisig.js';
export {
    assertNeverMultisig,
    MultisigError,
    type MultisigErrorCode,
} from './types.js';
