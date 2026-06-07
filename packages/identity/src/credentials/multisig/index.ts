/**
 * @coivitas/identity multisig L2 barrel export
 *
 * L2 identity-layer primitives:
 *   - issueMultisigToken: issuer-side issuance pipeline (8 steps)
 *   - verifyMultisigToken: verifier-side verify pipeline (8 steps)
 *
 * L2 delegates to L1 crypto primitives:
 *   - L1 verifyMultisigProof: Merkle inclusion + Ed25519 verify + quorum
 *   - L1 buildMerkleTree / generateMerkleLeaf: issuer-side Merkle commitment construction
 *
 * L2 delegates to L0 types:
 *   - L0 createMultisigToken factory: single-cast enforcement + brand type validation (no brand coercion allowed)
 *   - L0 validateMultisigToken: AJV strict mode, the 3rd line of defense
 */

export {
    issueMultisigToken,
    type IssueMultisigTokenInput,
    type SignerKeyMaterial,
} from './multisig-token-issuer.js';
export {
    verifyMultisigToken,
    type VerifyMultisigTokenOptions,
    type VerifyMultisigTokenResult,
} from './multisig-token-verifier.js';
