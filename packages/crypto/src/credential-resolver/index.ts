/**
 * @coivitas/crypto credential-resolver sub-protocol L1 barrel export
 *
 * Implements: cr v0.1 L1 crypto
 *
 * Three L1 crypto primitives:
 *   - canonicalizeResolvedCredentialIntegrityProof / canonicalizeResolvedCredentialIntegrityProofToString:
 *     JCS canonical encode → Uint8Array / string (RFC 8785; canonicalize npm by Erdtman;
 *     consistent pattern with csp v0.1; JSON.stringify fallback forbidden);
 *   - signResolvedCredentialIntegrityProof: signedPayload + privateKey → hex signature (issuer side);
 *   - verifyResolvedCredentialIntegrityProofSignature: proof + publicKey → { valid: true }
 *     OR throw CrError (verifier side; fail-closed, stub return true strictly forbidden);
 *   - extractIntegrityProofSignedPayload: full proof → signed payload (5 fields + cspVersion;
 *     strips proofSignature / resolverDid; shared helper for sign / verify).
 *
 * Error-code namespace (frozen at 14 entries; CR_* prefix):
 *   the CrError class + CrErrorCode union are imported from the single source @coivitas/types;
 *   L1 throws the literal frozen 14 codes (this L1 surface throws CR_INTEGRITY_PROOF_INVALID +
 *   CR_PORT_CONTRACT_VIOLATION; the other 12 codes are thrown by L2 / L0).
 *
 * Namespace isolation: CR_* is orthogonal to the CSP_* / HC_* / MULTISIG_* / CryptoError 9-code set (csp v0.1 constraint 4).
 *
 * Anti-phantom defense:
 *   - top-level import of canonicalize / ed25519 (no in-body require);
 *   - the 14-code CrErrorCode union is imported from the single L0 source (consistent with the csp / hcc / ms L1 pattern);
 *   - no stub default success / silent return true allowed (auth/verification primitive is strictly fail-closed);
 *   - canonicalize failure → fail-closed throw CR_INTEGRITY_PROOF_INVALID + reason 'jcs_canonicalize_failed'.
 */

export {
    canonicalizeResolvedCredentialIntegrityProof,
    canonicalizeResolvedCredentialIntegrityProofToString,
    extractIntegrityProofSignedPayload,
    type ResolvedCredentialIntegrityProofSignedPayload,
} from './canonicalize-integrity-proof.js';

export { signResolvedCredentialIntegrityProof } from './sign-integrity-proof.js';

export {
    verifyResolvedCredentialIntegrityProofSignature,
    type VerifyIntegrityProofSignatureResult,
} from './verify-integrity-proof.js';

export { CrError, type CrErrorCode } from './types.js';
