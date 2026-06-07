/**
 * Credential Resolver (CR) sub-protocol v0.1 — L1 crypto layer types
 *
 * "single source of error codes + L1 import" template:
 *   - L0 (@coivitas/types) is the single source of the 14-entry CrErrorCode union
 *   - L1 must import type; no inline / partial subset redefinition
 *   - L2 e2e cross-package must cover L0 schema reject + L1 throw + full-chain PASS across multiple cases
 *
 * Error-code namespace (isolation contract):
 *   - the L0 CrError class + CrErrorCode union are the single source of the 14 codes
 *   - L1 does not redefine the CrError class; it imports it directly from @coivitas/types
 *     (consistent with the csp / hcc / ms L1 pattern; namespace isolation CR_* vs CSP_* / HC_* / MULTISIG_* / CryptoError 9 codes)
 *
 * Robustness defense:
 *   - top-level import of canonicalSerialize / ed25519 (no in-body require);
 *   - every one of the 14 CrErrorCode codes has a throw-path (verifiable by source grep, to avoid dead error codes that never fire);
 *   - no stub default success / silent return true allowed (auth/verification primitive is strictly fail-closed);
 *   - JCS canonicalize failure → fail-closed throw CR_INTEGRITY_PROOF_INVALID + reason 'jcs_canonicalize_failed'.
 */

// single-source error-code import (not redefined inline in L1)
export type { CrErrorCode } from '@coivitas/types';
export { CrError } from '@coivitas/types';
