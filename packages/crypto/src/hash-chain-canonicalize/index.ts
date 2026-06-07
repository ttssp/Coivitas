/**
 * @coivitas/crypto hash-chain-canonicalize sub-protocol L1 barrel export
 *
 * v0.1 three L1 crypto primitives:
 *   - canonicalizeHashChainEntry / canonicalizeHashChainEntryToString:
 *     JCS canonical encode → Uint8Array / string (RFC 8785; canonicalize npm by Erdtman)
 *   - appendHashChainEntry: payload + lastEntry → new HashChainEntry (7 fields; enforced via brand factory)
 *   - verifyHashChain: entries[] → void (sequential traversal in 4 steps; fail-closed throw HC_*)
 *
 * v0.2 new L1 crypto helpers:
 *   - canonicalizeChainIdentity: JCS canonicalize of the three ChainIdentity fields into a unique string
 *   - verifyCanonicalizeConsistency: anti-self-equal canonicalize consistency verify
 *   - concatPreimage: concatenate canonicalPayloadBytes ‖ chainIdentityJcsBytes (payload first; identity second)
 *   - computeCanonicalPayloadHashHex: SHA-256(preimage) → lowercase hex 64 chars
 *   - recomputeCanonicalPayloadHash: verify path reuses the write path algorithm
 *   - assertCanonicalPayloadHashConsistent: verify entry.canonicalPayloadHash is literally equal to the recomputed hash
 *
 * Error-code namespace:
 *   - v0.1 frozen 6: HC_CANONICALIZE_FAILED / HC_HASH_MISMATCH / HC_PREVIOUS_HASH_BROKEN /
 *     HC_CHAIN_POSITION_NONMONOTONIC / HC_FIXTURE_CROSS_LANG_MISMATCH / HC_SCHEMA_VIOLATION
 *   - v0.2 added 2: HC_CHAIN_IDENTITY_PREIMAGE_FAILED + HC_CHAIN_IDENTITY_SCHEMA_BREAKING
 *
 * L0 types upgrade hand-off:
 *   - v0.2 ChainIdentity interface + ChainIdentityJcs brand + HccErrorCode v0.2 union pending extension in L0 types
 *   - these L1 helpers currently use inline ChainIdentityShape + string output + v0.1 error-code union (HC_HASH_MISMATCH etc.)
 *   - after the L0 types upgrade, these helpers switch to the ChainIdentity interface + ChainIdentityJcs brand + the real v0.2 error codes (HC_CHAIN_IDENTITY_PREIMAGE_FAILED etc.)
 *
 * L1 vs L3 boundary:
 *   - this L1 surface provides the bare HashChainEntry type + bare crypto primitives
 *   - the L3 manager layers on:
 *     chainIdentity contract + SQL row assembly + AJV strict + cross-spec invariant
 *   - L1 is not responsible for SQL row assembly / cross-scope verification / sub-protocol cross-spec invariant
 */

// v0.1 baseline primitives
export {
    canonicalizeHashChainEntry,
    canonicalizeHashChainEntryToString,
} from './canonicalize-hash-chain-entry.js';
export { appendHashChainEntry } from './append-hash-chain-entry.js';
export {
    verifyHashChain,
    type VerifyHashChainOptions,
} from './verify-hash-chain.js';

// v0.2 new helpers
export {
    canonicalizeChainIdentity,
    verifyCanonicalizeConsistency,
    type ChainIdentityShape,
} from './canonicalize-chain-identity.js';
export {
    concatPreimage,
    computeCanonicalPayloadHashHex,
} from './preimage-helpers.js';
export {
    recomputeCanonicalPayloadHash,
    assertCanonicalPayloadHashConsistent,
    assertCanonicalPayloadIsCanonical,
    type HashChainEntryV02Shape,
} from './verify-helpers.js';
