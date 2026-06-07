export { canonicalize } from './canonicalization.js';
export {
    detectEncoding,
    fromBase64Url,
    fromHex,
    toBase64Url,
    toHex,
} from './encoding.js';
// canonical signed payload sub-protocol L1 crypto
// 3 primitives: canonicalSerialize / canonicalHash / verifySignature
// error-code namespace isolation (CspError / CspErrorCode 13 codes vs the existing CryptoError 9 codes)
export * from './canonical-signed-payload/index.js';
export {
    aeadDecrypt,
    aeadEncrypt,
    buildAeadBytes,
    buildAeadNonce,
    computeKeyId,
    computeTranscriptHash,
    computeX25519SharedSecret,
    deriveChainKeyRekeyKeys,
    deriveSessionKeys,
    generateEphemeralX25519KeyPair,
    ownDirection,
    peerDirection,
    type AeadAadParams,
    type DerivedSessionKeys,
    type TranscriptHashInput,
} from './encryption.js';
export { HashChain } from './hash-chain.js';
// hash-chain-canonicalize sub-protocol L1 crypto
// 3 primitives: canonicalizeHashChainEntry(+ToString) / appendHashChainEntry / verifyHashChain
// single-source error codes imported from @coivitas/types (HashChainError + HccErrorCode 6 entries)
// coexists with the existing HashChain class (L1 general-algorithm primitive) without replacing it
export * from './hash-chain-canonicalize/index.js';
export { hash } from './hashing.js';
export { generateKeyPair } from './key-generation.js';
export { sign, verify } from './signing.js';
export {
    CryptoError,
    type CryptoErrorCode,
    type HashChainVerifyResult,
    type KeyPair,
} from './types.js';
// multisig sub-protocol L1 crypto
// main primitives: generateMerkleLeaf + buildMerkleTree + verifyMerkleInclusion + verifyMultisigProof
// error-code namespace isolation (MultisigError / MultisigErrorCode 14 codes vs the existing CryptoError 9 codes + CspError 13 codes)
export * from './multisig/index.js';

// credential-resolver sub-protocol L1 crypto
// main primitives: canonicalizeResolvedCredentialIntegrityProof (JCS RFC 8785) +
// signResolvedCredentialIntegrityProof (Ed25519 sign; issuer side) +
// verifyResolvedCredentialIntegrityProofSignature (Ed25519 verify; verifier side; fail-closed)
// single-source error codes imported from @coivitas/types (CrError + CrErrorCode 14 entries)
// error-code namespace isolation (CrError / CrErrorCode 14 codes vs CSP_* / HC_* / MULTISIG_* / CryptoError 9 codes)
// Architecture baseline:
// - OidcRawClaims/SamlRawClaims are nominally incompatible
// - OidcPort/SamlPort compile-time enforce returning Normalized*Claims
// - federation_identity_links.user_id FK RESTRICT (audit completeness)
// - SAML > OIDC > DID multi-source priority
// - independent crVersion namespace
export * from './credential-resolver/index.js';
