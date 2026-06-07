/**
 * @coivitas/crypto canonical-signed-payload sub-protocol L1 barrel export
 *
 * Three L1 crypto primitives:
 *   - canonicalSerialize: JCS canonical encode → Uint8Array (RFC 8785; canonicalize npm by Erdtman);
 *   - canonicalHash: canonicalSerialize + SHA-256 → digest (hex/base64url string OR Uint8Array);
 *   - verifySignature: canonicalSerialize + Ed25519 verify + optional semantic checks (audience/challenge/notAfter).
 *
 * Error-code namespace (isolation contract):
 *   - CspError class inheritance + CspErrorCode union imported from the single source @coivitas/types (13 codes);
 *     L1 throws use the unified 13 codes (CSP_SCHEMA_VIOLATION / CSP_CANONICALIZE_MISMATCH /
 *     CSP_SIGNATURE_INVALID / CSP_PAYLOAD_EXPIRED / CSP_CHALLENGE_INVALID /
 *     CSP_TOKEN_MISSING / CSP_AUDIENCE_MISMATCH, etc.);
 *   - orthogonal to the existing CryptoError class + CryptoErrorCode (INVALID_KEY_FORMAT / ... 9 codes) namespace.
 */

export {
    canonicalSerialize,
    canonicalSerializeToString,
} from './canonical-serialize.js';
export { canonicalHash, canonicalHashBytes } from './canonical-hash.js';
export {
    mapCspErrorCodeToMessage,
    verifySignature,
    type VerifySignatureOptions,
    type VerifySignatureResult,
} from './verify-signature.js';
export {
    assertNever,
    CspError,
    type CspErrorCode,
} from './types.js';
