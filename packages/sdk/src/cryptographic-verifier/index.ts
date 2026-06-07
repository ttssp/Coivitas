/**
 * cryptographic-verifier module exports (sdk v0.2 L5)
 *
 * Summary: publicly exposes the VerifierFactory orchestrator + brand types + verifier types +
 *       boundary checks + 3 factories + helpers (alg allowlist / cache / circuit
 *       breaker / rate limiter) + the SdkError error class.
 */

// brand types (L1 type)
export type {
    CertSubjectDn,
    JwtSubject,
    OAuth2ClientId,
    TrustedSettlerDid,
} from './brand-types.js';

// verifier types (input + output context)
export type {
    JwtVerifierContext,
    MtlsVerifierContext,
    OAuth2VerifierContext,
    VerifiedTransportContext,
    VerifierFactoryInput,
    VerifierKind,
} from './verifier-types.js';

// orchestrator (L5 dispatch by VerifierKind)
export { VerifierFactory } from './verifier-factory.js';

// 3 verifier factories (L2 cryptographic verify)
export { verifyMtlsAndDeriveDid } from './mtls-verifier.js';
export { verifyJwtAndDeriveDid } from './jwt-verifier.js';
export { verifyOAuth2AndDeriveDid } from './oauth2-verifier.js';

// boundary check (L3 sub-protocol boundary)
export {
    assertCrossCheckMappingConsistent,
    assertTrustedDidIsKindAndFresh,
    assertTrustedDidMatchesExpected,
    extractDidFromCertSubjectDn,
} from './boundary-check.js';

// mTLS helpers
export {
    extractDidFromCertSubject,
    parseX509Cert,
    validateCertChain,
} from './mtls-helpers.js';

// JWT helpers
export {
    JWT_ALG_ALLOWLIST,
    JWT_ALG_DENYLIST,
    createJwksWithRetry,
    verifyJwtAlgAllowed,
} from './jwt-helpers.js';

// OAuth2 helpers (DoS mitigation + RFC 7662 cache)
export {
    type CircuitState,
    OAuth2CircuitBreaker,
    OAuth2IntrospectionCache,
    OAuth2RateLimiter,
} from './oauth2-helpers.js';

// error class
export { SdkError, type SdkErrorCode } from './errors.js';
