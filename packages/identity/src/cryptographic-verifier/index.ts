/**
 * cryptographic-verifier — sdk v0.2 L2 identity cryptographic verifier factory barrel export
 *
 * Summary: exposes the 3 kinds of verifier factory + boundary check helpers + helper classes.
 * The path where sub-protocol consumers literally consume TrustedSettlerDid follows the boundary check pattern.
 *
 * Basis:
 *   - sdk v0.2 (3 verifier factories + boundary check pattern)
 *   - all brand types imported from the single source '@coivitas/types'
 */

// ─── mTLS verifier factory ───────────────────────────────────────────────────
export { verifyMtlsAndDeriveDid } from './verify-mtls.js';

// ─── JWT verifier factory ────────────────────────────────────────────────────
export { verifyJwtAndDeriveDid } from './verify-jwt.js';

// ─── OAuth2 verifier factory ─────────────────────────────────────────────────
export { verifyOAuth2AndDeriveDid } from './verify-oauth2.js';

// ─── mTLS helpers (cert parse + chain validate + DID extraction) ─────────────
export {
    parseX509Cert,
    validateCertChain,
    extractDidFromCertSubject,
} from './mtls-helpers.js';

// ─── JWT helpers (alg allowlist + verifyJwtAlgAllowed) ──────────────────────
export {
    JWT_ALG_ALLOWLIST,
    JWT_ALG_DENYLIST,
    verifyJwtAlgAllowed,
} from './jwt-helpers.js';

// ─── OAuth2 helpers (cache + circuit breaker + rate limiter) ─────────────────
export {
    OAuth2IntrospectionCache,
    OAuth2CircuitBreaker,
    OAuth2RateLimiter,
} from './oauth2-helpers.js';

// ─── Boundary check (L3 boundary-layer guard) ────────────────────────────────
export {
    assertTrustedDidMatchesExpected,
    assertTrustedDidIsKindAndFresh,
    extractDidFromCertSubjectDn,
    assertCrossCheckMappingConsistent,
} from './boundary-check.js';
