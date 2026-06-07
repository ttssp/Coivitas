/**
 * @coivitas/identity credential-resolver L2 barrel export
 *
 * L2 identity-layer primitives:
 *   - resolveCredential: CR main resolution entry (7-step algorithm; step 6 fail-closed revocation early position)
 *   - verifyResolvedCredential: consumer-side verification of ResolvedCredential integrity
 *
 * L2 port interfaces (dependency injection; 4 ports; rfpVerifier + ccrChainResolver removed):
 *   - OidcPort: minimal OIDC IdP resolver interface contract
 *   - SamlPort: minimal SAML IdP resolver interface contract (the SAML side)
 *   - FederationLinkResolver: federation_identity_links FK lookup port
 *   - CredentialRevocationChecker: federated credential revocation-check port (fail-closed)
 *
 * L2 delegates to L1 crypto primitives:
 *   - L1 canonicalizeResolvedCredentialIntegrityProof: JCS canonical encode (RFC 8785)
 *   - L1 signResolvedCredentialIntegrityProof: issuer-side Ed25519 sign
 *   - L1 verifyResolvedCredentialIntegrityProofSignature: verifier-side Ed25519 verify (fail-closed)
 *
 * L2 delegates to L0 types:
 *   - L0 CrError + CrErrorCode 14-item freeze (single source); assertNeverCrCode + handleCrError
 *   - L0 7 brand types + factories (no brand coercion): TenantId (re-exported from atp) / UserId /
 *     FederationLinkId / CrVersion / OidcRawClaims / SamlRawClaims / NormalizedOidcClaims /
 *     NormalizedSamlClaims
 *   - L0 JSON Schema + AJV strict mode 4 flags (validateCr)
 *
 * 5 architecture decisions:
 *   #1 OidcRawClaims/SamlRawClaims are nominally incompatible
 *   #2 OidcPort/SamlPort.verifyCallback() is compile-time forced to return Normalized*Claims
 *   #3 federation_identity_links.user_id FK ON DELETE RESTRICT (audit completeness prioritized)
 *   #4 SAML > OIDC > DID multi-source priority (ordered by traditional enterprise federation deployment maturity; v0.1 single-hop)
 *   #5 independent crVersion namespace (consistent with the csp/tb/rfp/atp/hcc/ms/dc/ccr 8-sub-protocol pattern)
 *
 * Anti-phantom defense (5 mandatory items):
 *   1. each of the 14 error codes grep-throws 100% PASS (source grep verify)
 *   2. each method of the 4 port interfaces (FederationLinkResolver / OidcPort / SamlPort / CredentialRevocationChecker)
 *      has an active invocation, grep PASS (literal active calls within this L2 credential-resolver.ts at step 3 / step 4 / step 6)
 *   3. design principles + invariants + docstring + algorithm implementation cross-grep reconciliation 100% PASS
 *   4. the L2 implementation does not over-enforce fields L0 does not require (does not reuse other sub-protocol namespaces)
 *   5. cross-spec alignment, bidirectional phantom verify
 */

export {
    resolveCredential,
    verifyResolvedCredential,
    type ResolveCredentialDeps,
} from './credential-resolver.js';

export type {
    OidcPort,
    SamlPort,
    FederationLinkResolver,
    CredentialRevocationChecker,
    ResolverKeyMaterial,
} from './cr-ports.js';
