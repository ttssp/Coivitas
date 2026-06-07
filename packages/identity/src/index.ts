export {
    buildAgentDocument,
    buildAgentIdentityDocument,
    createAgentIdentity,
    verifyAgentIdentityDocument,
    resolvePublicKeys,
    DEFAULT_GRACE_PERIOD_MS,
    MAX_GRACE_PERIOD_MS,
} from './did-agent.js';
export {
    createAgentDID,
    didKeyFromPublicKey,
    extractPublicKeyFromDIDKey,
    isDidAgent,
    isDidKey,
} from './did.js';
export {
    createBinding,
    createBindingProof,
    verifyBinding,
    verifyBindingProof,
} from './binding.js';
export { resolveAgentDID } from './resolve.js';
export { IdentityRegistry } from './registry.js';
export {
    registerIdentityRoutes,
    broadcastToNodes,
    type FederationBroadcastOptions,
} from './routes.js';
export {
    issueCapabilityToken,
    createCapabilityTokenPayload,
    delegateCapabilityToken,
    validateAttenuation,
    type IssueCapabilityTokenParams,
    type DelegateTokenParams,
} from './token-issuer.js';
export {
    checkTokenForAction,
    verifyCapabilityToken,
    verifyCapabilityTokenWithChain,
    type TokenActionCheckResult,
    type TokenVerificationResult,
} from './token-verifier.js';
export {
    RevocationList,
    type RevokeTokenParams,
    type RevocationRecord,
} from './revocation.js';
export {
    DC_VERSION,
    assertNeverDcError,
    handleDcError,
    resolveDcVersion,
    validateDelegationChain,
    type DcErrorCode,
} from './delegation-validator.js';
export { registerRevocationRoutes } from './revocation-routes.js';
export {
    type CreateAgentIdentityParams,
    type CreateAgentIdentityResult,
    type IdentityErrorCode,
    type RegistrationResult,
    type ResolveResult,
} from './types.js';
export {
    initiateKeyRotation,
    completeKeyRotation,
    verifyRotationProof,
    type RotatingDocument,
} from './key-rotation.js';
export {
    createFederatedResolver,
    createDefaultDnsRebindingGuard,
    createNullDnsRebindingGuard,
    isPrivateIP,
} from './federated-resolver.js';
export type {
    FederatedResolver,
    FederatedResolverConfig,
    FederatedResolverMetrics,
    FederatedNode,
    DIDBindingVerifier,
    DnsRebindingGuard,
    HealthState,
    NodeMetrics,
    WatermarkStore,
    VersionConflict,
    ResolutionCandidate,
} from '@coivitas/types';

// audit-share v0.2 L2 real verifier implementation (the early AuditEvaluatorNotImplemented stub has been fully removed)

// Namespace isolation (to avoid a name collision with audit-access v0.2's DelegatedAuditKey in packages/types/src/audit.ts):
// - internal type name: `DelegatedAuditKey` (spec literal fidelity; visible inside delegated-audit-key.ts)
// - external alias: `AuditShareDelegatedKey` (forwarded by this export; the two sub-protocols' DID fields have different semantics
// audit-access v0.2 DelegatedAuditKey = {id, principalDid, delegatedTo, scopeAgentDids,
// expiresAt, signature} vs audit-share v0.2 = {auditKeyId, delegatedFrom, delegatedTo,
// purpose='AUDIT', validFrom, validUntil, revoked?, proof});
export {
    createDelegatedAuditKey as createAuditShareDelegatedKey,
    verifyDelegatedAuditKey as verifyAuditShareDelegatedKey,
    type CreateDelegatedAuditKeyParams as CreateAuditShareDelegatedKeyParams,
    type DelegatedAuditKey as AuditShareDelegatedKey,
    type DelegatedAuditKeyProof as AuditShareDelegatedKeyProof,
    type ResolvePublicKeyFn as AuditShareResolvePublicKeyFn,
} from './delegated-audit-key.js';

// RFP v0.1 L2 implementation (resolver freshness proof verification + factory + consumer-side enforcement).
export {
    verifyResolverFreshness,
    createResolverFreshnessProof,
    verifyRfpForConsumer,
    verifyQuorumFreshness,
    RFP_HTTP_STATUS,
} from './resolver-freshness-proof.js';
export type {
    ResolverPublicKeyResolver,
    CreateRfpParams,
    RfpConsumerOptions,
    NodeRfpResult,
} from './resolver-freshness-proof.js';

// Priority 6 sub-protocol: Multisig (ms) v0.1 L2 identity
// issueMultisigToken (issuer-side issuance) + verifyMultisigToken (verifier-side verify pipeline)
export {
    issueMultisigToken,
    type IssueMultisigTokenInput,
    type SignerKeyMaterial,
    verifyMultisigToken,
    type VerifyMultisigTokenOptions,
    type VerifyMultisigTokenResult,
} from './credentials/multisig/index.js';

// Priority 8 sub-protocol: ControllerChainResolution (CCR) v0.1 L2 identity
// resolveControllerChain (main entry; 9-step algorithm; step 6 fail-closed revocation in an early position) +
// verifyChainIntegrityProof (consumer-side check) + validateCcrRequest (AJV strict entry check)
// MAX_CHAIN_DEPTH=5; 12 CCR_* error codes; 3 port interfaces (DidDocumentResolver / RfpVerifierPort / ControllerRevocationChecker)
export {
    resolveControllerChain,
    verifyChainIntegrityProof,
    validateCcrRequest,
} from './controller-chain-resolution/index.js';
export type {
    DidDocumentResolver,
    RfpVerifierPort,
    ControllerRevocationChecker,
    CcrResolverOptions,
} from './controller-chain-resolution/index.js';

// Priority 9 sub-protocol: Credential Resolver (CR) v0.1 L2 identity
// resolveCredential (main entry; 7-step algorithm; step 6 fail-closed revocation in an early position) +
// verifyResolvedCredential (consumer-side check)
// 4 port interfaces: OidcPort / SamlPort / FederationLinkResolver / CredentialRevocationChecker
// Namespace isolation: a different namespace from the existing packages/sdk/src/sso/ OidcPort / SamlPort (module-level isolation)
export {
    resolveCredential,
    verifyResolvedCredential,
    type ResolveCredentialDeps,
    type OidcPort as CredentialResolverOidcPort,
    type SamlPort as CredentialResolverSamlPort,
    type FederationLinkResolver,
    type CredentialRevocationChecker,
    type ResolverKeyMaterial,
} from './credentials/credential-resolver/index.js';

// audit-share v0.2 L2 collaboration (multi-tenant audit isolation)
// verifyCrossTenantAccess (7-step fail-closed algorithm; steps 7-8 + atp v0.1)
// AuditShareTenantResolver port interface
// SQL migration 028: delegated_audit_keys + audit_share_access_log + tenant_audit_share_policy
export {
    createAuditShareTenantResolver,
    AuditShareCrossTenantRejectError,
    type AuditShareTenantResolver,
    type AuditKeyLookupPort,
    type PolicyLookupPort,
    type DelegatedAuditKeyRecord,
    type AuditShareScopeRecord,
    type PolicyRecord,
    type AuditShareTenantResolverDeps,
} from './sso/audit-share-tenant-resolver.js';

// sdk v0.2 L2 identity cryptographic verifier factory
// 3-kind verifier factory (mTLS / JWT / OAuth2) + boundary check helpers
// Module: cryptographic-verifier/ (verify-mtls.ts + verify-jwt.ts + verify-oauth2.ts + boundary-check.ts)
export {
    verifyMtlsAndDeriveDid,
    verifyJwtAndDeriveDid,
    verifyOAuth2AndDeriveDid,
    parseX509Cert,
    validateCertChain,
    extractDidFromCertSubject,
    JWT_ALG_ALLOWLIST,
    JWT_ALG_DENYLIST,
    verifyJwtAlgAllowed,
    OAuth2IntrospectionCache,
    OAuth2CircuitBreaker,
    OAuth2RateLimiter,
    assertTrustedDidMatchesExpected,
    assertTrustedDidIsKindAndFresh,
    extractDidFromCertSubjectDn,
    assertCrossCheckMappingConsistent,
} from './cryptographic-verifier/index.js';
