/**
 * SSO module exports (SAML + OIDC + federation)
 *
 * Design constraints (fail-closed + security P0 guards):
 *   - Do not export any helper that bypasses signature / expiry / audience checks
 *   - SamlProvider / OidcProvider must be built via *ProviderConfig dependency injection (no bare cast)
 *   - TenantFederationProvider / TenantFederationAdapter must be injected via FederationPort (no brand cast)
 *   - Do not export any helper that bypasses the three P0 guards (TENANT_SCOPE_MISSING / INVALID_TYPE / NOT_FOUND)
 */

// ── SAML types ─────────────────────────────────────────────────────────────────
export type {
    SamlConfig,
    SamlIdentityProvider,
    SamlUserClaims,
    SamlErrorCode,
    SamlNameIdFormat,
    // Placeholder type skeletons for later sections (not implemented; see oidc-provider.ts for the full OIDC types)
    OidcConfig,
    TenantFederationRule,
} from './types.js';

export {
    SamlAuthError,
    parseSamlConfig,
    parseSamlIdentityProvider,
    parseSamlClaims,
    parseSamlNameIdFormat,
    parseSamlUserClaims,
} from './types.js';

// ── SAML Provider + Port ───────────────────────────────────────────────────────
export {
    SamlProvider,
    NodeSamlAdapter,
    SamlVerificationError,
} from './saml-provider.js';

export type {
    SamlPort,
    SamlProviderConfig,
    SamlHandlerConfig,
} from './saml-provider.js';

// ── SAML Express handler factory ───────────────────────────────────────────────
export {
    createSamlLoginHandler,
    createSamlCallbackHandler,
    createSamlLogoutHandler,
    handleSamlError,
} from './saml-provider.js';

// ── OIDC types + error system ──────────────────────────────────────────────────────
export type {
    OidcErrorCode,
    OidcProviderConfig,
    OidcIdentityProvider,
    OidcUserClaims,
} from './oidc-provider.js';

export {
    OidcAuthError,
    OidcVerificationError,
    parseOidcProviderConfig,
    parseOidcIdentityProvider,
    parseOidcClaims,
    parseOidcUserClaims,
} from './oidc-provider.js';

// ── OIDC Provider + Port ──────────────────────────────────────────────────────
export { OidcProvider, OpenIdClientAdapter } from './oidc-provider.js';

export type {
    OidcPort,
    OidcProviderInitConfig,
    OidcHandlerConfig,
    OidcSessionStore,
} from './oidc-provider.js';

// ── OIDC Express handler factory ──────────────────────────────────────────────
export {
    createOidcLoginHandler,
    createOidcCallbackHandler,
    createOidcLogoutHandler,
    handleOidcError,
} from './oidc-provider.js';

// ── Federation error system ────────────────────────────────────────────────────────
export {
    FederationErrorCode,
    FederationError,
    sanitizeFederationError,
    parseRole,
} from './tenant-federation.js';

// ── Federation types ────────────────────────────────────────────────────────────
export type {
    FederationErrorCodeValue,
    Role,
    Tenant,
    IdpMapping,
    User,
    FederationAuditEvent,
    FederationPort,
    FederationHandlerConfig,
    FederationLogoutContext,
    SamlFederationInput,
    OidcFederationInput,
    FederationInput,
    FederationResolution,
} from './tenant-federation.js';

// ── Federation Adapter + Provider ─────────────────────────────────────────────
export {
    TenantFederationAdapter,
    TenantFederationProvider,
} from './tenant-federation.js';

// ── Federation Express handler factory ────────────────────────────────────────
export {
    handleFederationError,
    createFederationResolveHandler,
    createFederationLogoutHandler,
} from './tenant-federation.js';

// ── SSO SDK API ────────────────────────────────────────────
export type {
    SSOClientErrorCode,
    SSOClientConfig,
    InitiateLoginRequest,
    InitiateLoginResult,
    ResolveAuthenticationRequest,
    ResolveAuthenticationResult,
    LogoutRequest,
    LogoutResult,
} from './sdk-api.js';

export { SSOClient, SSOClientError } from './sdk-api.js';
