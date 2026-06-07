/**
 * OIDC Provider (OIDC integration)
 *
 * Responsibilities:
 *   - OidcPort: abstracts openid-client behavior (interface injection; supports test mocks)
 *   - OpenIdClientAdapter: the production implementation of OidcPort (wraps the openid-client v6 API)
 *   - OidcProvider: the core OIDC RP (Relying Party) implementation
 *     - generateAuthorizeUrl: generate the OIDC authorize URL (with state / nonce / PKCE)
 *     - verifyCallback: handle the authorization code callback (id_token JWS verification + 3 P0 guards)
 *     - generateEndSessionUrl: generate the OIDC RP-initiated logout URL
 *   - Express handler factory (aligned with the SAML pattern):
 *     - createOidcLoginHandler: generate the authorize URL -> redirect to the IDP
 *     - createOidcCallbackHandler: handle the callback -> verify -> return OidcUserClaims
 *     - createOidcLogoutHandler: generate the end_session URL -> redirect to the IDP
 *
 * Security P0 guards (literally forbidden — grep tests verify the source contains no skip keywords):
 *   - signature verification must never be skipped: openid-client.authorizationCodeGrant must verify the id_token JWS
 *     + missing jwks -> throw OIDC_CONFIG_INVALID (reject initialization)
 *   - expiry verification must never be skipped: id_token.exp must be in the future; access_token.expires_at is checked
 *   - issuer + audience verification must never be skipped:
 *     - issuer literally === the configured issuer (layer 2b strict); a missing issuer field -> fail-closed throw
 *     - audience (aud) must contain clientId (layer 2b strict); a missing audience field -> fail-closed throw
 *     - forbid bypass configuration such as wildcardClient / acceptAnyAudience / acceptUnknownIssuer
 *   - a stub default 200 is forbidden (fail-closed; all errors -> 4xx/5xx + OidcErrorCode)
 *
 * Scope boundaries (aligned with SAML; documented to-do boundaries):
 *   - OIDC: IDP authentication primitive (the responsibility of this file)
 *   - tenant-scope claim verification is not implemented (defense against cross-tenant id_token substitution attacks)
 *   - the tenant-scope claim -> tenant_id mapping is the responsibility of the federation section
 *   - OidcUserClaims contains no tenant_id field; the tenant mapping is handled by TenantFederationRule
 *
 * Reuse checklist relative to the SAML pattern:
 *   1. Port-Adapter 3 layers: OidcPort interface / OpenIdClientAdapter / OidcProvider business class
 *   2. Two-layer fail-closed: openid-client built-in (layer 1) + verifyClaimsFromIdToken (layer 2)
 *   3. 12-entry closed error-code enum + handleOidcError -> HTTP status code mapping
 *   4. sanitizeOidcErrorMessage: fixed strings for the 4 P0 codes / 256-character truncation on the default path
 *   5. parseOidcClaims: Object.create(null) + FORBIDDEN_ATTRIBUTE_NAMES to defend against prototype pollution
 *   6. 3 Express handler factories (login / callback / logout)
 *
 * @see SAML saml-provider.ts (the same pattern's reuse baseline)
 * @see federation (cross-ref: tenant-scope claim verification)
 */

// ── OIDC error code system (fail-closed) ────────────────────────────────────────────

/**
 * OIDC error codes (12-entry closed enum; fail-closed system)
 *
 * Conclusion: every OIDC verification failure maps to a specific error code;
 * error codes correspond to HTTP status codes (mapped in the handler layer);
 * a stub default 200 is forbidden.
 */
export type OidcErrorCode =
    | 'OIDC_CONFIG_INVALID' // invalid configuration (issuer/clientId/clientSecret/jwks missing)
    | 'OIDC_AUTHORIZE_URL_FAILED' // authorize URL generation failed
    | 'OIDC_CALLBACK_INVALID' // callback parameter missing/malformed
    | 'OIDC_SIGNATURE_INVALID' // id_token JWS signature verification failed (P0)
    | 'OIDC_EXPIRED' // id_token.exp expired / access_token expired (P0)
    | 'OIDC_ISSUER_MISMATCH' // id_token.iss does not match the configured issuer (P0)
    | 'OIDC_AUDIENCE_MISMATCH' // id_token.aud does not contain clientId (P0)
    | 'OIDC_NONCE_MISMATCH' // id_token.nonce does not match the session's expected nonce
    | 'OIDC_CLAIMS_INVALID' // claims extraction failed (e.g. missing sub / prototype pollution)
    | 'OIDC_TOKEN_INVALID' // wrong token type (e.g. missing id_token)
    | 'OIDC_LOGOUT_URL_FAILED' // end_session URL generation failed
    | 'OIDC_INTERNAL_ERROR'; // internal error (catch-all; fail-closed)

/**
 * OidcAuthError: base class for all OIDC-related errors (fail-closed)
 *
 * Trigger scenarios:
 *   - id_token signature verification failed -> OIDC_SIGNATURE_INVALID (P0; fail-closed; must reject)
 *   - id_token.exp expired -> OIDC_EXPIRED (P0; fail-closed; must reject)
 *   - issuer mismatch -> OIDC_ISSUER_MISMATCH (P0; fail-closed; must reject)
 *   - audience mismatch -> OIDC_AUDIENCE_MISMATCH (P0; fail-closed; must reject)
 *   - invalid configuration (missing jwks, etc.) -> OIDC_CONFIG_INVALID (fail-closed)
 *   - nonce mismatch -> OIDC_NONCE_MISMATCH
 */
export class OidcAuthError extends Error {
    readonly code: OidcErrorCode;

    constructor(message: string, code: OidcErrorCode = 'OIDC_INTERNAL_ERROR') {
        super(message);
        this.name = 'OidcAuthError';
        this.code = code;
        Object.setPrototypeOf(this, new.target.prototype);
    }
}

// ── OIDC configuration types ─────────────────────────────────────────────────────────────

/**
 * OIDC Relying Party (RP) configuration
 *
 * Naming: uses `OidcProviderConfig` to avoid clashing with the placeholder OidcConfig in types.ts
 * (the types.ts placeholder is an early simplified skeleton; this type is the fully implemented type).
 *
 * Security invariants:
 *   - issuer must be non-empty (used for strict id_token.iss matching; no wildcard)
 *   - clientId must be non-empty (used for strict id_token.aud matching)
 *   - clientSecret must be non-empty (client authentication; no empty bypass)
 *   - redirectUri must be non-empty (callback URL; consistent with the IDP registration)
 *   - jwksUri must be non-empty (used for id_token JWS signature verification; no empty bypass)
 */
export interface OidcProviderConfig {
    /** OP issuer (authorization server identifier; used for id_token.iss verification)*/
    readonly issuer: string;
    /** RP client_id (used for id_token.aud verification)*/
    readonly clientId: string;
    /** RP client_secret (client authentication)*/
    readonly clientSecret: string;
    /** RP callback URL (kept consistent with the IDP registration)*/
    readonly redirectUri: string;
    /** RP end_session post_logout_redirect_uri (redirect after SLO; optional)*/
    readonly postLogoutRedirectUri?: string;
    /** the requested set of scopes; defaults to ['openid', 'profile', 'email']*/
    readonly scopes?: readonly string[];
}

/**
 * OIDC Identity Provider (OP) metadata
 *
 * Conclusion: contains the OP endpoint URLs + the jwks URI;
 * obtained via discovery (well-known/openid-configuration) or configured manually;
 * jwksUri must be non-empty (used for id_token JWS signature verification).
 */
export interface OidcIdentityProvider {
    /** OP issuer (usually consistent with OidcProviderConfig.issuer)*/
    readonly issuer: string;
    /** OP authorization endpoint*/
    readonly authorizationEndpoint: string;
    /** OP token endpoint*/
    readonly tokenEndpoint: string;
    /** OP userinfo endpoint (optional)*/
    readonly userinfoEndpoint?: string;
    /** OP end_session endpoint (RP-initiated logout; optional)*/
    readonly endSessionEndpoint?: string;
    /** OP JWKS URI (must be non-empty; source of the id_token signing public key)*/
    readonly jwksUri: string;
}

/**
 * OIDC user claims (extracted after id_token verification passes)
 *
 * Conclusion: extracts sub + standard claims + additional claims from the id_token claims;
 * only data that has passed the OidcProvider verifyCallback verification flow can create this type (parseOidcClaims factory);
 * the tenant mapping is not in this type (the responsibility of the federation section).
 */
export interface OidcUserClaims {
    /** Subject identifier (unique identifier within the OP; id_token.sub)*/
    readonly sub: string;
    /** id_token.iss (verified === the configured issuer)*/
    readonly issuer: string;
    /** id_token.aud (verified to contain clientId)*/
    readonly audience: string;
    /** access_token (used for subsequent protected resource requests; optional)*/
    readonly accessToken?: string;
    /** refresh_token (if present; optional)*/
    readonly refreshToken?: string;
    /** id_token (verified; optionally retained for auditing)*/
    readonly idToken?: string;
    /** access_token expiry time (Unix epoch seconds; optional)*/
    readonly accessTokenExpiresAt?: number;
    /** id_token.exp (Unix epoch seconds)*/
    readonly idTokenExpiresAt: number;
    /** verification timestamp (ISO 8601)*/
    readonly verifiedAt: string;
    /** extracted additional claims (standard fields filtered out; prototype-pollution safe)*/
    readonly attributes: Readonly<Record<string, string>>;
}

// ── Configuration parse / validate (bare casts forbidden) ────────────────────────────────────

/**
 * parseOidcProviderConfig: validate and build OidcProviderConfig (bare casts forbidden)
 *
 * Conclusion: the only valid path to create OidcProviderConfig;
 * a missing field -> fail-closed (OidcAuthError OIDC_CONFIG_INVALID).
 *
 * @throws OidcAuthError OIDC_CONFIG_INVALID if the configuration is invalid
 */
export function parseOidcProviderConfig(
    raw: Record<string, unknown>,
): OidcProviderConfig {
    const issuer = raw['issuer'];
    if (typeof issuer !== 'string' || issuer.trim() === '') {
        throw new OidcAuthError(
            'OidcProviderConfig.issuer is required and must be a non-empty string.',
            'OIDC_CONFIG_INVALID',
        );
    }

    const clientId = raw['clientId'];
    if (typeof clientId !== 'string' || clientId.trim() === '') {
        throw new OidcAuthError(
            'OidcProviderConfig.clientId is required and must be a non-empty string.',
            'OIDC_CONFIG_INVALID',
        );
    }

    const clientSecret = raw['clientSecret'];
    if (typeof clientSecret !== 'string' || clientSecret.trim() === '') {
        // P0: an empty client_secret is equivalent to no client authentication -> fail-closed reject
        throw new OidcAuthError(
            'OidcProviderConfig.clientSecret is required and must be non-empty. ' +
                'Empty client_secret would bypass OIDC client authentication.',
            'OIDC_CONFIG_INVALID',
        );
    }

    const redirectUri = raw['redirectUri'];
    if (typeof redirectUri !== 'string' || redirectUri.trim() === '') {
        throw new OidcAuthError(
            'OidcProviderConfig.redirectUri is required and must be a non-empty string.',
            'OIDC_CONFIG_INVALID',
        );
    }

    const postLogoutRedirectUri =
        typeof raw['postLogoutRedirectUri'] === 'string' &&
        raw['postLogoutRedirectUri'].trim() !== ''
            ? raw['postLogoutRedirectUri'].trim()
            : undefined;

    const rawScopes = raw['scopes'];
    const scopes: readonly string[] | undefined = Array.isArray(rawScopes)
        ? Object.freeze(
              rawScopes.filter(
                  (s): s is string => typeof s === 'string' && s.trim() !== '',
              ),
          )
        : undefined;

    return {
        issuer: issuer.trim(),
        clientId: clientId.trim(),
        clientSecret: clientSecret.trim(),
        redirectUri: redirectUri.trim(),
        postLogoutRedirectUri,
        scopes,
    };
}

/**
 * parseOidcIdentityProvider: validate and build OidcIdentityProvider (bare casts forbidden)
 *
 * @throws OidcAuthError OIDC_CONFIG_INVALID if the configuration is invalid (a missing jwksUri would bypass signature verification)
 */
export function parseOidcIdentityProvider(
    raw: Record<string, unknown>,
): OidcIdentityProvider {
    const issuer = raw['issuer'];
    if (typeof issuer !== 'string' || issuer.trim() === '') {
        throw new OidcAuthError(
            'OidcIdentityProvider.issuer is required.',
            'OIDC_CONFIG_INVALID',
        );
    }

    const authorizationEndpoint = raw['authorizationEndpoint'];
    if (
        typeof authorizationEndpoint !== 'string' ||
        authorizationEndpoint.trim() === ''
    ) {
        throw new OidcAuthError(
            'OidcIdentityProvider.authorizationEndpoint is required.',
            'OIDC_CONFIG_INVALID',
        );
    }

    const tokenEndpoint = raw['tokenEndpoint'];
    if (typeof tokenEndpoint !== 'string' || tokenEndpoint.trim() === '') {
        throw new OidcAuthError(
            'OidcIdentityProvider.tokenEndpoint is required.',
            'OIDC_CONFIG_INVALID',
        );
    }

    const jwksUri = raw['jwksUri'];
    if (typeof jwksUri !== 'string' || jwksUri.trim() === '') {
        // P0: a missing jwksUri -> cannot verify the id_token JWS signature -> fail-closed reject
        throw new OidcAuthError(
            'OidcIdentityProvider.jwksUri is required and must be non-empty. ' +
                'Empty jwksUri would bypass OIDC id_token signature verification (P0 violation).',
            'OIDC_CONFIG_INVALID',
        );
    }

    const userinfoEndpoint =
        typeof raw['userinfoEndpoint'] === 'string' &&
        raw['userinfoEndpoint'].trim() !== ''
            ? raw['userinfoEndpoint'].trim()
            : undefined;
    const endSessionEndpoint =
        typeof raw['endSessionEndpoint'] === 'string' &&
        raw['endSessionEndpoint'].trim() !== ''
            ? raw['endSessionEndpoint'].trim()
            : undefined;

    return {
        issuer: issuer.trim(),
        authorizationEndpoint: authorizationEndpoint.trim(),
        tokenEndpoint: tokenEndpoint.trim(),
        userinfoEndpoint,
        endSessionEndpoint,
        jwksUri: jwksUri.trim(),
    };
}

// ── parseOidcClaims (with prototype pollution defense; same pattern as SAML) ────

/**
 * parseOidcClaims: build OidcUserClaims from id_token claims (bare casts forbidden)
 *
 * Conclusion: the only valid path to create OidcUserClaims;
 * a missing / wrong-typed sub -> fail-closed throw (OIDC_CLAIMS_INVALID);
 * a prototype pollution attribute name (__proto__ / constructor / prototype) -> throw (fail-closed).
 *
 * Same pattern as SAML:
 *   - use Object.create(null) as the attributes base (eliminating the prototype chain)
 *   - reject known prototype pollution attack attribute names
 *   - the IDP can inject dangerous attribute names; without rejection, Object.freeze cannot block the prototype-pollution surface
 *
 * @param claims the id_token JWT Claims Set returned by openid-client.claims()
 * @param issuer the verified issuer
 * @param audience the verified audience (clientId)
 * @param tokenExtras additional token fields (accessToken / refreshToken / idToken / accessTokenExpiresAt)
 * @throws OidcAuthError OIDC_CLAIMS_INVALID if a required field is missing or it contains a forbidden attribute name
 */
export function parseOidcClaims(
    claims: Record<string, unknown>,
    issuer: string,
    audience: string,
    tokenExtras?: {
        accessToken?: string;
        refreshToken?: string;
        idToken?: string;
        accessTokenExpiresAt?: number;
    },
): OidcUserClaims {
    // sub must be present and non-empty
    const sub = claims['sub'];
    if (typeof sub !== 'string' || sub.trim() === '') {
        throw new OidcAuthError(
            'OIDC id_token missing valid "sub" claim.',
            'OIDC_CLAIMS_INVALID',
        );
    }

    // exp must be a finite number (Unix epoch seconds)
    const exp = claims['exp'];
    if (typeof exp !== 'number' || !Number.isFinite(exp)) {
        throw new OidcAuthError(
            'OIDC id_token missing valid "exp" claim.',
            'OIDC_CLAIMS_INVALID',
        );
    }

    // Known OIDC standard fields (not placed into attributes)
    const RESERVED_CLAIM_KEYS = new Set([
        'sub',
        'iss',
        'aud',
        'exp',
        'iat',
        'auth_time',
        'nonce',
        'acr',
        'amr',
        'azp',
        'nbf',
        'jti',
        'at_hash',
        'c_hash',
        's_hash',
    ]);

    // prototype pollution defense (same pattern as SAML)
    const FORBIDDEN_ATTRIBUTE_NAMES = new Set([
        '__proto__',
        'constructor',
        'prototype',
    ]);

    const attributes = Object.create(null) as Record<string, string>;
    for (const [key, value] of Object.entries(claims)) {
        if (FORBIDDEN_ATTRIBUTE_NAMES.has(key)) {
            throw new OidcAuthError(
                `OIDC claims contain forbidden attribute name: "${key}". ` +
                    'Prototype pollution attack detected. Authentication rejected (fail-closed).',
                'OIDC_CLAIMS_INVALID',
            );
        }
        if (RESERVED_CLAIM_KEYS.has(key)) continue;
        if (typeof value === 'string') {
            attributes[key] = value;
        }
    }

    return {
        sub: sub.trim(),
        issuer,
        audience,
        accessToken: tokenExtras?.accessToken,
        refreshToken: tokenExtras?.refreshToken,
        idToken: tokenExtras?.idToken,
        accessTokenExpiresAt: tokenExtras?.accessTokenExpiresAt,
        idTokenExpiresAt: exp,
        verifiedAt: new Date().toISOString(),
        attributes: Object.freeze(attributes),
    };
}

/**
 * parseOidcUserClaims: build OidcUserClaims from an unknown HTTP body (bare casts forbidden)
 *
 * Conclusion: use this function in place of a bare cast when the handler layer receives an unknown claims object from the HTTP body;
 * a missing field or invalid type -> fail-closed (OidcAuthError OIDC_CLAIMS_INVALID).
 *
 * @throws OidcAuthError OIDC_CLAIMS_INVALID if a required field is missing or has an invalid type
 */
export function parseOidcUserClaims(input: unknown): OidcUserClaims {
    if (!input || typeof input !== 'object') {
        throw new OidcAuthError(
            'OidcUserClaims: input must be a non-null object.',
            'OIDC_CLAIMS_INVALID',
        );
    }
    const raw = input as Record<string, unknown>;

    const sub = raw['sub'];
    if (typeof sub !== 'string' || sub.trim() === '') {
        throw new OidcAuthError(
            'OidcUserClaims.sub is required and must be a non-empty string.',
            'OIDC_CLAIMS_INVALID',
        );
    }

    const issuer = raw['issuer'];
    if (typeof issuer !== 'string' || issuer.trim() === '') {
        throw new OidcAuthError(
            'OidcUserClaims.issuer is required and must be a non-empty string.',
            'OIDC_CLAIMS_INVALID',
        );
    }

    const audience = raw['audience'];
    if (typeof audience !== 'string' || audience.trim() === '') {
        throw new OidcAuthError(
            'OidcUserClaims.audience is required and must be a non-empty string.',
            'OIDC_CLAIMS_INVALID',
        );
    }

    const idTokenExpiresAt = raw['idTokenExpiresAt'];
    if (typeof idTokenExpiresAt !== 'number' || !Number.isFinite(idTokenExpiresAt)) {
        throw new OidcAuthError(
            'OidcUserClaims.idTokenExpiresAt is required and must be a finite number.',
            'OIDC_CLAIMS_INVALID',
        );
    }

    const verifiedAt = raw['verifiedAt'];
    if (typeof verifiedAt !== 'string' || verifiedAt.trim() === '') {
        throw new OidcAuthError(
            'OidcUserClaims.verifiedAt is required and must be a non-empty ISO 8601 string.',
            'OIDC_CLAIMS_INVALID',
        );
    }

    const FORBIDDEN_ATTRIBUTE_NAMES = new Set(['__proto__', 'constructor', 'prototype']);
    const rawAttributes = raw['attributes'];
    if (!rawAttributes || typeof rawAttributes !== 'object' || Array.isArray(rawAttributes)) {
        throw new OidcAuthError(
            'OidcUserClaims.attributes is required and must be a non-null object.',
            'OIDC_CLAIMS_INVALID',
        );
    }
    const attributes = Object.create(null) as Record<string, string>;
    for (const [key, value] of Object.entries(rawAttributes as Record<string, unknown>)) {
        if (FORBIDDEN_ATTRIBUTE_NAMES.has(key)) {
            throw new OidcAuthError(
                `OidcUserClaims.attributes contains forbidden key "${key}".`,
                'OIDC_CLAIMS_INVALID',
            );
        }
        if (typeof value === 'string') {
            attributes[key] = value;
        }
    }

    return {
        sub: sub.trim(),
        issuer: issuer.trim(),
        audience: audience.trim(),
        accessToken: typeof raw['accessToken'] === 'string' ? raw['accessToken'] : undefined,
        refreshToken: typeof raw['refreshToken'] === 'string' ? raw['refreshToken'] : undefined,
        idToken: typeof raw['idToken'] === 'string' ? raw['idToken'] : undefined,
        accessTokenExpiresAt:
            typeof raw['accessTokenExpiresAt'] === 'number'
                ? raw['accessTokenExpiresAt']
                : undefined,
        idTokenExpiresAt,
        verifiedAt: verifiedAt.trim(),
        attributes: Object.freeze(attributes),
    };
}

// ── OidcPort (interface injection; test mock + production openid-client) ──────────────────────

/**
 * OidcPort: interface abstracting openid-client behavior
 *
 * Conclusion: isolates the openid-client implementation via interface injection;
 *   - tests inject a mock (without depending on an actual openid-client installation)
 *   - production injects OpenIdClientAdapter (which wraps openid-client v6)
 *
 * Security constraints:
 *   - getAuthorizeUrl: generate the authorize URL; must include state / nonce / optional PKCE
 *   - verifyCallback: fully execute the authorization code grant; verify the id_token JWS + claims;
 *     any verification failure -> throw (a stub success is not allowed)
 *   - getEndSessionUrl: generate the end_session URL; if the OP does not support it -> throw
 */
export interface OidcPort {
    /**
     * Generate the OIDC authorize URL
     *
     * @param params must contain state / nonce; optional scope / pkce_code_challenge / other parameters
     * @returns the OIDC authorize URL (with all required query parameters)
     * @throws if generation fails -> reject
     */
    getAuthorizeUrl(params: {
        state: string;
        nonce: string;
        codeChallenge?: string;
        codeChallengeMethod?: 'S256';
        scopes?: readonly string[];
        extraParams?: Record<string, string>;
    }): Promise<string>;

    /**
     * Handle the callback URL: fully execute the authorization code grant + verify the id_token
     *
     * Security P0 invariants (all must be verified):
     *   1. Signature verification: the id_token JWS must be verified with the jwks public key
     *   2. Expiry verification: id_token.exp must be > now
     *   3. Issuer verification: id_token.iss must === the configured issuer
     *   4. Audience verification: id_token.aud must contain clientId
     *
     * @param currentUrl the callback URL (with code / state, etc.)
     * @param expectedNonce the expected nonce (must match the nonce generated at authorize time)
     * @param codeVerifier the PKCE code_verifier (if PKCE is used)
     * @param expectedState the expected state (CSRF defense)
     * @returns the verified token response (with id_token / access_token / claims helper)
     * @throws OidcVerificationError on any verification failure (does not return a partial result)
     */
    verifyCallback(params: {
        currentUrl: URL | string;
        expectedNonce: string;
        expectedState: string;
        codeVerifier?: string;
    }): Promise<{
        idToken?: string;
        accessToken?: string;
        refreshToken?: string;
        expiresIn?: number;
        claims: Record<string, unknown>;
    }>;

    /**
     * Generate the OIDC RP-initiated end_session URL
     *
     * @param params must contain idTokenHint; optional postLogoutRedirectUri / state
     * @returns the end_session URL (with query parameters)
     * @throws OidcAuthError if the OP does not support end_session_endpoint
     */
    getEndSessionUrl(params: {
        idTokenHint: string;
        postLogoutRedirectUri?: string;
        state?: string;
    }): Promise<string>;
}

/**
 * OidcVerificationError: the verification error thrown internally by OidcPort.verifyCallback
 *
 * Conclusion: distinguishes different verification failure reasons so OidcProvider can map them to an OidcErrorCode;
 * the reason field is diagnostic information (not exposed to the end user).
 */
export class OidcVerificationError extends Error {
    readonly reason: string;

    constructor(reason: string) {
        super(`OIDC verification failed: ${reason}`);
        this.name = 'OidcVerificationError';
        this.reason = reason;
        Object.setPrototypeOf(this, new.target.prototype);
    }
}

// ── OpenIdClientAdapter (production implementation; wraps openid-client v6) ────────────────────

/**
 * OpenIdClientAdapter: the production implementation of OidcPort
 *
 * Conclusion: used in production; in tests a mock is injected via the OidcProviderConfig.oidcPort parameter.
 * Uses a dynamic import to lazily load openid-client, avoiding a hard dependency in the test environment.
 *
 * Security constraints (corresponding to the OidcPort contract):
 *   - jwksUri must be non-empty at construction time (already guaranteed by parseOidcIdentityProvider; double safeguard here)
 *   - no allowInsecureRequests (HTTP) configuration may be passed to openid-client (unless in an explicit dev mode; not supported by this class)
 *   - no configuration that bypasses signature / expiry / issuer / audience may be passed to openid-client
 *
 * openid-client v6 behavioral dependencies:
 *   - discovery() automatically fetches the jwks_uri (used for id_token JWS verification)
 *   - authorizationCodeGrant() internally verifies the id_token:
 *     - JWS signature (with the jwks public key)
 *     - exp / iat / nbf (if present)
 *     - iss === server.issuer
 *     - aud contains clientId
 *     - nonce === expectedNonce
 *     - state === expectedState
 *   - any verification failure -> throw (fail-closed)
 */
export class OpenIdClientAdapter implements OidcPort {
    private readonly config: OidcProviderConfig;
    private readonly idp: OidcIdentityProvider;
    /** the openid-client Configuration instance (lazily loaded)*/
    private clientConfiguration: unknown = null;

    constructor(config: OidcProviderConfig, idp: OidcIdentityProvider) {
        // Defensive validation: jwksUri must be non-empty (double safeguard; already checked by parseOidcIdentityProvider)
        if (!idp.jwksUri || idp.jwksUri.trim() === '') {
            throw new OidcAuthError(
                'OpenIdClientAdapter: jwksUri is empty. ' +
                    'Cannot initialize OIDC without IDP JWKS endpoint (P0 violation: signature verification unavailable).',
                'OIDC_CONFIG_INVALID',
            );
        }
        if (!config.clientSecret || config.clientSecret.trim() === '') {
            throw new OidcAuthError(
                'OpenIdClientAdapter: clientSecret is empty. ' +
                    'Cannot initialize OIDC client authentication without client_secret.',
                'OIDC_CONFIG_INVALID',
            );
        }
        this.config = config;
        this.idp = idp;
    }

    /**
     * Lazily load and initialize the openid-client Configuration
     *
     * Security constraints:
     *   - do not call allowInsecureRequests (HTTPS enforced)
     *   - do not pass implicit-flow options such as useIdTokenResponseType (authorization code grant only)
     *   - jwks is fetched automatically by openid-client via jwks_uri (cached)
     */
    private async getConfiguration(): Promise<unknown> {
        if (this.clientConfiguration) return this.clientConfiguration;

        // Dynamic import: avoids a hard dependency in the test environment
        // Note: use a two-layer `as unknown as ...` cast to isolate openid-client v6's strongly-typed signatures
        // - first layer unknown: declares that this Adapter does not depend on the actual shape of openid-client's internal ServerMetadata
        // - second layer minimal interface: this Adapter uses only the Configuration ctor + ClientSecretPost
        // - at runtime, openid-client's ServerMetadata validation logic is responsible for field completeness
        const oidcModule = await import('openid-client').catch(
            (err: unknown) => {
                throw new OidcAuthError(
                    `Failed to load openid-client: ${err instanceof Error ? err.message : String(err)}. ` +
                        'Ensure openid-client is installed in production.',
                    'OIDC_INTERNAL_ERROR',
                );
            },
        );
        const oidc = oidcModule as unknown as {
            Configuration: new (
                server: Record<string, unknown>,
                clientId: string,
                metadata?: Record<string, unknown> | string,
                clientAuthentication?: unknown,
            ) => unknown;
            ClientSecretPost: (clientSecret: string) => unknown;
        };

        // Construct ServerMetadata (OIDC OP metadata; minimal set)
        // Note: this Adapter does not perform automatic .well-known/openid-configuration discovery,
        // but passes values directly from the OidcIdentityProvider configuration (avoiding runtime network side effects)
        const serverMetadata: Record<string, unknown> = {
            issuer: this.idp.issuer,
            authorization_endpoint: this.idp.authorizationEndpoint,
            token_endpoint: this.idp.tokenEndpoint,
            jwks_uri: this.idp.jwksUri, // must be non-empty (validated by the constructor)
        };
        if (this.idp.userinfoEndpoint) {
            serverMetadata['userinfo_endpoint'] = this.idp.userinfoEndpoint;
        }
        if (this.idp.endSessionEndpoint) {
            serverMetadata['end_session_endpoint'] =
                this.idp.endSessionEndpoint;
        }

        try {
            this.clientConfiguration = new oidc.Configuration(
                serverMetadata,
                this.config.clientId,
                {
                    client_secret: this.config.clientSecret,
                    redirect_uris: [this.config.redirectUri],
                    response_types: ['code'],
                },
                oidc.ClientSecretPost(this.config.clientSecret),
            );
        } catch (err: unknown) {
            throw new OidcAuthError(
                `Failed to construct openid-client Configuration: ${err instanceof Error ? err.message : String(err)}`,
                'OIDC_CONFIG_INVALID',
            );
        }

        return this.clientConfiguration;
    }

    async getAuthorizeUrl(params: {
        state: string;
        nonce: string;
        codeChallenge?: string;
        codeChallengeMethod?: 'S256';
        scopes?: readonly string[];
        extraParams?: Record<string, string>;
    }): Promise<string> {
        const cfg = await this.getConfiguration();
        const oidcMod = await import('openid-client');
        const oidc = oidcMod as unknown as {
            buildAuthorizationUrl: (
                config: unknown,
                parameters: Record<string, string>,
            ) => URL;
        };

        const scopes =
            params.scopes && params.scopes.length > 0
                ? params.scopes
                : this.config.scopes && this.config.scopes.length > 0
                  ? this.config.scopes
                  : ['openid', 'profile', 'email'];

        const queryParams: Record<string, string> = {
            redirect_uri: this.config.redirectUri,
            scope: scopes.join(' '),
            state: params.state,
            nonce: params.nonce,
        };
        if (params.codeChallenge) {
            queryParams['code_challenge'] = params.codeChallenge;
            queryParams['code_challenge_method'] =
                params.codeChallengeMethod ?? 'S256';
        }
        if (params.extraParams) {
            for (const [key, value] of Object.entries(params.extraParams)) {
                queryParams[key] = value;
            }
        }

        try {
            const url = oidc.buildAuthorizationUrl(cfg, queryParams);
            return url.toString();
        } catch (err: unknown) {
            throw new OidcAuthError(
                `Failed to build OIDC authorize URL: ${err instanceof Error ? err.message : String(err)}`,
                'OIDC_AUTHORIZE_URL_FAILED',
            );
        }
    }

    async verifyCallback(params: {
        currentUrl: URL | string;
        expectedNonce: string;
        expectedState: string;
        codeVerifier?: string;
    }): Promise<{
        idToken?: string;
        accessToken?: string;
        refreshToken?: string;
        expiresIn?: number;
        claims: Record<string, unknown>;
    }> {
        const cfg = await this.getConfiguration();
        const oidcMod = await import('openid-client');
        const oidc = oidcMod as unknown as {
            authorizationCodeGrant: (
                config: unknown,
                currentUrl: URL | Request,
                checks?: {
                    expectedNonce?: string;
                    expectedState?: string;
                    pkceCodeVerifier?: string;
                },
            ) => Promise<{
                id_token?: string;
                access_token?: string;
                refresh_token?: string;
                expires_in?: number;
                claims(): Record<string, unknown> | undefined;
            }>;
        };

        const urlObj =
            typeof params.currentUrl === 'string'
                ? new URL(params.currentUrl)
                : params.currentUrl;

        try {
            // openid-client.authorizationCodeGrant verifies internally:
            // 1. id_token JWS signature (with jwks)
            // 2. iss === server.issuer
            // 3. aud contains clientId
            // 4. exp > now
            // 5. nonce === expectedNonce
            // 6. state === expectedState
            // Any failure -> throw (fail-closed)
            const tokenResponse = await oidc.authorizationCodeGrant(
                cfg,
                urlObj,
                {
                    expectedNonce: params.expectedNonce,
                    expectedState: params.expectedState,
                    pkceCodeVerifier: params.codeVerifier,
                },
            );

            const claims = tokenResponse.claims();
            if (!claims) {
                // Missing id_token -> fail-closed reject (a bare access_token is not accepted)
                throw new OidcVerificationError(
                    'token response missing id_token claims',
                );
            }

            return {
                idToken: tokenResponse.id_token,
                accessToken: tokenResponse.access_token,
                refreshToken: tokenResponse.refresh_token,
                expiresIn: tokenResponse.expires_in,
                claims,
            };
        } catch (err: unknown) {
            if (err instanceof OidcVerificationError) throw err;
            const reason = err instanceof Error ? err.message : String(err);
            throw new OidcVerificationError(reason);
        }
    }

    async getEndSessionUrl(params: {
        idTokenHint: string;
        postLogoutRedirectUri?: string;
        state?: string;
    }): Promise<string> {
        if (!this.idp.endSessionEndpoint) {
            throw new OidcAuthError(
                'OIDC OP does not advertise end_session_endpoint; cannot generate logout URL.',
                'OIDC_LOGOUT_URL_FAILED',
            );
        }

        const cfg = await this.getConfiguration();
        const oidcMod = await import('openid-client');
        const oidc = oidcMod as unknown as {
            buildEndSessionUrl: (
                config: unknown,
                parameters: Record<string, string>,
            ) => URL;
        };

        const queryParams: Record<string, string> = {
            id_token_hint: params.idTokenHint,
        };
        if (params.postLogoutRedirectUri) {
            queryParams['post_logout_redirect_uri'] =
                params.postLogoutRedirectUri;
        } else if (this.config.postLogoutRedirectUri) {
            queryParams['post_logout_redirect_uri'] =
                this.config.postLogoutRedirectUri;
        }
        if (params.state) {
            queryParams['state'] = params.state;
        }

        try {
            const url = oidc.buildEndSessionUrl(cfg, queryParams);
            return url.toString();
        } catch (err: unknown) {
            throw new OidcAuthError(
                `Failed to build OIDC end_session URL: ${err instanceof Error ? err.message : String(err)}`,
                'OIDC_LOGOUT_URL_FAILED',
            );
        }
    }
}

// ── OidcProvider (business core; wraps OidcPort + the two-layer 3 P0 guards) ─────────────────

/**
 * OidcProvider configuration (dependency injection)
 */
export interface OidcProviderInitConfig {
    /** RP configuration (issuer / clientId / clientSecret / redirectUri; already validated by parseOidcProviderConfig)*/
    readonly config: OidcProviderConfig;
    /** OP configuration (jwksUri, etc.; already validated by parseOidcIdentityProvider)*/
    readonly idp: OidcIdentityProvider;
    /**
     * OIDC port implementation injection (production = OpenIdClientAdapter; tests = mock)
     * If omitted, production automatically creates an OpenIdClientAdapter.
     */
    readonly oidcPort?: OidcPort;
}

/**
 * OidcProvider: the core OIDC RP implementation
 *
 * Conclusion: wraps the OidcPort interface; provides 3 main methods (generateAuthorizeUrl / verifyCallback / generateEndSessionUrl);
 * any callback verification failure -> fail-closed (reject + OidcAuthError);
 * no partial-PASS allowed.
 *
 * Security P0 invariants (all three must pass; any failure -> reject):
 *   Layer 1 (OidcPort.verifyCallback / openid-client.authorizationCodeGrant):
 *     1. id_token JWS signature verification (with jwks)
 *     2. id_token.exp / iat / nbf verification
 *     3. id_token.iss === server.issuer
 *     4. id_token.aud contains clientId
 *     5. id_token.nonce === expectedNonce
 *     6. state === expectedState
 *
 *   Layer 1.5 (classifyVerificationError):
 *     - classify OidcVerificationError.reason into an OidcErrorCode
 *     - unknown reason -> OIDC_SIGNATURE_INVALID (the strictest fallback; fail-closed)
 *
 *   Layer 2a (verifyExpiryFromClaims):
 *     - an additional literal check from claims.exp (double safeguard)
 *     - a missing field silent-returns (trusting layer 1; same pattern as SAML expiry)
 *
 *   Layer 2b (verifyIssuerAudienceFromClaims):
 *     - an additional literal === check from claims.iss / claims.aud (double safeguard)
 *     - a missing issuer / audience field -> fail-closed throw (cf. the SAML audience patch)
 *
 * Scope boundaries (see the file header):
 *   - this class's responsibility: IDP authentication primitive
 *   - tenant-scope claim verification (cross-tenant id_token substitution attacks) -> @see TenantFederationRule
 *   - OidcUserClaims contains no tenant_id; the tenant mapping is implemented in the federation section
 */
export class OidcProvider {
    private readonly config: OidcProviderConfig;
    private readonly idp: OidcIdentityProvider;
    private readonly oidcPort: OidcPort;

    constructor(initConfig: OidcProviderInitConfig) {
        // Defensive validation: jwksUri must be non-empty (already checked by parseOidcIdentityProvider; double safeguard here)
        if (!initConfig.idp.jwksUri || initConfig.idp.jwksUri.trim() === '') {
            throw new OidcAuthError(
                'OidcProvider: OidcIdentityProvider.jwksUri must be non-empty. ' +
                    'Empty jwks would bypass id_token signature verification (P0 violation).',
                'OIDC_CONFIG_INVALID',
            );
        }
        if (
            !initConfig.config.clientSecret ||
            initConfig.config.clientSecret.trim() === ''
        ) {
            throw new OidcAuthError(
                'OidcProvider: OidcProviderConfig.clientSecret must be non-empty.',
                'OIDC_CONFIG_INVALID',
            );
        }
        this.config = initConfig.config;
        this.idp = initConfig.idp;
        // Production: if oidcPort is not provided, automatically create an OpenIdClientAdapter
        this.oidcPort =
            initConfig.oidcPort ??
            new OpenIdClientAdapter(initConfig.config, initConfig.idp);
    }

    /**
     * generateAuthorizeUrl: generate the OIDC authorize URL
     *
     * @param params must contain state / nonce; optional codeChallenge / scopes / extraParams
     * @returns the authorize URL
     * @throws OidcAuthError OIDC_AUTHORIZE_URL_FAILED if generation fails
     */
    async generateAuthorizeUrl(params: {
        state: string;
        nonce: string;
        codeChallenge?: string;
        codeChallengeMethod?: 'S256';
        scopes?: readonly string[];
        extraParams?: Record<string, string>;
    }): Promise<string> {
        // state / nonce must be non-empty (the basis of CSRF / replay defense)
        if (!params.state || params.state.trim() === '') {
            throw new OidcAuthError(
                'OIDC authorize requires non-empty "state" parameter for CSRF protection.',
                'OIDC_AUTHORIZE_URL_FAILED',
            );
        }
        if (!params.nonce || params.nonce.trim() === '') {
            throw new OidcAuthError(
                'OIDC authorize requires non-empty "nonce" parameter for replay protection.',
                'OIDC_AUTHORIZE_URL_FAILED',
            );
        }

        try {
            return await this.oidcPort.getAuthorizeUrl(params);
        } catch (err: unknown) {
            if (err instanceof OidcAuthError) throw err;
            throw new OidcAuthError(
                `Authorize URL generation failed: ${err instanceof Error ? err.message : String(err)}`,
                'OIDC_AUTHORIZE_URL_FAILED',
            );
        }
    }

    /**
     * verifyCallback: handle the authorization code callback + verify the id_token + extract the user claims
     *
     * Security P0 invariants (three layers of verification; all must pass):
     *
     * Layer 1 (OidcPort.verifyCallback):
     *   - id_token JWS signature verification (with the jwks public key; built into openid-client)
     *   - time verification (exp / iat / nbf; built into openid-client)
     *   - issuer verification (iss === server.issuer; built into openid-client)
     *   - audience verification (aud contains clientId; built into openid-client)
     *   - nonce verification (nonce === expectedNonce; built into openid-client)
     *   - state verification (state === expectedState; built into openid-client)
     *
     * Layer 2a (this method's verifyExpiryFromClaims; double safeguard):
     *   - literally extract from claims.exp and re-check (guards against an internal openid-client regression bug)
     *
     * Layer 2b (this method's verifyIssuerAudienceFromClaims; double safeguard):
     *   - literally check claims.iss === the configured issuer (a missing issuer field -> throw; cf. SAML)
     *   - literally verify claims.aud contains clientId (a missing audience field -> throw; cf. SAML)
     *
     * Layer 3 (parseOidcClaims):
     *   - sub must be non-empty + correctly typed
     *   - reject prototype pollution attribute names
     *
     * @param params the callback parameters (with currentUrl / expectedNonce / expectedState / codeVerifier)
     * @returns the verified OidcUserClaims
     * @throws OidcAuthError any verification failure -> fail-closed reject (does not return a partial result)
     */
    async verifyCallback(params: {
        currentUrl: URL | string;
        expectedNonce: string;
        expectedState: string;
        codeVerifier?: string;
    }): Promise<OidcUserClaims> {
        // Layer 1: OidcPort verification (openid-client's built-in 6 checks)
        let tokenResponse: {
            idToken?: string;
            accessToken?: string;
            refreshToken?: string;
            expiresIn?: number;
            claims: Record<string, unknown>;
        };
        try {
            tokenResponse = await this.oidcPort.verifyCallback(params);
        } catch (err: unknown) {
            if (err instanceof OidcVerificationError) {
                // Layer 1.5: classify and map the reason to an OidcErrorCode
                const code = this.classifyVerificationError(err.reason);
                throw new OidcAuthError(
                    `OIDC callback verification failed: ${err.reason}`,
                    code,
                );
            }
            if (err instanceof OidcAuthError) throw err;
            throw new OidcAuthError(
                `OIDC callback verification failed: ${err instanceof Error ? err.message : String(err)}`,
                'OIDC_CALLBACK_INVALID',
            );
        }

        const claims = tokenResponse.claims;

        // Layer 2a: literal expiry verification (double safeguard; a missing field silent-returns = trusting layer 1)
        this.verifyExpiryFromClaims(claims, tokenResponse.expiresIn);

        // Layer 2b: literal issuer + audience verification (double safeguard; a missing field -> throw)
        this.verifyIssuerAudienceFromClaims(claims);

        // Layer 3: parseOidcClaims (sub extraction + prototype pollution defense)
        const accessTokenExpiresAt =
            typeof tokenResponse.expiresIn === 'number' &&
            Number.isFinite(tokenResponse.expiresIn)
                ? Math.floor(Date.now() / 1000) + tokenResponse.expiresIn
                : undefined;

        try {
            // Note: iss / aud have already passed layer 2b verification; extract them again here as a verified copy
            const verifiedIssuer = String(claims['iss']);
            const verifiedAudience = this.extractFirstAudience(claims['aud']);
            return parseOidcClaims(claims, verifiedIssuer, verifiedAudience, {
                idToken: tokenResponse.idToken,
                accessToken: tokenResponse.accessToken,
                refreshToken: tokenResponse.refreshToken,
                accessTokenExpiresAt,
            });
        } catch (err: unknown) {
            if (err instanceof OidcAuthError) throw err;
            throw new OidcAuthError(
                `OIDC claims extraction failed: ${err instanceof Error ? err.message : String(err)}`,
                'OIDC_CLAIMS_INVALID',
            );
        }
    }

    /**
     * generateEndSessionUrl: generate the OIDC RP-initiated end_session URL
     *
     * @param claims the verified OidcUserClaims (provides idToken; returned from verifyCallback)
     * @param state an optional state parameter (CSRF defense; recommended to provide)
     * @returns the end_session URL
     * @throws OidcAuthError OIDC_LOGOUT_URL_FAILED if generation fails / the OP does not support it
     */
    async generateEndSessionUrl(
        claims: OidcUserClaims,
        state?: string,
    ): Promise<string> {
        if (!claims.idToken || claims.idToken.trim() === '') {
            throw new OidcAuthError(
                'OIDC end_session requires non-empty id_token_hint from previously verified claims.',
                'OIDC_LOGOUT_URL_FAILED',
            );
        }
        try {
            return await this.oidcPort.getEndSessionUrl({
                idTokenHint: claims.idToken,
                postLogoutRedirectUri: this.config.postLogoutRedirectUri,
                state,
            });
        } catch (err: unknown) {
            if (err instanceof OidcAuthError) throw err;
            throw new OidcAuthError(
                `End_session URL generation failed: ${err instanceof Error ? err.message : String(err)}`,
                'OIDC_LOGOUT_URL_FAILED',
            );
        }
    }

    // ── Private helpers ──────────────────────────────────────────────────────────────

    /**
     * classifyVerificationError: map OidcVerificationError.reason to an OidcErrorCode
     *
     * Conclusion: classify via keyword matching; an unknown reason -> OIDC_SIGNATURE_INVALID (the strictest fallback; fail-closed).
     * Same pattern as SAML's classifyVerificationError.
     */
    private classifyVerificationError(reason: string): OidcErrorCode {
        const lower = reason.toLowerCase();
        if (
            lower.includes('signature') ||
            lower.includes('jws') ||
            lower.includes('invalid signature') ||
            lower.includes('jwks') ||
            lower.includes('kid')
        ) {
            return 'OIDC_SIGNATURE_INVALID';
        }
        if (
            lower.includes('expired') ||
            lower.includes('exp claim') ||
            lower.includes('exp ') ||
            lower.includes('token has expired') ||
            lower.includes('past') ||
            (lower.includes('jwt') && lower.includes('expir'))
        ) {
            return 'OIDC_EXPIRED';
        }
        if (
            lower.includes('iss ') ||
            lower.includes('issuer') ||
            lower.includes('iss claim')
        ) {
            return 'OIDC_ISSUER_MISMATCH';
        }
        if (
            lower.includes('aud ') ||
            lower.includes('audience') ||
            lower.includes('aud claim')
        ) {
            return 'OIDC_AUDIENCE_MISMATCH';
        }
        if (lower.includes('nonce')) {
            return 'OIDC_NONCE_MISMATCH';
        }
        if (
            lower.includes('state') ||
            lower.includes('csrf') ||
            lower.includes('mismatched state')
        ) {
            return 'OIDC_CALLBACK_INVALID';
        }
        if (
            lower.includes('missing id_token') ||
            lower.includes('id_token claims') ||
            lower.includes('no id_token')
        ) {
            return 'OIDC_TOKEN_INVALID';
        }
        // Unknown reason -> the strictest fallback (signature invalid; fail-closed)
        return 'OIDC_SIGNATURE_INVALID';
    }

    /**
     * verifyExpiryFromClaims: extract exp from the claims and verify it literally (layer 2a)
     *
     * Conclusion: a double safeguard; even if the OidcPort implementation omits the expiry check, this rejects it literally;
     * a missing field silent-returns (trusting layer 1; same pattern as SAML);
     * Note: unlike audience/issuer, a missing exp field does not throw (openid-client already requires exp).
     *
     * @throws OidcAuthError OIDC_EXPIRED if id_token.exp is in the past / the access_token expires_at is in the past
     */
    private verifyExpiryFromClaims(
        claims: Record<string, unknown>,
        accessTokenExpiresIn?: number,
    ): void {
        const nowSec = Math.floor(Date.now() / 1000);

        const exp = claims['exp'];
        if (typeof exp === 'number' && Number.isFinite(exp)) {
            if (nowSec >= exp) {
                throw new OidcAuthError(
                    `OIDC id_token has expired. exp: ${exp}, now: ${nowSec}. ` +
                        'id_token rejected (fail-closed).',
                    'OIDC_EXPIRED',
                );
            }
        }
        // Missing exp field -> silent-return (same pattern as SAML expiry; trusting layer 1)

        const nbf = claims['nbf'];
        if (typeof nbf === 'number' && Number.isFinite(nbf)) {
            if (nowSec < nbf) {
                throw new OidcAuthError(
                    `OIDC id_token not yet valid. nbf: ${nbf}, now: ${nowSec}. ` +
                        'id_token rejected (fail-closed).',
                    'OIDC_EXPIRED',
                );
            }
        }

        // access_token expires_in check: negative or 0 = already expired
        if (
            typeof accessTokenExpiresIn === 'number' &&
            Number.isFinite(accessTokenExpiresIn) &&
            accessTokenExpiresIn <= 0
        ) {
            throw new OidcAuthError(
                `OIDC access_token already expired (expires_in <= 0). ` +
                    'Authentication rejected (fail-closed).',
                'OIDC_EXPIRED',
            );
        }
    }

    /**
     * verifyIssuerAudienceFromClaims: literally verify iss + aud (layer 2b)
     *
     * Conclusion: a double safeguard; a missing field -> fail-closed throw (cf. the SAML audience patch).
     * Unlike SAML: OIDC's issuer / audience are both required at the protocol layer, so a missing one is a P0 violation.
     *
     * timing-safe note (same reasoning as SAML):
     *   - the issuer / audience comparison uses `===`; both are public configuration values (OP metadata + RP clientId);
     *     the timing oracle risk is assessed as LOW.
     *
     * @throws OidcAuthError OIDC_ISSUER_MISMATCH if iss is missing / does not match
     * @throws OidcAuthError OIDC_AUDIENCE_MISMATCH if aud is missing / does not contain clientId
     */
    private verifyIssuerAudienceFromClaims(
        claims: Record<string, unknown>,
    ): void {
        // Issuer verification: missing -> throw (cf. the SAML audience enforcement patch)
        const iss = claims['iss'];
        if (iss === undefined || iss === null) {
            throw new OidcAuthError(
                'OIDC id_token missing iss (issuer) claim (P0 violation: fail-closed). ' +
                    'Issuer claim is required; id_token without iss rejected.',
                'OIDC_ISSUER_MISMATCH',
            );
        }
        if (typeof iss !== 'string' || iss.trim() === '') {
            throw new OidcAuthError(
                'OIDC id_token iss claim is not a non-empty string. ' +
                    'id_token rejected (fail-closed).',
                'OIDC_ISSUER_MISMATCH',
            );
        }
        if (iss !== this.idp.issuer) {
            throw new OidcAuthError(
                `OIDC id_token issuer mismatch. Expected: "${this.idp.issuer}", got: "${iss}". ` +
                    'id_token rejected (fail-closed).',
                'OIDC_ISSUER_MISMATCH',
            );
        }

        // Audience verification: missing -> throw (cf. the SAML audience enforcement patch)
        const rawAud = claims['aud'];
        if (rawAud === undefined || rawAud === null) {
            throw new OidcAuthError(
                'OIDC id_token missing aud (audience) claim (P0 violation: fail-closed). ' +
                    'Audience claim is required; id_token without aud rejected.',
                'OIDC_AUDIENCE_MISMATCH',
            );
        }

        // aud may be a string or an array of strings
        const audiences: string[] = Array.isArray(rawAud)
            ? rawAud.filter((a): a is string => typeof a === 'string')
            : typeof rawAud === 'string'
              ? [rawAud]
              : [];

        if (audiences.length === 0) {
            throw new OidcAuthError(
                'OIDC id_token aud claim is empty or contains no valid string values. ' +
                    'id_token rejected (fail-closed).',
                'OIDC_AUDIENCE_MISMATCH',
            );
        }

        // Literal strict match: audiences must contain clientId
        const clientId = this.config.clientId;
        const matched = audiences.some((a) => a === clientId);
        if (!matched) {
            throw new OidcAuthError(
                `OIDC id_token audience mismatch. Expected clientId: "${clientId}", ` +
                    `got: [${audiences.map((a) => `"${a}"`).join(', ')}]. ` +
                    'id_token rejected (fail-closed).',
                'OIDC_AUDIENCE_MISMATCH',
            );
        }
    }

    /**
     * extractFirstAudience: extract the first valid string audience from the aud claim (passed into parseOidcClaims)
     *
     * Conclusion: layer 2b has already verified that aud contains clientId; here we only extract clientId as the verified audience.
     */
    private extractFirstAudience(rawAud: unknown): string {
        if (Array.isArray(rawAud)) {
            const found = rawAud.find(
                (a): a is string =>
                    typeof a === 'string' && a === this.config.clientId,
            );
            if (found) return found;
            // Fallback: the first string (in theory unreachable, since layer 2b has already verified)
            const first = rawAud.find(
                (a): a is string => typeof a === 'string',
            );
            return first ?? this.config.clientId;
        }
        if (typeof rawAud === 'string') return rawAud;
        return this.config.clientId;
    }
}

// ── Express handler factory ────────────────────────────────────────────────────

/**
 * Minimal Express type declarations (aligned with the SAML pattern + admin-console)
 */
interface OidcRequest {
    readonly headers: Record<string, string | string[] | undefined>;
    readonly body?: unknown;
    readonly query?: Record<string, string | string[] | undefined>;
    readonly url?: string;
    readonly originalUrl?: string;
}

interface OidcResponse {
    status(code: number): OidcResponse;
    json(body: unknown): OidcResponse;
    redirect(url: string): void;
}

type OidcNextFn = (err?: unknown) => void;

/**
 * OidcHandlerConfig: shared configuration for the handler factories (dependency injection)
 */
export interface OidcHandlerConfig {
    readonly provider: OidcProvider;
    /**
     * Session state storage interface: used to persist state / nonce / codeVerifier between login -> callback
     *
     * Security constraints:
     *   - the implementation must use a server-side session (cannot store plaintext in a cookie)
     *   - state / nonce are single-use (must be deleted after the callback)
     *   - if missing, the callback must fail-closed reject
     */
    readonly sessionStore: OidcSessionStore;
}

/**
 * OidcSessionStore: abstracts session storage (short-term persistence of state / nonce / codeVerifier)
 *
 * Conclusion: the login handler writes + the callback handler reads and deletes;
 * a production implementation can be based on Redis / cookie-session / express-session, etc.
 */
export interface OidcSessionStore {
    /** store into the session (the key is usually based on the req cookie / header; sessionId is provided by the caller)*/
    put(
        sessionId: string,
        data: { state: string; nonce: string; codeVerifier?: string },
    ): Promise<void>;
    /** read the session and delete it (single-use; invalidate immediately after the callback)*/
    consume(
        sessionId: string,
    ): Promise<
        { state: string; nonce: string; codeVerifier?: string } | undefined
    >;
}

// ── createOidcLoginHandler ────────────────────────────────────────────────────

/**
 * createOidcLoginHandler: generate the OIDC authorize URL -> redirect to the IDP
 *
 * Endpoint: GET /auth/oidc/login
 * Behavior:
 *   1. Generate state / nonce / (optional) codeVerifier
 *   2. Store into sessionStore (key = sessionId; preferably from a cookie)
 *   3. Generate the authorize URL -> 302 redirect
 * Errors: generation failure / sessionStore failure -> fail-closed 5xx + OidcErrorCode (a stub 200 is forbidden)
 *
 * sessionId extraction: req.headers['x-oidc-session-id'] (in production this should be replaced with a more secure session mechanism)
 */
export function createOidcLoginHandler(handlerConfig: OidcHandlerConfig) {
    return async (
        req: OidcRequest,
        res: OidcResponse,
        _next: OidcNextFn,
    ): Promise<void> => {
        try {
            const sessionId = readSessionId(req);
            if (!sessionId) {
                res.status(400).json({
                    error: 'OIDC_CALLBACK_INVALID',
                    message:
                        'Missing x-oidc-session-id header for OIDC login flow.',
                });
                return;
            }

            // Load openid-client's random helpers (generate state / nonce / codeVerifier)
            const oidcMod = await import('openid-client').catch(
                (err: unknown) => {
                    throw new OidcAuthError(
                        `Failed to load openid-client randomNonce/State helpers: ${err instanceof Error ? err.message : String(err)}`,
                        'OIDC_INTERNAL_ERROR',
                    );
                },
            );
            const oidc = oidcMod as unknown as {
                randomState: () => string;
                randomNonce: () => string;
                randomPKCECodeVerifier: () => string;
                calculatePKCECodeChallenge: (
                    verifier: string,
                ) => Promise<string>;
            };

            const state = oidc.randomState();
            const nonce = oidc.randomNonce();
            const codeVerifier = oidc.randomPKCECodeVerifier();
            const codeChallenge =
                await oidc.calculatePKCECodeChallenge(codeVerifier);

            await handlerConfig.sessionStore.put(sessionId, {
                state,
                nonce,
                codeVerifier,
            });

            const loginUrl = await handlerConfig.provider.generateAuthorizeUrl({
                state,
                nonce,
                codeChallenge,
                codeChallengeMethod: 'S256',
            });

            res.redirect(loginUrl);
        } catch (err: unknown) {
            handleOidcError(err, res);
        }
    };
}

// ── createOidcCallbackHandler ─────────────────────────────────────────────────

/**
 * createOidcCallbackHandler: receive the OIDC callback -> verify -> return OidcUserClaims
 *
 * Endpoint: GET /auth/oidc/callback?code=...&state=...
 * Behavior:
 *   1. Extract sessionId -> consume the session (state / nonce / codeVerifier)
 *   2. Call provider.verifyCallback (3 P0 checks: signature + expiry + issuer/audience)
 *   3. On success -> 200 + { claims: OidcUserClaims }
 * Errors: any verification failure -> fail-closed 4xx/5xx + OidcErrorCode (a stub 200 is forbidden)
 *
 * Security constraints:
 *   - missing sessionId -> 400 fail-closed
 *   - missing / already-consumed session -> 401 fail-closed (state replay defense)
 *   - verifyCallback failure -> 401 fail-closed
 */
export function createOidcCallbackHandler(handlerConfig: OidcHandlerConfig) {
    return async (
        req: OidcRequest,
        res: OidcResponse,
        _next: OidcNextFn,
    ): Promise<void> => {
        try {
            const sessionId = readSessionId(req);
            if (!sessionId) {
                res.status(400).json({
                    error: 'OIDC_CALLBACK_INVALID',
                    message:
                        'Missing x-oidc-session-id header for OIDC callback.',
                });
                return;
            }

            const session = await handlerConfig.sessionStore.consume(sessionId);
            if (!session) {
                res.status(401).json({
                    error: 'OIDC_CALLBACK_INVALID',
                    message:
                        'OIDC session not found or already consumed (state replay protection).',
                });
                return;
            }

            // Construct currentUrl (for openid-client.authorizationCodeGrant)
            const currentUrl = readCallbackUrl(req, handlerConfig);
            if (!currentUrl) {
                res.status(400).json({
                    error: 'OIDC_CALLBACK_INVALID',
                    message: 'Cannot construct callback URL from request.',
                });
                return;
            }

            const claims = await handlerConfig.provider.verifyCallback({
                currentUrl,
                expectedNonce: session.nonce,
                expectedState: session.state,
                codeVerifier: session.codeVerifier,
            });

            res.status(200).json({ claims });
        } catch (err: unknown) {
            handleOidcError(err, res);
        }
    };
}

// ── createOidcLogoutHandler ───────────────────────────────────────────────────

/**
 * createOidcLogoutHandler: generate the OIDC end_session URL -> redirect to the IDP
 *
 * Endpoint: POST /auth/oidc/logout (body contains idToken)
 * Behavior:
 *   1. Extract body.idToken
 *   2. Generate the end_session URL -> 302 redirect
 * Errors: missing idToken / generation failure -> fail-closed 4xx/5xx (a stub 200 is forbidden)
 */
export function createOidcLogoutHandler(handlerConfig: OidcHandlerConfig) {
    return async (
        req: OidcRequest,
        res: OidcResponse,
        _next: OidcNextFn,
    ): Promise<void> => {
        try {
            const body = req.body;
            if (
                body === null ||
                body === undefined ||
                typeof body !== 'object'
            ) {
                res.status(400).json({
                    error: 'OIDC_LOGOUT_URL_FAILED',
                    message:
                        'Request body is missing. Expected idToken in body.',
                });
                return;
            }

            const bodyRecord = body as Record<string, unknown>;
            const idToken = bodyRecord['idToken'] ?? bodyRecord['id_token'];
            if (typeof idToken !== 'string' || idToken.trim() === '') {
                res.status(400).json({
                    error: 'OIDC_LOGOUT_URL_FAILED',
                    message:
                        'idToken is required in request body for OIDC logout.',
                });
                return;
            }

            const stateValue =
                typeof bodyRecord['state'] === 'string' &&
                bodyRecord['state'].trim() !== ''
                    ? bodyRecord['state']
                    : undefined;

            // Construct partial claims (used only to generate the end_session URL)
            const partialClaims: OidcUserClaims = {
                sub: '',
                issuer: '',
                audience: '',
                idToken: idToken.trim(),
                idTokenExpiresAt: 0,
                verifiedAt: new Date().toISOString(),
                attributes: {},
            };

            const logoutUrl =
                await handlerConfig.provider.generateEndSessionUrl(
                    partialClaims,
                    stateValue,
                );
            res.redirect(logoutUrl);
        } catch (err: unknown) {
            handleOidcError(err, res);
        }
    };
}

// ── Error handling + helpers ────────────────────────────────────────────────────────

/**
 * handleOidcError: unified error response for SSO OIDC handlers (fail-closed)
 *
 * Conclusion: every OIDC handler catch block calls this function;
 * different error types map to different HTTP status codes;
 * a stub default 200 is forbidden.
 *
 * Error code -> HTTP status code mapping (aligned with the SAML pattern):
 *   - OIDC_CONFIG_INVALID -> 500 (configuration error; server-side problem)
 *   - OIDC_SIGNATURE_INVALID -> 401 (P0)
 *   - OIDC_EXPIRED -> 401 (P0)
 *   - OIDC_ISSUER_MISMATCH -> 401 (P0)
 *   - OIDC_AUDIENCE_MISMATCH -> 401 (P0)
 *   - OIDC_NONCE_MISMATCH -> 401
 *   - OIDC_CLAIMS_INVALID -> 401
 *   - OIDC_TOKEN_INVALID -> 401
 *   - OIDC_CALLBACK_INVALID -> 400 (malformed request)
 *   - OIDC_AUTHORIZE_URL_FAILED -> 502
 *   - OIDC_LOGOUT_URL_FAILED -> 400
 *   - others -> 500 (fail-closed)
 */
export function handleOidcError(err: unknown, res: OidcResponse): void {
    if (err instanceof OidcAuthError) {
        const status = oidcErrorCodeToHttpStatus(err.code);
        res.status(status).json({
            error: err.code,
            message: sanitizeOidcErrorMessage(err.message, err.code),
        });
        return;
    }
    // Unknown error -> fail-closed 500 (a stub default 200 is forbidden)
    res.status(500).json({
        error: 'OIDC_INTERNAL_ERROR',
        message: 'Internal OIDC error. Request aborted.',
    });
}

/**
 * oidcErrorCodeToHttpStatus: OidcErrorCode -> HTTP status code (fail-closed mapping)
 */
function oidcErrorCodeToHttpStatus(code: OidcErrorCode): number {
    switch (code) {
        case 'OIDC_CONFIG_INVALID':
            return 500;
        case 'OIDC_SIGNATURE_INVALID':
        case 'OIDC_EXPIRED':
        case 'OIDC_ISSUER_MISMATCH':
        case 'OIDC_AUDIENCE_MISMATCH':
        case 'OIDC_NONCE_MISMATCH':
        case 'OIDC_CLAIMS_INVALID':
        case 'OIDC_TOKEN_INVALID':
            return 401;
        case 'OIDC_CALLBACK_INVALID':
        case 'OIDC_LOGOUT_URL_FAILED':
            return 400;
        case 'OIDC_AUTHORIZE_URL_FAILED':
            return 502;
        case 'OIDC_INTERNAL_ERROR':
        default:
            return 500;
    }
}

/**
 * sanitizeOidcErrorMessage: sanitize the externally exposed error message
 *
 * Conclusion: the 4 P0 codes (OIDC_SIGNATURE_INVALID / OIDC_EXPIRED / OIDC_ISSUER_MISMATCH /
 * OIDC_AUDIENCE_MISMATCH) use fixed strings (avoiding leaking jwks / token internals);
 * other errors keep the original message (with truncation; at most 256 characters).
 */
function sanitizeOidcErrorMessage(
    message: string,
    code: OidcErrorCode,
): string {
    switch (code) {
        case 'OIDC_SIGNATURE_INVALID':
            return 'OIDC id_token signature is invalid. Authentication rejected.';
        case 'OIDC_EXPIRED':
            return 'OIDC id_token has expired. Please re-authenticate.';
        case 'OIDC_ISSUER_MISMATCH':
            return 'OIDC id_token issuer does not match expected OP. Authentication rejected.';
        case 'OIDC_AUDIENCE_MISMATCH':
            return 'OIDC id_token audience does not match this service. Authentication rejected.';
        default:
            // default path: 256-character truncation (prevents an over-long message from leaking internals)
            return message.length > 256
                ? message.slice(0, 253) + '...'
                : message;
    }
}

/**
 * readSessionId: extract the sessionId from the request header
 *
 * Conclusion: in production this should be replaced with a more secure session mechanism (cookie + signing / express-session);
 * this function only provides the handler factory's default behavior, making it easy to inject a custom sessionStore implementation.
 */
function readSessionId(req: OidcRequest): string | null {
    const raw = req.headers['x-oidc-session-id'];
    if (typeof raw === 'string' && raw.trim() !== '') return raw.trim();
    if (Array.isArray(raw) && raw.length > 0 && typeof raw[0] === 'string') {
        return raw[0].trim();
    }
    return null;
}

/**
 * readCallbackUrl: extract the callback URL from the request (including the query string)
 *
 * Conclusion: openid-client.authorizationCodeGrant needs the full URL (with the code / state query);
 * prefers req.originalUrl + the Host header; falls back to rebuilding from redirectUri + req.query.
 */
function readCallbackUrl(
    req: OidcRequest,
    handlerConfig: OidcHandlerConfig,
): URL | null {
    const host = req.headers['host'];
    const hostStr =
        typeof host === 'string'
            ? host
            : Array.isArray(host)
              ? host[0]
              : undefined;

    const path =
        typeof req.originalUrl === 'string'
            ? req.originalUrl
            : typeof req.url === 'string'
              ? req.url
              : undefined;

    if (hostStr && path) {
        // Prefer https:// (production); use http if the Host contains :80
        const proto = hostStr.includes(':80') ? 'http' : 'https';
        try {
            return new URL(`${proto}://${hostStr}${path}`);
        } catch {
            // fallthrough
        }
    }

    // Fallback: rebuild from redirectUri + req.query
    const redirectUri = (
        handlerConfig.provider as unknown as { config: OidcProviderConfig }
    ).config?.redirectUri;
    if (!redirectUri || !req.query) return null;
    try {
        const url = new URL(redirectUri);
        for (const [key, value] of Object.entries(req.query)) {
            if (typeof value === 'string') {
                url.searchParams.set(key, value);
            } else if (
                Array.isArray(value) &&
                value.length > 0 &&
                typeof value[0] === 'string'
            ) {
                url.searchParams.set(key, value[0]);
            }
        }
        return url;
    } catch {
        return null;
    }
}
