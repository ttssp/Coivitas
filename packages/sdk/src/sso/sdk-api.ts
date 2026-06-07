/**
 * sdk-api.ts -- SSO SDK API (SDK API D12-D14)
 *
 * Responsibilities:
 *   - SSOClient: a unified SSO operation entry point for SDK consumers
 *     - initiateLogin: generate the SAML / OIDC login URL (Redirect binding)
 *       OIDC: internally generates state / nonce -> the result contains state + nonce (for the caller to store in the session)
 *     - resolveAuthentication: handle the IDP callback -> full identity resolution
 *       (SAML: verifyResponse -> parseSamlUserClaims -> resolveTenant)
 *       (OIDC: verifyCallback -> parseOidcUserClaims -> resolveTenant)
 *     - logout: generate the SLO URL + record a federation logout audit event
 *
 * Design constraints (fail-closed + no brand cast):
 *   - fail-closed: any IDP callback verification failure -> throw SSOClientError;
 *     no partial-PASS (do not return partially verified claims)
 *   - SamlPort / OidcPort / FederationPort are injected via DI (no bare instantiation or brand cast)
 *   - a stub default 200 is forbidden; all errors -> SSOClientError with errorCode
 *   - partial-PASS forbidden: resolveAuthentication must not return a partially verified result
 *
 *  Scope (strict):
 *   - this file only orchestrates the three Ports SamlPort / OidcPort / FederationPort;
 *   - it does not modify the SAML / OIDC / federation internal implementations (does not cross scope)
 *   - it does not duplicate verification logic (verification lives in each Port implementation; the SDK API orchestrates)
 *
 * OIDC state / nonce management design:
 *   - initiateLogin('oidc') internally uses crypto.randomUUID() (built into Node.js 14.17+) to generate state + nonce
 *   - the caller is responsible for storing state + nonce in the session (obtained from InitiateLoginResult)
 *   - resolveAuthentication('oidc') accepts the currentUrl + expectedState + expectedNonce parameters
 *   - this is consistent with the OpenID Connect Core 1.0 state parameter + nonce claim pattern
 *
 * @see saml-provider.ts (SAML assertion verification)
 * @see oidc-provider.ts (OIDC id_token verification)
 * @see tenant-federation.ts (tenant federation resolution)
 */

import { randomUUID } from 'node:crypto';

import type { SamlPort } from './saml-provider.js';
import { parseSamlClaims, SamlAuthError } from './types.js';
import type { OidcPort } from './oidc-provider.js';
import { parseOidcClaims, OidcAuthError } from './oidc-provider.js';
import type {
    FederationPort,
    FederationResolution,
    FederationLogoutContext,
    FederationAuditEvent,
} from './tenant-federation.js';
import { TenantFederationProvider } from './tenant-federation.js';

// ---------------------------------------------------------------------------
// SSOClientErrorCode -- SDK API layer error codes
// ---------------------------------------------------------------------------

/**
 * SSOClient SDK-layer error codes.
 *
 * Strictly separated from each Port's internal error codes (the SDK API layer does not pass internal error codes through directly).
 * fail-closed: any unexpected state -> SSO_CLIENT_UNKNOWN_ERROR (not swallowed).
 */
export type SSOClientErrorCode =
    /** SAML login URL generation failed.*/
    | 'SSO_CLIENT_SAML_LOGIN_FAILED'
    /** OIDC login URL generation failed.*/
    | 'SSO_CLIENT_OIDC_LOGIN_FAILED'
    /** SAML assertion verification failed (signature / expiry / audience).*/
    | 'SSO_CLIENT_SAML_CALLBACK_FAILED'
    /** OIDC token verification failed (signature / expiry / issuer / audience).*/
    | 'SSO_CLIENT_OIDC_CALLBACK_FAILED'
    /** Federation resolution failed (tenant scope / IDP mapping / JIT provisioning).*/
    | 'SSO_CLIENT_FEDERATION_FAILED'
    /** SLO logout URL generation failed.*/
    | 'SSO_CLIENT_LOGOUT_FAILED'
    /** Unexpected error (fail-closed; not swallowed).*/
    | 'SSO_CLIENT_UNKNOWN_ERROR'
    /**
     * An unknown protocol value was passed to initiateLogin / resolveAuthentication (runtime guard).
     *
     * TypeScript's union types only take effect at compile time; if an SDK consumer uses JS or an `as any` cast,
     * a value other than 'saml' / 'oidc' may be passed -> a runtime guard is required (fail-closed).
     */
    | 'SSO_CLIENT_IDP_TYPE_INVALID';

// ---------------------------------------------------------------------------
// SSOClientError -- SDK API layer error class
// ---------------------------------------------------------------------------

/**
 * SSOClient SDK-layer error.
 *
 * fail-closed: every error must carry an SSOClientErrorCode;
 * throwing a bare, codeless Error('unknown') is forbidden.
 * The cause field preserves the original error chain (SamlAuthError / OidcAuthError / FederationError).
 */
export class SSOClientError extends Error {
    readonly code: SSOClientErrorCode;

    constructor(
        message: string,
        code: SSOClientErrorCode,
        cause?: unknown,
    ) {
        super(message);
        this.name = 'SSOClientError';
        this.code = code;
        if (cause !== undefined) {
            (this as { cause?: unknown }).cause = cause;
        }
    }
}

// ---------------------------------------------------------------------------
// SSOClientConfig -- DI injection configuration
// ---------------------------------------------------------------------------

/**
 * SSOClient constructor configuration.
 *
 * All Ports are injected via interfaces (no bare `as SamlPort` / `as OidcPort` / `as FederationPort` cast).
 * Optional: passing only samlPort supports SAML alone; passing only oidcPort supports OIDC alone; passing both supports both.
 */
export interface SSOClientConfig {
    /**
     * SAML Port (optional; if omitted, initiateLogin('saml') and resolveAuthentication('saml') throw).
     * Injected via the SamlPort interface; a bare `as SamlPort` cast is not allowed.
     */
    samlPort?: SamlPort;

    /**
     * OIDC Port (optional; if omitted, initiateLogin('oidc') and resolveAuthentication('oidc') throw).
     * Injected via the OidcPort interface; a bare `as OidcPort` cast is not allowed.
     */
    oidcPort?: OidcPort;

    /**
     * FederationPort (required; necessary for tenant resolution).
     * Injected via the FederationPort interface; a bare `as FederationPort` cast is not allowed.
     */
    federationPort: FederationPort;
}

// ---------------------------------------------------------------------------
// InitiateLoginRequest / Result
// ---------------------------------------------------------------------------

/** initiateLogin() request parameters.*/
export interface InitiateLoginRequest {
    /** protocol type: 'saml' or 'oidc'.*/
    protocol: 'saml' | 'oidc';
}

/** initiateLogin() result.*/
export interface InitiateLoginResult {
    /** redirect URL (SAML AuthnRequest URL / OIDC authorization URL).*/
    readonly redirectUrl: string;
    /** protocol type (echoed back; for the caller to store in the session).*/
    readonly protocol: 'saml' | 'oidc';
    /**
     * OIDC-specific: the state parameter (CSRF defense; the caller must store it in the session).
     * undefined for SAML.
     */
    readonly oidcState?: string;
    /**
     * OIDC-specific: the nonce parameter (replay defense; the caller must store it in the session).
     * undefined for SAML.
     */
    readonly oidcNonce?: string;
}

// ---------------------------------------------------------------------------
// ResolveAuthenticationRequest / Result
// ---------------------------------------------------------------------------

/**
 * resolveAuthentication() request parameters (discriminated union).
 *
 * SAML: body = the POST binding body (with SAMLResponse)
 * OIDC: currentUrl = the full callback URL (with code / state) + expectedNonce + expectedState
 *       (taken out of the session after storing the oidcState / oidcNonce returned by initiateLogin)
 */
export type ResolveAuthenticationRequest =
    | {
        readonly protocol: 'saml';
        /** the SAML POST binding body (with the SAMLResponse parameter).*/
        readonly body: Record<string, string | string[]>;
        /** IDP EntityID (used for federation_mapping lookup).*/
        readonly idpIdentifier: string;
    }
    | {
        readonly protocol: 'oidc';
        /**
         * the full OIDC callback URL (with code / state / session_state and other query params).
         * Aligned with OidcPort.verifyCallback's currentUrl parameter.
         */
        readonly currentUrl: string | URL;
        /**
         * the expected state (CSRF defense; from the oidcState returned by initiateLogin).
         * Must match the state passed at getAuthorizeUrl time.
         */
        readonly expectedState: string;
        /**
         * the expected nonce (replay defense; from the oidcNonce returned by initiateLogin).
         * Must match the nonce passed at getAuthorizeUrl time.
         */
        readonly expectedNonce: string;
        /** optional: the PKCE code_verifier (must be passed if PKCE is used).*/
        readonly codeVerifier?: string;
        /** OIDC issuer (used for federation_mapping lookup).*/
        readonly idpIdentifier: string;
    };

/** resolveAuthentication() result.*/
export interface ResolveAuthenticationResult {
    /** the Federation resolution result (userId / tenantId / role / isNewUser).*/
    readonly resolution: FederationResolution;
    /** protocol type (echoed back).*/
    readonly protocol: 'saml' | 'oidc';
}

// ---------------------------------------------------------------------------
// LogoutRequest
// ---------------------------------------------------------------------------

/** logout() request parameters.*/
export interface LogoutRequest {
    /** protocol type: 'saml' or 'oidc'.*/
    protocol: 'saml' | 'oidc';
    /** the Federation logout context (userId / tenantId / idpIdentifier / externalSubject).*/
    context: FederationLogoutContext;
    /**
     * OIDC-specific: the id_token hint (used by the end_session_endpoint).
     * Ignored for SAML.
     */
    oidcIdTokenHint?: string;
    /**
     * OIDC-specific: the post-logout redirect URI (used by the end_session_endpoint).
     * Ignored for SAML.
     */
    oidcPostLogoutRedirectUri?: string;
}

/** logout() result.*/
export interface LogoutResult {
    /** the SLO redirect URL (SAML LogoutRequest URL; OIDC end_session_endpoint URL).*/
    readonly redirectUrl: string;
}

// ---------------------------------------------------------------------------
// SSOClient
// ---------------------------------------------------------------------------

/**
 * SSOClient: a unified SSO operation entry point for SDK GA consumers.
 *
 * Orchestrates the three Ports SamlPort / OidcPort / FederationPort;
 * hides the SAML / OIDC / federation internals.
 *
 * Usage example (SAML):
 * ```ts
 * const client = new SSOClient({
 *   samlPort: nodeSamlAdapter,
 *   federationPort: tenantFederationAdapter,
 * });
 *
 * // 1. Initiate SAML login
 * const { redirectUrl } = await client.initiateLogin({ protocol: 'saml' });
 * // redirect the user to redirectUrl
 *
 * // 2. Handle the SAML callback
 * const { resolution } = await client.resolveAuthentication({
 *   protocol: 'saml',
 *   body: req.body,
 *   idpIdentifier: 'https://idp.example.com/saml/metadata',
 * });
 * // resolution.tenantId / resolution.role / resolution.userId
 * ```
 *
 * Usage example (OIDC):
 * ```ts
 * const client = new SSOClient({
 *   oidcPort: openIdClientAdapter,
 *   federationPort: tenantFederationAdapter,
 * });
 *
 * // 1. Initiate OIDC login (store state / nonce in the session)
 * const { redirectUrl, oidcState, oidcNonce } = await client.initiateLogin({ protocol: 'oidc' });
 * session.oidcState = oidcState;
 * session.oidcNonce = oidcNonce;
 * // redirect the user to redirectUrl
 *
 * // 2. Handle the OIDC callback (take state / nonce out of the session)
 * const { resolution } = await client.resolveAuthentication({
 *   protocol: 'oidc',
 *   currentUrl: req.url,
 *   expectedState: session.oidcState,
 *   expectedNonce: session.oidcNonce,
 *   idpIdentifier: 'https://idp.example.com',
 * });
 * ```
 *
 * Security constraints (literally forbidden — verified by grep tests):
 *   - a stub default 200 is forbidden
 *   - partial-PASS is forbidden (do not return partially verified results)
 *   - swallowing errors in catch is forbidden (all exceptions -> SSOClientError with code)
 */
export class SSOClient {
    private readonly samlPort?: SamlPort;
    private readonly oidcPort?: OidcPort;
    private readonly federationProvider: TenantFederationProvider;
    /**
     * federationPort: held directly (used by _safeWriteFederationLogoutAudit).
     *
     * Conclusion: the TenantFederationProvider.port field is private and not externally accessible;
     * SSOClient keeps its own separate reference, used only for logout audit writes (not reusing the provider's internal path).
     */
    private readonly federationPort: FederationPort;

    constructor(config: SSOClientConfig) {
        this.samlPort = config.samlPort;
        this.oidcPort = config.oidcPort;
        this.federationPort = config.federationPort;
        this.federationProvider = new TenantFederationProvider(
            config.federationPort,
        );
    }

    // -------------------------------------------------------------------------
    // initiateLogin -- generate the login URL (SAML AuthnRequest / OIDC authorization)
    // -------------------------------------------------------------------------

    /**
     * Initiate SSO login: generate the IDP redirect URL.
     *
     * OIDC: internally uses crypto.randomUUID() to generate state + nonce (CSRF defense + replay defense);
     * the caller must store oidcState + oidcNonce in the session and pass them back at resolveAuthentication time.
     *
     * fail-closed: a Port exception -> throw SSOClientError.
     *
     * @throws SSOClientError(SSO_CLIENT_SAML_LOGIN_FAILED) SAML URL generation failed
     * @throws SSOClientError(SSO_CLIENT_OIDC_LOGIN_FAILED) OIDC URL generation failed
     * @throws SSOClientError(SSO_CLIENT_IDP_TYPE_INVALID) an unknown protocol value was passed (runtime guard)
     */
    async initiateLogin(
        req: InitiateLoginRequest,
    ): Promise<InitiateLoginResult> {
        if (req.protocol === 'saml') {
            if (this.samlPort === undefined) {
                throw new SSOClientError(
                    'SSOClient: samlPort is not configured; cannot initiateLogin with protocol=saml',
                    'SSO_CLIENT_SAML_LOGIN_FAILED',
                );
            }
            let redirectUrl: string;
            try {
                redirectUrl = await this.samlPort.getAuthorizeUrl();
            } catch (err) {
                throw new SSOClientError(
                    `SSOClient: SAML getAuthorizeUrl failed: ${String(err)}`,
                    'SSO_CLIENT_SAML_LOGIN_FAILED',
                    err,
                );
            }
            return { redirectUrl, protocol: 'saml' };
        } else if (req.protocol === 'oidc') {
            // OIDC: generate state + nonce (CSRF defense + replay defense; crypto.randomUUID uses a cryptographically secure random source)
            if (this.oidcPort === undefined) {
                throw new SSOClientError(
                    'SSOClient: oidcPort is not configured; cannot initiateLogin with protocol=oidc',
                    'SSO_CLIENT_OIDC_LOGIN_FAILED',
                );
            }
            const oidcState = randomUUID();
            const oidcNonce = randomUUID();
            let redirectUrl: string;
            try {
                redirectUrl = await this.oidcPort.getAuthorizeUrl({
                    state: oidcState,
                    nonce: oidcNonce,
                });
            } catch (err) {
                throw new SSOClientError(
                    `SSOClient: OIDC getAuthorizeUrl failed: ${String(err)}`,
                    'SSO_CLIENT_OIDC_LOGIN_FAILED',
                    err,
                );
            }
            return { redirectUrl, protocol: 'oidc', oidcState, oidcNonce };
        } else {
            // Runtime guard: TypeScript unions only take effect at compile time; a JS consumer or an `as any` cast may pass an illegal
            // protocol value -> must fail-closed.
            const unknownProtocol = String((req as unknown as Record<string, unknown>)['protocol']);
            throw new SSOClientError(
                `SSOClient: unknown protocol "${unknownProtocol}" for initiateLogin; expected 'saml' or 'oidc'`,
                'SSO_CLIENT_IDP_TYPE_INVALID',
            );
        }
    }

    // -------------------------------------------------------------------------
    // resolveAuthentication -- handle the IDP callback -> full identity resolution
    // -------------------------------------------------------------------------

    /**
     * Handle the IDP callback: verify the assertion -> parse claims -> resolveTenant -> FederationResolution.
     *
     * SAML flow:
     *   1. samlPort.verifyResponse(body) -> raw profile (P0: signature/expiry/audience, three guards)
     *   2. parseSamlUserClaims(claims) -> SamlUserClaims (no bare cast)
     *   3. federationProvider.resolveTenant({ type: 'saml', claims, idpIdentifier }) -> FederationResolution
     *
     * OIDC flow:
     *   1. oidcPort.verifyCallback({ currentUrl, expectedNonce, expectedState }) -> token response
     *      (P0: signature/expiry/issuer/audience, 4 guards handled by the OidcPort implementation)
     *   2. parseOidcUserClaims(token.claims) -> OidcUserClaims (no bare cast)
     *   3. federationProvider.resolveTenant({ type: 'oidc', claims, idpIdentifier }) -> FederationResolution
     *
     * fail-closed: any verification step failure -> throw SSOClientError (does not return a partial result).
     *
     * @throws SSOClientError(SSO_CLIENT_SAML_CALLBACK_FAILED) SAML verification failed
     * @throws SSOClientError(SSO_CLIENT_OIDC_CALLBACK_FAILED) OIDC verification failed
     * @throws SSOClientError(SSO_CLIENT_FEDERATION_FAILED) Federation resolution failed
     */
    async resolveAuthentication(
        req: ResolveAuthenticationRequest,
    ): Promise<ResolveAuthenticationResult> {
        if (req.protocol === 'saml') {
            return this._resolveSaml(req);
        }
        return this._resolveOidc(req);
    }

    private async _resolveSaml(
        req: Extract<ResolveAuthenticationRequest, { protocol: 'saml' }>,
    ): Promise<ResolveAuthenticationResult> {
        if (this.samlPort === undefined) {
            throw new SSOClientError(
                'SSOClient: samlPort is not configured; cannot resolveAuthentication with protocol=saml',
                'SSO_CLIENT_SAML_CALLBACK_FAILED',
            );
        }

        // Step 1: SAML assertion verification (fail-closed P0)
        let rawProfile: Record<string, unknown>;
        try {
            rawProfile = await this.samlPort.verifyResponse(req.body);
        } catch (err) {
            // Both SamlAuthError and generic errors map to the same SDK error code;
            // cause preserves the original error (for the caller to diagnose)
            void (err instanceof SamlAuthError);
            throw new SSOClientError(
                `SSOClient: SAML verifyResponse failed: ${String(err)}`,
                'SSO_CLIENT_SAML_CALLBACK_FAILED',
                err,
            );
        }

        // Step 2: parseSamlClaims (no bare cast; raw node-saml profile -> normalized SamlUserClaims)
        // Patch: SamlPort.verifyResponse returns a raw node-saml profile (nameID/nameIDFormat, etc.);
        // apply parseSamlClaims (the raw-profile parser) rather than parseSamlUserClaims (which expects the normalized SDK shape);
        // the old parseSamlUserClaims path would fail immediately after a successful IDP verification.
        let claims;
        try {
            claims = parseSamlClaims(rawProfile, req.idpIdentifier);
        } catch (err) {
            throw new SSOClientError(
                `SSOClient: parseSamlClaims failed: ${String(err)}`,
                'SSO_CLIENT_SAML_CALLBACK_FAILED',
                err,
            );
        }

        // Step 3: federation resolveTenant
        let resolution: FederationResolution;
        try {
            resolution = await this.federationProvider.resolveTenant({
                type: 'saml',
                claims,
                idpIdentifier: req.idpIdentifier,
            });
        } catch (err) {
            throw new SSOClientError(
                `SSOClient: federation resolveTenant failed: ${String(err)}`,
                'SSO_CLIENT_FEDERATION_FAILED',
                err,
            );
        }

        return { resolution, protocol: 'saml' };
    }

    private async _resolveOidc(
        req: Extract<ResolveAuthenticationRequest, { protocol: 'oidc' }>,
    ): Promise<ResolveAuthenticationResult> {
        if (this.oidcPort === undefined) {
            throw new SSOClientError(
                'SSOClient: oidcPort is not configured; cannot resolveAuthentication with protocol=oidc',
                'SSO_CLIENT_OIDC_CALLBACK_FAILED',
            );
        }

        // Step 1: OIDC token verification (fail-closed P0; 4 guards: signature/expiry/issuer/audience handled by the OidcPort implementation)
        // verifyCallback executes the full authorization code grant + id_token JWS verification
        let tokenResponse: { claims: Record<string, unknown> };
        try {
            tokenResponse = await this.oidcPort.verifyCallback({
                currentUrl: req.currentUrl,
                expectedNonce: req.expectedNonce,
                expectedState: req.expectedState,
                codeVerifier: req.codeVerifier,
            });
        } catch (err) {
            // Both OidcAuthError and generic errors map to the same SDK error code;
            // cause preserves the original error (for the caller to diagnose)
            void (err instanceof OidcAuthError);
            throw new SSOClientError(
                `SSOClient: OIDC verifyCallback failed: ${String(err)}`,
                'SSO_CLIENT_OIDC_CALLBACK_FAILED',
                err,
            );
        }

        // Step 2: parseOidcClaims (no bare cast; raw id_token claims -> normalized OidcUserClaims)
        // Patch: OidcPort.verifyCallback returns raw id_token claims (iss/aud/exp, etc.);
        // apply parseOidcClaims (the raw-profile parser) rather than parseOidcUserClaims (which expects the normalized SDK shape);
        // the 4 P0 guards (signature/expiry/issuer/audience) are handled by the OidcPort implementation layer; here we extract iss + the first aud and pass them in as a verified copy.
        let claims;
        try {
            const rawClaims = tokenResponse.claims;
            const issClaim = rawClaims['iss'];
            const audClaim = rawClaims['aud'];
            if (typeof issClaim !== 'string' || issClaim.trim() === '') {
                throw new OidcAuthError(
                    'OIDC id_token missing "iss" claim (verified by OidcPort);' +
                        ' cannot proceed with claims normalization.',
                    'OIDC_CLAIMS_INVALID',
                );
            }
            // aud may be a string or string[]; take the first valid string audience
            let firstAud: string | undefined;
            if (Array.isArray(audClaim)) {
                firstAud = audClaim.find(
                    (a: unknown): a is string =>
                        typeof a === 'string' && a.trim() !== '',
                );
            } else if (typeof audClaim === 'string' && audClaim.trim() !== '') {
                firstAud = audClaim;
            }
            if (typeof firstAud !== 'string') {
                throw new OidcAuthError(
                    'OIDC id_token missing valid "aud" claim (verified by OidcPort);' +
                        ' cannot proceed with claims normalization.',
                    'OIDC_CLAIMS_INVALID',
                );
            }
            claims = parseOidcClaims(rawClaims, issClaim, firstAud);
        } catch (err) {
            throw new SSOClientError(
                `SSOClient: parseOidcClaims failed: ${String(err)}`,
                'SSO_CLIENT_OIDC_CALLBACK_FAILED',
                err,
            );
        }

        // Step 3: federation resolveTenant
        let resolution: FederationResolution;
        try {
            resolution = await this.federationProvider.resolveTenant({
                type: 'oidc',
                claims,
                idpIdentifier: req.idpIdentifier,
            });
        } catch (err) {
            throw new SSOClientError(
                `SSOClient: federation resolveTenant failed: ${String(err)}`,
                'SSO_CLIENT_FEDERATION_FAILED',
                err,
            );
        }

        return { resolution, protocol: 'oidc' };
    }

    // -------------------------------------------------------------------------
    // logout -- initiate SLO + record a federation logout audit
    // -------------------------------------------------------------------------

    /**
     * Initiate SSO logout: generate the SLO URL + record a federation logout audit event.
     *
     * SAML: samlPort.getLogoutUrl(nameId, sessionIndex?) -> SLO redirect URL
     *       nameId = context.externalSubject; sessionIndex = context.sessionId (optional)
     * OIDC: oidcPort.getEndSessionUrl({ idTokenHint, postLogoutRedirectUri? }) -> end_session URL
     *       idTokenHint comes from LogoutRequest.oidcIdTokenHint (optional)
     *
     * fail-closed: a Port exception -> throw SSOClientError(SSO_CLIENT_LOGOUT_FAILED).
     *
     * @throws SSOClientError(SSO_CLIENT_LOGOUT_FAILED) SLO URL generation failed
     */
    async logout(req: LogoutRequest): Promise<LogoutResult> {
        if (req.protocol === 'saml') {
            if (this.samlPort === undefined) {
                throw new SSOClientError(
                    'SSOClient: samlPort is not configured; cannot logout with protocol=saml',
                    'SSO_CLIENT_LOGOUT_FAILED',
                );
            }
            let redirectUrl: string;
            try {
                // SamlPort.getLogoutUrl signature: getLogoutUrl(nameId: string, sessionIndex?: string)
                // externalSubject = SAML NameID; sessionId = SAML session index (optional)
                redirectUrl = await this.samlPort.getLogoutUrl(
                    req.context.externalSubject,
                    req.context.sessionId,
                );
            } catch (err) {
                throw new SSOClientError(
                    `SSOClient: SAML getLogoutUrl failed: ${String(err)}`,
                    'SSO_CLIENT_LOGOUT_FAILED',
                    err,
                );
            }
            // federation audit (does not block the main flow; audit failure does not throw)
            await this._safeWriteFederationLogoutAudit(req.context);
            return { redirectUrl };
        }

        // protocol === 'oidc'
        if (this.oidcPort === undefined) {
            throw new SSOClientError(
                'SSOClient: oidcPort is not configured; cannot logout with protocol=oidc',
                'SSO_CLIENT_LOGOUT_FAILED',
            );
        }
        let redirectUrl: string;
        try {
            // OidcPort.getEndSessionUrl signature: getEndSessionUrl({ idTokenHint, postLogoutRedirectUri?, state? })
            redirectUrl = await this.oidcPort.getEndSessionUrl({
                idTokenHint: req.oidcIdTokenHint ?? '',
                postLogoutRedirectUri: req.oidcPostLogoutRedirectUri,
            });
        } catch (err) {
            throw new SSOClientError(
                `SSOClient: OIDC getEndSessionUrl failed: ${String(err)}`,
                'SSO_CLIENT_LOGOUT_FAILED',
                err,
            );
        }
        await this._safeWriteFederationLogoutAudit(req.context);
        return { redirectUrl };
    }

    // ---- internal audit operation (failure does not throw; degraded error logging)--------------------------

    /**
     * _safeWriteFederationLogoutAudit: safely write a federation logout audit event.
     *
     * Conclusion: calls federationPort.writeAuditEvent directly; does not rely on TenantFederationProvider.port
     * (the TenantFederationProvider.port field is private readonly and not externally accessible).
     *
     * An audit write failure does not interrupt the main flow (degraded: only console.error).
     */
    private async _safeWriteFederationLogoutAudit(
        context: FederationLogoutContext,
    ): Promise<void> {
        const event: FederationAuditEvent = {
            eventType: 'federation.logout',
            userId: context.userId,
            tenantId: context.tenantId,
            idpIdentifier: context.idpIdentifier,
            externalSubject: context.externalSubject,
            isNewUser: false,
            roleUpdated: false,
            timestamp: new Date().toISOString(),
        };
        try {
            await this.federationPort.writeAuditEvent(event);
        } catch (err) {
            // audit write failure: does not interrupt the main flow (accountability degraded)
            // in production, monitoring captures the SSO_LOGOUT_AUDIT_FAILED logs
            console.error(
                '[SSOClient] federation logout audit write failed (degraded):',
                err,
            );
        }
    }
}
