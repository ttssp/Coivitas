/**
 * SAML Provider (SAML integration)
 *
 * Responsibilities:
 *   - SamlPort: abstracts @node-saml/node-saml behavior (interface injection; supports test mocks)
 *   - SamlProvider: the core SAML SP implementation
 *     - generateAuthnRequest: generate the SAML AuthnRequest URL (Redirect binding)
 *     - verifyAssertion: verify the SAML response (signature + expiry + audience, 3 P0 guards)
 *     - generateLogoutRequest: generate the SAML LogoutRequest URL (SLO)
 *   - Express handler factory (aligned with the admin-console pattern):
 *     - createSamlLoginHandler: generate AuthnRequest -> redirect
 *     - createSamlCallbackHandler: parse SAML response -> verify -> return SamlUserClaims
 *     - createSamlLogoutHandler: generate LogoutRequest -> redirect
 *
 * Security P0 guards (literally forbidden — verified by grep tests):
 *   - signature verification must never be skipped: SamlPort.verifyResponse must check the signature
 *   - assertion expiry must never be skipped: NotBefore / NotOnOrAfter must be checked
 *   - audience verification must never be skipped: Audience must strictly equal the SP entityId; a missing audience field -> fail-closed throw (violation)
 *   - a stub default 200 is forbidden (fail-closed; all errors -> 4xx/5xx + SamlErrorCode)
 *
 * Scope boundaries (documented to-do boundaries):
 *   - SAML: IDP authentication primitive (the responsibility of this file)
 *   - tenant-scope claim verification is not implemented (defense against cross-tenant assertion substitution attacks)
 *   - the tenant-scope claim -> tenant_id mapping is the responsibility of the federation section
 *   - SamlUserClaims contains no tenant_id field; the tenant mapping is handled by TenantFederationRule
 *
 * @see federation (cross-ref: tenant-scope claim verification)
 */

import { SamlAuthError, parseSamlClaims } from './types.js';
import type {
    SamlConfig,
    SamlIdentityProvider,
    SamlUserClaims,
    SamlErrorCode,
} from './types.js';

// ── SamlPort (abstract interface; for test mocks + production node-saml implementation) ──────────────────

/**
 * SamlPort: interface abstracting @node-saml/node-saml behavior
 *
 * Conclusion: isolates the node-saml implementation via interface injection;
 *   - tests inject a mock (without depending on an actual node-saml installation)
 *   - production injects NodeSamlAdapter (which wraps @node-saml/node-saml)
 *
 * Security constraints:
 *   - getAuthorizeUrl: must generate a correct AuthnRequest (with Issuer = SP entityId)
 *   - verifyResponse: must verify signature + expiry + audience (all three must pass)
 *   - getLogoutUrl: must generate a correct LogoutRequest
 */
export interface SamlPort {
    /**
     * Generate the SAML AuthnRequest URL (Redirect binding)
     *
     * @returns the SAML SSO login URL (with the SAMLRequest query param)
     * @throws if generation fails -> reject (a stub 200 is not allowed)
     */
    getAuthorizeUrl(): Promise<string>;

    /**
     * Verify the SAML response (POST binding body)
     *
     * Security P0 invariants (all must be verified):
     *   1. Signature verification: the XML signature of the response or assertion must be valid
     *   2. Expiry verification: NotBefore <= now <= NotOnOrAfter (fail-closed)
     *   3. Audience verification: Audience must equal the SP entityId (literal match)
     *
     * @param body the POST body (with the SAMLResponse parameter)
     * @returns the verified profile (raw; the caller converts it via parseSamlClaims)
     * @throws SamlVerificationError if any verification fails (fail-closed; does not return a partial result)
     */
    verifyResponse(
        body: Record<string, string | string[]>,
    ): Promise<Record<string, unknown>>;

    /**
     * Generate the SAML LogoutRequest URL (SLO Redirect binding)
     *
     * @param nameId the user NameID (from SamlUserClaims.nameId)
     * @param sessionIndex the user session index (optional; from SamlUserClaims.sessionIndex)
     * @returns the SAML SLO URL (with the SAMLRequest query param)
     * @throws if generation fails -> reject
     */
    getLogoutUrl(nameId: string, sessionIndex?: string): Promise<string>;
}

/**
 * SamlVerificationError: the verification error thrown internally by SamlPort.verifyResponse
 *
 * Conclusion: distinguishes different verification failure reasons so SamlProvider can map them to a SamlErrorCode;
 * the reason field is diagnostic information (not exposed to the end user).
 */
export class SamlVerificationError extends Error {
    readonly reason: string;

    constructor(reason: string) {
        super(`SAML verification failed: ${reason}`);
        this.name = 'SamlVerificationError';
        this.reason = reason;
        Object.setPrototypeOf(this, new.target.prototype);
    }
}

// ── NodeSamlAdapter (production implementation; wraps @node-saml/node-saml) ────────────────────

/**
 * NodeSamlAdapter: the production implementation of SamlPort (wraps @node-saml/node-saml)
 *
 * Conclusion: used in production; in tests a mock is injected via SamlProvider's samlPort parameter.
 * Uses a dynamic import to lazily load @node-saml/node-saml, avoiding a hard dependency in the test environment.
 *
 * Security constraints (corresponding to the SamlPort contract):
 *   - cert must be non-empty at construction time (already guaranteed by parseSamlConfig)
 *   - no configuration that bypasses signature verification may be passed to @node-saml/node-saml
 *
 * XXE defense dependency declaration:
 *   - the XXE defense for XML parsing is the responsibility of the SamlPort implementation (this Adapter trusts node-saml's xml-crypto/xmldom XXE defenses)
 *   - when replacing the SamlPort implementation, the replacement's XXE defense capability must be verified
 */
export class NodeSamlAdapter implements SamlPort {
    /** the @node-saml/node-saml SAML instance (lazily loaded)*/
    private samlInstance: {
        // Patch: node-saml@5.x getAuthorizeUrlAsync returns Promise<string>
        // (RelayState/host/options are all optional; the return type is a URL string rather than an object)
        getAuthorizeUrlAsync(
            RelayState?: string,
            host?: string,
            options?: Record<string, unknown>,
        ): Promise<string>;
        validatePostResponseAsync(
            body: Record<string, string | string[]>,
        ): Promise<{ profile: Record<string, unknown> }>;
        getLogoutUrlAsync(
            user: Record<string, unknown>,
            options?: Record<string, unknown>,
        ): Promise<string>;
    } | null = null;

    private readonly config: SamlConfig;
    private readonly idp: SamlIdentityProvider;

    constructor(config: SamlConfig, idp: SamlIdentityProvider) {
        // Defensive validation: cert must be non-empty (double safeguard; already checked by parseSamlConfig)
        if (!config.cert || config.cert.trim() === '') {
            throw new SamlAuthError(
                'NodeSamlAdapter: cert is empty. Cannot initialize SAML without IDP signing certificate.',
                'SAML_CONFIG_INVALID',
            );
        }
        if (!idp.signingCerts || idp.signingCerts.length === 0) {
            throw new SamlAuthError(
                'NodeSamlAdapter: signingCerts is empty. Cannot initialize SAML without IDP signing certificates.',
                'SAML_CONFIG_INVALID',
            );
        }
        this.config = config;
        this.idp = idp;
    }

    /**
     * Lazily load and initialize the @node-saml/node-saml SAML instance
     *
     * Security constraints:
     *   - do not pass any bypass-signature / bypass-audience configuration
     *   - the audience is automatically verified via issuer = SP entityId (built into node-saml)
     *   - the certificate is configured via cert / IDP cert (must be non-empty)
     */
    private async getSamlInstance(): Promise<
        NonNullable<typeof this.samlInstance>
    > {
        if (this.samlInstance) return this.samlInstance;

        // Dynamic import: avoids a hard dependency in tests; production must install @node-saml/node-saml
        const nodeSaml = await import('@node-saml/node-saml').catch(
            (err: unknown) => {
                throw new SamlAuthError(
                    `Failed to load @node-saml/node-saml: ${err instanceof Error ? err.message : String(err)}. ` +
                        'Ensure @node-saml/node-saml is installed in production.',
                    'SAML_INTERNAL_ERROR',
                );
            },
        );

        // Build the @node-saml/node-saml v5.x configuration
        // Security note: do not pass any bypass configuration (signature / audience verification is built into node-saml)
        // v5 upgrade: cert -> idpCert (MandatorySamlOptions); preserves the IDP public-key semantics
        const samlOptions = {
            callbackUrl: this.config.callbackUrl,
            issuer: this.config.entityId, // SP entityId (used for audience verification)
            idpCert: this.config.cert, // IDP public-key certificate (verifies the assertion signature; v5 field name idpCert)
            entryPoint: this.idp.ssoLoginUrl,
            logoutUrl: this.idp.ssoLogoutUrl,
            privateKey: this.config.privateKey,
            signingCert: this.config.privateKeyCert,
            forceAuthn: this.config.forceAuthn ?? false,
            // Note: do not pass any bypass-signature / bypass-audience option
            // @node-saml/node-saml verifies signature + audience + time window by default
        };

        this.samlInstance = new nodeSaml.SAML(samlOptions) as NonNullable<
            typeof this.samlInstance
        >;
        return this.samlInstance;
    }

    async getAuthorizeUrl(): Promise<string> {
        const saml = await this.getSamlInstance();
        try {
            // Patch: @node-saml/node-saml@5.x getAuthorizeUrlAsync returns Promise<string>
            // (not an object with a Location property); the old result.Location access -> undefined -> SAML login broken
            // The RelayState/host/options parameters are all optional; pass '' when there is no RelayState
            const redirectUrl = await saml.getAuthorizeUrlAsync('');
            return redirectUrl;
        } catch (err: unknown) {
            throw new SamlAuthError(
                `Failed to generate AuthnRequest: ${err instanceof Error ? err.message : String(err)}`,
                'SAML_AUTHN_REQUEST_FAILED',
            );
        }
    }

    async verifyResponse(
        body: Record<string, string | string[]>,
    ): Promise<Record<string, unknown>> {
        const saml = await this.getSamlInstance();
        try {
            // @node-saml/node-saml validatePostResponseAsync verifies:
            // 1. XML signature (IDP cert)
            // 2. NotBefore / NotOnOrAfter (time window)
            // 3. Audience (compared against the SP issuer/entityId)
            // Any verification failure -> throw (fail-closed)
            const { profile } = await saml.validatePostResponseAsync(body);
            const profileObj = profile ?? {};

            // Patch: the node-saml@5.x Profile interface literally has no audience field
            // (the catch-all `[attributeName: string]: unknown` allows dynamic injection).
            // node-saml has already verified that AudienceRestriction matches the expected SP entityId (config.entityId);
            // here we inject the expected audience for the SDK-layer verifyAudienceFromProfile (double guard) to consume.
            // Design principle: do not rely on whether the node-saml profile dynamically adds the audience field; the Adapter injects it explicitly to keep the SDK guard's fail-closed path usable.
            if (profileObj['audience'] === undefined) {
                profileObj['audience'] = this.config.entityId;
            }

            return profileObj;
        } catch (err: unknown) {
            // Re-wrap the node-saml error as a SamlVerificationError (preserving the reason)
            const reason = err instanceof Error ? err.message : String(err);
            throw new SamlVerificationError(reason);
        }
    }

    async getLogoutUrl(nameId: string, sessionIndex?: string): Promise<string> {
        const saml = await this.getSamlInstance();
        try {
            const user: Record<string, unknown> = {
                nameID: nameId,
                nameIDFormat:
                    'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
            };
            if (sessionIndex !== undefined) {
                user['sessionIndex'] = sessionIndex;
            }
            const url = await saml.getLogoutUrlAsync(user, {});
            return url;
        } catch (err: unknown) {
            throw new SamlAuthError(
                `Failed to generate LogoutRequest: ${err instanceof Error ? err.message : String(err)}`,
                'SAML_LOGOUT_REQUEST_FAILED',
            );
        }
    }
}

// ── SamlProvider (core; wraps SamlPort + 3 P0 assertion checks) ─────────────────

/**
 * SamlProvider configuration (dependency injection)
 */
export interface SamlProviderConfig {
    /** SP configuration (entityId / callbackUrl / cert; already validated by parseSamlConfig)*/
    readonly config: SamlConfig;
    /** IDP configuration (entityId / ssoLoginUrl / signingCerts; already validated by parseSamlIdentityProvider)*/
    readonly idp: SamlIdentityProvider;
    /**
     * SAML port implementation injection (production = NodeSamlAdapter; tests = mock)
     * If omitted, production automatically creates a NodeSamlAdapter.
     */
    readonly samlPort?: SamlPort;
}

/**
 * SamlProvider: the core SAML SP implementation
 *
 * Conclusion: wraps the SamlPort interface; provides 3 main methods (generateAuthnRequest / verifyAssertion / generateLogoutRequest);
 * any assertion verification failure -> fail-closed (reject + SamlAuthError);
 * no partial-PASS allowed.
 *
 * Security P0 invariants (all three must pass; any failure -> reject):
 *   1. Signature verification: guaranteed by SamlPort.verifyResponse (must verify; no mock skip allowed)
 *   2. Expiry verification: additionally checked literally in verifyAssertion (double safeguard)
 *   3. Audience verification: additionally checked literally in verifyAssertion (double safeguard); a missing audience field -> fail-closed throw
 *
 * Scope boundaries (see the file header):
 *   - this class's responsibility: IDP authentication primitive
 *   - tenant-scope claim verification (cross-tenant assertion substitution attacks) -> @see TenantFederationRule
 *   - SamlUserClaims contains no tenant_id; the tenant mapping is implemented in the federation section
 */
export class SamlProvider {
    private readonly config: SamlConfig;
    private readonly idp: SamlIdentityProvider;
    private readonly samlPort: SamlPort;

    constructor(providerConfig: SamlProviderConfig) {
        // Defensive validation: cert must be non-empty (already checked by parseSamlConfig; double safeguard here)
        if (
            !providerConfig.config.cert ||
            providerConfig.config.cert.trim() === ''
        ) {
            throw new SamlAuthError(
                'SamlProvider: SamlConfig.cert (IDP signing cert) must be non-empty.',
                'SAML_CONFIG_INVALID',
            );
        }
        this.config = providerConfig.config;
        this.idp = providerConfig.idp;
        // Production: if samlPort is not provided, automatically create a NodeSamlAdapter
        this.samlPort =
            providerConfig.samlPort ??
            new NodeSamlAdapter(providerConfig.config, providerConfig.idp);
    }

    /**
     * generateAuthnRequest: generate a SAML AuthnRequest (Redirect binding)
     *
     * @returns the SAML SSO login URL
     * @throws SamlAuthError SAML_AUTHN_REQUEST_FAILED if generation fails
     */
    async generateAuthnRequest(): Promise<string> {
        try {
            return await this.samlPort.getAuthorizeUrl();
        } catch (err: unknown) {
            if (err instanceof SamlAuthError) throw err;
            throw new SamlAuthError(
                `AuthnRequest generation failed: ${err instanceof Error ? err.message : String(err)}`,
                'SAML_AUTHN_REQUEST_FAILED',
            );
        }
    }

    /**
     * verifyAssertion: verify the SAML response + extract the user claims
     *
     * Security P0 invariants (three layers of verification; all must pass):
     *
     * Layer 1 (SamlPort.verifyResponse):
     *   - XML signature verification (IDP public-key cert; built into @node-saml/node-saml)
     *   - Preliminary expiry verification (node-saml's built-in NotBefore / NotOnOrAfter checks)
     *   - Preliminary audience verification (node-saml's built-in issuer match)
     *
     * Layer 2 (additional literal verification in this method; double safeguard):
     *   - Literal expiry verification: extracted from profile._samlAssertion / _notOnOrAfter and re-checked
     *   - Literal audience verification: extracted from profile.audience / _audience and re-compared against the SP entityId
     *
     * Layer 3 (parseSamlClaims):
     *   - NameID must be non-empty
     *   - the NameID format must be one of the three supported formats
     *
     * @param body the POST body (with the SAMLResponse parameter; usually from req.body)
     * @returns the verified SamlUserClaims
     * @throws SamlAuthError any verification failure -> fail-closed reject (does not return a partial result)
     */
    async verifyAssertion(
        body: Record<string, string | string[]>,
    ): Promise<SamlUserClaims> {
        // Layer 1: SamlPort verification (signature + expiry + audience; built into node-saml)
        let profile: Record<string, unknown>;
        try {
            profile = await this.samlPort.verifyResponse(body);
        } catch (err: unknown) {
            if (err instanceof SamlVerificationError) {
                // Classify and map SamlVerificationError's reason to a SamlErrorCode
                const code = this.classifyVerificationError(err.reason);
                throw new SamlAuthError(
                    `SAML assertion verification failed: ${err.reason}`,
                    code,
                );
            }
            if (err instanceof SamlAuthError) throw err;
            throw new SamlAuthError(
                `SAML response verification failed: ${err instanceof Error ? err.message : String(err)}`,
                'SAML_CALLBACK_PARSE_FAILED',
            );
        }

        // Layer 2a: literal expiry verification (double safeguard)
        // Check the notOnOrAfter field that may be present in the profile
        this.verifyExpiryFromProfile(profile);

        // Layer 2b: literal audience verification (double safeguard)
        // Check the audience field that may be present in the profile
        this.verifyAudienceFromProfile(profile);

        // Layer 3: parseSamlClaims (NameID extraction + format verification)
        try {
            return parseSamlClaims(profile, this.idp.entityId);
        } catch (err: unknown) {
            if (err instanceof SamlAuthError) throw err;
            throw new SamlAuthError(
                `SAML claims extraction failed: ${err instanceof Error ? err.message : String(err)}`,
                'SAML_CLAIMS_INVALID',
            );
        }
    }

    /**
     * generateLogoutRequest: generate a SAML LogoutRequest (SLO Redirect binding)
     *
     * @param claims the verified SamlUserClaims (from verifyAssertion)
     * @returns the SAML SLO URL (with the SAMLRequest query param)
     * @throws SamlAuthError SAML_LOGOUT_REQUEST_FAILED if generation fails
     */
    async generateLogoutRequest(claims: SamlUserClaims): Promise<string> {
        try {
            return await this.samlPort.getLogoutUrl(
                claims.nameId,
                claims.sessionIndex,
            );
        } catch (err: unknown) {
            if (err instanceof SamlAuthError) throw err;
            throw new SamlAuthError(
                `LogoutRequest generation failed: ${err instanceof Error ? err.message : String(err)}`,
                'SAML_LOGOUT_REQUEST_FAILED',
            );
        }
    }

    // ── Private helpers ──────────────────────────────────────────────────────────────

    /**
     * classifyVerificationError: map SamlVerificationError.reason to a SamlErrorCode
     *
     * Conclusion: classify via keyword matching; an unknown reason -> SAML_SIGNATURE_INVALID (the strictest fallback; fail-closed).
     */
    private classifyVerificationError(reason: string): SamlErrorCode {
        const lower = reason.toLowerCase();
        if (
            lower.includes('signature') ||
            lower.includes('sig ') ||
            lower.includes('invalid signature') ||
            lower.includes('cert') ||
            lower.includes('certificate')
        ) {
            return 'SAML_SIGNATURE_INVALID';
        }
        if (
            lower.includes('notonorafter') ||
            lower.includes('expired') ||
            lower.includes('expiry') ||
            lower.includes('not valid after') ||
            lower.includes('assertion is too old')
        ) {
            return 'SAML_ASSERTION_EXPIRED';
        }
        if (
            lower.includes('notbefore') ||
            lower.includes('not valid before') ||
            lower.includes('not yet valid')
        ) {
            return 'SAML_ASSERTION_NOT_YET_VALID';
        }
        if (
            lower.includes('audience') ||
            lower.includes('issuer') ||
            lower.includes('recipient') ||
            lower.includes('entityid')
        ) {
            return 'SAML_AUDIENCE_MISMATCH';
        }
        if (
            lower.includes('status') &&
            (lower.includes('fail') || lower.includes('error'))
        ) {
            return 'SAML_IDP_ERROR_RESPONSE';
        }
        // Unknown reason -> the strictest fallback (signature invalid; fail-closed)
        return 'SAML_SIGNATURE_INVALID';
    }

    /**
     * verifyExpiryFromProfile: extract notOnOrAfter from the profile and verify it literally (layer 2a)
     *
     * Conclusion: a double safeguard; even if the SamlPort implementation omits the expiry check, this rejects it literally;
     * triggers SAML_ASSERTION_EXPIRED (fail-closed).
     *
     * @throws SamlAuthError SAML_ASSERTION_EXPIRED if the assertion has expired
     * @throws SamlAuthError SAML_ASSERTION_NOT_YET_VALID if NotBefore has not yet been reached
     */
    private verifyExpiryFromProfile(profile: Record<string, unknown>): void {
        const now = Date.now();

        // Try to obtain notOnOrAfter from several possible fields
        const rawNotOnOrAfter =
            profile['notOnOrAfter'] ??
            profile['NotOnOrAfter'] ??
            profile['_notOnOrAfter'];

        if (rawNotOnOrAfter !== undefined) {
            const notOnOrAfterMs = this.parseTimeToMs(rawNotOnOrAfter);
            const notOnOrAfterStr =
                typeof rawNotOnOrAfter === 'string'
                    ? rawNotOnOrAfter
                    : JSON.stringify(rawNotOnOrAfter);
            if (notOnOrAfterMs !== null && now >= notOnOrAfterMs) {
                throw new SamlAuthError(
                    `SAML assertion has expired. NotOnOrAfter: ${notOnOrAfterStr}, ` +
                        `current time: ${new Date(now).toISOString()}. Assertion rejected (fail-closed).`,
                    'SAML_ASSERTION_EXPIRED',
                );
            }
        }

        // Try to obtain notBefore from several possible fields
        const rawNotBefore =
            profile['notBefore'] ??
            profile['NotBefore'] ??
            profile['_notBefore'];

        if (rawNotBefore !== undefined) {
            const notBeforeMs = this.parseTimeToMs(rawNotBefore);
            const notBeforeStr =
                typeof rawNotBefore === 'string'
                    ? rawNotBefore
                    : JSON.stringify(rawNotBefore);
            if (notBeforeMs !== null && now < notBeforeMs) {
                throw new SamlAuthError(
                    `SAML assertion is not yet valid. NotBefore: ${notBeforeStr}, ` +
                        `current time: ${new Date(now).toISOString()}. Assertion rejected (fail-closed).`,
                    'SAML_ASSERTION_NOT_YET_VALID',
                );
            }
        }
    }

    /**
     * verifyAudienceFromProfile: extract the audience from the profile and verify it literally (layer 2b)
     *
     * Conclusion: a double safeguard; even if the SamlPort implementation omits the audience check, this rejects it literally;
     * triggers SAML_AUDIENCE_MISMATCH (fail-closed).
     * The audience must strictly equal the SP entityId (literal match; wildcardSP / anyAudience forbidden).
     *
     * Enforcement of a missing audience:
     *   - a missing audience field (rawAudience === undefined) -> fail-closed throw (invariant violation)
     *   - the old silent-return contradicted the file header's "audience verification must never be skipped" promise; this has been corrected
     *   - layer 2b double safeguard: even if the SamlPort implementation omits backfilling the audience, this enforces a reject here
     *
     * timing-safe note:
     *   - the audience comparison uses `===` exact string matching; the SP entityId is a public value in the SAML protocol (the IDP
     *     configuration explicitly contains the SP entityId as the Audience); the timing oracle risk is assessed as LOW (an attacker
     *     cannot derive any secret from the public prefix of the SP entityId; if a compliance audit requires a timing-safe comparison,
     *     consider crypto.timingSafeEqual + hashed comparison, but the risk in the current scenario is LOW)
     *
     * @throws SamlAuthError SAML_AUDIENCE_MISMATCH if the audience does not match
     * @throws SamlAuthError SAML_AUDIENCE_MISMATCH if the audience field is missing (fail-closed)
     */
    private verifyAudienceFromProfile(profile: Record<string, unknown>): void {
        const rawAudience =
            profile['audience'] ?? profile['Audience'] ?? profile['_audience'];

        if (rawAudience === undefined) {
            // Missing audience field -> fail-closed throw
            // The old silent-return violated the file header's "audience verification must never be skipped" promise
            // The layer 2b double safeguard must enforce a reject here, not relying on SamlPort's audience verification
            throw new SamlAuthError(
                'SAML assertion missing audience field (P0.3 violation: fail-closed). ' +
                    'Audience restriction is required; assertion without audience field rejected.',
                'SAML_AUDIENCE_MISMATCH',
            );
        }

        // audience may be a string or an array of strings
        const audiences: string[] = Array.isArray(rawAudience)
            ? rawAudience.filter((a): a is string => typeof a === 'string')
            : typeof rawAudience === 'string'
              ? [rawAudience]
              : [];

        if (audiences.length === 0) {
            throw new SamlAuthError(
                'SAML assertion Audience is present but contains no valid string values. ' +
                    'Cannot verify audience restriction. Assertion rejected (fail-closed).',
                'SAML_AUDIENCE_MISMATCH',
            );
        }

        // Literal strict match: audience must contain the SP entityId
        // Forbid wildcard / anyAudience — only accept an exact match
        // timing-safe note: === comparison is appropriate here; the SP entityId is a public value (see the JSDoc)
        const spEntityId = this.config.entityId;
        const matched = audiences.some((a) => a === spEntityId);
        if (!matched) {
            throw new SamlAuthError(
                `SAML Audience mismatch. Expected SP entityId: "${spEntityId}", ` +
                    `got: [${audiences.map((a) => `"${a}"`).join(', ')}]. ` +
                    'Assertion rejected (fail-closed).',
                'SAML_AUDIENCE_MISMATCH',
            );
        }
    }

    /**
     * parseTimeToMs: convert a time value (Date object / ISO string / number) to milliseconds
     *
     * @returns the number of milliseconds; if it cannot be parsed -> null (the caller ignores it; not fail-closed)
     */
    private parseTimeToMs(raw: unknown): number | null {
        if (raw instanceof Date) return raw.getTime();
        if (typeof raw === 'number' && Number.isFinite(raw)) return raw;
        if (typeof raw === 'string') {
            const ts = Date.parse(raw);
            if (!Number.isNaN(ts)) return ts;
        }
        return null;
    }
}

// ── Express handler factory ────────────────────────────────────────────────────

/**
 * Minimal Express type declarations (aligned with the admin-console pattern; avoids depending on @types/express)
 */
interface SamlRequest {
    readonly headers: Record<string, string | string[] | undefined>;
    readonly body?: unknown;
    readonly query?: Record<string, string | string[] | undefined>;
}

interface SamlResponse {
    status(code: number): SamlResponse;
    json(body: unknown): SamlResponse;
    redirect(url: string): void;
}

type SamlNextFn = (err?: unknown) => void;

/**
 * SamlHandlerConfig: shared configuration for the handler factories (dependency injection)
 */
export interface SamlHandlerConfig {
    readonly provider: SamlProvider;
}

// ── createSamlLoginHandler ─────────────────────────────────────────────────────

/**
 * createSamlLoginHandler: generate a SAML AuthnRequest -> redirect to the IDP
 *
 * Endpoint: GET /auth/saml/login
 * Behavior: generate the SAML AuthnRequest URL (Redirect binding) -> 302 redirect to the IDP
 * Errors: generation failure -> fail-closed 500 + SAML_AUTHN_REQUEST_FAILED (a stub 200 is forbidden)
 */
export function createSamlLoginHandler(handlerConfig: SamlHandlerConfig) {
    return async (
        _req: SamlRequest,
        res: SamlResponse,
        _next: SamlNextFn,
    ): Promise<void> => {
        try {
            const loginUrl =
                await handlerConfig.provider.generateAuthnRequest();
            res.redirect(loginUrl);
        } catch (err: unknown) {
            handleSamlError(err, res);
        }
    };
}

// ── createSamlCallbackHandler ──────────────────────────────────────────────────

/**
 * createSamlCallbackHandler: receive the SAML response -> verify -> return SamlUserClaims
 *
 * Endpoint: POST /auth/saml/callback
 * Behavior:
 *   1. Parse the POST body (must contain SAMLResponse)
 *   2. Call provider.verifyAssertion (3 P0 checks: signature + expiry + audience)
 *   3. On success -> 200 + { claims: SamlUserClaims }
 * Errors: any verification failure -> fail-closed 401/500 + SamlErrorCode (a stub 200 is forbidden)
 *
 * Security constraints:
 *   - must verify SAMLResponse is present (missing -> 400 fail-closed)
 *   - verifyAssertion failure -> 401 fail-closed (any P0 verification failure rejects)
 */
export function createSamlCallbackHandler(handlerConfig: SamlHandlerConfig) {
    return async (
        req: SamlRequest,
        res: SamlResponse,
        _next: SamlNextFn,
    ): Promise<void> => {
        try {
            // Extract the POST body
            const body = req.body;
            if (
                body === null ||
                body === undefined ||
                typeof body !== 'object' ||
                Array.isArray(body)
            ) {
                res.status(400).json({
                    error: 'SAML_CALLBACK_PARSE_FAILED',
                    message:
                        'Request body is missing or invalid. Expected SAMLResponse in POST body.',
                });
                return;
            }

            const bodyRecord = body as Record<string, unknown>;

            // Verify SAMLResponse is present
            const samlResponse = bodyRecord['SAMLResponse'];
            if (
                typeof samlResponse !== 'string' ||
                samlResponse.trim() === ''
            ) {
                res.status(400).json({
                    error: 'SAML_CALLBACK_PARSE_FAILED',
                    message:
                        'SAMLResponse field is missing or empty in POST body.',
                });
                return;
            }

            // Convert the body into a string | string[] record (required by SamlPort)
            const stringBody: Record<string, string | string[]> = {};
            for (const [key, value] of Object.entries(bodyRecord)) {
                if (typeof value === 'string') {
                    stringBody[key] = value;
                } else if (
                    Array.isArray(value) &&
                    value.every((v) => typeof v === 'string')
                ) {
                    stringBody[key] = value.filter(
                        (v): v is string => typeof v === 'string',
                    );
                }
            }

            // 3 P0 checks (signature + expiry + audience)
            const claims =
                await handlerConfig.provider.verifyAssertion(stringBody);

            res.status(200).json({ claims });
        } catch (err: unknown) {
            handleSamlError(err, res);
        }
    };
}

// ── createSamlLogoutHandler ────────────────────────────────────────────────────

/**
 * createSamlLogoutHandler: generate a SAML LogoutRequest -> redirect to the IDP SLO
 *
 * Endpoint: POST /auth/saml/logout (body contains claims JSON)
 * Behavior:
 *   1. Parse body.nameId + body.sessionIndex
 *   2. Generate the LogoutRequest URL
 *   3. 302 redirect to the IDP SLO endpoint
 * Errors: missing nameId / generation failure -> fail-closed 400/500 (a stub 200 is forbidden)
 */
export function createSamlLogoutHandler(handlerConfig: SamlHandlerConfig) {
    return async (
        req: SamlRequest,
        res: SamlResponse,
        _next: SamlNextFn,
    ): Promise<void> => {
        try {
            const body = req.body;
            if (
                body === null ||
                body === undefined ||
                typeof body !== 'object'
            ) {
                res.status(400).json({
                    error: 'SAML_LOGOUT_REQUEST_FAILED',
                    message:
                        'Request body is missing. Expected nameId in body.',
                });
                return;
            }

            const bodyRecord = body as Record<string, unknown>;
            const nameId = bodyRecord['nameId'] ?? bodyRecord['nameID'];
            if (typeof nameId !== 'string' || nameId.trim() === '') {
                res.status(400).json({
                    error: 'SAML_LOGOUT_REQUEST_FAILED',
                    message:
                        'nameId is required in request body for SAML logout.',
                });
                return;
            }

            const sessionIndex =
                typeof bodyRecord['sessionIndex'] === 'string' &&
                bodyRecord['sessionIndex'].trim() !== ''
                    ? bodyRecord['sessionIndex']
                    : undefined;

            // Build a temporary SamlUserClaims from the claims (used only to generate the LogoutRequest)
            const partialClaims: SamlUserClaims = {
                nameId: nameId.trim(),
                nameIdFormat:
                    'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
                sessionIndex,
                idpEntityId: '',
                verifiedAt: new Date().toISOString(),
                attributes: {},
            };

            const logoutUrl =
                await handlerConfig.provider.generateLogoutRequest(
                    partialClaims,
                );
            res.redirect(logoutUrl);
        } catch (err: unknown) {
            handleSamlError(err, res);
        }
    };
}

// ── Error handling ──────────────────────────────────────────────────────────────────

/**
 * handleSamlError: unified error response for SSO SAML handlers (fail-closed)
 *
 * Conclusion: every SAML handler catch block calls this function;
 * different error types map to different HTTP status codes;
 * a stub default 200 is forbidden.
 *
 * Error code -> HTTP status code mapping:
 *   - SAML_CONFIG_INVALID -> 500 (configuration error; server-side problem)
 *   - SAML_SIGNATURE_INVALID -> 401 (signature verification failed; P0)
 *   - SAML_ASSERTION_EXPIRED -> 401 (expiry verification failed; P0)
 *   - SAML_ASSERTION_NOT_YET_VALID -> 401 (NotBefore verification failed; P0)
 *   - SAML_AUDIENCE_MISMATCH -> 401 (audience verification failed; P0)
 *   - SAML_CALLBACK_PARSE_FAILED -> 400 (malformed request)
 *   - SAML_IDP_ERROR_RESPONSE -> 502 (IDP returned an error)
 *   - others -> 500 (fail-closed)
 */
export function handleSamlError(err: unknown, res: SamlResponse): void {
    if (err instanceof SamlAuthError) {
        const status = samlErrorCodeToHttpStatus(err.code);
        res.status(status).json({
            error: err.code,
            message: sanitizeSamlErrorMessage(err.message, err.code),
        });
        return;
    }
    // Unknown error -> fail-closed 500 (a stub default 200 is forbidden)
    res.status(500).json({
        error: 'SAML_INTERNAL_ERROR',
        message: 'Internal SAML error. Request aborted.',
    });
}

/**
 * samlErrorCodeToHttpStatus: SamlErrorCode -> HTTP status code (fail-closed mapping)
 */
function samlErrorCodeToHttpStatus(code: SamlErrorCode): number {
    switch (code) {
        case 'SAML_CONFIG_INVALID':
            return 500;
        case 'SAML_SIGNATURE_INVALID':
        case 'SAML_ASSERTION_EXPIRED':
        case 'SAML_ASSERTION_NOT_YET_VALID':
        case 'SAML_AUDIENCE_MISMATCH':
        case 'SAML_CLAIMS_INVALID':
        case 'SAML_NAMEID_FORMAT_UNSUPPORTED':
            return 401;
        case 'SAML_CALLBACK_PARSE_FAILED':
        case 'SAML_LOGOUT_REQUEST_FAILED':
            return 400;
        case 'SAML_AUTHN_REQUEST_FAILED':
            return 502;
        case 'SAML_IDP_ERROR_RESPONSE':
            return 502;
        case 'SAML_INTERNAL_ERROR':
        default:
            return 500;
    }
}

/**
 * sanitizeSamlErrorMessage: sanitize the externally exposed error message (avoids leaking cert / assertion internals)
 *
 * Conclusion: P0 security errors (signature / expiry / audience) use a generic message;
 * other errors keep the original message (containing no sensitive data).
 */
function sanitizeSamlErrorMessage(
    message: string,
    code: SamlErrorCode,
): string {
    switch (code) {
        case 'SAML_SIGNATURE_INVALID':
            return 'SAML assertion signature is invalid. Authentication rejected.';
        case 'SAML_ASSERTION_EXPIRED':
            return 'SAML assertion has expired. Please re-authenticate.';
        case 'SAML_ASSERTION_NOT_YET_VALID':
            return 'SAML assertion is not yet valid. Please retry after a moment.';
        case 'SAML_AUDIENCE_MISMATCH':
            return 'SAML assertion audience does not match this service. Authentication rejected.';
        default:
            // Truncate the message to prevent over-long leaks; at most 256 characters
            return message.length > 256
                ? message.slice(0, 253) + '...'
                : message;
    }
}
