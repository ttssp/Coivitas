/**
 * SSO public type definitions (SAML section)
 *
 * Responsibilities:
 *   - SAML configuration types (SamlConfig / SamlIdentityProvider)
 *   - SAML user claims type (SamlUserClaims)
 *   - SAML error code system (SamlAuthError; fail-closed)
 *   - Shared skeletons (placeholder declarations for later OIDC / federation / SDK API sections)
 *
 * Design constraints (fail-closed + security P0 guards):
 *   - SAML assertion verification must be fail-closed: signature / expiry / audience failure -> reject (no skip)
 *   - No `as SamlUserClaims` brand cast; use the parseSamlClaims() factory function
 *   - Strictly forbid introducing any verification-bypass option (skipSignatureVerify / skipExpiry / anyAudience, etc.)
 *
 * Security P0 guards (literally forbidden — grep tests verify the source contains none of the following keywords):
 *   - skipSignatureVerify / disableSigCheck / noSigValidation
 *   - skipExpiry / ignoreNotAfter / bypassExpiry
 *   - skipAudience / anyAudience / wildcardSP
 */

// ── SAML SP configuration ───────────────────────────────────────────────────────────────

/**
 * SAML Service Provider (SP) configuration
 *
 * Conclusion: the SP configuration contains the entityID (used for audience verification), the callback URL, and the certificate;
 * all fields are required and empty strings are not allowed (validated by parseSamlConfig).
 *
 * Security invariants:
 *   - entityId must strictly match the assertion Audience (no wildcardSP / anyAudience)
 *   - callbackUrl must be https:// or http://localhost (https is enforced in production)
 *   - cert must be a non-empty PEM certificate (an empty certificate skipping signature verification is forbidden)
 */
export interface SamlConfig {
    /**
     * SP entityID (used for audience restriction verification)
     * Example: "https://sp.example.com/saml/metadata"
     */
    readonly entityId: string;

    /**
     * SAML assertion consumer service (ACS) URL
     * Example: "https://sp.example.com/saml/callback"
     */
    readonly callbackUrl: string;

    /**
     * IDP public-key PEM certificate (used to verify the SAML response signature)
     * Must be non-empty; skipping signature verification is not allowed.
     */
    readonly cert: string;

    /**
     * SP private-key PEM (used to sign the AuthnRequest; optional; but if provided must be valid PEM)
     * If undefined, the AuthnRequest is not signed (the IDP assertion signature is still verified)
     */
    readonly privateKey?: string;

    /**
     * SP certificate PEM (paired with privateKey; used for AuthnRequest signature verification)
     */
    readonly privateKeyCert?: string;

    /**
     * IDP metadata URL (optional; built from SamlIdentityProvider.ssoLoginUrl by preference)
     */
    readonly idpMetadataUrl?: string;

    /**
     * Whether to force authentication (ForceAuthn = true; used for highly sensitive operations)
     * Defaults to false.
     */
    readonly forceAuthn?: boolean;
}

/**
 * SAML Identity Provider (IDP) configuration
 *
 * Conclusion: the IDP configuration is parsed from XML metadata by parseSamlIdentityProvider();
 * bare casts are forbidden.
 */
export interface SamlIdentityProvider {
    /**
     * IDP entityID (used for logging / auditing)
     */
    readonly entityId: string;

    /**
     * IDP SSO login endpoint (POST or Redirect binding)
     */
    readonly ssoLoginUrl: string;

    /**
     * IDP SSO logout endpoint (SingleLogoutService; optional)
     */
    readonly ssoLogoutUrl?: string;

    /**
     * IDP signing certificates (PEM; used for assertion signature verification)
     * Sourced from the metadata's <KeyDescriptor use="signing">.
     */
    readonly signingCerts: readonly string[];

    /**
     * Binding type: POST (default) or Redirect
     */
    readonly binding: 'POST' | 'Redirect';
}

// ── NameID Format ──────────────────────────────────────────────────────────────

/**
 * SAML Subject NameID format enum (the three supported formats)
 *
 * Conclusion: literally supports the three formats email / persistent / transient;
 * an unknown format -> SamlAuthError SAML_NAMEID_FORMAT_UNSUPPORTED (fail-closed).
 */
export type SamlNameIdFormat =
    | 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'
    | 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent'
    | 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient';

/** Set of valid NameID formats (used for validation; bare casts forbidden)*/
const VALID_NAMEID_FORMATS: ReadonlySet<string> = new Set<SamlNameIdFormat>([
    'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
    'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
    'urn:oasis:names:tc:SAML:2.0:nameid-format:transient',
]);

/**
 * Parse the NameID format (the only valid way to create a SamlNameIdFormat; bare casts forbidden)
 *
 * @throws SamlAuthError SAML_NAMEID_FORMAT_UNSUPPORTED if the format is invalid (fail-closed)
 */
export function parseSamlNameIdFormat(
    raw: string | undefined,
): SamlNameIdFormat {
    if (!raw || raw.trim() === '') {
        throw new SamlAuthError(
            'SAML NameID format is missing.',
            'SAML_NAMEID_FORMAT_UNSUPPORTED',
        );
    }
    if (!VALID_NAMEID_FORMATS.has(raw.trim())) {
        throw new SamlAuthError(
            `Unsupported SAML NameID format: "${raw.slice(0, 128)}". ` +
                `Supported: emailAddress, persistent, transient.`,
            'SAML_NAMEID_FORMAT_UNSUPPORTED',
        );
    }
    return raw.trim() as SamlNameIdFormat;
}

// ── SamlUserClaims ────────────────────────────────────────────────────────────

/**
 * User claims extracted after the SAML assertion has been verified
 *
 * Conclusion: extracts nameId + format + attributes from the assertion;
 * only data that has passed the saml-provider assertion verification flow can create this type (parseSamlClaims factory).
 */
export interface SamlUserClaims {
    /**
     * Subject NameID value (email / opaque ID)
     */
    readonly nameId: string;

    /**
     * Subject NameID format (one of the three verified formats)
     */
    readonly nameIdFormat: SamlNameIdFormat;

    /**
     * Session index (used to match the SLO LogoutRequest; optional)
     */
    readonly sessionIndex?: string;

    /**
     * IDP entityID (assertion source; used for auditing)
     */
    readonly idpEntityId: string;

    /**
     * Verification timestamp (ISO 8601; after the assertion NotBefore and before NotOnOrAfter)
     */
    readonly verifiedAt: string;

    /**
     * Additional attributes provided by the IDP (attribute statements)
     * key = attribute name; value = the first attribute value (string)
     */
    readonly attributes: Readonly<Record<string, string>>;
}

/**
 * parseSamlClaims: build SamlUserClaims from a node-saml profile (bare casts forbidden)
 *
 * Conclusion: the only valid path to create SamlUserClaims;
 * a missing field -> fail-closed (SamlAuthError SAML_CLAIMS_INVALID).
 *
 * @param profile the profile object returned by node-saml (after verification)
 * @param idpEntityId IDP entityID (from the SamlIdentityProvider configuration)
 * @throws SamlAuthError SAML_CLAIMS_INVALID if a required field is missing
 */
export function parseSamlClaims(
    profile: Record<string, unknown>,
    idpEntityId: string,
): SamlUserClaims {
    // nameId must be present and non-empty
    const nameId = profile['nameID'] ?? profile['nameId'] ?? profile['email'];
    if (typeof nameId !== 'string' || nameId.trim() === '') {
        throw new SamlAuthError(
            'SAML assertion missing valid NameID.',
            'SAML_CLAIMS_INVALID',
        );
    }

    // nameIdFormat: parse (fail-closed)
    const rawFormat = profile['nameIDFormat'] ?? profile['nameIdFormat'];
    const nameIdFormat = parseSamlNameIdFormat(
        typeof rawFormat === 'string' ? rawFormat : undefined,
    );

    // sessionIndex (optional)
    const sessionIndex =
        typeof profile['sessionIndex'] === 'string'
            ? profile['sessionIndex']
            : undefined;

    // attributes: extract all additional string-typed attributes
    // prototype pollution defense:
    // - use Object.create(null) as the base to eliminate the __proto__ prototype chain
    // - reject known prototype pollution attack attribute names: __proto__ / constructor / prototype
    // - the IDP can inject dangerous attribute names; without rejection, Object.freeze cannot block the prototype-pollution surface
    const FORBIDDEN_ATTRIBUTE_NAMES = new Set([
        '__proto__',
        'constructor',
        'prototype',
    ]);
    const attributes = Object.create(null) as Record<string, string>;
    for (const [key, value] of Object.entries(profile)) {
        if (
            key !== 'nameID' &&
            key !== 'nameId' &&
            key !== 'nameIDFormat' &&
            key !== 'nameIdFormat' &&
            key !== 'sessionIndex' &&
            key !== 'issuer' &&
            typeof value === 'string'
        ) {
            if (FORBIDDEN_ATTRIBUTE_NAMES.has(key)) {
                throw new SamlAuthError(
                    `SAML claims contain forbidden attribute name: "${key}". ` +
                        'Prototype pollution attack detected. Assertion rejected (fail-closed).',
                    'SAML_CLAIMS_INVALID',
                );
            }
            attributes[key] = value;
        }
    }

    return {
        nameId: nameId.trim(),
        nameIdFormat,
        sessionIndex,
        idpEntityId,
        verifiedAt: new Date().toISOString(),
        attributes: Object.freeze(attributes),
    };
}

// ── SAML configuration validation ─────────────────────────────────────────────────────────────

/**
 * parseSamlConfig: validate and build SamlConfig (bare casts forbidden)
 *
 * Conclusion: the only valid path to create SamlConfig;
 * a missing field / empty cert -> fail-closed (SamlAuthError SAML_CONFIG_INVALID).
 *
 * @throws SamlAuthError SAML_CONFIG_INVALID if the configuration is invalid
 */
export function parseSamlConfig(raw: Record<string, unknown>): SamlConfig {
    const entityId = raw['entityId'];
    if (typeof entityId !== 'string' || entityId.trim() === '') {
        throw new SamlAuthError(
            'SamlConfig.entityId is required and must be a non-empty string.',
            'SAML_CONFIG_INVALID',
        );
    }

    const callbackUrl = raw['callbackUrl'];
    if (typeof callbackUrl !== 'string' || callbackUrl.trim() === '') {
        throw new SamlAuthError(
            'SamlConfig.callbackUrl is required and must be a non-empty string.',
            'SAML_CONFIG_INVALID',
        );
    }

    const cert = raw['cert'];
    if (typeof cert !== 'string' || cert.trim() === '') {
        // Empty certificate -> cannot verify the signature -> fail-closed reject
        throw new SamlAuthError(
            'SamlConfig.cert (IDP signing certificate) is required and must be non-empty. ' +
                'An empty cert would bypass SAML signature verification.',
            'SAML_CONFIG_INVALID',
        );
    }

    const privateKey =
        typeof raw['privateKey'] === 'string' && raw['privateKey'].trim() !== ''
            ? raw['privateKey']
            : undefined;
    const privateKeyCert =
        typeof raw['privateKeyCert'] === 'string' &&
        raw['privateKeyCert'].trim() !== ''
            ? raw['privateKeyCert']
            : undefined;
    const idpMetadataUrl =
        typeof raw['idpMetadataUrl'] === 'string' &&
        raw['idpMetadataUrl'].trim() !== ''
            ? raw['idpMetadataUrl']
            : undefined;
    const forceAuthn = raw['forceAuthn'] === true;

    return {
        entityId: entityId.trim(),
        callbackUrl: callbackUrl.trim(),
        cert: cert.trim(),
        privateKey,
        privateKeyCert,
        idpMetadataUrl,
        forceAuthn,
    };
}

/**
 * parseSamlIdentityProvider: validate and build SamlIdentityProvider (bare casts forbidden)
 *
 * @throws SamlAuthError SAML_CONFIG_INVALID if the configuration is invalid
 */
export function parseSamlIdentityProvider(
    raw: Record<string, unknown>,
): SamlIdentityProvider {
    const entityId = raw['entityId'];
    if (typeof entityId !== 'string' || entityId.trim() === '') {
        throw new SamlAuthError(
            'SamlIdentityProvider.entityId is required.',
            'SAML_CONFIG_INVALID',
        );
    }

    const ssoLoginUrl = raw['ssoLoginUrl'];
    if (typeof ssoLoginUrl !== 'string' || ssoLoginUrl.trim() === '') {
        throw new SamlAuthError(
            'SamlIdentityProvider.ssoLoginUrl is required.',
            'SAML_CONFIG_INVALID',
        );
    }

    const rawCerts = raw['signingCerts'];
    if (!Array.isArray(rawCerts) || rawCerts.length === 0) {
        throw new SamlAuthError(
            'SamlIdentityProvider.signingCerts must be a non-empty array of PEM certificates. ' +
                'An empty signingCerts would bypass SAML signature verification.',
            'SAML_CONFIG_INVALID',
        );
    }
    const signingCerts: string[] = rawCerts.filter(
        (c): c is string => typeof c === 'string' && c.trim() !== '',
    );
    if (signingCerts.length === 0) {
        throw new SamlAuthError(
            'SamlIdentityProvider.signingCerts contains no valid (non-empty) PEM certificates.',
            'SAML_CONFIG_INVALID',
        );
    }

    const ssoLogoutUrl =
        typeof raw['ssoLogoutUrl'] === 'string' &&
        raw['ssoLogoutUrl'].trim() !== ''
            ? raw['ssoLogoutUrl']
            : undefined;

    const rawBinding = raw['binding'];
    const binding: 'POST' | 'Redirect' =
        rawBinding === 'Redirect' ? 'Redirect' : 'POST';

    return {
        entityId: entityId.trim(),
        ssoLoginUrl: ssoLoginUrl.trim(),
        ssoLogoutUrl,
        signingCerts: Object.freeze(signingCerts),
        binding,
    };
}

// ── Error code system ────────────────────────────────────────────────────────────────

/**
 * SAML error codes (fail-closed system)
 *
 * Conclusion: every SAML verification failure maps to a specific error code;
 * error codes correspond to HTTP status codes (mapped in the handler layer);
 * a stub default 200 is forbidden.
 */
export type SamlErrorCode =
    | 'SAML_CONFIG_INVALID' // invalid configuration (cert/entityId missing)
    | 'SAML_SIGNATURE_INVALID' // assertion signature verification failed (P0)
    | 'SAML_ASSERTION_EXPIRED' // NotOnOrAfter expired (P0)
    | 'SAML_ASSERTION_NOT_YET_VALID' // NotBefore not yet reached (P0)
    | 'SAML_AUDIENCE_MISMATCH' // Audience does not match the SP entityID (P0)
    | 'SAML_NAMEID_FORMAT_UNSUPPORTED' // NameID format unsupported
    | 'SAML_CLAIMS_INVALID' // assertion claims parsing failed
    | 'SAML_AUTHN_REQUEST_FAILED' // AuthnRequest generation failed
    | 'SAML_LOGOUT_REQUEST_FAILED' // LogoutRequest generation failed
    | 'SAML_CALLBACK_PARSE_FAILED' // callback XML parsing failed
    | 'SAML_IDP_ERROR_RESPONSE' // IDP returned a SAML error response
    | 'SAML_INTERNAL_ERROR'; // internal error (catch-all; fail-closed)

/**
 * SamlAuthError: base class for all SAML-related errors (fail-closed)
 *
 * Trigger scenarios:
 *   - signature verification failed -> SAML_SIGNATURE_INVALID (P0; fail-closed; must reject)
 *   - expiry verification failed -> SAML_ASSERTION_EXPIRED (P0; fail-closed; must reject)
 *   - audience verification failed -> SAML_AUDIENCE_MISMATCH (P0; fail-closed; must reject)
 *   - invalid configuration -> SAML_CONFIG_INVALID (fail-closed; empty cert forbidden)
 *   - NameID format unsupported -> SAML_NAMEID_FORMAT_UNSUPPORTED
 */
export class SamlAuthError extends Error {
    readonly code: SamlErrorCode;

    constructor(message: string, code: SamlErrorCode = 'SAML_INTERNAL_ERROR') {
        super(message);
        this.name = 'SamlAuthError';
        this.code = code;
        Object.setPrototypeOf(this, new.target.prototype);
    }
}

/**
 * parseSamlUserClaims: build SamlUserClaims from an unknown HTTP body (bare casts forbidden)
 *
 * Conclusion: use this function in place of a bare cast when the handler layer receives an unknown claims object from the HTTP body;
 * a missing field or invalid type -> fail-closed (SamlAuthError SAML_CLAIMS_INVALID).
 *
 * @throws SamlAuthError SAML_CLAIMS_INVALID if a required field is missing or has an invalid type
 */
export function parseSamlUserClaims(input: unknown): SamlUserClaims {
    if (!input || typeof input !== 'object') {
        throw new SamlAuthError(
            'SamlUserClaims: input must be a non-null object.',
            'SAML_CLAIMS_INVALID',
        );
    }
    const raw = input as Record<string, unknown>;

    const nameId = raw['nameId'];
    if (typeof nameId !== 'string' || nameId.trim() === '') {
        throw new SamlAuthError(
            'SamlUserClaims.nameId is required and must be a non-empty string.',
            'SAML_CLAIMS_INVALID',
        );
    }

    const nameIdFormat = parseSamlNameIdFormat(
        typeof raw['nameIdFormat'] === 'string' ? raw['nameIdFormat'] : undefined,
    );

    const idpEntityId = raw['idpEntityId'];
    if (typeof idpEntityId !== 'string' || idpEntityId.trim() === '') {
        throw new SamlAuthError(
            'SamlUserClaims.idpEntityId is required and must be a non-empty string.',
            'SAML_CLAIMS_INVALID',
        );
    }

    const verifiedAt = raw['verifiedAt'];
    if (typeof verifiedAt !== 'string' || verifiedAt.trim() === '') {
        throw new SamlAuthError(
            'SamlUserClaims.verifiedAt is required and must be a non-empty ISO 8601 string.',
            'SAML_CLAIMS_INVALID',
        );
    }

    const sessionIndex =
        typeof raw['sessionIndex'] === 'string' ? raw['sessionIndex'] : undefined;

    const rawAttributes = raw['attributes'];
    if (!rawAttributes || typeof rawAttributes !== 'object' || Array.isArray(rawAttributes)) {
        throw new SamlAuthError(
            'SamlUserClaims.attributes is required and must be a non-null object.',
            'SAML_CLAIMS_INVALID',
        );
    }
    const FORBIDDEN_ATTRIBUTE_NAMES = new Set(['__proto__', 'constructor', 'prototype']);
    const attributes = Object.create(null) as Record<string, string>;
    for (const [key, value] of Object.entries(rawAttributes as Record<string, unknown>)) {
        if (FORBIDDEN_ATTRIBUTE_NAMES.has(key)) {
            throw new SamlAuthError(
                `SamlUserClaims.attributes contains forbidden key "${key}".`,
                'SAML_CLAIMS_INVALID',
            );
        }
        if (typeof value === 'string') {
            attributes[key] = value;
        }
    }

    return {
        nameId: nameId.trim(),
        nameIdFormat,
        sessionIndex,
        idpEntityId: idpEntityId.trim(),
        verifiedAt: verifiedAt.trim(),
        attributes: Object.freeze(attributes),
    };
}

// ── Placeholder type skeletons for later sections (not implemented; extended by later OIDC / federation / SDK API sections) ────

/**
 * OidcConfig (OIDC section; pending implementation)
 * @todo OIDC
 */
export interface OidcConfig {
    readonly issuer: string;
    readonly clientId: string;
    readonly clientSecret: string;
    readonly redirectUri: string;
    readonly scope?: readonly string[];
}

/**
 * TenantFederationRule (federation section; pending implementation)
 * @todo federation
 */
export interface TenantFederationRule {
    readonly idpEntityId: string;
    readonly tenantId: string;
    readonly claimMapping?: Readonly<Record<string, string>>;
}
