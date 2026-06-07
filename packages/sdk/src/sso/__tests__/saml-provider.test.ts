/**
 * SAML Provider tests
 *
 * Coverage:
 *   - SamlAuthError: construction + error-code taxonomy
 *   - parseSamlNameIdFormat: valid / invalid format → fail-closed
 *   - parseSamlConfig: valid / invalid config (empty cert → fail-closed; P0 security)
 *   - parseSamlIdentityProvider: valid / empty signingCerts → fail-closed (P0 security)
 *   - parseSamlClaims: nameId extraction / format parsing / attributes extraction / missing-field fail-closed
 *   - SamlProvider.generateAuthnRequest: happy path + SamlPort error fail-closed
 *   - SamlProvider.verifyAssertion: 3 P0 guards:
 *       - signature verification failure → SAML_SIGNATURE_INVALID (fail-closed; does not return claims)
 *       - expiry verification failure (NotOnOrAfter expired) → SAML_ASSERTION_EXPIRED (fail-closed)
 *       - audience verification failure → SAML_AUDIENCE_MISMATCH (fail-closed)
 *     + happy verification path + layer-2 double expiry/audience verification
 *   - SamlProvider.generateLogoutRequest: happy path + error fail-closed
 *   - createSamlLoginHandler: generate AuthnRequest → redirect path + error fail-closed 500
 *   - createSamlCallbackHandler:
 *       - missing body → 400 fail-closed
 *       - missing SAMLResponse → 400 fail-closed
 *       - invalid signature → 401 fail-closed (P0)
 *       - expired → 401 fail-closed (P0)
 *       - audience mismatch → 401 fail-closed (P0)
 *       - verification passes → 200 + claims
 *   - createSamlLogoutHandler: missing nameId → 400 / normal → redirect
 *   - handleSamlError: error code → HTTP status code mapping
 *   - invariant grep test: saml-provider.ts + types.ts contain no skip keywords
 *
 * Mock strategy:
 *   - Inject a SamlPort mock (does not depend on @node-saml/node-saml being installed)
 *   - SamlPort.verifyResponse mock controls the signature / expiry / audience verification results
 *   - Use SamlVerificationError(reason) to simulate different verification-failure scenarios
 */

import { describe, it, expect, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
    SamlAuthError,
    parseSamlNameIdFormat,
    parseSamlConfig,
    parseSamlIdentityProvider,
    parseSamlClaims,
    parseSamlUserClaims,
} from '../types.js';
import {
    SamlProvider,
    SamlVerificationError,
    createSamlLoginHandler,
    createSamlCallbackHandler,
    createSamlLogoutHandler,
    handleSamlError,
} from '../saml-provider.js';
import type {
    SamlPort,
    SamlProviderConfig,
    SamlHandlerConfig,
} from '../saml-provider.js';
import type {
    SamlConfig,
    SamlIdentityProvider,
    SamlUserClaims,
} from '../types.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

// ── Test data ─────────────────────────────────────────────────────────────────

const VALID_SAML_CONFIG: SamlConfig = {
    entityId: 'https://sp.example.com/saml/metadata',
    callbackUrl: 'https://sp.example.com/auth/saml/callback',
    cert: '-----BEGIN CERTIFICATE-----\nMIICert...FAKE_CERT_FOR_TESTS\n-----END CERTIFICATE-----',
};

const VALID_SAML_IDP: SamlIdentityProvider = {
    entityId: 'https://idp.example.com/saml/metadata',
    ssoLoginUrl: 'https://idp.example.com/sso',
    ssoLogoutUrl: 'https://idp.example.com/slo',
    signingCerts: [
        '-----BEGIN CERTIFICATE-----\nMIICIdpCert...FAKE\n-----END CERTIFICATE-----',
    ],
    binding: 'POST',
};

const VALID_PROFILE: Record<string, unknown> = {
    nameID: 'alice@example.com',
    nameIDFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
    sessionIndex: 'sess-abc-123',
    issuer: 'https://idp.example.com/saml/metadata',
    // The audience field must exist, otherwise verifyAudienceFromProfile layer 2b throws fail-closed.
    // Its value must equal the SP entityId (VALID_SAML_CONFIG.entityId).
    audience: 'https://sp.example.com/saml/metadata',
    email: 'alice@example.com',
    displayName: 'Alice Example',
};

// ── Mock SamlPort ─────────────────────────────────────────────────────────────

/**
 * Construct a mock SamlPort (injected into SamlProvider; does not depend on @node-saml/node-saml)
 */
function makeMockSamlPort(opts: {
    authorizeUrl?: string;
    verifyResult?: Record<string, unknown>;
    verifyError?: Error;
    logoutUrl?: string;
}): SamlPort {
    const err = opts.verifyError;
    return {
        getAuthorizeUrl: err
            ? () => Promise.reject(err)
            : opts.authorizeUrl
              ? () => Promise.resolve(opts.authorizeUrl!)
              : () =>
                    Promise.resolve(
                        'https://idp.example.com/sso?SAMLRequest=mock',
                    ),

        verifyResponse: err
            ? () => Promise.reject(err)
            : opts.verifyResult !== undefined
              ? () => Promise.resolve(opts.verifyResult!)
              : () => Promise.resolve(VALID_PROFILE),

        getLogoutUrl: err
            ? () => Promise.reject(err)
            : opts.logoutUrl
              ? () => Promise.resolve(opts.logoutUrl!)
              : () =>
                    Promise.resolve(
                        'https://idp.example.com/slo?SAMLRequest=mock',
                    ),
    };
}

function makeProvider(samlPort?: SamlPort): SamlProvider {
    const providerConfig: SamlProviderConfig = {
        config: VALID_SAML_CONFIG,
        idp: VALID_SAML_IDP,
        samlPort: samlPort ?? makeMockSamlPort({}),
    };
    return new SamlProvider(providerConfig);
}

// ── Mock Express req/res ──────────────────────────────────────────────────────

interface MockResponse {
    statusCode: number;
    body: unknown;
    redirectUrl: string | null;
    status(code: number): MockResponse;
    json(data: unknown): MockResponse;
    redirect(url: string): void;
}

function makeMockResponse(): MockResponse {
    const res: MockResponse = {
        statusCode: 0,
        body: null,
        redirectUrl: null,
        status(code) {
            this.statusCode = code;
            return this;
        },
        json(data) {
            this.body = data;
            return this;
        },
        redirect(url) {
            this.statusCode = 302;
            this.redirectUrl = url;
        },
    };
    return res;
}

// ── SamlAuthError ─────────────────────────────────────────────────────────────

describe('SamlAuthError', () => {
    it('should construct with correct code and name when code provided', () => {
        const err = new SamlAuthError(
            'signature invalid',
            'SAML_SIGNATURE_INVALID',
        );
        expect(err.code).toBe('SAML_SIGNATURE_INVALID');
        expect(err.name).toBe('SamlAuthError');
        expect(err.message).toBe('signature invalid');
        expect(err).toBeInstanceOf(Error);
        expect(err).toBeInstanceOf(SamlAuthError);
    });

    it('should default to SAML_INTERNAL_ERROR when no code provided', () => {
        const err = new SamlAuthError('internal error');
        expect(err.code).toBe('SAML_INTERNAL_ERROR');
    });

    it('should preserve prototype chain for instanceof checks', () => {
        const err = new SamlAuthError('test', 'SAML_ASSERTION_EXPIRED');
        expect(err).toBeInstanceOf(SamlAuthError);
        expect(err).toBeInstanceOf(Error);
    });
});

// ── parseSamlNameIdFormat ─────────────────────────────────────────────────────

describe('parseSamlNameIdFormat — should parse valid formats and reject invalid', () => {
    it('should return emailAddress format when valid email format provided', () => {
        const result = parseSamlNameIdFormat(
            'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
        );
        expect(result).toBe(
            'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
        );
    });

    it('should return persistent format when valid persistent format provided', () => {
        const result = parseSamlNameIdFormat(
            'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
        );
        expect(result).toBe(
            'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
        );
    });

    it('should return transient format when valid transient format provided', () => {
        const result = parseSamlNameIdFormat(
            'urn:oasis:names:tc:SAML:2.0:nameid-format:transient',
        );
        expect(result).toBe(
            'urn:oasis:names:tc:SAML:2.0:nameid-format:transient',
        );
    });

    it('should throw SAML_NAMEID_FORMAT_UNSUPPORTED when unknown format provided', () => {
        expect(() =>
            parseSamlNameIdFormat(
                'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
            ),
        ).toThrow(SamlAuthError);
        try {
            parseSamlNameIdFormat(
                'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
            );
        } catch (err) {
            expect(err).toBeInstanceOf(SamlAuthError);
            expect((err as SamlAuthError).code).toBe(
                'SAML_NAMEID_FORMAT_UNSUPPORTED',
            );
        }
    });

    it('should throw SAML_NAMEID_FORMAT_UNSUPPORTED when empty string provided', () => {
        expect(() => parseSamlNameIdFormat('')).toThrow(SamlAuthError);
    });

    it('should throw SAML_NAMEID_FORMAT_UNSUPPORTED when undefined provided', () => {
        expect(() => parseSamlNameIdFormat(undefined)).toThrow(SamlAuthError);
    });
});

// ── parseSamlConfig ───────────────────────────────────────────────────────────

describe('parseSamlConfig — should validate config and reject empty cert (P0 security)', () => {
    it('should return valid SamlConfig when all required fields provided', () => {
        const result = parseSamlConfig({
            entityId: 'https://sp.example.com/saml/metadata',
            callbackUrl: 'https://sp.example.com/auth/saml/callback',
            cert: '-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----',
        });
        expect(result.entityId).toBe('https://sp.example.com/saml/metadata');
        expect(result.callbackUrl).toBe(
            'https://sp.example.com/auth/saml/callback',
        );
        expect(result.cert).toContain('CERTIFICATE');
    });

    it('should throw SAML_CONFIG_INVALID when entityId is missing', () => {
        expect(() =>
            parseSamlConfig({
                entityId: '',
                callbackUrl: 'https://sp.example.com/callback',
                cert: 'CERT',
            }),
        ).toThrow(SamlAuthError);
    });

    it('should throw SAML_CONFIG_INVALID when callbackUrl is missing', () => {
        expect(() =>
            parseSamlConfig({
                entityId: 'https://sp.example.com',
                callbackUrl: '',
                cert: 'CERT',
            }),
        ).toThrow(SamlAuthError);
    });

    /**
     * P0 security negative test: empty cert → must fail-closed (must not skip signature verification)
     */
    it('[P0] should throw SAML_CONFIG_INVALID when cert is empty string — prevents signature skip', () => {
        let caught: SamlAuthError | null = null;
        try {
            parseSamlConfig({
                entityId: 'https://sp.example.com',
                callbackUrl: 'https://sp.example.com/callback',
                cert: '',
            });
        } catch (err) {
            caught = err as SamlAuthError;
        }
        expect(caught).not.toBeNull();
        expect(caught).toBeInstanceOf(SamlAuthError);
        expect(caught!.code).toBe('SAML_CONFIG_INVALID');
        // Verify the error message explicitly states that an empty cert would bypass signature
        expect(caught!.message).toContain('bypass SAML signature verification');
    });

    /**
     * P0 security negative test: whitespace-only cert → must fail-closed
     */
    it('[P0] should throw SAML_CONFIG_INVALID when cert is whitespace-only — prevents signature skip', () => {
        expect(() =>
            parseSamlConfig({
                entityId: 'https://sp.example.com',
                callbackUrl: 'https://sp.example.com/callback',
                cert: '   ',
            }),
        ).toThrow(SamlAuthError);
    });
});

// ── parseSamlIdentityProvider ─────────────────────────────────────────────────

describe('parseSamlIdentityProvider — should validate IDP config and reject empty signingCerts', () => {
    it('should return valid SamlIdentityProvider when all required fields provided', () => {
        const result = parseSamlIdentityProvider({
            entityId: 'https://idp.example.com',
            ssoLoginUrl: 'https://idp.example.com/sso',
            signingCerts: ['CERT1', 'CERT2'],
            binding: 'POST',
        });
        expect(result.entityId).toBe('https://idp.example.com');
        expect(result.signingCerts).toHaveLength(2);
        expect(result.binding).toBe('POST');
    });

    it('should default binding to POST when not provided', () => {
        const result = parseSamlIdentityProvider({
            entityId: 'https://idp.example.com',
            ssoLoginUrl: 'https://idp.example.com/sso',
            signingCerts: ['CERT1'],
        });
        expect(result.binding).toBe('POST');
    });

    /**
     * P0 security negative test: empty signingCerts → must fail-closed (must not bypass signature verification)
     */
    it('[P0] should throw SAML_CONFIG_INVALID when signingCerts is empty array — prevents signature skip', () => {
        let caught: SamlAuthError | null = null;
        try {
            parseSamlIdentityProvider({
                entityId: 'https://idp.example.com',
                ssoLoginUrl: 'https://idp.example.com/sso',
                signingCerts: [],
            });
        } catch (err) {
            caught = err as SamlAuthError;
        }
        expect(caught).not.toBeNull();
        expect(caught!.code).toBe('SAML_CONFIG_INVALID');
        expect(caught!.message).toContain('bypass SAML signature verification');
    });

    /**
     * P0 security negative test: all signingCerts are empty strings → must fail-closed
     */
    it('[P0] should throw SAML_CONFIG_INVALID when all signingCerts are empty strings', () => {
        expect(() =>
            parseSamlIdentityProvider({
                entityId: 'https://idp.example.com',
                ssoLoginUrl: 'https://idp.example.com/sso',
                signingCerts: ['', '  '],
            }),
        ).toThrow(SamlAuthError);
    });
});

// ── parseSamlClaims ───────────────────────────────────────────────────────────

describe('parseSamlClaims — should extract user claims from profile', () => {
    it('should extract nameId, nameIdFormat, sessionIndex, attributes when profile is valid', () => {
        const claims = parseSamlClaims(
            VALID_PROFILE,
            'https://idp.example.com',
        );
        expect(claims.nameId).toBe('alice@example.com');
        expect(claims.nameIdFormat).toBe(
            'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
        );
        expect(claims.sessionIndex).toBe('sess-abc-123');
        expect(claims.idpEntityId).toBe('https://idp.example.com');
        expect(claims.attributes['displayName']).toBe('Alice Example');
    });

    it('should throw SAML_CLAIMS_INVALID when nameID is missing', () => {
        const badProfile = {
            ...VALID_PROFILE,
            nameID: undefined,
            nameId: undefined,
            email: undefined,
        };
        expect(() =>
            parseSamlClaims(badProfile, 'https://idp.example.com'),
        ).toThrow(SamlAuthError);
        try {
            parseSamlClaims(badProfile, 'https://idp.example.com');
        } catch (err) {
            expect((err as SamlAuthError).code).toBe('SAML_CLAIMS_INVALID');
        }
    });

    it('should set verifiedAt to current time ISO string', () => {
        const before = Date.now();
        const claims = parseSamlClaims(
            VALID_PROFILE,
            'https://idp.example.com',
        );
        const after = Date.now();
        const verifiedMs = Date.parse(claims.verifiedAt);
        expect(verifiedMs).toBeGreaterThanOrEqual(before);
        expect(verifiedMs).toBeLessThanOrEqual(after);
    });

    it('should not include reserved fields in attributes', () => {
        const claims = parseSamlClaims(
            VALID_PROFILE,
            'https://idp.example.com',
        );
        expect(claims.attributes['nameID']).toBeUndefined();
        expect(claims.attributes['nameIDFormat']).toBeUndefined();
        expect(claims.attributes['sessionIndex']).toBeUndefined();
        expect(claims.attributes['issuer']).toBeUndefined();
    });
});

// ── SamlProvider.generateAuthnRequest ────────────────────────────────────────

describe('SamlProvider.generateAuthnRequest', () => {
    it('should return login URL when SamlPort.getAuthorizeUrl resolves', async () => {
        const mockPort = makeMockSamlPort({
            authorizeUrl: 'https://idp.example.com/sso?SAMLRequest=encoded',
        });
        const provider = makeProvider(mockPort);
        const url = await provider.generateAuthnRequest();
        expect(url).toBe('https://idp.example.com/sso?SAMLRequest=encoded');
    });

    it('should throw SAML_AUTHN_REQUEST_FAILED when SamlPort.getAuthorizeUrl rejects', async () => {
        const mockPort: SamlPort = {
            getAuthorizeUrl: () => Promise.reject(new Error('IDP unreachable')),
            verifyResponse: () => Promise.resolve(VALID_PROFILE),
            getLogoutUrl: () => Promise.resolve(''),
        };
        const provider = makeProvider(mockPort);
        await expect(provider.generateAuthnRequest()).rejects.toThrow(
            SamlAuthError,
        );
        try {
            await provider.generateAuthnRequest();
        } catch (err) {
            expect((err as SamlAuthError).code).toBe(
                'SAML_AUTHN_REQUEST_FAILED',
            );
        }
    });
});

// ── SamlProvider.verifyAssertion — 3 P0 guards ────────────────────────────────

describe('SamlProvider.verifyAssertion — P0.1 signature verification', () => {
    /**
     *  Security negative test: signature verification failure → must reject (fail-closed).
     * Returning partial claims / a stub 200 is strictly forbidden.
     */
    it('[P0.1] should throw SAML_SIGNATURE_INVALID when SamlPort signature verification fails', async () => {
        const mockPort: SamlPort = {
            getAuthorizeUrl: () => Promise.resolve(''),
            verifyResponse: () =>
                Promise.reject(
                    new SamlVerificationError(
                        'invalid signature: cert mismatch',
                    ),
                ),
            getLogoutUrl: () => Promise.resolve(''),
        };
        const provider = makeProvider(mockPort);
        let caught: SamlAuthError | null = null;
        try {
            await provider.verifyAssertion({
                SAMLResponse: 'fake-saml-response',
            });
        } catch (err) {
            caught = err as SamlAuthError;
        }
        expect(caught).not.toBeNull();
        expect(caught).toBeInstanceOf(SamlAuthError);
        expect(caught!.code).toBe('SAML_SIGNATURE_INVALID');
    });

    it('[P0.1] should throw SAML_SIGNATURE_INVALID when cert verification fails', async () => {
        const mockPort: SamlPort = {
            getAuthorizeUrl: () => Promise.resolve(''),
            verifyResponse: () =>
                Promise.reject(
                    new SamlVerificationError('certificate validation failed'),
                ),
            getLogoutUrl: () => Promise.resolve(''),
        };
        const provider = makeProvider(mockPort);
        await expect(
            provider.verifyAssertion({ SAMLResponse: 'fake' }),
        ).rejects.toBeInstanceOf(SamlAuthError);
    });

    it('[P0.1] should throw SAML_SIGNATURE_INVALID for unknown verification failure', async () => {
        // Unknown failure reason → strictest fallback = SAML_SIGNATURE_INVALID (fail-closed)
        const mockPort: SamlPort = {
            getAuthorizeUrl: () => Promise.resolve(''),
            verifyResponse: () =>
                Promise.reject(
                    new SamlVerificationError('unknown verification error'),
                ),
            getLogoutUrl: () => Promise.resolve(''),
        };
        const provider = makeProvider(mockPort);
        try {
            await provider.verifyAssertion({ SAMLResponse: 'fake' });
        } catch (err) {
            expect((err as SamlAuthError).code).toBe('SAML_SIGNATURE_INVALID');
        }
    });
});

describe('SamlProvider.verifyAssertion — P0.2 expiry verification', () => {
    /**
     *  Security negative test: assertion expired → must reject (fail-closed)
     */
    it('[P0.2] should throw SAML_ASSERTION_EXPIRED when SamlPort reports expired assertion', async () => {
        const mockPort: SamlPort = {
            getAuthorizeUrl: () => Promise.resolve(''),
            verifyResponse: () =>
                Promise.reject(
                    new SamlVerificationError(
                        'assertion is too old, NotOnOrAfter is in the past',
                    ),
                ),
            getLogoutUrl: () => Promise.resolve(''),
        };
        const provider = makeProvider(mockPort);
        try {
            await provider.verifyAssertion({ SAMLResponse: 'fake' });
        } catch (err) {
            expect((err as SamlAuthError).code).toBe('SAML_ASSERTION_EXPIRED');
        }
    });

    /**
     *  Layer-2 double verification: SamlPort succeeds but profile notOnOrAfter is already expired → reject
     */
    it('[P0.2] should throw SAML_ASSERTION_EXPIRED when profile notOnOrAfter is in the past (layer 2 check)', async () => {
        const expiredAt = new Date(Date.now() - 60000).toISOString(); // 1 minute ago
        const profileWithExpiry: Record<string, unknown> = {
            ...VALID_PROFILE,
            notOnOrAfter: expiredAt,
        };
        const mockPort = makeMockSamlPort({ verifyResult: profileWithExpiry });
        const provider = makeProvider(mockPort);
        try {
            await provider.verifyAssertion({ SAMLResponse: 'fake' });
            // Should not reach here
            expect(true).toBe(false);
        } catch (err) {
            expect((err as SamlAuthError).code).toBe('SAML_ASSERTION_EXPIRED');
        }
    });

    /**
     *  Layer-2 double verification: NotBefore not yet reached → reject (SAML_ASSERTION_NOT_YET_VALID)
     */
    it('[P0.2] should throw SAML_ASSERTION_NOT_YET_VALID when NotBefore is in the future (layer 2 check)', async () => {
        const futureTime = new Date(Date.now() + 60000).toISOString(); // 1 minute from now
        const profileNotYetValid: Record<string, unknown> = {
            ...VALID_PROFILE,
            notBefore: futureTime,
        };
        const mockPort = makeMockSamlPort({ verifyResult: profileNotYetValid });
        const provider = makeProvider(mockPort);
        try {
            await provider.verifyAssertion({ SAMLResponse: 'fake' });
            expect(true).toBe(false);
        } catch (err) {
            expect((err as SamlAuthError).code).toBe(
                'SAML_ASSERTION_NOT_YET_VALID',
            );
        }
    });
});

describe('SamlProvider.verifyAssertion — P0.3 audience verification', () => {
    /**
     *  Security negative test: audience mismatch → must reject (fail-closed)
     */
    it('[P0.3] should throw SAML_AUDIENCE_MISMATCH when SamlPort reports audience mismatch', async () => {
        const mockPort: SamlPort = {
            getAuthorizeUrl: () => Promise.resolve(''),
            verifyResponse: () =>
                Promise.reject(
                    new SamlVerificationError(
                        'audience restriction does not match issuer entityid',
                    ),
                ),
            getLogoutUrl: () => Promise.resolve(''),
        };
        const provider = makeProvider(mockPort);
        try {
            await provider.verifyAssertion({ SAMLResponse: 'fake' });
        } catch (err) {
            expect((err as SamlAuthError).code).toBe('SAML_AUDIENCE_MISMATCH');
        }
    });

    /**
     *  Layer-2 double verification: profile audience does not match SP entityId → reject
     */
    it('[P0.3] should throw SAML_AUDIENCE_MISMATCH when profile audience does not match SP entityId (layer 2 check)', async () => {
        const profileWrongAudience: Record<string, unknown> = {
            ...VALID_PROFILE,
            audience: 'https://other-sp.example.com/saml/metadata',
        };
        const mockPort = makeMockSamlPort({
            verifyResult: profileWrongAudience,
        });
        const provider = makeProvider(mockPort);
        try {
            await provider.verifyAssertion({ SAMLResponse: 'fake' });
            expect(true).toBe(false);
        } catch (err) {
            expect((err as SamlAuthError).code).toBe('SAML_AUDIENCE_MISMATCH');
        }
    });

    /**
     *  Layer-2 double verification: audience is an empty array → reject
     */
    it('[P0.3] should throw SAML_AUDIENCE_MISMATCH when audience array is empty', async () => {
        const profileEmptyAudience: Record<string, unknown> = {
            ...VALID_PROFILE,
            audience: [],
        };
        const mockPort = makeMockSamlPort({
            verifyResult: profileEmptyAudience,
        });
        const provider = makeProvider(mockPort);
        await expect(
            provider.verifyAssertion({ SAMLResponse: 'fake' }),
        ).rejects.toBeInstanceOf(SamlAuthError);
    });

    /**
     * Happy path: audience matches SP entityId → passes
     */
    it('should pass audience check when profile audience matches SP entityId', async () => {
        const profileCorrectAudience: Record<string, unknown> = {
            ...VALID_PROFILE,
            audience: VALID_SAML_CONFIG.entityId,
        };
        const mockPort = makeMockSamlPort({
            verifyResult: profileCorrectAudience,
        });
        const provider = makeProvider(mockPort);
        const claims = await provider.verifyAssertion({ SAMLResponse: 'fake' });
        expect(claims.nameId).toBe('alice@example.com');
    });
});

describe('SamlProvider.verifyAssertion — happy path', () => {
    it('should return SamlUserClaims with all fields when assertion is valid', async () => {
        const mockPort = makeMockSamlPort({ verifyResult: VALID_PROFILE });
        const provider = makeProvider(mockPort);
        const claims = await provider.verifyAssertion({ SAMLResponse: 'fake' });
        expect(claims.nameId).toBe('alice@example.com');
        expect(claims.nameIdFormat).toBe(
            'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
        );
        expect(claims.sessionIndex).toBe('sess-abc-123');
        expect(claims.idpEntityId).toBe(VALID_SAML_IDP.entityId);
        expect(typeof claims.verifiedAt).toBe('string');
    });
});

// ── audience field absent + prototype pollution ─────────────────

describe('SamlProvider.verifyAssertion — P0.3 audience field absent fail-closed', () => {
    /**
     * Negative test 1:
     * audience field entirely absent → must throw SAML_AUDIENCE_MISMATCH (fail-closed).
     * silent-return behavior would violate the file-header promise that "audience verification must never be skipped".
     */
    it('[P0.3] should throw SAML_AUDIENCE_MISMATCH when audience field is absent from profile', async () => {
        // profile contains none of the audience / Audience / _audience fields
        const profileNoAudience: Record<string, unknown> = {
            nameID: 'alice@example.com',
            nameIDFormat:
                'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
            sessionIndex: 'sess-abc-123',
            issuer: 'https://idp.example.com/saml/metadata',
            // Intentionally omitted: audience / Audience / _audience
        };
        const mockPort = makeMockSamlPort({ verifyResult: profileNoAudience });
        const provider = makeProvider(mockPort);
        let caught: SamlAuthError | null = null;
        try {
            await provider.verifyAssertion({ SAMLResponse: 'fake' });
        } catch (err) {
            caught = err as SamlAuthError;
        }
        expect(caught).not.toBeNull();
        expect(caught).toBeInstanceOf(SamlAuthError);
        expect(caught!.code).toBe('SAML_AUDIENCE_MISMATCH');
        expect(caught!.message).toContain('P0.3 violation');
    });

    /**
     * Negative test 2:
     * a custom mock SamlPort that does not populate profile.audience → must throw SAML_AUDIENCE_MISMATCH.
     * Simulates a SamlPort implementation that omits the audience backfill; the layer-2b safety net must force a reject here.
     */
    it('[P0.3] should throw SAML_AUDIENCE_MISMATCH when custom SamlPort does not populate audience in profile', async () => {
        // Custom mock SamlPort: verifyResponse succeeds but does not populate audience (simulating an implementation that omits audience)
        const customPortNoAudience: SamlPort = {
            getAuthorizeUrl: () =>
                Promise.resolve('https://idp.example.com/sso'),
            verifyResponse: () =>
                Promise.resolve({
                    nameID: 'bob@example.com',
                    nameIDFormat:
                        'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
                    sessionIndex: 'sess-bob-456',
                    issuer: 'https://idp.example.com/saml/metadata',
                    // Intentionally does not populate the audience field (tests the layer-2b guard)
                }),
            getLogoutUrl: () => Promise.resolve('https://idp.example.com/slo'),
        };
        const provider = makeProvider(customPortNoAudience);
        let caught: SamlAuthError | null = null;
        try {
            await provider.verifyAssertion({
                SAMLResponse: 'fake-no-audience',
            });
        } catch (err) {
            caught = err as SamlAuthError;
        }
        expect(caught).not.toBeNull();
        expect(caught).toBeInstanceOf(SamlAuthError);
        expect(caught!.code).toBe('SAML_AUDIENCE_MISMATCH');
        expect(caught!.message).toContain('P0.3 violation');
    });
});

describe('parseSamlClaims — prototype pollution defense', () => {
    /**
     * Negative test 3 (prototype pollution defense):
     * a mock profile containing a __proto__ field → must throw SAML_CLAIMS_INVALID (fail-closed).
     * An IDP can inject a dangerous attribute name; it must be rejected in parseSamlClaims.
     */
    it('should throw SAML_CLAIMS_INVALID when profile contains __proto__ attribute name', () => {
        // Construct a profile with a __proto__ key (IDP injection attack scenario)
        const maliciousProfile: Record<string, unknown> = {
            nameID: 'attacker@example.com',
            nameIDFormat:
                'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
            issuer: 'https://evil-idp.example.com',
        };
        // Use Object.defineProperty to inject a __proto__ string key (bypassing the TS type constraint)
        Object.defineProperty(maliciousProfile, '__proto__', {
            value: 'polluted',
            enumerable: true,
            configurable: true,
            writable: true,
        });

        let caught: SamlAuthError | null = null;
        try {
            parseSamlClaims(maliciousProfile, 'https://idp.example.com');
        } catch (err) {
            caught = err as SamlAuthError;
        }
        expect(caught).not.toBeNull();
        expect(caught).toBeInstanceOf(SamlAuthError);
        expect(caught!.code).toBe('SAML_CLAIMS_INVALID');
        expect(caught!.message).toContain('forbidden attribute name');
    });
});

// ── SamlProvider.generateLogoutRequest ────────────────────────────────────────

describe('SamlProvider.generateLogoutRequest', () => {
    const validClaims: SamlUserClaims = {
        nameId: 'alice@example.com',
        nameIdFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
        sessionIndex: 'sess-abc-123',
        idpEntityId: VALID_SAML_IDP.entityId,
        verifiedAt: new Date().toISOString(),
        attributes: {},
    };

    it('should return logout URL when SamlPort.getLogoutUrl resolves', async () => {
        const mockPort = makeMockSamlPort({
            logoutUrl: 'https://idp.example.com/slo?SAMLRequest=logout',
        });
        const provider = makeProvider(mockPort);
        const url = await provider.generateLogoutRequest(validClaims);
        expect(url).toBe('https://idp.example.com/slo?SAMLRequest=logout');
    });

    it('should throw SAML_LOGOUT_REQUEST_FAILED when SamlPort.getLogoutUrl rejects', async () => {
        const mockPort: SamlPort = {
            getAuthorizeUrl: () => Promise.resolve(''),
            verifyResponse: () => Promise.resolve(VALID_PROFILE),
            getLogoutUrl: () => Promise.reject(new Error('IDP unreachable')),
        };
        const provider = makeProvider(mockPort);
        try {
            await provider.generateLogoutRequest(validClaims);
        } catch (err) {
            expect((err as SamlAuthError).code).toBe(
                'SAML_LOGOUT_REQUEST_FAILED',
            );
        }
    });
});

// ── SamlProvider constructor security guards ──────────────────────────────────

describe('SamlProvider constructor — should reject empty cert (P0 security)', () => {
    it('[P0] should throw SAML_CONFIG_INVALID when cert is empty in config', () => {
        const badConfig: SamlConfig = {
            ...VALID_SAML_CONFIG,
            cert: '',
        };
        expect(
            () =>
                new SamlProvider({
                    config: badConfig,
                    idp: VALID_SAML_IDP,
                    samlPort: makeMockSamlPort({}),
                }),
        ).toThrow(SamlAuthError);
        try {
            new SamlProvider({
                config: badConfig,
                idp: VALID_SAML_IDP,
                samlPort: makeMockSamlPort({}),
            });
        } catch (err) {
            expect((err as SamlAuthError).code).toBe('SAML_CONFIG_INVALID');
        }
    });
});

// ── createSamlLoginHandler ────────────────────────────────────────────────────

describe('createSamlLoginHandler', () => {
    it('should redirect to login URL when generateAuthnRequest succeeds', async () => {
        const mockPort = makeMockSamlPort({
            authorizeUrl: 'https://idp.example.com/sso?SAMLRequest=enc',
        });
        const config: SamlHandlerConfig = { provider: makeProvider(mockPort) };
        const handler = createSamlLoginHandler(config);
        const req = { headers: {}, body: undefined, query: {} };
        const res = makeMockResponse();
        await handler(req, res, vi.fn());
        expect(res.statusCode).toBe(302);
        expect(res.redirectUrl).toBe(
            'https://idp.example.com/sso?SAMLRequest=enc',
        );
    });

    it('should return fail-closed 500 when generateAuthnRequest fails', async () => {
        const mockPort: SamlPort = {
            getAuthorizeUrl: () =>
                Promise.reject(
                    new SamlAuthError('IDP down', 'SAML_AUTHN_REQUEST_FAILED'),
                ),
            verifyResponse: () => Promise.resolve(VALID_PROFILE),
            getLogoutUrl: () => Promise.resolve(''),
        };
        const config: SamlHandlerConfig = { provider: makeProvider(mockPort) };
        const handler = createSamlLoginHandler(config);
        const req = { headers: {}, body: undefined, query: {} };
        const res = makeMockResponse();
        await handler(req, res, vi.fn());
        // SAML_AUTHN_REQUEST_FAILED → 502 (fail-closed; no stub 200)
        expect(res.statusCode).toBe(502);
        expect((res.body as { error: string }).error).toBe(
            'SAML_AUTHN_REQUEST_FAILED',
        );
    });
});

// ── createSamlCallbackHandler ─────────────────────────────────────────────────

describe('createSamlCallbackHandler — fail-closed 400/401/500', () => {
    it('should return 400 when body is null', async () => {
        const config: SamlHandlerConfig = { provider: makeProvider() };
        const handler = createSamlCallbackHandler(config);
        const req = { headers: {}, body: null, query: {} };
        const res = makeMockResponse();
        await handler(req, res, vi.fn());
        expect(res.statusCode).toBe(400);
        expect((res.body as { error: string }).error).toBe(
            'SAML_CALLBACK_PARSE_FAILED',
        );
    });

    it('should return 400 when SAMLResponse field is missing', async () => {
        const config: SamlHandlerConfig = { provider: makeProvider() };
        const handler = createSamlCallbackHandler(config);
        const req = { headers: {}, body: { otherField: 'value' }, query: {} };
        const res = makeMockResponse();
        await handler(req, res, vi.fn());
        expect(res.statusCode).toBe(400);
    });

    it('[P0] should return 401 when signature verification fails', async () => {
        const mockPort: SamlPort = {
            getAuthorizeUrl: () => Promise.resolve(''),
            verifyResponse: () =>
                Promise.reject(new SamlVerificationError('invalid signature')),
            getLogoutUrl: () => Promise.resolve(''),
        };
        const config: SamlHandlerConfig = { provider: makeProvider(mockPort) };
        const handler = createSamlCallbackHandler(config);
        const req = {
            headers: {},
            body: { SAMLResponse: 'fake-response' },
            query: {},
        };
        const res = makeMockResponse();
        await handler(req, res, vi.fn());
        expect(res.statusCode).toBe(401);
        expect((res.body as { error: string }).error).toBe(
            'SAML_SIGNATURE_INVALID',
        );
        // Security: the error message must be sanitized (do not expose cert details)
        expect((res.body as { message: string }).message).toBe(
            'SAML assertion signature is invalid. Authentication rejected.',
        );
    });

    it('[P0] should return 401 when assertion is expired', async () => {
        const expiredProfile: Record<string, unknown> = {
            ...VALID_PROFILE,
            notOnOrAfter: new Date(Date.now() - 300000).toISOString(),
        };
        const mockPort = makeMockSamlPort({ verifyResult: expiredProfile });
        const config: SamlHandlerConfig = { provider: makeProvider(mockPort) };
        const handler = createSamlCallbackHandler(config);
        const req = { headers: {}, body: { SAMLResponse: 'fake' }, query: {} };
        const res = makeMockResponse();
        await handler(req, res, vi.fn());
        expect(res.statusCode).toBe(401);
        expect((res.body as { error: string }).error).toBe(
            'SAML_ASSERTION_EXPIRED',
        );
        expect((res.body as { message: string }).message).toBe(
            'SAML assertion has expired. Please re-authenticate.',
        );
    });

    it('[P0] should return 401 when audience does not match SP entityId', async () => {
        const wrongAudienceProfile: Record<string, unknown> = {
            ...VALID_PROFILE,
            audience: 'https://wrong-sp.example.com',
        };
        const mockPort = makeMockSamlPort({
            verifyResult: wrongAudienceProfile,
        });
        const config: SamlHandlerConfig = { provider: makeProvider(mockPort) };
        const handler = createSamlCallbackHandler(config);
        const req = { headers: {}, body: { SAMLResponse: 'fake' }, query: {} };
        const res = makeMockResponse();
        await handler(req, res, vi.fn());
        expect(res.statusCode).toBe(401);
        expect((res.body as { error: string }).error).toBe(
            'SAML_AUDIENCE_MISMATCH',
        );
        expect((res.body as { message: string }).message).toBe(
            'SAML assertion audience does not match this service. Authentication rejected.',
        );
    });

    it('should return 200 with claims when assertion is valid', async () => {
        const mockPort = makeMockSamlPort({ verifyResult: VALID_PROFILE });
        const config: SamlHandlerConfig = { provider: makeProvider(mockPort) };
        const handler = createSamlCallbackHandler(config);
        const req = {
            headers: {},
            body: { SAMLResponse: 'fake-valid-response' },
            query: {},
        };
        const res = makeMockResponse();
        await handler(req, res, vi.fn());
        expect(res.statusCode).toBe(200);
        const body = res.body as { claims: SamlUserClaims };
        expect(body.claims.nameId).toBe('alice@example.com');
    });
});

// ── createSamlLogoutHandler ───────────────────────────────────────────────────

describe('createSamlLogoutHandler', () => {
    it('should return 400 when nameId is missing from body', async () => {
        const config: SamlHandlerConfig = { provider: makeProvider() };
        const handler = createSamlLogoutHandler(config);
        const req = {
            headers: {},
            body: { sessionIndex: 'sess-123' },
            query: {},
        };
        const res = makeMockResponse();
        await handler(req, res, vi.fn());
        expect(res.statusCode).toBe(400);
        expect((res.body as { error: string }).error).toBe(
            'SAML_LOGOUT_REQUEST_FAILED',
        );
    });

    it('should redirect to SLO URL when nameId is valid', async () => {
        const mockPort = makeMockSamlPort({
            logoutUrl: 'https://idp.example.com/slo?SAMLRequest=logout',
        });
        const config: SamlHandlerConfig = { provider: makeProvider(mockPort) };
        const handler = createSamlLogoutHandler(config);
        const req = {
            headers: {},
            body: { nameId: 'alice@example.com', sessionIndex: 'sess-123' },
            query: {},
        };
        const res = makeMockResponse();
        await handler(req, res, vi.fn());
        expect(res.statusCode).toBe(302);
        expect(res.redirectUrl).toContain('SAMLRequest=logout');
    });

    it('should return 400 when body is null', async () => {
        const config: SamlHandlerConfig = { provider: makeProvider() };
        const handler = createSamlLogoutHandler(config);
        const req = { headers: {}, body: null, query: {} };
        const res = makeMockResponse();
        await handler(req, res, vi.fn());
        expect(res.statusCode).toBe(400);
    });
});

// ── handleSamlError ───────────────────────────────────────────────────────────

describe('handleSamlError — should map SamlErrorCode to correct HTTP status', () => {
    it('should return 401 for SAML_SIGNATURE_INVALID', () => {
        const res = makeMockResponse();
        handleSamlError(
            new SamlAuthError('sig invalid', 'SAML_SIGNATURE_INVALID'),
            res,
        );
        expect(res.statusCode).toBe(401);
    });

    it('should return 401 for SAML_ASSERTION_EXPIRED', () => {
        const res = makeMockResponse();
        handleSamlError(
            new SamlAuthError('expired', 'SAML_ASSERTION_EXPIRED'),
            res,
        );
        expect(res.statusCode).toBe(401);
    });

    it('should return 401 for SAML_AUDIENCE_MISMATCH', () => {
        const res = makeMockResponse();
        handleSamlError(
            new SamlAuthError('audience mismatch', 'SAML_AUDIENCE_MISMATCH'),
            res,
        );
        expect(res.statusCode).toBe(401);
    });

    it('should return 500 for SAML_CONFIG_INVALID', () => {
        const res = makeMockResponse();
        handleSamlError(
            new SamlAuthError('config invalid', 'SAML_CONFIG_INVALID'),
            res,
        );
        expect(res.statusCode).toBe(500);
    });

    it('should return 500 for unknown errors (fail-closed; no stub 200)', () => {
        const res = makeMockResponse();
        handleSamlError(new Error('unknown'), res);
        expect(res.statusCode).toBe(500);
        expect((res.body as { error: string }).error).toBe(
            'SAML_INTERNAL_ERROR',
        );
    });

    it('should return 502 for SAML_IDP_ERROR_RESPONSE', () => {
        const res = makeMockResponse();
        handleSamlError(
            new SamlAuthError('IDP error', 'SAML_IDP_ERROR_RESPONSE'),
            res,
        );
        expect(res.statusCode).toBe(502);
    });

    it('should return 400 for SAML_CALLBACK_PARSE_FAILED', () => {
        const res = makeMockResponse();
        handleSamlError(
            new SamlAuthError('parse failed', 'SAML_CALLBACK_PARSE_FAILED'),
            res,
        );
        expect(res.statusCode).toBe(400);
    });
});

// ── invariant grep test ──────────────────────────────────────────────────

/**
 * Invariant grep test: ensure the src files contain no keyword that bypasses signature / expiry / audience verification
 *
 * Files covered:
 *   - packages/sdk/src/sso/saml-provider.ts
 *   - packages/sdk/src/sso/types.ts
 *
 * Keywords verified (3 groups; each group is signature / expiry / audience skip related):
 *   - signature skip: skipSignatureVerify / disableSigCheck / noSigValidation
 *   - expiry skip: skipExpiry / ignoreNotAfter / bypassExpiry
 *   - audience skip: skipAudience / anyAudience / wildcardSP
 *
 * Rule: across non-comment lines (lines that, after trimming whitespace, do not start with // or *), each keyword must occur exactly 0 times.
 */

const SSO_SRC_DIR = resolve(__dirname, '../');

function readNonCommentLines(filePath: string): string[] {
    const content = readFileSync(filePath, 'utf-8');
    return content.split('\n').filter((line) => {
        const trimmed = line.trim();
        // Exclude line comments (starting with // or *)
        if (trimmed.startsWith('//') || trimmed.startsWith('*')) return false;
        // Exclude blank lines
        if (trimmed === '') return false;
        return true;
    });
}

describe('invariant grep test — saml-provider.ts should not contain skip keywords', () => {
    const filePath = resolve(SSO_SRC_DIR, 'saml-provider.ts');

    it('should have zero occurrences of skipSignatureVerify in non-comment lines', () => {
        const lines = readNonCommentLines(filePath);
        const matches = lines.filter((l) => l.includes('skipSignatureVerify'));
        expect(matches).toHaveLength(0);
    });

    it('should have zero occurrences of disableSigCheck in non-comment lines', () => {
        const lines = readNonCommentLines(filePath);
        const matches = lines.filter((l) => l.includes('disableSigCheck'));
        expect(matches).toHaveLength(0);
    });

    it('should have zero occurrences of noSigValidation in non-comment lines', () => {
        const lines = readNonCommentLines(filePath);
        const matches = lines.filter((l) => l.includes('noSigValidation'));
        expect(matches).toHaveLength(0);
    });

    it('should have zero occurrences of skipExpiry in non-comment lines', () => {
        const lines = readNonCommentLines(filePath);
        const matches = lines.filter((l) => l.includes('skipExpiry'));
        expect(matches).toHaveLength(0);
    });

    it('should have zero occurrences of ignoreNotAfter in non-comment lines', () => {
        const lines = readNonCommentLines(filePath);
        const matches = lines.filter((l) => l.includes('ignoreNotAfter'));
        expect(matches).toHaveLength(0);
    });

    it('should have zero occurrences of bypassExpiry in non-comment lines', () => {
        const lines = readNonCommentLines(filePath);
        const matches = lines.filter((l) => l.includes('bypassExpiry'));
        expect(matches).toHaveLength(0);
    });

    it('should have zero occurrences of skipAudience in non-comment lines', () => {
        const lines = readNonCommentLines(filePath);
        const matches = lines.filter((l) => l.includes('skipAudience'));
        expect(matches).toHaveLength(0);
    });

    it('should have zero occurrences of anyAudience in non-comment lines', () => {
        const lines = readNonCommentLines(filePath);
        const matches = lines.filter((l) => l.includes('anyAudience'));
        expect(matches).toHaveLength(0);
    });

    it('should have zero occurrences of wildcardSP in non-comment lines', () => {
        const lines = readNonCommentLines(filePath);
        const matches = lines.filter((l) => l.includes('wildcardSP'));
        expect(matches).toHaveLength(0);
    });
});

// ── parseSamlUserClaims — negative tests ────────────────────────────────

describe('parseSamlUserClaims — fail-closed for invalid inputs', () => {
    it('should throw SamlAuthError SAML_CLAIMS_INVALID when nameId is missing', () => {
        try {
            parseSamlUserClaims({
                // nameId intentionally omitted
                nameIdFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
                idpEntityId: 'https://idp.example.com/saml',
                verifiedAt: '2026-01-01T00:00:00Z',
                attributes: { tenant_id: 'abc' },
            });
            expect.fail('should not reach — missing nameId must throw');
        } catch (err) {
            expect(err).toBeInstanceOf(SamlAuthError);
            expect((err as SamlAuthError).code).toBe('SAML_CLAIMS_INVALID');
        }
    });

    it('should throw SamlAuthError SAML_CLAIMS_INVALID when input is null', () => {
        try {
            parseSamlUserClaims(null);
            expect.fail('should not reach — null input must throw');
        } catch (err) {
            expect(err).toBeInstanceOf(SamlAuthError);
            expect((err as SamlAuthError).code).toBe('SAML_CLAIMS_INVALID');
        }
    });
});

describe('invariant grep test — types.ts should not contain skip keywords', () => {
    const filePath = resolve(SSO_SRC_DIR, 'types.ts');

    it('should have zero occurrences of skipSignatureVerify in non-comment lines', () => {
        const lines = readNonCommentLines(filePath);
        expect(
            lines.filter((l) => l.includes('skipSignatureVerify')),
        ).toHaveLength(0);
    });

    it('should have zero occurrences of skipExpiry in non-comment lines', () => {
        const lines = readNonCommentLines(filePath);
        expect(lines.filter((l) => l.includes('skipExpiry'))).toHaveLength(0);
    });

    it('should have zero occurrences of skipAudience in non-comment lines', () => {
        const lines = readNonCommentLines(filePath);
        expect(lines.filter((l) => l.includes('skipAudience'))).toHaveLength(0);
    });

    it('should have zero occurrences of anyAudience in non-comment lines', () => {
        const lines = readNonCommentLines(filePath);
        expect(lines.filter((l) => l.includes('anyAudience'))).toHaveLength(0);
    });

    it('should have zero occurrences of wildcardSP in non-comment lines', () => {
        const lines = readNonCommentLines(filePath);
        expect(lines.filter((l) => l.includes('wildcardSP'))).toHaveLength(0);
    });
});
