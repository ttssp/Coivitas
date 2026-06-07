/**
 * OIDC Provider tests
 *
 * Coverage:
 *   - OidcAuthError: construction + 12-code error taxonomy
 *   - parseOidcProviderConfig: valid / empty clientSecret → fail-closed (P0 security)
 *   - parseOidcIdentityProvider: valid / empty jwksUri → fail-closed (P0 security)
 *   - parseOidcClaims: sub extraction / standard-claims filtering / extra attributes extraction
 *     + prototype pollution defense (__proto__ / constructor / prototype)
 *   - OidcProvider.generateAuthorizeUrl: happy path + required state/nonce + OidcPort error fail-closed
 *   - OidcProvider.verifyCallback: 3 P0 guards:
 *       - signature verification failure → OIDC_SIGNATURE_INVALID (fail-closed; does not return claims)
 *       - expiry verification failure (exp expired) → OIDC_EXPIRED (fail-closed)
 *       - issuer mismatch → OIDC_ISSUER_MISMATCH (fail-closed; absent also throws)
 *       - audience does not contain clientId → OIDC_AUDIENCE_MISMATCH (fail-closed; absent also throws)
 *     + happy verification path + layer-2 double expiry/iss/aud verification
 *   - OidcProvider.generateEndSessionUrl: happy path + error fail-closed
 *   - createOidcLoginHandler: missing sessionId → 400 / normal → redirect
 *   - createOidcCallbackHandler:
 *       - missing sessionId → 400 fail-closed
 *       - session not found → 401 fail-closed (state replay defense)
 *       - invalid signature → 401 fail-closed (P0)
 *       - expired → 401 fail-closed (P0)
 *       - issuer mismatch → 401 fail-closed (P0)
 *       - audience mismatch → 401 fail-closed (P0)
 *       - verification passes → 200 + claims
 *   - createOidcLogoutHandler: missing idToken → 400 / normal → redirect
 *   - handleOidcError: error code → HTTP status code mapping + 4 P0 sanitized fixed strings
 *   - invariant grep test: oidc-provider.ts contains none of the 14 skip keywords
 *
 * Mock strategy:
 *   - Inject an OidcPort mock (does not depend on openid-client being installed)
 *   - OidcPort.verifyCallback mock controls the signature / expiry / issuer / audience verification results
 *   - Use OidcVerificationError(reason) to simulate different verification-failure scenarios
 *
 * @see saml-provider.test.ts (reuses the same pattern as the baseline)
 */

import { describe, it, expect, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
    OidcAuthError,
    OidcVerificationError,
    parseOidcProviderConfig,
    parseOidcIdentityProvider,
    parseOidcClaims,
    parseOidcUserClaims,
    OidcProvider,
    createOidcLoginHandler,
    createOidcCallbackHandler,
    createOidcLogoutHandler,
    handleOidcError,
} from '../oidc-provider.js';
import type {
    OidcPort,
    OidcProviderConfig,
    OidcIdentityProvider,
    OidcProviderInitConfig,
    OidcHandlerConfig,
    OidcSessionStore,
    OidcUserClaims,
} from '../oidc-provider.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

// ── Test data ─────────────────────────────────────────────────────────────────

const VALID_OIDC_CONFIG: OidcProviderConfig = {
    issuer: 'https://op.example.com',
    clientId: 'test-client-id',
    clientSecret: 'test-client-secret-xyz-12345',
    redirectUri: 'https://rp.example.com/auth/oidc/callback',
    postLogoutRedirectUri: 'https://rp.example.com/logout-done',
    scopes: ['openid', 'profile', 'email'],
};

const VALID_OIDC_IDP: OidcIdentityProvider = {
    issuer: 'https://op.example.com',
    authorizationEndpoint: 'https://op.example.com/authorize',
    tokenEndpoint: 'https://op.example.com/token',
    userinfoEndpoint: 'https://op.example.com/userinfo',
    endSessionEndpoint: 'https://op.example.com/end_session',
    jwksUri: 'https://op.example.com/.well-known/jwks.json',
};

const futureExp = Math.floor(Date.now() / 1000) + 3600;
const pastExp = Math.floor(Date.now() / 1000) - 3600;

const VALID_CLAIMS: Record<string, unknown> = {
    sub: 'user-uuid-123',
    iss: 'https://op.example.com', // ✓ matches VALID_OIDC_IDP.issuer
    aud: 'test-client-id', // ✓ matches VALID_OIDC_CONFIG.clientId
    exp: futureExp,
    iat: Math.floor(Date.now() / 1000) - 60,
    nonce: 'nonce-xyz-789',
    email: 'alice@example.com',
    name: 'Alice Example',
    preferred_username: 'alice',
};

// ── Mock OidcPort ─────────────────────────────────────────────────────────────

function makeMockOidcPort(opts: {
    authorizeUrl?: string;
    verifyResult?: {
        idToken?: string;
        accessToken?: string;
        refreshToken?: string;
        expiresIn?: number;
        claims: Record<string, unknown>;
    };
    verifyError?: Error;
    endSessionUrl?: string;
    endSessionError?: Error;
    getAuthorizeUrlError?: Error;
}): OidcPort {
    return {
        getAuthorizeUrl: opts.getAuthorizeUrlError
            ? () => Promise.reject(opts.getAuthorizeUrlError!)
            : opts.authorizeUrl
              ? () => Promise.resolve(opts.authorizeUrl!)
              : () =>
                    Promise.resolve(
                        'https://op.example.com/authorize?state=s&nonce=n&client_id=test-client-id',
                    ),

        verifyCallback: opts.verifyError
            ? () => Promise.reject(opts.verifyError!)
            : opts.verifyResult
              ? () => Promise.resolve(opts.verifyResult!)
              : () =>
                    Promise.resolve({
                        idToken: 'fake.id.token',
                        accessToken: 'fake-access-token',
                        refreshToken: 'fake-refresh-token',
                        expiresIn: 3600,
                        claims: VALID_CLAIMS,
                    }),

        getEndSessionUrl: opts.endSessionError
            ? () => Promise.reject(opts.endSessionError!)
            : opts.endSessionUrl
              ? () => Promise.resolve(opts.endSessionUrl!)
              : () =>
                    Promise.resolve(
                        'https://op.example.com/end_session?id_token_hint=...&post_logout_redirect_uri=...',
                    ),
    };
}

function makeProvider(oidcPort?: OidcPort): OidcProvider {
    const cfg: OidcProviderInitConfig = {
        config: VALID_OIDC_CONFIG,
        idp: VALID_OIDC_IDP,
        oidcPort: oidcPort ?? makeMockOidcPort({}),
    };
    return new OidcProvider(cfg);
}

// ── Mock OidcSessionStore ─────────────────────────────────────────────────────

function makeInMemorySessionStore(): OidcSessionStore {
    const store = new Map<
        string,
        { state: string; nonce: string; codeVerifier?: string }
    >();
    return {
        put: (id, data) => {
            store.set(id, data);
            return Promise.resolve();
        },
        consume: (id) => {
            const data = store.get(id);
            store.delete(id);
            return Promise.resolve(data);
        },
    };
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

// ────────────────────────────────────────────────────────────────────────────────
// OidcAuthError
// ────────────────────────────────────────────────────────────────────────────────

describe('OidcAuthError', () => {
    it('should construct with correct code and name when code provided', () => {
        const err = new OidcAuthError('sig invalid', 'OIDC_SIGNATURE_INVALID');
        expect(err.code).toBe('OIDC_SIGNATURE_INVALID');
        expect(err.name).toBe('OidcAuthError');
        expect(err.message).toBe('sig invalid');
        expect(err).toBeInstanceOf(Error);
        expect(err).toBeInstanceOf(OidcAuthError);
    });

    it('should default to OIDC_INTERNAL_ERROR when no code provided', () => {
        const err = new OidcAuthError('internal');
        expect(err.code).toBe('OIDC_INTERNAL_ERROR');
    });

    it('should preserve prototype chain for instanceof checks', () => {
        const err = new OidcAuthError('test', 'OIDC_EXPIRED');
        expect(err).toBeInstanceOf(OidcAuthError);
        expect(err).toBeInstanceOf(Error);
    });
});

// ────────────────────────────────────────────────────────────────────────────────
// parseOidcProviderConfig — should validate config and reject empty fields
// ────────────────────────────────────────────────────────────────────────────────

describe('parseOidcProviderConfig — should validate config and reject empty fields', () => {
    it('should return valid OidcProviderConfig when all required fields provided', () => {
        const result = parseOidcProviderConfig({
            issuer: 'https://op.example.com',
            clientId: 'test',
            clientSecret: 'secret',
            redirectUri: 'https://rp.example.com/cb',
        });
        expect(result.issuer).toBe('https://op.example.com');
        expect(result.clientId).toBe('test');
        expect(result.clientSecret).toBe('secret');
        expect(result.redirectUri).toBe('https://rp.example.com/cb');
    });

    it('should throw OIDC_CONFIG_INVALID when issuer is missing', () => {
        expect(() =>
            parseOidcProviderConfig({
                issuer: '',
                clientId: 't',
                clientSecret: 's',
                redirectUri: 'https://r',
            }),
        ).toThrow(OidcAuthError);
    });

    it('should throw OIDC_CONFIG_INVALID when clientId is missing', () => {
        expect(() =>
            parseOidcProviderConfig({
                issuer: 'https://op',
                clientId: '',
                clientSecret: 's',
                redirectUri: 'https://r',
            }),
        ).toThrow(OidcAuthError);
    });

    /**
     * P0 security negative test: empty clientSecret → must fail-closed (must not bypass client authentication)
     */
    it('[P0] should throw OIDC_CONFIG_INVALID when clientSecret is empty string — prevents auth bypass', () => {
        let caught: OidcAuthError | null = null;
        try {
            parseOidcProviderConfig({
                issuer: 'https://op',
                clientId: 'c',
                clientSecret: '',
                redirectUri: 'https://r',
            });
        } catch (err) {
            caught = err as OidcAuthError;
        }
        expect(caught).not.toBeNull();
        expect(caught).toBeInstanceOf(OidcAuthError);
        expect(caught!.code).toBe('OIDC_CONFIG_INVALID');
        expect(caught!.message).toContain('bypass OIDC client authentication');
    });

    it('[P0] should throw OIDC_CONFIG_INVALID when clientSecret is whitespace-only', () => {
        expect(() =>
            parseOidcProviderConfig({
                issuer: 'https://op',
                clientId: 'c',
                clientSecret: '   ',
                redirectUri: 'https://r',
            }),
        ).toThrow(OidcAuthError);
    });

    it('should throw OIDC_CONFIG_INVALID when redirectUri is missing', () => {
        expect(() =>
            parseOidcProviderConfig({
                issuer: 'https://op',
                clientId: 'c',
                clientSecret: 's',
                redirectUri: '',
            }),
        ).toThrow(OidcAuthError);
    });

    it('should accept optional scopes and postLogoutRedirectUri when provided', () => {
        const cfg = parseOidcProviderConfig({
            issuer: 'https://op',
            clientId: 'c',
            clientSecret: 's',
            redirectUri: 'https://r',
            scopes: ['openid', 'profile'],
            postLogoutRedirectUri: 'https://r/logout',
        });
        expect(cfg.scopes).toEqual(['openid', 'profile']);
        expect(cfg.postLogoutRedirectUri).toBe('https://r/logout');
    });
});

// ────────────────────────────────────────────────────────────────────────────────
// parseOidcIdentityProvider — should validate IDP config and reject empty jwksUri
// ────────────────────────────────────────────────────────────────────────────────

describe('parseOidcIdentityProvider — should validate IDP config', () => {
    it('should return valid OidcIdentityProvider when all required fields provided', () => {
        const result = parseOidcIdentityProvider({
            issuer: 'https://op.example.com',
            authorizationEndpoint: 'https://op.example.com/authorize',
            tokenEndpoint: 'https://op.example.com/token',
            jwksUri: 'https://op.example.com/.well-known/jwks.json',
        });
        expect(result.issuer).toBe('https://op.example.com');
        expect(result.jwksUri).toBe(
            'https://op.example.com/.well-known/jwks.json',
        );
    });

    /**
     * P0 security negative test: empty jwksUri → must fail-closed (must not bypass id_token signature verification)
     */
    it('[P0] should throw OIDC_CONFIG_INVALID when jwksUri is empty — prevents signature verification skip', () => {
        let caught: OidcAuthError | null = null;
        try {
            parseOidcIdentityProvider({
                issuer: 'https://op',
                authorizationEndpoint: 'https://op/authorize',
                tokenEndpoint: 'https://op/token',
                jwksUri: '',
            });
        } catch (err) {
            caught = err as OidcAuthError;
        }
        expect(caught).not.toBeNull();
        expect(caught!.code).toBe('OIDC_CONFIG_INVALID');
        expect(caught!.message).toContain(
            'bypass OIDC id_token signature verification',
        );
    });

    it('[P0] should throw OIDC_CONFIG_INVALID when jwksUri is whitespace-only', () => {
        expect(() =>
            parseOidcIdentityProvider({
                issuer: 'https://op',
                authorizationEndpoint: 'https://op/a',
                tokenEndpoint: 'https://op/t',
                jwksUri: '  ',
            }),
        ).toThrow(OidcAuthError);
    });

    it('should throw OIDC_CONFIG_INVALID when authorizationEndpoint is missing', () => {
        expect(() =>
            parseOidcIdentityProvider({
                issuer: 'https://op',
                authorizationEndpoint: '',
                tokenEndpoint: 'https://op/t',
                jwksUri: 'https://op/jwks',
            }),
        ).toThrow(OidcAuthError);
    });
});

// ────────────────────────────────────────────────────────────────────────────────
// parseOidcClaims — should extract claims with prototype pollution defense
// ────────────────────────────────────────────────────────────────────────────────

describe('parseOidcClaims — should extract user claims from id_token', () => {
    it('should extract sub, exp, attributes from valid claims', () => {
        const result = parseOidcClaims(
            VALID_CLAIMS,
            'https://op.example.com',
            'test-client-id',
        );
        expect(result.sub).toBe('user-uuid-123');
        expect(result.issuer).toBe('https://op.example.com');
        expect(result.audience).toBe('test-client-id');
        expect(result.idTokenExpiresAt).toBe(futureExp);
        expect(result.attributes['email']).toBe('alice@example.com');
        expect(result.attributes['preferred_username']).toBe('alice');
    });

    it('should throw OIDC_CLAIMS_INVALID when sub is missing', () => {
        const noSub = { ...VALID_CLAIMS, sub: undefined };
        expect(() =>
            parseOidcClaims(noSub, 'https://op.example.com', 'test-client-id'),
        ).toThrow(OidcAuthError);
        try {
            parseOidcClaims(noSub, 'https://op.example.com', 'test-client-id');
        } catch (err) {
            expect((err as OidcAuthError).code).toBe('OIDC_CLAIMS_INVALID');
        }
    });

    it('should throw OIDC_CLAIMS_INVALID when exp is missing or invalid', () => {
        const noExp = { ...VALID_CLAIMS, exp: undefined };
        expect(() =>
            parseOidcClaims(noExp, 'https://op.example.com', 'test-client-id'),
        ).toThrow(OidcAuthError);
    });

    it('should exclude standard OIDC claims from attributes', () => {
        const result = parseOidcClaims(
            VALID_CLAIMS,
            'https://op.example.com',
            'test-client-id',
        );
        expect(result.attributes['sub']).toBeUndefined();
        expect(result.attributes['iss']).toBeUndefined();
        expect(result.attributes['aud']).toBeUndefined();
        expect(result.attributes['exp']).toBeUndefined();
        expect(result.attributes['nonce']).toBeUndefined();
    });

    it('should set verifiedAt to current time ISO string', () => {
        const before = Date.now();
        const result = parseOidcClaims(
            VALID_CLAIMS,
            'https://op.example.com',
            'test-client-id',
        );
        const after = Date.now();
        const ms = Date.parse(result.verifiedAt);
        expect(ms).toBeGreaterThanOrEqual(before);
        expect(ms).toBeLessThanOrEqual(after);
    });

    it('should pass tokenExtras into resulting claims when provided', () => {
        const result = parseOidcClaims(
            VALID_CLAIMS,
            'https://op.example.com',
            'test-client-id',
            {
                idToken: 'header.payload.sig',
                accessToken: 'access-xyz',
                refreshToken: 'refresh-xyz',
                accessTokenExpiresAt: 12345,
            },
        );
        expect(result.idToken).toBe('header.payload.sig');
        expect(result.accessToken).toBe('access-xyz');
        expect(result.refreshToken).toBe('refresh-xyz');
        expect(result.accessTokenExpiresAt).toBe(12345);
    });
});

// ────────────────────────────────────────────────────────────────────────────────
// OidcProvider.generateAuthorizeUrl
// ────────────────────────────────────────────────────────────────────────────────

describe('OidcProvider.generateAuthorizeUrl', () => {
    it('should return authorize URL when port resolves with valid state/nonce', async () => {
        const provider = makeProvider(
            makeMockOidcPort({
                authorizeUrl:
                    'https://op.example.com/authorize?state=s1&nonce=n1',
            }),
        );
        const url = await provider.generateAuthorizeUrl({
            state: 's1',
            nonce: 'n1',
        });
        expect(url).toBe('https://op.example.com/authorize?state=s1&nonce=n1');
    });

    it('should throw OIDC_AUTHORIZE_URL_FAILED when state is empty (CSRF protection)', async () => {
        const provider = makeProvider();
        await expect(
            provider.generateAuthorizeUrl({ state: '', nonce: 'n' }),
        ).rejects.toBeInstanceOf(OidcAuthError);
    });

    it('should throw OIDC_AUTHORIZE_URL_FAILED when nonce is empty (replay protection)', async () => {
        const provider = makeProvider();
        await expect(
            provider.generateAuthorizeUrl({ state: 's', nonce: '' }),
        ).rejects.toBeInstanceOf(OidcAuthError);
    });

    it('should throw OIDC_AUTHORIZE_URL_FAILED when port rejects', async () => {
        const provider = makeProvider(
            makeMockOidcPort({
                getAuthorizeUrlError: new Error('IDP unreachable'),
            }),
        );
        try {
            await provider.generateAuthorizeUrl({ state: 's', nonce: 'n' });
            expect.fail('should not reach');
        } catch (err) {
            expect((err as OidcAuthError).code).toBe(
                'OIDC_AUTHORIZE_URL_FAILED',
            );
        }
    });
});

// ────────────────────────────────────────────────────────────────────────────────
// OidcProvider.verifyCallback — signature
// ────────────────────────────────────────────────────────────────────────────────

describe('OidcProvider.verifyCallback — P0-A signature verification', () => {
    /**
     *  Security negative test: signature verification failure → must reject (fail-closed)
     */
    it('[P0-A] should throw OIDC_SIGNATURE_INVALID when port reports signature verification failure', async () => {
        const provider = makeProvider(
            makeMockOidcPort({
                verifyError: new OidcVerificationError(
                    'invalid signature: jwks key mismatch',
                ),
            }),
        );
        let caught: OidcAuthError | null = null;
        try {
            await provider.verifyCallback({
                currentUrl: 'https://rp.example.com/auth/oidc/callback?code=c',
                expectedNonce: 'n',
                expectedState: 's',
            });
        } catch (err) {
            caught = err as OidcAuthError;
        }
        expect(caught).not.toBeNull();
        expect(caught!.code).toBe('OIDC_SIGNATURE_INVALID');
    });

    it('[P0-A] should throw OIDC_SIGNATURE_INVALID when jwks fetch fails', async () => {
        const provider = makeProvider(
            makeMockOidcPort({
                verifyError: new OidcVerificationError(
                    'jwks endpoint returned 500',
                ),
            }),
        );
        try {
            await provider.verifyCallback({
                currentUrl: 'https://rp/cb?code=c',
                expectedNonce: 'n',
                expectedState: 's',
            });
            expect.fail('should not reach');
        } catch (err) {
            expect((err as OidcAuthError).code).toBe('OIDC_SIGNATURE_INVALID');
        }
    });

    it('[P0-A] should throw OIDC_SIGNATURE_INVALID when kid mismatch occurs', async () => {
        const provider = makeProvider(
            makeMockOidcPort({
                verifyError: new OidcVerificationError(
                    'jws kid not found in jwks',
                ),
            }),
        );
        try {
            await provider.verifyCallback({
                currentUrl: 'https://rp/cb?code=c',
                expectedNonce: 'n',
                expectedState: 's',
            });
            expect.fail('should not reach');
        } catch (err) {
            expect((err as OidcAuthError).code).toBe('OIDC_SIGNATURE_INVALID');
        }
    });

    it('[P0-A] should fallback to OIDC_SIGNATURE_INVALID when reason is unknown (most-strict fail-closed)', async () => {
        const provider = makeProvider(
            makeMockOidcPort({
                verifyError: new OidcVerificationError(
                    'something unknown went wrong',
                ),
            }),
        );
        try {
            await provider.verifyCallback({
                currentUrl: 'https://rp/cb?code=c',
                expectedNonce: 'n',
                expectedState: 's',
            });
            expect.fail('should not reach');
        } catch (err) {
            expect((err as OidcAuthError).code).toBe('OIDC_SIGNATURE_INVALID');
        }
    });
});

// ────────────────────────────────────────────────────────────────────────────────
// OidcProvider.verifyCallback — expiry
// ────────────────────────────────────────────────────────────────────────────────

describe('OidcProvider.verifyCallback — P0-B expiry verification', () => {
    /**
     *  Layer 1: port reports expired → throw OIDC_EXPIRED
     */
    it('[P0-B] should throw OIDC_EXPIRED when port reports id_token expired', async () => {
        const provider = makeProvider(
            makeMockOidcPort({
                verifyError: new OidcVerificationError(
                    'jwt expired, exp claim is in the past',
                ),
            }),
        );
        try {
            await provider.verifyCallback({
                currentUrl: 'https://rp/cb?code=c',
                expectedNonce: 'n',
                expectedState: 's',
            });
            expect.fail('should not reach');
        } catch (err) {
            expect((err as OidcAuthError).code).toBe('OIDC_EXPIRED');
        }
    });

    /**
     *  Layer 2: port succeeds but claims.exp is already expired → throw OIDC_EXPIRED (double safety)
     */
    it('[P0-B] should throw OIDC_EXPIRED when claims.exp is in the past (layer 2a check)', async () => {
        const expiredClaims = { ...VALID_CLAIMS, exp: pastExp };
        const provider = makeProvider(
            makeMockOidcPort({
                verifyResult: {
                    idToken: 'tok',
                    accessToken: 'at',
                    expiresIn: 3600,
                    claims: expiredClaims,
                },
            }),
        );
        try {
            await provider.verifyCallback({
                currentUrl: 'https://rp/cb?code=c',
                expectedNonce: 'n',
                expectedState: 's',
            });
            expect.fail('should not reach');
        } catch (err) {
            expect((err as OidcAuthError).code).toBe('OIDC_EXPIRED');
        }
    });

    /**
     *  Layer 2: nbf not yet reached → throw OIDC_EXPIRED
     */
    it('[P0-B] should throw OIDC_EXPIRED when claims.nbf is in the future (layer 2a check)', async () => {
        const futureNbf = Math.floor(Date.now() / 1000) + 600;
        const provider = makeProvider(
            makeMockOidcPort({
                verifyResult: {
                    idToken: 'tok',
                    accessToken: 'at',
                    expiresIn: 3600,
                    claims: { ...VALID_CLAIMS, nbf: futureNbf },
                },
            }),
        );
        try {
            await provider.verifyCallback({
                currentUrl: 'https://rp/cb?code=c',
                expectedNonce: 'n',
                expectedState: 's',
            });
            expect.fail('should not reach');
        } catch (err) {
            expect((err as OidcAuthError).code).toBe('OIDC_EXPIRED');
        }
    });

    /**
     *  Layer-2 silent-return: claims.exp field absent → trust layer 1 (does not throw)
     * Note: parseOidcClaims rejects a missing exp (layer 3); here we only test that layer 2a does not throw (silent-return)
     */
    it('[P0-B] should silent-return on missing exp at layer 2a (trust layer 1; layer 3 catches separately)', async () => {
        // Construct claims: exp absent, but keep the other fields
        // eslint-disable-next-line @typescript-eslint/no-unused-vars
        const { exp: _exp, ...claimsNoExp } = VALID_CLAIMS;
        const provider = makeProvider(
            makeMockOidcPort({
                verifyResult: {
                    idToken: 'tok',
                    accessToken: 'at',
                    expiresIn: 3600,
                    claims: claimsNoExp,
                },
            }),
        );
        // Layer 2a silent-returns; but layer-3 parseOidcClaims throws OIDC_CLAIMS_INVALID because exp is absent
        try {
            await provider.verifyCallback({
                currentUrl: 'https://rp/cb?code=c',
                expectedNonce: 'n',
                expectedState: 's',
            });
            expect.fail('should not reach (layer 3 rejects)');
        } catch (err) {
            expect((err as OidcAuthError).code).toBe('OIDC_CLAIMS_INVALID');
        }
    });

    /**
     *  access_token expires_in <= 0 → throw OIDC_EXPIRED
     */
    it('[P0-B] should throw OIDC_EXPIRED when access_token expires_in is non-positive (custom port no-populate)', async () => {
        const provider = makeProvider(
            makeMockOidcPort({
                verifyResult: {
                    idToken: 'tok',
                    accessToken: 'at',
                    expiresIn: -1,
                    claims: VALID_CLAIMS,
                },
            }),
        );
        try {
            await provider.verifyCallback({
                currentUrl: 'https://rp/cb?code=c',
                expectedNonce: 'n',
                expectedState: 's',
            });
            expect.fail('should not reach');
        } catch (err) {
            expect((err as OidcAuthError).code).toBe('OIDC_EXPIRED');
        }
    });
});

// ────────────────────────────────────────────────────────────────────────────────
// OidcProvider.verifyCallback — issuer
// ────────────────────────────────────────────────────────────────────────────────

describe('OidcProvider.verifyCallback — P0-C issuer verification', () => {
    /**
     *  issuer layer 1: port reports an issuer error → OIDC_ISSUER_MISMATCH
     */
    it('[P0-C] should throw OIDC_ISSUER_MISMATCH when port reports issuer mismatch', async () => {
        const provider = makeProvider(
            makeMockOidcPort({
                verifyError: new OidcVerificationError(
                    'unexpected JWT iss claim value',
                ),
            }),
        );
        try {
            await provider.verifyCallback({
                currentUrl: 'https://rp/cb?code=c',
                expectedNonce: 'n',
                expectedState: 's',
            });
            expect.fail('should not reach');
        } catch (err) {
            expect((err as OidcAuthError).code).toBe('OIDC_ISSUER_MISMATCH');
        }
    });

    /**
     *  issuer layer 2b: claims.iss field absent → throw (fail-closed; no silent-return)
     */
    it('[P0-C] should throw OIDC_ISSUER_MISMATCH when claims.iss is absent (P0 fail-closed)', async () => {
        // eslint-disable-next-line @typescript-eslint/no-unused-vars
        const { iss: _iss, ...claimsNoIss } = VALID_CLAIMS;
        const provider = makeProvider(
            makeMockOidcPort({
                verifyResult: {
                    idToken: 'tok',
                    accessToken: 'at',
                    expiresIn: 3600,
                    claims: claimsNoIss,
                },
            }),
        );
        let caught: OidcAuthError | null = null;
        try {
            await provider.verifyCallback({
                currentUrl: 'https://rp/cb?code=c',
                expectedNonce: 'n',
                expectedState: 's',
            });
        } catch (err) {
            caught = err as OidcAuthError;
        }
        expect(caught).not.toBeNull();
        expect(caught!.code).toBe('OIDC_ISSUER_MISMATCH');
        expect(caught!.message).toContain('P0 violation');
    });

    /**
     *  issuer layer 2b: claims.iss does not match → throw
     */
    it('[P0-C] should throw OIDC_ISSUER_MISMATCH when claims.iss does not match configured issuer', async () => {
        const wrongIssClaims = {
            ...VALID_CLAIMS,
            iss: 'https://evil-op.example.com',
        };
        const provider = makeProvider(
            makeMockOidcPort({
                verifyResult: {
                    idToken: 'tok',
                    accessToken: 'at',
                    expiresIn: 3600,
                    claims: wrongIssClaims,
                },
            }),
        );
        try {
            await provider.verifyCallback({
                currentUrl: 'https://rp/cb?code=c',
                expectedNonce: 'n',
                expectedState: 's',
            });
            expect.fail('should not reach');
        } catch (err) {
            expect((err as OidcAuthError).code).toBe('OIDC_ISSUER_MISMATCH');
        }
    });

    /**
     *  wildcard rejection: iss accepts no wildcard / prefix match
     */
    it('[P0-C] should reject wildcard issuer (literal === strict; no prefix match)', async () => {
        // Simulate an attacker-controlled subdomain; a wildcard match would let it through
        const wildIssClaims = {
            ...VALID_CLAIMS,
            iss: 'https://op.example.com.attacker.com',
        };
        const provider = makeProvider(
            makeMockOidcPort({
                verifyResult: {
                    idToken: 'tok',
                    accessToken: 'at',
                    expiresIn: 3600,
                    claims: wildIssClaims,
                },
            }),
        );
        try {
            await provider.verifyCallback({
                currentUrl: 'https://rp/cb?code=c',
                expectedNonce: 'n',
                expectedState: 's',
            });
            expect.fail('should not reach');
        } catch (err) {
            expect((err as OidcAuthError).code).toBe('OIDC_ISSUER_MISMATCH');
        }
    });
});

// ────────────────────────────────────────────────────────────────────────────────
// OidcProvider.verifyCallback — audience
// ────────────────────────────────────────────────────────────────────────────────

describe('OidcProvider.verifyCallback — P0-C audience verification', () => {
    /**
     *  audience layer 1: port reports an aud error → OIDC_AUDIENCE_MISMATCH
     */
    it('[P0-C] should throw OIDC_AUDIENCE_MISMATCH when port reports audience mismatch', async () => {
        const provider = makeProvider(
            makeMockOidcPort({
                verifyError: new OidcVerificationError(
                    'unexpected JWT aud claim value',
                ),
            }),
        );
        try {
            await provider.verifyCallback({
                currentUrl: 'https://rp/cb?code=c',
                expectedNonce: 'n',
                expectedState: 's',
            });
            expect.fail('should not reach');
        } catch (err) {
            expect((err as OidcAuthError).code).toBe('OIDC_AUDIENCE_MISMATCH');
        }
    });

    /**
     *  audience layer 2b: claims.aud field absent → throw (fail-closed)
     */
    it('[P0-C] should throw OIDC_AUDIENCE_MISMATCH when claims.aud is absent (P0 fail-closed)', async () => {
        // eslint-disable-next-line @typescript-eslint/no-unused-vars
        const { aud: _aud, ...claimsNoAud } = VALID_CLAIMS;
        const provider = makeProvider(
            makeMockOidcPort({
                verifyResult: {
                    idToken: 'tok',
                    accessToken: 'at',
                    expiresIn: 3600,
                    claims: claimsNoAud,
                },
            }),
        );
        let caught: OidcAuthError | null = null;
        try {
            await provider.verifyCallback({
                currentUrl: 'https://rp/cb?code=c',
                expectedNonce: 'n',
                expectedState: 's',
            });
        } catch (err) {
            caught = err as OidcAuthError;
        }
        expect(caught).not.toBeNull();
        expect(caught!.code).toBe('OIDC_AUDIENCE_MISMATCH');
        expect(caught!.message).toContain('P0 violation');
    });

    /**
     *  audience layer 2b: claims.aud does not match clientId → throw
     */
    it('[P0-C] should throw OIDC_AUDIENCE_MISMATCH when claims.aud does not contain clientId', async () => {
        const wrongAudClaims = {
            ...VALID_CLAIMS,
            aud: 'other-client-id',
        };
        const provider = makeProvider(
            makeMockOidcPort({
                verifyResult: {
                    idToken: 'tok',
                    accessToken: 'at',
                    expiresIn: 3600,
                    claims: wrongAudClaims,
                },
            }),
        );
        try {
            await provider.verifyCallback({
                currentUrl: 'https://rp/cb?code=c',
                expectedNonce: 'n',
                expectedState: 's',
            });
            expect.fail('should not reach');
        } catch (err) {
            expect((err as OidcAuthError).code).toBe('OIDC_AUDIENCE_MISMATCH');
        }
    });

    /**
     *  audience array: aud is an array but does not contain clientId → throw
     */
    it('[P0-C] should throw OIDC_AUDIENCE_MISMATCH when claims.aud array does not include clientId', async () => {
        const audArrayClaims = {
            ...VALID_CLAIMS,
            aud: ['other-client-1', 'other-client-2'],
        };
        const provider = makeProvider(
            makeMockOidcPort({
                verifyResult: {
                    idToken: 'tok',
                    accessToken: 'at',
                    expiresIn: 3600,
                    claims: audArrayClaims,
                },
            }),
        );
        try {
            await provider.verifyCallback({
                currentUrl: 'https://rp/cb?code=c',
                expectedNonce: 'n',
                expectedState: 's',
            });
            expect.fail('should not reach');
        } catch (err) {
            expect((err as OidcAuthError).code).toBe('OIDC_AUDIENCE_MISMATCH');
        }
    });

    /**
     *  audience array: aud is an array that contains clientId → passes
     */
    it('should pass audience check when claims.aud array includes clientId', async () => {
        const audArrayClaims = {
            ...VALID_CLAIMS,
            aud: ['other-client-1', 'test-client-id', 'other-client-2'],
        };
        const provider = makeProvider(
            makeMockOidcPort({
                verifyResult: {
                    idToken: 'tok',
                    accessToken: 'at',
                    expiresIn: 3600,
                    claims: audArrayClaims,
                },
            }),
        );
        const claims = await provider.verifyCallback({
            currentUrl: 'https://rp/cb?code=c',
            expectedNonce: 'n',
            expectedState: 's',
        });
        expect(claims.sub).toBe('user-uuid-123');
    });

    /**
     *  audience empty array → throw
     */
    it('[P0-C] should throw OIDC_AUDIENCE_MISMATCH when claims.aud is empty array', async () => {
        const provider = makeProvider(
            makeMockOidcPort({
                verifyResult: {
                    idToken: 'tok',
                    accessToken: 'at',
                    expiresIn: 3600,
                    claims: { ...VALID_CLAIMS, aud: [] },
                },
            }),
        );
        try {
            await provider.verifyCallback({
                currentUrl: 'https://rp/cb?code=c',
                expectedNonce: 'n',
                expectedState: 's',
            });
            expect.fail('should not reach');
        } catch (err) {
            expect((err as OidcAuthError).code).toBe('OIDC_AUDIENCE_MISMATCH');
        }
    });
});

// ────────────────────────────────────────────────────────────────────────────────
// OidcProvider.verifyCallback — happy path + nonce + token_invalid
// ────────────────────────────────────────────────────────────────────────────────

describe('OidcProvider.verifyCallback — happy path + other error codes', () => {
    it('should return OidcUserClaims when all P0 layers pass', async () => {
        const provider = makeProvider();
        const claims = await provider.verifyCallback({
            currentUrl: 'https://rp/cb?code=c',
            expectedNonce: 'nonce-xyz-789',
            expectedState: 'state-abc',
        });
        expect(claims.sub).toBe('user-uuid-123');
        expect(claims.issuer).toBe('https://op.example.com');
        expect(claims.audience).toBe('test-client-id');
        expect(claims.idToken).toBe('fake.id.token');
        expect(claims.accessTokenExpiresAt).toBeGreaterThan(
            Math.floor(Date.now() / 1000),
        );
    });

    it('should throw OIDC_NONCE_MISMATCH when port reports nonce mismatch', async () => {
        const provider = makeProvider(
            makeMockOidcPort({
                verifyError: new OidcVerificationError(
                    'expected nonce does not match received nonce',
                ),
            }),
        );
        try {
            await provider.verifyCallback({
                currentUrl: 'https://rp/cb?code=c',
                expectedNonce: 'n',
                expectedState: 's',
            });
            expect.fail('should not reach');
        } catch (err) {
            expect((err as OidcAuthError).code).toBe('OIDC_NONCE_MISMATCH');
        }
    });

    it('should throw OIDC_TOKEN_INVALID when port reports missing id_token claims', async () => {
        const provider = makeProvider(
            makeMockOidcPort({
                verifyError: new OidcVerificationError(
                    'token response missing id_token claims',
                ),
            }),
        );
        try {
            await provider.verifyCallback({
                currentUrl: 'https://rp/cb?code=c',
                expectedNonce: 'n',
                expectedState: 's',
            });
            expect.fail('should not reach');
        } catch (err) {
            expect((err as OidcAuthError).code).toBe('OIDC_TOKEN_INVALID');
        }
    });

    it('should throw OIDC_CALLBACK_INVALID when port reports state mismatch', async () => {
        const provider = makeProvider(
            makeMockOidcPort({
                verifyError: new OidcVerificationError(
                    'mismatched state parameter (csrf protection)',
                ),
            }),
        );
        try {
            await provider.verifyCallback({
                currentUrl: 'https://rp/cb?code=c',
                expectedNonce: 'n',
                expectedState: 's',
            });
            expect.fail('should not reach');
        } catch (err) {
            expect((err as OidcAuthError).code).toBe('OIDC_CALLBACK_INVALID');
        }
    });
});

// ────────────────────────────────────────────────────────────────────────────────
// OidcProvider.generateEndSessionUrl
// ────────────────────────────────────────────────────────────────────────────────

describe('OidcProvider.generateEndSessionUrl', () => {
    const validClaims: OidcUserClaims = {
        sub: 'u',
        issuer: 'https://op.example.com',
        audience: 'test-client-id',
        idToken: 'header.payload.sig',
        idTokenExpiresAt: futureExp,
        verifiedAt: new Date().toISOString(),
        attributes: {},
    };

    it('should return end_session URL when port resolves', async () => {
        const provider = makeProvider(
            makeMockOidcPort({
                endSessionUrl:
                    'https://op.example.com/end_session?id_token_hint=tok',
            }),
        );
        const url = await provider.generateEndSessionUrl(validClaims);
        expect(url).toBe(
            'https://op.example.com/end_session?id_token_hint=tok',
        );
    });

    it('should throw OIDC_LOGOUT_URL_FAILED when idToken is empty in claims', async () => {
        const provider = makeProvider();
        try {
            await provider.generateEndSessionUrl({
                ...validClaims,
                idToken: '',
            });
            expect.fail('should not reach');
        } catch (err) {
            expect((err as OidcAuthError).code).toBe('OIDC_LOGOUT_URL_FAILED');
        }
    });

    it('should throw OIDC_LOGOUT_URL_FAILED when port rejects', async () => {
        const provider = makeProvider(
            makeMockOidcPort({
                endSessionError: new Error('OP slo unavailable'),
            }),
        );
        try {
            await provider.generateEndSessionUrl(validClaims);
            expect.fail('should not reach');
        } catch (err) {
            expect((err as OidcAuthError).code).toBe('OIDC_LOGOUT_URL_FAILED');
        }
    });
});

// ────────────────────────────────────────────────────────────────────────────────
// OidcProvider constructor — should reject empty jwks / clientSecret
// ────────────────────────────────────────────────────────────────────────────────

describe('OidcProvider constructor — should reject empty jwksUri / clientSecret (P0 security)', () => {
    it('[P0] should throw OIDC_CONFIG_INVALID when jwksUri is empty in idp', () => {
        const badIdp: OidcIdentityProvider = {
            ...VALID_OIDC_IDP,
            jwksUri: '',
        };
        expect(
            () =>
                new OidcProvider({
                    config: VALID_OIDC_CONFIG,
                    idp: badIdp,
                    oidcPort: makeMockOidcPort({}),
                }),
        ).toThrow(OidcAuthError);
    });

    it('[P0] should throw OIDC_CONFIG_INVALID when clientSecret is empty in config', () => {
        const badConfig: OidcProviderConfig = {
            ...VALID_OIDC_CONFIG,
            clientSecret: '',
        };
        expect(
            () =>
                new OidcProvider({
                    config: badConfig,
                    idp: VALID_OIDC_IDP,
                    oidcPort: makeMockOidcPort({}),
                }),
        ).toThrow(OidcAuthError);
    });
});

// ────────────────────────────────────────────────────────────────────────────────
// createOidcLoginHandler
// ────────────────────────────────────────────────────────────────────────────────

describe('createOidcLoginHandler', () => {
    it('should return 400 when x-oidc-session-id header is missing', async () => {
        const provider = makeProvider();
        const sessionStore = makeInMemorySessionStore();
        const handlerConfig: OidcHandlerConfig = { provider, sessionStore };
        const handler = createOidcLoginHandler(handlerConfig);

        const req = { headers: {}, body: undefined, query: {} };
        const res = makeMockResponse();
        await handler(req, res, vi.fn());
        expect(res.statusCode).toBe(400);
        expect((res.body as { error: string }).error).toBe(
            'OIDC_CALLBACK_INVALID',
        );
    });

    /**
     * Note: the login handler dynamically imports openid-client to generate state / nonce / PKCE.
     * This test depends on openid-client being installed; in a real environment it redirects normally to the authorize URL.
     * Since the mock port already replaces the internal generateAuthorizeUrl call, this test exercises the randomNonce/State loading flow.
     */
    it('should redirect to authorize URL when session is set and openid-client helpers load', async () => {
        const provider = makeProvider(
            makeMockOidcPort({
                authorizeUrl: 'https://op.example.com/authorize?ok=1',
            }),
        );
        const sessionStore = makeInMemorySessionStore();
        const handlerConfig: OidcHandlerConfig = { provider, sessionStore };
        const handler = createOidcLoginHandler(handlerConfig);

        const req = {
            headers: { 'x-oidc-session-id': 'session-1' },
            body: undefined,
            query: {},
        };
        const res = makeMockResponse();
        await handler(req, res, vi.fn());
        // openid-client v6 is installed → should redirect successfully
        expect(res.statusCode).toBe(302);
        expect(res.redirectUrl).toBe('https://op.example.com/authorize?ok=1');
    });
});

// ────────────────────────────────────────────────────────────────────────────────
// createOidcCallbackHandler — fail-closed 400/401/500
// ────────────────────────────────────────────────────────────────────────────────

describe('createOidcCallbackHandler — fail-closed 400/401/500', () => {
    function setupCallbackHandler(opts: {
        provider?: OidcProvider;
        sessionPre?: {
            state: string;
            nonce: string;
            codeVerifier?: string;
        };
        sessionId?: string;
    }): {
        handler: ReturnType<typeof createOidcCallbackHandler>;
        sessionStore: OidcSessionStore;
    } {
        const provider = opts.provider ?? makeProvider();
        const sessionStore = makeInMemorySessionStore();
        if (opts.sessionPre && opts.sessionId) {
            void sessionStore.put(opts.sessionId, opts.sessionPre);
        }
        const handlerConfig: OidcHandlerConfig = { provider, sessionStore };
        return {
            handler: createOidcCallbackHandler(handlerConfig),
            sessionStore,
        };
    }

    it('should return 400 when x-oidc-session-id header is missing', async () => {
        const { handler } = setupCallbackHandler({});
        const req = {
            headers: {},
            body: undefined,
            query: { code: 'c', state: 's' },
        };
        const res = makeMockResponse();
        await handler(req, res, vi.fn());
        expect(res.statusCode).toBe(400);
    });

    it('should return 401 when session is not found (state replay protection)', async () => {
        const { handler } = setupCallbackHandler({});
        const req = {
            headers: { 'x-oidc-session-id': 'unknown', host: 'rp.example.com' },
            body: undefined,
            query: { code: 'c', state: 's' },
            originalUrl: '/auth/oidc/callback?code=c&state=s',
        };
        const res = makeMockResponse();
        await handler(req, res, vi.fn());
        expect(res.statusCode).toBe(401);
        expect((res.body as { error: string }).error).toBe(
            'OIDC_CALLBACK_INVALID',
        );
    });

    it('[P0] should return 401 when port reports signature verification failure', async () => {
        const provider = makeProvider(
            makeMockOidcPort({
                verifyError: new OidcVerificationError('invalid signature'),
            }),
        );
        const { handler } = setupCallbackHandler({
            provider,
            sessionPre: { state: 'st', nonce: 'no' },
            sessionId: 'sess-1',
        });
        const req = {
            headers: { 'x-oidc-session-id': 'sess-1', host: 'rp.example.com' },
            body: undefined,
            query: { code: 'c', state: 'st' },
            originalUrl: '/auth/oidc/callback?code=c&state=st',
        };
        const res = makeMockResponse();
        await handler(req, res, vi.fn());
        expect(res.statusCode).toBe(401);
        expect((res.body as { error: string }).error).toBe(
            'OIDC_SIGNATURE_INVALID',
        );
        expect((res.body as { message: string }).message).toBe(
            'OIDC id_token signature is invalid. Authentication rejected.',
        );
    });

    it('[P0] should return 401 when id_token is expired (layer 2a check)', async () => {
        const provider = makeProvider(
            makeMockOidcPort({
                verifyResult: {
                    idToken: 'tok',
                    expiresIn: 3600,
                    claims: { ...VALID_CLAIMS, exp: pastExp },
                },
            }),
        );
        const { handler } = setupCallbackHandler({
            provider,
            sessionPre: { state: 'st', nonce: 'no' },
            sessionId: 'sess-1',
        });
        const req = {
            headers: { 'x-oidc-session-id': 'sess-1', host: 'rp.example.com' },
            body: undefined,
            query: {},
            originalUrl: '/auth/oidc/callback?code=c&state=st',
        };
        const res = makeMockResponse();
        await handler(req, res, vi.fn());
        expect(res.statusCode).toBe(401);
        expect((res.body as { error: string }).error).toBe('OIDC_EXPIRED');
        expect((res.body as { message: string }).message).toBe(
            'OIDC id_token has expired. Please re-authenticate.',
        );
    });

    it('[P0] should return 401 when issuer does not match (layer 2b check)', async () => {
        const provider = makeProvider(
            makeMockOidcPort({
                verifyResult: {
                    idToken: 'tok',
                    expiresIn: 3600,
                    claims: { ...VALID_CLAIMS, iss: 'https://wrong' },
                },
            }),
        );
        const { handler } = setupCallbackHandler({
            provider,
            sessionPre: { state: 'st', nonce: 'no' },
            sessionId: 'sess-1',
        });
        const req = {
            headers: { 'x-oidc-session-id': 'sess-1', host: 'rp.example.com' },
            body: undefined,
            query: {},
            originalUrl: '/auth/oidc/callback?code=c&state=st',
        };
        const res = makeMockResponse();
        await handler(req, res, vi.fn());
        expect(res.statusCode).toBe(401);
        expect((res.body as { error: string }).error).toBe(
            'OIDC_ISSUER_MISMATCH',
        );
    });

    it('[P0] should return 401 when audience does not match clientId (layer 2b check)', async () => {
        const provider = makeProvider(
            makeMockOidcPort({
                verifyResult: {
                    idToken: 'tok',
                    expiresIn: 3600,
                    claims: { ...VALID_CLAIMS, aud: 'other-client' },
                },
            }),
        );
        const { handler } = setupCallbackHandler({
            provider,
            sessionPre: { state: 'st', nonce: 'no' },
            sessionId: 'sess-1',
        });
        const req = {
            headers: { 'x-oidc-session-id': 'sess-1', host: 'rp.example.com' },
            body: undefined,
            query: {},
            originalUrl: '/auth/oidc/callback?code=c&state=st',
        };
        const res = makeMockResponse();
        await handler(req, res, vi.fn());
        expect(res.statusCode).toBe(401);
        expect((res.body as { error: string }).error).toBe(
            'OIDC_AUDIENCE_MISMATCH',
        );
    });

    it('should return 200 with claims when verification passes', async () => {
        const { handler } = setupCallbackHandler({
            sessionPre: { state: 'st', nonce: 'nonce-xyz-789' },
            sessionId: 'sess-1',
        });
        const req = {
            headers: { 'x-oidc-session-id': 'sess-1', host: 'rp.example.com' },
            body: undefined,
            query: {},
            originalUrl: '/auth/oidc/callback?code=c&state=st',
        };
        const res = makeMockResponse();
        await handler(req, res, vi.fn());
        expect(res.statusCode).toBe(200);
        const body = res.body as { claims: OidcUserClaims };
        expect(body.claims.sub).toBe('user-uuid-123');
    });
});

// ────────────────────────────────────────────────────────────────────────────────
// createOidcLogoutHandler
// ────────────────────────────────────────────────────────────────────────────────

describe('createOidcLogoutHandler', () => {
    it('should return 400 when idToken is missing from body', async () => {
        const provider = makeProvider();
        const sessionStore = makeInMemorySessionStore();
        const handlerConfig: OidcHandlerConfig = { provider, sessionStore };
        const handler = createOidcLogoutHandler(handlerConfig);

        const req = { headers: {}, body: { other: 1 }, query: {} };
        const res = makeMockResponse();
        await handler(req, res, vi.fn());
        expect(res.statusCode).toBe(400);
        expect((res.body as { error: string }).error).toBe(
            'OIDC_LOGOUT_URL_FAILED',
        );
    });

    it('should return 400 when body is null', async () => {
        const provider = makeProvider();
        const sessionStore = makeInMemorySessionStore();
        const handlerConfig: OidcHandlerConfig = { provider, sessionStore };
        const handler = createOidcLogoutHandler(handlerConfig);

        const req = { headers: {}, body: null, query: {} };
        const res = makeMockResponse();
        await handler(req, res, vi.fn());
        expect(res.statusCode).toBe(400);
    });

    it('should redirect to end_session URL when idToken is valid', async () => {
        const provider = makeProvider(
            makeMockOidcPort({
                endSessionUrl: 'https://op.example.com/end_session?ok=1',
            }),
        );
        const sessionStore = makeInMemorySessionStore();
        const handlerConfig: OidcHandlerConfig = { provider, sessionStore };
        const handler = createOidcLogoutHandler(handlerConfig);

        const req = {
            headers: {},
            body: { idToken: 'header.payload.sig' },
            query: {},
        };
        const res = makeMockResponse();
        await handler(req, res, vi.fn());
        expect(res.statusCode).toBe(302);
        expect(res.redirectUrl).toContain('end_session');
    });
});

// ────────────────────────────────────────────────────────────────────────────────
// handleOidcError — error code → HTTP status mapping
// ────────────────────────────────────────────────────────────────────────────────

describe('handleOidcError — should map OidcErrorCode to correct HTTP status', () => {
    it('should return 401 for OIDC_SIGNATURE_INVALID with sanitized message', () => {
        const res = makeMockResponse();
        handleOidcError(
            new OidcAuthError(
                'jwks key mismatch internal detail',
                'OIDC_SIGNATURE_INVALID',
            ),
            res,
        );
        expect(res.statusCode).toBe(401);
        // P0 sanitized fixed string: should not contain the original internal detail
        expect((res.body as { message: string }).message).toBe(
            'OIDC id_token signature is invalid. Authentication rejected.',
        );
    });

    it('should return 401 for OIDC_EXPIRED with sanitized message', () => {
        const res = makeMockResponse();
        handleOidcError(
            new OidcAuthError('exp 1234 in past', 'OIDC_EXPIRED'),
            res,
        );
        expect(res.statusCode).toBe(401);
        expect((res.body as { message: string }).message).toBe(
            'OIDC id_token has expired. Please re-authenticate.',
        );
    });

    it('should return 401 for OIDC_ISSUER_MISMATCH with sanitized message', () => {
        const res = makeMockResponse();
        handleOidcError(
            new OidcAuthError(
                'expected https://op got https://evil',
                'OIDC_ISSUER_MISMATCH',
            ),
            res,
        );
        expect(res.statusCode).toBe(401);
        expect((res.body as { message: string }).message).toBe(
            'OIDC id_token issuer does not match expected OP. Authentication rejected.',
        );
    });

    it('should return 401 for OIDC_AUDIENCE_MISMATCH with sanitized message', () => {
        const res = makeMockResponse();
        handleOidcError(
            new OidcAuthError('aud mismatch detail', 'OIDC_AUDIENCE_MISMATCH'),
            res,
        );
        expect(res.statusCode).toBe(401);
        expect((res.body as { message: string }).message).toBe(
            'OIDC id_token audience does not match this service. Authentication rejected.',
        );
    });

    it('should return 500 for OIDC_CONFIG_INVALID', () => {
        const res = makeMockResponse();
        handleOidcError(
            new OidcAuthError('cfg invalid', 'OIDC_CONFIG_INVALID'),
            res,
        );
        expect(res.statusCode).toBe(500);
    });

    it('should return 502 for OIDC_AUTHORIZE_URL_FAILED', () => {
        const res = makeMockResponse();
        handleOidcError(
            new OidcAuthError('IDP down', 'OIDC_AUTHORIZE_URL_FAILED'),
            res,
        );
        expect(res.statusCode).toBe(502);
    });

    it('should return 400 for OIDC_CALLBACK_INVALID', () => {
        const res = makeMockResponse();
        handleOidcError(
            new OidcAuthError('parse failed', 'OIDC_CALLBACK_INVALID'),
            res,
        );
        expect(res.statusCode).toBe(400);
    });

    it('should return 500 for unknown errors (fail-closed; no stub 200)', () => {
        const res = makeMockResponse();
        handleOidcError(new Error('unknown'), res);
        expect(res.statusCode).toBe(500);
        expect((res.body as { error: string }).error).toBe(
            'OIDC_INTERNAL_ERROR',
        );
    });

    it('should truncate default-path messages at 256 chars to avoid leaking', () => {
        const longMsg = 'X'.repeat(500);
        const res = makeMockResponse();
        handleOidcError(new OidcAuthError(longMsg, 'OIDC_INTERNAL_ERROR'), res);
        const msg = (res.body as { message: string }).message;
        // The default 256-char truncation in sanitize has been applied (other non-P0 cases go through the default path)
        // But OIDC_INTERNAL_ERROR goes through the sanitize default in handleOidcError;
        // if OIDC_INTERNAL_ERROR falls into handleOidcError's fallback message, it may be a fixed string.
        // This case: OidcAuthError instanceof goes through the sanitize flow → default path → truncation
        expect(msg.length).toBeLessThanOrEqual(256);
    });
});

// ────────────────────────────────────────────────────────────────────────────────
// prototype pollution defense (same pattern as the SAML provider)
// ────────────────────────────────────────────────────────────────────────────────

describe('parseOidcClaims — prototype pollution defense', () => {
    /**
     * Test 1: __proto__ claim injection → throw OIDC_CLAIMS_INVALID
     */
    it('should throw OIDC_CLAIMS_INVALID when claims contain __proto__ attribute name', () => {
        const malicious: Record<string, unknown> = {
            sub: 'attacker',
            iss: 'https://op.example.com',
            aud: 'test-client-id',
            exp: futureExp,
        };
        Object.defineProperty(malicious, '__proto__', {
            value: 'polluted',
            enumerable: true,
            configurable: true,
            writable: true,
        });

        let caught: OidcAuthError | null = null;
        try {
            parseOidcClaims(
                malicious,
                'https://op.example.com',
                'test-client-id',
            );
        } catch (err) {
            caught = err as OidcAuthError;
        }
        expect(caught).not.toBeNull();
        expect(caught!.code).toBe('OIDC_CLAIMS_INVALID');
        expect(caught!.message).toContain('forbidden attribute name');
    });

    /**
     * Test 2: constructor claim injection → throw
     */
    it('should throw OIDC_CLAIMS_INVALID when claims contain constructor attribute name', () => {
        const malicious: Record<string, unknown> = {
            sub: 'attacker',
            iss: 'https://op.example.com',
            aud: 'test-client-id',
            exp: futureExp,
            constructor: 'evil',
        };

        let caught: OidcAuthError | null = null;
        try {
            parseOidcClaims(
                malicious,
                'https://op.example.com',
                'test-client-id',
            );
        } catch (err) {
            caught = err as OidcAuthError;
        }
        expect(caught).not.toBeNull();
        expect(caught!.code).toBe('OIDC_CLAIMS_INVALID');
        expect(caught!.message).toContain('forbidden attribute name');
    });

    /**
     * Test 3 (OIDC-specific): a custom port with the audience field absent → must throw.
     * Verifies that the verifyIssuerAudienceFromClaims layer-2b guard does not depend on OidcPort's internal audience backfill.
     */
    it('[P0-C audience] should throw OIDC_AUDIENCE_MISMATCH when custom port does not populate aud in claims', async () => {
        const customPortNoAud: OidcPort = {
            getAuthorizeUrl: () => Promise.resolve('https://op/authorize'),
            verifyCallback: () =>
                Promise.resolve({
                    idToken: 'tok',
                    expiresIn: 3600,
                    claims: {
                        sub: 'u',
                        iss: 'https://op.example.com',
                        exp: futureExp,
                        // Intentionally does not populate the aud field (tests the layer-2b guard)
                    },
                }),
            getEndSessionUrl: () => Promise.resolve('https://op/end_session'),
        };
        const provider = new OidcProvider({
            config: VALID_OIDC_CONFIG,
            idp: VALID_OIDC_IDP,
            oidcPort: customPortNoAud,
        });

        let caught: OidcAuthError | null = null;
        try {
            await provider.verifyCallback({
                currentUrl: 'https://rp/cb?code=c',
                expectedNonce: 'n',
                expectedState: 's',
            });
        } catch (err) {
            caught = err as OidcAuthError;
        }
        expect(caught).not.toBeNull();
        expect(caught!.code).toBe('OIDC_AUDIENCE_MISMATCH');
        expect(caught!.message).toContain('P0 violation');
    });
});

// ────────────────────────────────────────────────────────────────────────────────
// invariant grep test — oidc-provider.ts should not contain skip keywords
// ────────────────────────────────────────────────────────────────────────────────

/**
 * Invariant grep test: ensure the src file contains no keyword that bypasses signature / expiry / issuer / audience / nonce verification
 *
 * Files covered:
 *   - packages/sdk/src/sso/oidc-provider.ts
 *
 * Keywords verified (14 total; 3 categories):
 *   - oidc-provider.ts keywords (9):
 *     · signature skip: skipSignatureVerify / disableSigCheck / noSigValidation
 *     · expiry skip: skipExpiry / ignoreExp / bypassExpiry
 *     · issuer skip: skipIssuer / skipAudience / wildcardClient
 *   - internal claims keywords (5):
 *     · skipNonce / ignoreNonce / acceptUnknownIssuer / acceptAnyAudience / defaultProtocol200
 *
 * Rule: across non-comment lines (lines that, after trimming whitespace, do not start with // or *), each keyword must occur exactly 0 times.
 *
 * readNonCommentLines: must correctly exclude the JSDoc `*` + `//` prefixes (same implementation as SAML)
 */

const SSO_SRC_DIR = resolve(__dirname, '../');

function readNonCommentLines(filePath: string): string[] {
    const content = readFileSync(filePath, 'utf-8');
    return content.split('\n').filter((line) => {
        const trimmed = line.trim();
        if (trimmed.startsWith('//') || trimmed.startsWith('*')) return false;
        if (trimmed === '') return false;
        return true;
    });
}

// ── parseOidcUserClaims — negative tests ────────────────────────────────

describe('parseOidcUserClaims — fail-closed for invalid inputs', () => {
    it('should throw OidcAuthError OIDC_CLAIMS_INVALID when sub is missing', () => {
        try {
            parseOidcUserClaims({
                // sub intentionally omitted
                issuer: 'https://idp.example.com/oidc',
                audience: 'https://sp.example.com/oidc',
                idTokenExpiresAt: 9999999999,
                verifiedAt: '2026-01-01T00:00:00Z',
                attributes: {},
            });
            expect.fail('should not reach — missing sub must throw');
        } catch (err) {
            expect(err).toBeInstanceOf(OidcAuthError);
            expect((err as OidcAuthError).code).toBe('OIDC_CLAIMS_INVALID');
        }
    });

    it('should throw OidcAuthError OIDC_CLAIMS_INVALID when idTokenExpiresAt is Infinity', () => {
        try {
            parseOidcUserClaims({
                sub: 'user@example.com',
                issuer: 'https://idp.example.com/oidc',
                audience: 'https://sp.example.com/oidc',
                idTokenExpiresAt: Infinity, // non-finite → invalid
                verifiedAt: '2026-01-01T00:00:00Z',
                attributes: {},
            });
            expect.fail('should not reach — Infinity idTokenExpiresAt must throw');
        } catch (err) {
            expect(err).toBeInstanceOf(OidcAuthError);
            expect((err as OidcAuthError).code).toBe('OIDC_CLAIMS_INVALID');
        }
    });
});

describe('invariant grep test — oidc-provider.ts should not contain skip keywords', () => {
    const filePath = resolve(SSO_SRC_DIR, 'oidc-provider.ts');

    // 9 oidc-provider.ts keywords
    it('should have zero occurrences of skipSignatureVerify in non-comment lines', () => {
        const lines = readNonCommentLines(filePath);
        expect(
            lines.filter((l) => l.includes('skipSignatureVerify')),
        ).toHaveLength(0);
    });

    it('should have zero occurrences of disableSigCheck in non-comment lines', () => {
        const lines = readNonCommentLines(filePath);
        expect(lines.filter((l) => l.includes('disableSigCheck'))).toHaveLength(
            0,
        );
    });

    it('should have zero occurrences of noSigValidation in non-comment lines', () => {
        const lines = readNonCommentLines(filePath);
        expect(lines.filter((l) => l.includes('noSigValidation'))).toHaveLength(
            0,
        );
    });

    it('should have zero occurrences of skipExpiry in non-comment lines', () => {
        const lines = readNonCommentLines(filePath);
        expect(lines.filter((l) => l.includes('skipExpiry'))).toHaveLength(0);
    });

    it('should have zero occurrences of ignoreExp in non-comment lines', () => {
        const lines = readNonCommentLines(filePath);
        expect(lines.filter((l) => l.includes('ignoreExp'))).toHaveLength(0);
    });

    it('should have zero occurrences of bypassExpiry in non-comment lines', () => {
        const lines = readNonCommentLines(filePath);
        expect(lines.filter((l) => l.includes('bypassExpiry'))).toHaveLength(0);
    });

    it('should have zero occurrences of skipIssuer in non-comment lines', () => {
        const lines = readNonCommentLines(filePath);
        expect(lines.filter((l) => l.includes('skipIssuer'))).toHaveLength(0);
    });

    it('should have zero occurrences of skipAudience in non-comment lines', () => {
        const lines = readNonCommentLines(filePath);
        expect(lines.filter((l) => l.includes('skipAudience'))).toHaveLength(0);
    });

    it('should have zero occurrences of wildcardClient in non-comment lines', () => {
        const lines = readNonCommentLines(filePath);
        expect(lines.filter((l) => l.includes('wildcardClient'))).toHaveLength(
            0,
        );
    });

    // 5 internal claims keywords
    it('should have zero occurrences of skipNonce in non-comment lines', () => {
        const lines = readNonCommentLines(filePath);
        expect(lines.filter((l) => l.includes('skipNonce'))).toHaveLength(0);
    });

    it('should have zero occurrences of ignoreNonce in non-comment lines', () => {
        const lines = readNonCommentLines(filePath);
        expect(lines.filter((l) => l.includes('ignoreNonce'))).toHaveLength(0);
    });

    it('should have zero occurrences of acceptUnknownIssuer in non-comment lines', () => {
        const lines = readNonCommentLines(filePath);
        expect(
            lines.filter((l) => l.includes('acceptUnknownIssuer')),
        ).toHaveLength(0);
    });

    it('should have zero occurrences of acceptAnyAudience in non-comment lines', () => {
        const lines = readNonCommentLines(filePath);
        expect(
            lines.filter((l) => l.includes('acceptAnyAudience')),
        ).toHaveLength(0);
    });

    it('should have zero occurrences of defaultProtocol200 in non-comment lines', () => {
        const lines = readNonCommentLines(filePath);
        expect(
            lines.filter((l) => l.includes('defaultProtocol200')),
        ).toHaveLength(0);
    });
});
