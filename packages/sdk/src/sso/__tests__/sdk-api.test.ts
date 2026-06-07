/**
 * SSOClient SDK API tests
 *
 * Coverage (≥18 it()):
 *   - initiateLogin SAML success / Port not configured / Port throws
 *   - initiateLogin OIDC success (oidcState + oidcNonce present) / Port not configured / Port throws
 *   - initiateLogin unknown-protocol runtime guard (SSO_CLIENT_IDP_TYPE_INVALID)
 *   - resolveAuthentication SAML success / Port not configured / verifyResponse throws / parseSamlUserClaims fails / federation fails
 *   - resolveAuthentication OIDC success / Port not configured / verifyCallback throws / federation fails
 *   - logout SAML success / Port not configured / getLogoutUrl throws
 *   - logout OIDC success / getEndSessionUrl throws
 *   - SSOClientError shape (code + cause field verification)
 *
 * Security constraints (fail-closed):
 *   - Every Port failure must throw SSOClientError with an errorCode (never swallowed; no partial-PASS)
 *   - The SSO_CLIENT_IDP_TYPE_INVALID runtime guard covers the JS-consumer `as any` cast scenario
 *
 * Mock strategy:
 *   - vi.fn() injects the SamlPort / OidcPort / FederationPort mocks
 *   - Each it() configures the mock return / throw independently
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { SamlPort } from '../saml-provider.js';
import type { OidcPort } from '../oidc-provider.js';
import {
    SSOClient,
    SSOClientError,
} from '../sdk-api.js';
import type {
    InitiateLoginRequest,
    LogoutRequest,
    ResolveAuthenticationRequest,
} from '../sdk-api.js';
import type { FederationPort } from '../tenant-federation.js';

// ── mock factories ─────────────────────────────────────────────────────────────

/** Construct a minimal SamlPort mock */
function makeSamlPort(): SamlPort {
    return {
        getAuthorizeUrl: vi.fn(),
        verifyResponse: vi.fn(),
        getLogoutUrl: vi.fn(),
    } as unknown as SamlPort;
}

/** Construct a minimal OidcPort mock */
function makeOidcPort(): OidcPort {
    return {
        getAuthorizeUrl: vi.fn(),
        verifyCallback: vi.fn(),
        getEndSessionUrl: vi.fn(),
    } as unknown as OidcPort;
}

/** Construct a minimal FederationPort mock */
function makeFederationPort(): FederationPort {
    return {
        findIdpMapping: vi.fn(),
        findTenantById: vi.fn(),
        findUserByExternalSubject: vi.fn(),
        createUser: vi.fn(),
        updateUserRole: vi.fn(),
        writeAuditEvent: vi.fn(),
    } as unknown as FederationPort;
}

/** Construct a standard FederationResolution */
function makeResolution() {
    return {
        userId: 'user-111',
        tenantId: 'tenant-111',
        role: 'operator' as const,
        isNewUser: false,
    };
}

// ── SSOClientError shape ───────────────────────────────────────────────────────

describe('SSOClientError shape', () => {
    it('should have code and name fields', () => {
        const err = new SSOClientError('test', 'SSO_CLIENT_UNKNOWN_ERROR');
        expect(err.code).toBe('SSO_CLIENT_UNKNOWN_ERROR');
        expect(err.name).toBe('SSOClientError');
        expect(err.message).toBe('test');
    });

    it('should store cause when provided', () => {
        const cause = new Error('original');
        const err = new SSOClientError('wrapped', 'SSO_CLIENT_SAML_CALLBACK_FAILED', cause);
        expect((err as { cause?: unknown }).cause).toBe(cause);
    });

    it('should have undefined cause when not provided', () => {
        const err = new SSOClientError('no cause', 'SSO_CLIENT_FEDERATION_FAILED');
        expect((err as { cause?: unknown }).cause).toBeUndefined();
    });
});

// ── initiateLogin ──────────────────────────────────────────────────────────────

describe('SSOClient.initiateLogin', () => {
    let samlPort: SamlPort;
    let oidcPort: OidcPort;
    let federationPort: FederationPort;
    let clientSamlOnly: SSOClient;
    let clientOidcOnly: SSOClient;
    let clientBoth: SSOClient;

    beforeEach(() => {
        samlPort = makeSamlPort();
        oidcPort = makeOidcPort();
        federationPort = makeFederationPort();
        clientSamlOnly = new SSOClient({ samlPort, federationPort });
        clientOidcOnly = new SSOClient({ oidcPort, federationPort });
        clientBoth = new SSOClient({ samlPort, oidcPort, federationPort });
    });

    it('should return redirectUrl with protocol=saml when SAML succeeds', async () => {
        vi.mocked(samlPort).getAuthorizeUrl.mockResolvedValue('https://idp.example.com/sso/saml');
        const result = await clientBoth.initiateLogin({ protocol: 'saml' });
        expect(result.redirectUrl).toBe('https://idp.example.com/sso/saml');
        expect(result.protocol).toBe('saml');
        expect(result.oidcState).toBeUndefined();
        expect(result.oidcNonce).toBeUndefined();
    });

    it('should throw SSO_CLIENT_SAML_LOGIN_FAILED when samlPort not configured', async () => {
        await expect(clientOidcOnly.initiateLogin({ protocol: 'saml' }))
            .rejects.toMatchObject({
                code: 'SSO_CLIENT_SAML_LOGIN_FAILED',
                name: 'SSOClientError',
            });
    });

    it('should throw SSO_CLIENT_SAML_LOGIN_FAILED when samlPort.getAuthorizeUrl throws', async () => {
        vi.mocked(samlPort).getAuthorizeUrl.mockRejectedValue(new Error('SAML IdP unavailable'));
        await expect(clientSamlOnly.initiateLogin({ protocol: 'saml' }))
            .rejects.toMatchObject({ code: 'SSO_CLIENT_SAML_LOGIN_FAILED' });
    });

    it('should return redirectUrl + oidcState + oidcNonce when OIDC succeeds', async () => {
        vi.mocked(oidcPort).getAuthorizeUrl.mockResolvedValue('https://idp.example.com/oidc/auth?state=x');
        const result = await clientBoth.initiateLogin({ protocol: 'oidc' });
        expect(result.redirectUrl).toBe('https://idp.example.com/oidc/auth?state=x');
        expect(result.protocol).toBe('oidc');
        expect(typeof result.oidcState).toBe('string');
        expect(typeof result.oidcNonce).toBe('string');
        expect(result.oidcState!.length).toBeGreaterThan(0);
        expect(result.oidcNonce!.length).toBeGreaterThan(0);
    });

    it('should throw SSO_CLIENT_OIDC_LOGIN_FAILED when oidcPort not configured', async () => {
        await expect(clientSamlOnly.initiateLogin({ protocol: 'oidc' }))
            .rejects.toMatchObject({ code: 'SSO_CLIENT_OIDC_LOGIN_FAILED' });
    });

    it('should throw SSO_CLIENT_OIDC_LOGIN_FAILED when oidcPort.getAuthorizeUrl throws', async () => {
        vi.mocked(oidcPort).getAuthorizeUrl.mockRejectedValue(new Error('OIDC provider unreachable'));
        await expect(clientOidcOnly.initiateLogin({ protocol: 'oidc' }))
            .rejects.toMatchObject({ code: 'SSO_CLIENT_OIDC_LOGIN_FAILED' });
    });

    it('should throw SSO_CLIENT_IDP_TYPE_INVALID when unknown protocol value provided at runtime', async () => {
        // Runtime guard: simulate a JS consumer or `as any` cast passing an illegal protocol value
        const req = { protocol: 'oauth1' } as unknown as InitiateLoginRequest;
        await expect(clientBoth.initiateLogin(req))
            .rejects.toMatchObject({ code: 'SSO_CLIENT_IDP_TYPE_INVALID' });
    });

    it('should pass state and nonce to oidcPort.getAuthorizeUrl', async () => {
        vi.mocked(oidcPort).getAuthorizeUrl.mockResolvedValue('https://idp.example.com/oidc/auth');
        const result = await clientOidcOnly.initiateLogin({ protocol: 'oidc' });
        const callArg = vi.mocked(oidcPort).getAuthorizeUrl.mock.calls[0][0];
        expect(callArg.state).toBe(result.oidcState);
        expect(callArg.nonce).toBe(result.oidcNonce);
    });
});

// ── resolveAuthentication — SAML ───────────────────────────────────────────────

describe('SSOClient.resolveAuthentication (SAML)', () => {
    let samlPort: SamlPort;
    let federationPort: FederationPort;
    let client: SSOClient;

    /** Standard SAML callback body (includes the SAMLResponse parameter) */
    const samlBody: Record<string, string> = { SAMLResponse: 'base64encodedresponse' };

    /**
     * The SamlUserClaims-shaped object returned by verifyResponse.
     * Note: SamlPort.verifyResponse returns a raw node-saml profile (nameID/nameIDFormat, etc.);
     * the unit-test mock should match what production NodeSamlAdapter.verifyResponse actually returns (raw node-saml profile field names);
     * sdk-api.ts calls parseSamlClaims(rawProfile, idpIdentifier) to perform the normalization conversion.
     */
    function makeSamlProfile() {
        return {
            nameID: 'alice@example.com',
            nameIDFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
            // node-saml@5.x catch-all allows it; present after NodeSamlAdapter.verifyResponse injects audience
            audience: 'https://sp.example.com/saml',
            // node-saml raw attribute keys (the attribute key + value in the actual SAML AttributeStatement)
            tenant_id: 'tenant-111',
            role: 'operator',
        };
    }

    beforeEach(() => {
        samlPort = makeSamlPort();
        federationPort = makeFederationPort();
        client = new SSOClient({ samlPort, federationPort });
    });

    it('should return FederationResolution when SAML callback succeeds', async () => {
        vi.mocked(samlPort).verifyResponse.mockResolvedValue(makeSamlProfile() as Record<string, unknown>);
        const resolution = makeResolution();
        // Mock TenantFederationProvider.resolveTenant directly through federationPort
        vi.mocked(federationPort).findIdpMapping.mockResolvedValue({
            id: 'map-1',
            idpIdentifier: 'https://idp.example.com/saml/metadata',
            idpType: 'saml',
            allowedTenantIds: ['tenant-111'],
            createdAt: '2026-01-01T00:00:00Z',
            updatedAt: '2026-01-01T00:00:00Z',
        });
        vi.mocked(federationPort).findTenantById.mockResolvedValue({
            id: 'tenant-111',
            name: 'Test Tenant',
            createdAt: '2026-01-01T00:00:00Z',
        });
        vi.mocked(federationPort).findUserByExternalSubject.mockResolvedValue({
            id: resolution.userId,
            tenantId: resolution.tenantId,
            role: resolution.role,
            externalSubject: 'alice@example.com',
            idpIdentifier: 'https://idp.example.com/saml/metadata',
            createdAt: '2026-01-01T00:00:00Z',
        });
        vi.mocked(federationPort).writeAuditEvent.mockResolvedValue(undefined);
        const req: ResolveAuthenticationRequest = {
            protocol: 'saml',
            body: samlBody,
            idpIdentifier: 'https://idp.example.com/saml/metadata',
        };
        const result = await client.resolveAuthentication(req);
        expect(result.protocol).toBe('saml');
        expect(result.resolution.tenantId).toBe('tenant-111');
        expect(result.resolution.role).toBe('operator');
    });

    it('should throw SSO_CLIENT_SAML_CALLBACK_FAILED when samlPort not configured', async () => {
        const clientNoSaml = new SSOClient({ federationPort });
        const req: ResolveAuthenticationRequest = {
            protocol: 'saml',
            body: samlBody,
            idpIdentifier: 'https://idp.example.com/saml/metadata',
        };
        await expect(clientNoSaml.resolveAuthentication(req))
            .rejects.toMatchObject({ code: 'SSO_CLIENT_SAML_CALLBACK_FAILED' });
    });

    it('should throw SSO_CLIENT_SAML_CALLBACK_FAILED when samlPort.verifyResponse throws', async () => {
        vi.mocked(samlPort).verifyResponse.mockRejectedValue(new Error('Invalid SAML signature'));
        const req: ResolveAuthenticationRequest = {
            protocol: 'saml',
            body: samlBody,
            idpIdentifier: 'https://idp.example.com/saml/metadata',
        };
        await expect(client.resolveAuthentication(req))
            .rejects.toMatchObject({ code: 'SSO_CLIENT_SAML_CALLBACK_FAILED' });
    });

    it('should throw SSO_CLIENT_SAML_CALLBACK_FAILED when parseSamlUserClaims fails (missing nameID)', async () => {
        // Return a profile without the required fields → parseSamlUserClaims throws
        vi.mocked(samlPort).verifyResponse.mockResolvedValue({ issuer: 'x', attributes: {} } as Record<string, unknown>);
        const req: ResolveAuthenticationRequest = {
            protocol: 'saml',
            body: samlBody,
            idpIdentifier: 'https://idp.example.com/saml/metadata',
        };
        await expect(client.resolveAuthentication(req))
            .rejects.toMatchObject({ code: 'SSO_CLIENT_SAML_CALLBACK_FAILED' });
    });

    it('should throw SSO_CLIENT_FEDERATION_FAILED when federation resolveTenant fails', async () => {
        // verifyResponse + parseSamlUserClaims succeed; federation fails because the IDP is not registered
        vi.mocked(samlPort).verifyResponse.mockResolvedValue(makeSamlProfile() as Record<string, unknown>);
        vi.mocked(federationPort).findIdpMapping.mockResolvedValue(null); // IDP_NOT_REGISTERED
        const req: ResolveAuthenticationRequest = {
            protocol: 'saml',
            body: samlBody,
            idpIdentifier: 'https://idp.example.com/saml/metadata',
        };
        await expect(client.resolveAuthentication(req))
            .rejects.toMatchObject({ code: 'SSO_CLIENT_FEDERATION_FAILED' });
    });
});

// ── resolveAuthentication — OIDC ───────────────────────────────────────────────

describe('SSOClient.resolveAuthentication (OIDC)', () => {
    let oidcPort: OidcPort;
    let federationPort: FederationPort;
    let client: SSOClient;

    /**
     * Note: OidcPort.verifyCallback returns raw id_token claims (OIDC standard field names like iss/aud/exp);
     * the unit-test mock should match what production OpenIdClientAdapter.verifyCallback actually returns (the raw id_token JWT Claims Set);
     * sdk-api.ts extracts iss + the first aud + calls parseOidcClaims(rawClaims, iss, aud) to normalize.
     */
    function makeTokenResponse() {
        return {
            claims: {
                sub: 'alice@example.com',
                iss: 'https://idp.example.com/oidc',
                aud: 'client-app',
                exp: Math.floor(Date.now() / 1000) + 3600,
                iat: Math.floor(Date.now() / 1000),
                // raw OIDC claim keys (custom attributes; not reserved OIDC standard fields)
                tenant_id: 'tenant-111',
                role: 'operator',
            },
        };
    }

    beforeEach(() => {
        oidcPort = makeOidcPort();
        federationPort = makeFederationPort();
        client = new SSOClient({ oidcPort, federationPort });
    });

    it('should return FederationResolution when OIDC callback succeeds', async () => {
        vi.mocked(oidcPort).verifyCallback.mockResolvedValue(makeTokenResponse());
        vi.mocked(federationPort).findIdpMapping.mockResolvedValue({
            id: 'map-2',
            idpIdentifier: 'https://idp.example.com/oidc',
            idpType: 'oidc',
            allowedTenantIds: ['tenant-111'],
            createdAt: '2026-01-01T00:00:00Z',
            updatedAt: '2026-01-01T00:00:00Z',
        });
        vi.mocked(federationPort).findTenantById.mockResolvedValue({
            id: 'tenant-111',
            name: 'Test Tenant',
            createdAt: '2026-01-01T00:00:00Z',
        });
        vi.mocked(federationPort).findUserByExternalSubject.mockResolvedValue({
            id: 'user-222',
            tenantId: 'tenant-111',
            role: 'operator',
            externalSubject: 'alice@example.com',
            idpIdentifier: 'https://idp.example.com/oidc',
            createdAt: '2026-01-01T00:00:00Z',
        });
        vi.mocked(federationPort).writeAuditEvent.mockResolvedValue(undefined);
        const req: ResolveAuthenticationRequest = {
            protocol: 'oidc',
            currentUrl: 'https://app.example.com/callback?code=xxx&state=yyy',
            expectedState: 'yyy',
            expectedNonce: 'test-nonce',
            idpIdentifier: 'https://idp.example.com/oidc',
        };
        const result = await client.resolveAuthentication(req);
        expect(result.protocol).toBe('oidc');
        expect(result.resolution.tenantId).toBe('tenant-111');
    });

    it('should throw SSO_CLIENT_OIDC_CALLBACK_FAILED when oidcPort not configured', async () => {
        const clientNoOidc = new SSOClient({ federationPort });
        const req: ResolveAuthenticationRequest = {
            protocol: 'oidc',
            currentUrl: 'https://app.example.com/callback?code=xxx',
            expectedState: 'state-1',
            expectedNonce: 'nonce-1',
            idpIdentifier: 'https://idp.example.com/oidc',
        };
        await expect(clientNoOidc.resolveAuthentication(req))
            .rejects.toMatchObject({ code: 'SSO_CLIENT_OIDC_CALLBACK_FAILED' });
    });

    it('should throw SSO_CLIENT_OIDC_CALLBACK_FAILED when oidcPort.verifyCallback throws', async () => {
        vi.mocked(oidcPort).verifyCallback.mockRejectedValue(new Error('id_token expired'));
        const req: ResolveAuthenticationRequest = {
            protocol: 'oidc',
            currentUrl: 'https://app.example.com/callback?code=xxx',
            expectedState: 'state-1',
            expectedNonce: 'nonce-1',
            idpIdentifier: 'https://idp.example.com/oidc',
        };
        await expect(client.resolveAuthentication(req))
            .rejects.toMatchObject({ code: 'SSO_CLIENT_OIDC_CALLBACK_FAILED' });
    });

    it('should throw SSO_CLIENT_FEDERATION_FAILED when federation resolveTenant fails for OIDC', async () => {
        // verifyCallback + parseOidcUserClaims succeed; federation fails because the IDP is not registered
        vi.mocked(oidcPort).verifyCallback.mockResolvedValue(makeTokenResponse());
        vi.mocked(federationPort).findIdpMapping.mockResolvedValue(null); // IDP_NOT_REGISTERED
        const req: ResolveAuthenticationRequest = {
            protocol: 'oidc',
            currentUrl: 'https://app.example.com/callback?code=xxx',
            expectedState: 'state-1',
            expectedNonce: 'nonce-1',
            idpIdentifier: 'https://idp.example.com/oidc',
        };
        await expect(client.resolveAuthentication(req))
            .rejects.toMatchObject({ code: 'SSO_CLIENT_FEDERATION_FAILED' });
    });
});

// ── logout ─────────────────────────────────────────────────────────────────────

describe('SSOClient.logout', () => {
    const logoutContext = {
        userId: 'user-111',
        tenantId: 'tenant-111',
        idpIdentifier: 'https://idp.example.com/saml/metadata',
        externalSubject: 'alice@example.com',
    };

    it('should return redirectUrl when SAML logout succeeds', async () => {
        const samlPort = makeSamlPort();
        const federationPort = makeFederationPort();
        vi.mocked(samlPort).getLogoutUrl.mockResolvedValue('https://idp.example.com/sso/saml/logout');
        vi.mocked(federationPort).writeAuditEvent.mockResolvedValue(undefined);
        const client = new SSOClient({ samlPort, federationPort });
        const req: LogoutRequest = {
            protocol: 'saml',
            context: logoutContext,
        };
        const result = await client.logout(req);
        expect(result.redirectUrl).toBe('https://idp.example.com/sso/saml/logout');
    });

    it('should throw SSO_CLIENT_LOGOUT_FAILED when samlPort not configured', async () => {
        const federationPort = makeFederationPort();
        const clientNoSaml = new SSOClient({ federationPort });
        const req: LogoutRequest = {
            protocol: 'saml',
            context: logoutContext,
        };
        await expect(clientNoSaml.logout(req))
            .rejects.toMatchObject({ code: 'SSO_CLIENT_LOGOUT_FAILED' });
    });

    it('should throw SSO_CLIENT_LOGOUT_FAILED when samlPort.getLogoutUrl throws', async () => {
        const samlPort = makeSamlPort();
        const federationPort = makeFederationPort();
        vi.mocked(samlPort).getLogoutUrl.mockRejectedValue(new Error('SLO not supported'));
        const client = new SSOClient({ samlPort, federationPort });
        const req: LogoutRequest = {
            protocol: 'saml',
            context: logoutContext,
        };
        await expect(client.logout(req))
            .rejects.toMatchObject({ code: 'SSO_CLIENT_LOGOUT_FAILED' });
    });

    it('should return redirectUrl when OIDC logout succeeds', async () => {
        const oidcPort = makeOidcPort();
        const federationPort = makeFederationPort();
        vi.mocked(oidcPort).getEndSessionUrl.mockResolvedValue('https://idp.example.com/oidc/logout');
        vi.mocked(federationPort).writeAuditEvent.mockResolvedValue(undefined);
        const client = new SSOClient({ oidcPort, federationPort });
        const req: LogoutRequest = {
            protocol: 'oidc',
            context: { ...logoutContext, idpIdentifier: 'https://idp.example.com/oidc' },
            oidcIdTokenHint: 'id-token-hint-value',
        };
        const result = await client.logout(req);
        expect(result.redirectUrl).toBe('https://idp.example.com/oidc/logout');
    });

    it('should throw SSO_CLIENT_LOGOUT_FAILED when oidcPort.getEndSessionUrl throws', async () => {
        const oidcPort = makeOidcPort();
        const federationPort = makeFederationPort();
        vi.mocked(oidcPort).getEndSessionUrl.mockRejectedValue(new Error('end_session not supported'));
        const client = new SSOClient({ oidcPort, federationPort });
        const req: LogoutRequest = {
            protocol: 'oidc',
            context: { ...logoutContext, idpIdentifier: 'https://idp.example.com/oidc' },
        };
        await expect(client.logout(req))
            .rejects.toMatchObject({ code: 'SSO_CLIENT_LOGOUT_FAILED' });
    });

    it('should not throw when audit writeAuditEvent fails (degraded mode)', async () => {
        const samlPort = makeSamlPort();
        const federationPort = makeFederationPort();
        vi.mocked(samlPort).getLogoutUrl.mockResolvedValue('https://idp.example.com/slo');
        // The audit write throws; it should not block the main flow
        vi.mocked(federationPort).writeAuditEvent.mockRejectedValue(new Error('DB write error'));
        const client = new SSOClient({ samlPort, federationPort });
        const req: LogoutRequest = {
            protocol: 'saml',
            context: logoutContext,
        };
        await expect(client.logout(req)).resolves.toMatchObject({
            redirectUrl: 'https://idp.example.com/slo',
        });
    });
});
