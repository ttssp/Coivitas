/**
 * cryptographic-verifier unit tests — sdk v0.2 L2 identity factory, all paths
 *
 * Summary: covers the 4 scope main paths + fail-closed security constraint verification, ensuring each layer of the triple defense behaves correctly.
 *
 * Coverage matrix:
 *   Scope A — jwt-helpers: verifyJwtAlgAllowed (pure function; no external dependencies)
 *   Scope B — boundary-check: all paths of 4 functions (pure functions; no external dependencies)
 *   Scope C — oauth2-helpers: OAuth2IntrospectionCache + OAuth2CircuitBreaker + OAuth2RateLimiter
 *   Scope D — verify-jwt: verifyJwtAndDeriveDid (vi.mock the jose module)
 *   Scope E — verify-oauth2: verifyOAuth2AndDeriveDid (dependency-injected opts; no vi.mock needed)
 *   Scope F — verify-mtls: verifyMtlsAndDeriveDid (vi.mock mtls-helpers)
 *
 * Security constraint verification (fail-closed required):
 *   - all verify failure paths -> a specific SDK_* error code SdkError (must carry errorCode)
 *   - denylist alg ('none') -> SDK_JWT_VERIFY_FAILED
 *   - introspection active !== true -> SDK_OAUTH2_VERIFY_FAILED
 *   - circuit breaker OPEN -> SDK_OAUTH2_VERIFY_FAILED (does not call upstream)
 *   - rate limit exceeded -> SDK_OAUTH2_VERIFY_FAILED
 *   - DID mismatch -> SDK_MAPPING_MISMATCH
 *   - sdkVersion not "2.0.0" -> SDK_SCHEMA_VIOLATION
 *
 * Test naming convention: "should <expected result> when <condition>"
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { SdkError } from '@coivitas/types';
import type { DID, VerifiedTransportContext } from '@coivitas/types';

// ─── Scope A: jwt-helpers ─────────────────────────────────────────────────────
import {
    JWT_ALG_ALLOWLIST,
    JWT_ALG_DENYLIST,
    verifyJwtAlgAllowed,
} from '../cryptographic-verifier/jwt-helpers.js';

// ─── Scope B: boundary-check ──────────────────────────────────────────────────
import {
    assertTrustedDidMatchesExpected,
    assertTrustedDidIsKindAndFresh,
    extractDidFromCertSubjectDn,
    assertCrossCheckMappingConsistent,
} from '../cryptographic-verifier/boundary-check.js';

// ─── Scope C: oauth2-helpers ──────────────────────────────────────────────────
import {
    OAuth2IntrospectionCache,
    OAuth2CircuitBreaker,
    OAuth2RateLimiter,
} from '../cryptographic-verifier/oauth2-helpers.js';

// ─── Scope D: verify-jwt (vi.mock jose) ───────────────────────────────────────
import { verifyJwtAndDeriveDid } from '../cryptographic-verifier/verify-jwt.js';

// ─── Scope E: verify-oauth2 (dependency injection; no vi.mock) ────────────────────────────
import { verifyOAuth2AndDeriveDid } from '../cryptographic-verifier/verify-oauth2.js';
import type { IntrospectionResponse } from 'openid-client';

// ─── Scope F: verify-mtls (vi.mock mtls-helpers) ─────────────────────────────
import { verifyMtlsAndDeriveDid } from '../cryptographic-verifier/verify-mtls.js';

// ─────────────────────────────────────────────────────────────────────────────
// vi.mock — jose (Scope D)
// Summary: createRemoteJWKSet + jwtVerify are top-level exports of the jose module; vi.mock stubs them all
// ─────────────────────────────────────────────────────────────────────────────
vi.mock('jose', () => ({
    createRemoteJWKSet: vi.fn(),
    jwtVerify: vi.fn(),
}));

// ─────────────────────────────────────────────────────────────────────────────
// vi.mock — mtls-helpers (Scope F)
// Summary: parseX509Cert / validateCertChain / extractDidFromCertSubject are all stubbed
// ─────────────────────────────────────────────────────────────────────────────
vi.mock('../cryptographic-verifier/mtls-helpers.js', () => ({
    parseX509Cert: vi.fn(),
    validateCertChain: vi.fn(),
    extractDidFromCertSubject: vi.fn(),
}));

// ─────────────────────────────────────────────────────────────────────────────
// shared test constants
// ─────────────────────────────────────────────────────────────────────────────
const VALID_DID = 'did:example:abc123' as DID;
const OTHER_DID = 'did:example:xyz999' as DID;

/** Build the base64url segment of an ES256 JWT header */
function makeJwtHeader(alg: string): string {
    return Buffer.from(JSON.stringify({ alg, typ: 'JWT' })).toString(
        'base64url',
    );
}

/** Build a minimal JWT compact string (header.payload.sig); the signature segment is filled with random data */
function makeCompactJwt(alg: string, payloadObj: object = {}): string {
    const header = makeJwtHeader(alg);
    const payload = Buffer.from(JSON.stringify(payloadObj)).toString(
        'base64url',
    );
    const sig = Buffer.from('fakesig').toString('base64url');
    return `${header}.${payload}.${sig}`;
}

/** Build a fresh VerifiedTransportContext (verifiedAt = now) */
function makeVerifiedCtx(
    overrides: Partial<VerifiedTransportContext> = {},
): VerifiedTransportContext {
    return {
        trustedDid:
            VALID_DID as unknown as VerifiedTransportContext['trustedDid'],
        verifierKind: 'jwt',
        verifiedSubject:
            VALID_DID as unknown as VerifiedTransportContext['verifiedSubject'],
        verifiedAt: new Date().toISOString(),
        sdkVersion: '2.0.0',
        ...overrides,
    };
}

// ─────────────────────────────────────────────────────────────────────────────
// Scope A: jwt-helpers — verifyJwtAlgAllowed
// ─────────────────────────────────────────────────────────────────────────────
describe('jwt-helpers — verifyJwtAlgAllowed', () => {
    it('should pass when JWT header alg is ES256 (valid asymmetric)', () => {
        const jwt = makeCompactJwt('ES256');
        // not throwing means PASS
        expect(() => verifyJwtAlgAllowed(jwt)).not.toThrow();
    });

    it('should pass when JWT header alg is EdDSA (valid asymmetric)', () => {
        const jwt = makeCompactJwt('EdDSA');
        expect(() => verifyJwtAlgAllowed(jwt)).not.toThrow();
    });

    it('should pass when JWT header alg is RS256 (valid asymmetric)', () => {
        const jwt = makeCompactJwt('RS256');
        expect(() => verifyJwtAlgAllowed(jwt)).not.toThrow();
    });

    it('should throw SDK_JWT_VERIFY_FAILED when alg is "none" (denylist)', () => {
        const jwt = makeCompactJwt('none');
        try {
            verifyJwtAlgAllowed(jwt);
            expect.fail('should have thrown');
        } catch (err) {
            expect(err).toBeInstanceOf(SdkError);
            expect((err as SdkError).code).toBe('SDK_JWT_VERIFY_FAILED');
            expect((err as SdkError).message).toMatch(/denylist/i);
        }
    });

    it('should throw SDK_JWT_VERIFY_FAILED when alg is "NONE" (denylist uppercase)', () => {
        const jwt = makeCompactJwt('NONE');
        try {
            verifyJwtAlgAllowed(jwt);
            expect.fail('should have thrown');
        } catch (err) {
            expect(err).toBeInstanceOf(SdkError);
            expect((err as SdkError).code).toBe('SDK_JWT_VERIFY_FAILED');
        }
    });

    it('should throw SDK_JWT_VERIFY_FAILED when alg is HS256 without allowSymmetric', () => {
        const jwt = makeCompactJwt('HS256');
        try {
            verifyJwtAlgAllowed(jwt);
            expect.fail('should have thrown');
        } catch (err) {
            expect(err).toBeInstanceOf(SdkError);
            expect((err as SdkError).code).toBe('SDK_JWT_VERIFY_FAILED');
            expect((err as SdkError).message).toMatch(/not in allowlist/i);
        }
    });

    it('should pass when alg is HS256 with allowSymmetric=true', () => {
        const jwt = makeCompactJwt('HS256');
        expect(() =>
            verifyJwtAlgAllowed(jwt, { allowSymmetric: true }),
        ).not.toThrow();
    });

    it('should throw SDK_JWT_VERIFY_FAILED when JWT is not compact format (no dots)', () => {
        try {
            verifyJwtAlgAllowed('notacompactjwt');
            expect.fail('should have thrown');
        } catch (err) {
            expect(err).toBeInstanceOf(SdkError);
            expect((err as SdkError).code).toBe('SDK_JWT_VERIFY_FAILED');
        }
    });

    it('should throw SDK_JWT_VERIFY_FAILED when header base64url is not valid JSON', () => {
        const badHeader = Buffer.from('not-json!!!').toString('base64url');
        const jwt = `${badHeader}.payload.sig`;
        try {
            verifyJwtAlgAllowed(jwt);
            expect.fail('should have thrown');
        } catch (err) {
            expect(err).toBeInstanceOf(SdkError);
            expect((err as SdkError).code).toBe('SDK_JWT_VERIFY_FAILED');
        }
    });

    it('should throw SDK_JWT_VERIFY_FAILED when alg is unknown (XYZ999)', () => {
        const jwt = makeCompactJwt('XYZ999');
        try {
            verifyJwtAlgAllowed(jwt);
            expect.fail('should have thrown');
        } catch (err) {
            expect(err).toBeInstanceOf(SdkError);
            expect((err as SdkError).code).toBe('SDK_JWT_VERIFY_FAILED');
        }
    });

    it('should export JWT_ALG_ALLOWLIST with expected asymmetric algorithms', () => {
        // Summary: confirm the allowlist contains 7 asymmetric algorithms
        expect(JWT_ALG_ALLOWLIST.asymmetric).toContain('ES256');
        expect(JWT_ALG_ALLOWLIST.asymmetric).toContain('RS256');
        expect(JWT_ALG_ALLOWLIST.asymmetric).toContain('EdDSA');
        expect(JWT_ALG_ALLOWLIST.asymmetric).toHaveLength(7);
    });

    it('should export JWT_ALG_DENYLIST containing none variants', () => {
        expect(JWT_ALG_DENYLIST).toContain('none');
        expect(JWT_ALG_DENYLIST).toContain('NONE');
        expect(JWT_ALG_DENYLIST).toContain('None');
    });
});

// ─────────────────────────────────────────────────────────────────────────────
// Scope B: boundary-check — all paths of 4 functions
// ─────────────────────────────────────────────────────────────────────────────
describe('boundary-check — assertTrustedDidMatchesExpected', () => {
    it('should pass when trustedDid equals expectedDid', () => {
        const ctx = makeVerifiedCtx();
        expect(() =>
            assertTrustedDidMatchesExpected(ctx.trustedDid, VALID_DID),
        ).not.toThrow();
    });

    it('should throw SDK_MAPPING_MISMATCH when trustedDid does not match expectedDid', () => {
        const ctx = makeVerifiedCtx();
        try {
            assertTrustedDidMatchesExpected(ctx.trustedDid, OTHER_DID);
            expect.fail('should have thrown');
        } catch (err) {
            expect(err).toBeInstanceOf(SdkError);
            expect((err as SdkError).code).toBe('SDK_MAPPING_MISMATCH');
        }
    });
});

describe('boundary-check — assertTrustedDidIsKindAndFresh', () => {
    it('should pass with fresh context + correct DID + expected verifier kind', () => {
        const ctx = makeVerifiedCtx({ verifierKind: 'jwt' });
        expect(() =>
            assertTrustedDidIsKindAndFresh(ctx, {
                did: VALID_DID,
                verifierKinds: ['jwt'],
            }),
        ).not.toThrow();
    });

    it('should throw SDK_MAPPING_MISMATCH when DID does not match', () => {
        const ctx = makeVerifiedCtx();
        try {
            assertTrustedDidIsKindAndFresh(ctx, {
                did: OTHER_DID,
                verifierKinds: ['jwt'],
            });
            expect.fail('should have thrown');
        } catch (err) {
            expect(err).toBeInstanceOf(SdkError);
            expect((err as SdkError).code).toBe('SDK_MAPPING_MISMATCH');
        }
    });

    it('should throw SDK_MAPPING_MISMATCH when verifierKind is not in expected set', () => {
        const ctx = makeVerifiedCtx({ verifierKind: 'mtls' });
        try {
            assertTrustedDidIsKindAndFresh(ctx, {
                did: VALID_DID,
                verifierKinds: ['jwt', 'oauth2'],
            });
            expect.fail('should have thrown');
        } catch (err) {
            expect(err).toBeInstanceOf(SdkError);
            expect((err as SdkError).code).toBe('SDK_MAPPING_MISMATCH');
        }
    });

    it('should throw SDK_SCHEMA_VIOLATION when verifiedAt is stale (> 60s ago)', () => {
        const staleTimestamp = new Date(Date.now() - 120_000).toISOString(); // 2 minutes ago
        const ctx = makeVerifiedCtx({ verifiedAt: staleTimestamp });
        try {
            assertTrustedDidIsKindAndFresh(ctx, {
                did: VALID_DID,
                verifierKinds: ['jwt'],
            });
            expect.fail('should have thrown');
        } catch (err) {
            expect(err).toBeInstanceOf(SdkError);
            expect((err as SdkError).code).toBe('SDK_SCHEMA_VIOLATION');
            expect((err as SdkError).message).toMatch(/stale/i);
        }
    });

    it('should throw SDK_SCHEMA_VIOLATION when verifiedAt is future timestamp', () => {
        const futureTimestamp = new Date(Date.now() + 120_000).toISOString(); // 2 minutes in future
        const ctx = makeVerifiedCtx({ verifiedAt: futureTimestamp });
        try {
            assertTrustedDidIsKindAndFresh(ctx, {
                did: VALID_DID,
                verifierKinds: ['jwt'],
            });
            expect.fail('should have thrown');
        } catch (err) {
            expect(err).toBeInstanceOf(SdkError);
            expect((err as SdkError).code).toBe('SDK_SCHEMA_VIOLATION');
            expect((err as SdkError).message).toMatch(/future/i);
        }
    });

    it('should throw SDK_SCHEMA_VIOLATION when sdkVersion is not "2.0.0"', () => {
        const ctx = makeVerifiedCtx({ sdkVersion: '1.0.0' });
        try {
            assertTrustedDidIsKindAndFresh(ctx, {
                did: VALID_DID,
                verifierKinds: ['jwt'],
            });
            expect.fail('should have thrown');
        } catch (err) {
            expect(err).toBeInstanceOf(SdkError);
            expect((err as SdkError).code).toBe('SDK_SCHEMA_VIOLATION');
            expect((err as SdkError).message).toMatch(/2\.0\.0/);
        }
    });

    it('should pass with custom freshness tolerance when verifiedAt is within custom window', () => {
        // Summary: 90s ago; the default tolerance of 60s would fail; a custom tolerance of 120s should PASS
        const timestamp = new Date(Date.now() - 90_000).toISOString();
        const ctx = makeVerifiedCtx({ verifiedAt: timestamp });
        expect(() =>
            assertTrustedDidIsKindAndFresh(ctx, {
                did: VALID_DID,
                verifierKinds: ['jwt'],
                freshnessToleranceSeconds: 120,
            }),
        ).not.toThrow();
    });
});

describe('boundary-check — extractDidFromCertSubjectDn', () => {
    it('should extract DID from SAN URI format "URI=did:..."', () => {
        const dn = 'CN=Example, URI=did:example:abc123, O=Acme';
        const result = extractDidFromCertSubjectDn(dn);
        expect(result).toBe('did:example:abc123');
    });

    it('should extract DID from SAN URI format "URI:did:..." (colon separator)', () => {
        const dn = 'CN=Example, URI:did:web:example.com, O=Acme';
        const result = extractDidFromCertSubjectDn(dn);
        expect(result).toBe('did:web:example.com');
    });

    it('should extract DID from CN= fallback when no SAN URI present', () => {
        const dn = 'CN=did:key:z6MkTestKeyAbc123, O=Acme';
        const result = extractDidFromCertSubjectDn(dn);
        expect(result).toBe('did:key:z6MkTestKeyAbc123');
    });

    it('should throw SDK_SCHEMA_VIOLATION when no DID found in subject DN', () => {
        const dn = 'CN=Example, O=Acme, C=US';
        try {
            extractDidFromCertSubjectDn(dn);
            expect.fail('should have thrown');
        } catch (err) {
            expect(err).toBeInstanceOf(SdkError);
            expect((err as SdkError).code).toBe('SDK_SCHEMA_VIOLATION');
        }
    });

    it('should throw SDK_SCHEMA_VIOLATION when multiple distinct DIDs found via SAN URI', () => {
        const dn = 'URI=did:example:first, URI=did:example:second, O=Acme';
        try {
            extractDidFromCertSubjectDn(dn);
            expect.fail('should have thrown');
        } catch (err) {
            expect(err).toBeInstanceOf(SdkError);
            expect((err as SdkError).code).toBe('SDK_SCHEMA_VIOLATION');
            expect((err as SdkError).message).toMatch(/multiple distinct DID/i);
        }
    });

    it('should pass when multiple SAN URI entries contain the same DID', () => {
        // Summary: the same DID appearing repeatedly should not be treated as a conflict
        const dn = 'URI=did:example:abc123, URI=did:example:abc123, O=Acme';
        const result = extractDidFromCertSubjectDn(dn);
        expect(result).toBe('did:example:abc123');
    });

    it('should prefer SAN URI over CN= when both present', () => {
        const dn = 'CN=did:example:from-cn, URI=did:example:from-uri, O=Acme';
        const result = extractDidFromCertSubjectDn(dn);
        expect(result).toBe('did:example:from-uri');
    });
});

describe('boundary-check — assertCrossCheckMappingConsistent', () => {
    it('should pass for jwt kind when verifiedSubject equals trustedDid', () => {
        const ctx = makeVerifiedCtx({
            verifierKind: 'jwt',
            verifiedSubject:
                VALID_DID as unknown as VerifiedTransportContext['verifiedSubject'],
        });
        expect(() => assertCrossCheckMappingConsistent(ctx)).not.toThrow();
    });

    it('should pass for oauth2 kind when verifiedSubject equals trustedDid', () => {
        const ctx = makeVerifiedCtx({
            verifierKind: 'oauth2',
            verifiedSubject:
                VALID_DID as unknown as VerifiedTransportContext['verifiedSubject'],
        });
        expect(() => assertCrossCheckMappingConsistent(ctx)).not.toThrow();
    });

    it('should throw SDK_MAPPING_MISMATCH for jwt kind when verifiedSubject does not match trustedDid', () => {
        const ctx = makeVerifiedCtx({
            verifierKind: 'jwt',
            verifiedSubject:
                OTHER_DID as unknown as VerifiedTransportContext['verifiedSubject'],
        });
        try {
            assertCrossCheckMappingConsistent(ctx);
            expect.fail('should have thrown');
        } catch (err) {
            expect(err).toBeInstanceOf(SdkError);
            expect((err as SdkError).code).toBe('SDK_MAPPING_MISMATCH');
        }
    });

    it('should pass for mtls kind when subject DN contains the trustedDid via CN=', () => {
        // verifiedSubject = cert subject DN string containing the DID via CN=
        const certDn = `CN=${VALID_DID as string}, O=Acme`;
        const ctx = makeVerifiedCtx({
            verifierKind: 'mtls',
            verifiedSubject:
                certDn as unknown as VerifiedTransportContext['verifiedSubject'],
        });
        expect(() => assertCrossCheckMappingConsistent(ctx)).not.toThrow();
    });

    it('should throw SDK_MAPPING_MISMATCH for mtls kind when extracted DID does not match trustedDid', () => {
        // verifiedSubject contains OTHER_DID but trustedDid is VALID_DID
        const certDn = `CN=${OTHER_DID as string}, O=Acme`;
        const ctx = makeVerifiedCtx({
            verifierKind: 'mtls',
            verifiedSubject:
                certDn as unknown as VerifiedTransportContext['verifiedSubject'],
        });
        try {
            assertCrossCheckMappingConsistent(ctx);
            expect.fail('should have thrown');
        } catch (err) {
            expect(err).toBeInstanceOf(SdkError);
            expect((err as SdkError).code).toBe('SDK_MAPPING_MISMATCH');
        }
    });

    it('should throw SDK_SCHEMA_VIOLATION for mtls kind when verifiedSubject is empty', () => {
        const ctx = makeVerifiedCtx({
            verifierKind: 'mtls',
            verifiedSubject:
                '' as unknown as VerifiedTransportContext['verifiedSubject'],
        });
        try {
            assertCrossCheckMappingConsistent(ctx);
            expect.fail('should have thrown');
        } catch (err) {
            expect(err).toBeInstanceOf(SdkError);
            expect((err as SdkError).code).toBe('SDK_SCHEMA_VIOLATION');
        }
    });
});

// ─────────────────────────────────────────────────────────────────────────────
// Scope C: oauth2-helpers — OAuth2IntrospectionCache / CircuitBreaker / RateLimiter
// ─────────────────────────────────────────────────────────────────────────────
describe('oauth2-helpers — OAuth2IntrospectionCache', () => {
    const AUTH_A = {
        issuerUrl: 'https://auth-a.example.com',
        introspectionEndpoint: 'https://auth-a.example.com/introspect',
        introspectionClientId: 'rs-a',
        expectedAudience: 'api-a',
    };
    const AUTH_B = {
        issuerUrl: 'https://attacker.example.com',
        introspectionEndpoint: 'https://attacker.example.com/introspect',
        introspectionClientId: 'rs-b',
        expectedAudience: 'api-b',
    };

    it('should call introspect on cache miss and cache the active response', async () => {
        const cache = new OAuth2IntrospectionCache(60);
        const mockResponse = {
            active: true,
            exp: Math.floor(Date.now() / 1000) + 3600,
        };
        const introspect = vi.fn().mockResolvedValue(mockResponse);

        const result1 = await cache.getOrIntrospect(
            AUTH_A,
            'token-abc',
            introspect,
        );
        expect(result1).toEqual(mockResponse);
        expect(introspect).toHaveBeenCalledOnce();

        // second call — should hit the cache (no further introspect call)
        const result2 = await cache.getOrIntrospect(
            AUTH_A,
            'token-abc',
            introspect,
        );
        expect(result2).toEqual(mockResponse);
        expect(introspect).toHaveBeenCalledOnce(); // still 1 time
    });

    it('should NOT reuse cache across different trust authorities', async () => {
        // the same token under different authorities must each go through real introspection
        const cache = new OAuth2IntrospectionCache(60);
        const respA = {
            active: true,
            exp: Math.floor(Date.now() / 1000) + 3600,
            client_id: 'a',
        };
        const respAttacker = {
            active: true,
            exp: Math.floor(Date.now() / 1000) + 3600,
            client_id: 'attacker',
        };
        const introspect = vi
            .fn()
            .mockResolvedValueOnce(respA)
            .mockResolvedValueOnce(respAttacker);

        const r1 = await cache.getOrIntrospect(
            AUTH_A,
            'same-token',
            introspect,
        );
        // same token but different authority (attacker endpoint) -> cache miss -> real introspection
        const r2 = await cache.getOrIntrospect(
            AUTH_B,
            'same-token',
            introspect,
        );

        expect(r1.client_id).toBe('a');
        expect(r2.client_id).toBe('attacker');
        expect(introspect).toHaveBeenCalledTimes(2); // cache is not reused across authorities
    });

    it('should not reuse cache across different issuerUrl when endpoint/clientId/audience match', async () => {
        // the real network authority is issuerUrl (the discovery entry point).
        // even if endpoint/clientId/audience are identical, different issuers must each go through real introspection.
        const cache = new OAuth2IntrospectionCache(60);
        const issuerA = {
            issuerUrl: 'https://issuer-a.example.com',
            introspectionEndpoint: 'https://shared.example.com/introspect',
            introspectionClientId: 'rs-shared',
            expectedAudience: 'api-shared',
        };
        const issuerB = {
            ...issuerA,
            issuerUrl: 'https://issuer-b.example.com',
        };
        const respA = {
            active: true,
            exp: Math.floor(Date.now() / 1000) + 3600,
            client_id: 'from-a',
        };
        const respB = {
            active: true,
            exp: Math.floor(Date.now() / 1000) + 3600,
            client_id: 'from-b',
        };
        const introspect = vi
            .fn()
            .mockResolvedValueOnce(respA)
            .mockResolvedValueOnce(respB);

        const r1 = await cache.getOrIntrospect(issuerA, 'tok', introspect);
        const r2 = await cache.getOrIntrospect(issuerB, 'tok', introspect);

        expect(r1.client_id).toBe('from-a');
        expect(r2.client_id).toBe('from-b');
        expect(introspect).toHaveBeenCalledTimes(2); // cache is not reused across different issuers
    });

    it('should call introspect each time when response active is false (not cached)', async () => {
        const cache = new OAuth2IntrospectionCache(60);
        const mockResponse = { active: false };
        const introspect = vi.fn().mockResolvedValue(mockResponse);

        await cache.getOrIntrospect(AUTH_A, 'token-inactive', introspect);
        await cache.getOrIntrospect(AUTH_A, 'token-inactive', introspect);

        // inactive responses are not cached -> introspect is called every time
        expect(introspect).toHaveBeenCalledTimes(2);
    });

    it('should use different cache keys for different tokens', async () => {
        const cache = new OAuth2IntrospectionCache(60);
        const resp1 = {
            active: true,
            exp: Math.floor(Date.now() / 1000) + 3600,
            client_id: 'client1',
        };
        const resp2 = {
            active: true,
            exp: Math.floor(Date.now() / 1000) + 3600,
            client_id: 'client2',
        };
        const introspect = vi
            .fn()
            .mockResolvedValueOnce(resp1)
            .mockResolvedValueOnce(resp2);

        const r1 = await cache.getOrIntrospect(AUTH_A, 'token-1', introspect);
        const r2 = await cache.getOrIntrospect(AUTH_A, 'token-2', introspect);

        expect(r1.client_id).toBe('client1');
        expect(r2.client_id).toBe('client2');
        expect(introspect).toHaveBeenCalledTimes(2);
    });
});

describe('oauth2-helpers — OAuth2CircuitBreaker', () => {
    it('should allow calls when circuit is CLOSED', async () => {
        const cb = new OAuth2CircuitBreaker(5, 60);
        const result = await cb.execute(() => Promise.resolve('success'));
        expect(result).toBe('success');
        expect(cb.getState().state).toBe('CLOSED');
    });

    it('should transition to OPEN after failureThreshold consecutive failures', async () => {
        const cb = new OAuth2CircuitBreaker(3, 60);
        const failOp = () => Promise.reject(new Error('upstream error'));

        // 3 failures
        for (let i = 0; i < 3; i++) {
            await expect(cb.execute(failOp)).rejects.toThrow();
        }

        expect(cb.getState().state).toBe('OPEN');
    });

    it('should throw SDK_OAUTH2_VERIFY_FAILED when circuit is OPEN (fail-closed)', async () => {
        const cb = new OAuth2CircuitBreaker(1, 3600); // 1 failure → OPEN; 3600s cooldown
        const failOp = () => Promise.reject(new Error('upstream error'));
        await expect(cb.execute(failOp)).rejects.toThrow(); // trigger OPEN

        try {
            await cb.execute(() => Promise.resolve('should not reach'));
            expect.fail('should have thrown');
        } catch (err) {
            expect(err).toBeInstanceOf(SdkError);
            expect((err as SdkError).code).toBe('SDK_OAUTH2_VERIFY_FAILED');
            expect((err as SdkError).message).toMatch(/OPEN/);
        }
    });

    it('should reset to CLOSED when HALF_OPEN operation succeeds', async () => {
        const cb = new OAuth2CircuitBreaker(1, 0); // cooldown = 0ms -> HALF_OPEN immediately available
        const failOp = () => Promise.reject(new Error('fail'));
        await expect(cb.execute(failOp)).rejects.toThrow(); // trigger OPEN

        // cooldown = 0 -> next execute transitions to HALF_OPEN -> success -> CLOSED
        const result = await cb.execute(() => Promise.resolve('recovered'));
        expect(result).toBe('recovered');
        expect(cb.getState().state).toBe('CLOSED');
        expect(cb.getState().failCount).toBe(0);
    });
});

describe('oauth2-helpers — OAuth2RateLimiter', () => {
    it('should allow consume when tokens are available', () => {
        const limiter = new OAuth2RateLimiter(100, 100);
        // not throwing means PASS (100 tokens available)
        expect(() => limiter.consume()).not.toThrow();
    });

    it('should throw SDK_OAUTH2_VERIFY_FAILED when rate limit exceeded', () => {
        // Summary: capacity=1 refillPerSec=0 -> the 2nd consume should fail
        const limiter = new OAuth2RateLimiter(1, 0);
        limiter.consume(); // consume the only available token

        try {
            limiter.consume(); // no token available -> throw
            expect.fail('should have thrown');
        } catch (err) {
            expect(err).toBeInstanceOf(SdkError);
            expect((err as SdkError).code).toBe('SDK_OAUTH2_VERIFY_FAILED');
            expect((err as SdkError).message).toMatch(/rate limit/i);
        }
    });
});

// ─────────────────────────────────────────────────────────────────────────────
// Scope D: verify-jwt — verifyJwtAndDeriveDid (vi.mock jose)
// ─────────────────────────────────────────────────────────────────────────────
describe('verify-jwt — verifyJwtAndDeriveDid', () => {
    // Summary: get references to the mocked functions from the vi.mock jose
    let mockJwtVerify: ReturnType<typeof vi.fn>;
    let mockCreateRemoteJWKSet: ReturnType<typeof vi.fn>;

    beforeEach(async () => {
        // dynamically import the jose that has been intercepted by vi.mock
        const jose = await import('jose');
        mockJwtVerify = jose.jwtVerify as unknown as ReturnType<typeof vi.fn>;
        mockCreateRemoteJWKSet =
            jose.createRemoteJWKSet as unknown as ReturnType<typeof vi.fn>;
        vi.clearAllMocks();
    });

    it('should return VerifiedTransportContext when JWT is valid and sub matches expectedDid', async () => {
        const jwt = makeCompactJwt('ES256', { sub: VALID_DID as string });
        const mockJwks = { keys: [] };

        mockCreateRemoteJWKSet.mockReturnValue(mockJwks);
        mockJwtVerify.mockResolvedValue({
            payload: {
                sub: VALID_DID as string,
                iss: 'https://example.com',
                aud: 'myapi',
                exp: Math.floor(Date.now() / 1000) + 3600,
            },
            protectedHeader: { alg: 'ES256' },
        });

        const ctx = await verifyJwtAndDeriveDid({
            jwt,
            jwks: 'https://example.com/.well-known/jwks.json',
            expectedIssuer: 'https://example.com',
            expectedAudience: 'myapi',
            expectedDid: VALID_DID,
        });

        expect(ctx.trustedDid).toBe(VALID_DID);
        expect(ctx.verifierKind).toBe('jwt');
        expect(ctx.verifiedSubject).toBe(VALID_DID);
        expect(ctx.sdkVersion).toBe('2.0.0');
        expect(ctx.verifiedAt).toBeTruthy();
    });

    it('should throw SDK_JWT_VERIFY_FAILED when payload.exp is missing (non-expiring token)', async () => {
        // a signed token without exp must be fail-closed
        const jwt = makeCompactJwt('ES256');
        const mockJwks = { keys: [] };
        mockCreateRemoteJWKSet.mockReturnValue(mockJwks);
        mockJwtVerify.mockResolvedValue({
            payload: {
                sub: VALID_DID as string,
                iss: 'https://example.com',
                aud: 'myapi',
            }, // no exp
            protectedHeader: { alg: 'ES256' },
        });
        try {
            await verifyJwtAndDeriveDid({
                jwt,
                jwks: 'https://example.com/.well-known/jwks.json',
                expectedIssuer: 'https://example.com',
                expectedAudience: 'myapi',
                expectedDid: VALID_DID,
            });
            expect.fail('should have thrown');
        } catch (err) {
            expect(err).toBeInstanceOf(SdkError);
            expect((err as SdkError).code).toBe('SDK_JWT_VERIFY_FAILED');
            expect((err as SdkError).message).toMatch(/exp/i);
        }
    });

    it('should throw SDK_JWT_VERIFY_FAILED when alg is "none" (Step 0 denylist)', async () => {
        // Summary: the verifyJwtAlgAllowed precheck runs before jose jwtVerify; alg=none -> throw directly
        const jwt = makeCompactJwt('none');
        try {
            await verifyJwtAndDeriveDid({
                jwt,
                jwks: 'https://example.com/.well-known/jwks.json',
                expectedIssuer: 'https://example.com',
                expectedAudience: 'myapi',
                expectedDid: VALID_DID,
            });
            expect.fail('should have thrown');
        } catch (err) {
            expect(err).toBeInstanceOf(SdkError);
            expect((err as SdkError).code).toBe('SDK_JWT_VERIFY_FAILED');
        }
        // Summary: jose jwtVerify should not be called (Step 0 prechecks intercept it)
        expect(mockJwtVerify).not.toHaveBeenCalled();
    });

    it('should throw SDK_JWT_VERIFY_FAILED when jose jwtVerify rejects (signature invalid)', async () => {
        const jwt = makeCompactJwt('ES256');
        const mockJwks = { keys: [] };

        mockCreateRemoteJWKSet.mockReturnValue(mockJwks);
        mockJwtVerify.mockRejectedValue(
            new Error('JWSSignatureVerificationFailed'),
        );

        try {
            await verifyJwtAndDeriveDid({
                jwt,
                jwks: 'https://example.com/.well-known/jwks.json',
                expectedIssuer: 'https://example.com',
                expectedAudience: 'myapi',
                expectedDid: VALID_DID,
            });
            expect.fail('should have thrown');
        } catch (err) {
            expect(err).toBeInstanceOf(SdkError);
            expect((err as SdkError).code).toBe('SDK_JWT_VERIFY_FAILED');
            expect((err as SdkError).message).toMatch(/JWT verify failed/i);
        }
    });

    it('should throw SDK_JWT_VERIFY_FAILED when payload.sub is missing', async () => {
        const jwt = makeCompactJwt('ES256');
        const mockJwks = { keys: [] };

        mockCreateRemoteJWKSet.mockReturnValue(mockJwks);
        mockJwtVerify.mockResolvedValue({
            payload: {
                iss: 'https://example.com',
                exp: Math.floor(Date.now() / 1000) + 3600,
            }, // no sub (exp is present to ensure the exp check passes first and reaches the sub check)
            protectedHeader: { alg: 'ES256' },
        });

        try {
            await verifyJwtAndDeriveDid({
                jwt,
                jwks: 'https://example.com/.well-known/jwks.json',
                expectedIssuer: 'https://example.com',
                expectedAudience: 'myapi',
                expectedDid: VALID_DID,
            });
            expect.fail('should have thrown');
        } catch (err) {
            expect(err).toBeInstanceOf(SdkError);
            expect((err as SdkError).code).toBe('SDK_JWT_VERIFY_FAILED');
            expect((err as SdkError).message).toMatch(/sub missing/i);
        }
    });

    it('should throw SDK_MAPPING_MISMATCH when payload.sub does not match expectedDid', async () => {
        const jwt = makeCompactJwt('ES256');
        const mockJwks = { keys: [] };

        mockCreateRemoteJWKSet.mockReturnValue(mockJwks);
        mockJwtVerify.mockResolvedValue({
            payload: {
                sub: OTHER_DID as string,
                iss: 'https://example.com',
                exp: Math.floor(Date.now() / 1000) + 3600,
            },
            protectedHeader: { alg: 'ES256' },
        });

        try {
            await verifyJwtAndDeriveDid({
                jwt,
                jwks: 'https://example.com/.well-known/jwks.json',
                expectedIssuer: 'https://example.com',
                expectedAudience: 'myapi',
                expectedDid: VALID_DID, // expects VALID_DID but sub = OTHER_DID
            });
            expect.fail('should have thrown');
        } catch (err) {
            expect(err).toBeInstanceOf(SdkError);
            expect((err as SdkError).code).toBe('SDK_MAPPING_MISMATCH');
        }
    });

    it('should use static JWK set directly when jwks is an object (not URL string)', async () => {
        const jwt = makeCompactJwt('ES256');
        const staticJwks = {
            keys: [{ kty: 'EC', crv: 'P-256', x: 'abc', y: 'def' }],
        };

        // Summary: when jwks = object, createRemoteJWKSet is not called; it is passed directly to jwtVerify
        mockJwtVerify.mockResolvedValue({
            payload: {
                sub: VALID_DID as string,
                iss: 'https://example.com',
                exp: Math.floor(Date.now() / 1000) + 3600,
            },
            protectedHeader: { alg: 'ES256' },
        });

        await verifyJwtAndDeriveDid({
            jwt,
            jwks: staticJwks,
            expectedIssuer: 'https://example.com',
            expectedAudience: 'myapi',
            expectedDid: VALID_DID,
        });

        // createRemoteJWKSet should not be called (because jwks is an object)
        expect(mockCreateRemoteJWKSet).not.toHaveBeenCalled();
        expect(mockJwtVerify).toHaveBeenCalledOnce();
    });
});

// ─────────────────────────────────────────────────────────────────────────────
// Scope E: verify-oauth2 — verifyOAuth2AndDeriveDid (dependency injection; no vi.mock)
// ─────────────────────────────────────────────────────────────────────────────
describe('verify-oauth2 — verifyOAuth2AndDeriveDid', () => {
    /** Build a mock introspection response for injection */
    function makeIntrospectionMock(
        overrides: Record<string, unknown> = {},
    ): IntrospectionResponse {
        return {
            active: true,
            client_id: VALID_DID as string,
            aud: 'myapi',
            exp: Math.floor(Date.now() / 1000) + 3600,
            ...overrides,
        } as IntrospectionResponse;
    }

    /** A minimal valid OAuth2VerifierContext */
    const validCtx = {
        accessToken: 'test-access-token',
        issuerUrl: 'https://example.com',
        introspectionEndpoint: 'https://example.com/oauth/introspect',
        introspectionClientId: 'rs-client',
        introspectionClientSecret: 'rs-secret',
        expectedAudience: 'myapi',
        expectedDid: VALID_DID,
    };

    it('should return VerifiedTransportContext when introspection returns active=true and client_id matches', async () => {
        // Summary: introspectFn DI injection bypasses the OIDC discovery network call (necessary for unit testing)
        // Summary: an isolated cache instance prevents cross-test cache-hit pollution (the module-level _defaultCache has a 60s TTL)
        const ctx = await verifyOAuth2AndDeriveDid(validCtx, {
            cache: new OAuth2IntrospectionCache(60),
            introspectFn: (_token) => Promise.resolve(makeIntrospectionMock()),
        });

        expect(ctx.trustedDid).toBe(VALID_DID);
        expect(ctx.verifierKind).toBe('oauth2');
        expect(ctx.verifiedSubject).toBe(VALID_DID);
        expect(ctx.sdkVersion).toBe('2.0.0');
    });

    it('should throw SDK_OAUTH2_VERIFY_FAILED when introspection returns active=false', async () => {
        try {
            await verifyOAuth2AndDeriveDid(validCtx, {
                cache: new OAuth2IntrospectionCache(60),
                introspectFn: (_token) =>
                    Promise.resolve(makeIntrospectionMock({ active: false })),
            });
            expect.fail('should have thrown');
        } catch (err) {
            expect(err).toBeInstanceOf(SdkError);
            expect((err as SdkError).code).toBe('SDK_OAUTH2_VERIFY_FAILED');
            expect((err as SdkError).message).toMatch(/active !== true/);
        }
    });

    it('should throw SDK_OAUTH2_VERIFY_FAILED when token is expired (exp < now)', async () => {
        const expiredExp = Math.floor(Date.now() / 1000) - 3600; // 1 hour ago

        try {
            await verifyOAuth2AndDeriveDid(validCtx, {
                cache: new OAuth2IntrospectionCache(60),
                introspectFn: (_token) =>
                    Promise.resolve(makeIntrospectionMock({ exp: expiredExp })),
            });
            expect.fail('should have thrown');
        } catch (err) {
            expect(err).toBeInstanceOf(SdkError);
            expect((err as SdkError).code).toBe('SDK_OAUTH2_VERIFY_FAILED');
            expect((err as SdkError).message).toMatch(/expired/i);
        }
    });

    it('should throw SDK_OAUTH2_VERIFY_FAILED when aud claim does not include expectedAudience', async () => {
        try {
            await verifyOAuth2AndDeriveDid(validCtx, {
                cache: new OAuth2IntrospectionCache(60),
                introspectFn: (_token) =>
                    Promise.resolve(
                        makeIntrospectionMock({ aud: 'other-api' }),
                    ),
            });
            expect.fail('should have thrown');
        } catch (err) {
            expect(err).toBeInstanceOf(SdkError);
            expect((err as SdkError).code).toBe('SDK_OAUTH2_VERIFY_FAILED');
            expect((err as SdkError).message).toMatch(/expected audience/i);
        }
    });

    it('should pass when aud claim is array containing expectedAudience', async () => {
        const ctx = await verifyOAuth2AndDeriveDid(validCtx, {
            cache: new OAuth2IntrospectionCache(60),
            introspectFn: (_token) =>
                Promise.resolve(
                    makeIntrospectionMock({ aud: ['myapi', 'other-api'] }),
                ),
        });
        expect(ctx.trustedDid).toBe(VALID_DID);
    });

    it('should throw SDK_MAPPING_MISMATCH when client_id does not match expectedDid', async () => {
        try {
            await verifyOAuth2AndDeriveDid(validCtx, {
                cache: new OAuth2IntrospectionCache(60),
                introspectFn: (_token) =>
                    Promise.resolve(
                        makeIntrospectionMock({
                            client_id: OTHER_DID as string,
                        }),
                    ),
            });
            expect.fail('should have thrown');
        } catch (err) {
            expect(err).toBeInstanceOf(SdkError);
            expect((err as SdkError).code).toBe('SDK_MAPPING_MISMATCH');
        }
    });

    it('should use sub claim as fallback when client_id is absent', async () => {
        const responseWithSub = makeIntrospectionMock();
        // Summary: remove client_id, keep sub = VALID_DID -> sub fallback path
        delete (responseWithSub as Record<string, unknown>)['client_id'];
        (responseWithSub as Record<string, unknown>)['sub'] =
            VALID_DID as string;

        const ctx = await verifyOAuth2AndDeriveDid(validCtx, {
            cache: new OAuth2IntrospectionCache(60),
            introspectFn: (_token) => Promise.resolve(responseWithSub),
        });
        expect(ctx.trustedDid).toBe(VALID_DID);
        expect(ctx.verifiedSubject).toBe(VALID_DID);
    });

    it('should throw SDK_OAUTH2_VERIFY_FAILED when circuit breaker is OPEN', async () => {
        // Summary: circuit breaker OPEN -> fail-closed, does not call cache/introspection
        const openCircuitBreaker = new OAuth2CircuitBreaker(1, 3600);
        // force trigger OPEN
        await expect(
            openCircuitBreaker.execute(() => Promise.reject(new Error('fail'))),
        ).rejects.toThrow();

        expect(openCircuitBreaker.getState().state).toBe('OPEN');

        try {
            await verifyOAuth2AndDeriveDid(validCtx, {
                circuitBreaker: openCircuitBreaker,
            });
            expect.fail('should have thrown');
        } catch (err) {
            expect(err).toBeInstanceOf(SdkError);
            expect((err as SdkError).code).toBe('SDK_OAUTH2_VERIFY_FAILED');
            expect((err as SdkError).message).toMatch(/OPEN/);
        }
    });

    it('should throw SDK_OAUTH2_VERIFY_FAILED when rate limiter is exhausted', () => {
        // Summary: rate limiter exhausted -> Step 0 throws directly, does not enter the circuit breaker
        const exhaustedLimiter = new OAuth2RateLimiter(1, 0);
        exhaustedLimiter.consume(); // consume the only token

        return expect(
            verifyOAuth2AndDeriveDid(validCtx, {
                rateLimiter: exhaustedLimiter,
            }),
        ).rejects.toMatchObject({
            code: 'SDK_OAUTH2_VERIFY_FAILED',
        });
    });
});

// ─────────────────────────────────────────────────────────────────────────────
// Scope F: verify-mtls — verifyMtlsAndDeriveDid (vi.mock mtls-helpers)
// ─────────────────────────────────────────────────────────────────────────────
describe('verify-mtls — verifyMtlsAndDeriveDid', () => {
    let mockParseX509Cert: ReturnType<typeof vi.fn>;
    let mockValidateCertChain: ReturnType<typeof vi.fn>;
    let mockExtractDidFromCertSubject: ReturnType<typeof vi.fn>;

    beforeEach(async () => {
        const helpers =
            await import('../cryptographic-verifier/mtls-helpers.js');
        mockParseX509Cert = helpers.parseX509Cert as ReturnType<typeof vi.fn>;
        mockValidateCertChain = helpers.validateCertChain as ReturnType<
            typeof vi.fn
        >;
        mockExtractDidFromCertSubject =
            helpers.extractDidFromCertSubject as ReturnType<typeof vi.fn>;
        // Summary: resetAllMocks clears the mockImplementation (clearAllMocks only clears call records, not the impl)
        vi.resetAllMocks();
    });

    /** Build a mock X509Certificate-like object */
    function makeMockCert(did: string) {
        return {
            subjectName: {
                toString: () => `CN=${did}, O=TestOrg`,
            },
        };
    }

    it('should return VerifiedTransportContext when cert chain is valid and DID matches', async () => {
        const mockCert = makeMockCert(VALID_DID as string);
        mockParseX509Cert.mockReturnValue(mockCert);
        mockValidateCertChain.mockResolvedValue(true);
        mockExtractDidFromCertSubject.mockReturnValue(VALID_DID as string);

        const ctx = await verifyMtlsAndDeriveDid({
            clientCert: 'PEM_CERT_DATA',
            trustedRootCerts: ['ROOT_CA_PEM'],
            expectedDid: VALID_DID,
        });

        expect(ctx.trustedDid).toBe(VALID_DID);
        expect(ctx.verifierKind).toBe('mtls');
        expect(ctx.sdkVersion).toBe('2.0.0');
    });

    it('should throw SDK_MTLS_VERIFY_FAILED when cert chain validation fails', async () => {
        const mockCert = makeMockCert(VALID_DID as string);
        mockParseX509Cert.mockReturnValue(mockCert);
        mockValidateCertChain.mockResolvedValue(false); // chain validation fails
        mockExtractDidFromCertSubject.mockReturnValue(VALID_DID as string);

        try {
            await verifyMtlsAndDeriveDid({
                clientCert: 'BAD_CERT',
                trustedRootCerts: ['ROOT_CA_PEM'],
                expectedDid: VALID_DID,
            });
            expect.fail('should have thrown');
        } catch (err) {
            expect(err).toBeInstanceOf(SdkError);
            expect((err as SdkError).code).toBe('SDK_MTLS_VERIFY_FAILED');
            expect((err as SdkError).message).toMatch(
                /cert chain validation failed/i,
            );
        }
    });

    it('should throw SDK_MAPPING_MISMATCH when extracted DID does not match expectedDid', async () => {
        const mockCert = makeMockCert(OTHER_DID as string);
        mockParseX509Cert.mockReturnValue(mockCert);
        mockValidateCertChain.mockResolvedValue(true);
        mockExtractDidFromCertSubject.mockReturnValue(OTHER_DID as string); // cert DID = OTHER_DID

        try {
            await verifyMtlsAndDeriveDid({
                clientCert: 'CERT_WITH_WRONG_DID',
                trustedRootCerts: ['ROOT_CA_PEM'],
                expectedDid: VALID_DID, // expects VALID_DID
            });
            expect.fail('should have thrown');
        } catch (err) {
            expect(err).toBeInstanceOf(SdkError);
            expect((err as SdkError).code).toBe('SDK_MAPPING_MISMATCH');
        }
    });

    it('should throw SDK_MTLS_VERIFY_FAILED when parseX509Cert throws', async () => {
        mockParseX509Cert.mockImplementation(() => {
            throw new SdkError(
                'SDK_MTLS_VERIFY_FAILED',
                'cert parse failed (invalid DER/PEM)',
            );
        });

        try {
            await verifyMtlsAndDeriveDid({
                clientCert: 'INVALID_CERT_DATA',
                trustedRootCerts: ['ROOT_CA_PEM'],
                expectedDid: VALID_DID,
            });
            expect.fail('should have thrown');
        } catch (err) {
            expect(err).toBeInstanceOf(SdkError);
            expect((err as SdkError).code).toBe('SDK_MTLS_VERIFY_FAILED');
        }
    });

    it('should handle intermediateChain when provided', async () => {
        const mockCert = makeMockCert(VALID_DID as string);
        const mockIntermediate = makeMockCert('did:example:intermediate');
        const mockRootCert = makeMockCert('did:example:root-ca');
        // Summary: parseX509Cert is called 3 times — 1 for clientCert + 1 for the intermediateChain entry + 1 for the trustedRootCerts entry
        mockParseX509Cert
            .mockReturnValueOnce(mockCert)
            .mockReturnValueOnce(mockIntermediate)
            .mockReturnValueOnce(mockRootCert);
        mockValidateCertChain.mockResolvedValue(true);
        mockExtractDidFromCertSubject.mockReturnValue(VALID_DID as string);

        const ctx = await verifyMtlsAndDeriveDid({
            clientCert: 'CLIENT_CERT',
            trustedRootCerts: ['ROOT_CA_PEM'],
            intermediateChain: ['INTERMEDIATE_CERT'],
            expectedDid: VALID_DID,
        });

        expect(ctx.trustedDid).toBe(VALID_DID);
        expect(mockParseX509Cert).toHaveBeenCalledTimes(3);
    });
});
