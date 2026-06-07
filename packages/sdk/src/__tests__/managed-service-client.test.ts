/**
 * ManagedServiceClient unit tests
 *
 * Scenarios covered (D3 acceptance checklist):
 * 1. serviceUrl undefined → fall back directly (mock fallbackResolver verifies it is called)
 * 2. serviceUrl set + 200 → do not fall back, return the server response
 * 3. serviceUrl set + 500 → fall back; onFallback is called
 * 4. serviceUrl set + network error → fall back
 * 5. serviceUrl set + timeout (AbortError) → fall back
 * 6. serviceUrl set + 401/403 → throw ManagedServiceError(MANAGED_SERVICE_CLIENT_ERROR), do not fall back
 * 7. serviceUrl set + 429 → throw ManagedServiceError(MANAGED_SERVICE_RATE_LIMITED), do not fall back
 * 8. apiKey set → the fetch request carries an Authorization Bearer header
 * 9. apiKey unset → no Authorization header
 *
 * Note: the corresponding checkRevocation scenarios are covered in parallel to ensure branch coverage >= 90%.
 *
 * fetch is mocked with `vi.spyOn(globalThis, 'fetch')`, without introducing an extra mock library.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import type {
    AgentIdentityDocument,
    DID,
    FederatedResolver,
} from '@coivitas/types';

import {
    ManagedServiceClient,
    ManagedServiceError,
} from '../managed-service-client.js';
import type { RevocationResult } from '../managed-service-client.js';

// ============================================================
// Test helper: construct a minimal valid AgentIdentityDocument
// ============================================================

function makeDoc(did: string): AgentIdentityDocument {
    return {
        id: did as DID,
        version: '0.2.0',
        capabilityEndpoint: 'https://example.com/agent',
        verificationMethods: [],
        authentication: [],
        createdAt: '2024-01-01T00:00:00Z',
        updatedAt: '2024-01-01T00:00:00Z',
    } as unknown as AgentIdentityDocument;
}

// ============================================================
// Test helper: FederatedResolver spy holder
// Store the spies in standalone variables to avoid the expect(resolver.method) unbound-method warning
// ============================================================

interface ResolverSpies {
    resolveSpy: ReturnType<typeof vi.fn>;
    invalidateSpy: ReturnType<typeof vi.fn>;
    metricsSpy: ReturnType<typeof vi.fn>;
    closeSpy: ReturnType<typeof vi.fn>;
    resolver: FederatedResolver;
}

function makeFallbackResolver(
    resolveResult: AgentIdentityDocument | null = null,
): ResolverSpies {
    const resolveSpy = vi.fn().mockResolvedValue(resolveResult);
    const invalidateSpy = vi.fn();
    const metricsSpy = vi.fn().mockReturnValue({
        resolveTotal: 0,
        resolveSuccess: 0,
        resolveFail: 0,
        cacheMiss: 0,
        cacheHit: 0,
    });
    const closeSpy = vi.fn().mockResolvedValue(undefined);

    const resolver = {
        resolve: resolveSpy,
        invalidateCache: invalidateSpy,
        getMetrics: metricsSpy,
        close: closeSpy,
    } as unknown as FederatedResolver;

    return { resolveSpy, invalidateSpy, metricsSpy, closeSpy, resolver };
}

// ============================================================
// Test helper: construct a Response mock
// ============================================================

function makeOkResponse(body: unknown): Response {
    return {
        ok: true,
        status: 200,
        json: vi.fn().mockResolvedValue(body),
    } as unknown as Response;
}

function makeErrorResponse(status: number): Response {
    return {
        ok: false,
        status,
        json: vi.fn().mockResolvedValue({ error: `HTTP ${status}` }),
    } as unknown as Response;
}

// ============================================================
// Main test block
// ============================================================

describe('ManagedServiceClient', () => {
    let fetchSpy: ReturnType<typeof vi.spyOn<typeof globalThis, 'fetch'>>;

    beforeEach(() => {
        // Re-spy for each test case to ensure isolation
        fetchSpy = vi.spyOn(globalThis, 'fetch');
    });

    afterEach(() => {
        vi.restoreAllMocks();
    });

    // ----------------------------------------------------------
    // Scenario 1: serviceUrl undefined → fall back directly
    // ----------------------------------------------------------

    describe('resolveDid — serviceUrl undefined', () => {
        it('should call fallbackResolver directly when serviceUrl is not configured', async () => {
            const did = 'did:agent:test001' as DID;
            const doc = makeDoc(did);
            const { resolveSpy, resolver } = makeFallbackResolver(doc);
            const onFallback = vi.fn();

            const client = new ManagedServiceClient({
                fallbackResolver: resolver,
                onFallback,
                // serviceUrl not set
            });

            const result = await client.resolveDid(did);

            expect(result).toBe(doc);
            expect(resolveSpy).toHaveBeenCalledOnce();
            expect(resolveSpy).toHaveBeenCalledWith(did);
            // onFallback fires
            expect(onFallback).toHaveBeenCalledOnce();
            expect(onFallback).toHaveBeenCalledWith(
                'serviceUrl_not_configured',
                did,
            );
            // fetch should not be called
            expect(fetchSpy).not.toHaveBeenCalled();
        });
    });

    describe('checkRevocation — serviceUrl undefined', () => {
        it('should return fail-unknown result and call onFallback when serviceUrl not configured', async () => {
            // Changed from fail-open (revoked=false) to fail-unknown (revoked='unknown')
            const credId = 'cred-001';
            const { resolver } = makeFallbackResolver();
            const onFallback = vi.fn();

            const client = new ManagedServiceClient({
                fallbackResolver: resolver,
                onFallback,
            });

            const result = await client.checkRevocation(credId);

            // fail-unknown: revoked = 'unknown' + fallbackReason identifies the degradation reason
            expect(result.credentialId).toBe(credId);
            expect(result.revoked).toBe('unknown');
            expect(result.fallbackReason).toBe('serviceUrl_not_configured');
            expect(onFallback).toHaveBeenCalledWith(
                'serviceUrl_not_configured',
                credId,
            );
            expect(fetchSpy).not.toHaveBeenCalled();
        });
    });

    // ----------------------------------------------------------
    // Scenario 2: serviceUrl set + 200 → return the server response, do not fall back
    // ----------------------------------------------------------

    describe('resolveDid — 200 OK', () => {
        it('should return server response without fallback when service returns 200', async () => {
            const did = 'did:agent:test002' as DID;
            const serverDoc = makeDoc(did);
            const { resolveSpy, resolver } = makeFallbackResolver();
            const onFallback = vi.fn();

            fetchSpy.mockResolvedValueOnce(makeOkResponse(serverDoc));

            const client = new ManagedServiceClient({
                serviceUrl: 'https://managed.example.com',
                fallbackResolver: resolver,
                onFallback,
            });

            const result = await client.resolveDid(did);

            expect(result).toEqual(serverDoc);
            // fallback is not called
            expect(resolveSpy).not.toHaveBeenCalled();
            expect(onFallback).not.toHaveBeenCalled();
            // fetch is called once, with a URL that matches the spec
            expect(fetchSpy).toHaveBeenCalledOnce();
            const calledUrl: unknown = fetchSpy.mock.calls[0]?.[0];
            expect(
                typeof calledUrl === 'string' &&
                    calledUrl.includes('/v1/resolve/'),
            ).toBe(true);
            expect(
                typeof calledUrl === 'string' &&
                    calledUrl.includes(encodeURIComponent(did)),
            ).toBe(true);
        });
    });

    describe('checkRevocation — 200 OK', () => {
        it('should return revocation result from server without fallback', async () => {
            const credId = 'cred-200';
            const serverResult: RevocationResult = {
                credentialId: credId,
                revoked: true,
                revokedAt: '2024-06-01T00:00:00Z',
                reason: 'compromised',
            };
            const { resolveSpy, resolver } = makeFallbackResolver();

            fetchSpy.mockResolvedValueOnce(makeOkResponse(serverResult));

            const client = new ManagedServiceClient({
                serviceUrl: 'https://managed.example.com',
                fallbackResolver: resolver,
            });

            const result = await client.checkRevocation(credId);

            expect(result).toEqual(serverResult);
            expect(resolveSpy).not.toHaveBeenCalled();
            expect(fetchSpy).toHaveBeenCalledOnce();
            const calledUrl: unknown = fetchSpy.mock.calls[0]?.[0];
            expect(
                typeof calledUrl === 'string' &&
                    calledUrl.includes('/v1/revocation/'),
            ).toBe(true);
        });
    });

    // ----------------------------------------------------------
    // Scenario 3: serviceUrl set + 500 → fall back; onFallback is called
    // ----------------------------------------------------------

    describe('resolveDid — 500 server error', () => {
        it('should fallback and call onFallback when service returns 500', async () => {
            const did = 'did:agent:test003' as DID;
            const fallbackDoc = makeDoc(did);
            const { resolveSpy, resolver } = makeFallbackResolver(fallbackDoc);
            const onFallback = vi.fn();

            fetchSpy.mockResolvedValueOnce(makeErrorResponse(500));

            const client = new ManagedServiceClient({
                serviceUrl: 'https://managed.example.com',
                fallbackResolver: resolver,
                onFallback,
            });

            const result = await client.resolveDid(did);

            expect(result).toBe(fallbackDoc);
            expect(resolveSpy).toHaveBeenCalledOnce();
            expect(onFallback).toHaveBeenCalledOnce();
            // onFallback reason should contain server_error or HTTP-500-related info
            const reason: unknown = onFallback.mock.calls[0]?.[0];
            expect(
                typeof reason === 'string' && /server_error/i.test(reason),
            ).toBe(true);
        });
    });

    describe('checkRevocation — 500 server error', () => {
        it('should return fail-unknown result and call onFallback when service returns 500', async () => {
            // Changed from fail-open (revoked=false) to fail-unknown (revoked='unknown')
            const credId = 'cred-500';
            const { resolver } = makeFallbackResolver();
            const onFallback = vi.fn();

            fetchSpy.mockResolvedValueOnce(makeErrorResponse(500));

            const client = new ManagedServiceClient({
                serviceUrl: 'https://managed.example.com',
                fallbackResolver: resolver,
                onFallback,
            });

            const result = await client.checkRevocation(credId);

            expect(result.credentialId).toBe(credId);
            expect(result.revoked).toBe('unknown');
            expect(result.fallbackReason).toBeDefined();
            expect(onFallback).toHaveBeenCalledOnce();
        });
    });

    // ----------------------------------------------------------
    // Scenario 4: network error → fall back
    // ----------------------------------------------------------

    describe('resolveDid — network error', () => {
        it('should fallback when fetch throws a network error', async () => {
            const did = 'did:agent:test004' as DID;
            const fallbackDoc = makeDoc(did);
            const { resolveSpy, resolver } = makeFallbackResolver(fallbackDoc);
            const onFallback = vi.fn();

            fetchSpy.mockRejectedValueOnce(new Error('ECONNREFUSED'));

            const client = new ManagedServiceClient({
                serviceUrl: 'https://managed.example.com',
                fallbackResolver: resolver,
                onFallback,
            });

            const result = await client.resolveDid(did);

            expect(result).toBe(fallbackDoc);
            expect(resolveSpy).toHaveBeenCalledOnce();
            expect(onFallback).toHaveBeenCalledOnce();
            const reason: unknown = onFallback.mock.calls[0]?.[0];
            expect(
                typeof reason === 'string' && /network_error/i.test(reason),
            ).toBe(true);
        });
    });

    describe('checkRevocation — network error', () => {
        it('should return fail-unknown and call onFallback on network error', async () => {
            // Changed from fail-open (revoked=false) to fail-unknown (revoked='unknown')
            const credId = 'cred-net';
            const { resolver } = makeFallbackResolver();
            const onFallback = vi.fn();

            fetchSpy.mockRejectedValueOnce(new TypeError('Failed to fetch'));

            const client = new ManagedServiceClient({
                serviceUrl: 'https://managed.example.com',
                fallbackResolver: resolver,
                onFallback,
            });

            const result = await client.checkRevocation(credId);

            expect(result.revoked).toBe('unknown');
            expect(result.fallbackReason).toBeDefined();
            expect(onFallback).toHaveBeenCalledOnce();
        });
    });

    // ----------------------------------------------------------
    // Scenario 5: timeout (AbortError) → fall back
    // ----------------------------------------------------------

    describe('resolveDid — timeout (AbortError)', () => {
        it('should fallback with request_timeout reason when fetch is aborted', async () => {
            const did = 'did:agent:test005' as DID;
            const fallbackDoc = makeDoc(did);
            const { resolveSpy, resolver } = makeFallbackResolver(fallbackDoc);
            const onFallback = vi.fn();

            const abortError = new Error('The operation was aborted');
            abortError.name = 'AbortError';
            fetchSpy.mockRejectedValueOnce(abortError);

            const client = new ManagedServiceClient({
                serviceUrl: 'https://managed.example.com',
                fallbackResolver: resolver,
                onFallback,
                timeoutMs: 100,
            });

            const result = await client.resolveDid(did);

            expect(result).toBe(fallbackDoc);
            expect(resolveSpy).toHaveBeenCalledOnce();
            expect(onFallback).toHaveBeenCalledOnce();
            const reason: unknown = onFallback.mock.calls[0]?.[0];
            expect(reason).toBe('request_timeout');
        });
    });

    describe('resolveDid — timeout via aborted message', () => {
        it('should fallback with request_timeout when error message contains aborted', async () => {
            const did = 'did:agent:test005b' as DID;
            const { resolver } = makeFallbackResolver(makeDoc(did));
            const onFallback = vi.fn();

            // In some environments the AbortError message contains "aborted" but has a different name
            const abortError = new Error('The request was aborted');
            fetchSpy.mockRejectedValueOnce(abortError);

            const client = new ManagedServiceClient({
                serviceUrl: 'https://managed.example.com',
                fallbackResolver: resolver,
                onFallback,
            });

            const result = await client.resolveDid(did);

            expect(result).not.toBeUndefined();
            expect(onFallback).toHaveBeenCalledOnce();
            const reason: unknown = onFallback.mock.calls[0]?.[0];
            expect(reason).toBe('request_timeout');
        });
    });

    // ----------------------------------------------------------
    // Scenario 6: 4xx other than 429 → throw ManagedServiceError(MANAGED_SERVICE_CLIENT_ERROR), do not fall back
    // ----------------------------------------------------------

    describe('resolveDid — 404 Not Found', () => {
        it('should return null on 404 (DID not found is legitimate semantic, not error)', async () => {
            const did = 'did:agent:test006-404' as DID;
            const { resolveSpy, resolver } = makeFallbackResolver();
            const onFallback = vi.fn();

            fetchSpy.mockResolvedValueOnce(makeErrorResponse(404));

            const client = new ManagedServiceClient({
                serviceUrl: 'https://managed.example.com',
                fallbackResolver: resolver,
                onFallback,
            });

            const result = await client.resolveDid(did);

            // 404 maps to null (consistent with FederatedResolver semantics)
            expect(result).toBeNull();
            // no throw, no fallback, no metric (404 is legitimate semantics, not a degradation)
            expect(resolveSpy).not.toHaveBeenCalled();
            expect(onFallback).not.toHaveBeenCalled();
        });
    });

    describe('resolveDid — 401 Unauthorized', () => {
        it('should throw ManagedServiceError with CLIENT_ERROR code on 401', async () => {
            const did = 'did:agent:test006a' as DID;
            const { resolveSpy, resolver } = makeFallbackResolver();
            const onFallback = vi.fn();

            fetchSpy.mockResolvedValueOnce(makeErrorResponse(401));

            const client = new ManagedServiceClient({
                serviceUrl: 'https://managed.example.com',
                fallbackResolver: resolver,
                onFallback,
            });

            let thrown: unknown;
            try {
                await client.resolveDid(did);
            } catch (err) {
                thrown = err;
            }

            expect(thrown).toBeInstanceOf(ManagedServiceError);
            const e = thrown as ManagedServiceError;
            expect(e.code).toBe('MANAGED_SERVICE_CLIENT_ERROR');
            expect(e.statusCode).toBe(401);

            // fallback is not called
            expect(resolveSpy).not.toHaveBeenCalled();
            expect(onFallback).not.toHaveBeenCalled();
        });
    });

    describe('resolveDid — 403 Forbidden', () => {
        it('should throw ManagedServiceError with CLIENT_ERROR code on 403', async () => {
            const did = 'did:agent:test006b' as DID;
            const { resolveSpy, resolver } = makeFallbackResolver();

            fetchSpy.mockResolvedValueOnce(makeErrorResponse(403));

            const client = new ManagedServiceClient({
                serviceUrl: 'https://managed.example.com',
                fallbackResolver: resolver,
            });

            let thrown: unknown;
            try {
                await client.resolveDid(did);
            } catch (err) {
                thrown = err;
            }

            expect(thrown).toBeInstanceOf(ManagedServiceError);
            expect((thrown as ManagedServiceError).code).toBe(
                'MANAGED_SERVICE_CLIENT_ERROR',
            );
            expect((thrown as ManagedServiceError).statusCode).toBe(403);
            expect(resolveSpy).not.toHaveBeenCalled();
        });
    });

    describe('checkRevocation — 4xx non-429', () => {
        it('should throw ManagedServiceError with CLIENT_ERROR code on 404', async () => {
            const credId = 'cred-404';
            const { resolveSpy, resolver } = makeFallbackResolver();

            fetchSpy.mockResolvedValueOnce(makeErrorResponse(404));

            const client = new ManagedServiceClient({
                serviceUrl: 'https://managed.example.com',
                fallbackResolver: resolver,
            });

            let thrown: unknown;
            try {
                await client.checkRevocation(credId);
            } catch (err) {
                thrown = err;
            }

            expect(thrown).toBeInstanceOf(ManagedServiceError);
            expect((thrown as ManagedServiceError).code).toBe(
                'MANAGED_SERVICE_CLIENT_ERROR',
            );
            expect((thrown as ManagedServiceError).statusCode).toBe(404);
            expect(resolveSpy).not.toHaveBeenCalled();
        });
    });

    // ----------------------------------------------------------
    // Scenario 7: 429 → throw ManagedServiceError(MANAGED_SERVICE_RATE_LIMITED), do not fall back
    // ----------------------------------------------------------

    describe('resolveDid — 429 Rate Limited', () => {
        it('should throw ManagedServiceError with RATE_LIMITED code on 429', async () => {
            const did = 'did:agent:test007' as DID;
            const { resolveSpy, resolver } = makeFallbackResolver();
            const onFallback = vi.fn();

            fetchSpy.mockResolvedValueOnce(makeErrorResponse(429));

            const client = new ManagedServiceClient({
                serviceUrl: 'https://managed.example.com',
                fallbackResolver: resolver,
                onFallback,
            });

            let thrown: unknown;
            try {
                await client.resolveDid(did);
            } catch (err) {
                thrown = err;
            }

            expect(thrown).toBeInstanceOf(ManagedServiceError);
            expect((thrown as ManagedServiceError).code).toBe(
                'MANAGED_SERVICE_RATE_LIMITED',
            );
            expect((thrown as ManagedServiceError).statusCode).toBe(429);
            // fallback is not called
            expect(resolveSpy).not.toHaveBeenCalled();
            expect(onFallback).not.toHaveBeenCalled();
        });
    });

    describe('checkRevocation — 429 Rate Limited', () => {
        it('should throw ManagedServiceError with RATE_LIMITED code on 429', async () => {
            const credId = 'cred-429';
            const { resolveSpy, resolver } = makeFallbackResolver();

            fetchSpy.mockResolvedValueOnce(makeErrorResponse(429));

            const client = new ManagedServiceClient({
                serviceUrl: 'https://managed.example.com',
                fallbackResolver: resolver,
            });

            let thrown: unknown;
            try {
                await client.checkRevocation(credId);
            } catch (err) {
                thrown = err;
            }

            expect(thrown).toBeInstanceOf(ManagedServiceError);
            expect((thrown as ManagedServiceError).code).toBe(
                'MANAGED_SERVICE_RATE_LIMITED',
            );
            expect(resolveSpy).not.toHaveBeenCalled();
        });
    });

    // ----------------------------------------------------------
    // Scenario 8: apiKey set → the fetch request carries an Authorization Bearer header
    // ----------------------------------------------------------

    describe('apiKey — Authorization header', () => {
        it('should include Authorization Bearer header when apiKey is configured', async () => {
            const did = 'did:agent:test008' as DID;
            const apiKey = 'test-api-key-secret';
            const { resolver } = makeFallbackResolver();

            fetchSpy.mockResolvedValueOnce(makeOkResponse(makeDoc(did)));

            const client = new ManagedServiceClient({
                serviceUrl: 'https://managed.example.com',
                apiKey,
                fallbackResolver: resolver,
            });

            await client.resolveDid(did);

            expect(fetchSpy).toHaveBeenCalledOnce();
            // Access the fetch call arguments: use the unknown type, narrowing manually
            const rawOptions: unknown = fetchSpy.mock.calls[0]?.[1];
            const headers =
                rawOptions !== null &&
                typeof rawOptions === 'object' &&
                'headers' in rawOptions
                    ? (rawOptions as { headers?: Record<string, string> })
                          .headers
                    : undefined;
            expect(headers?.['Authorization']).toBe(`Bearer ${apiKey}`);
        });
    });

    // ----------------------------------------------------------
    // Scenario 9: apiKey unset → no Authorization header
    // ----------------------------------------------------------

    describe('apiKey — no Authorization header', () => {
        it('should not include Authorization header when apiKey is not configured', async () => {
            const did = 'did:agent:test009' as DID;
            const { resolver } = makeFallbackResolver();

            fetchSpy.mockResolvedValueOnce(makeOkResponse(makeDoc(did)));

            const client = new ManagedServiceClient({
                serviceUrl: 'https://managed.example.com',
                // apiKey not set
                fallbackResolver: resolver,
            });

            await client.resolveDid(did);

            expect(fetchSpy).toHaveBeenCalledOnce();
            const rawOptions: unknown = fetchSpy.mock.calls[0]?.[1];
            const headers =
                rawOptions !== null &&
                typeof rawOptions === 'object' &&
                'headers' in rawOptions
                    ? (rawOptions as { headers?: Record<string, string> })
                          .headers
                    : undefined;
            expect(headers?.['Authorization']).toBeUndefined();
        });
    });

    // ----------------------------------------------------------
    // Additional scenario: maxRetries > 0 verifies fallback after retries
    // ----------------------------------------------------------

    describe('resolveDid — maxRetries with 500 errors', () => {
        it('should retry specified times then fallback when all attempts get 500', async () => {
            const did = 'did:agent:test-retry' as DID;
            const fallbackDoc = makeDoc(did);
            const { resolveSpy, resolver } = makeFallbackResolver(fallbackDoc);
            const onFallback = vi.fn();

            // 3 x 500 (1 original + 2 retries)
            fetchSpy
                .mockResolvedValueOnce(makeErrorResponse(500))
                .mockResolvedValueOnce(makeErrorResponse(500))
                .mockResolvedValueOnce(makeErrorResponse(500));

            const client = new ManagedServiceClient({
                serviceUrl: 'https://managed.example.com',
                fallbackResolver: resolver,
                onFallback,
                maxRetries: 2,
            });

            const result = await client.resolveDid(did);

            expect(result).toBe(fallbackDoc);
            // 3 fetches total (1 original + 2 retries)
            expect(fetchSpy).toHaveBeenCalledTimes(3);
            expect(resolveSpy).toHaveBeenCalledOnce();
            expect(onFallback).toHaveBeenCalledOnce();
        });
    });

    // ----------------------------------------------------------
    // Additional scenario: trailing slash on serviceUrl is stripped
    // ----------------------------------------------------------

    describe('serviceUrl normalization', () => {
        it('should strip trailing slash from serviceUrl before building endpoint URLs', async () => {
            const did = 'did:agent:test-slash' as DID;
            const { resolver } = makeFallbackResolver();

            fetchSpy.mockResolvedValueOnce(makeOkResponse(makeDoc(did)));

            const client = new ManagedServiceClient({
                serviceUrl: 'https://managed.example.com/', // trailing slash
                fallbackResolver: resolver,
            });

            await client.resolveDid(did);

            const calledUrl: unknown = fetchSpy.mock.calls[0]?.[0];
            // should be ...com/v1/resolve/... rather than ...com//v1/resolve/...
            expect(
                typeof calledUrl === 'string' &&
                    !calledUrl.includes('//v1/resolve/'),
            ).toBe(true);
            expect(
                typeof calledUrl === 'string' &&
                    calledUrl.includes('/v1/resolve/'),
            ).toBe(true);
        });
    });

    // ----------------------------------------------------------
    // Additional scenario: ManagedServiceError property-shape verification
    // ----------------------------------------------------------

    describe('ManagedServiceError shape', () => {
        it('should have correct name, code, and statusCode properties', async () => {
            const did = 'did:agent:test-err-shape' as DID;
            const { resolver } = makeFallbackResolver();

            fetchSpy.mockResolvedValueOnce(makeErrorResponse(403));

            const client = new ManagedServiceClient({
                serviceUrl: 'https://managed.example.com',
                fallbackResolver: resolver,
            });

            let thrown: unknown;
            try {
                await client.resolveDid(did);
            } catch (err) {
                thrown = err;
            }

            expect(thrown).toBeInstanceOf(ManagedServiceError);
            const e = thrown as ManagedServiceError;
            expect(e.name).toBe('ManagedServiceError');
            expect(e.code).toBe('MANAGED_SERVICE_CLIENT_ERROR');
            expect(e.statusCode).toBe(403);
            expect(e.message).toContain('403');
        });
    });

    // ----------------------------------------------------------
    // Additional scenario: does not throw when onFallback is not provided (optional callback)
    // ----------------------------------------------------------

    describe('onFallback optional', () => {
        it('should not throw when onFallback is not provided and fallback triggers', async () => {
            const did = 'did:agent:test-no-cb' as DID;
            const { resolver } = makeFallbackResolver(makeDoc(did));

            fetchSpy.mockResolvedValueOnce(makeErrorResponse(500));

            const client = new ManagedServiceClient({
                serviceUrl: 'https://managed.example.com',
                fallbackResolver: resolver,
                // onFallback not set
            });

            // should not throw
            await expect(client.resolveDid(did)).resolves.not.toThrow();
        });
    });

    // ----------------------------------------------------------
    // Additional scenario: checkRevocation Accept header verification
    // ----------------------------------------------------------

    describe('checkRevocation — Accept header', () => {
        it('should send Accept application/json header in requests', async () => {
            const credId = 'cred-headers';
            const { resolver } = makeFallbackResolver();

            fetchSpy.mockResolvedValueOnce(
                makeOkResponse({
                    credentialId: credId,
                    revoked: false,
                }),
            );

            const client = new ManagedServiceClient({
                serviceUrl: 'https://managed.example.com',
                fallbackResolver: resolver,
            });

            await client.checkRevocation(credId);

            expect(fetchSpy).toHaveBeenCalledOnce();
            const rawOptions: unknown = fetchSpy.mock.calls[0]?.[1];
            const headers =
                rawOptions !== null &&
                typeof rawOptions === 'object' &&
                'headers' in rawOptions
                    ? (rawOptions as { headers?: Record<string, string> })
                          .headers
                    : undefined;
            expect(headers?.['Accept']).toBe('application/json');
        });
    });

    // ----------------------------------------------------------
    // Additional scenario: fetch throws a non-Error object (covers the String(err) branch)
    // ----------------------------------------------------------

    describe('resolveDid — non-Error fetch rejection', () => {
        it('should fallback when fetch rejects with a non-Error value', async () => {
            const did = 'did:agent:test-non-error' as DID;
            const { resolver } = makeFallbackResolver(makeDoc(did));
            const onFallback = vi.fn();

            // Throw a string rather than an Error object, covering the String(err) branch
            fetchSpy.mockRejectedValueOnce('connection lost');

            const client = new ManagedServiceClient({
                serviceUrl: 'https://managed.example.com',
                fallbackResolver: resolver,
                onFallback,
            });

            const result = await client.resolveDid(did);

            expect(result).not.toBeNull();
            expect(onFallback).toHaveBeenCalledOnce();
            // reason should contain the stringified error content
            const reason: unknown = onFallback.mock.calls[0]?.[0];
            expect(
                typeof reason === 'string' && reason.includes('network_error'),
            ).toBe(true);
        });
    });

    describe('checkRevocation — non-Error fetch rejection', () => {
        it('should return fail-unknown when fetch rejects with a non-Error value', async () => {
            // Changed from fail-open (revoked=false) to fail-unknown (revoked='unknown')
            const credId = 'cred-non-error';
            const { resolver } = makeFallbackResolver();
            const onFallback = vi.fn();

            // Throw a non-Error object, covering the else branch of err instanceof Error ? err : new Error(String(err))
            fetchSpy.mockRejectedValueOnce({ code: 'TIMEOUT' });

            const client = new ManagedServiceClient({
                serviceUrl: 'https://managed.example.com',
                fallbackResolver: resolver,
                onFallback,
            });

            const result = await client.checkRevocation(credId);

            expect(result.revoked).toBe('unknown');
            expect(result.fallbackReason).toBeDefined();
            expect(onFallback).toHaveBeenCalledOnce();
        });
    });

    // ----------------------------------------------------------
    // Additional scenario: with maxRetries=0 (default), a single failure falls back immediately
    // ----------------------------------------------------------

    describe('resolveDid — default maxRetries=0 behavior', () => {
        it('should fallback immediately on first failure when maxRetries is 0 (default)', async () => {
            const did = 'did:agent:test-default-retry' as DID;
            const { resolver } = makeFallbackResolver(makeDoc(did));
            const onFallback = vi.fn();

            fetchSpy.mockResolvedValueOnce(makeErrorResponse(503));

            const client = new ManagedServiceClient({
                serviceUrl: 'https://managed.example.com',
                fallbackResolver: resolver,
                onFallback,
                // maxRetries uses the default value of 0
            });

            await client.resolveDid(did);

            // fetch called only once (no retries)
            expect(fetchSpy).toHaveBeenCalledTimes(1);
            expect(onFallback).toHaveBeenCalledOnce();
        });
    });
});
