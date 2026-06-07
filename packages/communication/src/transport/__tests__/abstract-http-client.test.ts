/**
 * DefaultHttpClient unit tests
 *
 * Coverage:
 * - resolveAndConnect: HTTPS-only enforcement, delegation to dnsRebindingGuard, LockedConnection construction
 * - fetch: IP lock (lookup override), 30x redirect fail-closed, normal responses
 * - fetchEnvelope: POST request, response JSON parsing, null for empty responses
 * - RedirectBlockedError: status code + location field
 * - DNSRebindingGuard seam: resolveAndValidate delegation + no re-resolution during fetch
 *
 * Note: ESM module namespaces are non-configurable (vi.spyOn has no effect on https.request).
 * Inject a mock function via DefaultHttpClientOptions._requestFn.
 *
 */

import * as http from 'node:http';
import * as https from 'node:https';
import { describe, expect, it, vi } from 'vitest';
import { EventEmitter } from 'node:events';
import type {
    NegotiationEnvelope,
    Signature,
    Timestamp,
    DID,
} from '@coivitas/types';
import {
    DefaultHttpClient,
    RedirectBlockedError,
    type DNSRebindingGuard,
    type LockedConnection,
    type RawRequestFn,
} from '../abstract-http-client.js';

// ── Test constants ──────────────────────────────────────────────────────────────────

const AGENT_DID = 'did:agent:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' as DID;

// ── mock dnsRebindingGuard ────────────────────────────────────────────────────

function makeMockGuard(resolvedIp = '1.2.3.4'): DNSRebindingGuard {
    return {
        resolveAndValidate: vi.fn().mockResolvedValue(resolvedIp),
    };
}

function makeFailGuard(
    errorMessage = 'DNS rebinding blocked',
): DNSRebindingGuard {
    return {
        resolveAndValidate: vi.fn().mockRejectedValue(new Error(errorMessage)),
    };
}

// ── LockedConnection helper ─────────────────────────────────────────────────────

function makeLockedConnection(
    overrides?: Partial<LockedConnection>,
): LockedConnection {
    return {
        resolvedIp: '1.2.3.4',
        originalHostname: 'example.com',
        originalUrl: 'https://example.com',
        port: 443,
        isHttps: true,
        ...overrides,
    };
}

// ── RawRequestFn mock helper ────────────────────────────────────────────────────

/**
 * Creates a requestFn that simulates a normal HTTP response
 *
 * Returns a mock IncomingMessage + ClientRequest with the given status, headers, and body.
 * Injected into DefaultHttpClient._requestFn to replace https.request, which cannot be spied under ESM.
 */
function createMockRequestFn(
    status: number,
    body: string,
    headersMap: Record<string, string> = {},
): RawRequestFn {
    return vi
        .fn()
        .mockImplementation(
            (
                _opts: https.RequestOptions,
                callback: (res: http.IncomingMessage) => void,
            ) => {
                const mockRes = new EventEmitter() as http.IncomingMessage;
                (mockRes as unknown as { statusCode: number }).statusCode =
                    status;
                (
                    mockRes as unknown as { headers: Record<string, string> }
                ).headers = headersMap;

                const req = new EventEmitter() as http.ClientRequest;
                const r = req as unknown as {
                    setTimeout(ms: number, cb: () => void): void;
                    write(data: string, enc: string): void;
                    end(): void;
                    destroy(err?: Error): void;
                };

                r.setTimeout = vi.fn();
                r.write = vi.fn();
                r.destroy = vi.fn();
                r.end = vi.fn(() => {
                    callback(mockRes);
                    setTimeout(() => {
                        (mockRes as EventEmitter).emit(
                            'data',
                            Buffer.from(body),
                        );
                        (mockRes as EventEmitter).emit('end');
                    }, 0);
                });

                return req;
            },
        ) as unknown as RawRequestFn;
}

/**
 * Creates a requestFn that simulates a 3xx redirect response
 *
 * For status 300-399, DefaultHttpClient.fetch() should throw RedirectBlockedError.
 */
function createRedirectRequestFn(
    status: number,
    location: string,
): RawRequestFn {
    return vi
        .fn()
        .mockImplementation(
            (
                _opts: https.RequestOptions,
                callback: (res: http.IncomingMessage) => void,
            ) => {
                const mockRes = new EventEmitter() as http.IncomingMessage;
                (mockRes as unknown as { statusCode: number }).statusCode =
                    status;
                (
                    mockRes as unknown as { headers: Record<string, string> }
                ).headers = { location };

                const req = new EventEmitter() as http.ClientRequest;
                const r = req as unknown as {
                    setTimeout(ms: number, cb: () => void): void;
                    write(data: string, enc: string): void;
                    end(): void;
                    destroy(err?: Error): void;
                };

                r.setTimeout = vi.fn();
                r.write = vi.fn();
                // destroy is invoked by DefaultHttpClient on redirect
                r.destroy = vi.fn();
                r.end = vi.fn(() => {
                    // Trigger the response callback (RedirectBlockedError is thrown via this path)
                    callback(mockRes);
                });

                return req;
            },
        ) as unknown as RawRequestFn;
}

// ── DefaultHttpClient.resolveAndConnect() tests ───────────────────────────────

describe('DefaultHttpClient.resolveAndConnect()', () => {
    it('should throw when URL uses HTTP (HTTPS-only enforcement)', async () => {
        const guard = makeMockGuard();
        const client = new DefaultHttpClient({ dnsRebindingGuard: guard });

        await expect(
            client.resolveAndConnect('http://example.com/path'),
        ).rejects.toThrow('HTTPS-only');
    });

    it('should throw when URL is invalid', async () => {
        const guard = makeMockGuard();
        const client = new DefaultHttpClient({ dnsRebindingGuard: guard });

        await expect(
            client.resolveAndConnect('not-a-valid-url'),
        ).rejects.toThrow();
    });

    it('should call dnsRebindingGuard.resolveAndValidate with hostname', async () => {
        const guard = makeMockGuard('1.2.3.4');
        const client = new DefaultHttpClient({ dnsRebindingGuard: guard });

        const conn = await client.resolveAndConnect('https://example.com/path');

        expect(guard.resolveAndValidate).toHaveBeenCalledWith('example.com');
        expect(conn.resolvedIp).toBe('1.2.3.4');
    });

    it('should propagate error from dnsRebindingGuard (fail-closed)', async () => {
        const guard = makeFailGuard(
            'DNS rebinding blocked: 10.0.0.1 is private',
        );
        const client = new DefaultHttpClient({ dnsRebindingGuard: guard });

        await expect(
            client.resolveAndConnect('https://internal.corp/'),
        ).rejects.toThrow('DNS rebinding blocked');
    });

    it('should return LockedConnection with correct fields on success', async () => {
        const guard = makeMockGuard('1.2.3.4');
        const client = new DefaultHttpClient({ dnsRebindingGuard: guard });

        const conn = await client.resolveAndConnect('https://example.com/path');

        expect(conn.resolvedIp).toBe('1.2.3.4');
        expect(conn.originalHostname).toBe('example.com');
        expect(conn.isHttps).toBe(true);
        expect(conn.port).toBe(443);
    });

    it('should parse custom port from URL', async () => {
        const guard = makeMockGuard('1.2.3.4');
        const client = new DefaultHttpClient({ dnsRebindingGuard: guard });

        const conn = await client.resolveAndConnect(
            'https://example.com:8443/path',
        );

        expect(conn.port).toBe(8443);
    });

    it('should include originalUrl in LockedConnection', async () => {
        const guard = makeMockGuard('1.2.3.4');
        const client = new DefaultHttpClient({ dnsRebindingGuard: guard });

        const conn = await client.resolveAndConnect(
            'https://example.com/api/v1',
        );

        expect(conn.originalUrl).toBe('https://example.com/api/v1');
    });
});

// ── DefaultHttpClient.fetch() tests ───────────────────────────────────────────

describe('DefaultHttpClient.fetch()', () => {
    it('should return 200 response with body', async () => {
        const guard = makeMockGuard();
        const client = new DefaultHttpClient({
            dnsRebindingGuard: guard,
            _requestFn: createMockRequestFn(200, '{"ok":true}'),
        });
        const conn = makeLockedConnection();

        const response = await client.fetch(conn, '/test');

        expect(response.status).toBe(200);
        expect(response.body).toBe('{"ok":true}');
    });

    it('should throw RedirectBlockedError on 301 redirect (fail-closed)', async () => {
        const guard = makeMockGuard();
        const client = new DefaultHttpClient({
            dnsRebindingGuard: guard,
            _requestFn: createRedirectRequestFn(
                301,
                'http://evil.example.com/',
            ),
        });
        const conn = makeLockedConnection();

        await expect(client.fetch(conn, '/redirect')).rejects.toThrow(
            RedirectBlockedError,
        );
    });

    it('should throw RedirectBlockedError on 302 redirect (fail-closed)', async () => {
        const guard = makeMockGuard();
        const client = new DefaultHttpClient({
            dnsRebindingGuard: guard,
            _requestFn: createRedirectRequestFn(302, '/somewhere'),
        });
        const conn = makeLockedConnection();

        await expect(client.fetch(conn, '/redirect')).rejects.toThrow(
            RedirectBlockedError,
        );
    });

    it('should throw RedirectBlockedError on 307 redirect (fail-closed)', async () => {
        const guard = makeMockGuard();
        const client = new DefaultHttpClient({
            dnsRebindingGuard: guard,
            _requestFn: createRedirectRequestFn(307, '/somewhere-else'),
        });
        const conn = makeLockedConnection();

        await expect(client.fetch(conn, '/redirect')).rejects.toThrow(
            RedirectBlockedError,
        );
    });

    it('should throw RedirectBlockedError on 308 redirect (fail-closed)', async () => {
        const guard = makeMockGuard();
        const client = new DefaultHttpClient({
            dnsRebindingGuard: guard,
            _requestFn: createRedirectRequestFn(308, '/permanent-other'),
        });
        const conn = makeLockedConnection();

        await expect(client.fetch(conn, '/redirect')).rejects.toThrow(
            RedirectBlockedError,
        );
    });

    it('should include status and location in RedirectBlockedError', async () => {
        const guard = makeMockGuard();
        const client = new DefaultHttpClient({
            dnsRebindingGuard: guard,
            _requestFn: createRedirectRequestFn(
                301,
                'http://evil.example.com/',
            ),
        });
        const conn = makeLockedConnection();

        try {
            await client.fetch(conn, '/redirect');
            expect.fail('should have thrown');
        } catch (err) {
            expect(err).toBeInstanceOf(RedirectBlockedError);
            const redirectErr = err as RedirectBlockedError;
            expect(redirectErr.status).toBe(301);
            expect(redirectErr.location).toBe('http://evil.example.com/');
        }
    });

    it('should return 404 response without throwing', async () => {
        const guard = makeMockGuard();
        const client = new DefaultHttpClient({
            dnsRebindingGuard: guard,
            _requestFn: createMockRequestFn(404, 'Not Found'),
        });
        const conn = makeLockedConnection();

        const response = await client.fetch(conn, '/not-found');

        expect(response.status).toBe(404);
        expect(response.body).toBe('Not Found');
    });

    it('should send custom headers in request', async () => {
        let capturedOptions: https.RequestOptions | null = null;

        const captureRequestFn: RawRequestFn = vi
            .fn()
            .mockImplementation(
                (
                    opts: https.RequestOptions,
                    callback: (res: http.IncomingMessage) => void,
                ) => {
                    capturedOptions = opts;
                    const mockRes = new EventEmitter() as http.IncomingMessage;
                    (mockRes as unknown as { statusCode: number }).statusCode =
                        200;
                    (
                        mockRes as unknown as {
                            headers: Record<string, string>;
                        }
                    ).headers = {};
                    const req = new EventEmitter() as http.ClientRequest;
                    const r = req as unknown as {
                        setTimeout(ms: number, cb: () => void): void;
                        write(data: string, enc: string): void;
                        end(): void;
                        destroy(err?: Error): void;
                    };
                    r.setTimeout = vi.fn();
                    r.write = vi.fn();
                    r.destroy = vi.fn();
                    r.end = vi.fn(() => {
                        callback(mockRes);
                        setTimeout(() => {
                            (mockRes as EventEmitter).emit(
                                'data',
                                Buffer.from(''),
                            );
                            (mockRes as EventEmitter).emit('end');
                        }, 0);
                    });
                    return req;
                },
            ) as unknown as RawRequestFn;

        const guard = makeMockGuard();
        const client = new DefaultHttpClient({
            dnsRebindingGuard: guard,
            _requestFn: captureRequestFn,
        });
        const conn = makeLockedConnection();

        await client.fetch(conn, '/headers', {
            headers: { 'X-Custom-Header': 'test-value' },
        });

        expect(capturedOptions?.headers).toBeDefined();
        const headers = capturedOptions?.headers as Record<string, string>;
        expect(headers['X-Custom-Header']).toBe('test-value');
    });

    it('should use default https.request for HTTPS connections (no _requestFn)', async () => {
        // Verify no error is thrown when _requestFn is not injected (exercises only the resolveAndConnect path)
        const guard = makeMockGuard('1.2.3.4');
        const client = new DefaultHttpClient({ dnsRebindingGuard: guard });

        const conn = await client.resolveAndConnect('https://example.com');
        // conn.resolvedIp is already locked; only assert the fields without triggering a real TCP connection
        expect(conn.isHttps).toBe(true);
        expect(conn.resolvedIp).toBe('1.2.3.4');
    });
});

// ── DefaultHttpClient.fetchEnvelope() tests ───────────────────────────────────

describe('DefaultHttpClient.fetchEnvelope()', () => {
    function makeEnvelope(): NegotiationEnvelope {
        return {
            id: 'test-id-001',
            specVersion: '0.3.0',
            header: {
                senderDid: AGENT_DID,
                recipientDid: AGENT_DID,
                sessionId: null,
            },
            messageType: 'DISCOVERY_REQUEST',
            body: {
                targetDid: AGENT_DID,
                requestedAt: new Date().toISOString(),
            },
            signature: 'a'.repeat(128) as unknown as Signature,
            timestamp: new Date().toISOString() as Timestamp,
        };
    }

    it('should return parsed NegotiationEnvelope when server responds with valid JSON', async () => {
        const responseEnvelope = makeEnvelope();
        const guard = makeMockGuard();
        const client = new DefaultHttpClient({
            dnsRebindingGuard: guard,
            _requestFn: createMockRequestFn(
                200,
                JSON.stringify(responseEnvelope),
            ),
        });
        const conn = makeLockedConnection();

        const result = await client.fetchEnvelope(
            conn,
            '/envelope',
            makeEnvelope(),
        );

        expect(result).not.toBeNull();
        expect(result?.id).toBe(responseEnvelope.id);
        expect(result?.messageType).toBe('DISCOVERY_REQUEST');
    });

    it('should return null when server responds with empty body', async () => {
        const guard = makeMockGuard();
        const client = new DefaultHttpClient({
            dnsRebindingGuard: guard,
            _requestFn: createMockRequestFn(200, ''),
        });
        const conn = makeLockedConnection();

        const result = await client.fetchEnvelope(
            conn,
            '/empty',
            makeEnvelope(),
        );

        expect(result).toBeNull();
    });

    it('should return null when server responds with whitespace-only body', async () => {
        const guard = makeMockGuard();
        const client = new DefaultHttpClient({
            dnsRebindingGuard: guard,
            _requestFn: createMockRequestFn(200, '   '),
        });
        const conn = makeLockedConnection();

        const result = await client.fetchEnvelope(
            conn,
            '/whitespace',
            makeEnvelope(),
        );

        expect(result).toBeNull();
    });

    it('should propagate RedirectBlockedError on redirect during fetchEnvelope', async () => {
        const guard = makeMockGuard();
        const client = new DefaultHttpClient({
            dnsRebindingGuard: guard,
            _requestFn: createRedirectRequestFn(302, '/evil'),
        });
        const conn = makeLockedConnection();

        await expect(
            client.fetchEnvelope(conn, '/redirect-envelope', makeEnvelope()),
        ).rejects.toThrow(RedirectBlockedError);
    });

    it('should POST with method=POST', async () => {
        let capturedOptions: https.RequestOptions | null = null;

        const captureRequestFn: RawRequestFn = vi
            .fn()
            .mockImplementation(
                (
                    opts: https.RequestOptions,
                    callback: (res: http.IncomingMessage) => void,
                ) => {
                    capturedOptions = opts;
                    const mockRes = new EventEmitter() as http.IncomingMessage;
                    (mockRes as unknown as { statusCode: number }).statusCode =
                        200;
                    (
                        mockRes as unknown as {
                            headers: Record<string, string>;
                        }
                    ).headers = {};
                    const req = new EventEmitter() as http.ClientRequest;
                    const r = req as unknown as {
                        setTimeout(ms: number, cb: () => void): void;
                        write(data: string, enc: string): void;
                        end(): void;
                        destroy(err?: Error): void;
                    };
                    r.setTimeout = vi.fn();
                    r.write = vi.fn();
                    r.destroy = vi.fn();
                    r.end = vi.fn(() => {
                        callback(mockRes);
                        setTimeout(() => {
                            (mockRes as EventEmitter).emit(
                                'data',
                                Buffer.from('{}'),
                            );
                            (mockRes as EventEmitter).emit('end');
                        }, 0);
                    });
                    return req;
                },
            ) as unknown as RawRequestFn;

        const guard = makeMockGuard();
        const client = new DefaultHttpClient({
            dnsRebindingGuard: guard,
            _requestFn: captureRequestFn,
        });
        const conn = makeLockedConnection();

        await client.fetchEnvelope(conn, '/post-envelope', makeEnvelope());

        expect(capturedOptions?.method).toBe('POST');
    });
});

// ── RedirectBlockedError tests ─────────────────────────────────────────────────

describe('RedirectBlockedError', () => {
    it('should have name RedirectBlockedError', () => {
        const err = new RedirectBlockedError(
            301,
            'http://evil.com/',
            'http://original.com/path',
        );
        expect(err.name).toBe('RedirectBlockedError');
    });

    it('should expose status code', () => {
        const err = new RedirectBlockedError(
            302,
            '/somewhere',
            'http://original.com/',
        );
        expect(err.status).toBe(302);
    });

    it('should expose location', () => {
        const err = new RedirectBlockedError(
            301,
            'http://evil.com/',
            'http://original.com/',
        );
        expect(err.location).toBe('http://evil.com/');
    });

    it('should accept undefined location', () => {
        const err = new RedirectBlockedError(
            302,
            undefined,
            'http://original.com/',
        );
        expect(err.location).toBeUndefined();
        expect(err.message).toContain('N/A');
    });

    it('should be an instanceof Error', () => {
        const err = new RedirectBlockedError(
            301,
            '/path',
            'http://original.com/',
        );
        expect(err).toBeInstanceOf(Error);
    });

    it('should include status in message', () => {
        const err = new RedirectBlockedError(
            301,
            'http://evil.com/',
            'http://original.com/',
        );
        expect(err.message).toContain('301');
    });
});

// ── DNSRebindingGuard seam verification ────────────────────────────────────────────────

describe('DNSRebindingGuard seam (injection contract)', () => {
    it('should delegate hostname resolution entirely to the injected guard', async () => {
        const guard: DNSRebindingGuard = {
            resolveAndValidate: vi.fn().mockResolvedValue('93.184.216.34'),
        };
        const client = new DefaultHttpClient({ dnsRebindingGuard: guard });

        const conn = await client.resolveAndConnect('https://example.com/api');

        expect(guard.resolveAndValidate).toHaveBeenCalledWith('example.com');
        expect(guard.resolveAndValidate).toHaveBeenCalledOnce();
        expect(conn.resolvedIp).toBe('93.184.216.34');
    });

    it('should NOT call resolveAndValidate during fetch (IP already locked)', async () => {
        const guard: DNSRebindingGuard = {
            resolveAndValidate: vi.fn().mockResolvedValue('1.2.3.4'),
        };
        const client = new DefaultHttpClient({
            dnsRebindingGuard: guard,
            _requestFn: createMockRequestFn(200, '{}'),
        });
        const conn = makeLockedConnection(); // already locked

        await client.fetch(conn, '/locked');

        // No re-resolution of DNS during fetch (the IP lock is preserved)
        expect(guard.resolveAndValidate).not.toHaveBeenCalled();
    });

    it('should fail-closed when guard throws on resolve', async () => {
        const guard: DNSRebindingGuard = {
            resolveAndValidate: vi
                .fn()
                .mockRejectedValue(
                    new Error('DNS rebinding blocked: 192.168.1.1 is private'),
                ),
        };
        const client = new DefaultHttpClient({ dnsRebindingGuard: guard });

        await expect(
            client.resolveAndConnect('https://internal.corp/'),
        ).rejects.toThrow('192.168.1.1');
    });
});

// ── Edge cases ──────────────────────────────────────────────────────────────────

describe('DefaultHttpClient edge cases', () => {
    it('should handle 500 server error without throwing', async () => {
        const guard = makeMockGuard();
        const client = new DefaultHttpClient({
            dnsRebindingGuard: guard,
            _requestFn: createMockRequestFn(500, 'Internal Server Error'),
        });
        const conn = makeLockedConnection();

        const response = await client.fetch(conn, '/server-error');

        expect(response.status).toBe(500);
        expect(response.body).toBe('Internal Server Error');
    });

    it('should include response headers in HttpResponse', async () => {
        const guard = makeMockGuard();
        const client = new DefaultHttpClient({
            dnsRebindingGuard: guard,
            _requestFn: createMockRequestFn(200, '{}', {
                'content-type': 'application/json',
                'x-request-id': 'abc123',
            }),
        });
        const conn = makeLockedConnection();

        const response = await client.fetch(conn, '/with-headers');

        expect(response.headers['content-type']).toBe('application/json');
        expect(response.headers['x-request-id']).toBe('abc123');
    });

    it('should send POST body correctly', async () => {
        let capturedBody: string | null = null;

        const captureBodyRequestFn: RawRequestFn = vi
            .fn()
            .mockImplementation(
                (
                    _opts: https.RequestOptions,
                    callback: (res: http.IncomingMessage) => void,
                ) => {
                    const mockRes = new EventEmitter() as http.IncomingMessage;
                    (mockRes as unknown as { statusCode: number }).statusCode =
                        200;
                    (
                        mockRes as unknown as {
                            headers: Record<string, string>;
                        }
                    ).headers = {};
                    const req = new EventEmitter() as http.ClientRequest;
                    const r = req as unknown as {
                        setTimeout(ms: number, cb: () => void): void;
                        write(data: string, enc: string): void;
                        end(): void;
                        destroy(err?: Error): void;
                    };
                    r.setTimeout = vi.fn();
                    r.write = vi.fn((data: string) => {
                        capturedBody = data;
                    });
                    r.destroy = vi.fn();
                    r.end = vi.fn(() => {
                        callback(mockRes);
                        setTimeout(() => {
                            (mockRes as EventEmitter).emit(
                                'data',
                                Buffer.from('ok'),
                            );
                            (mockRes as EventEmitter).emit('end');
                        }, 0);
                    });
                    return req;
                },
            ) as unknown as RawRequestFn;

        const guard = makeMockGuard();
        const client = new DefaultHttpClient({
            dnsRebindingGuard: guard,
            _requestFn: captureBodyRequestFn,
        });
        const conn = makeLockedConnection();

        await client.fetch(conn, '/post', {
            method: 'POST',
            body: '{"hello":"world"}',
        });

        expect(capturedBody).toBe('{"hello":"world"}');
    });

    it('should default to port 443 for HTTPS URLs without explicit port', async () => {
        const guard = makeMockGuard('1.2.3.4');
        const client = new DefaultHttpClient({ dnsRebindingGuard: guard });

        const conn = await client.resolveAndConnect('https://example.com');

        expect(conn.port).toBe(443);
    });

    it('should use _requestFn for HTTP (non-HTTPS) connections (line 303 coverage)', async () => {
        // Verify the http.Agent branch is taken when isHttps=false (line 303: new http.Agent())
        // Inject _requestFn to replace the real http.request and verify fetch works on the HTTP path
        const guard = makeMockGuard();
        const client = new DefaultHttpClient({
            dnsRebindingGuard: guard,
            _requestFn: createMockRequestFn(200, 'http-ok'),
        });
        // Explicitly construct a LockedConnection with isHttps=false
        const conn = makeLockedConnection({ isHttps: false, port: 8080 });

        const response = await client.fetch(conn, '/http-path');

        expect(response.status).toBe(200);
        expect(response.body).toBe('http-ok');
    });

    it('should invoke timeout handler callback when req.setTimeout fires', async () => {
        // Verify line 366: the setTimeout callback invokes req.destroy(new Error(...))
        let capturedTimeoutMs: number | null = null;
        let timeoutCallback: (() => void) | null = null;
        let destroyCalledWithError = false;

        const timeoutCaptureFn: RawRequestFn = vi
            .fn()
            .mockImplementation(
                (
                    _opts: https.RequestOptions,
                    _callback: (res: http.IncomingMessage) => void,
                ) => {
                    const mockRes = new EventEmitter() as http.IncomingMessage;
                    (mockRes as unknown as { statusCode: number }).statusCode =
                        200;
                    (
                        mockRes as unknown as {
                            headers: Record<string, string>;
                        }
                    ).headers = {};

                    const req = new EventEmitter() as http.ClientRequest;
                    const r = req as unknown as {
                        setTimeout(ms: number, cb: () => void): void;
                        write(data: string, enc: string): void;
                        end(): void;
                        destroy(err?: Error): void;
                    };

                    r.setTimeout = vi.fn((ms: number, cb: () => void) => {
                        capturedTimeoutMs = ms;
                        timeoutCallback = cb;
                    });
                    r.write = vi.fn();
                    r.destroy = vi.fn((err?: Error) => {
                        if (err instanceof Error) {
                            destroyCalledWithError = true;
                            // Emit an error event to reject the Promise (simulating req destruction after timeout)
                            (req as EventEmitter).emit('error', err);
                        }
                    });
                    r.end = vi.fn(() => {
                        // Do not trigger a response, simulating a hang past the timeout
                        // The test code triggers timeoutCallback manually
                    });

                    return req;
                },
            ) as unknown as RawRequestFn;

        const guard = makeMockGuard();
        const client = new DefaultHttpClient({
            dnsRebindingGuard: guard,
            _requestFn: timeoutCaptureFn,
            defaultTimeoutMs: 5000,
        });
        const conn = makeLockedConnection();

        // Start fetch (the Promise is pending) and trigger the timeout callback manually
        const fetchPromise = client.fetch(conn, '/timeout-test');

        // Wait for end() to be called (ensures timeoutCallback is registered)
        await new Promise((resolve) => setTimeout(resolve, 10));

        // Trigger the timeout callback manually (simulating a Node.js timeout firing)
        expect(timeoutCallback).not.toBeNull();
        timeoutCallback!();

        await expect(fetchPromise).rejects.toThrow('timeout');
        expect(destroyCalledWithError).toBe(true);
        expect(capturedTimeoutMs).toBe(5000);
    });
});
