// HTTP transport enhancement tests: retries, timeout, Content-Type validation, connection pool.
// All unit tests use useConnectionPool: false and mock via vi.stubGlobal('fetch', ...).

import { EventEmitter } from 'node:events';
import { Readable } from 'node:stream';

import { afterEach, describe, expect, it, vi } from 'vitest';

import type {
    DID,
    NegotiationEnvelope,
    Signature,
    Timestamp,
} from '@coivitas/types';
import { ProtocolError } from '@coivitas/types';

import { HttpTransport } from '../http.js';

type HttpTransportModule = { HttpTransport: typeof HttpTransport };

const describeIfSockets =
    process.env.ENABLE_SOCKET_TESTS === '1' ? describe : describe.skip;

const baseEnvelope: NegotiationEnvelope = {
    id: '660e8400-e29b-41d4-a716-446655440001',
    specVersion: '1.0.0',
    header: {
        senderDid: 'did:agent:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0' as DID,
        recipientDid:
            'did:agent:00112233445566778899aabbccddeeff00112233' as DID,
        sessionId: null,
        sequenceNumber: 1,
    },
    messageType: 'NEGOTIATION_REQUEST',
    body: {
        action: 'INQUIRY',
        params: { sku: 'SKU-001' },
    },
    signature: 'a'.repeat(128) as Signature,
    timestamp: '2026-04-02T10:00:00.000Z' as Timestamp,
};

/** Builds a successful 200 JSON response*/
function makeOkResponse(body: NegotiationEnvelope): Response {
    return new Response(JSON.stringify(body), {
        status: 200,
        headers: { 'content-type': 'application/json' },
    });
}

/** Builds an empty response with the given status code*/
function makeStatusResponse(status: number): Response {
    return new Response(null, { status });
}

describe('HttpTransport', () => {
    afterEach(() => {
        vi.restoreAllMocks();
        vi.unstubAllGlobals();
    });

    // ─── 01a/01b/01c baseline (backward-compatible with the original tests) ───────────────────────────────

    it('sends envelopes over fetch and returns the parsed response payload', async () => {
        vi.stubGlobal(
            'fetch',
            vi.fn(() =>
                Promise.resolve(
                    makeOkResponse({
                        ...baseEnvelope,
                        messageType: 'NEGOTIATION_RESPONSE',
                        body: {
                            status: 'accepted',
                            requestId: baseEnvelope.id,
                        },
                    } satisfies NegotiationEnvelope),
                ),
            ),
        );

        const client = new HttpTransport({ useConnectionPool: false });
        const response = await client.send(
            baseEnvelope,
            'http://agent.example',
        );

        expect(response).toEqual({
            ...baseEnvelope,
            messageType: 'NEGOTIATION_RESPONSE',
            body: {
                status: 'accepted',
                requestId: baseEnvelope.id,
            },
        });
    });

    it('returns null when the remote endpoint replies with 204', async () => {
        vi.stubGlobal(
            'fetch',
            vi.fn(() => Promise.resolve(makeStatusResponse(204))),
        );

        await expect(
            new HttpTransport({ useConnectionPool: false }).send(
                baseEnvelope,
                'http://agent.example',
            ),
        ).resolves.toBeNull();
    });

    it('rejects non-2xx responses from the remote endpoint', async () => {
        vi.stubGlobal(
            'fetch',
            vi.fn(() => Promise.resolve(makeStatusResponse(500))),
        );

        // 500 triggers retries (default maxRetries=3), so set maxRetries=0 to fail immediately
        await expect(
            new HttpTransport({
                useConnectionPool: false,
                maxRetries: 0,
            }).send(baseEnvelope, 'http://agent.example'),
        ).rejects.toThrow(/status 500/i);
    });

    // ─── 01a exponential backoff retries ────────────────────────────────────────────────────

    it('should retry on 429 and succeed on the second attempt', async () => {
        const responseEnvelope: NegotiationEnvelope = {
            ...baseEnvelope,
            messageType: 'NEGOTIATION_RESPONSE',
            body: { status: 'accepted', requestId: baseEnvelope.id },
        };
        const mockFetch = vi
            .fn()
            .mockResolvedValueOnce(makeStatusResponse(429))
            .mockResolvedValueOnce(makeOkResponse(responseEnvelope));
        vi.stubGlobal('fetch', mockFetch);

        const client = new HttpTransport({
            useConnectionPool: false,
            maxRetries: 3,
            baseDelayMs: 0, // remove the delay in tests
            maxDelayMs: 0,
        });

        const result = await client.send(baseEnvelope, 'http://agent.example');
        expect(result).toEqual(responseEnvelope);
        expect(mockFetch).toHaveBeenCalledTimes(2);
    });

    it('should retry on 503 and succeed on the third attempt', async () => {
        const responseEnvelope: NegotiationEnvelope = {
            ...baseEnvelope,
            messageType: 'NEGOTIATION_RESPONSE',
            body: { status: 'accepted', requestId: baseEnvelope.id },
        };
        const mockFetch = vi
            .fn()
            .mockResolvedValueOnce(makeStatusResponse(503))
            .mockResolvedValueOnce(makeStatusResponse(503))
            .mockResolvedValueOnce(makeOkResponse(responseEnvelope));
        vi.stubGlobal('fetch', mockFetch);

        const client = new HttpTransport({
            useConnectionPool: false,
            maxRetries: 3,
            baseDelayMs: 0,
            maxDelayMs: 0,
        });

        const result = await client.send(baseEnvelope, 'http://agent.example');
        expect(result).toEqual(responseEnvelope);
        expect(mockFetch).toHaveBeenCalledTimes(3);
    });

    it('should exhaust retries and throw when all attempts return 5xx', async () => {
        const mockFetch = vi
            .fn()
            .mockResolvedValue(makeStatusResponse(500));
        vi.stubGlobal('fetch', mockFetch);

        const client = new HttpTransport({
            useConnectionPool: false,
            maxRetries: 3,
            baseDelayMs: 0,
            maxDelayMs: 0,
        });

        await expect(
            client.send(baseEnvelope, 'http://agent.example'),
        ).rejects.toThrow(/status 500/i);
        // 1 initial attempt + 3 retries = 4 attempts
        expect(mockFetch).toHaveBeenCalledTimes(4);
    });

    it('should NOT retry on 4xx errors other than 429', async () => {
        const mockFetch = vi
            .fn()
            .mockResolvedValue(makeStatusResponse(400));
        vi.stubGlobal('fetch', mockFetch);

        const client = new HttpTransport({
            useConnectionPool: false,
            maxRetries: 3,
            baseDelayMs: 0,
            maxDelayMs: 0,
        });

        await expect(
            client.send(baseEnvelope, 'http://agent.example'),
        ).rejects.toThrow(/status 400/i);
        // 4xx other than 429 are not retried, only sent once
        expect(mockFetch).toHaveBeenCalledTimes(1);
    });

    it('should NOT retry on 403 Forbidden', async () => {
        const mockFetch = vi
            .fn()
            .mockResolvedValue(makeStatusResponse(403));
        vi.stubGlobal('fetch', mockFetch);

        const client = new HttpTransport({
            useConnectionPool: false,
            maxRetries: 3,
            baseDelayMs: 0,
            maxDelayMs: 0,
        });

        await expect(
            client.send(baseEnvelope, 'http://agent.example'),
        ).rejects.toThrow(/status 403/i);
        expect(mockFetch).toHaveBeenCalledTimes(1);
    });

    // ─── 01b request timeout ────────────────────────────────────────────────────────

    it('should throw ProtocolError TRANSPORT_ERROR when fetch is aborted due to timeout', async () => {
        // Simulate fetch throwing an AbortError
        const abortError = new DOMException('signal is aborted', 'AbortError');
        vi.stubGlobal('fetch', vi.fn().mockRejectedValue(abortError));

        const client = new HttpTransport({
            useConnectionPool: false,
            timeoutMs: 50,
            maxRetries: 0,
        });

        const err = await client
            .send(baseEnvelope, 'http://agent.example')
            .catch((e: unknown) => e);

        expect(err).toBeInstanceOf(ProtocolError);
        expect((err as ProtocolError).code).toBe('TRANSPORT_ERROR');
        expect((err as ProtocolError).message).toContain('timed out');
    });

    it('should throw ProtocolError TRANSPORT_ERROR when request times out naturally', async () => {
        // Simulate fetch hanging forever, relying on AbortController to cancel
        vi.stubGlobal(
            'fetch',
            vi.fn(
                (_url: string, opts: RequestInit) =>
                    new Promise<Response>((_resolve, reject) => {
                        const signal = opts.signal as AbortSignal;
                        signal.addEventListener('abort', () => {
                            reject(
                                new DOMException(
                                    'The operation was aborted.',
                                    'AbortError',
                                ),
                            );
                        });
                    }),
            ),
        );

        const client = new HttpTransport({
            useConnectionPool: false,
            timeoutMs: 30, // 30ms timeout, so the test finishes quickly
            maxRetries: 0,
        });

        const err = await client
            .send(baseEnvelope, 'http://agent.example')
            .catch((e: unknown) => e);

        expect(err).toBeInstanceOf(ProtocolError);
        expect((err as ProtocolError).code).toBe('TRANSPORT_ERROR');
    });

    // ─── 01c Content-Type validation ───────────────────────────────────────────────

    it('should throw when response has wrong content-type', async () => {
        vi.stubGlobal(
            'fetch',
            vi.fn(() =>
                Promise.resolve(
                    new Response(JSON.stringify(baseEnvelope), {
                        status: 200,
                        headers: { 'content-type': 'text/plain' },
                    }),
                ),
            ),
        );

        const client = new HttpTransport({
            useConnectionPool: false,
            maxRetries: 0,
        });

        await expect(
            client.send(baseEnvelope, 'http://agent.example'),
        ).rejects.toThrow(/content-type/i);
    });

    it('should accept response with content-type including charset suffix', async () => {
        const responseEnvelope: NegotiationEnvelope = {
            ...baseEnvelope,
            messageType: 'NEGOTIATION_RESPONSE',
            body: { status: 'accepted', requestId: baseEnvelope.id },
        };
        vi.stubGlobal(
            'fetch',
            vi.fn(() =>
                Promise.resolve(
                    new Response(JSON.stringify(responseEnvelope), {
                        status: 200,
                        headers: {
                            'content-type': 'application/json; charset=utf-8',
                        },
                    }),
                ),
            ),
        );

        const client = new HttpTransport({ useConnectionPool: false });
        const result = await client.send(
            baseEnvelope,
            'http://agent.example',
        );
        expect(result).toEqual(responseEnvelope);
    });
});

// ─── 01d connection pool (node:http.request path) mock tests ───────────────────────
// Use vi.mock to mock the request function of node:http, covering the sendViaNodeHttp branch.
// Because the sandbox cannot bind a real port, the entire request/response lifecycle is simulated via EventEmitter mocks.

describe('HttpTransport connection pool (node:http)', () => {
    /**
     * Builds a mocked http.ClientRequest + IncomingMessage pair.
     * statusCode: response status code
     * headers: response headers
     * body: response body string (null means no body)
     * triggerTimeout: whether to emit a timeout event
     * triggerError: whether to emit an error event
     */
    function buildMockHttpPair(opts: {
        statusCode: number;
        headers?: Record<string, string>;
        body?: string | null;
        triggerTimeout?: boolean;
        triggerRequestError?: boolean;
    }) {
        // Mock IncomingMessage (response)
        const res = new EventEmitter() as NodeJS.EventEmitter & {
            statusCode: number;
            headers: Record<string, string>;
        };
        res.statusCode = opts.statusCode;
        res.headers = opts.headers ?? {};

        // Mock ClientRequest (request)
        const req = new EventEmitter() as NodeJS.EventEmitter & {
            write: (data: string) => void;
            end: () => void;
            destroy: () => void;
        };
        req.write = vi.fn();
        req.destroy = vi.fn(() => {
            req.emit('error', Object.assign(new Error('socket hang up'), { code: 'ECONNRESET' }));
        });
        req.end = vi.fn(() => {
            if (opts.triggerTimeout) {
                // Emit timeout on the next tick
                setImmediate(() => req.emit('timeout'));
                return;
            }
            if (opts.triggerRequestError) {
                setImmediate(() =>
                    req.emit('error', new Error('ECONNREFUSED')),
                );
                return;
            }
            // Normal path: after invoking callback(res), emit data/end
            setImmediate(() => {
                if (opts.body !== null && opts.body !== undefined) {
                    setImmediate(() => {
                        res.emit('data', Buffer.from(opts.body as string));
                        res.emit('end');
                    });
                } else {
                    setImmediate(() => res.emit('end'));
                }
            });
        });

        return { req, res };
    }

    it('should round-trip an envelope via node:http keep-alive Agent', async () => {
        const responseEnvelope: NegotiationEnvelope = {
            ...baseEnvelope,
            messageType: 'NEGOTIATION_RESPONSE',
            body: { status: 'accepted', requestId: baseEnvelope.id },
        };
        const { req, res } = buildMockHttpPair({
            statusCode: 200,
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify(responseEnvelope),
        });

        const mockRequest = vi.fn((_opts: unknown, callback: (res: unknown) => void) => {
            setImmediate(() => callback(res));
            return req;
        });

        vi.doMock('node:http', async (importOriginal) => {
            const actual = await importOriginal<typeof import('node:http')>();
            return { ...actual, request: mockRequest };
        });

        // Re-import so the mock takes effect
        const { HttpTransport: MockedTransport } = await (import('../http.js?mock-pool-1') as Promise<HttpTransportModule>);
        const client = new MockedTransport();
        const result = await client.send(baseEnvelope, 'http://agent.example');
        expect(result).toEqual(responseEnvelope);

        vi.doUnmock('node:http');
    });

    it('should return null for 204 via node:http', async () => {
        const { req, res } = buildMockHttpPair({ statusCode: 204, body: null });

        const mockRequest = vi.fn((_opts: unknown, callback: (res: unknown) => void) => {
            setImmediate(() => callback(res));
            return req;
        });

        vi.doMock('node:http', async (importOriginal) => {
            const actual = await importOriginal<typeof import('node:http')>();
            return { ...actual, request: mockRequest };
        });

        const { HttpTransport: MockedTransport } = await (import('../http.js?mock-pool-2') as Promise<HttpTransportModule>);
        const client = new MockedTransport();
        const result = await client.send(baseEnvelope, 'http://agent.example');
        expect(result).toBeNull();

        vi.doUnmock('node:http');
    });

    it('should throw ProtocolError on timeout via node:http', async () => {
        // Build the mock: after the timeout event, req.destroy emits no extra error event
        const req = new EventEmitter() as NodeJS.EventEmitter & {
            write: () => void;
            end: () => void;
            destroy: () => void;
        };
        req.write = vi.fn();
        // destroy only marks destruction, does not emit error (avoids a race)
        req.destroy = vi.fn();
        req.end = vi.fn(() => {
            // Emit timeout on the next tick
            setImmediate(() => req.emit('timeout'));
        });

        const mockRequest = vi.fn((_opts: unknown, _callback: (res: unknown) => void) => {
            return req;
        });

        vi.doMock('node:http', async (importOriginal) => {
            const actual = await importOriginal<typeof import('node:http')>();
            return { ...actual, request: mockRequest };
        });

        const { HttpTransport: MockedTransport } = await (import('../http.js?mock-pool-3') as Promise<HttpTransportModule>);
        const client = new MockedTransport({ timeoutMs: 50, maxRetries: 0 });
        const err = await client
            .send(baseEnvelope, 'http://agent.example')
            .catch((e: unknown) => e);

        expect(err).toBeInstanceOf(ProtocolError);
        expect((err as ProtocolError).code).toBe('TRANSPORT_ERROR');
        expect((err as ProtocolError).message).toContain('timed out');

        vi.doUnmock('node:http');
    });

    it('should wrap request error in ProtocolError via node:http', async () => {
        const { req } = buildMockHttpPair({
            statusCode: 200,
            body: null,
            triggerRequestError: true,
        });

        const mockRequest = vi.fn((_opts: unknown, _callback: (res: unknown) => void) => {
            return req;
        });

        vi.doMock('node:http', async (importOriginal) => {
            const actual = await importOriginal<typeof import('node:http')>();
            return { ...actual, request: mockRequest };
        });

        const { HttpTransport: MockedTransport } = await (import('../http.js?mock-pool-4') as Promise<HttpTransportModule>);
        const client = new MockedTransport({ maxRetries: 0 });
        const err = await client
            .send(baseEnvelope, 'http://agent.example')
            .catch((e: unknown) => e);

        expect(err).toBeInstanceOf(ProtocolError);
        expect((err as ProtocolError).code).toBe('TRANSPORT_ERROR');

        vi.doUnmock('node:http');
    });

    it('should retry 429 via node:http and succeed on second attempt', async () => {
        const responseEnvelope: NegotiationEnvelope = {
            ...baseEnvelope,
            messageType: 'NEGOTIATION_RESPONSE',
            body: { status: 'accepted', requestId: baseEnvelope.id },
        };
        let callCount = 0;

        const mockRequest = vi.fn((_opts: unknown, callback: (res: unknown) => void) => {
            callCount++;
            const res = new EventEmitter() as NodeJS.EventEmitter & {
                statusCode: number;
                headers: Record<string, string>;
            };
            if (callCount === 1) {
                res.statusCode = 429;
                res.headers = {};
            } else {
                res.statusCode = 200;
                res.headers = { 'content-type': 'application/json' };
            }
            const req = new EventEmitter() as NodeJS.EventEmitter & {
                write: () => void;
                end: () => void;
                destroy: () => void;
            };
            req.write = vi.fn();
            req.destroy = vi.fn();
            req.end = vi.fn(() => {
                setImmediate(() => {
                    callback(res);
                    setImmediate(() => {
                        if (callCount > 1) {
                            res.emit('data', Buffer.from(JSON.stringify(responseEnvelope)));
                        }
                        res.emit('end');
                    });
                });
            });
            return req;
        });

        vi.doMock('node:http', async (importOriginal) => {
            const actual = await importOriginal<typeof import('node:http')>();
            return { ...actual, request: mockRequest };
        });

        const { HttpTransport: MockedTransport } = await (import('../http.js?mock-pool-5') as Promise<HttpTransportModule>);
        const client = new MockedTransport({
            maxRetries: 3,
            baseDelayMs: 0,
            maxDelayMs: 0,
        });
        const result = await client.send(baseEnvelope, 'http://agent.example');
        expect(callCount).toBe(2);
        expect(result).toEqual(responseEnvelope);

        vi.doUnmock('node:http');
    });

    it('should throw on wrong content-type via node:http', async () => {
        const { req, res } = buildMockHttpPair({
            statusCode: 200,
            headers: { 'content-type': 'text/plain' },
            body: JSON.stringify(baseEnvelope),
        });

        const mockRequest = vi.fn((_opts: unknown, callback: (res: unknown) => void) => {
            setImmediate(() => callback(res));
            return req;
        });

        vi.doMock('node:http', async (importOriginal) => {
            const actual = await importOriginal<typeof import('node:http')>();
            return { ...actual, request: mockRequest };
        });

        const { HttpTransport: MockedTransport } = await (import('../http.js?mock-pool-6') as Promise<HttpTransportModule>);
        const client = new MockedTransport({ maxRetries: 0 });
        await expect(
            client.send(baseEnvelope, 'http://agent.example'),
        ).rejects.toThrow(/content-type/i);

        vi.doUnmock('node:http');
    });

    it('should NOT retry on 400 Bad Request via node:http', async () => {
        let callCount = 0;

        const mockRequest = vi.fn((_opts: unknown, callback: (res: unknown) => void) => {
            callCount++;
            const res = new EventEmitter() as NodeJS.EventEmitter & {
                statusCode: number;
                headers: Record<string, string>;
            };
            res.statusCode = 400;
            res.headers = {};
            const req = new EventEmitter() as NodeJS.EventEmitter & {
                write: () => void;
                end: () => void;
                destroy: () => void;
            };
            req.write = vi.fn();
            req.destroy = vi.fn();
            req.end = vi.fn(() => {
                setImmediate(() => {
                    callback(res);
                    setImmediate(() => res.emit('end'));
                });
            });
            return req;
        });

        vi.doMock('node:http', async (importOriginal) => {
            const actual = await importOriginal<typeof import('node:http')>();
            return { ...actual, request: mockRequest };
        });

        const { HttpTransport: MockedTransport } = await (import('../http.js?mock-pool-7') as Promise<HttpTransportModule>);
        const client = new MockedTransport({ maxRetries: 3 });
        await expect(
            client.send(baseEnvelope, 'http://agent.example'),
        ).rejects.toThrow(/status 400/i);
        // 4xx other than 429 are not retried, only sent once
        expect(callCount).toBe(1);

        vi.doUnmock('node:http');
    });
});

// ─── listen / close / handleRequest mock coverage ───────────────────────────────
// Replace createServer via vi.doMock('node:http') to cover the server-side branches.

describe('HttpTransport server-side (mocked)', () => {
    it('should cover listen and close when server starts and stops', async () => {
        // mock server object
        const serverEmitter = new EventEmitter();
        const mockServer = Object.assign(serverEmitter, {
            listen: vi.fn((_port: number, _host: string) => {
                // Emit the listening event synchronously
                setImmediate(() => serverEmitter.emit('listening'));
            }),
            address: vi.fn(() => ({ port: 12345 })),
            close: vi.fn((cb: (err?: Error) => void) => cb()),
            closeAllConnections: vi.fn(),
        });

        const mockCreateServer = vi.fn(
            (_handler: (req: unknown, res: unknown) => void) => mockServer,
        );

        vi.doMock('node:http', async (importOriginal) => {
            const actual = await importOriginal<typeof import('node:http')>();
            return {
                ...actual,
                createServer: mockCreateServer,
                // Agent unchanged, to avoid affecting the constructor
                Agent: actual.Agent,
                request: actual.request,
            };
        });

        const { HttpTransport: MockedTransport } = await (import('../http.js?mock-server-1') as Promise<HttpTransportModule>);
        const transport = new MockedTransport();

        const handler = vi.fn((_env: NegotiationEnvelope) =>
            Promise.resolve(null),
        );

        const port = await transport.listen(0, handler);
        expect(port).toBe(12345);

        // close normal path
        await transport.close();
        expect(mockServer.closeAllConnections).toHaveBeenCalled();
        expect(mockServer.close).toHaveBeenCalled();

        // close again (server is already null, should return directly)
        await transport.close();

        vi.doUnmock('node:http');
    });

    it('should handle POST with valid JSON body and return 200', async () => {
        let capturedHandler: ((req: unknown, res: unknown) => void) | null = null;
        const serverEmitter = new EventEmitter();
        const mockServer = Object.assign(serverEmitter, {
            listen: vi.fn((_port: number, _host: string) => {
                setImmediate(() => serverEmitter.emit('listening'));
            }),
            address: vi.fn(() => ({ port: 12346 })),
            close: vi.fn((cb: (err?: Error) => void) => cb()),
            closeAllConnections: vi.fn(),
        });

        const mockCreateServer = vi.fn(
            (handler: (req: unknown, res: unknown) => void) => {
                capturedHandler = handler;
                return mockServer;
            },
        );

        vi.doMock('node:http', async (importOriginal) => {
            const actual = await importOriginal<typeof import('node:http')>();
            return {
                ...actual,
                createServer: mockCreateServer,
                Agent: actual.Agent,
                request: actual.request,
            };
        });

        const { HttpTransport: MockedTransport } = await (import('../http.js?mock-server-2') as Promise<HttpTransportModule>);
        const transport = new MockedTransport();

        const responseEnvelope: NegotiationEnvelope = {
            ...baseEnvelope,
            messageType: 'NEGOTIATION_RESPONSE',
            body: { status: 'accepted', requestId: baseEnvelope.id },
        };

        await transport.listen(0, (_env) => Promise.resolve(responseEnvelope));

        // Construct an async-iterable Readable mock (readRequestBody uses for await...of)
        const bodyBuffer = Buffer.from(JSON.stringify(baseEnvelope));
        const reqStream = Readable.from([bodyBuffer]) as unknown as {
            method: string;
            headers: Record<string, string>;
        } & NodeJS.ReadableStream;
        (reqStream as unknown as Record<string, unknown>).method = 'POST';
        (reqStream as unknown as Record<string, unknown>).headers = { 'content-type': 'application/json' };

        const resObj = {
            statusCode: 0,
            end: vi.fn(),
            setHeader: vi.fn(),
        };

        // Trigger request handling (Readable provides an async iterator automatically, no manual emit needed)
        capturedHandler!(reqStream, resObj);

        // Wait for async processing to complete
        await new Promise<void>((resolve) => setTimeout(resolve, 50));

        expect(resObj.statusCode).toBe(200);
        expect(resObj.setHeader).toHaveBeenCalledWith('content-type', 'application/json');

        await transport.close();
        vi.doUnmock('node:http');
    });

    it('should return 204 when handler returns null', async () => {
        let capturedHandler: ((req: unknown, res: unknown) => void) | null = null;
        const serverEmitter = new EventEmitter();
        const mockServer = Object.assign(serverEmitter, {
            listen: vi.fn(() => setImmediate(() => serverEmitter.emit('listening'))),
            address: vi.fn(() => ({ port: 12347 })),
            close: vi.fn((cb: (err?: Error) => void) => cb()),
            closeAllConnections: vi.fn(),
        });

        vi.doMock('node:http', async (importOriginal) => {
            const actual = await importOriginal<typeof import('node:http')>();
            return {
                ...actual,
                createServer: vi.fn((h: (req: unknown, res: unknown) => void) => {
                    capturedHandler = h;
                    return mockServer;
                }),
                Agent: actual.Agent,
                request: actual.request,
            };
        });

        const { HttpTransport: MockedTransport } = await (import('../http.js?mock-server-3') as Promise<HttpTransportModule>);
        const transport = new MockedTransport();
        await transport.listen(0, () => Promise.resolve(null));

        // Use Readable.from to provide an async-iterable stream (for await...of relies on Symbol.asyncIterator)
        const bodyBuffer = Buffer.from(JSON.stringify(baseEnvelope));
        const reqStream = Readable.from([bodyBuffer]);
        (reqStream as unknown as Record<string, unknown>).method = 'POST';
        (reqStream as unknown as Record<string, unknown>).headers = { 'content-type': 'application/json' };

        const resObj = { statusCode: 0, end: vi.fn(), setHeader: vi.fn() };
        capturedHandler!(reqStream, resObj);

        await new Promise<void>((resolve) => setTimeout(resolve, 50));
        expect(resObj.statusCode).toBe(204);

        await transport.close();
        vi.doUnmock('node:http');
    });

    it('should return 405 for non-POST requests', async () => {
        let capturedHandler: ((req: unknown, res: unknown) => void) | null = null;
        const serverEmitter = new EventEmitter();
        const mockServer = Object.assign(serverEmitter, {
            listen: vi.fn(() => setImmediate(() => serverEmitter.emit('listening'))),
            address: vi.fn(() => ({ port: 12348 })),
            close: vi.fn((cb: (err?: Error) => void) => cb()),
            closeAllConnections: vi.fn(),
        });

        vi.doMock('node:http', async (importOriginal) => {
            const actual = await importOriginal<typeof import('node:http')>();
            return {
                ...actual,
                createServer: vi.fn((h: (req: unknown, res: unknown) => void) => {
                    capturedHandler = h;
                    return mockServer;
                }),
                Agent: actual.Agent,
                request: actual.request,
            };
        });

        const { HttpTransport: MockedTransport } = await (import('../http.js?mock-server-4') as Promise<HttpTransportModule>);
        const transport = new MockedTransport();
        await transport.listen(0, () => Promise.resolve(null));

        const reqObj = { method: 'GET', headers: {} };
        const resObj = { statusCode: 0, end: vi.fn(), setHeader: vi.fn() };
        capturedHandler!(reqObj, resObj);

        await new Promise<void>((resolve) => setTimeout(resolve, 20));
        expect(resObj.statusCode).toBe(405);

        await transport.close();
        vi.doUnmock('node:http');
    });

    it('should return 415 when request content-type is not application/json', async () => {
        let capturedHandler: ((req: unknown, res: unknown) => void) | null = null;
        const serverEmitter = new EventEmitter();
        const mockServer = Object.assign(serverEmitter, {
            listen: vi.fn(() => setImmediate(() => serverEmitter.emit('listening'))),
            address: vi.fn(() => ({ port: 12349 })),
            close: vi.fn((cb: (err?: Error) => void) => cb()),
            closeAllConnections: vi.fn(),
        });

        vi.doMock('node:http', async (importOriginal) => {
            const actual = await importOriginal<typeof import('node:http')>();
            return {
                ...actual,
                createServer: vi.fn((h: (req: unknown, res: unknown) => void) => {
                    capturedHandler = h;
                    return mockServer;
                }),
                Agent: actual.Agent,
                request: actual.request,
            };
        });

        const { HttpTransport: MockedTransport } = await (import('../http.js?mock-server-5') as Promise<HttpTransportModule>);
        const transport = new MockedTransport();
        await transport.listen(0, () => Promise.resolve(null));

        const reqObj = { method: 'POST', headers: { 'content-type': 'text/plain' } };
        const resObj = { statusCode: 0, end: vi.fn(), setHeader: vi.fn() };
        capturedHandler!(reqObj, resObj);

        await new Promise<void>((resolve) => setTimeout(resolve, 20));
        expect(resObj.statusCode).toBe(415);

        await transport.close();
        vi.doUnmock('node:http');
    });

    it('should return 400 when handler throws', async () => {
        let capturedHandler: ((req: unknown, res: unknown) => void) | null = null;
        const serverEmitter = new EventEmitter();
        const mockServer = Object.assign(serverEmitter, {
            listen: vi.fn(() => setImmediate(() => serverEmitter.emit('listening'))),
            address: vi.fn(() => ({ port: 12350 })),
            close: vi.fn((cb: (err?: Error) => void) => cb()),
            closeAllConnections: vi.fn(),
        });

        vi.doMock('node:http', async (importOriginal) => {
            const actual = await importOriginal<typeof import('node:http')>();
            return {
                ...actual,
                createServer: vi.fn((h: (req: unknown, res: unknown) => void) => {
                    capturedHandler = h;
                    return mockServer;
                }),
                Agent: actual.Agent,
                request: actual.request,
            };
        });

        const { HttpTransport: MockedTransport } = await (import('../http.js?mock-server-6') as Promise<HttpTransportModule>);
        const transport = new MockedTransport();
        await transport.listen(0, () => {
            throw new Error('handler error');
        });

        const reqEmitter = new EventEmitter() as NodeJS.EventEmitter & {
            method: string;
            headers: Record<string, string>;
        };
        reqEmitter.method = 'POST';
        reqEmitter.headers = { 'content-type': 'application/json' };
        const resObj = { statusCode: 0, end: vi.fn(), setHeader: vi.fn() };
        capturedHandler!(reqEmitter, resObj);

        setImmediate(() => {
            reqEmitter.emit('data', Buffer.from(JSON.stringify(baseEnvelope)));
            reqEmitter.emit('end');
        });

        await new Promise<void>((resolve) => setTimeout(resolve, 50));
        expect(resObj.statusCode).toBe(400);

        await transport.close();
        vi.doUnmock('node:http');
    });

    it('should throw when address() returns null after listen', async () => {
        const serverEmitter = new EventEmitter();
        const mockServer = Object.assign(serverEmitter, {
            listen: vi.fn((_port: number, _host: string) => {
                setImmediate(() => serverEmitter.emit('listening'));
            }),
            // address() returns null -> triggers the "failed to bind" error path
            address: vi.fn(() => null),
            close: vi.fn((cb: (err?: Error) => void) => cb()),
            closeAllConnections: vi.fn(),
        });

        vi.doMock('node:http', async (importOriginal) => {
            const actual = await importOriginal<typeof import('node:http')>();
            return {
                ...actual,
                createServer: vi.fn(() => mockServer),
                Agent: actual.Agent,
                request: actual.request,
            };
        });

        const { HttpTransport: MockedTransport } = await (import('../http.js?mock-server-7') as Promise<HttpTransportModule>);
        const transport = new MockedTransport();

        await expect(transport.listen(0, () => Promise.resolve(null))).rejects.toThrow(
            'HTTP transport failed to bind to a TCP port.',
        );

        vi.doUnmock('node:http');
    });

    it('should reject when server.close() calls back with an error', async () => {
        const serverEmitter = new EventEmitter();
        const closeError = new Error('close failed');
        const mockServer = Object.assign(serverEmitter, {
            listen: vi.fn((_port: number, _host: string) => {
                setImmediate(() => serverEmitter.emit('listening'));
            }),
            address: vi.fn(() => ({ port: 12351 })),
            // close callback carries an error -> reject(error) path
            close: vi.fn((cb: (err?: Error) => void) => cb(closeError)),
            closeAllConnections: vi.fn(),
        });

        vi.doMock('node:http', async (importOriginal) => {
            const actual = await importOriginal<typeof import('node:http')>();
            return {
                ...actual,
                createServer: vi.fn(() => mockServer),
                Agent: actual.Agent,
                request: actual.request,
            };
        });

        const { HttpTransport: MockedTransport } = await (import('../http.js?mock-server-8') as Promise<HttpTransportModule>);
        const transport = new MockedTransport();
        await transport.listen(0, () => Promise.resolve(null));

        await expect(transport.close()).rejects.toThrow('close failed');

        vi.doUnmock('node:http');
    });

    it('should return 400 with fallback message when handler throws non-Error', async () => {
        let capturedHandler: ((req: unknown, res: unknown) => void) | null = null;
        const serverEmitter = new EventEmitter();
        const mockServer = Object.assign(serverEmitter, {
            listen: vi.fn(() => setImmediate(() => serverEmitter.emit('listening'))),
            address: vi.fn(() => ({ port: 12352 })),
            close: vi.fn((cb: (err?: Error) => void) => cb()),
            closeAllConnections: vi.fn(),
        });

        vi.doMock('node:http', async (importOriginal) => {
            const actual = await importOriginal<typeof import('node:http')>();
            return {
                ...actual,
                createServer: vi.fn((h: (req: unknown, res: unknown) => void) => {
                    capturedHandler = h;
                    return mockServer;
                }),
                Agent: actual.Agent,
                request: actual.request,
            };
        });

        const { HttpTransport: MockedTransport } = await (import('../http.js?mock-server-9') as Promise<HttpTransportModule>);
        const transport = new MockedTransport();
        // handler throws a non-Error object -> triggers the 'Invalid transport payload' branch
        // eslint-disable-next-line @typescript-eslint/only-throw-error
        await transport.listen(0, () => { throw 'string error'; });

        const bodyBuffer = Buffer.from(JSON.stringify(baseEnvelope));
        const reqStream = Readable.from([bodyBuffer]);
        (reqStream as unknown as Record<string, unknown>).method = 'POST';
        (reqStream as unknown as Record<string, unknown>).headers = { 'content-type': 'application/json' };

        const resObj = { statusCode: 0, end: vi.fn(), setHeader: vi.fn() };
        capturedHandler!(reqStream, resObj);

        await new Promise<void>((resolve) => setTimeout(resolve, 50));
        expect(resObj.statusCode).toBe(400);
        expect(resObj.end).toHaveBeenCalledWith(
            JSON.stringify({ error: 'Invalid transport payload' }),
        );

        await transport.close();
        vi.doUnmock('node:http');
    });

    it('should handle string chunks in readRequestBody', async () => {

        let capturedHandler: ((req: unknown, res: unknown) => void) | null = null;
        const serverEmitter = new EventEmitter();
        const mockServer = Object.assign(serverEmitter, {
            listen: vi.fn(() => setImmediate(() => serverEmitter.emit('listening'))),
            address: vi.fn(() => ({ port: 12353 })),
            close: vi.fn((cb: (err?: Error) => void) => cb()),
            closeAllConnections: vi.fn(),
        });

        vi.doMock('node:http', async (importOriginal) => {
            const actual = await importOriginal<typeof import('node:http')>();
            return {
                ...actual,
                createServer: vi.fn((h: (req: unknown, res: unknown) => void) => {
                    capturedHandler = h;
                    return mockServer;
                }),
                Agent: actual.Agent,
                request: actual.request,
            };
        });

        const { HttpTransport: MockedTransport } = await (import('../http.js?mock-server-10') as Promise<HttpTransportModule>);
        const transport = new MockedTransport();
        await transport.listen(0, (_env) => Promise.resolve(null));

        // Provide a string chunk (triggers the typeof chunk === 'string' branch)
        const bodyStr = JSON.stringify(baseEnvelope);
        const reqStream = Readable.from([bodyStr]); // string item -> chunk is string
        (reqStream as unknown as Record<string, unknown>).method = 'POST';
        (reqStream as unknown as Record<string, unknown>).headers = { 'content-type': 'application/json' };

        const resObj = { statusCode: 0, end: vi.fn(), setHeader: vi.fn() };
        capturedHandler!(reqStream, resObj);

        await new Promise<void>((resolve) => setTimeout(resolve, 50));
        expect(resObj.statusCode).toBe(204);

        await transport.close();
        vi.doUnmock('node:http');
    });
});

describeIfSockets('HttpTransport socket integration', () => {
    const servers: HttpTransport[] = [];

    afterEach(async () => {
        await Promise.all(servers.map((transport) => transport.close()));
        servers.length = 0;
    });

    it('round-trips an envelope over HTTP POST', async () => {
        const server = new HttpTransport();
        servers.push(server);

        const port = await server.listen(0, (envelope) =>
            Promise.resolve({
                ...envelope,
                messageType: 'NEGOTIATION_RESPONSE',
                body: {
                    status: 'accepted',
                    requestId: envelope.id,
                },
            }),
        );

        const client = new HttpTransport();
        const response = await client.send(
            baseEnvelope,
            `http://127.0.0.1:${port}`,
        );

        expect(response).toEqual({
            ...baseEnvelope,
            messageType: 'NEGOTIATION_RESPONSE',
            body: {
                status: 'accepted',
                requestId: baseEnvelope.id,
            },
        });
    });
});
