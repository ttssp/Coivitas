// HTTP transport layer enhancements: exponential backoff retries, timeout, Content-Type validation, connection pool (keep-alive).
// Note: Node 20+ native fetch does not support the agent parameter; the connection pool is implemented via node:http(s).Agent + request.
// HTTPS: node:https is selected automatically based on the endpoint protocol; both sides support a keepAlive Agent.

import { createServer, request as httpRequest, Agent as HttpAgent } from 'node:http';
import { request as httpsRequest, Agent as HttpsAgent } from 'node:https';
import type {
    IncomingMessage,
    RequestOptions,
    ServerResponse,
} from 'node:http';
import { once } from 'node:events';

import { ProtocolError } from '@coivitas/types';
import type { NegotiationEnvelope } from '@coivitas/types';

import type { EnvelopeHandler, Transport } from './types.js';

export interface HttpTransportOptions {
    /** Request timeout (ms), default 30_000*/
    timeoutMs?: number;
    /** Listening host address, default 127.0.0.1*/
    host?: string;
    /** Maximum number of retries (429 / 5xx only), default 3*/
    maxRetries?: number;
    /** Backoff base delay (ms), default 200*/
    baseDelayMs?: number;
    /** Backoff maximum delay (ms), default 5_000*/
    maxDelayMs?: number;
    /**
     * Whether to use the built-in connection pool (keep-alive Agent).
     * When true, uses node:http.request; when false, uses the global fetch (convenient for unit-test mocking).
     * Defaults to true (production path); tests may explicitly pass false to continue using the fetch mock.
     */
    useConnectionPool?: boolean;
}

export class HttpTransport implements Transport {
    private readonly timeoutMs: number;
    private readonly host: string;
    private readonly maxRetries: number;
    private readonly baseDelayMs: number;
    private readonly maxDelayMs: number;
    private readonly useConnectionPool: boolean;
    private readonly httpAgent: HttpAgent;
    private readonly httpsAgent: HttpsAgent;
    private server: ReturnType<typeof createServer> | null = null;

    public constructor(options: HttpTransportOptions = {}) {
        this.timeoutMs = options.timeoutMs ?? 30_000;
        this.host = options.host ?? '127.0.0.1';
        this.maxRetries = options.maxRetries ?? 3;
        this.baseDelayMs = options.baseDelayMs ?? 200;
        this.maxDelayMs = options.maxDelayMs ?? 5_000;
        this.useConnectionPool = options.useConnectionPool ?? true;
        // Maintain a keep-alive Agent per protocol, to avoid HTTPS endpoints using the HTTP Agent
        this.httpAgent = new HttpAgent({ keepAlive: true });
        this.httpsAgent = new HttpsAgent({ keepAlive: true });
    }

    public async send(
        envelope: NegotiationEnvelope,
        endpoint: string,
    ): Promise<NegotiationEnvelope | null> {
        let lastError: Error | null = null;

        for (let attempt = 0; attempt <= this.maxRetries; attempt++) {
            if (attempt > 0) {
                // Exponential backoff: delay = min(baseDelayMs * 2^(attempt-1) + jitter, maxDelayMs)
                const jitter = Math.random() * this.baseDelayMs;
                const delay = Math.min(
                    this.baseDelayMs * Math.pow(2, attempt - 1) + jitter,
                    this.maxDelayMs,
                );
                await sleep(delay);
            }

            try {
                const result = await this.sendOnce(envelope, endpoint);
                return result;
            } catch (error) {
                if (error instanceof RetryableError) {
                    lastError = error;
                    continue;
                }
                // Non-retryable errors (4xx other than 429, Content-Type errors, timeouts, etc.) are thrown directly
                throw error;
            }
        }

        // Retries exhausted, throw the last error
        throw lastError ?? new Error('HTTP transport: max retries exceeded');
    }

    /** A single HTTP request; decides whether to wrap as a RetryableError based on the status code*/
    private async sendOnce(
        envelope: NegotiationEnvelope,
        endpoint: string,
    ): Promise<NegotiationEnvelope | null> {
        if (this.useConnectionPool) {
            return this.sendViaNodeHttp(envelope, endpoint);
        }
        return this.sendViaFetch(envelope, endpoint);
    }

    /** Send via node:http(s).request + keep-alive Agent (production path)*/
    private sendViaNodeHttp(
        envelope: NegotiationEnvelope,
        endpoint: string,
    ): Promise<NegotiationEnvelope | null> {
        return new Promise((resolve, reject) => {
            const url = new URL(endpoint);
            const isHttps = url.protocol === 'https:';
            const body = JSON.stringify(envelope);

            const options: RequestOptions = {
                hostname: url.hostname,
                // https defaults to 443, http defaults to 80
                port: url.port || (isHttps ? 443 : 80),
                path: url.pathname + url.search,
                method: 'POST',
                headers: {
                    'content-type': 'application/json',
                    'content-length': Buffer.byteLength(body),
                },
                agent: isHttps ? this.httpsAgent : this.httpAgent,
                timeout: this.timeoutMs,
            };
            const doRequest = isHttps ? httpsRequest : httpRequest;

            // settled flag: prevents a double reject from a timeout + error event race
            let settled = false;
            const safeReject = (err: Error): void => {
                if (!settled) {
                    settled = true;
                    reject(err);
                }
            };
            const safeResolve = (value: NegotiationEnvelope | null): void => {
                if (!settled) {
                    settled = true;
                    resolve(value);
                }
            };

            const req = doRequest(options, (res) => {
                const statusCode = res.statusCode ?? 0;
                const contentType = res.headers['content-type'] ?? '';

                // Collect the response body
                const chunks: Buffer[] = [];
                res.on('data', (chunk: Buffer) => chunks.push(chunk));
                res.on('end', () => {
                    const rawBody = Buffer.concat(chunks).toString('utf8');

                    if (statusCode === 204) {
                        safeResolve(null);
                        return;
                    }

                    // 5xx or 429: retryable
                    if (statusCode === 429 || statusCode >= 500) {
                        safeReject(
                            new RetryableError(
                                `HTTP transport request failed with status ${statusCode}.`,
                            ),
                        );
                        return;
                    }

                    // Other non-2xx: not retryable
                    if (statusCode < 200 || statusCode >= 300) {
                        safeReject(
                            new Error(
                                `HTTP transport request failed with status ${statusCode}.`,
                            ),
                        );
                        return;
                    }

                    // Validate the response Content-Type
                    if (!contentType.includes('application/json')) {
                        safeReject(
                            new Error(
                                `HTTP transport: unexpected content-type "${contentType}", expected application/json.`,
                            ),
                        );
                        return;
                    }

                    try {
                        safeResolve(
                            JSON.parse(rawBody) as NegotiationEnvelope,
                        );
                    } catch {
                        safeReject(
                            new Error(
                                'HTTP transport: failed to parse response body as JSON.',
                            ),
                        );
                    }
                });
                res.on('error', (err) => safeReject(err));
            });

            req.on('timeout', () => {
                // reject first, then destroy, to prevent the error event triggered by destroy from overriding the timeout message
                safeReject(
                    new ProtocolError(
                        'TRANSPORT_ERROR',
                        `HTTP transport request timed out after ${this.timeoutMs}ms.`,
                    ),
                );
                req.destroy();
            });

            req.on('error', (err) => {
                // Wrap socket errors (ECONNREFUSED / hangup, etc.) as TRANSPORT_ERROR
                safeReject(
                    new ProtocolError(
                        'TRANSPORT_ERROR',
                        `HTTP transport request error: ${err.message}`,
                    ),
                );
            });

            req.write(body);
            req.end();
        });
    }

    /** Send via the global fetch (test mock path, useConnectionPool=false)*/
    private async sendViaFetch(
        envelope: NegotiationEnvelope,
        endpoint: string,
    ): Promise<NegotiationEnvelope | null> {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), this.timeoutMs);

        try {
            const response = await fetch(endpoint, {
                method: 'POST',
                headers: { 'content-type': 'application/json' },
                body: JSON.stringify(envelope),
                signal: controller.signal,
            });

            const statusCode = response.status;

            if (statusCode === 204) {
                return null;
            }

            // 5xx or 429: retryable
            if (statusCode === 429 || statusCode >= 500) {
                throw new RetryableError(
                    `HTTP transport request failed with status ${statusCode}.`,
                );
            }

            // Other non-2xx: not retryable
            if (!response.ok) {
                throw new Error(
                    `HTTP transport request failed with status ${statusCode}.`,
                );
            }

            // Validate the response Content-Type
            const contentType = response.headers.get('content-type') ?? '';
            if (!contentType.includes('application/json')) {
                throw new Error(
                    `HTTP transport: unexpected content-type "${contentType}", expected application/json.`,
                );
            }

            return (await response.json()) as NegotiationEnvelope;
        } catch (error) {
            if (
                error instanceof RetryableError ||
                error instanceof ProtocolError
            ) {
                throw error;
            }
            // An abort triggered by the AbortController corresponds to a timeout
            if (
                error instanceof Error &&
                (error.name === 'AbortError' ||
                    error.message.includes('abort') ||
                    error.message.includes('signal'))
            ) {
                throw new ProtocolError(
                    'TRANSPORT_ERROR',
                    `HTTP transport request timed out after ${this.timeoutMs}ms.`,
                );
            }
            throw error;
        } finally {
            clearTimeout(timer);
        }
    }

    public async listen(
        port: number,
        handler: EnvelopeHandler,
    ): Promise<number> {
        await this.close();

        this.server = createServer((request, response) => {
            void this.handleRequest(request, response, handler);
        });

        this.server.listen(port, this.host);
        await once(this.server, 'listening');

        const address = this.server.address();
        if (!address || typeof address === 'string') {
            throw new Error('HTTP transport failed to bind to a TCP port.');
        }

        return address.port;
    }

    public async close(): Promise<void> {
        if (!this.server) {
            return;
        }

        const server = this.server;
        this.server = null;
        (
            server as { closeAllConnections?: () => void }
        ).closeAllConnections?.();

        await new Promise<void>((resolve, reject) => {
            server.close((error) => {
                if (error) {
                    reject(error);
                    return;
                }
                resolve();
            });
        });
    }

    private async handleRequest(
        request: IncomingMessage,
        response: ServerResponse,
        handler: EnvelopeHandler,
    ): Promise<void> {
        if (request.method !== 'POST') {
            response.statusCode = 405;
            response.end();
            return;
        }

        // Validate the request Content-Type (01c)
        const contentType = request.headers['content-type'] ?? '';
        if (!contentType.includes('application/json')) {
            response.statusCode = 415;
            response.setHeader('content-type', 'application/json');
            response.end(
                JSON.stringify({
                    error: `Unsupported Media Type: expected application/json, got "${contentType}"`,
                }),
            );
            return;
        }

        try {
            const body = await readRequestBody(request);
            const envelope = JSON.parse(body) as NegotiationEnvelope;
            const result = await handler(envelope);

            if (result === null) {
                response.statusCode = 204;
                response.end();
                return;
            }

            response.statusCode = 200;
            response.setHeader('content-type', 'application/json');
            response.end(JSON.stringify(result));
        } catch (error) {
            response.statusCode = 400;
            response.setHeader('content-type', 'application/json');
            response.end(
                JSON.stringify({
                    error:
                        error instanceof Error
                            ? error.message
                            : 'Invalid transport payload',
                }),
            );
        }
    }
}

/** Internal marker class for retryable errors (used only within this module)*/
class RetryableError extends Error {
    public override readonly name = 'RetryableError';
}

/** Async sleep utility*/
function sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
}

async function readRequestBody(request: IncomingMessage): Promise<string> {
    const chunks: Buffer[] = [];
    for await (const chunk of request as AsyncIterable<string | Buffer>) {
        if (typeof chunk === 'string') {
            chunks.push(Buffer.from(chunk));
        } else {
            chunks.push(chunk);
        }
    }
    return Buffer.concat(chunks).toString('utf8');
}
