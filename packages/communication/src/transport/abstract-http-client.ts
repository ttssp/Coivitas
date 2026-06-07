/**
 * Transport abstract HTTP client
 *
 * Scope:
 * - HTTP client interface definition (fetch / fetchEnvelope)
 * - Explicit IP lock (resolveAndConnect returns the IP; subsequent fetch uses the IP rather than the hostname)
 * - 30x redirect rejection (fail-closed)
 * - dnsRebindingGuard seam reserved (no DNS resolution logic implemented yet; full implementation later)
 *
 * Extension point: inject the implemented DNSRebindingGuard.
 *
 * Caller: packages/identity/src/federated-resolver.ts
 *
 * @frozen seam layer (do not change this interface when implementing the DNS logic)
 */

import * as https from 'node:https';
import * as http from 'node:http';

import type { NegotiationEnvelope } from '@coivitas/types';

// ── Internal: injectable request function type ─────────────────────────────────────────────
// Inject a mock function for tests; default to https.request / http.request in production.
// ESM module namespaces are non-configurable and vi.spyOn has no effect on https.request;
// dependency injection is the only reliable mock point.
/** @internal*/
export type RawRequestFn = (
    options: https.RequestOptions,
    callback: (res: http.IncomingMessage) => void,
) => http.ClientRequest;

// ── Core types ──────────────────────────────────────────────────────────────────

/**
 * DNS rebinding defense interface seam
 *
 * Scope: interface definition + seam injection.
 * The production implementation lives in packages/identity/src/dns-rebinding-guard.ts.
 *
 * Contract requirements:
 * 1. MUST actually perform DNS resolution (must not exceed the TTL cache)
 * 2. Dual-stack hosts MUST validate all address families (must not validate only one)
 * 3. The resolution result must not contain private IPs (127/8, ::1, RFC 1918, link-local, unique-local)
 * 4. throw on resolution failure (fail-closed)
 */
export interface DNSRebindingGuard {
    /**
     * Resolve a hostname into a validated IP address
     *
     * @param hostname - the hostname of the node URL (without the port)
     * @returns the validated IP string. The caller MUST use this IP as the connection target (IP lock)
     * @throws on a private IP / when resolution fails (fail-closed)
     */
    resolveAndValidate(hostname: string): Promise<string>;
}

// ── LockedConnection: IP-locked connection context ────────────────────────────────────────

/**
 * Resolved + IP-locked connection context
 *
 * The return value of resolveAndConnect(), carrying:
 * - resolvedIp: the IP address already validated by DNSRebindingGuard
 * - originalHostname: the original hostname (used for TLS SNI + certificate validation)
 * - originalUrl: the original URL (used for logging and debugging; fetch must not re-resolve DNS)
 *
 * Implementation constraints (per the federated-resolution spec):
 * - MUST connect to resolvedIp (not via system DNS)
 * - TLS servername MUST be set to originalHostname (preserving SNI and certificate hostname validation)
 */
export interface LockedConnection {
    /** The IP resolved and validated by the DNS rebinding guard*/
    resolvedIp: string;
    /** Original hostname (used for TLS SNI)*/
    originalHostname: string;
    /** Original full URL (with path, without the # fragment)*/
    originalUrl: string;
    /** Original port (HTTPS=443, HTTP=80 when unspecified)*/
    port: number;
    /** Whether HTTPS is used*/
    isHttps: boolean;
}

// ── IHttpClient interface ─────────────────────────────────────────────────────────

/**
 * Abstract HTTP client interface
 *
 * Providing:
 * 1. `resolveAndConnect(url)` — DNS resolution + IP lock establishment (returns a LockedConnection)
 * 2. `fetch(connection, path, options)` — perform an HTTP request using the locked IP (rejects redirects)
 * 3. `fetchEnvelope(connection, path, envelope)` — Envelope-specific wrapper
 *
 * Design principles (per the federated-resolution spec):
 * - resolveAndConnect holds the IP lock; subsequent fetch MUST use this IP rather than re-resolving DNS (TOCTOU defense)
 * - 30x redirects are always rejected (fail-closed, consistent with configuration-time validation)
 * - redirect: 'error' behavior is enforced
 */
export interface IHttpClient {
    /**
     * DNS resolution + IP lock establishment
     *
     * Internally calls dnsRebindingGuard.resolveAndValidate(hostname) and
     * wraps the resolution result into a LockedConnection to return.
     *
     * @param url - the target full URL (must be https://)
     * @returns the validated IP-locked connection context
     * @throws propagates from dnsRebindingGuard when resolution fails (fail-closed)
     * @throws on a non-HTTPS URL (v0.1 HTTPS-only enforcement)
     */
    resolveAndConnect(url: string): Promise<LockedConnection>;

    /**
     * Perform an HTTP request using the locked IP
     *
     * MUST connect to connection.resolvedIp (no DNS re-resolution).
     * 30x redirects are always fail-closed (not followed).
     *
     * @param connection - the IP-locked context returned by resolveAndConnect()
     * @param path - the request path (e.g. `/api/v1/resolve`)
     * @param options - request options (method, headers, body)
     * @returns the HTTP response body (a JSON string)
     * @throws RedirectBlockedError on a 30x redirect
     * @throws propagates on a network error
     */
    fetch(
        connection: LockedConnection,
        path: string,
        options?: FetchOptions,
    ): Promise<HttpResponse>;

    /**
     * Envelope-specific HTTP POST wrapper
     *
     * Serializes the envelope to JSON and POSTs it to connection+path,
     * then parses the response body into a NegotiationEnvelope.
     *
     * @param connection - the IP-locked context returned by resolveAndConnect()
     * @param path - the request path
     * @param envelope - the NegotiationEnvelope to send
     * @returns the response NegotiationEnvelope (or null if the response body is empty)
     * @throws RedirectBlockedError, network errors, JSON parse failures
     */
    fetchEnvelope(
        connection: LockedConnection,
        path: string,
        envelope: NegotiationEnvelope,
    ): Promise<NegotiationEnvelope | null>;
}

// ── FetchOptions + HttpResponse ───────────────────────────────────────────────

export interface FetchOptions {
    method?: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH' | 'HEAD';
    headers?: Record<string, string>;
    body?: string;
    timeoutMs?: number;
}

export interface HttpResponse {
    status: number;
    headers: Record<string, string | string[]>;
    body: string;
}

// ── RedirectBlockedError ───────────────────────────────────────────────────────

/**
 * 30x redirect rejection error (fail-closed)
 *
 * Per the federated-resolution spec + v0.1 redirect: 'error' behavior.
 * Any 3xx response throws this error immediately, without following the Location header.
 */
export class RedirectBlockedError extends Error {
    public readonly status: number;
    public readonly location: string | undefined;

    public constructor(
        status: number,
        location: string | undefined,
        url: string,
    ) {
        super(
            `HTTP redirect blocked (fail-closed): status=${status}, location=${location ?? 'N/A'}, url=${url}`,
        );
        this.name = 'RedirectBlockedError';
        this.status = status;
        this.location = location;
    }
}

// ── DefaultHttpClient (IHttpClient implementation) ──────────────────────────────────────

/**
 * The default implementation of IHttpClient
 *
 * Core behavior:
 * 1. resolveAndConnect: invokes the injected dnsRebindingGuard and locks the IP
 * 2. fetch: connects to the locked IP via https.Agent + lookup override
 *    (no system DNS; TLS servername is set to the original hostname)
 * 3. 30x redirect: throws RedirectBlockedError immediately (not followed)
 *
 * Implementation details (per the federated-resolution spec, TLS hostname validation):
 * - Use https.Agent + a `lookup` callback to override DNS (returning the locked IP)
 * - servername remains the original hostname (SNI + certificate hostname validation)
 * - Do not use rejectUnauthorized: false (certificate validation is not bypassed)
 */
export class DefaultHttpClient implements IHttpClient {
    private readonly guard: DNSRebindingGuard;
    private readonly defaultTimeoutMs: number;
    // Injectable request function (production = https/http.request; tests = mock)
    private readonly _requestFn: RawRequestFn | undefined;

    public constructor(options: DefaultHttpClientOptions) {
        this.guard = options.dnsRebindingGuard;
        this.defaultTimeoutMs = options.defaultTimeoutMs ?? 10_000;
        this._requestFn = options._requestFn;
    }

    /**
     * DNS resolution + IP lock establishment
     *
     * Enforces HTTPS-only (v0.1).
     * Calls dnsRebindingGuard.resolveAndValidate to perform the actual DNS resolution + private-IP check.
     */
    public async resolveAndConnect(url: string): Promise<LockedConnection> {
        let parsed: URL;
        try {
            parsed = new URL(url);
        } catch {
            throw new Error(`Invalid URL: ${url}`);
        }

        // v0.1: HTTPS-only (IP literals / HTTP / localhost are all rejected)
        if (parsed.protocol !== 'https:') {
            throw new Error(
                `DNS rebinding guard: HTTPS-only (received ${parsed.protocol}). ` +
                    `URL: ${url}`,
            );
        }

        const hostname = parsed.hostname;

        // Call dnsRebindingGuard to perform DNS resolution + private-range validation
        // Propagates when the guard fails (fail-closed)
        const resolvedIp = await this.guard.resolveAndValidate(hostname);

        const port =
            parsed.port !== ''
                ? parseInt(parsed.port, 10)
                : parsed.protocol === 'https:'
                  ? 443
                  : 80;

        return {
            resolvedIp,
            originalHostname: hostname,
            originalUrl: url,
            port,
            isHttps: parsed.protocol === 'https:',
        };
    }

    /**
     * Perform an HTTP request using the locked IP
     *
     * MUST connect to connection.resolvedIp (no DNS re-resolution).
     * 30x redirects are fail-closed.
     */
    public async fetch(
        connection: LockedConnection,
        path: string,
        options: FetchOptions = {},
    ): Promise<HttpResponse> {
        const { resolvedIp, originalHostname, port, isHttps } = connection;
        const method = options.method ?? 'GET';
        const timeoutMs = options.timeoutMs ?? this.defaultTimeoutMs;
        const headers = options.headers ?? {};
        const body = options.body;

        return new Promise<HttpResponse>((resolve, reject) => {
            // Create the HTTPS Agent — the lookup override locks to resolvedIp (TOCTOU defense)
            // servername = originalHostname (TLS SNI + certificate hostname validation preserved)
            // Note: Node.js Agent.lookup has a slightly different type signature across @types/node versions;
            // at runtime the lookup callback returns the locked IP, so the type here may match or may need a cast.
            const agent: https.Agent | http.Agent = isHttps
                ? new https.Agent({
                      servername: originalHostname,
                      lookup: (
                          _host: string,
                          _opts: unknown,
                          cb: (
                              err: NodeJS.ErrnoException | null,
                              address: string,
                              family: number,
                          ) => void,
                      ) => {
                          // Skip system DNS and return the validated IP directly (core of the TOCTOU defense)
                          const isV6 = resolvedIp.includes(':');
                          cb(null, resolvedIp, isV6 ? 6 : 4);
                      },
                  })
                : new http.Agent();

            const requestOptions: https.RequestOptions = {
                hostname: originalHostname,
                port,
                path,
                method,
                headers: {
                    'Content-Type': 'application/json',
                    ...headers,
                },
                agent,
                // Do not follow redirects (fail-closed)
            };

            if (body !== undefined) {
                requestOptions.headers = {
                    ...requestOptions.headers,
                    'Content-Length': String(Buffer.byteLength(body, 'utf8')),
                };
            }

            // Use the injected requestFn (tests) or the default module function (production)
            const rawRequest: RawRequestFn =
                this._requestFn ?? (isHttps ? https.request : http.request);

            const req = rawRequest(requestOptions, (res) => {
                const status = res.statusCode ?? 0;

                // 30x redirect: reject immediately (fail-closed)
                if (status >= 300 && status < 400) {
                    const location = res.headers.location;
                    req.destroy();
                    reject(
                        new RedirectBlockedError(
                            status,
                            typeof location === 'string' ? location : undefined,
                            connection.originalUrl + path,
                        ),
                    );
                    return;
                }

                const chunks: Buffer[] = [];
                res.on('data', (chunk: Buffer) => chunks.push(chunk));
                res.on('end', () => {
                    const responseBody = Buffer.concat(chunks).toString('utf8');
                    // Convert headers into a plain object
                    const responseHeaders: Record<string, string | string[]> =
                        {};
                    for (const [k, v] of Object.entries(res.headers)) {
                        if (v !== undefined) {
                            responseHeaders[k] = v;
                        }
                    }
                    resolve({
                        status,
                        headers: responseHeaders,
                        body: responseBody,
                    });
                });
                res.on('error', reject);
            });

            req.on('error', reject);

            // Timeout handling
            req.setTimeout(timeoutMs, () => {
                req.destroy(
                    new Error(
                        `HTTP request timeout (${timeoutMs}ms): ${connection.originalUrl}${path}`,
                    ),
                );
            });

            if (body !== undefined) {
                req.write(body, 'utf8');
            }
            req.end();
        });
    }

    /**
     * Envelope-specific HTTP POST wrapper
     *
     * POSTs the JSON-serialized envelope and parses the response body into a NegotiationEnvelope.
     * Returns null for an empty response body.
     */
    public async fetchEnvelope(
        connection: LockedConnection,
        path: string,
        envelope: NegotiationEnvelope,
    ): Promise<NegotiationEnvelope | null> {
        const body = JSON.stringify(envelope);
        const response = await this.fetch(connection, path, {
            method: 'POST',
            body,
        });

        if (response.body.trim() === '') {
            return null;
        }

        // Propagates when JSON parsing fails (handled by the caller)
        const parsed = JSON.parse(response.body) as NegotiationEnvelope;
        return parsed;
    }
}

// ── DefaultHttpClientOptions ──────────────────────────────────────────────────

export interface DefaultHttpClientOptions {
    /**
     * DNS rebinding defense seam (MUST be injected)
     *
     * Production implementation: packages/identity/src/dns-rebinding-guard.ts.
     * Tests: inject a mock guard (spy / stub).
     */
    dnsRebindingGuard: DNSRebindingGuard;

    /**
     * Default request timeout (milliseconds), default 10_000ms
     */
    defaultTimeoutMs?: number;

    /**
     * Injectable low-level request function (for testing only)
     *
     * ESM module namespaces are non-configurable (vi.spyOn has no effect on https.request),
     * so inject a mock via this field. Production code must not set this field.
     *
     * @internal
     */
    _requestFn?: RawRequestFn;
}
