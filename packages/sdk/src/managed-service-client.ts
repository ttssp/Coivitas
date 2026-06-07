/**
 * ManagedServiceClient
 *
 * Behavioral contract:
 * 1. serviceUrl undefined -> go straight to fallback (treated as "managed service not enabled")
 * 2. serviceUrl set but the request hits 5xx / network error / timeout -> automatically call fallbackResolver + call onFallback; do not throw
 * 3. serviceUrl set and the request returns 4xx (except 429) -> throw ManagedServiceError(MANAGED_SERVICE_CLIENT_ERROR), no fallback
 * 4. 429 (rate limit) -> throw ManagedServiceError(MANAGED_SERVICE_RATE_LIMITED), no fallback
 * 5. apiKey set -> header `Authorization: Bearer {apiKey}`; if unset, anonymous
 *
 * Fallback is not silent: it logs (INFO level, not WARN/ERROR, since fallback is expected graceful degradation).
 * The onFallback callback lets upper layers emit a metric.
 *
 * Endpoint mapping:
 *   resolveDid(did) -> GET {serviceUrl}/v1/resolve/{did}
 *   checkRevocation(credId) -> GET {serviceUrl}/v1/revocation/{credId}
 *
 * @module ManagedServiceClient
 */

import type {
    AgentIdentityDocument,
    FederatedResolver,
} from '@coivitas/types';

// ============================================================
// Local interface definitions (RevocationResult is not in @coivitas/types)
// ============================================================

/**
 * Revocation check result.
 * The minimal shape of the managed service API response body; other fields pass through.
 *
 * The revoked field is widened from boolean to boolean | 'unknown':
 *   - true: revoked (from the managed service's authoritative response)
 *   - false: not revoked (from the managed service's authoritative response)
 *   - 'unknown': the managed service is unavailable (serviceUrl not configured / network error / retries exhausted);
 *                by default the caller should **reject** treating unknown as not-revoked (fail-closed);
 *                to retain the unsafe degradation, the caller must explicitly opt in via treatUnknownAsNotRevoked
 */
export interface RevocationResult {
    credentialId: string;
    revoked: boolean | 'unknown';
    revokedAt?: string;
    reason?: string;
    /**
     * When revoked='unknown', the error degradation reason (for the caller's decision).
     * - 'serviceUrl_not_configured': the managed service is not configured
     * - 'request_timeout' / 'network_error: ...' / 'server_error: ...': network/service failure
     */
    fallbackReason?: string;
}

// ============================================================
// Custom error class
// Note: do not use ProtocolError (ProtocolErrorCode is frozen and no additions are allowed)
// MANAGED_SERVICE_CLIENT_ERROR / MANAGED_SERVICE_RATE_LIMITED are this client's internal codes
// ============================================================

export type ManagedServiceErrorCode =
    | 'MANAGED_SERVICE_CLIENT_ERROR'
    | 'MANAGED_SERVICE_RATE_LIMITED';

export class ManagedServiceError extends Error {
    public override readonly name = 'ManagedServiceError';
    public readonly code: ManagedServiceErrorCode;
    public readonly statusCode: number;

    constructor(
        code: ManagedServiceErrorCode,
        message: string,
        statusCode: number,
    ) {
        super(message);
        this.code = code;
        this.statusCode = statusCode;
    }
}

// ============================================================
// Config interface
// ============================================================

export interface ManagedServiceClientConfig {
    /**
     * Managed service root URL (e.g. "https://managed.example.com").
     * If undefined, the managed service is disabled and all requests go straight to fallback.
     * env: MANAGED_SERVICE_URL
     */
    serviceUrl?: string;

    /**
     * API key (Bearer token authentication).
     * If undefined, requests are anonymous (FREE tier).
     * env: MANAGED_SERVICE_API_KEY
     */
    apiKey?: string;

    /**
     * Request timeout (milliseconds), default 5000.
     * Falls back automatically on timeout.
     */
    timeoutMs?: number;

    /**
     * Maximum number of retries, default 0 (no retry, fall back directly).
     * Rationale: fallback is itself a form of retry.
     */
    maxRetries?: number;

    /**
     * Required: the fallback resolver, injected by the caller.
     * Used when the managed service is unavailable.
     */
    fallbackResolver: FederatedResolver;

    /**
     * Optional: fallback event callback, for upper layers to emit a metric / alert.
     * Called when fallback is triggered, with the reason string + the relevant identifier as arguments.
     */
    onFallback?: (reason: string, identifier: string) => void;
}

// ============================================================
// Internal constants
// ============================================================

const DEFAULT_TIMEOUT_MS = 5000;
const DEFAULT_MAX_RETRIES = 0;

// ============================================================
// ManagedServiceClient implementation
// ============================================================

export class ManagedServiceClient {
    private readonly serviceUrl: string | undefined;
    private readonly apiKey: string | undefined;
    private readonly timeoutMs: number;
    private readonly maxRetries: number;
    private readonly fallbackResolver: FederatedResolver;
    private readonly onFallback:
        | ((reason: string, identifier: string) => void)
        | undefined;

    constructor(config: ManagedServiceClientConfig) {
        // Strip the trailing slash to standardize path concatenation
        this.serviceUrl = config.serviceUrl?.replace(/\/$/, '');
        this.apiKey = config.apiKey;
        this.timeoutMs = config.timeoutMs ?? DEFAULT_TIMEOUT_MS;
        this.maxRetries = config.maxRetries ?? DEFAULT_MAX_RETRIES;
        this.fallbackResolver = config.fallbackResolver;
        this.onFallback = config.onFallback;
    }

    /**
     * Resolve a DID document.
     *
     * - serviceUrl unset -> fall back directly
     * - 5xx / network error / timeout -> fallback + onFallback
     * - 404 -> return null (the DID does not exist, which is valid semantics)
     * - 4xx other than 404/429 -> throw ManagedServiceError(MANAGED_SERVICE_CLIENT_ERROR)
     * - 429 -> throw ManagedServiceError(MANAGED_SERVICE_RATE_LIMITED)
     * - 200 -> return AgentIdentityDocument
     */
    async resolveDid(did: string): Promise<AgentIdentityDocument | null> {
        if (!this.serviceUrl) {
            this.triggerFallback('serviceUrl_not_configured', did);
            return this.fallbackResolver.resolve(did as never);
        }

        const url = `${this.serviceUrl}/v1/resolve/${encodeURIComponent(did)}`;

        let attempt = 0;
        let lastServerError: Error | undefined;

        do {
            try {
                const result =
                    await this.fetchWithTimeout<AgentIdentityDocument | null>(
                        url,
                    );
                return result;
            } catch (err) {
                if (err instanceof ManagedServiceError) {
                    // 404 is valid semantics for a nonexistent DID (consistent with FederatedResolver),
                    // converted to null rather than thrown, so the caller takes the normal document_not_found path.
                    if (err.statusCode === 404) {
                        return null;
                    }
                    // 4xx other than 404: throw straight up, no fallback, no retry
                    throw err;
                }
                // 5xx / network / timeout: record and allow a retry
                lastServerError =
                    err instanceof Error ? err : new Error(String(err));
                attempt++;
            }
        } while (attempt <= this.maxRetries);

        // Retries exhausted -> fallback
        const reason = lastServerError?.message ?? 'server_error';
        this.triggerFallback(reason, did);
        return this.fallbackResolver.resolve(did as never);
    }

    /**
     * Check the revocation status of a credential.
     *
     * Changed from fail-open to fail-unknown (a fail-closed boundary by default):
     *
     * - serviceUrl unset -> return { revoked: 'unknown', fallbackReason: 'serviceUrl_not_configured' } + onFallback
     * - 5xx / network error / timeout -> return { revoked: 'unknown', fallbackReason } + onFallback
     * - 4xx other than 429 -> throw ManagedServiceError(MANAGED_SERVICE_CLIENT_ERROR)
     * - 429 -> throw ManagedServiceError(MANAGED_SERVICE_RATE_LIMITED)
     * - 200 -> return RevocationResult (revoked: true | false, authoritative)
     *
     * **The caller must explicitly handle the revoked === 'unknown' state**:
     * - fail-closed (recommended, default): treat unknown as "undecidable" and reject the credential
     * - fail-open (unsafe, requires explicit opt-in): the caller's logic treats unknown as false,
     *   accepting the risk itself (a revoked credential may be wrongly accepted)
     *
     * The old fail-open behavior (unknown silently becoming false) is deprecated: it violates fail-closed.
     */
    async checkRevocation(credentialId: string): Promise<RevocationResult> {
        if (!this.serviceUrl) {
            this.triggerFallback('serviceUrl_not_configured', credentialId);
            return this.buildUnknownRevocationResult(
                credentialId,
                'serviceUrl_not_configured',
            );
        }

        const url = `${this.serviceUrl}/v1/revocation/${encodeURIComponent(credentialId)}`;

        let attempt = 0;
        let lastServerError: Error | undefined;

        do {
            try {
                const result =
                    await this.fetchWithTimeout<RevocationResult>(url);
                return result;
            } catch (err) {
                if (err instanceof ManagedServiceError) {
                    // 4xx error: throw straight up, no fallback, no retry
                    throw err;
                }
                // 5xx / network / timeout: record and allow a retry
                lastServerError =
                    err instanceof Error ? err : new Error(String(err));
                attempt++;
            }
        } while (attempt <= this.maxRetries);

        // Retries exhausted -> fail-unknown (no longer silently fail-open)
        const reason = lastServerError?.message ?? 'server_error';
        this.triggerFallback(reason, credentialId);
        return this.buildUnknownRevocationResult(credentialId, reason);
    }

    // ============================================================
    // Private methods
    // ============================================================

    /**
     * fetch wrapper with a timeout.
     *
     * Throwing rules:
     * - 4xx other than 429 -> ManagedServiceError(MANAGED_SERVICE_CLIENT_ERROR)
     * - 429 -> ManagedServiceError(MANAGED_SERVICE_RATE_LIMITED)
     * - 5xx / network error / timeout -> a plain Error (the caller decides on fallback)
     */
    private async fetchWithTimeout<T>(url: string): Promise<T> {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), this.timeoutMs);

        let response: Response;
        try {
            response = await fetch(url, {
                signal: controller.signal,
                headers: this.buildHeaders(),
            });
        } catch (err) {
            // network error or abort (timeout)
            const message = err instanceof Error ? err.message : String(err);
            const isTimeout =
                err instanceof Error &&
                (err.name === 'AbortError' || message.includes('aborted'));
            throw new Error(
                isTimeout ? 'request_timeout' : `network_error: ${message}`,
            );
        } finally {
            clearTimeout(timer);
        }

        // HTTP status code handling
        if (response.status === 429) {
            throw new ManagedServiceError(
                'MANAGED_SERVICE_RATE_LIMITED',
                `Rate limited by managed service (HTTP 429): ${url}`,
                429,
            );
        }

        if (response.status >= 400 && response.status < 500) {
            // 4xx other than 429: client error, no fallback
            throw new ManagedServiceError(
                'MANAGED_SERVICE_CLIENT_ERROR',
                `Client error from managed service (HTTP ${response.status}): ${url}`,
                response.status,
            );
        }

        if (!response.ok) {
            // 5xx: server error, the caller is responsible for fallback
            throw new Error(
                `server_error: HTTP ${response.status} from ${url}`,
            );
        }

        return response.json() as Promise<T>;
    }

    /**
     * Build the request headers.
     * Adds an Authorization: Bearer header when apiKey is present.
     */
    private buildHeaders(): Record<string, string> {
        const headers: Record<string, string> = {
            Accept: 'application/json',
        };
        if (this.apiKey) {
            headers['Authorization'] = `Bearer ${this.apiKey}`;
        }
        return headers;
    }

    /**
     * Trigger fallback: log at INFO level + call the onFallback callback.
     * INFO level: fallback is expected graceful degradation, not an error.
     */
    private triggerFallback(reason: string, identifier: string): void {
        // INFO level: graceful degradation, not an error
        console.info(
            `[ManagedServiceClient] fallback triggered: reason=${reason}, identifier=${identifier}`,
        );
        this.onFallback?.(reason, identifier);
    }

    /**
     * Fail-unknown revocation result (revoked='unknown').
     * Replaces the old buildFailOpenRevocationResult (revoked=false silent degradation, violating fail-closed).
     *
     * The caller must explicitly handle the revoked === 'unknown' state:
     * - default (recommended fail-closed): reject the credential;
     * - explicit opt-in fail-open: the caller's logic treats unknown as false, accepting the risk itself.
     */
    private buildUnknownRevocationResult(
        credentialId: string,
        fallbackReason: string,
    ): RevocationResult {
        return {
            credentialId,
            revoked: 'unknown',
            fallbackReason,
        };
    }
}
