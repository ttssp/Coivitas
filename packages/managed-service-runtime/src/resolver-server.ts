/**
 * DID resolver server (GET /v1/resolve/:did).
 *
 * Design notes (conclusion first, details after):
 * 1. Reuses @coivitas/identity's FederatedResolver.resolve():
 *    the returned AgentIdentityDocument is serialized directly to JSON (no new wire format introduced).
 * 2. middleware chain: auth -> rate-limit -> handler -> metrics + usage.
 * 3. The /metrics endpoint exposes Prometheus text (no auth; monitoring systems need open scrape access,
 *    so restrict source IPs with a reverse proxy ACL at the deployment side).
 * 4. The /health endpoint: returns 200 + simple JSON, for the K8s liveness probe.
 * 5. error handling:
 *    - DID not found -> 404 NOT_FOUND
 *    - resolution timeout / node quorum failure -> 502 RESOLVER_FAILED
 *    - other exceptions -> 500
 *
 */

import express, {
    type Application,
    type Request,
    type Response,
} from 'express';

import type { FederatedResolver } from '@coivitas/types';
import type { DID } from '@coivitas/types';

import { createAuthMiddleware } from './auth-middleware.js';
import {
    createMetrics,
    createMetricsHandler,
    type Metrics,
} from './metrics.js';
import { createRateLimiter } from './rate-limiter.js';
import { createRecordOnFinish } from './record-on-finish.js';
import { UsageRecorder } from './usage-recorder.js';
import type { AuthenticatedRequest } from './types.js';
import type { DatabasePool } from '@coivitas/shared';

export interface ResolverServerConfig {
    pool: DatabasePool;
    federatedResolver: FederatedResolver;
    /** Inject metrics (for testing / sharing across multiple services); defaults to createMetrics() */
    metrics?: Metrics;
    /** Inject a UsageRecorder; defaults to new UsageRecorder({pool}) */
    usageRecorder?: UsageRecorder;
    /**
     * trust proxy configuration. Defaults to false (secure default for directly-exposed-port deployments).
     * Only set explicitly to 1 (trust one hop) or higher (multi-layer proxies) when deploying behind a
     * reverse proxy (nginx / Caddy / Cloudflare). For a directly-exposed port, setting true would let clients
     * forge the X-Forwarded-For header and bypass IP-based rate limiting.
     *
     * env entry: MANAGED_SERVICE_TRUST_PROXY ("0" / "1" / integer N)
     */
    trustProxy?: boolean | number;
}

/**
 * Create the DID resolver Express app (does not bind a port; the caller calls listen()).
 */
export function createResolverApp(config: ResolverServerConfig): Application {
    const app = express();
    const metrics = config.metrics ?? createMetrics();
    const usage = config.usageRecorder ?? new UsageRecorder({ pool: config.pool });

    // trust proxy defaults to false (secure default for a directly-exposed port)
    // For reverse-proxy deployments, the caller explicitly passes trustProxy=1 (or higher)
    if (config.trustProxy !== undefined && config.trustProxy !== false) {
        app.set('trust proxy', config.trustProxy);
    }

    // /health bypasses auth: K8s liveness probe / load balancer health check
    app.get('/health', (_req: Request, res: Response) => {
        res.status(200).json({ status: 'ok', service: 'resolver' });
    });

    // /metrics bypasses auth: Prometheus scrape; restrict sources via a deployment-side ACL
    app.get('/metrics', createMetricsHandler(metrics));

    // /v1/resolve/:did middleware chain (single limiter):
    // 1. createRecordOnFinish: record metrics + usage on every finished request (including the 429/401 rejection paths)
    // 2. createRateLimiter(): pre-auth IP+FREE rate limiting (anti-token-DDoS)
    // 3. createAuthMiddleware: parse the Bearer token + inject req.auth
    // 4. handleResolve: business handler

    // Single-limiter design: does not use the postAuthProOnly two-limiter setup. Perfect tier-aware
    // distributed rate limiting is deferred to a later stage.
    // Current limitation: under the NAT-shared-IP scenario, the PRO tier is still metered by IP+FREE.
    app.get(
        '/v1/resolve/:did',
        createRecordOnFinish('resolver', metrics, usage),
        createRateLimiter(),
        createAuthMiddleware({ pool: config.pool }),
        (req, res) => handleResolve(req, res, config.federatedResolver),
    );

    return app;
}

async function handleResolve(
    req: Request,
    res: Response,
    federatedResolver: FederatedResolver,
): Promise<void> {
    const authReq = req as AuthenticatedRequest;
    const auth = authReq.auth;
    if (!auth) {
        // Defensive fail-closed
        res.status(500).json({
            error: { code: 'INTERNAL_ERROR', message: 'auth context missing.' },
        });
        return;
    }

    const didRaw = req.params.did;
    const did =
        typeof didRaw === 'string' && didRaw.length > 0
            ? (didRaw as DID)
            : null;

    if (!did) {
        respond(res, 400, { code: 'INVALID_DID', message: 'DID required.' });
        return;
    }

    try {
        const document = await federatedResolver.resolve(did);
        if (!document) {
            respond(res, 404, {
                code: 'NOT_FOUND',
                message: `DID ${did} not resolved.`,
            });
        } else {
            // Return the bare AgentIdentityDocument structure directly (no wrapper).
            // Avoids the case where the SDK ManagedServiceClient expects a bare doc but the server returns a wrapper,
            // causing publicKey parsing to fail. The contract is guarded by SDK tests + scripts/managed-service-smoke-test.
            res.status(200).json(document);
        }
    } catch (error) {
        const message = error instanceof Error ? error.message : 'unknown';
        respond(res, 502, {
            code: 'RESOLVER_FAILED',
            message: `Federated resolver failed: ${message}`,
        });
    }
}

function respond(
    res: Response,
    status: number,
    error: { code: string; message: string },
): void {
    if (res.headersSent) {
        return;
    }
    res.status(status).json({ error });
}

