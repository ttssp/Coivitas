/**
 * Revocation server (GET /v1/revocation/:credentialId).
 *
 * Design notes (conclusion first, details after):
 * 1. **The alpha-stage stub is fail-closed by default**: when no `checker` is explicitly injected, the handler
 *    returns 503 + STUB_REVOCATION_NOT_FOR_PRODUCTION at the response stage and never enters the 200 + body path.
 * - **Design rationale**: even after the bin guard + SDK fail-unknown
 *      have been tightened, returning 200 + `{revoked:false}` at the server's response stage is still a silent false-negative trust hole.
 *      Having the server refuse to emit a 200 + body at the earliest surface (the response stage) lets the SDK take the 5xx → fail-unknown
 *      path so the chain closes naturally; the minimal trustworthy trust boundary for the alpha stage is reached once the three layers of guards are combined.
 * 2. The middleware chain matches resolver-server: auth -> rate-limit -> handler -> metrics + usage.
 * 3. **Production path (a checker must be injected explicitly)**: the caller injects a real RevocationList adapter (full production implementation).
 *
 * Replacement example (a checker must be injected explicitly; no longer relies on the stub default):
 * ```ts
 * import { RevocationList } from '@coivitas/identity';
 * const list = new RevocationList(pool);
 * createRevocationApp({
 *     pool,
 *     checker: async (credentialId) => {
 *         const rec = await list.getRevocation(credentialId);
 *         return rec ? { revoked: true, revokedAt: rec.revokedAt, reason: rec.reason } : { revoked: false };
 *     },
 * });
 * ```
 *
 */

import express, {
    type Application,
    type Request,
    type Response,
} from 'express';

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

/** Revocation check result (consistent with the output of the future RevocationList adapter) */
export interface RevocationCheckResult {
    revoked: boolean;
    /** ISO 8601 timestamp, present only when revoked = true */
    revokedAt?: string;
    /** Revocation reason (optional) */
    reason?: string;
}

/** Revocation checker signature (implemented via RevocationList) */
export type RevocationChecker = (
    credentialId: string,
) => Promise<RevocationCheckResult>;

/**
 * The error code used when the default stub path returns 503 at the response stage.
 * The SDK receives a 5xx → retries exhausted → fail-unknown fallback → the caller fail-closed rejects.
 */
export const STUB_REVOCATION_NOT_FOR_PRODUCTION =
    'STUB_REVOCATION_NOT_FOR_PRODUCTION';

export interface RevocationServerConfig {
    pool: DatabasePool;
    /**
     * Revocation checker; when omitted, the in-memory stub is used (**alpha demo only**, must be replaced in production).
     */
    checker?: RevocationChecker;
    metrics?: Metrics;
    usageRecorder?: UsageRecorder;
    /**
     * trust proxy configuration. Defaults to false. See resolver-server.ts ResolverServerConfig.trustProxy for details.
     */
    trustProxy?: boolean | number;
}

/**
 * Built-in stub checker (a fallback reference; the normal path never enters this function):
 * when no checker is explicitly injected, the handler returns 503 directly at the response stage without calling this function.
 * The definition is kept for unit tests / historical compatibility; callers should not rely on its behavior.
 */
const stubChecker: RevocationChecker = (_credentialId: string) =>
    Promise.resolve({ revoked: false });

export function createRevocationApp(
    config: RevocationServerConfig,
): Application {
    const app = express();
    const metrics = config.metrics ?? createMetrics();
    const usage =
        config.usageRecorder ?? new UsageRecorder({ pool: config.pool });
    // Distinguish the two paths: "the caller explicitly injects a checker" vs "falling back to the stub default".
    // When explicitly injected, take the production path (200 + body); when not injected, the handler returns 503 directly to avoid a trust hole.
    const checkerProvided = config.checker !== undefined;
    const checker = config.checker ?? stubChecker;

    // trust proxy defaults to false; for reverse-proxy deployments, explicitly pass trustProxy=1
    if (config.trustProxy !== undefined && config.trustProxy !== false) {
        app.set('trust proxy', config.trustProxy);
    }

    app.get('/health', (_req: Request, res: Response) => {
        res.status(200).json({ status: 'ok', service: 'revocation' });
    });

    app.get('/metrics', createMetricsHandler(metrics));

    // Single-limiter chain (matches resolver-server.ts)
    app.get(
        '/v1/revocation/:credentialId',
        createRecordOnFinish('revocation', metrics, usage),
        createRateLimiter(),
        createAuthMiddleware({ pool: config.pool }),
        (req, res) => {
            if (!checkerProvided) {
                // The default stub path is fail-closed at the response stage
                respond(res, 503, {
                    code: STUB_REVOCATION_NOT_FOR_PRODUCTION,
                    message:
                        'Default stub checker is fail-closed in alpha; inject a real RevocationChecker (RevocationList) for production.',
                });
                return;
            }
            void handleRevocationCheck(req, res, checker);
        },
    );

    return app;
}

async function handleRevocationCheck(
    req: Request,
    res: Response,
    checker: RevocationChecker,
): Promise<void> {
    const authReq = req as AuthenticatedRequest;
    const auth = authReq.auth;
    if (!auth) {
        res.status(500).json({
            error: { code: 'INTERNAL_ERROR', message: 'auth context missing.' },
        });
        return;
    }

    const credentialIdRaw = req.params.credentialId;
    const credentialId =
        typeof credentialIdRaw === 'string' && credentialIdRaw.length > 0
            ? credentialIdRaw
            : null;
    if (!credentialId) {
        respond(res, 400, {
            code: 'INVALID_CREDENTIAL_ID',
            message: 'credentialId required.',
        });
        return;
    }

    try {
        const result = await checker(credentialId);
        res.status(200).json({
            credentialId,
            ...result,
        });
    } catch (error) {
        const message = error instanceof Error ? error.message : 'unknown';
        respond(res, 502, {
            code: 'REVOCATION_CHECK_FAILED',
            message: `Revocation check failed: ${message}`,
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
