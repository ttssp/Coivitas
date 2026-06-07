/**
 * record-on-finish middleware: record metrics + usage on res.on('finish').
 *
 * Previously, the resolver-server / revocation-server recorded in the handler's `finally` block,
 * missing requests rejected by the rate-limiter (429) / auth-middleware (401).
 * It now registers a res.on('finish') hook at the middleware entry point, so every finished request is recorded.
 *
 */

import type { NextFunction, Request, Response } from 'express';

import {
    recordResolverRequest,
    recordRevocationCheck,
    type Metrics,
} from './metrics.js';
import type { AuthenticatedRequest } from './types.js';
import { UsageRecorder } from './usage-recorder.js';

export type RecordOnFinishEndpoint = 'resolver' | 'revocation';

/**
 * Create the record-on-finish middleware.
 *
 * Must be mounted at the **very front** of the middleware chain (before rate-limiter / auth),
 * so that res.on('finish') fires no matter which middleware terminates the request.
 */
export function createRecordOnFinish(
    endpoint: RecordOnFinishEndpoint,
    metrics: Metrics,
    usage: UsageRecorder,
) {
    return (req: Request, res: Response, next: NextFunction): void => {
        const start = Date.now();
        res.on('finish', () => {
            const authReq = req as AuthenticatedRequest;
            const auth = authReq.auth;
            const tier = auth?.tier ?? 'FREE';
            const tenantDid = auth?.tenant?.tenantDid ?? null;
            const httpStatus = res.statusCode;
            const durationMs = Date.now() - start;

            if (endpoint === 'resolver') {
                recordResolverRequest(metrics, {
                    tenantDid,
                    tier,
                    httpStatus,
                    durationMs,
                });
            } else {
                recordRevocationCheck(metrics, {
                    tenantDid,
                    tier,
                    httpStatus,
                });
            }

            usage.record({
                tenantId: auth?.tenant?.id ?? null,
                apiKeyId: auth?.apiKey?.id ?? null,
                endpoint,
                isError: httpStatus >= 400,
            });
        });
        next();
    };
}
