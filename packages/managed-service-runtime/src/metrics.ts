/**
 * Prometheus metrics exporter (managed-service monitoring).
 *
 * Design notes (conclusion first, details after):
 * 1. Uses prom-client: an industry standard, avoiding reinventing the wheel.
 *    Does not conflict with the OTel exporter in packages/identity — this package has its own metrics namespace.
 * 2. Three core metrics (consistent set):
 *    - resolver_requests_total{tenant,tier,status} Counter
 *    - resolver_request_duration_ms{tenant,tier} Histogram (buckets 10/25/50/100/250/500/1000)
 *    - revocation_check_total{tenant,tier,status} Counter
 * 3. Controlling tenant label cardinality explosion:
 *    - tenant label value = tenant.tenantDid (B2B customer identity); FREE anonymous = 'anonymous'
 *    - PRO customer count << 1000 (B2B is not a mass-user SaaS scenario), so label cardinality stays bounded
 *    - if finer granularity is needed in the future, migrate to OTel exemplars
 * 4. Dedicated Registry: when the global register conflicts with other packages by default, pass an isolated
 *    register via createMetricsRegistry().
 * 5. /metrics endpoint: Prometheus pull mode; scrape via :8080/metrics and :8081/metrics.
 *
 */

import {
    Counter,
    Histogram,
    Registry,
    collectDefaultMetrics,
} from 'prom-client';
import type { Request, Response } from 'express';

import type { Tier } from './types.js';

/** Histogram bucket (milliseconds) */
export const DEFAULT_DURATION_BUCKETS_MS = [
    10, 25, 50, 100, 250, 500, 1000,
] as const;

/** Bundle of the three core metrics (record via the record* methods externally) */
export interface Metrics {
    registry: Registry;
    resolverRequests: Counter<'tenant' | 'tier' | 'status'>;
    resolverDurationMs: Histogram<'tenant' | 'tier'>;
    revocationChecks: Counter<'tenant' | 'tier' | 'status'>;
}

export interface CreateMetricsConfig {
    /** Whether to enable Node.js process metrics (CPU/Mem/event loop); defaults to true */
    collectDefault?: boolean;
    /** Histogram buckets (overrides the default); defaults to DEFAULT_DURATION_BUCKETS_MS */
    durationBuckets?: readonly number[];
}

/**
 * Create a dedicated metrics registry (does not pollute the global register).
 */
export function createMetrics(config: CreateMetricsConfig = {}): Metrics {
    const registry = new Registry();

    if (config.collectDefault !== false) {
        collectDefaultMetrics({ register: registry });
    }

    const buckets = [...(config.durationBuckets ?? DEFAULT_DURATION_BUCKETS_MS)];

    const resolverRequests = new Counter({
        name: 'resolver_requests_total',
        help: 'Total number of DID resolver requests by tenant / tier / status.',
        labelNames: ['tenant', 'tier', 'status'] as const,
        registers: [registry],
    });

    const resolverDurationMs = new Histogram({
        name: 'resolver_request_duration_ms',
        help: 'DID resolver request duration in milliseconds.',
        labelNames: ['tenant', 'tier'] as const,
        buckets,
        registers: [registry],
    });

    const revocationChecks = new Counter({
        name: 'revocation_check_total',
        help: 'Total number of revocation check requests by tenant / tier / status.',
        labelNames: ['tenant', 'tier', 'status'] as const,
        registers: [registry],
    });

    return { registry, resolverRequests, resolverDurationMs, revocationChecks };
}

/** Label extraction: keep the tenant dimension low-cardinality (FREE anonymous -> 'anonymous') */
export function tenantLabel(tenantDid: string | null | undefined): string {
    if (!tenantDid || tenantDid.length === 0) {
        return 'anonymous';
    }
    return tenantDid;
}

/** Label extraction: keep the HTTP status dimension low-cardinality (2xx/3xx/4xx/5xx buckets) */
export function statusLabel(httpStatus: number): string {
    if (httpStatus >= 500) return '5xx';
    if (httpStatus >= 400) return '4xx';
    if (httpStatus >= 300) return '3xx';
    if (httpStatus >= 200) return '2xx';
    return 'other';
}

/**
 * Express handler: export the Prometheus text format.
 *
 * Mounting example:
 * ```ts
 * app.get('/metrics', createMetricsHandler(metrics));
 * ```
 */
export function createMetricsHandler(metrics: Metrics) {
    return async function metricsHandler(
        _req: Request,
        res: Response,
    ): Promise<void> {
        try {
            const body = await metrics.registry.metrics();
            res.setHeader('Content-Type', metrics.registry.contentType);
            res.status(200).send(body);
        } catch (error) {
            res.status(500).json({
                error: {
                    code: 'METRICS_RENDER_FAILED',
                    message:
                        error instanceof Error
                            ? error.message
                            : 'unknown error',
                },
            });
        }
    };
}

/**
 * Convenience API: record a single resolver request.
 */
export function recordResolverRequest(
    metrics: Metrics,
    args: {
        tenantDid: string | null | undefined;
        tier: Tier;
        httpStatus: number;
        durationMs: number;
    },
): void {
    const tenant = tenantLabel(args.tenantDid);
    const status = statusLabel(args.httpStatus);
    metrics.resolverRequests.inc({ tenant, tier: args.tier, status }, 1);
    metrics.resolverDurationMs.observe(
        { tenant, tier: args.tier },
        Math.max(0, args.durationMs),
    );
}

/**
 * Convenience API: record a single revocation check.
 */
export function recordRevocationCheck(
    metrics: Metrics,
    args: {
        tenantDid: string | null | undefined;
        tier: Tier;
        httpStatus: number;
    },
): void {
    const tenant = tenantLabel(args.tenantDid);
    const status = statusLabel(args.httpStatus);
    metrics.revocationChecks.inc({ tenant, tier: args.tier, status }, 1);
}
