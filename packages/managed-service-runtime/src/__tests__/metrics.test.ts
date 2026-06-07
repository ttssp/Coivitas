/**
 * metrics.test.ts
 *
 * Test target: metrics (packages/managed-service-runtime/src/metrics.ts)
 */

import { describe, expect, it } from 'vitest';

import {
    createMetrics,
    createMetricsHandler,
    DEFAULT_DURATION_BUCKETS_MS,
    recordResolverRequest,
    recordRevocationCheck,
    statusLabel,
    tenantLabel,
} from '../metrics.js';

import type { Request, Response } from 'express';

describe('metrics', () => {
    describe('tenantLabel', () => {
        it('should return "anonymous" for null/undefined/empty', () => {
            expect(tenantLabel(null)).toBe('anonymous');
            expect(tenantLabel(undefined)).toBe('anonymous');
            expect(tenantLabel('')).toBe('anonymous');
        });

        it('should return DID as-is for non-empty input', () => {
            expect(tenantLabel('did:agent:abc')).toBe('did:agent:abc');
        });
    });

    describe('statusLabel', () => {
        it('should bucket by HTTP status class', () => {
            expect(statusLabel(200)).toBe('2xx');
            expect(statusLabel(204)).toBe('2xx');
            expect(statusLabel(301)).toBe('3xx');
            expect(statusLabel(404)).toBe('4xx');
            expect(statusLabel(429)).toBe('4xx');
            expect(statusLabel(500)).toBe('5xx');
            expect(statusLabel(502)).toBe('5xx');
        });

        it('should label out-of-range as "other"', () => {
            expect(statusLabel(0)).toBe('other');
            expect(statusLabel(100)).toBe('other');
        });
    });

    describe('createMetrics', () => {
        it('should create independent registry by default', () => {
            const m = createMetrics();
            expect(m.registry).toBeDefined();
            expect(m.resolverRequests).toBeDefined();
            expect(m.resolverDurationMs).toBeDefined();
            expect(m.revocationChecks).toBeDefined();
        });

        it('should use custom buckets when provided', () => {
            const m = createMetrics({
                durationBuckets: [1, 2, 3],
                collectDefault: false,
            });
            expect(m).toBeDefined();
        });

        it('should disable default metrics when collectDefault=false', () => {
            const m = createMetrics({ collectDefault: false });
            expect(m).toBeDefined();
        });

        it('should expose DEFAULT_DURATION_BUCKETS_MS as 7 buckets', () => {
            expect(DEFAULT_DURATION_BUCKETS_MS).toEqual([
                10, 25, 50, 100, 250, 500, 1000,
            ]);
        });
    });

    describe('recordResolverRequest', () => {
        it('should increment counter and observe histogram', async () => {
            const m = createMetrics({ collectDefault: false });
            recordResolverRequest(m, {
                tenantDid: 'did:agent:t1',
                tier: 'PRO',
                httpStatus: 200,
                durationMs: 42,
            });
            const text = await m.registry.metrics();
            expect(text).toContain('resolver_requests_total');
            expect(text).toContain('tenant="did:agent:t1"');
            expect(text).toContain('tier="PRO"');
            expect(text).toContain('status="2xx"');
        });

        it('should clamp negative durationMs to 0', async () => {
            const m = createMetrics({ collectDefault: false });
            recordResolverRequest(m, {
                tenantDid: null,
                tier: 'FREE',
                httpStatus: 200,
                durationMs: -5,
            });
            const text = await m.registry.metrics();
            expect(text).toContain('resolver_request_duration_ms_count');
        });
    });

    describe('recordRevocationCheck', () => {
        it('should increment revocation counter', async () => {
            const m = createMetrics({ collectDefault: false });
            recordRevocationCheck(m, {
                tenantDid: 'did:agent:t2',
                tier: 'PRO',
                httpStatus: 404,
            });
            const text = await m.registry.metrics();
            expect(text).toContain('revocation_check_total');
            expect(text).toContain('status="4xx"');
        });
    });

    describe('createMetricsHandler', () => {
        it('should return 200 with text body containing metric names', async () => {
            const m = createMetrics({ collectDefault: false });
            recordResolverRequest(m, {
                tenantDid: null,
                tier: 'FREE',
                httpStatus: 200,
                durationMs: 10,
            });

            const handler = createMetricsHandler(m);
            const res = makeMetricsResponse();
            await handler({} as Request, res.response);

            expect(res.statusCode).toBe(200);
            expect(res.body).toContain('resolver_requests_total');
        });

        it('should return 500 when registry.metrics() throws', async () => {
            const m = createMetrics({ collectDefault: false });
            // replace the metrics() method to trigger an error
            const original = m.registry.metrics.bind(m.registry);
            m.registry.metrics = () =>
                Promise.reject(new Error('render fail'));

            const handler = createMetricsHandler(m);
            const res = makeMetricsResponse();
            await handler({} as Request, res.response);

            expect(res.statusCode).toBe(500);
            expect(res.body).toContain('METRICS_RENDER_FAILED');

            // restore to avoid polluting other tests
            m.registry.metrics = original;
        });

        it('should serialize unknown error type as "unknown error"', async () => {
            const m = createMetrics({ collectDefault: false });
            // eslint-disable-next-line @typescript-eslint/prefer-promise-reject-errors
            m.registry.metrics = () => Promise.reject('weird-string-error');

            const handler = createMetricsHandler(m);
            const res = makeMetricsResponse();
            await handler({} as Request, res.response);

            expect(res.statusCode).toBe(500);
            expect(res.body).toContain('unknown error');
        });
    });
});

interface MetricsResponseHarness {
    response: Response;
    statusCode: number;
    body: string;
    headers: Record<string, string>;
}

function makeMetricsResponse(): MetricsResponseHarness {
    const harness: MetricsResponseHarness = {
        response: null as unknown as Response,
        statusCode: 0,
        body: '',
        headers: {},
    };
    const response = {
        status(code: number) {
            harness.statusCode = code;
            return response;
        },
        send(body: string) {
            harness.body = body;
            return response;
        },
        json(payload: unknown) {
            harness.body = JSON.stringify(payload);
            return response;
        },
        setHeader(name: string, value: string) {
            harness.headers[name] = value;
        },
    } as unknown as Response;
    harness.response = response;
    return harness;
}
