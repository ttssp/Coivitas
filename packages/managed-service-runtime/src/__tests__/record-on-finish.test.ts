/**
 * record-on-finish.test.ts
 *
 * Verifies that requests rejected by rate-limiter (429) / auth-middleware (401) are also recorded in metrics + usage.
 */

import { describe, expect, it, vi } from 'vitest';
import { EventEmitter } from 'node:events';

import { createMetrics, recordResolverRequest } from '../metrics.js';
import { createRecordOnFinish } from '../record-on-finish.js';
import type { AuthenticatedRequest } from '../types.js';

import type { Request, Response, NextFunction } from 'express';

class MockResponse extends EventEmitter {
    statusCode = 200;
}

function makeReq(overrides: Partial<AuthenticatedRequest> = {}): AuthenticatedRequest {
    return {
        ip: '1.2.3.4',
        socket: { remoteAddress: '1.2.3.4' },
        ...overrides,
    } as AuthenticatedRequest;
}

describe('record-on-finish', () => {
    it('should record metrics + usage on res.finish for 429 (rate-limited)', () => {
        const metrics = createMetrics();
        const recordSpy = vi.spyOn(metrics.resolverRequests, 'inc');
        const recordFn = vi.fn();
        const usage = { record: recordFn } as unknown as Parameters<typeof createRecordOnFinish>[2];

        const middleware = createRecordOnFinish('resolver', metrics, usage);
        const req = makeReq();
        const res = new MockResponse() as unknown as Response;
        const next = vi.fn() as NextFunction;

        middleware(req as Request, res, next);
        expect(next).toHaveBeenCalled();

        // simulate rejection by rate-limiter: res.statusCode = 429 + emit 'finish'
        (res as unknown as MockResponse).statusCode = 429;
        (res as unknown as MockResponse).emit('finish');

        expect(recordSpy).toHaveBeenCalled();
        expect(recordFn).toHaveBeenCalledWith(
            expect.objectContaining({
                endpoint: 'resolver',
                isError: true,
                tenantId: null,
                apiKeyId: null,
            }),
        );
    });

    it('should record metrics + usage on res.finish for 401 (auth rejected)', () => {
        const metrics = createMetrics();
        const recordFn = vi.fn();
        const usage = { record: recordFn } as unknown as Parameters<typeof createRecordOnFinish>[2];

        const middleware = createRecordOnFinish('resolver', metrics, usage);
        const req = makeReq();
        const res = new MockResponse() as unknown as Response;
        const next = vi.fn() as NextFunction;

        middleware(req as Request, res, next);
        (res as unknown as MockResponse).statusCode = 401;
        (res as unknown as MockResponse).emit('finish');

        expect(recordFn).toHaveBeenCalledWith(
            expect.objectContaining({
                endpoint: 'resolver',
                isError: true,
            }),
        );
    });

    it('should record PRO tier when req.auth populated by auth-middleware', () => {
        const metrics = createMetrics();
        const recordSpy = vi.spyOn(metrics.resolverRequests, 'inc');
        const recordFn = vi.fn();
        const usage = { record: recordFn } as unknown as Parameters<typeof createRecordOnFinish>[2];

        const middleware = createRecordOnFinish('resolver', metrics, usage);
        const apiKey = {
            id: 'pk-1',
            tenantId: 't1',
            keyHash: 'h',
            keyPrefix: 'p',
            description: null,
            expiresAt: null,
            lastUsedAt: null,
            status: 'ACTIVE',
        } as const;
        const tenant = {
            id: 't1',
            tenantDid: 'did:agent:t1',
            tier: 'PRO',
            displayName: 'T',
            contactEmail: null,
            status: 'ACTIVE',
        } as const;
        const req = makeReq({
            auth: { tier: 'PRO', tenant, apiKey, clientIp: '5.5.5.5' },
        });
        const res = new MockResponse() as unknown as Response;
        const next = vi.fn() as NextFunction;

        middleware(req as Request, res, next);
        // auth-middleware only injects req.auth after next(); here we set it directly for the simulation
        (res as unknown as MockResponse).statusCode = 200;
        (res as unknown as MockResponse).emit('finish');

        expect(recordSpy).toHaveBeenCalledWith(
            expect.objectContaining({ tier: 'PRO' }),
            1,
        );
        expect(recordFn).toHaveBeenCalledWith(
            expect.objectContaining({
                tenantId: 't1',
                apiKeyId: 'pk-1',
                endpoint: 'resolver',
                isError: false,
            }),
        );
    });

    it('should record revocation endpoint with revocationChecks counter', () => {
        const metrics = createMetrics();
        const revSpy = vi.spyOn(metrics.revocationChecks, 'inc');
        const recordFn = vi.fn();
        const usage = { record: recordFn } as unknown as Parameters<typeof createRecordOnFinish>[2];

        const middleware = createRecordOnFinish('revocation', metrics, usage);
        const req = makeReq();
        const res = new MockResponse() as unknown as Response;
        const next = vi.fn() as NextFunction;

        middleware(req as Request, res, next);
        (res as unknown as MockResponse).statusCode = 200;
        (res as unknown as MockResponse).emit('finish');

        expect(revSpy).toHaveBeenCalled();
        expect(recordFn).toHaveBeenCalledWith(
            expect.objectContaining({ endpoint: 'revocation' }),
        );
    });

    // regression guard: ensure next() is always called synchronously (must not depend on res.finish to trigger next)
    it('should call next() immediately, regardless of finish event', () => {
        const metrics = createMetrics();
        const recordFn = vi.fn();
        const usage = { record: recordFn } as unknown as Parameters<typeof createRecordOnFinish>[2];
        const middleware = createRecordOnFinish('resolver', metrics, usage);

        const req = makeReq();
        const res = new MockResponse() as unknown as Response;
        const next = vi.fn() as NextFunction;

        middleware(req as Request, res, next);

        expect(next).toHaveBeenCalled();
        // finish has not fired yet, so usage has not been recorded
        expect(recordFn).not.toHaveBeenCalled();
    });

    // suppress the unused warning: recordResolverRequest is called inside record-on-finish.ts
    it.skip('imports recordResolverRequest', () => {
        expect(recordResolverRequest).toBeDefined();
    });
});
