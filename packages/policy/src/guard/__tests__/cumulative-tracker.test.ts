import { describe, expect, it, vi } from 'vitest';

import type { CumulativeLimitScope } from '@coivitas/types';

import type { CumulativeTracker } from '../cumulative-tracker.js';
import { computeWindowStart } from '../cumulative-tracker.js';
import { ScopeEvaluator } from '../scope-evaluator.js';

// ---- computeWindowStart unit tests ----
describe('computeWindowStart', () => {
    const base = new Date('2026-04-21T14:37:00Z');

    it('should return current hour start when window is hour', () => {
        const result = computeWindowStart('hour', base);
        expect(result.toISOString()).toBe('2026-04-21T14:00:00.000Z');
    });

    it('should return UTC day start when window is day', () => {
        const result = computeWindowStart('day', base);
        expect(result.toISOString()).toBe('2026-04-21T00:00:00.000Z');
    });

    it('should return ISO Monday start when window is week', () => {
        // 2026-04-21 is Tuesday; Monday = 2026-04-20
        const result = computeWindowStart('week', base);
        expect(result.toISOString()).toBe('2026-04-20T00:00:00.000Z');
    });

    it('should return first day of month when window is month', () => {
        const result = computeWindowStart('month', base);
        expect(result.toISOString()).toBe('2026-04-01T00:00:00.000Z');
    });

    it('should handle Sunday correctly for week window', () => {
        // 2026-04-19 is Sunday → Monday = 2026-04-13
        const sunday = new Date('2026-04-19T10:00:00Z');
        const result = computeWindowStart('week', sunday);
        expect(result.toISOString()).toBe('2026-04-13T00:00:00.000Z');
    });
});

// ---- ScopeEvaluator cumulative_limit branch unit tests ----
// evaluateCumulativeLimit now calls checkAndReserve (no longer getCumulativeValue).
// The mock must satisfy the full CumulativeTracker interface (TypeScript compliance).
describe('ScopeEvaluator cumulative_limit branch', () => {
    const baseScopeDay: CumulativeLimitScope = {
        type: 'cumulative_limit',
        meterField: { source: 'action_record', metric: 'api_call_count' },
        max: 3,
        window: 'day',
    };

    /** Build a mock satisfying the full CumulativeTracker interface; checkAndReserve returns the specified result */
    function makeTracker(
        allowed: boolean,
        currentCumulative: number,
    ): CumulativeTracker {
        return {
            getCumulativeValue: vi.fn().mockResolvedValue(currentCumulative),
            checkAndReserve: vi
                .fn()
                .mockResolvedValue({ allowed, currentCumulative }),
            settleReservation: vi.fn().mockResolvedValue(undefined),
        };
    }

    it('should allow when cumulative + current <= max', async () => {
        // checkAndReserve: currentCumulative=2, allowed=true (2+1=3 <= 3)
        const mockTracker = makeTracker(true, 2);
        const evaluator = new ScopeEvaluator(mockTracker);
        const result = await evaluator.evaluate(baseScopeDay, {});
        expect(result).toEqual({ allowed: true });
    });

    it('should deny when cumulative + current > max', async () => {
        // checkAndReserve: currentCumulative=3, allowed=false (3+1=4 > 3)
        const mockTracker = makeTracker(false, 3);
        const evaluator = new ScopeEvaluator(mockTracker);
        const result = await evaluator.evaluate(baseScopeDay, {});
        expect(result.allowed).toBe(false);
        expect(result.reason).toMatch(/cumulative_limit exceeded/);
    });

    it('should return error when no tracker injected', async () => {
        const evaluator = new ScopeEvaluator();
        const result = await evaluator.evaluate(baseScopeDay, {});
        expect(result.allowed).toBe(false);
        expect(result.reason).toMatch(/no CumulativeTracker injected/);
    });

    it('should return error when metric unregistered', async () => {
        const mockTracker = makeTracker(true, 0);
        const evaluator = new ScopeEvaluator(mockTracker);
        const unknownScope: CumulativeLimitScope = {
            type: 'cumulative_limit',
            meterField: { source: 'action_record', metric: 'unknown_metric' },
            max: 100,
            window: 'day',
        };
        const result = await evaluator.evaluate(unknownScope, {});
        expect(result.allowed).toBe(false);
        expect(result.reason).toMatch(/unregistered meter field/);
    });

    it('should fail-closed when SUM metric params field missing', async () => {
        // params is missing the amount field → returns early before calling checkAndReserve
        const mockTracker = makeTracker(true, 1000);
        const evaluator = new ScopeEvaluator(mockTracker);
        const sumScope: CumulativeLimitScope = {
            type: 'cumulative_limit',
            meterField: {
                source: 'action_record',
                metric: 'transaction_amount',
            },
            max: 50000,
            window: 'day',
        };
        // params is missing the amount field
        const result = await evaluator.evaluate(sumScope, {});
        expect(result.allowed).toBe(false);
        expect(result.reason).toMatch(/cannot extract meter value/);
    });

    it('should allow SUM metric when within limit', async () => {
        // checkAndReserve: allowed=true, currentCumulative=10000
        const mockTracker = makeTracker(true, 10000);
        const evaluator = new ScopeEvaluator(mockTracker);
        const sumScope: CumulativeLimitScope = {
            type: 'cumulative_limit',
            meterField: {
                source: 'action_record',
                metric: 'transaction_amount',
            },
            max: 50000,
            window: 'day',
        };
        // 10000 + 5000 = 15000 <= 50000
        const result = await evaluator.evaluate(sumScope, { amount: 5000 });
        expect(result).toEqual({ allowed: true });
    });

    it('should call checkAndReserve with correct arguments including recordId from params', async () => {
        const mockTracker = makeTracker(true, 0);
        const evaluator = new ScopeEvaluator(mockTracker);
        // Inject __recordId and __agentDid into params (simulating what RuntimeGuard does)
        await evaluator.evaluate(baseScopeDay, {
            __agentDid: 'did:key:agent123',
            __recordId: 'test-record-uuid',
        });
        // eslint-disable-next-line @typescript-eslint/unbound-method
        expect(mockTracker.checkAndReserve).toHaveBeenCalledWith(
            'test-record-uuid',
            'did:key:agent123',
            { source: 'action_record', metric: 'api_call_count' },
            expect.any(Date), // windowStart
            expect.any(Date), // now
            3, // max
            1, // reserveAmount (COUNT → 1)
        );
    });

    // Regression: MeterFieldRef.source three-state fail-closed.
    // 'external_witness' / 'consensus_meter' must be rejected outright
    // and must not reach the ActionRecord ledger path (per the scope-extensions spec)
    it('should fail-closed with METRIC_SOURCE_NOT_IMPLEMENTED when source is external_witness', async () => {
        const mockTracker = makeTracker(true, 0);
        const evaluator = new ScopeEvaluator(mockTracker);
        const witnessScope: CumulativeLimitScope = {
            type: 'cumulative_limit',
            meterField: {
                source: 'external_witness',
                metric: 'api_call_count',
            },
            max: 100,
            window: 'day',
        };
        const result = await evaluator.evaluate(witnessScope, {});
        expect(result.allowed).toBe(false);
        expect(result.reason).toMatch(/METRIC_SOURCE_NOT_IMPLEMENTED/);
        expect(result.reason).toMatch(/external_witness/);
        // Key point: tracker.checkAndReserve must not be called (to avoid misreading the ActionRecord ledger)
        // eslint-disable-next-line @typescript-eslint/unbound-method
        expect(mockTracker.checkAndReserve).not.toHaveBeenCalled();
    });

    it('should fail-closed with METRIC_SOURCE_NOT_IMPLEMENTED when source is consensus_meter', async () => {
        const mockTracker = makeTracker(true, 0);
        const evaluator = new ScopeEvaluator(mockTracker);
        const consensusScope: CumulativeLimitScope = {
            type: 'cumulative_limit',
            meterField: {
                source: 'consensus_meter',
                metric: 'api_call_count',
            },
            max: 100,
            window: 'day',
        };
        const result = await evaluator.evaluate(consensusScope, {});
        expect(result.allowed).toBe(false);
        expect(result.reason).toMatch(/METRIC_SOURCE_NOT_IMPLEMENTED/);
        expect(result.reason).toMatch(/consensus_meter/);
        // eslint-disable-next-line @typescript-eslint/unbound-method
        expect(mockTracker.checkAndReserve).not.toHaveBeenCalled();
    });
});
