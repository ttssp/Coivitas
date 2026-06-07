import { describe, expect, it } from 'vitest';

import type { TemporalScope } from '@coivitas/types';

import { ScopeEvaluator } from '../scope-evaluator.js';

describe('ScopeEvaluator — temporal_scope', () => {
    const evaluator = new ScopeEvaluator();

    // Fixed reference time: 2026-04-20T10:00:00Z (Monday)
    const BASE_NOW = new Date('2026-04-20T10:00:00Z');

    const makeScope = (
        overrides: Partial<Omit<TemporalScope, 'type'>> = {},
    ): TemporalScope => ({
        type: 'temporal_scope',
        notBefore: '2026-04-20T09:00:00.000Z',
        notAfter: '2026-04-20T18:00:00.000Z',
        ...overrides,
    });

    // ── Basic absolute time range ────────────────────────────────────────────

    it('should allow when now is within notBefore and notAfter', async () => {
        const result = await evaluator.evaluate(makeScope(), {}, BASE_NOW);
        expect(result).toEqual({ allowed: true });
    });

    it('should deny when now is before notBefore', async () => {
        const now = new Date('2026-04-20T08:59:59Z');
        const result = await evaluator.evaluate(makeScope(), {}, now);
        expect(result).toEqual({
            allowed: false,
            reason: 'temporal_scope: not yet active (before notBefore)',
        });
    });

    it('should deny when now equals notAfter (boundary exclusive)', async () => {
        const now = new Date('2026-04-20T18:00:00.000Z');
        const result = await evaluator.evaluate(makeScope(), {}, now);
        expect(result).toEqual({
            allowed: false,
            reason: 'temporal_scope: expired (at or after notAfter)',
        });
    });

    it('should deny when now is after notAfter', async () => {
        const now = new Date('2026-04-20T18:00:01Z');
        const result = await evaluator.evaluate(makeScope(), {}, now);
        expect(result).toEqual({
            allowed: false,
            reason: 'temporal_scope: expired (at or after notAfter)',
        });
    });

    it('should allow when now equals notBefore (boundary inclusive)', async () => {
        const now = new Date('2026-04-20T09:00:00.000Z');
        const result = await evaluator.evaluate(makeScope(), {}, now);
        expect(result).toEqual({ allowed: true });
    });

    // ── recurringWindow (non-midnight-crossing) ────────────────────────────────

    it('should allow when now is within recurring window on a weekday', async () => {
        // 2026-04-20T04:00:00Z = Asia/Shanghai 12:00 Monday → window 09:00–18:00 on weekdays ✓
        const scope = makeScope({
            notBefore: '2026-04-20T00:00:00.000Z',
            notAfter: '2026-04-21T23:59:59.000Z',
            recurringWindow: {
                startTime: '09:00',
                endTime: '18:00',
                daysOfWeek: [1, 2, 3, 4, 5],
                timezone: 'Asia/Shanghai',
            },
        });
        const now = new Date('2026-04-20T04:00:00Z'); // 12:00 CST Monday
        const result = await evaluator.evaluate(scope, {}, now);
        expect(result).toEqual({ allowed: true });
    });

    it('should deny when now is outside recurring window time range', async () => {
        const scope = makeScope({
            recurringWindow: {
                startTime: '09:00',
                endTime: '18:00',
                daysOfWeek: [1, 2, 3, 4, 5],
                timezone: 'Asia/Shanghai',
            },
        });
        // 01:00 CST = 17:00 the previous day UTC → within the absolute range, but the time-of-day is wrong
        const now = new Date('2026-04-20T11:30:00Z'); // 19:30 CST, outside the window
        const result = await evaluator.evaluate(scope, {}, now);
        expect(result.allowed).toBe(false);
        expect(result.reason).toContain('outside recurring window');
    });

    it('should deny when now falls on a non-allowed day of week', async () => {
        const scope = makeScope({
            notBefore: '2026-04-25T00:00:00.000Z',
            notAfter: '2026-04-27T23:59:59.000Z',
            recurringWindow: {
                startTime: '09:00',
                endTime: '18:00',
                daysOfWeek: [1, 2, 3, 4, 5], // weekdays
                timezone: 'UTC',
            },
        });
        // 2026-04-26T10:00:00Z = Sunday
        const now = new Date('2026-04-26T10:00:00Z');
        const result = await evaluator.evaluate(scope, {}, now);
        expect(result.allowed).toBe(false);
        expect(result.reason).toContain('outside recurring window');
    });

    it('should allow every day when daysOfWeek is omitted', async () => {
        const scope = makeScope({
            recurringWindow: {
                startTime: '00:00',
                endTime: '23:59',
                timezone: 'UTC',
            },
        });
        const now = new Date('2026-04-20T12:00:00Z'); // Sunday
        const result = await evaluator.evaluate(scope, {}, now);
        expect(result).toEqual({ allowed: true });
    });

    // ── recurringWindow (midnight-crossing) ────────────────────────────────────

    it('should allow when now is in midnight-crossing window before midnight', async () => {
        // window 22:00–06:00 UTC, now is 23:00 Monday
        const scope = makeScope({
            notBefore: '2026-04-20T00:00:00.000Z',
            notAfter: '2026-04-21T23:59:59.000Z',
            recurringWindow: {
                startTime: '22:00',
                endTime: '06:00',
                daysOfWeek: [1], // Monday
                timezone: 'UTC',
            },
        });
        const now = new Date('2026-04-20T23:00:00Z'); // 23:00 UTC Monday
        const result = await evaluator.evaluate(scope, {}, now);
        expect(result).toEqual({ allowed: true });
    });

    it('should allow when now is in midnight-crossing window after midnight (attributed to the previous day)', async () => {
        // window 22:00–06:00 UTC, daysOfWeek=[1] (Monday)
        // now is Tuesday 02:00, attributed to the Monday night shift → allowed
        const scope = makeScope({
            notBefore: '2026-04-20T00:00:00.000Z',
            notAfter: '2026-04-22T23:59:59.000Z',
            recurringWindow: {
                startTime: '22:00',
                endTime: '06:00',
                daysOfWeek: [1], // Monday
                timezone: 'UTC',
            },
        });
        const now = new Date('2026-04-21T02:00:00Z'); // Tuesday 02:00 UTC → attributed to Monday
        const result = await evaluator.evaluate(scope, {}, now);
        expect(result).toEqual({ allowed: true });
    });

    it('should deny when now is between windows in midnight-crossing scenario', async () => {
        // window 22:00–06:00, now is 12:00 (outside the mid-window gap)
        const scope = makeScope({
            notBefore: '2026-04-20T00:00:00.000Z',
            notAfter: '2026-04-21T23:59:59.000Z',
            recurringWindow: {
                startTime: '22:00',
                endTime: '06:00',
                timezone: 'UTC',
            },
        });
        const now = new Date('2026-04-20T12:00:00Z');
        const result = await evaluator.evaluate(scope, {}, now);
        expect(result.allowed).toBe(false);
    });

    // ── Timezone boundaries ────────────────────────────────────────────────────

    it('should correctly evaluate timezone boundary (America/New_York UTC-4 in summer)', async () => {
        // 09:30 EDT = 13:30 UTC
        const scope = makeScope({
            notBefore: '2026-04-20T00:00:00.000Z',
            notAfter: '2026-04-21T23:59:59.000Z',
            recurringWindow: {
                startTime: '09:00',
                endTime: '17:00',
                daysOfWeek: [1, 2, 3, 4, 5],
                timezone: 'America/New_York',
            },
        });
        const now = new Date('2026-04-20T13:30:00Z'); // 09:30 EDT Monday
        const result = await evaluator.evaluate(scope, {}, now);
        expect(result).toEqual({ allowed: true });
    });

    it('should deny when now is outside timezone-local window', async () => {
        // 08:30 EDT = 12:30 UTC (window 09:00–17:00 EDT)
        const scope = makeScope({
            notBefore: '2026-04-20T00:00:00.000Z',
            notAfter: '2026-04-21T23:59:59.000Z',
            recurringWindow: {
                startTime: '09:00',
                endTime: '17:00',
                daysOfWeek: [1, 2, 3, 4, 5],
                timezone: 'America/New_York',
            },
        });
        const now = new Date('2026-04-20T12:30:00Z'); // 08:30 EDT, before the window
        const result = await evaluator.evaluate(scope, {}, now);
        expect(result.allowed).toBe(false);
    });

    // ── Invalid timezone ────────────────────────────────────────────────────

    it('should deny with invalid timezone reason when timezone is not a valid IANA name', async () => {
        const scope = makeScope({
            notBefore: '2026-04-20T00:00:00.000Z',
            notAfter: '2026-04-21T23:59:59.000Z',
            recurringWindow: {
                startTime: '09:00',
                endTime: '18:00',
                timezone: 'Not/A/Timezone',
            },
        });
        const result = await evaluator.evaluate(scope, {}, BASE_NOW);
        expect(result).toEqual({
            allowed: false,
            reason: 'temporal_scope: invalid timezone',
        });
    });

    // ── Boundary when notBefore/notAfter omit milliseconds ────────────────────────

    it('should allow when now equals notBefore without milliseconds (boundary inclusive)', async () => {
        // "2026-04-20T09:00:00Z" vs now.toISOString() "2026-04-20T09:00:00.000Z"
        // The old string comparison would misjudge (.000Z < Z); numeric comparison is correct
        const scope = makeScope({
            notBefore: '2026-04-20T09:00:00Z',
            notAfter: '2026-04-20T18:00:00Z',
        });
        const now = new Date('2026-04-20T09:00:00.000Z');
        const result = await evaluator.evaluate(scope, {}, now);
        expect(result).toEqual({ allowed: true });
    });

    // ── Default time (now not provided) ────────────────────────────────────────

    it('should use current time when now is not provided', async () => {
        // Set a scope that is definitely expired
        const scope = makeScope({
            notBefore: '2000-01-01T00:00:00.000Z',
            notAfter: '2000-01-02T00:00:00.000Z',
        });
        const result = await evaluator.evaluate(scope, {});
        expect(result).toEqual({
            allowed: false,
            reason: 'temporal_scope: expired (at or after notAfter)',
        });
    });

    // ── Reject non-IANA timezone aliases ─────────────────────────────────

    it('should deny when timezone is a non-IANA alias (CST)', async () => {
        const scope = makeScope({
            notBefore: '2026-04-20T00:00:00.000Z',
            notAfter: '2026-04-21T23:59:59.000Z',
            recurringWindow: {
                startTime: '09:00',
                endTime: '18:00',
                timezone: 'CST',
            },
        });
        const result = await evaluator.evaluate(scope, {}, BASE_NOW);
        expect(result).toEqual({
            allowed: false,
            reason: 'temporal_scope: invalid timezone',
        });
    });

    // ── Reject invalid startTime/endTime formats ────────────────────

    it('should deny when startTime uses hour 24 (out of range)', async () => {
        const scope = makeScope({
            notBefore: '2026-04-20T00:00:00.000Z',
            notAfter: '2026-04-21T23:59:59.000Z',
            recurringWindow: {
                startTime: '24:30',
                endTime: '18:00',
                timezone: 'UTC',
            },
        });
        const result = await evaluator.evaluate(scope, {}, BASE_NOW);
        expect(result).toEqual({
            allowed: false,
            reason: 'temporal_scope: invalid time format',
        });
    });

    // ── Reject an empty daysOfWeek array ────────────────────────────

    it('should deny all access when daysOfWeek is explicitly empty array', async () => {
        const scope = makeScope({
            notBefore: '2026-04-20T00:00:00.000Z',
            notAfter: '2026-04-21T23:59:59.000Z',
            recurringWindow: {
                startTime: '00:00',
                endTime: '23:59',
                daysOfWeek: [],
                timezone: 'UTC',
            },
        });
        const result = await evaluator.evaluate(scope, {}, BASE_NOW);
        expect(result.allowed).toBe(false);
        expect(result.reason).toContain(
            'outside recurring window (day of week)',
        );
    });

    // ── evaluateAll integration ────────────────────────────────────────────

    it('should integrate temporal_scope in evaluateAll with AND semantics', async () => {
        const scopes = [
            {
                type: 'allowlist' as const,
                field: 'action',
                values: ['read'],
            },
            makeScope(),
        ];
        const result = await evaluator.evaluateAll(
            scopes,
            { action: 'read' },
            BASE_NOW,
        );
        expect(result).toEqual({ allowed: true });
    });

    it('should short-circuit in evaluateAll when temporal_scope denies', async () => {
        const scopes = [
            makeScope({
                notBefore: '2000-01-01T00:00:00.000Z',
                notAfter: '2000-01-02T00:00:00.000Z',
            }),
            {
                type: 'allowlist' as const,
                field: 'action',
                values: ['read'],
            },
        ];
        const result = await evaluator.evaluateAll(
            scopes,
            { action: 'read' },
            BASE_NOW,
        );
        expect(result.allowed).toBe(false);
    });
});
