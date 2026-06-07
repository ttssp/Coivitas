import { describe, expect, it } from 'vitest';

import { makeSkippedStepRecord, runStep } from './runner.js';

// regression: makeSkippedStepRecord behavioral contract
describe('makeSkippedStepRecord', () => {
    it('should produce a record marked skipped=true with given reason', () => {
        const record = makeSkippedStepRecord(31, 'DHT routing', 'deferred');

        expect(record.number).toBe(31);
        expect(record.name).toBe('DHT routing');
        expect(record.skipped).toBe(true);
        expect(record.skipReason).toBe('deferred');
        expect(record.durationMs).toBe(0);
    });

    it('should set passed=true so skip does not signal failure to consumers', () => {
        const record = makeSkippedStepRecord(31, 'DHT routing', 'deferred');

        // a skipped record is not a failure: a caller judging step failure by the passed field should not get a false positive
        expect(record.passed).toBe(true);
    });

    it('should distinguish skipped from passed by the skipped flag, not by passed=false', () => {
        // counter-example: a conventional "pass with duration > 0" should not be mistaken for a skip
        const passed = { number: 30, name: 'x', durationMs: 5, passed: true };
        const skipped = makeSkippedStepRecord(31, 'y', 'z');

        expect(passed.passed).toBe(true);
        expect(skipped.passed).toBe(true);
        // the only distinguisher: the skipped field
        expect((passed as typeof skipped).skipped).toBeUndefined();
        expect(skipped.skipped).toBe(true);
    });
});

describe('runStep', () => {
    it('should record passed=true when fn resolves', async () => {
        const result = await runStep(
            1,
            'noop',
            () => Promise.resolve('value'),
            false,
        );

        expect(result.record.passed).toBe(true);
        expect(result.record.skipped).toBeUndefined();
        expect(result.value).toBe('value');
        expect(result.error).toBeUndefined();
    });

    it('should record passed=false when fn rejects', async () => {
        const result = await runStep(
            2,
            'fail',
            () => Promise.reject(new Error('boom')),
            false,
        );

        expect(result.record.passed).toBe(false);
        expect(result.record.skipped).toBeUndefined();
        expect(result.error?.message).toBe('boom');
    });
});
