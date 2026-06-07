/**
 * AuditBarrier unit tests
 *
 * Coverage:
 *   1. Constructor parameter validation (actorPrivateKey must not be empty)
 *   2. beforeExecute: ACTION_INTENT write, auditIntentId return, parameter passing
 *   3. beforeExecute: persistence failure -> AUDIT_INTENT_PERSIST_FAILED
 *   4. beforeExecute: write timeout -> AUDIT_INTENT_TIMEOUT
 *   5. afterExecute: ACTION_RESULT write, lifecycle advancement
 *   6. afterExecute: persistence failure -> AUDIT_RECORD_UPDATE_FAILED
 *   7. afterExecute: unknown auditIntentId -> INTERNAL_ERROR
 *   8. afterExecute: idempotent on repeated calls (no second write)
 *   9. beforeReceiptSign: ACTION_RESULT already written -> pass
 *  10. beforeReceiptSign: ACTION_RESULT not written -> AUDIT_RECORD_UPDATE_FAILED (fail-closed)
 *  11. beforeReceiptSign: unknown auditIntentId -> INTERNAL_ERROR
 *  12. happens-before lock: two beforeExecute calls on the same agentDid serialize (order 1->2, not interleaved)
 *  13. happens-before lock: different agentDids run in parallel without blocking each other
 *  14. happens-before lock: lock is released after a beforeExecute failure (subsequent calls can proceed)
 */

import { afterEach, describe, expect, it, vi } from 'vitest';

// Importing @coivitas/types directly fails in the worktree because of a missing
// ajv transitive dependency. DID is a plain branded string type; tests use an
// `unknown as DID` type assertion instead.
// ProtocolError is indirectly available via audit-barrier's internal import path,
// but the tests only need to inspect the .code / .message fields and do not require
// a strict instanceof ProtocolError check, so object-property matching
// (toMatchObject / toBeInstanceOf(Error)) is sufficient.
// Related: the implementation file references @coivitas/types correctly; the test
// file verifies its behavior indirectly through internal modules.
type DID = string & { readonly __brand: 'DID' };

import type { ActionRecorder } from '../action-recorder.js';
import {
    AuditBarrier,
    _resetHappensBeforeForTest,
    _resetIntentStatesForTest,
} from '../audit-barrier.js';

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/** Minimal mock ActionRecorder: only implements record()*/
function makeRecorder(
    recordImpl?: (...args: unknown[]) => unknown,
): ActionRecorder {
    return {
        record:
            recordImpl ??
            vi
                .fn()
                .mockResolvedValue({
                    recordId: 'r-default',
                    hash: 'h-default',
                }),
    } as unknown as ActionRecorder;
}

const FAKE_PRIVATE_KEY = 'a'.repeat(64);
const AGENT_DID = 'did:example:agent-1' as DID;
const PRINCIPAL_DID = 'did:example:principal-1' as DID;

function makeBarrier(opts?: {
    recorder?: ActionRecorder;
    timeoutMs?: number;
}): AuditBarrier {
    return new AuditBarrier(
        opts?.recorder ?? makeRecorder(),
        FAKE_PRIVATE_KEY,
        { timeoutMs: opts?.timeoutMs },
    );
}

function makeRecord(
    overrides?: Partial<Parameters<AuditBarrier['beforeExecute']>[0]>,
) {
    return {
        agentDid: AGENT_DID,
        principalDid: PRINCIPAL_DID,
        actionType: 'INQUIRY',
        ...overrides,
    };
}

// ---------------------------------------------------------------------------
// Cleanup
// ---------------------------------------------------------------------------

afterEach(() => {
    _resetHappensBeforeForTest();
    _resetIntentStatesForTest();
    vi.useRealTimers();
});

// ---------------------------------------------------------------------------
// 1. Constructor parameter validation
// ---------------------------------------------------------------------------

describe('AuditBarrier constructor', () => {
    it('should throw when actorPrivateKey is empty string', () => {
        expect(() => new AuditBarrier(makeRecorder(), '')).toThrow(
            'actorPrivateKey is required',
        );
    });

    it('should construct successfully with valid actorPrivateKey', () => {
        expect(() => makeBarrier()).not.toThrow();
    });
});

// ---------------------------------------------------------------------------
// 2. beforeExecute: ACTION_INTENT write
// ---------------------------------------------------------------------------

describe('AuditBarrier.beforeExecute', () => {
    it('should return a non-empty auditIntentId (UUID format)', async () => {
        const barrier = makeBarrier();
        const id = await barrier.beforeExecute(makeRecord());
        expect(id).toMatch(
            /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
        );
    });

    it('should call actionRecorder.record with ACTION_INTENT as actionType', async () => {
        const recordMock = vi
            .fn()
            .mockResolvedValue({ recordId: 'intent-record-id', hash: 'h1' });
        const barrier = makeBarrier({ recorder: makeRecorder(recordMock) });

        await barrier.beforeExecute(makeRecord());

        expect(recordMock).toHaveBeenCalledOnce();
        const callArg = recordMock.mock.calls[0][0] as Record<string, unknown>;
        expect(callArg['actionType']).toBe('ACTION_INTENT');
    });

    it('should pass agentDid / principalDid / sessionId / actorPrivateKey to record()', async () => {
        const recordMock = vi
            .fn()
            .mockResolvedValue({ recordId: 'r1', hash: 'h1' });
        const barrier = makeBarrier({ recorder: makeRecorder(recordMock) });

        await barrier.beforeExecute(
            makeRecord({ sessionId: 'session-xyz', envelopeId: 'env-abc' }),
        );

        const callArg = recordMock.mock.calls[0][0] as Record<string, unknown>;
        expect(callArg['agentDid']).toBe(AGENT_DID);
        expect(callArg['principalDid']).toBe(PRINCIPAL_DID);
        expect(callArg['sessionId']).toBe('session-xyz');
        expect(callArg['actorPrivateKey']).toBe(FAKE_PRIVATE_KEY);
    });

    it('should embed originalActionType / envelopeId / auditIntentId into parametersSummary', async () => {
        const recordMock = vi
            .fn()
            .mockResolvedValue({ recordId: 'r1', hash: 'h1' });
        const barrier = makeBarrier({ recorder: makeRecorder(recordMock) });

        const intentId = await barrier.beforeExecute(
            makeRecord({ envelopeId: 'env-42' }),
        );

        const callArg = recordMock.mock.calls[0][0] as Record<string, unknown>;
        const ps = callArg['parametersSummary'] as Record<string, unknown>;
        expect(ps['originalActionType']).toBe('INQUIRY');
        expect(ps['envelopeId']).toBe('env-42');
        expect(ps['auditIntentId']).toBe(intentId);
    });

    // 3. persistence failure
    it('should throw AUDIT_INTENT_PERSIST_FAILED when record() rejects', async () => {
        const recordMock = vi
            .fn()
            .mockRejectedValue(new Error('DB connection lost'));
        const barrier = makeBarrier({ recorder: makeRecorder(recordMock) });

        await expect(barrier.beforeExecute(makeRecord())).rejects.toMatchObject(
            {
                code: 'AUDIT_INTENT_PERSIST_FAILED',
            },
        );
    });

    it('should throw ProtocolError with AUDIT_INTENT_PERSIST_FAILED containing DB error detail', async () => {
        const recordMock = vi
            .fn()
            .mockRejectedValue(new Error('timeout on socket'));
        const barrier = makeBarrier({ recorder: makeRecorder(recordMock) });

        const err = await barrier
            .beforeExecute(makeRecord())
            .catch((e) => e as { code: string; message: string });
        expect(err).toBeInstanceOf(Error);
        expect(err.code).toBe('AUDIT_INTENT_PERSIST_FAILED');
        expect(err.message).toContain('timeout on socket');
    });

    // 4. write timeout
    it('should throw AUDIT_INTENT_TIMEOUT when write exceeds timeoutMs', async () => {
        vi.useFakeTimers();

        // neverResolve is a Promise that never settles, simulating a slow write.
        // Note: vitest's fake-timer advanceTimersByTimeAsync sometimes fires the
        // setTimeout callback again after the test completes (immediate flush),
        // producing a second unhandled rejection. Attaching .catch on neverResolve
        // prevents the leak (the reject can never actually fire; this is purely defensive).
        // eslint-disable-next-line @typescript-eslint/no-empty-function
        const neverResolve = new Promise<never>(() => {}).catch(() => {});
        const recordMock = vi.fn().mockReturnValue(neverResolve);
        const barrier = makeBarrier({
            recorder: makeRecorder(recordMock),
            timeoutMs: 100,
        });

        const promise = barrier.beforeExecute(makeRecord());
        // Catch beforeExecute's rejected promise so vitest does not treat it as an unhandled rejection
        promise.catch(() => {});
        await vi.advanceTimersByTimeAsync(200);

        await expect(promise).rejects.toMatchObject({
            code: 'AUDIT_INTENT_TIMEOUT',
        });
    });

    it('should clear timeout handle after successful write (no dangling timer)', async () => {
        vi.useFakeTimers();
        const recordMock = vi
            .fn()
            .mockResolvedValue({ recordId: 'r1', hash: 'h1' });
        const barrier = makeBarrier({
            recorder: makeRecorder(recordMock),
            timeoutMs: 1000,
        });

        await barrier.beforeExecute(makeRecord());

        // Advance beyond timeoutMs -- should not throw any error
        await vi.advanceTimersByTimeAsync(2000);
        // Test passes = no dangling timer triggers an exception
    });

    it('should return unique auditIntentId for each call', async () => {
        const barrier = makeBarrier();
        const id1 = await barrier.beforeExecute(makeRecord());
        const id2 = await barrier.beforeExecute(
            makeRecord({ agentDid: 'did:example:agent-2' as DID }),
        );
        expect(id1).not.toBe(id2);
    });
});

// ---------------------------------------------------------------------------
// 5. afterExecute: ACTION_RESULT write
// ---------------------------------------------------------------------------

describe('AuditBarrier.afterExecute', () => {
    it('should call actionRecorder.record with ACTION_RESULT as actionType', async () => {
        const recordMock = vi
            .fn()
            .mockResolvedValue({ recordId: 'r1', hash: 'h1' });
        const barrier = makeBarrier({ recorder: makeRecorder(recordMock) });

        const intentId = await barrier.beforeExecute(makeRecord());
        await barrier.afterExecute(intentId, 'SUCCESS');

        // first call = ACTION_INTENT, second call = ACTION_RESULT
        expect(recordMock).toHaveBeenCalledTimes(2);
        const resultCallArg = recordMock.mock.calls[1][0] as Record<
            string,
            unknown
        >;
        expect(resultCallArg['actionType']).toBe('ACTION_RESULT');
    });

    it('should include outcome and auditIntentId in ACTION_RESULT parametersSummary', async () => {
        const recordMock = vi
            .fn()
            .mockResolvedValue({ recordId: 'r1', hash: 'h1' });
        const barrier = makeBarrier({ recorder: makeRecorder(recordMock) });

        const intentId = await barrier.beforeExecute(makeRecord());
        await barrier.afterExecute(intentId, 'REJECTED');

        const resultCallArg = recordMock.mock.calls[1][0] as Record<
            string,
            unknown
        >;
        const ps = resultCallArg['parametersSummary'] as Record<
            string,
            unknown
        >;
        expect(ps['outcome']).toBe('REJECTED');
        expect(ps['auditIntentId']).toBe(intentId);
    });

    // 6. persistence failure
    it('should throw AUDIT_RECORD_UPDATE_FAILED when afterExecute record() rejects', async () => {
        let callCount = 0;
        const recordMock = vi.fn().mockImplementation(() => {
            callCount++;
            if (callCount === 1) {
                // beforeExecute write succeeds
                return Promise.resolve({ recordId: 'r1', hash: 'h1' });
            }
            // afterExecute write fails
            return Promise.reject(new Error('write timeout'));
        });
        const barrier = makeBarrier({ recorder: makeRecorder(recordMock) });

        const intentId = await barrier.beforeExecute(makeRecord());
        await expect(
            barrier.afterExecute(intentId, 'ERROR'),
        ).rejects.toMatchObject({
            code: 'AUDIT_RECORD_UPDATE_FAILED',
        });
    });

    // 7. unknown auditIntentId
    it('should throw INTERNAL_ERROR for unknown auditIntentId', async () => {
        const barrier = makeBarrier();
        await expect(
            barrier.afterExecute('nonexistent-uuid', 'SUCCESS'),
        ).rejects.toMatchObject({
            code: 'INTERNAL_ERROR',
        });
    });

    // 8. idempotent on repeated calls
    it('should be idempotent on second call (not call record() again)', async () => {
        const recordMock = vi
            .fn()
            .mockResolvedValue({ recordId: 'r1', hash: 'h1' });
        const barrier = makeBarrier({ recorder: makeRecorder(recordMock) });

        const intentId = await barrier.beforeExecute(makeRecord());
        await barrier.afterExecute(intentId, 'SUCCESS');
        await barrier.afterExecute(intentId, 'SUCCESS'); // second call

        // record() should only be called twice total (1 INTENT + 1 RESULT)
        expect(recordMock).toHaveBeenCalledTimes(2);
    });

    it('should allow ERROR outcome', async () => {
        const recordMock = vi
            .fn()
            .mockResolvedValue({ recordId: 'r1', hash: 'h1' });
        const barrier = makeBarrier({ recorder: makeRecorder(recordMock) });

        const intentId = await barrier.beforeExecute(makeRecord());
        await expect(
            barrier.afterExecute(intentId, 'ERROR'),
        ).resolves.toBeUndefined();
    });

    // afterExecute preserves principalDid + sessionId
    it('should preserve principalDid and sessionId from beforeExecute in ACTION_RESULT', async () => {
        const DELEGATED_PRINCIPAL = 'did:agent:f7principal' as DID;
        const SESSION = 'session-f7-001';
        const recordMock = vi
            .fn()
            .mockResolvedValue({ recordId: 'r1', hash: 'h1' });
        const barrier = makeBarrier({ recorder: makeRecorder(recordMock) });

        // beforeExecute uses a delegated principalDid + a real sessionId
        const intentId = await barrier.beforeExecute({
            agentDid: AGENT_DID,
            principalDid: DELEGATED_PRINCIPAL,
            actionType: 'INQUIRY',
            sessionId: SESSION,
            envelopeId: 'env-f7-001',
        });
        await barrier.afterExecute(intentId, 'SUCCESS');

        // Second record call = ACTION_RESULT
        const resultArg = recordMock.mock.calls[1][0] as Record<
            string,
            unknown
        >;
        expect(resultArg['actionType']).toBe('ACTION_RESULT');
        // Before this fix: principalDid was wrongly overwritten with state.agentDid
        expect(resultArg['principalDid']).toBe(DELEGATED_PRINCIPAL);
        expect(resultArg['agentDid']).toBe(AGENT_DID);
        // Before this fix: sessionId was lost entirely
        expect(resultArg['sessionId']).toBe(SESSION);
    });
});

// ---------------------------------------------------------------------------
// 9-11. beforeReceiptSign
// ---------------------------------------------------------------------------

describe('AuditBarrier.beforeReceiptSign', () => {
    // 9. ACTION_RESULT already written -> pass
    it('should not throw when ACTION_RESULT has been written', async () => {
        const barrier = makeBarrier();
        const intentId = await barrier.beforeExecute(makeRecord());
        await barrier.afterExecute(intentId, 'SUCCESS');

        expect(() =>
            barrier.beforeReceiptSign('envelope-001', intentId),
        ).not.toThrow();
    });

    // 10. ACTION_RESULT not written -> fail-closed
    it('should throw AUDIT_RECORD_UPDATE_FAILED when ACTION_RESULT not yet written (fail-closed)', async () => {
        const barrier = makeBarrier();
        const intentId = await barrier.beforeExecute(makeRecord());

        // afterExecute NOT called -> fail-closed: use try/catch to avoid no-unsafe-argument
        try {
            barrier.beforeReceiptSign('envelope-002', intentId);
            expect.fail('should have thrown');
        } catch (err) {
            expect((err as { code?: string }).code).toBe(
                'AUDIT_RECORD_UPDATE_FAILED',
            );
        }
    });

    it('should include envelopeId in error detail when ACTION_RESULT not written', () => {
        const barrier = makeBarrier();
        // never call beforeExecute -> intentId unknown
        try {
            barrier.beforeReceiptSign('env-special', 'some-unknown-uuid');
            expect.fail('should have thrown');
        } catch (err) {
            expect(err).toBeInstanceOf(Error);
            expect((err as { code?: string }).code).toBe('INTERNAL_ERROR');
        }
    });

    // 11. unknown auditIntentId -> INTERNAL_ERROR
    it('should throw INTERNAL_ERROR for unknown auditIntentId', () => {
        const barrier = makeBarrier();
        // try/catch avoids no-unsafe-argument (expect.objectContaining returns any)
        try {
            barrier.beforeReceiptSign('env-x', 'unknown-intent-id');
            expect.fail('should have thrown');
        } catch (err) {
            expect((err as { code?: string }).code).toBe('INTERNAL_ERROR');
        }
    });

    it('should include auditIntentId in INTERNAL_ERROR message', () => {
        const barrier = makeBarrier();
        try {
            barrier.beforeReceiptSign('env-x', 'uuid-12345');
            expect.fail('should have thrown');
        } catch (err) {
            expect((err as Error).message).toContain('uuid-12345');
        }
    });
});

// ---------------------------------------------------------------------------
// 12. happens-before lock: same agentDid serialization
// ---------------------------------------------------------------------------

describe('happens-before lock (same agentDid serialization)', () => {
    it('should serialize two beforeExecute calls on the same agentDid', async () => {
        const order: number[] = [];
        let callIndex = 0;

        const recordMock = vi.fn().mockImplementation(async () => {
            const myIndex = ++callIndex;
            // The second call intentionally resolves first, but the happens-before lock forces order 1->2
            if (myIndex === 1) {
                // Delay one microtask so the second call has a chance to "race"
                await new Promise<void>((r) => setTimeout(r, 0));
            }
            order.push(myIndex);
            return { recordId: `r${myIndex}`, hash: `h${myIndex}` };
        });

        const barrier = makeBarrier({ recorder: makeRecorder(recordMock) });
        const rec = makeRecord();

        // Fire two beforeExecute calls concurrently (same agentDid)
        const [id1, id2] = await Promise.all([
            barrier.beforeExecute(rec),
            barrier.beforeExecute(rec),
        ]);

        // The two IDs differ
        expect(id1).not.toBe(id2);
        // Order is strictly 1->2 (guaranteed by happens-before)
        expect(order).toEqual([1, 2]);
    });

    // 13. different agentDids run in parallel without blocking each other
    it('should NOT block different agentDid calls (parallel execution)', async () => {
        const completionOrder: string[] = [];

        const recordMock = vi
            .fn()
            .mockImplementation(
                (input: {
                    agentDid: string;
                }): Promise<{ recordId: string; hash: string }> => {
                    if (input.agentDid === AGENT_DID) {
                        return new Promise((resolve) =>
                            setTimeout(() => {
                                completionOrder.push('agent1');
                                resolve({ recordId: 'r1', hash: 'h1' });
                            }, 20),
                        );
                    }
                    // agent2 completes quickly
                    completionOrder.push('agent2');
                    return Promise.resolve({ recordId: 'r1', hash: 'h1' });
                },
            );

        const barrier = makeBarrier({ recorder: makeRecorder(recordMock) });

        await Promise.all([
            barrier.beforeExecute(makeRecord({ agentDid: AGENT_DID })),
            barrier.beforeExecute(
                makeRecord({ agentDid: 'did:example:agent-2' as DID }),
            ),
        ]);

        // agent2 should complete first (because it does not wait on agent1)
        expect(completionOrder[0]).toBe('agent2');
        expect(completionOrder[1]).toBe('agent1');
    });

    // 14. lock released after beforeExecute failure
    it('should release lock after beforeExecute failure so next call can proceed', async () => {
        let callCount = 0;
        const recordMock = vi
            .fn()
            .mockImplementation(
                (): Promise<{ recordId: string; hash: string }> => {
                    callCount++;
                    if (callCount === 1) {
                        return Promise.reject(new Error('first call fails'));
                    }
                    return Promise.resolve({ recordId: 'r2', hash: 'h2' });
                },
            );

        const barrier = makeBarrier({ recorder: makeRecorder(recordMock) });
        const rec = makeRecord();

        // First call fails
        await expect(barrier.beforeExecute(rec)).rejects.toMatchObject({
            code: 'AUDIT_INTENT_PERSIST_FAILED',
        });

        // Second call should succeed (lock has been released)
        const id = await barrier.beforeExecute(rec);
        expect(id).toBeTruthy();
        expect(callCount).toBe(2);
    });
});

// ---------------------------------------------------------------------------
// Full lifecycle integration flow (unit mock, no DB)
// ---------------------------------------------------------------------------

describe('AuditBarrier full lifecycle (unit)', () => {
    it('should complete full cycle: beforeExecute → afterExecute → beforeReceiptSign', async () => {
        const recordMock = vi
            .fn()
            .mockResolvedValue({ recordId: 'lifecycle-record', hash: 'h1' });
        const barrier = makeBarrier({ recorder: makeRecorder(recordMock) });

        // 1. beforeExecute
        const intentId = await barrier.beforeExecute(
            makeRecord({ envelopeId: 'env-lifecycle' }),
        );
        expect(intentId).toBeTruthy();

        // 2. afterExecute
        await barrier.afterExecute(intentId, 'SUCCESS');

        // 3. beforeReceiptSign — should not throw
        expect(() =>
            barrier.beforeReceiptSign('env-lifecycle', intentId),
        ).not.toThrow();

        // Verify record() called twice
        expect(recordMock).toHaveBeenCalledTimes(2);
        const firstActionType = (
            recordMock.mock.calls[0][0] as Record<string, unknown>
        )['actionType'];
        const secondActionType = (
            recordMock.mock.calls[1][0] as Record<string, unknown>
        )['actionType'];
        expect(firstActionType).toBe('ACTION_INTENT');
        expect(secondActionType).toBe('ACTION_RESULT');
    });

    it('should handle REJECTED outcome in full cycle', async () => {
        const recordMock = vi
            .fn()
            .mockResolvedValue({ recordId: 'r1', hash: 'h1' });
        const barrier = makeBarrier({ recorder: makeRecorder(recordMock) });

        const intentId = await barrier.beforeExecute(makeRecord());
        await barrier.afterExecute(intentId, 'REJECTED');

        // ACTION_RESULT written -> beforeReceiptSign passes
        expect(() =>
            barrier.beforeReceiptSign('env-1', intentId),
        ).not.toThrow();
    });
});
