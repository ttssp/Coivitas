import { describe, expect, it, vi } from 'vitest';

import {
    ACTION_VOCABULARY,
    ACTION_SESSION_SUPERSEDED,
    SESSION_GOVERNOR_DID,
} from '@coivitas/types';

import type { ActionRecordInput, RecordWriteResult } from '../types.js';
import { PolicyEngine } from '../engine.js';

describe('PolicyEngine', () => {
    it('records denied executions, approved executions, human denials, and executor failures', async () => {
        const record = vi
            .fn<(_: ActionRecordInput) => Promise<RecordWriteResult>>()
            .mockResolvedValue({
                recordId: 'record-1',
                hash: 'a'.repeat(64),
            });

        const deniedEngine = new PolicyEngine({
            guard: {
                check() {
                    return Promise.resolve({
                        allowed: false,
                        reason: 'no matching capability',
                    });
                },
            },
            recorder: { record },
        });

        await expect(
            deniedEngine.executeWithPolicy({
                action: 'INQUIRY',
                params: { recipient: 'supplier-a' },
                agentDid:
                    'did:agent:00112233445566778899aabbccddeeff00112233' as never,
                principalDid:
                    'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK' as never,
                actorPrivateKey: '0'.repeat(128),
                executor: () => Promise.resolve('ok'),
            }),
        ).resolves.toEqual({
            executed: false,
            reason: 'no matching capability',
            recordId: 'record-1',
        });

        const checkpointRecord = vi
            .fn<(_: ActionRecordInput) => Promise<RecordWriteResult>>()
            .mockResolvedValue({
                recordId: 'record-2',
                hash: 'b'.repeat(64),
            });
        const checkpointEngine = new PolicyEngine({
            guard: {
                check() {
                    return Promise.resolve({
                        allowed: true,
                        tokenId: 'urn:cap:1',
                    });
                },
            },
            recorder: { record: checkpointRecord },
            checkpoint: {
                requestConfirmation() {
                    return Promise.resolve(false);
                },
            },
        });

        await expect(
            checkpointEngine.executeWithPolicy({
                action: 'CONFIRM',
                params: { amount: 100 },
                agentDid:
                    'did:agent:00112233445566778899aabbccddeeff00112233' as never,
                principalDid:
                    'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK' as never,
                actorPrivateKey: '0'.repeat(128),
                requireHumanApproval: true,
                executor: () => Promise.resolve('ok'),
            }),
        ).resolves.toEqual({
            executed: false,
            reason: 'human approval denied',
            recordId: 'record-2',
        });

        const successRecord = vi
            .fn<(_: ActionRecordInput) => Promise<RecordWriteResult>>()
            .mockResolvedValueOnce({
                recordId: 'record-3',
                hash: 'c'.repeat(64),
            })
            .mockResolvedValueOnce({
                recordId: 'record-4',
                hash: 'd'.repeat(64),
            });
        const successEngine = new PolicyEngine({
            guard: {
                check() {
                    return Promise.resolve({
                        allowed: true,
                        tokenId: 'urn:cap:2',
                    });
                },
            },
            recorder: { record: successRecord },
        });

        await expect(
            successEngine.executeWithPolicy({
                action: 'QUOTE',
                params: { amount: 100 },
                agentDid:
                    'did:agent:00112233445566778899aabbccddeeff00112233' as never,
                principalDid:
                    'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK' as never,
                actorPrivateKey: '0'.repeat(128),
                executor: () => Promise.resolve({ ok: true }),
            }),
        ).resolves.toEqual({
            executed: true,
            result: { ok: true },
            recordId: 'record-3',
        });

        await expect(
            successEngine.executeWithPolicy({
                action: 'QUOTE',
                params: { amount: 100 },
                agentDid:
                    'did:agent:00112233445566778899aabbccddeeff00112233' as never,
                principalDid:
                    'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK' as never,
                actorPrivateKey: '0'.repeat(128),
                executor: () => {
                    throw new Error('executor failed');
                },
            }),
        ).rejects.toThrow('executor failed');

        expect(successRecord).toHaveBeenCalledTimes(2);
    });

    it('propagates delegationDepth from guard result to recorder', async () => {
        // Guard returns a result carrying delegationDepth (simulating a delegation
        // chain that verified successfully with depth=2); executeWithPolicy must write
        // depth verbatim into recorder.record() so the ActionRecord retains the audit signal.
        const record = vi
            .fn<(_: ActionRecordInput) => Promise<RecordWriteResult>>()
            .mockResolvedValue({
                recordId: 'record-depth',
                hash: 'f'.repeat(64),
            });
        const engine = new PolicyEngine({
            guard: {
                check() {
                    return Promise.resolve({
                        allowed: true,
                        tokenId: 'urn:cap:delegated',
                        delegationDepth: 2,
                    });
                },
            },
            recorder: { record },
        });

        await engine.executeWithPolicy({
            action: 'INQUIRY',
            params: {},
            agentDid:
                'did:agent:00112233445566778899aabbccddeeff00112233' as never,
            principalDid:
                'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK' as never,
            actorPrivateKey: '0'.repeat(128),
            executor: () => Promise.resolve({ ok: true }),
        });

        expect(record).toHaveBeenCalledTimes(1);
        expect(record.mock.calls[0]?.[0].delegationDepth).toBe(2);
    });

    it('propagates delegationDepth through human-checkpoint-denied path', async () => {
        const record = vi
            .fn<(_: ActionRecordInput) => Promise<RecordWriteResult>>()
            .mockResolvedValue({
                recordId: 'record-checkpoint-depth',
                hash: 'f'.repeat(64),
            });
        const engine = new PolicyEngine({
            guard: {
                check() {
                    return Promise.resolve({
                        allowed: true,
                        tokenId: 'urn:cap:delegated',
                        delegationDepth: 4,
                    });
                },
            },
            recorder: { record },
            checkpoint: {
                requestConfirmation() {
                    return Promise.resolve(false);
                },
            },
        });

        await engine.executeWithPolicy({
            action: 'CONFIRM',
            params: {},
            agentDid:
                'did:agent:00112233445566778899aabbccddeeff00112233' as never,
            principalDid:
                'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK' as never,
            actorPrivateKey: '0'.repeat(128),
            requireHumanApproval: true,
            executor: () => Promise.resolve('unreached'),
        });

        expect(record).toHaveBeenCalledTimes(1);
        expect(record.mock.calls[0]?.[0].delegationDepth).toBe(4);
    });

    it('handles undefined guardResult.tokenId (writes tokenId:null in authorizationRef) + undefined reason (records "action rejected" default)', async () => {
        // Covers the two nullish-coalescing branches in engine.ts:
        // `guardResult.tokenId ?? null` and `guardResult.reason ?? 'action rejected'`.
        const record = vi
            .fn<(_: ActionRecordInput) => Promise<RecordWriteResult>>()
            .mockResolvedValue({
                recordId: 'record-nullish',
                hash: 'f'.repeat(64),
            });

        // Branch 1: denied and guardResult.reason is undefined → reason falls back to 'action rejected'
        const deniedNoReasonEngine = new PolicyEngine({
            guard: {
                check() {
                    return Promise.resolve({ allowed: false });
                },
            },
            recorder: { record },
        });
        const deniedResult = await deniedNoReasonEngine.executeWithPolicy({
            action: 'INQUIRY',
            params: {},
            agentDid:
                'did:agent:00112233445566778899aabbccddeeff00112233' as never,
            principalDid:
                'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK' as never,
            actorPrivateKey: '0'.repeat(128),
            executor: () => Promise.resolve('unreached'),
        });
        if (deniedResult.executed) {
            throw new Error('unexpected executed=true');
        }
        expect(deniedResult.reason).toBe('action rejected');

        // Branch 2: allowed but guardResult.tokenId is undefined → authRef.tokenId=null
        const allowedNoTokenIdEngine = new PolicyEngine({
            guard: {
                check() {
                    return Promise.resolve({ allowed: true });
                },
            },
            recorder: { record },
            checkpoint: {
                requestConfirmation() {
                    return Promise.resolve(false);
                },
            },
        });
        await allowedNoTokenIdEngine.executeWithPolicy({
            action: 'CONFIRM',
            params: {},
            agentDid:
                'did:agent:00112233445566778899aabbccddeeff00112233' as never,
            principalDid:
                'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK' as never,
            actorPrivateKey: '0'.repeat(128),
            requireHumanApproval: true,
            executor: () => Promise.resolve('ok'),
        });
        // In the checkpoint-denied path, the record call's authorizationRef.tokenId should be null
        const checkpointCall = record.mock.calls[1]?.[0];
        expect(checkpointCall?.authorizationRef).toEqual({ tokenId: null });

        // Branch 3: success path with tokenId undefined
        const allowedSuccessEngine = new PolicyEngine({
            guard: {
                check() {
                    return Promise.resolve({ allowed: true });
                },
            },
            recorder: { record },
        });
        await allowedSuccessEngine.executeWithPolicy({
            action: 'INQUIRY',
            params: {},
            agentDid:
                'did:agent:00112233445566778899aabbccddeeff00112233' as never,
            principalDid:
                'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK' as never,
            actorPrivateKey: '0'.repeat(128),
            executor: () => Promise.resolve('ok'),
        });
        const successCall = record.mock.calls[2]?.[0];
        expect(successCall?.authorizationRef).toEqual({ tokenId: null });

        // Branch 4: error path with tokenId undefined
        const allowedErrorEngine = new PolicyEngine({
            guard: {
                check() {
                    return Promise.resolve({ allowed: true });
                },
            },
            recorder: { record },
        });
        await expect(
            allowedErrorEngine.executeWithPolicy({
                action: 'INQUIRY',
                params: {},
                agentDid:
                    'did:agent:00112233445566778899aabbccddeeff00112233' as never,
                principalDid:
                    'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK' as never,
                actorPrivateKey: '0'.repeat(128),
                executor: () => {
                    throw new Error('boom');
                },
            }),
        ).rejects.toThrow('boom');
        const errorCall = record.mock.calls[3]?.[0];
        expect(errorCall?.authorizationRef).toEqual({ tokenId: null });
    });

    it('records ERROR as "unknown error" when executor throws non-Error value', async () => {
        // Covers the "unknown error" branch at engine.ts line 177: executor throws a non-Error type.
        const record = vi
            .fn<(_: ActionRecordInput) => Promise<RecordWriteResult>>()
            .mockResolvedValue({
                recordId: 'record-non-error-throw',
                hash: 'f'.repeat(64),
            });
        const engine = new PolicyEngine({
            guard: {
                check() {
                    return Promise.resolve({
                        allowed: true,
                        tokenId: 'urn:cap:x',
                    });
                },
            },
            recorder: { record },
        });

        await expect(
            engine.executeWithPolicy({
                action: 'INQUIRY',
                params: {},
                agentDid:
                    'did:agent:00112233445566778899aabbccddeeff00112233' as never,
                principalDid:
                    'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK' as never,
                actorPrivateKey: '0'.repeat(128),
                executor: () => {
                    // Throw a string instead of an Error (intentional, to cover the engine's
                    // internal "unknown error" fallback branch)
                    // eslint-disable-next-line @typescript-eslint/only-throw-error
                    throw 'string-panic';
                },
            }),
        ).rejects.toMatch('string-panic');

        expect(record).toHaveBeenCalledTimes(1);
        expect(record.mock.calls[0]?.[0].resultSummary).toEqual({
            status: 'ERROR',
            message: 'unknown error',
        });
    });

    it('propagates delegationDepth through executor-failure path', async () => {
        const record = vi
            .fn<(_: ActionRecordInput) => Promise<RecordWriteResult>>()
            .mockResolvedValue({
                recordId: 'record-executor-fail',
                hash: 'f'.repeat(64),
            });
        const engine = new PolicyEngine({
            guard: {
                check() {
                    return Promise.resolve({
                        allowed: true,
                        tokenId: 'urn:cap:delegated',
                        delegationDepth: 5,
                    });
                },
            },
            recorder: { record },
        });

        await expect(
            engine.executeWithPolicy({
                action: 'INQUIRY',
                params: {},
                agentDid:
                    'did:agent:00112233445566778899aabbccddeeff00112233' as never,
                principalDid:
                    'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK' as never,
                actorPrivateKey: '0'.repeat(128),
                executor: () => {
                    throw new Error('boom');
                },
            }),
        ).rejects.toThrow('boom');

        expect(record).toHaveBeenCalledTimes(1);
        expect(record.mock.calls[0]?.[0].delegationDepth).toBe(5);
    });

    it('propagates delegationDepth on denied path', async () => {
        const record = vi
            .fn<(_: ActionRecordInput) => Promise<RecordWriteResult>>()
            .mockResolvedValue({
                recordId: 'record-denied-depth',
                hash: 'f'.repeat(64),
            });
        const engine = new PolicyEngine({
            guard: {
                check() {
                    return Promise.resolve({
                        allowed: false,
                        reason: 'no matching capability',
                        delegationDepth: 3,
                    });
                },
            },
            recorder: { record },
        });

        await engine.executeWithPolicy({
            action: 'INQUIRY',
            params: {},
            agentDid:
                'did:agent:00112233445566778899aabbccddeeff00112233' as never,
            principalDid:
                'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK' as never,
            actorPrivateKey: '0'.repeat(128),
            executor: () => Promise.resolve('unreached'),
        });

        expect(record).toHaveBeenCalledTimes(1);
        expect(record.mock.calls[0]?.[0].delegationDepth).toBe(3);
    });

    it('throws when human approval is required but no checkpoint is configured', async () => {
        const engine = new PolicyEngine({
            guard: {
                check() {
                    return Promise.resolve({
                        allowed: true,
                        tokenId: 'urn:cap:3',
                    });
                },
            },
            recorder: {
                record() {
                    return Promise.resolve({
                        recordId: 'record-5',
                        hash: 'e'.repeat(64),
                    });
                },
            },
        });

        await expect(
            engine.executeWithPolicy({
                action: 'CONFIRM',
                params: { amount: 100 },
                agentDid:
                    'did:agent:00112233445566778899aabbccddeeff00112233' as never,
                principalDid:
                    'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK' as never,
                actorPrivateKey: '0'.repeat(128),
                requireHumanApproval: true,
                executor: () => Promise.resolve('ok'),
            }),
        ).rejects.toThrow(
            'PolicyCheckpoint is required when requireHumanApproval is true.',
        );
    });

    // ─── externally pre-allocated recordId passed through to recorder ───────────────
    it('passes externally-provided recordId into recorder.record on SUCCESS path (receiver-owned id propagation)', async () => {
        // Background: the sender cumulative reservation's recordId must match
        // this ActionRecord.id (idempotency-key contract), and the id is generated
        // locally by the recipient via randomUUID (blocking the sender-controlled
        // envelope.id bypass attack). The engine must pass the caller-provided
        // recordId through to the recorder.
        const record = vi
            .fn<(_: ActionRecordInput) => Promise<RecordWriteResult>>()
            .mockResolvedValue({
                recordId: 'external-record-id-001',
                hash: 'c'.repeat(64),
            });

        const engine = new PolicyEngine({
            guard: {
                check() {
                    return Promise.resolve({
                        allowed: true,
                        tokenId: 'urn:cap:1',
                    });
                },
            },
            recorder: { record },
        });

        await engine.executeWithPolicy({
            action: 'INQUIRY',
            params: {},
            agentDid:
                'did:agent:00112233445566778899aabbccddeeff00112233' as never,
            principalDid:
                'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK' as never,
            actorPrivateKey: '0'.repeat(128),
            recordId: 'external-record-id-001',
            executor: () => Promise.resolve('ok'),
        });

        expect(record).toHaveBeenCalledWith(
            expect.objectContaining({ recordId: 'external-record-id-001' }),
        );
    });

    // ─── onExecutorSuccess hook invoked after executor, before recorder ──
    it('invokes onExecutorSuccess after executor resolves, before recorder.record(SUCCESS) (commit-gate ordering)', async () => {
        // Attack surface: when the executor succeeds but the recorder fails, an upper
        // layer that decides "committed" solely from executeWithPolicy's return/throw
        // would misjudge "already-committed business" as not committed → cancel the
        // sender reservation → quota bypass. Fix: the hook is invoked between the two,
        // so the upper layer can detect executor success before the recorder writes.
        const callOrder: string[] = [];

        const record = vi
            .fn<(_: ActionRecordInput) => Promise<RecordWriteResult>>()
            .mockImplementation(() => {
                callOrder.push('recorder');
                return Promise.resolve({
                    recordId: 'record-hook-1',
                    hash: 'd'.repeat(64),
                });
            });

        const onExecutorSuccess = vi.fn(() => {
            callOrder.push('hook');
        });

        const engine = new PolicyEngine({
            guard: {
                check() {
                    return Promise.resolve({
                        allowed: true,
                        tokenId: 'urn:cap:1',
                    });
                },
            },
            recorder: { record },
        });

        await engine.executeWithPolicy({
            action: 'INQUIRY',
            params: {},
            agentDid:
                'did:agent:00112233445566778899aabbccddeeff00112233' as never,
            principalDid:
                'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK' as never,
            actorPrivateKey: '0'.repeat(128),
            executor: () => {
                callOrder.push('executor');
                return Promise.resolve('ok');
            },
            onExecutorSuccess,
        });

        // Assert ordering: executor → hook → recorder
        expect(callOrder).toEqual(['executor', 'hook', 'recorder']);
        expect(onExecutorSuccess).toHaveBeenCalledTimes(1);
    });

    it('invokes onExecutorSuccess even when recorder.record(SUCCESS) throws (recorder-fail does not regress committed gate)', async () => {
        // Core counter-proof: executor succeeds → hook already invoked → recorder throws
        // → executeWithPolicy throws, but the hook already ran before the throw, so the
        // committed flag the caller sets from it is not erased by the throw.
        const onExecutorSuccess = vi.fn();

        const record = vi
            .fn<(_: ActionRecordInput) => Promise<RecordWriteResult>>()
            // First call (SUCCESS) fails, second call (ERROR path) succeeds
            .mockRejectedValueOnce(new Error('db connection lost'))
            .mockResolvedValueOnce({
                recordId: 'record-error-1',
                hash: 'e'.repeat(64),
            });

        const engine = new PolicyEngine({
            guard: {
                check() {
                    return Promise.resolve({
                        allowed: true,
                        tokenId: 'urn:cap:1',
                    });
                },
            },
            recorder: { record },
        });

        await expect(
            engine.executeWithPolicy({
                action: 'INQUIRY',
                params: {},
                agentDid:
                    'did:agent:00112233445566778899aabbccddeeff00112233' as never,
                principalDid:
                    'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK' as never,
                actorPrivateKey: '0'.repeat(128),
                executor: () => Promise.resolve('ok'),
                onExecutorSuccess,
            }),
        ).rejects.toThrow('db connection lost');

        // Key point: the recorder threw but the hook was already invoked — the caller's committed gate is reliable
        expect(onExecutorSuccess).toHaveBeenCalledTimes(1);
    });

    // ---------------------------------------------------------------------------
    // SESSION_SUPERSEDED cross-package integration
    // Verify that @coivitas/types ACTION_VOCABULARY is correctly visible across
    // packages at the policy layer (L3), and that the SESSION_SUPERSEDED control-plane
    // action can propagate through guard→recorder.
    // ---------------------------------------------------------------------------

    it('SESSION_SUPERSEDED is present in ACTION_VOCABULARY (cross-package import from @coivitas/types)', () => {
        // Core: ACTION_VOCABULARY imported cross-package from @coivitas/types is usable,
        // and the SESSION_SUPERSEDED value is in it (a v0.3.0 control-plane action).
        expect(
            (ACTION_VOCABULARY as readonly string[]).includes(
                ACTION_SESSION_SUPERSEDED,
            ),
        ).toBe(true);
    });

    it('SESSION_GOVERNOR_DID constant is correct from @coivitas/types', () => {
        // The control-plane actor DID constant is correct across packages.
        expect(SESSION_GOVERNOR_DID).toBe('did:system:session-governor');
    });

    it('propagates SESSION_SUPERSEDED action through guard→recorder (cross-package ActionVocabulary integration)', async () => {
        // The SESSION_SUPERSEDED control-plane ActionRecord propagates along the full path from guard to recorder:
        // - the action field is written to the recorder verbatim (not intercepted by the policy engine layer)
        // - agentDid uses SESSION_GOVERNOR_DID (the only legitimate control-plane actor)
        // - delegationDepth is returned by the guard and propagated (the control plane takes no business delegation chain, depth=0)
        const record = vi
            .fn<(_: ActionRecordInput) => Promise<RecordWriteResult>>()
            .mockResolvedValue({
                recordId: 'record-session-superseded',
                hash: 'c'.repeat(64),
            });

        const engine = new PolicyEngine({
            guard: {
                check() {
                    return Promise.resolve({
                        allowed: true,
                        tokenId: 'urn:cap:control-plane',
                        delegationDepth: 0,
                    });
                },
            },
            recorder: { record },
        });

        await engine.executeWithPolicy({
            action: ACTION_SESSION_SUPERSEDED,
            params: {
                oldSessionId: 'sess-old-001',
                newSessionId: 'sess-new-002',
                reason: 'EXPLICIT_CLOSE',
            },
            agentDid: SESSION_GOVERNOR_DID as never,
            principalDid: SESSION_GOVERNOR_DID as never,
            actorPrivateKey: '0'.repeat(128),
            executor: () => Promise.resolve({ superseded: true }),
        });

        expect(record).toHaveBeenCalledTimes(1);
        const call = record.mock.calls[0]?.[0];
        // The actionType field propagates correctly (the ActionRecordInput field is named actionType)
        expect(call?.actionType).toBe('SESSION_SUPERSEDED');
        // delegationDepth=0 — the control plane has no delegation chain
        expect(call?.delegationDepth).toBe(0);
    });
});
