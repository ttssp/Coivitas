import { ProtocolError, type DID } from '@coivitas/types';

import type { ActionRecordInput, RecordWriteResult } from './types.js';

export interface PolicyGuard {
    check(
        action: string,
        params: Record<string, unknown>,
        agentDid: DID,
        /**
         * Optional: authorization loop closure — only allow using the Token with this tokenId.
         * The caller should pass it via envelope.header.capabilityTokenRef in the L5 Orchestrator;
         * when not provided, the original behavior is retained.
         */
        requestedTokenId?: string,
    ): Promise<{
        allowed: boolean;
        reason?: string;
        tokenId?: string;
        /**
         * Delegation-chain depth (per the delegation-chain spec).
         * Used by the ActionRecorder when writing ActionRecord.delegationDepth for audit traceability.
         * 0 = no delegation chain (authorized directly by the principal); >0 = delegation depth.
         */
        delegationDepth?: number;
    }>;
}

export interface PolicyRecorder {
    record(input: ActionRecordInput): Promise<RecordWriteResult>;
}

export interface PolicyCheckpoint {
    requestConfirmation(context: {
        action: string;
        agentDid: DID;
        params: Record<string, unknown>;
    }): Promise<boolean>;
}

export interface ExecuteWithPolicyParams<T> {
    action: string;
    params: Record<string, unknown>;
    agentDid: DID;
    principalDid: DID;
    actorPrivateKey: string;
    executor: () => Promise<T>;
    requireHumanApproval?: boolean;
    /**
     * Optional: restrict the authorization decision to using only this tokenId.
     *
     * **Correct use case**: when the caller shares the same agent context as the RuntimeGuard
     * (agentDid matches the Token's issuedTo), it can be used to precisely select this agent's own
     * Token for authorization, avoiding a scan of the entire Token pool. Typical scenario: the agent
     * holds multiple Tokens internally but only one of them should be used.
     *
     * **⚠️ Do not use across contexts**: the L5 Orchestrator's `envelope.header.capabilityTokenRef`
     * points to the **sender**'s Token, which does not exist in the **recipient**'s TokenStore;
     * using the sender tokenId as the recipient-side requestedTokenId would cause the Token to never be found.
     * The recipient side should perform policy authorization independently against this agent's own Token pool.
     */
    requestedTokenId?: string;

    /**
     * Externally pre-allocated ActionRecord id (a recipient-side generated UUID).
     *
     * When the caller (Orchestrator) needs to bind the "recordId of the sender-side cumulative
     * reservation" together with "this ActionRecord.id" (the spec idempotency-key contract),
     * it pre-generates an id via randomUUID() before step3.5, used for:
     *   - tracker.checkAndReserve(recordId, ...) as the reservation idempotency key;
     *   - writing ActionRecord.id on both the success/failure path of this executeWithPolicy;
     *
     * When not provided, the original behavior is retained (recorder-internal `input.recordId ?? randomUUID()`).
     *
     * **Must not** use a sender-controlled value (such as envelope.id) — attack surface:
     * if the sender can choose the recordId, resending an envelope with the same id but different params
     * would hit the tracker idempotency semantics and not deduct quota again → quota bypass. The
     * recipient must generate the randomUUID locally.
     */
    recordId?: string;

    /**
     * Hook invoked after executor returns successfully but before recorder.record(SUCCESS).
     *
     * Invocation order (success path):
     *   try {
     *       result = await executor();
     *       await onExecutorSuccess?.(); // ← business side effects are committed; advance the committed marker
     *       record = await recorder.record({ ..., SUCCESS });
     *   } catch (error) {
     *       recorder.record({ ..., ERROR });
     *       throw error;
     *   }
     *
     * Attack surface (quota bypass): the committed marker was originally placed "after executeWithPolicy
     * returns success", but if recorder.record(SUCCESS) throws due to a DB fault, executeWithPolicy
     * throws rather than returns → committed remains false → the outer catch would cancel the sender
     * reservation for business that was already committed successfully (the executor already transferred
     * funds, yet the reservation is released). Advancing committed to after the executor succeeds but
     * before the recorder write ensures that on the "executor success + recorder failure" path the
     * reservation is not cancelled by mistake.
     *
     * A throw from the hook is not specially handled — it is treated as a post-executor side-effect
     * failure and goes down the catch branch to record ERROR. But in normal use the hook only performs
     * pure in-memory operations such as "set committed = true".
     */
    onExecutorSuccess?: () => void | Promise<void>;
}

export type ExecuteWithPolicyResult<T> =
    | { executed: true; result: T; recordId: string }
    | { executed: false; reason: string; recordId: string };

export class PolicyEngine {
    public constructor(
        private readonly dependencies: {
            guard: PolicyGuard;
            recorder: PolicyRecorder;
            checkpoint?: PolicyCheckpoint;
        },
    ) {}

    public async executeWithPolicy<T>(
        params: ExecuteWithPolicyParams<T>,
    ): Promise<ExecuteWithPolicyResult<T>> {
        const guardResult = await this.dependencies.guard.check(
            params.action,
            params.params,
            params.agentDid,
            params.requestedTokenId,
        );

        if (!guardResult.allowed) {
            const record = await this.dependencies.recorder.record({
                recordId: params.recordId,
                agentDid: params.agentDid,
                principalDid: params.principalDid,
                actionType: params.action,
                parametersSummary: params.params,
                authorizationRef: null,
                resultSummary: {
                    status: 'REJECTED',
                    reason: guardResult.reason,
                },
                actorPrivateKey: params.actorPrivateKey,
                delegationDepth: guardResult.delegationDepth,
            });

            return {
                executed: false,
                reason: guardResult.reason ?? 'action rejected',
                recordId: record.recordId,
            };
        }

        if (params.requireHumanApproval) {
            if (!this.dependencies.checkpoint) {
                throw new ProtocolError(
                    'INTERNAL_ERROR',
                    'PolicyCheckpoint is required when requireHumanApproval is true.',
                );
            }

            const approved =
                await this.dependencies.checkpoint.requestConfirmation({
                    action: params.action,
                    agentDid: params.agentDid,
                    params: params.params,
                });

            if (!approved) {
                const record = await this.dependencies.recorder.record({
                    recordId: params.recordId,
                    agentDid: params.agentDid,
                    principalDid: params.principalDid,
                    actionType: params.action,
                    parametersSummary: params.params,
                    authorizationRef: { tokenId: guardResult.tokenId ?? null },
                    resultSummary: {
                        status: 'REJECTED',
                        reason: 'human approval denied',
                    },
                    actorPrivateKey: params.actorPrivateKey,
                    delegationDepth: guardResult.delegationDepth,
                });

                return {
                    executed: false,
                    reason: 'human approval denied',
                    recordId: record.recordId,
                };
            }
        }

        try {
            const result = await params.executor();
            // Notify the caller after the executor succeeds but before recorder.record(SUCCESS) is written.
            // The Orchestrator uses it to advance the "reservation lifecycle" committed marker to the
            // point when "business side effects are committed" — so even if the recorder then fails and
            // throws, the reservation is not cancelled by mistake in the outer catch (a quota-bypass defense).
            if (params.onExecutorSuccess) {
                await params.onExecutorSuccess();
            }
            const record = await this.dependencies.recorder.record({
                recordId: params.recordId,
                agentDid: params.agentDid,
                principalDid: params.principalDid,
                actionType: params.action,
                parametersSummary: params.params,
                authorizationRef: { tokenId: guardResult.tokenId ?? null },
                resultSummary: { status: 'SUCCESS' },
                actorPrivateKey: params.actorPrivateKey,
                delegationDepth: guardResult.delegationDepth,
            });

            return {
                executed: true,
                result,
                recordId: record.recordId,
            };
        } catch (error) {
            await this.dependencies.recorder.record({
                recordId: params.recordId,
                agentDid: params.agentDid,
                principalDid: params.principalDid,
                actionType: params.action,
                parametersSummary: params.params,
                authorizationRef: { tokenId: guardResult.tokenId ?? null },
                resultSummary: {
                    status: 'ERROR',
                    message:
                        error instanceof Error
                            ? error.message
                            : 'unknown error',
                },
                actorPrivateKey: params.actorPrivateKey,
                delegationDepth: guardResult.delegationDepth,
            });

            throw error;
        }
    }
}
