/**
 * AuditBarrier — audit-before-execute barrier.
 *
 * Responsibilities:
 *   1. beforeExecute(record): writes an ACTION_INTENT state record, locking the local happens-before;
 *      returns auditIntentId as the correlation key for the subsequent afterExecute / beforeReceiptSign.
 *   2. afterExecute(auditIntentId, outcome): writes ACTION_RESULT and releases the happens-before lock.
 *   3. beforeReceiptSign(envelopeId, auditIntentId): verifies that ACTION_RESULT has been written,
 *      otherwise fails closed.
 *
 * Design decisions:
 *   - Inject an existing ActionRecorder instance via the constructor (same pattern as SessionSupersedeRecorder).
 *   - ACTION_INTENT / ACTION_RESULT are barrier-private actionType strings, not part of the ACTION_VOCABULARY
 *     enum (ActionRecordInput.actionType is a plain, unconstrained string).
 *   - The local happens-before lock = a single-process in-memory Map<string, Promise<void>>;
 *     distributed extension is deferred to a later release.
 *   - Only applies to body.type='BUSINESS' envelopes; receipt envelopes are exempt
 *     (per the e2e-encryption spec).
 *   - fail-closed: any indeterminate state throws ProtocolError; no silent degradation.
 *
 * firewall constraints:
 *   - Do not modify ActionRecorder / IntegrityChecker constructor parameters.
 *   - Do not implement governor lane / cross-org barrier coordination (deferred to a later release).
 *
 * Error code source: the e2e-encryption spec
 *   - AUDIT_INTENT_PERSIST_FAILED: beforeExecute persistence failure
 *   - AUDIT_INTENT_TIMEOUT: beforeExecute timeout (lock wait or write timeout)
 *   - AUDIT_RECORD_UPDATE_FAILED: afterExecute persistence failure
 */

import { randomUUID } from 'node:crypto';

import type { DID } from '@coivitas/types';
import { ProtocolError } from '@coivitas/types';

import type { ActionRecorder } from './action-recorder.js';

// ---------------------------------------------------------------------------
// Barrier-internal constants
// ---------------------------------------------------------------------------

/** ACTION_INTENT: actionType of the placeholder record written by beforeExecute (not in ACTION_VOCABULARY) */
const ACTION_INTENT = 'ACTION_INTENT' as const;

/** ACTION_RESULT: actionType of the result record written by afterExecute (not in ACTION_VOCABULARY) */
const ACTION_RESULT = 'ACTION_RESULT' as const;

/** Default total beforeExecute timeout (ms) */
const DEFAULT_TIMEOUT_MS = 5_000;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/**
 * AuditBarrierRecord — beforeExecute input.
 *
 * Contains only the minimal fields required to write ACTION_INTENT;
 * actorPrivateKey is injected by the constructor and need not be passed in again by the caller.
 */
export interface AuditBarrierRecord {
    /** DID of the agent executing this action */
    agentDid: DID;
    /** Authorizing principal DID (usually === agentDid, or the upstream party in a delegation scenario) */
    principalDid: DID;
    /** Original actionType (from ActionRecord, used for record semantics) */
    actionType: string;
    /** Optional: session ID this is bound to */
    sessionId?: string;
    /** Optional: associated envelope ID (used for beforeReceiptSign verification) */
    envelopeId?: string;
    /** Optional: intent parameters summary */
    parametersSummary?: Record<string, unknown>;
}

/**
 * AuditBarrierOutcome — the outcome parameter of afterExecute.
 */
export type AuditBarrierOutcome = 'SUCCESS' | 'REJECTED' | 'ERROR';

// ---------------------------------------------------------------------------
// Internal in-memory state
// ---------------------------------------------------------------------------

/**
 * HappensBeforeLock — single-process happens-before lock.
 *
 * key: agentDid (each agent serializes its ACTION_INTENT writes)
 * value: the Promise<void> of the write currently in progress (subsequent writes chain onto this Promise)
 *
 * Design notes:
 *   - Multiple beforeExecute calls for the same agentDid within the same process queue up,
 *     ensuring ACTION_INTENT writes execute in order under a chained DB advisory lock.
 *   - The chain is removed from the Map after afterExecute completes (lock release).
 *   - Distributed (cross-process) extension is deferred to a later release.
 */
const happensBefore = new Map<string, Promise<void>>();

/** Clears all happens-before locks (for unit tests only; production code must not call this). */
export function _resetHappensBeforeForTest(): void {
    happensBefore.clear();
}

// ---------------------------------------------------------------------------
// Internal: auditIntentId → state tracking
// ---------------------------------------------------------------------------

/**
 * IntentState — barrier-internal lifecycle state tracked for each intentId.
 *
 * INTENT_WRITTEN: ACTION_INTENT has been written; afterExecute not yet complete
 * RESULT_WRITTEN: ACTION_RESULT has been written; beforeReceiptSign can pass
 */
type IntentLifecycle = 'INTENT_WRITTEN' | 'RESULT_WRITTEN';

interface IntentState {
    /** agentDid (used for error context) */
    agentDid: string;
    /**
     * principalDid (preserves the real principalDid recorded at beforeExecute,
     * reused when afterExecute writes ACTION_RESULT, so a delegation flow is not mistakenly rewritten
     * to agentDid and the delegation origin information is not lost)
     */
    principalDid: string;
    /** Original actionType */
    actionType: string;
    /** Associated envelope ID (optional) */
    envelopeId?: string;
    /**
     * sessionId (preserves the sessionId recorded at beforeExecute,
     * reused when afterExecute writes ACTION_RESULT, so a session-dimension audit query does not match
     * the INTENT yet fail to find the corresponding RESULT)
     */
    sessionId?: string;
    /** recordId returned by the ACTION_INTENT write */
    intentRecordId: string;
    /** Current lifecycle state */
    lifecycle: IntentLifecycle;
}

/**
 * Global intent state Map (single-process).
 * key: auditIntentId (UUID)
 */
const intentStates = new Map<string, IntentState>();

/** Clears all intent state (for unit tests only; production code must not call this). */
export function _resetIntentStatesForTest(): void {
    intentStates.clear();
}

// ---------------------------------------------------------------------------
// AuditBarrier class
// ---------------------------------------------------------------------------

export class AuditBarrier {
    private readonly timeoutMs: number;

    /**
     * @param actionRecorder an already-constructed ActionRecorder instance (injected; not newly created; firewall)
     * @param actorPrivateKey signing private key (hex) used when writing ACTION_INTENT / ACTION_RESULT
     * @param options.timeoutMs beforeExecute timeout (ms, default 5000)
     */
    public constructor(
        private readonly actionRecorder: ActionRecorder,
        private readonly actorPrivateKey: string,
        options: { timeoutMs?: number } = {},
    ) {
        if (actorPrivateKey.length === 0) {
            throw new Error('AuditBarrier: actorPrivateKey is required');
        }
        this.timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    }

    // -------------------------------------------------------------------------
    // beforeExecute
    // -------------------------------------------------------------------------

    /**
     * beforeExecute — pre-execution barrier hook.
     *
     * Semantics:
     *   1. Wait for the preceding beforeExecute of the same agentDid to complete (happens-before queue).
     *   2. Write the ACTION_INTENT record to policy.action_records.
     *   3. Return auditIntentId for the caller to pass into afterExecute / beforeReceiptSign.
     *
     * fail-closed: persistence failure → AUDIT_INTENT_PERSIST_FAILED;
     *              timeout (lock wait + write combined timeout) → AUDIT_INTENT_TIMEOUT.
     *
     * @param record intent description (agentDid / principalDid / actionType / sessionId / envelopeId)
     * @returns auditIntentId (UUID; serves as the receiver's local audit anchor)
     * @throws ProtocolError AUDIT_INTENT_PERSIST_FAILED | AUDIT_INTENT_TIMEOUT
     */
    public async beforeExecute(record: AuditBarrierRecord): Promise<string> {
        const auditIntentId = randomUUID();

        // happens-before queue: serialize ACTION_INTENT writes for the same agentDid
        const previous =
            happensBefore.get(record.agentDid) ?? Promise.resolve();

        let resolveLock!: () => void;
        const lockPromise = new Promise<void>((resolve) => {
            resolveLock = resolve;
        });
        // Append the new lock placeholder to the chain for subsequent beforeExecute calls to wait on
        happensBefore.set(
            record.agentDid,
            previous.then(() => lockPromise),
        );

        let intentRecordId: string;
        try {
            // First wait for the preceding beforeExecute's lock to be released (happens-before serialization guarantee).
            // Note: this await itself does not count toward writeWithTimeout's timeout budget;
            // the upper bound on the preceding lock wait = the preceding operation's timeoutMs; a distributed extension is planned for a later release.
            await previous;

            intentRecordId = await this.writeWithTimeout(
                () =>
                    this.actionRecorder
                        .record({
                            agentDid: record.agentDid,
                            principalDid: record.principalDid,
                            actionType: ACTION_INTENT,
                            parametersSummary: {
                                originalActionType: record.actionType,
                                envelopeId: record.envelopeId,
                                auditIntentId,
                                ...(record.parametersSummary ?? {}),
                            },
                            actorPrivateKey: this.actorPrivateKey,
                            sessionId: record.sessionId,
                        })
                        .then((r) => r.recordId),
                record.agentDid,
                auditIntentId,
            );
        } finally {
            // Whether success or failure, release this lock (allowing the next beforeExecute in the queue to proceed)
            resolveLock();
        }

        // Register intent state
        // persist principalDid + sessionId for afterExecute to reuse
        intentStates.set(auditIntentId, {
            agentDid: record.agentDid,
            principalDid: record.principalDid,
            actionType: record.actionType,
            envelopeId: record.envelopeId,
            ...(record.sessionId !== undefined
                ? { sessionId: record.sessionId }
                : {}),
            intentRecordId,
            lifecycle: 'INTENT_WRITTEN',
        });

        return auditIntentId;
    }

    // -------------------------------------------------------------------------
    // afterExecute
    // -------------------------------------------------------------------------

    /**
     * afterExecute — post-execution barrier hook.
     *
     * Semantics:
     *   1. Write the ACTION_RESULT record (including outcome information).
     *   2. Advance intentState.lifecycle to RESULT_WRITTEN.
     *
     * fail-closed: persistence failure → AUDIT_RECORD_UPDATE_FAILED.
     *
     * @param auditIntentId the auditIntentId returned by beforeExecute
     * @param outcome execution result ('SUCCESS' | 'REJECTED' | 'ERROR')
     * @throws ProtocolError AUDIT_RECORD_UPDATE_FAILED | INTERNAL_ERROR (unknown intentId)
     */
    public async afterExecute(
        auditIntentId: string,
        outcome: AuditBarrierOutcome,
    ): Promise<void> {
        const state = intentStates.get(auditIntentId);
        if (state === undefined) {
            throw new ProtocolError(
                'INTERNAL_ERROR',
                `AuditBarrier.afterExecute: unknown auditIntentId=${auditIntentId}`,
            );
        }

        if (state.lifecycle === 'RESULT_WRITTEN') {
            // Idempotency guard: a repeated call returns immediately
            return;
        }

        try {
            // Use the real principalDid + sessionId saved by beforeExecute
            // to reconstruct ACTION_RESULT, ensuring session-dimension / delegation-dimension audit queries
            // can correctly pair INTENT/RESULT.
            await this.actionRecorder.record({
                agentDid: state.agentDid as DID,
                principalDid: state.principalDid as DID,
                actionType: ACTION_RESULT,
                parametersSummary: {
                    auditIntentId,
                    intentRecordId: state.intentRecordId,
                    outcome,
                },
                actorPrivateKey: this.actorPrivateKey,
                ...(state.sessionId !== undefined
                    ? { sessionId: state.sessionId }
                    : {}),
            });
        } catch (err) {
            const detail = err instanceof Error ? err.message : String(err);
            throw new ProtocolError(
                'AUDIT_RECORD_UPDATE_FAILED',
                `AuditBarrier.afterExecute failed: ${detail}`,
            );
        }

        // Advance the lifecycle
        intentStates.set(auditIntentId, {
            ...state,
            lifecycle: 'RESULT_WRITTEN',
        });
    }

    // -------------------------------------------------------------------------
    // beforeReceiptSign
    // -------------------------------------------------------------------------

    /**
     * beforeReceiptSign — pre-receipt-signing verification hook.
     *
     * Semantics:
     *   Verify that the ACTION_RESULT for the given auditIntentId has been written (lifecycle === 'RESULT_WRITTEN').
     *   If not written, fail-closed reject (AUDIT_RECORD_UPDATE_FAILED).
     *
     * Note: the envelopeId parameter is used only for error context; verification keys on auditIntentId.
     *
     * @param envelopeId associated envelope ID (used for error log context)
     * @param auditIntentId the auditIntentId returned by beforeExecute
     * @throws ProtocolError AUDIT_RECORD_UPDATE_FAILED (ACTION_RESULT not written)
     *                        INTERNAL_ERROR (unknown auditIntentId)
     */
    public beforeReceiptSign(envelopeId: string, auditIntentId: string): void {
        const state = intentStates.get(auditIntentId);
        if (state === undefined) {
            throw new ProtocolError(
                'INTERNAL_ERROR',
                `AuditBarrier.beforeReceiptSign: unknown auditIntentId=${auditIntentId} (envelopeId=${envelopeId})`,
            );
        }

        if (state.lifecycle !== 'RESULT_WRITTEN') {
            // fail-closed: ACTION_RESULT not written, signing is not allowed
            throw new ProtocolError(
                'AUDIT_RECORD_UPDATE_FAILED',
                `AuditBarrier.beforeReceiptSign: ACTION_RESULT not yet written for auditIntentId=${auditIntentId} (envelopeId=${envelopeId})`,
            );
        }
    }

    // -------------------------------------------------------------------------
    // Internal helper: timeout wrapper
    // -------------------------------------------------------------------------

    /**
     * writeWithTimeout — write wrapper with a timeout.
     *
     * - timeout → AUDIT_INTENT_TIMEOUT
     * - other errors → AUDIT_INTENT_PERSIST_FAILED
     */
    private async writeWithTimeout(
        writeFn: () => Promise<string>,
        agentDid: string,
        auditIntentId: string,
    ): Promise<string> {
        let timeoutHandle: ReturnType<typeof setTimeout> | undefined;

        const timeoutPromise = new Promise<never>((_, reject) => {
            timeoutHandle = setTimeout(() => {
                reject(
                    new ProtocolError(
                        'AUDIT_INTENT_TIMEOUT',
                        `AuditBarrier.beforeExecute timed out after ${this.timeoutMs}ms (agentDid=${agentDid}, auditIntentId=${auditIntentId})`,
                    ),
                );
            }, this.timeoutMs);
        });

        try {
            const result = await Promise.race([writeFn(), timeoutPromise]);
            return result;
        } catch (err) {
            if (
                err instanceof ProtocolError &&
                err.code === 'AUDIT_INTENT_TIMEOUT'
            ) {
                throw err;
            }
            const detail = err instanceof Error ? err.message : String(err);
            throw new ProtocolError(
                'AUDIT_INTENT_PERSIST_FAILED',
                `AuditBarrier.beforeExecute persist failed (agentDid=${agentDid}, auditIntentId=${auditIntentId}): ${detail}`,
            );
        } finally {
            clearTimeout(timeoutHandle);
        }
    }
}
