/**
 * SessionSupersedeRecorder — writer for SESSION_SUPERSEDED control-plane events.
 *
 * Responsibilities:
 *   1. Write close / supersede / markAuthorized control-plane events to policy.action_records,
 *      signed with SESSION_GOVERNOR_DID as the agentDid.
 *   2. Maintain simple module-level counters (session_supersede_total / session_close_total).
 *   3. Do not touch the ActionRecorder / IntegrityChecker constructors.
 *   4. Do not establish governor lane routing for now.
 *
 * Design decisions:
 *   - Inject an existing ActionRecorder instance via the constructor; do not new a new instance.
 *   - SESSION_GOVERNOR_DID cannot obtain a public key via federated DID resolution; the caller injects
 *     governorPrivateKey (the deployment layer passes it in via the GOVERNOR_PRIVATE_KEY env).
 *   - actionType is fixed to ACTION_SESSION_SUPERSEDED ('SESSION_SUPERSEDED').
 *   - agentDid === principalDid === SESSION_GOVERNOR_DID (in sync with the schema constraint).
 *   - reason is a schema field, not an error code.
 *   - (the sole control-plane chain-entry path)
 */

import {
    ACTION_SESSION_SUPERSEDED,
    SESSION_GOVERNOR_DID,
    type DID,
    type SessionSupersededParams,
} from '@coivitas/types';

import type { RecordWriteResult } from '../types.js';
import type {
    ActionRecorder,
    ControlPlaneActionRecorder,
} from './action-recorder.js';

// ---------------------------------------------------------------------------
// Simple module-level counters (no external telemetry package introduced for now)
// ---------------------------------------------------------------------------

/** Count of successful SESSION_SUPERSEDED event writes (across all reasons). */
let sessionSupersedeTotal = 0;

/** Count of SESSION_SUPERSEDED with reason=EXPLICIT_CLOSE or FORCED_CLOSE (session close count). */
let sessionCloseTotal = 0;

/** Read the cumulative SESSION_SUPERSEDED write count (for tests & monitoring probes). */
export function getSessionSupersedeTotal(): number {
    return sessionSupersedeTotal;
}

/** Read the cumulative session close count (for tests & monitoring probes). */
export function getSessionCloseTotal(): number {
    return sessionCloseTotal;
}

/** Reset the counters (for unit tests only; production code must not call this). */
export function _resetMetricsForTest(): void {
    sessionSupersedeTotal = 0;
    sessionCloseTotal = 0;
}

// ---------------------------------------------------------------------------
// Type: recordSupersede input
// ---------------------------------------------------------------------------

/**
 * SessionSupersedeRecordInput — recordSupersede() input.
 *
 * sessionId (optional): associated with the ActionRecord.session_id column; usually the old session ID is passed,
 * used to later filter the full-lifecycle audit chain of that session by session_id.
 *
 * affectedAgentDid / affectedPrincipalDid in params are required
 * (aligned with required[] in schemas.ts; governor lane subject-scoped
 * audit depends strongly on them).
 *
 * Note: write-path enforcement is in place.
 *   Both the reverse session-binding validation and write-path enforcement live in
 *   the ActionRecorder.record() kind='control-plane' branch.
 *   Any control-plane INSERT (including paths that bypass SessionSupersedeRecorder and call record()
 *   directly) must pass through the assertSessionBinding + assertSchemaCompliant guards.
 *   On mismatch it throws ProtocolError('INTERNAL_ERROR') fail-closed.
 */
export interface SessionSupersedeRecordInput {
    params: SessionSupersededParams;
    /** Associated session ID (usually params.oldSessionId) written to ActionRecord.session_id */
    sessionId?: string;
}

/**
 * SessionSupersedeAffectedSubject — the affected subject (business agent + principal)
 * required by the convenience methods (recordClose / recordMarkAuthorized).
 *
 * Explicitly injected by the caller; governor lane subject-scoped audit must be able to row-scope on this.
 */
export interface SessionSupersedeAffectedSubject {
    affectedAgentDid: DID;
    affectedPrincipalDid: DID;
}

// ---------------------------------------------------------------------------
// SessionSupersedeRecorder class
// ---------------------------------------------------------------------------

export class SessionSupersedeRecorder {
    /**
     * @param actionRecorder an already-constructed control-plane ActionRecorder instance (injected; not newly created).
     * Lane hard constraint: the constructor signature requires
     *   `ControlPlaneActionRecorder` (=`ActionRecorder & { kind: 'control-plane' }`);
     *   dual defense at compile time + runtime. The caller should first use `assertIsControlPlaneRecorder()`
     *   to narrow `ActionRecorder` to this type before injecting.
     *   Defense rationale: the control-plane chain-entry path may only be written by a control-plane recorder.
     * @param governorPrivateKey control-plane signing private key (hex format; injected via env)
     */
    public constructor(
        private readonly actionRecorder: ControlPlaneActionRecorder,
        private readonly governorPrivateKey: string,
    ) {
        if (governorPrivateKey.length === 0) {
            throw new Error(
                'SessionSupersedeRecorder: governorPrivateKey is required',
            );
        }
        // The runtime check is kept as a fallback (defending against a caller bypassing the type with an unsafe cast).
        if (actionRecorder.kind !== 'control-plane') {
            throw new Error(
                `SessionSupersedeRecorder: actionRecorder must be kind='control-plane' ` +
                    `(got kind='${(actionRecorder as ActionRecorder).kind}'). ` +
                    `The control-plane chain-entry path may only be held by a control-plane ActionRecorder ` +
                    `(audit chain integrity contract).`,
            );
        }
    }

    /**
     * recordSupersede — write a single SESSION_SUPERSEDED event to action_records.
     *
     * Applies to all 4 reasons (EXPLICIT_CLOSE / TOKEN_REVOKED / IDLE_EXPIRED / FORCED_CLOSE).
     * - reason=EXPLICIT_CLOSE / FORCED_CLOSE additionally increments session_close_total.
     *
     * @param input event input (params + optional sessionId)
     * @returns the write result (recordId + hash)
     */
    public async recordSupersede(
        input: SessionSupersedeRecordInput,
    ): Promise<RecordWriteResult> {
        const { params, sessionId } = input;

        const result = await this.actionRecorder.record({
            agentDid: SESSION_GOVERNOR_DID as DID,
            principalDid: SESSION_GOVERNOR_DID as DID,
            actionType: ACTION_SESSION_SUPERSEDED,
            parametersSummary: {
                oldSessionId: params.oldSessionId,
                newSessionId: params.newSessionId,
                reason: params.reason,
                timestamp: params.timestamp,
                // governor lane subject-scoped audit must be able to observe
                // affectedAgentDid / affectedPrincipalDid (the schema already makes them required).
                affectedAgentDid: params.affectedAgentDid,
                affectedPrincipalDid: params.affectedPrincipalDid,
            },
            actorPrivateKey: this.governorPrivateKey,
            sessionId: sessionId ?? params.oldSessionId,
        });

        // Increment the counters
        sessionSupersedeTotal++;
        if (
            params.reason === 'EXPLICIT_CLOSE' ||
            params.reason === 'FORCED_CLOSE'
        ) {
            sessionCloseTotal++;
        }

        return result;
    }

    /**
     * recordClose — convenience method: a SESSION_SUPERSEDED event with FORCED_CLOSE semantics.
     *
     * newSessionId is null (an active close with no successor session). The schema only allows FORCED_CLOSE
     * with a null newSessionId (all other reasons must have a non-null successor); FORCED_CLOSE is used uniformly
     * here to avoid the EXPLICIT_CLOSE + null combination violating the schema's hard constraint.
     *
     * @param oldSessionId the session ID being closed
     * @param timestamp event timestamp (ISO 8601)
     * @param affected the business agent + principal DID affected by this close (required by governor lane
     *   subject-scoped audit)
     */
    public async recordClose(
        oldSessionId: string,
        timestamp: string,
        affected: SessionSupersedeAffectedSubject,
    ): Promise<RecordWriteResult> {
        return this.recordSupersede({
            params: {
                oldSessionId,
                newSessionId: null,
                reason: 'FORCED_CLOSE',
                timestamp:
                    timestamp as import('@coivitas/types').Timestamp,
                affectedAgentDid: affected.affectedAgentDid,
                affectedPrincipalDid: affected.affectedPrincipalDid,
            },
            sessionId: oldSessionId,
        });
    }

    /**
     * recordMarkAuthorized — write a SESSION_SUPERSEDED event marking a successful session re-authorization.
     *
     * Uses the TOKEN_REVOKED reason (the old token is revoked, a new token is issued, completing a fresh handshake).
     * newSessionId points to the successor session.
     *
     * @param oldSessionId the old session ID being superseded
     * @param newSessionId the successor session ID
     * @param timestamp event timestamp (ISO 8601)
     * @param affected the business agent + principal DID affected by this session supersession (required)
     */
    public async recordMarkAuthorized(
        oldSessionId: string,
        newSessionId: string,
        timestamp: string,
        affected: SessionSupersedeAffectedSubject,
    ): Promise<RecordWriteResult> {
        return this.recordSupersede({
            params: {
                oldSessionId,
                newSessionId,
                reason: 'TOKEN_REVOKED',
                timestamp:
                    timestamp as import('@coivitas/types').Timestamp,
                affectedAgentDid: affected.affectedAgentDid,
                affectedPrincipalDid: affected.affectedPrincipalDid,
            },
            sessionId: oldSessionId,
        });
    }
}
