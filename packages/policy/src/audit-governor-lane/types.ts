/**
 * audit-governor-lane/types.ts -- complete governor lane protocol type definitions.
 *
 * 5 namespace error code classes + interface definitions.
 * Design note: the 5 namespace classes are formally adopted, preferring to reuse existing
 * error codes rather than adding new ones.
 *
 */

import type { DID, Timestamp } from '@coivitas/types';
import type { ControlPlaneActionRecorder } from '../recorder/action-recorder.js';

// ---------------------------------------------------------------------------
// 1. ARBITRATION_* operator arbitration flow error codes
// ---------------------------------------------------------------------------

/**
 * Operator arbitration flow error codes.
 *
 * Triggered when the governor's automated decision cannot determine the legitimacy of a session supersede.
 * Both are HTTP 500 (inconsistent server-side internal state, the caller cannot self-recover).
 */
export type ArbitrationErrorCode =
    | 'ARBITRATION_HALF_COMMITTED'
    | 'ARBITRATION_CHAIN_MALFORMED';

// ---------------------------------------------------------------------------
// 2. SIDE_TABLE_* shadow audit side table error codes
// ---------------------------------------------------------------------------

/**
 * Shadow audit side table tamper-evidence error codes.
 *
 * Maintains a shadow side table for the action_records main table, providing a tamper-evidence anchor.
 */
export type SideTableErrorCode =
    | 'SIDE_TABLE_ROW_TAMPERED'
    | 'SIDE_TABLE_ANCHOR_MISMATCH'
    | 'SIDE_TABLE_ANCHOR_MISSING';

// ---------------------------------------------------------------------------
// 3. CROSS_ORG_* cross-organization governance error codes
// ---------------------------------------------------------------------------

/**
 * Cross-organization governance error codes.
 *
 * Cannot trigger under the intra-org-only model. Enabled for cross-organization governance scenarios.
 */
export type CrossOrgErrorCode =
    | 'CROSS_ORG_PHASE3_REQUIRES_ARBITRATED_MODE'
    | 'CROSS_ORG_AUTOMATED_VERDICT_WRITE_FAILED';

// ---------------------------------------------------------------------------
// 4. MIRROR_PROOF_* cross-organization mirror proof error codes
// ---------------------------------------------------------------------------

/**
 * Cross-organization mirror proof error codes.
 */
export type MirrorProofErrorCode =
    'MIRROR_PROOF_ENCRYPTION_MIRROR_PROOF_UNAVAILABLE';

// ---------------------------------------------------------------------------
// 5. ARBITRATED_* operator arbitration state machine
// ---------------------------------------------------------------------------

/**
 * Values of sender_audit_intent.state, identifying where a SESSION_SUPERSEDED record sits in the arbitration flow.
 */
export type ArbitratedState = 'ARBITRATED_PENDING_OPERATOR' | 'ARBITRATED';

// ---------------------------------------------------------------------------
// Full namespace union (5 error code classes + arbitration state)
// ---------------------------------------------------------------------------

/** Complete union of the 5 namespace error code classes. */
export type GovernorLaneErrorCode =
    | ArbitrationErrorCode
    | SideTableErrorCode
    | CrossOrgErrorCode
    | MirrorProofErrorCode;

// ---------------------------------------------------------------------------
// SessionOwnerResolver interface
// ---------------------------------------------------------------------------

/**
 * SessionOwnerResolver -- sessionId -> owner DID reverse lookup.
 *
 * Used before the control-plane recorder INSERT to assert that the caller-supplied
 * affected DID matches the session's real owner.
 *
 * Returns null = sessionId does not exist -> fail-closed (reject the write).
 *
 */
export interface SessionOwnerResolver {
    resolveOwner(
        sessionId: string,
    ): Promise<{ agentDid: DID; principalDid: DID } | null>;
}

// ---------------------------------------------------------------------------
// SideTableAppender interface
// ---------------------------------------------------------------------------

/**
 * Shadow audit side table append-only appender.
 *
 * After every action_records write, synchronously writes to the side table, forming a
 * row hash chain + tamper-evidence anchor.
 *
 */
export interface SideTableAppender {
    /**
     * Appends a single side table record.
     *
     * The interface must support same-transaction atomic writes.
     * `transactionClient` is an optional parameter:
     *   - the InMemory stub ignores this parameter (in-memory state has no transaction)
     *   - PostgresSideTableAppender must use this client
     *     to append within the same pg transaction as the main table INSERT
     *   - when transactionClient is missing, the Postgres implementation should throw fail-closed
     *     (silently writing the side-table outside a transaction is not allowed)
     *
     * @param entry side-table row data
     * @param transactionClient optional transaction client (pg.PoolClient);
     *   required by the Postgres implementation, ignored by the InMemory stub.
     *   Typed as unknown to avoid a hard dependency of the types package on pg.
     * @returns the rowHash of the side table row
     * @throws ProtocolError('INTERNAL_ERROR') if the write fails
     */
    append(
        entry: SideTableEntry,
        transactionClient?: unknown,
    ): Promise<{ rowHash: string }>;

    /**
     * Verifies the integrity of the side table chain.
     *
     * Optionally inject mainTableLoader for cross-table comparison.
     * When a loader is injected, each side-table row's recordHash is compared against the main table's current value:
     * - main table row does not exist -> SIDE_TABLE_ANCHOR_MISSING
     * - main table row hash does not match the side-table snapshot -> SIDE_TABLE_ROW_TAMPERED
     *
     * @param agentDid optional restriction to a given agent's chain
     * @param mainTableLoader optional main table record loader (cross-table tamper detection)
     * @returns the verification result
     */
    verifyChain(
        agentDid?: DID,
        mainTableLoader?: MainTableRecordLoader,
    ): Promise<SideTableVerifyResult>;
}

export interface SideTableEntry {
    recordId: string;
    recordHash: string;
    agentDid: DID;
    createdAt: Timestamp;
}

/**
 * MainTableRecordLoader -- the cross-table comparison dependency of side-table verifyChain.
 *
 * verifyChain must read the current hash of the action_records main table and compare it
 * against the side-table snapshot's recordHash to detect main table tampering.
 *
 * Returns null = the main table row for recordId does not exist -> SIDE_TABLE_ANCHOR_MISSING.
 *
 */
export interface MainTableRecordLoader {
    loadRecord(recordId: string): Promise<{ recordHash: string } | null>;
}

export interface SideTableVerifyResult {
    valid: boolean;
    brokenAt?: string;
    errorCode?: SideTableErrorCode;
}

// ---------------------------------------------------------------------------
// OperatorArbitrationStateMachine interface
// ---------------------------------------------------------------------------

/**
 * Operator arbitration state machine.
 *
 * When the governor's automated decision cannot determine the legitimacy of a session supersede,
 * it enters ARBITRATED_PENDING_OPERATOR to await operator intervention for arbitration.
 *
 * State transitions:
 *   initial -> ARBITRATED_PENDING_OPERATOR (operator intervention request)
 *   ARBITRATED_PENDING_OPERATOR -> ARBITRATED (operator completes arbitration)
 *   any stage -> ARBITRATION_HALF_COMMITTED (crash before transaction commit)
 *   any stage -> ARBITRATION_CHAIN_MALFORMED (malformed hash chain)
 *
 */
export interface OperatorArbitrationStateMachine {
    /**
     * Request operator arbitration.
     *
     * @returns the arbitration request result (recordId + initial state)
     * @throws ProtocolError if starting the arbitration flow fails
     */
    requestArbitration(params: ArbitrationRequest): Promise<ArbitrationResult>;

    /**
     * Operator submits an arbitration verdict.
     *
     * @throws ProtocolError if writing the verdict fails
     */
    submitVerdict(
        arbitrationId: string,
        verdict: ArbitrationVerdict,
    ): Promise<ArbitrationResult>;

    /**
     * Query the arbitration state.
     */
    getState(arbitrationId: string): Promise<ArbitratedState | null>;
}

export interface ArbitrationRequest {
    /** the associated SESSION_SUPERSEDED recordId */
    relatedRecordId: string;
    /** description of the arbitration reason */
    reason: string;
    /** request time */
    timestamp: Timestamp;
}

export interface ArbitrationVerdict {
    /** operator DID (audit accountability) */
    operatorDid: DID;
    /** verdict: approve (confirm the supersede is legitimate) or reject (revoke the supersede) */
    decision: 'approve' | 'reject';
    /** rationale for the verdict */
    rationale: string;
    /** verdict time */
    timestamp: Timestamp;
}

export interface ArbitrationResult {
    arbitrationId: string;
    state: ArbitratedState;
    recordId?: string;
}

// ---------------------------------------------------------------------------
// ControlPlaneRequesterScope checker interface
// ---------------------------------------------------------------------------

/**
 * per-requester subject scope validation.
 *
 * Reuses the ControlPlaneRequesterScope interface definition from @coivitas/types.
 * This interface defines the checker's behavior.
 */
export interface ControlPlaneRequesterScopeChecker {
    /**
     * Checks whether the requester is authorized to read the governor records of the given affected DID.
     *
     * fail-closed:
     * - requester not in the scope map -> AUDIT_FORBIDDEN
     * - affectedAgentDid not in scope -> AUDIT_FORBIDDEN
     * - affectedPrincipalDid not in scope (when the scope constrains this dimension) -> AUDIT_FORBIDDEN
     */
    checkScope(
        requesterDid: DID,
        affectedAgentDid?: DID,
        affectedPrincipalDid?: DID,
    ): { allowed: true } | { allowed: false; reason: string };
}

// ---------------------------------------------------------------------------
// GovernorLaneFactory interface (factory output)
// ---------------------------------------------------------------------------

/**
 * GovernorLaneFactory output.
 *
 * createGovernorLaneRuntime(deps) returns this structure,
 * which contains the complete governor lane runtime components.
 */
export interface GovernorLaneRuntime {
    /** operator arbitration state machine */
    readonly arbitration: OperatorArbitrationStateMachine;
    /** shadow audit side table appender */
    readonly sideTable: SideTableAppender;
    /** SessionOwnerResolver instance */
    readonly sessionOwnerResolver: SessionOwnerResolver;
    /** assertSchemaCompliant validation function */
    readonly assertSchemaCompliant: (input: AssertSchemaCompliantInput) => void;
}

/**
 * GovernorLaneFactory dependencies.
 */
export interface GovernorLaneDeps {
    /** control-plane ActionRecorder instance */
    controlPlaneRecorder: ControlPlaneActionRecorder;
    /** session owner resolver */
    sessionOwnerResolver: SessionOwnerResolver;
    /** governor signing private key */
    governorPrivateKey: string;
}

// ---------------------------------------------------------------------------
// assertSchemaCompliant input
// ---------------------------------------------------------------------------

/**
 * assertSchemaCompliant input.
 *
 * Used to run full AJV schema validation before the control-plane recorder INSERT.
 * Full validation of DID pattern + ISO8601 + additionalProperties.
 */
export interface AssertSchemaCompliantInput {
    agentDid: string;
    principalDid: string;
    actionType: string;
    parametersSummary: Record<string, unknown> | null | undefined;
}
