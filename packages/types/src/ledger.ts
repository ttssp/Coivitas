import type { DID, Hash, Signature, Timestamp } from './base.js';

/**
 * ActionRecord — the ledger object shape.
 *
 * Corrects an earlier static-contract drift.
 * The runtime/DB/signing canonicalized payload has always used the object shape;
 * this interface's earlier hash/flat/enum shape was self-contained only within the type system + fixtures,
 * and never covered the records actually written. This rewrite brings the static contract back into consensus
 * with the spec + runtime + DB; the wire semantics are unchanged (no specVersion bump; stays at 0.1.0 / 0.2.0).
 *
 * Field semantics:
 * - parametersSummary: a readable summary of the action parameters (sensitive fields may be trimmed); the signing preimage must be reconstructible
 * - authorizationRef: the authorization-reference container; null when a rejected action has no matching token
 * - resultSummary: a structured result object { status, reason?, message? }
 *     status ∈ {'SUCCESS','REJECTED','ERROR'} (excluding PENDING_APPROVAL —
 *     PENDING_APPROVAL is a PolicyEngine Step 2 intermediate state and is never written to the ledger)
 *
 * Three fields added (frozen):
 * - delegationDepth: delegation-chain depth (0 = no delegation)
 * - sessionId: the session ID active at write time
 * - actorSignature: the agent's Ed25519 signature over unsigned_payload (dual-signed with ledgerSignature)
 * Backward compatibility: 0.1.0 records lack the latter three; they are treated as undefined on read.
 */
/**
 * ActionResultSummary — the spec's structured result object.
 *
 * status ∈ {'SUCCESS','REJECTED','ERROR'} (PENDING_APPROVAL is a PolicyEngine
 * Step 2 intermediate state and is never written to the ledger).
 *
 * Extension fields:
 * - amount: the aggregate metric field for scope-extensions cumulative_limit.
 *   Listed explicitly in the schema rather than additionalProperties:true, because: the contract is the protocol's constitution;
 *   opening additionalProperties would hand cross-implementation interop over to implicit conventions, breaking the single source of truth.
 *   Future new metric fields (the metric registry) must be listed explicitly.
 */
export interface ActionResultSummary {
    status: 'SUCCESS' | 'REJECTED' | 'ERROR';
    reason?: string;
    message?: string;
    /** scope-extensions cumulative_limit aggregate field (numeric metric)*/
    amount?: number;
}

/**
 * AuthorizationRef — the spec's authorization-reference container.
 *
 * tokenId is allowed to be null: the spec explicitly preserves the "token ID could not be determined (exceptional case)" branch;
 * runtime engine.ts already writes `{ tokenId: guardResult.tokenId ?? null }` on all three paths
 * (SUCCESS / manual rejection / execution exception).
 */
export interface AuthorizationRef {
    tokenId: string | null;
}

export interface ActionRecord {
    id: string;
    specVersion: string;
    agentDid: DID;
    principalDid: DID;
    action: string;
    parametersSummary: Record<string, unknown> | null;
    authorizationRef: AuthorizationRef | null;
    /**
     * The spec's field table writes `result_summary: object | null`;
     * runtime action-recorder.ts actually normalizes to null (in the no-result-context scenario).
     */
    resultSummary: ActionResultSummary | null;
    timestamp: Timestamp;
    prevHash: Hash | null;
    ledgerSignature: Signature;
    /** Added — delegation-chain depth, 0 when there is no delegation chain*/
    delegationDepth?: number;
    /** Added — the session ID active at write time*/
    sessionId?: string;
    /**
     * Added — the agent's Ed25519 signature over unsigned_payload (dual-signed with ledgerSignature).
     *
     * Marked optional for backward-compatible reading of specVersion 0.1.0 records (some early implementations
     * only wrote ledger_signature). On specVersion 0.2.0 writes, the schema forces it required via if/then;
     * see the actionRecord definition in schemas.ts.
     */
    actorSignature?: Signature;
}

export interface IntegrityProof {
    agentDid: DID;
    chainLength: number;
    headHash: Hash;
    computedAt: Timestamp;
    verifierDid?: DID;
}

/**
 * Cumulative-limit settlement state (the scope-extensions spec).
 *
 * The check-and-reserve flow writes PENDING; after the business completes, it is settled to SETTLED or RELEASED.
 */
export type ReservationState = 'PENDING' | 'SETTLED' | 'RELEASED';
