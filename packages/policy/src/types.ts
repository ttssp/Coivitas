import type { DID, Signature, Timestamp } from '@coivitas/types';

export interface ActionRecordInput {
    recordId?: string;
    agentDid: DID;
    principalDid: DID;
    actionType: string;
    parametersSummary?: Record<string, unknown> | null;
    authorizationRef?: Record<string, unknown> | null;
    resultSummary?: Record<string, unknown> | null;
    actorPrivateKey: string;
    /** Delegation chain depth, obtained from RuntimeGuardResult.delegationDepth; 0 = no delegation */
    delegationDepth?: number;
    /** Current session ID */
    sessionId?: string;
    /** Output encoding for hash and signature, defaults to 'hex' (frozen wire format convention) */
    outputEncoding?: 'hex' | 'base64url';
    createdAt?: Timestamp;
}

export interface PersistedActionRecord {
    recordId: string;
    agentDid: DID;
    principalDid: DID;
    actionType: string;
    parametersSummary: Record<string, unknown> | null;
    authorizationRef: Record<string, unknown> | null;
    resultSummary: Record<string, unknown> | null;
    recordHash: string;
    previousRecordHash: string;
    actorSignature: Signature;
    ledgerSignature: Signature;
    delegationDepth?: number;
    sessionId?: string;
    createdAt: Timestamp;
}

export interface ActionRecordQueryFilters {
    agentDid?: DID;
    principalDid?: DID;
    actionType?: string;
    createdFrom?: Timestamp;
    createdTo?: Timestamp;
    limit?: number;
    /** Cursor pagination: the "ISO8601|integer_id" composite string of the last record on the previous page */
    cursor?: string;
    /**
     * Sort direction: defaults to 'asc' (ascending by created_at, id, old -> new, consistent with the existing
     * cursor pagination convention). 'desc' is used for "fetch the most recent N records" semantics
     * (e.g. `ap ledger anchor --last N`); after the caller obtains the results, reverse them yourself if you
     * need chronological display. Cursor pagination is not guaranteed to be semantically correct in desc mode.
     */
    order?: 'asc' | 'desc';
}

export interface RecordWriteResult {
    recordId: string;
    hash: string;
}

export interface IntegrityCheckResult {
    valid: boolean;
    brokenAt?: string;
    reason?: string;
}

export type ResolveAgentPublicKey = (did: DID) => Promise<string | null>;

/**
 * Control-plane public key resolver.
 *
 * Used by IntegrityChecker to resolve the actor public key when verifying control-plane
 * ActionRecords such as SESSION_SUPERSEDED (the governor DID does not enter federated DID
 * resolution; it is injected by the L3 deployment context).
 *
 * **Required** on the production path; if absent, throw at construction time (to avoid
 * deferring a "fix it later" hazard).
 *
 * Returns null -> IntegrityChecker fail-closed (reason='agent public key unavailable').
 */
export type ResolveControlPlanePublicKey = (did: DID) => Promise<string | null>;

export interface RuntimeGuardResult {
    allowed: boolean;
    reason?: string;
    code?: string;
    tokenId?: string;
    /**
     * Delegation chain depth, 0 when there is no delegation chain. Used by ActionRecorder to write
     * ActionRecord.delegationDepth.
     */
    delegationDepth?: number;
}

export interface ExecuteWithPolicySuccess<T> {
    executed: true;
    result: T;
    recordId: string;
}

export interface ExecuteWithPolicyFailure {
    executed: false;
    reason: string;
    recordId: string;
}

export type ExecuteWithPolicyResult<T = unknown> =
    | ExecuteWithPolicySuccess<T>
    | ExecuteWithPolicyFailure;

export interface ActionRecordQueryResult {
    records: PersistedActionRecord[];
    /** Cursor for the next page; if undefined, this is already the last page */
    nextCursor?: string;
}
