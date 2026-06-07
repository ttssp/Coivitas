/**
 * Dispute Arbitration L3 port interface definitions (7 ports)
 *
 * Sub-protocol — dispute-arbitration v0.1
 *
 * All 7 ports must have an active invocation inside runDisputeArbitration7Steps();
 * any dead port (defined but not called) is not allowed (anti-phantom).
 *
 * Port list:
 *   1. MultisigPort — multi-signature operations
 *   2. ArbitratorSelector — arbitrator-pool management
 *   3. EvidenceStore — evidence storage
 *   4. RevocationChecker — revocation-status check
 *   5. SignatureVerifier — signature verification
 *   6. AtpRecorder — audit recording (atp v0.1 freeze; L2 class only)
 *   7. DisputeStore — dispute ledger
 */

import type {
    DisputeId,
    ArbitrationDecision,
    Dispute,
    DisputeFilingSignedPayload,
    Arbitrator,
    CanonicalHashHex,
    DisputeState,
    DisputeStateTransitionEvent,
} from '@coivitas/types';

// ─── Port 1: MultisigPort ────────────────────────────────────────────────────

/**
 * Multi-signature operation port
 *
 * Responsible for aggregating arbitrator signatures; the threshold is provided by computeThreshold().
 *
 */
export interface MultisigPort {
    /**
     * Aggregate arbitrator signatures
     * @param decision the arbitration decision (containing the canonical hash to be signed)
     * @param arbitrators the set of arbitrators participating in signing
     * @param threshold the multi-signature threshold (enforced)
     * @returns the ArbitrationDecision containing all valid signatures
     * @throws DA_INSUFFICIENT_SIGNATURES the signature count did not reach the threshold
     * @throws DA_ARBITRATOR_INVALID an arbitrator DID/key is invalid
     * @throws DA_PROVIDER_UNAVAILABLE the port is unavailable
     */
    aggregateSignatures(
        decision: ArbitrationDecision,
        arbitrators: readonly Arbitrator[],
        threshold: number,
    ): Promise<ArbitrationDecision>;

    /**
     * Verify a single arbitrator signature
     * @throws DA_SIGNED_PAYLOAD_INVALID the signature is invalid
     */
    verifyArbitratorSignature(
        arbitratorDid: string,
        signature: string,
        payload: string,
    ): Promise<boolean>;
}

// ─── Port 2: ArbitratorSelector ─────────────────────────────────────────────

/**
 * Arbitrator selection port
 *
 * Selects 3-5 active arbitrators from the arbitrator pool.
 * Invariant: the returned arbitrators count >= MIN_ARBITRATOR_COUNT.
 *
 */
export interface ArbitratorSelector {
    /**
     * Select the arbitrator set
     * @param disputeId the dispute ID (used for deterministic random selection)
     * @param poolSizeTarget the target pool size [3, 5]
     * @returns the list of active arbitrators (size = poolSizeTarget)
     * @throws DA_ARBITRATOR_INSUFFICIENT insufficient active arbitrators
     * @throws DA_PROVIDER_UNAVAILABLE the port is unavailable
     */
    selectArbitrators(
        disputeId: DisputeId,
        poolSizeTarget: number,
    ): Promise<readonly Arbitrator[]>;

    /**
     * Verify whether an arbitrator is in the active pool
     * @throws DA_ARBITRATOR_INVALID the arbitrator is invalid or inactive
     */
    validateArbitrator(arbitratorDid: string): Promise<boolean>;
}

// ─── Port 3: EvidenceStore ───────────────────────────────────────────────────

/**
 * Evidence storage port
 *
 * Responsible for storing and validating evidence URIs.
 *
 */
export interface EvidenceStore {
    /**
     * Validate evidence-URI reachability and integrity
     * @param evidenceUris the list of evidence URIs
     * @returns the list of URIs that passed validation
     * @throws DA_EVIDENCE_INVALID the URI format/content is invalid
     * @throws DA_PROVIDER_UNAVAILABLE the port is unavailable
     */
    validateEvidenceUris(
        evidenceUris: readonly string[],
    ): Promise<readonly string[]>;

    /**
     * Store evidence references
     * @param disputeId the dispute ID
     * @param uris the list of validated URIs
     * @param ctx the transaction context (optional; injected by DisputeTxManager.runInTransaction)
     * @throws DA_EVIDENCE_INVALID storage failed
     */
    storeEvidenceRef(
        disputeId: DisputeId,
        uris: readonly string[],
        ctx?: DisputeTransactionContext,
    ): Promise<void>;
}

// ─── Port 4: RevocationChecker ───────────────────────────────────────────────

/**
 * Revocation-status check port
 *
 * Verifies the revocation status of the dispute subject (token / DID).
 *
 */
export interface RevocationChecker {
    /**
     * Check whether a token has been revoked
     * @param token the CSP token string
     * @returns true = revoked
     * @throws DA_PROVIDER_UNAVAILABLE the port is unavailable
     */
    isTokenRevoked(token: string): Promise<boolean>;

    /**
     * Check whether the resources associated with a DID have been revoked
     * @param did the DID string
     * @throws DA_DISPUTE_REVOKED the DID-related resources have been revoked
     */
    checkDidRevocationStatus(did: string): Promise<void>;
}

// ─── Port 5: SignatureVerifier ───────────────────────────────────────────────

/**
 * Signature verification port
 *
 * Responsible for the cryptographic verification of the CSP claimant signature.
 *
 */
export interface SignatureVerifier {
    /**
     * Verify the CSP filing signature
     * @param payload DisputeFilingSignedPayload
     * @returns true = the signature is valid
     * @throws DA_SIGNED_PAYLOAD_INVALID the signature is invalid or the key does not match
     * @throws DA_FRESHNESS_INVALID notAfter has expired
     * @throws DA_PROVIDER_UNAVAILABLE the port is unavailable
     */
    verifyDisputeFilingSignature(
        payload: DisputeFilingSignedPayload,
    ): Promise<boolean>;

    /**
     * Check the freshness of the CSP notAfter
     * @param notAfter the ISO 8601 timestamp
     * @throws DA_FRESHNESS_INVALID notAfter has expired
     */
    checkFreshness(notAfter: string): void;
}

// ─── Port 6: AtpRecorder ─────────────────────────────────────────────────────

/**
 * Audit-event recording port (atp v0.1 freeze)
 *
 * Strict constraints:
 *   - auditClass is fixed to 'L2' (atp v0.1 freeze; adding 'dispute_event' or other custom classes is strictly forbidden)
 *   - use only the existing atp v0.1 audit-event schema
 *   - modifying the field definitions already frozen by atp v0.1 is not allowed
 *
 * + atp audit events
 */
export interface AtpRecorder {
    /**
     * Record a dispute state-transition audit event
     * @param event the transition event (auditClass fixed to 'L2')
     * @param ctx the transaction context (optional; injected by DisputeTxManager.runInTransaction)
     * @throws DA_PROVIDER_UNAVAILABLE the audit port is unavailable
     */
    recordDisputeTransition(
        event: DisputeStateTransitionEvent,
        ctx?: DisputeTransactionContext,
    ): Promise<void>;

    /**
     * Record a dispute-filing-submitted audit event
     * @param disputeId the dispute ID
     * @param canonicalHash the filing canonical hash
     * @param ctx the transaction context (optional; injected by DisputeTxManager.runInTransaction)
     * @throws DA_PROVIDER_UNAVAILABLE the audit port is unavailable
     */
    recordDisputeFiled(
        disputeId: DisputeId,
        canonicalHash: CanonicalHashHex,
        ctx?: DisputeTransactionContext,
    ): Promise<void>;

    /**
     * Record an arbitration-decision audit event
     * @param disputeId the dispute ID
     * @param decisionHash the decision canonical hash
     * @param ctx the transaction context (optional; injected by DisputeTxManager.runInTransaction)
     * @throws DA_PROVIDER_UNAVAILABLE the audit port is unavailable
     */
    recordArbitrationDecision(
        disputeId: DisputeId,
        decisionHash: CanonicalHashHex,
        ctx?: DisputeTransactionContext,
    ): Promise<void>;
}

// ─── TransactionContext + DisputeTxManager ───────────────────────────────────

/**
 * Database transaction context
 *
 * pg-style client: obtained by the caller via runInTransaction;
 * all operations within the transaction scope share this client.
 * The implementation layer should use pg.PoolClient or an equivalent implementation.
 *
 * atomic transaction wrapper.
 */
export interface DisputeTransactionContext {
    /**
     * Execute raw SQL within this transaction context (pg-style)
     * The implementation layer binds to pg.PoolClient.query();
     * the test layer can inject a spy/mock.
     */
    query(
        sql: string,
        params?: unknown[],
    ): Promise<{ rowCount: number | null }>;
}

/**
 * Dispute-arbitration transaction manager
 *
 * Encapsulates the three semantics BEGIN / COMMIT / ROLLBACK;
 * injected into the persistence segment of runDisputeArbitration7Steps (Steps 6-7);
 * all 7 await operations execute within the same transaction.
 *
 * Implementation constraints:
 *   - must genuinely implement BEGIN ... COMMIT / ROLLBACK (a no-op fake wrapper is not allowed)
 *   - any throw inside the callback → transaction ROLLBACK + re-throw
 *   - asynchronous cascade or hybrid implementations are strictly forbidden (dc v0.3 is synchronous only)
 */
export interface DisputeTxManager {
    /**
     * Execute the callback within a BEGIN ... COMMIT/ROLLBACK transaction block
     *
     * @param callback receives a DisputeTransactionContext; all operations inside run in the same transaction
     * @returns the callback's return value
     * @throws any throw inside the callback → ROLLBACK + re-throw the original error
     */
    runInTransaction<T>(
        callback: (ctx: DisputeTransactionContext) => Promise<T>,
    ): Promise<T>;
}

// ─── Port 7: DisputeStore ────────────────────────────────────────────────────

/**
 * Dispute-ledger storage port
 *
 * Responsible for CRUD of the Dispute entity; idempotency detection; state-transition persistence.
 *
 */
export interface DisputeStore {
    /**
     * Check whether a duplicate filing exists (idempotency detection; via canonical hash)
     * @param canonicalHash the filing canonical hash
     * @returns the existing disputeId (duplicate) or null (new filing)
     * @throws DA_PROVIDER_UNAVAILABLE the port is unavailable
     */
    findByCanonicalHash(
        canonicalHash: CanonicalHashHex,
    ): Promise<DisputeId | null>;

    /**
     * Query all fields of a Dispute by disputeId (double-spend defense idempotency)
     *
     * Double-spend defense idempotency semantics:
     *   same disputeId, different canonicalHash → throw DA_IDEMPOTENCY_VIOLATION (double-spend case);
     *   the original findByCanonicalHash cannot detect the "same disputeId, different canonicalHash" case
     *
     * @param disputeId the dispute ID
     * @returns the full Dispute record or null (new disputeId)
     * @throws DA_PROVIDER_UNAVAILABLE the port is unavailable
     */
    findByDisputeId(disputeId: DisputeId): Promise<Dispute | null>;

    /**
     * Persist a new dispute record
     *
     * @param dispute the Dispute entity
     * @param ctx the transaction context (optional; injected by DisputeTxManager.runInTransaction)
     * @throws DA_IDEMPOTENCY_VIOLATION canonical hash conflict
     * @throws DA_PROVIDER_UNAVAILABLE the port is unavailable
     */
    saveDispute(
        dispute: Dispute,
        ctx?: DisputeTransactionContext,
    ): Promise<void>;

    /**
     * Query the current state of a dispute
     * @throws DA_PROVIDER_UNAVAILABLE the port is unavailable
     */
    getDisputeState(disputeId: DisputeId): Promise<DisputeState | null>;

    /**
     * Update the dispute state (persisted after a state transition)
     *
     * @param disputeId the dispute ID
     * @param toState the target state
     * @param transitionedAt the transition timestamp
     * @param ctx the transaction context (optional; injected by DisputeTxManager.runInTransaction)
     * @throws DA_STATE_TRANSITION_INVALID invalid transition
     * @throws DA_PROVIDER_UNAVAILABLE the port is unavailable
     */
    updateDisputeState(
        disputeId: DisputeId,
        toState: DisputeState,
        transitionedAt: string,
        ctx?: DisputeTransactionContext,
    ): Promise<void>;

    /**
     * Persist the arbitration decision
     *
     * @param decision ArbitrationDecision
     * @param ctx the transaction context (optional; injected by DisputeTxManager.runInTransaction)
     * @throws DA_PROVIDER_UNAVAILABLE the port is unavailable
     */
    saveArbitrationDecision(
        decision: ArbitrationDecision,
        ctx?: DisputeTransactionContext,
    ): Promise<void>;
}
