/**
 * Dispute Arbitration L3 state-machine implementation
 *
 * Implementation list:
 *   - runDisputeArbitration7Steps() — the 7-step main algorithm
 *   - validateStateTransition() — 2-transition freeze enforcement
 *   - computeDisputeFilingCanonicalHash() — SHA-256/JCS canonical hash
 *   - computeThreshold() — three-layer enforce (algorithm layer)
 *   - checkAndExpireDispute() — 14-day timeout check
 *
 * Constraint #1 (three-layer enforce):
 *   algorithm layer = this file's computeThreshold(): poolSize < 3 → throw DA_ARBITRATOR_INSUFFICIENT
 *   constant layer = packages/types/src/dispute-arbitration/constants.ts MIN_ARBITRATOR_COUNT=3
 *   SQL DDL layer = 032_dispute_arbitration.sql CHECK (multisig_pool_size >= 3 AND multisig_pool_size <= 5)
 *
 * Constraint #2 (port enforcement):
 *   all 7 ports have an active invocation inside runDisputeArbitration7Steps();
 *   no uncalled dead port is allowed.
 *
 * Constraint #3 (14-day timeout):
 *   filedAt + MAX_DISPUTE_MS → FILED→EXPIRED terminal;
 *   checkAndExpireDispute() must be called at the step 1 verification point.
 *
 * Constraint #4 (csp dual-class):
 *   verify-time: DisputeFilingSignedPayload (CSP constraint 1 FULL)
 *   issuance-time: DisputeFiling (internal object)
 *   ArbitrationDecision: NOT-APPLICABLE
 *
 * Constraint #5 (2-transition freeze):
 *   FILED→RESOLVED + FILED→EXPIRED only;
 *   validateStateTransition() enforced at every state update.
 */

import {
    canonicalize as jcsCanonicalizeImpl,
    hash as cryptoHash,
} from '@coivitas/crypto';

import {
    DaError,
    toCanonicalHashHex,
    DA_VERSION_1_0_0,
    DISPUTE_STATE_TRANSITIONS,
    MIN_ARBITRATOR_COUNT,
    MAX_ARBITRATOR_COUNT,
    MAX_DISPUTE_MS,
    DA_SUPPORTED_VERSIONS,
    validateDisputeFilingSchema,
    type DisputeId,
    type DisputeState,
    type DisputeFiling,
    type DisputeFilingSignedPayload,
    type ArbitrationDecision,
    type Dispute,
    type CanonicalHashHex,
    type DaVerdict,
    type DisputeStateTransitionEvent,
} from '@coivitas/types';

import type {
    MultisigPort,
    ArbitratorSelector,
    EvidenceStore,
    RevocationChecker,
    SignatureVerifier,
    AtpRecorder,
    DisputeStore,
    DisputeTxManager,
} from './ports.js';

// ─── 7-step main algorithm inputs/outputs ───────────────────────────────────────────────────────

/**
 * runDisputeArbitration7Steps input
 *
 * Contains the 7 ports + filing data + configuration parameters.
 */
export interface DisputeArbitrationInput {
    /** the filing (issuance-time internal object; already passed L0 schema validation)*/
    readonly filing: DisputeFiling;
    /** the signed payload of the filing (verify-time; CSP constraint 1 FULL)*/
    readonly signedPayload: DisputeFilingSignedPayload;
    /** the target arbitrator-pool size [MIN_ARBITRATOR_COUNT, MAX_ARBITRATOR_COUNT]*/
    readonly poolSizeTarget: number;
    /** the verdict conclusion (passed in by the orchestration layer)*/
    readonly verdict: DaVerdict;
    /** tenant ID (ledger isolation)*/
    readonly tenantId: string;
    /**
     * the dispute-arbitration transaction manager (atomic transaction wrapper)
     *
     * All 7 await operations of Steps 6-7 execute inside txManager.runInTransaction;
     * any operation that throws → transaction ROLLBACK; success → COMMIT.
     * The implementation layer must pass in a real pg-style BEGIN/COMMIT/ROLLBACK implementation.
     */
    readonly txManager: DisputeTxManager;
    // 7 ports
    readonly multisigPort: MultisigPort;
    readonly arbitratorSelector: ArbitratorSelector;
    readonly evidenceStore: EvidenceStore;
    readonly revocationChecker: RevocationChecker;
    readonly signatureVerifier: SignatureVerifier;
    readonly atpRecorder: AtpRecorder;
    readonly disputeStore: DisputeStore;
}

/**
 * runDisputeArbitration7Steps return
 *
 * Contains the final arbitration decision + dispute state record + state-transition event.
 *
 */
export interface DisputeArbitrationResult {
    readonly dispute: Dispute;
    readonly decision: ArbitrationDecision;
    readonly transitionEvent: DisputeStateTransitionEvent;
}

// ─── validateStateTransition (Constraint #5) ───────────────────────────────────────

/**
 * validateStateTransition — 2-transition freeze enforcement
 *
 * Only FILED→RESOLVED + FILED→EXPIRED are allowed;
 * any other transition → throw DA_STATE_TRANSITION_INVALID.
 *
 * Constraint #5: 2-transition freeze.
 */
export function validateStateTransition(
    from: DisputeState,
    to: DisputeState,
): void {
    const isValid = DISPUTE_STATE_TRANSITIONS.some(
        ([f, t]) => f === from && t === to,
    );
    if (!isValid) {
        throw new DaError('DA_STATE_TRANSITION_INVALID', {
            reason: 'invalid_dispute_state_transition',
            from,
            to,
            allowedTransitions: DISPUTE_STATE_TRANSITIONS,
        });
    }
}

// ─── computeThreshold (Constraint #1 — algorithm layer) ───────────────────────────────

/**
 * computeThreshold — three-layer enforce, algorithm layer
 *
 * poolSize < MIN_ARBITRATOR_COUNT (3) → throw DA_ARBITRATOR_INSUFFICIENT
 * poolSize > MAX_ARBITRATOR_COUNT (5) → throw DA_ARBITRATOR_INVALID
 * threshold = floor(poolSize / 2) + 1 (majority quorum)
 *
 * Constraint #1: enforced at the algorithm layer;
 * working together with the constant layer (MIN_ARBITRATOR_COUNT=3) + the SQL DDL layer (CHECK multisig_pool_size >= 3).
 */
export function computeThreshold(poolSize: number): number {
    if (poolSize < MIN_ARBITRATOR_COUNT) {
        throw new DaError('DA_ARBITRATOR_INSUFFICIENT', {
            poolSize,
            minRequired: MIN_ARBITRATOR_COUNT,
            reason: 'arbitrator_pool_size_below_minimum_constitution_p35',
        });
    }
    if (poolSize > MAX_ARBITRATOR_COUNT) {
        throw new DaError('DA_ARBITRATOR_INVALID', {
            poolSize,
            maxCount: MAX_ARBITRATOR_COUNT,
            reason: 'arbitrator_pool_size_out_of_bounds',
        });
    }
    return Math.floor(poolSize / 2) + 1;
}

// ─── checkAndExpireDispute (Constraint #3 — 14-day timeout) ──────────────────────────────

/**
 * checkAndExpireDispute — 14-day timeout check
 *
 * If now - filedAt >= MAX_DISPUTE_MS → throw DA_TIMEOUT_EXCEEDED (the FILED→EXPIRED trigger signal)
 *
 * Constraint #3: a 14-day hard cap; decided by filedAt + MAX_DISPUTE_MS;
 * the caller must catch DA_TIMEOUT_EXCEEDED and perform the FILED→EXPIRED transition + audit.
 */
export function checkAndExpireDispute(filedAt: string, nowMs?: number): void {
    const filedMs = new Date(filedAt).getTime();
    const now = nowMs ?? Date.now();
    if (isNaN(filedMs)) {
        throw new DaError('DA_FILING_INVALID', {
            reason: 'filed_at_not_a_valid_iso8601_timestamp',
            filedAt,
        });
    }
    if (now - filedMs >= MAX_DISPUTE_MS) {
        throw new DaError('DA_TIMEOUT_EXCEEDED', {
            reason: 'dispute_exceeded_max_dispute_days_pc3',
            filedAt,
            maxDays: MAX_DISPUTE_MS / (24 * 3600 * 1000),
            elapsedMs: now - filedMs,
        });
    }
}

// ─── computeDisputeFilingCanonicalHash ───────────────────────────────────────

/**
 * computeDisputeFilingCanonicalHash — SHA-256/JCS canonical hash
 *
 * 13 fields enter the JCS (RFC 8785) canonical encoding → SHA-256 hash.
 * A JSON.stringify fallback is strictly forbidden; JCS must be used.
 *
 * 13 fields (ordering by JCS key sort):
 *   audience, challenge, claimantDid, cspVersion, disclosedClaims,
 *   disputeId, disputeType, evidenceUris, filedAt, notAfter,
 *   respondentDid, settlementOperationRef?, token
 *
 * Constraint #4 csp dual-class: this hash corresponds to the DisputeFilingSignedPayload verify-time.
 */
export function computeDisputeFilingCanonicalHash(
    payload: Pick<
        DisputeFiling,
        | 'disputeId'
        | 'claimantDid'
        | 'respondentDid'
        | 'disputeType'
        | 'evidenceUris'
        | 'settlementOperationRef'
        | 'cspVersion'
        | 'token'
        | 'disclosedClaims'
        | 'challenge'
        | 'audience'
        | 'notAfter'
        | 'filedAt'
    >,
): CanonicalHashHex {
    // 13-field normalized object; undefined fields do not enter the canonical form
    const canonicalObj: Record<string, unknown> = {
        audience: payload.audience,
        challenge: payload.challenge,
        claimantDid: payload.claimantDid,
        cspVersion: payload.cspVersion,
        disclosedClaims: payload.disclosedClaims,
        disputeId: payload.disputeId,
        disputeType: payload.disputeType,
        evidenceUris: [...payload.evidenceUris],
        filedAt: payload.filedAt,
        notAfter: payload.notAfter,
        respondentDid: payload.respondentDid,
        token: payload.token,
    };
    // settlementOperationRef enters the canonical form only when provided
    if (payload.settlementOperationRef !== undefined) {
        canonicalObj['settlementOperationRef'] = payload.settlementOperationRef;
    }

    let canonicalStr: string;
    try {
        // JCS RFC 8785 canonical encoding; a JSON.stringify fallback is strictly forbidden
        canonicalStr = jcsCanonicalizeImpl(canonicalObj);
    } catch (err) {
        throw new DaError('DA_CANONICAL_HASH_MISMATCH', {
            reason: 'jcs_canonicalize_failed_during_hash_computation',
            error: String(err),
        });
    }

    // hash() from @coivitas/crypto wraps sha256 → hex output (wire-format frozen)
    const hashHex = cryptoHash(canonicalStr, 'hex');
    return toCanonicalHashHex(hashHex);
}

// ─── runDisputeArbitration7Steps (main algorithm) ────────────────────────────────────

/**
 * runDisputeArbitration7Steps — the DA 7-step main algorithm
 *
 * Steps:
 *   Step 1: filing-field validation + version check + idempotency detection + 14-day timeout check
 *   Step 2: canonical hash computation + evidence-URI validation
 *   Step 3: CSP signature verification + freshness check + revocation-status check
 *   Step 4: arbitrator-pool selection + pool-size enforcement
 *   Step 5: multi-signature aggregation + threshold check
 *   Step 6: dispute-record persistence + audit record (filed)
 *   Step 7: FILED→RESOLVED state transition + arbitration-decision persistence + audit record (decision)
 *
 * Constraint #2: all 7 ports have an active invocation in this function (avoids dead ports).
 */
export async function runDisputeArbitration7Steps(
    input: DisputeArbitrationInput,
): Promise<DisputeArbitrationResult> {
    const {
        filing,
        signedPayload,
        poolSizeTarget,
        verdict,
        tenantId,
        txManager, // atomic transaction wrapper
        multisigPort, // Port 1
        arbitratorSelector, // Port 2
        evidenceStore, // Port 3
        revocationChecker, // Port 4
        signatureVerifier, // Port 5
        atpRecorder, // Port 6
        disputeStore, // Port 7
    } = input;

    // ── Step 1: filing-field validation + version check + idempotency detection + 14-day timeout check ──────────

    // Third layer of the triple defense, L3 enforce:
    // if L3 does not call validateDisputeFilingSchema → required/additionalProperties
    // enforcement is fully bypassed; malformed runtime JSON input would still reach revocation/multisig/persistence.
    // Therefore the 7-step entry first validates signedPayload with the L0 AJV validator (fail-closed throw DA_FILING_INVALID)
    const filingValidation = validateDisputeFilingSchema(signedPayload);
    if (!filingValidation.valid) {
        throw new DaError('DA_FILING_INVALID', {
            reason: 'dispute_filing_signed_payload_schema_validation_failed',
            disputeId: filing.disputeId,
            errors: filingValidation.errors,
        });
    }

    // version validation
    if (
        !(DA_SUPPORTED_VERSIONS as readonly string[]).includes(filing.daVersion)
    ) {
        throw new DaError('DA_VERSION_UNSUPPORTED', {
            reason: 'unsupported_da_version_in_filing',
            provided: filing.daVersion,
            supported: DA_SUPPORTED_VERSIONS,
        });
    }

    // timeout check (14 days; Constraint #3)
    // timeout → throw DA_TIMEOUT_EXCEEDED → the caller handles FILED→EXPIRED
    checkAndExpireDispute(filing.filedAt);

    // idempotency detection (Port 7 active — DisputeStore.findByCanonicalHash + findByDisputeId)

    // double-spend defense: two idempotency-detection paths:
    // (a) findByCanonicalHash → DA_DUPLICATE_FILING (same canonicalHash → duplicate dispute)
    // (b) findByDisputeId → DA_IDEMPOTENCY_VIOLATION (same disputeId, different canonicalHash → double-spend case)
    // path (a) alone cannot detect the "same disputeId, different canonicalHash" double-spend case, so both run in parallel.
    const preCheckHash = computeDisputeFilingCanonicalHash(filing);
    const existingId = await disputeStore.findByCanonicalHash(preCheckHash);
    if (existingId !== null) {
        throw new DaError('DA_DUPLICATE_FILING', {
            reason: 'duplicate_dispute_filing_canonical_hash_exists',
            canonicalHash: preCheckHash,
            existingDisputeId: existingId,
        });
    }

    // double-spend defense (b): same disputeId, different canonicalHash → IDEMPOTENCY_VIOLATION
    const existingDispute = await disputeStore.findByDisputeId(
        filing.disputeId,
    );
    if (existingDispute !== null) {
        // same disputeId but different canonicalHash → double-spend case
        if (existingDispute.disputeFilingCanonicalHash !== preCheckHash) {
            throw new DaError('DA_IDEMPOTENCY_VIOLATION', {
                reason: 'same_dispute_id_different_canonical_hash_double_filing_detected',
                disputeId: filing.disputeId,
                existingCanonicalHash:
                    existingDispute.disputeFilingCanonicalHash,
                newCanonicalHash: preCheckHash,
            });
        }
        // same disputeId, same canonicalHash → DUPLICATE_FILING (already caught in (a))
    }

    // ── Step 2: canonical hash computation + evidence-URI validation ─────────────────────────

    // canonical hash computation
    const filingCanonicalHash = computeDisputeFilingCanonicalHash(filing);

    // hash consistency check (signedPayload.canonicalHash must match)
    if (signedPayload.canonicalHash !== filingCanonicalHash) {
        throw new DaError('DA_CANONICAL_HASH_MISMATCH', {
            reason: 'signed_payload_canonical_hash_mismatch',
            expected: filingCanonicalHash,
            provided: signedPayload.canonicalHash,
        });
    }

    // evidence-URI validation (Port 3 active — EvidenceStore.validateEvidenceUris)
    const validatedUris = await evidenceStore.validateEvidenceUris(
        filing.evidenceUris,
    );

    // ── Step 3: CSP signature verification + freshness check + revocation-status check ─────────────────

    // freshness check (Port 5 active — SignatureVerifier.checkFreshness)
    signatureVerifier.checkFreshness(filing.notAfter);

    // revocation-status check — token (Port 4 active — RevocationChecker.isTokenRevoked)
    const isRevoked = await revocationChecker.isTokenRevoked(filing.token);
    if (isRevoked) {
        throw new DaError('DA_DISPUTE_REVOKED', {
            reason: 'csp_token_has_been_revoked',
            disputeId: filing.disputeId,
        });
    }

    // DID revocation check (Port 4 active — RevocationChecker.checkDidRevocationStatus)

    // fail-closed: must check the claimant + respondent DIDs + all selected arbitrator DIDs;
    // checking only the single claimant DID has insufficient coverage.
    // here we first check claimant + respondent (the arbitrator DID check is deferred until after the step 4 arbitrator-pool selection)
    await revocationChecker.checkDidRevocationStatus(filing.claimantDid);
    await revocationChecker.checkDidRevocationStatus(filing.respondentDid);

    // CSP signature verification (Port 5 active — SignatureVerifier.verifyDisputeFilingSignature)
    const sigValid =
        await signatureVerifier.verifyDisputeFilingSignature(signedPayload);
    if (!sigValid) {
        throw new DaError('DA_SIGNED_PAYLOAD_INVALID', {
            reason: 'dispute_filing_csp_signature_verification_failed',
            disputeId: filing.disputeId,
        });
    }

    // ── Step 4: arbitrator-pool selection + pool-size enforcement ──────────────────────────────

    // algorithm-layer enforcement (Constraint #1)
    const threshold = computeThreshold(poolSizeTarget);

    // arbitrator selection (Port 2 active — ArbitratorSelector.selectArbitrators)
    const arbitrators = await arbitratorSelector.selectArbitrators(
        filing.disputeId,
        poolSizeTarget,
    );

    // verify the selection result still satisfies the constraint
    if (arbitrators.length < MIN_ARBITRATOR_COUNT) {
        throw new DaError('DA_ARBITRATOR_INSUFFICIENT', {
            reason: 'selected_arbitrator_count_below_minimum',
            selected: arbitrators.length,
            minRequired: MIN_ARBITRATOR_COUNT,
        });
    }

    // arbitrator DID revocation check (fail-closed):
    // the revocation check must run before multisig signature verification (the signature of a revoked entity should not be accepted);
    // therefore it runs immediately after the step 4 arbitrator-pool selection.
    for (const arbitrator of arbitrators) {
        await revocationChecker.checkDidRevocationStatus(arbitrator.did);
    }

    // ── Step 5: multi-signature aggregation + threshold check ───────────────────────────────────

    // build the initial arbitration decision (unsigned)
    const nowIso = new Date().toISOString();
    const decisionCanonicalHash = toCanonicalHashHex(
        '0'.repeat(64), // placeholder; the actual hash is computed by MultisigPort after aggregation
    );

    const initialDecision: ArbitrationDecision = {
        decisionId: filing.disputeId, // use disputeId as the decisionId;
        disputeId: filing.disputeId,
        verdict,
        multisigThreshold: threshold,
        multisigPoolSize: poolSizeTarget,
        decisionCanonicalHash,
        arbitratorSignatures: [],
        decidedAt: nowIso,
    };

    // cross-field algorithm-layer guard:
    // if decision.multisigThreshold > decision.multisigPoolSize → throw DA_ARBITRATOR_INVALID
    if (initialDecision.multisigThreshold > initialDecision.multisigPoolSize) {
        throw new DaError('DA_ARBITRATOR_INVALID', {
            reason: 'multisig_threshold_exceeds_pool_size',
            multisigThreshold: initialDecision.multisigThreshold,
            multisigPoolSize: initialDecision.multisigPoolSize,
        });
    }

    // multi-signature aggregation (Port 1 active — MultisigPort.aggregateSignatures)
    const signedDecision = await multisigPort.aggregateSignatures(
        initialDecision,
        arbitrators,
        threshold,
    );

    // signature-count validation
    if (signedDecision.arbitratorSignatures.length < threshold) {
        throw new DaError('DA_INSUFFICIENT_SIGNATURES', {
            reason: 'insufficient_arbitrator_signatures_after_aggregation',
            required: threshold,
            actual: signedDecision.arbitratorSignatures.length,
        });
    }

    // full multisig validation (3 dimensions):
    // checking count >= threshold alone is insufficient; also required:
    // (a) signer uniqueness validation; (b) signer membership validation (must be in arbitrators set);
    // (c) signature crypto verify (via the MultisigPort.verifyArbitratorSignature port);
    // makes the multisig N-of-M robust;
    // all 3 dimensions are inline (uniqueness + membership + signature crypto verify)

    // dimension (a): signer uniqueness validation (Set-based O(N) deduplication)
    const seenSigners = new Set<string>();
    for (const sig of signedDecision.arbitratorSignatures) {
        if (seenSigners.has(sig.arbitratorDid)) {
            throw new DaError('DA_INSUFFICIENT_SIGNATURES', {
                reason: 'duplicate_arbitrator_signature_in_aggregation',
                duplicateDid: sig.arbitratorDid,
            });
        }
        seenSigners.add(sig.arbitratorDid);
    }

    // dimension (b): signer membership validation (must be in the selected arbitrators pool)
    const selectedDids = new Set(arbitrators.map((a) => a.did));
    for (const sig of signedDecision.arbitratorSignatures) {
        if (!selectedDids.has(sig.arbitratorDid)) {
            throw new DaError('DA_ARBITRATOR_INVALID', {
                reason: 'signer_not_in_selected_arbitrator_pool',
                signerDid: sig.arbitratorDid,
                selectedDids: Array.from(selectedDids),
            });
        }
    }

    // dimension (c): signature crypto verify (via the MultisigPort.verifyArbitratorSignature port)
    for (const sig of signedDecision.arbitratorSignatures) {
        const verified = await multisigPort.verifyArbitratorSignature(
            sig.arbitratorDid,
            sig.signature,
            signedDecision.decisionCanonicalHash,
        );
        if (!verified) {
            throw new DaError('DA_INSUFFICIENT_SIGNATURES', {
                reason: 'arbitrator_signature_crypto_verification_failed',
                signerDid: sig.arbitratorDid,
            });
        }
    }

    // ── Steps 6-7: atomic transaction wrapper ────────────────────────────────

    // If the 7 awaits run sequentially without a shared transaction context, then after any await #N fails
    // → committed operations cannot be rolled back → irreversible state corruption.

    // Therefore txManager.runInTransaction is given a real pg-style BEGIN/COMMIT/ROLLBACK;
    // all 7 awaits inside the callback run in the same transaction; any throw → transaction ROLLBACK + re-throw.
    // async cascade or hybrid implementations are strictly forbidden (synchronous only).

    // ── Step 6: dispute-record persistence + audit record (filed) ───────────────────────────

    // build the Dispute ledger entity (Step 6 preparation; built outside the tx to avoid unnecessary logic inside the tx)
    const dispute: Dispute = {
        disputeId: filing.disputeId,
        tenantId,
        currentState: 'FILED',
        disputeType: filing.disputeType,
        claimantDid: filing.claimantDid,
        respondentDid: filing.respondentDid,
        disputeFilingCanonicalHash: filingCanonicalHash,
        settlementOperationRef: filing.settlementOperationRef,
        evidenceUris: validatedUris,
        cspVersion: filing.cspVersion,
        daVersion: DA_VERSION_1_0_0,
        filedAt: filing.filedAt,
        attemptedAt: nowIso,
        createdAt: nowIso,
    };

    // 2-transition freeze validation (Constraint #5) — validated outside the tx; pure in-memory operation
    validateStateTransition('FILED', 'RESOLVED');

    // build resolvedAt + transitionEvent outside the tx (the timestamp is fixed before the tx starts; avoids time drift inside the tx)
    const resolvedAt = new Date().toISOString();

    const transitionEvent: DisputeStateTransitionEvent = {
        disputeId: filing.disputeId,
        fromState: 'FILED',
        toState: 'RESOLVED',
        transitionedAt: resolvedAt,
        triggeredBy: 'ARBITRATION_DECISION',
        auditClass: 'L2',
    };

    // build the final dispute entity (including resolvedAt; prepared outside the tx)
    const resolvedDispute: Dispute = {
        ...dispute,
        currentState: 'RESOLVED',
        resolvedAt,
    };

    // atomic transaction: all 7 awaits within the same BEGIN...COMMIT/ROLLBACK
    // await #1: saveDispute
    // await #2: recordDisputeFiled
    // await #3: storeEvidenceRef
    // await #4: updateDisputeState → RESOLVED
    // await #5: saveArbitrationDecision
    // await #6: recordDisputeTransition
    // await #7: recordArbitrationDecision
    await txManager.runInTransaction(async (ctx) => {
        // Step 6 — await #1: persist the dispute record (Port 7 active — DisputeStore.saveDispute)
        await disputeStore.saveDispute(dispute, ctx);

        // Step 6 — await #2: audit: dispute filed (Port 6 active — AtpRecorder.recordDisputeFiled)
        await atpRecorder.recordDisputeFiled(
            filing.disputeId,
            filingCanonicalHash,
            ctx,
        );

        // Step 6 — await #3: store evidence URIs (Port 3 active — EvidenceStore.storeEvidenceRef)
        await evidenceStore.storeEvidenceRef(
            filing.disputeId,
            validatedUris,
            ctx,
        );

        // Step 7 — await #4: persist the state transition (Port 7 active — DisputeStore.updateDisputeState)
        await disputeStore.updateDisputeState(
            filing.disputeId,
            'RESOLVED',
            resolvedAt,
            ctx,
        );

        // Step 7 — await #5: persist the arbitration decision (Port 7 active — DisputeStore.saveArbitrationDecision)
        await disputeStore.saveArbitrationDecision(signedDecision, ctx);

        // Step 7 — await #6: audit: state transition (Port 6 active — AtpRecorder.recordDisputeTransition)
        await atpRecorder.recordDisputeTransition(transitionEvent, ctx);

        // Step 7 — await #7: audit: arbitration decision (Port 6 active — AtpRecorder.recordArbitrationDecision)
        await atpRecorder.recordArbitrationDecision(
            filing.disputeId,
            signedDecision.decisionCanonicalHash,
            ctx,
        );
    });

    return {
        dispute: resolvedDispute,
        decision: signedDecision,
        transitionEvent,
    };
}

/**
 * runDisputeExpiry — timeout-expiry handling (FILED→EXPIRED)
 *
 * Called from a scheduled job or after step 1 catches DA_TIMEOUT_EXCEEDED;
 * performs the FILED→EXPIRED state transition + audit.
 *
 * Constraints #3 + #5: 14-day timeout + 2-transition freeze.
 */
export async function runDisputeExpiry(
    disputeId: DisputeId,
    disputeStore: DisputeStore,
    atpRecorder: AtpRecorder,
): Promise<void> {
    // 2-transition freeze validation
    validateStateTransition('FILED', 'EXPIRED');

    const expiredAt = new Date().toISOString();

    // persist the state transition
    await disputeStore.updateDisputeState(disputeId, 'EXPIRED', expiredAt);

    // audit: timeout transition event
    //
    // EXPIRED terminal state → reviewQueue: true (flag to enqueue into the manual-review queue)
    const transitionEvent: DisputeStateTransitionEvent = {
        disputeId,
        fromState: 'FILED',
        toState: 'EXPIRED',
        transitionedAt: expiredAt,
        triggeredBy: 'PC3_TIMEOUT_EXPIRY',
        auditClass: 'L2',
        reviewQueue: true,
    };

    await atpRecorder.recordDisputeTransition(transitionEvent);
}
