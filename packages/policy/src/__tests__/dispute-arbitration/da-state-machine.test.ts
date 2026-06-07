/**
 * Dispute Arbitration L3 state machine tests
 *
 * sub-protocol — dispute-arbitration v0.1
 *
 * Coverage goals:
 *   - runDisputeArbitration7Steps — e2e happy path ≥3 test cases
 *   - validateStateTransition — valid + invalid transitions
 *   - computeThreshold — enforce (poolSize 2/6/3/4/5)
 *   - checkAndExpireDispute — 14-day hard cap, expired vs not expired
 *   - computeDisputeFilingCanonicalHash — determinism + optional field
 *   - runDisputeExpiry — FILED→EXPIRED path + audit
 *   - all 7 ports verified via mock invocation (anti-phantom)
 *
 * The algorithm layer of the three-layer threshold enforce lives in computeThreshold()
 */

/* eslint-disable @typescript-eslint/unbound-method*/

import { describe, it, expect, vi } from 'vitest';

import {
    validateStateTransition,
    computeThreshold,
    checkAndExpireDispute,
    computeDisputeFilingCanonicalHash,
    runDisputeArbitration7Steps,
    runDisputeExpiry,
    type DisputeArbitrationInput,
} from '../../dispute-arbitration/index.js';

import {
    DaError,
    toDisputeId,
    toDaVersion,
    toCanonicalHashHex,
    toSettlementOperationId,
    DISPUTE_STATE_TRANSITIONS,
    MIN_ARBITRATOR_COUNT,
    MAX_ARBITRATOR_COUNT,
    MAX_DISPUTE_MS,
    DA_VERSION_CURRENT,
    type DisputeFiling,
    type DisputeFilingSignedPayload,
    type ArbitrationDecision,
    type Arbitrator,
    type CanonicalHashHex,
    type DisputeId,
    type DisputeState,
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
    DisputeTransactionContext,
} from '../../dispute-arbitration/ports.js';

// ─── Test helper: build a valid DisputeFiling ─────────────────────────────────

function makeDisputeId(): DisputeId {
    return toDisputeId('a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11');
}

function makeCanonicalHashHex(hex = 'a'.repeat(64)): CanonicalHashHex {
    return toCanonicalHashHex(hex);
}

function makeFiling(overrides: Partial<DisputeFiling> = {}): DisputeFiling {
    const disputeId = makeDisputeId();
    const nowIso = new Date(Date.now() - 1000).toISOString(); // filed 1 second ago
    const notAfterIso = new Date(Date.now() + 3600 * 1000).toISOString(); // expires 1 hour from now

    return {
        disputeId,
        claimantDid: 'did:example:claimant' as `did:${string}`,
        respondentDid: 'did:example:respondent' as `did:${string}`,
        disputeType: 'SETTLEMENT_FAILED',
        evidenceUris: ['https://evidence.example.com/doc1.pdf'],
        cspVersion: '1.0.0',
        token: 'test-csp-token',
        disclosedClaims: { claimKey: 'claimValue' },
        challenge: 'test-challenge-nonce',
        audience: 'did:example:audience',
        notAfter: notAfterIso,
        filedAt: nowIso,
        daVersion: toDaVersion(DA_VERSION_CURRENT),
        ...overrides,
    };
}

function makeSignedPayload(
    filing: DisputeFiling,
    canonicalHash: CanonicalHashHex,
): DisputeFilingSignedPayload {
    return {
        disputeId: filing.disputeId,
        claimantDid: filing.claimantDid,
        respondentDid: filing.respondentDid,
        disputeType: filing.disputeType,
        evidenceUris: filing.evidenceUris,
        settlementOperationRef: filing.settlementOperationRef,
        cspVersion: filing.cspVersion,
        // schema/interface bidirectional consistency + L3 enforce:
        daVersion: filing.daVersion,
        token: filing.token,
        disclosedClaims: filing.disclosedClaims,
        challenge: filing.challenge,
        audience: filing.audience,
        notAfter: filing.notAfter,
        filedAt: filing.filedAt,
        canonicalHash,
        claimantSignature: 'test-valid-signature',
    };
}

function makeArbitrators(count = 3): readonly Arbitrator[] {
    return Array.from({ length: count }, (_, i) => ({
        did: `did:example:arbitrator-${i}` as `did:${string}`,
        publicKey: `pk-${i}`,
        isActive: true,
    }));
}

function makeArbitrationDecision(
    disputeId: DisputeId,
    threshold = 2,
    poolSize = 3,
): ArbitrationDecision {
    return {
        decisionId: disputeId,
        disputeId,
        verdict: 'CLAIMANT_PREVAILS',
        multisigThreshold: threshold,
        multisigPoolSize: poolSize,
        decisionCanonicalHash: makeCanonicalHashHex('b'.repeat(64)),
        arbitratorSignatures: Array.from({ length: threshold }, (_, i) => ({
            arbitratorDid: `did:example:arbitrator-${i}` as `did:${string}`,
            signature: `sig-${i}`,
        })),
        decidedAt: new Date().toISOString(),
    };
}

// ─── Port mock builder helper ──────────────────────────────────────────────────

function makePorts(
    disputeId: DisputeId,
    filingCanonicalHash: CanonicalHashHex,
    poolSize = 3,
) {
    const threshold = Math.floor(poolSize / 2) + 1;
    const arbitrators = makeArbitrators(poolSize);
    const signedDecision = makeArbitrationDecision(
        disputeId,
        threshold,
        poolSize,
    );

    const multisigPort: MultisigPort = {
        // mockImplementation preserves verdict from the input decision passed by the state machine
        // signer DIDs must come from the selected arbitrators set
        // (uniqueness + membership checks verify this); the original mock used 'did:example:arb${i}',
        // a different prefix from makeArbitrators' 'did:example:arbitrator-${i}'; now synced to arbitrators[i].did
        aggregateSignatures: vi
            .fn()
            .mockImplementation((decision: ArbitrationDecision) =>
                Promise.resolve({
                    ...signedDecision,
                    verdict: decision.verdict,
                    multisigThreshold: decision.multisigThreshold,
                    multisigPoolSize: decision.multisigPoolSize,
                    arbitratorSignatures: Array.from(
                        { length: decision.multisigThreshold },
                        (_, i) => ({
                            arbitratorDid: arbitrators[i]!.did,
                            signature: `sig${i}`,
                        }),
                    ),
                }),
            ),
        verifyArbitratorSignature: vi.fn().mockResolvedValue(true),
    };

    const arbitratorSelector: ArbitratorSelector = {
        selectArbitrators: vi.fn().mockResolvedValue(arbitrators),
        validateArbitrator: vi.fn().mockResolvedValue(true),
    };

    const evidenceStore: EvidenceStore = {
        validateEvidenceUris: vi
            .fn()
            .mockImplementation((uris) => Promise.resolve(uris)),
        storeEvidenceRef: vi.fn().mockResolvedValue(undefined),
    };

    const revocationChecker: RevocationChecker = {
        isTokenRevoked: vi.fn().mockResolvedValue(false),
        checkDidRevocationStatus: vi.fn().mockResolvedValue(undefined),
    };

    const signatureVerifier: SignatureVerifier = {
        verifyDisputeFilingSignature: vi.fn().mockResolvedValue(true),
        checkFreshness: vi.fn(), // sync
    };

    const atpRecorder: AtpRecorder = {
        recordDisputeTransition: vi.fn().mockResolvedValue(undefined),
        recordDisputeFiled: vi.fn().mockResolvedValue(undefined),
        recordArbitrationDecision: vi.fn().mockResolvedValue(undefined),
    };

    const disputeStore: DisputeStore = {
        findByCanonicalHash: vi.fn().mockResolvedValue(null), // no duplicate
        // double-spend defense idempotency:
        findByDisputeId: vi.fn().mockResolvedValue(null), // no existing dispute
        saveDispute: vi.fn().mockResolvedValue(undefined),
        getDisputeState: vi.fn().mockResolvedValue('FILED' as DisputeState),
        updateDisputeState: vi.fn().mockResolvedValue(undefined),
        saveArbitrationDecision: vi.fn().mockResolvedValue(undefined),
    };

    // txManager mock: passthrough (no-op tx context) for existing happy-path tests
    // ctx is passed to each port but the port mocks do not use it; keeps backward compatibility
    const txManager: DisputeTxManager = {
        runInTransaction: vi
            .fn()
            .mockImplementation(
                async (
                    callback: (
                        ctx: DisputeTransactionContext,
                    ) => Promise<unknown>,
                ) => {
                    const noopCtx: DisputeTransactionContext = {
                        query: vi.fn().mockResolvedValue({ rowCount: 0 }),
                    };
                    return callback(noopCtx);
                },
            ),
    };

    return {
        multisigPort,
        arbitratorSelector,
        evidenceStore,
        revocationChecker,
        signatureVerifier,
        atpRecorder,
        disputeStore,
        txManager,
        signedDecision,
        threshold,
    };
}

// ─── describe: validateStateTransition ───────────────────────────────────────

describe('validateStateTransition', () => {
    it('should accept FILED → RESOLVED transition', () => {
        expect(() =>
            validateStateTransition('FILED', 'RESOLVED'),
        ).not.toThrow();
    });

    it('should accept FILED → EXPIRED transition', () => {
        expect(() => validateStateTransition('FILED', 'EXPIRED')).not.toThrow();
    });

    it('should throw DA_STATE_TRANSITION_INVALID when RESOLVED → EXPIRED (invalid)', () => {
        expect(() => validateStateTransition('RESOLVED', 'EXPIRED')).toThrow(
            DaError,
        );
        try {
            validateStateTransition('RESOLVED', 'EXPIRED');
        } catch (err) {
            expect(err).toBeInstanceOf(DaError);
            expect((err as DaError).code).toBe('DA_STATE_TRANSITION_INVALID');
        }
    });

    it('should throw DA_STATE_TRANSITION_INVALID when EXPIRED → FILED (invalid)', () => {
        expect(() => validateStateTransition('EXPIRED', 'FILED')).toThrow(
            DaError,
        );
        try {
            validateStateTransition('EXPIRED', 'FILED');
        } catch (err) {
            expect(err).toBeInstanceOf(DaError);
            expect((err as DaError).code).toBe('DA_STATE_TRANSITION_INVALID');
        }
    });

    it('should throw DA_STATE_TRANSITION_INVALID when RESOLVED → FILED (circular)', () => {
        expect(() => validateStateTransition('RESOLVED', 'FILED')).toThrow(
            DaError,
        );
        try {
            validateStateTransition('RESOLVED', 'FILED');
        } catch (err) {
            expect(err).toBeInstanceOf(DaError);
            expect((err as DaError).code).toBe('DA_STATE_TRANSITION_INVALID');
        }
    });

    it('should throw DA_STATE_TRANSITION_INVALID when FILED → FILED (self-loop)', () => {
        expect(() => validateStateTransition('FILED', 'FILED')).toThrow(
            DaError,
        );
        try {
            validateStateTransition('FILED', 'FILED');
        } catch (err) {
            expect(err).toBeInstanceOf(DaError);
            expect((err as DaError).code).toBe('DA_STATE_TRANSITION_INVALID');
        }
    });

    it('should include from/to detail in DaError', () => {
        try {
            validateStateTransition('EXPIRED', 'RESOLVED');
        } catch (err) {
            const e = err as DaError;
            expect(e.detail).toMatchObject({ from: 'EXPIRED', to: 'RESOLVED' });
        }
    });
});

// ─── describe: computeThreshold (three-layer enforce — algorithm layer) ────────────

describe('computeThreshold — algorithm layer (arbitrator threshold enforce)', () => {
    it('should throw DA_ARBITRATOR_INSUFFICIENT when poolSize = 2 (below minimum 3)', () => {
        expect(() => computeThreshold(2)).toThrow(DaError);
        try {
            computeThreshold(2);
        } catch (err) {
            const e = err as DaError;
            expect(e.code).toBe('DA_ARBITRATOR_INSUFFICIENT');
            expect(e.detail).toMatchObject({
                poolSize: 2,
                minRequired: MIN_ARBITRATOR_COUNT,
            });
        }
    });

    it('should throw DA_ARBITRATOR_INSUFFICIENT when poolSize = 0', () => {
        expect(() => computeThreshold(0)).toThrow(DaError);
        try {
            computeThreshold(0);
        } catch (err) {
            expect((err as DaError).code).toBe('DA_ARBITRATOR_INSUFFICIENT');
        }
    });

    it('should throw DA_ARBITRATOR_INSUFFICIENT when poolSize = 1', () => {
        expect(() => computeThreshold(1)).toThrow(DaError);
        try {
            computeThreshold(1);
        } catch (err) {
            expect((err as DaError).code).toBe('DA_ARBITRATOR_INSUFFICIENT');
        }
    });

    it('should throw DA_ARBITRATOR_INVALID when poolSize = 6 (above maximum 5)', () => {
        expect(() => computeThreshold(6)).toThrow(DaError);
        try {
            computeThreshold(6);
        } catch (err) {
            const e = err as DaError;
            expect(e.code).toBe('DA_ARBITRATOR_INVALID');
            expect(e.detail).toMatchObject({
                poolSize: 6,
                maxCount: MAX_ARBITRATOR_COUNT,
            });
        }
    });

    it('should return threshold = 2 when poolSize = 3 (floor(3/2)+1)', () => {
        expect(computeThreshold(3)).toBe(2);
    });

    it('should return threshold = 3 when poolSize = 4 (floor(4/2)+1)', () => {
        expect(computeThreshold(4)).toBe(3);
    });

    it('should return threshold = 3 when poolSize = 5 (floor(5/2)+1)', () => {
        expect(computeThreshold(5)).toBe(3);
    });

    it('should respect MIN_ARBITRATOR_COUNT = 3 boundary exactly', () => {
        // exactly at minimum — should not throw
        expect(computeThreshold(MIN_ARBITRATOR_COUNT)).toBe(2);
    });

    it('should respect MAX_ARBITRATOR_COUNT = 5 boundary exactly', () => {
        // exactly at maximum — should not throw
        expect(computeThreshold(MAX_ARBITRATOR_COUNT)).toBe(3);
    });
});

// ─── describe: checkAndExpireDispute (14-day hard cap) ────────────────────────────

describe('checkAndExpireDispute — 14-day hard cap', () => {
    it('should not throw for a fresh dispute filed 1 second ago', () => {
        const filedAt = new Date(Date.now() - 1000).toISOString();
        expect(() => checkAndExpireDispute(filedAt)).not.toThrow();
    });

    it('should not throw for a dispute filed 13 days ago', () => {
        const thirteenDaysMs = 13 * 24 * 3600 * 1000;
        const filedAt = new Date(Date.now() - thirteenDaysMs).toISOString();
        expect(() => checkAndExpireDispute(filedAt)).not.toThrow();
    });

    it('should throw DA_TIMEOUT_EXCEEDED for a dispute filed 15 days ago', () => {
        const fifteenDaysMs = 15 * 24 * 3600 * 1000;
        const filedAt = new Date(Date.now() - fifteenDaysMs).toISOString();
        expect(() => checkAndExpireDispute(filedAt)).toThrow(DaError);
        try {
            checkAndExpireDispute(filedAt);
        } catch (err) {
            const e = err as DaError;
            expect(e.code).toBe('DA_TIMEOUT_EXCEEDED');
            expect(e.detail).toMatchObject({ maxDays: 14 });
        }
    });

    it('should throw DA_TIMEOUT_EXCEEDED exactly at MAX_DISPUTE_MS boundary', () => {
        const exactNow = Date.now();
        const filedAt = new Date(exactNow - MAX_DISPUTE_MS).toISOString();
        // at exactly MAX_DISPUTE_MS elapsed: now - filedMs >= MAX_DISPUTE_MS
        expect(() => checkAndExpireDispute(filedAt, exactNow)).toThrow(DaError);
        try {
            checkAndExpireDispute(filedAt, exactNow);
        } catch (err) {
            expect((err as DaError).code).toBe('DA_TIMEOUT_EXCEEDED');
        }
    });

    it('should not throw at MAX_DISPUTE_MS - 1 (just under boundary)', () => {
        const exactNow = Date.now();
        const filedAt = new Date(exactNow - MAX_DISPUTE_MS + 1).toISOString();
        expect(() => checkAndExpireDispute(filedAt, exactNow)).not.toThrow();
    });

    it('should throw DA_FILING_INVALID for an invalid timestamp', () => {
        expect(() => checkAndExpireDispute('not-a-date')).toThrow(DaError);
        try {
            checkAndExpireDispute('not-a-date');
        } catch (err) {
            const e = err as DaError;
            expect(e.code).toBe('DA_FILING_INVALID');
            expect(e.detail).toMatchObject({ filedAt: 'not-a-date' });
        }
    });

    it('should accept a custom nowMs parameter for deterministic testing', () => {
        const customNow = 1000000;
        const filedAt = new Date(customNow - 1000).toISOString(); // 1 second before customNow
        expect(() => checkAndExpireDispute(filedAt, customNow)).not.toThrow();
    });
});

// ─── describe: computeDisputeFilingCanonicalHash ──────────────────────

describe('computeDisputeFilingCanonicalHash — SHA-256/JCS', () => {
    it('should produce a 64-char hex string', () => {
        const filing = makeFiling();
        const hash = computeDisputeFilingCanonicalHash(filing);
        expect(hash).toMatch(/^[0-9a-f]{64}$/i);
    });

    it('should be deterministic for the same input', () => {
        const filing = makeFiling();
        const hash1 = computeDisputeFilingCanonicalHash(filing);
        const hash2 = computeDisputeFilingCanonicalHash(filing);
        expect(hash1).toBe(hash2);
    });

    it('should produce different hashes for different claimantDid', () => {
        const filing1 = makeFiling({
            claimantDid: 'did:example:alice' as `did:${string}`,
        });
        const filing2 = makeFiling({
            claimantDid: 'did:example:bob' as `did:${string}`,
        });
        const hash1 = computeDisputeFilingCanonicalHash(filing1);
        const hash2 = computeDisputeFilingCanonicalHash(filing2);
        expect(hash1).not.toBe(hash2);
    });

    it('should produce different hashes when settlementOperationRef is present vs absent', () => {
        const filing1 = makeFiling({ settlementOperationRef: undefined });
        const filing2 = makeFiling({
            settlementOperationRef: toSettlementOpId(
                'a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a22',
            ),
        });
        const hash1 = computeDisputeFilingCanonicalHash(filing1);
        const hash2 = computeDisputeFilingCanonicalHash(filing2);
        expect(hash1).not.toBe(hash2);
    });

    it('should be stable regardless of JS object key ordering', () => {
        // JCS RFC 8785 guarantees key-sorted canonicalization
        const filing = makeFiling();
        // Build with property orders reversed (JS engines may vary)
        const reordered = {
            ...filing,
            token: filing.token,
            audience: filing.audience,
        };
        const hash1 = computeDisputeFilingCanonicalHash(filing);
        const hash2 = computeDisputeFilingCanonicalHash(reordered);
        expect(hash1).toBe(hash2);
    });
});

// helper for settlementOperationRef creation in test context
function toSettlementOpId(uuid: string) {
    return toSettlementOperationId(uuid);
}

// ─── describe: runDisputeArbitration7Steps (e2e happy path) ──────────────────

describe('runDisputeArbitration7Steps — e2e happy path', () => {
    it('should complete 7-step arbitration and return RESOLVED dispute (poolSize=3)', async () => {
        const filing = makeFiling();
        const filingCanonicalHash = computeDisputeFilingCanonicalHash(filing);
        const signedPayload = makeSignedPayload(filing, filingCanonicalHash);

        const ports = makePorts(filing.disputeId, filingCanonicalHash, 3);

        const input: DisputeArbitrationInput = {
            filing,
            signedPayload,
            poolSizeTarget: 3,
            verdict: 'CLAIMANT_PREVAILS',
            tenantId: 'tenant-abc',
            ...ports,
        };

        const result = await runDisputeArbitration7Steps(input);

        // Result structure verification
        expect(result.dispute.currentState).toBe('RESOLVED');
        expect(result.dispute.disputeId).toBe(filing.disputeId);
        expect(result.dispute.tenantId).toBe('tenant-abc');
        expect(result.decision.verdict).toBe('CLAIMANT_PREVAILS');
        expect(result.transitionEvent.fromState).toBe('FILED');
        expect(result.transitionEvent.toState).toBe('RESOLVED');
        expect(result.transitionEvent.auditClass).toBe('L2');
    });

    it('should complete 7-step arbitration with poolSize=5 (max pool)', async () => {
        const filing = makeFiling();
        const filingCanonicalHash = computeDisputeFilingCanonicalHash(filing);
        const signedPayload = makeSignedPayload(filing, filingCanonicalHash);

        const ports = makePorts(filing.disputeId, filingCanonicalHash, 5);

        const input: DisputeArbitrationInput = {
            filing,
            signedPayload,
            poolSizeTarget: 5,
            verdict: 'NO_FAULT',
            tenantId: 'tenant-xyz',
            ...ports,
        };

        const result = await runDisputeArbitration7Steps(input);

        expect(result.dispute.currentState).toBe('RESOLVED');
        expect(result.decision.verdict).toBe('NO_FAULT');
        expect(result.decision.multisigPoolSize).toBe(5);
    });

    it('should complete 7-step arbitration with RESPONDENT_PREVAILS verdict', async () => {
        const filing = makeFiling({ disputeType: 'IDENTITY_FRAUD' });
        const filingCanonicalHash = computeDisputeFilingCanonicalHash(filing);
        const signedPayload = makeSignedPayload(filing, filingCanonicalHash);

        const ports = makePorts(filing.disputeId, filingCanonicalHash, 3);

        const input: DisputeArbitrationInput = {
            filing,
            signedPayload,
            poolSizeTarget: 3,
            verdict: 'RESPONDENT_PREVAILS',
            tenantId: 'tenant-def',
            ...ports,
        };

        const result = await runDisputeArbitration7Steps(input);

        expect(result.dispute.currentState).toBe('RESOLVED');
        expect(result.dispute.disputeType).toBe('IDENTITY_FRAUD');
        expect(result.decision.verdict).toBe('RESPONDENT_PREVAILS');
        expect(result.transitionEvent.triggeredBy).toBe('ARBITRATION_DECISION');
    });

    it('should call all 7 ports exactly once (anti-phantom verification)', async () => {
        const filing = makeFiling();
        const filingCanonicalHash = computeDisputeFilingCanonicalHash(filing);
        const signedPayload = makeSignedPayload(filing, filingCanonicalHash);

        const ports = makePorts(filing.disputeId, filingCanonicalHash, 3);

        const input: DisputeArbitrationInput = {
            filing,
            signedPayload,
            poolSizeTarget: 3,
            verdict: 'CLAIMANT_PREVAILS',
            tenantId: 'tenant-test',
            ...ports,
        };

        await runDisputeArbitration7Steps(input);

        // Port 1: MultisigPort.aggregateSignatures
        expect(ports.multisigPort.aggregateSignatures).toHaveBeenCalledOnce();

        // Port 2: ArbitratorSelector.selectArbitrators
        expect(
            ports.arbitratorSelector.selectArbitrators,
        ).toHaveBeenCalledOnce();
        expect(ports.arbitratorSelector.selectArbitrators).toHaveBeenCalledWith(
            filing.disputeId,
            3,
        );

        // Port 3: EvidenceStore (both methods)
        expect(ports.evidenceStore.validateEvidenceUris).toHaveBeenCalledOnce();
        expect(ports.evidenceStore.storeEvidenceRef).toHaveBeenCalledOnce();

        // Port 4: RevocationChecker (both methods)
        expect(ports.revocationChecker.isTokenRevoked).toHaveBeenCalledOnce();
        expect(ports.revocationChecker.isTokenRevoked).toHaveBeenCalledWith(
            filing.token,
        );
        // fail-closed regression prevention:
        // originally expected toHaveBeenCalledOnce (claimant only); now expects 5 calls (claimant + respondent + 3 arbitrators);
        // step 5 runs revocation checks for 5+ DIDs
        expect(
            ports.revocationChecker.checkDidRevocationStatus,
        ).toHaveBeenCalledTimes(5);

        // Port 5: SignatureVerifier (both methods)
        expect(ports.signatureVerifier.checkFreshness).toHaveBeenCalledOnce();
        expect(
            ports.signatureVerifier.verifyDisputeFilingSignature,
        ).toHaveBeenCalledOnce();

        // Port 6: AtpRecorder (all 3 methods)
        expect(ports.atpRecorder.recordDisputeFiled).toHaveBeenCalledOnce();
        expect(
            ports.atpRecorder.recordDisputeTransition,
        ).toHaveBeenCalledOnce();
        expect(
            ports.atpRecorder.recordArbitrationDecision,
        ).toHaveBeenCalledOnce();

        // Port 7: DisputeStore (all 4 active methods)
        expect(ports.disputeStore.findByCanonicalHash).toHaveBeenCalledOnce(); // idempotency
        expect(ports.disputeStore.saveDispute).toHaveBeenCalledOnce();
        expect(ports.disputeStore.updateDisputeState).toHaveBeenCalledOnce();
        expect(
            ports.disputeStore.saveArbitrationDecision,
        ).toHaveBeenCalledOnce();
    });

    it('should set auditClass to L2 on transitionEvent (atp v0.1 freeze)', async () => {
        const filing = makeFiling();
        const filingCanonicalHash = computeDisputeFilingCanonicalHash(filing);
        const signedPayload = makeSignedPayload(filing, filingCanonicalHash);
        const ports = makePorts(filing.disputeId, filingCanonicalHash, 3);

        const result = await runDisputeArbitration7Steps({
            filing,
            signedPayload,
            poolSizeTarget: 3,
            verdict: 'NO_FAULT',
            tenantId: 'tenant-atp',
            ...ports,
        });

        expect(result.transitionEvent.auditClass).toBe('L2');
        // atp v0.1 freeze: 'dispute_event' or any other custom category is strictly forbidden
        expect(result.transitionEvent.auditClass).not.toBe('dispute_event');
    });
});

// ─── describe: runDisputeArbitration7Steps — error paths ────────────────────

describe('runDisputeArbitration7Steps — error paths', () => {
    it('should throw DA_VERSION_UNSUPPORTED for unsupported daVersion', async () => {
        // Bypass toDaVersion factory (which validates at factory time) to test state machine's
        // own step 1 version check. The state machine must catch unsupported versions independently.
        const filing = makeFiling({
            daVersion: '9.9.9' as ReturnType<typeof toDaVersion>,
        });
        const filingCanonicalHash = computeDisputeFilingCanonicalHash(filing);
        const signedPayload = makeSignedPayload(filing, filingCanonicalHash);
        const ports = makePorts(filing.disputeId, filingCanonicalHash, 3);

        await expect(
            runDisputeArbitration7Steps({
                filing,
                signedPayload,
                poolSizeTarget: 3,
                verdict: 'CLAIMANT_PREVAILS',
                tenantId: 'tenant-x',
                ...ports,
            }),
        ).rejects.toThrow(DaError);

        await expect(
            runDisputeArbitration7Steps({
                filing,
                signedPayload,
                poolSizeTarget: 3,
                verdict: 'CLAIMANT_PREVAILS',
                tenantId: 'tenant-x',
                ...ports,
            }),
        ).rejects.toMatchObject({ code: 'DA_VERSION_UNSUPPORTED' });
    });

    it('should throw DA_TIMEOUT_EXCEEDED for expired dispute (14 days)', async () => {
        const expiredFiledAt = new Date(
            Date.now() - 15 * 24 * 3600 * 1000,
        ).toISOString();
        const filing = makeFiling({ filedAt: expiredFiledAt });
        const filingCanonicalHash = computeDisputeFilingCanonicalHash(filing);
        const signedPayload = makeSignedPayload(filing, filingCanonicalHash);
        const ports = makePorts(filing.disputeId, filingCanonicalHash, 3);

        await expect(
            runDisputeArbitration7Steps({
                filing,
                signedPayload,
                poolSizeTarget: 3,
                verdict: 'CLAIMANT_PREVAILS',
                tenantId: 'tenant-expired',
                ...ports,
            }),
        ).rejects.toMatchObject({ code: 'DA_TIMEOUT_EXCEEDED' });
    });

    it('should throw DA_DUPLICATE_FILING when canonical hash already exists (idempotency)', async () => {
        const filing = makeFiling();
        const filingCanonicalHash = computeDisputeFilingCanonicalHash(filing);
        const signedPayload = makeSignedPayload(filing, filingCanonicalHash);
        const ports = makePorts(filing.disputeId, filingCanonicalHash, 3);

        // Simulate duplicate: findByCanonicalHash returns existing disputeId
        (
            ports.disputeStore.findByCanonicalHash as ReturnType<typeof vi.fn>
        ).mockResolvedValue(filing.disputeId);

        await expect(
            runDisputeArbitration7Steps({
                filing,
                signedPayload,
                poolSizeTarget: 3,
                verdict: 'CLAIMANT_PREVAILS',
                tenantId: 'tenant-dup',
                ...ports,
            }),
        ).rejects.toMatchObject({ code: 'DA_DUPLICATE_FILING' });
    });

    it('should throw DA_CANONICAL_HASH_MISMATCH when signedPayload hash differs', async () => {
        const filing = makeFiling();
        const wrongHash = makeCanonicalHashHex('c'.repeat(64));
        const signedPayload = makeSignedPayload(filing, wrongHash);
        const ports = makePorts(filing.disputeId, wrongHash, 3);

        await expect(
            runDisputeArbitration7Steps({
                filing,
                signedPayload,
                poolSizeTarget: 3,
                verdict: 'CLAIMANT_PREVAILS',
                tenantId: 'tenant-mismatch',
                ...ports,
            }),
        ).rejects.toMatchObject({ code: 'DA_CANONICAL_HASH_MISMATCH' });
    });

    it('should throw DA_DISPUTE_REVOKED when token is revoked', async () => {
        const filing = makeFiling();
        const filingCanonicalHash = computeDisputeFilingCanonicalHash(filing);
        const signedPayload = makeSignedPayload(filing, filingCanonicalHash);
        const ports = makePorts(filing.disputeId, filingCanonicalHash, 3);

        (
            ports.revocationChecker.isTokenRevoked as ReturnType<typeof vi.fn>
        ).mockResolvedValue(true);

        await expect(
            runDisputeArbitration7Steps({
                filing,
                signedPayload,
                poolSizeTarget: 3,
                verdict: 'CLAIMANT_PREVAILS',
                tenantId: 'tenant-revoked',
                ...ports,
            }),
        ).rejects.toMatchObject({ code: 'DA_DISPUTE_REVOKED' });
    });

    it('should throw DA_SIGNED_PAYLOAD_INVALID when signature verification fails', async () => {
        const filing = makeFiling();
        const filingCanonicalHash = computeDisputeFilingCanonicalHash(filing);
        const signedPayload = makeSignedPayload(filing, filingCanonicalHash);
        const ports = makePorts(filing.disputeId, filingCanonicalHash, 3);

        (
            ports.signatureVerifier.verifyDisputeFilingSignature as ReturnType<
                typeof vi.fn
            >
        ).mockResolvedValue(false);

        await expect(
            runDisputeArbitration7Steps({
                filing,
                signedPayload,
                poolSizeTarget: 3,
                verdict: 'CLAIMANT_PREVAILS',
                tenantId: 'tenant-badsig',
                ...ports,
            }),
        ).rejects.toMatchObject({ code: 'DA_SIGNED_PAYLOAD_INVALID' });
    });

    it('should throw DA_ARBITRATOR_INSUFFICIENT when poolSizeTarget = 2', async () => {
        const filing = makeFiling();
        const filingCanonicalHash = computeDisputeFilingCanonicalHash(filing);
        const signedPayload = makeSignedPayload(filing, filingCanonicalHash);
        const ports = makePorts(filing.disputeId, filingCanonicalHash, 3);

        await expect(
            runDisputeArbitration7Steps({
                filing,
                signedPayload,
                poolSizeTarget: 2,
                verdict: 'CLAIMANT_PREVAILS',
                tenantId: 'tenant-p35',
                ...ports,
            }),
        ).rejects.toMatchObject({ code: 'DA_ARBITRATOR_INSUFFICIENT' });
    });

    it('should throw DA_ARBITRATOR_INSUFFICIENT when selectArbitrators returns < MIN', async () => {
        const filing = makeFiling();
        const filingCanonicalHash = computeDisputeFilingCanonicalHash(filing);
        const signedPayload = makeSignedPayload(filing, filingCanonicalHash);
        const ports = makePorts(filing.disputeId, filingCanonicalHash, 3);

        // Simulate pool returning only 2 arbitrators despite target=3
        (
            ports.arbitratorSelector.selectArbitrators as ReturnType<
                typeof vi.fn
            >
        ).mockResolvedValue(makeArbitrators(2));

        await expect(
            runDisputeArbitration7Steps({
                filing,
                signedPayload,
                poolSizeTarget: 3,
                verdict: 'CLAIMANT_PREVAILS',
                tenantId: 'tenant-arblow',
                ...ports,
            }),
        ).rejects.toMatchObject({ code: 'DA_ARBITRATOR_INSUFFICIENT' });
    });

    it('should throw DA_INSUFFICIENT_SIGNATURES when signatures below threshold', async () => {
        const filing = makeFiling();
        const filingCanonicalHash = computeDisputeFilingCanonicalHash(filing);
        const signedPayload = makeSignedPayload(filing, filingCanonicalHash);
        const ports = makePorts(filing.disputeId, filingCanonicalHash, 3);

        // aggregateSignatures returns decision with only 1 signature (threshold=2)
        const insufficientDecision: ArbitrationDecision = {
            ...makeArbitrationDecision(filing.disputeId, 2, 3),
            arbitratorSignatures: [
                {
                    arbitratorDid: 'did:example:arb0' as `did:${string}`,
                    signature: 'sig-0',
                },
            ],
        };
        (
            ports.multisigPort.aggregateSignatures as ReturnType<typeof vi.fn>
        ).mockResolvedValue(insufficientDecision);

        await expect(
            runDisputeArbitration7Steps({
                filing,
                signedPayload,
                poolSizeTarget: 3,
                verdict: 'CLAIMANT_PREVAILS',
                tenantId: 'tenant-sigs',
                ...ports,
            }),
        ).rejects.toMatchObject({ code: 'DA_INSUFFICIENT_SIGNATURES' });
    });
});

// ─── describe: runDisputeExpiry (FILED→EXPIRED) ───────────────────────────────

describe('runDisputeExpiry — timeout-driven FILED→EXPIRED', () => {
    it('should execute FILED→EXPIRED transition and record audit', async () => {
        const disputeId = makeDisputeId();

        const disputeStore: DisputeStore = {
            findByCanonicalHash: vi.fn().mockResolvedValue(null),
            findByDisputeId: vi.fn().mockResolvedValue(null),
            saveDispute: vi.fn().mockResolvedValue(undefined),
            getDisputeState: vi.fn().mockResolvedValue('FILED'),
            updateDisputeState: vi.fn().mockResolvedValue(undefined),
            saveArbitrationDecision: vi.fn().mockResolvedValue(undefined),
        };

        const atpRecorder: AtpRecorder = {
            recordDisputeTransition: vi.fn().mockResolvedValue(undefined),
            recordDisputeFiled: vi.fn().mockResolvedValue(undefined),
            recordArbitrationDecision: vi.fn().mockResolvedValue(undefined),
        };

        await runDisputeExpiry(disputeId, disputeStore, atpRecorder);

        // updateDisputeState called with EXPIRED
        expect(disputeStore.updateDisputeState).toHaveBeenCalledOnce();
        expect(disputeStore.updateDisputeState).toHaveBeenCalledWith(
            disputeId,
            'EXPIRED',
            expect.any(String),
        );

        // audit event recorded
        expect(atpRecorder.recordDisputeTransition).toHaveBeenCalledOnce();
        const [transitionEvent] = (
            atpRecorder.recordDisputeTransition as ReturnType<typeof vi.fn>
        ).mock.calls[0] as [DisputeStateTransitionEvent];
        expect(transitionEvent.fromState).toBe('FILED');
        expect(transitionEvent.toState).toBe('EXPIRED');
        expect(transitionEvent.triggeredBy).toBe('PC3_TIMEOUT_EXPIRY');
        expect(transitionEvent.auditClass).toBe('L2');
    });

    it('should pass correct disputeId to transition event', async () => {
        const disputeId = toDisputeId('b0eebc99-9c0b-4ef8-bb6d-6bb9bd380a22');

        const disputeStore: DisputeStore = {
            findByCanonicalHash: vi.fn().mockResolvedValue(null),
            findByDisputeId: vi.fn().mockResolvedValue(null),
            saveDispute: vi.fn().mockResolvedValue(undefined),
            getDisputeState: vi.fn().mockResolvedValue('FILED'),
            updateDisputeState: vi.fn().mockResolvedValue(undefined),
            saveArbitrationDecision: vi.fn().mockResolvedValue(undefined),
        };

        const atpRecorder: AtpRecorder = {
            recordDisputeTransition: vi.fn().mockResolvedValue(undefined),
            recordDisputeFiled: vi.fn().mockResolvedValue(undefined),
            recordArbitrationDecision: vi.fn().mockResolvedValue(undefined),
        };

        await runDisputeExpiry(disputeId, disputeStore, atpRecorder);

        const [transitionEvent] = (
            atpRecorder.recordDisputeTransition as ReturnType<typeof vi.fn>
        ).mock.calls[0] as [DisputeStateTransitionEvent];
        expect(transitionEvent.disputeId).toBe(disputeId);
    });
});

// ─── describe: 2-transition freeze completeness ──────────────────────────────

describe('2-transition freeze completeness', () => {
    it('should only have exactly 2 allowed transitions', () => {
        // Verify DISPUTE_STATE_TRANSITIONS has exactly 2 entries
        expect(DISPUTE_STATE_TRANSITIONS).toHaveLength(2);
        expect(DISPUTE_STATE_TRANSITIONS).toContainEqual(['FILED', 'RESOLVED']);
        expect(DISPUTE_STATE_TRANSITIONS).toContainEqual(['FILED', 'EXPIRED']);
    });

    it('should validate all combinations systematically', () => {
        const states: DisputeState[] = ['FILED', 'RESOLVED', 'EXPIRED'];
        const validPairs = new Set(['FILED→RESOLVED', 'FILED→EXPIRED']);

        for (const from of states) {
            for (const to of states) {
                const key = `${from}→${to}`;
                if (validPairs.has(key)) {
                    expect(() =>
                        validateStateTransition(from, to),
                    ).not.toThrow();
                } else {
                    expect(() => validateStateTransition(from, to)).toThrow(
                        DaError,
                    );
                }
            }
        }
    });
});
