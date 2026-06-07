/**
 * Dispute arbitration atomic transaction fault-injection tests
 *
 * Rationale:
 *   the original 7 sequential awaits had no shared transaction context;
 *   after any await #N fails, already-committed operations cannot be rolled back
 *   → irreversible state corruption.
 *
 * Test goals:
 *   - happy path: all 7 awaits PASS → dispute RESOLVED + three-way verify (dispute/decision/audit)
 *   - fault at await #N (N=1..7): inject throw → transaction ROLLBACK
 *       · dispute state stays PENDING (saveDispute not committed)
 *       · no partial decision (saveArbitrationDecision not committed)
 *       · no partial audit events (recordDisputeFiled/recordDisputeTransition/recordArbitrationDecision not committed)
 *       · txManager.runInTransaction callback throws the original error
 *
 * Anti-phantom guard:
 *   txManager must implement real BEGIN/COMMIT/ROLLBACK semantics;
 *   the test simulates a real transaction by tracking the committed set;
 *   after fault injection it verifies the committed set is empty (ROLLBACK effect).
 */

/* eslint-disable @typescript-eslint/unbound-method*/

import { describe, it, expect, vi, beforeEach } from 'vitest';

import {
    computeDisputeFilingCanonicalHash,
    runDisputeArbitration7Steps,
    type DisputeArbitrationInput,
} from '../../dispute-arbitration/index.js';

import {
    DaError,
    toDisputeId,
    toDaVersion,
    toCanonicalHashHex,
    DA_VERSION_CURRENT,
    type DisputeFiling,
    type DisputeFilingSignedPayload,
    type ArbitrationDecision,
    type Arbitrator,
    type CanonicalHashHex,
    type DisputeId,
    type DisputeState,
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

// ─── Test helpers ─────────────────────────────────────────────────────────────

function makeDisputeId(suffix = '0'): DisputeId {
    return toDisputeId(`a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a1${suffix}`);
}

function makeCanonicalHashHex(char = 'a'): CanonicalHashHex {
    return toCanonicalHashHex(char.repeat(64));
}

function makeFiling(overrides: Partial<DisputeFiling> = {}): DisputeFiling {
    const disputeId = makeDisputeId('1');
    const nowIso = new Date(Date.now() - 1000).toISOString();
    const notAfterIso = new Date(Date.now() + 3600 * 1000).toISOString();

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
    const arbitrators = makeArbitrators(poolSize);
    return {
        decisionId: disputeId,
        disputeId,
        verdict: 'CLAIMANT_PREVAILS',
        multisigThreshold: threshold,
        multisigPoolSize: poolSize,
        decisionCanonicalHash: makeCanonicalHashHex('b'),
        arbitratorSignatures: Array.from({ length: threshold }, (_, i) => ({
            arbitratorDid: arbitrators[i]!.did,
            signature: `sig-${i}`,
        })),
        decidedAt: new Date().toISOString(),
    };
}

// ─── TxTracker: real transaction-semantics simulator ──────────────────────────

// Simulates BEGIN/COMMIT/ROLLBACK semantics:
// - writes into the staged set inside the callback
// - callback succeeds → staged is moved into committed
// - callback throws → staged is cleared (ROLLBACK effect) + re-throw the original error

// The committed set verifies the ROLLBACK effect: after fault injection committed is empty.

interface TxRecord {
    op: string;
    data?: unknown;
}

class TxTracker {
    private staged: TxRecord[] = [];
    readonly committed: TxRecord[] = [];

    stage(record: TxRecord): void {
        this.staged.push(record);
    }

    buildTxManager(): DisputeTxManager {
        return {
            runInTransaction: vi
                .fn()
                .mockImplementation(
                    async (
                        callback: (
                            ctx: DisputeTransactionContext,
                        ) => Promise<unknown>,
                    ) => {
                        this.staged = [];
                        const ctx: DisputeTransactionContext = {
                            query: vi.fn().mockResolvedValue({ rowCount: 1 }),
                        };
                        try {
                            const result = await callback(ctx);
                            // COMMIT: staged → committed
                            this.committed.push(...this.staged);
                            this.staged = [];
                            return result;
                        } catch (err) {
                            // ROLLBACK: discard staged
                            this.staged = [];
                            throw err;
                        }
                    },
                ),
        };
    }
}

// ─── Port mock builder helper ──────────────────────────────────────────────────

// Parameter faultAtAwait: if provided, throws an error at await #N (N = 1..7)
// awaitIndex is 1-based (matching the order of the 7 awaits in the dispatch)

function buildPorts(
    filing: DisputeFiling,
    filingCanonicalHash: CanonicalHashHex,
    tracker: TxTracker,
    faultAtAwait?: number,
): {
    ports: Omit<
        DisputeArbitrationInput,
        'filing' | 'signedPayload' | 'poolSizeTarget' | 'verdict' | 'tenantId'
    >;
    txManager: DisputeTxManager;
} {
    const poolSize = 3;
    const threshold = 2;
    const arbitrators = makeArbitrators(poolSize);
    const signedDecision = makeArbitrationDecision(
        filing.disputeId,
        threshold,
        poolSize,
    );

    // Fault-injection helper: if the current awaitIndex == faultAtAwait → throw
    let awaitCallCount = 0;
    function maybeThrow(label: string): void {
        awaitCallCount++;
        if (faultAtAwait !== undefined && awaitCallCount === faultAtAwait) {
            throw new Error(
                `fault-injected at await #${awaitCallCount} (${label})`,
            );
        }
    }

    const multisigPort: MultisigPort = {
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
        storeEvidenceRef: vi.fn().mockImplementation((_id, uris, _ctx) => {
            maybeThrow('storeEvidenceRef');
            tracker.stage({ op: 'storeEvidenceRef', data: uris });
            return Promise.resolve();
        }),
    };

    const revocationChecker: RevocationChecker = {
        isTokenRevoked: vi.fn().mockResolvedValue(false),
        checkDidRevocationStatus: vi.fn().mockResolvedValue(undefined),
    };

    const signatureVerifier: SignatureVerifier = {
        verifyDisputeFilingSignature: vi.fn().mockResolvedValue(true),
        checkFreshness: vi.fn(),
    };

    const atpRecorder: AtpRecorder = {
        recordDisputeTransition: vi.fn().mockImplementation((_event, _ctx) => {
            maybeThrow('recordDisputeTransition');
            tracker.stage({ op: 'recordDisputeTransition' });
            return Promise.resolve();
        }),
        recordDisputeFiled: vi.fn().mockImplementation((_id, _hash, _ctx) => {
            maybeThrow('recordDisputeFiled');
            tracker.stage({ op: 'recordDisputeFiled' });
            return Promise.resolve();
        }),
        recordArbitrationDecision: vi
            .fn()
            .mockImplementation((_id, _hash, _ctx) => {
                maybeThrow('recordArbitrationDecision');
                tracker.stage({ op: 'recordArbitrationDecision' });
                return Promise.resolve();
            }),
    };

    const disputeStore: DisputeStore = {
        findByCanonicalHash: vi.fn().mockResolvedValue(null),
        findByDisputeId: vi.fn().mockResolvedValue(null),
        saveDispute: vi.fn().mockImplementation((_dispute, _ctx) => {
            maybeThrow('saveDispute');
            tracker.stage({ op: 'saveDispute' });
            return Promise.resolve();
        }),
        getDisputeState: vi.fn().mockResolvedValue('FILED' as DisputeState),
        updateDisputeState: vi
            .fn()
            .mockImplementation((_id, _state, _ts, _ctx) => {
                maybeThrow('updateDisputeState');
                tracker.stage({ op: 'updateDisputeState' });
                return Promise.resolve();
            }),
        saveArbitrationDecision: vi
            .fn()
            .mockImplementation((_decision, _ctx) => {
                maybeThrow('saveArbitrationDecision');
                tracker.stage({ op: 'saveArbitrationDecision' });
                return Promise.resolve();
            }),
    };

    const txManager = tracker.buildTxManager();

    return {
        ports: {
            txManager,
            multisigPort,
            arbitratorSelector,
            evidenceStore,
            revocationChecker,
            signatureVerifier,
            atpRecorder,
            disputeStore,
        },
        txManager,
    };
}

// ─── Test setup helper ──────────────────────────────────────────────────────

function makeInput(
    filing: DisputeFiling,
    filingCanonicalHash: CanonicalHashHex,
    tracker: TxTracker,
    faultAtAwait?: number,
): DisputeArbitrationInput {
    const signedPayload = makeSignedPayload(filing, filingCanonicalHash);
    const { ports } = buildPorts(
        filing,
        filingCanonicalHash,
        tracker,
        faultAtAwait,
    );

    return {
        filing,
        signedPayload,
        poolSizeTarget: 3,
        verdict: 'CLAIMANT_PREVAILS',
        tenantId: 'tenant-atomic-test',
        ...ports,
    };
}

// ─── describe: atomic transaction — happy path ────────────────────────────────

describe('atomic transaction — happy path', () => {
    it('should commit all 7 ops when all awaits succeed (three-way verify)', async () => {
        const filing = makeFiling();
        const filingCanonicalHash = computeDisputeFilingCanonicalHash(filing);
        const tracker = new TxTracker();
        const input = makeInput(filing, filingCanonicalHash, tracker);

        const result = await runDisputeArbitration7Steps(input);

        // Result is correct
        expect(result.dispute.currentState).toBe('RESOLVED');
        expect(result.dispute.disputeId).toBe(filing.disputeId);
        expect(result.decision.verdict).toBe('CLAIMANT_PREVAILS');
        expect(result.transitionEvent.toState).toBe('RESOLVED');

        // Three-way verify: all 7 ops are committed
        expect(tracker.committed).toHaveLength(7);
        const ops = tracker.committed.map((r) => r.op);
        // await #1: saveDispute
        expect(ops).toContain('saveDispute');
        // await #2: recordDisputeFiled
        expect(ops).toContain('recordDisputeFiled');
        // await #3: storeEvidenceRef
        expect(ops).toContain('storeEvidenceRef');
        // await #4: updateDisputeState
        expect(ops).toContain('updateDisputeState');
        // await #5: saveArbitrationDecision
        expect(ops).toContain('saveArbitrationDecision');
        // await #6: recordDisputeTransition
        expect(ops).toContain('recordDisputeTransition');
        // await #7: recordArbitrationDecision
        expect(ops).toContain('recordArbitrationDecision');
    });

    it('should invoke txManager.runInTransaction exactly once', async () => {
        const filing = makeFiling();
        const filingCanonicalHash = computeDisputeFilingCanonicalHash(filing);
        const tracker = new TxTracker();
        const { ports, txManager } = buildPorts(
            filing,
            filingCanonicalHash,
            tracker,
        );
        const signedPayload = makeSignedPayload(filing, filingCanonicalHash);

        await runDisputeArbitration7Steps({
            filing,
            signedPayload,
            poolSizeTarget: 3,
            verdict: 'CLAIMANT_PREVAILS',
            tenantId: 'tenant-tx-once',
            ...ports,
        });

        expect(txManager.runInTransaction).toHaveBeenCalledOnce();
    });
});

// ─── describe: fault injection at each await position (N=1..7) ───────────────

// Each await #N corresponds to:
// #1 = saveDispute
// #2 = recordDisputeFiled
// #3 = storeEvidenceRef
// #4 = updateDisputeState
// #5 = saveArbitrationDecision
// #6 = recordDisputeTransition
// #7 = recordArbitrationDecision

describe('atomic transaction — fault injection at await #1 (saveDispute)', () => {
    let tracker: TxTracker;
    let filing: DisputeFiling;
    let filingCanonicalHash: CanonicalHashHex;

    beforeEach(() => {
        tracker = new TxTracker();
        filing = makeFiling();
        filingCanonicalHash = computeDisputeFilingCanonicalHash(filing);
    });

    it('should throw and rollback when saveDispute (await #1) fails', async () => {
        const input = makeInput(filing, filingCanonicalHash, tracker, 1);

        await expect(runDisputeArbitration7Steps(input)).rejects.toThrow(
            'fault-injected at await #1',
        );

        // ROLLBACK: no op is committed
        expect(tracker.committed).toHaveLength(0);
    });
});

describe('atomic transaction — fault injection at await #2 (recordDisputeFiled)', () => {
    let tracker: TxTracker;
    let filing: DisputeFiling;
    let filingCanonicalHash: CanonicalHashHex;

    beforeEach(() => {
        tracker = new TxTracker();
        filing = makeFiling();
        filingCanonicalHash = computeDisputeFilingCanonicalHash(filing);
    });

    it('should throw and rollback when recordDisputeFiled (await #2) fails', async () => {
        const input = makeInput(filing, filingCanonicalHash, tracker, 2);

        await expect(runDisputeArbitration7Steps(input)).rejects.toThrow(
            'fault-injected at await #2',
        );

        // saveDispute is staged but not committed due to ROLLBACK
        expect(tracker.committed).toHaveLength(0);
    });
});

describe('atomic transaction — fault injection at await #3 (storeEvidenceRef)', () => {
    let tracker: TxTracker;
    let filing: DisputeFiling;
    let filingCanonicalHash: CanonicalHashHex;

    beforeEach(() => {
        tracker = new TxTracker();
        filing = makeFiling();
        filingCanonicalHash = computeDisputeFilingCanonicalHash(filing);
    });

    it('should throw and rollback when storeEvidenceRef (await #3) fails', async () => {
        const input = makeInput(filing, filingCanonicalHash, tracker, 3);

        await expect(runDisputeArbitration7Steps(input)).rejects.toThrow(
            'fault-injected at await #3',
        );

        // saveDispute + recordDisputeFiled are staged but not committed due to ROLLBACK
        expect(tracker.committed).toHaveLength(0);
    });
});

describe('atomic transaction — fault injection at await #4 (updateDisputeState)', () => {
    let tracker: TxTracker;
    let filing: DisputeFiling;
    let filingCanonicalHash: CanonicalHashHex;

    beforeEach(() => {
        tracker = new TxTracker();
        filing = makeFiling();
        filingCanonicalHash = computeDisputeFilingCanonicalHash(filing);
    });

    it('should throw and rollback when updateDisputeState (await #4) fails', async () => {
        const input = makeInput(filing, filingCanonicalHash, tracker, 4);

        await expect(runDisputeArbitration7Steps(input)).rejects.toThrow(
            'fault-injected at await #4',
        );

        // 3 ops staged (saveDispute + recordDisputeFiled + storeEvidenceRef) but cleared by ROLLBACK
        expect(tracker.committed).toHaveLength(0);
    });
});

describe('atomic transaction — fault injection at await #5 (saveArbitrationDecision)', () => {
    let tracker: TxTracker;
    let filing: DisputeFiling;
    let filingCanonicalHash: CanonicalHashHex;

    beforeEach(() => {
        tracker = new TxTracker();
        filing = makeFiling();
        filingCanonicalHash = computeDisputeFilingCanonicalHash(filing);
    });

    it('should throw and rollback when saveArbitrationDecision (await #5) fails', async () => {
        const input = makeInput(filing, filingCanonicalHash, tracker, 5);

        await expect(runDisputeArbitration7Steps(input)).rejects.toThrow(
            'fault-injected at await #5',
        );

        // resolved state update is staged but cleared by ROLLBACK — no partial decision
        expect(tracker.committed).toHaveLength(0);
    });
});

describe('atomic transaction — fault injection at await #6 (recordDisputeTransition)', () => {
    let tracker: TxTracker;
    let filing: DisputeFiling;
    let filingCanonicalHash: CanonicalHashHex;

    beforeEach(() => {
        tracker = new TxTracker();
        filing = makeFiling();
        filingCanonicalHash = computeDisputeFilingCanonicalHash(filing);
    });

    it('should throw and rollback when recordDisputeTransition (await #6) fails', async () => {
        const input = makeInput(filing, filingCanonicalHash, tracker, 6);

        await expect(runDisputeArbitration7Steps(input)).rejects.toThrow(
            'fault-injected at await #6',
        );

        // 5 ops staged but ROLLBACK — no partial audit trail
        expect(tracker.committed).toHaveLength(0);
    });
});

describe('atomic transaction — fault injection at await #7 (recordArbitrationDecision)', () => {
    let tracker: TxTracker;
    let filing: DisputeFiling;
    let filingCanonicalHash: CanonicalHashHex;

    beforeEach(() => {
        tracker = new TxTracker();
        filing = makeFiling();
        filingCanonicalHash = computeDisputeFilingCanonicalHash(filing);
    });

    it('should throw and rollback when recordArbitrationDecision (await #7) fails', async () => {
        const input = makeInput(filing, filingCanonicalHash, tracker, 7);

        await expect(runDisputeArbitration7Steps(input)).rejects.toThrow(
            'fault-injected at await #7',
        );

        // 6 ops staged but ultimately ROLLBACK — no op committed; no partial audit
        expect(tracker.committed).toHaveLength(0);
    });
});

// ─── describe: rollback error identity ────────────────────────────────────────

// Verify txManager re-throws the original error (no wrapping; error identity preserved)

describe('atomic transaction — rollback re-throws original error', () => {
    it('should re-throw the original Error (not wrapped) on fault at await #3', async () => {
        const filing = makeFiling();
        const filingCanonicalHash = computeDisputeFilingCanonicalHash(filing);
        const tracker = new TxTracker();
        const input = makeInput(filing, filingCanonicalHash, tracker, 3);

        let caughtError: unknown;
        try {
            await runDisputeArbitration7Steps(input);
        } catch (err) {
            caughtError = err;
        }

        // The original error type must be Error (not a DaError wrapper)
        expect(caughtError).toBeInstanceOf(Error);
        expect((caughtError as Error).message).toContain(
            'fault-injected at await #3',
        );
        // committed is empty (already rolled back)
        expect(tracker.committed).toHaveLength(0);
    });

    it('should re-throw DaError from port without wrapping on DA error in tx', async () => {
        const filing = makeFiling();
        const filingCanonicalHash = computeDisputeFilingCanonicalHash(filing);
        const tracker = new TxTracker();

        // Build ports that inject a DaError instead of a plain Error
        const { ports } = buildPorts(filing, filingCanonicalHash, tracker);
        const signedPayload = makeSignedPayload(filing, filingCanonicalHash);

        // Override saveDispute so it throws a DaError
        (
            ports.disputeStore.saveDispute as ReturnType<typeof vi.fn>
        ).mockRejectedValue(
            new DaError('DA_PROVIDER_UNAVAILABLE', { reason: 'db_down' }),
        );

        await expect(
            runDisputeArbitration7Steps({
                filing,
                signedPayload,
                poolSizeTarget: 3,
                verdict: 'CLAIMANT_PREVAILS',
                tenantId: 'tenant-daerror',
                ...ports,
            }),
        ).rejects.toMatchObject({ code: 'DA_PROVIDER_UNAVAILABLE' });

        // ROLLBACK: committed is empty
        expect(tracker.committed).toHaveLength(0);
    });
});
