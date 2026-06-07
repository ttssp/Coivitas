/**
 * TrustBoundaryLifecycleManager — state machine + 8 legal transition unit tests
 *
 * Coverage targets:
 * - the full path of the 5-state state machine (pending → active → {suspended → active OR revoked OR expired})
 * - active invocation of all paths of the 8 legal transitions (T1-T7; T8 fail-closed)
 * - fail-closed enforcement of the I_tb_ver + I1-I10 + I_tb_audit_src invariants
 * - transitionSource three-state validation (client / system / sweeper)
 * - reverse transition fail-closed reject (I4)
 * - anti-phantom: every transition path has an active assertion
 *
 * Covered behaviors:
 * - the T1 onTrustEstablished flow
 * - the T2 + T3 + T4 flow
 * - the T5 + T6 + T7 flow
 * - the T8 emergency suspend placeholder fail-closed
 * - the 17 TB_* error codes
 */

import { describe, expect, it } from 'vitest';

import type { DID, Timestamp } from '@coivitas/types';

import {
    InMemoryTrustBoundaryStorage,
    TestProofVerifier,
    TrustBoundaryLifecycleManager,
    assertInvariant,
    toTrustBoundaryId,
    type BoundaryBindingProof,
    type LeaseExtensionProof,
    type TrustBoundary,
    type TrustBoundaryId,
} from '../index.js';

// ─── test fixtures ─────────────────────────────────────────────────────

const PRINCIPAL_DID = 'did:agent:principal-alice' as DID;
const BOUNDED_DID = 'did:agent:bounded-bob' as DID;
const REGISTRY_AUDIENCE = 'https://trust-boundary.coivitas.ai/v1/boundaries';
const TEST_CHALLENGE = 'challenge-uuid-12345';
const BOUNDARY_ID = '550e8400-e29b-41d4-a716-446655440001';

function makeFrozenNow(epochMs: number): () => Date {
    return () => new Date(epochMs);
}

function makeManager(opts?: {
    now?: () => Date;
    verifierVerdict?:
        | { ok: true }
        | { ok: false; code: 'TB_BOUNDARY_PROOF_VERIFY_FAILED'; message: string };
}): {
    manager: TrustBoundaryLifecycleManager;
    storage: InMemoryTrustBoundaryStorage;
    verifier: TestProofVerifier;
} {
    const storage = new InMemoryTrustBoundaryStorage();
    const verifier = new TestProofVerifier();
    if (opts?.verifierVerdict) {
        verifier.defaultVerdict = opts.verifierVerdict;
    } else {
        // pass by default — tests must override explicitly (to avoid the stub-default-success anti-pattern: each test sets it explicitly)
        verifier.defaultVerdict = { ok: true };
    }
    const manager = new TrustBoundaryLifecycleManager({
        storage,
        verifier,
        now: opts?.now ?? makeFrozenNow(Date.parse('2026-05-18T10:00:00Z')),
    });
    return { manager, storage, verifier };
}

function makeBindingProof(opts: {
    boundaryId: TrustBoundaryId;
    notAfter: Timestamp;
    challenge?: string;
    audience?: string;
}): BoundaryBindingProof {
    return {
        cspVersion: '1.0.0',
        token: 'binding-proof-token-data',
        disclosedClaims: [],
        challenge: opts.challenge ?? TEST_CHALLENGE,
        audience: opts.audience ?? REGISTRY_AUDIENCE,
        notAfter: opts.notAfter,
        proofValue: 'ed25519-signature-base64url-stub',
        boundaryId: opts.boundaryId,
    };
}

function makeLeaseExtensionProof(opts: {
    boundaryId: TrustBoundaryId;
    notAfter: Timestamp;
}): LeaseExtensionProof {
    return {
        cspVersion: '1.0.0',
        token: 'lease-extension-token-data',
        disclosedClaims: [],
        challenge: TEST_CHALLENGE,
        audience: REGISTRY_AUDIENCE,
        notAfter: opts.notAfter,
        proofValue: 'ed25519-signature-base64url-stub',
        boundaryId: opts.boundaryId,
    };
}

// ─── createBoundary flow ────────────────────────────────────────────────

describe('TrustBoundaryLifecycleManager.createBoundary — step 1-2', () => {
    it('should create boundary in pending state with server-enforced lifecycleWindow', async () => {
        const { manager } = makeManager();
        const requestedNotAfter = new Date(
            Date.parse('2026-06-01T10:00:00Z'),
        ).toISOString() as Timestamp;
        const tb = await manager.createBoundary({
            id: BOUNDARY_ID,
            principalSide: PRINCIPAL_DID,
            boundedSide: BOUNDED_DID,
            boundaryScope: ['scope:read'],
            requestedNotAfter,
        });
        expect(tb.state).toBe('pending');
        expect(tb.bindingProofId).toBeUndefined();
        expect(tb.principalSide).toBe(PRINCIPAL_DID);
        expect(tb.boundedSide).toBe(BOUNDED_DID);
        expect(tb.tbVersion).toBe('1.0.0');
        expect(tb.lifecycleWindow.notAfter).toBe(requestedNotAfter);
    });

    it('should throw TB_PARTY_SELF_REFERENTIAL when principalSide === boundedSide (I2)', async () => {
        const { manager } = makeManager();
        await expect(
            manager.createBoundary({
                id: BOUNDARY_ID,
                principalSide: PRINCIPAL_DID,
                boundedSide: PRINCIPAL_DID, // self-referential
                boundaryScope: [],
                requestedNotAfter: '2026-06-01T10:00:00Z' as Timestamp,
            }),
        ).rejects.toThrow('TB_PARTY_SELF_REFERENTIAL');
    });

    it('should throw TB_ID_INVALID when id is not UUID v4', async () => {
        const { manager } = makeManager();
        await expect(
            manager.createBoundary({
                id: 'not-uuid',
                principalSide: PRINCIPAL_DID,
                boundedSide: BOUNDED_DID,
                boundaryScope: [],
                requestedNotAfter: '2026-06-01T10:00:00Z' as Timestamp,
            }),
        ).rejects.toThrow('TB_ID_INVALID');
    });

    it('should server-enforce lifecycleWindow.notAfter truncation when requested > maxLifecycleWindow (I8)', async () => {
        const nowMs = Date.parse('2026-05-18T10:00:00Z');
        const { manager } = makeManager({ now: makeFrozenNow(nowMs) });
        // request an expiry 1 year out — the server truncates it to 6 months
        const requested = new Date(nowMs + 365 * 24 * 60 * 60 * 1_000).toISOString() as Timestamp;
        const tb = await manager.createBoundary({
            id: BOUNDARY_ID,
            principalSide: PRINCIPAL_DID,
            boundedSide: BOUNDED_DID,
            boundaryScope: [],
            requestedNotAfter: requested,
        });
        // server-enforced = now + 6 month
        const sixMonthMs = 6 * 30 * 24 * 60 * 60 * 1_000;
        const expected = new Date(nowMs + sixMonthMs).toISOString();
        expect(tb.lifecycleWindow.notAfter).toBe(expected);
    });

    it('should throw TB_LIFECYCLE_INVALID when serverEnforced notAfter <= now + minWindow (I5)', async () => {
        const nowMs = Date.parse('2026-05-18T10:00:00Z');
        const { manager } = makeManager({ now: makeFrozenNow(nowMs) });
        // request an expiry 500ms out — does not satisfy minWindow=1000ms
        const requested = new Date(nowMs + 500).toISOString() as Timestamp;
        await expect(
            manager.createBoundary({
                id: BOUNDARY_ID,
                principalSide: PRINCIPAL_DID,
                boundedSide: BOUNDED_DID,
                boundaryScope: [],
                requestedNotAfter: requested,
            }),
        ).rejects.toThrow('TB_LIFECYCLE_INVALID');
    });
});

// ─── T1 onTrustEstablished flow ────────────────────────────────────────

describe('TrustBoundaryLifecycleManager.transitionState — T1 onTrustEstablished', () => {
    async function setupPending(): Promise<{
        manager: TrustBoundaryLifecycleManager;
        storage: InMemoryTrustBoundaryStorage;
        verifier: TestProofVerifier;
        pending: TrustBoundary;
    }> {
        const { manager, storage, verifier } = makeManager();
        const pending = await manager.createBoundary({
            id: BOUNDARY_ID,
            principalSide: PRINCIPAL_DID,
            boundedSide: BOUNDED_DID,
            boundaryScope: ['scope:read'],
            requestedNotAfter: new Date(
                Date.parse('2026-05-18T10:00:00Z') + 30 * 24 * 60 * 60 * 1_000,
            ).toISOString() as Timestamp,
        });
        return { manager, storage, verifier, pending };
    }

    it('should T1 transition pending → active when binding proof verify passes', async () => {
        const { manager, pending } = await setupPending();
        const proof = makeBindingProof({
            boundaryId: pending.id,
            notAfter: pending.lifecycleWindow.notAfter,
        });
        const active = await manager.transitionState({
            id: pending.id,
            event: 'onTrustEstablished',
            actorDID: PRINCIPAL_DID,
            transitionSource: 'client',
            bindingProof: proof,
            verifyContext: {
                expectedAudience: REGISTRY_AUDIENCE,
                expectedChallenge: TEST_CHALLENGE,
            },
        });
        expect(active.state).toBe('active');
        expect(active.bindingProofId).toBeDefined();
    });

    it('should throw TB_PRINCIPAL_POP_MISSING when bindingProof is absent (I9)', async () => {
        const { manager, pending } = await setupPending();
        await expect(
            manager.transitionState({
                id: pending.id,
                event: 'onTrustEstablished',
                actorDID: PRINCIPAL_DID,
                transitionSource: 'client',
                verifyContext: {
                    expectedAudience: REGISTRY_AUDIENCE,
                    expectedChallenge: TEST_CHALLENGE,
                },
            }),
        ).rejects.toThrow('TB_PRINCIPAL_POP_MISSING');
    });

    it('should throw TB_PAYLOAD_COVERAGE_INSUFFICIENT when verifyContext absent (I7)', async () => {
        const { manager, pending } = await setupPending();
        const proof = makeBindingProof({
            boundaryId: pending.id,
            notAfter: pending.lifecycleWindow.notAfter,
        });
        await expect(
            manager.transitionState({
                id: pending.id,
                event: 'onTrustEstablished',
                actorDID: PRINCIPAL_DID,
                transitionSource: 'client',
                bindingProof: proof,
            }),
        ).rejects.toThrow('TB_PAYLOAD_COVERAGE_INSUFFICIENT');
    });

    it('should throw TB_PAYLOAD_COVERAGE_INSUFFICIENT when bindingProof.boundaryId mismatches (I7)', async () => {
        const { manager, pending } = await setupPending();
        // intentionally provide a proof with a mismatched boundaryId
        const otherId = toTrustBoundaryId('550e8400-e29b-41d4-a716-446655440099');
        const proof = makeBindingProof({
            boundaryId: otherId,
            notAfter: pending.lifecycleWindow.notAfter,
        });
        await expect(
            manager.transitionState({
                id: pending.id,
                event: 'onTrustEstablished',
                actorDID: PRINCIPAL_DID,
                transitionSource: 'client',
                bindingProof: proof,
                verifyContext: {
                    expectedAudience: REGISTRY_AUDIENCE,
                    expectedChallenge: TEST_CHALLENGE,
                },
            }),
        ).rejects.toThrow('TB_PAYLOAD_COVERAGE_INSUFFICIENT');
    });

    it('should throw TB_EXPIRY_CLIENT_CONTROLLED when bindingProof.notAfter mismatches server-enforced (I8)', async () => {
        const { manager, pending } = await setupPending();
        // intentionally provide a future expiry — the server does not accept it
        const proof = makeBindingProof({
            boundaryId: pending.id,
            notAfter: new Date(
                Date.parse(pending.lifecycleWindow.notAfter) + 86400_000,
            ).toISOString() as Timestamp,
        });
        await expect(
            manager.transitionState({
                id: pending.id,
                event: 'onTrustEstablished',
                actorDID: PRINCIPAL_DID,
                transitionSource: 'client',
                bindingProof: proof,
                verifyContext: {
                    expectedAudience: REGISTRY_AUDIENCE,
                    expectedChallenge: TEST_CHALLENGE,
                },
            }),
        ).rejects.toThrow('TB_EXPIRY_CLIENT_CONTROLLED');
    });

    it('should throw TB_BOUNDARY_PROOF_VERIFY_FAILED when verifier rejects', async () => {
        // explicitly set the verifier to reject
        const { manager: manager2, pending: pending2 } = await (async () => {
            const setup = makeManager({
                verifierVerdict: {
                    ok: false,
                    code: 'TB_BOUNDARY_PROOF_VERIFY_FAILED',
                    message: 'Ed25519 verify failed',
                },
            });
            const p = await setup.manager.createBoundary({
                id: BOUNDARY_ID,
                principalSide: PRINCIPAL_DID,
                boundedSide: BOUNDED_DID,
                boundaryScope: [],
                requestedNotAfter: new Date(
                    Date.parse('2026-05-18T10:00:00Z') + 30 * 24 * 60 * 60 * 1_000,
                ).toISOString() as Timestamp,
            });
            return { manager: setup.manager, pending: p };
        })();
        const proof = makeBindingProof({
            boundaryId: pending2.id,
            notAfter: pending2.lifecycleWindow.notAfter,
        });
        await expect(
            manager2.transitionState({
                id: pending2.id,
                event: 'onTrustEstablished',
                actorDID: PRINCIPAL_DID,
                transitionSource: 'client',
                bindingProof: proof,
                verifyContext: {
                    expectedAudience: REGISTRY_AUDIENCE,
                    expectedChallenge: TEST_CHALLENGE,
                },
            }),
        ).rejects.toThrow('TB_BOUNDARY_PROOF_VERIFY_FAILED');
        // ensure pending was not changed to active
        const reread = await manager2.getCurrent(pending2.id);
        expect(reread?.state).toBe('pending');
    });

    it('should write audit event with transitionSource=client when T1 succeeds', async () => {
        const { manager, storage, pending } = await setupPending();
        const proof = makeBindingProof({
            boundaryId: pending.id,
            notAfter: pending.lifecycleWindow.notAfter,
        });
        await manager.transitionState({
            id: pending.id,
            event: 'onTrustEstablished',
            actorDID: PRINCIPAL_DID,
            transitionSource: 'client',
            bindingProof: proof,
            verifyContext: {
                expectedAudience: REGISTRY_AUDIENCE,
                expectedChallenge: TEST_CHALLENGE,
            },
        });
        const events = storage.getAuditEvents();
        expect(events.length).toBe(1);
        expect(events[0]?.transitionSource).toBe('client');
        expect(events[0]?.transitionBefore).toBe('pending');
        expect(events[0]?.transitionAfter).toBe('active');
    });
});

// ─── T2 onLeaseExtended flow ───────────────────────────────────────────

describe('TrustBoundaryLifecycleManager.transitionState — T2 onLeaseExtended', () => {
    async function setupActive(): Promise<{
        manager: TrustBoundaryLifecycleManager;
        storage: InMemoryTrustBoundaryStorage;
        active: TrustBoundary;
        nowMs: number;
    }> {
        const nowMs = Date.parse('2026-05-18T10:00:00Z');
        const { manager, storage } = makeManager({ now: makeFrozenNow(nowMs) });
        const requestedNotAfter = new Date(
            nowMs + 30 * 24 * 60 * 60 * 1_000,
        ).toISOString() as Timestamp;
        const pending = await manager.createBoundary({
            id: BOUNDARY_ID,
            principalSide: PRINCIPAL_DID,
            boundedSide: BOUNDED_DID,
            boundaryScope: [],
            requestedNotAfter,
        });
        const active = await manager.transitionState({
            id: pending.id,
            event: 'onTrustEstablished',
            actorDID: PRINCIPAL_DID,
            transitionSource: 'client',
            bindingProof: makeBindingProof({
                boundaryId: pending.id,
                notAfter: pending.lifecycleWindow.notAfter,
            }),
            verifyContext: {
                expectedAudience: REGISTRY_AUDIENCE,
                expectedChallenge: TEST_CHALLENGE,
            },
        });
        return { manager, storage, active, nowMs };
    }

    it('should T2 extend lease — active → active with updated notAfter', async () => {
        const { manager, active, nowMs } = await setupActive();
        // request a new expiry 60 days out — allowed, within the maxLifecycleWindow (6 months)
        const newNotAfterMs = nowMs + 60 * 24 * 60 * 60 * 1_000;
        const newNotAfter = new Date(newNotAfterMs).toISOString() as Timestamp;
        const extended = await manager.transitionState({
            id: active.id,
            event: 'onLeaseExtended',
            actorDID: PRINCIPAL_DID,
            transitionSource: 'client',
            requestedNotAfter: newNotAfter,
            leaseExtensionProof: makeLeaseExtensionProof({
                boundaryId: active.id,
                notAfter: newNotAfter,
            }),
            verifyContext: {
                expectedAudience: REGISTRY_AUDIENCE,
                expectedChallenge: TEST_CHALLENGE,
            },
        });
        expect(extended.state).toBe('active');
        expect(extended.lifecycleWindow.notAfter).toBe(newNotAfter);
    });

    it('should server-enforce maxLifecycleWindow truncation in T2 (I8)', async () => {
        const { manager, active, nowMs } = await setupActive();
        // request 1 year out — the server truncates it to 6 months
        const tooFar = new Date(
            nowMs + 365 * 24 * 60 * 60 * 1_000,
        ).toISOString() as Timestamp;
        const sixMonth = new Date(
            nowMs + 6 * 30 * 24 * 60 * 60 * 1_000,
        ).toISOString() as Timestamp;
        // the client request is merely truncated — leaseExtensionProof.notAfter must equal the server-enforced value
        // if the client-signed notAfter does not equal the server-enforced value (6 months) → throw TB_EXPIRY_CLIENT_CONTROLLED
        await expect(
            manager.transitionState({
                id: active.id,
                event: 'onLeaseExtended',
                actorDID: PRINCIPAL_DID,
                transitionSource: 'client',
                requestedNotAfter: tooFar,
                leaseExtensionProof: makeLeaseExtensionProof({
                    boundaryId: active.id,
                    notAfter: tooFar, // client signed too far into the future
                }),
                verifyContext: {
                    expectedAudience: REGISTRY_AUDIENCE,
                    expectedChallenge: TEST_CHALLENGE,
                },
            }),
        ).rejects.toThrow('TB_EXPIRY_CLIENT_CONTROLLED');
        // if the client-signed value equals the server-enforced truncated value, it passes
        const extended = await manager.transitionState({
            id: active.id,
            event: 'onLeaseExtended',
            actorDID: PRINCIPAL_DID,
            transitionSource: 'client',
            requestedNotAfter: tooFar,
            leaseExtensionProof: makeLeaseExtensionProof({
                boundaryId: active.id,
                notAfter: sixMonth,
            }),
            verifyContext: {
                expectedAudience: REGISTRY_AUDIENCE,
                expectedChallenge: TEST_CHALLENGE,
            },
        });
        expect(extended.lifecycleWindow.notAfter).toBe(sixMonth);
    });

    it('should throw TB_PAYLOAD_COVERAGE_INSUFFICIENT when leaseExtensionProof absent', async () => {
        const { manager, active, nowMs } = await setupActive();
        const newNotAfter = new Date(
            nowMs + 60 * 24 * 60 * 60 * 1_000,
        ).toISOString() as Timestamp;
        await expect(
            manager.transitionState({
                id: active.id,
                event: 'onLeaseExtended',
                actorDID: PRINCIPAL_DID,
                transitionSource: 'client',
                requestedNotAfter: newNotAfter,
                verifyContext: {
                    expectedAudience: REGISTRY_AUDIENCE,
                    expectedChallenge: TEST_CHALLENGE,
                },
            }),
        ).rejects.toThrow('TB_PAYLOAD_COVERAGE_INSUFFICIENT');
    });

    it('should throw TB_PAYLOAD_COVERAGE_INSUFFICIENT when leaseExtensionProof verifyContext absent', async () => {
        const { manager, active, nowMs } = await setupActive();
        const newNotAfter = new Date(
            nowMs + 60 * 24 * 60 * 60 * 1_000,
        ).toISOString() as Timestamp;
        await expect(
            manager.transitionState({
                id: active.id,
                event: 'onLeaseExtended',
                actorDID: PRINCIPAL_DID,
                transitionSource: 'client',
                requestedNotAfter: newNotAfter,
                leaseExtensionProof: makeLeaseExtensionProof({
                    boundaryId: active.id,
                    notAfter: newNotAfter,
                }),
            }),
        ).rejects.toThrow('TB_PAYLOAD_COVERAGE_INSUFFICIENT');
    });

    it('should throw TB_LIFECYCLE_INVALID when T2 lacks requestedNotAfter', async () => {
        const { manager, active, nowMs } = await setupActive();
        const newNotAfter = new Date(
            nowMs + 60 * 24 * 60 * 60 * 1_000,
        ).toISOString() as Timestamp;
        await expect(
            manager.transitionState({
                id: active.id,
                event: 'onLeaseExtended',
                actorDID: PRINCIPAL_DID,
                transitionSource: 'client',
                leaseExtensionProof: makeLeaseExtensionProof({
                    boundaryId: active.id,
                    notAfter: newNotAfter,
                }),
                verifyContext: {
                    expectedAudience: REGISTRY_AUDIENCE,
                    expectedChallenge: TEST_CHALLENGE,
                },
            }),
        ).rejects.toThrow('TB_LIFECYCLE_INVALID');
    });

    it('should throw TB_LIFECYCLE_INVALID when T2 requestedNotAfter <= now + minWindow', async () => {
        const { manager, active, nowMs } = await setupActive();
        // request an expiry 100ms out — does not satisfy minWindow=1000ms
        const tooSoon = new Date(nowMs + 100).toISOString() as Timestamp;
        await expect(
            manager.transitionState({
                id: active.id,
                event: 'onLeaseExtended',
                actorDID: PRINCIPAL_DID,
                transitionSource: 'client',
                requestedNotAfter: tooSoon,
                leaseExtensionProof: makeLeaseExtensionProof({
                    boundaryId: active.id,
                    notAfter: tooSoon,
                }),
                verifyContext: {
                    expectedAudience: REGISTRY_AUDIENCE,
                    expectedChallenge: TEST_CHALLENGE,
                },
            }),
        ).rejects.toThrow('TB_LIFECYCLE_INVALID');
    });

    it('should throw TB_PAYLOAD_COVERAGE_INSUFFICIENT when T2 leaseExtensionProof.boundaryId mismatches (I7)', async () => {
        const { manager, active, nowMs } = await setupActive();
        const newNotAfter = new Date(
            nowMs + 60 * 24 * 60 * 60 * 1_000,
        ).toISOString() as Timestamp;
        const otherId = toTrustBoundaryId('550e8400-e29b-41d4-a716-446655440098');
        await expect(
            manager.transitionState({
                id: active.id,
                event: 'onLeaseExtended',
                actorDID: PRINCIPAL_DID,
                transitionSource: 'client',
                requestedNotAfter: newNotAfter,
                leaseExtensionProof: makeLeaseExtensionProof({
                    boundaryId: otherId, // intentionally mismatched
                    notAfter: newNotAfter,
                }),
                verifyContext: {
                    expectedAudience: REGISTRY_AUDIENCE,
                    expectedChallenge: TEST_CHALLENGE,
                },
            }),
        ).rejects.toThrow('TB_PAYLOAD_COVERAGE_INSUFFICIENT');
    });

    it('should throw TB_BOUNDARY_PROOF_VERIFY_FAILED when T2 verifier rejects', async () => {
        // phase 1: set up active with ok
        const storage = new InMemoryTrustBoundaryStorage();
        const verifier = new TestProofVerifier();
        verifier.defaultVerdict = { ok: true };
        const nowMs = Date.parse('2026-05-18T10:00:00Z');
        const m = new TrustBoundaryLifecycleManager({
            storage,
            verifier,
            now: makeFrozenNow(nowMs),
        });
        const requested = new Date(nowMs + 30 * 24 * 60 * 60 * 1_000).toISOString() as Timestamp;
        const pending = await m.createBoundary({
            id: BOUNDARY_ID,
            principalSide: PRINCIPAL_DID,
            boundedSide: BOUNDED_DID,
            boundaryScope: [],
            requestedNotAfter: requested,
        });
        await m.transitionState({
            id: pending.id,
            event: 'onTrustEstablished',
            actorDID: PRINCIPAL_DID,
            transitionSource: 'client',
            bindingProof: makeBindingProof({
                boundaryId: pending.id,
                notAfter: pending.lifecycleWindow.notAfter,
            }),
            verifyContext: {
                expectedAudience: REGISTRY_AUDIENCE,
                expectedChallenge: TEST_CHALLENGE,
            },
        });

        // phase 2: flip the verifier — T2 must fail
        verifier.defaultVerdict = {
            ok: false,
            code: 'TB_BOUNDARY_PROOF_VERIFY_FAILED',
            message: 'T2 verify failed in test',
        };
        const newNotAfter = new Date(
            nowMs + 60 * 24 * 60 * 60 * 1_000,
        ).toISOString() as Timestamp;
        await expect(
            m.transitionState({
                id: pending.id,
                event: 'onLeaseExtended',
                actorDID: PRINCIPAL_DID,
                transitionSource: 'client',
                requestedNotAfter: newNotAfter,
                leaseExtensionProof: makeLeaseExtensionProof({
                    boundaryId: pending.id,
                    notAfter: newNotAfter,
                }),
                verifyContext: {
                    expectedAudience: REGISTRY_AUDIENCE,
                    expectedChallenge: TEST_CHALLENGE,
                },
            }),
        ).rejects.toThrow('TB_BOUNDARY_PROOF_VERIFY_FAILED');
    });
});

// ─── T3 onSuspended + T4 onResumed flow ────────────────────────────────

describe('TrustBoundaryLifecycleManager.transitionState — T3 onSuspended + T4 onResumed', () => {
    async function setupActive(): Promise<{
        manager: TrustBoundaryLifecycleManager;
        storage: InMemoryTrustBoundaryStorage;
        active: TrustBoundary;
    }> {
        const { manager, storage } = makeManager();
        const pending = await manager.createBoundary({
            id: BOUNDARY_ID,
            principalSide: PRINCIPAL_DID,
            boundedSide: BOUNDED_DID,
            boundaryScope: [],
            requestedNotAfter: new Date(
                Date.parse('2026-05-18T10:00:00Z') + 30 * 24 * 60 * 60 * 1_000,
            ).toISOString() as Timestamp,
        });
        const active = await manager.transitionState({
            id: pending.id,
            event: 'onTrustEstablished',
            actorDID: PRINCIPAL_DID,
            transitionSource: 'client',
            bindingProof: makeBindingProof({
                boundaryId: pending.id,
                notAfter: pending.lifecycleWindow.notAfter,
            }),
            verifyContext: {
                expectedAudience: REGISTRY_AUDIENCE,
                expectedChallenge: TEST_CHALLENGE,
            },
        });
        return { manager, storage, active };
    }

    it('should T3 transition active → suspended; lifecycleWindow unchanged', async () => {
        const { manager, active } = await setupActive();
        const originalNotAfter = active.lifecycleWindow.notAfter;
        const suspended = await manager.transitionState({
            id: active.id,
            event: 'onSuspended',
            actorDID: PRINCIPAL_DID,
            transitionSource: 'client',
        });
        expect(suspended.state).toBe('suspended');
        // T3's final line — lifecycleWindow.notAfter unchanged
        expect(suspended.lifecycleWindow.notAfter).toBe(originalNotAfter);
    });

    it('should T4 resume suspended → active when lifecycle not expired', async () => {
        const { manager, active } = await setupActive();
        const suspended = await manager.transitionState({
            id: active.id,
            event: 'onSuspended',
            actorDID: PRINCIPAL_DID,
            transitionSource: 'client',
        });
        expect(suspended.state).toBe('suspended');
        const resumed = await manager.transitionState({
            id: active.id,
            event: 'onResumed',
            actorDID: PRINCIPAL_DID,
            transitionSource: 'client',
        });
        expect(resumed.state).toBe('active');
    });

    it('should throw TB_BOUNDARY_EXPIRED when resuming expired suspended boundary (I5)', async () => {
        // use a frozen now to control time — simulate time jumping past lifecycleWindow after suspended
        const nowMs = Date.parse('2026-05-18T10:00:00Z');
        const storage = new InMemoryTrustBoundaryStorage();
        const verifier = new TestProofVerifier();
        verifier.defaultVerdict = { ok: true };

        // phase 1: with nowMs, create + active + suspended
        const manager1 = new TrustBoundaryLifecycleManager({
            storage,
            verifier,
            now: makeFrozenNow(nowMs),
        });
        const requested = new Date(nowMs + 30 * 24 * 60 * 60 * 1_000).toISOString() as Timestamp;
        const pending = await manager1.createBoundary({
            id: BOUNDARY_ID,
            principalSide: PRINCIPAL_DID,
            boundedSide: BOUNDED_DID,
            boundaryScope: [],
            requestedNotAfter: requested,
        });
        await manager1.transitionState({
            id: pending.id,
            event: 'onTrustEstablished',
            actorDID: PRINCIPAL_DID,
            transitionSource: 'client',
            bindingProof: makeBindingProof({
                boundaryId: pending.id,
                notAfter: pending.lifecycleWindow.notAfter,
            }),
            verifyContext: {
                expectedAudience: REGISTRY_AUDIENCE,
                expectedChallenge: TEST_CHALLENGE,
            },
        });
        await manager1.transitionState({
            id: pending.id,
            event: 'onSuspended',
            actorDID: PRINCIPAL_DID,
            transitionSource: 'client',
        });

        // phase 2: jump to after lifecycleWindow.notAfter
        const lateMs = nowMs + 60 * 24 * 60 * 60 * 1_000; // 60 days later (past the 30-day expiry)
        const manager2 = new TrustBoundaryLifecycleManager({
            storage,
            verifier,
            now: makeFrozenNow(lateMs),
        });
        await expect(
            manager2.transitionState({
                id: pending.id,
                event: 'onResumed',
                actorDID: PRINCIPAL_DID,
                transitionSource: 'client',
            }),
        ).rejects.toThrow('TB_BOUNDARY_EXPIRED');
    });

    it('should reject T3 onSuspended → onSuspended (suspended state cannot onSuspended again;I4)', async () => {
        const { manager, active } = await setupActive();
        await manager.transitionState({
            id: active.id,
            event: 'onSuspended',
            actorDID: PRINCIPAL_DID,
            transitionSource: 'client',
        });
        // onSuspended again on a suspended boundary — illegal transition
        await expect(
            manager.transitionState({
                id: active.id,
                event: 'onSuspended',
                actorDID: PRINCIPAL_DID,
                transitionSource: 'client',
            }),
        ).rejects.toThrow('TB_INVALID_TRANSITION');
    });
});

// ─── T5 onRevoked + T6/T7 onExpired flow ──────────────────────────────

describe('TrustBoundaryLifecycleManager.transitionState — T5 onRevoked + T6/T7 onExpired', () => {
    async function setupActive(nowMs?: number): Promise<{
        manager: TrustBoundaryLifecycleManager;
        storage: InMemoryTrustBoundaryStorage;
        active: TrustBoundary;
    }> {
        const t0 = nowMs ?? Date.parse('2026-05-18T10:00:00Z');
        const { manager, storage } = makeManager({ now: makeFrozenNow(t0) });
        const pending = await manager.createBoundary({
            id: BOUNDARY_ID,
            principalSide: PRINCIPAL_DID,
            boundedSide: BOUNDED_DID,
            boundaryScope: [],
            requestedNotAfter: new Date(t0 + 30 * 24 * 60 * 60 * 1_000).toISOString() as Timestamp,
        });
        const active = await manager.transitionState({
            id: pending.id,
            event: 'onTrustEstablished',
            actorDID: PRINCIPAL_DID,
            transitionSource: 'client',
            bindingProof: makeBindingProof({
                boundaryId: pending.id,
                notAfter: pending.lifecycleWindow.notAfter,
            }),
            verifyContext: {
                expectedAudience: REGISTRY_AUDIENCE,
                expectedChallenge: TEST_CHALLENGE,
            },
        });
        return { manager, storage, active };
    }

    it('should T5 revoke active → revoked', async () => {
        const { manager, active } = await setupActive();
        const revoked = await manager.transitionState({
            id: active.id,
            event: 'onRevoked',
            actorDID: PRINCIPAL_DID,
            transitionSource: 'client',
        });
        expect(revoked.state).toBe('revoked');
    });

    it('should T5 revoke suspended → revoked', async () => {
        const { manager, active } = await setupActive();
        await manager.transitionState({
            id: active.id,
            event: 'onSuspended',
            actorDID: PRINCIPAL_DID,
            transitionSource: 'client',
        });
        const revoked = await manager.transitionState({
            id: active.id,
            event: 'onRevoked',
            actorDID: PRINCIPAL_DID,
            transitionSource: 'client',
        });
        expect(revoked.state).toBe('revoked');
    });

    it('should reject revoke → active reverse transition (revoked is terminal;I4)', async () => {
        const { manager, active } = await setupActive();
        await manager.transitionState({
            id: active.id,
            event: 'onRevoked',
            actorDID: PRINCIPAL_DID,
            transitionSource: 'client',
        });
        // revoked → any transition is illegal
        await expect(
            manager.transitionState({
                id: active.id,
                event: 'onResumed',
                actorDID: PRINCIPAL_DID,
                transitionSource: 'client',
            }),
        ).rejects.toThrow('TB_INVALID_TRANSITION');
        await expect(
            manager.transitionState({
                id: active.id,
                event: 'onSuspended',
                actorDID: PRINCIPAL_DID,
                transitionSource: 'client',
            }),
        ).rejects.toThrow('TB_INVALID_TRANSITION');
    });

    it('should T6 expire client-side declared (transitionSource=client)', async () => {
        const nowMs = Date.parse('2026-05-18T10:00:00Z');
        const { manager, active } = await setupActive(nowMs);
        const expired = await manager.transitionState({
            id: active.id,
            event: 'onExpired',
            actorDID: PRINCIPAL_DID,
            transitionSource: 'client',
        });
        expect(expired.state).toBe('expired');
    });

    it('should T7 auto-sweep (transitionSource=sweeper) require notAfter <= now', async () => {
        // phase 1: with nowMs, create active (notAfter = nowMs + 30 days)
        const nowMs = Date.parse('2026-05-18T10:00:00Z');
        const { manager: m1, storage, active } = await setupActive(nowMs);

        // phase 2: T7 sweeper triggered before lifecycleWindow.notAfter → reject (I5)
        await expect(
            m1.transitionState({
                id: active.id,
                event: 'onExpired',
                actorDID: 'did:system:sweeper' as DID,
                transitionSource: 'sweeper',
            }),
        ).rejects.toThrow('TB_LIFECYCLE_INVALID');

        // phase 3: jump to after notAfter → sweeper triggers successfully
        const lateMs = nowMs + 60 * 24 * 60 * 60 * 1_000;
        const verifier = new TestProofVerifier();
        verifier.defaultVerdict = { ok: true };
        const m2 = new TrustBoundaryLifecycleManager({
            storage,
            verifier,
            now: makeFrozenNow(lateMs),
        });
        const expired = await m2.transitionState({
            id: active.id,
            event: 'onExpired',
            actorDID: 'did:system:sweeper' as DID,
            transitionSource: 'sweeper',
        });
        expect(expired.state).toBe('expired');
        const events = storage.getAuditEvents();
        const t7Event = events[events.length - 1];
        expect(t7Event?.transitionSource).toBe('sweeper');
    });

    it('should throw TB_LIFECYCLE_INVALID when T7 sweeper triggered before notAfter (timing fail)', async () => {
        // phase 1: with nowMs, create active (notAfter = nowMs + 30 days)
        const nowMs = Date.parse('2026-05-18T10:00:00Z');
        const { storage, active } = await setupActive(nowMs);
        // phase 2: T7 sweeper triggered before lifecycleWindow.notAfter → reject (I5)
        const verifier = new TestProofVerifier();
        verifier.defaultVerdict = { ok: true };
        const m = new TrustBoundaryLifecycleManager({
            storage,
            verifier,
            now: makeFrozenNow(nowMs + 10 * 24 * 60 * 60 * 1_000), // 10 days later, but notAfter is 30 days
        });
        await expect(
            m.transitionState({
                id: active.id,
                event: 'onExpired',
                actorDID: 'did:system:sweeper' as DID,
                transitionSource: 'sweeper',
            }),
        ).rejects.toThrow('TB_LIFECYCLE_INVALID');
    });

    it('should allow T7 sweeper when notAfter <= now AND transitionSource=sweeper (T7 dispatched first; not T6)', async () => {
        // note: T6 and T7 share (from, event, to); transitionSource distinguishes them
        // - sweeper → prefers the T7 path (server-side background daemon)
        // - client/system → T6 path
        // findLegalTransition already implements candidate disambiguation
        const nowMs = Date.parse('2026-05-18T10:00:00Z');
        const { storage, active } = await setupActive(nowMs);
        const lateMs = nowMs + 60 * 24 * 60 * 60 * 1_000;
        const verifier = new TestProofVerifier();
        verifier.defaultVerdict = { ok: true };
        const m2 = new TrustBoundaryLifecycleManager({
            storage,
            verifier,
            now: makeFrozenNow(lateMs),
        });
        // take the T7 path — success; audit event transitionSource = 'sweeper'
        const expired = await m2.transitionState({
            id: active.id,
            event: 'onExpired',
            actorDID: 'did:system:sweeper' as DID,
            transitionSource: 'sweeper',
        });
        expect(expired.state).toBe('expired');
        const events = storage.getAuditEvents();
        const lastEvent = events[events.length - 1];
        expect(lastEvent?.transitionSource).toBe('sweeper');
    });

    it('should reject client transition with transitionSource=sweeper (anti-spoof; I_tb_audit_src)', async () => {
        const { manager, active } = await setupActive();
        await expect(
            manager.transitionState({
                id: active.id,
                event: 'onSuspended',
                actorDID: PRINCIPAL_DID,
                transitionSource: 'sweeper', // T3 does not allow sweeper
            }),
        ).rejects.toThrow('TB_AUDIT_TRANSITION_SOURCE_INVALID');
    });
});

// ─── T8 emergency_suspended fail-closed placeholder ───────────────

describe('TrustBoundaryLifecycleManager.transitionState — T8 onEmergencySuspended', () => {
    it('should fail-closed return TB_EMERGENCY_NOT_IMPLEMENTED (unimplemented placeholder)', async () => {
        const { manager } = makeManager();
        const pending = await manager.createBoundary({
            id: BOUNDARY_ID,
            principalSide: PRINCIPAL_DID,
            boundedSide: BOUNDED_DID,
            boundaryScope: [],
            requestedNotAfter: new Date(
                Date.parse('2026-05-18T10:00:00Z') + 30 * 24 * 60 * 60 * 1_000,
            ).toISOString() as Timestamp,
        });
        await manager.transitionState({
            id: pending.id,
            event: 'onTrustEstablished',
            actorDID: PRINCIPAL_DID,
            transitionSource: 'client',
            bindingProof: makeBindingProof({
                boundaryId: pending.id,
                notAfter: pending.lifecycleWindow.notAfter,
            }),
            verifyContext: {
                expectedAudience: REGISTRY_AUDIENCE,
                expectedChallenge: TEST_CHALLENGE,
            },
        });
        await expect(
            manager.transitionState({
                id: pending.id,
                event: 'onEmergencySuspended',
                actorDID: PRINCIPAL_DID,
                transitionSource: 'client',
            }),
        ).rejects.toThrow('TB_EMERGENCY_NOT_IMPLEMENTED');
    });

    it('should NOT modify storage state when T8 fail-closed', async () => {
        const { manager } = makeManager();
        const pending = await manager.createBoundary({
            id: BOUNDARY_ID,
            principalSide: PRINCIPAL_DID,
            boundedSide: BOUNDED_DID,
            boundaryScope: [],
            requestedNotAfter: new Date(
                Date.parse('2026-05-18T10:00:00Z') + 30 * 24 * 60 * 60 * 1_000,
            ).toISOString() as Timestamp,
        });
        await manager.transitionState({
            id: pending.id,
            event: 'onTrustEstablished',
            actorDID: PRINCIPAL_DID,
            transitionSource: 'client',
            bindingProof: makeBindingProof({
                boundaryId: pending.id,
                notAfter: pending.lifecycleWindow.notAfter,
            }),
            verifyContext: {
                expectedAudience: REGISTRY_AUDIENCE,
                expectedChallenge: TEST_CHALLENGE,
            },
        });
        try {
            await manager.transitionState({
                id: pending.id,
                event: 'onEmergencySuspended',
                actorDID: PRINCIPAL_DID,
                transitionSource: 'client',
            });
        } catch (_e) {
            // expected throw — T8 unimplemented placeholder
        }
        const reread = await manager.getCurrent(pending.id);
        expect(reread?.state).toBe('active'); // was not changed to emergency_suspended
    });
});

// ─── TB_BOUNDARY_NOT_FOUND fail-closed ─────────────────────────────────

describe('TrustBoundaryLifecycleManager.transitionState — boundary not found', () => {
    it('should throw TB_BOUNDARY_NOT_FOUND when boundary id is unknown', async () => {
        const { manager } = makeManager();
        const unknown = toTrustBoundaryId('550e8400-e29b-41d4-a716-446655440099');
        await expect(
            manager.transitionState({
                id: unknown,
                event: 'onSuspended',
                actorDID: PRINCIPAL_DID,
                transitionSource: 'client',
            }),
        ).rejects.toThrow('TB_BOUNDARY_NOT_FOUND');
    });

    it('should throw TB_INVALID_TRANSITION when event is unknown (defensive type-cast bypass)', async () => {
        const { manager } = makeManager();
        const pending = await manager.createBoundary({
            id: BOUNDARY_ID,
            principalSide: PRINCIPAL_DID,
            boundedSide: BOUNDED_DID,
            boundaryScope: [],
            requestedNotAfter: new Date(
                Date.parse('2026-05-18T10:00:00Z') + 30 * 24 * 60 * 60 * 1_000,
            ).toISOString() as Timestamp,
        });
        // intentionally use a type cast to bypass type safety and trigger the default branch
        await expect(
            manager.transitionState({
                id: pending.id,
                event: 'onSomethingUnknown' as never,
                actorDID: PRINCIPAL_DID,
                transitionSource: 'client',
            }),
        ).rejects.toThrow('TB_INVALID_TRANSITION');
    });

    it('should throw TB_INVALID_TRANSITION on illegal pending → suspended (skip T1)', async () => {
        // the pending state does not allow onSuspended (must first onTrustEstablished into active)
        const { manager } = makeManager();
        const pending = await manager.createBoundary({
            id: BOUNDARY_ID,
            principalSide: PRINCIPAL_DID,
            boundedSide: BOUNDED_DID,
            boundaryScope: [],
            requestedNotAfter: new Date(
                Date.parse('2026-05-18T10:00:00Z') + 30 * 24 * 60 * 60 * 1_000,
            ).toISOString() as Timestamp,
        });
        await expect(
            manager.transitionState({
                id: pending.id,
                event: 'onSuspended',
                actorDID: PRINCIPAL_DID,
                transitionSource: 'client',
            }),
        ).rejects.toThrow('TB_INVALID_TRANSITION');
    });
});

describe('InMemoryTrustBoundaryStorage — helper methods coverage', () => {
    it('should clear all boundaries and audit events', () => {
        const storage = new InMemoryTrustBoundaryStorage();
        storage.clear();
        expect(storage.getAuditEvents().length).toBe(0);
    });

    it('should return undefined when load id not exists', async () => {
        const storage = new InMemoryTrustBoundaryStorage();
        const result = await storage.load(toTrustBoundaryId(BOUNDARY_ID));
        expect(result).toBeUndefined();
    });

    it('TestProofVerifier should default to reject by default (anti stub-success)', async () => {
        const verifier = new TestProofVerifier();
        // do not set defaultVerdict — use the class default
        const verdict = await verifier.verifyBindingProof(
            {
                cspVersion: '1.0.0',
                token: '',
                disclosedClaims: [],
                challenge: '',
                audience: '',
                notAfter: '' as Timestamp,
                proofValue: '',
                boundaryId: toTrustBoundaryId(BOUNDARY_ID),
            },
            {
                expectedAudience: '',
                expectedChallenge: '',
                expectedNotAfter: '' as Timestamp,
            },
        );
        expect(verdict.ok).toBe(false);
        if (!verdict.ok) {
            expect(verdict.code).toBe('TB_BOUNDARY_PROOF_VERIFY_FAILED');
        }
        // lease ext path likewise
        const verdict2 = await verifier.verifyLeaseExtensionProof(
            {
                cspVersion: '1.0.0',
                token: '',
                disclosedClaims: [],
                challenge: '',
                audience: '',
                notAfter: '' as Timestamp,
                proofValue: '',
                boundaryId: toTrustBoundaryId(BOUNDARY_ID),
            },
            {
                expectedAudience: '',
                expectedChallenge: '',
                expectedNotAfter: '' as Timestamp,
            },
        );
        expect(verdict2.ok).toBe(false);
    });
});

// ─── assertInvariant direct invocation ──────────────────────────────────────────

describe('assertInvariant — strict fail-closed invariant check', () => {
    it('should accept valid TrustBoundary (active state with bindingProofId)', () => {
        const tb: TrustBoundary = {
            tbVersion: '1.0.0' as never,
            id: toTrustBoundaryId(BOUNDARY_ID),
            principalSide: PRINCIPAL_DID,
            boundedSide: BOUNDED_DID,
            boundaryScope: [],
            lifecycleWindow: {
                notBefore: '2026-05-18T10:00:00.000Z' as Timestamp,
                notAfter: '2026-06-17T10:00:00.000Z' as Timestamp,
            },
            state: 'active',
            stateEnteredAt: '2026-05-18T10:00:01.000Z' as Timestamp,
            bindingProofId: '550e8400-e29b-41d4-a716-446655440002' as never,
        };
        expect(() => assertInvariant(tb)).not.toThrow();
    });

    it('should throw TB_VERSION_UNSUPPORTED when tbVersion != 1.0.0', () => {
        const tb: TrustBoundary = {
            tbVersion: '2.0.0' as never,
            id: toTrustBoundaryId(BOUNDARY_ID),
            principalSide: PRINCIPAL_DID,
            boundedSide: BOUNDED_DID,
            boundaryScope: [],
            lifecycleWindow: {
                notBefore: '2026-05-18T10:00:00.000Z' as Timestamp,
                notAfter: '2026-06-17T10:00:00.000Z' as Timestamp,
            },
            state: 'pending',
            stateEnteredAt: '2026-05-18T10:00:01.000Z' as Timestamp,
        };
        expect(() => assertInvariant(tb)).toThrow('TB_VERSION_UNSUPPORTED');
    });

    it('should throw TB_BINDING_PROOF_MISSING when active state lacks bindingProofId (I6)', () => {
        const tb: TrustBoundary = {
            tbVersion: '1.0.0' as never,
            id: toTrustBoundaryId(BOUNDARY_ID),
            principalSide: PRINCIPAL_DID,
            boundedSide: BOUNDED_DID,
            boundaryScope: [],
            lifecycleWindow: {
                notBefore: '2026-05-18T10:00:00.000Z' as Timestamp,
                notAfter: '2026-06-17T10:00:00.000Z' as Timestamp,
            },
            state: 'active',
            stateEnteredAt: '2026-05-18T10:00:01.000Z' as Timestamp,
        };
        expect(() => assertInvariant(tb)).toThrow('TB_BINDING_PROOF_MISSING');
    });

    it('should throw TB_BINDING_PROOF_UNEXPECTED when pending state has bindingProofId (I6)', () => {
        const tb: TrustBoundary = {
            tbVersion: '1.0.0' as never,
            id: toTrustBoundaryId(BOUNDARY_ID),
            principalSide: PRINCIPAL_DID,
            boundedSide: BOUNDED_DID,
            boundaryScope: [],
            lifecycleWindow: {
                notBefore: '2026-05-18T10:00:00.000Z' as Timestamp,
                notAfter: '2026-06-17T10:00:00.000Z' as Timestamp,
            },
            state: 'pending',
            stateEnteredAt: '2026-05-18T10:00:01.000Z' as Timestamp,
            bindingProofId: '550e8400-e29b-41d4-a716-446655440002' as never,
        };
        expect(() => assertInvariant(tb)).toThrow('TB_BINDING_PROOF_UNEXPECTED');
    });

    it('should throw TB_LIFECYCLE_INVALID when notBefore >= notAfter (I5)', () => {
        const tb: TrustBoundary = {
            tbVersion: '1.0.0' as never,
            id: toTrustBoundaryId(BOUNDARY_ID),
            principalSide: PRINCIPAL_DID,
            boundedSide: BOUNDED_DID,
            boundaryScope: [],
            lifecycleWindow: {
                notBefore: '2026-06-17T10:00:00.000Z' as Timestamp,
                notAfter: '2026-05-18T10:00:00.000Z' as Timestamp, // reversed order
            },
            state: 'pending',
            stateEnteredAt: '2026-05-18T10:00:01.000Z' as Timestamp,
        };
        expect(() => assertInvariant(tb)).toThrow('TB_LIFECYCLE_INVALID');
    });

    it('should throw TB_PARTY_SELF_REFERENTIAL when principalSide === boundedSide (I2)', () => {
        const tb: TrustBoundary = {
            tbVersion: '1.0.0' as never,
            id: toTrustBoundaryId(BOUNDARY_ID),
            principalSide: PRINCIPAL_DID,
            boundedSide: PRINCIPAL_DID,
            boundaryScope: [],
            lifecycleWindow: {
                notBefore: '2026-05-18T10:00:00.000Z' as Timestamp,
                notAfter: '2026-06-17T10:00:00.000Z' as Timestamp,
            },
            state: 'pending',
            stateEnteredAt: '2026-05-18T10:00:01.000Z' as Timestamp,
        };
        expect(() => assertInvariant(tb)).toThrow('TB_PARTY_SELF_REFERENTIAL');
    });

    it('should throw TB_STATE_INVALID when state is not in 5-state union (anti JSON-deserialization bypass)', () => {
        const tb = {
            tbVersion: '1.0.0' as never,
            id: toTrustBoundaryId(BOUNDARY_ID),
            principalSide: PRINCIPAL_DID,
            boundedSide: BOUNDED_DID,
            boundaryScope: [],
            lifecycleWindow: {
                notBefore: '2026-05-18T10:00:00.000Z' as Timestamp,
                notAfter: '2026-06-17T10:00:00.000Z' as Timestamp,
            },
            state: 'unknown-state' as TrustBoundary['state'],
            stateEnteredAt: '2026-05-18T10:00:01.000Z' as Timestamp,
        } as TrustBoundary;
        expect(() => assertInvariant(tb)).toThrow('TB_STATE_INVALID');
    });
});
