/**
 * handshake-integration — handshake middleware + envelope receive verify unit tests
 *
 * Coverage targets:
 * - onHandshakeComplete: the full pending → active flow + the I7+I8+I9 fail-closed paths
 * - assertBoundaryActive: the fail-closed path for each of the 5 state branches
 *   - active → pass
 *   - pending → TB_STATE_INVALID
 *   - suspended → TB_SUSPENDED_OPERATION_DENIED
 *   - revoked → TB_BOUNDARY_EXPIRED
 *   - expired → TB_BOUNDARY_EXPIRED
 *   - not found → TB_BOUNDARY_NOT_FOUND
 * - onLeaseExtension: lease-only renewal
 *
 * Covered behaviors:
 * - the trust boundary establishment flow
 * - T2 onLeaseExtended lease-only
 * - verify the trust-boundary is ESTABLISHED before receiving an envelope
 */

import { describe, expect, it } from 'vitest';

import type { DID, Timestamp } from '@coivitas/types';

import {
    InMemoryTrustBoundaryStorage,
    TestProofVerifier,
    TbProtocolError,
    TrustBoundaryLifecycleManager,
    createHandshakeBoundaryMiddleware,
    toTrustBoundaryId,
} from '../index.js';

const PRINCIPAL_DID = 'did:agent:principal-alice' as DID;
const BOUNDED_DID = 'did:agent:bounded-bob' as DID;
const REGISTRY_AUDIENCE = 'https://trust-boundary.coivitas.ai/v1/boundaries';
const TEST_CHALLENGE = 'challenge-uuid-12345';
const BOUNDARY_ID = '550e8400-e29b-41d4-a716-446655440010';

function makeMiddleware(opts?: {
    nowMs?: number;
    verifierVerdict?:
        | { ok: true }
        | { ok: false; code: 'TB_BOUNDARY_PROOF_VERIFY_FAILED'; message: string };
}): {
    middleware: ReturnType<typeof createHandshakeBoundaryMiddleware>;
    manager: TrustBoundaryLifecycleManager;
    storage: InMemoryTrustBoundaryStorage;
    verifier: TestProofVerifier;
    nowMs: number;
} {
    const nowMs = opts?.nowMs ?? Date.parse('2026-05-18T10:00:00Z');
    const storage = new InMemoryTrustBoundaryStorage();
    const verifier = new TestProofVerifier();
    verifier.defaultVerdict = opts?.verifierVerdict ?? { ok: true };
    const manager = new TrustBoundaryLifecycleManager({
        storage,
        verifier,
        now: () => new Date(nowMs),
    });
    const middleware = createHandshakeBoundaryMiddleware({ manager });
    return { middleware, manager, storage, verifier, nowMs };
}

function makeBindingProofPayload(opts: { notAfter: string }): {
    cspVersion: string;
    token: string;
    disclosedClaims: readonly string[];
    challenge: string;
    audience: string;
    notAfter: string;
    proofValue: string;
} {
    return {
        cspVersion: '1.0.0',
        token: 'binding-proof-token',
        disclosedClaims: [],
        challenge: TEST_CHALLENGE,
        audience: REGISTRY_AUDIENCE,
        notAfter: opts.notAfter,
        proofValue: 'ed25519-signature-stub',
    };
}

describe('handshake-integration.onHandshakeComplete — pending → active full flow', () => {
    it('should complete handshake + create active boundary when verifier accepts', async () => {
        const { middleware, nowMs } = makeMiddleware();
        // key — server-enforced notAfter = nowMs + 30 days (within the maxLifecycleWindow of 6 months)
        const requestedNotAfter = new Date(
            nowMs + 30 * 24 * 60 * 60 * 1_000,
        ).toISOString();
        const boundary = await middleware.onHandshakeComplete(
            {
                expectedAudience: REGISTRY_AUDIENCE,
                expectedChallenge: TEST_CHALLENGE,
                principalSide: PRINCIPAL_DID,
                boundedSide: BOUNDED_DID,
                boundaryScope: ['scope:read'],
                requestedNotAfter,
                boundaryId: BOUNDARY_ID,
            },
            makeBindingProofPayload({ notAfter: requestedNotAfter }),
            PRINCIPAL_DID,
        );
        expect(boundary.state).toBe('active');
        expect(boundary.principalSide).toBe(PRINCIPAL_DID);
        expect(boundary.boundedSide).toBe(BOUNDED_DID);
        expect(boundary.bindingProofId).toBeDefined();
    });

    it('should fail-closed when verifier rejects (TB_BOUNDARY_PROOF_VERIFY_FAILED)', async () => {
        const { middleware, nowMs } = makeMiddleware({
            verifierVerdict: {
                ok: false,
                code: 'TB_BOUNDARY_PROOF_VERIFY_FAILED',
                message: 'Ed25519 verify failed in test',
            },
        });
        const requestedNotAfter = new Date(
            nowMs + 30 * 24 * 60 * 60 * 1_000,
        ).toISOString();
        await expect(
            middleware.onHandshakeComplete(
                {
                    expectedAudience: REGISTRY_AUDIENCE,
                    expectedChallenge: TEST_CHALLENGE,
                    principalSide: PRINCIPAL_DID,
                    boundedSide: BOUNDED_DID,
                    boundaryScope: [],
                    requestedNotAfter,
                    boundaryId: BOUNDARY_ID,
                },
                makeBindingProofPayload({ notAfter: requestedNotAfter }),
                PRINCIPAL_DID,
            ),
        ).rejects.toThrow('TB_BOUNDARY_PROOF_VERIFY_FAILED');
    });

    it('should fail-closed I8 when bindingProof.notAfter mismatches server-enforced', async () => {
        const { middleware, nowMs } = makeMiddleware();
        const serverEnforced = new Date(
            nowMs + 30 * 24 * 60 * 60 * 1_000,
        ).toISOString();
        // intentionally set bindingProof.notAfter to a different value — server rejects (I8)
        const clientForged = new Date(
            nowMs + 60 * 24 * 60 * 60 * 1_000,
        ).toISOString();
        await expect(
            middleware.onHandshakeComplete(
                {
                    expectedAudience: REGISTRY_AUDIENCE,
                    expectedChallenge: TEST_CHALLENGE,
                    principalSide: PRINCIPAL_DID,
                    boundedSide: BOUNDED_DID,
                    boundaryScope: [],
                    requestedNotAfter: serverEnforced,
                    boundaryId: BOUNDARY_ID,
                },
                makeBindingProofPayload({ notAfter: clientForged }),
                PRINCIPAL_DID,
            ),
        ).rejects.toThrow('TB_EXPIRY_CLIENT_CONTROLLED');
    });
});

describe('handshake-integration.assertBoundaryActive — envelope receive enforcement', () => {
    async function setupActive(): Promise<{
        middleware: ReturnType<typeof createHandshakeBoundaryMiddleware>;
        manager: TrustBoundaryLifecycleManager;
        boundaryId: ReturnType<typeof toTrustBoundaryId>;
    }> {
        const { middleware, manager, nowMs } = makeMiddleware();
        const requestedNotAfter = new Date(
            nowMs + 30 * 24 * 60 * 60 * 1_000,
        ).toISOString();
        const boundary = await middleware.onHandshakeComplete(
            {
                expectedAudience: REGISTRY_AUDIENCE,
                expectedChallenge: TEST_CHALLENGE,
                principalSide: PRINCIPAL_DID,
                boundedSide: BOUNDED_DID,
                boundaryScope: [],
                requestedNotAfter,
                boundaryId: BOUNDARY_ID,
            },
            makeBindingProofPayload({ notAfter: requestedNotAfter }),
            PRINCIPAL_DID,
        );
        return { middleware, manager, boundaryId: boundary.id };
    }

    it('should pass when boundary state = active', async () => {
        const { middleware, boundaryId } = await setupActive();
        const boundary = await middleware.assertBoundaryActive(boundaryId);
        expect(boundary.state).toBe('active');
    });

    it('should throw TB_BOUNDARY_NOT_FOUND when boundary id unknown', async () => {
        const { middleware } = makeMiddleware();
        const unknown = toTrustBoundaryId('550e8400-e29b-41d4-a716-446655440099');
        await expect(middleware.assertBoundaryActive(unknown)).rejects.toThrow(
            'TB_BOUNDARY_NOT_FOUND',
        );
    });

    it('should throw TB_STATE_INVALID when boundary state = pending', async () => {
        const { middleware, manager, nowMs } = makeMiddleware();
        // only createBoundary (pending), no transitionState
        const requestedNotAfter = new Date(
            nowMs + 30 * 24 * 60 * 60 * 1_000,
        ).toISOString();
        const pending = await manager.createBoundary({
            id: BOUNDARY_ID,
            principalSide: PRINCIPAL_DID,
            boundedSide: BOUNDED_DID,
            boundaryScope: [],
            requestedNotAfter: requestedNotAfter as Timestamp,
        });
        await expect(middleware.assertBoundaryActive(pending.id)).rejects.toThrow(
            'TB_STATE_INVALID',
        );
    });

    it('should throw TB_SUSPENDED_OPERATION_DENIED when boundary state = suspended', async () => {
        const { middleware, manager, boundaryId } = await setupActive();
        await manager.transitionState({
            id: boundaryId,
            event: 'onSuspended',
            actorDID: PRINCIPAL_DID,
            transitionSource: 'client',
        });
        await expect(middleware.assertBoundaryActive(boundaryId)).rejects.toThrow(
            'TB_SUSPENDED_OPERATION_DENIED',
        );
    });

    it('should throw TB_BOUNDARY_EXPIRED when boundary state = revoked', async () => {
        const { middleware, manager, boundaryId } = await setupActive();
        await manager.transitionState({
            id: boundaryId,
            event: 'onRevoked',
            actorDID: PRINCIPAL_DID,
            transitionSource: 'client',
        });
        await expect(middleware.assertBoundaryActive(boundaryId)).rejects.toThrow(
            'TB_BOUNDARY_EXPIRED',
        );
    });

    it('should throw TB_BOUNDARY_EXPIRED when boundary state = expired', async () => {
        const { middleware, manager, boundaryId } = await setupActive();
        await manager.transitionState({
            id: boundaryId,
            event: 'onExpired',
            actorDID: PRINCIPAL_DID,
            transitionSource: 'client',
        });
        await expect(middleware.assertBoundaryActive(boundaryId)).rejects.toThrow(
            'TB_BOUNDARY_EXPIRED',
        );
    });
});

describe('handshake-integration.onLeaseExtension — lease-only', () => {
    it('should T2 extend lease when verifier + I7+I8 pass', async () => {
        const { middleware, nowMs } = makeMiddleware();
        const requestedNotAfter = new Date(
            nowMs + 30 * 24 * 60 * 60 * 1_000,
        ).toISOString();
        const active = await middleware.onHandshakeComplete(
            {
                expectedAudience: REGISTRY_AUDIENCE,
                expectedChallenge: TEST_CHALLENGE,
                principalSide: PRINCIPAL_DID,
                boundedSide: BOUNDED_DID,
                boundaryScope: [],
                requestedNotAfter,
                boundaryId: BOUNDARY_ID,
            },
            makeBindingProofPayload({ notAfter: requestedNotAfter }),
            PRINCIPAL_DID,
        );
        const newNotAfter = new Date(
            nowMs + 60 * 24 * 60 * 60 * 1_000,
        ).toISOString();
        const extended = await middleware.onLeaseExtension(
            {
                boundaryId: active.id,
                requestedNotAfter: newNotAfter,
                expectedAudience: REGISTRY_AUDIENCE,
                expectedChallenge: TEST_CHALLENGE,
            },
            {
                cspVersion: '1.0.0',
                token: 'lease-ext-token',
                disclosedClaims: [],
                challenge: TEST_CHALLENGE,
                audience: REGISTRY_AUDIENCE,
                notAfter: newNotAfter,
                proofValue: 'ed25519-stub',
            },
            PRINCIPAL_DID,
        );
        expect(extended.state).toBe('active');
        expect(extended.lifecycleWindow.notAfter).toBe(newNotAfter);
    });

    it('should fail-closed when verifier rejects lease extension', async () => {
        // phase 1: create active with verifier ok
        const storage = new InMemoryTrustBoundaryStorage();
        const verifier = new TestProofVerifier();
        const nowMs = Date.parse('2026-05-18T10:00:00Z');

        verifier.defaultVerdict = { ok: true };
        const manager1 = new TrustBoundaryLifecycleManager({
            storage,
            verifier,
            now: () => new Date(nowMs),
        });
        const middleware = createHandshakeBoundaryMiddleware({ manager: manager1 });
        const requestedNotAfter = new Date(
            nowMs + 30 * 24 * 60 * 60 * 1_000,
        ).toISOString();
        const active = await middleware.onHandshakeComplete(
            {
                expectedAudience: REGISTRY_AUDIENCE,
                expectedChallenge: TEST_CHALLENGE,
                principalSide: PRINCIPAL_DID,
                boundedSide: BOUNDED_DID,
                boundaryScope: [],
                requestedNotAfter,
                boundaryId: BOUNDARY_ID,
            },
            makeBindingProofPayload({ notAfter: requestedNotAfter }),
            PRINCIPAL_DID,
        );

        // phase 2: flip the verifier to reject — lease extension must fail
        verifier.defaultVerdict = {
            ok: false,
            code: 'TB_BOUNDARY_PROOF_VERIFY_FAILED',
            message: 'lease ext verify failed in test',
        };
        const newNotAfter = new Date(
            nowMs + 60 * 24 * 60 * 60 * 1_000,
        ).toISOString();
        await expect(
            middleware.onLeaseExtension(
                {
                    boundaryId: active.id,
                    requestedNotAfter: newNotAfter,
                    expectedAudience: REGISTRY_AUDIENCE,
                    expectedChallenge: TEST_CHALLENGE,
                },
                {
                    cspVersion: '1.0.0',
                    token: 'lease-ext-token',
                    disclosedClaims: [],
                    challenge: TEST_CHALLENGE,
                    audience: REGISTRY_AUDIENCE,
                    notAfter: newNotAfter,
                    proofValue: 'ed25519-stub',
                },
                PRINCIPAL_DID,
            ),
        ).rejects.toThrow('TB_BOUNDARY_PROOF_VERIFY_FAILED');
    });
});

describe('handshake-integration — TbProtocolError instanceof check', () => {
    it('assertBoundaryActive should throw instanceof TbProtocolError', async () => {
        const { middleware } = makeMiddleware();
        const unknown = toTrustBoundaryId('550e8400-e29b-41d4-a716-446655440099');
        try {
            await middleware.assertBoundaryActive(unknown);
            throw new Error('expected to throw');
        } catch (e) {
            expect(e).toBeInstanceOf(TbProtocolError);
            expect((e as TbProtocolError).code).toBe('TB_BOUNDARY_NOT_FOUND');
        }
    });
});
