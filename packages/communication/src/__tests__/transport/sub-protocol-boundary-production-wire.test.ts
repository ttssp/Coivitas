/* eslint-disable @typescript-eslint/require-await --
 * The boundary wrapper signature takes `() => Promise<T>`; the async throw lambdas in the test
 * do not need await (throw terminates immediately), but lint still reports require-await. Disabling this rule for the whole file is sufficient.
 */

/**
 * sub-protocol boundary production-wire integration test
 *
 * Background:
 *   The boundary wrapper was previously exported but never applied on a production path
 *   (only a test-only caller + the export site).
 *
 *   This test anchors the mandatory L3/L4 boundary wrapper production wire as
 *   actually installed — 6 sub-protocol-specific wrappers (sub-protocol-wrappers.ts) +
 *   6 envelope handler decorators (sub-protocol-handler-decorator.ts), each handling
 *   the production-wire catch path of 1 sub-protocol L0 error class:
 *
 *     case 1: SrError → runSettlementRetryBoundary + withSettlementRetryHandler
 *     case 2: DaError → runDisputeArbitrationBoundary + withDisputeArbitrationHandler
 *     case 3: AuditShareError → runAuditShareBoundary + withAuditShareHandler
 *     case 4: AuditError → runAuditTamperProofBoundary + withAuditTamperProofHandler
 *     case 5: HashChainError → runHashChainBoundary + withHashChainHandler
 *     case 6: CrError → runCredentialResolverBoundary + withCredentialResolverHandler
 *
 *   Each case literally verifies:
 *     (a) Calling the sub-protocol-specific wrapper directly — the sub-protocol L0 error is caught
 *         + unwrapped as ProtocolError('INTERNAL_ERROR', '<SUB_CODE>: <msg>')
 *     (b) After wrapping with the envelope handler decorator, a sub-protocol L0 error thrown inside
 *         the handler is caught at the L4 boundary + converted to a ProtocolError; envelope.id is passed
 *         through as the requestId
 *
 * Anti-phantom enforcement:
 *   The test must really throw + the caller must really catch + the fields must really be verified; stubbed default
 *   success / partial-PASS / export-only substitutes for the anchor are not allowed.
 */

import { describe, expect, it } from 'vitest';

import {
    AuditError,
    AuditShareError,
    CrError,
    DaError,
    HashChainError,
    ProtocolError,
    SrError,
    toSignature,
    type DID,
    type NegotiationEnvelope,
    type Timestamp,
} from '@coivitas/types';

import {
    runAuditShareBoundary,
    runAuditTamperProofBoundary,
    runCredentialResolverBoundary,
    runDisputeArbitrationBoundary,
    runHashChainBoundary,
    runSettlementRetryBoundary,
} from '../../transport/sub-protocol-wrappers.js';

import {
    withAuditShareHandler,
    withAuditTamperProofHandler,
    withCredentialResolverHandler,
    withDisputeArbitrationHandler,
    withHashChainHandler,
    withSettlementRetryHandler,
} from '../../transport/sub-protocol-handler-decorator.js';

// ─── Minimal envelope construction for tests (the transport boundary only needs envelope.id pass-through) ─────

/**
 * Builds a minimal NegotiationEnvelope for decorator tests;
 * the real production path validates the entire field set via parseEnvelope/verifyEnvelope,
 * but the boundary wrap layer only reads envelope.id for requestId pass-through, so the other fields are not required.
 */
/**
 * Notes on test-fixture brand conversion:
 *   - Signature: uses the toSignature factory (base64url runtime validation; no brand cast)
 *   - DID / Timestamp: no public factory; the test fixture path uses a type assertion
 *     (an existing project test-fixture pattern; the production path must not use a bare cast — it must go through a factory)
 *
 * The boundary wrap only reads envelope.id for pass-through; the other fields are not of concern to the wrap.
 */
function makeTestEnvelope(id: string): NegotiationEnvelope {
    return {
        id,
        specVersion: '0.1.0',
        header: {
            senderDid: 'did:test:sender' as DID,
            recipientDid: 'did:test:recipient' as DID,
            sessionId: 'session-test',
            sequenceNumber: 1,
        },
        messageType: 'NEGOTIATION_REQUEST',
        body: {},
        signature: toSignature('a'.repeat(128)),
        timestamp: '2026-05-20T00:00:00.000Z' as Timestamp,
    };
}

// ─── case 1: SrError → settlement-retry boundary ─────────────────────────────

describe('production wire — case 1: SrError from settlement-retry', () => {
    it('should unwrap SrError as ProtocolError when caller invokes runSettlementRetryBoundary', async () => {
        const inner = new SrError('SR_RETRY_EXHAUSTED');
        try {
            await runSettlementRetryBoundary(async () => {
                throw inner;
            }, 'req-sr-1');
            expect.fail('expected ProtocolError throw');
        } catch (err) {
            expect(err).toBeInstanceOf(ProtocolError);
            const pe = err as ProtocolError;
            expect(pe.code).toBe('INTERNAL_ERROR');
            expect(pe.detail).toContain('SR_RETRY_EXHAUSTED');
            expect(pe.requestId).toBe('req-sr-1');
        }
    });

    it('should unwrap SrError when envelope handler decorated by withSettlementRetryHandler', async () => {
        const innerHandler = async (_envelope: NegotiationEnvelope) => {
            throw new SrError('SR_STATE_TRANSITION_INVALID');
        };
        const wrapped = withSettlementRetryHandler(innerHandler);
        const env = makeTestEnvelope('env-sr-1');

        try {
            await wrapped(env);
            expect.fail('expected ProtocolError throw');
        } catch (err) {
            expect(err).toBeInstanceOf(ProtocolError);
            const pe = err as ProtocolError;
            expect(pe.code).toBe('INTERNAL_ERROR');
            expect(pe.detail).toContain('SR_STATE_TRANSITION_INVALID');
            // envelope.id is passed through to ProtocolError.requestId (audit log correlation)
            expect(pe.requestId).toBe('env-sr-1');
        }
    });
});

// ─── case 2: DaError → dispute-arbitration boundary ──────────────────────────

describe('production wire — case 2: DaError from dispute-arbitration', () => {
    it('should unwrap DaError as ProtocolError when caller invokes runDisputeArbitrationBoundary', async () => {
        const inner = new DaError('DA_STATE_TRANSITION_INVALID');
        try {
            await runDisputeArbitrationBoundary(async () => {
                throw inner;
            }, 'req-da-1');
            expect.fail('expected ProtocolError throw');
        } catch (err) {
            expect(err).toBeInstanceOf(ProtocolError);
            const pe = err as ProtocolError;
            expect(pe.code).toBe('INTERNAL_ERROR');
            expect(pe.detail).toContain('DA_STATE_TRANSITION_INVALID');
            expect(pe.requestId).toBe('req-da-1');
        }
    });

    it('should unwrap DaError when envelope handler decorated by withDisputeArbitrationHandler', async () => {
        const innerHandler = async (_envelope: NegotiationEnvelope) => {
            throw new DaError('DA_ARBITRATOR_INSUFFICIENT');
        };
        const wrapped = withDisputeArbitrationHandler(innerHandler);
        const env = makeTestEnvelope('env-da-1');

        try {
            await wrapped(env);
            expect.fail('expected ProtocolError throw');
        } catch (err) {
            expect(err).toBeInstanceOf(ProtocolError);
            const pe = err as ProtocolError;
            expect(pe.code).toBe('INTERNAL_ERROR');
            expect(pe.detail).toContain('DA_ARBITRATOR_INSUFFICIENT');
            expect(pe.requestId).toBe('env-da-1');
        }
    });
});

// ─── case 3: AuditShareError → audit-share boundary ──────────────────────────

describe('production wire — case 3: AuditShareError from audit-share', () => {
    it('should unwrap AuditShareError as ProtocolError when caller invokes runAuditShareBoundary', async () => {
        const inner = new AuditShareError(
            'AUDIT_SHARE_SCHEMA_INVALID',
            'schema fail',
        );
        try {
            await runAuditShareBoundary(async () => {
                throw inner;
            }, 'req-as-1');
            expect.fail('expected ProtocolError throw');
        } catch (err) {
            expect(err).toBeInstanceOf(ProtocolError);
            const pe = err as ProtocolError;
            expect(pe.code).toBe('INTERNAL_ERROR');
            expect(pe.detail).toContain('AUDIT_SHARE_SCHEMA_INVALID');
            expect(pe.requestId).toBe('req-as-1');
        }
    });

    it('should unwrap AuditShareError when envelope handler decorated by withAuditShareHandler', async () => {
        const innerHandler = async (_envelope: NegotiationEnvelope) => {
            throw new AuditShareError('AUDIT_SHARE_TOKEN_INVALID', 'token bad');
        };
        const wrapped = withAuditShareHandler(innerHandler);
        const env = makeTestEnvelope('env-as-1');

        try {
            await wrapped(env);
            expect.fail('expected ProtocolError throw');
        } catch (err) {
            expect(err).toBeInstanceOf(ProtocolError);
            const pe = err as ProtocolError;
            expect(pe.code).toBe('INTERNAL_ERROR');
            expect(pe.detail).toContain('AUDIT_SHARE_TOKEN_INVALID');
            expect(pe.requestId).toBe('env-as-1');
        }
    });
});

// ─── case 4: AuditError → audit-tamper-proof boundary ────────────────────────

describe('production wire — case 4: AuditError from audit-tamper-proof', () => {
    it('should unwrap AuditError as ProtocolError when caller invokes runAuditTamperProofBoundary', async () => {
        const inner = new AuditError(
            'AUDIT_HASH_CHAIN_BROKEN',
            'hash chain broken at chainPosition 42',
        );
        try {
            await runAuditTamperProofBoundary(async () => {
                throw inner;
            }, 'req-atp-1');
            expect.fail('expected ProtocolError throw');
        } catch (err) {
            expect(err).toBeInstanceOf(ProtocolError);
            const pe = err as ProtocolError;
            expect(pe.code).toBe('INTERNAL_ERROR');
            expect(pe.detail).toContain('AUDIT_HASH_CHAIN_BROKEN');
            expect(pe.requestId).toBe('req-atp-1');
        }
    });

    it('should unwrap AuditError when envelope handler decorated by withAuditTamperProofHandler', async () => {
        const innerHandler = async (_envelope: NegotiationEnvelope) => {
            throw new AuditError(
                'AUDIT_TENANT_SCOPE_VIOLATION',
                'tenant scope violated',
            );
        };
        const wrapped = withAuditTamperProofHandler(innerHandler);
        const env = makeTestEnvelope('env-atp-1');

        try {
            await wrapped(env);
            expect.fail('expected ProtocolError throw');
        } catch (err) {
            expect(err).toBeInstanceOf(ProtocolError);
            const pe = err as ProtocolError;
            expect(pe.code).toBe('INTERNAL_ERROR');
            expect(pe.detail).toContain('AUDIT_TENANT_SCOPE_VIOLATION');
            expect(pe.requestId).toBe('env-atp-1');
        }
    });
});

// ─── case 5: HashChainError → hcc boundary ───────────────────────────────────

describe('production wire — case 5: HashChainError from hcc', () => {
    it('should unwrap HashChainError as ProtocolError when caller invokes runHashChainBoundary', async () => {
        const inner = new HashChainError(
            'HC_PREVIOUS_HASH_BROKEN',
            'previous hash mismatch at entry 7',
        );
        try {
            await runHashChainBoundary(async () => {
                throw inner;
            }, 'req-hc-1');
            expect.fail('expected ProtocolError throw');
        } catch (err) {
            expect(err).toBeInstanceOf(ProtocolError);
            const pe = err as ProtocolError;
            expect(pe.code).toBe('INTERNAL_ERROR');
            expect(pe.detail).toContain('HC_PREVIOUS_HASH_BROKEN');
            expect(pe.requestId).toBe('req-hc-1');
        }
    });

    it('should unwrap HashChainError when envelope handler decorated by withHashChainHandler', async () => {
        const innerHandler = async (_envelope: NegotiationEnvelope) => {
            throw new HashChainError(
                'HC_PREVIOUS_HASH_BROKEN',
                'chain integrity violation',
            );
        };
        const wrapped = withHashChainHandler(innerHandler);
        const env = makeTestEnvelope('env-hc-1');

        try {
            await wrapped(env);
            expect.fail('expected ProtocolError throw');
        } catch (err) {
            expect(err).toBeInstanceOf(ProtocolError);
            const pe = err as ProtocolError;
            expect(pe.code).toBe('INTERNAL_ERROR');
            expect(pe.detail).toContain('HC_PREVIOUS_HASH_BROKEN');
            expect(pe.requestId).toBe('env-hc-1');
        }
    });
});

// ─── case 6: CrError → credential-resolver boundary ──────────────────────────

describe('production wire — case 6: CrError from credential-resolver', () => {
    it('should unwrap CrError as ProtocolError when caller invokes runCredentialResolverBoundary', async () => {
        const inner = new CrError('CR_OIDC_CLAIM_INVALID');
        try {
            await runCredentialResolverBoundary(async () => {
                throw inner;
            }, 'req-cr-1');
            expect.fail('expected ProtocolError throw');
        } catch (err) {
            expect(err).toBeInstanceOf(ProtocolError);
            const pe = err as ProtocolError;
            expect(pe.code).toBe('INTERNAL_ERROR');
            expect(pe.detail).toContain('CR_OIDC_CLAIM_INVALID');
            expect(pe.requestId).toBe('req-cr-1');
        }
    });

    it('should unwrap CrError when envelope handler decorated by withCredentialResolverHandler', async () => {
        const innerHandler = async (_envelope: NegotiationEnvelope) => {
            throw new CrError('CR_OIDC_CLAIM_INVALID');
        };
        const wrapped = withCredentialResolverHandler(innerHandler);
        const env = makeTestEnvelope('env-cr-1');

        try {
            await wrapped(env);
            expect.fail('expected ProtocolError throw');
        } catch (err) {
            expect(err).toBeInstanceOf(ProtocolError);
            const pe = err as ProtocolError;
            expect(pe.code).toBe('INTERNAL_ERROR');
            expect(pe.detail).toContain('CR_OIDC_CLAIM_INVALID');
            expect(pe.requestId).toBe('env-cr-1');
        }
    });
});

// ─── cross-case sanity — ProtocolError pass-through + success path not broken ────────────────

describe('production wire — cross-case sanity invariants', () => {
    it('should pass-through ProtocolError unchanged when sub-protocol-specific wrapper sees existing ProtocolError', async () => {
        // The ProtocolError was already thrown at the L3+ boundary and should not be wrapped in another layer (to avoid
        // stacking the detail field with duplicate '${sub-code}: ${msg}')
        const original = new ProtocolError(
            'AUTHORIZATION_INSUFFICIENT',
            'pre-wrapped detail',
            'req-pre-wrapped',
        );
        await expect(
            runSettlementRetryBoundary(async () => {
                throw original;
            }),
        ).rejects.toBe(original);
    });

    it('should preserve return value when sub-protocol op succeeds (no error path)', async () => {
        const result = await runAuditShareBoundary(async () => ({
            ok: true,
            data: [1, 2, 3],
        }));
        expect(result).toEqual({ ok: true, data: [1, 2, 3] });
    });

    it('should preserve handler return value when decorator wraps successful handler', async () => {
        const env = makeTestEnvelope('env-success');
        const innerHandler = async (incoming: NegotiationEnvelope) => {
            // happy path: the handler returns a response envelope normally (echo style)
            return {
                ...incoming,
                id: `${incoming.id}-response`,
            } as NegotiationEnvelope;
        };
        const wrapped = withHashChainHandler(innerHandler);
        const result = await wrapped(env);
        expect(result).not.toBeNull();
        expect(result?.id).toBe('env-success-response');
    });
});
