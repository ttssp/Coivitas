/**
 * EnvelopeDiscoveryDispatcher unit tests
 *
 * Covers all 6 steps of the dispatch flow + fail-closed paths + validateDiscoveryResponseBody.
 *
 * Acceptance criteria: lines >= 95%, branches >= 90%
 */

import { describe, expect, it, vi } from 'vitest';
import { generateKeyPair, verify, canonicalize } from '@coivitas/crypto';
import type {
    DID,
    DiscoveryResponseBody,
    NegotiationEnvelope,
    Signature,
    Timestamp,
} from '@coivitas/types';
import { SPEC_VERSION_0_3_0 } from '@coivitas/types';
import {
    EnvelopeDiscoveryDispatcher,
    validateDiscoveryResponseBody,
    type DiscoveryHandler,
} from '../envelope-discovery.js';

// ── Test constants ────────────────────────────────────────────────────────────

const AGENT_DID_A = 'did:agent:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' as DID;
const AGENT_DID_B = 'did:agent:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' as DID;
const AGENT_DID_C = 'did:agent:cccccccccccccccccccccccccccccccccccccccc' as DID;

const NOW_ISO = '2026-05-01T12:00:00.000Z';
const NOW_MS = new Date(NOW_ISO).getTime();

// ── Test helpers ───────────────────────────────────────────────────────────────

/**
 * Builds a minimal valid NegotiationEnvelope (a fake signature is fine; the dispatcher does not verify it)
 */
function makeDiscoveryRequestEnvelope(overrides?: {
    specVersion?: string;
    body?: Record<string, unknown>;
    senderDid?: DID;
    recipientDid?: DID;
}): NegotiationEnvelope {
    const requestedAt = NOW_ISO as Timestamp;
    const body: Record<string, unknown> = overrides?.body ?? {
        targetDid: AGENT_DID_C,
        requestedAt,
    };

    return {
        id: 'test-envelope-id-1234',
        specVersion: overrides?.specVersion ?? SPEC_VERSION_0_3_0,
        header: {
            senderDid: overrides?.senderDid ?? AGENT_DID_A,
            recipientDid: overrides?.recipientDid ?? AGENT_DID_B,
            sessionId: null,
        },
        messageType: 'DISCOVERY_REQUEST',
        body,
        signature: 'a'.repeat(128) as unknown as Signature,
        timestamp: NOW_ISO as Timestamp,
    };
}

/**
 * Builds a valid DiscoveryResponseBody
 */
function makeResponseBody(targetDid: DID = AGENT_DID_C): DiscoveryResponseBody {
    return {
        agentDid: targetDid,
        agentCardJson: JSON.stringify({ id: targetDid, specVersion: '0.3.0' }),
        respondedAt: NOW_ISO as Timestamp,
        documentVersion: 1,
    };
}

/**
 * Builds an EnvelopeDiscoveryDispatcher (privateKey is an already-generated Ed25519 key)
 */
function makeDispatcher(options?: { clockSkewMs?: number; nowMs?: number }) {
    const { privateKey } = generateKeyPair();
    const dispatcher = new EnvelopeDiscoveryDispatcher({
        responderDid: AGENT_DID_B,
        responderPrivateKey: privateKey,
        clockSkewMs: options?.clockSkewMs,
        now: () => options?.nowMs ?? NOW_MS,
    });
    return { dispatcher, privateKey };
}

// ── Tests ──────────────────────────────────────────────────────────────────────

describe('EnvelopeDiscoveryDispatcher.dispatch()', () => {
    // ── [1] specVersion gate ──────────────────────────────────────────────────

    describe('step [1]: specVersion gate', () => {
        it('should return INVALID_MESSAGE ERROR when specVersion is 0.1.0', async () => {
            const { dispatcher } = makeDispatcher();
            const envelope = makeDiscoveryRequestEnvelope({
                specVersion: '0.1.0',
            });

            const result = await dispatcher.dispatch(envelope);

            expect(result.messageType).toBe('ERROR');
            expect(result.body.code).toBe('INVALID_MESSAGE');
            expect(String(result.body.message)).toContain('0.1.0');
        });

        it('should return INVALID_MESSAGE ERROR when specVersion is 0.2.0', async () => {
            const { dispatcher } = makeDispatcher();
            const envelope = makeDiscoveryRequestEnvelope({
                specVersion: '0.2.0',
            });

            const result = await dispatcher.dispatch(envelope);

            expect(result.messageType).toBe('ERROR');
            expect(result.body.code).toBe('INVALID_MESSAGE');
        });

        it('should return INVALID_MESSAGE ERROR when specVersion is empty string', async () => {
            const { dispatcher } = makeDispatcher();
            const envelope = makeDiscoveryRequestEnvelope({ specVersion: '' });

            const result = await dispatcher.dispatch(envelope);

            expect(result.messageType).toBe('ERROR');
            expect(result.body.code).toBe('INVALID_MESSAGE');
        });

        it('should accept specVersion 0.3.0 and proceed to next step', async () => {
            const { dispatcher } = makeDispatcher();
            // No handler registered; expect to reach step [3] (DISCOVERY_NOT_SUPPORTED)
            const envelope = makeDiscoveryRequestEnvelope({
                specVersion: '0.3.0',
            });

            const result = await dispatcher.dispatch(envelope);

            // Not an error produced by the specVersion gate (specVersion passed)
            expect(result.body.code).not.toBe('SPEC_VERSION_MISMATCH');
        });
    });

    // ── [2] body parsing ──────────────────────────────────────────────────────

    describe('step [2]: body parsing', () => {
        it('should return INVALID_MESSAGE when targetDid is missing', async () => {
            const { dispatcher } = makeDispatcher();
            const envelope = makeDiscoveryRequestEnvelope({
                body: { requestedAt: NOW_ISO },
            });

            const result = await dispatcher.dispatch(envelope);

            expect(result.messageType).toBe('ERROR');
            expect(result.body.code).toBe('INVALID_MESSAGE');
            expect(String(result.body.message)).toContain('targetDid');
        });

        it('should return INVALID_MESSAGE when targetDid has wrong format', async () => {
            const { dispatcher } = makeDispatcher();
            const envelope = makeDiscoveryRequestEnvelope({
                body: {
                    targetDid: 'did:key:z6Mktest',
                    requestedAt: NOW_ISO,
                },
            });

            const result = await dispatcher.dispatch(envelope);

            expect(result.messageType).toBe('ERROR');
            expect(result.body.code).toBe('INVALID_MESSAGE');
        });

        it('should return INVALID_MESSAGE when requestedAt is missing', async () => {
            const { dispatcher } = makeDispatcher();
            const envelope = makeDiscoveryRequestEnvelope({
                body: { targetDid: AGENT_DID_C },
            });

            const result = await dispatcher.dispatch(envelope);

            expect(result.messageType).toBe('ERROR');
            expect(result.body.code).toBe('INVALID_MESSAGE');
            expect(String(result.body.message)).toContain('requestedAt');
        });

        it('should return INVALID_MESSAGE when requestedAt format is invalid', async () => {
            const { dispatcher } = makeDispatcher();
            const envelope = makeDiscoveryRequestEnvelope({
                body: {
                    targetDid: AGENT_DID_C,
                    requestedAt: '2026/05/01 12:00:00',
                },
            });

            const result = await dispatcher.dispatch(envelope);

            expect(result.messageType).toBe('ERROR');
            expect(result.body.code).toBe('INVALID_MESSAGE');
        });

        it('should return INVALID_MESSAGE when body has unknown fields', async () => {
            const { dispatcher } = makeDispatcher();
            const envelope = makeDiscoveryRequestEnvelope({
                body: {
                    targetDid: AGENT_DID_C,
                    requestedAt: NOW_ISO,
                    extraField: 'should-be-rejected',
                },
            });

            const result = await dispatcher.dispatch(envelope);

            expect(result.messageType).toBe('ERROR');
            expect(result.body.code).toBe('INVALID_MESSAGE');
            expect(String(result.body.message)).toContain('extraField');
        });
    });

    // ── [2.5] clock skew ───────────────────────────────────────────────────────

    describe('step [2.5]: clock skew validation', () => {
        it('should return CLOCK_SKEW_EXCEEDED when requestedAt is 6 minutes in the past', async () => {
            const clockSkewMs = 300_000; // 5 minutes
            const { dispatcher } = makeDispatcher({
                clockSkewMs,
                nowMs: NOW_MS,
            });

            // 6 minutes ago
            const oldRequestedAt = new Date(
                NOW_MS - 360_000,
            ).toISOString() as Timestamp;
            const envelope = makeDiscoveryRequestEnvelope({
                body: {
                    targetDid: AGENT_DID_C,
                    requestedAt: oldRequestedAt,
                },
            });

            const result = await dispatcher.dispatch(envelope);

            expect(result.messageType).toBe('ERROR');
            expect(result.body.code).toBe('CLOCK_SKEW_EXCEEDED');
        });

        it('should return CLOCK_SKEW_EXCEEDED when requestedAt is 6 minutes in the future', async () => {
            const { dispatcher } = makeDispatcher({ nowMs: NOW_MS });

            const futureRequestedAt = new Date(
                NOW_MS + 360_000,
            ).toISOString() as Timestamp;
            const envelope = makeDiscoveryRequestEnvelope({
                body: {
                    targetDid: AGENT_DID_C,
                    requestedAt: futureRequestedAt,
                },
            });

            const result = await dispatcher.dispatch(envelope);

            expect(result.messageType).toBe('ERROR');
            expect(result.body.code).toBe('CLOCK_SKEW_EXCEEDED');
        });

        it('should accept requestedAt within default clockSkew window', async () => {
            const { dispatcher } = makeDispatcher({ nowMs: NOW_MS });

            // 2 minutes ago (within the 5-minute window)
            const recentRequestedAt = new Date(
                NOW_MS - 120_000,
            ).toISOString() as Timestamp;
            const envelope = makeDiscoveryRequestEnvelope({
                body: {
                    targetDid: AGENT_DID_C,
                    requestedAt: recentRequestedAt,
                },
            });

            const result = await dispatcher.dispatch(envelope);

            // clockSkew passes (no handler registered, so the result is DISCOVERY_NOT_SUPPORTED)
            expect(result.body.code).toBe('DISCOVERY_NOT_SUPPORTED');
        });
    });

    // ── [3] handler not registered ────────────────────────────────────────────

    describe('step [3]: handler not registered', () => {
        it('should return DISCOVERY_NOT_SUPPORTED when no handler is registered', async () => {
            const { dispatcher } = makeDispatcher();
            const envelope = makeDiscoveryRequestEnvelope();

            const result = await dispatcher.dispatch(envelope);

            expect(result.messageType).toBe('ERROR');
            expect(result.body.code).toBe('DISCOVERY_NOT_SUPPORTED');
            expect(String(result.body.message)).toContain(
                'DISCOVERY_NOT_SUPPORTED',
            );
        });

        it('should include relatedEnvelopeId in error body', async () => {
            const { dispatcher } = makeDispatcher();
            const envelope = makeDiscoveryRequestEnvelope();

            const result = await dispatcher.dispatch(envelope);

            expect(result.body.relatedEnvelopeId).toBe(envelope.id);
        });
    });

    // ── [4] handler invocation ────────────────────────────────────────────────

    describe('step [4]: handler invocation', () => {
        it('should return AGENT_CARD_NOT_FOUND when handler returns null', async () => {
            const { dispatcher } = makeDispatcher();
            const handler: DiscoveryHandler = vi.fn().mockResolvedValue(null);
            dispatcher.registerDiscoveryHandler(handler);

            const envelope = makeDiscoveryRequestEnvelope();
            const result = await dispatcher.dispatch(envelope);

            expect(result.messageType).toBe('ERROR');
            expect(result.body.code).toBe('AGENT_CARD_NOT_FOUND');
        });

        it('should return INTERNAL_ERROR when handler throws', async () => {
            const { dispatcher } = makeDispatcher();
            const handler: DiscoveryHandler = vi
                .fn()
                .mockRejectedValue(new Error('DB connection failed'));
            dispatcher.registerDiscoveryHandler(handler);

            const envelope = makeDiscoveryRequestEnvelope();
            const result = await dispatcher.dispatch(envelope);

            expect(result.messageType).toBe('ERROR');
            expect(result.body.code).toBe('INTERNAL_ERROR');
            expect(String(result.body.message)).toContain(
                'DB connection failed',
            );
        });

        it('should pass correct request + senderDid to handler', async () => {
            const { dispatcher } = makeDispatcher();
            const handler: DiscoveryHandler = vi
                .fn()
                .mockResolvedValue(makeResponseBody());
            dispatcher.registerDiscoveryHandler(handler);

            const envelope = makeDiscoveryRequestEnvelope({
                senderDid: AGENT_DID_A,
            });
            await dispatcher.dispatch(envelope);

            expect(handler).toHaveBeenCalledWith(
                expect.objectContaining({
                    targetDid: AGENT_DID_C,
                    // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
                    requestedAt: expect.any(String),
                }),
                AGENT_DID_A,
            );
        });
    });

    // ── [5] DISCOVERY_RESPONSE envelope build ─────────────────────────────────

    describe('step [5]: DISCOVERY_RESPONSE envelope build', () => {
        it('should return DISCOVERY_RESPONSE envelope when handler succeeds', async () => {
            const { dispatcher } = makeDispatcher();
            const responseBody = makeResponseBody(AGENT_DID_C);
            const handler: DiscoveryHandler = vi
                .fn()
                .mockResolvedValue(responseBody);
            dispatcher.registerDiscoveryHandler(handler);

            const envelope = makeDiscoveryRequestEnvelope();
            const result = await dispatcher.dispatch(envelope);

            expect(result.messageType).toBe('DISCOVERY_RESPONSE');
            expect(result.specVersion).toBe(SPEC_VERSION_0_3_0);
        });

        it('should set correct body fields in DISCOVERY_RESPONSE', async () => {
            const { dispatcher } = makeDispatcher();
            const responseBody = makeResponseBody(AGENT_DID_C);
            const handler: DiscoveryHandler = vi
                .fn()
                .mockResolvedValue(responseBody);
            dispatcher.registerDiscoveryHandler(handler);

            const envelope = makeDiscoveryRequestEnvelope();
            const result = await dispatcher.dispatch(envelope);

            expect(result.body.agentDid).toBe(AGENT_DID_C);
            expect(result.body.agentCardJson).toBe(responseBody.agentCardJson);
            expect(result.body.respondedAt).toBe(responseBody.respondedAt);
            expect(result.body.documentVersion).toBe(1);
        });

        it('should set senderDid = responderDid and recipientDid = senderDid of request', async () => {
            const { dispatcher } = makeDispatcher();
            const handler: DiscoveryHandler = vi
                .fn()
                .mockResolvedValue(makeResponseBody());
            dispatcher.registerDiscoveryHandler(handler);

            const envelope = makeDiscoveryRequestEnvelope({
                senderDid: AGENT_DID_A,
            });
            const result = await dispatcher.dispatch(envelope);

            expect(result.header.senderDid).toBe(AGENT_DID_B); // responderDid
            expect(result.header.recipientDid).toBe(AGENT_DID_A); // request senderDid
        });

        it('should produce a valid Ed25519 signature on DISCOVERY_RESPONSE', async () => {
            // Create the dispatcher with the same key pair
            const kp = generateKeyPair();
            const dispatcher = new EnvelopeDiscoveryDispatcher({
                responderDid: AGENT_DID_B,
                responderPrivateKey: kp.privateKey,
                now: () => NOW_MS,
            });
            const handler: DiscoveryHandler = vi
                .fn()
                .mockResolvedValue(makeResponseBody());
            dispatcher.registerDiscoveryHandler(handler);

            const envelope = makeDiscoveryRequestEnvelope();
            const result = await dispatcher.dispatch(envelope);

            // Signature verification
            const { signature, ...payloadWithoutSig } = result;
            const canonical = canonicalize(payloadWithoutSig);
            const bytes = new TextEncoder().encode(canonical);
            const valid = verify(bytes, signature as string, kp.publicKey);
            expect(valid).toBe(true);
        });
    });

    // ── handler re-registration ───────────────────────────────────────────────

    describe('handler re-registration', () => {
        it('should replace handler when registerDiscoveryHandler is called again', async () => {
            const { dispatcher } = makeDispatcher();

            const firstHandler: DiscoveryHandler = vi
                .fn()
                .mockResolvedValue(null);
            const secondHandler: DiscoveryHandler = vi
                .fn()
                .mockResolvedValue(makeResponseBody());

            dispatcher.registerDiscoveryHandler(firstHandler);
            dispatcher.registerDiscoveryHandler(secondHandler);

            const envelope = makeDiscoveryRequestEnvelope();
            const result = await dispatcher.dispatch(envelope);

            expect(firstHandler).not.toHaveBeenCalled();
            expect(secondHandler).toHaveBeenCalledOnce();
            expect(result.messageType).toBe('DISCOVERY_RESPONSE');
        });
    });

    // ── ERROR envelope common fields ──────────────────────────────────────────

    describe('ERROR envelope common fields', () => {
        it('should set specVersion 0.3.0 on ERROR envelopes', async () => {
            const { dispatcher } = makeDispatcher();
            const envelope = makeDiscoveryRequestEnvelope({
                specVersion: '0.1.0',
            });

            const result = await dispatcher.dispatch(envelope);

            expect(result.specVersion).toBe(SPEC_VERSION_0_3_0);
        });

        it('should set messageType ERROR on all error paths', async () => {
            const { dispatcher } = makeDispatcher();
            const envelope = makeDiscoveryRequestEnvelope({
                specVersion: '0.2.0',
            });

            const result = await dispatcher.dispatch(envelope);

            expect(result.messageType).toBe('ERROR');
        });

        it('should have a valid UUID as id on ERROR envelopes', async () => {
            const { dispatcher } = makeDispatcher();
            const envelope = makeDiscoveryRequestEnvelope({
                specVersion: '0.1.0',
            });

            const result = await dispatcher.dispatch(envelope);

            expect(result.id).toMatch(
                /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
            );
        });
    });
});

// ── validateDiscoveryResponseBody tests ───────────────────────────────────────

describe('validateDiscoveryResponseBody()', () => {
    function makeValidBody(overrides?: Partial<Record<string, unknown>>) {
        return {
            agentDid: AGENT_DID_C,
            agentCardJson: '{"id":"' + AGENT_DID_C + '"}',
            respondedAt: NOW_ISO,
            documentVersion: 1,
            ...overrides,
        };
    }

    it('should return parsed body when all fields are valid', () => {
        const body = makeValidBody();
        const result = validateDiscoveryResponseBody(body, AGENT_DID_C);

        expect(result.agentDid).toBe(AGENT_DID_C);
        expect(result.agentCardJson).toBe(body.agentCardJson);
        expect(result.respondedAt).toBe(NOW_ISO);
        expect(result.documentVersion).toBe(1);
    });

    it('should throw INVALID_MESSAGE when agentDid is missing', () => {
        const body = makeValidBody({ agentDid: undefined });
        expect(() => validateDiscoveryResponseBody(body, AGENT_DID_C)).toThrow(
            'INVALID_MESSAGE',
        );
    });

    it('should throw INVALID_MESSAGE when agentDid has wrong format', () => {
        const body = makeValidBody({ agentDid: 'not-a-did' });
        expect(() => validateDiscoveryResponseBody(body, AGENT_DID_C)).toThrow(
            'INVALID_MESSAGE',
        );
    });

    it('should throw INVALID_MESSAGE when agentCardJson is empty string', () => {
        const body = makeValidBody({ agentCardJson: '' });
        expect(() => validateDiscoveryResponseBody(body, AGENT_DID_C)).toThrow(
            'INVALID_MESSAGE',
        );
    });

    it('should throw INVALID_MESSAGE when agentCardJson is not a string', () => {
        const body = makeValidBody({ agentCardJson: 42 });
        expect(() => validateDiscoveryResponseBody(body, AGENT_DID_C)).toThrow(
            'INVALID_MESSAGE',
        );
    });

    it('should throw INVALID_MESSAGE when respondedAt format is invalid', () => {
        const body = makeValidBody({ respondedAt: '2026-05-01' });
        expect(() => validateDiscoveryResponseBody(body, AGENT_DID_C)).toThrow(
            'INVALID_MESSAGE',
        );
    });

    it('should throw INVALID_MESSAGE when documentVersion is 0', () => {
        const body = makeValidBody({ documentVersion: 0 });
        expect(() => validateDiscoveryResponseBody(body, AGENT_DID_C)).toThrow(
            'INVALID_MESSAGE',
        );
    });

    it('should throw INVALID_MESSAGE when documentVersion is negative', () => {
        const body = makeValidBody({ documentVersion: -1 });
        expect(() => validateDiscoveryResponseBody(body, AGENT_DID_C)).toThrow(
            'INVALID_MESSAGE',
        );
    });

    it('should throw INVALID_MESSAGE when documentVersion is not integer', () => {
        const body = makeValidBody({ documentVersion: 1.5 });
        expect(() => validateDiscoveryResponseBody(body, AGENT_DID_C)).toThrow(
            'INVALID_MESSAGE',
        );
    });

    it('should throw DISCOVERY_TARGET_MISMATCH when agentDid !== expectedTargetDid', () => {
        const body = makeValidBody({ agentDid: AGENT_DID_C });
        expect(() => validateDiscoveryResponseBody(body, AGENT_DID_A)).toThrow(
            'DISCOVERY_TARGET_MISMATCH',
        );
    });

    it('should include both DIDs in DISCOVERY_TARGET_MISMATCH error message', () => {
        const body = makeValidBody({ agentDid: AGENT_DID_C });
        try {
            validateDiscoveryResponseBody(body, AGENT_DID_A);
            expect.fail('should have thrown');
        } catch (err) {
            expect(String((err as Error).message)).toContain(AGENT_DID_C);
            expect(String((err as Error).message)).toContain(AGENT_DID_A);
        }
    });

    it('should accept documentVersion 2 and above', () => {
        const body = makeValidBody({ documentVersion: 2 });
        const result = validateDiscoveryResponseBody(body, AGENT_DID_C);
        expect(result.documentVersion).toBe(2);
    });
});
