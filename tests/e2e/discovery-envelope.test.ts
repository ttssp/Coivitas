/**
 * discovery-envelope E2E test
 *
 * Coverage:
 *   1. DISCOVERY_REQUEST/RESPONSE Body send/receive (enumerated MessageType path)
 *   2. EnvelopeDiscoveryDispatcher handler registration + handler routing
 *   3. specVersion='0.3.0' validation gating
 *   4. No handler registered -> DISCOVERY_NOT_SUPPORTED error
 *   5. handler returns null -> AGENT_CARD_NOT_FOUND error
 *   6. handler throws -> INTERNAL_ERROR error
 *   7. Target DID mismatch -> DISCOVERY_TARGET_MISMATCH (receiver-side validateDiscoveryResponseBody)
 *   8. Excessive clock skew -> CLOCK_SKEW_EXCEEDED error
 *
 * Design decisions:
 *   - Pure in-memory test, no DB / Socket dependency (no gating).
 *   - DID format is strictly did:agent:[40 hex chars] (envelope-discovery.ts).
 *   - DiscoveryRequestBody only contains {targetDid, requestedAt}, no requestedFields.
 *   - DiscoveryResponseBody contains {agentDid, agentCardJson, respondedAt, documentVersion}.
 *   - ERROR envelope body format: {code, message, relatedEnvelopeId}.
 *   - EnvelopeDiscoveryDispatcher constructor accepts a DiscoveryDispatcherOptions object.
 *   - dispatch() does not verify signatures (the caller MUST complete verifyEnvelope beforehand).
 *
 */

import { describe, expect, it, beforeEach } from 'vitest';

import { generateKeyPair } from '../../packages/crypto/src/index.js';
import {
    EnvelopeDiscoveryDispatcher,
    validateDiscoveryResponseBody,
} from '../../packages/communication/src/index.js';
import type { DiscoveryHandler } from '../../packages/communication/src/index.js';
import type {
    DiscoveryResponseBody,
    NegotiationEnvelope,
    DID,
    Timestamp,
} from '../../packages/types/src/index.js';

// ─── Helper: generate a valid did:agent:<40 hex chars> DID ──────────────────────────

function makeAgentDID(): DID {
    // 40 hex chars = 20 random bytes
    const bytes = new Uint8Array(20);
    for (let i = 0; i < 20; i++) {
        bytes[i] = Math.floor(Math.random() * 256);
    }
    const hex = Array.from(bytes)
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('');
    return `did:agent:${hex}` as DID;
}

// ─── Helper: generate an ISO 8601 UTC formatted timestamp ──────────────────────────────

function nowTimestamp(): Timestamp {
    return new Date()
        .toISOString()
        .replace(/(\.\d{3})\d*Z/, '$1Z') as Timestamp;
}

// ─── Helper: build a minimal DISCOVERY_REQUEST NegotiationEnvelope ───────────────────
// Note: dispatcher.dispatch() does not verify signatures, so here we only need to
// construct a structurally correct object.
// specVersion must = '0.3.0' (dispatcher's internal isSpecVersion030OrAbove check).

function buildMinimalDiscoveryRequest(params: {
    senderDid: DID;
    targetDid: DID;
    requestedAt?: Timestamp;
    specVersion?: string;
}): NegotiationEnvelope {
    return {
        id: crypto.randomUUID(),
        specVersion: params.specVersion ?? '0.3.0',
        header: {
            senderDid: params.senderDid,
            recipientDid: params.targetDid,
            sessionId: null,
        },
        messageType: 'DISCOVERY_REQUEST',
        body: {
            targetDid: params.targetDid,
            requestedAt: params.requestedAt ?? nowTimestamp(),
        },
        signature: 'mock-sig-not-verified' as NegotiationEnvelope['signature'],
        timestamp: nowTimestamp(),
    };
}

// ─── Helper: build a baseline DiscoveryResponseBody ───────────────────────────────────

function makeResponseBody(agentDid: DID): DiscoveryResponseBody {
    const card = { did: agentDid, services: [] };
    return {
        agentDid,
        agentCardJson: JSON.stringify(card),
        respondedAt: nowTimestamp(),
        documentVersion: 1,
    };
}

// ─── Test suite ────────────────────────────────────────────────────────────────

describe('discovery-envelope E2E', () => {
    let targetKp: ReturnType<typeof generateKeyPair>;
    let senderDid: DID;
    let targetDid: DID;

    beforeEach(() => {
        targetKp = generateKeyPair();
        senderDid = makeAgentDID();
        targetDid = makeAgentDID();
    });

    // ─── 1. dispatcher registration + handler normal routing -> DISCOVERY_RESPONSE ─────────

    it('should route DISCOVERY_REQUEST to registered handler and return DISCOVERY_RESPONSE envelope', async () => {
        const dispatcher = new EnvelopeDiscoveryDispatcher({
            responderDid: targetDid,
            responderPrivateKey: targetKp.privateKey,
        });

        const handler: DiscoveryHandler = (req, callerDid) => {
            // targetDid in the body is passed through correctly
            expect(req.targetDid).toBe(targetDid);
            expect(callerDid).toBe(senderDid);
            return Promise.resolve(makeResponseBody(targetDid));
        };

        dispatcher.registerDiscoveryHandler(handler);

        const requestEnv = buildMinimalDiscoveryRequest({
            senderDid,
            targetDid,
        });
        const responseEnv = await dispatcher.dispatch(requestEnv);

        expect(responseEnv.messageType).toBe('DISCOVERY_RESPONSE');
        expect(responseEnv.specVersion).toBe('0.3.0');
        expect(responseEnv.header.senderDid).toBe(targetDid);
        expect(responseEnv.header.recipientDid).toBe(senderDid);

        const body = responseEnv.body as DiscoveryResponseBody;
        expect(body.agentDid).toBe(targetDid);
        expect(typeof body.agentCardJson).toBe('string');
        expect(body.agentCardJson.length).toBeGreaterThan(0);
        expect(typeof body.documentVersion).toBe('number');
        expect(body.documentVersion).toBeGreaterThanOrEqual(1);
    });

    // ─── 2. handler returns null -> AGENT_CARD_NOT_FOUND ────────────────────────

    it('should return AGENT_CARD_NOT_FOUND error when handler returns null', async () => {
        const dispatcher = new EnvelopeDiscoveryDispatcher({
            responderDid: targetDid,
            responderPrivateKey: targetKp.privateKey,
        });

        const handler: DiscoveryHandler = () => Promise.resolve(null);
        dispatcher.registerDiscoveryHandler(handler);

        const requestEnv = buildMinimalDiscoveryRequest({
            senderDid,
            targetDid,
        });
        const responseEnv = await dispatcher.dispatch(requestEnv);

        expect(responseEnv.messageType).toBe('ERROR');
        const body = responseEnv.body as {
            code: string;
            message: string;
            relatedEnvelopeId: string;
        };
        expect(body.code).toBe('AGENT_CARD_NOT_FOUND');
        expect(body.relatedEnvelopeId).toBe(requestEnv.id);
    });

    // ─── 3. No handler registered -> DISCOVERY_NOT_SUPPORTED ───────────────────────

    it('should return DISCOVERY_NOT_SUPPORTED when no handler registered', async () => {
        const dispatcher = new EnvelopeDiscoveryDispatcher({
            responderDid: targetDid,
            responderPrivateKey: targetKp.privateKey,
        });

        const requestEnv = buildMinimalDiscoveryRequest({
            senderDid,
            targetDid,
        });
        const responseEnv = await dispatcher.dispatch(requestEnv);

        expect(responseEnv.messageType).toBe('ERROR');
        const body = responseEnv.body as {
            code: string;
            relatedEnvelopeId: string;
        };
        expect(body.code).toBe('DISCOVERY_NOT_SUPPORTED');
        expect(body.relatedEnvelopeId).toBe(requestEnv.id);
    });

    // ─── 4. handler throws -> INTERNAL_ERROR ─────────────────────────────────

    it('should return INTERNAL_ERROR when handler throws', async () => {
        const dispatcher = new EnvelopeDiscoveryDispatcher({
            responderDid: targetDid,
            responderPrivateKey: targetKp.privateKey,
        });

        const handler: DiscoveryHandler = () =>
            Promise.reject(new Error('Handler internal failure'));
        dispatcher.registerDiscoveryHandler(handler);

        const requestEnv = buildMinimalDiscoveryRequest({
            senderDid,
            targetDid,
        });
        const responseEnv = await dispatcher.dispatch(requestEnv);

        expect(responseEnv.messageType).toBe('ERROR');
        const body = responseEnv.body as {
            code: string;
            message: string;
            relatedEnvelopeId: string;
        };
        expect(body.code).toBe('INTERNAL_ERROR');
        expect(body.message).toContain('Handler internal failure');
        expect(body.relatedEnvelopeId).toBe(requestEnv.id);
    });

    // ─── 5. specVersion != '0.3.0' -> INVALID_MESSAGE ───────────────────────

    it('should return INVALID_MESSAGE when specVersion is not 0.3.0', async () => {
        const dispatcher = new EnvelopeDiscoveryDispatcher({
            responderDid: targetDid,
            responderPrivateKey: targetKp.privateKey,
        });

        const handler: DiscoveryHandler = () =>
            Promise.resolve(makeResponseBody(targetDid));
        dispatcher.registerDiscoveryHandler(handler);

        // use an old specVersion
        const requestEnv = buildMinimalDiscoveryRequest({
            senderDid,
            targetDid,
            specVersion: '0.1.0',
        });
        const responseEnv = await dispatcher.dispatch(requestEnv);

        expect(responseEnv.messageType).toBe('ERROR');
        const body = responseEnv.body as { code: string };
        expect(body.code).toBe('INVALID_MESSAGE');
    });

    // ─── 6. body contains unknown fields -> INVALID_MESSAGE ───────────────────────────────

    it('should return INVALID_MESSAGE when request body has unknown fields', async () => {
        const dispatcher = new EnvelopeDiscoveryDispatcher({
            responderDid: targetDid,
            responderPrivateKey: targetKp.privateKey,
        });

        const handler: DiscoveryHandler = () =>
            Promise.resolve(makeResponseBody(targetDid));
        dispatcher.registerDiscoveryHandler(handler);

        // add requestedFields (DiscoveryRequestBody does not allow extra fields)
        const badEnv: NegotiationEnvelope = {
            id: crypto.randomUUID(),
            specVersion: '0.3.0',
            header: { senderDid, recipientDid: targetDid, sessionId: null },
            messageType: 'DISCOVERY_REQUEST',
            body: {
                targetDid,
                requestedAt: nowTimestamp(),
                requestedFields: ['capabilities'], // unknown field
            },
            signature: 'mock-sig' as NegotiationEnvelope['signature'],
            timestamp: nowTimestamp(),
        };

        const responseEnv = await dispatcher.dispatch(badEnv);

        expect(responseEnv.messageType).toBe('ERROR');
        const body = responseEnv.body as { code: string };
        expect(body.code).toBe('INVALID_MESSAGE');
    });

    // ─── 7. Excessive clock skew -> CLOCK_SKEW_EXCEEDED ──────────────────────────────

    it('should return CLOCK_SKEW_EXCEEDED when requestedAt is far in the past', async () => {
        const dispatcher = new EnvelopeDiscoveryDispatcher({
            responderDid: targetDid,
            responderPrivateKey: targetKp.privateKey,
            clockSkewMs: 60_000, // 1 minute
        });

        const handler: DiscoveryHandler = () =>
            Promise.resolve(makeResponseBody(targetDid));
        dispatcher.registerDiscoveryHandler(handler);

        // build requestedAt as 10 minutes ago (exceeds the 1-minute clockSkewMs)
        const pastTime = new Date(Date.now() - 10 * 60 * 1000);
        const pastTimestamp = pastTime
            .toISOString()
            .replace(/(\.\d{3})\d*Z/, '$1Z') as Timestamp;

        const requestEnv = buildMinimalDiscoveryRequest({
            senderDid,
            targetDid,
            requestedAt: pastTimestamp,
        });
        const responseEnv = await dispatcher.dispatch(requestEnv);

        expect(responseEnv.messageType).toBe('ERROR');
        const body = responseEnv.body as { code: string };
        expect(body.code).toBe('CLOCK_SKEW_EXCEEDED');
    });

    // ─── 8. Registering handlers multiple times: the last one overrides the previous ────────────────────────────

    it('should use the last registered handler when multiple handlers registered', async () => {
        const dispatcher = new EnvelopeDiscoveryDispatcher({
            responderDid: targetDid,
            responderPrivateKey: targetKp.privateKey,
        });

        const firstCard = JSON.stringify({ did: targetDid, tag: 'FIRST' });
        const secondCard = JSON.stringify({ did: targetDid, tag: 'SECOND' });

        const firstHandler: DiscoveryHandler = () =>
            Promise.resolve({
                agentDid: targetDid,
                agentCardJson: firstCard,
                respondedAt: nowTimestamp(),
                documentVersion: 1,
            });
        const secondHandler: DiscoveryHandler = () =>
            Promise.resolve({
                agentDid: targetDid,
                agentCardJson: secondCard,
                respondedAt: nowTimestamp(),
                documentVersion: 2,
            });

        dispatcher.registerDiscoveryHandler(firstHandler);
        dispatcher.registerDiscoveryHandler(secondHandler);

        const requestEnv = buildMinimalDiscoveryRequest({
            senderDid,
            targetDid,
        });
        const responseEnv = await dispatcher.dispatch(requestEnv);

        expect(responseEnv.messageType).toBe('DISCOVERY_RESPONSE');
        const body = responseEnv.body as DiscoveryResponseBody;
        // the last registered handler takes effect
        expect(body.agentCardJson).toBe(secondCard);
        expect(body.documentVersion).toBe(2);
    });

    // ─── 9. validateDiscoveryResponseBody — success path ────────────────────────

    it('should validate correct DISCOVERY_RESPONSE body without throwing', () => {
        const body = {
            agentDid: targetDid,
            agentCardJson: JSON.stringify({ did: targetDid }),
            respondedAt: nowTimestamp(),
            documentVersion: 3,
        };

        expect(() => {
            validateDiscoveryResponseBody(body, targetDid);
        }).not.toThrow();

        const result = validateDiscoveryResponseBody(body, targetDid);
        expect(result.agentDid).toBe(targetDid);
        expect(result.documentVersion).toBe(3);
    });

    // ─── 10. validateDiscoveryResponseBody — agentDid mismatch -> DISCOVERY_TARGET_MISMATCH

    it('should throw DISCOVERY_TARGET_MISMATCH when agentDid does not match expectedTargetDid', () => {
        const wrongDid = makeAgentDID();
        const body = {
            agentDid: wrongDid,
            agentCardJson: JSON.stringify({ did: wrongDid }),
            respondedAt: nowTimestamp(),
            documentVersion: 1,
        };

        expect(() => {
            validateDiscoveryResponseBody(body, targetDid);
        }).toThrow();

        try {
            validateDiscoveryResponseBody(body, targetDid);
        } catch (e: unknown) {
            const err = e as { code?: string };
            expect(err.code).toBe('DISCOVERY_TARGET_MISMATCH');
        }
    });

    // ─── 11. ERROR envelope body structure validation ───────────────────────────────────

    it('should return ERROR envelope with correct body structure {code, message, relatedEnvelopeId}', async () => {
        const dispatcher = new EnvelopeDiscoveryDispatcher({
            responderDid: targetDid,
            responderPrivateKey: targetKp.privateKey,
        });
        // no handler -> DISCOVERY_NOT_SUPPORTED
        const requestEnv = buildMinimalDiscoveryRequest({
            senderDid,
            targetDid,
        });
        const responseEnv = await dispatcher.dispatch(requestEnv);

        expect(responseEnv.messageType).toBe('ERROR');

        const body = responseEnv.body;
        // must contain code, message, relatedEnvelopeId (not {error: {code}})
        expect(typeof body['code']).toBe('string');
        expect(typeof body['message']).toBe('string');
        expect(typeof body['relatedEnvelopeId']).toBe('string');
        expect(body['relatedEnvelopeId']).toBe(requestEnv.id);
        // does not contain the error field (legacy format)
        expect(body['error']).toBeUndefined();
    });

    // ─── 12. Full E2E: dispatcher dispatch -> validateDiscoveryResponseBody validation ─

    it('should support full E2E: dispatch DISCOVERY_REQUEST then validate response body', async () => {
        const dispatcher = new EnvelopeDiscoveryDispatcher({
            responderDid: targetDid,
            responderPrivateKey: targetKp.privateKey,
        });

        const agentCardJson = JSON.stringify({
            did: targetDid,
            services: [
                { type: 'Coivitas', endpoint: 'https://example.com' },
            ],
        });

        const handler: DiscoveryHandler = () =>
            Promise.resolve({
                agentDid: targetDid,
                agentCardJson,
                respondedAt: nowTimestamp(),
                documentVersion: 5,
            });
        dispatcher.registerDiscoveryHandler(handler);

        const requestEnv = buildMinimalDiscoveryRequest({
            senderDid,
            targetDid,
        });
        const responseEnv = await dispatcher.dispatch(requestEnv);

        expect(responseEnv.messageType).toBe('DISCOVERY_RESPONSE');

        // receiver-side validation
        const validated = validateDiscoveryResponseBody(
            responseEnv.body,
            targetDid,
        );
        expect(validated.agentDid).toBe(targetDid);
        expect(validated.agentCardJson).toBe(agentCardJson);
        expect(validated.documentVersion).toBe(5);
        expect(validated.respondedAt).toMatch(
            /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/,
        );
    });
});
