/**
 * DISCOVERY MessageType wire integration tests
 *
 * Coverage:
 * 1. MessageType enum extension (DISCOVERY_REQUEST / DISCOVERY_RESPONSE have entered the valid value set)
 * 2. DiscoveryRequestBody schema validation (valid + invalid fixtures)
 * 3. DiscoveryResponseBody schema validation (valid + invalid fixtures, including the v0.2 new documentVersion)
 * 4. negotiationEnvelope schema accepts DISCOVERY_* messageType
 * 5. negotiationEnvelope schema rejects unknown messageType
 *
 */
import { describe, expect, it } from 'vitest';

import type {
    DID,
    DiscoveryRequestBody,
    DiscoveryResponseBody,
    MessageType,
    NegotiationEnvelope,
    Signature,
    Timestamp,
} from '../index.js';
import { MESSAGE_TYPES, validateAgainstSchema } from '../index.js';

// ── Shared fixture constants ─────────────────────────────────────────────────────────
const senderDid = 'did:agent:abc123def456abc123def456abc123def456abc1' as DID;
const targetDid = 'did:agent:fed654cba321fed654cba321fed654cba321fed6' as DID;
const signature = 'a'.repeat(128) as Signature;
const timestamp = '2026-04-30T10:00:00.000Z' as Timestamp;
const respondedAt = '2026-04-30T10:00:01.000Z' as Timestamp;

// Minimal valid AgentCard JSON (used for the agentCardJson field)
const minimalAgentCardJson = JSON.stringify({
    did: targetDid,
    specVersion: '0.2.0',
    displayName: 'Test Agent',
    serviceEndpoints: [
        {
            id: 'negotiation',
            type: 'NegotiationEndpoint',
            url: 'https://agent.example.com/negotiate',
        },
    ],
    capabilitiesDeclared: ['INQUIRY'],
    publicKey: 'b'.repeat(64),
    documentVersion: 3,
    updatedAt: '2026-04-30T09:00:00.000Z',
    signature: 'c'.repeat(128),
});

// ── MessageType enum extension ─────────────────────────────────────────

describe('MessageType enum extension (discovery spec)', () => {
    it('should include DISCOVERY_REQUEST in MESSAGE_TYPES constant', () => {
        expect(MESSAGE_TYPES).toContain('DISCOVERY_REQUEST');
    });

    it('should include DISCOVERY_RESPONSE in MESSAGE_TYPES constant', () => {
        expect(MESSAGE_TYPES).toContain('DISCOVERY_RESPONSE');
    });

    it('should preserve all 6 v0.1 MessageType values', () => {
        const v01Values: MessageType[] = [
            'HANDSHAKE_INIT',
            'HANDSHAKE_ACK',
            'NEGOTIATION_REQUEST',
            'NEGOTIATION_RESPONSE',
            'NEGOTIATION_CONFIRM',
            'ERROR',
        ];
        for (const value of v01Values) {
            expect(MESSAGE_TYPES).toContain(value);
        }
    });

    it('should have exactly 8 MessageType values total', () => {
        expect(MESSAGE_TYPES.length).toBe(8);
    });
});

// ── DiscoveryRequestBody schema ────────────────────────────────────

describe('DiscoveryRequestBody schema validation (discovery spec)', () => {
    const validRequest: DiscoveryRequestBody = {
        targetDid,
        requestedAt: timestamp,
    };

    it('should accept a valid DiscoveryRequestBody with required fields', () => {
        expect(
            validateAgainstSchema(validRequest, 'discoveryRequestBody'),
        ).toEqual({ valid: true, errors: [] });
    });

    it('should accept a DiscoveryRequestBody with a different valid targetDid', () => {
        const req: DiscoveryRequestBody = {
            targetDid:
                'did:agent:0000111122223333444455556666777788889999' as DID,
            requestedAt: timestamp,
        };
        expect(validateAgainstSchema(req, 'discoveryRequestBody').valid).toBe(
            true,
        );
    });

    it('should reject a DiscoveryRequestBody missing targetDid', () => {
        const { targetDid: _t, ...withoutTargetDid } = validRequest;
        const result = validateAgainstSchema(
            withoutTargetDid,
            'discoveryRequestBody',
        );
        expect(result.valid).toBe(false);
        expect(result.errors.length).toBeGreaterThan(0);
    });

    it('should reject a DiscoveryRequestBody missing requestedAt', () => {
        const { requestedAt: _r, ...withoutRequestedAt } = validRequest;
        const result = validateAgainstSchema(
            withoutRequestedAt,
            'discoveryRequestBody',
        );
        expect(result.valid).toBe(false);
        expect(result.errors.length).toBeGreaterThan(0);
    });

    it('should reject a DiscoveryRequestBody with invalid DID format (not did:agent:)', () => {
        const result = validateAgainstSchema(
            {
                targetDid:
                    'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
                requestedAt: timestamp,
            },
            'discoveryRequestBody',
        );
        expect(result.valid).toBe(false);
    });

    it('should reject a DiscoveryRequestBody with invalid timestamp format', () => {
        const result = validateAgainstSchema(
            {
                targetDid,
                requestedAt: '2026-04-30', // missing the time portion
            },
            'discoveryRequestBody',
        );
        expect(result.valid).toBe(false);
    });

    it('should reject a DiscoveryRequestBody with extra unknown fields (additionalProperties: false)', () => {
        const result = validateAgainstSchema(
            {
                ...validRequest,
                unknownField: 'not-allowed',
            },
            'discoveryRequestBody',
        );
        expect(result.valid).toBe(false);
    });
});

// ── DiscoveryResponseBody schema ───────────────────────────────────

describe('DiscoveryResponseBody schema validation (discovery spec)', () => {
    const validResponse: DiscoveryResponseBody = {
        agentDid: targetDid,
        agentCardJson: minimalAgentCardJson,
        respondedAt,
        documentVersion: 3,
    };

    it('should accept a valid DiscoveryResponseBody with all required fields', () => {
        expect(
            validateAgainstSchema(validResponse, 'discoveryResponseBody'),
        ).toEqual({ valid: true, errors: [] });
    });

    it('should accept a DiscoveryResponseBody with documentVersion = 1 (minimum valid)', () => {
        const resp: DiscoveryResponseBody = {
            ...validResponse,
            documentVersion: 1,
        };
        expect(validateAgainstSchema(resp, 'discoveryResponseBody').valid).toBe(
            true,
        );
    });

    it('should reject a DiscoveryResponseBody missing agentDid', () => {
        const { agentDid: _a, ...withoutAgentDid } = validResponse;
        const result = validateAgainstSchema(
            withoutAgentDid,
            'discoveryResponseBody',
        );
        expect(result.valid).toBe(false);
    });

    it('should reject a DiscoveryResponseBody missing agentCardJson', () => {
        const { agentCardJson: _c, ...withoutCardJson } = validResponse;
        const result = validateAgainstSchema(
            withoutCardJson,
            'discoveryResponseBody',
        );
        expect(result.valid).toBe(false);
    });

    it('should reject a DiscoveryResponseBody missing respondedAt', () => {
        const { respondedAt: _r, ...withoutRespondedAt } = validResponse;
        const result = validateAgainstSchema(
            withoutRespondedAt,
            'discoveryResponseBody',
        );
        expect(result.valid).toBe(false);
    });

    it('should reject a DiscoveryResponseBody missing documentVersion (v0.2 required field)', () => {
        const { documentVersion: _d, ...withoutDocVersion } = validResponse;
        const result = validateAgainstSchema(
            withoutDocVersion,
            'discoveryResponseBody',
        );
        expect(result.valid).toBe(false);
        expect(result.errors.length).toBeGreaterThan(0);
    });

    it('should reject a DiscoveryResponseBody with documentVersion = 0 (below minimum)', () => {
        const result = validateAgainstSchema(
            { ...validResponse, documentVersion: 0 },
            'discoveryResponseBody',
        );
        expect(result.valid).toBe(false);
    });

    it('should reject a DiscoveryResponseBody with non-integer documentVersion', () => {
        const result = validateAgainstSchema(
            { ...validResponse, documentVersion: 1.5 },
            'discoveryResponseBody',
        );
        expect(result.valid).toBe(false);
    });

    it('should reject a DiscoveryResponseBody with empty agentCardJson', () => {
        const result = validateAgainstSchema(
            { ...validResponse, agentCardJson: '' },
            'discoveryResponseBody',
        );
        expect(result.valid).toBe(false);
    });

    it('should reject a DiscoveryResponseBody with invalid agentDid format', () => {
        const result = validateAgainstSchema(
            {
                ...validResponse,
                agentDid: 'not-a-did',
            },
            'discoveryResponseBody',
        );
        expect(result.valid).toBe(false);
    });

    it('should reject a DiscoveryResponseBody with extra unknown fields (additionalProperties: false)', () => {
        const result = validateAgainstSchema(
            {
                ...validResponse,
                extraField: 'not-allowed',
            },
            'discoveryResponseBody',
        );
        expect(result.valid).toBe(false);
    });
});

// ── negotiationEnvelope accepts DISCOVERY_* messageType ──────────────────────────

describe('negotiationEnvelope with DISCOVERY MessageType (discovery spec)', () => {
    const baseEnvelope = (
        messageType: MessageType,
        body: Record<string, unknown>,
    ): NegotiationEnvelope => ({
        id: '550e8400-e29b-41d4-a716-446655440099',
        specVersion: '0.3.0',
        header: {
            senderDid,
            recipientDid: targetDid,
            sessionId: null,
        },
        messageType,
        body,
        signature,
        timestamp,
    });

    it('should accept a NegotiationEnvelope with messageType DISCOVERY_REQUEST', () => {
        const envelope = baseEnvelope('DISCOVERY_REQUEST', {
            targetDid,
            requestedAt: timestamp,
        });
        expect(
            validateAgainstSchema(envelope, 'negotiationEnvelope').valid,
        ).toBe(true);
    });

    it('should accept a NegotiationEnvelope with messageType DISCOVERY_RESPONSE', () => {
        const envelope = baseEnvelope('DISCOVERY_RESPONSE', {
            agentDid: targetDid,
            agentCardJson: minimalAgentCardJson,
            respondedAt,
            documentVersion: 3,
        });
        expect(
            validateAgainstSchema(envelope, 'negotiationEnvelope').valid,
        ).toBe(true);
    });

    it('should reject a NegotiationEnvelope with an unknown messageType', () => {
        const result = validateAgainstSchema(
            {
                ...baseEnvelope('DISCOVERY_REQUEST', {}),
                messageType: 'UNKNOWN_TYPE',
            },
            'negotiationEnvelope',
        );
        expect(result.valid).toBe(false);
    });
});

// ── discovery v0.2 new error-code registration ─────────────────────────────────

describe('discovery v0.2 error code registration (discovery spec)', () => {
    /**
     * Acceptance criterion A8: DISCOVERY_NOT_SUPPORTED / DISCOVERY_TARGET_MISMATCH must
     * pass protocolError schema validation (already registered in PROTOCOL_ERROR_CODES).
     * Reserved future namespaces (DISCOVERY_DHT_* / DISCOVERY_BROADCAST_* / DISCOVERY_REGISTRY_*)
     * must not appear.
     */

    it('should accept DISCOVERY_NOT_SUPPORTED as a valid protocolError code', () => {
        const result = validateAgainstSchema(
            {
                code: 'DISCOVERY_NOT_SUPPORTED',
                message: 'No discovery handler registered',
            },
            'protocolError',
        );
        expect(result.valid).toBe(true);
    });

    it('should accept DISCOVERY_TARGET_MISMATCH as a valid protocolError code', () => {
        const result = validateAgainstSchema(
            {
                code: 'DISCOVERY_TARGET_MISMATCH',
                message: 'response.agentDid does not match request.targetDid',
            },
            'protocolError',
        );
        expect(result.valid).toBe(true);
    });

    it('should reject DISCOVERY_DHT_ERROR as a reserved future code (A8 guard)', () => {
        const result = validateAgainstSchema(
            {
                code: 'DISCOVERY_DHT_ERROR',
                message: 'reserved future code must not pass schema',
            },
            'protocolError',
        );
        expect(result.valid).toBe(false);
    });

    it('should reject DISCOVERY_BROADCAST_FAILED as a reserved future code (A8 guard)', () => {
        const result = validateAgainstSchema(
            {
                code: 'DISCOVERY_BROADCAST_FAILED',
                message: 'reserved future code must not pass schema',
            },
            'protocolError',
        );
        expect(result.valid).toBe(false);
    });
});
