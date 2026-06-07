// AgentCard type and schema validation tests
import { describe, expect, it } from 'vitest';

import type { AgentCard, DID, Signature, Timestamp } from '../index.js';
import { validateAgainstSchema } from '../index.js';

const agentDid = 'did:agent:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0' as DID;
const publicKey = 'a'.repeat(64);
const signature = 'b'.repeat(128) as Signature;
const timestamp = '2026-04-21T10:00:00.000Z' as Timestamp;

const baseCard = (overrides: Partial<AgentCard> = {}): AgentCard => ({
    did: agentDid,
    specVersion: '0.1.0',
    serviceEndpoints: [
        {
            id: 'negotiation',
            type: 'NegotiationEndpoint',
            url: 'https://agent.example.com/negotiate',
        },
    ],
    capabilitiesDeclared: ['INQUIRY', 'QUOTE'],
    publicKey,
    documentVersion: 1,
    updatedAt: timestamp,
    signature,
    ...overrides,
});

describe('AgentCard schema validation', () => {
    it('should accept a minimal valid AgentCard when all required fields are present', () => {
        expect(validateAgainstSchema(baseCard(), 'agentCard')).toEqual({
            valid: true,
            errors: [],
        });
    });

    it('should accept an AgentCard with optional displayName and description fields', () => {
        const card = baseCard({
            displayName: 'Test Agent',
            description: 'An agent for testing purposes',
        });
        expect(validateAgainstSchema(card, 'agentCard').valid).toBe(true);
    });

    it('should accept an AgentCard with multiple service endpoints', () => {
        const card = baseCard({
            serviceEndpoints: [
                {
                    id: 'negotiation',
                    type: 'NegotiationEndpoint',
                    url: 'https://agent.example.com/negotiate',
                },
                {
                    id: 'audit',
                    type: 'AuditEndpoint',
                    url: 'https://agent.example.com/audit',
                },
            ],
        });
        expect(validateAgainstSchema(card, 'agentCard').valid).toBe(true);
    });

    it('should accept an AgentCard with empty capabilitiesDeclared array', () => {
        const card = baseCard({ capabilitiesDeclared: [] });
        expect(validateAgainstSchema(card, 'agentCard').valid).toBe(true);
    });

    it('should accept an AgentCard with specVersion 0.2.0 and documentVersion > 1', () => {
        const card = baseCard({ specVersion: '0.2.0', documentVersion: 3 });
        expect(validateAgainstSchema(card, 'agentCard').valid).toBe(true);
    });

    it('should reject an AgentCard missing the required did field', () => {
        // eslint-disable-next-line @typescript-eslint/no-unused-vars
        const { did: _did, ...cardWithoutDid } = baseCard();
        const result = validateAgainstSchema(cardWithoutDid, 'agentCard');
        expect(result.valid).toBe(false);
        expect(result.errors.length).toBeGreaterThan(0);
    });

    it('should reject an AgentCard with invalid did format (not did:agent:)', () => {
        const card = baseCard({
            did: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK' as DID,
        });
        const result = validateAgainstSchema(card, 'agentCard');
        expect(result.valid).toBe(false);
    });

    it('should reject an AgentCard with invalid publicKey (wrong length)', () => {
        const card = baseCard({ publicKey: 'short' });
        const result = validateAgainstSchema(card, 'agentCard');
        expect(result.valid).toBe(false);
    });

    it('should reject an AgentCard with documentVersion less than 1', () => {
        const card = baseCard({ documentVersion: 0 });
        const result = validateAgainstSchema(card, 'agentCard');
        expect(result.valid).toBe(false);
    });

    it('should reject an AgentCard with extra unknown fields (additionalProperties: false)', () => {
        const card = {
            ...baseCard(),
            unknownField: 'not-allowed',
        };
        const result = validateAgainstSchema(card, 'agentCard');
        expect(result.valid).toBe(false);
    });
});
