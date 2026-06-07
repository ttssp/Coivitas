// Transition-period gate tests (frozen supplemental contract).
// Covers three transition-period constraints:
// (1) A delegation Token is rejected by the verifier (guaranteed by identity/token-verifier)
// (2) A 0.2.0 document with version>1 / containing rotationProof is rejected by the verifier (same as above)
// (3) A 0.1.0 Token containing temporal_scope / cumulative_limit is rejected by validateScopeVersion

import { describe, expect, it } from 'vitest';

import type {
    AgentIdentityDocument,
    CapabilityToken,
    DID,
    RotationProof,
    Signature,
    Timestamp,
} from '../index.js';
import {
    SPEC_VERSION,
    validateAgainstSchema,
    validateScopeVersion,
} from '../index.js';

const principalDid =
    'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK' as DID;
const agentDid = 'did:agent:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0' as DID;
const delegateeDid =
    'did:agent:b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1' as DID;
const publicKey = 'a'.repeat(64);
const signature = 'b'.repeat(128) as Signature;
const timestamp = '2026-04-15T10:00:00.000Z' as Timestamp;
const expiresAt = '2026-04-16T10:00:00.000Z' as Timestamp;

const baseToken = (
    overrides: Partial<CapabilityToken> = {},
): CapabilityToken => ({
    id: 'urn:cap:550e8400-e29b-41d4-a716-446655440000',
    specVersion: SPEC_VERSION,
    issuerDid: principalDid,
    principalDid,
    issuedTo: agentDid,
    issuedAt: timestamp,
    expiresAt,
    capabilities: [
        {
            action: 'INQUIRY',
            scope: {
                type: 'allowlist',
                field: 'product_category',
                values: ['electronics'],
            },
        },
    ],
    revocationUrl: 'https://revocation.example.com/v1/{id}',
    proof: {
        type: 'Ed25519Signature2026',
        created: timestamp,
        verificationMethod: `${principalDid}#key-1`,
        value: signature,
    },
    ...overrides,
});

describe('validateScopeVersion (scope version gate)', () => {
    it('accepts 0.1.0 token with baseline scopes only', () => {
        const token = baseToken();
        expect(validateScopeVersion(token)).toEqual({ valid: true });
    });

    it('rejects 0.1.0 token containing temporal_scope', () => {
        const token = baseToken({
            capabilities: [
                {
                    action: 'INQUIRY',
                    scope: {
                        type: 'temporal_scope',
                        notBefore: timestamp,
                        notAfter: expiresAt,
                    },
                },
            ],
        });
        const result = validateScopeVersion(token);
        expect(result.valid).toBe(false);
        expect(result.reason).toMatch(/temporal_scope/);
        expect(result.reason).toMatch(/0\.1\.0/);
    });

    it('rejects 0.1.0 token containing cumulative_limit', () => {
        const token = baseToken({
            capabilities: [
                {
                    action: 'CONFIRM',
                    scope: {
                        type: 'cumulative_limit',
                        meterField: {
                            source: 'action_record',
                            metric: 'transaction_amount',
                        },
                        max: 50000,
                        window: 'day',
                    },
                },
            ],
        });
        const result = validateScopeVersion(token);
        expect(result.valid).toBe(false);
        expect(result.reason).toMatch(/cumulative_limit/);
    });

    it('accepts 0.2.0 token carrying new scope types', () => {
        const token = baseToken({
            specVersion: '0.2.0',
            capabilities: [
                {
                    action: 'INQUIRY',
                    scope: {
                        type: 'temporal_scope',
                        notBefore: timestamp,
                        notAfter: expiresAt,
                    },
                },
            ],
        });
        expect(validateScopeVersion(token)).toEqual({ valid: true });
    });
});

describe('agentIdentityDocument schema (rotation gate)', () => {
    const baseDoc = (
        overrides: Partial<AgentIdentityDocument> = {},
    ): AgentIdentityDocument => ({
        id: agentDid,
        specVersion: SPEC_VERSION,
        principalDid,
        publicKey,
        bindingProof: {
            principalDid,
            agentDid,
            issuedAt: timestamp,
            expiresAt: null,
            signature,
        },
        createdAt: timestamp,
        updatedAt: timestamp,
        ...overrides,
    });

    it('accepts a 0.1.0 v=1 document (baseline)', () => {
        expect(
            validateAgainstSchema(baseDoc(), 'agentIdentityDocument').valid,
        ).toBe(true);
    });

    it('accepts a 0.2.0 document with version=1 (no rotation yet)', () => {
        const doc = baseDoc({ specVersion: '0.2.0', version: 1 });
        expect(validateAgainstSchema(doc, 'agentIdentityDocument').valid).toBe(
            true,
        );
    });

    it('accepts a 0.2.0 document with rotationProof + version=2', () => {
        const rotationProof: RotationProof = {
            oldPublicKey: publicKey,
            newPublicKey: 'd'.repeat(64),
            oldKeySignature: signature,
            newKeySignature: signature,
            principalSignature: signature,
            agentDid,
            rotatedAt: timestamp,
        };
        const doc = baseDoc({
            specVersion: '0.2.0',
            version: 2,
            previousPublicKey: publicKey,
            rotationProof,
        });
        // Schema lets it through; the business verifier (verifyAgentIdentityDocument) must reject v>1 on its own.
        expect(validateAgainstSchema(doc, 'agentIdentityDocument').valid).toBe(
            true,
        );
    });
});

// Handshake schema is compatible with the 0.1.0 wire:
// - principalDid may still be omitted for the 0.1.0 HANDSHAKE_INIT (0.2.0 makes it required at runtime)
// - the sessionId:'' (frozen placeholder) of a rejected HANDSHAKE_ACK is not rejected by the schema
describe('handshake schemas (0.1.0 wire backward compat)', () => {
    it('accepts handshakeChallenge without principalDid (0.1.0 INIT shape)', () => {
        const phase1Challenge = {
            challengeId: '9f5c0e20-1a6a-4b3c-9d1d-0a1b2c3d4e5f',
            initiatorDid: agentDid,
            responderDid: delegateeDid,
            nonce: 'a'.repeat(64),
            timestamp,
            expiresAt,
            initiatorCapabilities: ['INQUIRY'],
        };
        expect(
            validateAgainstSchema(phase1Challenge, 'handshakeChallenge').valid,
        ).toBe(true);
    });

    it('accepts rejected HANDSHAKE_ACK with sessionId=""', () => {
        const rejectedResponse = {
            challengeId: '9f5c0e20-1a6a-4b3c-9d1d-0a1b2c3d4e5f',
            sessionId: '',
            responderDid: delegateeDid,
            responderCapabilities: [],
            nonce: 'a'.repeat(64),
            timestamp,
        };
        expect(
            validateAgainstSchema(rejectedResponse, 'handshakeResponse').valid,
        ).toBe(true);
    });
});

describe('capabilityToken schema (delegationChain shape gate)', () => {
    it('accepts a 0.2.0 token with delegationChain present', () => {
        const token = baseToken({
            specVersion: '0.2.0',
            delegationChain: [
                {
                    parentTokenId:
                        'urn:cap:11111111-1111-4111-8111-111111111111',
                    delegatorDid: agentDid,
                    delegateeDid,
                    parentCapabilities: baseToken().capabilities,
                    parentExpiresAt: expiresAt,
                    attenuatedCapabilities: baseToken().capabilities,
                    proof: {
                        type: 'Ed25519Signature2026',
                        created: timestamp,
                        verificationMethod: `${agentDid}#key-1`,
                        value: signature,
                    },
                },
            ],
            proof: {
                type: 'Ed25519Signature2026',
                created: timestamp,
                verificationMethod: `${agentDid}#key-1`,
                value: signature,
            },
        });
        // Schema lets it through; the token-verifier must explicitly reject it via the delegationChain transition gate.
        expect(validateAgainstSchema(token, 'capabilityToken').valid).toBe(
            true,
        );
    });

    it('rejects delegationChain exceeding MAX_DELEGATION_DEPTH (5)', () => {
        const depth6 = Array.from({ length: 6 }, (_, i) => ({
            parentTokenId: `urn:cap:11111111-1111-4111-8111-${String(
                i,
            ).padStart(12, '0')}`,
            delegatorDid: agentDid,
            delegateeDid,
            parentCapabilities: baseToken().capabilities,
            parentExpiresAt: expiresAt,
            attenuatedCapabilities: baseToken().capabilities,
            proof: {
                type: 'Ed25519Signature2026' as const,
                created: timestamp,
                verificationMethod: `${agentDid}#key-1`,
                value: signature,
            },
        }));
        const token = baseToken({
            specVersion: '0.2.0',
            delegationChain: depth6,
        });
        expect(validateAgainstSchema(token, 'capabilityToken').valid).toBe(
            false,
        );
    });
});
