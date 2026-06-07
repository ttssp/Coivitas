import { describe, expect, it } from 'vitest';

import type {
    ActionRecord,
    AgentIdentityDocument,
    CapabilityToken,
    DID,
    EnvelopeHeader,
    Hash,
    IntegrityProof,
    NegotiationEnvelope,
    PrincipalIdentity,
    SessionRecord,
    SignedAuditQuery,
    Signature,
    Timestamp,
} from '../index.js';
import { SPEC_VERSION, validateAgainstSchema } from '../index.js';

const principalDid =
    'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK' as DID;
const agentDid = 'did:agent:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0' as DID;
const publicKey = 'a'.repeat(64);
const signature = 'b'.repeat(128) as Signature;
const hash = 'c'.repeat(64) as Hash;
const timestamp = '2026-03-31T10:00:00.000Z' as Timestamp;

describe('validateAgainstSchema', () => {
    it('validates a principal identity document', () => {
        const principal: PrincipalIdentity = {
            did: principalDid,
            publicKey,
            displayName: 'Alice Chen',
            createdAt: timestamp,
        };

        expect(validateAgainstSchema(principal, 'principalIdentity')).toEqual({
            valid: true,
            errors: [],
        });
    });

    it('reports detailed errors for invalid identity data', () => {
        const result = validateAgainstSchema(
            {
                did: 'did:agent:not-allowed',
                publicKey: 'short',
                createdAt: '2026-03-31',
            },
            'principalIdentity',
        );

        expect(result.valid).toBe(false);
        expect(result.errors.length).toBeGreaterThan(0);
        expect(
            result.errors.some((error) => error.instancePath === '/did'),
        ).toBe(true);
    });

    it('validates an agent identity document', () => {
        const document: AgentIdentityDocument = {
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
            capabilities: ['INQUIRY', 'QUOTE'],
            serviceEndpoints: [
                {
                    id: 'negotiation',
                    type: 'NegotiationEndpoint',
                    url: 'https://agent.example.com/negotiate',
                },
            ],
            createdAt: timestamp,
            updatedAt: timestamp,
        };

        expect(
            validateAgainstSchema(document, 'agentIdentityDocument').valid,
        ).toBe(true);
    });

    it('validates a capability token with both scope variants available', () => {
        const token: CapabilityToken = {
            id: 'urn:cap:550e8400-e29b-41d4-a716-446655440000',
            specVersion: SPEC_VERSION,
            issuerDid: principalDid,
            principalDid,
            issuedTo: agentDid,
            issuedAt: timestamp,
            expiresAt: '2026-04-01T10:00:00.000Z' as Timestamp,
            capabilities: [
                {
                    action: 'INQUIRY',
                    scope: {
                        type: 'allowlist',
                        field: 'product_category',
                        values: ['electronics', 'office'],
                    },
                },
                {
                    action: 'QUOTE',
                    scope: {
                        type: 'numeric_limit',
                        field: 'amount_usd',
                        max: 10000,
                        currency: 'USD',
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
        };

        expect(validateAgainstSchema(token, 'capabilityToken')).toEqual({
            valid: true,
            errors: [],
        });
    });

    it('validates additional authorization and ledger payloads within the current action vocabulary', () => {
        const token: CapabilityToken = {
            id: 'urn:cap:750e8400-e29b-41d4-a716-446655440000',
            specVersion: SPEC_VERSION,
            issuerDid: principalDid,
            principalDid,
            issuedTo: agentDid,
            issuedAt: timestamp,
            expiresAt: '2026-04-01T10:00:00.000Z' as Timestamp,
            capabilities: [
                {
                    action: 'RECORD',
                    scope: {
                        type: 'allowlist',
                        field: 'ledger_id',
                        values: ['primary-ledger', 'backup-ledger'],
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
        };

        const actionRecord: ActionRecord = {
            id: '770e8400-e29b-41d4-a716-446655440000',
            specVersion: SPEC_VERSION,
            agentDid,
            principalDid,
            action: 'RECORD',
            parametersSummary: { ledger_id: 'primary-ledger' },
            authorizationRef: { tokenId: token.id },
            resultSummary: { status: 'SUCCESS' },
            timestamp,
            prevHash: null,
            ledgerSignature: signature,
        };

        expect(validateAgainstSchema(token, 'capabilityToken').valid).toBe(
            true,
        );
        expect(validateAgainstSchema(actionRecord, 'actionRecord').valid).toBe(
            true,
        );
    });

    it('rejects invalid revocation url and empty capabilities', () => {
        const result = validateAgainstSchema(
            {
                id: 'urn:cap:550e8400-e29b-41d4-a716-446655440000',
                specVersion: SPEC_VERSION,
                issuerDid: principalDid,
                principalDid,
                issuedTo: agentDid,
                issuedAt: timestamp,
                expiresAt: '2026-04-01T10:00:00.000Z',
                capabilities: [],
                revocationUrl: 'http://revocation.example.com/no-placeholder',
                proof: {
                    type: 'Ed25519Signature2026',
                    created: timestamp,
                    verificationMethod: `${principalDid}#key-1`,
                    value: signature,
                },
            },
            'capabilityToken',
        );

        expect(result.valid).toBe(false);
        expect(
            result.errors.some(
                (error) => error.instancePath === '/capabilities',
            ),
        ).toBe(true);
        expect(
            result.errors.some(
                (error) => error.instancePath === '/revocationUrl',
            ),
        ).toBe(true);
    });

    it('validates negotiation envelope and header types', () => {
        const header: EnvelopeHeader = {
            senderDid: agentDid,
            recipientDid:
                'did:agent:00112233445566778899aabbccddeeff00112233' as DID,
            sessionId: null,
            sequenceNumber: 1,
        };

        const envelope: NegotiationEnvelope = {
            id: '660e8400-e29b-41d4-a716-446655440001',
            specVersion: SPEC_VERSION,
            header,
            messageType: 'NEGOTIATION_REQUEST',
            body: {
                action: 'INQUIRY',
                params: { product_category: 'electronics' },
            },
            signature,
            timestamp,
        };

        expect(
            validateAgainstSchema(envelope, 'negotiationEnvelope').valid,
        ).toBe(true);
    });

    it('validates action records and integrity proof', () => {
        const actionRecord: ActionRecord = {
            id: '880e8400-e29b-41d4-a716-446655440002',
            specVersion: SPEC_VERSION,
            agentDid,
            principalDid,
            action: 'INQUIRY',
            parametersSummary: { product_category: 'electronics' },
            authorizationRef: {
                tokenId: '550e8400-e29b-41d4-a716-446655440000',
            },
            resultSummary: { status: 'SUCCESS' },
            timestamp,
            prevHash: null,
            ledgerSignature: signature,
        };

        const integrityProof: IntegrityProof = {
            agentDid,
            chainLength: 1,
            headHash: hash,
            computedAt: timestamp,
            verifierDid: principalDid,
        };

        expect(validateAgainstSchema(actionRecord, 'actionRecord').valid).toBe(
            true,
        );
        expect(
            validateAgainstSchema(integrityProof, 'integrityProof').valid,
        ).toBe(true);
    });

    it('handles null and unknown schema ids without crashing', () => {
        expect(validateAgainstSchema(null, 'principalIdentity').valid).toBe(
            false,
        );
        expect(validateAgainstSchema({}, 'protocolError').valid).toBe(false);
    });

    it('validates a SessionRecord (session-persistence)', () => {
        const sessionRecord: SessionRecord = {
            sessionId: '11111111-2222-4333-8444-555555555555',
            initiatorDid: agentDid,
            responderDid:
                'did:agent:00112233445566778899aabbccddeeff00112233' as DID,
            principalDid: principalDid,
            capabilityTokenId: null,
            capabilityTokenFingerprint: null,
            state: 'ACTIVE',
            negotiatedCapabilities: ['INQUIRY'],
            establishedAt: timestamp,
            lastSeenAt: timestamp,
            lastAuthorizedAt: timestamp,
            idleSince: null,
            closedAt: null,
            closeReason: null,
            supersedesSessionId: null,
            didPairKey: `${agentDid}:did:agent:00112233445566778899aabbccddeeff00112233`,
            createdAt: timestamp,
            updatedAt: timestamp,
            revision: '1',
        };
        expect(
            validateAgainstSchema(sessionRecord, 'sessionRecord').valid,
        ).toBe(true);
    });

    it('rejects a SessionRecord with invalid state value', () => {
        const result = validateAgainstSchema(
            {
                sessionId: '11111111-2222-4333-8444-555555555555',
                initiatorDid: agentDid,
                responderDid:
                    'did:agent:00112233445566778899aabbccddeeff00112233',
                principalDid: principalDid,
                capabilityTokenId: null,
                capabilityTokenFingerprint: null,
                state: 'PENDING', // invalid — not in enum
                negotiatedCapabilities: [],
                establishedAt: null,
                lastSeenAt: timestamp,
                lastAuthorizedAt: timestamp,
                idleSince: null,
                closedAt: null,
                closeReason: null,
                supersedesSessionId: null,
                didPairKey: 'pair-key',
                createdAt: timestamp,
                updatedAt: timestamp,
                revision: '1',
            },
            'sessionRecord',
        );
        expect(result.valid).toBe(false);
    });

    it('validates a SignedAuditQuery (audit-access-model)', () => {
        const auditQuery: SignedAuditQuery = {
            requesterDid: principalDid,
            targetAgentDid: agentDid,
            httpMethod: 'GET',
            resourceBinding: { route: 'records.list', recordId: null },
            queryParams: {},
            snapshotBoundary: {
                headCreatedAt: timestamp,
                headRecordId: 'rec-00000000-0000-4000-8000-000000000001',
            },
            timestamp,
            signature,
        };
        expect(
            validateAgainstSchema(auditQuery, 'signedAuditQuery').valid,
        ).toBe(true);
    });

    it('validates a SignedAuditQuery with records.get resourceBinding', () => {
        const auditQuery: SignedAuditQuery = {
            requesterDid: principalDid,
            targetAgentDid: agentDid,
            httpMethod: 'GET',
            resourceBinding: {
                route: 'records.get',
                recordId: 'rec-00000000-0000-4000-8000-000000000001',
            },
            queryParams: {},
            snapshotBoundary: {
                headCreatedAt: timestamp,
                headRecordId: 'rec-00000000-0000-4000-8000-000000000001',
            },
            timestamp,
            signature,
        };
        expect(
            validateAgainstSchema(auditQuery, 'signedAuditQuery').valid,
        ).toBe(true);
    });

    it('rejects a SignedAuditQuery missing the required signature field', () => {
        const result = validateAgainstSchema(
            {
                requesterDid: principalDid,
                targetAgentDid: agentDid,
                httpMethod: 'GET',
                resourceBinding: { route: 'records.list', recordId: null },
                queryParams: {},
                snapshotBoundary: {
                    headCreatedAt: timestamp,
                    headRecordId: 'some-record-id',
                },
                timestamp,
                // signature is missing
            },
            'signedAuditQuery',
        );
        expect(result.valid).toBe(false);
    });

    it('validates auditSnapshotBoundary with optional headRecordHash', () => {
        expect(
            validateAgainstSchema(
                {
                    headCreatedAt: timestamp,
                    headRecordId: 'rec-00000000-0000-4000-8000-000000000001',
                    headRecordHash: hash,
                },
                'auditSnapshotBoundary',
            ).valid,
        ).toBe(true);
    });

    it('validates auditResourceBinding variants (verify, chain.verify)', () => {
        expect(
            validateAgainstSchema(
                {
                    route: 'records.verify',
                    recordId: 'rec-00000000-0000-4000-8000-000000000001',
                },
                'auditResourceBinding',
            ).valid,
        ).toBe(true);

        expect(
            validateAgainstSchema(
                { route: 'records.chain.verify', recordId: null },
                'auditResourceBinding',
            ).valid,
        ).toBe(true);
    });

    // POLICY_CREATED/UPDATED/REVOKED are written to a separate table policy_change_records,
    // and no longer enter the actionRecord schema (the frozen 6-value ActionVocabulary stays unchanged).
    it('rejects actionRecord with POLICY_CREATED action (not in frozen action enum)', () => {
        const record = {
            id: '990e8400-e29b-41d4-a716-446655440099',
            specVersion: SPEC_VERSION,
            agentDid,
            principalDid,
            action: 'POLICY_CREATED',
            parametersSummary: {
                policyId: 'policy-001',
                policyVersion: 1,
                changeType: 'CREATED',
            },
            authorizationRef: null,
            resultSummary: { status: 'SUCCESS' },
            timestamp,
            prevHash: null,
            ledgerSignature: signature,
        };
        expect(validateAgainstSchema(record, 'actionRecord').valid).toBe(false);
    });

    it('rejects actionRecord with POLICY_UPDATED action (not in frozen action enum)', () => {
        const record = {
            id: '990e8400-e29b-41d4-a716-446655440088',
            specVersion: SPEC_VERSION,
            agentDid,
            principalDid,
            action: 'POLICY_UPDATED',
            parametersSummary: {
                policyId: 'policy-001',
                policyVersion: 2,
                changeType: 'UPDATED',
                changedFields: ['scope'],
            },
            authorizationRef: null,
            resultSummary: { status: 'SUCCESS' },
            timestamp,
            prevHash: hash,
            ledgerSignature: signature,
        };
        expect(validateAgainstSchema(record, 'actionRecord').valid).toBe(false);
    });

    it('rejects actionRecord with unknown action value (non-vocabulary)', () => {
        const record = {
            id: '990e8400-e29b-41d4-a716-446655440077',
            specVersion: SPEC_VERSION,
            agentDid,
            principalDid,
            action: 'DELETE',
            parametersSummary: null,
            authorizationRef: null,
            resultSummary: { status: 'SUCCESS' },
            timestamp,
            prevHash: null,
            ledgerSignature: signature,
        };
        expect(validateAgainstSchema(record, 'actionRecord').valid).toBe(false);
    });
});

// PolicyChangeParams AJV validation (fail-closed)
describe('validateAgainstSchema policyChangeParams', () => {
    it('validates a valid POLICY_CREATED params', () => {
        expect(
            validateAgainstSchema(
                {
                    policyId: 'policy-abc-123',
                    policyVersion: 1,
                    changeType: 'CREATED',
                },
                'policyChangeParams',
            ).valid,
        ).toBe(true);
    });

    it('validates a valid POLICY_UPDATED params with changedFields', () => {
        expect(
            validateAgainstSchema(
                {
                    policyId: 'policy-abc-123',
                    policyVersion: 3,
                    changeType: 'UPDATED',
                    changedFields: ['scope', 'expiresAt'],
                },
                'policyChangeParams',
            ).valid,
        ).toBe(true);
    });

    it('validates a valid POLICY_REVOKED params with revokedAt', () => {
        expect(
            validateAgainstSchema(
                {
                    policyId: 'policy-abc-123',
                    policyVersion: 3,
                    changeType: 'REVOKED',
                    revokedAt: '2026-05-06T12:00:00.000Z',
                },
                'policyChangeParams',
            ).valid,
        ).toBe(true);
    });

    it('rejects when policyId is empty string', () => {
        const result = validateAgainstSchema(
            {
                policyId: '',
                policyVersion: 1,
                changeType: 'CREATED',
            },
            'policyChangeParams',
        );
        expect(result.valid).toBe(false);
        expect(result.errors.some((e) => e.instancePath === '/policyId')).toBe(
            true,
        );
    });

    it('rejects when policyVersion is 0 (below minimum 1)', () => {
        const result = validateAgainstSchema(
            {
                policyId: 'policy-abc-123',
                policyVersion: 0,
                changeType: 'CREATED',
            },
            'policyChangeParams',
        );
        expect(result.valid).toBe(false);
        expect(
            result.errors.some((e) => e.instancePath === '/policyVersion'),
        ).toBe(true);
    });

    it('rejects POLICY_REVOKED params that include changedFields (allOf constraint)', () => {
        const result = validateAgainstSchema(
            {
                policyId: 'policy-abc-123',
                policyVersion: 2,
                changeType: 'REVOKED',
                changedFields: ['scope'],
            },
            'policyChangeParams',
        );
        expect(result.valid).toBe(false);
    });

    it('rejects when revokedAt has a malformed timestamp format', () => {
        const result = validateAgainstSchema(
            {
                policyId: 'policy-abc-123',
                policyVersion: 2,
                changeType: 'REVOKED',
                revokedAt: '2026-05-06 12:00:00', // missing T and Z
            },
            'policyChangeParams',
        );
        expect(result.valid).toBe(false);
        expect(
            result.errors.some((e) => e.instancePath === '/revokedAt'),
        ).toBe(true);
    });

    it('rejects when changeType is not in the allowed enum', () => {
        const result = validateAgainstSchema(
            {
                policyId: 'policy-abc-123',
                policyVersion: 1,
                changeType: 'DELETED',
            },
            'policyChangeParams',
        );
        expect(result.valid).toBe(false);
    });

    // CREATED is not allowed to carry changedFields (semantic contradiction: a creation event has no diff)
    it('should reject POLICY_CREATED params that include changedFields', () => {
        const result = validateAgainstSchema(
            {
                policyId: 'policy-abc-123',
                policyVersion: 1,
                changeType: 'CREATED',
                changedFields: ['scope'],
            },
            'policyChangeParams',
        );
        expect(result.valid).toBe(false);
    });

    // CREATED is not allowed to carry revokedAt (semantic contradiction: a creation event is not a revocation)
    it('should reject POLICY_CREATED params that include revokedAt', () => {
        const result = validateAgainstSchema(
            {
                policyId: 'policy-abc-123',
                policyVersion: 1,
                changeType: 'CREATED',
                revokedAt: '2026-05-06T12:00:00.000Z',
            },
            'policyChangeParams',
        );
        expect(result.valid).toBe(false);
    });

    // UPDATED is not allowed to carry revokedAt (semantic contradiction: a modification event is not a revocation)
    it('should reject POLICY_UPDATED params that include revokedAt', () => {
        const result = validateAgainstSchema(
            {
                policyId: 'policy-abc-123',
                policyVersion: 2,
                changeType: 'UPDATED',
                changedFields: ['scope'],
                revokedAt: '2026-05-06T12:00:00.000Z',
            },
            'policyChangeParams',
        );
        expect(result.valid).toBe(false);
    });

    // REVOKED is not allowed to carry changedFields (existing constraint, happy-path verification)
    it('should still reject POLICY_REVOKED params with changedFields (existing constraint regression)', () => {
        const result = validateAgainstSchema(
            {
                policyId: 'policy-abc-123',
                policyVersion: 2,
                changeType: 'REVOKED',
                changedFields: ['scope'],
                revokedAt: '2026-05-06T12:00:00.000Z',
            },
            'policyChangeParams',
        );
        expect(result.valid).toBe(false);
    });

    // happy path — minimal valid CREATED/UPDATED/REVOKED cases still pass
    it('should accept POLICY_CREATED without optional fields (happy path)', () => {
        const result = validateAgainstSchema(
            {
                policyId: 'policy-abc-123',
                policyVersion: 1,
                changeType: 'CREATED',
            },
            'policyChangeParams',
        );
        expect(result.valid).toBe(true);
    });

    it('should accept POLICY_UPDATED with changedFields and without revokedAt (happy path)', () => {
        const result = validateAgainstSchema(
            {
                policyId: 'policy-abc-123',
                policyVersion: 2,
                changeType: 'UPDATED',
                changedFields: ['scope'],
            },
            'policyChangeParams',
        );
        expect(result.valid).toBe(true);
    });

    it('should accept POLICY_REVOKED with revokedAt and without changedFields (happy path)', () => {
        const result = validateAgainstSchema(
            {
                policyId: 'policy-abc-123',
                policyVersion: 3,
                changeType: 'REVOKED',
                revokedAt: '2026-05-06T12:00:00.000Z',
            },
            'policyChangeParams',
        );
        expect(result.valid).toBe(true);
    });
});
