/**
 * SESSION_SUPERSEDED ActionVocabulary extension schema landing tests
 *
 * Coverage:
 * - ActionVocabulary main enum extension: 5 → 6 values (+ SESSION_SUPERSEDED)
 * - SESSION_SUPERSEDED three-state coexistence: 0.1.0/0.2.0 fail-closed rejection; 0.3.0 accepted
 * - actor DID forced equality: agentDid === principalDid === did:system:session-governor
 * - parametersSummary shape: sessionSupersededParams 4 fields required
 * - 4 reason enum values (EXPLICIT_CLOSE / TOKEN_REVOKED / IDLE_EXPIRED / FORCED_CLOSE)
 * - newSessionId === null is only valid when reason='FORCED_CLOSE'
 * - Business actions (INQUIRY/QUOTE/CONFIRM/PUBLISH/RECORD) retain the strict didAgent/didKey mode (regression)
 * - PROTOCOL_ERROR_CODES.SESSION_SUPERSEDED namespace isolation does not collide
 * - reason is a schema field, not an error code; control-plane entry into the chain does not bypass invariants
 */

import { describe, expect, it } from 'vitest';

import {
    ACTION_SESSION_SUPERSEDED,
    ACTION_VOCABULARY,
    isSessionGovernorDid,
    isSessionSupersededReason,
    SESSION_GOVERNOR_DID,
    SESSION_SUPERSEDED_REASONS,
    type DID,
    type Signature,
    type Timestamp,
} from '../index.js';
import { validateAgainstSchema } from '../index.js';

// Fixed test data
const governorDid = SESSION_GOVERNOR_DID as unknown as DID;
const ledgerSig = 'a'.repeat(128) as Signature;
const actorSig = 'b'.repeat(128) as Signature;
const ts = '2026-04-27T01:00:00.000Z' as Timestamp;
// Affected business subject fields.
const affectedAgentDid = 'did:agent:a3f1b2c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0';
const affectedPrincipalDid =
    'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';

/**
 * Builds a SESSION_SUPERSEDED ActionRecord baseline. All fields default to valid; the caller overrides individual fields.
 * parametersSummary must include affectedAgentDid + affectedPrincipalDid.
 */
const buildSupersedeRecord = (
    overrides: Record<string, unknown> = {},
): Record<string, unknown> => ({
    id: 'rec-550e8400-e29b-41d4-a716-050e00000001',
    specVersion: '0.3.0',
    agentDid: governorDid,
    principalDid: governorDid,
    action: ACTION_SESSION_SUPERSEDED,
    parametersSummary: {
        oldSessionId: '550e8400-e29b-41d4-a716-446655440010',
        newSessionId: '550e8400-e29b-41d4-a716-446655440011',
        reason: 'EXPLICIT_CLOSE',
        timestamp: ts,
        affectedAgentDid,
        affectedPrincipalDid,
    },
    authorizationRef: null,
    resultSummary: { status: 'SUCCESS' },
    timestamp: ts,
    prevHash: null,
    ledgerSignature: ledgerSig,
    actorSignature: actorSig,
    delegationDepth: 0,
    ...overrides,
});

// ---------------------------------------------------------------------------
// 1. ActionVocabulary main enum extension (5 → 6 values)
// ---------------------------------------------------------------------------
describe('ActionVocabulary main enum extension', () => {
    it('should include SESSION_SUPERSEDED as 6th vocabulary entry', () => {
        expect(ACTION_VOCABULARY).toContain('SESSION_SUPERSEDED');
        expect(ACTION_VOCABULARY).toHaveLength(6);
    });

    it('should retain frozen 5 baseline entries', () => {
        expect(ACTION_VOCABULARY).toEqual(
            expect.arrayContaining([
                'INQUIRY',
                'QUOTE',
                'CONFIRM',
                'PUBLISH',
                'RECORD',
            ]),
        );
    });

    it('should expose ACTION_SESSION_SUPERSEDED literal constant', () => {
        expect(ACTION_SESSION_SUPERSEDED).toBe('SESSION_SUPERSEDED');
    });

    it('should freeze SESSION_SUPERSEDED_REASONS as 4 enum values', () => {
        expect(SESSION_SUPERSEDED_REASONS).toEqual([
            'EXPLICIT_CLOSE',
            'TOKEN_REVOKED',
            'IDLE_EXPIRED',
            'FORCED_CLOSE',
        ]);
    });
});

// ---------------------------------------------------------------------------
// 2. actor DID forced equality (did:system:session-governor)
// ---------------------------------------------------------------------------
describe('SESSION_SUPERSEDED actor DID forced equality', () => {
    it('should accept agentDid === principalDid === did:system:session-governor', () => {
        const result = validateAgainstSchema(
            buildSupersedeRecord(),
            'actionRecord',
        );
        expect(result.valid).toBe(true);
    });

    it('should reject agentDid != did:system:session-governor', () => {
        const result = validateAgainstSchema(
            buildSupersedeRecord({
                agentDid: 'did:agent:a3f1b2c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0',
            }),
            'actionRecord',
        );
        expect(result.valid).toBe(false);
    });

    it('should reject principalDid != did:system:session-governor', () => {
        const result = validateAgainstSchema(
            buildSupersedeRecord({
                principalDid:
                    'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
            }),
            'actionRecord',
        );
        expect(result.valid).toBe(false);
    });

    it('should expose isSessionGovernorDid type guard', () => {
        expect(isSessionGovernorDid(SESSION_GOVERNOR_DID)).toBe(true);
        expect(isSessionGovernorDid('did:agent:other')).toBe(false);
    });
});

// ---------------------------------------------------------------------------
// 3. specVersion three-state coexistence (0.1.0 / 0.2.0 reject; 0.3.0 accept)
// ---------------------------------------------------------------------------
describe('specVersion three-state acceptance policy for SESSION_SUPERSEDED', () => {
    it('should accept SESSION_SUPERSEDED on specVersion 0.3.0', () => {
        const result = validateAgainstSchema(
            buildSupersedeRecord({ specVersion: '0.3.0' }),
            'actionRecord',
        );
        expect(result.valid).toBe(true);
    });

    it('should reject SESSION_SUPERSEDED on specVersion 0.1.0 (enum lacks the 6th value)', () => {
        const record = buildSupersedeRecord({ specVersion: '0.1.0' });
        // v0.1.0 has no actorSignature / delegationDepth required constraint; here we test only action rejection
        delete record.actorSignature;
        delete record.delegationDepth;
        const result = validateAgainstSchema(record, 'actionRecord');
        expect(result.valid).toBe(false);
    });

    it('should reject SESSION_SUPERSEDED on specVersion 0.2.0 (action branch enforces 0.3.0)', () => {
        const result = validateAgainstSchema(
            buildSupersedeRecord({ specVersion: '0.2.0' }),
            'actionRecord',
        );
        expect(result.valid).toBe(false);
    });
});

// ---------------------------------------------------------------------------
// 4. parametersSummary shape (sessionSupersededParams 4 fields required)
// ---------------------------------------------------------------------------
describe('SESSION_SUPERSEDED parametersSummary shape (sessionSupersededParams)', () => {
    it('should reject missing oldSessionId', () => {
        const result = validateAgainstSchema(
            buildSupersedeRecord({
                parametersSummary: {
                    newSessionId: '550e8400-e29b-41d4-a716-446655440021',
                    reason: 'EXPLICIT_CLOSE',
                    timestamp: ts,
                    affectedAgentDid,
                    affectedPrincipalDid,
                },
            }),
            'actionRecord',
        );
        expect(result.valid).toBe(false);
    });

    it('should reject missing newSessionId field', () => {
        const result = validateAgainstSchema(
            buildSupersedeRecord({
                parametersSummary: {
                    oldSessionId: '550e8400-e29b-41d4-a716-446655440020',
                    reason: 'EXPLICIT_CLOSE',
                    timestamp: ts,
                    affectedAgentDid,
                    affectedPrincipalDid,
                },
            }),
            'actionRecord',
        );
        expect(result.valid).toBe(false);
    });

    it('should reject missing reason', () => {
        const result = validateAgainstSchema(
            buildSupersedeRecord({
                parametersSummary: {
                    oldSessionId: '550e8400-e29b-41d4-a716-446655440020',
                    newSessionId: '550e8400-e29b-41d4-a716-446655440021',
                    timestamp: ts,
                    affectedAgentDid,
                    affectedPrincipalDid,
                },
            }),
            'actionRecord',
        );
        expect(result.valid).toBe(false);
    });

    it('should reject missing timestamp', () => {
        const result = validateAgainstSchema(
            buildSupersedeRecord({
                parametersSummary: {
                    oldSessionId: '550e8400-e29b-41d4-a716-446655440020',
                    newSessionId: '550e8400-e29b-41d4-a716-446655440021',
                    reason: 'EXPLICIT_CLOSE',
                    affectedAgentDid,
                    affectedPrincipalDid,
                },
            }),
            'actionRecord',
        );
        expect(result.valid).toBe(false);
    });

    it('should reject extra additionalProperties in parametersSummary', () => {
        const result = validateAgainstSchema(
            buildSupersedeRecord({
                parametersSummary: {
                    oldSessionId: '550e8400-e29b-41d4-a716-446655440020',
                    newSessionId: '550e8400-e29b-41d4-a716-446655440021',
                    reason: 'EXPLICIT_CLOSE',
                    timestamp: ts,
                    affectedAgentDid,
                    affectedPrincipalDid,
                    extraField: 'not-allowed',
                },
            }),
            'actionRecord',
        );
        expect(result.valid).toBe(false);
    });
});

// ---------------------------------------------------------------------------
// 5. 4 reason enum values (coverage + unknown reason rejection)
// ---------------------------------------------------------------------------
describe('SESSION_SUPERSEDED reason 4 enum values + unknown rejection', () => {
    it.each(['EXPLICIT_CLOSE', 'TOKEN_REVOKED', 'IDLE_EXPIRED'] as const)(
        'should accept reason=%s with non-null newSessionId',
        (reason) => {
            const result = validateAgainstSchema(
                buildSupersedeRecord({
                    parametersSummary: {
                        oldSessionId: '550e8400-e29b-41d4-a716-446655440030',
                        newSessionId: '550e8400-e29b-41d4-a716-446655440031',
                        reason,
                        timestamp: ts,
                        affectedAgentDid,
                        affectedPrincipalDid,
                    },
                }),
                'actionRecord',
            );
            expect(result.valid).toBe(true);
        },
    );

    it('should accept reason=FORCED_CLOSE with newSessionId=null', () => {
        const result = validateAgainstSchema(
            buildSupersedeRecord({
                parametersSummary: {
                    oldSessionId: '550e8400-e29b-41d4-a716-446655440040',
                    newSessionId: null,
                    reason: 'FORCED_CLOSE',
                    timestamp: ts,
                    affectedAgentDid,
                    affectedPrincipalDid,
                },
            }),
            'actionRecord',
        );
        expect(result.valid).toBe(true);
    });

    it('should reject unknown reason value (NETWORK_TIMEOUT not in 4-enum)', () => {
        const result = validateAgainstSchema(
            buildSupersedeRecord({
                parametersSummary: {
                    oldSessionId: '550e8400-e29b-41d4-a716-446655440050',
                    newSessionId: '550e8400-e29b-41d4-a716-446655440051',
                    reason: 'NETWORK_TIMEOUT',
                    timestamp: ts,
                    affectedAgentDid,
                    affectedPrincipalDid,
                },
            }),
            'actionRecord',
        );
        expect(result.valid).toBe(false);
    });

    it('should expose isSessionSupersededReason type guard', () => {
        expect(isSessionSupersededReason('EXPLICIT_CLOSE')).toBe(true);
        expect(isSessionSupersededReason('FORCED_CLOSE')).toBe(true);
        expect(isSessionSupersededReason('UNKNOWN')).toBe(false);
        expect(isSessionSupersededReason(null)).toBe(false);
    });
});

// ---------------------------------------------------------------------------
// 6. newSessionId === null is only valid under FORCED_CLOSE (rejected for other reasons)
// ---------------------------------------------------------------------------
describe('coupling constraint between newSessionId nullability and reason', () => {
    it.each(['EXPLICIT_CLOSE', 'TOKEN_REVOKED', 'IDLE_EXPIRED'] as const)(
        'should reject newSessionId=null when reason=%s',
        (reason) => {
            const result = validateAgainstSchema(
                buildSupersedeRecord({
                    parametersSummary: {
                        oldSessionId: '550e8400-e29b-41d4-a716-446655440060',
                        newSessionId: null,
                        reason,
                        timestamp: ts,
                        affectedAgentDid,
                        affectedPrincipalDid,
                    },
                }),
                'actionRecord',
            );
            expect(result.valid).toBe(false);
        },
    );
});

// ---------------------------------------------------------------------------
// 7. Business action regression (ensure the SESSION_SUPERSEDED branch does not break existing contracts)
// ---------------------------------------------------------------------------
describe('business actions (5 frozen values) retain the strict didAgent/didKey mode', () => {
    const businessRecord = (action: string): Record<string, unknown> => ({
        id: 'rec-550e8400-e29b-41d4-a716-050e00000022',
        specVersion: '0.3.0',
        agentDid: 'did:agent:a3f1b2c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0',
        principalDid:
            'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
        action,
        parametersSummary: { product_category: 'electronics' },
        authorizationRef: {
            tokenId: 'urn:cap:550e8400-e29b-41d4-a716-446655440000',
        },
        resultSummary: { status: 'SUCCESS' },
        timestamp: ts,
        prevHash: null,
        ledgerSignature: ledgerSig,
        actorSignature: actorSig,
        delegationDepth: 0,
    });

    it.each(['INQUIRY', 'QUOTE', 'CONFIRM', 'PUBLISH', 'RECORD'] as const)(
        'should accept business action=%s with strict didAgent/didKey',
        (action) => {
            const result = validateAgainstSchema(
                businessRecord(action),
                'actionRecord',
            );
            expect(result.valid).toBe(true);
        },
    );

    it('should reject business action with did:system:session-governor as agentDid', () => {
        const record = businessRecord('INQUIRY');
        record.agentDid = SESSION_GOVERNOR_DID;
        const result = validateAgainstSchema(record, 'actionRecord');
        expect(result.valid).toBe(false);
    });
});

// ---------------------------------------------------------------------------
// 8. Standalone sessionSupersededParams schema validation (using SCHEMA_IDS directly)
// ---------------------------------------------------------------------------
describe('sessionSupersededParams schema standalone validation entry point', () => {
    it('should validate well-formed params via direct schema id', () => {
        const result = validateAgainstSchema(
            {
                oldSessionId: '550e8400-e29b-41d4-a716-446655440010',
                newSessionId: '550e8400-e29b-41d4-a716-446655440011',
                reason: 'EXPLICIT_CLOSE',
                timestamp: ts,
                affectedAgentDid,
                affectedPrincipalDid,
            },
            'sessionSupersededParams',
        );
        expect(result.valid).toBe(true);
    });

    it('should validate FORCED_CLOSE with null newSessionId', () => {
        const result = validateAgainstSchema(
            {
                oldSessionId: '550e8400-e29b-41d4-a716-446655440010',
                newSessionId: null,
                reason: 'FORCED_CLOSE',
                timestamp: ts,
                affectedAgentDid,
                affectedPrincipalDid,
            },
            'sessionSupersededParams',
        );
        expect(result.valid).toBe(true);
    });
});

// ---------------------------------------------------------------------------
// 9. affectedAgentDid + affectedPrincipalDid affected-subject binding
// The superseded business agent/principal must enter the
// immutable signed payload (top-level agentDid/principalDid forced = governor, the business
// subjects may only be carried inside parametersSummary.affected*; missing or malformed → fail-closed).
// ---------------------------------------------------------------------------
describe('affectedAgentDid + affectedPrincipalDid affected-subject binding', () => {
    it('should reject when parametersSummary.affectedAgentDid is missing', () => {
        // Use destructure to exclude the affectedAgentDid field, ensuring the schema required rule triggers
        const result = validateAgainstSchema(
            buildSupersedeRecord({
                parametersSummary: {
                    oldSessionId: '550e8400-e29b-41d4-a716-446655440010',
                    newSessionId: '550e8400-e29b-41d4-a716-446655440011',
                    reason: 'EXPLICIT_CLOSE',
                    timestamp: ts,
                    affectedPrincipalDid,
                },
            }),
            'actionRecord',
        );
        expect(result.valid).toBe(false);
    });

    it('should reject when parametersSummary.affectedPrincipalDid is missing', () => {
        const result = validateAgainstSchema(
            buildSupersedeRecord({
                parametersSummary: {
                    oldSessionId: '550e8400-e29b-41d4-a716-446655440010',
                    newSessionId: '550e8400-e29b-41d4-a716-446655440011',
                    reason: 'EXPLICIT_CLOSE',
                    timestamp: ts,
                    affectedAgentDid,
                },
            }),
            'actionRecord',
        );
        expect(result.valid).toBe(false);
    });

    it('should reject affectedAgentDid with invalid did:agent pattern (fail-closed)', () => {
        const result = validateAgainstSchema(
            buildSupersedeRecord({
                parametersSummary: {
                    oldSessionId: '550e8400-e29b-41d4-a716-446655440010',
                    newSessionId: '550e8400-e29b-41d4-a716-446655440011',
                    reason: 'EXPLICIT_CLOSE',
                    timestamp: ts,
                    // Invalid: did:key used in the affectedAgentDid field
                    affectedAgentDid:
                        'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
                    affectedPrincipalDid,
                },
            }),
            'actionRecord',
        );
        expect(result.valid).toBe(false);
    });

    it('should reject affectedPrincipalDid with invalid did:key pattern (fail-closed)', () => {
        const result = validateAgainstSchema(
            buildSupersedeRecord({
                parametersSummary: {
                    oldSessionId: '550e8400-e29b-41d4-a716-446655440010',
                    newSessionId: '550e8400-e29b-41d4-a716-446655440011',
                    reason: 'EXPLICIT_CLOSE',
                    timestamp: ts,
                    affectedAgentDid,
                    // Invalid: did:agent used in the affectedPrincipalDid field
                    affectedPrincipalDid:
                        'did:agent:a3f1b2c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0',
                },
            }),
            'actionRecord',
        );
        expect(result.valid).toBe(false);
    });

    it('should accept all 4 reason variants with affected* fields', () => {
        for (const reason of SESSION_SUPERSEDED_REASONS) {
            const newSessionId =
                reason === 'FORCED_CLOSE'
                    ? null
                    : '550e8400-e29b-41d4-a716-446655440011';
            const result = validateAgainstSchema(
                buildSupersedeRecord({
                    parametersSummary: {
                        oldSessionId: '550e8400-e29b-41d4-a716-446655440010',
                        newSessionId,
                        reason,
                        timestamp: ts,
                        affectedAgentDid,
                        affectedPrincipalDid,
                    },
                }),
                'actionRecord',
            );
            expect(result.valid).toBe(true);
        }
    });
});
