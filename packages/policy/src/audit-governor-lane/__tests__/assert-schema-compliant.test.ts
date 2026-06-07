/**
 * assertSchemaCompliant unit tests.
 *
 * Coverage:
 * - Non-SESSION_SUPERSEDED action -> skipped (no throw)
 * - Valid SESSION_SUPERSEDED payload -> passes
 * - parametersSummary null -> throw
 * - parametersSummary undefined -> throw
 * - affectedAgentDid not matching the did:agent:* pattern -> throw
 * - affectedPrincipalDid not matching the did:key:* pattern -> throw
 * - timestamp not matching ISO8601 -> throw
 * - additionalProperties extra field -> throw
 * - oldSessionId empty string -> throw
 * - reason with an invalid enum value -> throw
 * - FORCED_CLOSE + non-null newSessionId (string) -> pass
 * - EXPLICIT_CLOSE + null newSessionId -> throw
 *
 */

import { describe, it, expect } from 'vitest';

import { assertSchemaCompliant } from '../assert-schema-compliant.js';
import type { AssertSchemaCompliantInput } from '../types.js';

// didAgent pattern = ^did:agent:[a-f0-9]{40}$
// didKey pattern = ^did:key:[a-zA-Z0-9._%-]+$
const VALID_AGENT_DID = 'did:agent:' + 'a'.repeat(40);
const VALID_PRINCIPAL_DID = 'did:key:z6MkpTHR8VNs5xAbcde';

const VALID_PARAMS: Record<string, unknown> = {
    oldSessionId: 'sess-old-001',
    newSessionId: 'sess-new-001',
    reason: 'EXPLICIT_CLOSE',
    timestamp: '2026-05-05T10:00:00.000Z',
    affectedAgentDid: VALID_AGENT_DID,
    affectedPrincipalDid: VALID_PRINCIPAL_DID,
};

const VALID_INPUT: AssertSchemaCompliantInput = {
    agentDid: 'did:system:session-governor',
    principalDid: 'did:system:session-governor',
    actionType: 'SESSION_SUPERSEDED',
    parametersSummary: { ...VALID_PARAMS },
};

describe('assertSchemaCompliant', () => {
    // --- skip non-SESSION_SUPERSEDED ---

    it('should skip validation when actionType is not SESSION_SUPERSEDED', () => {
        // no throw for business lane actions
        assertSchemaCompliant({
            agentDid: 'did:agent:any',
            principalDid: 'did:key:any',
            actionType: 'INQUIRY',
            parametersSummary: null,
        });
    });

    it('should skip validation for RECORD action', () => {
        assertSchemaCompliant({
            agentDid: 'did:agent:any',
            principalDid: 'did:key:any',
            actionType: 'RECORD',
            parametersSummary: { arbitrary: true },
        });
    });

    // --- happy path ---

    it('should pass for valid SESSION_SUPERSEDED payload', () => {
        assertSchemaCompliant(VALID_INPUT);
    });

    it('should pass for FORCED_CLOSE with null newSessionId', () => {
        assertSchemaCompliant({
            ...VALID_INPUT,
            parametersSummary: {
                ...VALID_PARAMS,
                reason: 'FORCED_CLOSE',
                newSessionId: null,
            },
        });
    });

    it('should pass for FORCED_CLOSE with string newSessionId', () => {
        assertSchemaCompliant({
            ...VALID_INPUT,
            parametersSummary: {
                ...VALID_PARAMS,
                reason: 'FORCED_CLOSE',
                newSessionId: 'sess-new-forced',
            },
        });
    });

    it('should pass for TOKEN_REVOKED reason', () => {
        assertSchemaCompliant({
            ...VALID_INPUT,
            parametersSummary: {
                ...VALID_PARAMS,
                reason: 'TOKEN_REVOKED',
            },
        });
    });

    it('should pass for IDLE_EXPIRED reason', () => {
        assertSchemaCompliant({
            ...VALID_INPUT,
            parametersSummary: {
                ...VALID_PARAMS,
                reason: 'IDLE_EXPIRED',
            },
        });
    });

    // --- null / undefined parametersSummary ---

    it('should throw when parametersSummary is null', () => {
        expect(() =>
            assertSchemaCompliant({
                ...VALID_INPUT,
                parametersSummary: null,
            }),
        ).toThrow('parametersSummary is null/undefined');
    });

    it('should throw when parametersSummary is undefined', () => {
        expect(() =>
            assertSchemaCompliant({
                ...VALID_INPUT,
                parametersSummary: undefined,
            }),
        ).toThrow('parametersSummary is null/undefined');
    });

    // --- DID pattern validation ---

    it('should throw when affectedAgentDid does not match did:agent:* pattern', () => {
        expect(() =>
            assertSchemaCompliant({
                ...VALID_INPUT,
                parametersSummary: {
                    ...VALID_PARAMS,
                    affectedAgentDid: 'did:key:wrong-format',
                },
            }),
        ).toThrow('AJV schema');
    });

    it('should throw when affectedAgentDid is not a DID', () => {
        expect(() =>
            assertSchemaCompliant({
                ...VALID_INPUT,
                parametersSummary: {
                    ...VALID_PARAMS,
                    affectedAgentDid: 'plain-string',
                },
            }),
        ).toThrow('AJV schema');
    });

    it('should throw when affectedPrincipalDid does not match did:key:* pattern', () => {
        expect(() =>
            assertSchemaCompliant({
                ...VALID_INPUT,
                parametersSummary: {
                    ...VALID_PARAMS,
                    affectedPrincipalDid: 'did:agent:wrong-format',
                },
            }),
        ).toThrow('AJV schema');
    });

    // --- ISO8601 timestamp ---

    it('should throw when timestamp is not ISO8601', () => {
        expect(() =>
            assertSchemaCompliant({
                ...VALID_INPUT,
                parametersSummary: {
                    ...VALID_PARAMS,
                    timestamp: 'not-a-timestamp',
                },
            }),
        ).toThrow('AJV schema');
    });

    // --- additionalProperties ---

    it('should throw when parametersSummary has extra fields', () => {
        expect(() =>
            assertSchemaCompliant({
                ...VALID_INPUT,
                parametersSummary: {
                    ...VALID_PARAMS,
                    extraField: 'not-allowed',
                },
            }),
        ).toThrow('AJV schema');
    });

    // --- oldSessionId ---

    it('should throw when oldSessionId is empty string', () => {
        expect(() =>
            assertSchemaCompliant({
                ...VALID_INPUT,
                parametersSummary: {
                    ...VALID_PARAMS,
                    oldSessionId: '',
                },
            }),
        ).toThrow('AJV schema');
    });

    it('should throw when oldSessionId is missing', () => {
        const params = { ...VALID_PARAMS };
        delete (params as Record<string, unknown>)['oldSessionId'];
        expect(() =>
            assertSchemaCompliant({
                ...VALID_INPUT,
                parametersSummary: params,
            }),
        ).toThrow('AJV schema');
    });

    // --- reason enum ---

    it('should throw when reason is invalid enum value', () => {
        expect(() =>
            assertSchemaCompliant({
                ...VALID_INPUT,
                parametersSummary: {
                    ...VALID_PARAMS,
                    reason: 'INVALID_REASON',
                },
            }),
        ).toThrow('AJV schema');
    });

    // --- reason/newSessionId pairing ---

    it('should throw when EXPLICIT_CLOSE has null newSessionId', () => {
        expect(() =>
            assertSchemaCompliant({
                ...VALID_INPUT,
                parametersSummary: {
                    ...VALID_PARAMS,
                    reason: 'EXPLICIT_CLOSE',
                    newSessionId: null,
                },
            }),
        ).toThrow('AJV schema');
    });

    it('should throw when TOKEN_REVOKED has null newSessionId', () => {
        expect(() =>
            assertSchemaCompliant({
                ...VALID_INPUT,
                parametersSummary: {
                    ...VALID_PARAMS,
                    reason: 'TOKEN_REVOKED',
                    newSessionId: null,
                },
            }),
        ).toThrow('AJV schema');
    });

    it('should throw when IDLE_EXPIRED has null newSessionId', () => {
        expect(() =>
            assertSchemaCompliant({
                ...VALID_INPUT,
                parametersSummary: {
                    ...VALID_PARAMS,
                    reason: 'IDLE_EXPIRED',
                    newSessionId: null,
                },
            }),
        ).toThrow('AJV schema');
    });

    // --- error metadata ---

    it('should throw ProtocolError with code INTERNAL_ERROR', () => {
        try {
            assertSchemaCompliant({
                ...VALID_INPUT,
                parametersSummary: null,
            });
            expect.fail('should have thrown');
        } catch (err: unknown) {
            expect((err as { code: string }).code).toBe('INTERNAL_ERROR');
        }
    });

});
