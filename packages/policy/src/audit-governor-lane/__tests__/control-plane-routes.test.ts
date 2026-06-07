/**
 * GovernorLaneScopeChecker + dispatch assertions unit tests.
 *
 * Coverage:
 * - GovernorLaneScopeChecker 6-point scope validation
 * - isGovernorLaneTarget determination
 * - assertLaneDispatchConsistency lane isolation
 * - assertUnsignedHeadNotGovernor honest declaration
 * - business lane privilege-escalation guard
 *
 */

import { describe, it, expect } from 'vitest';
import type { DID, Timestamp, Signature } from '@coivitas/types';
import { SESSION_GOVERNOR_DID } from '@coivitas/types';
import type { VerifiedAuditRequest } from '@coivitas/types';

import {
    GovernorLaneScopeChecker,
    isGovernorLaneTarget,
    assertLaneDispatchConsistency,
    assertUnsignedHeadNotGovernor,
} from '../control-plane-routes.js';
import type { ControlPlaneRequesterScope } from '@coivitas/types';

const REQUESTER_DID = 'did:key:z6MkRequester...' as DID;
const AGENT_DID_A = 'did:agent:agent-A' as DID;
const AGENT_DID_B = 'did:agent:agent-B' as DID;
const PRINCIPAL_DID_A = 'did:key:z6MkPrincipalA...' as DID;
const PRINCIPAL_DID_B = 'did:key:z6MkPrincipalB...' as DID;
const GOVERNOR_DID = SESSION_GOVERNOR_DID as DID;
const TIMESTAMP = '2026-05-05T10:00:00.000Z' as Timestamp;

function makeScopeMap(
    scopes: Array<[string, ControlPlaneRequesterScope]>,
): ReadonlyMap<string, ControlPlaneRequesterScope> {
    return new Map(scopes);
}

describe('GovernorLaneScopeChecker', () => {
    describe('checkScope', () => {
        it('should allow when requester and affectedAgentDid are in scope', () => {
            const checker = new GovernorLaneScopeChecker(
                makeScopeMap([
                    [
                        REQUESTER_DID as string,
                        {
                            allowedAffectedAgentDids: new Set([AGENT_DID_A]),
                        },
                    ],
                ]),
            );

            const result = checker.checkScope(REQUESTER_DID, AGENT_DID_A);
            expect(result.allowed).toBe(true);
        });

        it('should deny when requester not in scope map', () => {
            const checker = new GovernorLaneScopeChecker(makeScopeMap([]));

            const result = checker.checkScope(REQUESTER_DID, AGENT_DID_A);
            expect(result.allowed).toBe(false);
            if (!result.allowed) {
                expect(result.reason).toContain('not found');
            }
        });

        it('should deny when allowedAffectedAgentDids is empty', () => {
            const checker = new GovernorLaneScopeChecker(
                makeScopeMap([
                    [
                        REQUESTER_DID as string,
                        {
                            allowedAffectedAgentDids: new Set(),
                        },
                    ],
                ]),
            );

            const result = checker.checkScope(REQUESTER_DID, AGENT_DID_A);
            expect(result.allowed).toBe(false);
            if (!result.allowed) {
                expect(result.reason).toContain('empty');
            }
        });

        it('should deny when affectedAgentDid is undefined (fail-closed)', () => {
            const checker = new GovernorLaneScopeChecker(
                makeScopeMap([
                    [
                        REQUESTER_DID as string,
                        {
                            allowedAffectedAgentDids: new Set([AGENT_DID_A]),
                        },
                    ],
                ]),
            );

            const result = checker.checkScope(REQUESTER_DID, undefined);
            expect(result.allowed).toBe(false);
            if (!result.allowed) {
                expect(result.reason).toContain('required');
            }
        });

        it('should deny when affectedAgentDid not in scope', () => {
            const checker = new GovernorLaneScopeChecker(
                makeScopeMap([
                    [
                        REQUESTER_DID as string,
                        {
                            allowedAffectedAgentDids: new Set([AGENT_DID_A]),
                        },
                    ],
                ]),
            );

            const result = checker.checkScope(REQUESTER_DID, AGENT_DID_B);
            expect(result.allowed).toBe(false);
            if (!result.allowed) {
                expect(result.reason).toContain('not in requester scope');
            }
        });

        it('should allow when principal dimension is unconstrained', () => {
            const checker = new GovernorLaneScopeChecker(
                makeScopeMap([
                    [
                        REQUESTER_DID as string,
                        {
                            allowedAffectedAgentDids: new Set([AGENT_DID_A]),
                            // allowedAffectedPrincipalDids undefined -> unconstrained
                        },
                    ],
                ]),
            );

            const result = checker.checkScope(
                REQUESTER_DID,
                AGENT_DID_A,
                PRINCIPAL_DID_A,
            );
            expect(result.allowed).toBe(true);
        });

        it('should deny when principal constrained and affectedPrincipalDid missing', () => {
            const checker = new GovernorLaneScopeChecker(
                makeScopeMap([
                    [
                        REQUESTER_DID as string,
                        {
                            allowedAffectedAgentDids: new Set([AGENT_DID_A]),
                            allowedAffectedPrincipalDids: new Set([
                                PRINCIPAL_DID_A,
                            ]),
                        },
                    ],
                ]),
            );

            const result = checker.checkScope(
                REQUESTER_DID,
                AGENT_DID_A,
                undefined,
            );
            expect(result.allowed).toBe(false);
        });

        it('should deny when affectedPrincipalDid not in scope', () => {
            const checker = new GovernorLaneScopeChecker(
                makeScopeMap([
                    [
                        REQUESTER_DID as string,
                        {
                            allowedAffectedAgentDids: new Set([AGENT_DID_A]),
                            allowedAffectedPrincipalDids: new Set([
                                PRINCIPAL_DID_A,
                            ]),
                        },
                    ],
                ]),
            );

            const result = checker.checkScope(
                REQUESTER_DID,
                AGENT_DID_A,
                PRINCIPAL_DID_B,
            );
            expect(result.allowed).toBe(false);
            if (!result.allowed) {
                expect(result.reason).toContain('not in requester scope');
            }
        });

        it('should allow when affectedPrincipalDid is in scope', () => {
            const checker = new GovernorLaneScopeChecker(
                makeScopeMap([
                    [
                        REQUESTER_DID as string,
                        {
                            allowedAffectedAgentDids: new Set([AGENT_DID_A]),
                            allowedAffectedPrincipalDids: new Set([
                                PRINCIPAL_DID_A,
                            ]),
                        },
                    ],
                ]),
            );

            const result = checker.checkScope(
                REQUESTER_DID,
                AGENT_DID_A,
                PRINCIPAL_DID_A,
            );
            expect(result.allowed).toBe(true);
        });
    });
});

describe('isGovernorLaneTarget', () => {
    it('should return true for SESSION_GOVERNOR_DID', () => {
        expect(isGovernorLaneTarget(GOVERNOR_DID)).toBe(true);
    });

    it('should return false for business agent DID', () => {
        expect(isGovernorLaneTarget(AGENT_DID_A)).toBe(false);
    });

    it('should return false for principal DID', () => {
        expect(isGovernorLaneTarget(REQUESTER_DID)).toBe(false);
    });
});

describe('assertLaneDispatchConsistency', () => {
    const baseQuery = {
        requesterDid: REQUESTER_DID,
        httpMethod: 'GET' as const,
        resourceBinding: { route: 'records.list' as const, recordId: null },
        queryParams: {},
        timestamp: TIMESTAMP,
        signature: 'sig' as Signature,
    };

    it('should pass for business lane + non-governor target', () => {
        const request: VerifiedAuditRequest = {
            lane: 'business',
            query: {
                ...baseQuery,
                targetAgentDid: AGENT_DID_A,
            },
            resolvedIdentity: {} as never,
            identityStatus: 'active',
            verifiedAt: TIMESTAMP,
        };
        // no throw
        assertLaneDispatchConsistency(request);
    });

    it('should pass for control-plane lane + governor target', () => {
        const request: VerifiedAuditRequest = {
            lane: 'control-plane',
            query: {
                ...baseQuery,
                targetAgentDid: GOVERNOR_DID,
            },
            resolution: {
                did: GOVERNOR_DID,
                metadata: {},
                verifiedAt: TIMESTAMP,
            },
            verifiedAt: TIMESTAMP,
        };
        // no throw
        assertLaneDispatchConsistency(request);
    });

    it('should throw when business lane targets governor DID', () => {
        const request: VerifiedAuditRequest = {
            lane: 'business',
            query: {
                ...baseQuery,
                targetAgentDid: GOVERNOR_DID,
            },
            resolvedIdentity: {} as never,
            identityStatus: 'active',
            verifiedAt: TIMESTAMP,
        };
        expect(() => assertLaneDispatchConsistency(request)).toThrow(
            'Lane dispatch violation',
        );
    });

    it('should throw when control-plane lane targets non-governor DID', () => {
        const request: VerifiedAuditRequest = {
            lane: 'control-plane',
            query: {
                ...baseQuery,
                targetAgentDid: AGENT_DID_A,
            },
            resolution: {
                did: GOVERNOR_DID,
                metadata: {},
                verifiedAt: TIMESTAMP,
            },
            verifiedAt: TIMESTAMP,
        };
        expect(() => assertLaneDispatchConsistency(request)).toThrow(
            'Lane dispatch violation',
        );
    });
});

describe('assertUnsignedHeadNotGovernor', () => {
    it('should pass for business agent DID', () => {
        // no throw
        assertUnsignedHeadNotGovernor(AGENT_DID_A);
    });

    it('should throw for governor DID (P0.2 honest declaration)', () => {
        expect(() => assertUnsignedHeadNotGovernor(GOVERNOR_DID)).toThrow(
            'AUDIT_FORBIDDEN',
        );
        expect(() => assertUnsignedHeadNotGovernor(GOVERNOR_DID)).toThrow(
            'governor_unsigned_head_denied',
        );
    });
});
