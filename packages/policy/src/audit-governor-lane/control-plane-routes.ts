/**
 * control-plane-routes.ts -- governor lane HTTP routes.
 *
 * Control-plane lane branch route registration for the 6-endpoint matrix.
 * Remote signature verification + per-requester ControlPlaneRequesterScope scope validation.
 *
 * This module does not replace the main route registration in action-record-routes.ts;
 * instead it provides governor-lane-specific route enhancement functions that layer a
 * scope validation tier on top of the main routes.
 *
 */

import {
    ProtocolError,
    SESSION_GOVERNOR_DID,
    type DID,
} from '@coivitas/types';
import type {
    ControlPlaneRequesterScope,
    VerifiedAuditRequest,
} from '@coivitas/types';

import type { ControlPlaneRequesterScopeChecker } from './types.js';

// ---------------------------------------------------------------------------
// GovernorLaneScopeChecker -- per-requester subject scope validation implementation
// ---------------------------------------------------------------------------

/**
 * GovernorLaneScopeChecker -- per-requester ControlPlaneRequesterScope validation.
 *
 * Uses a deployer-injected scope map (requesterDid -> ControlPlaneRequesterScope)
 * to perform per-requester subject scope validation.
 *
 * fail-closed:
 * - requester not in the scope map -> AUDIT_FORBIDDEN
 * - affectedAgentDid missing -> AUDIT_FORBIDDEN
 * - affectedAgentDid not in scope -> AUDIT_FORBIDDEN
 * - allowedAffectedPrincipalDids is constrained and affectedPrincipalDid is not in scope -> AUDIT_FORBIDDEN
 *
 */
export class GovernorLaneScopeChecker implements ControlPlaneRequesterScopeChecker {
    constructor(
        private readonly scopeMap: ReadonlyMap<
            string,
            ControlPlaneRequesterScope
        >,
    ) {}

    public checkScope(
        requesterDid: DID,
        affectedAgentDid?: DID,
        affectedPrincipalDid?: DID,
    ): { allowed: true } | { allowed: false; reason: string } {
        const scope = this.scopeMap.get(requesterDid as string);

        // requester not in the scope map
        if (scope === undefined) {
            return {
                allowed: false,
                reason: `requesterDid '${requesterDid}' not found in control-plane scope map`,
            };
        }

        // allowedAffectedAgentDids is an empty set -> reject any request
        if (scope.allowedAffectedAgentDids.size === 0) {
            return {
                allowed: false,
                reason: `requesterDid '${requesterDid}' has empty allowedAffectedAgentDids (no access)`,
            };
        }

        // affectedAgentDid missing -> require an explicit subject declaration
        if (affectedAgentDid === undefined) {
            return {
                allowed: false,
                reason: `queryParams.affectedAgentDid is required for control-plane lane (fail-closed)`,
            };
        }

        // affectedAgentDid not in scope
        if (!scope.allowedAffectedAgentDids.has(affectedAgentDid)) {
            return {
                allowed: false,
                reason:
                    `affectedAgentDid '${affectedAgentDid}' not in requester scope ` +
                    `(allowed: ${[...scope.allowedAffectedAgentDids].join(', ')})`,
            };
        }

        // Optional constraint on the principal dimension
        if (scope.allowedAffectedPrincipalDids !== undefined) {
            if (affectedPrincipalDid === undefined) {
                return {
                    allowed: false,
                    reason: `queryParams.affectedPrincipalDid is required when scope constrains principal dimension`,
                };
            }
            if (!scope.allowedAffectedPrincipalDids.has(affectedPrincipalDid)) {
                return {
                    allowed: false,
                    reason:
                        `affectedPrincipalDid '${affectedPrincipalDid}' not in requester scope ` +
                        `(allowed: ${[...scope.allowedAffectedPrincipalDids].join(', ')})`,
                };
            }
        }

        return { allowed: true };
    }
}

// ---------------------------------------------------------------------------
// isGovernorLaneTarget -- dual-lane dispatch decision
// ---------------------------------------------------------------------------

/**
 * Determines whether targetAgentDid points to the governor lane.
 * Step 11 entry point: targetAgentDid === SESSION_GOVERNOR_DID -> control-plane lane.
 */
export function isGovernorLaneTarget(targetAgentDid: DID): boolean {
    return (targetAgentDid as string) === SESSION_GOVERNOR_DID;
}

// ---------------------------------------------------------------------------
// assertGovernorLaneDispatch -- prevents privilege-escalating dispatch
// ---------------------------------------------------------------------------

/**
 * Asserts that the lane of a verified request is consistent with its target.
 *
 * A business lane requester must not request governor DID data (privilege-escalation guard).
 * A governor lane requester must not request business DID data (lane isolation).
 *
 * @throws ProtocolError('INTERNAL_ERROR') on a dispatch error
 */
export function assertLaneDispatchConsistency(
    request: VerifiedAuditRequest,
): void {
    const targetIsGovernor = isGovernorLaneTarget(request.query.targetAgentDid);

    if (request.lane === 'business' && targetIsGovernor) {
        throw new ProtocolError(
            'INTERNAL_ERROR',
            `Lane dispatch violation: business lane request targets governor DID ` +
                `'${request.query.targetAgentDid}'. ` +
                `Governor DID must route to control-plane lane.`,
        );
    }

    if (request.lane === 'control-plane' && !targetIsGovernor) {
        throw new ProtocolError(
            'INTERNAL_ERROR',
            `Lane dispatch violation: control-plane lane request targets non-governor DID ` +
                `'${request.query.targetAgentDid}'. ` +
                `Control-plane lane only serves governor DID.`,
        );
    }
}

// ---------------------------------------------------------------------------
// assertUnsignedHeadDenied -- leak prevention for unsigned /ledger/head
// ---------------------------------------------------------------------------

/**
 * For the unsigned /ledger/head endpoint, governor DID -> 403 AUDIT_FORBIDDEN.
 *
 * Honest declaration: never silently expose the governor head.
 *
 */
export function assertUnsignedHeadNotGovernor(targetAgentDid: DID): void {
    if (isGovernorLaneTarget(targetAgentDid)) {
        throw new ProtocolError(
            'INTERNAL_ERROR',
            `AUDIT_FORBIDDEN: unsigned /ledger/head does not serve governor DID ` +
                `(P0.2 honest declaration: use signed control-plane audit query instead). ` +
                `detail='governor_unsigned_head_denied'`,
        );
    }
}
