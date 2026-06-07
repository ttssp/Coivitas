/**
 * PolicyChangeRecord — Policy control-plane event type constants and parameter structures.
 *
 * Design decision: reuse the action_records table, do not add a new SQL table; do not enter the
 * main ACTION_VOCABULARY enum (reuse over addition).
 *
 * Design constraints:
 * 1. These 3 action types **do not enter** ACTION_VOCABULARY or HANDSHAKE_CAPABILITY_VOCABULARY,
 *    to prevent the frozen enum from being patch-spread.
 * 2. Written to the policy.action_records.action_type column (varchar, no DB enum constraint).
 * 3. PolicyChangeRecorder writes directly using the recorder/shared.ts utility functions, bypassing
 *    the ActionRecorder.assertLaneAllowed lane check while retaining the hash chain + signing mechanism.
 * 4. Keeps specVersion v0.3.0, not triggering a wire format break.
 *
 * self-check: the constants in this module appear only in the ActionRecord.action field,
 * **do not** enter PROTOCOL_ERROR_CODES, and do not collide with the error code namespace.
 */

import type { Timestamp } from './base.js';

// ---------------------------------------------------------------------------
// Policy control-plane action type constants
// ---------------------------------------------------------------------------

/**
 * Policy creation event action type.
 *
 * Written to policy.action_records.action_type;
 * used only by PolicyChangeRecorder, not via ActionRecorder.assertLaneAllowed.
 */
export const ACTION_POLICY_CREATED = 'POLICY_CREATED' as const;

/**
 * Policy modification event action type.
 *
 * Written to policy.action_records.action_type;
 * used only by PolicyChangeRecorder, not via ActionRecorder.assertLaneAllowed.
 */
export const ACTION_POLICY_UPDATED = 'POLICY_UPDATED' as const;

/**
 * Policy revocation/deactivation event action type.
 *
 * Written to policy.action_records.action_type;
 * used only by PolicyChangeRecorder, not via ActionRecorder.assertLaneAllowed.
 */
export const ACTION_POLICY_REVOKED = 'POLICY_REVOKED' as const;

/**
 * The set of Policy control-plane action types (runtime enum source).
 *
 * Uses:
 * - PolicyChangeRecorder internally validates actionType legality;
 * - the action_type IN (...) filter condition for audit queries.
 *
 * Not a member of ACTION_VOCABULARY or HANDSHAKE_CAPABILITY_VOCABULARY
 * (— to prevent the frozen enum from being patch-spread).
 */
export const POLICY_ACTION_TYPES = [
    ACTION_POLICY_CREATED,
    ACTION_POLICY_UPDATED,
    ACTION_POLICY_REVOKED,
] as const;

/** Policy control-plane action type union (type-layer reference).*/
export type PolicyActionType = (typeof POLICY_ACTION_TYPES)[number];

// ---------------------------------------------------------------------------
// PolicyChangeParams — written to ActionRecord.parametersSummary
// ---------------------------------------------------------------------------

/**
 * The parametersSummary shape of a Policy change event (written to policy.action_records.parameters_summary).
 *
 * Field descriptions:
 * - policyId: the policy unique identifier (required for all change types)
 * - policyVersion: the version after the operation (CREATED=1, UPDATED=N+1, REVOKED=final N)
 * - changeType: corresponds one-to-one with the action type, so queries do not need to JOIN the action table
 * - changedFields: the list of changed field names for POLICY_UPDATED (optional, used for diff review)
 * - revokedAt: the revocation timestamp for POLICY_REVOKED (optional, records the exact revocation moment)
 *
 * Relationship: this object is written **as a whole** as ActionRecord.parametersSummary,
 * serialized via JSON.stringify and stored in a jsonb column.
 */
export interface PolicyChangeParams {
    /** the policy unique identifier (must not be empty).*/
    policyId: string;
    /** the version after the operation (CREATED=1, UPDATED=N+1, REVOKED=final N).*/
    policyVersion: number;
    /** the change type, corresponding to ActionRecord.actionType (with the `POLICY_` prefix removed).*/
    changeType: 'CREATED' | 'UPDATED' | 'REVOKED';
    /**
     * The list of changed field names for POLICY_UPDATED (optional).
     * Example: ['scope', 'expiresAt']. Used for diff review; does not affect hash chain integrity.
     */
    changedFields?: string[];
    /**
     * The revocation timestamp for POLICY_REVOKED (optional).
     * Records the exact revocation moment, distinct from ActionRecord.timestamp (the record write moment).
     */
    revokedAt?: Timestamp;
}

// ---------------------------------------------------------------------------
// type guards (runtime helpers; AJV remains authoritative for schema validation)
// ---------------------------------------------------------------------------

/** Determines whether the given string is a legal Policy action type.*/
export const isPolicyActionType = (value: unknown): value is PolicyActionType =>
    typeof value === 'string' &&
    (POLICY_ACTION_TYPES as readonly string[]).includes(value);

/** Determines whether the given object conforms to the minimal PolicyChangeParams structure (policyId + policyVersion + changeType).*/
export const isPolicyChangeParams = (
    value: unknown,
): value is PolicyChangeParams => {
    if (typeof value !== 'object' || value === null) return false;
    const obj = value as Record<string, unknown>;
    return (
        typeof obj['policyId'] === 'string' &&
        obj['policyId'].length > 0 &&
        typeof obj['policyVersion'] === 'number' &&
        obj['policyVersion'] >= 1 &&
        (obj['changeType'] === 'CREATED' ||
            obj['changeType'] === 'UPDATED' ||
            obj['changeType'] === 'REVOKED')
    );
};
