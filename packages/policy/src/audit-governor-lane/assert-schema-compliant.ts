/**
 * assert-schema-compliant.ts -- full AJV validation for control-plane SESSION_SUPERSEDED.
 *
 * Background: assertLaneAllowed only checks the 5 required fields + reason enum +
 * reason/newSessionId pairing, missing DID pattern + ISO8601 + additionalProperties
 * validation. This module fills in the full validation.
 *
 * This module uses the AJV compiled validator from @coivitas/types/validation to run
 * full schema validation on the SESSION_SUPERSEDED parametersSummary.
 *
 * Validation items (complete list):
 * - affectedAgentDid matches the did:agent:* pattern
 * - affectedPrincipalDid matches the did:key:* pattern
 * - timestamp matches the ISO8601 pattern
 * - oldSessionId / newSessionId minLength:1 (when non-null)
 * - reason enum of 4 values
 * - reason/newSessionId pairing (FORCED_CLOSE allows null)
 * - additionalProperties: false rejects unknown fields
 *
 */

import {
    ACTION_SESSION_SUPERSEDED,
    ProtocolError,
    validateAgainstSchema,
} from '@coivitas/types';

import type { AssertSchemaCompliantInput } from './types.js';

/**
 * Runs full AJV schema validation on control-plane SESSION_SUPERSEDED input.
 *
 * Validation only triggers when actionType === SESSION_SUPERSEDED.
 * On validation failure, throw ProtocolError('INTERNAL_ERROR') fail-closed.
 *
 * Uses INTERNAL_ERROR + detail for disambiguation (error code reuse).
 * The detail carries the AJV error path for easier debugging.
 *
 * @param input the subset of ActionRecordInput to validate
 * @throws ProtocolError('INTERNAL_ERROR') on validation failure
 */
export function assertSchemaCompliant(input: AssertSchemaCompliantInput): void {
    // Only SESSION_SUPERSEDED triggers the full AJV validation
    if (input.actionType !== ACTION_SESSION_SUPERSEDED) {
        return;
    }

    if (
        input.parametersSummary === null ||
        input.parametersSummary === undefined
    ) {
        throw new ProtocolError(
            'INTERNAL_ERROR',
            `assertSchemaCompliant: SESSION_SUPERSEDED parametersSummary is null/undefined. ` +
                `AJV schema requires object with 6 required fields. ` +
                `(schema compliance contract).`,
        );
    }

    // Use validateAgainstSchema from @coivitas/types to validate sessionSupersededParams
    const result = validateAgainstSchema(
        input.parametersSummary,
        'sessionSupersededParams',
    );

    if (!result.valid) {
        const errorSummary = result.errors
            .map((e) => `${e.instancePath || '/'}: ${e.message} (${e.keyword})`)
            .join('; ');

        throw new ProtocolError(
            'INTERNAL_ERROR',
            `assertSchemaCompliant: SESSION_SUPERSEDED parametersSummary fails AJV schema. ` +
                `Errors: ${errorSummary}. ` +
                `(schema compliance contract).`,
        );
    }
}
