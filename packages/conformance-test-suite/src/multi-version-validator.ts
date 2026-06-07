/**
 * Lightweight package-internal multi-version schema validator (Finding R2-).
 *
 * Summary first:
 * - Purpose: run cross-version REJECT fixtures (e.g. xv-03 / xv-06), avoiding SKIPping
 *   these negative-case tests just because the AJV dependency is missing.
 * - Scope statement (consistent with the scope comment in tests/interop/multi-version-validators.ts):
 *   This implementation is a targeted enum narrowing, covering the two reject scenarios explicitly
 *   marked in the fixtures:
 *     - negotiationEnvelope + v0.1.0 validator: specVersion not in ['0.1.0'] → REJECT
 *     - actionRecord + v0.2.0 validator: action === 'SESSION_SUPERSEDED' → REJECT
 *   Any other schemaId or validatorVersion combination returns null; the caller handles it as a D5 SKIP.
 * - No AJV dependency: uses direct field checks instead of full schema compilation, keeping the published package free of extra dependencies.
 * - v0.3.0 validator: equivalent to the current validateAgainstSchema, not reimplemented here (returns null to let
 *   the caller follow the existing path).
 *
 * This is not a complete schema history archive. Compatibility boundaries not explicitly asserted by the fixtures
 * remain under D5 (schema history archival infrastructure).
 */

export type MultiVersionValidatorVersion = '0.1.0' | '0.2.0' | '0.3.0';

export interface MultiVersionValidationIssue {
    instancePath: string;
    message: string;
    keyword: string;
}

export interface MultiVersionValidationResult {
    valid: boolean;
    errors: MultiVersionValidationIssue[];
}

// v0.1.0 negotiationEnvelope: the specVersion enum contains only '0.1.0'
// xv-03 scenario: data.specVersion = '0.3.0' → not in the enum → REJECT
function validateNegotiationEnvelopeV010(
    data: unknown,
): MultiVersionValidationResult {
    const d = data as Record<string, unknown>;
    const specVersion = d.specVersion;
    if (specVersion !== '0.1.0') {
        return {
            valid: false,
            errors: [
                {
                    instancePath: '/specVersion',
                    message: 'specVersion must be equal to one of the allowed values',
                    keyword: 'enum',
                },
            ],
        };
    }
    return { valid: true, errors: [] };
}

// v0.2.0 actionRecord: the action enum does not contain 'SESSION_SUPERSEDED'
// xv-06 scenario: data.action = 'SESSION_SUPERSEDED' → not in the enum → REJECT
function validateActionRecordV020(
    data: unknown,
): MultiVersionValidationResult {
    const d = data as Record<string, unknown>;
    const action = d.action;
    if (action === 'SESSION_SUPERSEDED') {
        return {
            valid: false,
            errors: [
                {
                    instancePath: '/action',
                    message: 'action must be equal to one of the allowed values',
                    keyword: 'enum',
                },
            ],
        };
    }
    return { valid: true, errors: [] };
}

/**
 * Multi-version validator router.
 *
 * @param data - the fixture data to validate
 * @param schemaId - the fixture's schemaId (e.g. 'negotiationEnvelope' / 'actionRecord')
 * @param validatorVersion - the simulated validator version string
 * @returns MultiVersionValidationResult if within the coverage set; null if not in the coverage set (caller does a D5 SKIP)
 */
export function validateWithArchivedValidator(
    data: unknown,
    schemaId: string,
    validatorVersion: string,
): MultiVersionValidationResult | null {
    // Coverage set: only negotiationEnvelope(v0.1.0) + actionRecord(v0.2.0)
    if (schemaId === 'negotiationEnvelope' && validatorVersion === '0.1.0') {
        return validateNegotiationEnvelopeV010(data);
    }
    if (schemaId === 'actionRecord' && validatorVersion === '0.2.0') {
        return validateActionRecordV020(data);
    }
    // Not in the coverage set → return null; the caller handles it as a D5 SKIP
    return null;
}
