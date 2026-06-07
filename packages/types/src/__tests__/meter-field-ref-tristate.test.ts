/**
 * MeterFieldRef.source tristate extension tests
 *
 * Acceptance criteria:
 * 1. The TypeScript interface accepts the tristate source values
 * 2. The JSON schema validator accepts the tristate
 * 3. The schema validator rejects invalid source values
 * 4. 'action_record' existing behavior stays unchanged (backward compatibility)
 * 5. The METRIC_SOURCE_NOT_IMPLEMENTED error code exists in ProtocolErrorCode
 */
import { describe, expect, it } from 'vitest';

import type {
    MeterFieldRef,
    MeterFieldRefSource,
    ProtocolErrorCode,
} from '../index.js';
import { validateAgainstSchema } from '../index.js';

// tristate value constants (convenient for table-driven tests)
const VALID_SOURCES: MeterFieldRefSource[] = [
    'action_record',
    'external_witness',
    'consensus_meter',
];

// helper: build a valid meterFieldRef object
function makeMeterFieldRef(
    source: MeterFieldRefSource,
    metric = 'transaction_amount',
): MeterFieldRef {
    return { source, metric };
}

// helper: build a cumulative_limit scope object with meterField (used for schema validation)
function makeCumulativeLimitScope(source: MeterFieldRefSource) {
    return {
        type: 'cumulative_limit',
        meterField: makeMeterFieldRef(source),
        max: 1000,
        window: 'day',
    };
}

// ——————————————————————————————————————————
// 1. TypeScript type checking (compile time)
// ——————————————————————————————————————————
describe('MeterFieldRef type system', () => {
    it('should accept action_record source when constructing MeterFieldRef', () => {
        const ref: MeterFieldRef = makeMeterFieldRef('action_record');
        expect(ref.source).toBe('action_record');
    });

    it('should accept external_witness source when constructing MeterFieldRef', () => {
        const ref: MeterFieldRef = makeMeterFieldRef('external_witness');
        expect(ref.source).toBe('external_witness');
    });

    it('should accept consensus_meter source when constructing MeterFieldRef', () => {
        const ref: MeterFieldRef = makeMeterFieldRef('consensus_meter');
        expect(ref.source).toBe('consensus_meter');
    });

    it('should expose MeterFieldRefSource type covering all three states', () => {
        // type-level assertion: each item of the VALID_SOURCES array is assignable to MeterFieldRefSource
        const exhaustive: MeterFieldRefSource[] = VALID_SOURCES;
        expect(exhaustive).toHaveLength(3);
    });
});

// ——————————————————————————————————————————
// 2. JSON schema validation (runtime)
// ——————————————————————————————————————————
describe('meterFieldRef schema validator — tristate acceptance', () => {
    it.each(VALID_SOURCES)(
        'should accept source=%s when validating meterFieldRef against schema',
        (source) => {
            const result = validateAgainstSchema(
                makeMeterFieldRef(source),
                'meterFieldRef',
            );
            expect(result.valid).toBe(true);
            expect(result.errors).toHaveLength(0);
        },
    );

    it('should reject unknown source value when validating meterFieldRef against schema', () => {
        const result = validateAgainstSchema(
            // intentionally pass an invalid value to test fail-closed
            { source: 'blockchain_oracle', metric: 'transaction_amount' },
            'meterFieldRef',
        );
        expect(result.valid).toBe(false);
        expect(result.errors.length).toBeGreaterThan(0);
    });

    it('should reject missing source field when validating meterFieldRef against schema', () => {
        const result = validateAgainstSchema(
            { metric: 'transaction_amount' },
            'meterFieldRef',
        );
        expect(result.valid).toBe(false);
    });
});

// ——————————————————————————————————————————
// 3. tristate validation within a cumulative_limit scope
// ——————————————————————————————————————————
describe('cumulativeLimitScope schema validator — meterField source tristate', () => {
    it.each(VALID_SOURCES)(
        'should accept cumulative_limit scope with source=%s when validating schema',
        (source) => {
            const result = validateAgainstSchema(
                makeCumulativeLimitScope(source),
                'cumulativeLimitScope',
            );
            expect(result.valid).toBe(true);
        },
    );

    it('should reject cumulative_limit scope with invalid source when validating schema', () => {
        const result = validateAgainstSchema(
            {
                type: 'cumulative_limit',
                meterField: {
                    source: 'invalid_source',
                    metric: 'api_call_count',
                },
                max: 100,
                window: 'hour',
            },
            'cumulativeLimitScope',
        );
        expect(result.valid).toBe(false);
    });
});

// ——————————————————————————————————————————
// 4. Backward compatibility: action_record existing behavior unchanged
// ——————————————————————————————————————————
describe('MeterFieldRef backward compatibility', () => {
    it('should preserve action_record as default implemented source', () => {
        // backward compatibility: schema validation of existing action_record must keep passing
        const result = validateAgainstSchema(
            {
                source: 'action_record',
                metric: 'transaction_amount',
                unit: 'USD',
                precision: 2,
            },
            'meterFieldRef',
        );
        expect(result.valid).toBe(true);
    });

    it('should accept action_record with optional unit and precision when validating schema', () => {
        const result = validateAgainstSchema(
            { source: 'action_record', metric: 'api_call_count' },
            'meterFieldRef',
        );
        expect(result.valid).toBe(true);
    });
});

// ——————————————————————————————————————————
// 5. METRIC_SOURCE_NOT_IMPLEMENTED error code existence
// ——————————————————————————————————————————
describe('METRIC_SOURCE_NOT_IMPLEMENTED error code', () => {
    it('should exist in ProtocolErrorCode union type when checking error codes', () => {
        // compile-time type guard: if ProtocolErrorCode lacks this value, TS will error
        const code: ProtocolErrorCode = 'METRIC_SOURCE_NOT_IMPLEMENTED';
        expect(code).toBe('METRIC_SOURCE_NOT_IMPLEMENTED');
    });
});
