/**
 * Dispute Arbitration L0 JSON Schema definitions
 *
 * Sub-protocol — dispute-arbitration v0.1
 *
 * AJV strict mode 4 flags:
 *   strict: true — unknown keywords raise an error
 *   strictSchema: true — strict schema structure
 *   strictTypes: true — strict types
 *   allowUnionTypes: false — type arrays (union) not allowed
 *
 * JSON.stringify fallback is forbidden; canonicalize must use JCS RFC 8785.
 */

import AjvModule from 'ajv';
import { DaError } from './errors.js';

// ESM/CJS dual-module compatibility mode (see the existing pattern in csp-validation.ts)
/* v8 ignore next 2*/
const Ajv =
    (AjvModule as unknown as { default: typeof AjvModule }).default ??
    AjvModule;

// ValidateFn local type — preserves .errors access (avoids TS2709 namespace-as-type)
type ValidateFn = ((data: unknown) => boolean) & {
    errors?: Array<{ instancePath?: string; message?: string }> | null;
};

// AjvLike interface — only needs compile (avoids the TS2351 construct error)
type AjvLike = {
    compile(schema: object): ValidateFn;
};
import {
    DA_DISPUTE_TYPE_VALUES,
    DA_STATE_VALUES,
    DA_VERDICT_VALUES,
    MIN_ARBITRATOR_COUNT,
    MAX_ARBITRATOR_COUNT,
} from './constants.js';

// ─── DisputeFilingSignedPayload Schema ───────────────────────────────────────

/**
 * DisputeFilingSignedPayload JSON Schema
 *
 * Validates the CSP verify-time filing; 13 fields enter the canonical hash.
 */
export const DISPUTE_FILING_SIGNED_PAYLOAD_SCHEMA = {
    $schema: 'http://json-schema.org/draft-07/schema#',
    $id: 'https://coivitas/dispute-arbitration/v1/dispute-filing-signed-payload',
    type: 'object',
    required: [
        'disputeId',
        'claimantDid',
        'respondentDid',
        'disputeType',
        'evidenceUris',
        'cspVersion',
        'token',
        'disclosedClaims',
        'challenge',
        'audience',
        'notAfter',
        'filedAt',
        'daVersion',
        'canonicalHash',
        'claimantSignature',
    ],
    properties: {
        disputeId: {
            type: 'string',
            pattern:
                '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$',
        },
        claimantDid: {
            type: 'string',
            pattern: '^did:',
        },
        respondentDid: {
            type: 'string',
            pattern: '^did:',
        },
        disputeType: {
            type: 'string',
            enum: [...DA_DISPUTE_TYPE_VALUES],
        },
        evidenceUris: {
            type: 'array',
            items: { type: 'string' },
            minItems: 0,
        },
        settlementOperationRef: {
            type: 'string',
            pattern:
                '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$',
        },
        cspVersion: { type: 'string' },
        token: { type: 'string' },
        disclosedClaims: { type: 'object' },
        challenge: { type: 'string' },
        audience: { type: 'string' },
        notAfter: { type: 'string' },
        filedAt: { type: 'string' },
        daVersion: { type: 'string' },
        canonicalHash: {
            type: 'string',
            pattern: '^[0-9a-f]{64}$',
        },
        claimantSignature: { type: 'string' },
    },
    additionalProperties: false,
} as const;

// ─── ArbitrationDecision Schema ───────────────────────────────────────────────

/**
 * ArbitrationDecision JSON Schema
 *
 * Validates the arbitration decision; multisigPoolSize is subject to the three-layer enforcement constraint.
 */
export const ARBITRATION_DECISION_SCHEMA = {
    $schema: 'http://json-schema.org/draft-07/schema#',
    $id: 'https://coivitas/dispute-arbitration/v1/arbitration-decision',
    type: 'object',
    required: [
        'decisionId',
        'disputeId',
        'verdict',
        'multisigThreshold',
        'multisigPoolSize',
        'decisionCanonicalHash',
        'arbitratorSignatures',
        'decidedAt',
    ],
    properties: {
        decisionId: { type: 'string' },
        disputeId: {
            type: 'string',
            pattern:
                '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$',
        },
        verdict: {
            type: 'string',
            enum: [...DA_VERDICT_VALUES],
        },
        multisigThreshold: {
            type: 'integer',
            minimum: 2,
            maximum: MAX_ARBITRATOR_COUNT,
        },
        /** SQL DDL layer mirror: CHECK (multisig_pool_size >= 3 AND multisig_pool_size <= 5)*/
        multisigPoolSize: {
            type: 'integer',
            minimum: MIN_ARBITRATOR_COUNT,
            maximum: MAX_ARBITRATOR_COUNT,
        },
        decisionCanonicalHash: {
            type: 'string',
            pattern: '^[0-9a-f]{64}$',
        },
        arbitratorSignatures: {
            type: 'array',
            items: {
                type: 'object',
                required: ['arbitratorDid', 'signature'],
                properties: {
                    arbitratorDid: { type: 'string', pattern: '^did:' },
                    signature: { type: 'string' },
                },
                additionalProperties: false,
            },
            minItems: 1,
        },
        decidedAt: { type: 'string' },
    },
    additionalProperties: false,
} as const;

// ─── Dispute Schema ───────────────────────────────────────────────────────────

/**
 * Dispute ledger entity JSON Schema
 */
export const DISPUTE_SCHEMA = {
    $schema: 'http://json-schema.org/draft-07/schema#',
    $id: 'https://coivitas/dispute-arbitration/v1/dispute',
    type: 'object',
    required: [
        'disputeId',
        'tenantId',
        'currentState',
        'disputeType',
        'claimantDid',
        'respondentDid',
        'disputeFilingCanonicalHash',
        'evidenceUris',
        'cspVersion',
        'daVersion',
        'filedAt',
        'attemptedAt',
        'createdAt',
    ],
    properties: {
        disputeId: {
            type: 'string',
            pattern:
                '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$',
        },
        tenantId: { type: 'string' },
        currentState: {
            type: 'string',
            enum: [...DA_STATE_VALUES],
        },
        disputeType: {
            type: 'string',
            enum: [...DA_DISPUTE_TYPE_VALUES],
        },
        claimantDid: { type: 'string', pattern: '^did:' },
        respondentDid: { type: 'string', pattern: '^did:' },
        disputeFilingCanonicalHash: {
            type: 'string',
            pattern: '^[0-9a-f]{64}$',
        },
        settlementOperationRef: { type: 'string' },
        evidenceUris: {
            type: 'array',
            items: { type: 'string' },
        },
        cspVersion: { type: 'string' },
        daVersion: { type: 'string' },
        filedAt: { type: 'string' },
        resolvedAt: { type: 'string' },
        expiredAt: { type: 'string' },
        attemptedAt: { type: 'string' },
        createdAt: { type: 'string' },
    },
    additionalProperties: false,
} as const;

// ─── AJV instance (strict mode 4 flags) ─────────────────────────────────────────

/**
 * Create an AJV validator (strict mode 4 flags)
 *
 * strict: true — unknown keywords raise an error
 * strictSchema: true — strict schema structure
 * strictTypes: true — strict types
 * allowUnionTypes: false — type arrays (union) not allowed
 */
function createAjv(): AjvLike {
    return new (Ajv as unknown as new (
        opts: Record<string, unknown>,
    ) => AjvLike)({
        strict: true,
        strictSchema: true,
        strictTypes: true,
        allowUnionTypes: false,
    });
}

// ─── Validation functions ─────────────────────────────────────────────────────────────────

let _validateDisputeFiling: ValidateFn | undefined;
let _validateArbitrationDecision: ValidateFn | undefined;

/**
 * validateDisputeFilingSchema — DisputeFilingSignedPayload AJV validation
 *
 * Returns the list of validation errors; an empty array means it passed.
 * Invalid → DaError DA_FILING_INVALID.
 *
 * AJV strict mode 4 flags.
 */
export function validateDisputeFilingSchema(data: unknown): {
    valid: boolean;
    errors: string[];
} {
    if (!_validateDisputeFiling) {
        const ajv = createAjv();
        _validateDisputeFiling = ajv.compile(
            DISPUTE_FILING_SIGNED_PAYLOAD_SCHEMA,
        );
    }
    const validate = _validateDisputeFiling;
    const valid = validate(data);
    if (!valid) {
        /* v8 ignore next 3*/
        const errors = (validate.errors ?? []).map(
            (e) => `${e.instancePath ?? '/'} ${e.message ?? 'unknown'}`,
        );
        return { valid: false, errors };
    }
    return { valid: true, errors: [] };
}

/**
 * validateArbitrationDecisionSchema — ArbitrationDecision AJV validation
 *
 * Returns the list of validation errors; an empty array means it passed.
 * Invalid → DaError DA_ARBITRATOR_INVALID.
 *
 * AJV strict mode 4 flags.
 */
export function validateArbitrationDecisionSchema(data: unknown): {
    valid: boolean;
    errors: string[];
} {
    if (!_validateArbitrationDecision) {
        const ajv = createAjv();
        _validateArbitrationDecision = ajv.compile(ARBITRATION_DECISION_SCHEMA);
    }
    const validate = _validateArbitrationDecision;
    const valid = validate(data);
    if (!valid) {
        /* v8 ignore next 3*/
        const errors = (validate.errors ?? []).map(
            (e) => `${e.instancePath ?? '/'} ${e.message ?? 'unknown'}`,
        );
        return { valid: false, errors };
    }
    return { valid: true, errors: [] };
}

/**
 * assertValidDisputeFiling — throwing validation helper
 *
 * Invalid schema → throw DaError DA_FILING_INVALID.
 */
export function assertValidDisputeFiling(data: unknown): void {
    const result = validateDisputeFilingSchema(data);
    if (!result.valid) {
        throw new DaError('DA_FILING_INVALID', {
            reason: 'dispute_filing_schema_validation_failed',
            errors: result.errors,
        });
    }
}

/**
 * assertValidArbitrationDecision — throwing validation helper
 *
 * Invalid schema → throw DaError DA_ARBITRATOR_INVALID.
 */
export function assertValidArbitrationDecision(data: unknown): void {
    const result = validateArbitrationDecisionSchema(data);
    if (!result.valid) {
        throw new DaError('DA_ARBITRATOR_INVALID', {
            reason: 'arbitration_decision_schema_validation_failed',
            errors: result.errors,
        });
    }
}
