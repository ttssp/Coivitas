/**
 * Settlement Retry (SR) sub-protocol v0.1 — AJV strict mode validator (Layer 3 of defense)
 *
 * Priority-10 sub-protocol — settlement-retry
 *
 * Layer 3 of the triple line of defense:
 *   AJV strict mode 4 flags (reuses the csp/atp pattern):
 *     strict: true — global strict mode guard
 *     strictSchema: true — strict validation of schema structure
 *     strictNumbers: true — strict numeric types
 *     strictTypes: true — strict types
 *   validateFormats: true — format "uuid" validation mandatory
 *   addFormats(ajv) — ajv-formats mandatory
 *   allErrors: false — fail-closed: reject on the first invariant violation (do not accumulate errors)
 *
 * Independent-instance design:
 *   This file creates an independent AJV instance; it does not reuse the validation.ts global instance / csp-validation.ts / atp-validation.ts
 *   (consistent with the atp-validation.ts pattern; each sub-protocol maintains its own strict instance)
 *
 * AJV instantiation location: the types package (this file); the L3 policy package imports the validation functions from types
 *   (L3 must not call new Ajv directly; avoids inverting the L0 ↔ L3 dependency layers)
 *
 * No brand cast: this file only performs schema validation; it does no as-casts;
 *           brand type conversions are handled by the factory functions in brands.ts + types.ts.
 */

import AjvModule from 'ajv';
import addFormatsModule from 'ajv-formats';
import {
    IDEMPOTENCY_RECORD_SCHEMA,
    RETRY_ATTEMPT_SCHEMA,
    SETTLEMENT_OPERATION_SCHEMA,
} from './schemas.js';

// ESM/CJS dual-module fallback loading for ajv and ajv-formats (one branch is always covered; determined by the runtime environment)
/* v8 ignore next 2*/
const Ajv =
    (AjvModule as unknown as { default: typeof AjvModule }).default ??
    AjvModule;
/* v8 ignore next 3*/
const addFormats =
    (addFormatsModule as unknown as { default: typeof addFormatsModule })
        .default ?? addFormatsModule;

// ─── Validation result types ────────────────────────────────────────────────────────────────

/**
 * SrValidationResult — SR JSON Schema validation result
 *
 * Deterministic binary state: PASS (valid:true) or REJECT (valid:false + errors)
 * There is no RUNTIME_DEPENDENT third state (fail-closed; consistent with the atp pattern)
 */
export type SrValidationResult =
    | { readonly valid: true }
    | { readonly valid: false; readonly errors: SrValidationError[] };

/**
 * SrValidationError — a single validation error
 */
export interface SrValidationError {
    /** JSON Pointer error path*/
    readonly instancePath: string;
    /** error message*/
    readonly message: string;
    /** AJV keyword*/
    readonly keyword: string;
}

// ─── AJV independent instance (Layer 3 of defense; strict:true; independent sr instance) ─────────────────────

type AjvLike = {
    addSchema(schema: object): void;
    getSchema(ref: string):
        | (((data: unknown) => boolean) & {
              errors?:
                  | {
                        instancePath: string;
                        message?: string;
                        keyword: string;
                    }[]
                  | null;
          })
        | undefined;
};

// eslint-disable-next-line @typescript-eslint/no-unnecessary-type-assertion
const ajv: AjvLike = new (Ajv as unknown as new (
    opts: Record<string, unknown>,
) => AjvLike)({
    // Core configuration for Layer 3 of defense (consistent with the csp/atp pattern)
    strict: true,
    strictSchema: true,
    strictNumbers: true,
    strictTypes: true,
    // fail-closed: reject on the first invariant violation (do not accumulate errors; allErrors:false)
    allErrors: false,
    // format "uuid" validation mandatory
    validateFormats: true,
}) as AjvLike;

// ajv-formats mandatory (registers format "uuid")
(addFormats as unknown as (a: AjvLike) => void)(ajv);

// Register the 3 SR schemas
ajv.addSchema(SETTLEMENT_OPERATION_SCHEMA as unknown as object);
ajv.addSchema(RETRY_ATTEMPT_SCHEMA as unknown as object);
ajv.addSchema(IDEMPOTENCY_RECORD_SCHEMA as unknown as object);

// ─── Internal helper functions ─────────────────────────────────────────────────────────────

/**
 * runValidation — internal schema validation helper (extracts common logic)
 */
function runValidation(schemaId: string, data: unknown): SrValidationResult {
    const validator = ajv.getSchema(schemaId);

    // The schema is registered at module init; the validator can never be undefined; fail-closed guard
    /* v8 ignore next 11*/
    if (!validator) {
        return {
            valid: false,
            errors: [
                {
                    instancePath: '/',
                    message: `SR_SCHEMA_VIOLATION: schema not registered: ${schemaId}`,
                    keyword: 'schema',
                },
            ],
        };
    }

    const valid = validator(data);

    if (!valid) {
        const errors: SrValidationError[] = (validator.errors ?? []).map(
            (e) => ({
                instancePath: e.instancePath || '/',
                message: e.message ?? 'SR_SCHEMA_VIOLATION: validation failed',
                keyword: e.keyword,
            }),
        );
        return { valid: false, errors };
    }

    return { valid: true };
}

// ─── validateSettlementOperation — public entry point ─────────────────────────────────

/**
 * validateSettlementOperation — SettlementOperation JSON Schema validation (Layer 2+3 defense linkage)
 *
 * Runs AJV strict mode validation over the passed-in unknown data.
 * Validation failure → SrValidationResult.valid:false + errors.
 * Validation success → SrValidationResult.valid:true.
 *
 * fail-closed principles:
 *   - schema validator undefined → valid:false (impossible path; already registered)
 *   - validator(data) false → valid:false + mapped AJV errors
 *
 * Call sites:
 *   - L3 executeSettlementRetry step 3 (input validation; schema layer guard)
 *   - before writing settlement_operations (DB layer pre-guard)
 *
 * @param data data to validate (unknown)
 * @returns SrValidationResult (deterministic binary state)
 */
export function validateSettlementOperation(data: unknown): SrValidationResult {
    return runValidation(SETTLEMENT_OPERATION_SCHEMA.$id, data);
}

// ─── validateRetryAttempt — public entry point ────────────────────────────────────────

/**
 * validateRetryAttempt — RetryAttempt JSON Schema validation (Layer 2+3 defense linkage)
 *
 * Runs AJV strict mode validation over the passed-in unknown data.
 *
 * Call sites:
 *   - L3 executeSettlementRetry step 8 (before writing settlement_retries)
 *
 * @param data data to validate (unknown)
 * @returns SrValidationResult (deterministic binary state)
 */
export function validateRetryAttempt(data: unknown): SrValidationResult {
    return runValidation(RETRY_ATTEMPT_SCHEMA.$id, data);
}

// ─── validateIdempotencyRecord — public entry point ────────────────────────────────────

/**
 * validateIdempotencyRecord — IdempotencyRecord JSON Schema validation (Layer 2+3 defense linkage)
 *
 * Runs AJV strict mode validation over the passed-in unknown data.
 *
 * Call sites:
 *   - L3 executeSettlementRetry step 2 (before writing the idempotency record)
 *
 * @param data data to validate (unknown)
 * @returns SrValidationResult (deterministic binary state)
 */
export function validateIdempotencyRecord(data: unknown): SrValidationResult {
    return runValidation(IDEMPOTENCY_RECORD_SCHEMA.$id, data);
}
