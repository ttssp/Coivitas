/**
 * CSP v0.1 AJV strict mode validator (3rd defense layer)
 *
 * sub-protocol — canonical signed payload
 *
 * Triple defense, layer 3:
 *   AJV strict mode, 4 flags:
 *     strict: true — global strict-mode guard
 *     strictSchema: true — strict schema-structure validation
 *     strictNumbers: true — strict numeric types
 *     strictTypes: true — strict types
 *   validateFormats: true — format "uuid" / "date-time" / "uri" validation required
 *   addFormats(ajv) — ajv-formats required
 *
 * Standalone-instance design:
 *   This file creates a standalone AJV instance; it does not reuse the global
 *   instance in validation.ts (the global instance is strict:false; the CSP layer-3
 *   defense requires strict:true; the two are semantically incompatible).
 *
 * fail-closed: allErrors:false ensures the first format-invariant violation rejects (no error accumulation).
 *
 * Guard: this file only runs schema validate; it does not do brand as-casts;
 *        brand-type conversion is the responsibility of the factory functions in types.ts.
 */

import AjvModule from 'ajv';
import addFormatsModule from 'ajv-formats';
import cspSchema from '../schemas/canonical-signed-payload.schema.json' with { type: 'json' };

// ESM/CJS dual-module fallback loading for ajv and ajv-formats (one branch is always taken; decided by the runtime environment)
/* v8 ignore next 2*/
const Ajv = (AjvModule as unknown as { default: typeof AjvModule }).default ?? AjvModule;
/* v8 ignore next 3*/
const addFormats =
    (addFormatsModule as unknown as { default: typeof addFormatsModule }).default ??
    addFormatsModule;

/**
 * CspValidationResult — CSP JSON Schema validation result
 *
 * Deterministic binary state: PASS (valid:true) or REJECT (valid:false + errors).
 * No RUNTIME_DEPENDENT tri-state (fail-closed).
 */
export type CspValidationResult =
    | { readonly valid: true }
    | { readonly valid: false; readonly errors: CspValidationError[] };

/**
 * CspValidationError — a single validation error
 */
export interface CspValidationError {
    /** JSON Pointer error path*/
    readonly instancePath: string;
    /** error message*/
    readonly message: string;
    /** AJV keyword*/
    readonly keyword: string;
}

// ─── Standalone AJV instance (layer-3 defense; strict:true; independent of the validation.ts global instance) ─────

type AjvLike = {
    addSchema(schema: object): void;
    getSchema(
        ref: string,
    ): ((data: unknown) => boolean) & { errors?: { instancePath: string; message?: string; keyword: string }[] | null } | undefined;
};

const ajv: AjvLike = new (Ajv as unknown as new (opts: Record<string, unknown>) => AjvLike)({
    // Core config for the layer-3 defense
    strict: true,
    strictSchema: true,
    strictNumbers: true,
    strictTypes: true,
    // fail-closed: the first invariant violation rejects (no error accumulation)
    allErrors: false,
    // format "uuid" / "date-time" / "uri" validation required
    validateFormats: true,
}) as AjvLike;

// ajv-formats required (registers format "uuid" / "date-time" / "uri")
(addFormats as unknown as (a: AjvLike) => void)(ajv);

// Register the CSP schema
ajv.addSchema(cspSchema as object);

const CSP_SCHEMA_REF = `${cspSchema.$id}`;

// ─── validateCspPayload public entry point ─────────────────────────────────────────────

/**
 * validateCspPayload — CSP JSON Schema validation (layer-2 + layer-3 defense in concert)
 *
 * Runs AJV strict-mode validation on the supplied unknown data.
 * Validation fails → CspValidationResult.valid:false + errors.
 * Validation passes → CspValidationResult.valid:true.
 *
 * fail-closed principle:
 *   - schema validator undefined → valid:false (impossible path; already registered)
 *   - validator(data) false → valid:false + mapped AJV errors
 *
 * Use case: the JSON Schema validation step of the verifier-side verify pipeline.
 *
 * @param data data to validate (unknown)
 * @returns CspValidationResult (deterministic binary state)
 */
export function validateCspPayload(data: unknown): CspValidationResult {
    const validator = ajv.getSchema(CSP_SCHEMA_REF);

    // The schema is registered at module init; the validator cannot be undefined; fail-closed guard
    /* v8 ignore next 12*/
    if (!validator) {
        return {
            valid: false,
            errors: [
                {
                    instancePath: '/',
                    message: `CSP_SCHEMA_VIOLATION: schema not registered: ${CSP_SCHEMA_REF}`,
                    keyword: 'schema',
                },
            ],
        };
    }

    const valid = validator(data);

    if (!valid) {
        const errors: CspValidationError[] = (validator.errors ?? []).map((e) => ({
            instancePath: e.instancePath || '/',
            message: e.message ?? 'CSP_SCHEMA_VIOLATION: validation failed',
            keyword: e.keyword,
        }));
        return { valid: false, errors };
    }

    return { valid: true };
}
