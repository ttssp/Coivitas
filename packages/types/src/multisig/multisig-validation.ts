/**
 * Multisig v0.1 AJV strict mode validator (defense layer 3)
 *
 * Priority 6 sub-protocol — multisig (ms)
 *
 * Defense layer 3 of the triple defense:
 *   The 4 AJV strict mode flags:
 *     strict: true — global strict mode guard
 *     strictSchema: true — strict schema structure validation
 *     strictNumbers: true — strict numeric typing
 *     strictTypes: true — strict typing
 *   validateFormats: true — format "uuid" / "date-time" / "uri" validation is mandatory
 *   addFormats(ajv) — ajv-formats is mandatory
 *
 * Standalone instance design (reuses the csp-validation.ts pattern):
 *   This file creates a standalone AJV instance and also registers the csp v0.1 schema
 *   (for $ref resolution); it does not reuse the global instance from validation.ts
 *   (the global instance is strict:false; the ms layer-3 defense requires strict:true).
 *
 * fail-closed: allErrors:false ensures the first format invariant violation triggers a reject
 * (errors are not accumulated).
 *
 * No brand cast: this file only performs schema validation, never an as-cast;
 *           brand type conversion is the responsibility of the factory functions in types.ts.
 */

import AjvModule from 'ajv';
import addFormatsModule from 'ajv-formats';

import cspSchema from '../schemas/canonical-signed-payload.schema.json' with { type: 'json' };
import multisigTokenSchema from '../schemas/multisig-token-v0.1.schema.json' with { type: 'json' };

// ESM/CJS dual-module fallback loading for ajv and ajv-formats (exactly one branch applies; determined by the runtime environment)
/* v8 ignore next 2*/
const Ajv = (AjvModule as unknown as { default: typeof AjvModule }).default ?? AjvModule;
/* v8 ignore next 3*/
const addFormats =
    (addFormatsModule as unknown as { default: typeof addFormatsModule }).default ??
    addFormatsModule;

/**
 * MultisigValidationResult — Multisig JSON Schema validation result
 *
 * Deterministic binary state: PASS (valid:true) or REJECT (valid:false + errors).
 * There is no RUNTIME_DEPENDENT third state.
 */
export type MultisigValidationResult =
    | { readonly valid: true }
    | { readonly valid: false; readonly errors: MultisigValidationError[] };

/**
 * MultisigValidationError — a single validation error
 */
export interface MultisigValidationError {
    /** JSON Pointer error path*/
    readonly instancePath: string;
    /** Error message*/
    readonly message: string;
    /** AJV keyword*/
    readonly keyword: string;
}

// ─── Standalone AJV instance (layer-3 defense; strict:true; independent of the validation.ts global instance) ─────

type AjvLike = {
    addSchema(schema: object): void;
    getSchema(
        ref: string,
    ):
        | (((data: unknown) => boolean) & {
              errors?:
                  | { instancePath: string; message?: string; keyword: string }[]
                  | null;
          })
        | undefined;
};

const ajv: AjvLike = new (Ajv as unknown as new (
    opts: Record<string, unknown>,
) => AjvLike)({
    strict: true,
    strictSchema: true,
    strictNumbers: true,
    strictTypes: true,
    allErrors: false,
    validateFormats: true,
}) as AjvLike;

// ajv-formats is mandatory (format "uuid" / "date-time" / "uri")
(addFormats as unknown as (a: AjvLike) => void)(ajv);

// Register the csp v0.1 schema (the multisig schema $ref depends on it)
ajv.addSchema(cspSchema as object);

// Register the multisig v0.1 schema
ajv.addSchema(multisigTokenSchema as object);

const MULTISIG_TOKEN_SCHEMA_REF = `${multisigTokenSchema.$id}`;

// ─── validateMultisigToken public entry point ─────────────────────────────────────────

/**
 * validateMultisigToken — Multisig JSON Schema validation (layer 2+3 defense, working together)
 *
 * Runs AJV strict mode validation against the incoming unknown data.
 * Validation fails → MultisigValidationResult.valid:false + errors.
 * Validation passes → MultisigValidationResult.valid:true.
 *
 * fail-closed principle:
 *   - schema validator undefined → valid:false (impossible path; it is already registered)
 *   - validator(data) false → valid:false + mapped AJV errors
 *
 * Call sites:
 *   - L1 crypto verifyMultisigProof step 0 (the caller performs a fail-closed schema check directly at the L1 entry)
 *   - L2 identity multisig-token-verifier pipeline step 7.1
 *
 * @param data data to validate (unknown)
 * @returns MultisigValidationResult (deterministic binary state)
 */
export function validateMultisigToken(data: unknown): MultisigValidationResult {
    const validator = ajv.getSchema(MULTISIG_TOKEN_SCHEMA_REF);

    // the schema is registered at module init; validator cannot be undefined; fail-closed guard
    /* v8 ignore next 12*/
    if (!validator) {
        return {
            valid: false,
            errors: [
                {
                    instancePath: '/',
                    message: `MULTISIG_SCHEMA_VIOLATION: schema not registered: ${MULTISIG_TOKEN_SCHEMA_REF}`,
                    keyword: 'schema',
                },
            ],
        };
    }

    const valid = validator(data);

    if (!valid) {
        const errors: MultisigValidationError[] = (validator.errors ?? []).map(
            (e) => ({
                instancePath: e.instancePath || '/',
                message: e.message ?? 'MULTISIG_SCHEMA_VIOLATION: validation failed',
                keyword: e.keyword,
            }),
        );
        return { valid: false, errors };
    }

    return { valid: true };
}
