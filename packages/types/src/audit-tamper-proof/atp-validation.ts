/**
 * atp v0.1 AJV strict mode validator (defense layer 3)
 *
 * sub-protocol — audit-tamper-proof
 *
 * Layer 3 of the triple defense:
 *   AJV strict mode 4 flags (reuses the csp pattern):
 *     strict: true — global strict mode guard
 *     strictSchema: true — strict schema structure validation
 *     strictNumbers: true — strict numeric typing
 *     strictTypes: true — strict typing
 *   validateFormats: true — format "uuid" / "date-time" validation is mandatory
 *   addFormats(ajv) — ajv-formats is mandatory
 *
 * Standalone instance design:
 *   This file creates a standalone AJV instance; it does not reuse the validation.ts global instance / csp-validation.ts atp instance
 *   (the global instance is strict:false; atp and csp each maintain their own standalone strict instance).
 *
 * fail-closed: allErrors:false ensures the first format invariant violation is rejected immediately (no error accumulation)
 *
 * Guard: this file only performs schema validation; it does not perform brand as-cast;
 *       brand type conversion is the responsibility of the factory functions in types.ts.
 */

import AjvModule from 'ajv';
import addFormatsModule from 'ajv-formats';
import atpSchema from '../schemas/audit-event-v0.1.schema.json' with { type: 'json' };

// ESM/CJS dual-module fallback loading for ajv and ajv-formats (one branch is always covered; determined by the runtime environment)
/* v8 ignore next 2*/
const Ajv = (AjvModule as unknown as { default: typeof AjvModule }).default ?? AjvModule;
/* v8 ignore next 3*/
const addFormats =
    (addFormatsModule as unknown as { default: typeof addFormatsModule }).default ??
    addFormatsModule;

/**
 * AtpValidationResult — atp JSON Schema validation result
 *
 * Deterministic two-state: PASS (valid:true) or REJECT (valid:false + errors)
 * There is no RUNTIME_DEPENDENT third state (fail-closed)
 */
export type AtpValidationResult =
    | { readonly valid: true }
    | { readonly valid: false; readonly errors: AtpValidationError[] };

/**
 * AtpValidationError — a single validation error
 */
export interface AtpValidationError {
    /** JSON Pointer error path*/
    readonly instancePath: string;
    /** error message*/
    readonly message: string;
    /** AJV keyword*/
    readonly keyword: string;
}

// ─── AJV standalone instance (defense layer 3; strict:true; standalone atp instance) ─────────────────────

type AjvLike = {
    addSchema(schema: object): void;
    getSchema(
        ref: string,
    ): ((data: unknown) => boolean) & { errors?: { instancePath: string; message?: string; keyword: string }[] | null } | undefined;
};

const ajv: AjvLike = new (Ajv as unknown as new (opts: Record<string, unknown>) => AjvLike)({
    // defense layer 3 core configuration (consistent with the csp pattern)
    strict: true,
    strictSchema: true,
    strictNumbers: true,
    strictTypes: true,
    // fail-closed: reject on the first invariant violation (no error accumulation; allErrors:false)
    allErrors: false,
    // format "uuid" / "date-time" validation is mandatory
    validateFormats: true,
}) as AjvLike;

// ajv-formats is mandatory (registers formats "uuid" / "date-time")
(addFormats as unknown as (a: AjvLike) => void)(ajv);

// register the atp schema
ajv.addSchema(atpSchema as object);

const ATP_SCHEMA_REF = `${atpSchema.$id}`;

// ─── validateAuditEvent public entry ─────────────────────────────────────────────

/**
 * validateAuditEvent — atp AuditEvent JSON Schema validation (layers 2+3 of the defense, working together)
 *
 * Runs AJV strict mode validation against the incoming unknown data.
 * Validation failure → AtpValidationResult.valid:false + errors (maps to AUDIT_SCHEMA_VIOLATION).
 * Validation success → AtpValidationResult.valid:true.
 *
 * fail-closed principle:
 *   - schema validator undefined → valid:false (impossible path; already registered)
 *   - validator(data) false → valid:false + AJV errors mapping
 *
 * Call sites:
 *   - the writer side validates right after constructing an AuditEvent candidate;
 *   - the verifier side runs JSON Schema validate.
 *
 * @param data data to validate (unknown)
 * @returns AtpValidationResult (deterministic two-state)
 */
export function validateAuditEvent(data: unknown): AtpValidationResult {
    const validator = ajv.getSchema(ATP_SCHEMA_REF);

    // the schema is registered at module init time; validator can never be undefined; fail-closed guard
    /* v8 ignore next 12*/
    if (!validator) {
        return {
            valid: false,
            errors: [
                {
                    instancePath: '/',
                    message: `AUDIT_SCHEMA_VIOLATION: schema not registered: ${ATP_SCHEMA_REF}`,
                    keyword: 'schema',
                },
            ],
        };
    }

    const valid = validator(data);

    if (!valid) {
        const errors: AtpValidationError[] = (validator.errors ?? []).map((e) => ({
            instancePath: e.instancePath || '/',
            message: e.message ?? 'AUDIT_SCHEMA_VIOLATION: validation failed',
            keyword: e.keyword,
        }));
        return { valid: false, errors };
    }

    return { valid: true };
}
