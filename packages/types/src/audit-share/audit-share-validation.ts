/**
 * audit-share v0.2 AJV strict mode validator (defense layer 3)
 *
 * Layer 3 of the triple defense:
 *   AJV strict mode 4 flags:
 *     strict: true — global strict mode guard
 *     strictSchema: true — strict schema structure validation
 *     strictNumbers: true — strict numeric typing
 *     strictTypes: true — strict typing
 *   validateFormats: true — format "uuid" / "date-time" validation is mandatory
 *   addFormats(ajv) — ajv-formats is mandatory
 *
 * Standalone instance design:
 *   This file creates a standalone AJV instance; it does not reuse the global instance from validation.ts
 *   (the global instance is strict:false; the audit-share layer 3 defense requires strict:true).
 *
 * fail-closed: allErrors:false ensures the first format invariant violation is rejected immediately (no error accumulation)
 *
 * This file only performs schema validation; it does not perform as-cast;
 *   brand type conversion is the responsibility of the factory functions in types.ts.
 *
 * defense-in-depth:
 *   The L3 AuditShareManager 11-step entry must call validateAuditShareRequestSchema();
 *   fail-closed throw AUDIT_SHARE_SCHEMA_INVALID;
 *   L3 does not rely on a caller-side schema guard — defense-in-depth is mandatory.
 */

import AjvModule from 'ajv';
import addFormatsModule from 'ajv-formats';
import auditShareSchema from '../schemas/audit-share-v0.2.schema.json' with { type: 'json' };

// ESM/CJS dual-module fallback loading for ajv and ajv-formats
/* v8 ignore next 2*/
const Ajv =
    (AjvModule as unknown as { default: typeof AjvModule }).default ??
    AjvModule;
/* v8 ignore next 3*/
const addFormats =
    (addFormatsModule as unknown as { default: typeof addFormatsModule })
        .default ?? addFormatsModule;

/**
 * AuditShareValidationResult — schema validation result
 *
 * Deterministic two-state: PASS (valid:true) or REJECT (valid:false + errors)
 * There is no runtime-dependent third state.
 */
export type AuditShareValidationResult =
    | { readonly valid: true }
    | { readonly valid: false; readonly errors: AuditShareValidationError[] };

/**
 * AuditShareValidationError — a single validation error
 */
export interface AuditShareValidationError {
    /** JSON Pointer error path*/
    readonly instancePath: string;
    /** error message*/
    readonly message: string;
    /** AJV keyword*/
    readonly keyword: string;
}

// ─── AJV standalone instance (defense layer 3; strict:true; independent of the validation.ts global instance) ─

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

const ajv: AjvLike = new (Ajv as unknown as new (
    opts: Record<string, unknown>,
) => AjvLike)({
    strict: true,
    strictSchema: true,
    strictNumbers: true,
    strictTypes: true,
    allErrors: false,
    validateFormats: true,
});

(addFormats as unknown as (a: AjvLike) => void)(ajv);

// register the audit-share schema
ajv.addSchema(auditShareSchema as object);

const AUDIT_SHARE_SCHEMA_REF = `${auditShareSchema.$id}`;

// ─── validateAuditShareRequestSchema public entry ──────────────────────────────

/**
 * validateAuditShareRequestSchema — audit-share request JSON Schema validation (layers 2+3 of the defense, working together)
 *
 * Runs AJV strict mode validation against the incoming unknown data.
 * Validation failure → AuditShareValidationResult.valid:false + errors.
 * Validation success → AuditShareValidationResult.valid:true.
 *
 * fail-closed principle:
 *   - schema validator undefined → valid:false (impossible path; already registered)
 *   - validator(data) false → valid:false + AJV errors mapping
 *
 * Call site:
 *   L3 AuditShareManager.verifyAuditRequest step 1
 *   fail-closed throw new AuditShareError('AUDIT_SHARE_SCHEMA_INVALID', ...)
 *
 * @param data data to validate (unknown)
 * @returns AuditShareValidationResult (deterministic two-state)
 */
export function validateAuditShareRequestSchema(
    data: unknown,
): AuditShareValidationResult {
    const validator = ajv.getSchema(AUDIT_SHARE_SCHEMA_REF);

    // the schema is registered at module init time; validator can never be undefined; fail-closed guard
    /* v8 ignore next 12*/
    if (!validator) {
        return {
            valid: false,
            errors: [
                {
                    instancePath: '/',
                    message: `AUDIT_SHARE_SCHEMA_INVALID: schema not registered: ${AUDIT_SHARE_SCHEMA_REF}`,
                    keyword: 'schema',
                },
            ],
        };
    }

    const valid = validator(data);

    if (!valid) {
        const errors: AuditShareValidationError[] = (
            validator.errors ?? []
        ).map((e) => ({
            instancePath: e.instancePath || '/',
            message:
                e.message ?? 'AUDIT_SHARE_SCHEMA_INVALID: validation failed',
            keyword: e.keyword,
        }));
        return { valid: false, errors };
    }

    return { valid: true };
}
