/**
 * HCC v0.2 AJV strict-mode validator (third line of defense; reuses the csp pattern).
 *
 * hcc v0.2 — hash-chain-canonicalize schema breaking change
 *
 * Third line of the triple defense:
 *   AJV strict mode, 5 flags:
 *     strict: true — global strict-mode guard; unknown keywords raise errors
 *     validateFormats: true — enable validation of the "uuid" / "date-time" formats
 *     strictSchema: true — strict validation of schema structure
 *     strictNumbers: true — NaN / Infinity raise errors
 *     strictTypes: true — type mismatches raise errors
 *
 * Dedicated-instance design (same as csp):
 *   This file creates a dedicated AJV instance; it does not reuse the global instance in validation.ts
 *   (the global instance is strict:false; HCC's third line of defense requires strict:true; the two semantics are incompatible)
 *
 * fail-closed guard:
 *   allErrors:false ensures the first schema-invariant violation rejects immediately (errors are not accumulated)
 *
 * "no brand cast" guard: this file only performs schema validation; it does no as-casts;
 *           brand type conversion is the responsibility of the factory functions in types.ts.
 */

// JSON Schema draft 2020-12 — hccSchema $schema "https://json-schema.org/draft/2020-12"
// Must import Ajv2020 (ajv/dist/2020.js) — the default Ajv (draft-07 baseline) does not register the draft 2020-12 meta-schema → module load throws "no schema with key or ref"
// Otherwise the vitest run for the entire packages/crypto test suite FAILS (affecting every test file that references the @coivitas/types barrel)
import AjvModule from 'ajv/dist/2020.js';
import addFormatsModule from 'ajv-formats';
import hccSchema from '../schemas/hash-chain-entry-v0.2.schema.json' with { type: 'json' };

// ESM/CJS dual-module fallback loading for ajv and ajv-formats (same pattern as csp-validation)
/* v8 ignore next 2*/
// eslint-disable-next-line @typescript-eslint/no-unsafe-assignment -- ajv ESM/CJS bridging (same pattern across csp + atp + hcc)
const Ajv =
    (AjvModule as unknown as { default: typeof AjvModule }).default ??
    AjvModule;
/* v8 ignore next 3*/
// eslint-disable-next-line @typescript-eslint/no-unsafe-assignment -- ajv-formats ESM/CJS bridging (same pattern across csp + atp + hcc)
const addFormats =
    (addFormatsModule as unknown as { default: typeof addFormatsModule })
        .default ?? addFormatsModule;

/**
 * HccValidationResult — result of HCC JSON Schema validation.
 *
 * Deterministic two-state: PASS (valid:true) or REJECT (valid:false + errors).
 * There is no RUNTIME_DEPENDENT third state (reuses the csp pattern).
 */
export type HccValidationResult =
    | { readonly valid: true }
    | { readonly valid: false; readonly errors: HccValidationError[] };

/**
 * HccValidationError — a single validation error.
 */
export interface HccValidationError {
    /** JSON Pointer error path*/
    readonly instancePath: string;
    /** error message*/
    readonly message: string;
    /** AJV keyword*/
    readonly keyword: string;
}

// ─── Dedicated AJV instance (third line of defense; strict:true; independent of the global instance in validation.ts) ─────

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

// eslint-disable-next-line @typescript-eslint/no-unnecessary-type-assertion -- ajv ESM/CJS bridging cast (same pattern across csp + atp)
const ajv: AjvLike = new (Ajv as unknown as new (
    opts: Record<string, unknown>,
) => AjvLike)({
    // core config of the third line of defense (all 5 flags enabled)
    strict: true,
    strictSchema: true,
    strictNumbers: true,
    strictTypes: true,
    // fail-closed: the first invariant violation rejects immediately (errors are not accumulated)
    allErrors: false,
    // validation of the "uuid" / "date-time" formats must be enabled
    validateFormats: true,
    // the draft/2020-12 meta-schema is not in the standard ajv@8 instance — skip meta-validation of the schema itself
    // (data validation logic is unaffected; this only affects the schema's structural self-check; the hcc v0.2 schema has passed spec review)
    validateSchema: false,
}) as AjvLike;

// ajv-formats must be enabled (registers the "uuid" / "date-time" formats)
(addFormats as unknown as (a: AjvLike) => void)(ajv);

// register the HCC schema
ajv.addSchema(hccSchema as object);

const HCC_SCHEMA_REF = `${hccSchema.$id}`;

// ─── validateHashChainEntrySchema public entry point ──────────────────────────────────

/**
 * validateHashChainEntrySchema — HCC JSON Schema validation (linking the 2nd and 3rd lines of defense).
 *
 * Runs AJV strict-mode validation against the passed-in unknown data.
 * Validation failure → HccValidationResult.valid:false + errors.
 * Validation pass → HccValidationResult.valid:true.
 *
 * fail-closed principle:
 *   - schema validator undefined → valid:false (impossible path; already registered)
 *   - validator(data) false → valid:false + mapping of AJV errors
 *
 * Call site: the verifyHashChain pipeline (L1 hash-chain-canonicalize.ts step 1).
 *
 * @param data the data to validate (unknown)
 * @returns HccValidationResult (deterministic two-state)
 */
export function validateHashChainEntrySchema(
    data: unknown,
): HccValidationResult {
    const validator = ajv.getSchema(HCC_SCHEMA_REF);

    // the schema is registered at module initialization; validator can never be undefined; fail-closed guard
    /* v8 ignore next 12*/
    if (!validator) {
        return {
            valid: false,
            errors: [
                {
                    instancePath: '/',
                    message: `HC_SCHEMA_VIOLATION: schema not registered: ${HCC_SCHEMA_REF}`,
                    keyword: 'schema',
                },
            ],
        };
    }

    const valid = validator(data);

    if (!valid) {
        const errors: HccValidationError[] = (validator.errors ?? []).map(
            (e) => ({
                instancePath: e.instancePath || '/',
                message: e.message ?? 'HC_SCHEMA_VIOLATION: validation failed',
                keyword: e.keyword,
            }),
        );
        return { valid: false, errors };
    }

    return { valid: true };
}
