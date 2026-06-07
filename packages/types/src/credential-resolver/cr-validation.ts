/**
 * CR v0.1 AJV strict mode validator (3rd defense layer)
 *
 * credential-resolver sub-protocol
 *
 * Triple defense, layer 3 (csp / multisig / hcc / atp pattern reuse):
 *   AJV strict mode, 4 flags (consistent with csp v0.1 / RFP v0.1 / CCR v0.1):
 *     strict: true — global strict-mode guard; unknown keywords error out
 *     strictSchema: true — strict schema-structure validation
 *     strictNumbers: true — NaN / Infinity error out
 *     strictTypes: true — type mismatches error out
 *   validateFormats: true — format "uuid" / "date-time" / "uri" / "email" validation required
 *   addFormats(ajv) — ajv-formats required
 *
 * Standalone-instance design (same as csp / hcc / multisig):
 *   This file creates a standalone AJV instance; it does not reuse the validation.ts global instance
 *   (the global instance is strict:false; the CR layer-3 defense requires strict:true; the two are semantically incompatible).
 *
 * fail-closed guard:
 *   allErrors:false ensures the first schema-invariant violation rejects (no error accumulation).
 *
 * No-brand-cast guard: this file only runs schema validate; it does not do as-casts;
 *           brand-type conversion is the responsibility of the factory functions in factories.ts.
 */

import AjvModule from 'ajv';
import addFormatsModule from 'ajv-formats';
import crSchema from '../schemas/credential-resolver-v0.1.schema.json' with { type: 'json' };

// ESM/CJS dual-module fallback loading for ajv and ajv-formats (same pattern as csp / hcc / multisig)
/* v8 ignore next 2*/
const Ajv =
    (AjvModule as unknown as { default: typeof AjvModule }).default ??
    AjvModule;
/* v8 ignore next 3*/
const addFormats =
    (addFormatsModule as unknown as { default: typeof addFormatsModule })
        .default ?? addFormatsModule;

/**
 * CrValidationResult — CR JSON Schema validation result
 *
 * Deterministic binary state: PASS (valid:true) or REJECT (valid:false + errors).
 * No RUNTIME_DEPENDENT tri-state (csp / hcc / multisig pattern reuse).
 */
export type CrValidationResult =
    | { readonly valid: true }
    | { readonly valid: false; readonly errors: CrValidationError[] };

/**
 * CrValidationError — a single validation error
 */
export interface CrValidationError {
    /** JSON Pointer error path*/
    readonly instancePath: string;
    /** error message*/
    readonly message: string;
    /** AJV keyword*/
    readonly keyword: string;
}

/**
 * CrSchemaName — the schema entry points supported for validation (consistent with the schema's $defs)
 *
 * 7 standalone schemas:
 *   OidcRawClaims / SamlRawClaims / NormalizedOidcClaims / NormalizedSamlClaims /
 *   FederationIdentityLink / ResolvedCredentialIntegrityProof / ResolvedCredential
 */
export type CrSchemaName =
    | 'OidcRawClaims'
    | 'SamlRawClaims'
    | 'NormalizedOidcClaims'
    | 'NormalizedSamlClaims'
    | 'FederationIdentityLink'
    | 'ResolvedCredentialIntegrityProof'
    | 'ResolvedCredential';

// ─── Standalone AJV instance (layer-3 defense; strict:true; independent of the validation.ts global instance) ─────

type AjvLike = {
    addSchema(schema: object): void;
    compile(schema: object): ((data: unknown) => boolean) & {
        errors?:
            | { instancePath: string; message?: string; keyword: string }[]
            | null;
    };
};

// eslint-disable-next-line @typescript-eslint/no-unnecessary-type-assertion -- ajv ESM/CJS bridging cast (same pattern as csp + atp + hcc + ms)
const ajv: AjvLike = new (Ajv as unknown as new (
    opts: Record<string, unknown>,
) => AjvLike)({
    // Core config for the layer-3 defense (pattern consistent with csp + hcc + ms + RFP + CCR)
    strict: true,
    strictSchema: true,
    strictNumbers: true,
    strictTypes: true,
    // fail-closed: the first invariant violation rejects (no error accumulation)
    allErrors: false,
    // format "uuid" / "date-time" / "uri" / "email" validation required
    validateFormats: true,
}) as AjvLike;

// ajv-formats required (registers format "uuid" / "date-time" / "uri" / "email")
(addFormats as unknown as (a: AjvLike) => void)(ajv);

// Register the CR root schema (contains 7 $defs sub-schemas)
ajv.addSchema(crSchema as object);

/**
 * Precompile the 7 $defs sub-schema validators (compiled once at startup; reused at runtime)
 *
 * Each entry: schema name → validator function (with errors cache)
 */
const SCHEMA_VALIDATORS: Record<
    CrSchemaName,
    | (((data: unknown) => boolean) & {
          errors?:
              | { instancePath: string; message?: string; keyword: string }[]
              | null;
      })
    | undefined
> = {
    OidcRawClaims: ajv.compile({
        $ref: 'https://coivitas.ai/schemas/credential-resolver-v0.1.json#/$defs/OidcRawClaims',
    }),
    SamlRawClaims: ajv.compile({
        $ref: 'https://coivitas.ai/schemas/credential-resolver-v0.1.json#/$defs/SamlRawClaims',
    }),
    NormalizedOidcClaims: ajv.compile({
        $ref: 'https://coivitas.ai/schemas/credential-resolver-v0.1.json#/$defs/NormalizedOidcClaims',
    }),
    NormalizedSamlClaims: ajv.compile({
        $ref: 'https://coivitas.ai/schemas/credential-resolver-v0.1.json#/$defs/NormalizedSamlClaims',
    }),
    FederationIdentityLink: ajv.compile({
        $ref: 'https://coivitas.ai/schemas/credential-resolver-v0.1.json#/$defs/FederationIdentityLink',
    }),
    ResolvedCredentialIntegrityProof: ajv.compile({
        $ref: 'https://coivitas.ai/schemas/credential-resolver-v0.1.json#/$defs/ResolvedCredentialIntegrityProof',
    }),
    ResolvedCredential: ajv.compile({
        $ref: 'https://coivitas.ai/schemas/credential-resolver-v0.1.json#/$defs/ResolvedCredential',
    }),
};

// ─── validateCr public entry point ─────────────────────────────────────────────────────

/**
 * validateCr — CR JSON Schema validation (layer-2 + layer-3 defense in concert)
 *
 * Runs AJV strict-mode validation on the supplied unknown data.
 * Validation fails → CrValidationResult.valid:false + errors.
 * Validation passes → CrValidationResult.valid:true.
 *
 * fail-closed principle:
 *   - schema validator undefined → valid:false (impossible path; already registered)
 *   - validator(data) false → valid:false + mapped AJV errors
 *
 * Use cases:
 *   - factories.ts toOidcRawClaims / toSamlRawClaims / toNormalizedOidcClaims / toNormalizedSamlClaims
 *   - L2 identity layer credential-resolver.ts step 1 (schema validate again after brand narrow;
 *     defense-in-depth pattern)
 *
 * @param schemaName the schema name to validate against (one of the 7 $defs entry points)
 * @param data data to validate (unknown)
 * @returns CrValidationResult (deterministic binary state)
 */
export function validateCr(
    schemaName: CrSchemaName,
    data: unknown,
): CrValidationResult {
    const validator = SCHEMA_VALIDATORS[schemaName];

    // The schema is registered at module init; the validator cannot be undefined; fail-closed guard
    /* v8 ignore next 12*/
    if (!validator) {
        return {
            valid: false,
            errors: [
                {
                    instancePath: '/',
                    message: `CR_SCHEMA_INVALID: schema not registered: ${schemaName}`,
                    keyword: 'schema',
                },
            ],
        };
    }

    const ok = validator(data);
    if (ok) {
        return { valid: true };
    }
    const ajvErrors = validator.errors ?? [];
    return {
        valid: false,
        errors: ajvErrors.map((err) => ({
            instancePath: err.instancePath ?? '',
            message: err.message ?? 'schema validation failed',
            keyword: err.keyword ?? 'unknown',
        })),
    };
}
