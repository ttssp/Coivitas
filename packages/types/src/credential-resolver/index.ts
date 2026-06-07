/**
 * Credential Resolver (CR) sub-protocol v0.1 L0 module exports
 *
 * credential-resolver sub-protocol
 *
 * Triple defense (csp + multisig + hcc pattern reuse):
 *   Layer 1 (types.ts): TypeScript brand types — compile-time guard (no brand cast; phantom-type only)
 *     + CrError / CrErrorCode 14-item freeze + assertNeverCrCode + handleCrError
 *   Layer 2 (../schemas/credential-resolver-v0.1.schema.json): JSON Schema — runtime schema layer
 *   Layer 3 (cr-validation.ts): AJV strict mode, 4 flags — runtime schema-engine layer
 *
 * Error-code namespace (freeze, 14 items; CR_* prefix;
 *   does not conflict with CSP_* / RFP_* / DELEGATION_* / ATP_* / HCC_* / MS_* / CCR_* / TB_*).
 */

export * from './types.js';
export * from './factories.js';
export {
    validateCr,
    type CrValidationResult,
    type CrValidationError,
    type CrSchemaName,
} from './cr-validation.js';
