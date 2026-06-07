/**
 * Hash Chain Canonicalize (HCC) v0.1 L0 module exports.
 *
 * Priority 5 sub-protocol.
 *
 * Triple defense (reuses the csp pattern):
 *   Line 1 (types.ts): TypeScript brand types — compile-time guard (no brand cast)
 *   Line 2 (schemas/hash-chain-entry.schema.json): JSON Schema — runtime Schema layer
 *   Line 3 (hcc-validation.ts): AJV strict mode, 5 flags — runtime Schema-engine layer
 *
 * Error-code namespace (freezes 6 entries; HC_* prefix; does not conflict with CSP_* / RFP_* / TB_*).
 */

export * from './types.js';
export * from './hcc-validation.js';
