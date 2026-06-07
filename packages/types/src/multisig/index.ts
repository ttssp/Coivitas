/**
 * Multisig sub-protocol (ms) v0.1 module exports.
 *
 * Sub-protocol module.
 *
 * Triple defense:
 *   Line 1 (types.ts): TypeScript brand types — compile-time guard (SignerId / MerklePath /
 *     MultisigVersion / MultisigToken brand + factory)
 *   Line 2 (../schemas/multisig-token-v0.1.schema.json): JSON Schema — runtime Schema layer
 *   Line 3 (multisig-validation.ts): AJV strict mode — runtime Schema-engine layer
 *
 * 14 active MULTISIG_* error codes in the namespace (frozen in v0.1; originally 17 - 3 removed)
 */

export * from './types.js';
export * from './multisig-validation.js';
