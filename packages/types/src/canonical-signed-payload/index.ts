/**
 * Canonical Signed Payload (CSP) v0.1 module exports
 *
 * Priority-1 sub-protocol
 *
 * Triple defense:
 *   Layer 1 (types.ts): TypeScript brand types — compile-time guard
 *   Layer 2 (schemas/canonical-signed-payload.schema.json): JSON Schema — runtime schema layer
 *   Layer 3 (csp-validation.ts): AJV strict mode — runtime schema-engine layer
 */

export * from './types.js';
export * from './csp-validation.js';
