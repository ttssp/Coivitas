/**
 * Audit Tamper-Proof (atp) v0.1 module exports
 *
 * Priority-4 sub-protocol
 *
 * Triple defense:
 *   Layer 1 (types.ts): TypeScript brand type — compile-time guard
 *   Layer 2 (schemas/audit-event-v0.1.schema.json): JSON Schema — runtime schema layer
 *   Layer 3 (atp-validation.ts): AJV strict mode — runtime schema engine layer
 */

export * from './types.js';
export * from './atp-validation.js';
