/**
 * Settlement Retry (SR) sub-protocol v0.1 — module exports
 *
 * priority-10 sub-protocol
 *
 * Triple line of defense:
 *   Layer 1 (brands.ts + types.ts + errors.ts): TypeScript brand type — compile-time guard
 *   Layer 2 (schemas.ts): JSON Schema strict — runtime Schema layer
 *   Layer 3 (packages/policy/src/settlement-retry/*.ts L3): AJV strict mode 4 flags — runtime Schema engine layer
 */

export * from './brands.js';
export * from './errors.js';
export * from './ports.js';
export * from './schemas.js';
export * from './sr-validation.js';
export * from './types.js';
