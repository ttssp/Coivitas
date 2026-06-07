// Multi-version schema validator registry types (L0 pure interfaces).
// Design approach: schemas.ts single-instance AJV → per-specVersion standalone AJV instances,
// eliminating the RUNTIME_DEPENDENT third state.

import type { SupportedSpecVersion } from '../base.js';

// Re-exports the version constants from base.ts for downstream consumption (single entry point semantics)
export type { SupportedSpecVersion } from '../base.js';

/**
 * Validation result type — deterministic PASS or REJECT (no more RUNTIME_DEPENDENT).
 */
export type ValidationResult =
    | { readonly valid: true }
    | { readonly valid: false; readonly errors: string[] };

/**
 * SpecVersionedValidator — a per-specVersion standalone AJV instance.
 *
 * Each specVersion loads its corresponding schema snapshot directory and
 * compiles its validator functions independently, without interference.
 *
 */
export interface SpecVersionedValidator {
    readonly specVersion: SupportedSpecVersion;

    /**
     * Validates the payload under the given schemaId.
     *
     * @param schemaId e.g. 'signedAuditQuery', 'envelope', 'actionRecord'
     * @param data the data to validate
     * @returns deterministic PASS or REJECT
     */
    validate(schemaId: string, data: unknown): ValidationResult;
}

/**
 * SchemaValidatorRegistry — specVersion -> validator mapping.
 *
 * Replaces the original schemas.ts single-instance pattern:
 *   - retains the current() convenience method (= the v0.3.0 validator, backward compatible)
 *   - adds forVersion(specVersion) to route by version
 *   - adds supportedVersions() to enumerate all archived versions
 *
 */
export interface SchemaValidatorRegistry {
    /** Get the current version (0.3.0) validator — backward compatible*/
    current(): SpecVersionedValidator;

    /** Get a validator by specVersion; returns null for an unregistered version*/
    forVersion(specVersion: string): SpecVersionedValidator | null;

    /** Enumerate all registered versions*/
    supportedVersions(): readonly string[];
}
