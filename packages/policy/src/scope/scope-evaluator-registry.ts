/**
 * ScopeEvaluator plugin registry
 *
 * Design origin: DSL extension point.
 *
 * Core responsibilities:
 * 1. Maintain the set of built-in Scope type constants (tamper-resistant).
 * 2. Provide a register(type, fn) API with security constraints:
 *    - Reject empty/blank type.
 *    - Reject conflicts with built-in types (not allowed even with force=true).
 *    - Reject duplicate registration (unless force=true).
 * 3. Provide get/listTypes query APIs.
 * 4. Export globalScopeEvaluatorRegistry (global singleton) and createIsolatedRegistry (for tests).
 *
 * Design decision:
 * - cumulative_limit is the first verification scenario — it is a built-in type, and any third-party attempt to override it is rejected.
 * - Future external_witness / consensus_meter types will be extended through this registry.
 */

import type { EvaluatorFn } from '../guard/scope-evaluator.js';

/**
 * The set of built-in Scope types (read-only).
 * Third-party registrations must not conflict with any type in this set.
 *
 * cumulative_limit is included as the protection target of the "first verification scenario" —
 * ensuring the built-in cumulative-limit evaluator cannot be silently replaced by external code.
 */
export const BUILT_IN_SCOPE_TYPES: ReadonlySet<string> = Object.freeze(
    new Set([
        'allowlist',
        'numeric_limit',
        'temporal_scope',
        'cumulative_limit',
    ]),
);

export interface RegisterOptions {
    /**
     * Whether to forcibly overwrite an existing third-party registration.
     * Note: force=true still does not allow overwriting a built-in type.
     */
    force?: boolean;
}

/**
 * ScopeEvaluator plugin registry.
 *
 * Each instance maintains an independent map of third-party evaluators; it does not store built-in types.
 * Security constraints are enforced at registration time and cannot be bypassed.
 */
export class ScopeEvaluatorRegistry {
    readonly #plugins: Map<string, EvaluatorFn> = new Map();

    /**
     * Registers a third-party Scope evaluator.
     *
     * Security constraints (in priority order):
     * 1. type must be a non-empty, non-blank string.
     * 2. type must not conflict with a built-in type (force cannot bypass this rule).
     * 3. The same type must not be registered twice (unless force=true).
     *
     * @param type the Scope DSL type identifier (e.g. 'custom_quota')
     * @param fn the evaluator function (synchronous or asynchronous)
     * @param opts registration options
     * @throws Error when any security constraint is violated
     */
    public register(
        type: string,
        fn: EvaluatorFn,
        opts?: RegisterOptions,
    ): void {
        // Constraint 1: type must be a non-empty string.
        if (!type || type.trim().length === 0) {
            throw new Error(
                `ScopeEvaluatorRegistry: type must be a non-empty string, got: ${JSON.stringify(type)}`,
            );
        }

        // Constraint 2: type must not conflict with a built-in type (any force setting is ineffective here).
        if (BUILT_IN_SCOPE_TYPES.has(type)) {
            throw new Error(
                `ScopeEvaluatorRegistry: type "${type}" conflicts with built-in scope type and cannot be overridden. ` +
                    `Built-in types: ${[...BUILT_IN_SCOPE_TYPES].join(', ')}`,
            );
        }

        // Constraint 3: duplicate-registration check (force=true allows overwriting a third-party registration).
        if (this.#plugins.has(type) && !opts?.force) {
            throw new Error(
                `ScopeEvaluatorRegistry: type "${type}" is already registered. ` +
                    `Use { force: true } to overwrite an existing third-party registration.`,
            );
        }

        this.#plugins.set(type, fn);
    }

    /**
     * Retrieves a registered third-party evaluator function.
     * For built-in types this method returns undefined (handled by ScopeEvaluator itself).
     *
     * @returns the evaluator function, or undefined (not registered)
     */
    public get(type: string): EvaluatorFn | undefined {
        return this.#plugins.get(type);
    }

    /**
     * Lists all registered third-party Scope types.
     * Does not include built-in types.
     */
    public listTypes(): string[] {
        return [...this.#plugins.keys()];
    }
}

/**
 * Global singleton registry.
 *
 * The application layer registers plugins via globalScopeEvaluatorRegistry.register();
 * ScopeEvaluator automatically queries this registry during evaluate().
 */
export const globalScopeEvaluatorRegistry = new ScopeEvaluatorRegistry();

/**
 * Creates a new instance fully isolated from the global registry.
 * Primarily for unit tests, to avoid state pollution between tests.
 */
export function createIsolatedRegistry(): ScopeEvaluatorRegistry {
    return new ScopeEvaluatorRegistry();
}
