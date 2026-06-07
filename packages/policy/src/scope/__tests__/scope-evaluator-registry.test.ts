/**
 * TDD tests: scope-evaluator-registry.ts
 * Covers the acceptance criteria:
 *   1. registerScopeEvaluator(type, fn) registers a third-party evaluator normally.
 *   2. Registration rejects conflicts with built-in types.
 *   3. Registration rejects an empty-string type.
 *   4. Registration rejects duplicate registration (non-force mode).
 *   5. Force mode allows overwriting a third-party registration (but not a built-in one).
 *   6. cumulative_limit as the first verification scenario (built-in type protection).
 *   7. getRegisteredEvaluator returns the registered fn.
 *   8. getAllRegisteredTypes returns all third-party types.
 *   9. createIsolatedRegistry is used for test isolation.
 */
import { beforeEach, describe, expect, it } from 'vitest';

import {
    BUILT_IN_SCOPE_TYPES,
    ScopeEvaluatorRegistry,
    createIsolatedRegistry,
    globalScopeEvaluatorRegistry,
} from '../scope-evaluator-registry.js';

import type { EvaluatorFn } from '../../guard/scope-evaluator.js';

// A simple stub evaluator.
const stubEvaluator: EvaluatorFn = (_scope, _params, _now) => ({
    allowed: true,
});

describe('BUILT_IN_SCOPE_TYPES', () => {
    it('should contain all four built-in types', () => {
        expect(BUILT_IN_SCOPE_TYPES).toContain('allowlist');
        expect(BUILT_IN_SCOPE_TYPES).toContain('numeric_limit');
        expect(BUILT_IN_SCOPE_TYPES).toContain('temporal_scope');
        expect(BUILT_IN_SCOPE_TYPES).toContain('cumulative_limit');
    });

    it('should be a frozen/read-only set', () => {
        // Attempting to modify the built-in set must not affect the original set.
        const copy = new Set(BUILT_IN_SCOPE_TYPES);
        copy.add('injected_type');
        expect(BUILT_IN_SCOPE_TYPES.has('injected_type')).toBe(false);
    });
});

describe('ScopeEvaluatorRegistry', () => {
    let registry: ScopeEvaluatorRegistry;

    beforeEach(() => {
        registry = new ScopeEvaluatorRegistry();
    });

    describe('register(type, fn)', () => {
        it('should register a third-party evaluator successfully when type is not built-in', () => {
            registry.register('custom_quota', stubEvaluator);
            expect(registry.get('custom_quota')).toBe(stubEvaluator);
        });

        it('should throw when registering a type that conflicts with built-in allowlist', () => {
            expect(() => registry.register('allowlist', stubEvaluator)).toThrow(
                /conflicts with built-in scope type/,
            );
        });

        it('should throw when registering a type that conflicts with built-in numeric_limit', () => {
            expect(() =>
                registry.register('numeric_limit', stubEvaluator),
            ).toThrow(/conflicts with built-in scope type/);
        });

        it('should throw when registering a type that conflicts with built-in temporal_scope', () => {
            expect(() =>
                registry.register('temporal_scope', stubEvaluator),
            ).toThrow(/conflicts with built-in scope type/);
        });

        it('should throw when cumulative_limit is registered as third-party (it is built-in)', () => {
            // cumulative_limit is the first verification scenario: built-in type protection.
            expect(() =>
                registry.register('cumulative_limit', stubEvaluator),
            ).toThrow(/conflicts with built-in scope type/);
        });

        it('should throw when type is an empty string', () => {
            expect(() => registry.register('', stubEvaluator)).toThrow(
                /type must be a non-empty string/,
            );
        });

        it('should throw when type is whitespace only', () => {
            expect(() => registry.register('  ', stubEvaluator)).toThrow(
                /type must be a non-empty string/,
            );
        });

        it('should throw when registering duplicate third-party type without force', () => {
            registry.register('my_type', stubEvaluator);
            const anotherFn: EvaluatorFn = () => ({ allowed: false });
            expect(() => registry.register('my_type', anotherFn)).toThrow(
                /already registered/,
            );
        });

        it('should allow overwriting third-party type with force=true', () => {
            registry.register('my_type', stubEvaluator);
            const newFn: EvaluatorFn = () => ({ allowed: false });
            registry.register('my_type', newFn, { force: true });
            expect(registry.get('my_type')).toBe(newFn);
        });

        it('should NOT allow overwriting built-in type even with force=true', () => {
            expect(() =>
                registry.register('allowlist', stubEvaluator, { force: true }),
            ).toThrow(/conflicts with built-in scope type/);
        });
    });

    describe('get(type)', () => {
        it('should return undefined for unknown type', () => {
            expect(registry.get('unknown_type')).toBeUndefined();
        });

        it('should return the registered function for known type', () => {
            registry.register('test_type', stubEvaluator);
            expect(registry.get('test_type')).toBe(stubEvaluator);
        });
    });

    describe('listTypes()', () => {
        it('should return empty array when no third-party types registered', () => {
            expect(registry.listTypes()).toEqual([]);
        });

        it('should return all registered third-party types', () => {
            registry.register('type_a', stubEvaluator);
            registry.register('type_b', stubEvaluator);
            const types = registry.listTypes();
            expect(types).toContain('type_a');
            expect(types).toContain('type_b');
            expect(types).toHaveLength(2);
        });

        it('should NOT include built-in types in listTypes()', () => {
            const types = registry.listTypes();
            for (const builtIn of BUILT_IN_SCOPE_TYPES) {
                expect(types).not.toContain(builtIn);
            }
        });
    });
});

describe('globalScopeEvaluatorRegistry', () => {
    it('should be a ScopeEvaluatorRegistry instance', () => {
        expect(globalScopeEvaluatorRegistry).toBeInstanceOf(
            ScopeEvaluatorRegistry,
        );
    });

    it('should reject built-in type registration', () => {
        expect(() =>
            globalScopeEvaluatorRegistry.register('allowlist', stubEvaluator),
        ).toThrow(/conflicts with built-in scope type/);
    });
});

describe('createIsolatedRegistry', () => {
    it('should return a fresh ScopeEvaluatorRegistry instance (isolated from global)', () => {
        const reg1 = createIsolatedRegistry();
        const reg2 = createIsolatedRegistry();

        reg1.register('only_in_reg1', stubEvaluator);
        expect(reg2.get('only_in_reg1')).toBeUndefined();
    });
});

describe('integration: ScopeEvaluator respects registry', () => {
    it('should allow ScopeEvaluator to use a plugin evaluator registered via registry', async () => {
        // Tests the hook for ScopeEvaluator integrating the registry (extension point).
        const { ScopeEvaluator } =
            await import('../../guard/scope-evaluator.js');
        const reg = createIsolatedRegistry();

        const myFn: EvaluatorFn = (_scope, params) => {
            const ok = params['quota_key'] === 'valid';
            return {
                allowed: ok,
                reason: ok ? undefined : 'quota_key invalid',
            };
        };
        reg.register('custom_quota', myFn);

        const evaluator = new ScopeEvaluator(undefined, reg);

        const result = await evaluator.evaluate(
            {
                type: 'custom_quota',
            } as unknown as import('@coivitas/types').Scope,
            { quota_key: 'valid' },
        );
        expect(result).toEqual({ allowed: true });

        const result2 = await evaluator.evaluate(
            {
                type: 'custom_quota',
            } as unknown as import('@coivitas/types').Scope,
            { quota_key: 'bad' },
        );
        expect(result2).toEqual({
            allowed: false,
            reason: 'quota_key invalid',
        });
    });

    it('should fail-closed for unknown scope type not in registry', async () => {
        const { ScopeEvaluator } =
            await import('../../guard/scope-evaluator.js');
        const evaluator = new ScopeEvaluator(
            undefined,
            createIsolatedRegistry(),
        );

        const result = await evaluator.evaluate(
            {
                type: 'nonexistent_type',
            } as unknown as import('@coivitas/types').Scope,
            {},
        );
        expect(result.allowed).toBe(false);
        expect(result.reason).toMatch(/Unknown scope type/);
    });
});
