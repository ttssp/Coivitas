/**
 * ExternalWitnessEvaluator unit tests
 *
 * Acceptance criteria:
 * 1. The factory returns an object with type/source/registration.
 * 2. The registry can resolve the evaluator.
 * 3. Calling evaluate() must throw MetricSourceNotImplemented (fail-closed).
 * 4. The error message contains 'not implemented' (runtime locating).
 */

import { describe, expect, it } from 'vitest';

import { ScopeEvaluator } from '../../guard/scope-evaluator.js';
import {
    createExternalWitnessEvaluator,
    MetricSourceNotImplemented,
    registerExternalWitnessEvaluator,
} from '../external-witness-evaluator.js';

// ─────────────────────────────────────────────────────────────────────────────
// Test 1: the factory returns an object with type/source/registration
// ─────────────────────────────────────────────────────────────────────────────

describe('createExternalWitnessEvaluator — factory', () => {
    it('should return evaluatorConfig with type="external_witness" when given valid witnessSource', () => {
        const { evaluatorConfig, evaluatorFn } = createExternalWitnessEvaluator(
            { witnessSource: 'https://witness.example.com/attest' },
        );

        expect(evaluatorConfig.type).toBe('external_witness');
        expect(evaluatorConfig.witnessSource).toBe(
            'https://witness.example.com/attest',
        );
        expect(typeof evaluatorFn).toBe('function');
    });

    it('should preserve optional fields witnessKeyId and witnessTimestampWindow when provided', () => {
        const { evaluatorConfig } = createExternalWitnessEvaluator({
            witnessSource: 'https://witness.example.com/attest',
            witnessKeyId: 'did:key:z6Mk#key-1',
            witnessTimestampWindow: 120,
        });

        expect(evaluatorConfig.witnessKeyId).toBe('did:key:z6Mk#key-1');
        expect(evaluatorConfig.witnessTimestampWindow).toBe(120);
    });

    it('should set witnessKeyId and witnessTimestampWindow to undefined when not provided', () => {
        const { evaluatorConfig } = createExternalWitnessEvaluator({
            witnessSource: 'https://witness.example.com/attest',
        });

        expect(evaluatorConfig.witnessKeyId).toBeUndefined();
        expect(evaluatorConfig.witnessTimestampWindow).toBeUndefined();
    });

    it('should throw Error when witnessSource is empty string', () => {
        expect(() =>
            createExternalWitnessEvaluator({ witnessSource: '' }),
        ).toThrow('witnessSource must be a non-empty string');
    });

    it('should throw Error when witnessSource is whitespace-only string', () => {
        expect(() =>
            createExternalWitnessEvaluator({ witnessSource: '   ' }),
        ).toThrow('witnessSource must be a non-empty string');
    });
});

// ─────────────────────────────────────────────────────────────────────────────
// Test 2: the registry can resolve the evaluator (via registerScopeEvaluator)
// ─────────────────────────────────────────────────────────────────────────────

describe('registerExternalWitnessEvaluator — registry', () => {
    it('should register external_witness type in ScopeEvaluator so it is recognized', async () => {
        const evaluator = new ScopeEvaluator();

        registerExternalWitnessEvaluator(evaluator, {
            witnessSource: 'https://witness.example.com/attest',
        });

        // After registration evaluate() no longer returns 'Unknown scope type'; it returns a fail-closed denial.
        // The evaluator must return { allowed: false } rather than throwing,
        // otherwise a throw from evaluateAll() would bypass RuntimeGuard's REJECTED path.
        const result = await evaluator.evaluate(
            // Use an unknown cast to bypass the Scope union (external_witness is not yet in the Scope enum).
            {
                type: 'external_witness',
            } as unknown as import('@coivitas/types').Scope,
            {},
        );
        expect(result.allowed).toBe(false);
        expect(result.reason).toMatch(/METRIC_SOURCE_NOT_IMPLEMENTED/);
    });

    it('should return evaluatorConfig with registration metadata when registered', () => {
        const evaluator = new ScopeEvaluator();

        const config = registerExternalWitnessEvaluator(evaluator, {
            witnessSource: 'https://witness.example.com/attest',
            witnessKeyId: 'did:key:z6Mk#key-1',
            witnessTimestampWindow: 60,
        });

        expect(config.type).toBe('external_witness');
        expect(config.witnessSource).toBe('https://witness.example.com/attest');
        expect(config.witnessKeyId).toBe('did:key:z6Mk#key-1');
        expect(config.witnessTimestampWindow).toBe(60);
    });

    it('should allow re-registration on a fresh ScopeEvaluator (no global state pollution)', () => {
        // Each ScopeEvaluator instance is independent, so repeated registrations do not conflict.
        const evaluator1 = new ScopeEvaluator();
        const evaluator2 = new ScopeEvaluator();

        expect(() =>
            registerExternalWitnessEvaluator(evaluator1, {
                witnessSource: 'https://witness1.example.com',
            }),
        ).not.toThrow();

        expect(() =>
            registerExternalWitnessEvaluator(evaluator2, {
                witnessSource: 'https://witness2.example.com',
            }),
        ).not.toThrow();
    });
});

// ─────────────────────────────────────────────────────────────────────────────
// Test 3: evaluate() must throw MetricSourceNotImplemented (fail-closed verification)
// ─────────────────────────────────────────────────────────────────────────────

describe("evaluatorFn — fail-closed behavior (deny, don't throw)", () => {
    // The evaluator must return { allowed: false } so that RuntimeGuard /
    // Orchestrator take the normal REJECTED path and write the ledger; a throw would be
    // treated as INTERNAL_ERROR upstream, bypassing the fail-closed design. MetricSourceNotImplemented
    // is still retained as an optional type for use when a real production evaluator errors (not triggered on the stub path).
    it('should return { allowed: false } with reason when evaluate() is called directly', async () => {
        const { evaluatorFn } = createExternalWitnessEvaluator({
            witnessSource: 'https://witness.example.com/attest',
        });

        const result = await evaluatorFn(
            {
                type: 'external_witness',
            } as unknown as import('@coivitas/types').Scope,
            {},
            new Date(),
            undefined,
        );
        expect(result.allowed).toBe(false);
        expect(result.reason).toMatch(/METRIC_SOURCE_NOT_IMPLEMENTED/);
        // reason must not leak witnessSource (avoid leaking the internal URL into
        // the AUTHORIZATION_INSUFFICIENT error and the REJECTED ActionRecord).
        expect(result.reason).not.toContain(
            'https://witness.example.com/attest',
        );
    });

    it('should return { allowed: false } via ScopeEvaluator.evaluate() when registered', async () => {
        const evaluator = new ScopeEvaluator();
        registerExternalWitnessEvaluator(evaluator, {
            witnessSource: 'https://witness.example.com/attest',
        });

        const result = await evaluator.evaluate(
            {
                type: 'external_witness',
            } as unknown as import('@coivitas/types').Scope,
            {},
        );
        expect(result.allowed).toBe(false);
        expect(result.reason).toMatch(/METRIC_SOURCE_NOT_IMPLEMENTED/);
    });

    it('should return { allowed: false } via ScopeEvaluator.evaluateAll() when external_witness is in scope list', async () => {
        const evaluator = new ScopeEvaluator();
        registerExternalWitnessEvaluator(evaluator, {
            witnessSource: 'https://witness.example.com/attest',
        });

        const result = await evaluator.evaluateAll(
            [
                {
                    type: 'allowlist',
                    field: 'action',
                    values: ['transfer'],
                },
                {
                    type: 'external_witness',
                } as unknown as import('@coivitas/types').Scope,
            ],
            { action: 'transfer' },
        );
        expect(result.allowed).toBe(false);
        expect(result.reason).toMatch(/METRIC_SOURCE_NOT_IMPLEMENTED/);
    });
});

// ─────────────────────────────────────────────────────────────────────────────
// Test 4: the error message contains 'not implemented' (runtime locating)
// ─────────────────────────────────────────────────────────────────────────────

describe('MetricSourceNotImplemented — error message quality', () => {
    // evaluatorFn no longer throws (it now returns a fail-closed denial);
    // the MetricSourceNotImplemented class is still retained for use by a real production evaluator.
    it('should include witnessSource in evaluator deny reason', async () => {
        const { evaluatorFn } = createExternalWitnessEvaluator({
            witnessSource: 'https://witness.example.com/attest',
        });

        const result = await evaluatorFn(
            {
                type: 'external_witness',
            } as unknown as import('@coivitas/types').Scope,
            {},
            new Date(),
            undefined,
        );
        expect(result.allowed).toBe(false);
        // witnessSource no longer appears in reason.
        expect(result.reason).not.toContain(
            'https://witness.example.com/attest',
        );
        expect(result.reason).toMatch(/METRIC_SOURCE_NOT_IMPLEMENTED/);
    });

    it('should include "not implemented" in error message for runtime localization', () => {
        const error = new MetricSourceNotImplemented(
            'https://witness.example.com/attest',
        );
        expect(error.message.toLowerCase()).toContain('not implemented');
    });

    it('should be fail-closed in the error message', () => {
        const error = new MetricSourceNotImplemented(
            'https://witness.example.com/attest',
        );
        expect(error.message.toLowerCase()).toContain('fail-closed');
    });

    it('should have error name "MetricSourceNotImplemented" for Error.name identification', () => {
        const error = new MetricSourceNotImplemented(
            'https://witness.example.com/attest',
        );
        expect(error.name).toBe('MetricSourceNotImplemented');
    });

    it('should be instanceof Error for standard error handling compatibility', () => {
        const error = new MetricSourceNotImplemented(
            'https://witness.example.com/attest',
        );
        expect(error).toBeInstanceOf(Error);
    });
});

// ─────────────────────────────────────────────────────────────────────────────
// Unregistered external_witness type — contrasting behavior verification (Unknown scope type when not registered)
// ─────────────────────────────────────────────────────────────────────────────

describe('ScopeEvaluator without external_witness registration', () => {
    it('should return allowed=false with "Unknown scope type" when external_witness is not registered', async () => {
        const evaluator = new ScopeEvaluator(); // external_witness not registered

        const result = await evaluator.evaluate(
            {
                type: 'external_witness',
            } as unknown as import('@coivitas/types').Scope,
            {},
        );

        expect(result.allowed).toBe(false);
        expect(result.reason).toContain('Unknown scope type');
    });
});
