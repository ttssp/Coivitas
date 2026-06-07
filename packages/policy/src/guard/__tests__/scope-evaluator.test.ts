import { describe, expect, it } from 'vitest';

import type { Scope } from '@coivitas/types';

import { ScopeEvaluator } from '../scope-evaluator.js';

describe('ScopeEvaluator', () => {
    const evaluator = new ScopeEvaluator();

    it('supports allowlist matching and wildcard suffixes', async () => {
        expect(
            await evaluator.evaluate(
                {
                    type: 'allowlist',
                    field: 'recipient',
                    values: ['supplier-a', '*.acme.com'],
                },
                { recipient: 'supplier-a' },
            ),
        ).toEqual({ allowed: true });

        expect(
            await evaluator.evaluate(
                {
                    type: 'allowlist',
                    field: 'recipient',
                    values: ['supplier-a', '*.acme.com'],
                },
                { recipient: 'buyer.acme.com' },
            ),
        ).toEqual({ allowed: true });
    });

    it('rejects empty allowlists and missing params', async () => {
        expect(
            await evaluator.evaluate(
                {
                    type: 'allowlist',
                    field: 'recipient',
                    values: [],
                },
                { recipient: 'supplier-a' },
            ),
        ).toEqual({
            allowed: false,
            reason: 'recipient allowlist is empty',
        });

        expect(
            await evaluator.evaluate(
                {
                    type: 'allowlist',
                    field: 'recipient',
                    values: ['supplier-a'],
                },
                {},
            ),
        ).toEqual({
            allowed: false,
            reason: 'recipient is missing or not a string',
        });
    });

    it('supports numeric limits and rejects non-numbers', async () => {
        expect(
            await evaluator.evaluate(
                {
                    type: 'numeric_limit',
                    field: 'amount',
                    max: 500,
                },
                { amount: 500 },
            ),
        ).toEqual({ allowed: true });

        expect(
            await evaluator.evaluate(
                {
                    type: 'numeric_limit',
                    field: 'amount',
                    max: 500,
                },
                { amount: 501 },
            ),
        ).toEqual({
            allowed: false,
            reason: 'amount exceeds max 500',
        });

        expect(
            await evaluator.evaluate(
                {
                    type: 'numeric_limit',
                    field: 'amount',
                    max: 500,
                },
                { amount: '500' },
            ),
        ).toEqual({
            allowed: false,
            reason: 'amount is not a number',
        });
    });
});

describe('ScopeEvaluator extensibility', () => {
    it('should return Unknown scope type when scope type is not registered', async () => {
        const evaluator = new ScopeEvaluator();
        const result = await evaluator.evaluate(
            { type: 'nonexistent_type' } as unknown as Scope,
            {},
        );
        expect(result).toEqual({
            allowed: false,
            reason: 'Unknown scope type: nonexistent_type',
        });
    });

    it('should allow registering a custom evaluator at runtime', async () => {
        const evaluator = new ScopeEvaluator();
        evaluator.registerScopeEvaluator(
            'my_custom_scope',
            (_scope, params) => {
                return { allowed: params['allowed'] === true };
            },
        );

        expect(
            await evaluator.evaluate(
                { type: 'my_custom_scope' } as unknown as Scope,
                { allowed: true },
            ),
        ).toEqual({ allowed: true });

        expect(
            await evaluator.evaluate(
                { type: 'my_custom_scope' } as unknown as Scope,
                { allowed: false },
            ),
        ).toEqual({ allowed: false });
    });

    it('should throw when attempting to override a built-in evaluator (security constraint)', () => {
        // On registration, validate that the type does not conflict with known built-ins; overriding a built-in type is forbidden
        const evaluator = new ScopeEvaluator();
        expect(() =>
            evaluator.registerScopeEvaluator('allowlist', () => ({
                allowed: false,
                reason: 'overridden',
            })),
        ).toThrow(/conflicts with built-in scope type/);
    });

    it('should support async custom evaluators', async () => {
        const evaluator = new ScopeEvaluator();
        evaluator.registerScopeEvaluator(
            'async_scope',
            async (_scope, params) => {
                await Promise.resolve();
                return { allowed: params['ok'] === true };
            },
        );

        const result = await evaluator.evaluate(
            { type: 'async_scope' } as unknown as Scope,
            { ok: true },
        );
        expect(result).toEqual({ allowed: true });
    });
});
