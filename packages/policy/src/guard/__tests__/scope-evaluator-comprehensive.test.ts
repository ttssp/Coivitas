import { describe, expect, it } from 'vitest';

import { ScopeEvaluator } from '../scope-evaluator.js';

describe('ScopeEvaluator comprehensive behavior', () => {
    const evaluator = new ScopeEvaluator();

    it('applies AND semantics across multiple scopes', async () => {
        expect(
            await evaluator.evaluateAll(
                [
                    {
                        type: 'allowlist',
                        field: 'product_category',
                        values: ['electronics'],
                    },
                    {
                        type: 'numeric_limit',
                        field: 'quantity',
                        max: 500,
                    },
                ],
                {
                    product_category: 'electronics',
                    quantity: 500,
                },
            ),
        ).toEqual({ allowed: true });

        expect(
            await evaluator.evaluateAll(
                [
                    {
                        type: 'allowlist',
                        field: 'product_category',
                        values: ['electronics'],
                    },
                    {
                        type: 'numeric_limit',
                        field: 'quantity',
                        max: 500,
                    },
                ],
                {
                    product_category: 'office',
                    quantity: 500,
                },
            ),
        ).toEqual({
            allowed: false,
            reason: 'product_category is not in the allowlist',
        });
    });

    it('treats missing numeric-limit params as allowed and empty scope arrays as allow', async () => {
        expect(
            await evaluator.evaluateAll(
                [
                    {
                        type: 'numeric_limit',
                        field: 'amount',
                        max: 500,
                    },
                ],
                {},
            ),
        ).toEqual({ allowed: true });

        expect(await evaluator.evaluateAll([], { anything: true })).toEqual({
            allowed: true,
        });
    });
});
