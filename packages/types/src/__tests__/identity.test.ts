import { describe, expect, it } from 'vitest';

import type { ResolvedPublicKeys } from '../identity.js';
import { validateAgainstSchema } from '../validation.js';

const currentKey = 'a'.repeat(64);
const previousKey = 'b'.repeat(64);
// cutoff timestamp (ISO-8601 format aligned with the timestamp $ref pattern)
const cutoff = '2026-04-28T00:00:00.000Z';

describe('ResolvedPublicKeys (v0.3.0 dual key + cutoff)', () => {
    describe('schema validation — 4 fallback semantics', () => {
        it('should validate STABLE state (single key, no previous)', () => {
            const keys: ResolvedPublicKeys = {
                current: currentKey,
                rotationState: 'STABLE',
            };
            const result = validateAgainstSchema(keys, 'resolvedPublicKeys');
            expect(result.valid).toBe(true);
            expect(result.errors).toHaveLength(0);
        });

        it('should validate ROTATING state with previous + cutoff (exiting window: current preferred, fallback previous with cutoff check)', () => {
            // four-state semantics (2)/(3): the ROTATING enum value covers both the "exiting window" and "entering window" sub-phases
            // cutoff (previousValidBefore) is a fail-closed security invariant
            const keys: ResolvedPublicKeys = {
                current: currentKey,
                previous: previousKey,
                previousValidBefore: cutoff,
                rotationState: 'ROTATING',
            };
            const result = validateAgainstSchema(keys, 'resolvedPublicKeys');
            expect(result.valid).toBe(true);
            expect(result.errors).toHaveLength(0);
        });

        it('should validate FROZEN state (keys frozen, only current valid)', () => {
            // four-state semantics (4): FROZEN indicates compromise / administrator lock
            // previous is not returned; any rotation operation is blocked
            const keys: ResolvedPublicKeys = {
                current: currentKey,
                rotationState: 'FROZEN',
            };
            const result = validateAgainstSchema(keys, 'resolvedPublicKeys');
            expect(result.valid).toBe(true);
            expect(result.errors).toHaveLength(0);
        });

        it('should validate ROTATING with different current key + cutoff (entering window: signing key already switched)', () => {
            // four-state semantics (3): shares the ROTATING enum value with (2)
            // the difference is that the orchestrator has already switched the signing key to current,
            // but remote verifiers must still accept in-flight artifacts signed by the previous key
            const newKey = 'c'.repeat(64);
            const keys: ResolvedPublicKeys = {
                current: newKey,
                previous: currentKey,
                previousValidBefore: cutoff,
                rotationState: 'ROTATING',
            };
            const result = validateAgainstSchema(keys, 'resolvedPublicKeys');
            expect(result.valid).toBe(true);
            expect(result.errors).toHaveLength(0);
        });
    });

    describe('schema validation — invalid cases', () => {
        it('should reject when current is missing', () => {
            const result = validateAgainstSchema(
                { rotationState: 'STABLE' },
                'resolvedPublicKeys',
            );
            expect(result.valid).toBe(false);
            expect(
                result.errors.some(
                    (e) =>
                        e.message?.includes('current') || e.instancePath === '',
                ),
            ).toBe(true);
        });

        it('should reject unknown rotationState value', () => {
            const result = validateAgainstSchema(
                { current: currentKey, rotationState: 'CHURNING' },
                'resolvedPublicKeys',
            );
            expect(result.valid).toBe(false);
        });

        it('should reject ROTATING without previous (semantic contradiction)', () => {
            const result = validateAgainstSchema(
                { current: currentKey, rotationState: 'ROTATING' },
                'resolvedPublicKeys',
            );
            expect(result.valid).toBe(false);
        });

        it('should reject STABLE with previous present (semantic contradiction)', () => {
            const result = validateAgainstSchema(
                {
                    current: currentKey,
                    previous: previousKey,
                    rotationState: 'STABLE',
                },
                'resolvedPublicKeys',
            );
            expect(result.valid).toBe(false);
        });
    });

    // cutoff path coverage
    describe('previousValidBefore cutoff', () => {
        it('should reject ROTATING with previous but missing previousValidBefore (missing cutoff = fail-closed)', () => {
            // cutoff is a security invariant
            // missing cutoff = signature verification cannot detect "a token forged with the old key after rotation" → fail-closed reject
            const result = validateAgainstSchema(
                {
                    current: currentKey,
                    previous: previousKey,
                    rotationState: 'ROTATING',
                },
                'resolvedPublicKeys',
            );
            expect(result.valid).toBe(false);
            expect(
                result.errors.some((e) =>
                    e.message?.includes('previousValidBefore'),
                ),
            ).toBe(true);
        });

        it('should reject STABLE with previousValidBefore present (STABLE should not have cutoff)', () => {
            // STABLE semantics = no rotation in progress; a cutoff field appearing = caller passed it in error
            // schema fail-closed reject avoids the verification window being incorrectly widened
            const result = validateAgainstSchema(
                {
                    current: currentKey,
                    previousValidBefore: cutoff,
                    rotationState: 'STABLE',
                },
                'resolvedPublicKeys',
            );
            expect(result.valid).toBe(false);
        });

        it('should reject FROZEN with previousValidBefore present (FROZEN should not have cutoff)', () => {
            // FROZEN = compromise / administrator lock; same as STABLE, a cutoff is not allowed to appear
            const result = validateAgainstSchema(
                {
                    current: currentKey,
                    previousValidBefore: cutoff,
                    rotationState: 'FROZEN',
                },
                'resolvedPublicKeys',
            );
            expect(result.valid).toBe(false);
        });
    });

    describe('KeyRotationState enum validation', () => {
        it('should accept all three valid states', () => {
            for (const state of ['STABLE', 'ROTATING', 'FROZEN']) {
                const result = validateAgainstSchema(state, 'keyRotationState');
                expect(result.valid).toBe(true);
            }
        });

        it('should reject invalid state values', () => {
            for (const state of ['ACTIVE', 'RETIRED', 'CHURNING', '']) {
                const result = validateAgainstSchema(state, 'keyRotationState');
                expect(result.valid).toBe(false);
            }
        });
    });
});
