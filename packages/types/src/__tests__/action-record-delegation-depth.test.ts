/**
 * delegationDepth schema v0.3.0 required field landing tests
 *
 * Coverage:
 * - Three-state version compatibility matrix (0.1.0 / 0.2.0 / 0.3.0)
 * - delegationDepth boundary values (0, 1, 3, 5=MAX, 6>MAX, -1<0)
 * - Type errors (string instead of integer)
 * - v0.3.0 required gate (missing field -> AJV fail-closed rejection)
 * - fail-closed; no additional error-code namespace introduced
 */

import { describe, expect, it } from 'vitest';

import type { DID, Signature, Timestamp } from '../index.js';
import { MAX_DELEGATION_DEPTH, validateAgainstSchema } from '../index.js';

// Fixed test data
const agentDid = 'did:agent:a3f1b2c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0' as DID;
const principalDid =
    'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK' as DID;
const signature = 'a'.repeat(128) as Signature;
const actorSig = 'b'.repeat(128) as Signature;
const timestamp = '2026-04-27T00:01:00.000Z' as Timestamp;

/**
 * Builds an ActionRecord baseline. specVersion and delegationDepth are overridden by the caller.
 * Defaults to specVersion='0.3.0' + delegationDepth=0 with actorSignature populated.
 */
const buildRecord = (
    overrides: Record<string, unknown> = {},
): Record<string, unknown> => ({
    id: 'rec-550e8400-e29b-41d4-a716-050d00000001',
    specVersion: '0.3.0',
    agentDid,
    principalDid,
    action: 'INQUIRY',
    parametersSummary: { product_category: 'electronics' },
    authorizationRef: {
        tokenId: 'urn:cap:550e8400-e29b-41d4-a716-446655440000',
    },
    resultSummary: { status: 'SUCCESS' },
    timestamp,
    prevHash: null,
    ledgerSignature: signature,
    actorSignature: actorSig,
    delegationDepth: 0,
    ...overrides,
});

// ---------------------------------------------------------------------------
// 1. Three-state version compatibility matrix
// ---------------------------------------------------------------------------
describe('delegationDepth specVersion three-state compatibility matrix', () => {
    // 0.1.0: delegationDepth optional -> missing field should pass
    it('should pass when v0.1.0 ActionRecord omits delegationDepth', () => {
        const record = buildRecord({ specVersion: '0.1.0' });
        delete record.delegationDepth;
        delete record.actorSignature; // 0.1.0 does not require actorSignature
        const result = validateAgainstSchema(record, 'actionRecord');
        expect(result.valid).toBe(true);
    });

    // 0.1.0: delegationDepth present should also pass (forward-compatible write)
    it('should pass when v0.1.0 ActionRecord includes delegationDepth=2', () => {
        const record = buildRecord({
            specVersion: '0.1.0',
            delegationDepth: 2,
        });
        delete record.actorSignature;
        const result = validateAgainstSchema(record, 'actionRecord');
        expect(result.valid).toBe(true);
    });

    // 0.2.0: delegationDepth optional -> missing field should pass (actorSignature required)
    it('should pass when v0.2.0 ActionRecord omits delegationDepth', () => {
        const record = buildRecord({ specVersion: '0.2.0' });
        delete record.delegationDepth;
        const result = validateAgainstSchema(record, 'actionRecord');
        expect(result.valid).toBe(true);
    });

    // 0.2.0: delegationDepth present should also pass
    it('should pass when v0.2.0 ActionRecord includes delegationDepth=3', () => {
        const record = buildRecord({
            specVersion: '0.2.0',
            delegationDepth: 3,
        });
        const result = validateAgainstSchema(record, 'actionRecord');
        expect(result.valid).toBe(true);
    });

    // 0.3.0: delegationDepth required -> missing field should be rejected
    it('should reject when v0.3.0 ActionRecord omits delegationDepth', () => {
        const record = buildRecord({ specVersion: '0.3.0' });
        delete record.delegationDepth;
        const result = validateAgainstSchema(record, 'actionRecord');
        expect(result.valid).toBe(false);
        // Confirm it is a required error and not some other error
        const requiredError = result.errors.find(
            (e) =>
                e.keyword === 'required' &&
                e.message?.includes('delegationDepth'),
        );
        expect(requiredError).toBeDefined();
    });

    // 0.3.0: delegationDepth present -> should pass
    it('should pass when v0.3.0 ActionRecord includes delegationDepth=0', () => {
        const record = buildRecord({
            specVersion: '0.3.0',
            delegationDepth: 0,
        });
        const result = validateAgainstSchema(record, 'actionRecord');
        expect(result.valid).toBe(true);
    });

    // 0.3.0: actorSignature is also required (inherits the 0.2.0 constraint + 0.3.0 extension)
    it('should reject when v0.3.0 ActionRecord omits actorSignature', () => {
        const record = buildRecord({ specVersion: '0.3.0' });
        delete record.actorSignature;
        const result = validateAgainstSchema(record, 'actionRecord');
        expect(result.valid).toBe(false);
        const requiredError = result.errors.find(
            (e) =>
                e.keyword === 'required' &&
                e.message?.includes('actorSignature'),
        );
        expect(requiredError).toBeDefined();
    });
});

// ---------------------------------------------------------------------------
// 2. delegationDepth boundary value tests
// ---------------------------------------------------------------------------
describe('delegationDepth boundary values', () => {
    it('should accept depth=0 (minimum, no delegation)', () => {
        const result = validateAgainstSchema(
            buildRecord({ delegationDepth: 0 }),
            'actionRecord',
        );
        expect(result.valid).toBe(true);
    });

    it('should accept depth=1 (single hop delegation)', () => {
        const result = validateAgainstSchema(
            buildRecord({ delegationDepth: 1 }),
            'actionRecord',
        );
        expect(result.valid).toBe(true);
    });

    it('should accept depth=3 (mid-range)', () => {
        const result = validateAgainstSchema(
            buildRecord({ delegationDepth: 3 }),
            'actionRecord',
        );
        expect(result.valid).toBe(true);
    });

    it('should accept depth=MAX_DELEGATION_DEPTH (upper boundary inclusive)', () => {
        expect(MAX_DELEGATION_DEPTH).toBe(5); // anchor the constant value
        const result = validateAgainstSchema(
            buildRecord({ delegationDepth: MAX_DELEGATION_DEPTH }),
            'actionRecord',
        );
        expect(result.valid).toBe(true);
    });

    it('should reject depth=MAX_DELEGATION_DEPTH+1 (exceeds maximum)', () => {
        const result = validateAgainstSchema(
            buildRecord({ delegationDepth: MAX_DELEGATION_DEPTH + 1 }),
            'actionRecord',
        );
        expect(result.valid).toBe(false);
        const maxError = result.errors.find((e) => e.keyword === 'maximum');
        expect(maxError).toBeDefined();
    });

    it('should reject depth=-1 (below minimum)', () => {
        const result = validateAgainstSchema(
            buildRecord({ delegationDepth: -1 }),
            'actionRecord',
        );
        expect(result.valid).toBe(false);
        const minError = result.errors.find((e) => e.keyword === 'minimum');
        expect(minError).toBeDefined();
    });

    it('should reject depth=6 specifically (fixture alignment)', () => {
        const result = validateAgainstSchema(
            buildRecord({ delegationDepth: 6 }),
            'actionRecord',
        );
        expect(result.valid).toBe(false);
    });
});

// ---------------------------------------------------------------------------
// 3. Type errors
// ---------------------------------------------------------------------------
describe('delegationDepth type validation', () => {
    it('should reject string value for delegationDepth', () => {
        const result = validateAgainstSchema(
            buildRecord({ delegationDepth: 'three' }),
            'actionRecord',
        );
        expect(result.valid).toBe(false);
        const typeError = result.errors.find((e) => e.keyword === 'type');
        expect(typeError).toBeDefined();
    });

    it('should reject float value for delegationDepth (must be integer)', () => {
        const result = validateAgainstSchema(
            buildRecord({ delegationDepth: 2.5 }),
            'actionRecord',
        );
        expect(result.valid).toBe(false);
        const typeError = result.errors.find((e) => e.keyword === 'type');
        expect(typeError).toBeDefined();
    });

    it('should reject null value for delegationDepth in v0.3.0', () => {
        const result = validateAgainstSchema(
            buildRecord({ delegationDepth: null }),
            'actionRecord',
        );
        expect(result.valid).toBe(false);
    });

    it('should reject boolean value for delegationDepth', () => {
        const result = validateAgainstSchema(
            buildRecord({ delegationDepth: true }),
            'actionRecord',
        );
        expect(result.valid).toBe(false);
    });
});

// ---------------------------------------------------------------------------
// 4. MAX_DELEGATION_DEPTH constant consistency
// ---------------------------------------------------------------------------
describe('MAX_DELEGATION_DEPTH constant consistency', () => {
    it('should equal 5 (authorization.ts:125 baseline)', () => {
        expect(MAX_DELEGATION_DEPTH).toBe(5);
    });

    it('should be used as schema maximum (no redefinition)', () => {
        // Verify depth=5 passes but depth=6 fails, proving the schema maximum correctly references the constant
        const pass = validateAgainstSchema(
            buildRecord({ delegationDepth: 5 }),
            'actionRecord',
        );
        const fail = validateAgainstSchema(
            buildRecord({ delegationDepth: 6 }),
            'actionRecord',
        );
        expect(pass.valid).toBe(true);
        expect(fail.valid).toBe(false);
    });
});

// ---------------------------------------------------------------------------
// 5. v0.2.0 actorSignature gate regression (ensure the allOf refactor did not break existing constraints)
// ---------------------------------------------------------------------------
describe('v0.2.0 actorSignature required gate (regression)', () => {
    it('should reject v0.2.0 ActionRecord without actorSignature', () => {
        const record = buildRecord({ specVersion: '0.2.0' });
        delete record.actorSignature;
        const result = validateAgainstSchema(record, 'actionRecord');
        expect(result.valid).toBe(false);
    });

    it('should pass v0.2.0 ActionRecord with actorSignature', () => {
        const record = buildRecord({ specVersion: '0.2.0' });
        const result = validateAgainstSchema(record, 'actionRecord');
        expect(result.valid).toBe(true);
    });

    it('should pass v0.1.0 ActionRecord without actorSignature', () => {
        const record = buildRecord({ specVersion: '0.1.0' });
        delete record.actorSignature;
        const result = validateAgainstSchema(record, 'actionRecord');
        expect(result.valid).toBe(true);
    });
});
