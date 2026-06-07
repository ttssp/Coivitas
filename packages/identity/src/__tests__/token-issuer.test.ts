import { describe, expect, it } from 'vitest';

import { canonicalize, generateKeyPair, verify } from '@coivitas/crypto';
import type {
    Capability,
    CapabilityToken,
    DID,
    Timestamp,
} from '@coivitas/types';

import {
    delegateCapabilityToken,
    didKeyFromPublicKey,
    issueCapabilityToken,
    validateAttenuation,
    verifyCapabilityToken,
} from '../index.js';

// ─── Shared test helpers ─────────────────────────────────────────────────────────────
function makeIssuer() {
    const kp = generateKeyPair();
    const did = didKeyFromPublicKey(Buffer.from(kp.publicKey, 'hex'));
    return { ...kp, did };
}

const AGENT_DID_1 = 'did:agent:aabbccddee112233445566778899aabbccddeeff' as DID;
const AGENT_DID_2 = 'did:agent:bbccddee11223344556677889900aabbccddeeff' as DID;
const AGENT_DID_3 = 'did:agent:ccddee1122334455667788990011aabbccddeeff' as DID;

function makeRootToken(
    issuer: ReturnType<typeof makeIssuer>,
    caps: Capability[],
    issuedTo?: DID,
): CapabilityToken {
    return issueCapabilityToken({
        issuerDid: issuer.did,
        issuedTo: issuedTo ?? AGENT_DID_1,
        capabilities: caps,
        expiresAt: '2030-01-01T00:00:00.000Z' as Timestamp,
        revocationUrl: 'https://revocation.example.com/v1/{id}',
        issuerPrivateKey: issuer.privateKey,
        issuedAt: '2026-01-01T00:00:00.000Z' as Timestamp,
    });
}

const allowlistCap = (values: string[]): Capability => ({
    action: 'INQUIRY',
    scope: { type: 'allowlist', field: 'category', values },
});

const numericCap = (max: number): Capability => ({
    action: 'TRANSFER',
    scope: { type: 'numeric_limit', field: 'amount', max, currency: 'CNY' },
});

// ─── validateAttenuation ──────────────────────────────────────────────────────
describe('validateAttenuation', () => {
    it('should return true when child allowlist is subset of parent', () => {
        const parent: Capability[] = [
            allowlistCap(['electronics', 'books', 'toys']),
        ];
        const child: Capability[] = [allowlistCap(['electronics', 'books'])];
        expect(validateAttenuation(parent, child)).toBe(true);
    });

    it('should return false when child allowlist introduces value not in parent', () => {
        const parent: Capability[] = [allowlistCap(['electronics'])];
        const child: Capability[] = [allowlistCap(['electronics', 'books'])];
        expect(validateAttenuation(parent, child)).toBe(false);
    });

    it('should return true when child numeric_limit max is less than or equal to parent', () => {
        const parent: Capability[] = [numericCap(1000)];
        const child: Capability[] = [numericCap(500)];
        expect(validateAttenuation(parent, child)).toBe(true);
    });

    it('should return false when child numeric_limit max exceeds parent', () => {
        const parent: Capability[] = [numericCap(500)];
        const child: Capability[] = [numericCap(1000)];
        expect(validateAttenuation(parent, child)).toBe(false);
    });

    it('should return false when child introduces action not in parent (rule 2c via action subset)', () => {
        const parent: Capability[] = [allowlistCap(['a'])];
        const child: Capability[] = [allowlistCap(['a']), numericCap(100)];
        // child action TRANSFER not in parent → rule 1 violation
        expect(validateAttenuation(parent, child)).toBe(false);
    });

    it('should return false when parent scope dimension is missing in child (rule 2a)', () => {
        // parent has allowlist + numeric; child only has allowlist
        const parent: Capability[] = [
            {
                action: 'INQUIRY',
                scope: { type: 'allowlist', field: 'cat', values: ['a'] },
            },
            {
                action: 'INQUIRY',
                scope: { type: 'numeric_limit', field: 'count', max: 10 },
            },
        ];
        const child: Capability[] = [
            {
                action: 'INQUIRY',
                scope: { type: 'allowlist', field: 'cat', values: ['a'] },
            },
        ];
        expect(validateAttenuation(parent, child)).toBe(false);
    });

    it('should return false when child introduces new dimension not in parent (rule 2c)', () => {
        // parent has allowlist only; child adds numeric_limit
        const parent: Capability[] = [
            {
                action: 'INQUIRY',
                scope: { type: 'allowlist', field: 'cat', values: ['a'] },
            },
        ];
        const child: Capability[] = [
            {
                action: 'INQUIRY',
                scope: { type: 'allowlist', field: 'cat', values: ['a'] },
            },
            {
                action: 'INQUIRY',
                scope: { type: 'numeric_limit', field: 'count', max: 10 },
            },
        ];
        expect(validateAttenuation(parent, child)).toBe(false);
    });

    it('should return AttenuationResult { ok: true } in structured-result mode when valid', () => {
        const parent: Capability[] = [allowlistCap(['a', 'b'])];
        const child: Capability[] = [allowlistCap(['a'])];
        const result = validateAttenuation(parent, child, {
            parentSpecVersion: '0.1.0',
            childSpecVersion: '0.1.0',
        });
        expect(result).toEqual({ ok: true });
    });

    it('should return AttenuationResult { ok: false } with detail in structured-result mode on violation', () => {
        const parent: Capability[] = [allowlistCap(['a'])];
        const child: Capability[] = [allowlistCap(['a', 'b'])];
        const result = validateAttenuation(parent, child, {
            parentSpecVersion: '0.1.0',
            childSpecVersion: '0.1.0',
        });
        expect(result).toMatchObject({ ok: false, mixedVersion: false });
        if (!('ok' in result) || result.ok) throw new Error('Expected failure');
        expect(result.detail).toMatchObject({
            rule: 'allowlist_violation',
            field: 'category',
        });
    });

    it('should return mixedVersion true when 0.1.0 child drops temporal_scope from 0.2.0 parent (rule 2a)', () => {
        const parent: Capability[] = [
            {
                action: 'INQUIRY',
                scope: { type: 'allowlist', field: 'cat', values: ['a'] },
            },
            {
                action: 'INQUIRY',
                scope: {
                    type: 'temporal_scope',
                    notBefore: '2026-01-01T00:00:00.000Z' as Timestamp,
                    notAfter: '2030-01-01T00:00:00.000Z' as Timestamp,
                },
            },
        ];
        const child: Capability[] = [
            {
                action: 'INQUIRY',
                scope: { type: 'allowlist', field: 'cat', values: ['a'] },
            },
        ];
        const result = validateAttenuation(parent, child, {
            parentSpecVersion: '0.2.0',
            childSpecVersion: '0.1.0',
        });
        expect(result).toMatchObject({ ok: false, mixedVersion: true });
    });

    it('should return mixedVersion true when 0.2.0 child introduces temporal_scope into 0.1.0 parent (rule 2c)', () => {
        const parent: Capability[] = [
            {
                action: 'INQUIRY',
                scope: { type: 'allowlist', field: 'cat', values: ['a'] },
            },
        ];
        const child: Capability[] = [
            {
                action: 'INQUIRY',
                scope: { type: 'allowlist', field: 'cat', values: ['a'] },
            },
            {
                action: 'INQUIRY',
                scope: {
                    type: 'temporal_scope',
                    notBefore: '2026-01-01T00:00:00.000Z' as Timestamp,
                    notAfter: '2027-01-01T00:00:00.000Z' as Timestamp,
                },
            },
        ];
        const result = validateAttenuation(parent, child, {
            parentSpecVersion: '0.1.0',
            childSpecVersion: '0.2.0',
        });
        expect(result).toMatchObject({ ok: false, mixedVersion: true });
    });

    it('should return ok=true when child capabilities are empty (all actions dropped is valid attenuation)', () => {
        // : child can drop actions entirely; empty child = all actions dropped = valid subset
        // application-level guards (delegateCapabilityToken) enforce at least 1 cap separately
        const parent: Capability[] = [allowlistCap(['a'])];
        const result = validateAttenuation(parent, [], {
            parentSpecVersion: '0.1.0',
            childSpecVersion: '0.1.0',
        });
        expect(result).toEqual({ ok: true });
    });

    it('should handle temporal_scope notBefore/notAfter subset check', () => {
        const makeTemporalCap = (nb: string, na: string): Capability => ({
            action: 'READ',
            scope: {
                type: 'temporal_scope',
                notBefore: nb as Timestamp,
                notAfter: na as Timestamp,
            },
        });
        // child range within parent range → ok
        expect(
            validateAttenuation(
                [
                    makeTemporalCap(
                        '2026-01-01T00:00:00.000Z',
                        '2030-01-01T00:00:00.000Z',
                    ),
                ],
                [
                    makeTemporalCap(
                        '2027-01-01T00:00:00.000Z',
                        '2029-01-01T00:00:00.000Z',
                    ),
                ],
            ),
        ).toBe(true);
        // child notBefore earlier than parent → fail
        expect(
            validateAttenuation(
                [
                    makeTemporalCap(
                        '2027-01-01T00:00:00.000Z',
                        '2030-01-01T00:00:00.000Z',
                    ),
                ],
                [
                    makeTemporalCap(
                        '2026-01-01T00:00:00.000Z',
                        '2030-01-01T00:00:00.000Z',
                    ),
                ],
            ),
        ).toBe(false);
        // child notAfter later than parent → fail
        expect(
            validateAttenuation(
                [
                    makeTemporalCap(
                        '2026-01-01T00:00:00.000Z',
                        '2029-01-01T00:00:00.000Z',
                    ),
                ],
                [
                    makeTemporalCap(
                        '2026-01-01T00:00:00.000Z',
                        '2030-01-01T00:00:00.000Z',
                    ),
                ],
            ),
        ).toBe(false);
    });

    it('should pass when child temporal recurringWindow is subset of parent window', () => {
        const parentCap: Capability = {
            action: 'READ',
            scope: {
                type: 'temporal_scope',
                notBefore: '2026-01-01T00:00:00.000Z' as Timestamp,
                notAfter: '2030-01-01T00:00:00.000Z' as Timestamp,
                recurringWindow: {
                    startTime: '08:00',
                    endTime: '20:00',
                    timezone: 'UTC',
                },
            },
        };
        const childCap: Capability = {
            action: 'READ',
            scope: {
                type: 'temporal_scope',
                notBefore: '2026-01-01T00:00:00.000Z' as Timestamp,
                notAfter: '2030-01-01T00:00:00.000Z' as Timestamp,
                recurringWindow: {
                    startTime: '10:00',
                    endTime: '18:00',
                    timezone: 'UTC',
                },
            },
        };
        expect(validateAttenuation([parentCap], [childCap])).toBe(true);
    });

    it('should return false when allowlist field mismatch (child scope field differs from parent)', () => {
        // allowlist with same type but different field → treated as different dimension (rule 2c)
        const parent: Capability[] = [
            {
                action: 'INQUIRY',
                scope: { type: 'allowlist', field: 'category', values: ['a'] },
            },
        ];
        const child: Capability[] = [
            {
                action: 'INQUIRY',
                scope: { type: 'allowlist', field: 'status', values: ['a'] },
            },
        ];
        // child has dim "allowlist:status" not in parent (has "allowlist:category") → rule 2c
        expect(validateAttenuation(parent, child)).toBe(false);
    });

    it('should return false when numeric_limit field mismatch in isScopeSubset', () => {
        // Same action, both have numeric_limit but same key "numeric_limit:amount" vs "numeric_limit:count"
        // parent: numeric_limit:amount, child: numeric_limit:count → rule 2c triggers (child has new dim)
        const parent: Capability[] = [
            {
                action: 'TRANSFER',
                scope: { type: 'numeric_limit', field: 'amount', max: 1000 },
            },
        ];
        const child: Capability[] = [
            {
                action: 'TRANSFER',
                scope: { type: 'numeric_limit', field: 'count', max: 5 },
            },
        ];
        // child dim "numeric_limit:count" not in parent → rule 2c
        expect(validateAttenuation(parent, child)).toBe(false);
    });

    it('should handle cumulative_limit scope subset check (valid, same window)', () => {
        // : window must be exactly equal; child with same window but lower max → ok
        const parentCap: Capability = {
            action: 'TRANSFER',
            scope: {
                type: 'cumulative_limit',
                meterField: { source: 'action_record', metric: 'amount' },
                max: 10000,
                window: 'day',
                currency: 'CNY',
            },
        };
        const childCap: Capability = {
            action: 'TRANSFER',
            scope: {
                type: 'cumulative_limit',
                meterField: { source: 'action_record', metric: 'amount' },
                max: 5000,
                window: 'day',
                currency: 'CNY',
            },
        };
        expect(validateAttenuation([parentCap], [childCap])).toBe(true);
    });

    it('should return false when cumulative_limit child window differs from parent (strict equality)', () => {
        // : month→day is NOT a subset — different windows cannot guarantee limit adherence
        const parentCap: Capability = {
            action: 'TRANSFER',
            scope: {
                type: 'cumulative_limit',
                meterField: { source: 'action_record', metric: 'amount' },
                max: 10000,
                window: 'month',
                currency: 'CNY',
            },
        };
        const childCap: Capability = {
            action: 'TRANSFER',
            scope: {
                type: 'cumulative_limit',
                meterField: { source: 'action_record', metric: 'amount' },
                max: 5000,
                window: 'day',
                currency: 'CNY',
            },
        };
        expect(validateAttenuation([parentCap], [childCap])).toBe(false);
    });

    it('should return false when cumulative_limit child max exceeds parent', () => {
        const parentCap: Capability = {
            action: 'TRANSFER',
            scope: {
                type: 'cumulative_limit',
                meterField: { source: 'action_record', metric: 'amount' },
                max: 1000,
                window: 'day',
                currency: 'CNY',
            },
        };
        const childCap: Capability = {
            action: 'TRANSFER',
            scope: {
                type: 'cumulative_limit',
                meterField: { source: 'action_record', metric: 'amount' },
                max: 2000,
                window: 'day',
                currency: 'CNY',
            },
        };
        expect(validateAttenuation([parentCap], [childCap])).toBe(false);
    });

    it('should return false when cumulative_limit child window is wider than parent', () => {
        const parentCap: Capability = {
            action: 'TRANSFER',
            scope: {
                type: 'cumulative_limit',
                meterField: { source: 'action_record', metric: 'amount' },
                max: 10000,
                window: 'day',
                currency: 'CNY',
            },
        };
        const childCap: Capability = {
            action: 'TRANSFER',
            scope: {
                type: 'cumulative_limit',
                meterField: { source: 'action_record', metric: 'amount' },
                max: 5000,
                window: 'month', // wider window → violation
                currency: 'CNY',
            },
        };
        expect(validateAttenuation([parentCap], [childCap])).toBe(false);
    });

    it('should return false when cumulative_limit child meterField metric differs', () => {
        const parentCap: Capability = {
            action: 'TRANSFER',
            scope: {
                type: 'cumulative_limit',
                meterField: { source: 'action_record', metric: 'amount' },
                max: 10000,
                window: 'day',
                currency: 'CNY',
            },
        };
        const childCap: Capability = {
            action: 'TRANSFER',
            scope: {
                type: 'cumulative_limit',
                meterField: { source: 'action_record', metric: 'count' }, // different metric
                max: 50,
                window: 'day',
                currency: 'CNY',
            },
        };
        // child dim key "cumulative_limit:count" not in parent "cumulative_limit:amount" → rule 2c
        expect(validateAttenuation([parentCap], [childCap])).toBe(false);
    });

    it('should return false when cumulative_limit child currency differs from parent', () => {
        const parentCap: Capability = {
            action: 'TRANSFER',
            scope: {
                type: 'cumulative_limit',
                meterField: { source: 'action_record', metric: 'amount' },
                max: 10000,
                window: 'day',
                currency: 'CNY',
            },
        };
        const childCap: Capability = {
            action: 'TRANSFER',
            scope: {
                type: 'cumulative_limit',
                meterField: { source: 'action_record', metric: 'amount' },
                max: 5000,
                window: 'day',
                currency: 'USD', // different currency
            },
        };
        expect(validateAttenuation([parentCap], [childCap])).toBe(false);
    });

    it('should return false when cumulative_limit same metric but meterField unit differs (deepEquals check)', () => {
        // same metric (same scopeMatchKey) but different meterField unit → deepEquals fails
        const parentCap: Capability = {
            action: 'TRANSFER',
            scope: {
                type: 'cumulative_limit',
                meterField: {
                    source: 'action_record',
                    metric: 'amount',
                    unit: 'CNY',
                },
                max: 10000,
                window: 'day',
            },
        };
        const childCap: Capability = {
            action: 'TRANSFER',
            scope: {
                type: 'cumulative_limit',
                meterField: {
                    source: 'action_record',
                    metric: 'amount',
                    unit: 'USD',
                },
                max: 5000,
                window: 'day',
            },
        };
        expect(validateAttenuation([parentCap], [childCap])).toBe(false);
    });

    it('should pass when temporal_scope child has recurringWindow but parent does not', () => {
        const parentCap: Capability = {
            action: 'READ',
            scope: {
                type: 'temporal_scope',
                notBefore: '2026-01-01T00:00:00.000Z' as Timestamp,
                notAfter: '2030-01-01T00:00:00.000Z' as Timestamp,
                // no recurringWindow
            },
        };
        const childCap: Capability = {
            action: 'READ',
            scope: {
                type: 'temporal_scope',
                notBefore: '2026-01-01T00:00:00.000Z' as Timestamp,
                notAfter: '2030-01-01T00:00:00.000Z' as Timestamp,
                recurringWindow: {
                    startTime: '09:00',
                    endTime: '17:00',
                    timezone: 'UTC',
                },
            },
        };
        // child is more restrictive (has window) → subset → ok
        expect(validateAttenuation([parentCap], [childCap])).toBe(true);
    });

    it('should handle cross-midnight recurring window subset check', () => {
        // parent: 22:00-06:00 (cross-midnight), child: 23:00-05:00 (subset)
        const parentCap: Capability = {
            action: 'READ',
            scope: {
                type: 'temporal_scope',
                notBefore: '2026-01-01T00:00:00.000Z' as Timestamp,
                notAfter: '2030-01-01T00:00:00.000Z' as Timestamp,
                recurringWindow: {
                    startTime: '22:00',
                    endTime: '06:00',
                    timezone: 'UTC',
                },
            },
        };
        const childCap: Capability = {
            action: 'READ',
            scope: {
                type: 'temporal_scope',
                notBefore: '2026-01-01T00:00:00.000Z' as Timestamp,
                notAfter: '2030-01-01T00:00:00.000Z' as Timestamp,
                recurringWindow: {
                    startTime: '23:00',
                    endTime: '05:00',
                    timezone: 'UTC',
                },
            },
        };
        expect(validateAttenuation([parentCap], [childCap])).toBe(true);
    });

    it('should handle daysOfWeek subset check (child days are subset of parent days)', () => {
        const parentCap: Capability = {
            action: 'READ',
            scope: {
                type: 'temporal_scope',
                notBefore: '2026-01-01T00:00:00.000Z' as Timestamp,
                notAfter: '2030-01-01T00:00:00.000Z' as Timestamp,
                recurringWindow: {
                    startTime: '09:00',
                    endTime: '17:00',
                    timezone: 'UTC',
                    daysOfWeek: [1, 2, 3, 4, 5], // Mon-Fri
                },
            },
        };
        const childCap: Capability = {
            action: 'READ',
            scope: {
                type: 'temporal_scope',
                notBefore: '2026-01-01T00:00:00.000Z' as Timestamp,
                notAfter: '2030-01-01T00:00:00.000Z' as Timestamp,
                recurringWindow: {
                    startTime: '10:00',
                    endTime: '16:00',
                    timezone: 'UTC',
                    daysOfWeek: [1, 2, 3], // Mon-Wed subset of Mon-Fri
                },
            },
        };
        expect(validateAttenuation([parentCap], [childCap])).toBe(true);
    });

    it('should return false when child daysOfWeek extends beyond parent daysOfWeek', () => {
        const parentCap: Capability = {
            action: 'READ',
            scope: {
                type: 'temporal_scope',
                notBefore: '2026-01-01T00:00:00.000Z' as Timestamp,
                notAfter: '2030-01-01T00:00:00.000Z' as Timestamp,
                recurringWindow: {
                    startTime: '09:00',
                    endTime: '17:00',
                    timezone: 'UTC',
                    daysOfWeek: [1, 2, 3], // Mon-Wed
                },
            },
        };
        const childCap: Capability = {
            action: 'READ',
            scope: {
                type: 'temporal_scope',
                notBefore: '2026-01-01T00:00:00.000Z' as Timestamp,
                notAfter: '2030-01-01T00:00:00.000Z' as Timestamp,
                recurringWindow: {
                    startTime: '10:00',
                    endTime: '16:00',
                    timezone: 'UTC',
                    daysOfWeek: [1, 2, 3, 4, 5], // Mon-Fri → violates Mon-Wed parent
                },
            },
        };
        expect(validateAttenuation([parentCap], [childCap])).toBe(false);
    });

    it('should fail when child temporal recurringWindow extends beyond parent window', () => {
        const parentCap: Capability = {
            action: 'READ',
            scope: {
                type: 'temporal_scope',
                notBefore: '2026-01-01T00:00:00.000Z' as Timestamp,
                notAfter: '2030-01-01T00:00:00.000Z' as Timestamp,
                recurringWindow: {
                    startTime: '10:00',
                    endTime: '18:00',
                    timezone: 'UTC',
                },
            },
        };
        const childCap: Capability = {
            action: 'READ',
            scope: {
                type: 'temporal_scope',
                notBefore: '2026-01-01T00:00:00.000Z' as Timestamp,
                notAfter: '2030-01-01T00:00:00.000Z' as Timestamp,
                recurringWindow: {
                    startTime: '08:00',
                    endTime: '20:00',
                    timezone: 'UTC',
                },
            },
        };
        expect(validateAttenuation([parentCap], [childCap])).toBe(false);
    });

    // valid action drop should be allowed
    it('should return true when child drops an action entirely (valid attenuation)', () => {
        const parent: Capability[] = [
            allowlistCap(['a', 'b']),
            numericCap(1000),
        ];
        // child drops TRANSFER entirely — this is valid (narrowing scope)
        const child: Capability[] = [allowlistCap(['a'])];
        expect(validateAttenuation(parent, child)).toBe(true);
    });

    it('should return true in structured-result mode when child drops an action entirely', () => {
        const parent: Capability[] = [
            allowlistCap(['a', 'b']),
            numericCap(1000),
        ];
        const child: Capability[] = [allowlistCap(['a'])];
        const result = validateAttenuation(parent, child, {
            parentSpecVersion: '0.1.0',
            childSpecVersion: '0.1.0',
        });
        expect(result).toEqual({ ok: true });
    });

    // parent has recurringWindow but child omits it → violation
    it('should return false when parent has recurringWindow but child does not', () => {
        const parentCap: Capability = {
            action: 'READ',
            scope: {
                type: 'temporal_scope',
                notBefore: '2026-01-01T00:00:00.000Z' as Timestamp,
                notAfter: '2030-01-01T00:00:00.000Z' as Timestamp,
                recurringWindow: {
                    startTime: '09:00',
                    endTime: '17:00',
                    timezone: 'UTC',
                },
            },
        };
        const childCap: Capability = {
            action: 'READ',
            scope: {
                type: 'temporal_scope',
                notBefore: '2026-01-01T00:00:00.000Z' as Timestamp,
                notAfter: '2030-01-01T00:00:00.000Z' as Timestamp,
                // no recurringWindow: child is unrestricted within notBefore/notAfter → violates subset
            },
        };
        expect(validateAttenuation([parentCap], [childCap])).toBe(false);
    });

    // timezone mismatch in recurringWindow → violation (scope-extensions)
    it('should return false when child recurringWindow timezone differs from parent', () => {
        const parentCap: Capability = {
            action: 'READ',
            scope: {
                type: 'temporal_scope',
                notBefore: '2026-01-01T00:00:00.000Z' as Timestamp,
                notAfter: '2030-01-01T00:00:00.000Z' as Timestamp,
                recurringWindow: {
                    startTime: '09:00',
                    endTime: '17:00',
                    timezone: 'UTC',
                },
            },
        };
        const childCap: Capability = {
            action: 'READ',
            scope: {
                type: 'temporal_scope',
                notBefore: '2026-01-01T00:00:00.000Z' as Timestamp,
                notAfter: '2030-01-01T00:00:00.000Z' as Timestamp,
                recurringWindow: {
                    startTime: '09:00',
                    endTime: '17:00',
                    timezone: 'Asia/Shanghai',
                },
            },
        };
        expect(validateAttenuation([parentCap], [childCap])).toBe(false);
    });

    // ─── silent dimension overwrite + empty allowlist + mixed dimensions ─────────────────────────

    // Background: attenuation builds childDimMap /
    // parentDimMap with Map.set, so when two scopes with the same scopeMatchKey
    // appear under one action the earlier one is silently overwritten, letting the
    // strictest scope be replaced by a looser one (a malicious parent token can make
    // the child broader than the parent under AND semantics). The spec requires
    // fail-closed: reject duplicated dimensions outright, with a schema-layer
    // uniqueItems constraint plus a runtime-layer double safeguard.

    describe('duplicate dimension fail-closed', () => {
        it('rejects parent capabilities containing duplicated allowlist dimension on the same action', () => {
            // Two allowlist:category under one action, simulating a malicious parent token: the second
            // one looks strict (['a']), but if parentDimMap uses Map.set and is then overwritten by a
            // third (['a','b','c']), the semantics of "parent=['a']" are broken. fail-closed requires an
            // outright reject.
            const parent: Capability[] = [
                {
                    action: 'INQUIRY',
                    scope: {
                        type: 'allowlist',
                        field: 'category',
                        values: ['a'],
                    },
                },
                {
                    action: 'INQUIRY',
                    scope: {
                        type: 'allowlist',
                        field: 'category',
                        values: ['a', 'b', 'c'],
                    },
                },
            ];
            const child: Capability[] = [
                {
                    action: 'INQUIRY',
                    scope: {
                        type: 'allowlist',
                        field: 'category',
                        values: ['a'],
                    },
                },
            ];
            expect(validateAttenuation(parent, child)).toBe(false);
        });

        it('rejects child capabilities containing duplicated allowlist dimension on the same action', () => {
            // child duplicates the same dimension: fail-closed disallows out-of-schema "spread authorization"
            const parent: Capability[] = [
                {
                    action: 'INQUIRY',
                    scope: {
                        type: 'allowlist',
                        field: 'category',
                        values: ['a', 'b', 'c'],
                    },
                },
            ];
            const child: Capability[] = [
                {
                    action: 'INQUIRY',
                    scope: {
                        type: 'allowlist',
                        field: 'category',
                        values: ['a'],
                    },
                },
                {
                    action: 'INQUIRY',
                    scope: {
                        type: 'allowlist',
                        field: 'category',
                        values: ['b'],
                    },
                },
            ];
            expect(validateAttenuation(parent, child)).toBe(false);
        });

        it('rejects duplicated numeric_limit on same (action, field)', () => {
            const parent: Capability[] = [
                {
                    action: 'TRANSFER',
                    scope: { type: 'numeric_limit', field: 'amount', max: 100 },
                },
                {
                    action: 'TRANSFER',
                    scope: {
                        type: 'numeric_limit',
                        field: 'amount',
                        max: 1000,
                    },
                },
            ];
            const child: Capability[] = [
                {
                    action: 'TRANSFER',
                    scope: { type: 'numeric_limit', field: 'amount', max: 50 },
                },
            ];
            expect(validateAttenuation(parent, child)).toBe(false);
        });

        it('rejects duplicated cumulative_limit on same (action, metric)', () => {
            const parent: Capability[] = [
                {
                    action: 'TRANSFER',
                    scope: {
                        type: 'cumulative_limit',
                        meterField: {
                            source: 'action_record',
                            metric: 'amount',
                        },
                        max: 1000,
                        window: 'day',
                        currency: 'CNY',
                    },
                },
                {
                    action: 'TRANSFER',
                    scope: {
                        type: 'cumulative_limit',
                        meterField: {
                            source: 'action_record',
                            metric: 'amount',
                        },
                        max: 10000,
                        window: 'day',
                        currency: 'CNY',
                    },
                },
            ];
            const child: Capability[] = [
                {
                    action: 'TRANSFER',
                    scope: {
                        type: 'cumulative_limit',
                        meterField: {
                            source: 'action_record',
                            metric: 'amount',
                        },
                        max: 500,
                        window: 'day',
                        currency: 'CNY',
                    },
                },
            ];
            expect(validateAttenuation(parent, child)).toBe(false);
        });

        it('rejects duplicated temporal_scope on same action (single-instance dimension)', () => {
            const parent: Capability[] = [
                {
                    action: 'READ',
                    scope: {
                        type: 'temporal_scope',
                        notBefore: '2026-01-01T00:00:00.000Z' as Timestamp,
                        notAfter: '2027-01-01T00:00:00.000Z' as Timestamp,
                    },
                },
                {
                    action: 'READ',
                    scope: {
                        type: 'temporal_scope',
                        notBefore: '2026-01-01T00:00:00.000Z' as Timestamp,
                        notAfter: '2030-01-01T00:00:00.000Z' as Timestamp,
                    },
                },
            ];
            const child: Capability[] = [
                {
                    action: 'READ',
                    scope: {
                        type: 'temporal_scope',
                        notBefore: '2026-01-01T00:00:00.000Z' as Timestamp,
                        notAfter: '2027-01-01T00:00:00.000Z' as Timestamp,
                    },
                },
            ];
            expect(validateAttenuation(parent, child)).toBe(false);
        });

        it('returns structured detail rule "duplicate_dimension" in phase2 mode', () => {
            const parent: Capability[] = [
                {
                    action: 'INQUIRY',
                    scope: {
                        type: 'allowlist',
                        field: 'category',
                        values: ['a'],
                    },
                },
                {
                    action: 'INQUIRY',
                    scope: {
                        type: 'allowlist',
                        field: 'category',
                        values: ['a', 'b'],
                    },
                },
            ];
            const child: Capability[] = [
                {
                    action: 'INQUIRY',
                    scope: {
                        type: 'allowlist',
                        field: 'category',
                        values: ['a'],
                    },
                },
            ];
            const result = validateAttenuation(parent, child, {
                parentSpecVersion: '0.1.0',
                childSpecVersion: '0.1.0',
            });
            expect(result).toMatchObject({ ok: false });
            if (!('ok' in result) || result.ok)
                throw new Error('Expected failure');
            expect(result.detail).toMatchObject({
                rule: 'duplicate_dimension',
            });
        });
    });

    describe('empty allowlist fail-closed', () => {
        it('rejects parent allowlist with empty values array', () => {
            // An empty parent allowlist = "authorize zero items", a dead token on issuance; fail-fast reject
            const parent: Capability[] = [
                {
                    action: 'INQUIRY',
                    scope: { type: 'allowlist', field: 'category', values: [] },
                },
            ];
            const child: Capability[] = [
                {
                    action: 'INQUIRY',
                    scope: { type: 'allowlist', field: 'category', values: [] },
                },
            ];
            expect(validateAttenuation(parent, child)).toBe(false);
        });

        it('rejects child allowlist with empty values array', () => {
            const parent: Capability[] = [
                {
                    action: 'INQUIRY',
                    scope: {
                        type: 'allowlist',
                        field: 'category',
                        values: ['a', 'b'],
                    },
                },
            ];
            const child: Capability[] = [
                {
                    action: 'INQUIRY',
                    scope: { type: 'allowlist', field: 'category', values: [] },
                },
            ];
            expect(validateAttenuation(parent, child)).toBe(false);
        });
    });

    describe('mixed-dimension attenuation', () => {
        // A capability set containing allowlist + temporal + cumulative at once
        const mixedParent: Capability[] = [
            {
                action: 'TRANSFER',
                scope: {
                    type: 'allowlist',
                    field: 'category',
                    values: ['retail', 'b2b', 'wholesale'],
                },
            },
            {
                action: 'TRANSFER',
                scope: {
                    type: 'temporal_scope',
                    notBefore: '2026-01-01T00:00:00.000Z' as Timestamp,
                    notAfter: '2030-01-01T00:00:00.000Z' as Timestamp,
                },
            },
            {
                action: 'TRANSFER',
                scope: {
                    type: 'cumulative_limit',
                    meterField: { source: 'action_record', metric: 'amount' },
                    max: 100000,
                    window: 'day',
                    currency: 'CNY',
                },
            },
        ];

        it('passes when all three dimensions narrow simultaneously', () => {
            const child: Capability[] = [
                {
                    action: 'TRANSFER',
                    scope: {
                        type: 'allowlist',
                        field: 'category',
                        values: ['retail'],
                    },
                },
                {
                    action: 'TRANSFER',
                    scope: {
                        type: 'temporal_scope',
                        notBefore: '2027-01-01T00:00:00.000Z' as Timestamp,
                        notAfter: '2029-01-01T00:00:00.000Z' as Timestamp,
                    },
                },
                {
                    action: 'TRANSFER',
                    scope: {
                        type: 'cumulative_limit',
                        meterField: {
                            source: 'action_record',
                            metric: 'amount',
                        },
                        max: 50000,
                        window: 'day',
                        currency: 'CNY',
                    },
                },
            ];
            expect(validateAttenuation(mixedParent, child)).toBe(true);
        });

        it('rejects when allowlist dimension violates while others narrow correctly', () => {
            const child: Capability[] = [
                {
                    action: 'TRANSFER',
                    scope: {
                        type: 'allowlist',
                        field: 'category',
                        values: ['retail', 'enterprise'],
                    },
                }, // 'enterprise' exceeds the parent
                {
                    action: 'TRANSFER',
                    scope: {
                        type: 'temporal_scope',
                        notBefore: '2027-01-01T00:00:00.000Z' as Timestamp,
                        notAfter: '2029-01-01T00:00:00.000Z' as Timestamp,
                    },
                },
                {
                    action: 'TRANSFER',
                    scope: {
                        type: 'cumulative_limit',
                        meterField: {
                            source: 'action_record',
                            metric: 'amount',
                        },
                        max: 50000,
                        window: 'day',
                        currency: 'CNY',
                    },
                },
            ];
            expect(validateAttenuation(mixedParent, child)).toBe(false);
        });

        it('rejects when temporal dimension violates while others narrow correctly', () => {
            const child: Capability[] = [
                {
                    action: 'TRANSFER',
                    scope: {
                        type: 'allowlist',
                        field: 'category',
                        values: ['retail'],
                    },
                },
                {
                    action: 'TRANSFER',
                    scope: {
                        type: 'temporal_scope',
                        notBefore: '2025-06-01T00:00:00.000Z' as Timestamp, // earlier than the parent notBefore
                        notAfter: '2029-01-01T00:00:00.000Z' as Timestamp,
                    },
                },
                {
                    action: 'TRANSFER',
                    scope: {
                        type: 'cumulative_limit',
                        meterField: {
                            source: 'action_record',
                            metric: 'amount',
                        },
                        max: 50000,
                        window: 'day',
                        currency: 'CNY',
                    },
                },
            ];
            expect(validateAttenuation(mixedParent, child)).toBe(false);
        });

        it('rejects when cumulative dimension violates while others narrow correctly', () => {
            const child: Capability[] = [
                {
                    action: 'TRANSFER',
                    scope: {
                        type: 'allowlist',
                        field: 'category',
                        values: ['retail'],
                    },
                },
                {
                    action: 'TRANSFER',
                    scope: {
                        type: 'temporal_scope',
                        notBefore: '2027-01-01T00:00:00.000Z' as Timestamp,
                        notAfter: '2029-01-01T00:00:00.000Z' as Timestamp,
                    },
                },
                {
                    action: 'TRANSFER',
                    scope: {
                        type: 'cumulative_limit',
                        meterField: {
                            source: 'action_record',
                            metric: 'amount',
                        },
                        max: 200000, // exceeds the parent max
                        window: 'day',
                        currency: 'CNY',
                    },
                },
            ];
            expect(validateAttenuation(mixedParent, child)).toBe(false);
        });

        it('rejects when child drops one of the three required dimensions (rule 2a)', () => {
            // child keeps only allowlist + cumulative, missing temporal_scope
            const child: Capability[] = [
                {
                    action: 'TRANSFER',
                    scope: {
                        type: 'allowlist',
                        field: 'category',
                        values: ['retail'],
                    },
                },
                {
                    action: 'TRANSFER',
                    scope: {
                        type: 'cumulative_limit',
                        meterField: {
                            source: 'action_record',
                            metric: 'amount',
                        },
                        max: 50000,
                        window: 'day',
                        currency: 'CNY',
                    },
                },
            ];
            expect(validateAttenuation(mixedParent, child)).toBe(false);
        });
    });

    // ─── follow-up review regressions ──────────────────────────────────
    describe('follow-up review regressions', () => {
        // parent restricts daysOfWeek, child provides recurringWindow but omits daysOfWeek.
        // The previous implementation's "if (child.daysOfWeek !== undefined)" short-circuit made the
        // child equivalent to "available every day" — broadening authorization outright.
        it('should reject delegation when parent has daysOfWeek and child omits daysOfWeek', () => {
            const parentCap: Capability = {
                action: 'READ',
                scope: {
                    type: 'temporal_scope',
                    notBefore: '2026-01-01T00:00:00.000Z' as Timestamp,
                    notAfter: '2030-01-01T00:00:00.000Z' as Timestamp,
                    recurringWindow: {
                        startTime: '09:00',
                        endTime: '17:00',
                        timezone: 'UTC',
                        daysOfWeek: [1, 2, 3, 4, 5],
                    },
                },
            };
            const childCap: Capability = {
                action: 'READ',
                scope: {
                    type: 'temporal_scope',
                    notBefore: '2026-01-01T00:00:00.000Z' as Timestamp,
                    notAfter: '2030-01-01T00:00:00.000Z' as Timestamp,
                    recurringWindow: {
                        startTime: '09:00',
                        endTime: '17:00',
                        timezone: 'UTC',
                        // daysOfWeek omitted -> every day -> violates the parent weekdays restriction
                    },
                },
            };
            expect(validateAttenuation([parentCap], [childCap])).toBe(false);
        });

        // parent defines currency=CNY, child omits currency.
        // The previous implementation's "c.currency !== undefined && c.currency !== p.currency"
        // short-circuit made the child equivalent to "any currency" — broadening authorization outright.
        // The spec requires strict equality.
        it('should reject delegation when parent has currency and child omits currency', () => {
            const parentCap: Capability = {
                action: 'TRANSFER',
                scope: {
                    type: 'cumulative_limit',
                    meterField: { source: 'action_record', metric: 'amount' },
                    max: 50000,
                    window: 'day',
                    currency: 'CNY',
                },
            };
            const childCap: Capability = {
                action: 'TRANSFER',
                scope: {
                    type: 'cumulative_limit',
                    meterField: { source: 'action_record', metric: 'amount' },
                    max: 30000,
                    window: 'day',
                    // currency omitted -> loses the currency constraint -> violates the subset
                },
            };
            expect(validateAttenuation([parentCap], [childCap])).toBe(false);
        });

        // allow the "same metric, different window" combination.
        // Previously scopeMatchKey encoded only the metric -> this combination was wrongly rejected as duplicate_dimension.
        it('should accept parent with two cumulative_limit scopes for same metric and different windows (daily + monthly)', () => {
            const parent: Capability[] = [
                {
                    action: 'TRANSFER',
                    scope: {
                        type: 'cumulative_limit',
                        meterField: {
                            source: 'action_record',
                            metric: 'amount',
                        },
                        max: 50000,
                        window: 'day',
                        currency: 'CNY',
                    },
                },
                {
                    action: 'TRANSFER',
                    scope: {
                        type: 'cumulative_limit',
                        meterField: {
                            source: 'action_record',
                            metric: 'amount',
                        },
                        max: 1000000,
                        window: 'month',
                        currency: 'CNY',
                    },
                },
            ];
            // child subset (keeps both entries and tightens both maxes)
            const child: Capability[] = [
                {
                    action: 'TRANSFER',
                    scope: {
                        type: 'cumulative_limit',
                        meterField: {
                            source: 'action_record',
                            metric: 'amount',
                        },
                        max: 30000,
                        window: 'day',
                        currency: 'CNY',
                    },
                },
                {
                    action: 'TRANSFER',
                    scope: {
                        type: 'cumulative_limit',
                        meterField: {
                            source: 'action_record',
                            metric: 'amount',
                        },
                        max: 500000,
                        window: 'month',
                        currency: 'CNY',
                    },
                },
            ];
            expect(validateAttenuation(parent, child)).toBe(true);
        });
    });
});

// ─── delegateCapabilityToken ──────────────────────────────────────────────────
describe('delegateCapabilityToken', () => {
    it('should issue a valid single-hop child token when child is DID subset', () => {
        const issuer = makeIssuer();
        const delegatorKp = generateKeyPair();
        const rootToken = makeRootToken(
            issuer,
            [allowlistCap(['a', 'b', 'c'])],
            AGENT_DID_1,
        );

        const child = delegateCapabilityToken({
            parentToken: rootToken,
            delegatorPrivateKey: delegatorKp.privateKey,
            delegateeDid: AGENT_DID_2,
            attenuatedCapabilities: [allowlistCap(['a'])],
            expiresAt: '2029-01-01T00:00:00.000Z' as Timestamp,
            revocationUrl: 'https://revocation.example.com/v1/{id}',
            issuedAt: '2026-06-01T00:00:00.000Z' as Timestamp,
        });

        expect(child.issuedTo).toBe(AGENT_DID_2);
        expect(child.issuerDid).toBe(issuer.did);
        expect(child.principalDid).toBe(issuer.did);
        expect(child.specVersion).toBe('0.2.0');
        expect(child.delegationChain).toHaveLength(1);
        expect(child.delegationChain![0]!.delegateeDid).toBe(AGENT_DID_2);
        expect(child.delegationChain![0]!.parentTokenId).toBe(rootToken.id);
    });

    it('should produce a two-hop chain when delegating from child token', () => {
        const issuer = makeIssuer();
        const agent1Kp = generateKeyPair();
        const agent2Kp = generateKeyPair();
        const rootToken = makeRootToken(
            issuer,
            [allowlistCap(['a', 'b'])],
            AGENT_DID_1,
        );

        const child1 = delegateCapabilityToken({
            parentToken: rootToken,
            delegatorPrivateKey: agent1Kp.privateKey,
            delegateeDid: AGENT_DID_2,
            attenuatedCapabilities: [allowlistCap(['a', 'b'])],
            expiresAt: '2029-01-01T00:00:00.000Z' as Timestamp,
            revocationUrl: 'https://revocation.example.com/v1/{id}',
            issuedAt: '2026-06-01T00:00:00.000Z' as Timestamp,
        });

        const child2 = delegateCapabilityToken({
            parentToken: child1,
            delegatorPrivateKey: agent2Kp.privateKey,
            delegateeDid: AGENT_DID_3,
            attenuatedCapabilities: [allowlistCap(['a'])],
            expiresAt: '2028-01-01T00:00:00.000Z' as Timestamp,
            revocationUrl: 'https://revocation.example.com/v1/{id}',
            issuedAt: '2026-06-01T00:00:00.000Z' as Timestamp,
        });

        expect(child2.delegationChain).toHaveLength(2);
        expect(child2.delegationChain![1]!.delegateeDid).toBe(AGENT_DID_3);
    });

    it('should throw SCOPE_EXCEEDED when attenuated capabilities violate attenuation (action not in parent)', () => {
        const issuer = makeIssuer();
        const delegatorKp = generateKeyPair();
        const rootToken = makeRootToken(
            issuer,
            [allowlistCap(['a'])],
            AGENT_DID_1,
        );

        expect(() =>
            delegateCapabilityToken({
                parentToken: rootToken,
                delegatorPrivateKey: delegatorKp.privateKey,
                delegateeDid: AGENT_DID_2,
                attenuatedCapabilities: [numericCap(100)], // TRANSFER not in parent
                expiresAt: '2029-01-01T00:00:00.000Z' as Timestamp,
                revocationUrl: 'https://revocation.example.com/v1/{id}',
                issuedAt: '2026-06-01T00:00:00.000Z' as Timestamp,
            }),
        ).toThrow('[SCOPE_EXCEEDED]');
    });

    it('should throw SCOPE_EXCEEDED when child allowlist exceeds parent allowlist', () => {
        const issuer = makeIssuer();
        const delegatorKp = generateKeyPair();
        const rootToken = makeRootToken(
            issuer,
            [allowlistCap(['a'])],
            AGENT_DID_1,
        );

        expect(() =>
            delegateCapabilityToken({
                parentToken: rootToken,
                delegatorPrivateKey: delegatorKp.privateKey,
                delegateeDid: AGENT_DID_2,
                attenuatedCapabilities: [allowlistCap(['a', 'b'])],
                expiresAt: '2029-01-01T00:00:00.000Z' as Timestamp,
                revocationUrl: 'https://revocation.example.com/v1/{id}',
                issuedAt: '2026-06-01T00:00:00.000Z' as Timestamp,
            }),
        ).toThrow('[SCOPE_EXCEEDED]');
    });

    it('should throw SCOPE_EXCEEDED when child numeric_limit exceeds parent', () => {
        const issuer = makeIssuer();
        const delegatorKp = generateKeyPair();
        const rootToken = makeRootToken(issuer, [numericCap(500)], AGENT_DID_1);

        expect(() =>
            delegateCapabilityToken({
                parentToken: rootToken,
                delegatorPrivateKey: delegatorKp.privateKey,
                delegateeDid: AGENT_DID_2,
                attenuatedCapabilities: [numericCap(1000)],
                expiresAt: '2029-01-01T00:00:00.000Z' as Timestamp,
                revocationUrl: 'https://revocation.example.com/v1/{id}',
                issuedAt: '2026-06-01T00:00:00.000Z' as Timestamp,
            }),
        ).toThrow('[SCOPE_EXCEEDED]');
    });

    it('should throw SCOPE_EXCEEDED when delegation chain depth would exceed MAX_DELEGATION_DEPTH', () => {
        const issuer = makeIssuer();
        const delegatorKp = generateKeyPair();

        // Build a token with 5 existing delegationChain entries (at max depth already)
        const rootToken = makeRootToken(
            issuer,
            [allowlistCap(['a'])],
            AGENT_DID_1,
        );
        // Inject a fake chain of depth 5 to simulate the limit
        const fakeChain = Array.from({ length: 5 }, (_, i) => ({
            parentTokenId: `urn:cap:fake-${i}`,
            delegatorDid: AGENT_DID_1,
            delegateeDid: AGENT_DID_2,
            parentCapabilities: [allowlistCap(['a'])],
            parentExpiresAt: '2030-01-01T00:00:00.000Z' as Timestamp,
            attenuatedCapabilities: [allowlistCap(['a'])],
            proof: rootToken.proof, // reuse proof structure for test purposes
        }));
        const deepToken: CapabilityToken = {
            ...rootToken,
            delegationChain: fakeChain,
        };

        expect(() =>
            delegateCapabilityToken({
                parentToken: deepToken,
                delegatorPrivateKey: delegatorKp.privateKey,
                delegateeDid: AGENT_DID_2,
                attenuatedCapabilities: [allowlistCap(['a'])],
                expiresAt: '2029-01-01T00:00:00.000Z' as Timestamp,
                revocationUrl: 'https://revocation.example.com/v1/{id}',
                issuedAt: '2026-06-01T00:00:00.000Z' as Timestamp,
            }),
        ).toThrow('[SCOPE_EXCEEDED]');
    });

    it('should throw TOKEN_EXPIRED when child expiresAt exceeds parent expiresAt', () => {
        const issuer = makeIssuer();
        const delegatorKp = generateKeyPair();
        const rootToken = makeRootToken(
            issuer,
            [allowlistCap(['a'])],
            AGENT_DID_1,
        );
        // rootToken.expiresAt = 2030-01-01; child tries 2031
        expect(() =>
            delegateCapabilityToken({
                parentToken: rootToken,
                delegatorPrivateKey: delegatorKp.privateKey,
                delegateeDid: AGENT_DID_2,
                attenuatedCapabilities: [allowlistCap(['a'])],
                expiresAt: '2031-01-01T00:00:00.000Z' as Timestamp,
                revocationUrl: 'https://revocation.example.com/v1/{id}',
                issuedAt: '2026-06-01T00:00:00.000Z' as Timestamp,
            }),
        ).toThrow('[TOKEN_EXPIRED]');
    });

    it('should throw IDENTITY_NOT_FOUND when delegateeDid is not did:agent:', () => {
        const issuer = makeIssuer();
        const delegatorKp = generateKeyPair();
        const rootToken = makeRootToken(
            issuer,
            [allowlistCap(['a'])],
            AGENT_DID_1,
        );

        expect(() =>
            delegateCapabilityToken({
                parentToken: rootToken,
                delegatorPrivateKey: delegatorKp.privateKey,
                delegateeDid: issuer.did as unknown as DID, // did:key: not did:agent:
                attenuatedCapabilities: [allowlistCap(['a'])],
                expiresAt: '2029-01-01T00:00:00.000Z' as Timestamp,
                revocationUrl: 'https://revocation.example.com/v1/{id}',
                issuedAt: '2026-06-01T00:00:00.000Z' as Timestamp,
            }),
        ).toThrow('[IDENTITY_NOT_FOUND]');
    });

    it('should throw SCOPE_EXCEEDED when attenuated capabilities are empty', () => {
        const issuer = makeIssuer();
        const delegatorKp = generateKeyPair();
        const rootToken = makeRootToken(
            issuer,
            [allowlistCap(['a'])],
            AGENT_DID_1,
        );

        expect(() =>
            delegateCapabilityToken({
                parentToken: rootToken,
                delegatorPrivateKey: delegatorKp.privateKey,
                delegateeDid: AGENT_DID_2,
                attenuatedCapabilities: [],
                expiresAt: '2029-01-01T00:00:00.000Z' as Timestamp,
                revocationUrl: 'https://revocation.example.com/v1/{id}',
                issuedAt: '2026-06-01T00:00:00.000Z' as Timestamp,
            }),
        ).toThrow('[SCOPE_EXCEEDED]');
    });

    it('should throw TOKEN_EXPIRED when child expiresAt is not later than issuedAt', () => {
        const issuer = makeIssuer();
        const delegatorKp = generateKeyPair();
        const rootToken = makeRootToken(
            issuer,
            [allowlistCap(['a'])],
            AGENT_DID_1,
        );

        expect(() =>
            delegateCapabilityToken({
                parentToken: rootToken,
                delegatorPrivateKey: delegatorKp.privateKey,
                delegateeDid: AGENT_DID_2,
                attenuatedCapabilities: [allowlistCap(['a'])],
                expiresAt: '2026-01-01T00:00:00.000Z' as Timestamp, // same as issuedAt
                revocationUrl: 'https://revocation.example.com/v1/{id}',
                issuedAt: '2026-06-01T00:00:00.000Z' as Timestamp,
            }),
        ).toThrow('[TOKEN_EXPIRED]');
    });

    it('should throw INTERNAL_ERROR when revocationUrl is invalid in delegateCapabilityToken', () => {
        const issuer = makeIssuer();
        const delegatorKp = generateKeyPair();
        const rootToken = makeRootToken(
            issuer,
            [allowlistCap(['a'])],
            AGENT_DID_1,
        );

        expect(() =>
            delegateCapabilityToken({
                parentToken: rootToken,
                delegatorPrivateKey: delegatorKp.privateKey,
                delegateeDid: AGENT_DID_2,
                attenuatedCapabilities: [allowlistCap(['a'])],
                expiresAt: '2029-01-01T00:00:00.000Z' as Timestamp,
                revocationUrl: 'not-a-url/{id}', // invalid
                issuedAt: '2026-06-01T00:00:00.000Z' as Timestamp,
            }),
        ).toThrow('[INTERNAL_ERROR]');
    });

    it('should produce a child token whose DelegationProof signature is verifiable', () => {
        const issuer = makeIssuer();
        const delegatorKp = generateKeyPair();
        const rootToken = makeRootToken(
            issuer,
            [allowlistCap(['a', 'b'])],
            AGENT_DID_1,
        );

        const child = delegateCapabilityToken({
            parentToken: rootToken,
            delegatorPrivateKey: delegatorKp.privateKey,
            delegateeDid: AGENT_DID_2,
            attenuatedCapabilities: [allowlistCap(['a'])],
            expiresAt: '2029-01-01T00:00:00.000Z' as Timestamp,
            revocationUrl: 'https://revocation.example.com/v1/{id}',
            issuedAt: '2026-06-01T00:00:00.000Z' as Timestamp,
        });

        const proof = child.delegationChain![0]!;
        const { proof: proofField, ...payload } = proof;

        // Rebuild the signing bytes (matching delegateCapabilityToken's internal logic)
        const payloadBytes = new TextEncoder().encode(
            canonicalize(payload as unknown as Record<string, unknown>),
        );
        const isValid = verify(
            payloadBytes,
            proofField.value,
            delegatorKp.publicKey,
        );
        expect(isValid).toBe(true);
    });

    // ─── follow-up review regression ──────────────────────────────────────────
    // Previously delegateCapabilityToken called validateAttenuation with 2 args, making the
    // mixedVersion guard dead code: when a 0.1.0 parent token is attenuated into a 0.2.0 child
    // token, the child could inject a versioned scope (temporal_scope/cumulative_limit) on the same
    // action — scopes the 0.1.0 verifier cannot see -> silent authorization broadening. This test
    // introduces a valid 0.1.0 parent + valid 0.1.0 subset (sharing action 'TRANSFER'), then has the
    // child separately append a temporal_scope to trigger the rule 2c + isMixed path, ensuring the
    // delegation is rejected at issuance.
    it('should throw SCOPE_EXCEEDED with mixedVersion detail when parent specVersion is 0.1.0 and child introduces a versioned scope', () => {
        const issuer = makeIssuer();
        const delegatorKp = generateKeyPair();
        // parent = 0.1.0 (issueCapabilityToken defaults to SPEC_VERSION='0.1.0')
        const rootToken = makeRootToken(
            issuer,
            [
                {
                    action: 'TRANSFER',
                    scope: {
                        type: 'numeric_limit',
                        field: 'amount',
                        max: 1000,
                        currency: 'CNY',
                    },
                },
            ],
            AGENT_DID_1,
        );
        expect(rootToken.specVersion).toBe('0.1.0');

        // Child attempts to introduce a versioned scope (temporal_scope) on the same action 'TRANSFER'
        // — constituting rule 2c "child introduces a new dimension the parent lacks". Combined with
        // parent=0.1.0 / child=0.2.0, this should trigger the mixedVersion path, throwing SCOPE_EXCEEDED
        // with the mixedVersion marker in detail/message.
        expect(() =>
            delegateCapabilityToken({
                parentToken: rootToken,
                delegatorPrivateKey: delegatorKp.privateKey,
                delegateeDid: AGENT_DID_2,
                attenuatedCapabilities: [
                    {
                        action: 'TRANSFER',
                        scope: {
                            type: 'numeric_limit',
                            field: 'amount',
                            max: 500,
                            currency: 'CNY',
                        },
                    },
                    {
                        action: 'TRANSFER',
                        scope: {
                            type: 'temporal_scope',
                            notBefore: '2026-01-01T00:00:00.000Z' as Timestamp,
                            notAfter: '2028-01-01T00:00:00.000Z' as Timestamp,
                        },
                    },
                ],
                expiresAt: '2027-01-01T00:00:00.000Z' as Timestamp,
                revocationUrl: 'https://revocation.example.com/v1/{id}',
                issuedAt: '2026-06-01T00:00:00.000Z' as Timestamp,
            }),
        ).toThrow(/Mixed-version delegation rejected/);
    });
});

describe('issueCapabilityToken', () => {
    it('should throw SIGNATURE_INVALID when issuerDid is not did:key', () => {
        const issuer = generateKeyPair();
        expect(() =>
            issueCapabilityToken({
                issuerDid: AGENT_DID_1 as unknown as ReturnType<
                    typeof makeIssuer
                >['did'],
                issuedTo: AGENT_DID_2,
                capabilities: [allowlistCap(['a'])],
                expiresAt: '2030-01-01T00:00:00.000Z' as Timestamp,
                revocationUrl: 'https://revocation.example.com/v1/{id}',
                issuerPrivateKey: issuer.privateKey,
                issuedAt: '2026-01-01T00:00:00.000Z' as Timestamp,
            }),
        ).toThrow('[SIGNATURE_INVALID]');
    });

    it('should throw IDENTITY_NOT_FOUND when issuedTo is not did:agent', () => {
        const issuer = makeIssuer();
        expect(() =>
            issueCapabilityToken({
                issuerDid: issuer.did,
                issuedTo: issuer.did as unknown as typeof AGENT_DID_1,
                capabilities: [allowlistCap(['a'])],
                expiresAt: '2030-01-01T00:00:00.000Z' as Timestamp,
                revocationUrl: 'https://revocation.example.com/v1/{id}',
                issuerPrivateKey: issuer.privateKey,
                issuedAt: '2026-01-01T00:00:00.000Z' as Timestamp,
            }),
        ).toThrow('[IDENTITY_NOT_FOUND]');
    });

    it('should throw INTERNAL_ERROR when revocationUrl is a malformed string that fails URL parsing', () => {
        const issuer = makeIssuer();
        // URL that contains {id} but is not a valid URL (e.g., no scheme) — triggers catch block
        expect(() =>
            issueCapabilityToken({
                issuerDid: issuer.did,
                issuedTo: AGENT_DID_1,
                capabilities: [allowlistCap(['a'])],
                expiresAt: '2030-01-01T00:00:00.000Z' as Timestamp,
                revocationUrl: 'not-a-url/{id}',
                issuerPrivateKey: issuer.privateKey,
                issuedAt: '2026-01-01T00:00:00.000Z' as Timestamp,
            }),
        ).toThrow('[INTERNAL_ERROR]');
    });

    it('issues a signed capability token that verifies successfully', () => {
        const issuer = generateKeyPair();
        const issuerDid = didKeyFromPublicKey(
            Buffer.from(issuer.publicKey, 'hex'),
        );
        const issuedTo =
            'did:agent:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0' as DID;

        const token = issueCapabilityToken({
            issuerDid,
            issuedTo,
            capabilities: [
                {
                    action: 'INQUIRY',
                    scope: {
                        type: 'allowlist',
                        field: 'product_category',
                        values: ['electronics'],
                    },
                },
            ],
            expiresAt: '2026-04-22T10:00:00.000Z' as Timestamp,
            revocationUrl: 'https://revocation.example.com/v1/{id}',
            issuerPrivateKey: issuer.privateKey,
            issuedAt: '2026-04-21T10:00:00.000Z' as Timestamp,
        });

        expect(token.id).toMatch(/^urn:cap:[0-9a-f-]{36}$/);
        expect(token.principalDid).toBe(issuerDid);
        expect(token.proof.verificationMethod).toBe(`${issuerDid}#key-1`);
        expect(
            verifyCapabilityToken(
                token,
                '2026-04-21T10:00:01.000Z' as Timestamp,
            ),
        ).toEqual({
            valid: true,
        });
    });

    it('rejects empty capabilities', () => {
        const issuer = generateKeyPair();
        const issuerDid = didKeyFromPublicKey(
            Buffer.from(issuer.publicKey, 'hex'),
        );

        expect(() =>
            issueCapabilityToken({
                issuerDid,
                issuedTo:
                    'did:agent:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0' as DID,
                capabilities: [],
                expiresAt: '2026-04-22T10:00:00.000Z' as Timestamp,
                revocationUrl: 'https://revocation.example.com/v1/{id}',
                issuerPrivateKey: issuer.privateKey,
                issuedAt: '2026-04-21T10:00:00.000Z' as Timestamp,
            }),
        ).toThrow('[SCOPE_EXCEEDED]');
    });

    it('rejects past expiry timestamps', () => {
        const issuer = generateKeyPair();
        const issuerDid = didKeyFromPublicKey(
            Buffer.from(issuer.publicKey, 'hex'),
        );

        expect(() =>
            issueCapabilityToken({
                issuerDid,
                issuedTo:
                    'did:agent:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0' as DID,
                capabilities: [
                    {
                        action: 'INQUIRY',
                        scope: {
                            type: 'allowlist',
                            field: 'product_category',
                            values: ['electronics'],
                        },
                    },
                ],
                expiresAt: '2026-04-20T10:00:00.000Z' as Timestamp,
                revocationUrl: 'https://revocation.example.com/v1/{id}',
                issuerPrivateKey: issuer.privateKey,
                issuedAt: '2026-04-21T10:00:00.000Z' as Timestamp,
            }),
        ).toThrow('[TOKEN_EXPIRED]');
    });

    it('rejects malformed revocation URL templates', () => {
        const issuer = generateKeyPair();
        const issuerDid = didKeyFromPublicKey(
            Buffer.from(issuer.publicKey, 'hex'),
        );

        expect(() =>
            issueCapabilityToken({
                issuerDid,
                issuedTo:
                    'did:agent:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0' as DID,
                capabilities: [
                    {
                        action: 'INQUIRY',
                        scope: {
                            type: 'allowlist',
                            field: 'product_category',
                            values: ['electronics'],
                        },
                    },
                ],
                expiresAt: '2026-04-22T10:00:00.000Z' as Timestamp,
                revocationUrl: 'https://revocation.example.com/v1/list',
                issuerPrivateKey: issuer.privateKey,
                issuedAt: '2026-04-21T10:00:00.000Z' as Timestamp,
            }),
        ).toThrow('[INTERNAL_ERROR]');
    });
});
