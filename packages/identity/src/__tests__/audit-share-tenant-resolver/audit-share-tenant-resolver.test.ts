/**
 * audit-share-tenant-resolver integration tests
 *
 * Coverage goals (>=95% line coverage + 3 mandatory cases):
 *   1. same tenant ACCEPT (no DelegatedAuditKey required)
 *   2. cross-tenant with a valid DelegatedAuditKey ACCEPT
 *   3. cross-tenant without a DelegatedAuditKey REJECT (fail-closed)
 *   + edge cases: delegator authority mismatch / scope binding mismatch / revoked / expired / policy miss
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
    createAuditShareTenantResolver,
    AuditShareCrossTenantRejectError,
    type AuditKeyLookupPort,
    type PolicyLookupPort,
    type DelegatedAuditKeyRecord,
} from '../../sso/audit-share-tenant-resolver.js';

// ── fixture helpers ──────────────────────────────────────────────────────────

const TENANT_A = 'tenant-a-uuid';
const TENANT_B = 'tenant-b-uuid';
const TENANT_C = 'tenant-c-uuid';
const KEY_ID = 'key-uuid-1234';
const AUDIT_CLASS = 'L2';
const PRINCIPAL_DID = 'did:agent:alpha';
const DELEGATE_DID = 'did:agent:beta';

/** Valid DelegatedAuditKeyRecord (tenant_A -> tenant_B delegation) */
function makeValidKey(overrides: Partial<DelegatedAuditKeyRecord> = {}): DelegatedAuditKeyRecord {
    const validFrom = new Date(Date.now() - 60_000).toISOString(); // 1 min ago
    const validUntil = new Date(Date.now() + 3_600_000).toISOString(); // 1 hr from now
    return {
        auditKeyId: KEY_ID,
        tenantId: TENANT_A,        // delegator = requester tenant
        delegatedFrom: PRINCIPAL_DID,
        delegatedTo: DELEGATE_DID,
        scope: { tenantId: TENANT_B, auditClass: AUDIT_CLASS },
        revoked: false,
        validFrom,
        validUntil,
        ...overrides,
    };
}

/** Create a mock AuditKeyLookupPort */
function makeAuditKeyLookup(key: DelegatedAuditKeyRecord | null): AuditKeyLookupPort {
    return {
        findByAuditKeyId: vi.fn().mockResolvedValue(key),
    };
}

/** Create a mock PolicyLookupPort (authorized by default) */
function makePolicyLookup(found: boolean = true): PolicyLookupPort {
    const record = found
        ? {
              principalDid: PRINCIPAL_DID,
              allowedTenantId: TENANT_B,
              auditClass: AUDIT_CLASS,
              grantedBy: 'admin',
          }
        : null;
    return {
        findPolicy: vi.fn().mockResolvedValue(record),
    };
}

// ── test suite ─────────────────────────────────────────────────────────────────

describe('createAuditShareTenantResolver', () => {
    // ── Case 1: same tenant ACCEPT ──────────────────────────────────────────
    describe('same tenant', () => {
        it('should ACCEPT when requesterTenantId === targetTenantId without DB lookup', async () => {
            const auditKeyLookup = makeAuditKeyLookup(null);
            const policyLookup = makePolicyLookup(false);
            const resolver = createAuditShareTenantResolver({ auditKeyLookup, policyLookup });

            // same tenant — no delegation key required, ACCEPT directly
            await expect(
                resolver.verifyCrossTenantAccess(TENANT_A, TENANT_A, KEY_ID, AUDIT_CLASS),
            ).resolves.toBeUndefined();

            // Step 1 fast-path: DB is not queried
            expect(auditKeyLookup.findByAuditKeyId).not.toHaveBeenCalled();
            expect(policyLookup.findPolicy).not.toHaveBeenCalled();
        });

        it('should ACCEPT same tenant even if auditKeyId is empty string', async () => {
            const auditKeyLookup = makeAuditKeyLookup(null);
            const policyLookup = makePolicyLookup(false);
            const resolver = createAuditShareTenantResolver({ auditKeyLookup, policyLookup });

            await expect(
                resolver.verifyCrossTenantAccess(TENANT_B, TENANT_B, '', AUDIT_CLASS),
            ).resolves.toBeUndefined();

            expect(auditKeyLookup.findByAuditKeyId).not.toHaveBeenCalled();
        });
    });

    // ── Case 2: cross-tenant ACCEPT (valid DelegatedAuditKey + whitelist policy) ──
    describe('cross-tenant ACCEPT — valid DelegatedAuditKey + policy whitelist', () => {
        it('should ACCEPT when DelegatedAuditKey is valid and policy whitelist found', async () => {
            const key = makeValidKey();
            const auditKeyLookup = makeAuditKeyLookup(key);
            const policyLookup = makePolicyLookup(true);
            const resolver = createAuditShareTenantResolver({ auditKeyLookup, policyLookup });

            await expect(
                resolver.verifyCrossTenantAccess(TENANT_A, TENANT_B, KEY_ID, AUDIT_CLASS),
            ).resolves.toBeUndefined();

            // Port invocation verify — anti-phantom: both port methods are called
            expect(auditKeyLookup.findByAuditKeyId).toHaveBeenCalledWith(KEY_ID);
            expect(policyLookup.findPolicy).toHaveBeenCalledWith(
                PRINCIPAL_DID,  // key.delegatedFrom
                TENANT_B,       // targetTenantId
                AUDIT_CLASS,
            );
        });

        it('should ACCEPT cross-tenant with different auditClass in scope', async () => {
            const key = makeValidKey({ scope: { tenantId: TENANT_B, auditClass: 'L3' } });
            const auditKeyLookup = makeAuditKeyLookup(key);
            const policyLookup = makePolicyLookup(true);
            const resolver = createAuditShareTenantResolver({ auditKeyLookup, policyLookup });

            // scope.auditClass is L3 but auditClass param is L3 — policy lookup uses param
            await expect(
                resolver.verifyCrossTenantAccess(TENANT_A, TENANT_B, KEY_ID, 'L3'),
            ).resolves.toBeUndefined();
        });
    });

    // ── Case 3: cross-tenant REJECT — key not found ─────────────────────────
    describe('cross-tenant REJECT — DelegatedAuditKey not found (fail-closed)', () => {
        it('should throw AUDIT_SHARE_CROSS_TENANT_REJECT when key is not found', async () => {
            const auditKeyLookup = makeAuditKeyLookup(null); // key lookup miss
            const policyLookup = makePolicyLookup(false);
            const resolver = createAuditShareTenantResolver({ auditKeyLookup, policyLookup });

            const error = await resolver
                .verifyCrossTenantAccess(TENANT_A, TENANT_B, KEY_ID, AUDIT_CLASS)
                .catch((e: unknown) => e);

            expect(error).toBeInstanceOf(AuditShareCrossTenantRejectError);
            const err = error as AuditShareCrossTenantRejectError;
            expect(err.code).toBe('AUDIT_SHARE_CROSS_TENANT_REJECT');
            expect(err.requesterTenantId).toBe(TENANT_A);
            expect(err.targetTenantId).toBe(TENANT_B);
            expect(err.auditKeyId).toBe(KEY_ID);
            expect(err.message).toContain('not found');

            // policy lookup should NOT be called when key is missing
            expect(policyLookup.findPolicy).not.toHaveBeenCalled();
        });
    });

    // ── Step 3: delegator authority mismatch REJECT ─────────────────────────────
    describe('cross-tenant REJECT — delegator authority mismatch', () => {
        it('should throw AUDIT_SHARE_CROSS_TENANT_REJECT when key.tenantId !== requesterTenantId', async () => {
            // key belongs to TENANT_C, but the requester is TENANT_A -> authority mismatch
            const key = makeValidKey({ tenantId: TENANT_C });
            const auditKeyLookup = makeAuditKeyLookup(key);
            const policyLookup = makePolicyLookup(true);
            const resolver = createAuditShareTenantResolver({ auditKeyLookup, policyLookup });

            const error = await resolver
                .verifyCrossTenantAccess(TENANT_A, TENANT_B, KEY_ID, AUDIT_CLASS)
                .catch((e: unknown) => e);

            expect(error).toBeInstanceOf(AuditShareCrossTenantRejectError);
            const err = error as AuditShareCrossTenantRejectError;
            expect(err.code).toBe('AUDIT_SHARE_CROSS_TENANT_REJECT');
            expect(err.message).toContain(`${TENANT_C}`);
            expect(err.message).toContain(`${TENANT_A}`);
        });
    });

    // ── Step 4: scope binding mismatch REJECT ───────────────────────────────────
    describe('cross-tenant REJECT — scope binding mismatch', () => {
        it('should throw when key.scope.tenantId !== targetTenantId', async () => {
            // scope is bound to TENANT_C, but targetTenantId is TENANT_B -> scope mismatch
            const key = makeValidKey({ scope: { tenantId: TENANT_C, auditClass: AUDIT_CLASS } });
            const auditKeyLookup = makeAuditKeyLookup(key);
            const policyLookup = makePolicyLookup(true);
            const resolver = createAuditShareTenantResolver({ auditKeyLookup, policyLookup });

            const error = await resolver
                .verifyCrossTenantAccess(TENANT_A, TENANT_B, KEY_ID, AUDIT_CLASS)
                .catch((e: unknown) => e);

            expect(error).toBeInstanceOf(AuditShareCrossTenantRejectError);
            const err = error as AuditShareCrossTenantRejectError;
            expect(err.message).toContain(`${TENANT_C}`);
            expect(err.message).toContain(`${TENANT_B}`);

            // policy should NOT be called when scope mismatch
            expect(policyLookup.findPolicy).not.toHaveBeenCalled();
        });
    });

    // ── Step 5: revoked REJECT ───────────────────────────────────────────────
    describe('cross-tenant REJECT — revoked DelegatedAuditKey', () => {
        it('should throw when key is revoked', async () => {
            const key = makeValidKey({ revoked: true });
            const auditKeyLookup = makeAuditKeyLookup(key);
            const policyLookup = makePolicyLookup(true);
            const resolver = createAuditShareTenantResolver({ auditKeyLookup, policyLookup });

            const error = await resolver
                .verifyCrossTenantAccess(TENANT_A, TENANT_B, KEY_ID, AUDIT_CLASS)
                .catch((e: unknown) => e);

            expect(error).toBeInstanceOf(AuditShareCrossTenantRejectError);
            expect((error as AuditShareCrossTenantRejectError).message).toContain('revoked');
            expect(policyLookup.findPolicy).not.toHaveBeenCalled();
        });
    });

    // ── Step 6: validity window REJECT ─────────────────────────────────────
    describe('cross-tenant REJECT — validity window violations', () => {
        it('should throw when key is expired (validUntil in the past)', async () => {
            const expiredUntil = new Date(Date.now() - 3_600_000).toISOString();
            const key = makeValidKey({ validUntil: expiredUntil });
            const auditKeyLookup = makeAuditKeyLookup(key);
            const policyLookup = makePolicyLookup(true);
            const resolver = createAuditShareTenantResolver({ auditKeyLookup, policyLookup });

            const error = await resolver
                .verifyCrossTenantAccess(TENANT_A, TENANT_B, KEY_ID, AUDIT_CLASS)
                .catch((e: unknown) => e);

            expect(error).toBeInstanceOf(AuditShareCrossTenantRejectError);
            expect((error as AuditShareCrossTenantRejectError).message).toContain('validity window');
            expect(policyLookup.findPolicy).not.toHaveBeenCalled();
        });

        it('should throw when now is before validFrom (future key)', async () => {
            const futureFrom = new Date(Date.now() + 3_600_000).toISOString();
            const futureUntil = new Date(Date.now() + 7_200_000).toISOString();
            const key = makeValidKey({ validFrom: futureFrom, validUntil: futureUntil });
            const auditKeyLookup = makeAuditKeyLookup(key);
            const policyLookup = makePolicyLookup(true);

            // getNow injection: fix the current time to be before validFrom
            const fixedNow = new Date(Date.now()); // now < futureFrom
            const resolver = createAuditShareTenantResolver({
                auditKeyLookup,
                policyLookup,
                getNow: () => fixedNow,
            });

            const error = await resolver
                .verifyCrossTenantAccess(TENANT_A, TENANT_B, KEY_ID, AUDIT_CLASS)
                .catch((e: unknown) => e);

            expect(error).toBeInstanceOf(AuditShareCrossTenantRejectError);
            expect((error as AuditShareCrossTenantRejectError).message).toContain('validity window');
        });

        it('should ACCEPT when getNow returns exactly validFrom (boundary inclusive)', async () => {
            const validFrom = new Date(Date.now()).toISOString();
            const validUntil = new Date(Date.now() + 3_600_000).toISOString();
            const key = makeValidKey({ validFrom, validUntil });
            const auditKeyLookup = makeAuditKeyLookup(key);
            const policyLookup = makePolicyLookup(true);

            // getNow at exactly validFrom
            const fixedNow = new Date(validFrom);
            const resolver = createAuditShareTenantResolver({
                auditKeyLookup,
                policyLookup,
                getNow: () => fixedNow,
            });

            await expect(
                resolver.verifyCrossTenantAccess(TENANT_A, TENANT_B, KEY_ID, AUDIT_CLASS),
            ).resolves.toBeUndefined();
        });
    });

    // ── Step 7: policy whitelist miss REJECT ────────────────────────────────
    describe('cross-tenant REJECT — policy whitelist miss', () => {
        it('should throw when tenant_audit_share_policy not found (no whitelist entry)', async () => {
            const key = makeValidKey();
            const auditKeyLookup = makeAuditKeyLookup(key);
            const policyLookup = makePolicyLookup(false); // no policy
            const resolver = createAuditShareTenantResolver({ auditKeyLookup, policyLookup });

            const error = await resolver
                .verifyCrossTenantAccess(TENANT_A, TENANT_B, KEY_ID, AUDIT_CLASS)
                .catch((e: unknown) => e);

            expect(error).toBeInstanceOf(AuditShareCrossTenantRejectError);
            const err = error as AuditShareCrossTenantRejectError;
            expect(err.code).toBe('AUDIT_SHARE_CROSS_TENANT_REJECT');
            expect(err.message).toContain('No tenant_audit_share_policy found');
            expect(err.message).toContain(PRINCIPAL_DID);
            expect(err.message).toContain(TENANT_B);
        });
    });

    // ── error class structure verification ─────────────────────────────────────────────────
    describe('AuditShareCrossTenantRejectError structure', () => {
        it('should have correct code + name + public fields', () => {
            const err = new AuditShareCrossTenantRejectError(
                TENANT_A,
                TENANT_B,
                KEY_ID,
                'test reason',
            );

            expect(err.code).toBe('AUDIT_SHARE_CROSS_TENANT_REJECT');
            expect(err.name).toBe('AuditShareCrossTenantRejectError');
            expect(err.requesterTenantId).toBe(TENANT_A);
            expect(err.targetTenantId).toBe(TENANT_B);
            expect(err.auditKeyId).toBe(KEY_ID);
            expect(err.message).toContain('test reason');
            expect(err.message).toContain('AUDIT_SHARE_CROSS_TENANT_REJECT');
            expect(err).toBeInstanceOf(Error);
        });

        it('should include null auditKeyId in message', () => {
            const err = new AuditShareCrossTenantRejectError(
                TENANT_A,
                TENANT_B,
                null,
                'reason',
            );
            expect(err.auditKeyId).toBeNull();
            expect(err.message).toContain('null');
        });
    });

    // ── getNow injection tests ────────────────────────────────────────────────
    describe('getNow injection', () => {
        it('should use custom getNow for validity window check', async () => {
            const key = makeValidKey();
            const auditKeyLookup = makeAuditKeyLookup(key);
            const policyLookup = makePolicyLookup(true);

            // inject a fixed time (within the validity window)
            const fixedNow = new Date(Date.now() + 100);
            const getNow = vi.fn(() => fixedNow);
            const resolver = createAuditShareTenantResolver({ auditKeyLookup, policyLookup, getNow });

            await expect(
                resolver.verifyCrossTenantAccess(TENANT_A, TENANT_B, KEY_ID, AUDIT_CLASS),
            ).resolves.toBeUndefined();

            expect(getNow).toHaveBeenCalledOnce();
        });
    });

    // ── port invocation order verification (anti-phantom) ──────────────────────────────
    describe('port invocation order — anti-phantom', () => {
        it('should call auditKeyLookup before policyLookup in cross-tenant path', async () => {
            const callOrder: string[] = [];
            const key = makeValidKey();

            const auditKeyLookup: AuditKeyLookupPort = {
                findByAuditKeyId: vi.fn().mockImplementation(async () => {
                    callOrder.push('auditKeyLookup');
                    return key;
                }),
            };
            const policyLookup: PolicyLookupPort = {
                findPolicy: vi.fn().mockImplementation(async () => {
                    callOrder.push('policyLookup');
                    return {
                        principalDid: PRINCIPAL_DID,
                        allowedTenantId: TENANT_B,
                        auditClass: AUDIT_CLASS,
                        grantedBy: 'admin',
                    };
                }),
            };

            const resolver = createAuditShareTenantResolver({ auditKeyLookup, policyLookup });
            await resolver.verifyCrossTenantAccess(TENANT_A, TENANT_B, KEY_ID, AUDIT_CLASS);

            expect(callOrder).toEqual(['auditKeyLookup', 'policyLookup']);
        });
    });
});
