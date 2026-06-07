/**
 * multi-tenant-resolver — L3 unit tests (negative-case defense enforced)
 *
 * Test scope:
 *   1. InMemoryTenantResolver: register + resolve + throw when not registered
 *   2. assertTenantScope: cross-tenant write reject (AUDIT_TENANT_SCOPE_VIOLATION)
 *   3. assertDbRoleMatchesAuditClass: audit_writer_l1 ↔ L1;
 *      audit_writer_l2 ↔ L2/L3; mismatch reject
 */

import { describe, expect, it } from 'vitest';
import { type DID, AuditError, toAuditClass, toTenantId } from '@coivitas/types';
import {
    InMemoryTenantResolver,
    assertDbRoleMatchesAuditClass,
    assertTenantScope,
    type CallerPrincipal,
} from '../multi-tenant-resolver.js';

const TENANT_A = toTenantId('11111111-aaaa-4bbb-8ccc-111111111111');
const TENANT_B = toTenantId('22222222-aaaa-4bbb-8ccc-222222222222');
const DID_ALICE = 'did:key:z6MkAlice' as DID;
const DID_BOB = 'did:key:z6MkBob' as DID;
const DID_UNKNOWN = 'did:key:z6MkUnknown' as DID;

describe('InMemoryTenantResolver — caller → tenant mapping', () => {
    it('should return tenant when caller DID is registered', async () => {
        const resolver = new InMemoryTenantResolver();
        resolver.register(DID_ALICE, TENANT_A);
        const result = await resolver.resolveCallerTenant({
            actorDid: DID_ALICE,
        });
        expect(result).toBe(TENANT_A);
    });

    it('should throw AUDIT_TENANT_SCOPE_VIOLATION when caller DID is not registered (negative-case defense: no default tenant fallback allowed)', async () => {
        const resolver = new InMemoryTenantResolver();
        await expect(
            resolver.resolveCallerTenant({ actorDid: DID_UNKNOWN }),
        ).rejects.toThrow('AUDIT_TENANT_SCOPE_VIOLATION');
    });

    it('should allow re-registering same DID overwriting previous mapping (test convenience)', async () => {
        const resolver = new InMemoryTenantResolver();
        resolver.register(DID_ALICE, TENANT_A);
        resolver.register(DID_ALICE, TENANT_B);
        const result = await resolver.resolveCallerTenant({
            actorDid: DID_ALICE,
        });
        expect(result).toBe(TENANT_B);
    });

    it('should not leak tenant when querying with different actor DID (multi-tenant isolation)', async () => {
        const resolver = new InMemoryTenantResolver();
        resolver.register(DID_ALICE, TENANT_A);
        resolver.register(DID_BOB, TENANT_B);
        const result = await resolver.resolveCallerTenant({
            actorDid: DID_BOB,
        });
        expect(result).toBe(TENANT_B);
        expect(result).not.toBe(TENANT_A);
    });
});

describe('assertTenantScope — cross-tenant write rejection', () => {
    it('should pass when input tenantId equals resolved tenantId', () => {
        expect(() => assertTenantScope(TENANT_A, TENANT_A)).not.toThrow();
    });

    it('should throw AUDIT_TENANT_SCOPE_VIOLATION when input tenantId differs from resolved tenantId', () => {
        expect(() => assertTenantScope(TENANT_A, TENANT_B)).toThrow(
            'AUDIT_TENANT_SCOPE_VIOLATION',
        );
    });

    it('should throw AuditError instance not bare Error when cross-tenant detected', () => {
        try {
            assertTenantScope(TENANT_A, TENANT_B);
        } catch (e) {
            expect(e).toBeInstanceOf(AuditError);
            expect((e as AuditError).code).toBe(
                'AUDIT_TENANT_SCOPE_VIOLATION',
            );
        }
    });
});

describe('assertDbRoleMatchesAuditClass — DB role maps to audit_class', () => {
    it('should pass when dbRole=audit_writer_l1 and auditClass=L1', () => {
        expect(() =>
            assertDbRoleMatchesAuditClass(
                'audit_writer_l1',
                toAuditClass('L1'),
            ),
        ).not.toThrow();
    });

    it('should throw AUDIT_TENANT_SCOPE_VIOLATION when dbRole=audit_writer_l1 but auditClass=L2', () => {
        expect(() =>
            assertDbRoleMatchesAuditClass(
                'audit_writer_l1',
                toAuditClass('L2'),
            ),
        ).toThrow('AUDIT_TENANT_SCOPE_VIOLATION');
    });

    it('should pass when dbRole=audit_writer_l2 and auditClass=L2', () => {
        expect(() =>
            assertDbRoleMatchesAuditClass(
                'audit_writer_l2',
                toAuditClass('L2'),
            ),
        ).not.toThrow();
    });

    it('should pass when dbRole=audit_writer_l2 and auditClass=L3', () => {
        expect(() =>
            assertDbRoleMatchesAuditClass(
                'audit_writer_l2',
                toAuditClass('L3'),
            ),
        ).not.toThrow();
    });

    it('should throw AUDIT_TENANT_SCOPE_VIOLATION when dbRole=audit_writer_l2 but auditClass=L1', () => {
        expect(() =>
            assertDbRoleMatchesAuditClass(
                'audit_writer_l2',
                toAuditClass('L1'),
            ),
        ).toThrow('AUDIT_TENANT_SCOPE_VIOLATION');
    });

    it('should skip enforcement when dbRole is undefined (v0.1 spec backlog)', () => {
        const caller: CallerPrincipal = { actorDid: DID_ALICE };
        expect(() =>
            assertDbRoleMatchesAuditClass(
                caller.dbRole,
                toAuditClass('L1'),
            ),
        ).not.toThrow();
    });
});
