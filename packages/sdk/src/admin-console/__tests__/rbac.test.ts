/**
 * Admin Console RBAC tests
 *
 * Coverage:
 *   - parseAdminRole: valid / invalid / missing role → fail-closed
 *   - getRoleFromRequest: X-Role header parsing + case handling
 *   - hasPermission: permission-matrix completeness
 *   - requirePermission: insufficient permission → AdminRbacError fail-closed
 *   - RBAC does not allow default-allow / passing by default when role is absent (fail-closed invariant)
 *   - fail-closed invariant grep test: rbac.ts + types.ts do not contain bypassTenant / skipAuth / adminGlobalAccess
 *
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { resolve, dirname } from 'node:path';
import {
    parseAdminRole,
    AdminRbacError,
    ROLE_PERMISSIONS,
} from '../types.js';
import {
    getRoleFromRequest,
    hasPermission,
    requirePermission,
} from '../rbac.js';
import type { AdminPermission } from '../types.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

// ── parseAdminRole ────────────────────────────────────────────────────────────

describe('parseAdminRole — should parse valid roles and reject invalid', () => {
    it('should return admin when X-Role is "admin"', () => {
        expect(parseAdminRole('admin')).toBe('admin');
    });

    it('should return tenant-admin when X-Role is "tenant-admin"', () => {
        expect(parseAdminRole('tenant-admin')).toBe('tenant-admin');
    });

    it('should return viewer when X-Role is "viewer"', () => {
        expect(parseAdminRole('viewer')).toBe('viewer');
    });

    it('should normalize case: "ADMIN" → "admin"', () => {
        expect(parseAdminRole('ADMIN')).toBe('admin');
    });

    it('should throw AdminRbacError ADMIN_ROLE_MISSING when role is undefined', () => {
        expect(() => parseAdminRole(undefined)).toThrowError(AdminRbacError);
        try {
            parseAdminRole(undefined);
        } catch (err) {
            expect(err instanceof AdminRbacError).toBe(true);
            expect((err as AdminRbacError).code).toBe('ADMIN_ROLE_MISSING');
        }
    });

    it('should throw AdminRbacError ADMIN_ROLE_MISSING when role is empty string', () => {
        expect(() => parseAdminRole('')).toThrowError(AdminRbacError);
        try {
            parseAdminRole('');
        } catch (err) {
            expect((err as AdminRbacError).code).toBe('ADMIN_ROLE_MISSING');
        }
    });

    it('should throw AdminRbacError ADMIN_ROLE_UNKNOWN when role is unknown', () => {
        expect(() => parseAdminRole('superuser')).toThrowError(AdminRbacError);
        try {
            parseAdminRole('superuser');
        } catch (err) {
            expect(err instanceof AdminRbacError).toBe(true);
            expect((err as AdminRbacError).code).toBe('ADMIN_ROLE_UNKNOWN');
        }
    });

    it('should throw AdminRbacError ADMIN_ROLE_UNKNOWN when role is "god-mode"', () => {
        expect(() => parseAdminRole('god-mode')).toThrowError(AdminRbacError);
    });
});

// ── getRoleFromRequest ────────────────────────────────────────────────────────

describe('getRoleFromRequest — should extract AdminRole from X-Role header', () => {
    it('should return admin when X-Role header is "admin"', () => {
        const role = getRoleFromRequest({ headers: { 'x-role': 'admin' } });
        expect(role).toBe('admin');
    });

    it('should return tenant-admin when X-Role header is "tenant-admin"', () => {
        const role = getRoleFromRequest({ headers: { 'x-role': 'tenant-admin' } });
        expect(role).toBe('tenant-admin');
    });

    it('should be case-insensitive for X-Role header name', () => {
        const role = getRoleFromRequest({ headers: { 'X-Role': 'viewer' } });
        expect(role).toBe('viewer');
    });

    it('should throw AdminRbacError ADMIN_ROLE_MISSING when X-Role header is absent', () => {
        expect(() => getRoleFromRequest({ headers: {} })).toThrowError(AdminRbacError);
        try {
            getRoleFromRequest({ headers: {} });
        } catch (err) {
            expect((err as AdminRbacError).code).toBe('ADMIN_ROLE_MISSING');
        }
    });

    it('should throw AdminRbacError ADMIN_ROLE_UNKNOWN when X-Role is unknown value', () => {
        expect(() => getRoleFromRequest({ headers: { 'x-role': 'manager' } })).toThrowError(AdminRbacError);
    });
});

// ── ROLE_PERMISSIONS permission matrix ─────────────────────────────────────────────────

describe('ROLE_PERMISSIONS — should have correct permission matrix', () => {
    it('should grant admin all 8 permissions', () => {
        const adminPerms = ROLE_PERMISSIONS['admin'];
        const allPerms: AdminPermission[] = [
            'tenant:list', 'tenant:get', 'tenant:update', 'tenant:delete',
            'policy:list', 'policy:get', 'policy:update', 'policy:delete',
        ];
        for (const perm of allPerms) {
            expect(adminPerms.has(perm)).toBe(true);
        }
    });

    it('should deny admin tenant:delete in tenant-admin role', () => {
        const tenantAdminPerms = ROLE_PERMISSIONS['tenant-admin'];
        expect(tenantAdminPerms.has('tenant:delete')).toBe(false);
        expect(tenantAdminPerms.has('policy:delete')).toBe(false);
    });

    it('should grant tenant-admin read+write but not delete', () => {
        const perms = ROLE_PERMISSIONS['tenant-admin'];
        expect(perms.has('tenant:list')).toBe(true);
        expect(perms.has('tenant:get')).toBe(true);
        expect(perms.has('tenant:update')).toBe(true);
        expect(perms.has('policy:list')).toBe(true);
        expect(perms.has('policy:get')).toBe(true);
        expect(perms.has('policy:update')).toBe(true);
    });

    it('should grant viewer only list+get permissions', () => {
        const perms = ROLE_PERMISSIONS['viewer'];
        expect(perms.has('tenant:list')).toBe(true);
        expect(perms.has('tenant:get')).toBe(true);
        expect(perms.has('tenant:update')).toBe(false);
        expect(perms.has('tenant:delete')).toBe(false);
        expect(perms.has('policy:list')).toBe(true);
        expect(perms.has('policy:get')).toBe(true);
        expect(perms.has('policy:update')).toBe(false);
        expect(perms.has('policy:delete')).toBe(false);
    });
});

// ── hasPermission ─────────────────────────────────────────────────────────────

describe('hasPermission — should return boolean without throwing', () => {
    it('should return true for admin tenant:delete', () => {
        expect(hasPermission('admin', 'tenant:delete')).toBe(true);
    });

    it('should return false for viewer tenant:update', () => {
        expect(hasPermission('viewer', 'tenant:update')).toBe(false);
    });

    it('should return false for tenant-admin tenant:delete', () => {
        expect(hasPermission('tenant-admin', 'tenant:delete')).toBe(false);
    });
});

// ── requirePermission (fail-closed) ──────────────────────────────────────────

describe('requirePermission — should enforce permissions fail-closed', () => {
    it('should not throw when admin has required permission', () => {
        expect(() => requirePermission('admin', 'tenant:delete')).not.toThrow();
    });

    it('should throw AdminRbacError when viewer attempts tenant:update', () => {
        expect(() => requirePermission('viewer', 'tenant:update')).toThrowError(AdminRbacError);
        try {
            requirePermission('viewer', 'tenant:update');
        } catch (err) {
            expect((err as AdminRbacError).code).toBe('ADMIN_PERMISSION_DENIED');
            expect((err as AdminRbacError).message).toContain('tenant:update');
        }
    });

    it('should throw AdminRbacError when tenant-admin attempts policy:delete', () => {
        expect(() => requirePermission('tenant-admin', 'policy:delete')).toThrowError(AdminRbacError);
    });

    it('should throw AdminRbacError when viewer attempts policy:update', () => {
        expect(() => requirePermission('viewer', 'policy:update')).toThrowError(AdminRbacError);
    });
});

// ── fail-closed invariant grep test ──────────────────────────────────────────

describe('fail-closed invariant grep test — RBAC source files must not contain bypass patterns', () => {
    /**
     * nonCommentLines helper: filters out comment lines (consistent with the multi-tenancy test style)
     */
    function nonCommentLines(src: string): string[] {
        return src
            .split('\n')
            .filter(line => !line.trim().startsWith('//') && !line.trim().startsWith('*'));
    }

    it('should not contain bypassTenant in rbac.ts or types.ts', () => {
        const rbacSrc = readFileSync(resolve(__dirname, '../rbac.ts'), 'utf-8');
        const typesSrc = readFileSync(resolve(__dirname, '../types.ts'), 'utf-8');

        const rbacLines = nonCommentLines(rbacSrc);
        const typesLines = nonCommentLines(typesSrc);

        expect(rbacLines.join('\n')).not.toMatch(/bypassTenant/);
        expect(typesLines.join('\n')).not.toMatch(/bypassTenant/);
    });

    it('should not contain skipAuth in rbac.ts or types.ts', () => {
        const rbacSrc = readFileSync(resolve(__dirname, '../rbac.ts'), 'utf-8');
        const typesSrc = readFileSync(resolve(__dirname, '../types.ts'), 'utf-8');

        expect(nonCommentLines(rbacSrc).join('\n')).not.toMatch(/skipAuth/);
        expect(nonCommentLines(typesSrc).join('\n')).not.toMatch(/skipAuth/);
    });

    it('should not contain adminGlobalAccess in rbac.ts or types.ts', () => {
        const rbacSrc = readFileSync(resolve(__dirname, '../rbac.ts'), 'utf-8');
        const typesSrc = readFileSync(resolve(__dirname, '../types.ts'), 'utf-8');

        expect(nonCommentLines(rbacSrc).join('\n')).not.toMatch(/adminGlobalAccess/);
        expect(nonCommentLines(typesSrc).join('\n')).not.toMatch(/adminGlobalAccess/);
    });

    it('should contain parseAdminRole in types.ts (fail-closed role factory)', () => {
        const typesSrc = readFileSync(resolve(__dirname, '../types.ts'), 'utf-8');
        expect(typesSrc).toMatch(/parseAdminRole/);
    });

    it('should contain requirePermission in rbac.ts (fail-closed permission check)', () => {
        const rbacSrc = readFileSync(resolve(__dirname, '../rbac.ts'), 'utf-8');
        expect(rbacSrc).toMatch(/requirePermission/);
    });

    it('should have AdminRbacError thrown for ADMIN_ROLE_MISSING in types.ts', () => {
        const typesSrc = readFileSync(resolve(__dirname, '../types.ts'), 'utf-8');
        expect(typesSrc).toMatch(/ADMIN_ROLE_MISSING/);
    });

    it('should have ADMIN_PERMISSION_DENIED in rbac.ts', () => {
        const rbacSrc = readFileSync(resolve(__dirname, '../rbac.ts'), 'utf-8');
        expect(rbacSrc).toMatch(/ADMIN_PERMISSION_DENIED/);
    });
});
