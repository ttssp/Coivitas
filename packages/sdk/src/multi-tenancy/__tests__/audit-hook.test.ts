/**
 * InMemoryTenantAuditHook + InMemoryTenantAuditFilter tests
 *
 * Coverage:
 *   - pre-call hook injects tenantId (invariant assertion)
 *   - post-call hook injects tenantId + outcome
 *   - every audit event must contain tenantId (literal assertion)
 *   - audit queries must be filtered by tenantId (cross-tenant leak prevention)
 *   - missing TenantContext -> fail-closed (TenantContextMissingError)
 *   - TenantAuditCrossLeakError when filter called without tenantId
 *   - invariant grep test (tenantId appears literally >= 3 times in the audit source)
 *
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { resolve, dirname } from 'node:path';
import {
    InMemoryTenantAuditHook,
    InMemoryTenantAuditFilter,
    TenantAuditCrossLeakError,
} from '../audit-hook.js';
import {
    makeTenantId,
    TenantContextMissingError,
} from '../types.js';
import type { TenantContext, TenantId } from '../types.js';
import type { DID, Timestamp } from '@coivitas/types';

// ── Helper factories ──────────────────────────────────────────────────────────

const __dirname = dirname(fileURLToPath(import.meta.url));

function makeCtx(tenantId: TenantId): TenantContext {
    return {
        tenantId,
        actorDid: 'did:example:alice' as unknown as DID,
        createdAt: new Date().toISOString() as Timestamp,
    };
}

// ── pre-call hook ─────────────────────────────────────────────────────────────

describe('InMemoryTenantAuditHook.preCall — should inject tenantId', () => {
    it('should create audit event with correct tenantId on pre-call', async () => {
        const hook = new InMemoryTenantAuditHook();
        const tenantId = makeTenantId('acme-corp');
        const ctx = makeCtx(tenantId);

        const event = await hook.preCall(ctx, 'key-custody.sign', 'key-id-001');

        expect(event.tenantId).toBe('acme-corp');
        expect(event.action).toBe('key-custody.sign.pre');
        expect(event.resource).toBe('key-id-001');
        expect(event.outcome).toBe('success');
    });

    it('should throw TenantContextMissingError when ctx is undefined', async () => {
        const hook = new InMemoryTenantAuditHook();

        await expect(hook.preCall(undefined, 'my-action')).rejects.toThrowError(
            TenantContextMissingError,
        );
    });

    it('should persist event to tenant-scoped storage', async () => {
        const hook = new InMemoryTenantAuditHook();
        const tenantId = makeTenantId('store-tenant');
        const ctx = makeCtx(tenantId);

        await hook.preCall(ctx, 'some.operation');

        const events = hook.getEventsForTenant(tenantId);
        expect(events).toHaveLength(1);
        expect(events[0].tenantId).toBe('store-tenant');
    });
});

// ── post-call hook ────────────────────────────────────────────────────────────

describe('InMemoryTenantAuditHook.postCall — should inject tenantId + outcome', () => {
    it('should create audit event with correct tenantId and outcome on post-call', async () => {
        const hook = new InMemoryTenantAuditHook();
        const tenantId = makeTenantId('acme-corp');
        const ctx = makeCtx(tenantId);

        const event = await hook.postCall(ctx, 'key-custody.decrypt', 'success', 'key-id-002');

        expect(event.tenantId).toBe('acme-corp');
        expect(event.action).toBe('key-custody.decrypt.post');
        expect(event.outcome).toBe('success');
        expect(event.resource).toBe('key-id-002');
    });

    it('should record denied outcome on post-call', async () => {
        const hook = new InMemoryTenantAuditHook();
        const tenantId = makeTenantId('denied-tenant');
        const ctx = makeCtx(tenantId);

        const event = await hook.postCall(ctx, 'tenant.access', 'denied');

        expect(event.outcome).toBe('denied');
        expect(event.tenantId).toBe('denied-tenant');
    });

    it('should throw TenantContextMissingError when ctx is undefined on post-call', async () => {
        const hook = new InMemoryTenantAuditHook();

        await expect(hook.postCall(undefined, 'my-action', 'success')).rejects.toThrowError(
            TenantContextMissingError,
        );
    });
});

// ── every audit event must contain tenantId ──────────────────────────────────

describe('TenantAuditEvent — should always contain tenantId', () => {
    it('should include tenantId in every audit event created via preCall', async () => {
        const hook = new InMemoryTenantAuditHook();
        const tenantId = makeTenantId('required-tenant');
        const ctx = makeCtx(tenantId);

        const event = await hook.preCall(ctx, 'test.action');

        // Invariant: tenantId must exist and be non-empty
        expect(event.tenantId).toBeDefined();
        expect(event.tenantId).not.toBe('');
        expect(event.tenantId).toBe('required-tenant');
    });

    it('should include eventId and timestamp in every audit event', async () => {
        const hook = new InMemoryTenantAuditHook();
        const ctx = makeCtx(makeTenantId('ts-tenant'));

        const event = await hook.preCall(ctx, 'timestamped.action');

        expect(event.eventId).toBeDefined();
        expect(event.eventId.length).toBeGreaterThan(0);
        expect(event.timestamp).toBeDefined();
    });
});

// ── TenantAuditFilter cross-tenant protection ─────────────────────────────────

describe('InMemoryTenantAuditFilter — should prevent cross-tenant data leakage', () => {
    it('should filter events by tenantId and exclude other tenants', async () => {
        const hook = new InMemoryTenantAuditHook();
        const filter = new InMemoryTenantAuditFilter();
        const tenantA = makeTenantId('tenant-a');
        const tenantB = makeTenantId('tenant-b');

        await hook.preCall(makeCtx(tenantA), 'action.a');
        await hook.preCall(makeCtx(tenantA), 'action.a2');
        await hook.preCall(makeCtx(tenantB), 'action.b');

        // Merge all events
        const allEvents = [
            ...hook.getEventsForTenant(tenantA),
            ...hook.getEventsForTenant(tenantB),
        ];

        // Filter by tenant-a
        const filteredA = filter.filter(allEvents, tenantA);
        expect(filteredA).toHaveLength(2);
        expect(filteredA.every(e => e.tenantId === 'tenant-a')).toBe(true);

        // Filter by tenant-b
        const filteredB = filter.filter(allEvents, tenantB);
        expect(filteredB).toHaveLength(1);
        expect(filteredB[0].tenantId).toBe('tenant-b');
    });

    it('should throw TenantAuditCrossLeakError when filter called without tenantId', () => {
        const filter = new InMemoryTenantAuditFilter();
        expect(() => filter.filter([], undefined)).toThrowError(TenantAuditCrossLeakError);
    });

    it('should throw TenantAuditCrossLeakError when validateQuery called without tenantId', () => {
        const filter = new InMemoryTenantAuditFilter();
        expect(() => filter.validateQuery({ tenantId: undefined })).toThrowError(
            TenantAuditCrossLeakError,
        );
    });
});

// ── tenant isolation invariant grep test ─────────────────────────────────────

describe('tenant isolation invariant grep test — audit-hook.ts tenantId occurrences', () => {
    it('should contain tenantId in audit event fields at least 3 times in audit-hook.ts', () => {
        const srcPath = resolve(__dirname, '../audit-hook.ts');
        const src = readFileSync(srcPath, 'utf-8');

        // Literal requirement: audit.*tenantId appears >= 3 times
        const tenantIdMatches = (src.match(/tenantId/g) ?? []).length;
        expect(tenantIdMatches).toBeGreaterThanOrEqual(3);
    });

    it('should not contain globalRateLimit or defaultTenant in audit-hook.ts', () => {
        const srcPath = resolve(__dirname, '../audit-hook.ts');
        const src = readFileSync(srcPath, 'utf-8');

        expect(src).not.toMatch(/globalRateLimit/);
        expect(src).not.toMatch(/defaultTenant/);
        expect(src).not.toMatch(/untenanted/);
    });
});
