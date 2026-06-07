/**
 * TenantId branded type + TenantContext + MultiTenantSDKConfig tests (D1)
 *
 * Coverage:
 *   - TenantId makeTenantId valid/invalid formats
 *   - TenantContext requires tenantId
 *   - MultiTenantSDKConfig missing tenantResolver -> fail-closed
 *   - error code literalization (TenantErrorCode)
 *   - validateMultiTenantSDKConfig completeness check
 *
 */

import { describe, it, expect } from 'vitest';
import {
    makeTenantId,
    TenantNotFoundError,
    TenantUnauthorizedError,
    TenantContextMissingError,
    TenantConfigInvalidError,
    validateMultiTenantSDKConfig,
} from '../types.js';
import type { MultiTenantSDKConfig, TenantContext } from '../types.js';
import type { DID, Timestamp } from '@coivitas/types';

// ── Helper factory ────────────────────────────────────────────────────────────

function makeValidConfig(overrides?: Partial<MultiTenantSDKConfig>): MultiTenantSDKConfig {
    return {
        tenantResolver: () => Promise.resolve({
            tenantId: makeTenantId('test-tenant'),
            createdAt: new Date().toISOString() as Timestamp,
        }),
        defaultRateLimitConfig: {
            requestsPerSecond: 100,
            requestsPerMinute: 1000,
            burstCapacity: 50,
            algorithm: 'token-bucket',
        },
        ...overrides,
    };
}

// ── TenantId branded type ─────────────────────────────────────────────────────

describe('TenantId branded type — should enforce format via makeTenantId', () => {
    it('should create valid TenantId when format is correct', () => {
        const id = makeTenantId('acme-corp');
        expect(id).toBe('acme-corp');
        expect(typeof id).toBe('string');
    });

    it('should accept alphanumeric with underscores and hyphens', () => {
        expect(() => makeTenantId('tenant_001-prod')).not.toThrow();
        expect(() => makeTenantId('TENANT-UPPER_CASE')).not.toThrow();
        expect(() => makeTenantId('a')).not.toThrow();
        expect(() => makeTenantId('a'.repeat(128))).not.toThrow();
    });

    it('should throw TenantUnauthorizedError when tenantId is empty', () => {
        expect(() => makeTenantId('')).toThrowError(TenantUnauthorizedError);
        const err = (() => {
            try { makeTenantId(''); } catch (e) { return e; }
        })() as TenantUnauthorizedError;
        expect(err.code).toBe('TENANT_ID_INVALID_FORMAT');
    });

    it('should throw TenantUnauthorizedError when tenantId exceeds 128 chars', () => {
        expect(() => makeTenantId('a'.repeat(129))).toThrowError(TenantUnauthorizedError);
    });

    it('should throw TenantUnauthorizedError when tenantId contains invalid characters', () => {
        expect(() => makeTenantId('tenant with spaces')).toThrowError(TenantUnauthorizedError);
        expect(() => makeTenantId('tenant@domain.com')).toThrowError(TenantUnauthorizedError);
        expect(() => makeTenantId('tenant/path')).toThrowError(TenantUnauthorizedError);
    });
});

// ── TenantContext requires tenantId ──────────────────────────────────────────

describe('TenantContext — should require tenantId', () => {
    it('should be constructible with required tenantId and createdAt', () => {
        const ctx: TenantContext = {
            tenantId: makeTenantId('acme-corp'),
            createdAt: new Date().toISOString() as Timestamp,
        };
        expect(ctx.tenantId).toBe('acme-corp');
    });

    it('should carry optional actorDid and metadata', () => {
        const ctx: TenantContext = {
            tenantId: makeTenantId('acme-corp'),
            actorDid: 'did:example:alice' as unknown as DID,
            createdAt: new Date().toISOString() as Timestamp,
            metadata: { requestId: 'req-001' },
        };
        expect(ctx.actorDid).toBe('did:example:alice');
        expect(ctx.metadata?.requestId).toBe('req-001');
    });
});

// ── MultiTenantSDKConfig validation ──────────────────────────────────────────

describe('MultiTenantSDKConfig — should validate on construction', () => {
    it('should pass validation for a valid config', () => {
        expect(() => validateMultiTenantSDKConfig(makeValidConfig())).not.toThrow();
    });

    it('should throw TenantConfigInvalidError when tenantResolver is missing', () => {
        const config = makeValidConfig({ tenantResolver: undefined as unknown as MultiTenantSDKConfig['tenantResolver'] });
        expect(() => validateMultiTenantSDKConfig(config)).toThrowError(TenantConfigInvalidError);
    });

    it('should throw TenantConfigInvalidError when tenantResolver is not a function', () => {
        const config = makeValidConfig({ tenantResolver: 'not-a-function' as unknown as MultiTenantSDKConfig['tenantResolver'] });
        expect(() => validateMultiTenantSDKConfig(config)).toThrowError(TenantConfigInvalidError);
    });

    it('should throw TenantConfigInvalidError when requestsPerSecond is non-positive', () => {
        const config = makeValidConfig({
            defaultRateLimitConfig: {
                requestsPerSecond: 0,
                requestsPerMinute: 1000,
                burstCapacity: 50,
                algorithm: 'token-bucket',
            },
        });
        expect(() => validateMultiTenantSDKConfig(config)).toThrowError(TenantConfigInvalidError);
    });

    it('should throw TenantConfigInvalidError when algorithm is invalid', () => {
        const config = makeValidConfig({
            defaultRateLimitConfig: {
                requestsPerSecond: 10,
                requestsPerMinute: 600,
                burstCapacity: 5,
                algorithm: 'leaky-bucket' as unknown as 'token-bucket' | 'sliding-window',
            },
        });
        expect(() => validateMultiTenantSDKConfig(config)).toThrowError(TenantConfigInvalidError);
    });
});

// ── Error code literalization ─────────────────────────────────────────────────

describe('TenantError subclasses — should have correct error codes', () => {
    it('should assign TENANT_NOT_FOUND code to TenantNotFoundError', () => {
        const err = new TenantNotFoundError('not found');
        expect(err.code).toBe('TENANT_NOT_FOUND');
        expect(err instanceof TenantNotFoundError).toBe(true);
    });

    it('should assign TENANT_UNAUTHORIZED code to TenantUnauthorizedError', () => {
        const err = new TenantUnauthorizedError('unauthorized');
        expect(err.code).toBe('TENANT_UNAUTHORIZED');
        expect(err instanceof TenantUnauthorizedError).toBe(true);
    });

    it('should assign TENANT_CONTEXT_MISSING code to TenantContextMissingError', () => {
        const err = new TenantContextMissingError('my-operation');
        expect(err.code).toBe('TENANT_CONTEXT_MISSING');
        expect(err.message).toContain('my-operation');
    });

    it('should assign TENANT_CONFIG_INVALID code to TenantConfigInvalidError', () => {
        const err = new TenantConfigInvalidError('invalid config');
        expect(err.code).toBe('TENANT_CONFIG_INVALID');
    });
});
