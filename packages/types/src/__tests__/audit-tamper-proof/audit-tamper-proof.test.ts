/**
 * atp v0.1 L0 types + AJV strict mode validator tests
 *
 * audit tamper-proof sub-protocol
 * coverage target: ≥95% lines/statements/functions; ≥90% branches
 *
 * Test scope:
 *   1. brand type factory functions (toAtpVersionString / toTenantId / toAuditEventId /
 *      toAuditEventHash / toAuditAction / toAuditClass)
 *   2. handleAuditError full coverage of 17 error codes + assertNeverAuditError exhaustive
 *      (fail-closed; ≥ 1 throw-path per code)
 *   3. validateAuditEvent AJV strict mode (3rd line of defense) — happy path + multiple fail-closed paths
 *   4. constant exports (ATP_SUPPORTED_VERSIONS / ATP_VERSION_CURRENT / ATP_GENESIS_MARKER /
 *      ATP_AUDIT_ACTION_MAX_LENGTH / ATP_ERROR_CODES / AUDIT_CLASSES)
 *   5. AuditError standalone class (does not extend ProtocolError)
 */

import { describe, expect, it } from 'vitest';
import {
    // Brand type factories
    toAtpVersionString,
    toTenantId,
    toAuditEventId,
    toAuditEventHash,
    toAuditAction,
    toAuditClass,
    // Error handling
    handleAuditError,
    assertNeverAuditError,
    AuditError,
    // Validation
    validateAuditEvent,
    // Constants
    ATP_SUPPORTED_VERSIONS,
    ATP_VERSION_CURRENT,
    ATP_GENESIS_MARKER,
    ATP_AUDIT_ACTION_MAX_LENGTH,
    ATP_ERROR_CODES,
    AUDIT_CLASSES,
} from '../../audit-tamper-proof/index.js';
import type {
    AuditErrorCode,
    AuditEvent,
} from '../../audit-tamper-proof/types.js';

// ─── Test Fixtures ───────────────────────────────────────────────────────────

const VALID_UUID_V4 = '550e8400-e29b-41d4-a716-446655440000';
const VALID_TENANT_ID = '11111111-2222-4333-8444-555555555555';
const VALID_EVENT_ID = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee';
const VALID_SHA256_HEX =
    'a'.repeat(64);
const VALID_TIMESTAMP = '2026-05-13T00:00:00.000Z';
const VALID_DID = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';

function makeValidAuditEventObject(): Record<string, unknown> {
    return {
        atpVersion: '1.0.0',
        eventId: VALID_EVENT_ID,
        tenantId: VALID_TENANT_ID,
        auditClass: 'L1',
        actorDid: VALID_DID,
        action: 'TOKEN_VERIFY',
        target: 'token-id-001',
        canonicalPayload: '{"foo":"bar"}',
        tamperProofHash: VALID_SHA256_HEX,
        previousHash: null,
        timestamp: VALID_TIMESTAMP,
        signature: null,
    };
}

// ─── 1. Brand Type Factory Functions (brand guards) ────────────────

describe('toAtpVersionString', () => {
    it('should accept valid v1.0.0 when atpVersion is supported', () => {
        const result = toAtpVersionString('1.0.0');
        expect(result).toBe('1.0.0');
    });

    it('should throw AUDIT_VERSION_UNSUPPORTED when not valid semver format', () => {
        expect(() => toAtpVersionString('v1.0')).toThrow(
            'AUDIT_VERSION_UNSUPPORTED',
        );
    });

    it('should throw AUDIT_VERSION_UNSUPPORTED when valid semver but not supported version', () => {
        expect(() => toAtpVersionString('1.0.1')).toThrow(
            'AUDIT_VERSION_UNSUPPORTED',
        );
    });

    it('should throw AUDIT_VERSION_UNSUPPORTED when version is empty string', () => {
        expect(() => toAtpVersionString('')).toThrow(
            'AUDIT_VERSION_UNSUPPORTED',
        );
    });
});

describe('toTenantId', () => {
    it('should accept valid UUID v4 when tenantId is well-formed', () => {
        const result = toTenantId(VALID_TENANT_ID);
        expect(result).toBe(VALID_TENANT_ID);
    });

    it('should accept uppercase UUID v4 when caller normalizes via upper-case', () => {
        const upper = VALID_TENANT_ID.toUpperCase();
        const result = toTenantId(upper);
        expect(result).toBe(upper);
    });

    it('should throw AUDIT_TENANT_SCOPE_VIOLATION when format invalid', () => {
        expect(() => toTenantId('not-a-uuid')).toThrow(
            'AUDIT_TENANT_SCOPE_VIOLATION',
        );
    });

    it('should throw AUDIT_TENANT_SCOPE_VIOLATION when UUID v1 instead of v4', () => {
        // UUID v1 third group starts with 1, not 4
        expect(() =>
            toTenantId('550e8400-e29b-11d4-a716-446655440000'),
        ).toThrow('AUDIT_TENANT_SCOPE_VIOLATION');
    });

    it('should throw AUDIT_TENANT_SCOPE_VIOLATION when empty string', () => {
        expect(() => toTenantId('')).toThrow('AUDIT_TENANT_SCOPE_VIOLATION');
    });
});

describe('toAuditEventId', () => {
    it('should accept valid UUID v4 when eventId is well-formed', () => {
        const result = toAuditEventId(VALID_EVENT_ID);
        expect(result).toBe(VALID_EVENT_ID);
    });

    it('should throw CSP_CHALLENGE_INVALID when format invalid (reuse csp toUuidV4String)', () => {
        // csp factory reused; throws CSP_CHALLENGE_INVALID per csp v0.1
        expect(() => toAuditEventId('not-a-uuid')).toThrow(
            'CSP_CHALLENGE_INVALID',
        );
    });
});

describe('toAuditEventHash', () => {
    it('should accept valid SHA-256 hex when 64 lowercase hex chars', () => {
        const result = toAuditEventHash(VALID_SHA256_HEX);
        expect(result).toBe(VALID_SHA256_HEX);
    });

    it('should accept GENESIS_MARKER zero-hex when 64 zeros', () => {
        const result = toAuditEventHash(ATP_GENESIS_MARKER);
        expect(result).toBe(ATP_GENESIS_MARKER);
    });

    it('should throw AUDIT_HASH_CHAIN_BROKEN when not 64 hex chars', () => {
        expect(() => toAuditEventHash('a'.repeat(63))).toThrow(
            'AUDIT_HASH_CHAIN_BROKEN',
        );
    });

    it('should throw AUDIT_HASH_CHAIN_BROKEN when uppercase hex (lowercase only)', () => {
        expect(() => toAuditEventHash('A'.repeat(64))).toThrow(
            'AUDIT_HASH_CHAIN_BROKEN',
        );
    });

    it('should throw AUDIT_HASH_CHAIN_BROKEN when contains non-hex chars', () => {
        expect(() =>
            toAuditEventHash('z'.repeat(64)),
        ).toThrow('AUDIT_HASH_CHAIN_BROKEN');
    });

    it('should throw AUDIT_HASH_CHAIN_BROKEN when empty string', () => {
        expect(() => toAuditEventHash('')).toThrow('AUDIT_HASH_CHAIN_BROKEN');
    });
});

describe('toAuditAction', () => {
    it('should accept action when length within [1, 256]', () => {
        const result = toAuditAction('TOKEN_VERIFY');
        expect(result).toBe('TOKEN_VERIFY');
    });

    it('should accept action at boundary 256 chars', () => {
        const max = 'a'.repeat(256);
        const result = toAuditAction(max);
        expect(result).toBe(max);
    });

    it('should throw AUDIT_ACTION_INVALID when empty string', () => {
        expect(() => toAuditAction('')).toThrow('AUDIT_ACTION_INVALID');
    });

    it('should throw AUDIT_ACTION_INVALID when length 257 (out of [1, 256])', () => {
        expect(() => toAuditAction('a'.repeat(257))).toThrow(
            'AUDIT_ACTION_INVALID',
        );
    });
});

describe('toAuditClass', () => {
    it('should accept L1 when class is L1', () => {
        expect(toAuditClass('L1')).toBe('L1');
    });

    it('should accept L2 when class is L2', () => {
        expect(toAuditClass('L2')).toBe('L2');
    });

    it('should accept L3 when class is L3', () => {
        expect(toAuditClass('L3')).toBe('L3');
    });

    it('should throw AUDIT_SCHEMA_VIOLATION when class is L4 (out of enum)', () => {
        expect(() => toAuditClass('L4')).toThrow('AUDIT_SCHEMA_VIOLATION');
    });

    it('should throw AUDIT_SCHEMA_VIOLATION when class is empty string', () => {
        expect(() => toAuditClass('')).toThrow('AUDIT_SCHEMA_VIOLATION');
    });

    it('should throw AUDIT_SCHEMA_VIOLATION when class is lowercase l1 (case sensitive)', () => {
        expect(() => toAuditClass('l1')).toThrow('AUDIT_SCHEMA_VIOLATION');
    });
});

// ─── 2. handleAuditError full coverage of 17 errcodes (fail-closed) ─────────

describe('handleAuditError — 17 error codes exhaustive', () => {
    const allCodes: AuditErrorCode[] = [...ATP_ERROR_CODES];

    it('should freeze 17 AUDIT_* codes in ATP_ERROR_CODES literal alignment', () => {
        expect(allCodes).toHaveLength(17);
    });

    for (const code of [
        'AUDIT_VERSION_UNSUPPORTED',
        'AUDIT_SCHEMA_VIOLATION',
        'AUDIT_TENANT_SCOPE_VIOLATION',
        'AUDIT_CANONICALIZE_BYPASS_DETECTED',
        'AUDIT_CANONICALIZE_MISMATCH',
        'AUDIT_HASH_CHAIN_BROKEN',
        'AUDIT_TAMPER_DETECTED',
        'AUDIT_FAIL_CLOSED',
        'AUDIT_ATOMICITY_VIOLATED',
        'AUDIT_GENESIS_VIOLATION',
        'AUDIT_TIMESTAMP_INVALID',
        'AUDIT_EVENT_SIGNATURE_INVALID',
        'AUDIT_ACTOR_DID_INVALID',
        'AUDIT_ACTION_INVALID',
        'AUDIT_ADVISORY_LOCK_FAILED',
        'AUDIT_FETCH_LAST_HASH_FAILED',
        'AUDIT_REVERSE_REPLAY_FAILED',
    ] as const) {
        it(`should map ${code} to fatal:true with 4xx/5xx httpStatus when handleAuditError called`, () => {
            const ctx = handleAuditError(code);
            expect(ctx.code).toBe(code);
            expect(ctx.fatal).toBe(true);
            expect([400, 401, 403, 409, 422, 500, 503]).toContain(
                ctx.httpStatus,
            );
            expect(ctx.message.length).toBeGreaterThan(0);
        });
    }

    it('should throw "Unreachable" when assertNeverAuditError called with bogus code (compile-time exhaustive)', () => {
        const bogus = 'AUDIT_NOT_A_REAL_CODE' as unknown as never;
        expect(() => assertNeverAuditError(bogus)).toThrow('Unreachable');
    });
});

// ─── 3. AuditError standalone class (no cross-module coupling) ─────

describe('AuditError independent class', () => {
    it('should construct AuditError with code+detail+context when called via constructor', () => {
        const err = new AuditError(
            'AUDIT_TENANT_SCOPE_VIOLATION',
            'tenant mismatch',
            { actor: VALID_DID, tenant: VALID_TENANT_ID },
        );
        expect(err.code).toBe('AUDIT_TENANT_SCOPE_VIOLATION');
        expect(err.detail).toBe('tenant mismatch');
        expect(err.context?.actor).toBe(VALID_DID);
        expect(err.name).toBe('AuditError');
        expect(err.message).toContain('[AUDIT_TENANT_SCOPE_VIOLATION]');
    });

    it('should not extend ProtocolError when AuditError is constructed (avoids modifying L0 main union)', () => {
        const err = new AuditError('AUDIT_TAMPER_DETECTED', 'detail');
        // AuditError extends Error; does not extend ProtocolError; enforces decoupling
        expect(err).toBeInstanceOf(Error);
        expect(err).toBeInstanceOf(AuditError);
        // Does not expose the ProtocolError interface (constructor 3rd argument is context, not requestId)
        expect((err as unknown as { requestId?: string }).requestId).toBeUndefined();
    });
});

// ─── 4. validateAuditEvent AJV strict mode (3rd line of defense, fail-closed) ────────

describe('validateAuditEvent (3rd line of defense, AJV strict)', () => {
    it('should return valid:true when AuditEvent is well-formed', () => {
        const result = validateAuditEvent(makeValidAuditEventObject());
        expect(result.valid).toBe(true);
    });

    it('should return valid:false when atpVersion is not const "1.0.0"', () => {
        const ev = makeValidAuditEventObject();
        ev.atpVersion = '1.0.1';
        const result = validateAuditEvent(ev);
        expect(result.valid).toBe(false);
        if (!result.valid) {
            expect(result.errors[0]?.message).toBeDefined();
        }
    });

    it('should return valid:false when tenantId is not UUID v4 format', () => {
        const ev = makeValidAuditEventObject();
        ev.tenantId = 'not-a-uuid';
        const result = validateAuditEvent(ev);
        expect(result.valid).toBe(false);
    });

    it('should return valid:false when auditClass is not in enum L1/L2/L3', () => {
        const ev = makeValidAuditEventObject();
        ev.auditClass = 'L9';
        const result = validateAuditEvent(ev);
        expect(result.valid).toBe(false);
    });

    it('should return valid:false when tamperProofHash is not 64 hex chars', () => {
        const ev = makeValidAuditEventObject();
        ev.tamperProofHash = 'short';
        const result = validateAuditEvent(ev);
        expect(result.valid).toBe(false);
    });

    it('should return valid:false when previousHash is invalid hex string', () => {
        const ev = makeValidAuditEventObject();
        ev.previousHash = 'xxxx';
        const result = validateAuditEvent(ev);
        expect(result.valid).toBe(false);
    });

    it('should accept previousHash=null when GENESIS state', () => {
        const ev = makeValidAuditEventObject();
        ev.previousHash = null;
        const result = validateAuditEvent(ev);
        expect(result.valid).toBe(true);
    });

    it('should return valid:false when additional property is present (additionalProperties:false)', () => {
        const ev = { ...makeValidAuditEventObject(), unexpected: 'field' };
        const result = validateAuditEvent(ev);
        expect(result.valid).toBe(false);
    });

    it('should return valid:false when required field eventId missing', () => {
        const ev = makeValidAuditEventObject();
        delete ev.eventId;
        const result = validateAuditEvent(ev);
        expect(result.valid).toBe(false);
    });

    it('should return valid:false when actorDid does not start with did:', () => {
        const ev = makeValidAuditEventObject();
        ev.actorDid = 'not-a-did';
        const result = validateAuditEvent(ev);
        expect(result.valid).toBe(false);
    });

    it('should return valid:false when action length is 257 chars (maxLength 256)', () => {
        const ev = makeValidAuditEventObject();
        ev.action = 'a'.repeat(257);
        const result = validateAuditEvent(ev);
        expect(result.valid).toBe(false);
    });

    it('should return valid:false when canonicalPayload is empty string (minLength 1)', () => {
        const ev = makeValidAuditEventObject();
        ev.canonicalPayload = '';
        const result = validateAuditEvent(ev);
        expect(result.valid).toBe(false);
    });

    it('should return valid:false when timestamp is not ISO 8601 date-time format', () => {
        const ev = makeValidAuditEventObject();
        ev.timestamp = 'not-a-date';
        const result = validateAuditEvent(ev);
        expect(result.valid).toBe(false);
    });
});

// ─── 5. Constant export alignment ──────────────────────────────────

describe('Constants exports', () => {
    it('should export ATP_SUPPORTED_VERSIONS containing only "1.0.0" when v0.1 freeze', () => {
        expect(ATP_SUPPORTED_VERSIONS).toEqual(['1.0.0']);
    });

    it('should export ATP_VERSION_CURRENT as "1.0.0" when v0.1 default', () => {
        expect(ATP_VERSION_CURRENT).toBe('1.0.0');
    });

    it('should export ATP_GENESIS_MARKER as 64 zero hex chars', () => {
        expect(ATP_GENESIS_MARKER).toBe('0'.repeat(64));
        expect(ATP_GENESIS_MARKER).toHaveLength(64);
    });

    it('should export ATP_AUDIT_ACTION_MAX_LENGTH as 256', () => {
        expect(ATP_AUDIT_ACTION_MAX_LENGTH).toBe(256);
    });

    it('should export AUDIT_CLASSES containing L1/L2/L3 in order', () => {
        expect(AUDIT_CLASSES).toEqual(['L1', 'L2', 'L3']);
    });

    it('should export ATP_ERROR_CODES containing exactly 17 unique values', () => {
        expect(ATP_ERROR_CODES).toHaveLength(17);
        const set = new Set<string>(ATP_ERROR_CODES);
        expect(set.size).toBe(17);
    });
});

// ─── 6. AuditEvent interface field-set alignment ────────────

describe('AuditEvent interface field set (TS interface vs schema align)', () => {
    it('should have all 11 required + 1 optional fields when constructed', () => {
        // Compile-time + runtime dual alignment; all TS interface fields ← all schema required fields
        const ev: AuditEvent = {
            atpVersion: toAtpVersionString('1.0.0'),
            eventId: toAuditEventId(VALID_EVENT_ID),
            tenantId: toTenantId(VALID_TENANT_ID),
            auditClass: toAuditClass('L1'),
            actorDid: VALID_DID as AuditEvent['actorDid'],
            action: toAuditAction('TOKEN_VERIFY'),
            target: 'token-id-001',
            canonicalPayload: '{"foo":"bar"}',
            tamperProofHash: toAuditEventHash(VALID_SHA256_HEX),
            previousHash: null,
            timestamp: VALID_TIMESTAMP as AuditEvent['timestamp'],
            signature: null,
        };
        expect(ev.atpVersion).toBe('1.0.0');
        expect(ev.previousHash).toBeNull();
        expect(ev.signature).toBeNull();
        expect(ev.auditClass).toBe('L1');
    });
});
