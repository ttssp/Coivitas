/**
 * buildTamperProofHashInput — shared helper unit tests
 *
 * Test scope:
 *   1. all 10 fields bound (signature + tamperProofHash excluded)
 *   2. GENESIS_MARKER placeholder (previousHash === null -> "0"*64)
 *   3. deterministic output when called repeatedly on the same event
 *   4. any metadata field change -> hash input string changes (DBA tamper defense)
 */

import { describe, expect, it } from 'vitest';
import {
    type DID,
    type Signature,
    type Timestamp,
    ATP_GENESIS_MARKER,
    toAtpVersionString,
    toAuditAction,
    toAuditClass,
    toAuditEventHash,
    toAuditEventId,
    toTenantId,
} from '@coivitas/types';
import { buildTamperProofHashInput } from '../build-tamper-proof-hash-input.js';

const VALID_TENANT_ID = toTenantId('11111111-2222-4333-8444-555555555555');
const VALID_EVENT_ID = toAuditEventId('aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee');
const VALID_DID = 'did:key:z6MkActor' as DID;
const VALID_PREVIOUS_HASH = toAuditEventHash('b'.repeat(64));

function makeBaseEvent() {
    return {
        atpVersion: toAtpVersionString('1.0.0'),
        eventId: VALID_EVENT_ID,
        tenantId: VALID_TENANT_ID,
        auditClass: toAuditClass('L1'),
        actorDid: VALID_DID,
        action: toAuditAction('TOKEN_VERIFY'),
        target: 'token-id-001',
        canonicalPayload: '{"foo":"bar"}',
        previousHash: VALID_PREVIOUS_HASH,
        timestamp: '2026-05-13T00:00:00.000Z' as Timestamp,
    } as const;
}

describe('buildTamperProofHashInput — all 10 fields bound', () => {
    it('should produce identical output for two identical events when called twice', () => {
        const ev = makeBaseEvent();
        const a = buildTamperProofHashInput(ev);
        const b = buildTamperProofHashInput(ev);
        expect(a).toBe(b);
    });

    it('should include GENESIS_MARKER when previousHash is null', () => {
        const ev = { ...makeBaseEvent(), previousHash: null };
        const result = buildTamperProofHashInput(ev);
        expect(result).toContain(ATP_GENESIS_MARKER);
    });

    it('should use real previousHash hex when previousHash !== null', () => {
        const ev = makeBaseEvent();
        const result = buildTamperProofHashInput(ev);
        expect(result).toContain(VALID_PREVIOUS_HASH);
        expect(result).not.toContain(ATP_GENESIS_MARKER);
    });

    it('should produce different output when actorDid is changed (all 10 fields bound; DBA tamper defense)', () => {
        const a = buildTamperProofHashInput(makeBaseEvent());
        const b = buildTamperProofHashInput({
            ...makeBaseEvent(),
            actorDid: 'did:key:z6MkDifferent' as DID,
        });
        expect(a).not.toBe(b);
    });

    it('should produce different output when action is changed (binding test)', () => {
        const a = buildTamperProofHashInput(makeBaseEvent());
        const b = buildTamperProofHashInput({
            ...makeBaseEvent(),
            action: toAuditAction('ENVELOPE_RECORDED'),
        });
        expect(a).not.toBe(b);
    });

    it('should produce different output when target is changed (binding test)', () => {
        const a = buildTamperProofHashInput(makeBaseEvent());
        const b = buildTamperProofHashInput({
            ...makeBaseEvent(),
            target: 'different-target',
        });
        expect(a).not.toBe(b);
    });

    it('should produce different output when auditClass is changed (binding test)', () => {
        const a = buildTamperProofHashInput(makeBaseEvent());
        const b = buildTamperProofHashInput({
            ...makeBaseEvent(),
            auditClass: toAuditClass('L2'),
        });
        expect(a).not.toBe(b);
    });

    it('should produce different output when timestamp is changed (binding test)', () => {
        const a = buildTamperProofHashInput(makeBaseEvent());
        const b = buildTamperProofHashInput({
            ...makeBaseEvent(),
            timestamp: '2026-05-14T00:00:00.000Z' as Timestamp,
        });
        expect(a).not.toBe(b);
    });

    it('should produce different output when tenantId is changed (multi-tenant isolation binding)', () => {
        const a = buildTamperProofHashInput(makeBaseEvent());
        const b = buildTamperProofHashInput({
            ...makeBaseEvent(),
            tenantId: toTenantId('22222222-3333-4444-8555-666666666666'),
        });
        expect(a).not.toBe(b);
    });

    it('should produce different output when eventId is changed (binding test)', () => {
        const a = buildTamperProofHashInput(makeBaseEvent());
        const b = buildTamperProofHashInput({
            ...makeBaseEvent(),
            eventId: toAuditEventId('ffffffff-bbbb-4ccc-8ddd-eeeeeeeeeeee'),
        });
        expect(a).not.toBe(b);
    });

    it('should produce different output when atpVersion is changed (binding test)', () => {
        // atpVersion field value change (v0.1 has the unique value "1.0.0"; constructing a dummy is enough to test binding)
        const a = buildTamperProofHashInput(makeBaseEvent());
        // Construct an illegal atpVersion directly to test binding (bypassing the factory)
        const b = buildTamperProofHashInput({
            ...makeBaseEvent(),
            atpVersion: '0.9.9' as ReturnType<typeof toAtpVersionString>,
        });
        expect(a).not.toBe(b);
    });

    it('should produce different output when canonicalPayload is changed (binding test)', () => {
        const a = buildTamperProofHashInput(makeBaseEvent());
        const b = buildTamperProofHashInput({
            ...makeBaseEvent(),
            canonicalPayload: '{"foo":"different"}',
        });
        expect(a).not.toBe(b);
    });
});
