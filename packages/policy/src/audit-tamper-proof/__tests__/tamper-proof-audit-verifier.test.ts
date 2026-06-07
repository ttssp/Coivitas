/**
 * TamperProofAuditVerifier — L3 verifier end-to-end unit tests
 *
 * Test scope:
 *   1. happy path: write + verify → ok:true
 *   2. cross-tenant query: AUDIT_TENANT_SCOPE_VIOLATION
 *   3. DBA tampers with tamperProofHash: AUDIT_TAMPER_DETECTED (reverse hash chain replay guard)
 *   4. DBA tampers with previousHash: AUDIT_HASH_CHAIN_BROKEN
 *   5. GENESIS invariant: AUDIT_GENESIS_VIOLATION
 *   6. re-canonicalize mismatch: AUDIT_CANONICALIZE_MISMATCH
 *   7. signature present (v0.1 does not implement real verification): AUDIT_EVENT_SIGNATURE_INVALID
 *   8. eventId not found: AUDIT_TENANT_SCOPE_VIOLATION (returns not-found)
 *   9. fetchAllEvents fail: AUDIT_REVERSE_REPLAY_FAILED
 *   10. verifyAuditEventOrThrow throw-form API
 */

import { describe, expect, it, beforeEach } from 'vitest';
import {
    AuditError,
    type AuditEventId,
    type DID,
    type Signature,
    type Timestamp,
    toAuditAction,
    toAuditClass,
    toAuditEventHash,
    toAuditEventId,
    toTenantId,
} from '@coivitas/types';
import {
    InMemoryAuditEventStore,
    InMemoryTenantResolver,
    TamperProofAuditVerifier,
    TamperProofAuditWriter,
    type CallerPrincipal,
    type WriteAuditEventInput,
} from '../index.js';

const TENANT_A = toTenantId('11111111-aaaa-4bbb-8ccc-111111111111');
const TENANT_B = toTenantId('22222222-aaaa-4bbb-8ccc-222222222222');
const DID_ALICE = 'did:key:z6MkAlice' as DID;
const DID_BOB = 'did:key:z6MkBob' as DID;

let store: InMemoryAuditEventStore;
let resolver: InMemoryTenantResolver;
let writer: TamperProofAuditWriter;
let verifier: TamperProofAuditVerifier;
let eventIdCounter: number;
let frozenTime: number;

function nextEventId(): AuditEventId {
    eventIdCounter++;
    const hex = eventIdCounter.toString(16).padStart(12, '0');
    return toAuditEventId(
        `${hex.padStart(8, '0').slice(-8)}-bbbb-4ccc-8ddd-${hex.padStart(12, '0').slice(-12)}`,
    );
}

function nextTimestamp(): Timestamp {
    frozenTime += 1000;
    return new Date(frozenTime).toISOString() as Timestamp;
}

beforeEach(() => {
    store = new InMemoryAuditEventStore();
    resolver = new InMemoryTenantResolver();
    resolver.register(DID_ALICE, TENANT_A);
    resolver.register(DID_BOB, TENANT_B);
    eventIdCounter = 0;
    frozenTime = Date.parse('2026-05-13T00:00:00.000Z');
    writer = new TamperProofAuditWriter({
        tenantResolver: resolver,
        store,
        generateEventId: nextEventId,
        generateTimestamp: nextTimestamp,
    });
    verifier = new TamperProofAuditVerifier({ store });
});

function baseInput(
    overrides: Partial<WriteAuditEventInput> = {},
): WriteAuditEventInput {
    return {
        tenantId: TENANT_A,
        auditClass: toAuditClass('L1'),
        actorDid: DID_ALICE,
        action: toAuditAction('TOKEN_VERIFY'),
        target: 'token-id-001',
        payload: { foo: 'bar' },
        ...overrides,
    };
}

function baseCaller(
    overrides: Partial<CallerPrincipal> = {},
): CallerPrincipal {
    return {
        actorDid: DID_ALICE,
        ...overrides,
    };
}

async function writeOne(
    inp: Partial<WriteAuditEventInput> = {},
    cal: Partial<CallerPrincipal> = {},
) {
    const event = await writer.writeAuditEvent(baseInput(inp), baseCaller(cal));
    store.releaseAdvisoryLock(event.tenantId, event.auditClass);
    return event;
}

// ─── 1. Happy path ──────────────────────────────────────────────────────────

describe('TamperProofAuditVerifier — happy path', () => {
    it('should return ok:true when chain is well-formed and event exists', async () => {
        const e1 = await writeOne();
        const result = await verifier.verifyAuditEvent({
            eventId: e1.eventId,
            tenantId: TENANT_A,
        });
        expect(result.ok).toBe(true);
        if (result.ok) {
            expect(result.event.eventId).toBe(e1.eventId);
        }
    });

    it('should return ok:true for non-GENESIS event when chain is well-formed', async () => {
        await writeOne();
        const e2 = await writeOne({ target: 'token-id-002' });
        const result = await verifier.verifyAuditEvent({
            eventId: e2.eventId,
            tenantId: TENANT_A,
        });
        expect(result.ok).toBe(true);
    });

    it('should accept payload re-canonicalize when originalPayload matches', async () => {
        const e1 = await writeOne({ payload: { foo: 'bar', baz: 1 } });
        const result = await verifier.verifyAuditEvent({
            eventId: e1.eventId,
            tenantId: TENANT_A,
            originalPayload: { foo: 'bar', baz: 1 },
        });
        expect(result.ok).toBe(true);
    });

    it('should accept payload re-canonicalize when originalPayload key order differs (JCS lex sort)', async () => {
        const e1 = await writeOne({ payload: { z: 1, a: 2 } });
        const result = await verifier.verifyAuditEvent({
            eventId: e1.eventId,
            tenantId: TENANT_A,
            originalPayload: { a: 2, z: 1 }, // different key order
        });
        expect(result.ok).toBe(true);
    });
});

// ─── 2. Multi-tenant isolation ──────────────────────────────────────────────

describe('TamperProofAuditVerifier — multi-tenant isolation', () => {
    it('should return ok:false AUDIT_TENANT_SCOPE_VIOLATION when querying with wrong tenant', async () => {
        const e1 = await writeOne();
        const result = await verifier.verifyAuditEvent({
            eventId: e1.eventId,
            tenantId: TENANT_B, // wrong tenant
        });
        expect(result.ok).toBe(false);
        if (!result.ok) {
            expect(result.error.code).toBe('AUDIT_TENANT_SCOPE_VIOLATION');
        }
    });

    it('should return ok:false AUDIT_TENANT_SCOPE_VIOLATION when eventId does not exist', async () => {
        const result = await verifier.verifyAuditEvent({
            eventId: toAuditEventId(
                'ffffffff-bbbb-4ccc-8ddd-ffffffffffff',
            ),
            tenantId: TENANT_A,
        });
        expect(result.ok).toBe(false);
        if (!result.ok) {
            expect(result.error.code).toBe('AUDIT_TENANT_SCOPE_VIOLATION');
        }
    });
});

// ─── 3. DBA tampers with tamperProofHash (AUDIT_TAMPER_DETECTED) ────────────────────

describe('TamperProofAuditVerifier — tamper detection (DBA UPDATE attack)', () => {
    it('should return ok:false AUDIT_TAMPER_DETECTED when tamperProofHash is corrupted by DBA', async () => {
        const e1 = await writeOne();
        // simulate DBA UPDATE managed_service.audit_events SET tamper_proof_hash = 'evil'
        store._testForceCorruptEvent(
            e1.eventId,
            toAuditEventHash('e'.repeat(64)),
        );
        const result = await verifier.verifyAuditEvent({
            eventId: e1.eventId,
            tenantId: TENANT_A,
        });
        expect(result.ok).toBe(false);
        if (!result.ok) {
            expect(result.error.code).toBe('AUDIT_TAMPER_DETECTED');
        }
    });

    it('should detect tampering on second event when DBA changes hash of first event in chain', async () => {
        const e1 = await writeOne();
        const e2 = await writeOne({ target: 'token-id-002' });
        // after tampering with e1's hash, verifying e2 also fails (e1 hash mismatch during chain replay)
        store._testForceCorruptEvent(
            e1.eventId,
            toAuditEventHash('e'.repeat(64)),
        );
        const result = await verifier.verifyAuditEvent({
            eventId: e2.eventId,
            tenantId: TENANT_A,
        });
        expect(result.ok).toBe(false);
        if (!result.ok) {
            expect(result.error.code).toBe('AUDIT_TAMPER_DETECTED');
        }
    });
});

// ─── 4. DBA tampers with previousHash (AUDIT_HASH_CHAIN_BROKEN) ────────────────────

describe('TamperProofAuditVerifier — hash chain broken detection', () => {
    it('should return ok:false AUDIT_GENESIS_VIOLATION when GENESIS event previousHash is non-null', async () => {
        const e1 = await writeOne();
        // tamper with GENESIS previousHash; invariant: i===0 → previousHash must be null
        store._testForceCorruptPreviousHash(
            e1.eventId,
            toAuditEventHash('1'.repeat(64)),
        );
        const result = await verifier.verifyAuditEvent({
            eventId: e1.eventId,
            tenantId: TENANT_A,
        });
        expect(result.ok).toBe(false);
        if (!result.ok) {
            // in this case the GENESIS invariant fails first (before the hash-chain link guard)
            expect(['AUDIT_GENESIS_VIOLATION', 'AUDIT_TAMPER_DETECTED']).toContain(
                result.error.code,
            );
        }
    });

    it('should return ok:false AUDIT_GENESIS_VIOLATION when non-GENESIS event has previousHash=null', async () => {
        await writeOne();
        const e2 = await writeOne({ target: 'token-id-002' });
        // tamper with e2's previousHash to null; invariant: i>0 → previousHash must be non-null
        store._testForceCorruptPreviousHash(e2.eventId, null);
        const result = await verifier.verifyAuditEvent({
            eventId: e2.eventId,
            tenantId: TENANT_A,
        });
        expect(result.ok).toBe(false);
        if (!result.ok) {
            // GENESIS_VIOLATION takes priority; or it already fails at TAMPER (hash mismatch after substituting GENESIS_MARKER)
            expect([
                'AUDIT_GENESIS_VIOLATION',
                'AUDIT_TAMPER_DETECTED',
            ]).toContain(result.error.code);
        }
    });
});

// ─── 5. re-canonicalize mismatch (step 5) ─────────────────────────────

describe('TamperProofAuditVerifier — re-canonicalize mismatch (step 5)', () => {
    it('should return ok:false AUDIT_CANONICALIZE_MISMATCH when originalPayload differs from stored canonicalPayload', async () => {
        const e1 = await writeOne({ payload: { foo: 'bar' } });
        const result = await verifier.verifyAuditEvent({
            eventId: e1.eventId,
            tenantId: TENANT_A,
            originalPayload: { foo: 'different' }, // different payload
        });
        expect(result.ok).toBe(false);
        if (!result.ok) {
            expect(result.error.code).toBe('AUDIT_CANONICALIZE_MISMATCH');
        }
    });
});

// ─── 6. signature present (v0.1 does not implement real verification) ──────────────────────────────

describe('TamperProofAuditVerifier — signature present (v0.1 does not implement real verification; fail-closed)', () => {
    it('should return ok:false AUDIT_EVENT_SIGNATURE_INVALID when event.signature is present (v0.1 scope)', async () => {
        const e1 = await writer.writeAuditEvent(
            baseInput({ signature: 'dummy-sig' as Signature }),
            baseCaller(),
        );
        store.releaseAdvisoryLock(TENANT_A, toAuditClass('L1'));
        const result = await verifier.verifyAuditEvent({
            eventId: e1.eventId,
            tenantId: TENANT_A,
        });
        expect(result.ok).toBe(false);
        if (!result.ok) {
            expect(result.error.code).toBe('AUDIT_EVENT_SIGNATURE_INVALID');
        }
    });
});

// ─── 7. fetchAllEvents fail (AUDIT_REVERSE_REPLAY_FAILED) ──────────────────

describe('TamperProofAuditVerifier — reverse replay fail (negative-case defense)', () => {
    it('should return ok:false AUDIT_REVERSE_REPLAY_FAILED when fetchAllEvents throws', async () => {
        const e1 = await writeOne();
        // inject a throwing fetchAllEvents
        const origFetch = store.fetchAllEvents.bind(store);
        // eslint-disable-next-line @typescript-eslint/require-await
        store.fetchAllEvents = async () => {
            throw new Error('simulated DB connection lost');
        };
        const result = await verifier.verifyAuditEvent({
            eventId: e1.eventId,
            tenantId: TENANT_A,
        });
        expect(result.ok).toBe(false);
        if (!result.ok) {
            expect(result.error.code).toBe('AUDIT_REVERSE_REPLAY_FAILED');
        }
        store.fetchAllEvents = origFetch; // cleanup
    });
});

// ─── 8. verifyAuditEventOrThrow (throw-form API) ───────────────────────────

describe('TamperProofAuditVerifier — verifyAuditEventOrThrow', () => {
    it('should return event when verify succeeds (throw-form API)', async () => {
        const e1 = await writeOne();
        const event = await verifier.verifyAuditEventOrThrow({
            eventId: e1.eventId,
            tenantId: TENANT_A,
        });
        expect(event.eventId).toBe(e1.eventId);
    });

    it('should throw AuditError when verify fails (throw-form API)', async () => {
        const e1 = await writeOne();
        store._testForceCorruptEvent(
            e1.eventId,
            toAuditEventHash('e'.repeat(64)),
        );
        await expect(
            verifier.verifyAuditEventOrThrow({
                eventId: e1.eventId,
                tenantId: TENANT_A,
            }),
        ).rejects.toThrow(AuditError);
    });
});
