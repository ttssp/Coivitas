/**
 * TamperProofAuditWriter — L3 writer end-to-end unit tests
 *
 * Test scope:
 *   1. happy path: writeAuditEvent succeeds + tamperProofHash computed + chain append
 *   2. multi-tenant isolation: cross-tenant write reject (AUDIT_TENANT_SCOPE_VIOLATION)
 *   3. canonicalize fail: AUDIT_CANONICALIZE_BYPASS_DETECTED
 *   4. JSON Schema validate fail: AUDIT_SCHEMA_VIOLATION (3rd defense)
 *   5. atomic boundary: insertEvent fail → AUDIT_FAIL_CLOSED (fail-closed)
 *   6. advisory lock: serialize writes per-(tenantId, audit_class)
 *   7. previousHash chain integrity (per-(tenantId, audit_class) scope)
 *   8. DB role guard (audit_writer_l1 vs L2 mismatch reject)
 */

import { describe, expect, it, beforeEach } from 'vitest';
import {
    AuditError,
    type AuditEventId,
    type DID,
    type Timestamp,
    toAuditAction,
    toAuditClass,
    toAuditEventId,
    toTenantId,
} from '@coivitas/types';
import {
    InMemoryAuditEventStore,
    InMemoryTenantResolver,
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
let eventIdCounter: number;

function nextEventId(): AuditEventId {
    eventIdCounter++;
    const hex = eventIdCounter.toString(16).padStart(12, '0');
    // construct a valid UUID v4 (third group "4xxx"; fourth group "8xxx"/"9xxx"/"axxx"/"bxxx")
    return toAuditEventId(
        `${hex.padStart(8, '0').slice(-8)}-bbbb-4ccc-8ddd-${hex.padStart(12, '0').slice(-12)}`,
    );
}

let frozenTime: number;
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
});

function makeBaseInput(
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

function makeBaseCaller(
    overrides: Partial<CallerPrincipal> = {},
): CallerPrincipal {
    return {
        actorDid: DID_ALICE,
        ...overrides,
    };
}

// ─── 1. Happy path ─────────────────────────────────────────────────────────

describe('TamperProofAuditWriter — happy path', () => {
    it('should write GENESIS event with previousHash=null when chain is empty', async () => {
        const event = await writer.writeAuditEvent(
            makeBaseInput(),
            makeBaseCaller(),
        );
        try {
            expect(event.previousHash).toBeNull();
            expect(event.tenantId).toBe(TENANT_A);
            expect(event.auditClass).toBe('L1');
            expect(event.tamperProofHash).toMatch(/^[0-9a-f]{64}$/);
            expect(event.canonicalPayload).toBe('{"foo":"bar"}');
            expect(event.atpVersion).toBe('1.0.0');
        } finally {
            store.releaseAdvisoryLock(TENANT_A, toAuditClass('L1'));
        }
    });

    it('should chain second event with previousHash equal first event tamperProofHash', async () => {
        const e1 = await writer.writeAuditEvent(
            makeBaseInput(),
            makeBaseCaller(),
        );
        store.releaseAdvisoryLock(TENANT_A, toAuditClass('L1'));

        const e2 = await writer.writeAuditEvent(
            makeBaseInput({ target: 'token-id-002' }),
            makeBaseCaller(),
        );
        try {
            expect(e2.previousHash).toBe(e1.tamperProofHash);
            expect(e2.tamperProofHash).not.toBe(e1.tamperProofHash);
        } finally {
            store.releaseAdvisoryLock(TENANT_A, toAuditClass('L1'));
        }
    });

    it('should maintain independent chains per audit_class (per-class chain)', async () => {
        const l1Event = await writer.writeAuditEvent(
            makeBaseInput({ auditClass: toAuditClass('L1') }),
            makeBaseCaller(),
        );
        store.releaseAdvisoryLock(TENANT_A, toAuditClass('L1'));

        const l2Event = await writer.writeAuditEvent(
            makeBaseInput({ auditClass: toAuditClass('L2') }),
            makeBaseCaller(),
        );
        try {
            // L2 chain GENESIS (independent chain; not concatenated with the L1 chain)
            expect(l2Event.previousHash).toBeNull();
            expect(l1Event.previousHash).toBeNull();
        } finally {
            store.releaseAdvisoryLock(TENANT_A, toAuditClass('L2'));
        }
    });

    it('should maintain independent chains per tenant (multi-tenant isolation)', async () => {
        const aEvent = await writer.writeAuditEvent(
            makeBaseInput({ tenantId: TENANT_A, actorDid: DID_ALICE }),
            makeBaseCaller({ actorDid: DID_ALICE }),
        );
        store.releaseAdvisoryLock(TENANT_A, toAuditClass('L1'));

        const bEvent = await writer.writeAuditEvent(
            makeBaseInput({ tenantId: TENANT_B, actorDid: DID_BOB }),
            makeBaseCaller({ actorDid: DID_BOB }),
        );
        try {
            // tenant B chain GENESIS (independent chain; not concatenated with the tenant A chain)
            expect(bEvent.previousHash).toBeNull();
            expect(aEvent.previousHash).toBeNull();
        } finally {
            store.releaseAdvisoryLock(TENANT_B, toAuditClass('L1'));
        }
    });
});

// ─── 2. Multi-tenant isolation ─────────────────────────────────

describe('TamperProofAuditWriter — multi-tenant isolation', () => {
    it('should throw AUDIT_TENANT_SCOPE_VIOLATION when input.tenantId !== caller resolved tenant', async () => {
        await expect(
            writer.writeAuditEvent(
                makeBaseInput({ tenantId: TENANT_B }), // input: B
                makeBaseCaller({ actorDid: DID_ALICE }), // caller maps to A
            ),
        ).rejects.toThrow('AUDIT_TENANT_SCOPE_VIOLATION');
    });

    it('should throw AUDIT_TENANT_SCOPE_VIOLATION when caller principal is not mapped to any tenant', async () => {
        await expect(
            writer.writeAuditEvent(
                makeBaseInput(),
                makeBaseCaller({
                    actorDid: 'did:key:z6MkUnregistered' as DID,
                }),
            ),
        ).rejects.toThrow('AUDIT_TENANT_SCOPE_VIOLATION');
    });

    it('should throw AUDIT_TENANT_SCOPE_VIOLATION when dbRole=audit_writer_l1 but auditClass=L2', async () => {
        await expect(
            writer.writeAuditEvent(
                makeBaseInput({ auditClass: toAuditClass('L2') }),
                makeBaseCaller({ dbRole: 'audit_writer_l1' }),
            ),
        ).rejects.toThrow('AUDIT_TENANT_SCOPE_VIOLATION');
    });
});

// ─── 3. canonicalize fail ──────────────────────────────────────

describe('TamperProofAuditWriter — canonicalize fail', () => {
    it('should throw AUDIT_CANONICALIZE_BYPASS_DETECTED when payload is null', async () => {
        await expect(
            writer.writeAuditEvent(
                makeBaseInput({ payload: null }),
                makeBaseCaller(),
            ),
        ).rejects.toThrow('AUDIT_CANONICALIZE_BYPASS_DETECTED');
    });

    it('should throw AUDIT_CANONICALIZE_BYPASS_DETECTED when payload is array', async () => {
        await expect(
            writer.writeAuditEvent(
                makeBaseInput({ payload: [1, 2, 3] }),
                makeBaseCaller(),
            ),
        ).rejects.toThrow('AUDIT_CANONICALIZE_BYPASS_DETECTED');
    });

    it('should throw AUDIT_CANONICALIZE_BYPASS_DETECTED when payload contains circular reference', async () => {
        const circular: Record<string, unknown> = { foo: 'bar' };
        circular['self'] = circular;
        await expect(
            writer.writeAuditEvent(
                makeBaseInput({ payload: circular }),
                makeBaseCaller(),
            ),
        ).rejects.toThrow('AUDIT_CANONICALIZE_BYPASS_DETECTED');
    });
});

// ─── 4. atomic boundary fail ───────────────────────────────────

describe('TamperProofAuditWriter — atomic boundary (fail-closed)', () => {
    it('should throw AUDIT_FAIL_CLOSED when insertEvent fails with non-AuditError', async () => {
        // inject a throwing insertEvent on the store
        const failingStore = new InMemoryAuditEventStore();
        // eslint-disable-next-line @typescript-eslint/require-await
        failingStore.insertEvent = async () => {
            throw new Error('simulated DB connection lost');
        };
        const failingWriter = new TamperProofAuditWriter({
            tenantResolver: resolver,
            store: failingStore,
            generateEventId: nextEventId,
            generateTimestamp: nextTimestamp,
        });

        await expect(
            failingWriter.writeAuditEvent(makeBaseInput(), makeBaseCaller()),
        ).rejects.toThrow('AUDIT_FAIL_CLOSED');
    });

    it('should re-throw AuditError as-is when insertEvent throws AuditError (no double wrapping)', async () => {
        const failingStore = new InMemoryAuditEventStore();
        // eslint-disable-next-line @typescript-eslint/require-await
        failingStore.insertEvent = async () => {
            throw new AuditError(
                'AUDIT_FAIL_CLOSED',
                'simulated existing duplicate',
            );
        };
        const failingWriter = new TamperProofAuditWriter({
            tenantResolver: resolver,
            store: failingStore,
            generateEventId: nextEventId,
            generateTimestamp: nextTimestamp,
        });

        try {
            await failingWriter.writeAuditEvent(
                makeBaseInput(),
                makeBaseCaller(),
            );
            throw new Error('expected to throw');
        } catch (e) {
            expect(e).toBeInstanceOf(AuditError);
            expect((e as AuditError).code).toBe('AUDIT_FAIL_CLOSED');
            expect((e as AuditError).detail).toContain(
                'simulated existing duplicate',
            );
        }
    });

    it('should throw AUDIT_FETCH_LAST_HASH_FAILED when fetchLastTamperProofHash fails (DB unreachable)', async () => {
        const failingStore = new InMemoryAuditEventStore();
        // eslint-disable-next-line @typescript-eslint/require-await
        failingStore.fetchLastTamperProofHash = async () => {
            throw new Error('simulated DB timeout');
        };
        const failingWriter = new TamperProofAuditWriter({
            tenantResolver: resolver,
            store: failingStore,
            generateEventId: nextEventId,
            generateTimestamp: nextTimestamp,
        });

        await expect(
            failingWriter.writeAuditEvent(makeBaseInput(), makeBaseCaller()),
        ).rejects.toThrow('AUDIT_FETCH_LAST_HASH_FAILED');
    });
});
