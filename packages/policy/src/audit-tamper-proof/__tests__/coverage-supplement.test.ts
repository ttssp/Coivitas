/**
 * coverage-supplement — fill in L3 uncovered branches/lines
 *
 * Primary coverage:
 *   1. TamperProofAuditWriter default generateEventId / generateTimestamp (361-372)
 *   2. AUDIT_SCHEMA_VIOLATION 3rd-layer fail-closed path (314-327)
 *   3. TamperProofAuditVerifier chain.length===0 storage state corruption (247-256)
 *   4. AUDIT_HASH_CHAIN_BROKEN genuine chain link broken (not hash tampering, which triggers TAMPER first)
 *   5. InMemoryAuditEventStore _testForceCorrupt edge cases + dup insert reject
 *   6. verifier signature=null fast-path already covered; reverse replay AuditError rethrow
 */

import { describe, expect, it, beforeEach } from 'vitest';
import {
    AuditError,
    type AuditEventId,
    type DID,
    type Timestamp,
    toAtpVersionString,
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
const DID_ALICE = 'did:key:z6MkAlice' as DID;

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
    return { actorDid: DID_ALICE, ...overrides };
}

describe('coverage-supplement: TamperProofAuditWriter default generators', () => {
    it('should generate UUID v4 eventId by default when generateEventId is not provided', async () => {
        const store = new InMemoryAuditEventStore();
        const resolver = new InMemoryTenantResolver();
        resolver.register(DID_ALICE, TENANT_A);

        const writer = new TamperProofAuditWriter({
            tenantResolver: resolver,
            store,
            // do not pass generateEventId / generateTimestamp; use the defaults
        });

        const ev = await writer.writeAuditEvent(makeBaseInput(), makeBaseCaller());
        try {
            // default generateEventId uses crypto.randomUUID → UUID v4
            expect(ev.eventId).toMatch(
                /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
            );
            // default generateTimestamp uses new Date().toISOString()
            expect(ev.timestamp).toMatch(
                /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/,
            );
        } finally {
            store.releaseAdvisoryLock(TENANT_A, toAuditClass('L1'));
        }
    });
});

describe('coverage-supplement: AUDIT_SCHEMA_VIOLATION 3rd line of defense fail-closed', () => {
    it('should throw AUDIT_SCHEMA_VIOLATION when generated event fails AJV validate (e.g. timestamp invalid)', async () => {
        const store = new InMemoryAuditEventStore();
        const resolver = new InMemoryTenantResolver();
        resolver.register(DID_ALICE, TENANT_A);

        // inject generateTimestamp returning a non-ISO 8601 format → AJV format date-time validate fail
        let eid = 0;
        const writer = new TamperProofAuditWriter({
            tenantResolver: resolver,
            store,
            generateEventId: () => {
                eid++;
                const hex = eid.toString(16).padStart(12, '0');
                return toAuditEventId(
                    `${hex.padStart(8, '0').slice(-8)}-bbbb-4ccc-8ddd-${hex.padStart(12, '0').slice(-12)}`,
                );
            },
            // provide a non-ISO 8601 timestamp to trigger AJV format date-time fail
            generateTimestamp: () => 'not-a-valid-date' as Timestamp,
        });

        await expect(
            writer.writeAuditEvent(makeBaseInput(), makeBaseCaller()),
        ).rejects.toThrow('AUDIT_SCHEMA_VIOLATION');
    });
});

describe('coverage-supplement: TamperProofAuditVerifier chain.length===0 storage corruption', () => {
    it('should return ok:false AUDIT_REVERSE_REPLAY_FAILED when fetchEventById returns event but fetchAllEvents returns []', async () => {
        const store = new InMemoryAuditEventStore();
        const verifier = new TamperProofAuditVerifier({ store });

        // construct an event and manually inject it into the store but bypass the chain (simulating storage state corruption)
        const event = {
            atpVersion: toAtpVersionString('1.0.0'),
            eventId: toAuditEventId(
                '11111111-bbbb-4ccc-8ddd-111111111111',
            ),
            tenantId: TENANT_A,
            auditClass: toAuditClass('L1'),
            actorDid: DID_ALICE,
            action: toAuditAction('TOKEN_VERIFY'),
            target: 'foo',
            canonicalPayload: '{"foo":"bar"}',
            tamperProofHash: toAuditEventHash('a'.repeat(64)),
            previousHash: null,
            timestamp: '2026-05-13T00:00:00.000Z' as Timestamp,
            signature: null,
        };

        // inject directly into the events Map (without going through insertEvent; chainsByTenantClass is not updated)
        // access private fields; allowed in the test stub context (not production)
        (store as unknown as { events: Map<string, typeof event> }).events.set(
            event.eventId,
            event,
        );

        const result = await verifier.verifyAuditEvent({
            eventId: event.eventId,
            tenantId: TENANT_A,
        });
        expect(result.ok).toBe(false);
        if (!result.ok) {
            expect(result.error.code).toBe('AUDIT_REVERSE_REPLAY_FAILED');
        }
    });
});

describe('coverage-supplement: AUDIT_HASH_CHAIN_BROKEN (chain link broken; mock storage)', () => {
    it('should detect AUDIT_HASH_CHAIN_BROKEN via storage mock where chain[2] previousHash links to non-existent hash X (X != chain[1].tamperProofHash) and hash itself recomputes successfully', async () => {
        // use a storage mock to inject a 2-event chain:
        // chain[0]: GENESIS; tamperProofHash = H0 (real-recompute); previousHash = null
        // chain[1]: previousHash = WRONG_HASH (a fixed 64 hex, not H0); tamperProofHash = computed for real using WRONG_HASH
        // so that:
        // - recomputedHash check chain[1] = sha256(buildInput with previousHash=WRONG_HASH) → matches stored
        // - previousHash chain check chain[1].previousHash !== chain[0].tamperProofHash → HASH_CHAIN_BROKEN fail
        const store = new InMemoryAuditEventStore();
        const resolver = new InMemoryTenantResolver();
        resolver.register(DID_ALICE, TENANT_A);
        let eid = 0;
        const writer = new TamperProofAuditWriter({
            tenantResolver: resolver,
            store,
            generateEventId: () => {
                eid++;
                const hex = eid.toString(16).padStart(12, '0');
                return toAuditEventId(
                    `${hex.padStart(8, '0').slice(-8)}-bbbb-4ccc-8ddd-${hex.padStart(12, '0').slice(-12)}`,
                );
            },
            generateTimestamp: () => '2026-05-13T00:00:00.000Z' as Timestamp,
        });
        const verifier = new TamperProofAuditVerifier({ store });

        // write two events along the normal chain
        const e1 = await writer.writeAuditEvent(makeBaseInput(), makeBaseCaller());
        store.releaseAdvisoryLock(TENANT_A, toAuditClass('L1'));
        const e2 = await writer.writeAuditEvent(
            makeBaseInput({ target: 'token-id-002', payload: { foo: 'bar2' } }),
            makeBaseCaller(),
        );
        store.releaseAdvisoryLock(TENANT_A, toAuditClass('L1'));

        // via mock chain mutation, fully replace e1 with a different event (same eventId but different hash);
        // keep e2.previousHash still = the original e1.tamperProofHash (chain stale);
        // while e1's new tamperProofHash no longer equals e2.previousHash → HASH_CHAIN_BROKEN

        // here we directly mock store.fetchAllEvents to return a hand-assembled chain (e1 with replaced hash; e2 original)
        // note: e1's new hash must match itself after recompute; otherwise TAMPER fails first

        // simplified path: construct a fake e1_alt whose fields all differ except for hash;
        // call buildTamperProofHashInput to compute the correct hash; then mock fetchAllEvents to return [e1_alt, e2]
        // now e1_alt.tamperProofHash recomputes OK; but e2.previousHash !== e1_alt.tamperProofHash → CHAIN_BROKEN

        // simplification strategy: copy e1 but rename its action → recompute hash differs → chain[0] tamperProofHash field must be aligned
        // compute the new hash directly with buildTamperProofHashInput
        const e1Alt = { ...e1, action: toAuditAction('DIFFERENT_ACTION') };
        // this helper reuses the internal export pattern of build-tamper-proof-hash-input
        const { buildTamperProofHashInput } = await import(
            '../build-tamper-proof-hash-input.js'
        );
        const { hash } = await import('@coivitas/crypto');
        const newHash = hash(buildTamperProofHashInput(e1Alt), 'hex');
        const e1AltWithHash = { ...e1Alt, tamperProofHash: toAuditEventHash(newHash) };

        // mock fetchAllEvents
        // eslint-disable-next-line @typescript-eslint/require-await
        store.fetchAllEvents = async () => [e1AltWithHash, e2];

        const result = await verifier.verifyAuditEvent({
            eventId: e2.eventId,
            tenantId: TENANT_A,
        });
        expect(result.ok).toBe(false);
        if (!result.ok) {
            // chain[0] recomputes OK (action's new hash already aligned);
            // chain[1] (e2) recomputes using e2's original fields → recomputedHash matches stored;
            // but the chain link check: e2.previousHash !== e1AltWithHash.tamperProofHash → HASH_CHAIN_BROKEN
            expect(result.error.code).toBe('AUDIT_HASH_CHAIN_BROKEN');
        }
    });

    it('original placeholder test (kept for reference)', async () => {
        // this scenario is fairly hard to manufacture (recomputedHash must match yet previousHash does not link to the prior node);
        // real-world path: the tamper-proof hash input includes previousHash; changing previousHash → recomputedHash also changes; TAMPER fails first

        // but with a storage-corruption simulation: inject "chain[2]'s previousHash equals hash X but X !== chain[1].tamperProofHash"
        // while chain[2]'s tamperProofHash is actually computed with previousHash=X → recomputedHash matches X but the chain link is broken

        // inject into the inMemory store so reverseHashChainReplay hits the HASH_CHAIN_BROKEN guard:
        // need to construct a chain[2] whose previousHash is X (fixed hex) and whose tamperProofHash is computed with X;
        // while chain[1].tamperProofHash !== X (chain link broken)

        // simplified test: with a chain of length 2, change chain[1].previousHash to a non-null but wrong value of chain[0].tamperProofHash
        // (recomputedHash then does not match → TAMPER fails first);

        // the genuine HASH_CHAIN_BROKEN path is more realistic to test on the production PostgresAuditEventStore side;
        // this unit test only triggers TAMPER (first) on the in-memory store;
        // the chain-rewire attack scenario will be added later in the PostgresAuditEventStore integration test.

        // here we only comment on the design intent of the chain-broken path; the actual line 317-328 coverage comes from a storage-corruption
        // simulation where fetchAllEvents returns a chain (in which chain[2] previousHash uses hash X; chain[1].tamperProofHash !== X
        // while chain[2] tamperProofHash is actually computed with previousHash=X) — taking the store mock path below
        const store = new InMemoryAuditEventStore();
        // genuinely constructing the chain-broken scenario is too complex (recomputedHash must be computed with the wrong previousHash;
        // but the hash algorithm cannot avoid recomputing for a mock chain); so this case is left as integration-test backlog for now
        // (to be added later in PostgresAuditEventStore); here it is just a placeholder noting the branch has been identified.
        expect(store).toBeDefined();
    });
});

describe('coverage-supplement: InMemoryAuditEventStore edge cases', () => {
    it('should throw AUDIT_FAIL_CLOSED when insertEvent called with duplicate eventId (append-only)', async () => {
        const store = new InMemoryAuditEventStore();
        const event = {
            atpVersion: toAtpVersionString('1.0.0'),
            eventId: toAuditEventId(
                '11111111-bbbb-4ccc-8ddd-222222222222',
            ),
            tenantId: TENANT_A,
            auditClass: toAuditClass('L1'),
            actorDid: DID_ALICE,
            action: toAuditAction('TOKEN_VERIFY'),
            target: 'foo',
            canonicalPayload: '{"a":1}',
            tamperProofHash: toAuditEventHash('a'.repeat(64)),
            previousHash: null,
            timestamp: '2026-05-13T00:00:00.000Z' as Timestamp,
            signature: null,
        };
        await store.insertEvent(event);
        await expect(store.insertEvent(event)).rejects.toThrow(
            'AUDIT_FAIL_CLOSED',
        );
    });

    it('should throw Error when _testForceCorruptEvent called with unknown eventId', () => {
        const store = new InMemoryAuditEventStore();
        const fakeId = toAuditEventId('ffffffff-bbbb-4ccc-8ddd-ffffffffffff');
        expect(() =>
            store._testForceCorruptEvent(fakeId, toAuditEventHash('a'.repeat(64))),
        ).toThrow('not found');
    });

    it('should throw Error when _testForceCorruptPreviousHash called with unknown eventId', () => {
        const store = new InMemoryAuditEventStore();
        const fakeId = toAuditEventId('eeeeeeee-bbbb-4ccc-8ddd-eeeeeeeeeeee');
        expect(() =>
            store._testForceCorruptPreviousHash(fakeId, null),
        ).toThrow('not found');
    });

    it('should return null fetchLastTamperProofHash when chain is empty', async () => {
        const store = new InMemoryAuditEventStore();
        const result = await store.fetchLastTamperProofHash(
            TENANT_A,
            toAuditClass('L1'),
        );
        expect(result).toBeNull();
    });

    it('should return null fetchEventById when cross-tenant query', async () => {
        const store = new InMemoryAuditEventStore();
        const event = {
            atpVersion: toAtpVersionString('1.0.0'),
            eventId: toAuditEventId(
                'cccccccc-bbbb-4ccc-8ddd-cccccccccccc',
            ),
            tenantId: TENANT_A,
            auditClass: toAuditClass('L1'),
            actorDid: DID_ALICE,
            action: toAuditAction('TOKEN_VERIFY'),
            target: 'foo',
            canonicalPayload: '{"a":1}',
            tamperProofHash: toAuditEventHash('a'.repeat(64)),
            previousHash: null,
            timestamp: '2026-05-13T00:00:00.000Z' as Timestamp,
            signature: null,
        };
        await store.insertEvent(event);
        const other = toTenantId('99999999-aaaa-4bbb-8ccc-999999999999');
        const result = await store.fetchEventById(event.eventId, other);
        expect(result).toBeNull();
    });

    it('should release advisory lock allowing next acquire to proceed', async () => {
        const store = new InMemoryAuditEventStore();
        await store.acquireAdvisoryLock(TENANT_A, toAuditClass('L1'));
        store.releaseAdvisoryLock(TENANT_A, toAuditClass('L1'));
        // the 2nd acquire should resolve immediately (no hang)
        const startTs = Date.now();
        await store.acquireAdvisoryLock(TENANT_A, toAuditClass('L1'));
        const elapsed = Date.now() - startTs;
        // should not exceed 50ms (measured to be < 5ms; 50ms buffer given to avoid CI jitter)
        expect(elapsed).toBeLessThan(50);
        store.releaseAdvisoryLock(TENANT_A, toAuditClass('L1'));
    });

    it('should serialize 2 concurrent acquireAdvisoryLock calls (second waits for first release)', async () => {
        const store = new InMemoryAuditEventStore();
        await store.acquireAdvisoryLock(TENANT_A, toAuditClass('L1'));
        let secondAcquired = false;
        const secondPromise = store
            .acquireAdvisoryLock(TENANT_A, toAuditClass('L1'))
            .then(() => {
                secondAcquired = true;
            });
        // while not released, the second acquire should stay pending
        await new Promise((r) => setTimeout(r, 20));
        expect(secondAcquired).toBe(false);
        store.releaseAdvisoryLock(TENANT_A, toAuditClass('L1'));
        await secondPromise;
        expect(secondAcquired).toBe(true);
        store.releaseAdvisoryLock(TENANT_A, toAuditClass('L1'));
    });
});

describe('coverage-supplement: verifier non-AuditError catch wrap', () => {
    it('should wrap non-AuditError thrown internally as AUDIT_REVERSE_REPLAY_FAILED', async () => {
        const store = new InMemoryAuditEventStore();
        const resolver = new InMemoryTenantResolver();
        resolver.register(DID_ALICE, TENANT_A);
        let eid = 0;
        const writer = new TamperProofAuditWriter({
            tenantResolver: resolver,
            store,
            generateEventId: () => {
                eid++;
                const hex = eid.toString(16).padStart(12, '0');
                return toAuditEventId(
                    `${hex.padStart(8, '0').slice(-8)}-bbbb-4ccc-8ddd-${hex.padStart(12, '0').slice(-12)}`,
                );
            },
            generateTimestamp: () => '2026-05-13T00:00:00.000Z' as Timestamp,
        });
        const verifier = new TamperProofAuditVerifier({ store });
        const ev = await writer.writeAuditEvent(makeBaseInput(), makeBaseCaller());
        store.releaseAdvisoryLock(TENANT_A, toAuditClass('L1'));

        // inject a fetchEventById that throws a non-AuditError
        // eslint-disable-next-line @typescript-eslint/require-await
        store.fetchEventById = async () => {
            throw new Error('simulated unexpected error');
        };
        const result = await verifier.verifyAuditEvent({
            eventId: ev.eventId,
            tenantId: TENANT_A,
        });
        expect(result.ok).toBe(false);
        if (!result.ok) {
            // the verifier catch block wraps it as AUDIT_REVERSE_REPLAY_FAILED
            expect(result.error.code).toBe('AUDIT_REVERSE_REPLAY_FAILED');
        }
    });
});
