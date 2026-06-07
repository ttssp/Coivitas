/**
 * Cross-trust-domain cumulative settle protocol tests
 *
 * Test coverage matrix:
 * === pure protocol logic (no PG dependency) ===
 * 1. buildSettlePayload determinism
 * 2. buildSettlePayload produces different payloads for different fields
 * 3. Ed25519 signature creation and verification (sign/verify)
 * 4. verification fails with the wrong public key
 * 5. payload tampering detection
 * 6. SenderSettleTracker.createSettleRequest creates a valid signed request
 * 7. unique settleId generation (UUID v4)
 * 8. DEFAULT_CONFIG defaults (5min TTL / 30s interval / 100 batch)
 * 9. assertSafeSchemaName rejects dangerous input (SQL injection protection)
 * 10. toISOString handles Date objects
 *
 * === PG integration tests (require DATABASE_URL) ===
 * 11. appendSettle writes PENDING state
 * 12. appendSettle idempotency (same settleId not written twice)
 * 13. appendSettle rejects the wrong public key
 * 14. confirmSettle batch PENDING → SETTLED
 * 15. confirmSettle does not transition TTL-expired records
 * 16. reapExpiredPending reaps expired PENDING records
 * 17. reconcile basic reconciliation flow (Ed25519 verification)
 * 18. reconcile composite cursor prevents double-counting
 * 19. reconcile network partition + recovery
 * 20. reconcile agentDid isolation
 * 21. reconcile metric isolation
 * 22. PendingReaper background scheduled reaping
 * 23. concurrent idempotency (multiple appendSettle with the same settleId)
 *
 * PG tests use schema isolation (test_settle_domain_a / test_settle_domain_b),
 * rebuilt each beforeEach, cleaned up in afterAll.
 */

import { generateKeyPair, sign, verify } from '@coivitas/crypto';
import { createPool } from '@coivitas/shared';
import { Pool } from 'pg';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import { buildSettlePayload, toISOString } from '../payload.js';
import { dropDomainSchema, initDomainSchema } from '../schema.js';
import { RecipientSettleHandler } from '../settle-handler.js';
import { SenderSettleTracker } from '../settle-tracker.js';
import { DEFAULT_CONFIG } from '../types.js';
import { PendingReaper } from '../pending-reaper.js';

// ========== test constants ==========

const SCHEMA_A = 'test_settle_domain_a';
const SCHEMA_B = 'test_settle_domain_b';
const DOMAIN_A = 'trust-domain-a.example.com';
const DOMAIN_B = 'trust-domain-b.example.com';
const AGENT_DID = 'did:agent:test-agent-1';
const METRIC = 'transaction_amount';
const WINDOW_START = '2026-05-01T00:00:00.000Z';

// PG availability gating
const PG_SKIP = !process.env['DATABASE_URL'];
const CONNECTION_STRING =
    process.env['DATABASE_URL'] ??
    'postgresql://coivitas:coivitas@localhost:5432/coivitas_dev';

// ========== pure protocol logic tests (no PG dependency) ==========

describe('cross-domain settle protocol logic (no PG dependency)', () => {
    // generate a fresh key pair per test to ensure isolation
    const keyA = generateKeyPair();
    const keyB = generateKeyPair();

    describe('buildSettlePayload determinism', () => {
        it('should build deterministic payload when given same inputs', () => {
            const base = {
                settleId: 'test-settle-001',
                senderDomain: DOMAIN_A,
                recipientDomain: DOMAIN_B,
                agentDid: AGENT_DID,
                metric: METRIC,
                amount: 5000,
                window: 'day',
                windowStart: WINDOW_START,
            };
            expect(buildSettlePayload(base)).toBe(buildSettlePayload(base));
        });

        it('should produce different payloads when amount differs', () => {
            const base = {
                settleId: 'test-settle-001',
                senderDomain: DOMAIN_A,
                recipientDomain: DOMAIN_B,
                agentDid: AGENT_DID,
                metric: METRIC,
                window: 'day',
                windowStart: WINDOW_START,
            };
            expect(buildSettlePayload({ ...base, amount: 5000 })).not.toBe(
                buildSettlePayload({ ...base, amount: 3000 }),
            );
        });

        it('should produce different payloads when settleId differs', () => {
            const base = {
                senderDomain: DOMAIN_A,
                recipientDomain: DOMAIN_B,
                agentDid: AGENT_DID,
                metric: METRIC,
                amount: 100,
                window: 'day',
                windowStart: WINDOW_START,
            };
            expect(buildSettlePayload({ ...base, settleId: 'id-1' })).not.toBe(
                buildSettlePayload({ ...base, settleId: 'id-2' }),
            );
        });

        it('should include all required fields in payload', () => {
            const payload = buildSettlePayload({
                settleId: 'test-001',
                senderDomain: DOMAIN_A,
                recipientDomain: DOMAIN_B,
                agentDid: AGENT_DID,
                metric: METRIC,
                amount: 500,
                window: 'hour',
                windowStart: WINDOW_START,
            });
            const parsed = JSON.parse(payload) as Record<string, unknown>;
            expect(parsed).toMatchObject({
                settleId: 'test-001',
                senderDomain: DOMAIN_A,
                recipientDomain: DOMAIN_B,
                agentDid: AGENT_DID,
                metric: METRIC,
                amount: 500,
                window: 'hour',
                windowStart: WINDOW_START,
            });
        });
    });

    describe('Ed25519 signature verification', () => {
        it('should sign and verify correctly with matching key pair', () => {
            const payload = buildSettlePayload({
                settleId: 'sig-test-001',
                senderDomain: DOMAIN_A,
                recipientDomain: DOMAIN_B,
                agentDid: AGENT_DID,
                metric: METRIC,
                amount: 1000,
                window: 'day',
                windowStart: WINDOW_START,
            });
            const bytes = Buffer.from(payload, 'utf-8');
            const sig = sign(bytes, keyA.privateKey);
            expect(verify(bytes, sig, keyA.publicKey)).toBe(true);
        });

        it('should fail verification when using wrong public key', () => {
            const payload = buildSettlePayload({
                settleId: 'sig-test-002',
                senderDomain: DOMAIN_A,
                recipientDomain: DOMAIN_B,
                agentDid: AGENT_DID,
                metric: METRIC,
                amount: 1000,
                window: 'day',
                windowStart: WINDOW_START,
            });
            const bytes = Buffer.from(payload, 'utf-8');
            const sig = sign(bytes, keyA.privateKey);
            // verify keyA's signature with keyB's public key → false
            expect(verify(bytes, sig, keyB.publicKey)).toBe(false);
        });

        it('should fail verification when payload is tampered', () => {
            const originalPayload = buildSettlePayload({
                settleId: 'sig-test-003',
                senderDomain: DOMAIN_A,
                recipientDomain: DOMAIN_B,
                agentDid: AGENT_DID,
                metric: METRIC,
                amount: 5000,
                window: 'day',
                windowStart: WINDOW_START,
            });
            const originalBytes = Buffer.from(originalPayload, 'utf-8');
            const sig = sign(originalBytes, keyA.privateKey);

            // rebuild the payload after tampering with the amount
            const tamperedPayload = buildSettlePayload({
                settleId: 'sig-test-003',
                senderDomain: DOMAIN_A,
                recipientDomain: DOMAIN_B,
                agentDid: AGENT_DID,
                metric: METRIC,
                amount: 500, // tampered
                window: 'day',
                windowStart: WINDOW_START,
            });
            const tamperedBytes = Buffer.from(tamperedPayload, 'utf-8');
            expect(verify(tamperedBytes, sig, keyA.publicKey)).toBe(false);
        });
    });

    describe('SenderSettleTracker.createSettleRequest (in-memory only)', () => {
        it('should create a valid settle request with Ed25519 signature', () => {
            // createSettleRequest needs no PG connection; the dummy pool is never called
            const dummyPool = {} as Pool;
            const tracker = new SenderSettleTracker(
                dummyPool,
                SCHEMA_A,
                keyA.privateKey,
                keyA.publicKey,
                DOMAIN_A,
            );
            const req = tracker.createSettleRequest({
                recipientDomain: DOMAIN_B,
                agentDid: AGENT_DID,
                metric: METRIC,
                amount: 5000,
                window: 'day',
                windowStart: WINDOW_START,
            });

            expect(req.settleId).toBeTruthy();
            expect(req.senderDomain).toBe(DOMAIN_A);
            expect(req.recipientDomain).toBe(DOMAIN_B);
            expect(req.amount).toBe(5000);
            expect(req.senderLedgerSignature).toBeTruthy();

            // verify the Ed25519 signature is correct
            const payload = buildSettlePayload(req);
            const bytes = Buffer.from(payload, 'utf-8');
            expect(
                verify(bytes, req.senderLedgerSignature, keyA.publicKey),
            ).toBe(true);
        });

        it('should generate unique settle IDs for different requests', () => {
            const dummyPool = {} as Pool;
            const tracker = new SenderSettleTracker(
                dummyPool,
                SCHEMA_A,
                keyA.privateKey,
                keyA.publicKey,
                DOMAIN_A,
            );
            const ids = new Set<string>();
            for (let i = 0; i < 10; i++) {
                const req = tracker.createSettleRequest({
                    recipientDomain: DOMAIN_B,
                    agentDid: AGENT_DID,
                    metric: METRIC,
                    amount: 100 * (i + 1),
                    window: 'day',
                    windowStart: WINDOW_START,
                });
                ids.add(req.settleId);
            }
            expect(ids.size).toBe(10);
        });
    });

    describe('DEFAULT_CONFIG defaults', () => {
        it('should have 5-minute pending TTL', () => {
            expect(DEFAULT_CONFIG.pendingTtlMs).toBe(5 * 60 * 1000);
        });

        it('should have 30-second reap interval', () => {
            expect(DEFAULT_CONFIG.reapIntervalMs).toBe(30 * 1000);
        });

        it('should have batch size of 100', () => {
            expect(DEFAULT_CONFIG.reconcileBatchSize).toBe(100);
        });
    });

    describe('assertSafeSchemaName (SQL injection protection)', () => {
        it('should reject schema names with special characters', async () => {
            // initDomainSchema calls assertSafeSchemaName internally
            // input validation can be verified without a real PG connection
            const { initDomainSchema: init } = await import('../schema.js');
            const fakePool = {
                query: () => Promise.resolve(),
            } as unknown as Pool;

            await expect(
                init(fakePool, "evil'; DROP TABLE settle_records; --"),
            ).rejects.toThrow('SETTLE_SCHEMA_INVALID');
            await expect(init(fakePool, 'UPPERCASE_SCHEMA')).rejects.toThrow(
                'SETTLE_SCHEMA_INVALID',
            );
            await expect(
                init(fakePool, '123_starts_with_digit'),
            ).rejects.toThrow('SETTLE_SCHEMA_INVALID');
            await expect(init(fakePool, '')).rejects.toThrow(
                'SETTLE_SCHEMA_INVALID',
            );
        });

        it('should accept valid schema names', async () => {
            const { initDomainSchema: init } = await import('../schema.js');
            // mock PG pool (all return resolved)
            const queries: string[] = [];
            const fakePool = {
                query: (sql: string) => {
                    queries.push(sql);
                    return Promise.resolve({ rows: [], rowCount: 0 });
                },
            } as unknown as Pool;

            // should not throw
            await expect(
                init(fakePool, 'valid_schema'),
            ).resolves.toBeUndefined();
            await expect(init(fakePool, 'schema123')).resolves.toBeUndefined();
            await expect(
                init(fakePool, 'test_settle_domain_b'),
            ).resolves.toBeUndefined();
        });
    });

    describe('toISOString', () => {
        it('should return ISO 8601 string when given Date object', () => {
            const date = new Date('2026-05-01T00:00:00.000Z');
            expect(toISOString(date)).toBe('2026-05-01T00:00:00.000Z');
        });

        it('should pass through string unchanged', () => {
            const str = '2026-05-01T00:00:00.000Z';
            expect(toISOString(str)).toBe(str);
        });

        it('should not produce locale-format strings from Date', () => {
            const date = new Date('2026-05-01T00:00:00.000Z');
            const result = toISOString(date);
            // locale format (e.g. "Thu May 01 2026") would NOT end with 'Z'
            expect(result).toMatch(
                /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/,
            );
        });
    });
});

// ========== PG integration tests ==========

describe.skipIf(PG_SKIP)('cross-domain settle PG integration tests', () => {
    let pool: Pool;
    let recipientHandler: RecipientSettleHandler;
    let senderTracker: SenderSettleTracker;
    let keyA: { publicKey: string; privateKey: string };
    let keyB: { publicKey: string; privateKey: string };

    beforeAll(() => {
        pool = createPool({ connectionString: CONNECTION_STRING });
        keyA = generateKeyPair();
        keyB = generateKeyPair();
    });

    beforeEach(async () => {
        // rebuild both schemas before each test to ensure full isolation
        await dropDomainSchema(pool, SCHEMA_A);
        await dropDomainSchema(pool, SCHEMA_B);
        await initDomainSchema(pool, SCHEMA_A);
        await initDomainSchema(pool, SCHEMA_B);

        // recipient countersigns with keyB private key, verifies the sender signature with keyA public key
        recipientHandler = new RecipientSettleHandler(
            pool,
            SCHEMA_B,
            keyB.privateKey,
        );

        // sender signs the request with the keyA private key
        senderTracker = new SenderSettleTracker(
            pool,
            SCHEMA_A,
            keyA.privateKey,
            keyA.publicKey,
            DOMAIN_A,
        );
    });

    afterAll(async () => {
        await dropDomainSchema(pool, SCHEMA_A);
        await dropDomainSchema(pool, SCHEMA_B);
        await pool.end();
    });

    it('should write settle record in PENDING state when appendSettle is called', async () => {
        const req = senderTracker.createSettleRequest({
            recipientDomain: DOMAIN_B,
            agentDid: AGENT_DID,
            metric: METRIC,
            amount: 5000,
            window: 'day',
            windowStart: WINDOW_START,
        });

        const record = await recipientHandler.appendSettle(req, keyA.publicKey);

        expect(record.settleId).toBe(req.settleId);
        expect(record.state).toBe('PENDING');
        expect(record.senderDomain).toBe(DOMAIN_A);
        expect(record.recipientDomain).toBe(DOMAIN_B);
        expect(record.amount).toBe(5000);
        expect(record.settledAt).toBeNull();
        expect(record.expiresAt).toBeTruthy();

        // recipientLedgerSignature should be a valid Ed25519 signature (keyB private key)
        const payload = buildSettlePayload(req);
        const bytes = Buffer.from(payload, 'utf-8');
        expect(
            verify(bytes, record.recipientLedgerSignature, keyB.publicKey),
        ).toBe(true);
    });

    it('should be idempotent when appendSettle called twice with same settleId', async () => {
        const req = senderTracker.createSettleRequest({
            recipientDomain: DOMAIN_B,
            agentDid: AGENT_DID,
            metric: METRIC,
            amount: 100,
            window: 'day',
            windowStart: WINDOW_START,
        });

        const record1 = await recipientHandler.appendSettle(
            req,
            keyA.publicKey,
        );
        const record2 = await recipientHandler.appendSettle(
            req,
            keyA.publicKey,
        );

        expect(record1.settleId).toBe(record2.settleId);
        expect(record1.state).toBe(record2.state);
        expect(record1.recipientLedgerSignature).toBe(
            record2.recipientLedgerSignature,
        );
    });

    it('should reject appendSettle when sender signature uses wrong key', async () => {
        // sign with keyB private key, but claim to the recipient it was signed with the keyA public key
        const wrongKeyReq: ReturnType<
            typeof senderTracker.createSettleRequest
        > = (() => {
            const tracker2 = new SenderSettleTracker(
                pool,
                SCHEMA_A,
                keyB.privateKey, // wrong: signs with B's private key
                keyB.publicKey,
                DOMAIN_A,
            );
            return tracker2.createSettleRequest({
                recipientDomain: DOMAIN_B,
                agentDid: AGENT_DID,
                metric: METRIC,
                amount: 9999,
                window: 'day',
                windowStart: WINDOW_START,
            });
        })();

        // but tells the recipient to verify with the keyA public key → verification fails
        await expect(
            recipientHandler.appendSettle(wrongKeyReq, keyA.publicKey),
        ).rejects.toThrow('SETTLE_SIGNATURE_INVALID');
    });

    it('should transition PENDING to SETTLED when confirmSettle is called (batch)', async () => {
        const req = senderTracker.createSettleRequest({
            recipientDomain: DOMAIN_B,
            agentDid: AGENT_DID,
            metric: METRIC,
            amount: 200,
            window: 'day',
            windowStart: WINDOW_START,
        });

        await recipientHandler.appendSettle(req, keyA.publicKey);
        // batch confirm (single item passed as a list)
        await recipientHandler.confirmSettle([req.settleId]);

        const records = await recipientHandler.querySettles({
            senderDomain: DOMAIN_A,
            agentDid: AGENT_DID,
            metric: METRIC,
            limit: 10,
        });
        const record = records.find((r) => r.settleId === req.settleId);
        expect(record?.state).toBe('SETTLED');
        expect(record?.settledAt).not.toBeNull();
    });

    it('should not confirm settle when record is expired (TTL guard)', async () => {
        // set TTL to 1ms so it expires immediately
        const tinyTtlHandler = new RecipientSettleHandler(
            pool,
            SCHEMA_B,
            keyB.privateKey,
            {
                pendingTtlMs: 1,
                reapIntervalMs: 30_000,
                reconcileBatchSize: 100,
            },
        );

        const req = senderTracker.createSettleRequest({
            recipientDomain: DOMAIN_B,
            agentDid: AGENT_DID,
            metric: METRIC,
            amount: 300,
            window: 'day',
            windowStart: WINDOW_START,
        });

        await tinyTtlHandler.appendSettle(req, keyA.publicKey);

        // wait for the record to expire
        await new Promise((resolve) => setTimeout(resolve, 10));

        // attempt to confirm the expired record (should be silently ignored, not throw)
        await expect(
            tinyTtlHandler.confirmSettle([req.settleId]),
        ).resolves.toBeUndefined();

        // state should still be PENDING (reaper not running), not SETTLED
        const records = await tinyTtlHandler.querySettles({
            senderDomain: DOMAIN_A,
            agentDid: AGENT_DID,
            metric: METRIC,
            limit: 10,
        });
        const record = records.find((r) => r.settleId === req.settleId);
        expect(record?.state).toBe('PENDING'); // neither reaped by the reaper nor confirmed
    });

    it('should mark expired PENDING records as RELEASED when reapExpiredPending is called', async () => {
        const tinyTtlHandler = new RecipientSettleHandler(
            pool,
            SCHEMA_B,
            keyB.privateKey,
            {
                pendingTtlMs: 1,
                reapIntervalMs: 30_000,
                reconcileBatchSize: 100,
            },
        );

        // write 3 records
        const reqs = [];
        for (let i = 0; i < 3; i++) {
            const req = senderTracker.createSettleRequest({
                recipientDomain: DOMAIN_B,
                agentDid: AGENT_DID,
                metric: METRIC,
                amount: 100 * (i + 1),
                window: 'day',
                windowStart: WINDOW_START,
            });
            await tinyTtlHandler.appendSettle(req, keyA.publicKey);
            reqs.push(req);
        }

        // wait for expiry
        await new Promise((resolve) => setTimeout(resolve, 10));

        const reaped = await tinyTtlHandler.reapExpiredPending();
        expect(reaped).toBe(3);

        // all records should be RELEASED
        const records = await tinyTtlHandler.querySettles({
            senderDomain: DOMAIN_A,
            agentDid: AGENT_DID,
            metric: METRIC,
            limit: 10,
        });
        for (const r of records) {
            expect(r.state).toBe('RELEASED');
        }
    });

    it('should reconcile settle records with Ed25519 signature verification', async () => {
        // sender creates 3 settle requests
        const reqs = [];
        for (let i = 0; i < 3; i++) {
            const req = senderTracker.createSettleRequest({
                recipientDomain: DOMAIN_B,
                agentDid: AGENT_DID,
                metric: METRIC,
                amount: 100 * (i + 1),
                window: 'day',
                windowStart: WINDOW_START,
            });
            await recipientHandler.appendSettle(req, keyA.publicKey);
            reqs.push(req);
        }

        // run reconciliation
        const results = await senderTracker.reconcile(
            recipientHandler,
            keyB.publicKey,
            AGENT_DID,
            METRIC,
            DOMAIN_B,
        );

        expect(results).toHaveLength(3);
        for (const r of results) {
            expect(r.verified).toBe(true);
            // result.state reflects the "fetch-time" PENDING; confirmSettle only takes
            // effect after verified; query the recipient directly to check the post-reconcile SETTLED state.
            expect(r.state).toBe('PENDING');
        }

        // after reconciliation the recipient side should have transitioned to SETTLED
        const records = await recipientHandler.querySettles({
            senderDomain: DOMAIN_A,
            agentDid: AGENT_DID,
            metric: METRIC,
            limit: 10,
        });
        expect(records).toHaveLength(3);
        for (const r of records) {
            expect(r.state).toBe('SETTLED');
        }
    });

    it('should prevent double-counting with composite cursor', async () => {
        // write 5 records
        for (let i = 0; i < 5; i++) {
            const req = senderTracker.createSettleRequest({
                recipientDomain: DOMAIN_B,
                agentDid: AGENT_DID,
                metric: METRIC,
                amount: 100,
                window: 'day',
                windowStart: WINDOW_START,
            });
            await recipientHandler.appendSettle(req, keyA.publicKey);
        }

        // first reconciliation (batch size = 3)
        const tracker3 = new SenderSettleTracker(
            pool,
            SCHEMA_A,
            keyA.privateKey,
            keyA.publicKey,
            DOMAIN_A,
            {
                ...DEFAULT_CONFIG,
                reconcileBatchSize: 3,
            },
        );
        const results1 = await tracker3.reconcile(
            recipientHandler,
            keyB.publicKey,
            AGENT_DID,
            METRIC,
            DOMAIN_B,
        );
        expect(results1).toHaveLength(3);

        // second reconciliation (should continue from the cursor, returning only the remaining 2)
        const results2 = await tracker3.reconcile(
            recipientHandler,
            keyB.publicKey,
            AGENT_DID,
            METRIC,
            DOMAIN_B,
        );
        expect(results2).toHaveLength(2);

        // third reconciliation (cursor already at the end, should return empty)
        const results3 = await tracker3.reconcile(
            recipientHandler,
            keyB.publicKey,
            AGENT_DID,
            METRIC,
            DOMAIN_B,
        );
        expect(results3).toHaveLength(0);
    });

    it('should recover from network partition and complete reconciliation', async () => {
        // write 5 records
        const totalReqs = [];
        for (let i = 0; i < 5; i++) {
            const req = senderTracker.createSettleRequest({
                recipientDomain: DOMAIN_B,
                agentDid: AGENT_DID,
                metric: METRIC,
                amount: 100,
                window: 'day',
                windowStart: WINDOW_START,
            });
            await recipientHandler.appendSettle(req, keyA.publicKey);
            totalReqs.push(req);
        }

        // simulate partition: reconcile batch = 2, first pass only handles 2 records
        const partitionTracker = new SenderSettleTracker(
            pool,
            SCHEMA_A,
            keyA.privateKey,
            keyA.publicKey,
            DOMAIN_A,
            {
                ...DEFAULT_CONFIG,
                reconcileBatchSize: 2,
            },
        );
        const r1 = await partitionTracker.reconcile(
            recipientHandler,
            keyB.publicKey,
            AGENT_DID,
            METRIC,
            DOMAIN_B,
        );
        expect(r1).toHaveLength(2);

        // continue reconciliation after recovery (write more records to simulate new transactions during recovery)
        for (let i = 0; i < 2; i++) {
            const req = senderTracker.createSettleRequest({
                recipientDomain: DOMAIN_B,
                agentDid: AGENT_DID,
                metric: METRIC,
                amount: 200,
                window: 'day',
                windowStart: WINDOW_START,
            });
            await recipientHandler.appendSettle(req, keyA.publicKey);
        }

        const r2 = await partitionTracker.reconcile(
            recipientHandler,
            keyB.publicKey,
            AGENT_DID,
            METRIC,
            DOMAIN_B,
        );
        // batch = 2, continuing from the cursor
        expect(r2).toHaveLength(2);

        const r3 = await partitionTracker.reconcile(
            recipientHandler,
            keyB.publicKey,
            AGENT_DID,
            METRIC,
            DOMAIN_B,
        );
        // last 3 (5-2=3 + 2=7 total, 4 taken, 3 remaining, batch 2 → take 2)
        expect(r3).toHaveLength(2);

        const r4 = await partitionTracker.reconcile(
            recipientHandler,
            keyB.publicKey,
            AGENT_DID,
            METRIC,
            DOMAIN_B,
        );
        // last 1
        expect(r4).toHaveLength(1);

        // reconciliation now complete
        const r5 = await partitionTracker.reconcile(
            recipientHandler,
            keyB.publicKey,
            AGENT_DID,
            METRIC,
            DOMAIN_B,
        );
        expect(r5).toHaveLength(0);
    });

    it('should isolate settle records by agentDid', async () => {
        const agentDid2 = 'did:agent:different-agent';

        const req1 = senderTracker.createSettleRequest({
            recipientDomain: DOMAIN_B,
            agentDid: AGENT_DID,
            metric: METRIC,
            amount: 100,
            window: 'day',
            windowStart: WINDOW_START,
        });
        const req2 = senderTracker.createSettleRequest({
            recipientDomain: DOMAIN_B,
            agentDid: agentDid2,
            metric: METRIC,
            amount: 200,
            window: 'day',
            windowStart: WINDOW_START,
        });

        await recipientHandler.appendSettle(req1, keyA.publicKey);
        await recipientHandler.appendSettle(req2, keyA.publicKey);

        // reconciling agentDid1 sees only its own 1 record
        const r1 = await senderTracker.reconcile(
            recipientHandler,
            keyB.publicKey,
            AGENT_DID,
            METRIC,
            DOMAIN_B,
        );
        expect(r1).toHaveLength(1);
        expect(r1[0]!.settleId).toBe(req1.settleId);
    });

    it('should isolate settle records by metric', async () => {
        const metric2 = 'call_count';

        const req1 = senderTracker.createSettleRequest({
            recipientDomain: DOMAIN_B,
            agentDid: AGENT_DID,
            metric: METRIC,
            amount: 100,
            window: 'day',
            windowStart: WINDOW_START,
        });
        const req2 = senderTracker.createSettleRequest({
            recipientDomain: DOMAIN_B,
            agentDid: AGENT_DID,
            metric: metric2,
            amount: 5,
            window: 'day',
            windowStart: WINDOW_START,
        });

        await recipientHandler.appendSettle(req1, keyA.publicKey);
        await recipientHandler.appendSettle(req2, keyA.publicKey);

        // reconciling METRIC sees only 1 record
        const r1 = await senderTracker.reconcile(
            recipientHandler,
            keyB.publicKey,
            AGENT_DID,
            METRIC,
            DOMAIN_B,
        );
        expect(r1).toHaveLength(1);
        expect(r1[0]!.settleId).toBe(req1.settleId);
    });

    it('should batch reap expired PENDING records via PendingReaper', async () => {
        const tinyTtlHandler = new RecipientSettleHandler(
            pool,
            SCHEMA_B,
            keyB.privateKey,
            {
                pendingTtlMs: 1,
                reapIntervalMs: 50, // 50ms interval
                reconcileBatchSize: 100,
            },
        );

        // write 2 records
        for (let i = 0; i < 2; i++) {
            const req = senderTracker.createSettleRequest({
                recipientDomain: DOMAIN_B,
                agentDid: AGENT_DID,
                metric: METRIC,
                amount: 10,
                window: 'day',
                windowStart: WINDOW_START,
            });
            await tinyTtlHandler.appendSettle(req, keyA.publicKey);
        }

        const reaper = new PendingReaper(tinyTtlHandler, 50);
        reaper.start();

        // wait for the reaper to fire at least once
        await new Promise((resolve) => setTimeout(resolve, 100));
        reaper.stop();

        // verify the records have been reaped
        const records = await tinyTtlHandler.querySettles({
            senderDomain: DOMAIN_A,
            agentDid: AGENT_DID,
            metric: METRIC,
            limit: 10,
        });
        for (const r of records) {
            expect(r.state).toBe('RELEASED');
        }
    });

    it('should handle concurrent idempotent appendSettle with same settleId', async () => {
        const req = senderTracker.createSettleRequest({
            recipientDomain: DOMAIN_B,
            agentDid: AGENT_DID,
            metric: METRIC,
            amount: 777,
            window: 'day',
            windowStart: WINDOW_START,
        });

        // concurrent writes of the same settleId (simulating network retries)
        const results = await Promise.all([
            recipientHandler.appendSettle(req, keyA.publicKey),
            recipientHandler.appendSettle(req, keyA.publicKey),
            recipientHandler.appendSettle(req, keyA.publicKey),
        ]);

        // all results should return the same settleId
        for (const r of results) {
            expect(r.settleId).toBe(req.settleId);
        }

        // only 1 record exists in the database
        const queryResult = await pool.query<{ count: string }>(
            `SELECT COUNT(*)::text as count FROM ${SCHEMA_B}.settle_records WHERE settle_id = $1`,
            [req.settleId],
        );
        expect(queryResult.rows[0]?.count).toBe('1');
    });
});
