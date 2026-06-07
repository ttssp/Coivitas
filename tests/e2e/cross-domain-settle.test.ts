/**
 * E2E cross-trust-domain cumulative settle protocol tests
 *
 * Coverage (DB-gated, requires DATABASE_URL):
 *   1. recipient.appendSettle → write in PENDING state
 *   2. sender.querySettles → pull reconciliation finds the PENDING record
 *   3. recipient.confirmSettle → PENDING → SETTLED
 *   4. PendingReaper TTL-expiry reaping (short-TTL injection): PENDING → RELEASED
 *   5. appendSettle idempotency (the same settleId is not written twice)
 *   6. Note: atomic two-phase commit is deferred to a later release (intra-org-only trust model)
 *
 * Design decisions:
 *   - Use separate schemas (test_e2e_settle_a / test_e2e_settle_b) to isolate data.
 *   - beforeEach rebuilds the schemas; afterAll cleans up.
 *   - Gate with describeIfDatabase; without a DB everything is skipped (no error when CI has no PG).
 *   - Inject a short reapIntervalMs=50ms and pendingTtlMs=-1ms (already expired) into PendingReaper to speed up tests.
 *
 */

import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import { generateKeyPair, verify } from '../../packages/crypto/src/index.js';
import { createPool } from '../../packages/shared/src/index.js';
import type { DatabasePool } from '../../packages/shared/src/index.js';
import {
    dropDomainSchema,
    initDomainSchema,
} from '../../packages/policy/src/cross-domain-settle/schema.js';
import { RecipientSettleHandler } from '../../packages/policy/src/cross-domain-settle/settle-handler.js';
import { SenderSettleTracker } from '../../packages/policy/src/cross-domain-settle/settle-tracker.js';
import { PendingReaper } from '../../packages/policy/src/cross-domain-settle/pending-reaper.js';
import { buildSettlePayload } from '../../packages/policy/src/cross-domain-settle/payload.js';

// ─── DB gating ─────────────────────────────────────────────────────────────

const describeIfDatabase = process.env.DATABASE_URL ? describe : describe.skip;

// ─── Test constants ──────────────────────────────────────────────────────────

const SCHEMA_A = 'test_e2e_settle_a';
const SCHEMA_B = 'test_e2e_settle_b';
const DOMAIN_A = 'e2e-domain-a.test';
const DOMAIN_B = 'e2e-domain-b.test';
const AGENT_DID = 'did:agent:' + 'a'.repeat(40);
const METRIC = 'api_call_count';
const WINDOW_START = '2026-05-01T00:00:00.000Z';

// ─── E2E test suite ──────────────────────────────────────────────────────────

describeIfDatabase('cross-domain-settle E2E', () => {
    let pool: DatabasePool;
    let recipientHandler: RecipientSettleHandler;
    let senderTracker: SenderSettleTracker;
    let keyA: { publicKey: string; privateKey: string };
    let keyB: { publicKey: string; privateKey: string };
    const CONNECTION_STRING =
        process.env.DATABASE_URL ??
        'postgresql://coivitas:coivitas@localhost:5432/coivitas_dev';

    beforeAll(() => {
        pool = createPool({ connectionString: CONNECTION_STRING });
        keyA = generateKeyPair();
        keyB = generateKeyPair();
    });

    beforeEach(async () => {
        // Rebuild the schemas: fully wiped before each test (isolation)
        await dropDomainSchema(pool, SCHEMA_A);
        await dropDomainSchema(pool, SCHEMA_B);
        await initDomainSchema(pool, SCHEMA_A);
        await initDomainSchema(pool, SCHEMA_B);

        // The recipient countersigns with keyB's private key; accepts keyA's public key to verify the sender's signature
        recipientHandler = new RecipientSettleHandler(
            pool,
            SCHEMA_B,
            keyB.privateKey,
        );

        // The sender signs requests with keyA's private key
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

    // -----------------------------------------------------------------------
    // Test 1: recipient.appendSettle → write in PENDING state
    // -----------------------------------------------------------------------
    it('should write settle record in PENDING state when recipient appends settle', async () => {
        const req = senderTracker.createSettleRequest({
            recipientDomain: DOMAIN_B,
            agentDid: AGENT_DID,
            metric: METRIC,
            amount: 1000,
            window: 'day',
            windowStart: WINDOW_START,
        });

        const record = await recipientHandler.appendSettle(req, keyA.publicKey);

        expect(record.settleId).toBe(req.settleId);
        expect(record.state).toBe('PENDING');
        expect(record.senderDomain).toBe(DOMAIN_A);
        expect(record.recipientDomain).toBe(DOMAIN_B);
        expect(record.agentDid).toBe(AGENT_DID);
        expect(record.metric).toBe(METRIC);
        expect(record.amount).toBe(1000);
        expect(record.settledAt).toBeNull();
        expect(record.expiresAt).toBeTruthy();

        // The recipient countersignature should be a valid Ed25519 signature
        const payload = buildSettlePayload(req);
        const bytes = Buffer.from(payload, 'utf-8');
        expect(
            verify(bytes, record.recipientLedgerSignature, keyB.publicKey),
        ).toBe(true);
    });

    // -----------------------------------------------------------------------
    // Test 2: sender.querySettles → pull reconciliation, finds the PENDING record
    // -----------------------------------------------------------------------
    it('should allow sender to pull settle records via querySettles after recipient appends', async () => {
        const req = senderTracker.createSettleRequest({
            recipientDomain: DOMAIN_B,
            agentDid: AGENT_DID,
            metric: METRIC,
            amount: 2500,
            window: 'day',
            windowStart: WINDOW_START,
        });

        await recipientHandler.appendSettle(req, keyA.publicKey);

        // The sender queries reconciliation records from the recipient schema (pull mode)
        const records = await recipientHandler.querySettles({
            senderDomain: DOMAIN_A,
            agentDid: AGENT_DID,
            metric: METRIC,
            limit: 10,
        });

        expect(records).toHaveLength(1);
        expect(records[0]?.settleId).toBe(req.settleId);
        expect(records[0]?.state).toBe('PENDING');
        expect(records[0]?.amount).toBe(2500);
    });

    // -----------------------------------------------------------------------
    // Test 3: SenderSettleTracker.reconcile() → signature verification + cursor advancement +
    // batch confirmation, end to end
    // -----------------------------------------------------------------------
    // The old version called recipientHandler.confirmSettle() directly, bypassing the
    // sender-side reconcile path — recipient signature verification, cursor
    // advancement, and batch confirmation were never triggered. This test instead uses the reconcile()
    // entry point and asserts four things:
    // (a) ReconciliationResult.verified === true (the recipient signature-verification path runs)
    // (b) record state PENDING → SETTLED (confirmSettle batch UPDATE)
    // (c) the cursor advances to the end of this batch (liveness-first)
    // (d) a second reconcile gets no records (the cursor is past the batch)
    it('should transition settle record from PENDING to SETTLED via SenderSettleTracker.reconcile() and advance cursor', async () => {
        const req = senderTracker.createSettleRequest({
            recipientDomain: DOMAIN_B,
            agentDid: AGENT_DID,
            metric: METRIC,
            amount: 750,
            window: 'hour',
            windowStart: WINDOW_START,
        });

        await recipientHandler.appendSettle(req, keyA.publicKey);

        // (a) reconcile entry point: pull PENDING + verify signatures + batch confirm + advance cursor
        const results = await senderTracker.reconcile(
            recipientHandler,
            keyB.publicKey,
            AGENT_DID,
            METRIC,
            DOMAIN_B,
        );

        expect(results).toHaveLength(1);
        expect(results[0]?.settleId).toBe(req.settleId);
        expect(results[0]?.verified).toBe(true);
        // At pull time, reconcile sees PENDING; confirmSettle only takes effect after verification
        expect(results[0]?.state).toBe('PENDING');

        // (b) The recipient-side record has transitioned to SETTLED
        const records = await recipientHandler.querySettles({
            senderDomain: DOMAIN_A,
            agentDid: AGENT_DID,
            metric: METRIC,
            limit: 10,
        });

        expect(records).toHaveLength(1);
        expect(records[0]?.state).toBe('SETTLED');
        expect(records[0]?.settledAt).not.toBeNull();

        // (c)+(d) The cursor has advanced — a second reconcile gets no new records
        const empty = await senderTracker.reconcile(
            recipientHandler,
            keyB.publicKey,
            AGENT_DID,
            METRIC,
            DOMAIN_B,
        );
        expect(empty).toHaveLength(0);
    });

    // -----------------------------------------------------------------------
    // Test 4: PendingReaper TTL-expiry reaping (PENDING → RELEASED)
    // -----------------------------------------------------------------------
    it('should reap expired PENDING records via PendingReaper and mark them RELEASED', async () => {
        // Use an extremely short TTL (-1ms) to ensure the record expires immediately
        const recipientHandlerWithShortTtl = new RecipientSettleHandler(
            pool,
            SCHEMA_B,
            keyB.privateKey,
            { pendingTtlMs: -1, reapIntervalMs: 50, reconcileBatchSize: 100 },
        );

        const req = senderTracker.createSettleRequest({
            recipientDomain: DOMAIN_B,
            agentDid: AGENT_DID,
            metric: METRIC,
            amount: 300,
            window: 'week',
            windowStart: WINDOW_START,
        });

        await recipientHandlerWithShortTtl.appendSettle(req, keyA.publicKey);

        // Run the reap immediately (the record is already expired)
        const reaper = new PendingReaper(
            recipientHandlerWithShortTtl,
            50, // reapIntervalMs
        );
        const reaped = await reaper.reapOnce();

        expect(reaped).toBeGreaterThanOrEqual(1);

        // Verify the record state has transitioned to RELEASED
        const records = await recipientHandlerWithShortTtl.querySettles({
            senderDomain: DOMAIN_A,
            agentDid: AGENT_DID,
            metric: METRIC,
            limit: 10,
        });
        // querySettles returns records in all states, including RELEASED
        const releasedRecord = records.find((r) => r.settleId === req.settleId);
        expect(releasedRecord?.state).toBe('RELEASED');
    });

    // -----------------------------------------------------------------------
    // Test 5: appendSettle idempotency (the same settleId is not written twice)
    // -----------------------------------------------------------------------
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
        expect(record1.state).toBe('PENDING');
        expect(record2.state).toBe('PENDING');
        // Idempotent: both writes yield the same result (the same recipient countersignature)
        expect(record1.recipientLedgerSignature).toBe(
            record2.recipientLedgerSignature,
        );

        // Only 1 record exists in the DB
        const records = await recipientHandler.querySettles({
            senderDomain: DOMAIN_A,
            agentDid: AGENT_DID,
            metric: METRIC,
            limit: 10,
        });
        expect(records).toHaveLength(1);
    });

    // -----------------------------------------------------------------------
    // Test 6: atomicity deferred to a later release (intra-org-only)
    // Cross-domain atomic commit is not implemented this cycle; confirms the current model uses the "recipient append + sender pull" approach
    // -----------------------------------------------------------------------
    it('should support append-then-pull reconciliation pattern without atomic commit', async () => {
        // Create 3 settle requests
        const reqs = [1, 2, 3].map((i) =>
            senderTracker.createSettleRequest({
                recipientDomain: DOMAIN_B,
                agentDid: AGENT_DID,
                metric: METRIC,
                amount: 100 * i,
                window: 'day',
                windowStart: WINDOW_START,
            }),
        );

        // The recipient appends them one by one
        for (const req of reqs) {
            await recipientHandler.appendSettle(req, keyA.publicKey);
        }

        // sender pull reconciliation: fetch all 3 in one go
        const records = await recipientHandler.querySettles({
            senderDomain: DOMAIN_A,
            agentDid: AGENT_DID,
            metric: METRIC,
            limit: 100,
        });

        expect(records).toHaveLength(3);
        expect(records.every((r) => r.state === 'PENDING')).toBe(true);

        // Batch confirm (simulating the sender confirming reconciliation)
        const settleIds = records.map((r) => r.settleId);
        await recipientHandler.confirmSettle(settleIds);

        // Verify all have transitioned to SETTLED
        const afterConfirm = await recipientHandler.querySettles({
            senderDomain: DOMAIN_A,
            agentDid: AGENT_DID,
            metric: METRIC,
            limit: 100,
        });
        expect(afterConfirm.every((r) => r.state === 'SETTLED')).toBe(true);
    });
});
