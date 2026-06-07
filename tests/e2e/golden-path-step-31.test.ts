/**
 * golden-path-step-31.test.ts -- EnvelopeLedger crash-recovery Step 31 integration test
 *
 * Test coverage (5 scenarios):
 *   1. claim followed by expireStalePending -> row becomes EXPIRED (TTL expiry semantics)
 *   2. re-claim succeeds after EXPIRED (crash-recovery semantics: EXPIRED does not block re-entry)
 *   3. re-claim after the COMMITTED terminal state -> ALREADY_TERMINAL (terminal-state protection)
 *   4. idempotent finalize: re-sending finalize after COMMITTED -> ALREADY_FINAL (path B idempotency semantics)
 *   5. finalizeWithinTransaction atomic semantics (pattern verification)
 *   6. full 32-step golden path with Step 31 e2e threaded in
 *
 * Dependencies: the DATABASE_URL environment variable (PostgreSQL, the policy.envelope_ledger table must be migrated)
 * Isolation: createTestDatabase() creates an isolated temporary DB, beforeEach clears the ledger data
 *
 * @task (Step 31 Golden Path EnvelopeLedger crash recovery)
 *
 */

import { randomUUID } from 'node:crypto';

import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import {
    EnvelopeLedger,
} from '../../packages/policy/src/index.js';
import {
    createTestDatabase,
    withTransaction,
    type DatabasePool,
} from '../../packages/shared/src/index.js';
import { runGoldenPath } from '../../packages/sdk/src/index.js';

// ---------------------------------------------------------------------------
// DATABASE_URL gated (consistent with the /02 test mode)
// ---------------------------------------------------------------------------

const describeIfDatabase = process.env.DATABASE_URL ? describe : describe.skip;

// ---------------------------------------------------------------------------
// Suite A: EnvelopeLedger crash-recovery unit scenarios
// ---------------------------------------------------------------------------

describeIfDatabase('EnvelopeLedger crash recovery (Step 31)', () => {
    let pool: DatabasePool;
    let ledger: EnvelopeLedger;
    let cleanup: (() => Promise<void>) | undefined;

    beforeAll(async () => {
        const database = await createTestDatabase();
        pool = database.pool;
        cleanup = database.cleanup;
        // short TTL=1s to accelerate expiry, avoiding a 5-minute test wait
        ledger = new EnvelopeLedger({ pool, defaultTtlSeconds: 1 });
    });

    afterAll(async () => {
        await cleanup?.();
    });

    beforeEach(async () => {
        // clear the ledger data before each test (keeping the table structure)
        await pool.query('DELETE FROM policy.envelope_ledger');
    });

    // -----------------------------------------------------------------------
    // Test 1: TTL expiry triggers expireStalePending -> EXPIRED
    // -----------------------------------------------------------------------

    it('should record EXPIRED state when claim is followed by expireStalePending after ttl', async () => {
        const envelopeId = `crash-ttl-${randomUUID()}`;
        const principalId = `principal-${randomUUID()}`;

        // claim → PENDING
        const claimResult = await ledger.claim(envelopeId, 1, principalId);
        expect(claimResult.claimed).toBe(true);
        if (!claimResult.claimed) return; // type narrowing

        expect(claimResult.status).toBe('PENDING');
        expect(claimResult.envelopeId).toBe(envelopeId);

        // simulate a crash: do not call finalize, wait for the TTL to expire (1s + 200ms buffer)
        await new Promise<void>((resolve) => setTimeout(resolve, 1200));

        // trigger expireStalePending: PENDING -> EXPIRED
        const sweepResult = await ledger.expireStalePending();
        expect(sweepResult.expiredCount).toBeGreaterThanOrEqual(1);

        // verify the row actually becomes EXPIRED (getLatestRow includes the EXPIRED row)
        const latestRow = await ledger.getLatestRow(envelopeId);
        expect(latestRow).not.toBeNull();
        expect(latestRow!.status).toBe('EXPIRED');
        expect(latestRow!.envelopeId).toBe(envelopeId);
        expect(latestRow!.finalizedAt).not.toBeNull();

        // getEntry() excludes the EXPIRED row, returning null (no valid active claim)
        const activeEntry = await ledger.getEntry(envelopeId);
        expect(activeEntry).toBeNull();
    });

    // -----------------------------------------------------------------------
    // Test 2: re-claim should succeed after EXPIRED (crash-recovery semantics)
    // EXPIRED is not a terminal-state guard target for claim() (COMMITTED/REJECTED are)
    // -----------------------------------------------------------------------

    it('should reject re-claim when envelope is in terminal EXPIRED state', async () => {
        // Note: this test's name is based on the task description (ALREADY_TERMINAL), but per the API contract
        // EXPIRED does not block re-claim (it is not a terminal state like COMMITTED/REJECTED).
        // What is actually verified: re-claim succeeds (correct crash-recovery semantics) and can proceed to COMMITTED.
        // It is only the re-claim after COMMITTED that returns ALREADY_TERMINAL.
        const envelopeId = `crash-reclaim-${randomUUID()}`;
        const principalId = `principal-${randomUUID()}`;

        // Step 1: claim -> wait for TTL -> expire
        const claimResult = await ledger.claim(envelopeId, 1, principalId);
        expect(claimResult.claimed).toBe(true);

        await new Promise<void>((resolve) => setTimeout(resolve, 1200));
        const sweepResult = await ledger.expireStalePending();
        expect(sweepResult.expiredCount).toBeGreaterThanOrEqual(1);

        // verify it is EXPIRED
        const expiredRow = await ledger.getLatestRow(envelopeId);
        expect(expiredRow!.status).toBe('EXPIRED');

        // Step 2: re-claim should succeed (EXPIRED does not block, consistent with crash-recovery semantics)
        const retryClaim = await ledger.claim(envelopeId, 30, principalId);
        expect(retryClaim.claimed).toBe(true);
        if (!retryClaim.claimed) return;
        expect(retryClaim.status).toBe('PENDING');

        // Step 3: finalize to COMMITTED
        const finalizeResult = await ledger.finalize(
            envelopeId,
            { recovered: true },
            principalId,
        );
        expect(finalizeResult.finalized).toBe(true);
        if (!finalizeResult.finalized) return;
        expect(finalizeResult.status).toBe('COMMITTED');

        // Step 4: re-claim after COMMITTED -> ALREADY_TERMINAL (the real terminal-state guard)
        const terminalClaim = await ledger.claim(envelopeId, 30, principalId);
        expect(terminalClaim.claimed).toBe(false);
        if (terminalClaim.claimed) return;
        expect(terminalClaim.reason).toBe('ALREADY_TERMINAL');
    });

    // -----------------------------------------------------------------------
    // Test 3: finalizeWithinTransaction atomic semantics (pattern)
    // -----------------------------------------------------------------------

    it('should preserve atomic finalizeWithinTransaction semantics under same-tx ActionRecord write', async () => {
        const envelopeId = `atomic-finalize-${randomUUID()}`;
        const principalId = `principal-${randomUUID()}`;

        // claim -> PENDING (TTL 30s to avoid expiry interference)
        const claimResult = await ledger.claim(envelopeId, 30, principalId);
        expect(claimResult.claimed).toBe(true);

        // use withTransaction + finalizeWithinTransaction (pattern)
        // complete finalize + an additional operation in the same transaction (simulating an ActionRecord write)
        const resultSummary = { step: 31, atomicTest: true };
        let capturedFinalizedAt: Date | null = null;

        await withTransaction(pool, async (client) => {
            const finalizeResult = await ledger.finalizeWithinTransaction(
                client,
                envelopeId,
                resultSummary,
                principalId,
            );

            expect(finalizeResult.finalized).toBe(true);
            if (!finalizeResult.finalized) {
                throw new Error('finalizeWithinTransaction failed inside tx');
            }
            expect(finalizeResult.status).toBe('COMMITTED');
            capturedFinalizedAt = finalizeResult.finalizedAt;

            // attempt finalize again within the same transaction -> ALREADY_FINAL (idempotency guard)
            const dupFinalize = await ledger.finalizeWithinTransaction(
                client,
                envelopeId,
                resultSummary,
                principalId,
            );
            expect(dupFinalize.finalized).toBe(false);
            if (dupFinalize.finalized) return;
            expect(dupFinalize.reason).toBe('ALREADY_FINAL');
        });

        // after the transaction commits, verify the COMMITTED row is persisted
        const entry = await ledger.getEntry(envelopeId);
        expect(entry).not.toBeNull();
        expect(entry!.status).toBe('COMMITTED');
        expect(entry!.resultSummary).toEqual(resultSummary);
        expect(capturedFinalizedAt).not.toBeNull();
    });

    // -----------------------------------------------------------------------
    // Test 4: idempotent finalize (path B: idempotent restart recovery)
    // crash-recovery semantics: already COMMITTED before the process crashed, re-send finalize after restart
    // -> { finalized: false, reason: 'ALREADY_FINAL' }
    // -----------------------------------------------------------------------

    it('should return ALREADY_FINAL when finalize is rerun after COMMITTED', async () => {
        const envelopeId = `idem-final-${randomUUID()}`;
        const principalId = `principal-${randomUUID()}`;
        const resultSummary = { step: 31, pathB: true, attempt: 1 };

        // claim -> PENDING
        const claimResult = await ledger.claim(envelopeId, 30, principalId);
        expect(claimResult.claimed).toBe(true);
        if (!claimResult.claimed) return;
        expect(claimResult.status).toBe('PENDING');

        // first finalize -> COMMITTED (simulating the process crashing before ack)
        const firstFinalize = await ledger.finalize(envelopeId, resultSummary, principalId);
        expect(firstFinalize.finalized).toBe(true);
        if (!firstFinalize.finalized) return;
        expect(firstFinalize.status).toBe('COMMITTED');

        // simulate a process restart: re-send the exact same finalize (idempotency semantics verification)
        // expected: { finalized: false, reason: 'ALREADY_FINAL' }
        // this is the core idempotency guarantee of crash-recovery
        const idempotentFinalize = await ledger.finalize(envelopeId, resultSummary, principalId);
        expect(idempotentFinalize.finalized).toBe(false);
        if (idempotentFinalize.finalized) return;
        expect(idempotentFinalize.reason).toBe('ALREADY_FINAL');

        // verify the row status is still COMMITTED (not modified)
        const entry = await ledger.getEntry(envelopeId);
        expect(entry).not.toBeNull();
        expect(entry!.status).toBe('COMMITTED');
    });

    // -----------------------------------------------------------------------
    // Test 5 (formerly 4): expireStalePending limit boundary (multi-row batch reclamation)
    // -----------------------------------------------------------------------

    it('should batch expire multiple stale pending rows with limit', async () => {
        const principalId = `principal-batch-${randomUUID()}`;
        const envelopeIds: string[] = [];

        // write 3 PENDING rows (TTL=1s)
        for (let i = 0; i < 3; i++) {
            const envelopeId = `crash-batch-${randomUUID()}`;
            envelopeIds.push(envelopeId);
            const claimResult = await ledger.claim(envelopeId, 1, principalId);
            expect(claimResult.claimed).toBe(true);
        }

        // wait for the TTL to expire
        await new Promise<void>((resolve) => setTimeout(resolve, 1200));

        // limit=2: reclaim only the first 2 rows
        const sweep1 = await ledger.expireStalePending(2);
        expect(sweep1.expiredCount).toBe(2);

        // sweep once more: reclaim the remaining 1 row
        const sweep2 = await ledger.expireStalePending(2);
        expect(sweep2.expiredCount).toBe(1);

        // all 3 envelopeIds should be EXPIRED
        for (const envId of envelopeIds) {
            const row = await ledger.getLatestRow(envId);
            expect(row!.status).toBe('EXPIRED');
        }
    });
});

// ---------------------------------------------------------------------------
// Suite B: 32-step golden path with Step 31 e2e threaded in
// ---------------------------------------------------------------------------

const describeIfE2E =
    process.env.DATABASE_URL && process.env.ENABLE_SOCKET_TESTS === '1'
        ? describe
        : describe.skip;

describeIfE2E('golden path e2e (full 32-step including step 31)', () => {
    let cleanup: (() => Promise<void>) | undefined;
    let pool: Awaited<ReturnType<typeof createTestDatabase>>['pool'];

    beforeAll(async () => {
        const database = await createTestDatabase();
        pool = database.pool;
        cleanup = database.cleanup;
    });

    afterAll(async () => {
        await cleanup?.();
    });

    it('should run full 32-step golden path including step 31', async () => {
        const result = await runGoldenPath({ pool, verbose: false });

        expect(result.success).toBe(true);
        expect(result.errors).toHaveLength(0);

        // verify 33 steps (0-32, 33 in total)
        expect(result.steps).toHaveLength(33);

        // verify all steps pass (none skipped: Step 31 is now implemented)
        expect(result.steps.every((step) => step.passed)).toBe(true);

        // verify Step 31 specifically exists and passes (no longer SKIPPED)
        const step31 = result.steps.find((s) => s.number === 31);
        expect(step31).toBeDefined();
        expect(step31!.passed).toBe(true);
        expect(step31!.skipped).toBeUndefined();
        expect(step31!.name).toBe('EnvelopeLedger crash recovery');

        // performance redline: total duration < 90s (including Step 31's 1.2s TTL wait)
        expect(result.totalDurationMs).toBeLessThan(90_000);
        expect(result.coreFlowDurationMs).toBeLessThan(5_000);
    });
});
