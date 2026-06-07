/**
 * envelope-ledger.test.ts -- EnvelopeLedger production-implementation unit tests
 *
 * Test coverage:
 *   1. claim: create a PENDING row, TTL setting, concurrent claim conflict (ALREADY_PENDING)
 *       re-claim after a terminal state (COMMITTED/REJECTED) → ALREADY_TERMINAL
 *      claim() performs an atomic terminal-state check within the transaction (TOCTOU window elimination)
 *       claimerId is written + getEntry returns claimerId
 *   2. finalize: PENDING → COMMITTED, resultSummary write
 *       finalize after TTL expiry → LEASE_EXPIRED
 *      on LEASE_EXPIRED the row is atomically marked EXPIRED, and subsequent claim() is not blocked
 *      claimerId ownership verification on finalize
 *   3. reject: PENDING → REJECTED
 *      claimerId ownership verification on reject
 *   4. expireStalePending: DB-side TTL comparison, bulk recycle PENDING → EXPIRED
 *       SKIP LOCKED + subquery CTE, limit takes effect correctly
 *   5. getEntry: query the latest non-EXPIRED row, return null when only EXPIRED rows exist
 *   6. failure rollback: claim → crash → re-claim (claim is allowed again after EXPIRED recycle)
 *   7. same-transaction pattern: finalizeWithinTransaction + outer withTransaction
 *   8. status runtime validation (no brand cast): parseLedgerClaimStatus throws on illegal values
 *   9. state-machine constraint: an already-COMMITTED entry cannot be finalized again (ALREADY_FINAL)
 *  10. state-machine constraint: an already-REJECTED entry cannot be rejected again (ALREADY_FINAL)
 *  11. state-machine constraint: NOT_FOUND scenario (finalize/reject when no PENDING row exists)
 *
 * Dependencies: a local PostgreSQL (docker-compose up -d), the DATABASE_URL environment variable
 * Isolation: createTestDatabase() creates an independent temporary DB
 *
 */

import { randomUUID } from 'node:crypto';

import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import {
    createTestDatabase,
    withTransaction,
    type DatabasePool,
} from '@coivitas/shared';

import { EnvelopeLedger } from '../envelope-ledger.js';
import {
    isLedgerClaimStatus,
    LEDGER_CLAIM_STATUSES,
    parseLedgerClaimStatus,
} from '../types.js';

// ---------------------------------------------------------------------------
// Test isolation: skip the whole suite when DATABASE_URL is not set
// ---------------------------------------------------------------------------

const describeIfDatabase = process.env.DATABASE_URL ? describe : describe.skip;

// ---------------------------------------------------------------------------
// Suite
// ---------------------------------------------------------------------------

describeIfDatabase('EnvelopeLedger (production impl)', () => {
    let pool: DatabasePool;
    let ledger: EnvelopeLedger;
    let cleanup: (() => Promise<void>) | undefined;

    beforeAll(async () => {
        // createTestDatabase() runs the SQL migrations of all packages (including 006-create-envelope-ledger.sql)
        const database = await createTestDatabase();
        pool = database.pool;
        cleanup = database.cleanup;

        ledger = new EnvelopeLedger({ pool, defaultTtlSeconds: 30 });
    });

    afterAll(async () => {
        await cleanup?.();
    });

    beforeEach(async () => {
        // clear the ledger data before each test (keep the table structure)
        await pool.query('DELETE FROM policy.envelope_ledger');
    });

    // -------------------------------------------------------------------------
    // 1. claim()
    // -------------------------------------------------------------------------

    describe('claim()', () => {
        it('should create a PENDING entry when claiming a new envelope', async () => {
            const envelopeId = randomUUID();

            const result = await ledger.claim(envelopeId);

            expect(result.claimed).toBe(true);
            if (!result.claimed) throw new Error('unreachable');
            expect(result.envelopeId).toBe(envelopeId);
            expect(result.status).toBe('PENDING');
            expect(typeof result.id).toBe('string');
            expect(result.id.length).toBeGreaterThan(0);
            expect(result.claimedAt).toBeInstanceOf(Date);
            expect(result.ttlSeconds).toBe(30);
        });

        it('should use custom ttlSeconds when provided', async () => {
            const envelopeId = randomUUID();

            const result = await ledger.claim(envelopeId, 60);

            expect(result.claimed).toBe(true);
            if (!result.claimed) throw new Error('unreachable');
            expect(result.ttlSeconds).toBe(60);
        });

        it('should return ALREADY_PENDING when claiming an already-pending envelope', async () => {
            const envelopeId = randomUUID();

            await ledger.claim(envelopeId);
            const result = await ledger.claim(envelopeId);

            expect(result.claimed).toBe(false);
            if (result.claimed) throw new Error('unreachable');
            expect(result.reason).toBe('ALREADY_PENDING');
            expect(result.envelopeId).toBe(envelopeId);
        });

        it('should allow re-claim after EXPIRED recycle when TTL=0 equivalent (immediate expiry)', async () => {
            const envelopeId = randomUUID();

            // Claim with 1s TTL
            await ledger.claim(envelopeId, 1);

            // Force immediate expire via direct DB update (set claimed_at far in past)
            await pool.query(
                `UPDATE policy.envelope_ledger
                 SET claimed_at = NOW() - interval '1 hour'
                 WHERE envelope_id = $1 AND status = 'PENDING'`,
                [envelopeId],
            );

            // Expire stale PENDING
            const expireResult = await ledger.expireStalePending();
            expect(expireResult.expiredCount).toBe(1);

            // Now re-claim should succeed
            const reclaimResult = await ledger.claim(envelopeId);
            expect(reclaimResult.claimed).toBe(true);
        });

        it('should handle concurrent claims correctly via partial unique index', async () => {
            // concurrently submit 10 claims for the same envelopeId
            const envelopeId = randomUUID();
            const promises = Array.from({ length: 10 }, () =>
                ledger.claim(envelopeId),
            );
            const results = await Promise.all(promises);

            const successes = results.filter((r) => r.claimed);
            const conflicts = results.filter((r) => !r.claimed);

            // only 1 succeeds; the rest are all ALREADY_PENDING
            expect(successes).toHaveLength(1);
            expect(conflicts).toHaveLength(9);
            conflicts.forEach((r) => {
                if (r.claimed) throw new Error('unreachable');
                expect(r.reason).toBe('ALREADY_PENDING');
            });
        });

        // forbid a new PENDING claim after a terminal state (COMMITTED)
        it('should return ALREADY_TERMINAL when claiming after COMMITTED', async () => {
            const envelopeId = randomUUID();
            await ledger.claim(envelopeId);
            await ledger.finalize(envelopeId); // → COMMITTED

            const result = await ledger.claim(envelopeId);

            expect(result.claimed).toBe(false);
            if (result.claimed) throw new Error('unreachable');
            expect(result.reason).toBe('ALREADY_TERMINAL');
            expect(result.envelopeId).toBe(envelopeId);
        });

        // forbid a new PENDING claim after a terminal state (REJECTED)
        it('should return ALREADY_TERMINAL when claiming after REJECTED', async () => {
            const envelopeId = randomUUID();
            await ledger.claim(envelopeId);
            await ledger.reject(envelopeId); // → REJECTED

            const result = await ledger.claim(envelopeId);

            expect(result.claimed).toBe(false);
            if (result.claimed) throw new Error('unreachable');
            expect(result.reason).toBe('ALREADY_TERMINAL');
        });

        // claimerId is written + getEntry returns claimerId
        it('should store claimerId in DB and return it via getEntry', async () => {
            const envelopeId = randomUUID();
            const claimerId = `worker-${randomUUID()}`;

            const claimResult = await ledger.claim(envelopeId, 30, claimerId);
            expect(claimResult.claimed).toBe(true);

            const entry = await ledger.getEntry(envelopeId);
            expect(entry).not.toBeNull();
            expect(entry!.claimerId).toBe(claimerId);
        });

        // when no claimerId is provided, claimerId is null (backward compatibility)
        it('should store null claimerId when not provided (backward compat)', async () => {
            const envelopeId = randomUUID();

            await ledger.claim(envelopeId); // no claimerId
            const entry = await ledger.getEntry(envelopeId);

            expect(entry!.claimerId).toBeNull();
        });

        // TOCTOU elimination — claim performs an atomic terminal-state check within the transaction
        // behavior verification: finalize immediately after claim, then claim → should return ALREADY_TERMINAL
        // (a true TOCTOU requires two concurrent connections; here we verify the atomic behavior is correct in a single-threaded scenario)
        it('should block re-claim atomically after concurrent finalize (TOCTOU coverage)', async () => {
            const envelopeId = randomUUID();

            // establish the COMMITTED terminal state
            await ledger.claim(envelopeId);
            await ledger.finalize(envelopeId);

            // 10 concurrent claims (all should return ALREADY_TERMINAL; none may succeed)
            const results = await Promise.all(
                Array.from({ length: 10 }, () => ledger.claim(envelopeId)),
            );

            expect(results.every((r) => !r.claimed)).toBe(true);
            results.forEach((r) => {
                if (r.claimed) throw new Error('unreachable');
                expect(r.reason).toBe('ALREADY_TERMINAL');
            });
        });
    });

    // -------------------------------------------------------------------------
    // 2. finalize()
    // -------------------------------------------------------------------------

    describe('finalize()', () => {
        it('should transition PENDING to COMMITTED', async () => {
            const envelopeId = randomUUID();
            await ledger.claim(envelopeId);

            const result = await ledger.finalize(envelopeId);

            expect(result.finalized).toBe(true);
            if (!result.finalized) throw new Error('unreachable');
            expect(result.envelopeId).toBe(envelopeId);
            expect(result.status).toBe('COMMITTED');
            expect(result.finalizedAt).toBeInstanceOf(Date);
        });

        it('should persist resultSummary on COMMITTED row', async () => {
            const envelopeId = randomUUID();
            await ledger.claim(envelopeId);

            const summary = { outcome: 'success', code: 200 };
            await ledger.finalize(envelopeId, summary);

            const entry = await ledger.getEntry(envelopeId);
            expect(entry).not.toBeNull();
            expect(entry!.status).toBe('COMMITTED');
            expect(entry!.resultSummary).toEqual(summary);
        });

        it('should return NOT_FOUND when no PENDING row exists', async () => {
            const envelopeId = randomUUID();

            const result = await ledger.finalize(envelopeId);

            expect(result.finalized).toBe(false);
            if (result.finalized) throw new Error('unreachable');
            expect(result.reason).toBe('NOT_FOUND');
        });

        it('should return ALREADY_FINAL when envelope is already COMMITTED', async () => {
            const envelopeId = randomUUID();
            await ledger.claim(envelopeId);
            await ledger.finalize(envelopeId);

            const result = await ledger.finalize(envelopeId);

            expect(result.finalized).toBe(false);
            if (result.finalized) throw new Error('unreachable');
            expect(result.reason).toBe('ALREADY_FINAL');
        });

        it('should return ALREADY_FINAL when envelope is already REJECTED', async () => {
            const envelopeId = randomUUID();
            await ledger.claim(envelopeId);
            await ledger.reject(envelopeId);

            const result = await ledger.finalize(envelopeId);

            expect(result.finalized).toBe(false);
            if (result.finalized) throw new Error('unreachable');
            expect(result.reason).toBe('ALREADY_FINAL');
        });

        // finalize returns LEASE_EXPIRED when the TTL has expired (the sweeper has not recycled it yet)
        it('should return LEASE_EXPIRED when PENDING row TTL has elapsed', async () => {
            const envelopeId = randomUUID();
            await ledger.claim(envelopeId, 1);

            // set claimed_at into the past (simulate TTL expiry, sweeper not running)
            await pool.query(
                `UPDATE policy.envelope_ledger
                 SET claimed_at = NOW() - interval '1 hour'
                 WHERE envelope_id = $1 AND status = 'PENDING'`,
                [envelopeId],
            );

            // the TTL has already expired at finalize time, so it should return LEASE_EXPIRED
            const result = await ledger.finalize(envelopeId);

            expect(result.finalized).toBe(false);
            if (result.finalized) throw new Error('unreachable');
            expect(result.reason).toBe('LEASE_EXPIRED');
        });

        // after LEASE_EXPIRED the row should be atomically marked EXPIRED, so a re-claim is no longer blocked
        it('should atomically mark row as EXPIRED on LEASE_EXPIRED, unblocking re-claim', async () => {
            const envelopeId = randomUUID();
            await ledger.claim(envelopeId, 1);

            // force expiry (simulate the sweeper not running)
            await pool.query(
                `UPDATE policy.envelope_ledger
                 SET claimed_at = NOW() - interval '1 hour'
                 WHERE envelope_id = $1 AND status = 'PENDING'`,
                [envelopeId],
            );

            // finalize should return LEASE_EXPIRED and atomically mark the row EXPIRED
            const finalizeResult = await ledger.finalize(envelopeId);
            expect(finalizeResult.finalized).toBe(false);
            if (finalizeResult.finalized) throw new Error('unreachable');
            expect(finalizeResult.reason).toBe('LEASE_EXPIRED');

            // the row should now be EXPIRED (getEntry does not return EXPIRED rows)
            const entry = await ledger.getEntry(envelopeId);
            expect(entry).toBeNull();

            // a re-claim should succeed (not blocked by ALREADY_PENDING)
            const reclaimResult = await ledger.claim(envelopeId);
            expect(reclaimResult.claimed).toBe(true);
        });

        // claimerId ownership verification on finalize
        it('should return NOT_FOUND when claimerId does not match stored claimerId on finalize', async () => {
            const envelopeId = randomUUID();
            const realClaimerId = `worker-${randomUUID()}`;
            const wrongClaimerId = `impostor-${randomUUID()}`;

            await ledger.claim(envelopeId, 30, realClaimerId);

            // call finalize with the wrong claimerId
            const result = await ledger.finalize(envelopeId, null, wrongClaimerId);

            expect(result.finalized).toBe(false);
            if (result.finalized) throw new Error('unreachable');
            // when ownership does not match, the SELECT finds no matching row → NOT_FOUND
            expect(result.reason).toBe('NOT_FOUND');

            // the PENDING row should remain unmodified
            const entry = await ledger.getEntry(envelopeId);
            expect(entry).not.toBeNull();
            expect(entry!.status).toBe('PENDING');
        });

        // a correct claimerId allows finalize
        it('should allow finalize when claimerId matches (ownership pass)', async () => {
            const envelopeId = randomUUID();
            const claimerId = `worker-${randomUUID()}`;

            await ledger.claim(envelopeId, 30, claimerId);

            const result = await ledger.finalize(envelopeId, null, claimerId);

            expect(result.finalized).toBe(true);
        });
    });

    // -------------------------------------------------------------------------
    // 3. finalizeWithinTransaction() -- shared-transaction pattern (reusable interface)
    // -------------------------------------------------------------------------

    describe('finalizeWithinTransaction()', () => {
        it('should finalize within caller-provided transaction', async () => {
            const envelopeId = randomUUID();
            await ledger.claim(envelopeId);

            const result = await withTransaction(pool, async (client) => {
                return ledger.finalizeWithinTransaction(client, envelopeId);
            });

            expect(result.finalized).toBe(true);
            const entry = await ledger.getEntry(envelopeId);
            expect(entry!.status).toBe('COMMITTED');
        });

        it('should rollback finalize when outer transaction is aborted', async () => {
            const envelopeId = randomUUID();
            await ledger.claim(envelopeId);

            // simulate an ActionRecord write failure → ROLLBACK of the whole transaction
            await expect(
                withTransaction(pool, async (client) => {
                    await ledger.finalizeWithinTransaction(client, envelopeId);
                    // deliberately throw an error to trigger ROLLBACK
                    throw new Error('ActionRecord write failed (simulated)');
                }),
            ).rejects.toThrow('ActionRecord write failed (simulated)');

            // the PENDING row should remain unchanged (ROLLBACK takes effect)
            const entry = await ledger.getEntry(envelopeId);
            expect(entry).not.toBeNull();
            expect(entry!.status).toBe('PENDING');
        });

        it('should allow retry finalize after rollback (crash-recovery pattern)', async () => {
            const envelopeId = randomUUID();
            await ledger.claim(envelopeId);

            // the first finalize fails (simulated crash)
            await expect(
                withTransaction(pool, async (client) => {
                    await ledger.finalizeWithinTransaction(client, envelopeId);
                    throw new Error('crash');
                }),
            ).rejects.toThrow('crash');

            // a retried finalize should succeed (the PENDING row is still there)
            const result = await ledger.finalize(envelopeId);
            expect(result.finalized).toBe(true);
        });

        it('should return NOT_FOUND within transaction when no PENDING row exists', async () => {
            const envelopeId = randomUUID();

            const result = await withTransaction(pool, (client) =>
                ledger.finalizeWithinTransaction(client, envelopeId),
            );

            expect(result.finalized).toBe(false);
            if (result.finalized) throw new Error('unreachable');
            expect(result.reason).toBe('NOT_FOUND');
        });

        it('should atomically finalize and write side-effect within same transaction', async () => {
            const envelopeId = randomUUID();
            await ledger.claim(envelopeId);

            // simulate two operations written in the same transaction (finalize + an additional write, e.g. sideTableAppender.append)
            // both share the same PoolClient
            const sideEffects: string[] = [];

            await withTransaction(pool, async (client) => {
                const result = await ledger.finalizeWithinTransaction(
                    client,
                    envelopeId,
                    { key: 'value' },
                );
                expect(result.finalized).toBe(true);

                // simulate sideTableAppender writing within the same client
                await client.query(
                    `SELECT 1 AS side_effect`, // no-op SQL
                );
                sideEffects.push('appended');
            });

            expect(sideEffects).toHaveLength(1);
            const entry = await ledger.getEntry(envelopeId);
            expect(entry!.status).toBe('COMMITTED');
        });
    });

    // -------------------------------------------------------------------------
    // 4. reject()
    // -------------------------------------------------------------------------

    describe('reject()', () => {
        it('should transition PENDING to REJECTED', async () => {
            const envelopeId = randomUUID();
            await ledger.claim(envelopeId);

            const result = await ledger.reject(envelopeId);

            expect(result.rejected).toBe(true);
            if (!result.rejected) throw new Error('unreachable');
            expect(result.envelopeId).toBe(envelopeId);
            expect(result.status).toBe('REJECTED');
            expect(result.finalizedAt).toBeInstanceOf(Date);
        });

        it('should return NOT_FOUND when no PENDING row exists', async () => {
            const envelopeId = randomUUID();

            const result = await ledger.reject(envelopeId);

            expect(result.rejected).toBe(false);
            if (result.rejected) throw new Error('unreachable');
            expect(result.reason).toBe('NOT_FOUND');
        });

        it('should return ALREADY_FINAL when envelope is already COMMITTED', async () => {
            const envelopeId = randomUUID();
            await ledger.claim(envelopeId);
            await ledger.finalize(envelopeId);

            const result = await ledger.reject(envelopeId);

            expect(result.rejected).toBe(false);
            if (result.rejected) throw new Error('unreachable');
            expect(result.reason).toBe('ALREADY_FINAL');
        });

        it('should return ALREADY_FINAL when envelope is already REJECTED', async () => {
            const envelopeId = randomUUID();
            await ledger.claim(envelopeId);
            await ledger.reject(envelopeId);

            const result = await ledger.reject(envelopeId);

            expect(result.rejected).toBe(false);
            if (result.rejected) throw new Error('unreachable');
            expect(result.reason).toBe('ALREADY_FINAL');
        });

        // claimerId ownership verification on reject
        it('should return NOT_FOUND when claimerId does not match for reject', async () => {
            const envelopeId = randomUUID();
            const realClaimerId = `worker-${randomUUID()}`;
            const wrongClaimerId = `impostor-${randomUUID()}`;

            await ledger.claim(envelopeId, 30, realClaimerId);

            const result = await ledger.reject(envelopeId, wrongClaimerId);

            expect(result.rejected).toBe(false);
            if (result.rejected) throw new Error('unreachable');
            // ownership does not match → the SELECT returns empty → NOT_FOUND
            expect(result.reason).toBe('NOT_FOUND');

            // the PENDING row should remain unmodified
            const entry = await ledger.getEntry(envelopeId);
            expect(entry!.status).toBe('PENDING');
        });
    });

    // -------------------------------------------------------------------------
    // 5. rejectWithinTransaction() -- shared-transaction pattern
    // -------------------------------------------------------------------------

    describe('rejectWithinTransaction()', () => {
        it('should rollback reject when outer transaction is aborted', async () => {
            const envelopeId = randomUUID();
            await ledger.claim(envelopeId);

            await expect(
                withTransaction(pool, async (client) => {
                    await ledger.rejectWithinTransaction(client, envelopeId);
                    throw new Error('simulated crash after reject');
                }),
            ).rejects.toThrow('simulated crash after reject');

            // the PENDING row should remain unchanged
            const entry = await ledger.getEntry(envelopeId);
            expect(entry).not.toBeNull();
            expect(entry!.status).toBe('PENDING');
        });
    });

    // -------------------------------------------------------------------------
    // 6. expireStalePending()
    // -------------------------------------------------------------------------

    describe('expireStalePending()', () => {
        it('should return expiredCount=0 when no stale PENDING rows exist', async () => {
            const result = await ledger.expireStalePending();
            expect(result.expiredCount).toBe(0);
        });

        it('should expire PENDING rows whose TTL has elapsed', async () => {
            const envId1 = randomUUID();
            const envId2 = randomUUID();
            const envId3 = randomUUID();

            // claim three envelopes
            await ledger.claim(envId1, 1);
            await ledger.claim(envId2, 1);
            await ledger.claim(envId3, 3600); // long TTL, will not expire

            // set the claimed_at of the first two into the past
            await pool.query(
                `UPDATE policy.envelope_ledger
                 SET claimed_at = NOW() - interval '1 hour'
                 WHERE envelope_id = ANY($1) AND status = 'PENDING'`,
                [[envId1, envId2]],
            );

            const result = await ledger.expireStalePending();

            expect(result.expiredCount).toBe(2);

            // envId1/envId2 are now EXPIRED (getEntry does not return EXPIRED rows)
            expect(await ledger.getEntry(envId1)).toBeNull();
            expect(await ledger.getEntry(envId2)).toBeNull();

            // envId3 is still PENDING
            const entry3 = await ledger.getEntry(envId3);
            expect(entry3).not.toBeNull();
            expect(entry3!.status).toBe('PENDING');
        });

        it('should not expire PENDING rows within TTL', async () => {
            const envelopeId = randomUUID();
            await ledger.claim(envelopeId, 3600);

            const result = await ledger.expireStalePending();
            expect(result.expiredCount).toBe(0);
        });

        it('should allow re-claim after expiry (crash-recovery)', async () => {
            const envelopeId = randomUUID();
            await ledger.claim(envelopeId, 1);

            // force expiry
            await pool.query(
                `UPDATE policy.envelope_ledger
                 SET claimed_at = NOW() - interval '1 hour'
                 WHERE envelope_id = $1 AND status = 'PENDING'`,
                [envelopeId],
            );
            await ledger.expireStalePending();

            // a re-claim should succeed
            const result = await ledger.claim(envelopeId);
            expect(result.claimed).toBe(true);
        });

        it('should respect limit parameter for bulk expiry', async () => {
            // create 5 expired PENDING rows
            const envIds = Array.from({ length: 5 }, () => randomUUID());
            for (const id of envIds) {
                await ledger.claim(id, 1);
            }
            await pool.query(
                `UPDATE policy.envelope_ledger
                 SET claimed_at = NOW() - interval '1 hour'
                 WHERE status = 'PENDING'`,
            );

            // limit=3: only recycle 3 rows
            const result = await ledger.expireStalePending(3);
            expect(result.expiredCount).toBe(3);
        });
    });

    // -------------------------------------------------------------------------
    // 7. getEntry()
    // -------------------------------------------------------------------------

    describe('getEntry()', () => {
        it('should return null when no entry exists', async () => {
            const entry = await ledger.getEntry(randomUUID());
            expect(entry).toBeNull();
        });

        it('should return PENDING entry after claim', async () => {
            const envelopeId = randomUUID();
            await ledger.claim(envelopeId);

            const entry = await ledger.getEntry(envelopeId);
            expect(entry).not.toBeNull();
            expect(entry!.status).toBe('PENDING');
        });

        it('should return COMMITTED entry after finalize', async () => {
            const envelopeId = randomUUID();
            await ledger.claim(envelopeId);
            await ledger.finalize(envelopeId);

            const entry = await ledger.getEntry(envelopeId);
            expect(entry!.status).toBe('COMMITTED');
        });

        it('should return REJECTED entry after reject', async () => {
            const envelopeId = randomUUID();
            await ledger.claim(envelopeId);
            await ledger.reject(envelopeId);

            const entry = await ledger.getEntry(envelopeId);
            expect(entry!.status).toBe('REJECTED');
        });

        it('should return null when only EXPIRED rows exist', async () => {
            const envelopeId = randomUUID();
            await ledger.claim(envelopeId, 1);

            // force expiry
            await pool.query(
                `UPDATE policy.envelope_ledger
                 SET claimed_at = NOW() - interval '1 hour'
                 WHERE envelope_id = $1 AND status = 'PENDING'`,
                [envelopeId],
            );
            await ledger.expireStalePending();

            const entry = await ledger.getEntry(envelopeId);
            expect(entry).toBeNull();
        });

        it('should return correct EnvelopeLedgerEntry structure', async () => {
            const envelopeId = randomUUID();
            await ledger.claim(envelopeId, 45);

            const entry = await ledger.getEntry(envelopeId);
            expect(entry).not.toBeNull();
            expect(entry!.envelopeId).toBe(envelopeId);
            expect(entry!.status).toBe('PENDING');
            expect(entry!.ttlSeconds).toBe(45);
            expect(entry!.claimerId).toBeNull(); // null when no claimerId
            expect(entry!.claimedAt).toBeInstanceOf(Date);
            expect(entry!.finalizedAt).toBeNull();
            expect(entry!.resultSummary).toBeNull();
            expect(entry!.createdAt).toBeInstanceOf(Date);
        });
    });

    // -------------------------------------------------------------------------
    // 8. getLatestRow() -- query including EXPIRED rows
    // -------------------------------------------------------------------------

    describe('getLatestRow()', () => {
        it('should return EXPIRED row when only EXPIRED rows exist', async () => {
            const envelopeId = randomUUID();
            await ledger.claim(envelopeId, 1);

            // force expiry
            await pool.query(
                `UPDATE policy.envelope_ledger
                 SET claimed_at = NOW() - interval '1 hour'
                 WHERE envelope_id = $1 AND status = 'PENDING'`,
                [envelopeId],
            );
            await ledger.expireStalePending();

            const row = await ledger.getLatestRow(envelopeId);
            expect(row).not.toBeNull();
            expect(row!.status).toBe('EXPIRED');
        });
    });

    // -------------------------------------------------------------------------
    // 9. status runtime validation (no brand cast)
    // -------------------------------------------------------------------------

    describe('parseLedgerClaimStatus (runtime validation)', () => {
        it('should accept all valid status values', () => {
            for (const status of LEDGER_CLAIM_STATUSES) {
                expect(() => parseLedgerClaimStatus(status)).not.toThrow();
                expect(parseLedgerClaimStatus(status)).toBe(status);
            }
        });

        it('should throw on invalid status value (fail-closed)', () => {
            expect(() => parseLedgerClaimStatus('INVALID')).toThrow();
            expect(() => parseLedgerClaimStatus('')).toThrow();
            expect(() => parseLedgerClaimStatus(null)).toThrow();
            expect(() => parseLedgerClaimStatus(undefined)).toThrow();
            expect(() => parseLedgerClaimStatus(42)).toThrow();
        });

        it('should identify valid statuses via isLedgerClaimStatus', () => {
            expect(isLedgerClaimStatus('PENDING')).toBe(true);
            expect(isLedgerClaimStatus('COMMITTED')).toBe(true);
            expect(isLedgerClaimStatus('REJECTED')).toBe(true);
            expect(isLedgerClaimStatus('EXPIRED')).toBe(true);
            expect(isLedgerClaimStatus('INVALID')).toBe(false);
            expect(isLedgerClaimStatus('')).toBe(false);
            expect(isLedgerClaimStatus(null)).toBe(false);
        });
    });

    // -------------------------------------------------------------------------
    // 10. state-machine constraint (multi-envelope concurrent isolation)
    // -------------------------------------------------------------------------

    describe('state machine isolation', () => {
        it('should handle different envelopes independently', async () => {
            const envA = randomUUID();
            const envB = randomUUID();

            await ledger.claim(envA);
            await ledger.claim(envB);

            await ledger.finalize(envA);
            await ledger.reject(envB);

            const entryA = await ledger.getEntry(envA);
            const entryB = await ledger.getEntry(envB);

            expect(entryA!.status).toBe('COMMITTED');
            expect(entryB!.status).toBe('REJECTED');
        });

        it('should allow COMMITTED and REJECTED on different envelopes simultaneously', async () => {
            const envelopes = Array.from({ length: 5 }, () => randomUUID());

            for (const id of envelopes) {
                await ledger.claim(id);
            }
            // finalize odd indices, reject even indices
            for (let i = 0; i < envelopes.length; i++) {
                if (i % 2 === 0) {
                    await ledger.finalize(envelopes[i]!);
                } else {
                    await ledger.reject(envelopes[i]!);
                }
            }

            for (let i = 0; i < envelopes.length; i++) {
                const entry = await ledger.getEntry(envelopes[i]!);
                expect(entry!.status).toBe(i % 2 === 0 ? 'COMMITTED' : 'REJECTED');
            }
        });
    });

    // -------------------------------------------------------------------------
    // 11. performance baseline (informal, print only)
    // -------------------------------------------------------------------------

    describe('performance baseline', () => {
        it('should handle 50 sequential claim+finalize within 15s', async () => {
            const start = Date.now();
            for (let i = 0; i < 50; i++) {
                const id = randomUUID();
                await ledger.claim(id);
                await ledger.finalize(id);
            }
            const elapsed = Date.now() - start;
            // baseline: 50 iterations < 15s (loose, tolerant of the CI environment)
            expect(elapsed).toBeLessThan(15_000);
        });
    });
});

// ---------------------------------------------------------------------------
// Pure-logic tests (no DB dependency)
// ---------------------------------------------------------------------------

describe('parseLedgerClaimStatus (unit, no DB)', () => {
    it('should parse all valid statuses without DB', () => {
        const statuses = ['PENDING', 'COMMITTED', 'REJECTED', 'EXPIRED'] as const;
        for (const s of statuses) {
            expect(parseLedgerClaimStatus(s)).toBe(s);
        }
    });

    it('should throw on brand-cast unsafe values', () => {
        const invalidValues = [
            'pending',       // lowercase
            'Pending',       // capitalized first letter
            'COMMITED',      // misspelling
            ' PENDING',      // leading space
            'PENDING ',      // trailing space
            '{}',
        ];
        for (const v of invalidValues) {
            expect(() => parseLedgerClaimStatus(v)).toThrow();
        }
    });
});

describe('LEDGER_CLAIM_STATUSES', () => {
    it('should contain exactly 4 status values', () => {
        expect(LEDGER_CLAIM_STATUSES).toHaveLength(4);
        expect(LEDGER_CLAIM_STATUSES).toContain('PENDING');
        expect(LEDGER_CLAIM_STATUSES).toContain('COMMITTED');
        expect(LEDGER_CLAIM_STATUSES).toContain('REJECTED');
        expect(LEDGER_CLAIM_STATUSES).toContain('EXPIRED');
    });
});
