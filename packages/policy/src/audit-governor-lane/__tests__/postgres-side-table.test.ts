/**
 * postgres-side-table.test.ts -- PostgresSideTableAppender Postgres persistence implementation tests.
 *
 * Coverage (B5 acceptance criteria):
 *   1. Same-transaction atomic write: append + verifyChain happy path, chain verification passes
 *   2. Rollback: when the ActionRecord write fails, the side table INSERT rolls back in sync (atomicity guarantee)
 *   3. Missing transactionClient -> fail-closed
 *   4. verifyChain multi-row chain integrity + eventual chain consistency
 *   5. agentDid-filtered verifyChain semantics
 *
 * Dependencies: local PostgreSQL (docker-compose up -d), DATABASE_URL environment variable
 * Isolation: createTestDatabase() creates an isolated temporary DB, cleaned up in afterAll
 *
 */

import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import {
    createTestDatabase,
    withTransaction,
    type DatabasePool,
} from '@coivitas/shared';

import {
    PostgresSideTableAppender,
    SIDE_TABLE_GENESIS_HASH,
    computeRowHash,
} from '../side-table.js';
import type { SideTableEntry } from '../types.js';
import type { DID, Timestamp } from '@coivitas/types';

// ---------------------------------------------------------------------------
// Test isolation: skip the whole suite when DATABASE_URL is not set
// ---------------------------------------------------------------------------

const describeIfDatabase = process.env.DATABASE_URL ? describe : describe.skip;

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

const AGENT_DID_A = 'did:agent:test-alpha' as DID;
const AGENT_DID_B = 'did:agent:test-beta' as DID;
const TIMESTAMP = '2026-05-06T10:00:00.000Z' as Timestamp;

function makeEntry(
    recordId: string,
    recordHash: string,
    agentDid: DID = AGENT_DID_A,
): SideTableEntry {
    return { recordId, recordHash, agentDid, createdAt: TIMESTAMP };
}

// ---------------------------------------------------------------------------
// Suite
// ---------------------------------------------------------------------------

describeIfDatabase('PostgresSideTableAppender (production impl)', () => {
    let pool: DatabasePool;
    let appender: PostgresSideTableAppender;
    let cleanup: (() => Promise<void>) | undefined;

    beforeAll(async () => {
        const database = await createTestDatabase();
        pool = database.pool;
        cleanup = database.cleanup;
        appender = new PostgresSideTableAppender(pool);
    });

    afterAll(async () => {
        await cleanup?.();
    }, 30000); // dropping the test DB + multi-schema cleanup measured >10s, raised to 30s

    beforeEach(async () => {
        // session_replication_role requires superuser privileges,
        // and a plain CI app role gets permission denied. Switch to ALTER TABLE DISABLE/ENABLE TRIGGER ALL
        // (only requires table owner privileges, weaker than superuser; the repo app role is usually the owner).
        // The three queries must still run on the same connection (to avoid affecting other sessions in the pool).
        const client = await pool.connect();
        try {
            await client.query(
                `ALTER TABLE policy.audit_side_table DISABLE TRIGGER ALL`,
            );
            await client.query(`DELETE FROM policy.audit_side_table`);
            await client.query(
                `ALTER TABLE policy.audit_side_table ENABLE TRIGGER ALL`,
            );
        } finally {
            client.release();
        }
    });

    // -------------------------------------------------------------------------
    // 1. Same-transaction atomic write + verifyChain happy path
    // -------------------------------------------------------------------------

    describe('append — same-transaction atomic write', () => {
        it('should append first entry with genesis prevRowHash and persist to DB', async () => {
            const entry = makeEntry('rec-001', 'hash-001');

            let result: { rowHash: string } | undefined;
            await withTransaction(pool, async (client) => {
                result = await appender.append(entry, client);
            });

            expect(result).toBeDefined();
            expect(result!.rowHash).toMatch(/^[0-9a-f]{64}$/);

            // DB persistence verification
            const dbResult = await pool.query(
                `SELECT record_id, prev_row_hash, row_hash FROM policy.audit_side_table`,
            );
            expect(dbResult.rows).toHaveLength(1);
            const row = dbResult.rows[0] as {
                record_id: string;
                prev_row_hash: string;
                row_hash: string;
            };
            expect(row.record_id).toBe('rec-001');
            expect(row.prev_row_hash).toBe(SIDE_TABLE_GENESIS_HASH);
            expect(row.row_hash).toBe(result!.rowHash);
        });

        it('should chain two entries with correct prevRowHash linkage', async () => {
            const entry1 = makeEntry('rec-001', 'hash-001');
            const entry2 = makeEntry('rec-002', 'hash-002');

            let rowHash1: string | undefined;
            let rowHash2: string | undefined;

            await withTransaction(pool, async (client) => {
                const r1 = await appender.append(entry1, client);
                rowHash1 = r1.rowHash;
                const r2 = await appender.append(entry2, client);
                rowHash2 = r2.rowHash;
            });

            // Verify the hash chain linkage
            const expectedRowHash2 = computeRowHash(
                rowHash1!,
                'rec-002',
                'hash-002',
                AGENT_DID_A as string,
                TIMESTAMP as string,
            );
            expect(rowHash2!).toBe(expectedRowHash2);

            // DB persistence verification
            const dbResult = await pool.query(
                `SELECT record_id, prev_row_hash, row_hash FROM policy.audit_side_table ORDER BY id ASC`,
            );
            expect(dbResult.rows).toHaveLength(2);
            const rows = dbResult.rows as Array<{
                record_id: string;
                prev_row_hash: string;
                row_hash: string;
            }>;
            expect(rows[0]!.record_id).toBe('rec-001');
            expect(rows[1]!.record_id).toBe('rec-002');
            expect(rows[1]!.prev_row_hash).toBe(rowHash1!);
        });

        it('should verify multi-entry chain with verifyChain', async () => {
            await withTransaction(pool, async (client) => {
                await appender.append(makeEntry('rec-001', 'hash-001'), client);
                await appender.append(makeEntry('rec-002', 'hash-002'), client);
                await appender.append(makeEntry('rec-003', 'hash-003'), client);
            });

            const result = await appender.verifyChain();
            expect(result.valid).toBe(true);
        });

        it('should return valid true for empty chain', async () => {
            const result = await appender.verifyChain();
            expect(result.valid).toBe(true);
        });
    });

    // -------------------------------------------------------------------------
    // 2. Rollback: when the ActionRecord write fails, the side table INSERT rolls back in sync
    // -------------------------------------------------------------------------

    describe('rollback — side-table reverts when outer transaction aborts', () => {
        it('should rollback side table INSERT when transaction is rolled back', async () => {
            // Simulate: an error occurs after the ActionRecord write, causing the transaction to roll back
            await expect(
                withTransaction(pool, async (client) => {
                    await appender.append(
                        makeEntry('rec-rollback', 'hash-rb'),
                        client,
                    );

                    // Simulate a subsequent operation failing (force rollback)
                    throw new Error('simulated ActionRecord write failure');
                }),
            ).rejects.toThrow('simulated ActionRecord write failure');

            // Verify there is no data in the DB (transaction rolled back)
            const dbResult = await pool.query(
                `SELECT count(*) as count FROM policy.audit_side_table`,
            );
            const count = parseInt(
                (dbResult.rows[0] as { count: string }).count,
                10,
            );
            expect(count).toBe(0);
        });

        it('should not affect other committed rows when one transaction rolls back', async () => {
            // Commit one row first
            await withTransaction(pool, async (client) => {
                await appender.append(
                    makeEntry('rec-committed', 'hash-c'),
                    client,
                );
            });

            // Open another transaction, append, then roll back
            await expect(
                withTransaction(pool, async (client) => {
                    await appender.append(
                        makeEntry('rec-rolled-back', 'hash-r'),
                        client,
                    );
                    throw new Error('forced rollback');
                }),
            ).rejects.toThrow('forced rollback');

            // Only the first row is persisted
            const dbResult = await pool.query(
                `SELECT record_id FROM policy.audit_side_table ORDER BY id ASC`,
            );
            expect(dbResult.rows).toHaveLength(1);
            expect((dbResult.rows[0] as { record_id: string }).record_id).toBe(
                'rec-committed',
            );
        });
    });

    // -------------------------------------------------------------------------
    // 3. Missing transactionClient -> fail-closed
    // -------------------------------------------------------------------------

    describe('fail-closed — transactionClient missing or invalid', () => {
        it('should throw ProtocolError when transactionClient is undefined (fail-closed)', async () => {
            const entry = makeEntry('rec-fc', 'hash-fc');

            await expect(appender.append(entry)).rejects.toMatchObject({
                code: 'INTERNAL_ERROR',
            });
        });

        it('should throw ProtocolError when transactionClient is null (fail-closed)', async () => {
            const entry = makeEntry('rec-fc-null', 'hash-fc');

            await expect(appender.append(entry, null)).rejects.toMatchObject({
                code: 'INTERNAL_ERROR',
            });
        });

        it('should throw ProtocolError when transactionClient is a plain object without .query (fail-closed)', async () => {
            const entry = makeEntry('rec-fc-bad', 'hash-fc');

            await expect(
                appender.append(entry, { notQuery: true }),
            ).rejects.toMatchObject({
                code: 'INTERNAL_ERROR',
            });
        });

        it('should throw ProtocolError when transactionClient is pg.Pool (Pool lacks .release, not a PoolClient)', async () => {
            // pg.Pool has .query but not .release;
            // mistakenly passing a pool would cause append to run on a new connection, breaking the same-transaction atomic write contract.
            // assertPoolClient must detect and reject a pg.Pool by its missing .release.
            const entry = makeEntry('rec-fc-pool', 'hash-fc');

            // Pass the suite-level pool (a pg.Pool instance) as transactionClient
            const error = await appender
                .append(entry, pool)
                .catch((e: unknown) => e);
            expect(error).toMatchObject({
                code: 'INTERNAL_ERROR',
            });
            // Ensure the error message indicates this is a Pool rather than a PoolClient (to help the caller diagnose quickly)
            expect(
                String((error as { message?: string }).message ?? ''),
            ).toContain('PoolClient');
        });

        it('should not commit any data when fail-closed throws', async () => {
            const entry = makeEntry('rec-fc-no-data', 'hash-fc');

            try {
                await appender.append(entry);
            } catch {
                // expected throw
            }

            const dbResult = await pool.query(
                `SELECT count(*) as count FROM policy.audit_side_table`,
            );
            const count = parseInt(
                (dbResult.rows[0] as { count: string }).count,
                10,
            );
            expect(count).toBe(0);
        });
    });

    // -------------------------------------------------------------------------
    // 4. verifyChain — agentDid filter semantics
    // -------------------------------------------------------------------------

    describe('verifyChain — agentDid filter', () => {
        it('should verify valid chain when filtered by agentDid', async () => {
            await withTransaction(pool, async (client) => {
                await appender.append(
                    makeEntry('rec-a1', 'hash-a1', AGENT_DID_A),
                    client,
                );
                await appender.append(
                    makeEntry('rec-b1', 'hash-b1', AGENT_DID_B),
                    client,
                );
                await appender.append(
                    makeEntry('rec-a2', 'hash-a2', AGENT_DID_A),
                    client,
                );
            });

            const resultA = await appender.verifyChain(AGENT_DID_A);
            expect(resultA.valid).toBe(true);

            const resultB = await appender.verifyChain(AGENT_DID_B);
            expect(resultB.valid).toBe(true);
        });

        it('should return valid true for agentDid with no matching rows', async () => {
            await withTransaction(pool, async (client) => {
                await appender.append(
                    makeEntry('rec-a1', 'hash-a1', AGENT_DID_A),
                    client,
                );
            });

            const result = await appender.verifyChain(AGENT_DID_B);
            expect(result.valid).toBe(true);
        });
    });

    // -------------------------------------------------------------------------
    // 5. verifyChain — tamper detection (modifying the DB directly via SQL)
    // -------------------------------------------------------------------------

    describe('verifyChain — tamper detection', () => {
        it('should detect tampered row_hash -> SIDE_TABLE_ROW_TAMPERED', async () => {
            await withTransaction(pool, async (client) => {
                await appender.append(makeEntry('rec-001', 'hash-001'), client);
                await appender.append(makeEntry('rec-002', 'hash-002'), client);
            });

            // Switch to ALTER TABLE DISABLE/ENABLE TRIGGER ALL
            // instead of session_replication_role (which requires superuser); only requires table owner privileges.
            const tamperClient = await pool.connect();
            try {
                await tamperClient.query(
                    `ALTER TABLE policy.audit_side_table DISABLE TRIGGER ALL`,
                );
                await tamperClient.query(
                    `UPDATE policy.audit_side_table SET row_hash = 'tampered-000' WHERE record_id = 'rec-002'`,
                );
                await tamperClient.query(
                    `ALTER TABLE policy.audit_side_table ENABLE TRIGGER ALL`,
                );
            } finally {
                tamperClient.release();
            }

            const result = await appender.verifyChain();
            expect(result.valid).toBe(false);
            expect(result.errorCode).toBe('SIDE_TABLE_ROW_TAMPERED');
            expect(result.brokenAt).toBe('rec-002');
        });

        it('should detect tampered prev_row_hash -> SIDE_TABLE_ANCHOR_MISMATCH', async () => {
            await withTransaction(pool, async (client) => {
                await appender.append(makeEntry('rec-001', 'hash-001'), client);
                await appender.append(makeEntry('rec-002', 'hash-002'), client);
            });

            // Switch to ALTER TABLE DISABLE/ENABLE TRIGGER ALL
            // instead of session_replication_role (which requires superuser); only requires table owner privileges.
            const tamperClient = await pool.connect();
            try {
                await tamperClient.query(
                    `ALTER TABLE policy.audit_side_table DISABLE TRIGGER ALL`,
                );
                await tamperClient.query(
                    `UPDATE policy.audit_side_table SET prev_row_hash = 'tampered-prev' WHERE record_id = 'rec-002'`,
                );
                await tamperClient.query(
                    `ALTER TABLE policy.audit_side_table ENABLE TRIGGER ALL`,
                );
            } finally {
                tamperClient.release();
            }

            const result = await appender.verifyChain();
            expect(result.valid).toBe(false);
            expect(result.errorCode).toBe('SIDE_TABLE_ANCHOR_MISMATCH');
            expect(result.brokenAt).toBe('rec-002');
        });

        // -----------------------------------------------------------------------
        // round-trip test: verifyChain immediately after append should be valid=true
        // Catches the bug where pg TIMESTAMPTZ -> Date deserialization disagrees with the ISO string passed into append
        // -----------------------------------------------------------------------

        it('should return valid=true immediately after append (round-trip regression)', async () => {
            await withTransaction(pool, async (client) => {
                await appender.append(
                    makeEntry('rec-rt-001', 'hash-rt-001'),
                    client,
                );
                await appender.append(
                    makeEntry('rec-rt-002', 'hash-rt-002'),
                    client,
                );
            });

            // verifyChain re-reads rows from the DB (including TIMESTAMPTZ deserialization);
            // if created_at is not normalized to an ISO string, the hash will mismatch and report SIDE_TABLE_ROW_TAMPERED.
            const result = await appender.verifyChain();
            expect(result.valid).toBe(true);
        });
    });

    // -------------------------------------------------------------------------
    // 6. Concurrent-write safety (advisory lock)
    // -------------------------------------------------------------------------

    describe('concurrent append — advisory lock serialization', () => {
        // Approach C — Promise.race verifies advisory lock serialization.
        // client1 takes advisory_xact_lock and does not commit, so client2's append should block (waiting on the lock);
        // use Promise.race + a setTimeout sentinel to verify the block, then commit client1 to release the lock,
        // and verify that client2 completes and prev_row_hash links correctly.
        it(
            'should correctly chain two concurrent appends without fork (advisory lock)',
            { timeout: 30000 },
            async () => {
                const client1 = await pool.connect();
                const client2 = await pool.connect();

                try {
                    await client1.query('BEGIN');
                    await client2.query('BEGIN');

                    // Step 1: client1 append — takes advisory_xact_lock + INSERT
                    const result1 = await appender.append(
                        makeEntry('rec-con-001', 'hash-con-001'),
                        client1,
                    );
                    // client1's transaction is not committed, so advisory_xact_lock is still held

                    // Step 2: start client2's append (it will block waiting on advisory_xact_lock)
                    const BLOCKED_SENTINEL = Symbol('blocked');
                    const promise2 = appender.append(
                        makeEntry('rec-con-002', 'hash-con-002'),
                        client2,
                    );

                    // Step 3: Promise.race verifies that client2 is indeed blocking
                    // If promise2 does not resolve within 200ms, the advisory lock is serializing correctly
                    const raceResult = await Promise.race([
                        promise2.then((r) => r),
                        new Promise<typeof BLOCKED_SENTINEL>((resolve) =>
                            setTimeout(() => resolve(BLOCKED_SENTINEL), 200),
                        ),
                    ]);
                    expect(raceResult).toBe(BLOCKED_SENTINEL);

                    // Step 4: commit client1 to release the lock -> client2 should complete its append
                    await client1.query('COMMIT');
                    const result2 = await promise2;
                    await client2.query('COMMIT');

                    // Assert: both row hashes are valid and distinct
                    expect(result1.rowHash).toMatch(/^[0-9a-f]{64}$/);
                    expect(result2.rowHash).toMatch(/^[0-9a-f]{64}$/);
                    expect(result1.rowHash).not.toBe(result2.rowHash);

                    // Verify there are two rows in the DB and the hash chain is continuous (no fork)
                    const dbResult = await pool.query<{
                        record_id: string;
                        row_hash: string;
                        prev_row_hash: string;
                    }>(
                        `SELECT record_id, row_hash, prev_row_hash
                     FROM policy.audit_side_table
                     ORDER BY id ASC`,
                    );
                    expect(dbResult.rows).toHaveLength(2);

                    const [row1, row2] = dbResult.rows;
                    // First row prev = GENESIS
                    expect(row1!.prev_row_hash).toBe(SIDE_TABLE_GENESIS_HASH);
                    // Second row prev = first row's row_hash (chain continuous, no fork)
                    expect(row2!.prev_row_hash).toBe(row1!.row_hash);

                    // verifyChain validates the full chain successfully
                    const verifyResult = await appender.verifyChain();
                    expect(verifyResult.valid).toBe(true);
                } finally {
                    client1.release();
                    client2.release();
                }
            },
        );
    });
});
