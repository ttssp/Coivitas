/**
 * 028-hcc-v0.2-backward-compatibility.test.ts — migration script unit + integration tests
 *
 *   — Case 1-6 test coverage
 *
 * Test strategy:
 *   - Unit layer: mock pg.Pool + pg.PoolClient — pure logic verification; no dependency on a real DB
 *   - Integration layer: Case 6 is marked integration — depends on a real DB (skipped in CI via SKIP_DB_TESTS=1)
 *
 * Case coverage:
 *   Case 1: pre-check totalEstimate=0 → no-op (early return)
 *   Case 2: genesis entry (chain_position=0) → previousHash=64 zeros
 *   Case 3: non-genesis entry → fetchPrevCommittedHash fetches the chain_position-1 hash
 *   Case 4: --dry-run mode → no UPDATE, no COMMIT; diff log still emitted
 *   Case 5: multi-tenant chain isolation — the two chains keep their own previousHash anchors without mixing
 *   Case 6: retry + crash recovery — processBatchWithRetry exponential backoff; idempotent restart
 */

import {
    describe,
    it,
    expect,
    vi,
    beforeEach,
    type MockedFunction,
} from 'vitest';
import type { Pool, PoolClient, QueryResult } from 'pg';

// Module under test (imported via a relative path from scripts/migrations/)
import { migrateHccV01ToV02 } from '../028-hcc-v0.2-backward-compatibility.js';

// ─── mock factories ────────────────────────────────────────────────────────────

/**
 * createMockClient — create a mock PoolClient
 *
 * Supports query returning different results in call order (the queryResults queue)
 */
function createMockClient(
    queryResults: Array<Partial<QueryResult>>,
): PoolClient {
    let callCount = 0;
    const mockQuery = vi.fn().mockImplementation(async () => {
        const result = queryResults[callCount] ?? { rows: [] };
        callCount++;
        return result as QueryResult;
    });
    return {
        query: mockQuery,
        release: vi.fn(),
    } as unknown as PoolClient;
}

/**
 * createMockPool — create a mock Pool
 *
 * poolQueryResults: queue returned by pool.query() in call order
 * clientQueryResults: queue returned by client.query() in call order (after connect())
 */
function createMockPool(
    poolQueryResults: Array<Partial<QueryResult>>,
    clientQueryResults: Array<Partial<QueryResult>> = [],
): Pool {
    let poolCallCount = 0;
    const mockClient = createMockClient(clientQueryResults);

    const mockQuery = vi.fn().mockImplementation(async () => {
        const result = poolQueryResults[poolCallCount] ?? { rows: [] };
        poolCallCount++;
        return result as QueryResult;
    });

    return {
        query: mockQuery,
        connect: vi.fn().mockResolvedValue(mockClient),
        end: vi.fn().mockResolvedValue(undefined),
    } as unknown as Pool;
}

// ─── Case 1: totalEstimate=0 early return ─────────────────────────────────────

describe('028 migration script', () => {
    describe('Case 1: pre-check totalEstimate=0 → no-op', () => {
        it('should return empty progress when no entries need migration', async () => {
            // Conclusion: when totalEstimate=0, return no-op progress immediately; do not call listMigrationChains
            const pool = createMockPool([
                // pool.query #1: pre-check — union_total=0
                {
                    rows: [
                        {
                            null_jcs_count: '0',
                            v01_count: '0',
                            union_total: '0',
                        },
                    ],
                },
            ]);

            const progress = await migrateHccV01ToV02(pool);

            expect(progress.entriesProcessed).toBe(0);
            expect(progress.entriesFailed).toBe(0);
            expect(progress.batchesProcessed).toBe(0);
            expect(progress.batchesCommitted).toBe(0);
            expect(progress.currentBatchFirstEntryId).toBeNull();

            // pool.query is called only once (pre-check); listMigrationChains is not triggered (pool.query #2 is never called)
            expect((pool.query as MockedFunction<Pool['query']>).mock.calls).toHaveLength(1);
        });
    });

    // ─── Case 2: genesis entry previousHash = 64 zeros ──────────────────────

    describe('Case 2: genesis entry (chain_position=0) → previousHash=64 zeros', () => {
        it('should use 64-zero genesis hash for chain_position=0', async () => {
            // Conclusion: genesis entry (chain_position=0) → fetchPrevCommittedHash returns 64 zeros;
            // does not query the prev DB row; the UPDATE's previous_hash field = 64 zeros
            const GENESIS_HASH =
                '0000000000000000000000000000000000000000000000000000000000000000';

            const pool = createMockPool(
                [
                    // pool.query #1: pre-check — union_total=1
                    {
                        rows: [
                            {
                                null_jcs_count: '1',
                                v01_count: '1',
                                union_total: '1',
                            },
                        ],
                    },
                    // pool.query #2: listMigrationChains — 1 chain partition
                    {
                        rows: [
                            {
                                chain_namespace: 'atp',
                                tenant_id: 'tenant-uuid-1',
                                audit_class: 'L1',
                            },
                        ],
                    },
                    // pool.query #3: selectNextBatch — 1 entry (genesis)
                    {
                        rows: [
                            {
                                entry_id: 'entry-uuid-1',
                                canonical_payload:
                                    '{"action":"test","timestamp":1700000000}',
                                canonical_payload_hash: 'old-hash-v01',
                                previous_hash: GENESIS_HASH,
                                chain_position: 0,
                                chain_namespace: 'atp',
                                tenant_id: 'tenant-uuid-1',
                                audit_class: 'L1',
                            },
                        ],
                    },
                    // pool.query #4: selectNextBatch (second call) — empty (pagination done)
                    { rows: [] },
                ],
                [
                    // client.query #1: BEGIN
                    { rows: [] },
                    // client.query #2: fetchPrevCommittedHash
                    // genesis (chain_position=0) → does not query the DB; this result is never used
                    { rows: [] },
                    // client.query #3: UPDATE
                    { rows: [], rowCount: 1 },
                    // client.query #4: COMMIT
                    { rows: [] },
                ],
            );

            const progress = await migrateHccV01ToV02(pool, { dryRun: false });

            expect(progress.entriesProcessed).toBe(1);
            expect(progress.entriesFailed).toBe(0);
            expect(progress.batchesCommitted).toBe(1);

            // client.query call verification: BEGIN → UPDATE (includes genesis previous_hash=64 zeros) → COMMIT
            const mockClient = await (pool.connect as MockedFunction<Pool['connect']>)();
            const clientQuery = (mockClient.query as MockedFunction<PoolClient['query']>);
            // BEGIN is the first client.query call
            const beginCall = clientQuery.mock.calls[0];
            expect(beginCall?.[0]).toBe('BEGIN');

            // UPDATE call — verify the previous_hash param = GENESIS_HASH
            const updateCall = clientQuery.mock.calls.find(
                (call) =>
                    typeof call[0] === 'string' &&
                    (call[0] as string).includes('UPDATE hash_chain_entries'),
            );
            expect(updateCall).toBeDefined();
            // params[2] = previous_hash (the 3rd argument; $3 in SQL)
            const updateParams = updateCall?.[1] as string[];
            expect(updateParams?.[2]).toBe(GENESIS_HASH);
        });
    });

    // ─── Case 3: non-genesis entry → fetchPrevCommittedHash queries DB ───────

    describe('Case 3: non-genesis entry → fetchPrevCommittedHash queries DB', () => {
        it('should query DB for previousHash when chain_position > 0', async () => {
            // Conclusion: non-genesis entry (chain_position=1) → fetchPrevCommittedHash queries the DB;
            // the canonical_payload_hash of the already-committed row at chain_position=0 is used as previousHash
            const prevCommittedHash =
                'abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890';

            const pool = createMockPool(
                [
                    // pool.query #1: pre-check — union_total=1
                    {
                        rows: [
                            {
                                null_jcs_count: '1',
                                v01_count: '1',
                                union_total: '1',
                            },
                        ],
                    },
                    // pool.query #2: listMigrationChains — 1 chain partition
                    {
                        rows: [
                            {
                                chain_namespace: 'policy',
                                tenant_id: null,
                                audit_class: null,
                            },
                        ],
                    },
                    // pool.query #3: selectNextBatch — 1 entry (chain_position=1)
                    {
                        rows: [
                            {
                                entry_id: 'entry-uuid-2',
                                canonical_payload:
                                    '{"action":"approve","timestamp":1700000001}',
                                canonical_payload_hash: 'old-hash-v01-pos1',
                                previous_hash: 'old-prev-hash-pos0',
                                chain_position: 1,
                                chain_namespace: 'policy',
                                tenant_id: null,
                                audit_class: null,
                            },
                        ],
                    },
                    // pool.query #4: selectNextBatch (second call) — empty
                    { rows: [] },
                ],
                [
                    // client.query #1: BEGIN
                    { rows: [] },
                    // client.query #2: fetchPrevCommittedHash
                    // chain_position=1 → query the row at chain_position=0
                    {
                        rows: [
                            {
                                canonical_payload_hash: prevCommittedHash,
                                hcc_version: '2.0.0', // previous entry already committed
                            },
                        ],
                    },
                    // client.query #3: UPDATE entry-uuid-2
                    { rows: [], rowCount: 1 },
                    // client.query #4: COMMIT
                    { rows: [] },
                ],
            );

            const progress = await migrateHccV01ToV02(pool, { dryRun: false });

            expect(progress.entriesProcessed).toBe(1);
            expect(progress.entriesFailed).toBe(0);

            // Verify fetchPrevCommittedHash queried the DB (client.query at least 4 times: BEGIN + fetchPrev + UPDATE + COMMIT)
            const mockClient = await (pool.connect as MockedFunction<Pool['connect']>)();
            const clientQuery = mockClient.query as MockedFunction<PoolClient['query']>;
            // fetchPrevCommittedHash's SELECT call — verify IS NOT DISTINCT FROM + chain_position param
            const selectCall = clientQuery.mock.calls.find(
                (call) =>
                    typeof call[0] === 'string' &&
                    (call[0] as string).includes(
                        'IS NOT DISTINCT FROM',
                    ),
            );
            expect(selectCall).toBeDefined();

            // The UPDATE call's previous_hash param = prevCommittedHash
            const updateCall = clientQuery.mock.calls.find(
                (call) =>
                    typeof call[0] === 'string' &&
                    (call[0] as string).includes('UPDATE hash_chain_entries'),
            );
            const updateParams = updateCall?.[1] as string[];
            expect(updateParams?.[2]).toBe(prevCommittedHash);
        });

        it('should fail-closed when fetchPrevCommittedHash finds hcc_version != 2.0.0', async () => {
            // Conclusion: previous entry hcc_version != '2.0.0' → fail-closed throw
            // (the previous batch is not committed; the previousHash chained recompute cannot be sustained)
            const pool = createMockPool(
                [
                    // pool.query #1: pre-check
                    {
                        rows: [
                            {
                                null_jcs_count: '1',
                                v01_count: '1',
                                union_total: '1',
                            },
                        ],
                    },
                    // pool.query #2: listMigrationChains
                    {
                        rows: [
                            {
                                chain_namespace: 'atp',
                                tenant_id: 'tenant-2',
                                audit_class: 'L2',
                            },
                        ],
                    },
                    // pool.query #3: selectNextBatch — chain_position=1
                    {
                        rows: [
                            {
                                entry_id: 'entry-uuid-3',
                                canonical_payload: '{"action":"reject"}',
                                canonical_payload_hash: 'old-hash',
                                previous_hash: 'old-prev',
                                chain_position: 1,
                                chain_namespace: 'atp',
                                tenant_id: 'tenant-2',
                                audit_class: 'L2',
                            },
                        ],
                    },
                ],
                [
                    // client.query #1: BEGIN
                    { rows: [] },
                    // client.query #2: fetchPrevCommittedHash — hcc_version is still '1.0.0'
                    {
                        rows: [
                            {
                                canonical_payload_hash: 'some-hash',
                                hcc_version: '1.0.0', // not committed → fail-closed
                            },
                        ],
                    },
                    // client.query #3: ROLLBACK (called after the processBatch catch)
                    { rows: [] },
                ],
            );

            // processBatchWithRetry retryPerBatch=1 → only 1 attempt → throw
            await expect(
                migrateHccV01ToV02(pool, {
                    retryPerBatch: 1,
                }),
            ).rejects.toThrow('previousHash anchor in inconsistent state');
        });
    });

    // ─── Case 4: dry-run mode → no UPDATE, no COMMIT ─────────────────────────

    describe('Case 4: --dry-run mode → no UPDATE, no COMMIT', () => {
        it('should not call UPDATE or COMMIT in dry-run mode', async () => {
            // Conclusion: dryRun=true → processBatch does not call BEGIN/COMMIT/UPDATE;
            // batchesCommitted=0; entriesProcessed still counts (diff log still emitted)
            const pool = createMockPool(
                [
                    // pool.query #1: pre-check
                    {
                        rows: [
                            {
                                null_jcs_count: '1',
                                v01_count: '1',
                                union_total: '1',
                            },
                        ],
                    },
                    // pool.query #2: listMigrationChains
                    {
                        rows: [
                            {
                                chain_namespace: 'atp',
                                tenant_id: 'tenant-dry',
                                audit_class: 'L3',
                            },
                        ],
                    },
                    // pool.query #3: selectNextBatch — 1 genesis entry
                    {
                        rows: [
                            {
                                entry_id: 'entry-dry-1',
                                canonical_payload:
                                    '{"action":"audit","class":"L3"}',
                                canonical_payload_hash: 'old-hash-dry',
                                previous_hash:
                                    '0000000000000000000000000000000000000000000000000000000000000000',
                                chain_position: 0,
                                chain_namespace: 'atp',
                                tenant_id: 'tenant-dry',
                                audit_class: 'L3',
                            },
                        ],
                    },
                    // pool.query #4: selectNextBatch second call — empty
                    { rows: [] },
                ],
                // In dry-run mode, client.query does not call BEGIN/UPDATE/COMMIT
                [],
            );

            const progress = await migrateHccV01ToV02(pool, { dryRun: true });

            // dry-run: entriesProcessed=1 (counted); batchesCommitted=0 (no commit)
            expect(progress.entriesProcessed).toBe(1);
            expect(progress.batchesCommitted).toBe(0);

            // In dry-run, pool.connect() is still called (to obtain a client for the genesis check),
            // but client.query is only used for fetchPrevCommittedHash's SELECT (which does not query the DB for genesis),
            // so client.query contains no BEGIN / UPDATE / COMMIT calls
            const mockClient = await (pool.connect as MockedFunction<Pool['connect']>)();
            const clientQuery = mockClient.query as MockedFunction<PoolClient['query']>;
            const allClientCalls = clientQuery.mock.calls.map((c) => c[0]);

            // Strict verification: no BEGIN; no UPDATE; no COMMIT (dry-run guard)
            expect(allClientCalls).not.toContain('BEGIN');
            expect(allClientCalls).not.toContain('COMMIT');
            expect(
                allClientCalls.every(
                    (q) =>
                        typeof q !== 'string' ||
                        !q.includes('UPDATE hash_chain_entries'),
                ),
            ).toBe(true);
        });
    });

    // ─── Case 5: multi-tenant chain isolation ───────────────────────────────

    describe('Case 5: multi-tenant chain isolation — each chain keeps its own previousHash anchor', () => {
        it('should process chains independently without crossing previousHash anchors', async () => {
            // Conclusion: listMigrationChains returns 2 chain partitions;
            // each chain runs selectNextBatch independently; previousHash anchors do not cross between chains
            const pool = createMockPool(
                [
                    // pool.query #1: pre-check
                    {
                        rows: [
                            {
                                null_jcs_count: '2',
                                v01_count: '2',
                                union_total: '2',
                            },
                        ],
                    },
                    // pool.query #2: listMigrationChains — 2 chain partitions
                    {
                        rows: [
                            {
                                chain_namespace: 'atp',
                                tenant_id: 'tenant-A',
                                audit_class: 'L1',
                            },
                            {
                                chain_namespace: 'atp',
                                tenant_id: 'tenant-B',
                                audit_class: 'L1',
                            },
                        ],
                    },
                    // pool.query #3: selectNextBatch (chain A, first call) — 1 genesis entry
                    {
                        rows: [
                            {
                                entry_id: 'entry-A-1',
                                canonical_payload: '{"chain":"A"}',
                                canonical_payload_hash: 'hash-A-old',
                                previous_hash:
                                    '0000000000000000000000000000000000000000000000000000000000000000',
                                chain_position: 0,
                                chain_namespace: 'atp',
                                tenant_id: 'tenant-A',
                                audit_class: 'L1',
                            },
                        ],
                    },
                    // pool.query #4: selectNextBatch (chain A, second call) — empty
                    { rows: [] },
                    // pool.query #5: selectNextBatch (chain B, first call) — 1 genesis entry
                    {
                        rows: [
                            {
                                entry_id: 'entry-B-1',
                                canonical_payload: '{"chain":"B"}',
                                canonical_payload_hash: 'hash-B-old',
                                previous_hash:
                                    '0000000000000000000000000000000000000000000000000000000000000000',
                                chain_position: 0,
                                chain_namespace: 'atp',
                                tenant_id: 'tenant-B',
                                audit_class: 'L1',
                            },
                        ],
                    },
                    // pool.query #6: selectNextBatch (chain B, second call) — empty
                    { rows: [] },
                ],
                [
                    // client A: BEGIN, UPDATE, COMMIT
                    { rows: [] }, // BEGIN
                    { rows: [], rowCount: 1 }, // UPDATE entry-A-1
                    { rows: [] }, // COMMIT
                    // client B: BEGIN, UPDATE, COMMIT (the same mock client is reused)
                    { rows: [] }, // BEGIN
                    { rows: [], rowCount: 1 }, // UPDATE entry-B-1
                    { rows: [] }, // COMMIT
                ],
            );

            const progress = await migrateHccV01ToV02(pool, { dryRun: false });

            // Each of the two chains processes 1 entry
            expect(progress.entriesProcessed).toBe(2);
            expect(progress.batchesCommitted).toBe(2);
            expect(progress.entriesFailed).toBe(0);

            // selectNextBatch IS NOT DISTINCT FROM call: tenant_id uses the corresponding tenant value
            const poolQuery = pool.query as MockedFunction<Pool['query']>;
            // pool.query #3 (selectNextBatch chain A) — params[1] = 'tenant-A'
            const selectChainACall = poolQuery.mock.calls[2];
            const paramsA = selectChainACall?.[1] as string[];
            expect(paramsA?.[1]).toBe('tenant-A');

            // pool.query #5 (selectNextBatch chain B) — params[1] = 'tenant-B'
            const selectChainBCall = poolQuery.mock.calls[4];
            const paramsB = selectChainBCall?.[1] as string[];
            expect(paramsB?.[1]).toBe('tenant-B');
        });
    });

    // ─── Case 6: retry + crash recovery ──────────────────────────────────────

    describe('Case 6: retry + crash recovery — processBatchWithRetry exponential backoff', () => {
        it('should retry on transient failure and succeed on second attempt', async () => {
            // Conclusion: processBatch throws on the first attempt (transient error); retry succeeds on the second attempt.
            // Idempotent — on retry, the WHERE (hcc_version='1.0.0' OR chain_identity_jcs IS NULL) automatically filters out already-committed entries
            let batchCallCount = 0;

            const pool = createMockPool(
                [
                    // pool.query #1: pre-check
                    {
                        rows: [
                            {
                                null_jcs_count: '1',
                                v01_count: '1',
                                union_total: '1',
                            },
                        ],
                    },
                    // pool.query #2: listMigrationChains
                    {
                        rows: [
                            {
                                chain_namespace: 'atp',
                                tenant_id: 'tenant-retry',
                                audit_class: 'L1',
                            },
                        ],
                    },
                    // pool.query #3: selectNextBatch — 1 genesis entry
                    {
                        rows: [
                            {
                                entry_id: 'entry-retry-1',
                                canonical_payload: '{"action":"retry_test"}',
                                canonical_payload_hash: 'old-hash-retry',
                                previous_hash:
                                    '0000000000000000000000000000000000000000000000000000000000000000',
                                chain_position: 0,
                                chain_namespace: 'atp',
                                tenant_id: 'tenant-retry',
                                audit_class: 'L1',
                            },
                        ],
                    },
                    // pool.query #4: selectNextBatch second call — empty
                    { rows: [] },
                ],
                [
                    // First attempt: BEGIN → throw deadlock (the mock client's 2nd query throws)
                    { rows: [] }, // BEGIN (attempt 1)
                    // 2nd client.query: simulate a deadlock error — handled specially via the mock
                    // 3rd: ROLLBACK (processBatch catch)
                    { rows: [] }, // ROLLBACK (attempt 1)
                    // Second attempt: BEGIN → UPDATE → COMMIT (success)
                    { rows: [] }, // BEGIN (attempt 2)
                    { rows: [], rowCount: 1 }, // UPDATE
                    { rows: [] }, // COMMIT
                ],
            );

            // Special handling: the first pool.connect call returns a failing client; the second returns a successful client.
            // Sequenced mock pool.connect returns
            let connectCallCount = 0;
            const failClient: PoolClient = {
                query: vi
                    .fn()
                    .mockImplementationOnce(async () => ({ rows: [] })) // BEGIN
                    .mockImplementationOnce(async () => {
                        throw new Error('deadlock detected on test');
                    }) // deadlock on first query after BEGIN
                    .mockImplementationOnce(async () => ({ rows: [] })), // ROLLBACK
                release: vi.fn(),
            } as unknown as PoolClient;

            const successClient: PoolClient = {
                query: vi
                    .fn()
                    .mockImplementationOnce(async () => ({ rows: [] })) // BEGIN
                    .mockImplementationOnce(async () => ({ rows: [], rowCount: 1 })) // UPDATE
                    .mockImplementationOnce(async () => ({ rows: [] })), // COMMIT
                release: vi.fn(),
            } as unknown as PoolClient;

            (pool.connect as MockedFunction<Pool['connect']>)
                .mockResolvedValueOnce(failClient)
                .mockResolvedValueOnce(successClient);

            // retryPerBatch=2 → first attempt fails; second attempt succeeds
            const progress = await migrateHccV01ToV02(pool, {
                dryRun: false,
                retryPerBatch: 2,
            });

            expect(progress.entriesProcessed).toBe(1);
            expect(progress.batchesCommitted).toBe(1);
            expect(progress.entriesFailed).toBe(0);

            // connect is called twice (first fails; second succeeds)
            expect(
                (pool.connect as MockedFunction<Pool['connect']>).mock.calls,
            ).toHaveLength(2);
        });

        it('should throw after exhausting all retries', async () => {
            // Conclusion: all retryPerBatch attempts fail → throw Error (do not swallow the error)
            const pool = createMockPool(
                [
                    // pool.query #1: pre-check
                    {
                        rows: [
                            {
                                null_jcs_count: '1',
                                v01_count: '1',
                                union_total: '1',
                            },
                        ],
                    },
                    // pool.query #2: listMigrationChains
                    {
                        rows: [
                            {
                                chain_namespace: 'atp',
                                tenant_id: 'tenant-exhaust',
                                audit_class: 'L1',
                            },
                        ],
                    },
                    // pool.query #3: selectNextBatch — 1 entry
                    {
                        rows: [
                            {
                                entry_id: 'entry-exhaust-1',
                                canonical_payload: '{"action":"exhaust"}',
                                canonical_payload_hash: 'old-hash-exhaust',
                                previous_hash:
                                    '0000000000000000000000000000000000000000000000000000000000000000',
                                chain_position: 0,
                                chain_namespace: 'atp',
                                tenant_id: 'tenant-exhaust',
                                audit_class: 'L1',
                            },
                        ],
                    },
                ],
                [],
            );

            // Every connect returns a client that always fails
            const alwaysFailClient: PoolClient = {
                query: vi
                    .fn()
                    .mockImplementationOnce(async () => ({ rows: [] })) // BEGIN
                    .mockImplementationOnce(async () => {
                        throw new Error('ECONNREFUSED connection always fails');
                    })
                    .mockImplementationOnce(async () => ({ rows: [] })) // ROLLBACK
                    .mockImplementationOnce(async () => ({ rows: [] })) // BEGIN attempt 2
                    .mockImplementationOnce(async () => {
                        throw new Error('ECONNREFUSED connection always fails');
                    })
                    .mockImplementationOnce(async () => ({ rows: [] })), // ROLLBACK attempt 2
                release: vi.fn(),
            } as unknown as PoolClient;

            (pool.connect as MockedFunction<Pool['connect']>).mockResolvedValue(
                alwaysFailClient,
            );

            await expect(
                migrateHccV01ToV02(pool, {
                    retryPerBatch: 2,
                }),
            ).rejects.toThrow('ECONNREFUSED');
        });
    });
});
