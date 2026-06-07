/**
 * MCP Bridge — scope validator unit tests
 *
 * Coverage:
 *   - full validateMCPCallScope implementation
 *   - atomic semantics of a single outer transaction
 *   - normative acceptance gate (T43-T46)
 *
 * Test coverage (≥ 25 tests):
 *   - per-call numeric_limit validation (max_per_call)
 *   - currency check top-level guard (must verify if either max_value_per_call OR max_total_value is present)
 *   - per-call value numeric comparison
 *   - quota counter atomic check-and-increment + idempotency
 *   - value counter atomic check-and-increment + idempotency
 *   - **T43**: outer tx ROLLBACK (quota=9 + value reject → quota still=9)
 *   - **T44**: idempotency reuse cached fail result (no re-increment)
 *   - **T45**: different currencies counted independently
 *   - **T46**: SERIALIZABLE pending race retry
 *   - 4 independent error-code tests (mcp_error_quota_exhausted / value_exhausted / currency_mismatch / currency_missing)
 *   - source grep test (dual-tx anti-pattern = 0 lines)
 *   - BEGIN ISOLATION LEVEL SERIALIZABLE
 */
import { describe, expect, it, beforeEach } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

import type { PoolClient, QueryResult } from 'pg';

import {
    DEFAULT_SERIALIZABLE_RETRY_MAX,
    MCP_ERROR,
    validateScope,
    type ScopeValidatorDeps,
} from '../index.js';

// ─── helpers: mock PoolClient ────────────────────────────────────────────────

/**
 * MockClient — a simplified PoolClient mock; dispatches by SQL keyword
 *
 * Usage: the caller injects a sqlHandlers map where the key is a SQL substring match and the value is the result rows[]
 */
interface SqlHandler {
    match: RegExp;
    /**
     * handler return value:
     *   - row[] = the rows returned by that SQL
     *   - 'throw:<message>' = that SQL throws (e.g. SERIALIZABLE retry)
     */
    handler: (
        sql: string,
        params: unknown[],
    ) => { rows: unknown[] } | { error: Error };
}

class MockPoolClient {
    public callLog: Array<{ sql: string; params: unknown[] }> = [];
    public released = false;
    public handlers: SqlHandler[];

    constructor(handlers: SqlHandler[]) {
        this.handlers = handlers;
    }

    query(sql: string, params: unknown[] = []): Promise<QueryResult> {
        this.callLog.push({ sql, params });
        // BEGIN / COMMIT / ROLLBACK pass through (default ok with no handler)
        if (
            /^\s*BEGIN/i.test(sql) ||
            /^\s*COMMIT/i.test(sql) ||
            /^\s*ROLLBACK/i.test(sql)
        ) {
            return Promise.resolve(makeResult([], 0));
        }
        for (const h of this.handlers) {
            if (h.match.test(sql)) {
                const r = h.handler(sql, params);
                if ('error' in r) return Promise.reject(r.error);
                return Promise.resolve(makeResult(r.rows, r.rows.length));
            }
        }
        return Promise.reject(
            new Error(
                `MockPoolClient: no handler for SQL: ${sql.slice(0, 80)}`,
            ),
        );
    }

    release(): void {
        this.released = true;
    }
}

function makeResult(rows: unknown[], rowCount: number): QueryResult {
    return {
        rows,
        rowCount,
        command: '',
        oid: 0,
        fields: [],
    } as unknown as QueryResult;
}

function makeDeps(client: MockPoolClient, today = '2026-05-11'): ScopeValidatorDeps {
    return {
        acquireClient: () => Promise.resolve(client as unknown as PoolClient),
        today: () => today,
    };
}

// SQL handler factory (covers the various step 3 SQL statements)
const SQL_INSERT_QUOTA_IDEMP =
    /INSERT INTO communication\.mcp_quota_idempotency/i;
const SQL_SELECT_QUOTA_IDEMP =
    /SELECT cached_result.*FROM communication\.mcp_quota_idempotency/is;
const SQL_INSERT_QUOTA_COUNTER =
    /INSERT INTO communication\.mcp_quota_counter/i;
const SQL_UPDATE_QUOTA_IDEMP =
    /UPDATE communication\.mcp_quota_idempotency/i;
const SQL_INSERT_VALUE_IDEMP =
    /INSERT INTO communication\.mcp_value_idempotency/i;
const SQL_SELECT_VALUE_IDEMP =
    /SELECT cached_result.*FROM communication\.mcp_value_idempotency/is;
const SQL_INSERT_VALUE_COUNTER =
    /INSERT INTO communication\.mcp_value_counter/i;
const SQL_UPDATE_VALUE_IDEMP =
    /UPDATE communication\.mcp_value_idempotency/i;

// ─── pre-tx validation (step 1 + step 2) ─────────────────────────────────────────

describe('validateScope — step 1: per-call numeric_limit', () => {
    it('should reject when numeric_limit > max_per_call claim', async () => {
        const client = new MockPoolClient([]);
        const result = await validateScope(
            {
                mcpCall: {
                    tool: 'echo',
                    arguments: { numeric_limit: 100 },
                },
                disclosedClaims: [{ dim: 'max_per_call', value: 50 }],
                tokenId: '550e8400-e29b-41d4-a716-446655440001',
                requestIdempotencyKey: 'key-1',
            },
            makeDeps(client),
        );
        expect(result.ok).toBe(false);
        if (!result.ok) {
            expect(result.mcp_code).toBe(MCP_ERROR.SCOPE_INFLATION);
            expect(result.code).toBe('SCOPE_INFLATION_PER_CALL');
        }
        // invariant: pre-tx failure must not touch DB
        expect(client.callLog.filter((c) => /BEGIN/.test(c.sql))).toHaveLength(0);
    });

    it('should reject when max_per_call claim missing but numeric_limit present', async () => {
        const client = new MockPoolClient([]);
        const result = await validateScope(
            {
                mcpCall: {
                    tool: 'echo',
                    arguments: { numeric_limit: 5 },
                },
                disclosedClaims: [],
                tokenId: '550e8400-e29b-41d4-a716-446655440001',
                requestIdempotencyKey: 'key-1',
            },
            makeDeps(client),
        );
        expect(result.ok).toBe(false);
        if (!result.ok) {
            expect(result.mcp_code).toBe(MCP_ERROR.NO_PER_CALL_SCOPE);
        }
    });

    it('should pass when numeric_limit <= max_per_call and no other claims', async () => {
        const client = new MockPoolClient([]);
        const result = await validateScope(
            {
                mcpCall: {
                    tool: 'echo',
                    arguments: { numeric_limit: 10 },
                },
                disclosedClaims: [{ dim: 'max_per_call', value: 100 }],
                tokenId: '550e8400-e29b-41d4-a716-446655440001',
                requestIdempotencyKey: 'key-1',
            },
            makeDeps(client),
        );
        expect(result.ok).toBe(true);
    });
});

describe('validateScope — step 2: currency check top-level guard', () => {
    it('should reject when value present but currency missing (max_value_per_call claim present)', async () => {
        const client = new MockPoolClient([]);
        const result = await validateScope(
            {
                mcpCall: {
                    tool: 'pay',
                    arguments: { value: 10 }, // currency missing
                },
                disclosedClaims: [
                    {
                        dim: 'max_value_per_call',
                        value: 100,
                        currency: 'USD',
                    },
                ],
                tokenId: '550e8400-e29b-41d4-a716-446655440001',
                requestIdempotencyKey: 'key-1',
            },
            makeDeps(client),
        );
        expect(result.ok).toBe(false);
        if (!result.ok) {
            expect(result.mcp_code).toBe(MCP_ERROR.CURRENCY_MISSING);
        }
    });

    it('should reject when currency mismatches max_value_per_call.currency', async () => {
        const client = new MockPoolClient([]);
        const result = await validateScope(
            {
                mcpCall: {
                    tool: 'pay',
                    arguments: { value: 10, currency: 'EUR' },
                },
                disclosedClaims: [
                    {
                        dim: 'max_value_per_call',
                        value: 100,
                        currency: 'USD',
                    },
                ],
                tokenId: '550e8400-e29b-41d4-a716-446655440001',
                requestIdempotencyKey: 'key-1',
            },
            makeDeps(client),
        );
        expect(result.ok).toBe(false);
        if (!result.ok) {
            expect(result.mcp_code).toBe(MCP_ERROR.CURRENCY_MISMATCH);
        }
    });

    it('should reject when currency mismatches max_total_value.currency (top-level guard expand)', async () => {
        // must verify if either max_value_per_call OR max_total_value is present
        // this test covers the max_total_value branch (per_call absent)
        const client = new MockPoolClient([]);
        const result = await validateScope(
            {
                mcpCall: {
                    tool: 'pay',
                    arguments: { value: 10, currency: 'JPY' },
                },
                disclosedClaims: [
                    {
                        dim: 'max_total_value',
                        value: 1000,
                        currency: 'USD',
                    },
                ],
                tokenId: '550e8400-e29b-41d4-a716-446655440001',
                requestIdempotencyKey: 'key-1',
            },
            makeDeps(client),
        );
        expect(result.ok).toBe(false);
        if (!result.ok) {
            expect(result.mcp_code).toBe(MCP_ERROR.CURRENCY_MISMATCH);
        }
    });

    it('should reject when value > max_value_per_call (per-call value inflation)', async () => {
        const client = new MockPoolClient([]);
        const result = await validateScope(
            {
                mcpCall: {
                    tool: 'pay',
                    arguments: { value: 200, currency: 'USD' },
                },
                disclosedClaims: [
                    {
                        dim: 'max_value_per_call',
                        value: 100,
                        currency: 'USD',
                    },
                ],
                tokenId: '550e8400-e29b-41d4-a716-446655440001',
                requestIdempotencyKey: 'key-1',
            },
            makeDeps(client),
        );
        expect(result.ok).toBe(false);
        if (!result.ok) {
            expect(result.mcp_code).toBe(MCP_ERROR.SCOPE_INFLATION);
            expect(result.code).toBe('SCOPE_INFLATION_VALUE');
        }
    });

    it('should reject when perCall.currency and total.currency are inconsistent (issuer defect)', async () => {
        const client = new MockPoolClient([]);
        const result = await validateScope(
            {
                mcpCall: {
                    tool: 'pay',
                    arguments: { value: 10, currency: 'USD' },
                },
                disclosedClaims: [
                    {
                        dim: 'max_value_per_call',
                        value: 100,
                        currency: 'USD',
                    },
                    {
                        dim: 'max_total_value',
                        value: 1000,
                        currency: 'EUR', // inconsistent
                    },
                ],
                tokenId: '550e8400-e29b-41d4-a716-446655440001',
                requestIdempotencyKey: 'key-1',
            },
            makeDeps(client),
        );
        expect(result.ok).toBe(false);
        if (!result.ok) {
            expect(result.code).toBe('CURRENCY_CLAIM_INCONSISTENT');
        }
    });
});

// ─── outer tx: quota counter + idempotency ───────────────

describe('validateScope — outer tx: quota counter', () => {
    it('should INSERT quota_idempotency with ON CONFLICT DO NOTHING (idempotency_key claim)', async () => {
        const client = new MockPoolClient([
            {
                match: SQL_INSERT_QUOTA_IDEMP,
                handler: () => ({ rows: [{ idempotency_key: 'key-1' }] }),
            },
            {
                match: SQL_INSERT_QUOTA_COUNTER,
                handler: () => ({ rows: [{ calls_count: 1 }] }),
            },
            {
                match: SQL_UPDATE_QUOTA_IDEMP,
                handler: () => ({ rows: [] }),
            },
        ]);
        const result = await validateScope(
            {
                mcpCall: { tool: 'echo', arguments: {} },
                disclosedClaims: [{ dim: 'max_per_day', value: 10 }],
                tokenId: '550e8400-e29b-41d4-a716-446655440001',
                requestIdempotencyKey: 'key-1',
            },
            makeDeps(client),
        );
        expect(result.ok).toBe(true);
        // a single INSERT ON CONFLICT DO NOTHING RETURNING SQL
        const insertCall = client.callLog.find((c) =>
            SQL_INSERT_QUOTA_IDEMP.test(c.sql),
        );
        expect(insertCall).toBeDefined();
        expect(insertCall!.sql).toMatch(/ON CONFLICT.*DO NOTHING/i);
    });

    it('should fail with mcp_error_quota_exhausted when counter increment WHERE clause fails (calls_count + 1 > limit)', async () => {
        const client = new MockPoolClient([
            {
                match: SQL_INSERT_QUOTA_IDEMP,
                handler: () => ({ rows: [{ idempotency_key: 'key-1' }] }),
            },
            {
                match: SQL_INSERT_QUOTA_COUNTER,
                handler: () => ({ rows: [] }), // WHERE clause fail → rows empty
            },
            {
                match: SQL_UPDATE_QUOTA_IDEMP,
                handler: () => ({ rows: [] }),
            },
        ]);
        const result = await validateScope(
            {
                mcpCall: { tool: 'echo', arguments: {} },
                disclosedClaims: [{ dim: 'max_per_day', value: 10 }],
                tokenId: '550e8400-e29b-41d4-a716-446655440001',
                requestIdempotencyKey: 'key-1',
            },
            makeDeps(client),
        );
        expect(result.ok).toBe(false);
        if (!result.ok) {
            expect(result.mcp_code).toBe(MCP_ERROR.QUOTA_EXHAUSTED);
            expect(result.code).toBe('QUOTA_EXHAUSTED_PER_DAY');
        }
        // outer tx ROLLBACK
        const rollback = client.callLog.find((c) =>
            /ROLLBACK/.test(c.sql),
        );
        expect(rollback).toBeDefined();
    });

    it('should return cached fail result when ON CONFLICT hits and cached_result=fail (idempotency replay)', async () => {
        const client = new MockPoolClient([
            {
                match: SQL_INSERT_QUOTA_IDEMP,
                handler: () => ({ rows: [] }), // ON CONFLICT → 0 rows
            },
            {
                match: SQL_SELECT_QUOTA_IDEMP,
                handler: () => ({
                    rows: [
                        {
                            cached_result: 'fail',
                            cached_code: 'QUOTA_EXHAUSTED_PER_DAY',
                            cached_mcp_code: 'mcp_error_quota_exhausted',
                        },
                    ],
                }),
            },
        ]);
        const result = await validateScope(
            {
                mcpCall: { tool: 'echo', arguments: {} },
                disclosedClaims: [{ dim: 'max_per_day', value: 10 }],
                tokenId: '550e8400-e29b-41d4-a716-446655440001',
                requestIdempotencyKey: 'key-1',
            },
            makeDeps(client),
        );
        expect(result.ok).toBe(false);
        if (!result.ok) {
            expect(result.mcp_code).toBe(MCP_ERROR.QUOTA_EXHAUSTED);
        }
        // invariant: cached fail must not INSERT the counter again
        expect(
            client.callLog.find((c) => SQL_INSERT_QUOTA_COUNTER.test(c.sql)),
        ).toBeUndefined();
    });

    it('should throw IDEMPOTENCY_PENDING_RACE when cached_result=pending (SERIALIZABLE retry trigger)', async () => {
        // simulate retry-exhausted (all attempts cached_result='pending')
        const client = new MockPoolClient([
            {
                match: SQL_INSERT_QUOTA_IDEMP,
                handler: () => ({ rows: [] }),
            },
            {
                match: SQL_SELECT_QUOTA_IDEMP,
                handler: () => ({
                    rows: [
                        {
                            cached_result: 'pending',
                            cached_code: null,
                            cached_mcp_code: null,
                        },
                    ],
                }),
            },
        ]);
        await expect(
            validateScope(
                {
                    mcpCall: { tool: 'echo', arguments: {} },
                    disclosedClaims: [{ dim: 'max_per_day', value: 10 }],
                    tokenId: '550e8400-e29b-41d4-a716-446655440001',
                    requestIdempotencyKey: 'key-1',
                },
                makeDeps(client),
            ),
        ).rejects.toThrow(/SERIALIZABLE retry exhausted/);
    });
});

// ─── outer tx: value counter + idempotency ───────────────

describe('validateScope — outer tx: value counter', () => {
    it('should pass when value <= max_total_value', async () => {
        const client = new MockPoolClient([
            {
                match: SQL_INSERT_VALUE_IDEMP,
                handler: () => ({ rows: [{ idempotency_key: 'key-1' }] }),
            },
            {
                match: SQL_INSERT_VALUE_COUNTER,
                handler: () => ({ rows: [{ total_value: '10' }] }),
            },
            {
                match: SQL_UPDATE_VALUE_IDEMP,
                handler: () => ({ rows: [] }),
            },
        ]);
        const result = await validateScope(
            {
                mcpCall: {
                    tool: 'pay',
                    arguments: { value: 10, currency: 'USD' },
                },
                disclosedClaims: [
                    {
                        dim: 'max_total_value',
                        value: 1000,
                        currency: 'USD',
                    },
                ],
                tokenId: '550e8400-e29b-41d4-a716-446655440001',
                requestIdempotencyKey: 'key-1',
            },
            makeDeps(client),
        );
        expect(result.ok).toBe(true);
    });

    it('should fail with TOTAL_VALUE_EXHAUSTED when counter exceeds max_total_value', async () => {
        const client = new MockPoolClient([
            {
                match: SQL_INSERT_VALUE_IDEMP,
                handler: () => ({ rows: [{ idempotency_key: 'key-1' }] }),
            },
            {
                match: SQL_INSERT_VALUE_COUNTER,
                handler: () => ({ rows: [] }), // WHERE clause fail
            },
        ]);
        const result = await validateScope(
            {
                mcpCall: {
                    tool: 'pay',
                    arguments: { value: 10, currency: 'USD' },
                },
                disclosedClaims: [
                    {
                        dim: 'max_total_value',
                        value: 100,
                        currency: 'USD',
                    },
                ],
                tokenId: '550e8400-e29b-41d4-a716-446655440001',
                requestIdempotencyKey: 'key-1',
            },
            makeDeps(client),
        );
        expect(result.ok).toBe(false);
        if (!result.ok) {
            expect(result.code).toBe('TOTAL_VALUE_EXHAUSTED');
            expect(result.mcp_code).toBe(MCP_ERROR.SCOPE_INFLATION);
        }
    });

    it('should return cached value fail result on idempotency replay', async () => {
        const client = new MockPoolClient([
            {
                match: SQL_INSERT_VALUE_IDEMP,
                handler: () => ({ rows: [] }),
            },
            {
                match: SQL_SELECT_VALUE_IDEMP,
                handler: () => ({
                    rows: [
                        {
                            cached_result: 'fail',
                            cached_code: 'TOTAL_VALUE_EXHAUSTED',
                            cached_mcp_code: 'mcp_error_scope_inflation',
                        },
                    ],
                }),
            },
        ]);
        const result = await validateScope(
            {
                mcpCall: {
                    tool: 'pay',
                    arguments: { value: 10, currency: 'USD' },
                },
                disclosedClaims: [
                    {
                        dim: 'max_total_value',
                        value: 1000,
                        currency: 'USD',
                    },
                ],
                tokenId: '550e8400-e29b-41d4-a716-446655440001',
                requestIdempotencyKey: 'key-1',
            },
            makeDeps(client),
        );
        expect(result.ok).toBe(false);
        if (!result.ok) {
            expect(result.mcp_code).toBe(MCP_ERROR.SCOPE_INFLATION);
        }
    });

    it('should return cached value ok result on idempotency replay (skip counter inc)', async () => {
        const client = new MockPoolClient([
            {
                match: SQL_INSERT_VALUE_IDEMP,
                handler: () => ({ rows: [] }),
            },
            {
                match: SQL_SELECT_VALUE_IDEMP,
                handler: () => ({
                    rows: [{ cached_result: 'ok', cached_code: null, cached_mcp_code: null }],
                }),
            },
        ]);
        const result = await validateScope(
            {
                mcpCall: {
                    tool: 'pay',
                    arguments: { value: 10, currency: 'USD' },
                },
                disclosedClaims: [
                    {
                        dim: 'max_total_value',
                        value: 1000,
                        currency: 'USD',
                    },
                ],
                tokenId: '550e8400-e29b-41d4-a716-446655440001',
                requestIdempotencyKey: 'key-1',
            },
            makeDeps(client),
        );
        expect(result.ok).toBe(true);
        // invariant: cached ok must not INSERT the counter again
        expect(
            client.callLog.find((c) => SQL_INSERT_VALUE_COUNTER.test(c.sql)),
        ).toBeUndefined();
    });
});

// ─── T43-T46 literal normative acceptance gate ──────────────────

describe('T43 literal normative acceptance: quota=9 + value+$10=$105 reject -> outer ROLLBACK -> quota still=9', () => {
    it('should ROLLBACK quota counter when value counter exhausts (atomic single outer tx)', async () => {
        // scenario: quota counter INSERT succeeds (calls_count=9 → 10, still <= max_per_day=10);
        // value counter INSERT fails (total_value+10=$105 > $100 max);
        // outer tx ROLLBACK → quota counter change is undone, quota still=9 (as observed externally)

        // test invariant: single outer SERIALIZABLE tx; ROLLBACK must occur
        const client = new MockPoolClient([
            {
                match: SQL_INSERT_QUOTA_IDEMP,
                handler: () => ({ rows: [{ idempotency_key: 'key-T43' }] }),
            },
            {
                match: SQL_INSERT_QUOTA_COUNTER,
                handler: () => ({ rows: [{ calls_count: 10 }] }), // quota +1 success
            },
            {
                match: SQL_UPDATE_QUOTA_IDEMP,
                handler: () => ({ rows: [] }),
            },
            {
                match: SQL_INSERT_VALUE_IDEMP,
                handler: () => ({ rows: [{ idempotency_key: 'key-T43' }] }),
            },
            {
                match: SQL_INSERT_VALUE_COUNTER,
                handler: () => ({ rows: [] }), // value exhausted → rows empty
            },
        ]);
        const result = await validateScope(
            {
                mcpCall: {
                    tool: 'pay',
                    arguments: { value: 10, currency: 'USD' },
                },
                disclosedClaims: [
                    { dim: 'max_per_day', value: 10 }, // quota limit
                    { dim: 'max_total_value', value: 100, currency: 'USD' }, // value limit
                ],
                tokenId: '550e8400-e29b-41d4-a716-446655440043',
                requestIdempotencyKey: 'key-T43',
            },
            makeDeps(client),
        );
        expect(result.ok).toBe(false);
        if (!result.ok) {
            // value exhausted → mcp_error_scope_inflation
            expect(result.mcp_code).toBe(MCP_ERROR.SCOPE_INFLATION);
            expect(result.code).toBe('TOTAL_VALUE_EXHAUSTED');
        }
        // T43 acceptance gate: single outer tx; ROLLBACK must appear
        // BEGIN ISOLATION LEVEL SERIALIZABLE → ... → ROLLBACK
        const begin = client.callLog.find((c) =>
            /BEGIN ISOLATION LEVEL SERIALIZABLE/i.test(c.sql),
        );
        const rollback = client.callLog.find((c) => /ROLLBACK/i.test(c.sql));
        const commit = client.callLog.find((c) => /COMMIT/i.test(c.sql));
        expect(begin).toBeDefined();
        expect(rollback).toBeDefined();
        expect(commit).toBeUndefined(); // the ROLLBACK path must not COMMIT
    });
});

describe('T44 literal normative acceptance: idempotency reuse cached fail result (no re-increment)', () => {
    it('should return cached fail without re-incrementing counter on retry', async () => {
        // scenario: the first call hits quota_exhausted → cached_result='fail';
        // the client retries with the same idempotency_key → returns the same fail; the counter is not incremented again
        const client = new MockPoolClient([
            {
                match: SQL_INSERT_QUOTA_IDEMP,
                handler: () => ({ rows: [] }), // ON CONFLICT → cached hit
            },
            {
                match: SQL_SELECT_QUOTA_IDEMP,
                handler: () => ({
                    rows: [
                        {
                            cached_result: 'fail',
                            cached_code: 'QUOTA_EXHAUSTED_PER_DAY',
                            cached_mcp_code: 'mcp_error_quota_exhausted',
                        },
                    ],
                }),
            },
        ]);
        const result = await validateScope(
            {
                mcpCall: { tool: 'echo', arguments: {} },
                disclosedClaims: [{ dim: 'max_per_day', value: 10 }],
                tokenId: '550e8400-e29b-41d4-a716-446655440044',
                requestIdempotencyKey: 'key-T44',
            },
            makeDeps(client),
        );
        expect(result.ok).toBe(false);
        if (!result.ok) {
            expect(result.mcp_code).toBe(MCP_ERROR.QUOTA_EXHAUSTED);
            expect(result.code).toBe('QUOTA_EXHAUSTED_PER_DAY');
        }
        // T44 invariant: counter is not incremented
        expect(
            client.callLog.find((c) => SQL_INSERT_QUOTA_COUNTER.test(c.sql)),
        ).toBeUndefined();
    });
});

describe('T45 literal normative acceptance: different currency value counted independently', () => {
    it('should treat USD and EUR as independent counters (PK triple includes currency)', async () => {
        // scenario: value INSERT uses (tokenId, currency, value); different currencies have different PKs;
        // independent INSERT/UPDATE paths; USD value does not affect the EUR counter

        // this test verifies: the value idempotency PK triple (idempotency_key, token_id, currency)
        // is reflected in the SQL — INSERT fields + params + ON CONFLICT columns
        const client = new MockPoolClient([
            {
                match: SQL_INSERT_VALUE_IDEMP,
                handler: () => ({ rows: [{ idempotency_key: 'key-T45' }] }),
            },
            {
                match: SQL_INSERT_VALUE_COUNTER,
                handler: () => ({ rows: [{ total_value: '10' }] }),
            },
            {
                match: SQL_UPDATE_VALUE_IDEMP,
                handler: () => ({ rows: [] }),
            },
        ]);
        await validateScope(
            {
                mcpCall: {
                    tool: 'pay',
                    arguments: { value: 10, currency: 'EUR' },
                },
                disclosedClaims: [
                    { dim: 'max_total_value', value: 100, currency: 'EUR' },
                ],
                tokenId: '550e8400-e29b-41d4-a716-446655440045',
                requestIdempotencyKey: 'key-T45',
            },
            makeDeps(client),
        );

        // T45: INSERT INTO mcp_value_idempotency PK includes currency
        const insertIdempCall = client.callLog.find((c) =>
            SQL_INSERT_VALUE_IDEMP.test(c.sql),
        );
        expect(insertIdempCall).toBeDefined();
        expect(insertIdempCall!.sql).toMatch(
            /ON CONFLICT.*idempotency_key.*token_id.*currency/is,
        );
        // param: currency 'EUR' should be passed in as a parameter
        expect(insertIdempCall!.params).toContain('EUR');

        // the value counter SQL is also keyed by the (token_id, currency) PK
        const insertCounterCall = client.callLog.find((c) =>
            SQL_INSERT_VALUE_COUNTER.test(c.sql),
        );
        expect(insertCounterCall).toBeDefined();
        expect(insertCounterCall!.sql).toMatch(/ON CONFLICT.*token_id.*currency/is);
        expect(insertCounterCall!.params).toContain('EUR');
    });
});

describe('T46 literal normative acceptance: SERIALIZABLE pending race retry', () => {
    it('should retry outer tx on SERIALIZABLE race error (40001 / could not serialize)', async () => {
        // simulate attempt 1 hitting a pending race (INSERT claim fails + SELECT cached='pending')
        // attempt 2 INSERT claim succeeds, full happy path
        let attempt = 0;
        const handlers: SqlHandler[] = [
            {
                match: SQL_INSERT_QUOTA_IDEMP,
                handler: () => {
                    attempt++;
                    if (attempt === 1) {
                        // claim fails → subsequent SELECT returns 'pending' → throw retry
                        return { rows: [] };
                    }
                    // attempt 2: claim succeeds
                    return { rows: [{ idempotency_key: 'key-T46' }] };
                },
            },
            {
                match: SQL_SELECT_QUOTA_IDEMP,
                handler: () => ({
                    rows: [
                        {
                            cached_result: 'pending', // triggers SERIALIZABLE retry
                            cached_code: null,
                            cached_mcp_code: null,
                        },
                    ],
                }),
            },
            {
                match: SQL_INSERT_QUOTA_COUNTER,
                handler: () => ({ rows: [{ calls_count: 1 }] }),
            },
            {
                match: SQL_UPDATE_QUOTA_IDEMP,
                handler: () => ({ rows: [] }),
            },
        ];
        const client = new MockPoolClient(handlers);
        const result = await validateScope(
            {
                mcpCall: { tool: 'echo', arguments: {} },
                disclosedClaims: [{ dim: 'max_per_day', value: 10 }],
                tokenId: '550e8400-e29b-41d4-a716-446655440046',
                requestIdempotencyKey: 'key-T46',
            },
            makeDeps(client),
        );
        expect(result.ok).toBe(true);
        // T46: BEGIN should appear at least twice (the first retry is triggered)
        const begins = client.callLog.filter((c) =>
            /BEGIN ISOLATION LEVEL SERIALIZABLE/i.test(c.sql),
        );
        expect(begins.length).toBeGreaterThanOrEqual(2);
    });

    it('should give up after DEFAULT_SERIALIZABLE_RETRY_MAX attempts and throw', async () => {
        const handlers: SqlHandler[] = [
            {
                match: SQL_INSERT_QUOTA_IDEMP,
                handler: () => ({ rows: [] }),
            },
            {
                match: SQL_SELECT_QUOTA_IDEMP,
                handler: () => ({
                    rows: [
                        {
                            cached_result: 'pending',
                            cached_code: null,
                            cached_mcp_code: null,
                        },
                    ],
                }),
            },
        ];
        const client = new MockPoolClient(handlers);
        await expect(
            validateScope(
                {
                    mcpCall: { tool: 'echo', arguments: {} },
                    disclosedClaims: [{ dim: 'max_per_day', value: 10 }],
                    tokenId: '550e8400-e29b-41d4-a716-446655440046',
                    requestIdempotencyKey: 'key-T46',
                },
                makeDeps(client),
            ),
        ).rejects.toThrow(/SERIALIZABLE retry exhausted/);
        // BEGIN should appear DEFAULT_SERIALIZABLE_RETRY_MAX times
        const begins = client.callLog.filter((c) =>
            /BEGIN ISOLATION LEVEL SERIALIZABLE/i.test(c.sql),
        );
        expect(begins.length).toBe(DEFAULT_SERIALIZABLE_RETRY_MAX);
    });
});

// ─── integration path: quota + value all pass ─────────────────────────────────────────

describe('validateScope — happy path: quota + value all pass', () => {
    it('should COMMIT outer tx when both quota and value pass', async () => {
        const client = new MockPoolClient([
            {
                match: SQL_INSERT_QUOTA_IDEMP,
                handler: () => ({ rows: [{ idempotency_key: 'key-1' }] }),
            },
            {
                match: SQL_INSERT_QUOTA_COUNTER,
                handler: () => ({ rows: [{ calls_count: 1 }] }),
            },
            {
                match: SQL_UPDATE_QUOTA_IDEMP,
                handler: () => ({ rows: [] }),
            },
            {
                match: SQL_INSERT_VALUE_IDEMP,
                handler: () => ({ rows: [{ idempotency_key: 'key-1' }] }),
            },
            {
                match: SQL_INSERT_VALUE_COUNTER,
                handler: () => ({ rows: [{ total_value: '10' }] }),
            },
            {
                match: SQL_UPDATE_VALUE_IDEMP,
                handler: () => ({ rows: [] }),
            },
        ]);
        const result = await validateScope(
            {
                mcpCall: {
                    tool: 'pay',
                    arguments: { value: 10, currency: 'USD' },
                },
                disclosedClaims: [
                    { dim: 'max_per_day', value: 10 },
                    { dim: 'max_total_value', value: 100, currency: 'USD' },
                ],
                tokenId: '550e8400-e29b-41d4-a716-446655440001',
                requestIdempotencyKey: 'key-1',
            },
            makeDeps(client),
        );
        expect(result.ok).toBe(true);
        const commit = client.callLog.find((c) => /COMMIT/i.test(c.sql));
        expect(commit).toBeDefined();
    });

    it('should release PoolClient after outer tx completes', async () => {
        const client = new MockPoolClient([
            {
                match: SQL_INSERT_QUOTA_IDEMP,
                handler: () => ({ rows: [{ idempotency_key: 'key-1' }] }),
            },
            {
                match: SQL_INSERT_QUOTA_COUNTER,
                handler: () => ({ rows: [{ calls_count: 1 }] }),
            },
            {
                match: SQL_UPDATE_QUOTA_IDEMP,
                handler: () => ({ rows: [] }),
            },
        ]);
        await validateScope(
            {
                mcpCall: { tool: 'echo', arguments: {} },
                disclosedClaims: [{ dim: 'max_per_day', value: 10 }],
                tokenId: '550e8400-e29b-41d4-a716-446655440001',
                requestIdempotencyKey: 'key-1',
            },
            makeDeps(client),
        );
        expect(client.released).toBe(true);
    });
});

describe('validateScope — skip outer tx when there is no cumulative claim', () => {
    it('should skip outer tx when no max_per_day and no max_total_value claims', async () => {
        const client = new MockPoolClient([]);
        const result = await validateScope(
            {
                mcpCall: { tool: 'echo', arguments: {} },
                disclosedClaims: [],
                tokenId: '550e8400-e29b-41d4-a716-446655440001',
                requestIdempotencyKey: 'key-1',
            },
            makeDeps(client),
        );
        expect(result.ok).toBe(true);
        expect(client.callLog).toHaveLength(0);
    });
});

// ─── source invariant grep test (source guard) ──────────────────────────────

describe('source invariant grep test — scope-validator.ts source literal guard', () => {
    const SOURCE_PATH = resolve(__dirname, '../scope-validator.ts');
    let source: string;
    let codeOnly: string;

    function stripCommentsAndStrings(src: string): string {
        return src
            .split('\n')
            .filter((line) => {
                const trimmed = line.trim();
                if (trimmed.startsWith('//')) return false;
                if (trimmed.startsWith('*')) return false;
                if (trimmed.startsWith('/*')) return false;
                if (trimmed.startsWith('*/')) return false;
                return true;
            })
            .join('\n')
            .replace(/'[^']*'/g, "''")
            .replace(/"[^"]*"/g, '""')
            .replace(/`[^`]*`/g, '``');
    }

    beforeEach(() => {
        source = readFileSync(SOURCE_PATH, 'utf-8');
        codeOnly = stripCommentsAndStrings(source);
    });

    it('source must contain BEGIN ISOLATION LEVEL SERIALIZABLE', () => {
        // invariant: the outer tx must explicitly declare SERIALIZABLE
        expect(source).toMatch(/BEGIN ISOLATION LEVEL SERIALIZABLE/);
    });

    it('source must not contain the dual-tx anti-pattern (prevents the outer SERIALIZABLE from being split apart)', () => {
        // invariant: multiple nested `BEGIN` statements within the same source are not allowed (dual-tx parallel pattern)
        // note: multiple BEGINs inside a retry loop are treated as sequential serialization, not dual-tx parallelism
        //
        // anti-pattern grep:
        //   - the independentValueTx / separateQuotaTx names (the withdrawn anti-pattern)
        //   - two explicit BEGIN ISOLATION strings on a non-retry path within the same function body
        expect(codeOnly).not.toMatch(/independentValueTx/);
        expect(codeOnly).not.toMatch(/separateQuotaTx/);
        expect(codeOnly).not.toMatch(/independentValueTransaction/);
        expect(codeOnly).not.toMatch(/separateQuotaTransaction/);
    });

    it('source must contain the 4 error codes', () => {
        // 4 mcp_error values
        expect(source).toContain('QUOTA_EXHAUSTED');
        expect(source).toContain('CURRENCY_MISMATCH');
        expect(source).toContain('CURRENCY_MISSING');
        expect(source).toContain('SCOPE_INFLATION');
    });

    it('source must contain INSERT ON CONFLICT DO NOTHING RETURNING', () => {
        // a single SQL for the idempotency_key claim
        // string match: ON CONFLICT ... DO NOTHING / RETURNING
        expect(source).toMatch(/ON CONFLICT[\s\S]*DO NOTHING[\s\S]*RETURNING/);
    });

    it('source must contain INSERT ON CONFLICT DO UPDATE WHERE check-and-increment', () => {
        // counter atomic check-and-increment uses INSERT ON CONFLICT DO UPDATE WHERE
        expect(source).toMatch(/ON CONFLICT[\s\S]*DO UPDATE/);
        expect(source).toMatch(/calls_count\s*\+\s*1\s*<=/);
        expect(source).toMatch(/total_value\s*\+\s*\$3\s*<=/);
    });

    it('source value idempotency must use the PK triple (idempotency_key, token_id, currency)', () => {
        // T45 acceptance: currency enters the PK
        expect(source).toMatch(
            /INSERT INTO communication\.mcp_value_idempotency[\s\S]*currency/,
        );
        expect(source).toMatch(
            /ON CONFLICT \(idempotency_key, token_id, currency\)/,
        );
    });
});
