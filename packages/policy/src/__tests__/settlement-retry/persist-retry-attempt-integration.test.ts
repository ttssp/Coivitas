/**
 * persist-retry-attempt-integration.test.ts
 *
 * PgRetryAttemptWriter integration tests.
 *
 * Test goals:
 *   - real SQL INSERT INTO settlement_retries (happy path; row exists in the DB)
 *   - DB connection failure → throw SrError SR_STATE_TRANSITION_INVALID (fail-closed)
 *   - PK duplicate (same attempt.id written twice) → throw SrError SR_IDEMPOTENCY_VIOLATION
 *
 * Test constraints:
 *   - requires the DATABASE_URL environment variable; skipped otherwise (describeIfDatabase pattern)
 *   - createTestDatabase() creates an isolated DB and runs all migrations (including 031)
 *   - settlement_operations FK pre-inserted (settlement_retries.operation_id NOT NULL REF)
 *   - cleanup() drops the test DB (afterAll)
 *
 * A42 guard: field three-way reconciliation (RetryAttempt types ↔ JSON Schema ↔ SQL DDL migration 031) test coverage.
 */

import { randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import {
    createTestDatabase,
    type TestDatabaseContext,
} from '@coivitas/shared';
import { SrError, type RetryAttempt } from '@coivitas/types';

import { PgRetryAttemptWriter } from '../../settlement-retry/index.js';

// ─── describeIfDatabase — skip guard for DB-dependent tests ─────────────────────────────

const describeIfDatabase = process.env.DATABASE_URL ? describe : describe.skip;

// ─── Test constants ──────────────────────────────────────────────────────────────────

/**
 * FIXED_OPERATION_ID — pre-inserted settlement_operations.id (shared FK parent for all tests)
 *
 * Fixed UUID v4 value; shared as the same parent row across cases (a distinct attempt_number makes each PK unique).
 */
const FIXED_OPERATION_ID = 'a1b2c3d4-e5f6-4789-89ab-cdef01234567';

/**
 * FIXED_TENANT_ID — managed_service.tenants.id (FK prerequisite; same value compatible with integration.test.ts)
 *
 * If the test DB lacks a row with this tenant_id → the settlement_operations INSERT fails (FK violation).
 * Workaround: INSERT INTO managed_service.tenants first, then INSERT settlement_operations.
 */
const FIXED_TENANT_ID = 'b2c3d4e5-f6a7-4891-9abc-def012345678';

// ─── buildAttempt — test RetryAttempt fixture builder ─────────────────────────

/**
 * buildAttempt — build a minimal valid RetryAttempt fixture
 *
 * All fields must be populated (AJV schema validation); auditEventId is a random UUID v4.
 *
 * @param overrides optional field overrides (for testing different cases)
 */
function buildAttempt(overrides?: Partial<RetryAttempt>): RetryAttempt {
    const now = new Date().toISOString() as RetryAttempt['attemptedAt'];
    return {
        id: randomUUID() as RetryAttempt['id'],
        operationId: FIXED_OPERATION_ID as RetryAttempt['operationId'],
        attemptNumber: 1,
        fromState: 'PENDING',
        toState: 'SUCCEEDED',
        attemptedAt: now,
        completedAt: now,
        resultSummary: 'provider returned SUCCEEDED',
        failureReason: null,
        backoffDelayMs: 1000,
        auditEventId: randomUUID() as RetryAttempt['auditEventId'],
        ...overrides,
    };
}

// ─── DB row type definitions (guard for ESLint @typescript-eslint/no-unsafe-assignment) ─────────

/**
 * SettlementRetryRowFull — the SELECT field-set type for case 1
 *
 * query returns rows: any[] → an explicit as assertion satisfies the no-unsafe-assignment rule.
 */
interface SettlementRetryRowFull {
    id: string;
    operation_id: string;
    attempt_number: number;
    from_state: string;
    to_state: string;
    backoff_delay_ms: number;
}

/**
 * SettlementRetryRowOptional — the SELECT field-set type for case 4 (nullable-field verification)
 */
interface SettlementRetryRowOptional {
    completed_at: string | null;
    result_summary: string | null;
    failure_reason: string | null;
}

// ─── Integration tests ──────────────────────────────────────────────────────────────────

describeIfDatabase('PgRetryAttemptWriter integration', () => {
    let ctx: TestDatabaseContext;
    let writer: PgRetryAttemptWriter;

    beforeAll(async () => {
        ctx = await createTestDatabase();
        writer = new PgRetryAttemptWriter(ctx.pool);

        // Prerequisite: insert a managed_service.tenants row (settlement_operations FK chain)
        // Fields: id, tenant_did (UNIQUE), tier (FREE|PRO), display_name, status (DEFAULT ACTIVE)
        await ctx.pool.query(
            `INSERT INTO managed_service.tenants (id, tenant_did, tier, display_name, status)
             VALUES ($1, $2, 'FREE', $3, 'ACTIVE')
             ON CONFLICT (id) DO NOTHING`,
            [
                FIXED_TENANT_ID,
                'did:key:z6MkTestTenantPersistRetry001',
                'test-tenant-persist-retry',
            ],
        );

        // Prerequisite: insert a settlement_operations row (settlement_retries.operation_id FK)
        await ctx.pool.query(
            `INSERT INTO settlement_operations (
                id, sr_version, tenant_id, idempotency_key, settlement_type,
                principal_did, counterparty_did, amount, currency,
                signed_payload, current_state, attempt_count, revoked,
                created_at, updated_at
            ) VALUES (
                $1, '1.0.0', $2,
                'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2',
                'fiat_transfer',
                'did:key:z6MkpTest001', 'did:key:z6MkpTest002',
                10000, 'USD',
                '{}', 'PENDING', 0, FALSE, NOW(), NOW()
            )
            ON CONFLICT (id) DO NOTHING`,
            [FIXED_OPERATION_ID, FIXED_TENANT_ID],
        );
    });

    afterAll(async () => {
        await ctx.cleanup();
    });

    // ─── case 1: happy path — INSERT row persisted, verifiable in DB ──────────

    it('should insert RetryAttempt row and verify it exists in DB when valid attempt provided', async () => {
        const attempt = buildAttempt({
            attemptNumber: 1,
            fromState: 'PENDING',
            toState: 'SUCCEEDED',
        });

        // Real SQL INSERT (no stub)
        await expect(writer.insert(attempt)).resolves.toBeUndefined();

        // Verify the row exists in the DB (phantom enforcement guard: a stub would not produce this row)
        const result = await ctx.pool.query(
            'SELECT id, operation_id, attempt_number, from_state, to_state, backoff_delay_ms FROM settlement_retries WHERE id = $1',
            [attempt.id],
        );

        expect(result.rows).toHaveLength(1);
        const row = result.rows[0] as SettlementRetryRowFull;
        expect(row.id).toBe(attempt.id);
        expect(row.operation_id).toBe(FIXED_OPERATION_ID);
        expect(row.attempt_number).toBe(1);
        expect(row.from_state).toBe('PENDING');
        expect(row.to_state).toBe('SUCCEEDED');
        expect(row.backoff_delay_ms).toBe(1000);
    });

    // ─── case 2: DB failure — throw SrError fail-closed ──────────────────────

    it('should throw SrError SR_STATE_TRANSITION_INVALID when DB insert fails due to FK violation', async () => {
        // Use a non-existent operation_id → FK violation → throw SrError (fail-closed)
        const attempt = buildAttempt({
            operationId:
                'ffffffff-ffff-4fff-bfff-ffffffffffff' as RetryAttempt['operationId'],
        });

        await expect(writer.insert(attempt)).rejects.toSatisfy(
            (err: unknown) => {
                expect(err).toBeInstanceOf(SrError);
                const srErr = err as SrError;
                // FK violation → pg error 23503 (foreign_key_violation) → SR_STATE_TRANSITION_INVALID
                expect(srErr.code).toBe('SR_STATE_TRANSITION_INVALID');
                return true;
            },
        );
    });

    // ─── case 3: idempotency / PK duplicate — throw SrError SR_IDEMPOTENCY_VIOLATION ─

    it('should throw SrError SR_IDEMPOTENCY_VIOLATION when same attempt.id inserted twice', async () => {
        const attempt = buildAttempt({
            attemptNumber: 2,
            fromState: 'FAILED',
            toState: 'FAILED',
        });

        // First insert → success
        await expect(writer.insert(attempt)).resolves.toBeUndefined();

        // Second insert with the same id → PK 23505 → SR_IDEMPOTENCY_VIOLATION
        await expect(writer.insert(attempt)).rejects.toSatisfy(
            (err: unknown) => {
                expect(err).toBeInstanceOf(SrError);
                const srErr = err as SrError;
                expect(srErr.code).toBe('SR_IDEMPOTENCY_VIOLATION');
                return true;
            },
        );
    });

    // ─── case 4: null optional fields — INSERT succeeds (completedAt + resultSummary + failureReason null) ─

    it('should insert RetryAttempt row with null optional fields when completedAt and resultSummary are null', async () => {
        const attempt = buildAttempt({
            attemptNumber: 3,
            fromState: 'IN_PROGRESS',
            toState: 'FAILED',
            completedAt: null,
            resultSummary: null,
            failureReason: 'SR_PROVIDER_TIMEOUT',
        });

        await expect(writer.insert(attempt)).resolves.toBeUndefined();

        const result = await ctx.pool.query(
            'SELECT completed_at, result_summary, failure_reason FROM settlement_retries WHERE id = $1',
            [attempt.id],
        );

        expect(result.rows).toHaveLength(1);
        const row = result.rows[0] as SettlementRetryRowOptional;
        expect(row.completed_at).toBeNull();
        expect(row.result_summary).toBeNull();
        expect(row.failure_reason).toBe('SR_PROVIDER_TIMEOUT');
    });
});
