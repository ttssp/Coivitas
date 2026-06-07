/**
 * postgres-arbitration.test.ts -- PostgresOperatorArbitrationStateMachine Postgres persistence implementation tests.
 *
 * Coverage (B5 acceptance criteria):
 *   1. requestArbitration happy path -> ARBITRATED_PENDING_OPERATOR, persisted to DB
 *   2. Duplicate relatedRecordId in PENDING -> ARBITRATION_HALF_COMMITTED (F2-recur defense)
 *   3. submitVerdict happy path -> ARBITRATED, DB state updated
 *   4. Illegal state transition: ARBITRATED -> ARBITRATED -> rejected with ARBITRATION_CHAIN_MALFORMED
 *   5. getState: non-existent -> null; PENDING -> ARBITRATED_PENDING_OPERATOR; ARBITRATED -> ARBITRATED
 *   6. submitVerdict for a non-existent arbitrationId -> ARBITRATION_CHAIN_MALFORMED
 *   7. After ARBITRATED, the same relatedRecordId can create a new arbitration (SQL UNIQUE INDEX covers PENDING only)
 *
 * Dependencies: local PostgreSQL (docker-compose up -d), DATABASE_URL environment variable
 * Isolation: createTestDatabase() creates an isolated temporary DB, cleaned up in afterAll
 *
 */

import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import {
    createTestDatabase,
    type DatabasePool,
} from '@coivitas/shared';

import { PostgresOperatorArbitrationStateMachine } from '../arbitration.js';
import type { ArbitrationVerdict } from '../types.js';
import type { DID, Timestamp } from '@coivitas/types';

// ---------------------------------------------------------------------------
// Test isolation: skip the whole suite when DATABASE_URL is not set
// ---------------------------------------------------------------------------

const describeIfDatabase = process.env.DATABASE_URL ? describe : describe.skip;

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

const TIMESTAMP = '2026-05-06T10:00:00.000Z' as Timestamp;
const OPERATOR_DID = 'did:key:z6MkOperatorPostgres...' as DID;

const sampleVerdict = (): ArbitrationVerdict => ({
    operatorDid: OPERATOR_DID,
    decision: 'approve' as const,
    rationale: 'Automated request verified by operator',
    timestamp: TIMESTAMP,
});

// ---------------------------------------------------------------------------
// Suite
// ---------------------------------------------------------------------------

describeIfDatabase('PostgresOperatorArbitrationStateMachine (production impl)', () => {
    let pool: DatabasePool;
    let sm: PostgresOperatorArbitrationStateMachine;
    let cleanup: (() => Promise<void>) | undefined;

    beforeAll(async () => {
        const database = await createTestDatabase();
        pool = database.pool;
        cleanup = database.cleanup;
        sm = new PostgresOperatorArbitrationStateMachine(pool);
    });

    afterAll(async () => {
        await cleanup?.();
    });

    beforeEach(async () => {
        // Clear arbitration records before each test (keep the table structure)
        await pool.query('DELETE FROM policy.arbitration_records');
    });

    // -------------------------------------------------------------------------
    // 1. requestArbitration happy path
    // -------------------------------------------------------------------------

    describe('requestArbitration', () => {
        it('should create arbitration in ARBITRATED_PENDING_OPERATOR state and persist to DB', async () => {
            const result = await sm.requestArbitration({
                relatedRecordId: 'rec-001',
                reason: 'Automated decision uncertain',
                timestamp: TIMESTAMP,
            });

            expect(result.state).toBe('ARBITRATED_PENDING_OPERATOR');
            expect(result.arbitrationId).toBeTruthy();

            // DB persistence verification
            const dbResult = await pool.query<{
                id: string;
                state: string;
                related_record_id: string;
            }>(
                `SELECT id, state, related_record_id FROM policy.arbitration_records WHERE id = $1`,
                [result.arbitrationId],
            );
            expect(dbResult.rows).toHaveLength(1);
            expect(dbResult.rows[0]!.state).toBe('ARBITRATED_PENDING_OPERATOR');
            expect(dbResult.rows[0]!.related_record_id).toBe('rec-001');
        });

        it('should generate unique arbitrationId per request', async () => {
            const r1 = await sm.requestArbitration({
                relatedRecordId: 'rec-001',
                reason: 'test',
                timestamp: TIMESTAMP,
            });
            // Submit r1 to release relatedRecordId from PENDING
            await sm.submitVerdict(r1.arbitrationId, sampleVerdict());

            const r2 = await sm.requestArbitration({
                relatedRecordId: 'rec-002',
                reason: 'test',
                timestamp: TIMESTAMP,
            });

            expect(r1.arbitrationId).not.toBe(r2.arbitrationId);
        });

        // -----------------------------------------------------------------------
        // 2. Duplicate relatedRecordId in PENDING -> ARBITRATION_HALF_COMMITTED
        // F2-recur half-committed defense
        // -----------------------------------------------------------------------

        it('should throw ARBITRATION_HALF_COMMITTED when relatedRecordId already has pending arbitration', async () => {
            await sm.requestArbitration({
                relatedRecordId: 'rec-duplicate',
                reason: 'first request',
                timestamp: TIMESTAMP,
            });

            // Same relatedRecordId, still in PENDING state -> should be rejected
            await expect(
                sm.requestArbitration({
                    relatedRecordId: 'rec-duplicate',
                    reason: 'duplicate attempt',
                    timestamp: TIMESTAMP,
                }),
            ).rejects.toThrow('ARBITRATION_HALF_COMMITTED');
        });

        it('should allow new arbitration for same relatedRecordId after previous is ARBITRATED', async () => {
            const r1 = await sm.requestArbitration({
                relatedRecordId: 'rec-reuse',
                reason: 'first',
                timestamp: TIMESTAMP,
            });
            await sm.submitVerdict(r1.arbitrationId, sampleVerdict());

            // The previous one is in a terminal state, so the same relatedRecordId should allow a new one
            const r2 = await sm.requestArbitration({
                relatedRecordId: 'rec-reuse',
                reason: 'new issue',
                timestamp: TIMESTAMP,
            });
            expect(r2.state).toBe('ARBITRATED_PENDING_OPERATOR');
            expect(r2.arbitrationId).not.toBe(r1.arbitrationId);
        });
    });

    // -------------------------------------------------------------------------
    // 3. submitVerdict happy path
    // -------------------------------------------------------------------------

    describe('submitVerdict', () => {
        it('should transition to ARBITRATED on valid verdict', async () => {
            const req = await sm.requestArbitration({
                relatedRecordId: 'rec-verdict',
                reason: 'test',
                timestamp: TIMESTAMP,
            });

            const result = await sm.submitVerdict(req.arbitrationId, sampleVerdict());
            expect(result.state).toBe('ARBITRATED');
            expect(result.arbitrationId).toBe(req.arbitrationId);

            // DB persistence verification
            const dbResult = await pool.query<{ state: string; verdict: unknown }>(
                `SELECT state, verdict FROM policy.arbitration_records WHERE id = $1`,
                [req.arbitrationId],
            );
            expect(dbResult.rows).toHaveLength(1);
            expect(dbResult.rows[0]!.state).toBe('ARBITRATED');
            expect(dbResult.rows[0]!.verdict).not.toBeNull();
        });

        it('should support reject decision', async () => {
            const req = await sm.requestArbitration({
                relatedRecordId: 'rec-reject-verdict',
                reason: 'test',
                timestamp: TIMESTAMP,
            });

            const result = await sm.submitVerdict(req.arbitrationId, {
                operatorDid: OPERATOR_DID,
                decision: 'reject' as const,
                rationale: 'Not justified',
                timestamp: TIMESTAMP,
            });

            expect(result.state).toBe('ARBITRATED');
        });

        it('should throw ARBITRATION_CHAIN_MALFORMED for non-existent arbitrationId', async () => {
            await expect(
                sm.submitVerdict('non-existent-uuid', sampleVerdict()),
            ).rejects.toThrow('ARBITRATION_CHAIN_MALFORMED');
        });

        // -----------------------------------------------------------------------
        // 4. Illegal state transition: ARBITRATED -> ARBITRATED -> reject
        // -----------------------------------------------------------------------

        it('should throw ARBITRATION_CHAIN_MALFORMED for illegal transition ARBITRATED -> ARBITRATED', async () => {
            const req = await sm.requestArbitration({
                relatedRecordId: 'rec-illegal',
                reason: 'test',
                timestamp: TIMESTAMP,
            });

            // Valid submitVerdict: PENDING -> ARBITRATED
            await sm.submitVerdict(req.arbitrationId, sampleVerdict());

            // Illegal submitVerdict: ARBITRATED -> ARBITRATED (transition from a terminal state)
            await expect(
                sm.submitVerdict(req.arbitrationId, {
                    operatorDid: OPERATOR_DID,
                    decision: 'reject' as const,
                    rationale: 'second attempt',
                    timestamp: TIMESTAMP,
                }),
            ).rejects.toThrow('ARBITRATION_CHAIN_MALFORMED');

            // Verify the DB state was not unexpectedly changed
            const dbResult = await pool.query<{ state: string }>(
                `SELECT state FROM policy.arbitration_records WHERE id = $1`,
                [req.arbitrationId],
            );
            expect(dbResult.rows[0]!.state).toBe('ARBITRATED');
        });
    });

    // -------------------------------------------------------------------------
    // 5. getState
    // -------------------------------------------------------------------------

    describe('getState', () => {
        it('should return null for non-existent arbitrationId', async () => {
            const state = await sm.getState('does-not-exist');
            expect(state).toBeNull();
        });

        it('should return ARBITRATED_PENDING_OPERATOR after request', async () => {
            const req = await sm.requestArbitration({
                relatedRecordId: 'rec-state-pending',
                reason: 'test',
                timestamp: TIMESTAMP,
            });

            const state = await sm.getState(req.arbitrationId);
            expect(state).toBe('ARBITRATED_PENDING_OPERATOR');
        });

        it('should return ARBITRATED after verdict', async () => {
            const req = await sm.requestArbitration({
                relatedRecordId: 'rec-state-arb',
                reason: 'test',
                timestamp: TIMESTAMP,
            });
            await sm.submitVerdict(req.arbitrationId, sampleVerdict());

            const state = await sm.getState(req.arbitrationId);
            expect(state).toBe('ARBITRATED');
        });
    });

    // -------------------------------------------------------------------------
    // 6. Multiple concurrent relatedRecordIds do not interfere with each other
    // -------------------------------------------------------------------------

    describe('isolation — multiple relatedRecordIds', () => {
        it('should handle multiple independent relatedRecordIds simultaneously', async () => {
            const r1 = await sm.requestArbitration({
                relatedRecordId: 'rec-iso-1',
                reason: 'first',
                timestamp: TIMESTAMP,
            });
            const r2 = await sm.requestArbitration({
                relatedRecordId: 'rec-iso-2',
                reason: 'second',
                timestamp: TIMESTAMP,
            });

            expect(r1.arbitrationId).not.toBe(r2.arbitrationId);
            expect(r1.state).toBe('ARBITRATED_PENDING_OPERATOR');
            expect(r2.state).toBe('ARBITRATED_PENDING_OPERATOR');

            // Submitting r1 does not affect r2
            await sm.submitVerdict(r1.arbitrationId, sampleVerdict());

            expect(await sm.getState(r1.arbitrationId)).toBe('ARBITRATED');
            expect(await sm.getState(r2.arbitrationId)).toBe('ARBITRATED_PENDING_OPERATOR');
        });
    });
});
