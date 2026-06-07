import { randomUUID } from 'node:crypto';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { generateKeyPair } from '@coivitas/crypto';
import {
    createAgentIdentity,
    didKeyFromPublicKey,
    IdentityRegistry,
} from '@coivitas/identity';
import { createTestDatabase } from '@coivitas/shared';
import type { DID } from '@coivitas/types';

import { ActionRecorder } from '../../recorder/action-recorder.js';
import { PostgresCumulativeTracker } from '../postgres-cumulative-tracker.js';

const describeIfDatabase = process.env.DATABASE_URL ? describe : describe.skip;

// When pg performs a server-side DROP DATABASE, the connection pool may still hold an unfinished statement;
// after pool.end() returns, a residual client throws 57P01 on the next tick (terminating connection
// due to administrator command), which vitest treats as an Uncaught Exception → exit code 1.
// This error is a benign manifestation of the teardown race and does not affect test assertions; silence 57P01 within the afterAll scope.
const ADMIN_TERMINATION_CODE = '57P01';
function isAdminTermination(error: unknown): boolean {
    return (
        typeof error === 'object' &&
        error !== null &&
        'code' in error &&
        (error as { code?: unknown }).code === ADMIN_TERMINATION_CODE
    );
}

describeIfDatabase('PostgresCumulativeTracker integration', () => {
    let cleanup: (() => Promise<void>) | undefined;
    let pool: Awaited<ReturnType<typeof createTestDatabase>>['pool'];
    let recorder: ActionRecorder;
    let tracker: PostgresCumulativeTracker;
    let agentDid: DID;
    let principalDid: DID;
    let agentPrivateKey: string;

    beforeAll(async () => {
        const database = await createTestDatabase();
        cleanup = database.cleanup;
        pool = database.pool;

        const registry = new IdentityRegistry(pool);
        const principal = generateKeyPair();
        principalDid = didKeyFromPublicKey(
            Buffer.from(principal.publicKey, 'hex'),
        );
        const agent = createAgentIdentity({
            principalDid,
            principalPrivateKey: principal.privateKey,
        });
        agentDid = agent.document.id;
        agentPrivateKey = agent.privateKey;
        await registry.register(agent.document);

        const ledger = generateKeyPair();
        recorder = new ActionRecorder(pool, {
            kind: 'standard',
            ledgerPrivateKey: ledger.privateKey.slice(0, 64),
        });
        tracker = new PostgresCumulativeTracker(pool, recorder.ledgerPublicKey);
    });

    afterAll(async () => {
        // See the file header comment: after pool.end(), a residual client asynchronously throws 57P01.
        // Inject a temporary error handler that swallows only 57P01; other errors still propagate.
        const swallow57P01 = (error: unknown): void => {
            if (!isAdminTermination(error)) throw error;
        };
        pool?.on('error', swallow57P01);
        try {
            await cleanup?.();
        } catch (error) {
            if (!isAdminTermination(error)) throw error;
        } finally {
            pool?.off('error', swallow57P01);
        }
    });

    it('should count api_call_count correctly after 3 records', async () => {
        const now = new Date();
        const windowStart = new Date(now);
        windowStart.setUTCHours(0, 0, 0, 0); // day window start

        for (let i = 0; i < 3; i++) {
            await recorder.record({
                agentDid,
                principalDid,
                actionType: 'API_CALL',
                resultSummary: { status: 'SUCCESS' },
                actorPrivateKey: agentPrivateKey,
            });
        }

        const count = await tracker.getCumulativeValue(
            agentDid,
            { source: 'action_record', metric: 'api_call_count' },
            windowStart,
            new Date(),
        );
        expect(count).toBe(3);
    });

    it('should sum transaction_amount correctly after 3 SUCCESS records', async () => {
        const now = new Date();
        const windowStart = new Date(now);
        windowStart.setUTCHours(0, 0, 0, 0);

        // A separate agent to avoid interfering with the previous test
        const principal2 = generateKeyPair();
        const principalDid2 = didKeyFromPublicKey(
            Buffer.from(principal2.publicKey, 'hex'),
        );
        const agent2 = createAgentIdentity({
            principalDid: principalDid2,
            principalPrivateKey: principal2.privateKey,
        });
        const registry2 = new IdentityRegistry(pool);
        await registry2.register(agent2.document);

        const amounts = [1000, 2000, 3000];
        for (const amount of amounts) {
            await recorder.record({
                agentDid: agent2.document.id,
                principalDid: principalDid2,
                actionType: 'TRANSACTION',
                resultSummary: { status: 'SUCCESS', amount },
                actorPrivateKey: agent2.privateKey,
            });
        }

        const total = await tracker.getCumulativeValue(
            agent2.document.id,
            { source: 'action_record', metric: 'transaction_amount' },
            windowStart,
            new Date(),
        );
        expect(total).toBe(6000);
    });

    it('should fail-closed when any ledgerSignature in window is invalid', async () => {
        const now = new Date();
        const windowStart = new Date(now);
        windowStart.setUTCHours(0, 0, 0, 0);

        // A separate agent
        const principal3 = generateKeyPair();
        const principalDid3 = didKeyFromPublicKey(
            Buffer.from(principal3.publicKey, 'hex'),
        );
        const agent3 = createAgentIdentity({
            principalDid: principalDid3,
            principalPrivateKey: principal3.privateKey,
        });
        const registry3 = new IdentityRegistry(pool);
        await registry3.register(agent3.document);

        // Write 3 records
        const ids: string[] = [];
        for (let i = 0; i < 3; i++) {
            const res = await recorder.record({
                agentDid: agent3.document.id,
                principalDid: principalDid3,
                actionType: 'API_CALL',
                resultSummary: { status: 'SUCCESS' },
                actorPrivateKey: agent3.privateKey,
            });
            ids.push(res.recordId);
        }

        // Tamper with the first record's ledgerSignature
        await pool.query(
            `UPDATE policy.action_records SET ledger_signature = repeat('0', 128) WHERE record_id = $1`,
            [ids[0]],
        );

        // Any invalid signature → fail-closed; the whole-window aggregation throws, preventing under-counting of the cumulative value
        await expect(
            tracker.getCumulativeValue(
                agent3.document.id,
                { source: 'action_record', metric: 'api_call_count' },
                windowStart,
                new Date(),
            ),
        ).rejects.toThrow('ledgerSignature invalid');
    });

    it('should throw for unregistered metric', async () => {
        await expect(
            tracker.getCumulativeValue(
                agentDid,
                { source: 'action_record', metric: 'nonexistent_metric' },
                new Date(),
                new Date(),
            ),
        ).rejects.toThrow('unregistered meter field: nonexistent_metric');
    });

    // -----------------------------------------------------------------------
    // checkAndReserve / settleReservation integration tests
    // -----------------------------------------------------------------------

    it('should allow reserve when below limit and create PENDING row', async () => {
        const now = new Date();
        const windowStart = new Date(now);
        windowStart.setUTCHours(0, 0, 0, 0);

        // A separate agent to avoid interfering with other tests
        const principal4 = generateKeyPair();
        const principalDid4 = didKeyFromPublicKey(
            Buffer.from(principal4.publicKey, 'hex'),
        );
        const agent4 = createAgentIdentity({
            principalDid: principalDid4,
            principalPrivateKey: principal4.privateKey,
        });
        await new IdentityRegistry(pool).register(agent4.document);

        const recordId = randomUUID();
        const result = await tracker.checkAndReserve(
            recordId,
            agent4.document.id,
            { source: 'action_record', metric: 'api_call_count' },
            windowStart,
            now,
            5, // max
            1, // reserveAmount
        );
        expect(result.allowed).toBe(true);
        expect(result.currentCumulative).toBe(0);

        // Verify the PENDING row has been written to the database
        const row = await pool.query<{
            result_summary: { status: string; reserveAmount?: number };
        }>(
            `SELECT result_summary FROM policy.action_records WHERE record_id = $1`,
            [recordId],
        );
        expect(row.rows).toHaveLength(1);
        expect(row.rows[0].result_summary.status).toBe('PENDING');
        expect(row.rows[0].result_summary.reserveAmount).toBe(1);
    });

    it('should deny reserve when cumulative + reserveAmount would exceed max', async () => {
        const principal5 = generateKeyPair();
        const principalDid5 = didKeyFromPublicKey(
            Buffer.from(principal5.publicKey, 'hex'),
        );
        const agent5 = createAgentIdentity({
            principalDid: principalDid5,
            principalPrivateKey: principal5.privateKey,
        });
        await new IdentityRegistry(pool).register(agent5.document);

        // Write 2 real records (api_call_count: COUNT+*)
        for (let i = 0; i < 2; i++) {
            await recorder.record({
                agentDid: agent5.document.id,
                principalDid: principalDid5,
                actionType: 'API_CALL',
                resultSummary: { status: 'SUCCESS' },
                actorPrivateKey: agent5.privateKey,
            });
        }

        // now must be captured after the records are written, otherwise the aggregation window's right boundary
        // cuts off before record.created_at → cumulative 0 → over-limit admission
        const now = new Date();
        const windowStart = new Date(now);
        windowStart.setUTCHours(0, 0, 0, 0);

        // max=2, cumulative already 2 → should deny (2 + 1 > 2)
        const recordId = randomUUID();
        const result = await tracker.checkAndReserve(
            recordId,
            agent5.document.id,
            { source: 'action_record', metric: 'api_call_count' },
            windowStart,
            now,
            2, // max
            1, // reserveAmount
        );
        expect(result.allowed).toBe(false);
    });

    it('should be idempotent: same recordId called twice returns same result without double-reserve', async () => {
        const now = new Date();
        const windowStart = new Date(now);
        windowStart.setUTCHours(0, 0, 0, 0);

        const principal6 = generateKeyPair();
        const principalDid6 = didKeyFromPublicKey(
            Buffer.from(principal6.publicKey, 'hex'),
        );
        const agent6 = createAgentIdentity({
            principalDid: principalDid6,
            principalPrivateKey: principal6.privateKey,
        });
        await new IdentityRegistry(pool).register(agent6.document);

        const recordId = randomUUID();
        const meterField = {
            source: 'action_record' as const,
            metric: 'api_call_count',
        };

        const first = await tracker.checkAndReserve(
            recordId,
            agent6.document.id,
            meterField,
            windowStart,
            now,
            5,
            1,
        );
        const second = await tracker.checkAndReserve(
            recordId,
            agent6.document.id,
            meterField,
            windowStart,
            now,
            5,
            1,
        );

        // Both results are identical (idempotent)
        expect(first.allowed).toBe(second.allowed);
        expect(first.currentCumulative).toBe(second.currentCumulative);

        // There is only one PENDING row (no duplicate write)
        const rows = await pool.query(
            `SELECT record_id FROM policy.action_records WHERE record_id = $1`,
            [recordId],
        );
        expect(rows.rows).toHaveLength(1);
    });

    it('should settle PENDING to SETTLED on SUCCESS (COUNT+*)', async () => {
        const now = new Date();
        const windowStart = new Date(now);
        windowStart.setUTCHours(0, 0, 0, 0);

        const principal7 = generateKeyPair();
        const principalDid7 = didKeyFromPublicKey(
            Buffer.from(principal7.publicKey, 'hex'),
        );
        const agent7 = createAgentIdentity({
            principalDid: principalDid7,
            principalPrivateKey: principal7.privateKey,
        });
        await new IdentityRegistry(pool).register(agent7.document);

        const recordId = randomUUID();
        const meterField = {
            source: 'action_record' as const,
            metric: 'api_call_count',
        };

        await tracker.checkAndReserve(
            recordId,
            agent7.document.id,
            meterField,
            windowStart,
            now,
            10,
            1,
        );
        await tracker.settleReservation(recordId, 'SUCCESS');

        const row = await pool.query<{ result_summary: { status: string } }>(
            `SELECT result_summary FROM policy.action_records WHERE record_id = $1`,
            [recordId],
        );
        expect(row.rows[0].result_summary.status).toBe('SETTLED');
    });

    it('should settle PENDING to RELEASED on REJECTED (COUNT+SUCCESS)', async () => {
        const now = new Date();
        const windowStart = new Date(now);
        windowStart.setUTCHours(0, 0, 0, 0);

        const principal8 = generateKeyPair();
        const principalDid8 = didKeyFromPublicKey(
            Buffer.from(principal8.publicKey, 'hex'),
        );
        const agent8 = createAgentIdentity({
            principalDid: principalDid8,
            principalPrivateKey: principal8.privateKey,
        });
        await new IdentityRegistry(pool).register(agent8.document);

        // transaction_amount: SUM + countFilter='SUCCESS'
        const recordId = randomUUID();
        const meterField = {
            source: 'action_record' as const,
            metric: 'transaction_amount',
        };

        await tracker.checkAndReserve(
            recordId,
            agent8.document.id,
            meterField,
            windowStart,
            now,
            10000,
            500,
        );
        await tracker.settleReservation(recordId, 'REJECTED');

        const row = await pool.query<{ result_summary: { status: string } }>(
            `SELECT result_summary FROM policy.action_records WHERE record_id = $1`,
            [recordId],
        );
        // SUM + REJECTED → RELEASED (failed transactions do not consume SUM quota)
        expect(row.rows[0].result_summary.status).toBe('RELEASED');
    });

    it('should throw on SUM overage when settledAmount > max', async () => {
        const now = new Date();
        const windowStart = new Date(now);
        windowStart.setUTCHours(0, 0, 0, 0);

        const principal9 = generateKeyPair();
        const principalDid9 = didKeyFromPublicKey(
            Buffer.from(principal9.publicKey, 'hex'),
        );
        const agent9 = createAgentIdentity({
            principalDid: principalDid9,
            principalPrivateKey: principal9.privateKey,
        });
        await new IdentityRegistry(pool).register(agent9.document);

        const recordId = randomUUID();
        const meterField = {
            source: 'action_record' as const,
            metric: 'transaction_amount',
        };

        // max=1000, reserveAmount=500, cumulativeAtReserve=0 → reservation passes
        await tracker.checkAndReserve(
            recordId,
            agent9.document.id,
            meterField,
            windowStart,
            now,
            1000,
            500,
        );

        // settledAmount=1001 > max=1000 → should throw
        await expect(
            tracker.settleReservation(recordId, 'SUCCESS', 1001),
        ).rejects.toThrow(/exceeds max/);
    });

    it('should count PENDING reservations in aggregation to prevent concurrent over-reserve', async () => {
        const now = new Date();
        const windowStart = new Date(now);
        windowStart.setUTCHours(0, 0, 0, 0);

        const principalA = generateKeyPair();
        const principalDidA = didKeyFromPublicKey(
            Buffer.from(principalA.publicKey, 'hex'),
        );
        const agentA = createAgentIdentity({
            principalDid: principalDidA,
            principalPrivateKey: principalA.privateKey,
        });
        await new IdentityRegistry(pool).register(agentA.document);

        const meterField = {
            source: 'action_record' as const,
            metric: 'api_call_count',
        };
        const max = 3;

        // First reservation (recordId=r1): 0 + 1 = 1 ≤ 3 → allowed
        const r1 = randomUUID();
        const res1 = await tracker.checkAndReserve(
            r1,
            agentA.document.id,
            meterField,
            windowStart,
            now,
            max,
            1,
        );
        expect(res1.allowed).toBe(true);

        // Second reservation (recordId=r2): 1 + 1 = 2 ≤ 3 → allowed (reads the first PENDING)
        const r2 = randomUUID();
        const res2 = await tracker.checkAndReserve(
            r2,
            agentA.document.id,
            meterField,
            windowStart,
            now,
            max,
            1,
        );
        expect(res2.allowed).toBe(true);

        // Third reservation (recordId=r3): 2 + 1 = 3 ≤ 3 → allowed
        const r3 = randomUUID();
        const res3 = await tracker.checkAndReserve(
            r3,
            agentA.document.id,
            meterField,
            windowStart,
            now,
            max,
            1,
        );
        expect(res3.allowed).toBe(true);

        // Fourth reservation (recordId=r4): 3 + 1 = 4 > 3 → denied (concurrent over-limit is blocked)
        const r4 = randomUUID();
        const res4 = await tracker.checkAndReserve(
            r4,
            agentA.document.id,
            meterField,
            windowStart,
            now,
            max,
            1,
        );
        expect(res4.allowed).toBe(false);
    });
});
