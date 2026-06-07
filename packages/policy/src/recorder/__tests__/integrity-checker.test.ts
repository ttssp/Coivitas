import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { generateKeyPair } from '@coivitas/crypto';
import {
    createAgentIdentity,
    didKeyFromPublicKey,
    IdentityRegistry,
} from '@coivitas/identity';
import { createTestDatabase } from '@coivitas/shared';
import type { DID } from '@coivitas/types';

import { ActionRecorder, IntegrityChecker } from '../../index.js';

const describeIfDatabase = process.env.DATABASE_URL ? describe : describe.skip;

describeIfDatabase('IntegrityChecker', () => {
    let cleanup: (() => Promise<void>) | undefined;
    let pool: Awaited<ReturnType<typeof createTestDatabase>>['pool'];
    let recorder: ActionRecorder;
    let checker: IntegrityChecker;
    let agentDid: DID;
    let principalDid: DID;
    let agentPrivateKey: string;
    let registry: IdentityRegistry;

    beforeAll(async () => {
        const database = await createTestDatabase();
        cleanup = database.cleanup;
        pool = database.pool;

        registry = new IdentityRegistry(pool);
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
        // After the DU refactor this uses standard mode.
        // This test suite does not involve any SESSION_SUPERSEDED record; a governor DID automatically fail-closes.
        checker = new IntegrityChecker(pool, {
            kind: 'standard',
            ledgerPrivateKey: ledger.privateKey.slice(0, 64),
            ledgerPublicKey: recorder.ledgerPublicKey,
            resolveIdentity: async (did) =>
                (await registry.query(did))?.publicKey ?? null,
        });
    });

    afterAll(async () => {
        await cleanup?.();
    });

    it('returns valid for an intact chain and pinpoints tampering', async () => {
        const created: string[] = [];

        for (let index = 0; index < 3; index += 1) {
            const result = await recorder.record({
                agentDid: agentDid as never,
                principalDid: principalDid as never,
                actionType: 'INQUIRY',
                parametersSummary: { index },
                resultSummary: { ok: true },
                actorPrivateKey: agentPrivateKey,
            });
            created.push(result.recordId);
        }

        await expect(
            checker.verifyIntegrity(agentDid as never),
        ).resolves.toEqual({ valid: true });

        await pool.query(
            `UPDATE policy.action_records SET result_summary = '{"tampered":true}'::jsonb WHERE record_id = $1`,
            [created[1]],
        );

        await expect(
            checker.verifyIntegrity(agentDid as never),
        ).resolves.toMatchObject({
            valid: false,
            brokenAt: created[1],
        });
    });
});
