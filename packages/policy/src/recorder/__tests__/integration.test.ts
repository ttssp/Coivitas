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

// This test is restored after the DU refactor (it was previously skipped
// because the required resolveControlPlanePublicKey parameter was missing; the DU refactor
// resolved that via kind='standard').
const describeIfDatabase = process.env.DATABASE_URL ? describe : describe.skip;

describeIfDatabase('policy integration', () => {
    let cleanup: (() => Promise<void>) | undefined;
    let pool: Awaited<ReturnType<typeof createTestDatabase>>['pool'];
    let recorder: ActionRecorder;
    let checker: IntegrityChecker;
    let registry: IdentityRegistry;
    let agentDid: DID;
    let principalDid: DID;
    let agentPrivateKey: string;

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
        // DU standard mode, no resolveControlPlanePublicKey needed
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

    it('writes 1000 records, reads all via cursor pagination, verifies chain', async () => {
        for (let i = 0; i < 1000; i++) {
            await recorder.record({
                agentDid: agentDid as never,
                principalDid: principalDid as never,
                actionType:
                    i % 3 === 0 ? 'INQUIRY' : i % 3 === 1 ? 'QUOTE' : 'BIND',
                parametersSummary: { index: i },
                authorizationRef: { tokenId: `token-${i}` },
                resultSummary: { status: 'SUCCESS' },
                actorPrivateKey: agentPrivateKey,
            });
        }

        const pageSize = 100;
        let cursor: string | undefined;
        const allRecords: Awaited<
            ReturnType<typeof recorder.query>
        >['records'] = [];

        do {
            const result = await recorder.query({
                agentDid: agentDid as never,
                limit: pageSize,
                cursor,
            });
            allRecords.push(...result.records);
            cursor = result.nextCursor;
        } while (cursor !== undefined);

        expect(allRecords).toHaveLength(1000);

        const ids = new Set(allRecords.map((r) => r.recordId));
        expect(ids.size).toBe(1000);

        await expect(
            checker.verifyIntegrity(agentDid as never),
        ).resolves.toEqual({ valid: true });
    }, 120_000);

    it('detects tampering at record 500', async () => {
        const { records: first600 } = await recorder.query({
            agentDid: agentDid as never,
            limit: 600,
        });
        const target = first600[499]!;

        await pool.query(
            `UPDATE policy.action_records SET actor_signature = repeat('0', 128) WHERE record_id = $1`,
            [target.recordId],
        );

        await expect(
            checker.verifyIntegrity(agentDid as never),
        ).resolves.toMatchObject({
            valid: false,
            brokenAt: target.recordId,
        });
        // Explicit 30s timeout: under coverage instrumentation, a 600-record query + UPDATE + full chain verify exceeds vitest's default 5s.
    }, 30_000);
});
