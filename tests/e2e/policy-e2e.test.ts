import { PassThrough } from 'node:stream';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { generateKeyPair } from '../../packages/crypto/src/index.js';
import {
    createAgentIdentity,
    didKeyFromPublicKey,
    IdentityRegistry,
    issueCapabilityToken,
    RevocationList,
} from '../../packages/identity/src/index.js';
import {
    ActionRecorder,
    HumanCheckpoint,
    PolicyEngine,
    RuntimeGuard,
    TokenStore,
} from '../../packages/policy/src/index.js';
import { createTestDatabase } from '../../packages/shared/src/index.js';
import type { DID, Timestamp } from '../../packages/types/src/index.js';

const describeIfDatabase = process.env.DATABASE_URL ? describe : describe.skip;

describeIfDatabase('policy e2e', () => {
    let cleanup: (() => Promise<void>) | undefined;
    let registry: IdentityRegistry;
    let tokenStore: TokenStore;
    let revocations: RevocationList;
    let recorder: ActionRecorder;
    let agentDid: DID;
    let principalDid: DID;
    let agentPrivateKey: string;
    let confirmTokenId = '';

    beforeAll(async () => {
        const database = await createTestDatabase();
        cleanup = database.cleanup;

        registry = new IdentityRegistry(database.pool);
        tokenStore = new TokenStore(database.pool);
        revocations = new RevocationList(database.pool);

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
        recorder = new ActionRecorder(database.pool, {
            kind: 'standard',
            ledgerPrivateKey: ledger.privateKey.slice(0, 64),
        });

        const issuer = generateKeyPair();
        const issuerDid = didKeyFromPublicKey(
            Buffer.from(issuer.publicKey, 'hex'),
        );
        const inquiryToken = issueCapabilityToken({
            issuerDid,
            issuedTo: agentDid,
            capabilities: [
                {
                    action: 'INQUIRY',
                    scope: {
                        type: 'allowlist',
                        field: 'recipient',
                        values: ['supplier-a'],
                    },
                },
            ],
            expiresAt: '2026-04-22T10:00:00.000Z' as Timestamp,
            revocationUrl: 'https://revocation.example.com/v1/{id}',
            issuerPrivateKey: issuer.privateKey,
            issuedAt: '2026-04-21T10:00:00.000Z' as Timestamp,
        });
        const confirmToken = issueCapabilityToken({
            issuerDid,
            issuedTo: agentDid,
            capabilities: [
                {
                    action: 'CONFIRM',
                    scope: {
                        type: 'numeric_limit',
                        field: 'confirmed_price',
                        max: 10_000,
                        currency: 'USD',
                    },
                },
            ],
            expiresAt: '2026-04-22T10:00:00.000Z' as Timestamp,
            revocationUrl: 'https://revocation.example.com/v1/{id}',
            issuerPrivateKey: issuer.privateKey,
            issuedAt: '2026-04-21T10:00:00.000Z' as Timestamp,
        });

        confirmTokenId = confirmToken.id;
        await tokenStore.store(agentDid, inquiryToken);
        await tokenStore.store(agentDid, confirmToken);
    });

    afterAll(async () => {
        await cleanup?.();
    });

    it('covers allowed execution, human approval, action recording, and revoked denial without mocks', async () => {
        const guard = new RuntimeGuard({
            tokenStore,
            revocationChecker: async (tokenId) =>
                revocations.isRevoked(tokenId),
            now: () => '2026-04-21T10:05:00.000Z' as Timestamp,
        });
        const checkpointInput = new PassThrough();
        const checkpointOutput = new PassThrough();
        const checkpoint = new HumanCheckpoint({
            input: checkpointInput,
            output: checkpointOutput,
            timeoutMs: 500,
        });
        const engine = new PolicyEngine({
            guard,
            recorder,
            checkpoint,
        });

        await expect(
            engine.executeWithPolicy({
                action: 'INQUIRY',
                params: { recipient: 'supplier-a' },
                agentDid,
                principalDid,
                actorPrivateKey: agentPrivateKey,
                executor: () => Promise.resolve({ step: 8, status: 'allowed' }),
            }),
        ).resolves.toMatchObject({
            executed: true,
            result: { step: 8, status: 'allowed' },
        });

        checkpointInput.write('y\n');
        await expect(
            engine.executeWithPolicy({
                action: 'CONFIRM',
                params: { confirmed_price: 9500 },
                agentDid,
                principalDid,
                actorPrivateKey: agentPrivateKey,
                requireHumanApproval: true,
                executor: () =>
                    Promise.resolve({ step: 10, status: 'approved' }),
            }),
        ).resolves.toMatchObject({
            executed: true,
            result: { step: 10, status: 'approved' },
        });

        await revocations.revoke({
            tokenId: confirmTokenId,
            revokedBy: principalDid,
            reason: 'MANUAL_REVOCATION',
        });

        await expect(
            engine.executeWithPolicy({
                action: 'CONFIRM',
                params: { confirmed_price: 9500 },
                agentDid,
                principalDid,
                actorPrivateKey: agentPrivateKey,
                executor: () =>
                    Promise.resolve({ step: 15, status: 'should-not-run' }),
            }),
        ).resolves.toMatchObject({
            executed: false,
            reason: 'capability revoked',
        });

        const { records } = await recorder.query({
            agentDid,
            limit: 10,
        });

        expect(records).toHaveLength(3);
        expect(records[0]?.resultSummary).toMatchObject({ status: 'SUCCESS' });
        expect(records[1]?.resultSummary).toMatchObject({ status: 'SUCCESS' });
        expect(records[2]?.resultSummary).toMatchObject({
            status: 'REJECTED',
            reason: 'capability revoked',
        });
    });
});
