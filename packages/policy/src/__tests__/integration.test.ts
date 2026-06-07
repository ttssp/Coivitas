import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { generateKeyPair } from '@coivitas/crypto';
import {
    createAgentIdentity,
    didKeyFromPublicKey,
    issueCapabilityToken,
    RevocationList,
} from '@coivitas/identity';
import { createTestDatabase } from '@coivitas/shared';
import type { DID, Timestamp } from '@coivitas/types';

import { PolicyEngine } from '../engine.js';
import { RuntimeGuard } from '../guard/runtime-guard.js';
import { TokenStore } from '../guard/token-store.js';
import { ActionRecorder } from '../index.js';

const describeIfDatabase = process.env.DATABASE_URL ? describe : describe.skip;

describeIfDatabase('policy integration', () => {
    let cleanup: (() => Promise<void>) | undefined;
    let tokenStore: TokenStore;
    let revocations: RevocationList;
    let recorder: ActionRecorder;
    let agentDid: DID;
    let principalDid: DID;
    let agentPrivateKey: string;

    beforeAll(async () => {
        const database = await createTestDatabase();
        cleanup = database.cleanup;
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

        const ledger = generateKeyPair();
        recorder = new ActionRecorder(database.pool, {
            kind: 'standard',
            ledgerPrivateKey: ledger.privateKey.slice(0, 64),
        });
    });

    afterAll(async () => {
        await cleanup?.();
    });

    it('covers allow, deny, and revoked flows without mocks', async () => {
        const issuer = generateKeyPair();
        const issuerDid = didKeyFromPublicKey(
            Buffer.from(issuer.publicKey, 'hex'),
        );
        const token = issueCapabilityToken({
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

        await tokenStore.store(agentDid, token);

        const guard = new RuntimeGuard({
            tokenStore,
            revocationChecker: async (tokenId) =>
                revocations.isRevoked(tokenId),
            now: () => '2026-04-21T10:05:00.000Z' as Timestamp,
        });
        const engine = new PolicyEngine({
            guard,
            recorder,
        });

        const allowed = await engine.executeWithPolicy({
            action: 'INQUIRY',
            params: { recipient: 'supplier-a' },
            agentDid,
            principalDid,
            actorPrivateKey: agentPrivateKey,
            executor: () => Promise.resolve({ ok: true }),
        });
        expect(allowed.executed).toBe(true);
        expect(allowed).toMatchObject({
            result: { ok: true },
        });
        expect(allowed.recordId).toEqual(expect.any(String));

        const denied = await engine.executeWithPolicy({
            action: 'INQUIRY',
            params: { recipient: 'supplier-b' },
            agentDid,
            principalDid,
            actorPrivateKey: agentPrivateKey,
            executor: () => Promise.resolve({ ok: true }),
        });
        expect(denied).toMatchObject({
            executed: false,
            reason: 'scope check failed: recipient is not in the allowlist',
        });
        expect(denied.recordId).toEqual(expect.any(String));

        await revocations.revoke({
            tokenId: token.id,
            revokedBy: issuerDid,
            reason: 'MANUAL_REVOCATION',
        });

        const revoked = await engine.executeWithPolicy({
            action: 'INQUIRY',
            params: { recipient: 'supplier-a' },
            agentDid,
            principalDid,
            actorPrivateKey: agentPrivateKey,
            executor: () => Promise.resolve({ ok: true }),
        });
        expect(revoked).toMatchObject({
            executed: false,
            reason: 'capability revoked',
        });
        expect(revoked.recordId).toEqual(expect.any(String));
    });
});
