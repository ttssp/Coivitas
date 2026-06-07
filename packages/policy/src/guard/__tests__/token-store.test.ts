import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { generateKeyPair } from '@coivitas/crypto';
import {
    didKeyFromPublicKey,
    issueCapabilityToken,
} from '@coivitas/identity';
import { createTestDatabase } from '@coivitas/shared';
import type { DID, Timestamp } from '@coivitas/types';

import { TokenStore } from '../token-store.js';

const describeIfDatabase = process.env.DATABASE_URL ? describe : describe.skip;

describeIfDatabase('TokenStore', () => {
    let cleanup: (() => Promise<void>) | undefined;
    let tokenStore: TokenStore;
    let agentDid: DID;

    beforeAll(async () => {
        const database = await createTestDatabase();
        cleanup = database.cleanup;
        tokenStore = new TokenStore(database.pool);
        agentDid = 'did:agent:00112233445566778899aabbccddeeff00112233' as DID;
    });

    afterAll(async () => {
        await cleanup?.();
    });

    it('stores, loads, and removes tokens', async () => {
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
                        type: 'numeric_limit',
                        field: 'amount',
                        max: 500,
                    },
                },
            ],
            expiresAt: '2026-04-22T10:00:00.000Z' as Timestamp,
            revocationUrl: 'https://revocation.example.com/v1/{id}',
            issuerPrivateKey: issuer.privateKey,
            issuedAt: '2026-04-21T10:00:00.000Z' as Timestamp,
        });

        await tokenStore.store(agentDid, token);
        await expect(tokenStore.getToken(token.id)).resolves.toEqual(token);
        await expect(tokenStore.getTokensForAgent(agentDid)).resolves.toEqual([
            token,
        ]);
        await expect(tokenStore.remove(token.id)).resolves.toBe(true);
        await expect(tokenStore.getToken(token.id)).resolves.toBeNull();
    });
});
