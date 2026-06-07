import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { createTestDatabase } from '@coivitas/shared';
import { generateKeyPair } from '@coivitas/crypto';
import type { DID, Timestamp } from '@coivitas/types';

import {
    didKeyFromPublicKey,
    issueCapabilityToken,
    RevocationList,
    verifyCapabilityToken,
} from '../index.js';

const describeIfDatabase = process.env.DATABASE_URL ? describe : describe.skip;

describeIfDatabase('credential integration', () => {
    let cleanup: (() => Promise<void>) | undefined;
    let revocations: RevocationList;

    beforeAll(async () => {
        const database = await createTestDatabase();
        cleanup = database.cleanup;
        revocations = new RevocationList(database.pool);
    });

    afterAll(async () => {
        await cleanup?.();
    });

    it('issues, verifies, revokes, and keeps cryptographic verification independent from revocation status', async () => {
        const issuer = generateKeyPair();
        const issuerDid = didKeyFromPublicKey(
            Buffer.from(issuer.publicKey, 'hex'),
        );
        const issuedTo =
            'did:agent:00112233445566778899aabbccddeeff00112233' as DID;

        const token = issueCapabilityToken({
            issuerDid,
            issuedTo,
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

        expect(
            verifyCapabilityToken(
                token,
                '2026-04-21T10:10:00.000Z' as Timestamp,
            ),
        ).toEqual({
            valid: true,
        });

        await revocations.revoke({
            tokenId: token.id,
            revokedBy: issuerDid,
            reason: 'MANUAL_REVOCATION',
        });

        await expect(revocations.isRevoked(token.id)).resolves.toBe(true);
        expect(
            verifyCapabilityToken(
                token,
                '2026-04-21T10:10:00.000Z' as Timestamp,
            ),
        ).toEqual({
            valid: true,
        });
    });
});
