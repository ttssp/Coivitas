import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';

import { createTestDatabase } from '@coivitas/shared';
import type { DID, Timestamp } from '@coivitas/types';

import { RevocationList } from '../index.js';

const describeIfDatabase = process.env.DATABASE_URL ? describe : describe.skip;

describeIfDatabase('RevocationList', () => {
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

    it('revoke is idempotent and lookup APIs work', async () => {
        const revokedBy =
            'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK' as DID;
        const first = await revocations.revoke({
            tokenId: 'urn:cap:550e8400-e29b-41d4-a716-446655440000',
            revokedBy,
            reason: 'MANUAL_REVOCATION',
        });

        const second = await revocations.revoke({
            tokenId: 'urn:cap:550e8400-e29b-41d4-a716-446655440000',
            revokedBy,
            reason: 'KEY_COMPROMISE',
        });

        expect(second).toEqual(first);
        expect(await revocations.isRevoked(first.tokenId)).toBe(true);
        expect(await revocations.isRevoked('urn:cap:missing')).toBe(false);

        const listed = await revocations.getRevocations(
            new Date(
                new Date(first.revokedAt).getTime() - 1000,
            ).toISOString() as Timestamp,
        );
        expect(listed).toHaveLength(1);
        expect(listed[0]).toEqual(first);
    });
});

describe('RevocationList cache', () => {
    it('reuses cached lookup results within the TTL window', async () => {
        let now = 1_000;
        const query = vi.fn(() =>
            Promise.resolve({
                rows: [{ exists: false }],
                rowCount: 1,
            }),
        );

        const revocations = new RevocationList({ query } as never, {
            cacheTtlMs: 500,
            now: () => now,
        });

        await expect(revocations.isRevoked('urn:cap:cache-test')).resolves.toBe(
            false,
        );
        await expect(revocations.isRevoked('urn:cap:cache-test')).resolves.toBe(
            false,
        );
        expect(query).toHaveBeenCalledTimes(1);

        now = 1_501;

        await expect(revocations.isRevoked('urn:cap:cache-test')).resolves.toBe(
            false,
        );
        expect(query).toHaveBeenCalledTimes(2);
    });
});
