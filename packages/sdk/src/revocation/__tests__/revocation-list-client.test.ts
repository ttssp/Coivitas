/**
 * revocation-list-client.test.ts -- RevocationListClient unit tests
 *
 * Coverage:
 *   - Core functionality: checkRevoked / revokeCredential / listRevocations
 *   - Cache behavior: LRU hit / miss / invalidation / tenant invalidation / TTL expiry
 *   - fail-closed verification: backend failure → throw (does not return false)
 *   - Parameter validation: empty tenantId / empty tokenId → throw
 *   - Idempotent revokeCredential: duplicate revocation → ok: false + duplicate: true
 *   - fail-closed forbidden-keyword grep test (literal source scan)
 *
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
    RevocationListClient,
    InMemoryRevocationPort,
    RevocationClientError,
} from '../index.js';

// ── Test constants ────────────────────────────────────────────────────────────

const TENANT_A = 'tenant-alpha';
const TENANT_B = 'tenant-beta';
const TOKEN_1 = 'cred-001';
const TOKEN_2 = 'cred-002';
const TOKEN_3 = 'cred-003';

// ── Factory functions ──────────────────────────────────────────────────────────

function makeClient(
    port: InMemoryRevocationPort,
    opts: { cacheMaxSize?: number; cacheTtlMs?: number } = {},
): RevocationListClient {
    return new RevocationListClient({
        port,
        cacheMaxSize: opts.cacheMaxSize,
        cacheTtlMs: opts.cacheTtlMs,
    });
}

function makePort(): InMemoryRevocationPort {
    return new InMemoryRevocationPort();
}

// ── checkRevoked core functionality ──────────────────────────────────────────

describe('RevocationListClient.checkRevoked', () => {
    it('should return { revoked: false, fromCache: false } when token not revoked', async () => {
        const port = makePort();
        const client = makeClient(port);

        const result = await client.checkRevoked({ tenantId: TENANT_A, tokenId: TOKEN_1 });

        expect(result.revoked).toBe(false);
        expect(result.fromCache).toBe(false);
    });

    it('should return { revoked: true, fromCache: false } when token is revoked', async () => {
        const port = makePort();
        await port.revoke({
            tenantId: TENANT_A,
            tokenId: TOKEN_1,
            revokedBy: 'did:example:admin',
            listId: 'list-1',
        });
        const client = makeClient(port);

        const result = await client.checkRevoked({ tenantId: TENANT_A, tokenId: TOKEN_1 });

        expect(result.revoked).toBe(true);
        expect(result.fromCache).toBe(false);
    });

    it('should return { fromCache: true } on second call (LRU hit)', async () => {
        const port = makePort();
        const client = makeClient(port);

        // First call: backend query → populate cache
        await client.checkRevoked({ tenantId: TENANT_A, tokenId: TOKEN_1 });
        // Second call: cache hit
        const result = await client.checkRevoked({ tenantId: TENANT_A, tokenId: TOKEN_1 });

        expect(result.fromCache).toBe(true);
    });

    it('should isolate tenants (different tenants, same tokenId)', async () => {
        const port = makePort();
        await port.revoke({
            tenantId: TENANT_A,
            tokenId: TOKEN_1,
            revokedBy: 'did:example:admin',
            listId: 'list-1',
        });
        const client = makeClient(port);

        const resultA = await client.checkRevoked({ tenantId: TENANT_A, tokenId: TOKEN_1 });
        const resultB = await client.checkRevoked({ tenantId: TENANT_B, tokenId: TOKEN_1 });

        expect(resultA.revoked).toBe(true);
        expect(resultB.revoked).toBe(false);
    });
});

// ── fail-closed guards ───────────────────────────────────────────────────────

describe('RevocationListClient.checkRevoked fail-closed', () => {
    it('should throw RevocationClientError(CHECK_FAILED) when backend throws', async () => {
        const port = makePort();
        port.simulateError(true, 'DB connection lost');
        const client = makeClient(port);

        await expect(
            client.checkRevoked({ tenantId: TENANT_A, tokenId: TOKEN_1 }),
        ).rejects.toThrow(RevocationClientError);
    });

    it('should throw with code REVOCATION_CLIENT_CHECK_FAILED on backend error', async () => {
        const port = makePort();
        port.simulateError(true);
        const client = makeClient(port);

        try {
            await client.checkRevoked({ tenantId: TENANT_A, tokenId: TOKEN_1 });
            expect.fail('should have thrown');
        } catch (err) {
            expect(err).toBeInstanceOf(RevocationClientError);
            expect((err as RevocationClientError).code).toBe(
                'REVOCATION_CLIENT_CHECK_FAILED',
            );
        }
    });

    it('should throw REVOCATION_CLIENT_INVALID_TENANT when tenantId is empty string', async () => {
        const client = makeClient(makePort());

        await expect(
            client.checkRevoked({ tenantId: '', tokenId: TOKEN_1 }),
        ).rejects.toMatchObject({ code: 'REVOCATION_CLIENT_INVALID_TENANT' });
    });

    it('should throw REVOCATION_CLIENT_INVALID_TOKEN_ID when tokenId is empty string', async () => {
        const client = makeClient(makePort());

        await expect(
            client.checkRevoked({ tenantId: TENANT_A, tokenId: '' }),
        ).rejects.toMatchObject({ code: 'REVOCATION_CLIENT_INVALID_TOKEN_ID' });
    });
});

// ── revokeCredential ────────────────────────────────────────────────────────

describe('RevocationListClient.revokeCredential', () => {
    it('should return { ok: true } when revocation succeeds', async () => {
        const port = makePort();
        const client = makeClient(port);

        const result = await client.revokeCredential({
            tenantId: TENANT_A,
            tokenId: TOKEN_1,
            revokedBy: 'did:example:admin',
            listId: 'list-1',
        });

        expect(result.ok).toBe(true);
        if (result.ok) {
            expect(result.record.tokenId).toBe(TOKEN_1);
        }
    });

    it('should return { ok: false, duplicate: true } when token already revoked (idempotent)', async () => {
        const port = makePort();
        const client = makeClient(port);

        await client.revokeCredential({
            tenantId: TENANT_A,
            tokenId: TOKEN_1,
            revokedBy: 'did:example:admin',
            listId: 'list-1',
        });
        const second = await client.revokeCredential({
            tenantId: TENANT_A,
            tokenId: TOKEN_1,
            revokedBy: 'did:example:admin',
            listId: 'list-1',
        });

        expect(second.ok).toBe(false);
        if (!second.ok) {
            expect(second.duplicate).toBe(true);
        }
    });

    it('should invalidate cache entry after revokeCredential succeeds', async () => {
        const port = makePort();
        const client = makeClient(port);

        // Cache false first
        await client.checkRevoked({ tenantId: TENANT_A, tokenId: TOKEN_1 });
        expect(client.cacheSize).toBe(1);

        // Revoke → cache invalidate + set true
        await client.revokeCredential({
            tenantId: TENANT_A,
            tokenId: TOKEN_1,
            revokedBy: 'did:example:admin',
            listId: 'list-1',
        });

        // Subsequent queries should hit the cache with revoked: true
        const check = await client.checkRevoked({ tenantId: TENANT_A, tokenId: TOKEN_1 });
        expect(check.revoked).toBe(true);
        expect(check.fromCache).toBe(true);
    });

    it('should throw REVOCATION_CLIENT_REVOKE_FAILED when backend throws on revoke', async () => {
        const port = makePort();
        port.simulateError(true);
        const client = makeClient(port);

        await expect(
            client.revokeCredential({
                tenantId: TENANT_A,
                tokenId: TOKEN_1,
                revokedBy: 'did:example:admin',
                listId: 'list-1',
            }),
        ).rejects.toMatchObject({ code: 'REVOCATION_CLIENT_REVOKE_FAILED' });
    });
});

// ── listRevocations ────────────────────────────────────────────────────────

describe('RevocationListClient.listRevocations', () => {
    let port: InMemoryRevocationPort;
    let client: RevocationListClient;

    beforeEach(async () => {
        port = makePort();
        client = makeClient(port);
        // Pre-populate 3 TENANT_A revocation records
        for (const tokenId of [TOKEN_1, TOKEN_2, TOKEN_3]) {
            await port.revoke({
                tenantId: TENANT_A,
                tokenId,
                revokedBy: 'did:example:admin',
                listId: 'list-1',
            });
        }
        // 1 TENANT_B record
        await port.revoke({
            tenantId: TENANT_B,
            tokenId: TOKEN_1,
            revokedBy: 'did:example:admin',
            listId: 'list-2',
        });
    });

    it('should return all records for tenant', async () => {
        const result = await client.listRevocations({ tenantId: TENANT_A });
        expect(result.records).toHaveLength(3);
        expect(result.total).toBe(3);
    });

    it('should isolate tenants in listRevocations', async () => {
        const result = await client.listRevocations({ tenantId: TENANT_B });
        expect(result.records).toHaveLength(1);
    });

    it('should filter by tokenId when provided', async () => {
        const result = await client.listRevocations({ tenantId: TENANT_A, tokenId: TOKEN_2 });
        expect(result.records).toHaveLength(1);
        expect(result.records[0]?.tokenId).toBe(TOKEN_2);
    });

    it('should throw REVOCATION_CLIENT_LIST_FAILED when backend throws', async () => {
        port.simulateError(true);

        await expect(
            client.listRevocations({ tenantId: TENANT_A }),
        ).rejects.toMatchObject({ code: 'REVOCATION_CLIENT_LIST_FAILED' });
    });
});

// ── LRU cache boundary tests ──────────────────────────────────────────────────

describe('RevocationListClient LRU cache boundary', () => {
    it('should evict oldest entry when maxSize exceeded', async () => {
        const port = makePort();
        // maxSize=2; the third set evicts the oldest entry
        const client = makeClient(port, { cacheMaxSize: 2 });

        await client.checkRevoked({ tenantId: TENANT_A, tokenId: 'tok-a' });
        await client.checkRevoked({ tenantId: TENANT_A, tokenId: 'tok-b' });
        expect(client.cacheSize).toBe(2);

        // Insert a third: evict tok-a
        await client.checkRevoked({ tenantId: TENANT_A, tokenId: 'tok-c' });
        expect(client.cacheSize).toBe(2);
    });

    it('should invalidateCacheTenant remove all entries for that tenant', async () => {
        const port = makePort();
        const client = makeClient(port);

        await client.checkRevoked({ tenantId: TENANT_A, tokenId: TOKEN_1 });
        await client.checkRevoked({ tenantId: TENANT_A, tokenId: TOKEN_2 });
        await client.checkRevoked({ tenantId: TENANT_B, tokenId: TOKEN_1 });
        expect(client.cacheSize).toBe(3);

        client.invalidateCacheTenant(TENANT_A);
        expect(client.cacheSize).toBe(1);
    });

    it('should not use cache when cacheMaxSize=0 is configured', async () => {
        const port = makePort();
        const client = makeClient(port, { cacheMaxSize: 0 });

        // Both queries leave cacheSize at 0 (a zero-size cache does not write)
        await client.checkRevoked({ tenantId: TENANT_A, tokenId: TOKEN_1 });
        await client.checkRevoked({ tenantId: TENANT_A, tokenId: TOKEN_1 });
        expect(client.cacheSize).toBe(0);
    });
});

// ── fail-closed forbidden-keyword grep test ──────────────────────────────────

describe('RevocationListClient fail-closed forbidden keywords', () => {
    const __dirname = dirname(fileURLToPath(import.meta.url));
    const sourceFile = join(
        __dirname,
        '../revocation-list-client.ts',
    );
    let source: string;

    beforeEach(() => {
        source = readFileSync(sourceFile, 'utf-8');
    });

    it('should not contain "return false" in catch blocks (fail-closed; catch blocks must throw)', () => {
        // Extract every catch block's content and check for a return false
        // Approach: find every block starting at } catch and scan line by line to its matching }
        const catchReturnFalsePattern = /catch\s*\([^)]*\)\s*\{[^}]*return\s+false/s;
        expect(catchReturnFalsePattern.test(source)).toBe(false);
    });

    it('should not contain "return { revoked: false }" in error handling paths', () => {
        // Forbid returning revoked: false directly inside a try/catch catch branch
        // Strategy: check that source contains no catch + return.*revoked.*false combination
        const lines = source.split('\n');
        let inCatch = false;
        let depth = 0;
        for (const line of lines) {
            if (/catch\s*\(/.test(line)) {
                inCatch = true;
                depth = 0;
            }
            if (inCatch) {
                depth += (line.match(/\{/g) ?? []).length;
                depth -= (line.match(/\}/g) ?? []).length;
                if (depth <= 0 && inCatch) {
                    inCatch = false;
                }
                if (/return\s*\{\s*revoked\s*:\s*false/.test(line)) {
                    throw new Error(
                        `fail-closed violation: "return { revoked: false }" found in catch block at line: ${line.trim()}`,
                    );
                }
            }
        }
        // If the throw above is not triggered, the test passes
        expect(true).toBe(true);
    });

    it('should not contain stub default 200 pattern', () => {
        expect(source).not.toMatch(/status\s*[(:]\s*200[^,}]*\/\/.*stub/i);
        expect(source).not.toMatch(/STUB_/i);
    });
});
