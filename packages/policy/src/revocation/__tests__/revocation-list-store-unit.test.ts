/**
 * revocation-list-store-unit.test.ts -- RevocationListStore unit tests
 *
 * Coverage:
 *   - _revokeWithClient catch block: PostgreSQL UNIQUE violation (23505)
 *     → REVOCATION_LIST_VERSION_CONFLICT (constraint includes list_version)
 *   - 23505 but constraint does not include list_version → REVOCATION_STORE_ERROR
 *   - non-23505 DB error → REVOCATION_STORE_ERROR
 *   - revoke() missing-parameter validation (REVOCATION_INVALID_PARAMS)
 *   - revoke() invalid reason validation (REVOCATION_INVALID_PARAMS)
 *
 * Note: this file uses a mock Pool and does not depend on a real PostgreSQL.
 *
 */

import { describe, expect, it, vi, beforeEach, type Mock } from 'vitest';
import type { Pool, PoolClient } from 'pg';
import { RevocationListStore } from '../revocation-list-store.js';

// ---------------------------------------------------------------------------
// Mock Pool + PoolClient factory
// ---------------------------------------------------------------------------

function makeMockClient(overrides?: {
    queryImpl?: Mock;
}): { client: PoolClient; queryMock: Mock } {
    const queryMock: Mock = overrides?.queryImpl ?? vi.fn();
    const client = {
        query: queryMock,
        release: vi.fn(),
    } as unknown as PoolClient;
    return { client, queryMock };
}

function makeMockPool(client: PoolClient): Pool {
    return {
        connect: vi.fn().mockResolvedValue(client),
        query: vi.fn(),
    } as unknown as Pool;
}

// ---------------------------------------------------------------------------
// Valid RevocationWriteInput (minimal required set)
// ---------------------------------------------------------------------------

const VALID_INPUT = {
    tenantId: 'tenant-a',
    tokenId: 'token-abc',
    revokedBy: 'did:ap:admin-001',
    listId: 'list-001',
    reason: 'KEY_COMPROMISE',
} as const;

// ---------------------------------------------------------------------------
// F1: _revokeWithClient catch block — REVOCATION_LIST_VERSION_CONFLICT
// ---------------------------------------------------------------------------

describe('RevocationListStore._revokeWithClient (catch block)', () => {
    let store: RevocationListStore;

    beforeEach(() => {
        vi.resetAllMocks();
    });

    it('should return REVOCATION_LIST_VERSION_CONFLICT when PostgreSQL 23505 with list_version constraint', async () => {
        // Simulate: BEGIN OK, getNextListVersion OK, dup-check OK, INSERT throws UNIQUE violation
        const pgUniqueError = Object.assign(new Error('duplicate key value violates unique constraint'), {
            code: '23505',
            constraint: 'uniq_revocation_records_list_version',
        });

        const { client, queryMock } = makeMockClient();
        // BEGIN → ok
        queryMock.mockResolvedValueOnce({ rows: [], rowCount: 0 });
        // SELECT COALESCE(MAX) FOR UPDATE → next_version=1
        queryMock.mockResolvedValueOnce({ rows: [{ next_version: '1' }], rowCount: 1 });
        // dup-check SELECT → no duplicate
        queryMock.mockResolvedValueOnce({ rows: [], rowCount: 0 });
        // INSERT → UNIQUE violation throw
        queryMock.mockRejectedValueOnce(pgUniqueError);
        // ROLLBACK → ok
        queryMock.mockResolvedValueOnce({ rows: [], rowCount: 0 });

        const pool = makeMockPool(client);
        store = new RevocationListStore({ pool });

        const result = await store.revoke(VALID_INPUT);
        expect(result.ok).toBe(false);
        if (!result.ok) {
            expect(result.code).toBe('REVOCATION_LIST_VERSION_CONFLICT');
            expect(result.message).toContain('uniq_revocation_records_list_version');
        }
    });

    it('should return REVOCATION_STORE_ERROR when PostgreSQL 23505 but constraint does NOT include list_version', async () => {
        // Simulate: UNIQUE violation but the constraint is token_id UNIQUE (does not include list_version)
        const pgUniqueError = Object.assign(new Error('duplicate key value violates unique constraint'), {
            code: '23505',
            constraint: 'uniq_revocation_records_token_id',
        });

        const { client, queryMock } = makeMockClient();
        queryMock.mockResolvedValueOnce({ rows: [], rowCount: 0 }); // BEGIN
        queryMock.mockResolvedValueOnce({ rows: [{ next_version: '1' }], rowCount: 1 }); // getNext
        queryMock.mockResolvedValueOnce({ rows: [], rowCount: 0 }); // dup-check
        queryMock.mockRejectedValueOnce(pgUniqueError); // INSERT violation
        queryMock.mockResolvedValueOnce({ rows: [], rowCount: 0 }); // ROLLBACK

        const pool = makeMockPool(client);
        store = new RevocationListStore({ pool });

        const result = await store.revoke(VALID_INPUT);
        expect(result.ok).toBe(false);
        if (!result.ok) {
            expect(result.code).toBe('REVOCATION_STORE_ERROR');
        }
    });

    it('should return REVOCATION_STORE_ERROR when PostgreSQL error code is NOT 23505', async () => {
        // Simulate: connection timeout or a generic DB error (code != 23505)
        const pgGenericError = Object.assign(new Error('connection timeout'), {
            code: '08006',
        });

        const { client, queryMock } = makeMockClient();
        queryMock.mockResolvedValueOnce({ rows: [], rowCount: 0 }); // BEGIN
        queryMock.mockRejectedValueOnce(pgGenericError); // getNextListVersion fails
        queryMock.mockResolvedValueOnce({ rows: [], rowCount: 0 }); // ROLLBACK

        const pool = makeMockPool(client);
        store = new RevocationListStore({ pool });

        const result = await store.revoke(VALID_INPUT);
        expect(result.ok).toBe(false);
        if (!result.ok) {
            expect(result.code).toBe('REVOCATION_STORE_ERROR');
        }
    });

    it('should return REVOCATION_STORE_ERROR when error has no code property', async () => {
        // Simulate: a plain JS Error (no pg error code)
        const plainError = new Error('unexpected failure');

        const { client, queryMock } = makeMockClient();
        queryMock.mockResolvedValueOnce({ rows: [], rowCount: 0 }); // BEGIN
        queryMock.mockResolvedValueOnce({ rows: [{ next_version: '1' }], rowCount: 1 }); // getNext
        queryMock.mockRejectedValueOnce(plainError); // dup-check fails
        queryMock.mockResolvedValueOnce({ rows: [], rowCount: 0 }); // ROLLBACK

        const pool = makeMockPool(client);
        store = new RevocationListStore({ pool });

        const result = await store.revoke(VALID_INPUT);
        expect(result.ok).toBe(false);
        if (!result.ok) {
            expect(result.code).toBe('REVOCATION_STORE_ERROR');
        }
    });
});

// ---------------------------------------------------------------------------
// revoke() parameter validation (REVOCATION_INVALID_PARAMS)
// ---------------------------------------------------------------------------

describe('RevocationListStore.revoke() param validation', () => {
    let store: RevocationListStore;

    beforeEach(() => {
        vi.resetAllMocks();
        const { client } = makeMockClient();
        const pool = makeMockPool(client);
        store = new RevocationListStore({ pool });
    });

    it('should return REVOCATION_INVALID_PARAMS when tenantId is empty', async () => {
        const result = await store.revoke({ ...VALID_INPUT, tenantId: '' });
        expect(result.ok).toBe(false);
        if (!result.ok) {
            expect(result.code).toBe('REVOCATION_INVALID_PARAMS');
        }
    });

    it('should return REVOCATION_INVALID_PARAMS when tokenId is empty', async () => {
        const result = await store.revoke({ ...VALID_INPUT, tokenId: '' });
        expect(result.ok).toBe(false);
        if (!result.ok) {
            expect(result.code).toBe('REVOCATION_INVALID_PARAMS');
        }
    });

    it('should return REVOCATION_INVALID_PARAMS when revokedBy is empty', async () => {
        const result = await store.revoke({ ...VALID_INPUT, revokedBy: '' });
        expect(result.ok).toBe(false);
        if (!result.ok) {
            expect(result.code).toBe('REVOCATION_INVALID_PARAMS');
        }
    });

    it('should return REVOCATION_INVALID_PARAMS when listId is empty', async () => {
        const result = await store.revoke({ ...VALID_INPUT, listId: '' });
        expect(result.ok).toBe(false);
        if (!result.ok) {
            expect(result.code).toBe('REVOCATION_INVALID_PARAMS');
        }
    });

    it('should return REVOCATION_INVALID_PARAMS when reason is invalid', async () => {
        const result = await store.revoke({
            ...VALID_INPUT,
            reason: 'INVALID_REASON' as unknown as 'KEY_COMPROMISE',
        });
        expect(result.ok).toBe(false);
        if (!result.ok) {
            expect(result.code).toBe('REVOCATION_INVALID_PARAMS');
            expect(result.message).toContain('Invalid reason');
        }
    });
});
