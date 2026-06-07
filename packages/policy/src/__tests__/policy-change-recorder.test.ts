/**
 * policy-change-recorder.test.ts
 *
 * Test goal: the PolicyChangeRecorder middleware (packages/policy/src/middleware/policy-change-recorder.ts)
 *
 * Coverage strategy:
 * - unit tests (mock DB): cover the hash chain, signatures, fail-closed, lane bypass and other logic branches
 * - integration tests (DATABASE_URL gated): cover real DB transaction atomicity (strategy 3, 4, 5)
 *
 * 5 core integration-test scenarios (the dedicated policy_change_records table is separate from the action-record track):
 * 1. POLICY_CREATED auto-record written to the dedicated policy_change_records table
 * 2. POLICY_UPDATED auto-record written to the dedicated policy_change_records table
 * 3. POLICY_REVOKED auto-record written to the dedicated policy_change_records table
 * 4. wrapOperation: policy operation fails → audit record is not written (ROLLBACK)
 * 5. wrapOperation: hash chain continuity verification (prev_row_hash links correctly)
 */

import {
    afterAll,
    beforeAll,
    describe,
    expect,
    it,
    vi,
} from 'vitest';

import { generateKeyPair } from '@coivitas/crypto';
import { createTestDatabase } from '@coivitas/shared';
import type { DID, Timestamp } from '@coivitas/types';
import {
    ACTION_POLICY_CREATED,
    ACTION_POLICY_REVOKED,
    ACTION_POLICY_UPDATED,
    isPolicyActionType,
    isPolicyChangeParams,
    POLICY_ACTION_TYPES,
} from '@coivitas/types';

import { PolicyChangeRecorder } from '../middleware/policy-change-recorder.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeTimestamp(offset = 0): Timestamp {
    return new Date(Date.now() + offset).toISOString() as Timestamp;
}

function makeLedgerKey(): string {
    return generateKeyPair().privateKey.slice(0, 64);
}

function makeActorKey(): string {
    return generateKeyPair().privateKey.slice(0, 64);
}

function makeAgentDid(): DID {
    return `did:agent:${'a'.repeat(40)}` as DID;
}

function makePrincipalDid(): DID {
    return `did:key:zTest${Math.random().toString(36).slice(2)}` as DID;
}

// ---------------------------------------------------------------------------
// Unit tests (mock DB)
// ---------------------------------------------------------------------------

describe('PolicyChangeRecorder unit tests', () => {
    const ledgerKey = makeLedgerKey();
    const actorKey = makeActorKey();
    const agentDid = makeAgentDid();
    const principalDid = makePrincipalDid();

    function makeMockPool(rows: Record<string, unknown>[] = []) {
        return {
            query: vi.fn().mockResolvedValue({ rows }),
            connect: vi.fn().mockResolvedValue({
                query: vi.fn().mockResolvedValue({ rows }),
                release: vi.fn(),
            }),
        } as unknown as import('@coivitas/shared').DatabasePool;
    }

    it('should throw when LEDGER_PRIVATE_KEY is missing', () => {
        const pool = makeMockPool();
        expect(
            () => new PolicyChangeRecorder(pool, ''),
        ).toThrow('LEDGER_PRIVATE_KEY is required');
    });

    // -------------------------------------------------------------------------
    // Constructor fail-closed validation of the LEDGER_PRIVATE_KEY format
    // -------------------------------------------------------------------------

    it('should throw in constructor when LEDGER_PRIVATE_KEY is invalid hex', () => {
        const pool = makeMockPool();
        // 64 characters but containing non-hex characters ('g', 'z', etc. are invalid)
        const invalidHexKey = 'g'.repeat(64);
        expect(
            () => new PolicyChangeRecorder(pool, invalidHexKey),
        ).toThrow('LEDGER_PRIVATE_KEY is invalid');
    });

    it('should throw in constructor when LEDGER_PRIVATE_KEY has wrong length', () => {
        const pool = makeMockPool();
        // 32 valid hex characters (= 16 bytes), neither 64 nor 128 characters
        const wrongLengthKey = 'ab'.repeat(16); // 32 chars
        expect(
            () => new PolicyChangeRecorder(pool, wrongLengthKey),
        ).toThrow('LEDGER_PRIVATE_KEY is invalid');
    });

    it('should throw in constructor when LEDGER_PRIVATE_KEY is 63 chars (off-by-one)', () => {
        const pool = makeMockPool();
        // 63 valid hex characters (one short of 64)
        const offByOneKey = 'ab'.repeat(31) + 'a'; // 63 chars
        expect(
            () => new PolicyChangeRecorder(pool, offByOneKey),
        ).toThrow('LEDGER_PRIVATE_KEY is invalid');
    });

    it('should fall back to process.env.LEDGER_PRIVATE_KEY when ledgerPrivateKey arg is undefined', () => {
        const pool = makeMockPool();
        const envKey = makeLedgerKey();
        const originalEnv = process.env.LEDGER_PRIVATE_KEY;
        try {
            process.env.LEDGER_PRIVATE_KEY = envKey;
            // Omit the ledgerPrivateKey argument to trigger the env var branch
            const recorder = new PolicyChangeRecorder(pool);
            expect(recorder.ledgerPublicKey).toHaveLength(64);
        } finally {
            process.env.LEDGER_PRIVATE_KEY = originalEnv;
        }
    });

    it('should expose ledgerPublicKey derived from ledgerPrivateKey', () => {
        const pool = makeMockPool();
        const recorder = new PolicyChangeRecorder(pool, ledgerKey);
        // 64-char hex seed → 128-char expanded → last 64 = publicKey (hex)
        expect(recorder.ledgerPublicKey).toHaveLength(64);
        expect(recorder.ledgerPublicKey).toMatch(/^[0-9a-f]{64}$/);
    });

    it('should throw when params.changeType does not match recordCreated', async () => {
        const pool = makeMockPool();
        const recorder = new PolicyChangeRecorder(pool, ledgerKey);
        const mockClient = {
            query: vi.fn().mockResolvedValue({ rows: [] }),
        } as unknown as import('pg').PoolClient;

        await expect(
            recorder.recordCreated(mockClient, {
                agentDid,
                principalDid,
                params: {
                    policyId: 'policy-001',
                    policyVersion: 1,
                    changeType: 'UPDATED', // intentionally wrong
                },
                actorPrivateKey: actorKey,
            }),
        ).rejects.toThrow("does not match actionType='POLICY_CREATED'");
    });

    it('should throw when params.changeType does not match recordUpdated', async () => {
        const pool = makeMockPool();
        const recorder = new PolicyChangeRecorder(pool, ledgerKey);
        const mockClient = {
            query: vi.fn().mockResolvedValue({ rows: [] }),
        } as unknown as import('pg').PoolClient;

        await expect(
            recorder.recordUpdated(mockClient, {
                agentDid,
                principalDid,
                params: {
                    policyId: 'policy-001',
                    policyVersion: 2,
                    changeType: 'CREATED', // intentionally wrong
                },
                actorPrivateKey: actorKey,
            }),
        ).rejects.toThrow("does not match actionType='POLICY_UPDATED'");
    });

    it('should throw when params.changeType does not match recordRevoked', async () => {
        const pool = makeMockPool();
        const recorder = new PolicyChangeRecorder(pool, ledgerKey);
        const mockClient = {
            query: vi.fn().mockResolvedValue({ rows: [] }),
        } as unknown as import('pg').PoolClient;

        await expect(
            recorder.recordRevoked(mockClient, {
                agentDid,
                principalDid,
                params: {
                    policyId: 'policy-001',
                    policyVersion: 1,
                    changeType: 'UPDATED', // intentionally wrong
                },
                actorPrivateKey: actorKey,
            }),
        ).rejects.toThrow("does not match actionType='POLICY_REVOKED'");
    });

    it('should throw in wrapOperation when actionType is not a POLICY_ACTION_TYPE', async () => {
        const pool = makeMockPool();
        const recorder = new PolicyChangeRecorder(pool, ledgerKey);

        await expect(
            recorder.wrapOperation(
                'policy-001',
                'UNKNOWN_TYPE' as import('@coivitas/types').PolicyActionType,
                {
                    agentDid,
                    principalDid,
                    actorPrivateKey: actorKey,
                    policyVersion: 1,
                    operation: () => Promise.resolve('result'),
                },
            ),
        ).rejects.toThrow("unknown actionType='UNKNOWN_TYPE'");
    });

    it('should execute wrapOperation with revokedAt and return operation result', async () => {
        // Build a mock client that handles BEGIN/COMMIT + 3 functional queries
        const mockQueryFn = vi
            .fn()
            .mockResolvedValue({ rows: [] }); // BEGIN, lock, load, INSERT, COMMIT all ok

        const mockClient = {
            query: mockQueryFn,
            release: vi.fn(),
        };

        const pool = {
            connect: vi.fn().mockResolvedValue(mockClient),
        } as unknown as import('@coivitas/shared').DatabasePool;

        const recorder = new PolicyChangeRecorder(pool, ledgerKey);
        const revokedAt = makeTimestamp();

        const result = await recorder.wrapOperation(
            'policy-revoke-wrap',
            ACTION_POLICY_REVOKED,
            {
                agentDid,
                principalDid,
                actorPrivateKey: actorKey,
                policyVersion: 5,
                revokedAt,
                operation: () => Promise.resolve('revoked-ok'),
            },
        );

        expect(result).toBe('revoked-ok');
        // BEGIN + lock + load + INSERT + COMMIT = 5 query calls
        expect(mockQueryFn).toHaveBeenCalledTimes(5);

        // The INSERT args contain POLICY_REVOKED
        const insertCall = mockQueryFn.mock.calls[3]!;
        expect(insertCall[1]).toContain('POLICY_REVOKED');
    });

    it('should execute wrapOperation with changedFields (POLICY_UPDATED)', async () => {
        const mockQueryFn = vi
            .fn()
            .mockResolvedValue({ rows: [] });

        const mockClient = {
            query: mockQueryFn,
            release: vi.fn(),
        };

        const pool = {
            connect: vi.fn().mockResolvedValue(mockClient),
        } as unknown as import('@coivitas/shared').DatabasePool;

        const recorder = new PolicyChangeRecorder(pool, ledgerKey);

        const result = await recorder.wrapOperation(
            'policy-update-wrap',
            ACTION_POLICY_UPDATED,
            {
                agentDid,
                principalDid,
                actorPrivateKey: actorKey,
                policyVersion: 3,
                changedFields: ['scope', 'ttl'],
                operation: () => Promise.resolve({ updated: true }),
            },
        );

        expect(result).toEqual({ updated: true });
        expect(mockQueryFn).toHaveBeenCalledTimes(5); // BEGIN + 3 func + COMMIT
        // INSERT args contain POLICY_UPDATED
        expect(mockQueryFn.mock.calls[3]![1]).toContain('POLICY_UPDATED');
    });

    it('should call SAVEPOINT then lockAgentChain and loadPreviousHash before INSERT on recordCreated', async () => {
        const mockQueryFn = vi
            .fn()
            .mockResolvedValueOnce({ rows: [] }) // SAVEPOINT
            .mockResolvedValueOnce({ rows: [] }) // lockAgentChain
            .mockResolvedValueOnce({ rows: [] }) // loadPreviousRecordHash (empty chain)
            .mockResolvedValueOnce({ rows: [] }); // INSERT

        const mockClient = {
            query: mockQueryFn,
        } as unknown as import('pg').PoolClient;

        const pool = makeMockPool();
        const recorder = new PolicyChangeRecorder(pool, ledgerKey);

        const result = await recorder.recordCreated(mockClient, {
            agentDid,
            principalDid,
            params: {
                policyId: 'policy-001',
                policyVersion: 1,
                changeType: 'CREATED',
            },
            actorPrivateKey: actorKey,
        });

        // 4 query calls (SAVEPOINT + lock + load + INSERT)
        expect(mockQueryFn).toHaveBeenCalledTimes(4);

        // Call 1: SAVEPOINT (DB-level transaction enforcement)
        expect(mockQueryFn.mock.calls[0]![0]).toContain('SAVEPOINT');
        // Call 2: pg_advisory_xact_lock
        expect(mockQueryFn.mock.calls[1]![0]).toContain(
            'pg_advisory_xact_lock',
        );
        // Call 3: SELECT row_hash (load previous hash from policy_change_records)
        expect(mockQueryFn.mock.calls[2]![0]).toContain('row_hash');
        // Call 4: INSERT INTO policy.policy_change_records (dedicated table)
        expect(mockQueryFn.mock.calls[3]![0]).toContain(
            'policy.policy_change_records',
        );

        // INSERT args: action_type = 'POLICY_CREATED'
        expect(mockQueryFn.mock.calls[3]![1]).toContain('POLICY_CREATED');

        // Returns recordId (UUID) + hash (base64url or hex)
        expect(result.recordId).toMatch(
            /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
        );
        expect(result.hash.length).toBeGreaterThan(0);
    });

    it('should use previousRecordHash from DB in hash chain when chain is non-empty', async () => {
        const previousHash = 'a'.repeat(43); // base64url style hash
        const mockQueryFn = vi
            .fn()
            .mockResolvedValueOnce({ rows: [] }) // SAVEPOINT
            .mockResolvedValueOnce({ rows: [] }) // lockAgentChain
            .mockResolvedValueOnce({
                rows: [{ row_hash: previousHash }],
            }) // loadPreviousRowHash (policy_change_records.row_hash)
            .mockResolvedValueOnce({ rows: [] }); // INSERT

        const mockClient = {
            query: mockQueryFn,
        } as unknown as import('pg').PoolClient;

        const pool = makeMockPool();
        const recorder = new PolicyChangeRecorder(pool, ledgerKey);

        const result = await recorder.recordUpdated(mockClient, {
            agentDid,
            principalDid,
            params: {
                policyId: 'policy-001',
                policyVersion: 2,
                changeType: 'UPDATED',
                changedFields: ['scope'],
            },
            actorPrivateKey: actorKey,
        });

        // In the INSERT args, prev_row_hash ($7) should equal previousHash
        // Note: calls[3] is the INSERT (calls[0]=SAVEPOINT, [1]=lock, [2]=load, [3]=INSERT)
        const insertArgs = mockQueryFn.mock.calls[3]![1] as unknown[];
        expect(insertArgs[6]).toBe(previousHash); // $7 = prev_row_hash (index 6)

        // The returned hash should not equal previousHash (showing the hash chain advanced)
        expect(result.hash).not.toBe(previousHash);
    });

    it('should propagate DB error from INSERT (fail-closed)', async () => {
        const mockQueryFn = vi
            .fn()
            .mockResolvedValueOnce({ rows: [] }) // SAVEPOINT
            .mockResolvedValueOnce({ rows: [] }) // lockAgentChain
            .mockResolvedValueOnce({ rows: [] }) // loadPreviousHash
            .mockRejectedValueOnce(new Error('DB INSERT failed')); // INSERT fail

        const mockClient = {
            query: mockQueryFn,
        } as unknown as import('pg').PoolClient;

        const pool = makeMockPool();
        const recorder = new PolicyChangeRecorder(pool, ledgerKey);

        await expect(
            recorder.recordRevoked(mockClient, {
                agentDid,
                principalDid,
                params: {
                    policyId: 'policy-001',
                    policyVersion: 1,
                    changeType: 'REVOKED',
                    revokedAt: makeTimestamp(),
                },
                actorPrivateKey: actorKey,
            }),
        ).rejects.toThrow('DB INSERT failed');
    });

    it('should use custom recordId when provided', async () => {
        const customRecordId = '12345678-1234-4123-8123-123456789abc';
        const mockQueryFn = vi
            .fn()
            .mockResolvedValueOnce({ rows: [] }) // SAVEPOINT
            .mockResolvedValueOnce({ rows: [] }) // lockAgentChain
            .mockResolvedValueOnce({ rows: [] }) // loadPreviousHash
            .mockResolvedValueOnce({ rows: [] }); // INSERT

        const mockClient = {
            query: mockQueryFn,
        } as unknown as import('pg').PoolClient;

        const pool = makeMockPool();
        const recorder = new PolicyChangeRecorder(pool, ledgerKey);

        const result = await recorder.recordCreated(mockClient, {
            agentDid,
            principalDid,
            params: {
                policyId: 'policy-001',
                policyVersion: 1,
                changeType: 'CREATED',
            },
            actorPrivateKey: actorKey,
            recordId: customRecordId,
        });

        expect(result.recordId).toBe(customRecordId);
        // INSERT $1 = recordId (calls[3] because calls[0]=SAVEPOINT, [1]=lock, [2]=load, [3]=INSERT)
        const insertArgs = mockQueryFn.mock.calls[3]![1] as unknown[];
        expect(insertArgs[0]).toBe(customRecordId);
    });

    // -------------------------------------------------------------------------
    // AJV fail-closed validation before DB write
    // Verify that validateAgainstSchema('policyChangeParams') is called on all write paths

    // record* methods issue a SAVEPOINT (1 DB call) before writeWithinTransaction;
    // AJV validation happens after SAVEPOINT (inside writeWithinTransaction), so:
    // - lock / load / INSERT should not be called (AJV throws before those 3 DB operations)
    // - SAVEPOINT will be called (once)
    // -------------------------------------------------------------------------

    it('should throw before lock/load/INSERT when policyId is empty string (F2 fail-closed)', async () => {
        const pool = makeMockPool();
        const recorder = new PolicyChangeRecorder(pool, ledgerKey);
        const mockClient = {
            query: vi.fn().mockResolvedValue({ rows: [] }), // SAVEPOINT will be called, then AJV throws
        } as unknown as import('pg').PoolClient;

        await expect(
            recorder.recordCreated(mockClient, {
                agentDid,
                principalDid,
                params: {
                    policyId: '',  // violates minLength: 1
                    policyVersion: 1,
                    changeType: 'CREATED',
                },
                actorPrivateKey: actorKey,
            }),
        ).rejects.toThrow();

        // SAVEPOINT already called (once); lock/load/INSERT should not be called (AJV throws before them)
        const mockClientTyped = mockClient as { query: ReturnType<typeof vi.fn> };
        expect(mockClientTyped.query).toHaveBeenCalledTimes(1);
        expect(mockClientTyped.query.mock.calls[0]![0]).toContain('SAVEPOINT');
    });

    it('should throw before lock/load/INSERT when policyVersion is 0 (F2 fail-closed)', async () => {
        const pool = makeMockPool();
        const recorder = new PolicyChangeRecorder(pool, ledgerKey);
        const mockClient = {
            query: vi.fn().mockResolvedValue({ rows: [] }),
        } as unknown as import('pg').PoolClient;

        await expect(
            recorder.recordUpdated(mockClient, {
                agentDid,
                principalDid,
                params: {
                    policyId: 'policy-001',
                    policyVersion: 0,  // violates minimum: 1
                    changeType: 'UPDATED',
                },
                actorPrivateKey: actorKey,
            }),
        ).rejects.toThrow();

        const mockClientTyped = mockClient as { query: ReturnType<typeof vi.fn> };
        expect(mockClientTyped.query).toHaveBeenCalledTimes(1);
        expect(mockClientTyped.query.mock.calls[0]![0]).toContain('SAVEPOINT');
    });

    it('should throw before lock/load/INSERT when POLICY_REVOKED has changedFields (F2 allOf constraint)', async () => {
        const pool = makeMockPool();
        const recorder = new PolicyChangeRecorder(pool, ledgerKey);
        const mockClient = {
            query: vi.fn().mockResolvedValue({ rows: [] }),
        } as unknown as import('pg').PoolClient;

        await expect(
            recorder.recordRevoked(mockClient, {
                agentDid,
                principalDid,
                params: {
                    policyId: 'policy-001',
                    policyVersion: 3,
                    changeType: 'REVOKED',
                    changedFields: ['scope'],  // REVOKED does not allow changedFields (allOf constraint)
                } as import('@coivitas/types').PolicyChangeParams,
                actorPrivateKey: actorKey,
            }),
        ).rejects.toThrow();

        const mockClientTyped = mockClient as { query: ReturnType<typeof vi.fn> };
        expect(mockClientTyped.query).toHaveBeenCalledTimes(1);
        expect(mockClientTyped.query.mock.calls[0]![0]).toContain('SAVEPOINT');
    });

    it('should throw before lock/load/INSERT when revokedAt has invalid timestamp format (F2 format constraint)', async () => {
        const pool = makeMockPool();
        const recorder = new PolicyChangeRecorder(pool, ledgerKey);
        const mockClient = {
            query: vi.fn().mockResolvedValue({ rows: [] }),
        } as unknown as import('pg').PoolClient;

        await expect(
            recorder.recordRevoked(mockClient, {
                agentDid,
                principalDid,
                params: {
                    policyId: 'policy-001',
                    policyVersion: 3,
                    changeType: 'REVOKED',
                    revokedAt: 'not-a-timestamp' as import('@coivitas/types').Timestamp,
                },
                actorPrivateKey: actorKey,
            }),
        ).rejects.toThrow();

        const mockClientTyped = mockClient as { query: ReturnType<typeof vi.fn> };
        expect(mockClientTyped.query).toHaveBeenCalledTimes(1);
        expect(mockClientTyped.query.mock.calls[0]![0]).toContain('SAVEPOINT');
    });

    it('should throw before DB write in wrapOperation when policyId is empty (F2 wrapOperation path)', async () => {
        // wrapOperation builds params from its own arguments; policyId is passed directly
        // Test: an empty policyId triggers AJV validation failure, aborting before operation
        const pool = makeMockPool();
        const recorder = new PolicyChangeRecorder(pool, ledgerKey);
        const operationFn = vi.fn().mockResolvedValue('result');

        await expect(
            recorder.wrapOperation('', ACTION_POLICY_CREATED, {  // empty policyId
                agentDid,
                principalDid,
                actorPrivateKey: actorKey,
                policyVersion: 1,
                operation: operationFn,
            }),
        ).rejects.toThrow();
    });

    // -------------------------------------------------------------------------
    // wrapOperation pre-operation fail-closed test cases
    // Verify AJV validation runs before operation, so the operation mock should not be called
    // -------------------------------------------------------------------------

    it('should throw before operation runs when policyId is empty in wrapOperation', async () => {
        const pool = makeMockPool();
        const recorder = new PolicyChangeRecorder(pool, ledgerKey);
        const operationFn = vi.fn().mockResolvedValue('result');

        await expect(
            recorder.wrapOperation('', ACTION_POLICY_CREATED, {
                agentDid,
                principalDid,
                actorPrivateKey: actorKey,
                policyVersion: 1,
                operation: operationFn,
            }),
        ).rejects.toThrow();

        // Key assertion: operation should not be called (validation fails outside the transaction, before operation)
        expect(operationFn).not.toHaveBeenCalled();
    });

    it('should throw before operation runs when policyVersion is 0 in wrapOperation', async () => {
        const pool = makeMockPool();
        const recorder = new PolicyChangeRecorder(pool, ledgerKey);
        const operationFn = vi.fn().mockResolvedValue('result');

        await expect(
            recorder.wrapOperation('policy-001', ACTION_POLICY_CREATED, {
                agentDid,
                principalDid,
                actorPrivateKey: actorKey,
                policyVersion: 0,  // violates minimum: 1
                operation: operationFn,
            }),
        ).rejects.toThrow();

        // Validation fails before operation, so operation should not be called
        expect(operationFn).not.toHaveBeenCalled();
    });

    it('should throw before operation runs when POLICY_CREATED has policyVersion != 1 (allOf const constraint)', async () => {
        const pool = makeMockPool();
        const recorder = new PolicyChangeRecorder(pool, ledgerKey);
        const operationFn = vi.fn().mockResolvedValue('result');

        // The allOf constraint for POLICY_CREATED requires policyVersion === 1; passing 2 violates const:1
        await expect(
            recorder.wrapOperation('policy-001', ACTION_POLICY_CREATED, {
                agentDid,
                principalDid,
                actorPrivateKey: actorKey,
                policyVersion: 2,  // CREATED's allOf constraint requires policyVersion === 1
                operation: operationFn,
            }),
        ).rejects.toThrow();

        // Validation fails before operation, so operation should not be called
        expect(operationFn).not.toHaveBeenCalled();
    });

    it('should throw before operation runs when POLICY_REVOKED has changedFields (allOf constraint)', async () => {
        const pool = makeMockPool();
        const recorder = new PolicyChangeRecorder(pool, ledgerKey);
        const operationFn = vi.fn().mockResolvedValue('result');

        // POLICY_REVOKED + changedFields violates the allOf constraint
        await expect(
            recorder.wrapOperation('policy-001', ACTION_POLICY_REVOKED, {
                agentDid,
                principalDid,
                actorPrivateKey: actorKey,
                policyVersion: 3,
                changedFields: ['scope'],  // REVOKED does not allow changedFields
                operation: operationFn,
            }),
        ).rejects.toThrow();

        // Validation fails before operation, so operation should not be called
        expect(operationFn).not.toHaveBeenCalled();
    });

    // -------------------------------------------------------------------------
    // actorPrivateKey format validation — fails before wrapOperation's operation
    // Verify the validatePreOperation gate also validates actorPrivateKey (a pre-check at the same level as params)
    // -------------------------------------------------------------------------

    it('should throw before operation runs when actorPrivateKey is empty string', async () => {
        const pool = makeMockPool();
        const recorder = new PolicyChangeRecorder(pool, ledgerKey);
        const operationFn = vi.fn().mockResolvedValue('result');

        await expect(
            recorder.wrapOperation('policy-001', ACTION_POLICY_CREATED, {
                agentDid,
                principalDid,
                actorPrivateKey: '',  // empty key: invalid format
                policyVersion: 1,
                operation: operationFn,
            }),
        ).rejects.toThrow('actorPrivateKey');

        // Key assertion: operation should not be called (key validation fails before operation)
        expect(operationFn).not.toHaveBeenCalled();
    });

    it('should throw before operation runs when actorPrivateKey has wrong length', async () => {
        const pool = makeMockPool();
        const recorder = new PolicyChangeRecorder(pool, ledgerKey);
        const operationFn = vi.fn().mockResolvedValue('result');

        // 32-char hex (16 bytes), neither 64 nor 128 characters → normalizeSigningPrivateKey throws
        const shortKey = 'ab'.repeat(16); // 32 chars

        await expect(
            recorder.wrapOperation('policy-001', ACTION_POLICY_UPDATED, {
                agentDid,
                principalDid,
                actorPrivateKey: shortKey,
                policyVersion: 2,
                operation: operationFn,
            }),
        ).rejects.toThrow('actorPrivateKey');

        expect(operationFn).not.toHaveBeenCalled();
    });

    it('should throw before operation runs when actorPrivateKey contains non-hex chars', async () => {
        const pool = makeMockPool();
        const recorder = new PolicyChangeRecorder(pool, ledgerKey);
        const operationFn = vi.fn().mockResolvedValue('result');

        // 64 characters but containing non-hex characters ('g', 'z', etc. are invalid)
        const invalidHexKey = 'g'.repeat(64);

        await expect(
            recorder.wrapOperation('policy-001', ACTION_POLICY_REVOKED, {
                agentDid,
                principalDid,
                actorPrivateKey: invalidHexKey,
                policyVersion: 3,
                operation: operationFn,
            }),
        ).rejects.toThrow('actorPrivateKey');

        expect(operationFn).not.toHaveBeenCalled();
    });

    it('should proceed normally when actorPrivateKey is valid 64-char hex (positive case)', async () => {
        const mockQueryFn = vi.fn().mockResolvedValue({ rows: [] });
        const mockClient = { query: mockQueryFn, release: vi.fn() };
        const pool = {
            connect: vi.fn().mockResolvedValue(mockClient),
        } as unknown as import('@coivitas/shared').DatabasePool;

        const recorder = new PolicyChangeRecorder(pool, ledgerKey);
        const operationFn = vi.fn().mockResolvedValue('created-ok');

        const result = await recorder.wrapOperation('policy-001', ACTION_POLICY_CREATED, {
            agentDid,
            principalDid,
            actorPrivateKey: actorKey,  // valid 64-char hex key
            policyVersion: 1,
            operation: operationFn,
        });

        expect(result).toBe('created-ok');
        // operation should be called normally
        expect(operationFn).toHaveBeenCalledOnce();
        // BEGIN + lock + load + INSERT + COMMIT = 5 DB calls
        expect(mockQueryFn).toHaveBeenCalledTimes(5);
    });

    // -------------------------------------------------------------------------
    // SAVEPOINT DB-level transaction enforcement test
    // Verify that the first SQL issued by record* methods is SAVEPOINT (DB-level enforcement that the client is inside a transaction block)
    // -------------------------------------------------------------------------

    it('should issue SAVEPOINT as first DB call in recordCreated', async () => {
        const mockQueryFn = vi
            .fn()
            .mockResolvedValueOnce({ rows: [] }) // SAVEPOINT
            .mockResolvedValueOnce({ rows: [] }) // lock
            .mockResolvedValueOnce({ rows: [] }) // load
            .mockResolvedValueOnce({ rows: [] }); // INSERT

        const mockClient = { query: mockQueryFn } as unknown as import('pg').PoolClient;
        const recorder = new PolicyChangeRecorder(makeMockPool(), ledgerKey);

        await recorder.recordCreated(mockClient, {
            agentDid,
            principalDid,
            params: { policyId: 'p-sp-1', policyVersion: 1, changeType: 'CREATED' },
            actorPrivateKey: actorKey,
        });

        // The first SQL must be SAVEPOINT
        expect(mockQueryFn.mock.calls[0]![0]).toContain('SAVEPOINT');
        expect(mockQueryFn.mock.calls[0]![0]).toContain('policy_change_audit_guard');
        // 4 calls total (SAVEPOINT + lock + load + INSERT)
        expect(mockQueryFn).toHaveBeenCalledTimes(4);
    });

    it('should issue SAVEPOINT as first DB call in recordUpdated', async () => {
        const mockQueryFn = vi
            .fn()
            .mockResolvedValueOnce({ rows: [] }) // SAVEPOINT
            .mockResolvedValueOnce({ rows: [] }) // lock
            .mockResolvedValueOnce({ rows: [] }) // load
            .mockResolvedValueOnce({ rows: [] }); // INSERT

        const mockClient = { query: mockQueryFn } as unknown as import('pg').PoolClient;
        const recorder = new PolicyChangeRecorder(makeMockPool(), ledgerKey);

        await recorder.recordUpdated(mockClient, {
            agentDid,
            principalDid,
            params: { policyId: 'p-sp-2', policyVersion: 2, changeType: 'UPDATED', changedFields: ['ttl'] },
            actorPrivateKey: actorKey,
        });

        expect(mockQueryFn.mock.calls[0]![0]).toContain('SAVEPOINT');
        expect(mockQueryFn.mock.calls[0]![0]).toContain('policy_change_audit_guard');
        expect(mockQueryFn).toHaveBeenCalledTimes(4);
    });

    it('should issue SAVEPOINT as first DB call in recordRevoked', async () => {
        const mockQueryFn = vi
            .fn()
            .mockResolvedValueOnce({ rows: [] }) // SAVEPOINT
            .mockResolvedValueOnce({ rows: [] }) // lock
            .mockResolvedValueOnce({ rows: [] }) // load
            .mockResolvedValueOnce({ rows: [] }); // INSERT

        const mockClient = { query: mockQueryFn } as unknown as import('pg').PoolClient;
        const recorder = new PolicyChangeRecorder(makeMockPool(), ledgerKey);

        await recorder.recordRevoked(mockClient, {
            agentDid,
            principalDid,
            params: { policyId: 'p-sp-3', policyVersion: 1, changeType: 'REVOKED' },
            actorPrivateKey: actorKey,
        });

        expect(mockQueryFn.mock.calls[0]![0]).toContain('SAVEPOINT');
        expect(mockQueryFn.mock.calls[0]![0]).toContain('policy_change_audit_guard');
        expect(mockQueryFn).toHaveBeenCalledTimes(4);
    });

    it('should propagate PostgreSQL error when client is not in a transaction (DB-level enforcement)', async () => {
        // Simulate the real PostgreSQL error when SAVEPOINT runs in a non-transaction context
        const pgSavepointError = new Error(
            'ERROR: SAVEPOINT can only be used in transaction blocks',
        );
        const mockQueryFn = vi.fn().mockRejectedValueOnce(pgSavepointError);

        const mockClient = { query: mockQueryFn } as unknown as import('pg').PoolClient;
        const recorder = new PolicyChangeRecorder(makeMockPool(), ledgerKey);

        await expect(
            recorder.recordCreated(mockClient, {
                agentDid,
                principalDid,
                params: { policyId: 'p-sp-no-tx', policyVersion: 1, changeType: 'CREATED' },
                actorPrivateKey: actorKey,
            }),
        ).rejects.toThrow('SAVEPOINT can only be used in transaction blocks');

        // Only SAVEPOINT is called (lock/load/INSERT are never reached)
        expect(mockQueryFn).toHaveBeenCalledTimes(1);
        expect(mockQueryFn.mock.calls[0]![0]).toContain('SAVEPOINT');
    });
});

// ---------------------------------------------------------------------------
// Type-utility unit tests
// ---------------------------------------------------------------------------

describe('policy-change-record type guards', () => {
    it('should recognize valid POLICY_ACTION_TYPES', () => {
        expect(isPolicyActionType('POLICY_CREATED')).toBe(true);
        expect(isPolicyActionType('POLICY_UPDATED')).toBe(true);
        expect(isPolicyActionType('POLICY_REVOKED')).toBe(true);
        expect(isPolicyActionType('INQUIRY')).toBe(false);
        expect(isPolicyActionType('SESSION_SUPERSEDED')).toBe(false);
        expect(isPolicyActionType('')).toBe(false);
        expect(isPolicyActionType(null)).toBe(false);
    });

    it('should export correct POLICY_ACTION_TYPES constants', () => {
        expect(POLICY_ACTION_TYPES).toContain(ACTION_POLICY_CREATED);
        expect(POLICY_ACTION_TYPES).toContain(ACTION_POLICY_UPDATED);
        expect(POLICY_ACTION_TYPES).toContain(ACTION_POLICY_REVOKED);
        expect(POLICY_ACTION_TYPES).toHaveLength(3);
    });

    it('should validate PolicyChangeParams with isPolicyChangeParams', () => {
        expect(
            isPolicyChangeParams({
                policyId: 'p-001',
                policyVersion: 1,
                changeType: 'CREATED',
            }),
        ).toBe(true);
        expect(
            isPolicyChangeParams({
                policyId: 'p-001',
                policyVersion: 2,
                changeType: 'UPDATED',
                changedFields: ['scope'],
            }),
        ).toBe(true);
        expect(
            isPolicyChangeParams({
                policyId: 'p-001',
                policyVersion: 3,
                changeType: 'REVOKED',
            }),
        ).toBe(true);

        // invalid cases
        expect(isPolicyChangeParams(null)).toBe(false);
        expect(isPolicyChangeParams({})).toBe(false);
        expect(
            isPolicyChangeParams({
                policyId: '',
                policyVersion: 1,
                changeType: 'CREATED',
            }),
        ).toBe(false); // empty policyId
        expect(
            isPolicyChangeParams({
                policyId: 'p-001',
                policyVersion: 0,
                changeType: 'CREATED',
            }),
        ).toBe(false); // policyVersion < 1
        expect(
            isPolicyChangeParams({
                policyId: 'p-001',
                policyVersion: 1,
                changeType: 'UNKNOWN',
            }),
        ).toBe(false); // invalid changeType
    });

    it('should not contaminate ACTION_VOCABULARY with POLICY_* types', async () => {
        const { ACTION_VOCABULARY } = await import('@coivitas/types');
        for (const policyType of POLICY_ACTION_TYPES) {
            expect(ACTION_VOCABULARY).not.toContain(policyType);
        }
    });

    it('should not contaminate HANDSHAKE_CAPABILITY_VOCABULARY with POLICY_* types', async () => {
        const { HANDSHAKE_CAPABILITY_VOCABULARY } = await import(
            '@coivitas/types'
        );
        for (const policyType of POLICY_ACTION_TYPES) {
            expect(HANDSHAKE_CAPABILITY_VOCABULARY).not.toContain(policyType);
        }
    });
});

// ---------------------------------------------------------------------------
// Integration tests (DATABASE_URL gated)
// ---------------------------------------------------------------------------

const describeIfDatabase = process.env.DATABASE_URL
    ? describe
    : describe.skip;

describeIfDatabase('PolicyChangeRecorder integration', () => {
    let cleanup: (() => Promise<void>) | undefined;
    let dbPool: import('@coivitas/shared').DatabasePool;
    let recorder: PolicyChangeRecorder;
    let agentDid: DID;
    let principalDid: DID;
    let actorKey: string;

    beforeAll(async () => {
        const db = await createTestDatabase();
        cleanup = db.cleanup;
        dbPool = db.pool;

        const ledgerKp = generateKeyPair();
        const actorKp = generateKeyPair();
        recorder = new PolicyChangeRecorder(dbPool, ledgerKp.privateKey.slice(0, 64));
        actorKey = actorKp.privateKey.slice(0, 64);

        // Use a fixed-format DID (required by the schema regex)
        agentDid = `did:agent:${'b'.repeat(40)}` as DID;
        principalDid = `did:key:zTest${actorKp.publicKey.slice(0, 16)}` as DID;
    });

    afterAll(async () => {
        await cleanup?.();
    });

    it('should write POLICY_CREATED record to policy_change_records table', async () => {
        const policyId = `policy-created-${Date.now()}`;

        // wrapOperation manages the transaction automatically
        await recorder.wrapOperation(policyId, ACTION_POLICY_CREATED, {
            agentDid,
            principalDid,
            actorPrivateKey: actorKey,
            policyVersion: 1,
            operation: () => Promise.resolve('policy-created-ok'),
        });

        // Verify the record is written to the dedicated policy_change_records table (params field, not parameters_summary)
        const rows = await dbPool.query<{
            action_type: string;
            params: Record<string, unknown>;
        }>(
            `SELECT action_type, params
             FROM policy.policy_change_records
             WHERE agent_did = $1 AND action_type = 'POLICY_CREATED'
             ORDER BY id DESC LIMIT 1`,
            [agentDid],
        );

        expect(rows.rows).toHaveLength(1);
        expect(rows.rows[0]!.action_type).toBe('POLICY_CREATED');
        expect(rows.rows[0]!.params).toMatchObject({
            policyId,
            policyVersion: 1,
            changeType: 'CREATED',
        });
    });

    it('should write POLICY_UPDATED record with changedFields to policy_change_records', async () => {
        const policyId = `policy-updated-${Date.now()}`;

        await recorder.wrapOperation(policyId, ACTION_POLICY_UPDATED, {
            agentDid,
            principalDid,
            actorPrivateKey: actorKey,
            policyVersion: 2,
            changedFields: ['scope', 'expiresAt'],
            operation: () => Promise.resolve({ updated: true }),
        });

        const rows = await dbPool.query<{
            action_type: string;
            params: Record<string, unknown>;
        }>(
            `SELECT action_type, params
             FROM policy.policy_change_records
             WHERE agent_did = $1 AND action_type = 'POLICY_UPDATED'
             ORDER BY id DESC LIMIT 1`,
            [agentDid],
        );

        expect(rows.rows).toHaveLength(1);
        expect(rows.rows[0]!.action_type).toBe('POLICY_UPDATED');
        expect(rows.rows[0]!.params).toMatchObject({
            policyId,
            policyVersion: 2,
            changeType: 'UPDATED',
            changedFields: ['scope', 'expiresAt'],
        });
    });

    it('should write POLICY_REVOKED record with revokedAt to policy_change_records', async () => {
        const policyId = `policy-revoked-${Date.now()}`;
        const revokedAt = makeTimestamp();

        await recorder.wrapOperation(policyId, ACTION_POLICY_REVOKED, {
            agentDid,
            principalDid,
            actorPrivateKey: actorKey,
            policyVersion: 3,
            revokedAt,
            operation: () => Promise.resolve(null),
        });

        const rows = await dbPool.query<{
            action_type: string;
            params: Record<string, unknown>;
        }>(
            `SELECT action_type, params
             FROM policy.policy_change_records
             WHERE agent_did = $1 AND action_type = 'POLICY_REVOKED'
             ORDER BY id DESC LIMIT 1`,
            [agentDid],
        );

        expect(rows.rows).toHaveLength(1);
        expect(rows.rows[0]!.action_type).toBe('POLICY_REVOKED');
        expect(rows.rows[0]!.params).toMatchObject({
            policyId,
            policyVersion: 3,
            changeType: 'REVOKED',
            revokedAt,
        });
    });

    it('should rollback audit record when operation throws (fail-closed atomic)', async () => {
        const policyId = `policy-op-fail-${Date.now()}`;

        // The operation throws internally
        await expect(
            recorder.wrapOperation(policyId, ACTION_POLICY_CREATED, {
                agentDid,
                principalDid,
                actorPrivateKey: actorKey,
                policyVersion: 1,
                operation: () => Promise.reject(new Error('Policy operation failed')),
            }),
        ).rejects.toThrow('Policy operation failed');

        // Confirm nothing was written to policy_change_records (the transaction rolled back)
        const rows = await dbPool.query<{ count: number }>(
            `SELECT COUNT(*)::int as count
             FROM policy.policy_change_records
             WHERE agent_did = $1
               AND params->>'policyId' = $2`,
            [agentDid, policyId],
        );
        expect(rows.rows[0]!.count).toBe(0);
    });

    it('should maintain hash chain continuity across multiple writes', async () => {
        const uniqueAgentDid = `did:agent:${'c'.repeat(40)}` as DID;
        const policyId = `policy-chain-${Date.now()}`;

        // Write 3 records and verify hash chain continuity
        await recorder.wrapOperation(policyId, ACTION_POLICY_CREATED, {
            agentDid: uniqueAgentDid,
            principalDid,
            actorPrivateKey: actorKey,
            policyVersion: 1,
            operation: () => Promise.resolve('create'),
        });

        await recorder.wrapOperation(policyId, ACTION_POLICY_UPDATED, {
            agentDid: uniqueAgentDid,
            principalDid,
            actorPrivateKey: actorKey,
            policyVersion: 2,
            changedFields: ['scope'],
            operation: () => Promise.resolve('update'),
        });

        await recorder.wrapOperation(policyId, ACTION_POLICY_REVOKED, {
            agentDid: uniqueAgentDid,
            principalDid,
            actorPrivateKey: actorKey,
            policyVersion: 2,
            operation: () => Promise.resolve('revoke'),
        });

        const rows = await dbPool.query<{
            row_hash: string;
            prev_row_hash: string;
            action_type: string;
        }>(
            `SELECT row_hash, prev_row_hash, action_type
             FROM policy.policy_change_records
             WHERE agent_did = $1
             ORDER BY id ASC`,
            [uniqueAgentDid],
        );

        expect(rows.rows).toHaveLength(3);

        // Row 1: prev_row_hash = '' (genesis, the first row of the chain)
        expect(rows.rows[0]!.prev_row_hash).toBe('');

        // Row 2: prev_row_hash = row 1's row_hash
        expect(rows.rows[1]!.prev_row_hash).toBe(
            rows.rows[0]!.row_hash,
        );

        // Row 3: prev_row_hash = row 2's row_hash
        expect(rows.rows[2]!.prev_row_hash).toBe(
            rows.rows[1]!.row_hash,
        );
    });
});
