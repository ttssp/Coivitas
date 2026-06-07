/**
 * Settlement Retry (SR) sub-protocol v0.1 — L3 core algorithm tests
 *
 * Coverage goal: ≥95% line/func/statement
 *
 * Test groups:
 *   1. computeIdempotencyKey — SHA-256(JCS) key derivation + canonicalize failure fail-closed
 *   2. executeSettlementRetry step 1 — SR_CANONICAL_HASH_MISMATCH
 *   3. executeSettlementRetry step 2 — SR_IDEMPOTENCY_VIOLATION + idempotent terminal-state return
 *   4. executeSettlementRetry step 3 — SR_VERSION_UNSUPPORTED + SR_AMOUNT_INVALID
 *   5. executeSettlementRetry step 4 — SR_SIGNED_PAYLOAD_INVALID + SR_FRESHNESS_INVALID
 *   6. executeSettlementRetry step 5 — SR_OPERATION_REVOKED (fail-closed + network error)
 *   7. executeSettlementRetry step 6 — SR_STATE_TRANSITION_INVALID (terminal state guard)
 *   8. executeSettlementRetry step 7 — SR_RETRY_EXHAUSTED + SR_BACKOFF_INVALID + provider path
 *   9. executeSettlementRetry complete success path (SUCCEEDED)
 *  10. executeSettlementRetry FAILED → DEAD_LETTER path (MAX_RETRY_ATTEMPTS boundary)
 *  11. executeSettlementRetry FAILED → FAILED retry-can-continue path
 */

import { describe, it, expect, vi, type MockedFunction } from 'vitest';
import {
    toOperationId,
    toSrTenantId,
    toAmount,
    toCurrency,
    toIdempotencyKey,
    SR_VERSION_1_0_0,
    MAX_RETRY_ATTEMPTS,
    SrError,
    type SettlementOperation,
    type IdempotencyRecord,
    type LedgerPort,
    type IdempotencyStore,
    type RetryScheduler,
    type RevocationChecker,
    type SignatureVerifier,
    type AtpRecorder,
    type IdempotencyKey,
} from '@coivitas/types';
import {
    executeSettlementRetry,
    computeIdempotencyKey,
    type RetryAttemptWriter,
} from '../../settlement-retry/index.js';

// ─── Fixed test constants ─────────────────────────────────────────────────────

const FIXED_OPERATION_ID = toOperationId(
    'a1b2c3d4-e5f6-4789-89ab-cdef01234567',
);
const FIXED_TENANT_ID = toSrTenantId('b2c3d4e5-f6a7-4891-9abc-def012345678');
const FIXED_PRINCIPAL_DID = 'did:key:z6MkpTest001';
const FIXED_COUNTERPARTY_DID = 'did:key:z6MkpTest002';
const FIXED_AMOUNT = toAmount(10000);
const FIXED_CURRENCY = toCurrency('USD');
const FIXED_SETTLER_DID =
    'did:key:z6MkpSettler001' as import('@coivitas/types').DID;
const FIXED_AUDIT_EVENT_ID = 'aaa00000-0000-4000-8000-000000000001';

// notAfter pinned to 1 hour in the future
const FUTURE_NOT_AFTER = new Date(
    Date.now() + 3_600_000,
).toISOString() as import('@coivitas/types').Timestamp;
const PAST_NOT_AFTER = new Date(
    Date.now() - 3_600_000,
).toISOString() as import('@coivitas/types').Timestamp;
const NOW_TS =
    new Date().toISOString() as import('@coivitas/types').Timestamp;

// ─── Signed payload base template ─────────────────────────────────────────────

/**
 * makeSignedPayload — build a SettlementOperationSignedPayload test fixture
 *
 * The test allows `as unknown as` type bypasses (fixture layer; not a production path);
 * production paths must construct via the factory (brand casts are forbidden).
 */
function makeSignedPayload(overrides?: {
    challenge?: string;
    cspVersion?: string;
    notAfter?: string;
    audience?: string;
    srVersion?: string;
}): import('@coivitas/types').SettlementOperationSignedPayload {
    return {
        cspVersion: (overrides?.cspVersion ??
            '1.0.0') as import('@coivitas/types').CspVersionString,
        token: 'eyJ.test.token' as unknown as import('@coivitas/types').CapabilityToken,
        disclosedClaims: [] as import('@coivitas/types').ScopeClaim[],
        challenge: (overrides?.challenge ??
            'a1b2c3d4-e5f6-4789-89ab-cdef01234567') as import('@coivitas/types').UuidV4String,
        audience: (overrides?.audience ??
            FIXED_SETTLER_DID) as import('@coivitas/types').CspAudience,
        notAfter: (overrides?.notAfter ??
            FUTURE_NOT_AFTER) as import('@coivitas/types').Timestamp,
        srVersion: (overrides?.srVersion ??
            SR_VERSION_1_0_0) as import('@coivitas/types').SrVersion,
        payloadSignature: 'a'.repeat(
            128,
        ) as import('@coivitas/types').Signature,
        principalDid:
            FIXED_PRINCIPAL_DID as import('@coivitas/types').DID,
    } as import('@coivitas/types').SettlementOperationSignedPayload;
}

// ─── Test fixture: makeOperation ──────────────────────────────────────────────

/**
 * makeOperation — build a valid SettlementOperation test fixture
 *
 * Note: idempotencyKey is precomputed on first call; overrides may replace any field.
 * The test precomputes the computeIdempotencyKey output and stores it as the COMPUTED_KEY constant.
 */
function makeOperation(
    overrides?: Partial<SettlementOperation>,
): SettlementOperation {
    const base: SettlementOperation = {
        id: FIXED_OPERATION_ID,
        srVersion: SR_VERSION_1_0_0,
        tenantId: FIXED_TENANT_ID,
        idempotencyKey: COMPUTED_KEY,
        settlementType: 'fiat_transfer',
        principalDid: FIXED_PRINCIPAL_DID,
        counterpartyDid: FIXED_COUNTERPARTY_DID,
        amount: FIXED_AMOUNT,
        currency: FIXED_CURRENCY,
        signedPayload: makeSignedPayload(),
        currentState: 'PENDING',
        attemptCount: 0,
        revoked: false,
        createdAt: NOW_TS,
        updatedAt: NOW_TS,
        finalizedAt: null,
    };
    const merged = { ...base, ...overrides };
    // test fixture integration:
    // the step 1 hash check is an early defense; if an override touches the 6 fields
    // (amount/principalDid/settlementType/currency/signedPayload), idempotencyKey must be recomputed to keep the fixture consistent
    if (
        overrides &&
        ('amount' in overrides ||
            'principalDid' in overrides ||
            'settlementType' in overrides ||
            'currency' in overrides ||
            'signedPayload' in overrides)
    ) {
        merged.idempotencyKey = computeIdempotencyKey({
            operationId: merged.id,
            principalDid:
                merged.principalDid as import('@coivitas/types').DID,
            settlementType: merged.settlementType,
            amount: merged.amount,
            currency: merged.currency,
            cspVersion: merged.signedPayload.cspVersion,
        });
    }
    return merged;
}

// COMPUTED_KEY: precomputed test idempotencyKey (aligned with makeSignedPayload's default cspVersion='1.0.0')
// Computed once at module top level so all fixtures can reuse it
const COMPUTED_KEY: IdempotencyKey = computeIdempotencyKey({
    operationId: FIXED_OPERATION_ID,
    principalDid: FIXED_PRINCIPAL_DID as import('@coivitas/types').DID,
    settlementType: 'fiat_transfer',
    amount: FIXED_AMOUNT,
    currency: FIXED_CURRENCY,
    cspVersion: '1.0.0',
});

// ─── Mock port factory functions ───────────────────────────────────────────────

function makeLedgerPort(
    result: Partial<Awaited<ReturnType<LedgerPort['submitSettlement']>>> = {
        providerTxId: 'tx-001',
        finalState: 'SUCCEEDED',
    },
): LedgerPort {
    return {
        submitSettlement: vi.fn().mockResolvedValue(result),
    };
}

function makeIdempotencyStore(
    existingRecord: IdempotencyRecord | null = null,
): {
    store: IdempotencyStore;
    mocks: {
        acquireAdvisoryLock: MockedFunction<
            IdempotencyStore['acquireAdvisoryLock']
        >;
        findByKey: MockedFunction<IdempotencyStore['findByKey']>;
        insertRecord: MockedFunction<IdempotencyStore['insertRecord']>;
        updateState: MockedFunction<IdempotencyStore['updateState']>;
    };
} {
    const acquireAdvisoryLock = vi
        .fn<IdempotencyStore['acquireAdvisoryLock']>()
        .mockResolvedValue(undefined);
    const findByKey = vi
        .fn<IdempotencyStore['findByKey']>()
        .mockResolvedValue(existingRecord);
    const insertRecord = vi
        .fn<IdempotencyStore['insertRecord']>()
        .mockResolvedValue(undefined);
    const updateState = vi
        .fn<IdempotencyStore['updateState']>()
        .mockResolvedValue(undefined);
    return {
        store: { acquireAdvisoryLock, findByKey, insertRecord, updateState },
        mocks: { acquireAdvisoryLock, findByKey, insertRecord, updateState },
    };
}

function makeRetryScheduler(delayMs = 1000): RetryScheduler {
    return {
        computeBackoffDelay: vi.fn().mockReturnValue(delayMs),
    };
}

function makeRevocationChecker(isRevoked = false): RevocationChecker {
    return {
        isOperationRevoked: vi.fn().mockResolvedValue(isRevoked),
    };
}

function makeSignatureVerifier(
    valid = true,
    reason?: string,
): SignatureVerifier {
    return {
        verify: vi.fn().mockResolvedValue({ valid, reason }),
    };
}

function makeAtpRecorder(): AtpRecorder {
    return {
        recordEvent: vi.fn().mockResolvedValue(FIXED_AUDIT_EVENT_ID),
    };
}

/**
 * makeRetryAttemptWriter — build a RetryAttemptWriter test mock
 *
 * persistRetryAttempt is wired up for real; unit tests inject an in-memory mock.
 * insert() resolves by default; tests can override it to simulate the DB-failure path.
 */
function makeRetryAttemptWriter(
    insertResult: 'success' | Error = 'success',
): RetryAttemptWriter {
    const insertFn =
        insertResult === 'success'
            ? vi.fn().mockResolvedValue(undefined)
            : vi.fn().mockRejectedValue(insertResult);
    return {
        insert: insertFn,
    };
}

/**
 * makeDeps — build the full set of port dependencies
 *
 * All ports default to the happy path; override as needed.
 */
function makeDeps(overrides?: {
    ledger?: LedgerPort;
    idempotency?: { store: IdempotencyStore };
    scheduler?: RetryScheduler;
    revocation?: RevocationChecker;
    signature?: SignatureVerifier;
    atp?: AtpRecorder;
    retryAttemptWriter?: RetryAttemptWriter;
}) {
    const { store: idempotencyStore } =
        overrides?.idempotency ?? makeIdempotencyStore();
    return {
        ledgerPort: overrides?.ledger ?? makeLedgerPort(),
        idempotencyStore,
        retryScheduler: overrides?.scheduler ?? makeRetryScheduler(),
        revocationChecker: overrides?.revocation ?? makeRevocationChecker(),
        atpRecorder: overrides?.atp ?? makeAtpRecorder(),
        signatureVerifier: overrides?.signature ?? makeSignatureVerifier(),
        expectedSettlerDid: FIXED_SETTLER_DID,
        retryAttemptWriter:
            overrides?.retryAttemptWriter ?? makeRetryAttemptWriter(),
    };
}

// ─── Helper: call executeSettlementRetry ───────────────────────────────────────

async function callExecute(
    operation: SettlementOperation,
    overrides?: Parameters<typeof makeDeps>[0],
): Promise<SettlementOperation> {
    const deps = makeDeps(overrides);
    return executeSettlementRetry(
        operation,
        deps.ledgerPort,
        deps.idempotencyStore,
        deps.retryScheduler,
        deps.revocationChecker,
        deps.atpRecorder,
        deps.signatureVerifier,
        deps.expectedSettlerDid,
        deps.retryAttemptWriter,
    );
}

// ─── 1. computeIdempotencyKey ─────────────────────────────────────────────────

describe('computeIdempotencyKey', () => {
    it('should return 64-char lowercase hex string when valid input provided', () => {
        const key = computeIdempotencyKey({
            operationId: FIXED_OPERATION_ID,
            principalDid:
                FIXED_PRINCIPAL_DID as import('@coivitas/types').DID,
            settlementType: 'fiat_transfer',
            amount: FIXED_AMOUNT,
            currency: FIXED_CURRENCY,
            cspVersion: '1.0.0',
        });
        expect(key).toMatch(/^[0-9a-f]{64}$/);
    });

    it('should return deterministic output for same inputs', () => {
        const input = {
            operationId: FIXED_OPERATION_ID,
            principalDid:
                FIXED_PRINCIPAL_DID as import('@coivitas/types').DID,
            settlementType: 'fiat_transfer' as const,
            amount: FIXED_AMOUNT,
            currency: FIXED_CURRENCY,
            cspVersion: '1.0.0',
        };
        const key1 = computeIdempotencyKey(input);
        const key2 = computeIdempotencyKey(input);
        expect(key1).toBe(key2);
    });

    it('should produce different keys when amount differs', () => {
        const base = {
            operationId: FIXED_OPERATION_ID,
            principalDid:
                FIXED_PRINCIPAL_DID as import('@coivitas/types').DID,
            settlementType: 'fiat_transfer' as const,
            amount: FIXED_AMOUNT,
            currency: FIXED_CURRENCY,
            cspVersion: '1.0.0',
        };
        const key1 = computeIdempotencyKey(base);
        const key2 = computeIdempotencyKey({
            ...base,
            amount: toAmount(99999),
        });
        expect(key1).not.toBe(key2);
    });

    it('should produce different keys when settlementType differs', () => {
        const base = {
            operationId: FIXED_OPERATION_ID,
            principalDid:
                FIXED_PRINCIPAL_DID as import('@coivitas/types').DID,
            settlementType: 'fiat_transfer' as const,
            amount: FIXED_AMOUNT,
            currency: FIXED_CURRENCY,
            cspVersion: '1.0.0',
        };
        const key1 = computeIdempotencyKey(base);
        const key2 = computeIdempotencyKey({
            ...base,
            settlementType: 'digital_wallet',
        });
        expect(key1).not.toBe(key2);
    });
});

// ─── 2. step 1: SR_CANONICAL_HASH_MISMATCH ───────────────────────────────────

describe('executeSettlementRetry step 1 — SR_CANONICAL_HASH_MISMATCH', () => {
    it('should throw SR_CANONICAL_HASH_MISMATCH when idempotencyKey does not match recomputed key', async () => {
        // Intentionally use a wrong idempotency key (all-zero sha-256)
        const tampered = makeOperation({
            idempotencyKey: toIdempotencyKey('0'.repeat(64)),
        });

        await expect(callExecute(tampered)).rejects.toSatisfy(
            (err: unknown) =>
                err instanceof SrError &&
                err.code === 'SR_CANONICAL_HASH_MISMATCH',
        );
    });

    it('should include storedKey and recomputedKey in error detail when hash mismatch detected', async () => {
        const wrongKey = toIdempotencyKey('f'.repeat(64));
        const tampered = makeOperation({ idempotencyKey: wrongKey });

        let caught: SrError | undefined;
        try {
            await callExecute(tampered);
        } catch (err) {
            if (err instanceof SrError) caught = err;
        }

        expect(caught).toBeDefined();
        expect(caught!.code).toBe('SR_CANONICAL_HASH_MISMATCH');
        expect(caught!.detail).toMatchObject({
            storedKey: wrongKey,
            reason: 'idempotency_key_field_drift_detected',
        });
    });
});

// ─── 3. step 2: SR_IDEMPOTENCY_VIOLATION + idempotent terminal-state return ──────────────────────

describe('executeSettlementRetry step 2 — idempotency guard', () => {
    it('should throw SR_IDEMPOTENCY_VIOLATION when existing record has different operationId', async () => {
        const conflictingRecord: IdempotencyRecord = {
            key: COMPUTED_KEY,
            tenantId: FIXED_TENANT_ID,
            operationId: toOperationId('c3d4e5f6-a7b8-4901-abcd-ef0123456789'), // different operation
            currentState: 'PENDING',
            createdAt: NOW_TS,
            finalizedAt: null,
        };

        const { store } = makeIdempotencyStore(conflictingRecord);
        await expect(
            callExecute(makeOperation(), { idempotency: { store } }),
        ).rejects.toSatisfy(
            (err: unknown) =>
                err instanceof SrError &&
                err.code === 'SR_IDEMPOTENCY_VIOLATION',
        );
    });

    it('should return current operation idempotently when existing record is SUCCEEDED terminal', async () => {
        const succeededRecord: IdempotencyRecord = {
            key: COMPUTED_KEY,
            tenantId: FIXED_TENANT_ID,
            operationId: FIXED_OPERATION_ID,
            currentState: 'SUCCEEDED',
            createdAt: NOW_TS,
            finalizedAt: NOW_TS,
        };

        const { store } = makeIdempotencyStore(succeededRecord);
        const operation = makeOperation({ currentState: 'SUCCEEDED' });
        const result = await callExecute(operation, { idempotency: { store } });

        // Idempotent terminal state: return the operation directly (do not re-execute)
        expect(result.id).toBe(operation.id);
        expect(result.currentState).toBe('SUCCEEDED');
    });

    it('should return current operation idempotently when existing record is DEAD_LETTER terminal', async () => {
        const deadLetterRecord: IdempotencyRecord = {
            key: COMPUTED_KEY,
            tenantId: FIXED_TENANT_ID,
            operationId: FIXED_OPERATION_ID,
            currentState: 'DEAD_LETTER',
            createdAt: NOW_TS,
            finalizedAt: NOW_TS,
        };

        const { store } = makeIdempotencyStore(deadLetterRecord);
        const operation = makeOperation({ currentState: 'DEAD_LETTER' });
        const result = await callExecute(operation, { idempotency: { store } });

        expect(result.id).toBe(operation.id);
        expect(result.currentState).toBe('DEAD_LETTER');
    });

    it('should insert idempotency record on first call when no existing record', async () => {
        const { store, mocks } = makeIdempotencyStore(null);
        await callExecute(makeOperation(), { idempotency: { store } });
        expect(mocks.insertRecord).toHaveBeenCalledOnce();
        expect(mocks.insertRecord).toHaveBeenCalledWith(
            expect.objectContaining({
                key: COMPUTED_KEY,
                tenantId: FIXED_TENANT_ID,
                operationId: FIXED_OPERATION_ID,
            }),
        );
    });

    it('should continue execution when existing record has same operationId and non-terminal state', async () => {
        // FAILED is a recoverable state (non-terminal)
        const recoveryRecord: IdempotencyRecord = {
            key: COMPUTED_KEY,
            tenantId: FIXED_TENANT_ID,
            operationId: FIXED_OPERATION_ID,
            currentState: 'FAILED',
            createdAt: NOW_TS,
            finalizedAt: null,
        };

        const { store, mocks } = makeIdempotencyStore(recoveryRecord);
        // FAILED → IN_PROGRESS retry continues
        const operation = makeOperation({
            currentState: 'FAILED',
            attemptCount: 1,
        });
        const result = await callExecute(operation, { idempotency: { store } });

        // Should continue executing to a terminal or new state
        expect(['SUCCEEDED', 'FAILED', 'DEAD_LETTER']).toContain(
            result.currentState,
        );
        // insertRecord should not be called again (the record already exists)
        expect(mocks.insertRecord).not.toHaveBeenCalled();
    });
});

// ─── 4. step 3: SR_VERSION_UNSUPPORTED + SR_AMOUNT_INVALID ───────────────────

describe('executeSettlementRetry step 3 — field validation', () => {
    it('should throw SR_AMOUNT_INVALID when amount is 0', async () => {
        // The amount brand type permits constructing 0 at the memory level; this tests L3's runtime check
        const operation = makeOperation({
            amount: 0 as import('@coivitas/types').Amount,
        });

        await expect(callExecute(operation)).rejects.toSatisfy(
            (err: unknown) =>
                err instanceof SrError && err.code === 'SR_AMOUNT_INVALID',
        );
    });

    it('should throw SR_AMOUNT_INVALID when amount is negative', async () => {
        const operation = makeOperation({
            amount: -1 as import('@coivitas/types').Amount,
        });

        await expect(callExecute(operation)).rejects.toSatisfy(
            (err: unknown) =>
                err instanceof SrError && err.code === 'SR_AMOUNT_INVALID',
        );
    });

    it('should throw SR_VERSION_UNSUPPORTED when settlementType is unsupported', async () => {
        // Bypass the brand type to inject an illegal value at the fixture layer
        const operation = makeOperation({
            settlementType:
                'wire_transfer' as import('@coivitas/types').SettlementType,
        });

        await expect(callExecute(operation)).rejects.toSatisfy(
            (err: unknown) =>
                err instanceof SrError && err.code === 'SR_VERSION_UNSUPPORTED',
        );
    });

    it('should throw SR_VERSION_UNSUPPORTED when srVersion is unsupported', async () => {
        const operation = makeOperation({
            srVersion: '9.9.9' as import('@coivitas/types').SrVersion,
        });

        await expect(callExecute(operation)).rejects.toSatisfy(
            (err: unknown) =>
                err instanceof SrError && err.code === 'SR_VERSION_UNSUPPORTED',
        );
    });
});

// ─── 5. step 4: SR_SIGNED_PAYLOAD_INVALID + SR_FRESHNESS_INVALID ─────────────

describe('executeSettlementRetry step 4 — signedPayload validation', () => {
    it('should throw SR_SIGNED_PAYLOAD_INVALID when challenge is empty', async () => {
        const operation = makeOperation({
            signedPayload: makeSignedPayload({ challenge: '' }),
        });

        await expect(callExecute(operation)).rejects.toSatisfy(
            (err: unknown) =>
                err instanceof SrError &&
                err.code === 'SR_SIGNED_PAYLOAD_INVALID',
        );
    });

    it('should throw SR_SIGNED_PAYLOAD_INVALID when challenge is whitespace only', async () => {
        const operation = makeOperation({
            signedPayload: makeSignedPayload({ challenge: '   ' }),
        });

        await expect(callExecute(operation)).rejects.toSatisfy(
            (err: unknown) =>
                err instanceof SrError &&
                err.code === 'SR_SIGNED_PAYLOAD_INVALID',
        );
    });

    it('should throw SR_VERSION_UNSUPPORTED when cspVersion is not 1.0.0', async () => {
        const operation = makeOperation({
            signedPayload: makeSignedPayload({ cspVersion: '2.0.0' }),
        });

        await expect(callExecute(operation)).rejects.toSatisfy(
            (err: unknown) =>
                err instanceof SrError && err.code === 'SR_VERSION_UNSUPPORTED',
        );
    });

    it('should throw SR_FRESHNESS_INVALID when notAfter is in the past', async () => {
        const operation = makeOperation({
            signedPayload: makeSignedPayload({ notAfter: PAST_NOT_AFTER }),
        });

        await expect(callExecute(operation)).rejects.toSatisfy(
            (err: unknown) =>
                err instanceof SrError && err.code === 'SR_FRESHNESS_INVALID',
        );
    });

    it('should throw SR_FRESHNESS_INVALID when notAfter is not parseable', async () => {
        const operation = makeOperation({
            signedPayload: makeSignedPayload({ notAfter: 'not-a-date' }),
        });

        await expect(callExecute(operation)).rejects.toSatisfy(
            (err: unknown) =>
                err instanceof SrError && err.code === 'SR_FRESHNESS_INVALID',
        );
    });

    it('should throw SR_SIGNED_PAYLOAD_INVALID when audience does not match expectedSettlerDid', async () => {
        const operation = makeOperation({
            signedPayload: makeSignedPayload({
                audience: 'did:key:z6MkpWrongAudience',
            }),
        });

        await expect(callExecute(operation)).rejects.toSatisfy(
            (err: unknown) =>
                err instanceof SrError &&
                err.code === 'SR_SIGNED_PAYLOAD_INVALID',
        );
    });

    it('should throw SR_SIGNED_PAYLOAD_INVALID when Ed25519 signature verification fails', async () => {
        const failingSig = makeSignatureVerifier(false, 'ed25519_test_failure');
        const operation = makeOperation();

        await expect(
            callExecute(operation, { signature: failingSig }),
        ).rejects.toSatisfy(
            (err: unknown) =>
                err instanceof SrError &&
                err.code === 'SR_SIGNED_PAYLOAD_INVALID',
        );
    });
});

// ─── 6. step 5: SR_OPERATION_REVOKED (fail-closed) ───────────────────────────

describe('executeSettlementRetry step 5 — revocation check fail-closed', () => {
    it('should throw SR_OPERATION_REVOKED when operation is revoked by revocationChecker', async () => {
        const revoked = makeRevocationChecker(true);

        await expect(
            callExecute(makeOperation(), { revocation: revoked }),
        ).rejects.toSatisfy(
            (err: unknown) =>
                err instanceof SrError && err.code === 'SR_OPERATION_REVOKED',
        );
    });

    it('should throw SR_OPERATION_REVOKED on network error from revocationChecker (fail-closed)', async () => {
        const networkErr: RevocationChecker = {
            isOperationRevoked: vi
                .fn()
                .mockRejectedValue(new Error('network timeout')),
        };

        await expect(
            callExecute(makeOperation(), { revocation: networkErr }),
        ).rejects.toSatisfy(
            (err: unknown) =>
                err instanceof SrError &&
                err.code === 'SR_OPERATION_REVOKED' &&
                (err.detail as Record<string, unknown>)?.reason ===
                    'revocation_check_network_failure_fail_closed',
        );
    });

    it('should throw SR_OPERATION_REVOKED when operation.revoked field is true (defense-in-depth)', async () => {
        const operation = makeOperation({ revoked: true });

        await expect(callExecute(operation)).rejects.toSatisfy(
            (err: unknown) =>
                err instanceof SrError &&
                err.code === 'SR_OPERATION_REVOKED' &&
                (err.detail as Record<string, unknown>)?.reason ===
                    'operation_revoked_field_set_defense_in_depth',
        );
    });
});

// ─── 7. step 6: SR_STATE_TRANSITION_INVALID (terminal state guard) ────────────

describe('executeSettlementRetry step 6 — state transition guard', () => {
    it('should throw SR_STATE_TRANSITION_INVALID when operation is in SUCCEEDED terminal state', async () => {
        const operation = makeOperation({
            currentState: 'SUCCEEDED',
            attemptCount: 1,
        });

        await expect(callExecute(operation)).rejects.toSatisfy(
            (err: unknown) =>
                err instanceof SrError &&
                err.code === 'SR_STATE_TRANSITION_INVALID',
        );
    });

    it('should throw SR_STATE_TRANSITION_INVALID when operation is in DEAD_LETTER terminal state', async () => {
        const operation = makeOperation({
            currentState: 'DEAD_LETTER',
            attemptCount: 3,
        });

        await expect(callExecute(operation)).rejects.toSatisfy(
            (err: unknown) =>
                err instanceof SrError &&
                err.code === 'SR_STATE_TRANSITION_INVALID',
        );
    });
});

// ─── 8. step 7: SR_RETRY_EXHAUSTED + SR_BACKOFF_INVALID ──────────────────────

describe('executeSettlementRetry step 7 — retry exhaustion and backoff', () => {
    it('should throw SR_RETRY_EXHAUSTED when attemptCount >= MAX_RETRY_ATTEMPTS', async () => {
        const operation = makeOperation({
            currentState: 'PENDING',
            attemptCount: MAX_RETRY_ATTEMPTS,
        });

        await expect(callExecute(operation)).rejects.toSatisfy(
            (err: unknown) =>
                err instanceof SrError && err.code === 'SR_RETRY_EXHAUSTED',
        );
    });

    it('should include attemptCount and maxRetryAttempts in SR_RETRY_EXHAUSTED detail', async () => {
        const operation = makeOperation({
            currentState: 'PENDING',
            attemptCount: MAX_RETRY_ATTEMPTS,
        });

        let caught: SrError | undefined;
        try {
            await callExecute(operation);
        } catch (err) {
            if (err instanceof SrError) caught = err;
        }

        expect(caught?.code).toBe('SR_RETRY_EXHAUSTED');
        expect(caught?.detail).toMatchObject({
            attemptCount: MAX_RETRY_ATTEMPTS,
            maxRetryAttempts: MAX_RETRY_ATTEMPTS,
            reason: 'retry_attempts_exhausted_moved_to_dead_letter',
        });
    });

    it('should throw SR_BACKOFF_INVALID when scheduler returns delay > 60000ms', async () => {
        const badScheduler = makeRetryScheduler(99_999);

        await expect(
            callExecute(makeOperation(), { scheduler: badScheduler }),
        ).rejects.toSatisfy(
            (err: unknown) =>
                err instanceof SrError && err.code === 'SR_BACKOFF_INVALID',
        );
    });

    it('should throw SR_BACKOFF_INVALID when scheduler returns negative delay', async () => {
        const badScheduler = makeRetryScheduler(-1);

        await expect(
            callExecute(makeOperation(), { scheduler: badScheduler }),
        ).rejects.toSatisfy(
            (err: unknown) =>
                err instanceof SrError && err.code === 'SR_BACKOFF_INVALID',
        );
    });

    it('should propagate SR_PROVIDER_UNAVAILABLE when ledger throws that error', async () => {
        const failingLedger: LedgerPort = {
            submitSettlement: vi.fn().mockRejectedValue(
                new SrError('SR_PROVIDER_UNAVAILABLE', {
                    reason: 'connection_refused',
                }),
            ),
        };

        await expect(
            callExecute(makeOperation(), { ledger: failingLedger }),
        ).rejects.toSatisfy(
            (err: unknown) =>
                err instanceof SrError &&
                err.code === 'SR_PROVIDER_UNAVAILABLE',
        );
    });

    it('should propagate SR_PROVIDER_TIMEOUT when ledger throws that error', async () => {
        const timeoutLedger: LedgerPort = {
            submitSettlement: vi.fn().mockRejectedValue(
                new SrError('SR_PROVIDER_TIMEOUT', {
                    reason: 'deadline_exceeded',
                }),
            ),
        };

        await expect(
            callExecute(makeOperation(), { ledger: timeoutLedger }),
        ).rejects.toSatisfy(
            (err: unknown) =>
                err instanceof SrError && err.code === 'SR_PROVIDER_TIMEOUT',
        );
    });

    it('should propagate SR_PROVIDER_DECLINED when ledger throws that error', async () => {
        const declinedLedger: LedgerPort = {
            submitSettlement: vi.fn().mockRejectedValue(
                new SrError('SR_PROVIDER_DECLINED', {
                    reason: 'account_suspended',
                }),
            ),
        };

        await expect(
            callExecute(makeOperation(), { ledger: declinedLedger }),
        ).rejects.toSatisfy(
            (err: unknown) =>
                err instanceof SrError && err.code === 'SR_PROVIDER_DECLINED',
        );
    });

    it('should throw SR_PROVIDER_RESPONSE_INVALID when provider returns invalid finalState', async () => {
        const invalidLedger: LedgerPort = {
            submitSettlement: vi.fn().mockResolvedValue({
                providerTxId: 'tx-invalid',
                finalState: 'UNKNOWN_STATE' as 'SUCCEEDED',
                responseMessage: 'bad state',
            }),
        };

        await expect(
            callExecute(makeOperation(), { ledger: invalidLedger }),
        ).rejects.toSatisfy(
            (err: unknown) =>
                err instanceof SrError &&
                err.code === 'SR_PROVIDER_RESPONSE_INVALID',
        );
    });
});

// ─── 9. complete success path (SUCCEEDED) ──────────────────────────────────────────────

describe('executeSettlementRetry — complete SUCCEEDED path', () => {
    it('should return operation with SUCCEEDED state when provider returns SUCCEEDED', async () => {
        const result = await callExecute(makeOperation());

        expect(result.currentState).toBe('SUCCEEDED');
        expect(result.attemptCount).toBe(1);
        expect(result.finalizedAt).not.toBeNull();
    });

    it('should call acquireAdvisoryLock before findByKey when executing', async () => {
        const { store, mocks } = makeIdempotencyStore(null);
        const callOrder: string[] = [];

        mocks.acquireAdvisoryLock.mockImplementation(() => {
            callOrder.push('acquireAdvisoryLock');
            return Promise.resolve();
        });
        mocks.findByKey.mockImplementation(() => {
            callOrder.push('findByKey');
            return Promise.resolve(null);
        });

        await callExecute(makeOperation(), { idempotency: { store } });

        expect(callOrder[0]).toBe('acquireAdvisoryLock');
        expect(callOrder[1]).toBe('findByKey');
    });

    it('should call atpRecorder.recordEvent with auditClass L2 on success', async () => {
        const atp = makeAtpRecorder();
        await callExecute(makeOperation(), { atp });

        // eslint-disable-next-line @typescript-eslint/unbound-method
        expect(vi.mocked(atp.recordEvent)).toHaveBeenCalledWith(
            expect.objectContaining({ auditClass: 'L2' }),
        );
    });

    it('should call ledgerPort.submitSettlement with the full operation', async () => {
        const ledger = makeLedgerPort();
        const operation = makeOperation();
        await callExecute(operation, { ledger });

        // eslint-disable-next-line @typescript-eslint/unbound-method
        expect(vi.mocked(ledger.submitSettlement)).toHaveBeenCalledWith(
            operation,
        );
    });

    it('should call updateState with SUCCEEDED and finalizedAt when succeeded', async () => {
        const { store, mocks } = makeIdempotencyStore(null);
        await callExecute(makeOperation(), { idempotency: { store } });

        const updateCalls = mocks.updateState.mock.calls;
        const succeededCall = updateCalls.find(
            (args) => args[2] === 'SUCCEEDED',
        );
        expect(succeededCall).toBeDefined();
        expect(succeededCall![3]).toBeDefined(); // finalizedAt
    });
});

// ─── 10. FAILED → DEAD_LETTER path ───────────────────────────────────────────

describe('executeSettlementRetry — FAILED to DEAD_LETTER path', () => {
    it('should return DEAD_LETTER when attemptNumber reaches MAX_RETRY_ATTEMPTS on FAILED result', async () => {
        // attemptCount = MAX_RETRY_ATTEMPTS - 1; after this failure attemptNumber = MAX_RETRY_ATTEMPTS → DEAD_LETTER
        const operation = makeOperation({
            currentState: 'FAILED',
            attemptCount: MAX_RETRY_ATTEMPTS - 1,
        });

        const failedLedger = makeLedgerPort({
            providerTxId: 'tx-fail',
            finalState: 'FAILED',
            responseCode: 'DECLINED',
        });

        const result = await callExecute(operation, { ledger: failedLedger });

        expect(result.currentState).toBe('DEAD_LETTER');
        expect(result.attemptCount).toBe(MAX_RETRY_ATTEMPTS);
        expect(result.finalizedAt).not.toBeNull();
    });

    it('should call updateState with DEAD_LETTER when last attempt fails', async () => {
        const { store, mocks } = makeIdempotencyStore(null);
        const operation = makeOperation({
            currentState: 'FAILED',
            attemptCount: MAX_RETRY_ATTEMPTS - 1,
        });

        const failedLedger = makeLedgerPort({
            providerTxId: 'tx-fail',
            finalState: 'FAILED',
        });
        await callExecute(operation, {
            idempotency: { store },
            ledger: failedLedger,
        });

        const updateCalls = mocks.updateState.mock.calls;
        const deadLetterCall = updateCalls.find(
            (args) => args[2] === 'DEAD_LETTER',
        );
        expect(deadLetterCall).toBeDefined();
    });
});

// ─── 11. FAILED → FAILED retry-can-continue path ──────────────────────────────────────

describe('executeSettlementRetry — FAILED with retry remaining', () => {
    it('should return FAILED state when attempt fails and retries remain', async () => {
        const operation = makeOperation({
            currentState: 'PENDING',
            attemptCount: 0,
        });

        const failedLedger = makeLedgerPort({
            providerTxId: 'tx-fail',
            finalState: 'FAILED',
            responseMessage: 'temporary error',
        });

        const result = await callExecute(operation, { ledger: failedLedger });

        // attemptCount=0 → attemptNumber=1 → 1 < MAX_RETRY_ATTEMPTS(3) → FAILED (retryable)
        expect(result.currentState).toBe('FAILED');
        expect(result.attemptCount).toBe(1);
        expect(result.finalizedAt).toBeNull();
    });

    it('should update attemptCount by 1 on FAILED result', async () => {
        const operation = makeOperation({
            currentState: 'PENDING',
            attemptCount: 1,
        });
        const failedLedger = makeLedgerPort({
            providerTxId: 'tx-fail',
            finalState: 'FAILED',
        });

        const result = await callExecute(operation, { ledger: failedLedger });

        expect(result.attemptCount).toBe(2);
    });

    it('should call signatureVerifier.verify with expectedSettlerDid from runtime context', async () => {
        const sig = makeSignatureVerifier(true);
        const operation = makeOperation();
        await callExecute(operation, { signature: sig });

        // eslint-disable-next-line @typescript-eslint/unbound-method
        expect(vi.mocked(sig.verify)).toHaveBeenCalledWith(
            expect.objectContaining({
                expectedAudience: FIXED_SETTLER_DID,
            }),
        );
    });

    it('should call revocationChecker.isOperationRevoked with operationId', async () => {
        const revocation = makeRevocationChecker(false);
        const operation = makeOperation();
        await callExecute(operation, { revocation });

        // eslint-disable-next-line @typescript-eslint/unbound-method
        expect(vi.mocked(revocation.isOperationRevoked)).toHaveBeenCalledWith(
            FIXED_OPERATION_ID,
        );
    });
});

// ─── 12. SrError basic assertions ─────────────────────────────────────────────────────

describe('SrError — error-code structure', () => {
    it('should be an instance of Error when constructed', () => {
        const err = new SrError('SR_RETRY_EXHAUSTED', { reason: 'test' });
        expect(err).toBeInstanceOf(Error);
        expect(err).toBeInstanceOf(SrError);
    });

    it('should have code and detail fields when constructed', () => {
        const detail = { attempt: 3, reason: 'exhausted' };
        const err = new SrError('SR_RETRY_EXHAUSTED', detail);
        expect(err.code).toBe('SR_RETRY_EXHAUSTED');
        expect(err.detail).toEqual(detail);
    });

    it('should include code in error message when constructed', () => {
        const err = new SrError('SR_IDEMPOTENCY_VIOLATION', {});
        expect(err.message).toContain('SR_IDEMPOTENCY_VIOLATION');
    });
});
