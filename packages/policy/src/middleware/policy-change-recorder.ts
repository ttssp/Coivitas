/**
 * PolicyChangeRecorder — automatic audit middleware for Policy changes.
 *
 * Design goals (standalone table, split from action-record):
 * 1. Wrap rather than intrude: do not modify existing PolicyEngine code; intercept CRUD operations
 *    via external calls.
 * 2. Same-transaction atomic write: the policy operation and the audit record write execute within
 *    the same PoolClient transaction, following the EnvelopeLedger.finalizeWithinTransaction pattern.
 * 3. fail-closed: throw on write failure; do not silently swallow errors.
 * 4. Standalone-table writes: POLICY_CREATED/UPDATED/REVOKED are written to the standalone
 *    policy.policy_change_records table (SQL 007), and do not enter the frozen policy.action_records
 *    (ACTION_VOCABULARY). The hash chain + dual signature (actor + ledger) mechanism is preserved,
 *    reusing the recorder/shared.ts utility functions.
 *
 * Usage pattern (same-transaction wrapping):
 * ```ts
 * const recorder = new PolicyChangeRecorder(dbPool, ledgerPrivateKey);
 * const result = await recorder.recordCreated(client, {
 *     agentDid, principalDid, params, actorPrivateKey
 * });
 * ```
 *
 * Or use wrapOperation to manage the transaction automatically:
 * ```ts
 * await recorder.wrapOperation(policyId, 'CREATED', {
 *     agentDid, principalDid, actorPrivateKey, policyVersion: 1,
 *     operation: async (client) => { ... }
 * });
 * ```
 */

import { randomUUID } from 'node:crypto';

import type { PoolClient } from 'pg';

import { type DatabasePool, withTransaction } from '@coivitas/shared';
import type { DID, Timestamp } from '@coivitas/types';
import {
    ACTION_POLICY_CREATED,
    ACTION_POLICY_REVOKED,
    ACTION_POLICY_UPDATED,
    type PolicyActionType,
    type PolicyChangeParams,
    POLICY_ACTION_TYPES,
    SCHEMA_IDS,
    validateAgainstSchema,
} from '@coivitas/types';

import { LEDGER_ENCODING } from '../recorder/encoding-config.js';
import {
    buildUnsignedRecordPayload,
    computeRecordHash,
    createRecordSignature,
    derivePublicKeyFromPrivateKey,
    normalizeSigningPrivateKey,
} from '../recorder/shared.js';
import { toTimestamp } from '../_shared/timestamp.js';

// ---------------------------------------------------------------------------
// Type definitions
// ---------------------------------------------------------------------------

/** Write result */
export interface PolicyRecordWriteResult {
    recordId: string;
    hash: string;
}

/** Input for a single policy record write (the client already holds a transactional PoolClient) */
export interface PolicyRecordInput {
    /** DID of the policy-owner agent */
    agentDid: DID;
    /** DID of the principal performing the change (admin/operator) */
    principalDid: DID;
    /** Policy change parameters (written into parametersSummary) */
    params: PolicyChangeParams;
    /** actor signing private key (64-byte hex seed or 128-byte hex expanded) */
    actorPrivateKey: string;
    /** Optional: preset recordId (idempotency scenario) */
    recordId?: string;
    /** Optional: timestamp override (for testing) */
    createdAt?: Timestamp;
}

/** wrapOperation invocation options */
export interface WrapOperationOptions<T> {
    /** DID of the policy-owner agent */
    agentDid: DID;
    /** DID of the principal performing the change (admin/operator) */
    principalDid: DID;
    /** actor signing private key */
    actorPrivateKey: string;
    /** Policy version number after the operation */
    policyVersion: number;
    /** Changed fields (only meaningful for UPDATED) */
    changedFields?: string[];
    /** Revocation timestamp (only meaningful for REVOKED) */
    revokedAt?: Timestamp;
    /** The actual policy operation, executed within the same transaction */
    operation: (client: PoolClient) => Promise<T>;
}

// ---------------------------------------------------------------------------
// PolicyChangeRecorder implementation
// ---------------------------------------------------------------------------

/**
 * PolicyChangeRecorder — the main class of the automatic audit middleware.
 *
 * Design constraints:
 * - Does not call ActionRecorder.record(), bypassing the assertLaneAllowed lane check.
 * - Uses the recorder/shared.ts utility functions directly to preserve the hash chain + signing mechanism.
 * - INSERT uses the standalone table policy.policy_change_records (SQL migration 007).
 * - The frozen policy.action_records (ACTION_VOCABULARY) is left unchanged.
 * - All write paths are fail-closed.
 */
export class PolicyChangeRecorder {
    private readonly ledgerPrivateKey: string;
    public readonly ledgerPublicKey: string;

    public constructor(
        private readonly dbPool: DatabasePool,
        ledgerPrivateKey?: string,
    ) {
        const configuredKey =
            ledgerPrivateKey ?? process.env.LEDGER_PRIVATE_KEY ?? '';
        if (configuredKey.length === 0) {
            throw new Error(
                'PolicyChangeRecorder: LEDGER_PRIVATE_KEY is required (fail-closed).',
            );
        }

        // fail-closed: validate the LEDGER_PRIVATE_KEY format inside the constructor.
        // Accepted: 64-char hex (32-byte seed) or 128-char hex (64-byte expanded key).
        // Invalid: wrong length → throw immediately; contains non-hex characters → throw immediately;
        // an internal throw from normalizeSigningPrivateKey/derivePublicKeyFromPrivateKey → re-wrap and throw.
        // Purpose: ensure fail-closed at construction time, disallowing the existence of an object
        // with an invalid key, avoiding the inconsistent state of "an out-of-transaction side effect
        // already happened but createRecordSignature throws".
        const HEX_RE = /^[0-9a-fA-F]+$/;
        if (configuredKey.length !== 64 && configuredKey.length !== 128) {
            throw new Error(
                `PolicyChangeRecorder: LEDGER_PRIVATE_KEY is invalid (must be 64-byte or 128-byte hex; fail-closed): ` +
                    `invalid key length ${configuredKey.length} (expected 64 or 128 hex characters).`,
            );
        }
        if (!HEX_RE.test(configuredKey)) {
            throw new Error(
                `PolicyChangeRecorder: LEDGER_PRIVATE_KEY is invalid (must be 64-byte or 128-byte hex; fail-closed): ` +
                    `key contains non-hexadecimal characters.`,
            );
        }
        let normalizedKey: string;
        let publicKey: string;
        try {
            normalizedKey = normalizeSigningPrivateKey(configuredKey);
            publicKey = derivePublicKeyFromPrivateKey(configuredKey);
        } catch (err) {
            const detail = err instanceof Error ? err.message : String(err);
            throw new Error(
                `PolicyChangeRecorder: LEDGER_PRIVATE_KEY is invalid (must be 64-byte or 128-byte hex; fail-closed): ${detail}`,
            );
        }
        this.ledgerPrivateKey = normalizedKey;
        this.ledgerPublicKey = publicKey;
    }

    // -------------------------------------------------------------------------
    // Single-step write methods (the caller already holds a transactional PoolClient)
    // -------------------------------------------------------------------------

    /**
     * Write a POLICY_CREATED audit record within the caller's transactional PoolClient.
     *
     * Precondition: the caller has already BEGIN-ed a transaction; this method executes within that
     * same transaction.
     * fail-closed: throw on write failure; the caller must ensure ROLLBACK.
     *
     * Transaction enforcement: the first SQL statement is a SAVEPOINT; PostgreSQL throws "SAVEPOINT
     * can only be used in transaction blocks" when executed in a non-transactional context, serving
     * as a DB-level guard. This prevents a write without an open transaction from breaking the hash
     * chain's atomicity.
     */
    public async recordCreated(
        client: PoolClient,
        input: PolicyRecordInput,
    ): Promise<PolicyRecordWriteResult> {
        this.validateActionType(ACTION_POLICY_CREATED, input.params);
        // SAVEPOINT as the first SQL statement; the DB layer enforces that the client must be in a transaction block
        await client.query('SAVEPOINT policy_change_audit_guard');
        return this.writeWithinTransaction(
            client,
            ACTION_POLICY_CREATED,
            input,
        );
    }

    /**
     * Write a POLICY_UPDATED audit record within the caller's transactional PoolClient.
     *
     * Transaction enforcement: same as recordCreated, with SAVEPOINT as the first SQL statement.
     */
    public async recordUpdated(
        client: PoolClient,
        input: PolicyRecordInput,
    ): Promise<PolicyRecordWriteResult> {
        this.validateActionType(ACTION_POLICY_UPDATED, input.params);
        // SAVEPOINT as the first SQL statement; the DB layer enforces that the client must be in a transaction block
        await client.query('SAVEPOINT policy_change_audit_guard');
        return this.writeWithinTransaction(
            client,
            ACTION_POLICY_UPDATED,
            input,
        );
    }

    /**
     * Write a POLICY_REVOKED audit record within the caller's transactional PoolClient.
     *
     * Transaction enforcement: same as recordCreated, with SAVEPOINT as the first SQL statement.
     */
    public async recordRevoked(
        client: PoolClient,
        input: PolicyRecordInput,
    ): Promise<PolicyRecordWriteResult> {
        this.validateActionType(ACTION_POLICY_REVOKED, input.params);
        // SAVEPOINT as the first SQL statement; the DB layer enforces that the client must be in a transaction block
        await client.query('SAVEPOINT policy_change_audit_guard');
        return this.writeWithinTransaction(
            client,
            ACTION_POLICY_REVOKED,
            input,
        );
    }

    // -------------------------------------------------------------------------
    // Automatic transaction wrapping method
    // -------------------------------------------------------------------------

    /**
     * Wrap the policy operation and the audit record write within the same database transaction
     * (atomic write).
     *
     * Transaction order:
     * 1. options.operation(client) (the actual policy operation, within the same transaction)
     * 2. writeWithinTransaction → AJV gate + advisory lock + chain-head query
     * 3. INSERT policy.policy_change_records (audit record written to the standalone table, within
     *    the same transaction, SQL 007)
     *
     * fail-closed: if either step 1 or step 3 throws, the entire transaction is ROLLBACK-ed.
     *
     * @param policyId - the unique policy identifier
     * @param actionType - the change type ('POLICY_CREATED' | 'POLICY_UPDATED' | 'POLICY_REVOKED')
     * @param options - the operation options
     * @returns the return value of the policy operation (type parameter T)
     */
    public async wrapOperation<T>(
        policyId: string,
        actionType: PolicyActionType,
        options: WrapOperationOptions<T>,
    ): Promise<T> {
        this.assertValidPolicyActionType(actionType);

        const changeType = actionType.replace('POLICY_', '') as
            | 'CREATED'
            | 'UPDATED'
            | 'REVOKED';

        const params: PolicyChangeParams = {
            policyId,
            policyVersion: options.policyVersion,
            changeType,
            ...(options.changedFields !== undefined
                ? { changedFields: options.changedFields }
                : {}),
            ...(options.revokedAt !== undefined
                ? { revokedAt: options.revokedAt }
                : {}),
        };

        // step 1 (fail-closed pre-validation): before the transaction opens and operation executes,
        // validate both the params validity and the actorPrivateKey format.
        // Purpose: if either is invalid, abort before any business-logic side effect occurs.
        // operation() may have out-of-transaction side effects here (e.g. issuing HTTP, writing
        // Redis); if validation only happened inside writeWithinTransaction, operation would have
        // already executed but the audit record would not be written → "no audit but state changed"
        // violates the fail-closed promise.
        // The AJV validation inside writeWithinTransaction is kept as second-line defense-in-depth (not removed).
        this.validatePreOperation(params, options.actorPrivateKey);

        return withTransaction(this.dbPool, async (client: PoolClient) => {
            // The policy operation runs first (business logic takes priority), then the audit record is written
            const operationResult = await options.operation(client);

            await this.writeWithinTransaction(client, actionType, {
                agentDid: options.agentDid,
                principalDid: options.principalDid,
                params,
                actorPrivateKey: options.actorPrivateKey,
            });

            return operationResult;
        });
    }

    // -------------------------------------------------------------------------
    // Private method: core write logic
    // -------------------------------------------------------------------------

    /**
     * Perform the hash chain write within the caller's transactional PoolClient.
     *
     * Steps:
     * 1. AJV fail-closed gate (validateAgainstSchema policyChangeParams)
     * 2. lockAgentChain (SELECT pg_advisory_xact_lock(hashtext(agentDid)))
     * 3. loadPreviousRowHash (SELECT row_hash FROM policy.policy_change_records ... FOR UPDATE)
     * 4. buildUnsignedRecordPayload + computeRecordHash + createRecordSignature x2
     * 5. INSERT INTO policy.policy_change_records (standalone table, SQL migration 007)
     *
     * Does not open a new transaction (managed by the caller), satisfying the same-transaction
     * atomic-write requirement.
     */
    private async writeWithinTransaction(
        client: PoolClient,
        actionType: PolicyActionType,
        input: PolicyRecordInput,
    ): Promise<PolicyRecordWriteResult> {
        const recordId = input.recordId ?? randomUUID();
        const createdAt = (input.createdAt ??
            new Date().toISOString()) as Timestamp;
        const outputEncoding = LEDGER_ENCODING;

        // 0. AJV-validate PolicyChangeParams (fail-closed)
        // Run before any DB operation to prevent invalid data from being written into the
        // tamper-proof audit ledger.
        // validateAgainstSchema returns { valid, errors } and does not throw automatically;
        // fail-closed requires explicit checking and throwing.
        const paramsValidation = validateAgainstSchema(
            input.params,
            SCHEMA_IDS.policyChangeParams,
        );
        if (!paramsValidation.valid) {
            const detail = paramsValidation.errors
                .map((e) => `${e.instancePath} ${e.message}`)
                .join('; ');
            throw new Error(
                `PolicyChangeRecorder: invalid PolicyChangeParams (fail-closed): ${detail}`,
            );
        }

        // 1. Row-level lock (prevents concurrent writes to the same agent's hash chain, consistent with ActionRecorder logic)
        await client.query(
            'SELECT pg_advisory_xact_lock(hashtext($1))',
            [input.agentDid],
        );

        // 2. Load the previous record hash (the hash chain link point)
        // The standalone table policy_change_records uses the row_hash field (distinct from action_records.record_hash).
        // FOR UPDATE and the advisory lock doubly protect against concurrent writes.
        const prevResult = await client.query<{ row_hash: string }>(
            `SELECT row_hash
             FROM policy.policy_change_records
             WHERE agent_did = $1
             ORDER BY id DESC
             LIMIT 1
             FOR UPDATE`,
            [input.agentDid],
        );
        const previousRecordHash = prevResult.rows[0]?.row_hash ?? '';

        // 3. Build the payload, compute the hash, and create the dual signatures
        const parametersSummary =
            input.params as unknown as Record<string, unknown>;

        const unsignedPayload = buildUnsignedRecordPayload({
            recordId,
            agentDid: input.agentDid,
            principalDid: input.principalDid,
            actionType,
            parametersSummary,
            authorizationRef: null,
            resultSummary: null,
            previousRecordHash,
            createdAt,
        });

        const recordHash = computeRecordHash(
            unsignedPayload,
            previousRecordHash,
            outputEncoding,
        );

        const actorSignature = createRecordSignature(
            unsignedPayload,
            input.actorPrivateKey,
            outputEncoding,
        );

        const ledgerSignature = createRecordSignature(
            unsignedPayload,
            this.ledgerPrivateKey,
            outputEncoding,
        );

        // 4. INSERT INTO the standalone table policy_change_records (SQL migration 007)
        // For the field design, see 007-create-policy-change-records.sql:
        // - params (JSONB) = PolicyChangeParams
        // - row_hash = this row's hash (recordHash)
        // - prev_row_hash = the previous row's hash (the chain's first row = '')
        await client.query(
            `INSERT INTO policy.policy_change_records (
                record_id,
                agent_did,
                principal_did,
                action_type,
                params,
                row_hash,
                prev_row_hash,
                actor_signature,
                ledger_signature,
                created_at
            ) VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7, $8, $9, $10)`,
            [
                recordId,
                input.agentDid,
                input.principalDid,
                actionType,
                JSON.stringify(parametersSummary),
                recordHash,
                previousRecordHash,
                actorSignature,
                ledgerSignature,
                createdAt,
            ],
        );

        return { recordId, hash: recordHash };
    }

    /**
     * Unified pre-validation gate (fail-closed).
     *
     * Validates before any transaction opens and operation() executes:
     * 1. params validity (AJV, reusing the existing wrapOperation validation logic)
     * 2. actorPrivateKey format (abort if normalizeSigningPrivateKey throws)
     *
     * Purpose: prevent the inconsistent state where "operation() has already executed and produced
     *          business side effects, but the key is invalid at the signing stage → the audit record
     *          write fails → there is no audit record but the policy state has already changed".
     *
     * The AJV validation inside wrapOperation (step 1) already covers params; this method adds an
     * actorPrivateKey format check, forming a "params + actorPrivateKey" double pre-operation gate.
     * The record* method paths also need to validate actorPrivateKey, but record* leaves transaction
     * management to the caller; within its writeWithinTransaction, createRecordSignature throws at the
     * signing stage and the caller must roll back on their own; this gate applies only to the
     * wrapOperation path.
     */
    private validatePreOperation(
        params: PolicyChangeParams,
        actorPrivateKey: string,
    ): void {
        // 1. AJV-validate params (same logic as the existing wrapOperation validation, a unified entry point)
        const validation = validateAgainstSchema(
            params,
            SCHEMA_IDS.policyChangeParams,
        );
        if (!validation.valid) {
            const detail = validation.errors
                .map((e) => `${e.instancePath} ${e.message}`)
                .join('; ');
            throw new Error(
                `PolicyChangeRecorder: invalid PolicyChangeParams (pre-operation fail-closed): ${detail}`,
            );
        }

        // 2. actorPrivateKey format check (validated before operation executes, to prevent a throw at the signing stage)
        // Accepted: 64-char hex (32-byte seed) or 128-char hex (64-byte expanded key).
        // Note: normalizeSigningPrivateKey does not throw on non-64-char input (it passes it through),
        // so the length and hex characters must be checked explicitly before calling. This is
        // consistent with the constructor's LEDGER_PRIVATE_KEY validation logic.
        const HEX_RE = /^[0-9a-fA-F]+$/;
        if (
            actorPrivateKey.length !== 64 &&
            actorPrivateKey.length !== 128
        ) {
            throw new Error(
                `PolicyChangeRecorder: invalid actorPrivateKey (pre-operation fail-closed): ` +
                    `invalid key length ${actorPrivateKey.length} (expected 64 or 128 hex characters).`,
            );
        }
        if (!HEX_RE.test(actorPrivateKey)) {
            throw new Error(
                `PolicyChangeRecorder: invalid actorPrivateKey (pre-operation fail-closed): ` +
                    `key contains non-hexadecimal characters.`,
            );
        }
        try {
            normalizeSigningPrivateKey(actorPrivateKey);
        } catch (err) {
            const detail = err instanceof Error ? err.message : String(err);
            throw new Error(
                `PolicyChangeRecorder: invalid actorPrivateKey (pre-operation fail-closed): ${detail}`,
            );
        }
    }

    /**
     * Validate the correspondence between params.changeType and actionType.
     *
     * fail-closed: throw on a mismatch (a programming error; prevents audit data inconsistency).
     */
    private validateActionType(
        expectedActionType: PolicyActionType,
        params: PolicyChangeParams,
    ): void {
        const expectedChangeType = expectedActionType.replace(
            'POLICY_',
            '',
        ) as PolicyChangeParams['changeType'];
        if (params.changeType !== expectedChangeType) {
            throw new Error(
                `PolicyChangeRecorder: params.changeType='${params.changeType}' ` +
                    `does not match actionType='${expectedActionType}' ` +
                    `(expected changeType='${expectedChangeType}'). ` +
                    `Audit data consistency violation (fail-closed).`,
            );
        }
    }

    /** Assert that actionType is within the POLICY_ACTION_TYPES allowlist (fail-closed). */
    private assertValidPolicyActionType(actionType: string): void {
        if (!(POLICY_ACTION_TYPES as readonly string[]).includes(actionType)) {
            throw new Error(
                `PolicyChangeRecorder: unknown actionType='${actionType}'. ` +
                    `Must be one of: ${POLICY_ACTION_TYPES.join(', ')}.`,
            );
        }
    }
}

// ---------------------------------------------------------------------------
// toTimestamp re-export (for use by tests / the integration layer)
// ---------------------------------------------------------------------------
export { toTimestamp };
