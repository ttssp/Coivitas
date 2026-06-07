/**
 * RecipientSettleHandler — recipient-side settle append protocol (production implementation)
 *
 * Design points:
 * 1. Signatures: Ed25519 (@coivitas/crypto sign/verify), replacing the earlier HMAC-SHA256 approach
 * 2. Idempotent writes: ON CONFLICT DO NOTHING + a concurrent-race SELECT fallback
 * 3. TTL hard boundary: confirmSettle adds an expires_at > NOW() condition
 * 4. Batch confirmSettle: the caller passes a batch of settleId values; a single UPDATE … WHERE IN (…)
 *
 * Does not touch: IntegrityChecker / ActionRecorder / audit-* / recorder (firewall).
 * Does not use: later-stage error codes such as CROSS_ORG_* / ARBITRATION_* / MIRROR_PROOF_*.
 */

import { sign, verify } from '@coivitas/crypto';
import type { DatabasePool } from '@coivitas/shared';

import { buildSettlePayload, toISOString } from './payload.js';
import type {
    SettleProtocolConfig,
    SettleRecord,
    SettleRequest,
    SettleRow,
} from './types.js';
import { DEFAULT_CONFIG } from './types.js';

export class RecipientSettleHandler {
    public constructor(
        private readonly pool: DatabasePool,
        private readonly schema: string,
        /** recipient-domain ledger private key (Ed25519 hex, used for countersigning)*/
        private readonly recipientPrivateKey: string,
        private readonly config: SettleProtocolConfig = DEFAULT_CONFIG,
    ) {}

    /**
     * Receive and persist a settle request.
     *
     * Protocol semantics:
     * 1. Verify the sender Ed25519 ledger signature (using the sender public key)
     * 2. Idempotency check: same settleId already exists → return the existing record
     * 3. recipient countersigns (Ed25519)
     * 4. Write PENDING, expires_at = NOW() + TTL
     *
     * @param req settle request (from the sender domain)
     * @param senderPublicKey sender-domain ledger public key (Ed25519 hex, used to verify senderLedgerSignature)
     */
    public async appendSettle(
        req: SettleRequest,
        senderPublicKey: string,
    ): Promise<SettleRecord> {
        // 1. verify the sender ledger signature (Ed25519)
        const payload = buildSettlePayload(req);
        const payloadBytes = Buffer.from(payload, 'utf-8');
        const valid = verify(
            payloadBytes,
            req.senderLedgerSignature,
            senderPublicKey,
        );
        if (!valid) {
            throw new Error(
                `SETTLE_SIGNATURE_INVALID: sender ledger signature verification failed for settle ${req.settleId}`,
            );
        }

        // 2. idempotency check: return directly if the settleId already exists
        const existing = await this.pool.query<SettleRow>(
            `SELECT * FROM ${this.schema}.settle_records WHERE settle_id = $1`,
            [req.settleId],
        );
        if (existing.rows.length > 0) {
            return this.mapRow(existing.rows[0]!);
        }

        // 3. recipient-domain countersignature (Ed25519)
        const recipientSig = sign(payloadBytes, this.recipientPrivateKey);

        // 4. compute the expiry time
        const now = new Date();
        const expiresAt = new Date(now.getTime() + this.config.pendingTtlMs);

        // 5. write PENDING; ON CONFLICT DO NOTHING handles concurrent-race idempotency
        const result = await this.pool.query<SettleRow>(
            `INSERT INTO ${this.schema}.settle_records
             (settle_id, sender_domain, recipient_domain, agent_did, metric,
              amount, "window", window_start, sender_ledger_signature,
              recipient_ledger_signature, state, created_at, expires_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'PENDING', $11, $12)
             ON CONFLICT (settle_id) DO NOTHING
             RETURNING *`,
            [
                req.settleId,
                req.senderDomain,
                req.recipientDomain,
                req.agentDid,
                req.metric,
                req.amount,
                req.window,
                req.windowStart,
                req.senderLedgerSignature,
                recipientSig,
                now.toISOString(),
                expiresAt.toISOString(),
            ],
        );

        // when ON CONFLICT DO NOTHING wins a race, RETURNING is empty: SELECT once more
        if (result.rows.length === 0) {
            const retry = await this.pool.query<SettleRow>(
                `SELECT * FROM ${this.schema}.settle_records WHERE settle_id = $1`,
                [req.settleId],
            );
            return this.mapRow(retry.rows[0]!);
        }

        return this.mapRow(result.rows[0]!);
    }

    /**
     * Batch-confirm settles (PENDING → SETTLED).
     *
     * No longer UPDATEs row by row; uses a single batch update with WHERE settle_id = ANY($1).
     * Adds an expires_at > NOW() condition to prevent confirming already-expired PENDING records.
     * TTL provides a hard release boundary — once expired, confirmSettle silently skips even if the reaper is not running.
     *
     * @param settleIds list of settle IDs to confirm
     */
    public async confirmSettle(settleIds: string[]): Promise<void> {
        if (settleIds.length === 0) return;
        await this.pool.query(
            `UPDATE ${this.schema}.settle_records
             SET state = 'SETTLED', settled_at = NOW()
             WHERE settle_id = ANY($1) AND state = 'PENDING' AND expires_at > NOW()`,
            [settleIds],
        );
        // already-expired, already-SETTLED, and already-RELEASED are all valid idempotent cases; do not throw
    }

    /**
     * TTL-expiry reaping job: batch-mark timed-out PENDING records as RELEASED.
     * @returns the number of records reaped
     */
    public async reapExpiredPending(): Promise<number> {
        const result = await this.pool.query(
            `UPDATE ${this.schema}.settle_records
             SET state = 'RELEASED'
             WHERE state = 'PENDING' AND expires_at < NOW()`,
        );
        return result.rowCount ?? 0;
    }

    /**
     * Query settle records matching the given conditions (for sender-side pull reconciliation).
     *
     * Uses a (created_at, settle_id) composite cursor to avoid skipping records during high-concurrency batch INSERTs.
     *
     * @param params query parameters
     */
    public async querySettles(params: {
        senderDomain: string;
        agentDid: string;
        metric: string;
        /** composite cursor: the last created_at from the previous reconciliation (ISO 8601)*/
        afterCreatedAt?: string;
        /** composite cursor: the last settle_id from the previous reconciliation (tie-breaker)*/
        afterSettleId?: string;
        limit: number;
    }): Promise<SettleRecord[]> {
        const values: unknown[] = [
            params.senderDomain,
            params.agentDid,
            params.metric,
        ];

        let cursorClause = '';
        if (params.afterCreatedAt && params.afterSettleId) {
            // composite cursor: (created_at, settle_id) > (afterCreatedAt, afterSettleId)
            // ROW comparison leverages PG row-type semantics to correctly handle multiple records with the same created_at
            cursorClause = ` AND (created_at, settle_id) > ($${values.length + 1}::TIMESTAMPTZ, $${values.length + 2})`;
            values.push(params.afterCreatedAt, params.afterSettleId);
        }

        const query = `
            SELECT * FROM ${this.schema}.settle_records
            WHERE sender_domain = $1 AND agent_did = $2 AND metric = $3
            ${cursorClause}
            ORDER BY created_at ASC, settle_id ASC
            LIMIT $${values.length + 1}
        `;
        values.push(params.limit);

        const result = await this.pool.query<SettleRow>(query, values);
        return result.rows.map((r) => this.mapRow(r));
    }

    private mapRow(row: SettleRow): SettleRecord {
        return {
            settleId: row.settle_id,
            senderDomain: row.sender_domain,
            recipientDomain: row.recipient_domain,
            agentDid: row.agent_did,
            metric: row.metric,
            amount: Number(row.amount),
            window: row.window,
            // PG Date objects must use toISOString(), not String()
            windowStart: toISOString(row.window_start),
            senderLedgerSignature: row.sender_ledger_signature,
            recipientLedgerSignature: row.recipient_ledger_signature,
            state: row.state as SettleRecord['state'],
            createdAt: toISOString(row.created_at),
            settledAt: row.settled_at ? toISOString(row.settled_at) : null,
            expiresAt: toISOString(row.expires_at),
        };
    }
}
