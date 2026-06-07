/**
 * SenderSettleTracker — sender-side settle creation + pull reconciliation tracking (production implementation)
 *
 * Design points:
 * 1. Signatures: Ed25519 (@coivitas/crypto sign/verify)
 * 2. Cursor: (created_at, settle_id) composite key
 * 3. Batch reconcile confirmation: call RecipientSettleHandler.confirmSettle(settleIds[]) for a single update
 *
 * Reconciliation cursor advancement strategy:
 * The cursor advances to the end of the batch regardless of whether any verified=false records exist in it.
 * Rationale: liveness first > at-least-once-retry. Letting a tampered record block the cursor would stall the reconciliation loop.
 * The caller should check results[].verified=false and route it to the alert channel, manually resetting the cursor if necessary.
 */

import { randomUUID } from 'node:crypto';

import { sign, verify } from '@coivitas/crypto';
import type { DatabasePool } from '@coivitas/shared';

import { buildSettlePayload, toISOString } from './payload.js';
import type { RecipientSettleHandler } from './settle-handler.js';
import type {
    CursorRow,
    ReconciliationCursor,
    ReconciliationResult,
    SettleProtocolConfig,
    SettleRequest,
} from './types.js';
import { DEFAULT_CONFIG } from './types.js';

export class SenderSettleTracker {
    public constructor(
        private readonly localPool: DatabasePool,
        private readonly localSchema: string,
        /** sender-domain ledger private key (Ed25519 hex, used to sign settle requests)*/
        private readonly senderPrivateKey: string,
        /** sender-domain ledger public key (Ed25519 hex, stored for reconciliation reference)*/
        private readonly senderPublicKey: string,
        private readonly senderDomain: string,
        private readonly config: SettleProtocolConfig = DEFAULT_CONFIG,
    ) {}

    /**
     * Create and sign a settle request (Ed25519).
     * The returned SettleRequest is sent by the caller to the recipient domain over the transport layer.
     */
    public createSettleRequest(params: {
        recipientDomain: string;
        agentDid: string;
        metric: string;
        amount: number;
        window: 'hour' | 'day' | 'week' | 'month';
        windowStart: string;
    }): SettleRequest {
        const settleId = randomUUID();
        const payload = buildSettlePayload({
            settleId,
            senderDomain: this.senderDomain,
            recipientDomain: params.recipientDomain,
            agentDid: params.agentDid,
            metric: params.metric,
            amount: params.amount,
            window: params.window,
            windowStart: params.windowStart,
        });
        const payloadBytes = Buffer.from(payload, 'utf-8');
        const signature = sign(payloadBytes, this.senderPrivateKey);

        return {
            settleId,
            senderDomain: this.senderDomain,
            recipientDomain: params.recipientDomain,
            agentDid: params.agentDid,
            metric: params.metric,
            amount: params.amount,
            window: params.window,
            windowStart: params.windowStart,
            senderLedgerSignature: signature,
            createdAt: new Date().toISOString(),
        };
    }

    /**
     * Pull-mode reconciliation: pull settle records from the recipient domain, batch-verify signatures, update the local composite cursor.
     *
     * Returns: a reconciliation result per record (settleId, state, verified).
     * verified=true: recipient Ed25519 signature passes, settle is trusted.
     * verified=false: signature verification failed, must route to the alert channel.
     *
     * Batch confirmation: a single UPDATE WHERE settle_id = ANY(confirmedIds).
     *
     * @param recipientHandler recipient-side handler instance (simulates a cross-domain call)
     * @param recipientPublicKey recipient-domain ledger public key (Ed25519 hex)
     * @param agentDid agent DID
     * @param metric measurement metric
     * @param recipientDomain recipient-domain identifier
     */
    public async reconcile(
        recipientHandler: RecipientSettleHandler,
        recipientPublicKey: string,
        agentDid: string,
        metric: string,
        recipientDomain: string,
    ): Promise<ReconciliationResult[]> {
        // 1. read the local composite reconciliation cursor
        const cursor = await this.getCursor(agentDid, metric, recipientDomain);

        // 2. pull new records from the recipient domain (composite cursor pagination)
        const records = await recipientHandler.querySettles({
            senderDomain: this.senderDomain,
            agentDid,
            metric,
            afterCreatedAt: cursor.lastCreatedAt ?? undefined,
            afterSettleId: cursor.lastSettleId ?? undefined,
            limit: this.config.reconcileBatchSize,
        });

        if (records.length === 0) {
            return [];
        }

        // 3. batch-verify recipient Ed25519 signatures
        const results: ReconciliationResult[] = [];
        const confirmedIds: string[] = [];

        for (const record of records) {
            const payload = buildSettlePayload({
                settleId: record.settleId,
                senderDomain: record.senderDomain,
                recipientDomain: record.recipientDomain,
                agentDid: record.agentDid,
                metric: record.metric,
                amount: record.amount,
                window: record.window,
                windowStart: record.windowStart,
            });
            const payloadBytes = Buffer.from(payload, 'utf-8');
            const verified = verify(
                payloadBytes,
                record.recipientLedgerSignature,
                recipientPublicKey,
            );

            // result.state reflects the "fetch-time" state (PENDING); confirmSettle only
            // takes effect after verified; if the caller needs the post-reconcile SETTLED state, it should
            // query the recipient directly.
            results.push({
                settleId: record.settleId,
                state: record.state,
                recipientLedgerSignature: record.recipientLedgerSignature,
                verified,
            });

            // collect verified records still in PENDING state for subsequent batch confirmation
            if (verified && record.state === 'PENDING') {
                confirmedIds.push(record.settleId);
            }
        }

        // 4. batch confirm (a single UPDATE WHERE IN), no longer serial row by row
        if (confirmedIds.length > 0) {
            await recipientHandler.confirmSettle(confirmedIds);
        }

        // 5. update the composite cursor (advance to the end of the batch, liveness-first strategy)
        const lastRecord = records[records.length - 1]!;
        await this.updateCursor(
            agentDid,
            metric,
            recipientDomain,
            lastRecord.createdAt,
            lastRecord.settleId,
        );

        return results;
    }

    private async getCursor(
        agentDid: string,
        metric: string,
        recipientDomain: string,
    ): Promise<ReconciliationCursor> {
        const result = await this.localPool.query<CursorRow>(
            `SELECT last_created_at, last_settle_id, last_reconciled_at
             FROM ${this.localSchema}.reconciliation_cursors
             WHERE sender_domain = $1 AND recipient_domain = $2
               AND agent_did = $3 AND metric = $4`,
            [this.senderDomain, recipientDomain, agentDid, metric],
        );

        if (result.rows.length === 0) {
            return {
                lastCreatedAt: null,
                lastSettleId: null,
                lastReconciledAt: null,
            };
        }

        const row = result.rows[0]!;
        return {
            lastCreatedAt: row.last_created_at
                ? toISOString(row.last_created_at)
                : null,
            lastSettleId: row.last_settle_id,
            lastReconciledAt: row.last_reconciled_at
                ? toISOString(row.last_reconciled_at)
                : null,
        };
    }

    private async updateCursor(
        agentDid: string,
        metric: string,
        recipientDomain: string,
        lastCreatedAt: string,
        lastSettleId: string,
    ): Promise<void> {
        await this.localPool.query(
            `INSERT INTO ${this.localSchema}.reconciliation_cursors
             (sender_domain, recipient_domain, agent_did, metric, last_created_at, last_settle_id, last_reconciled_at)
             VALUES ($1, $2, $3, $4, $5::TIMESTAMPTZ, $6, NOW())
             ON CONFLICT (sender_domain, recipient_domain, agent_did, metric)
             DO UPDATE SET
               last_created_at = EXCLUDED.last_created_at,
               last_settle_id = EXCLUDED.last_settle_id,
               last_reconciled_at = NOW()`,
            [
                this.senderDomain,
                recipientDomain,
                agentDid,
                metric,
                lastCreatedAt,
                lastSettleId,
            ],
        );
    }
}
