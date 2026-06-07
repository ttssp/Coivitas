/**
 * Cross-trust-domain cumulative settle protocol type definitions
 *
 * Production specification points:
 * - Signatures use @coivitas/crypto Ed25519
 * - The cursor uses a (created_at, settle_id) composite key
 * - Schema name escaping
 *
 * Trust model: intra-org-only
 * The two domains share the same organization's ops infrastructure and hold independent ledger keys for audit independence.
 */

/** Settlement record state machine: PENDING → SETTLED | RELEASED (TTL-expiry reaping path)*/
export type SettleState = 'PENDING' | 'SETTLED' | 'RELEASED';

/**
 * Cross-domain settle request (sender → recipient)
 *
 * The sender domain creates the request and signs it with senderLedgerKey.
 * The recipient domain verifies the signature, writes the PENDING state, and adds its own countersignature.
 */
export interface SettleRequest {
    /** globally unique settle ID (idempotency key, UUID v4)*/
    settleId: string;
    /** sender-domain identifier*/
    senderDomain: string;
    /** recipient-domain identifier*/
    recipientDomain: string;
    /** agent DID*/
    agentDid: string;
    /** measurement metric key (metering field registry key)*/
    metric: string;
    /** settle amount (SUM type; COUNT type is fixed at 1)*/
    amount: number;
    /** time window*/
    window: 'hour' | 'day' | 'week' | 'month';
    /** window start time (UTC ISO 8601)*/
    windowStart: string;
    /** sender-domain ledger signature (Ed25519 hex signature over the settle payload)*/
    senderLedgerSignature: string;
    /** settle creation time (UTC ISO 8601)*/
    createdAt: string;
}

/**
 * recipient-side settle record (returned after being written to the recipient-domain database)
 */
export interface SettleRecord {
    settleId: string;
    senderDomain: string;
    recipientDomain: string;
    agentDid: string;
    metric: string;
    amount: number;
    window: string;
    windowStart: string;
    senderLedgerSignature: string;
    /** recipient-domain ledger Ed25519 hex countersignature over the settle payload (reconciliation credential)*/
    recipientLedgerSignature: string;
    state: SettleState;
    createdAt: string;
    settledAt: string | null;
    expiresAt: string;
}

/**
 * sender-side single reconciliation result
 */
export interface ReconciliationResult {
    settleId: string;
    state: SettleState;
    recipientLedgerSignature: string;
    /** reconciliation succeeded: recipient Ed25519 signature verification passed*/
    verified: boolean;
}

/**
 * Protocol configuration
 */
export interface SettleProtocolConfig {
    /** TTL of the PENDING state (milliseconds), default 5 minutes*/
    pendingTtlMs: number;
    /** reaping job polling interval (milliseconds), default 30 seconds*/
    reapIntervalMs: number;
    /** reconciliation pull batch size, default 100*/
    reconcileBatchSize: number;
}

/** Default protocol configuration*/
export const DEFAULT_CONFIG: SettleProtocolConfig = {
    pendingTtlMs: 5 * 60 * 1000, // 5 minutes
    reapIntervalMs: 30 * 1000, // 30 seconds
    reconcileBatchSize: 100,
};

/**
 * Reconciliation cursor (composite key prevents skipping records with the same created_at)
 */
export interface ReconciliationCursor {
    /** created_at of the last record from the previous reconciliation (ISO 8601)*/
    lastCreatedAt: string | null;
    /** settle_id of the last record from the previous reconciliation (tie-breaker)*/
    lastSettleId: string | null;
    /** time of the last reconciliation*/
    lastReconciledAt: string | null;
}

/**
 * DB row type (snake_case, raw format returned by the PG driver)
 * TIMESTAMPTZ columns are returned as Date objects by the PG node driver; must be converted via toISOString().
 */
export interface SettleRow {
    settle_id: string;
    sender_domain: string;
    recipient_domain: string;
    agent_did: string;
    metric: string;
    amount: string | number;
    window: string;
    window_start: string | Date;
    sender_ledger_signature: string;
    recipient_ledger_signature: string;
    state: string;
    created_at: string | Date;
    settled_at: string | Date | null;
    expires_at: string | Date;
}

export interface CursorRow {
    sender_domain: string;
    recipient_domain: string;
    agent_did: string;
    metric: string;
    last_created_at: string | Date | null;
    last_settle_id: string | null;
    last_reconciled_at: string | Date | null;
}
