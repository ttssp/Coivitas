/**
 * AuditMetaLedger — reserved interface for the "audit of the audit"
 *
 * Interface skeleton + NullAuditMetaLedger no-op implementation (zero performance overhead).
 * The production implementation is PostgresAuditMetaLedger with hash chain + batch buffer.
 *
 * Design rationale:
 *   - Dependencies not ready (requires a separate SQL migration 006-meta-ledger)
 *   - Write amplification risk (a later batch/buffer strategy evaluation)
 *   - Current substitute: HTTP-layer access log + X-Audit-Requester header
 *   - Reserving the interface lets the production implementation avoid changing the middleware signature
 */

import type {
    AuditAccessErrorCode,
    AuditEventRecord,
} from '@coivitas/types';
import type { AuditResourceBinding } from '../audit/types.js';

export type { AuditEventRecord };

/**
 * meta-ledger write interface
 *
 */
export interface AuditMetaLedger {
    /**
     * Record a single audit query event.
     *
     * Not implemented by the NullAuditMetaLedger no-op implementation.
     * The PostgresAuditMetaLedger standard implementation provides hash chain tamper-evidence.
     */
    recordEvent(event: AuditMetaLedgerEvent): Promise<void>;

    /**
     * Verify the integrity of the meta-ledger chain.
     *
     * Not implemented by the no-op implementation.
     * The production implementation performs row-by-row prevEventHash verification + genesis hash check.
     */
    verifyChain?(): Promise<{ valid: boolean; brokenAt?: string }>;
}

/**
 * meta-ledger event parameters (built when the audit middleware calls it)
 */
export interface AuditMetaLedgerEvent {
    /** Audit querier DID */
    requesterDid: string;
    /** Queried target agent DID */
    targetAgentDid: string;
    /** Query route */
    route: AuditResourceBinding['route'];
    /** Authorization decision */
    decision: 'allowed' | 'denied';
    /** Error code if denied */
    errorCode?: AuditAccessErrorCode;
    /** Event timestamp (ISO 8601 UTC) */
    timestamp: string;
    /** Associated nonce (present in v0.2) */
    nonce?: string;
}

/**
 * No-op implementation of meta-ledger.
 *
 * All calls are no-ops with zero performance overhead.
 * Replaced by injecting PostgresAuditMetaLedger.
 *
 */
export class NullAuditMetaLedger implements AuditMetaLedger {
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    public recordEvent(_event: AuditMetaLedgerEvent): Promise<void> {
        return Promise.resolve();
    }
}
