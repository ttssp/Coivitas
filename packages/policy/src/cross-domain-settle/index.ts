/**
 * Cross-trust-domain cumulative settle protocol
 *
 * Production implementation based on pull-mode reconciliation + an Ed25519 signature chain.
 *
 * Exports:
 * - RecipientSettleHandler: recipient-side settle append + TTL reaping
 * - SenderSettleTracker: sender-side settle request creation + pull reconciliation
 * - PendingReaper: background TTL-expiry reaping job
 * - initDomainSchema / dropDomainSchema: schema initialization (runtime DDL)
 * - buildSettlePayload: settle payload construction (deterministic JSON)
 * - types: SettleState / SettleRequest / SettleRecord / ReconciliationResult / SettleProtocolConfig
 */

export { PendingReaper } from './pending-reaper.js';
export { buildSettlePayload, toISOString } from './payload.js';
export { dropDomainSchema, initDomainSchema } from './schema.js';
export { RecipientSettleHandler } from './settle-handler.js';
export { SenderSettleTracker } from './settle-tracker.js';
export type {
    CursorRow,
    ReconciliationCursor,
    ReconciliationResult,
    SettleProtocolConfig,
    SettleRecord,
    SettleRequest,
    SettleRow,
    SettleState,
} from './types.js';
export { DEFAULT_CONFIG } from './types.js';
