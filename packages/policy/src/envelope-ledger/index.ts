/**
 * envelope-ledger/index.ts -- EnvelopeLedger module public exports
 *
 */

export { EnvelopeLedger, type EnvelopeLedgerOptions } from './envelope-ledger.js';
export {
    // types
    LEDGER_CLAIM_STATUSES,
    isLedgerClaimStatus,
    parseLedgerClaimStatus,
    type LedgerClaimStatus,
    type EnvelopeLedgerEntry,
    // claim()
    type ClaimResult,
    type ClaimSuccess,
    type ClaimConflict,
    type ClaimConflictReason,
    // finalize()
    type FinalizeResult,
    type FinalizeSuccess,
    type FinalizeFailure,
    type FinalizeFailureReason,
    // reject()
    type RejectResult,
    type RejectSuccess,
    type RejectFailure,
    type RejectFailureReason,
    // expireStalePending()
    type ExpireResult,
} from './types.js';
