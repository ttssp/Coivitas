/**
 * Dispute Arbitration L3 barrel export
 *
 * Sub-protocol — dispute-arbitration v0.1
 */

// Port interfaces
export type {
    MultisigPort,
    ArbitratorSelector,
    EvidenceStore,
    RevocationChecker,
    SignatureVerifier,
    AtpRecorder,
    DisputeStore,
    DisputeTransactionContext,
    DisputeTxManager,
} from './ports.js';

// State machine
export type {
    DisputeArbitrationInput,
    DisputeArbitrationResult,
} from './state-machine.js';

export {
    validateStateTransition,
    computeThreshold,
    checkAndExpireDispute,
    computeDisputeFilingCanonicalHash,
    runDisputeArbitration7Steps,
    runDisputeExpiry,
} from './state-machine.js';
