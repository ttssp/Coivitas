/**
 * Dispute Arbitration L0 barrel export
 *
 * Sub-protocol — dispute-arbitration v0.1
 */

// Constants
export {
    MIN_ARBITRATOR_COUNT,
    MAX_ARBITRATOR_COUNT,
    MAX_DISPUTE_DAYS,
    MAX_DISPUTE_MS,
    DA_VERSION_CURRENT,
    DA_SUPPORTED_VERSIONS,
    DA_VERDICT_VALUES,
    DA_DISPUTE_TYPE_VALUES,
    DA_STATE_VALUES,
} from './constants.js';

// Types
export type {
    DisputeId,
    DaVersion,
    SettlementOperationId,
    CanonicalHashHex,
    DisputeState,
    DisputeType,
    DaVerdict,
    Arbitrator,
    ArbitratorSignature,
    DisputeFiling,
    DisputeFilingSignedPayload,
    ArbitrationDecision,
    Dispute,
    DisputeStateTransitionEvent,
} from './types.js';

export { DISPUTE_STATE_TRANSITIONS } from './types.js';

// Errors
export type { DaErrorCode } from './errors.js';
export { DaError, handleDaError, assertNeverDaCode } from './errors.js';

// Factories
export {
    toDisputeId,
    toDaVersion,
    toSettlementOperationId,
    toCanonicalHashHex,
    DA_VERSION_1_0_0,
} from './factories.js';

// Schema
export {
    DISPUTE_FILING_SIGNED_PAYLOAD_SCHEMA,
    ARBITRATION_DECISION_SCHEMA,
    DISPUTE_SCHEMA,
    validateDisputeFilingSchema,
    validateArbitrationDecisionSchema,
    assertValidDisputeFiling,
    assertValidArbitrationDecision,
} from './schemas.js';
