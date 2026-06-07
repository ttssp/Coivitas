/**
 * Dispute Arbitration L0 constant definitions
 *
 * Sub-protocol — dispute-arbitration v0.1
 *
 * Three-layer enforcement:
 *   Layer 1 (spec layer): MIN_ARBITRATOR_COUNT = 3 (this file)
 *   Layer 2 (SQL DDL layer): CHECK (multisig_pool_size >= 3 AND multisig_pool_size <= 5)
 *   Layer 3 (algorithm layer): computeThreshold() throws DA_ARBITRATOR_INSUFFICIENT below MIN
 *
 * A missing layer blocks; the three layers must stay consistent in lockstep.
 */

// ─── Arbitrator pool size constraints (three-layer enforcement — spec layer) ──────────────────────────

/**
 * Minimum arbitrator pool size
 *
 * Hard lower bound = 3;
 * any arbitration proceeding must run in a pool of >=3 arbitrators;
 * below this value → the algorithm layer throws DA_ARBITRATOR_INSUFFICIENT.
 */
export const MIN_ARBITRATOR_COUNT = 3 as const;

/**
 * Maximum arbitrator pool size
 *
 * Maximum 5-arbitrator pool; exceeding it → DA_ARBITRATOR_INVALID.
 */
export const MAX_ARBITRATOR_COUNT = 5 as const;

// ─── Dispute lifecycle constraints ────────────────────────────────────────────────────────

/**
 * Maximum dispute lifetime in days (14-day hard upper bound)
 *
 * filedAt + MAX_DISPUTE_DAYS * 24h → EXPIRED terminal state.
 * Exceeding it → FILED automatically transitions to EXPIRED; irreversible.
 */
export const MAX_DISPUTE_DAYS = 14 as const;

/**
 * Maximum dispute lifetime in milliseconds (derived from MAX_DISPUTE_DAYS)
 */
export const MAX_DISPUTE_MS = MAX_DISPUTE_DAYS * 24 * 3600 * 1000;

// ─── Version constants ────────────────────────────────────────────────────────────────

/**
 * Current dispute-arbitration protocol version
 *
 * The only valid value for the daVersion field; v0.1 spec frozen.
 */
export const DA_VERSION_CURRENT = '1.0.0' as const;

/**
 * List of supported DA versions (used for DA_VERSION_UNSUPPORTED validation)
 */
export const DA_SUPPORTED_VERSIONS = ['1.0.0'] as const;

// ─── Arbitration result constants ────────────────────────────────────────────────────────

/**
 * Valid verdict enum values (ArbitrationDecision.verdict)
 */
export const DA_VERDICT_VALUES = [
    'CLAIMANT_PREVAILS',
    'RESPONDENT_PREVAILS',
    'NO_FAULT',
] as const;

/**
 * Valid dispute type enum values (DisputeType)
 */
export const DA_DISPUTE_TYPE_VALUES = [
    'SETTLEMENT_FAILED',
    'SCOPE_VIOLATION',
    'IDENTITY_FRAUD',
    'DELEGATION_REVOCATION_ABUSE',
    'DATA_ACCESS_BREACH',
] as const;

/**
 * Valid dispute state enum values (3-state reduction: FILED / RESOLVED / EXPIRED)
 */
export const DA_STATE_VALUES = ['FILED', 'RESOLVED', 'EXPIRED'] as const;
