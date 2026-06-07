/**
 * types.ts -- EnvelopeLedger type definitions
 *
 * 4-state state machine:
 *   PENDING → COMMITTED (terminal, successful finalize)
 *   PENDING → REJECTED (terminal, explicit reject)
 *   PENDING → EXPIRED (reclaimable, batch-reclaimed after TTL expiry, allows claim again)
 *
 * Constraints:
 *   - the status field must be validated at runtime; the `as LedgerClaimStatus` brand cast must not be used
 *   - fail-closed; an invalid status value throws and is not silently coerced
 *
 */

// ---------------------------------------------------------------------------
// LedgerClaimStatus -- 4-state enum
// ---------------------------------------------------------------------------

/** The set of legal values for the EnvelopeLedger row's 4-state state machine. */
export const LEDGER_CLAIM_STATUSES = [
    'PENDING',
    'COMMITTED',
    'REJECTED',
    'EXPIRED',
] as const;

/** EnvelopeLedger row status (4-state discriminant). */
export type LedgerClaimStatus = (typeof LEDGER_CLAIM_STATUSES)[number];

/**
 * Runtime type guard: validates whether a raw DB string is a legal LedgerClaimStatus.
 *
 * Use this function instead of the `as LedgerClaimStatus` brand cast (brand cast is forbidden).
 */
export function isLedgerClaimStatus(value: unknown): value is LedgerClaimStatus {
    return (
        typeof value === 'string' &&
        (LEDGER_CLAIM_STATUSES as readonly string[]).includes(value)
    );
}

/**
 * Parse a LedgerClaimStatus from a raw DB string; throws when invalid (fail-closed).
 *
 * @throws Error if value is not a legal LedgerClaimStatus
 */
export function parseLedgerClaimStatus(value: unknown): LedgerClaimStatus {
    if (!isLedgerClaimStatus(value)) {
        throw new Error(
            `EnvelopeLedger: invalid status value from DB: ${JSON.stringify(value)}. ` +
                `Expected one of: ${LEDGER_CLAIM_STATUSES.join(', ')}`,
        );
    }
    return value;
}

// ---------------------------------------------------------------------------
// EnvelopeLedgerEntry -- single-row snapshot (read-only)
// ---------------------------------------------------------------------------

/** EnvelopeLedger DB row snapshot (query result, immutable). */
export interface EnvelopeLedgerEntry {
    /** DB auto-increment primary key (BigInt string, default node-postgres behavior) */
    readonly id: string;
    /** envelope business identifier */
    readonly envelopeId: string;
    /** row status */
    readonly status: LedgerClaimStatus;
    /** TTL in seconds (set on claim) */
    readonly ttlSeconds: number;
    /** claimer identifier (optional, passed in by the claim() caller; null means no ownership binding) */
    readonly claimerId: string | null;
    /** claim timestamp (DB server-side time) */
    readonly claimedAt: Date;
    /** finalize / reject timestamp (written on terminal state; null while not yet terminal) */
    readonly finalizedAt: Date | null;
    /** final result summary (written when COMMITTED; null otherwise) */
    readonly resultSummary: Record<string, unknown> | null;
    /** row creation timestamp */
    readonly createdAt: Date;
}

// ---------------------------------------------------------------------------
// claim() return types
// ---------------------------------------------------------------------------

/** claim() success: a new PENDING row has been atomically written. */
export interface ClaimSuccess {
    readonly claimed: true;
    /** the new row's DB auto-increment primary key */
    readonly id: string;
    /** envelope business identifier */
    readonly envelopeId: string;
    /** current status (always PENDING) */
    readonly status: 'PENDING';
    /** claim timestamp */
    readonly claimedAt: Date;
    /** TTL in seconds */
    readonly ttlSeconds: number;
}

/** claim() failure reasons. */
export type ClaimConflictReason =
    | 'ALREADY_PENDING'   // the envelope already has a PENDING row (concurrent claim conflict)
    | 'ALREADY_TERMINAL'; // the envelope already has a COMMITTED or REJECTED terminal row and cannot be claimed again

/** claim() failure: the envelope has a conflict (PENDING / COMMITTED / REJECTED). */
export interface ClaimConflict {
    readonly claimed: false;
    readonly reason: ClaimConflictReason;
    readonly envelopeId: string;
}

/** claim() result discriminated union. */
export type ClaimResult = ClaimSuccess | ClaimConflict;

// ---------------------------------------------------------------------------
// finalize() return types
// ---------------------------------------------------------------------------

/** finalize() success: PENDING → COMMITTED + same-transaction ActionRecord write. */
export interface FinalizeSuccess {
    readonly finalized: true;
    readonly envelopeId: string;
    readonly status: 'COMMITTED';
    readonly finalizedAt: Date;
}

/** finalize() failure reasons. */
export type FinalizeFailureReason =
    | 'NOT_FOUND'      // no PENDING row (and no terminal row either)
    | 'ALREADY_FINAL'  // already terminal (COMMITTED or REJECTED)
    | 'LEASE_EXPIRED'; // the PENDING row exists but its TTL has expired (not yet reclaimed by the sweeper)

/** finalize() failure. */
export interface FinalizeFailure {
    readonly finalized: false;
    readonly reason: FinalizeFailureReason;
    readonly envelopeId: string;
}

/** finalize() result discriminated union. */
export type FinalizeResult = FinalizeSuccess | FinalizeFailure;

// ---------------------------------------------------------------------------
// reject() return types
// ---------------------------------------------------------------------------

/** reject() success: PENDING → REJECTED. */
export interface RejectSuccess {
    readonly rejected: true;
    readonly envelopeId: string;
    readonly status: 'REJECTED';
    readonly finalizedAt: Date;
}

/** reject() failure reasons. */
export type RejectFailureReason =
    | 'NOT_FOUND'      // no PENDING row
    | 'ALREADY_FINAL'; // already terminal

/** reject() failure. */
export interface RejectFailure {
    readonly rejected: false;
    readonly reason: RejectFailureReason;
    readonly envelopeId: string;
}

/** reject() result discriminated union. */
export type RejectResult = RejectSuccess | RejectFailure;

// ---------------------------------------------------------------------------
// expireStalePending() return type
// ---------------------------------------------------------------------------

/** expireStalePending() execution result. */
export interface ExpireResult {
    /** number of rows reclaimed in this batch */
    readonly expiredCount: number;
}
