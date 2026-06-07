/**
 * Dispute Arbitration L0 error-code definitions
 *
 * Dispute-arbitration sub-protocol — v0.1
 *
 * 15 error codes frozen (no additions allowed outside a runtime).
 * Every error code must have a throw-path in an implementation path (avoids defining unused error codes).
 *
 * DaError extends Error; does not extend ProtocolError.
 *
 * The L0 error class pattern across sub-protocols is not forcibly unified — DaError `.detail:
 * Record<string, unknown>` is TS2416-incompatible with ProtocolError `.detail: string`,
 * an inline refactor is not feasible; DaError stays at extends Error.
 */

// ─── Error-code union type (15 entries frozen) ───────────────────────────────────────────

/**
 * DA protocol error codes
 *
 * Error codes frozen; any addition must go through a spec revision.
 *
 * 15 entries:
 *   - DA_FILING_INVALID: filing field validation failed (step 1)
 *   - DA_DUPLICATE_FILING: idempotency check detected a duplicate submission (step 1)
 *   - DA_CANONICAL_HASH_MISMATCH: hash chain verification failed (step 2)
 *   - DA_SIGNED_PAYLOAD_INVALID: CSP signature verification failed (step 3)
 *   - DA_TIMEOUT_EXCEEDED: 14-day timeout (step 1 + checkAndExpire)
 *   - DA_STATE_TRANSITION_INVALID: invalid state transition (validateStateTransition)
 *   - DA_ARBITRATOR_INVALID: invalid arbitrator field / pool size (step 4)
 *   - DA_ARBITRATOR_INSUFFICIENT: arbitrator count below the minimum (step 4 + computeThreshold)
 *   - DA_INSUFFICIENT_SIGNATURES: signature count below the threshold (step 5)
 *   - DA_EVIDENCE_INVALID: evidence URI validation failed (step 2)
 *   - DA_PROVIDER_UNAVAILABLE: dependency port unavailable (common to all steps)
 *   - DA_VERSION_UNSUPPORTED: daVersion not in the supported list (step 1)
 *   - DA_DISPUTE_REVOKED: the dispute subject has been revoked (step 3)
 *   - DA_IDEMPOTENCY_VIOLATION: idempotency key conflict (step 1)
 *   - DA_FRESHNESS_INVALID: CSP notAfter expired (step 3)
 */
export type DaErrorCode =
    | 'DA_FILING_INVALID'
    | 'DA_DUPLICATE_FILING'
    | 'DA_CANONICAL_HASH_MISMATCH'
    | 'DA_SIGNED_PAYLOAD_INVALID'
    | 'DA_TIMEOUT_EXCEEDED'
    | 'DA_STATE_TRANSITION_INVALID'
    | 'DA_ARBITRATOR_INVALID'
    | 'DA_ARBITRATOR_INSUFFICIENT'
    | 'DA_INSUFFICIENT_SIGNATURES'
    | 'DA_EVIDENCE_INVALID'
    | 'DA_PROVIDER_UNAVAILABLE'
    | 'DA_VERSION_UNSUPPORTED'
    | 'DA_DISPUTE_REVOKED'
    | 'DA_IDEMPOTENCY_VIOLATION'
    | 'DA_FRESHNESS_INVALID';

// ─── DaError class ───────────────────────────────────────────────────

/**
 * DA protocol error class
 *
 * Extends Error; not ProtocolError.
 * detail carries structured context; the reason field is used for the message summary.
 */
export class DaError extends Error {
    public readonly code: DaErrorCode;
    public readonly detail: Record<string, unknown>;

    constructor(code: DaErrorCode, detail?: Record<string, unknown>) {
        const reason =
            typeof detail?.['reason'] === 'string' ? detail['reason'] : code;
        super(`DaError [${code}]: ${reason}`);
        this.name = 'DaError';
        this.code = code;
        this.detail = detail ?? {};
        Object.setPrototypeOf(this, new.target.prototype);
    }
}

// ─── Error handling helpers ─────────────────────────────────────────────────────────────

/**
 * handleDaError — exhaustive switch over the 15 error codes
 *
 * Used for the unified log/audit path; every case has a return;
 * assertNeverDaCode prevents an uncovered code from leaking through.
 */
export function handleDaError(error: DaError): {
    logged: true;
    code: DaErrorCode;
} {
    switch (error.code) {
        case 'DA_FILING_INVALID':
            return { logged: true, code: error.code };
        case 'DA_DUPLICATE_FILING':
            return { logged: true, code: error.code };
        case 'DA_CANONICAL_HASH_MISMATCH':
            return { logged: true, code: error.code };
        case 'DA_SIGNED_PAYLOAD_INVALID':
            return { logged: true, code: error.code };
        case 'DA_TIMEOUT_EXCEEDED':
            return { logged: true, code: error.code };
        case 'DA_STATE_TRANSITION_INVALID':
            return { logged: true, code: error.code };
        case 'DA_ARBITRATOR_INVALID':
            return { logged: true, code: error.code };
        case 'DA_ARBITRATOR_INSUFFICIENT':
            return { logged: true, code: error.code };
        case 'DA_INSUFFICIENT_SIGNATURES':
            return { logged: true, code: error.code };
        case 'DA_EVIDENCE_INVALID':
            return { logged: true, code: error.code };
        case 'DA_PROVIDER_UNAVAILABLE':
            return { logged: true, code: error.code };
        case 'DA_VERSION_UNSUPPORTED':
            return { logged: true, code: error.code };
        case 'DA_DISPUTE_REVOKED':
            return { logged: true, code: error.code };
        case 'DA_IDEMPOTENCY_VIOLATION':
            return { logged: true, code: error.code };
        case 'DA_FRESHNESS_INVALID':
            return { logged: true, code: error.code };
        default:
            return assertNeverDaCode(error.code);
    }
}

/**
 * assertNeverDaCode — exhaustive union guard
 *
 * Currently reuses DA_STATE_TRANSITION_INVALID as the never-code;
 * a dedicated diagnostic code should be introduced in a future version.
 */
export function assertNeverDaCode(code: never): never {
    throw new DaError('DA_STATE_TRANSITION_INVALID', {
        reason: 'exhaustive_guard_unreachable_da_error_code',
        unreachableCode: code,
    });
}
