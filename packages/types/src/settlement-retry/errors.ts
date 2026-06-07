/**
 * Settlement Retry (SR) sub-protocol v0.1 — error codes, error class, handler function
 *
 *
 * 14 SR_* error codes frozen in v0.1 (strictly converged):
 *   every error code must have at least 1 throw site in the implementation (no dead error codes).
 *
 * Removed-item notes (v0.1 freeze convergence):
 *   SR_REVOCATION_CHECK_FAILED → SR_OPERATION_REVOKED (semantic convergence)
 *   SR_SIGNATURE_INVALID → SR_SIGNED_PAYLOAD_INVALID (5-field invariant channel)
 *   SR_INSUFFICIENT_FUNDS → independent RetryAttemptFailureReason union (failureReason channel only)
 *   SR_REGULATORY_REJECTED → independent RetryAttemptFailureReason union
 *   SR_SCHEMA_VIOLATION → factory brand-cast prohibition shares the existing throw-path channel
 *   SR_INTERNAL_ERROR → independent RetryAttemptFailureReason union
 *
 * SrError extends Error (not ProtocolError):
 *   the ProtocolError constructor accepts a frozen 53-value ProtocolErrorCode union;
 *   SR_* error codes cannot join that frozen union;
 *   consistent with all sub-protocol error classes such as HashChainError / AuditError /
 *   CrError / MultisigError — each independently extends Error.
 *
 * Namespace isolation: SR_* is orthogonal to the following namespaces:
 *   CSP_* / RFP_* / DELEGATION_* / ATP_* / HCC_* / MS_* / CCR_* / CR_* / TB_*
 */

// ─── SrErrorCode (14 items frozen in v0.1) ─────────────────────────────────────────

/**
 * SR sub-protocol error codes (14 throw-path-only items; frozen in v0.1)
 *
 * Each error code corresponds to at least 1 throw path in the algorithm.
 * assertNeverSrCode is used in the default branch of the handleSrError switch to ensure compile-time completeness.
 *
 * Three-way consistency verify anchor:
 *    14 lines of error-code definitions = 14 union members = 14 cases in the handleSrError switch
 *
 * Error-code groups:
 *   Idempotency — SR_IDEMPOTENCY_VIOLATION
 *   Canonical hash — SR_CANONICAL_HASH_MISMATCH
 *   State machine — SR_STATE_TRANSITION_INVALID
 *   Retry limit — SR_RETRY_EXHAUSTED
 *   Provider — SR_PROVIDER_UNAVAILABLE, SR_PROVIDER_TIMEOUT, SR_PROVIDER_DECLINED, SR_PROVIDER_RESPONSE_INVALID
 *   Revocation — SR_OPERATION_REVOKED
 *   Signature — SR_SIGNED_PAYLOAD_INVALID
 *   Freshness — SR_FRESHNESS_INVALID
 *   Version — SR_VERSION_UNSUPPORTED
 *   Amount — SR_AMOUNT_INVALID
 *   Backoff parameter — SR_BACKOFF_INVALID
 */
export type SrErrorCode =
    | 'SR_IDEMPOTENCY_VIOLATION' // step 2: concurrent conflict, same key but different operationId
    | 'SR_CANONICAL_HASH_MISMATCH' // step 1: idempotency_key derived hash mismatch
    | 'SR_STATE_TRANSITION_INVALID' // step 6+7+9: illegal state transition
    | 'SR_RETRY_EXHAUSTED' // step 7: reached MAX_RETRY_ATTEMPTS
    | 'SR_PROVIDER_UNAVAILABLE' // step 7: provider unreachable
    | 'SR_PROVIDER_TIMEOUT' // step 7: provider timed out
    | 'SR_PROVIDER_DECLINED' // step 7: provider risk-control decline
    | 'SR_PROVIDER_RESPONSE_INVALID' // step 7: provider returned an invalid finalState
    | 'SR_OPERATION_REVOKED' // step 5: operation already revoked (fail-closed)
    | 'SR_SIGNED_PAYLOAD_INVALID' // step 4: invalid signature / missing 5 fields / audience binding failed
    | 'SR_FRESHNESS_INVALID' // step 4: signedPayload notAfter has expired
    | 'SR_VERSION_UNSUPPORTED' // step 3: settlementType / srVersion / cspVersion not supported
    | 'SR_AMOUNT_INVALID' // step 3: amount <= 0
    | 'SR_BACKOFF_INVALID'; // step 7: backoffDelayMs out of the [0, 60000] range

// ─── SrError error class ────────────────────────────────────────────────────────────

/**
 * SrError — settlement-retry sub-protocol error class
 *
 * extends Error (not ProtocolError):
 *   the ProtocolError constructor accepts a frozen 53-value ProtocolErrorCode union;
 *   SR_* cannot join that frozen union; this pattern is consistent with all sub-protocol
 *   error classes such as HashChainError (hcc) / AuditError (atp) / CrError (cr) / MultisigError (ms).
 */
export class SrError extends Error {
    public override readonly name = 'SrError';
    public readonly code: SrErrorCode;
    public readonly detail?: Record<string, unknown>;

    public constructor(code: SrErrorCode, detail?: Record<string, unknown>) {
        super(
            `[SR] ${code}${detail !== undefined ? ': ' + JSON.stringify(detail) : ''}`,
        );
        this.code = code;
        this.detail = detail;
        // V8 stack trace correctness
        if (Error.captureStackTrace) {
            Error.captureStackTrace(this, SrError);
        }
    }
}

// ─── assertNeverSrCode — compile-time exhaustive guard ───────────────────────────────

/**
 * assertNeverSrCode — compile-time exhaustive enum check
 *
 * Called in the default branch of the handleSrError switch;
 * if a newly added SrErrorCode is not handled in the switch → TypeScript compile error.
 * Runtime fallback throws SR_STATE_TRANSITION_INVALID (tracked via the unexpectedCode field; consistent with the pattern).
 */
export function assertNeverSrCode(code: never): never {
    throw new SrError('SR_STATE_TRANSITION_INVALID', {
        unexpectedCode: code,
        reason: 'sr_error_code_union_exhaustive_violation',
    });
}

// ─── SrErrorContext — handleSrError return type ──────────────────────────────────

/**
 * SrErrorContext — handleSrError result (consistent with the CrErrorContext pattern)
 *
 * httpStatus: corresponding HTTP status code (used for L4/L5 error response mapping)
 * severity: alert level (error = manual handling required; warn = can be retried automatically; info = normal flow branch)
 * message: a concise, externally exposable error description
 */
export interface SrErrorContext {
    readonly httpStatus: number;
    readonly severity: 'error' | 'warn' | 'info';
    readonly message: string;
    readonly retryable: boolean;
}

// ─── handleSrError — 14-case switch + exhaustive ──────────────────────────────

/**
 * handleSrError — SR error-code handling map (14-case exhaustive switch)
 *
 * Each SrErrorCode maps to one SrErrorContext;
 * the default branch calls assertNeverSrCode to ensure compile-time completeness.
 *
 * retryable semantics:
 *   true = the caller may schedule an exponential-backoff retry
 *   false = not retryable (requires manual intervention or is a terminal state)
 */
export function handleSrError(err: SrError): SrErrorContext {
    switch (err.code) {
        case 'SR_IDEMPOTENCY_VIOLATION':
            return {
                httpStatus: 409,
                severity: 'error',
                message:
                    'Idempotency violation: concurrent settlement conflict on same key',
                retryable: false,
            };

        case 'SR_CANONICAL_HASH_MISMATCH':
            return {
                httpStatus: 422,
                severity: 'error',
                message:
                    'Canonical hash recomputation mismatch; operation tampered or field drift',
                retryable: false,
            };

        case 'SR_STATE_TRANSITION_INVALID':
            return {
                httpStatus: 422,
                severity: 'error',
                message: 'Settlement operation state transition is not allowed',
                retryable: false,
            };

        case 'SR_RETRY_EXHAUSTED':
            return {
                httpStatus: 422,
                severity: 'warn',
                message:
                    'Settlement operation retry attempts exhausted; moved to dead letter',
                retryable: false,
            };

        case 'SR_PROVIDER_UNAVAILABLE':
            return {
                httpStatus: 503,
                severity: 'warn',
                message: 'Settlement provider is currently unavailable',
                retryable: true,
            };

        case 'SR_PROVIDER_TIMEOUT':
            return {
                httpStatus: 504,
                severity: 'warn',
                message: 'Settlement provider timed out',
                retryable: true,
            };

        case 'SR_PROVIDER_DECLINED':
            return {
                httpStatus: 422,
                severity: 'warn',
                message:
                    'Settlement provider declined the operation (PSP risk control)',
                retryable: false,
            };

        case 'SR_PROVIDER_RESPONSE_INVALID':
            return {
                httpStatus: 502,
                severity: 'error',
                message:
                    'Provider returned invalid finalState (expected SUCCEEDED or FAILED)',
                retryable: false,
            };

        case 'SR_OPERATION_REVOKED':
            return {
                httpStatus: 422,
                severity: 'error',
                message:
                    'Settlement operation has been revoked; rejected (fail-closed)',
                retryable: false,
            };

        case 'SR_SIGNED_PAYLOAD_INVALID':
            return {
                httpStatus: 422,
                severity: 'error',
                message:
                    'Signed payload invalid: missing fields / signature verify failed / audience binding failed',
                retryable: false,
            };

        case 'SR_FRESHNESS_INVALID':
            return {
                httpStatus: 422,
                severity: 'error',
                message: 'Signed payload notAfter has expired',
                retryable: false,
            };

        case 'SR_VERSION_UNSUPPORTED':
            return {
                httpStatus: 400,
                severity: 'error',
                message:
                    'SR protocol version / settlementType / cspVersion not supported',
                retryable: false,
            };

        case 'SR_AMOUNT_INVALID':
            return {
                httpStatus: 400,
                severity: 'error',
                message:
                    'Settlement amount must be a positive integer (minimum currency unit)',
                retryable: false,
            };

        case 'SR_BACKOFF_INVALID':
            return {
                httpStatus: 500,
                severity: 'error',
                message: 'Backoff delay out of valid range [0, 60000] ms',
                retryable: false,
            };

        default:
            return assertNeverSrCode(err.code);
    }
}
