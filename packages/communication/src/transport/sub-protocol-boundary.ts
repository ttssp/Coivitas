/**
 * sub-protocol L0 error -> ProtocolError L3/L4 boundary wrapper
 *
 * Summary: wrapSubProtocolBoundary + explicit catch of the 6 sub-protocol L0 errors —
 *          unwraps CrError / HashChainError / AuditShareError / AuditError / SrError / DaError
 *          into ProtocolError('INTERNAL_ERROR', '${origErr.code}: ${origErr.message}').
 *
 * Design intent:
 * - catch ProtocolError only covers 2 sub-protocol L0 error classes (CcrError + RfpError extends ProtocolError);
 *   the remaining 6 extend Error — they are not caught by catch ProtocolError
 * - Mitigation: the L3/L4 boundary mandatorily unwraps + re-throws as ProtocolError
 *   (callers do not catch sub-protocol L0 error classes directly; they catch ProtocolError uniformly)
 * - At the code level: the error code field is the frozen union member 'INTERNAL_ERROR'; the real sub-protocol
 *   error code goes into the detail field (frozen union sustained literally; no new code introduced)
 *
 * Note: in the example `new ProtocolError('SUBPROTOCOL_LAYER_FAIL', ...)` the
 *     code field name is not within the frozen 53-member ProtocolErrorCode union; the actual implementation uses
 *     'INTERNAL_ERROR' (a frozen member) + the detail field to preserve the full original sub-code information
 *     (namespace reserved + frozen union introduces no new code). This trade-off is recorded in
 *     followup tracking; a future breaking-format-change negotiation window
 *     can re-evaluate whether to add a 'SUBPROTOCOL_LAYER_FAIL' member to ProtocolErrorCode.
 *
 * Related design note: mandatory L3/L4 boundary wrapper
 * Related: sub-protocol L0 error catch boundary wrapper
 */

import { ProtocolError } from '@coivitas/types';
import { AuditShareError } from '@coivitas/types';
import { CrError } from '@coivitas/types';
import { HashChainError } from '@coivitas/types';
import { AuditError } from '@coivitas/types';
import { SrError } from '@coivitas/types';
import { DaError } from '@coivitas/types';

/**
 * Union of the 6 sub-protocol L0 error classes (Alt α′ baseline: 6 classes extending Error)
 */
export type SubProtocolL0Error =
    | CrError
    | HashChainError
    | AuditShareError
    | AuditError
    | SrError
    | DaError;

/**
 * isSubProtocolL0Error — type guard
 *
 * Uses instanceof to check the 6 sub-protocol L0 error classes (the extends-Error pattern;
 * Alt α′ baseline). CcrError + RfpError extend ProtocolError, so this function
 * does not match them (they are already ProtocolError subclasses, caught directly by catch ProtocolError).
 */
export function isSubProtocolL0Error(err: unknown): err is SubProtocolL0Error {
    return (
        err instanceof CrError ||
        err instanceof HashChainError ||
        err instanceof AuditShareError ||
        err instanceof AuditError ||
        err instanceof SrError ||
        err instanceof DaError
    );
}

/**
 * subProtocolErrorCode — gets the typed sub-code of a sub-protocol L0 error
 *
 * The 6 sub-protocol L0 error classes name the field consistently (.code); under the extends-Error pattern
 * (after the Alt α′ empirical fallback), returns the literal sub-code so that
 * wrapSubProtocolBoundary preserves the full sub-code information in the detail field.
 */
export function subProtocolErrorCode(err: SubProtocolL0Error): string {
    return err.code;
}

/**
 * wrapSubProtocolBoundary — L3/L4 boundary wrapper
 *
 * Flow:
 * 1. Call op synchronously/asynchronously
 * 2. Throws ProtocolError -> re-throw as-is (the caller already catches ProtocolError)
 * 3. Throws one of the 6 sub-protocol L0 errors -> unwrap + re-throw as ProtocolError
 *    ('INTERNAL_ERROR', '${origErr.code}: ${origErr.message}', requestId)
 * 4. Throws another unknown error -> re-throw as ProtocolError
 *    ('INTERNAL_ERROR', '${origErr.message}', requestId)
 *
 * @param op the async operation to wrap (Promise OR => Promise)
 * @param requestId Optional; populates the ProtocolError requestId field for convenient audit logging
 *
 * @example
 * ```typescript
 * await wrapSubProtocolBoundary(
 * => settlementRetry.persistRetryAttempt(...),
 *     requestId,
 * );
 * // SrError is automatically unwrapped as ProtocolError('INTERNAL_ERROR', 'SR_PERSIST_FAILED: ...')
 * ```
 */
export async function wrapSubProtocolBoundary<T>(
    op: () => Promise<T>,
    requestId?: string,
): Promise<T> {
    try {
        return await op();
    } catch (err) {
        // 1. ProtocolError (including the CcrError + RfpError subclasses) -> re-throw as-is
        if (err instanceof ProtocolError) {
            throw err;
        }

        // 2. The 6 sub-protocol L0 errors -> unwrap + re-throw as ProtocolError
        if (isSubProtocolL0Error(err)) {
            const subCode = subProtocolErrorCode(err);
            throw new ProtocolError(
                'INTERNAL_ERROR',
                `${subCode}: ${err.message}`,
                requestId,
            );
        }

        // 3. Other unknown errors (including the base Error class OR non-Error objects) -> fallback ProtocolError
        const fallbackMessage =
            err instanceof Error ? err.message : String(err);
        throw new ProtocolError(
            'INTERNAL_ERROR',
            `unknown sub-protocol layer fail: ${fallbackMessage}`,
            requestId,
        );
    }
}

/**
 * wrapSubProtocolBoundarySync — synchronous version of the wrapper
 *
 * Same as wrapSubProtocolBoundary but for a synchronous op (does not await a Promise).
 */
export function wrapSubProtocolBoundarySync<T>(
    op: () => T,
    requestId?: string,
): T {
    try {
        return op();
    } catch (err) {
        if (err instanceof ProtocolError) {
            throw err;
        }
        if (isSubProtocolL0Error(err)) {
            const subCode = subProtocolErrorCode(err);
            throw new ProtocolError(
                'INTERNAL_ERROR',
                `${subCode}: ${err.message}`,
                requestId,
            );
        }
        const fallbackMessage =
            err instanceof Error ? err.message : String(err);
        throw new ProtocolError(
            'INTERNAL_ERROR',
            `unknown sub-protocol layer fail: ${fallbackMessage}`,
            requestId,
        );
    }
}
