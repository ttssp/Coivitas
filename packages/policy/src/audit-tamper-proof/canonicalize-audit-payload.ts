/**
 * atp v0.1 L3 canonicalizeAuditPayload — RFC 8785 JCS strict (top-level import)
 *
 * audit-tamper-proof v0.1 L3 sub-protocol
 *
 * No brand cast + negative-case defense enforced:
 *   - top-level import canonicalize from '@coivitas/crypto'
 *   - no dynamic import inside the function body (run-time injection risk);
 *   - no JSON.stringify fallback (on failure, report error code AUDIT_CANONICALIZE_BYPASS_DETECTED).
 *
 * fail-closed enforcement:
 *   canonicalize failure → throw AuditError(AUDIT_CANONICALIZE_BYPASS_DETECTED);
 *   never returns null / empty / fallback; the caller takes the ROLLBACK path.
 *
 * Behavioral contract:
 *   canonicalPayload = canonicalize(payload) // from the canonicalize npm package (top-level import)
 *   failure → throw AUDIT_CANONICALIZE_BYPASS_DETECTED + transaction ROLLBACK
 */

import { canonicalize } from '@coivitas/crypto';
import { AuditError } from '@coivitas/types';

/**
 * canonicalizeAuditPayload — the only legal entry point for RFC 8785 JCS canonicalize
 *
 * Accepts an arbitrary application-layer JSON object (Record<string, unknown>);
 * emits a string after RFC 8785 JCS canonicalize (UTF-8 literal byte sequence);
 * throws AuditError(AUDIT_CANONICALIZE_BYPASS_DETECTED; fail-closed) on failure.
 *
 * Type-constraint note:
 *   the crypto wrapper canonicalize() takes Record<string, unknown> (object form);
 *   the atp payload is wrapped as an object inside the audit event (the application-layer caller provides an object);
 *   a non-object payload (primitive / array / null) triggers AUDIT_CANONICALIZE_BYPASS_DETECTED
 *   (strict fail-closed; negative-case defense).
 *
 * @param payload arbitrary JSON object (Record<string, unknown>)
 * @returns RFC 8785 JCS canonicalize string
 * @throws AuditError(AUDIT_CANONICALIZE_BYPASS_DETECTED) on failure
 */
export function canonicalizeAuditPayload(payload: unknown): string {
    // Negative-case defense: the top-level import of canonicalize is already in effect; no dynamic import inside the function body
    // Negative-case defense: canonicalize failure throws rather than stubbing success

    // payload must be an object (not null; not array; not primitive)
    if (
        payload === null ||
        typeof payload !== 'object' ||
        Array.isArray(payload)
    ) {
        throw new AuditError(
            'AUDIT_CANONICALIZE_BYPASS_DETECTED',
            `payload must be a JSON object (Record<string, unknown>);got ${
                payload === null ? 'null' : Array.isArray(payload) ? 'array' : typeof payload
            }`,
            { payloadType: typeof payload },
        );
    }

    try {
        const result = canonicalize(payload as Record<string, unknown>);
        // the canonicalize package returns undefined for non-serializable values such as undefined / function;
        // fail-closed guard: any non-string output → AUDIT_CANONICALIZE_BYPASS_DETECTED
        if (typeof result !== 'string' || result.length === 0) {
            throw new AuditError(
                'AUDIT_CANONICALIZE_BYPASS_DETECTED',
                `canonicalize returned non-string or empty result (type=${typeof result}); payload contains non-serializable value (function / undefined / symbol)`,
                { payloadType: typeof payload },
            );
        }
        return result;
    } catch (err) {
        // if it is already an AuditError, rethrow directly; do not wrap a second time
        if (err instanceof AuditError) {
            throw err;
        }
        // other errors (e.g. circular reference) → AUDIT_CANONICALIZE_BYPASS_DETECTED
        const message = err instanceof Error ? err.message : String(err);
        throw new AuditError(
            'AUDIT_CANONICALIZE_BYPASS_DETECTED',
            `canonicalize failed: ${message}`,
            { payloadType: typeof payload, originalError: message },
        );
    }
}
