/**
 * 6 sub-protocol-specific L3/L4 boundary wrappers (mandatory wrap)
 *
 * Summary:
 *   Per contract — the 6 sub-protocol L0 error classes
 *   (CrError/HashChainError/AuditShareError/AuditError/SrError/DaError)
 *   must be unwrapped at the L3/L4 boundary and re-thrown as ProtocolError; they are not
 *   allowed to escape the L3/L4 boundary directly to the caller.
 *
 *   wrapSubProtocolBoundary (sub-protocol-boundary.ts) is the generic fallback helper.
 *   This file provides 6 sub-protocol-specific named wrappers:
 *     - runSettlementRetryBoundary — wrap SrError-throwing op
 *     - runDisputeArbitrationBoundary — wrap DaError-throwing op
 *     - runAuditShareBoundary — wrap AuditShareError-throwing op
 *     - runAuditTamperProofBoundary — wrap AuditError-throwing op (audit-tamper-proof)
 *     - runHashChainBoundary — wrap HashChainError-throwing op
 *     - runCredentialResolverBoundary — wrap CrError-throwing op
 *
 * Design intent (named wrappers vs a single generic wrapper):
 *   1. Clearer intent on the caller side — when invoking a sub-protocol entry, the caller
 *      explicitly states "which sub-protocol's L3/L4 boundary I am crossing", making
 *      commits and code reviews easier to read.
 *   2. Production grep verify SOP hits — the production wire requires at least one call
 *      site per sub-protocol; 6 helpers = 6 independent grep namespaces.
 *   3. Type-narrow safety — each helper handles "force-unwrap when the corresponding
 *      sub-protocol L0 error matches" + "cover other sub-protocol L0 errors too (fallback)"
 *      + "re-throw ProtocolError as-is" + "fall back to ProtocolError for unknown errors".
 *
 * Implementation strategy:
 *   Each helper actually delegates to wrapSubProtocolBoundary (single source-of-truth catch
 *   semantics); the try/catch logic is not duplicated, but exporting 6 named functions
 *   yields 6 independent caller consumption points (production grep anchors).
 *
 * Related design note: mandatory L3/L4 boundary wrapper
 * Related: sub-protocol L0 error catch boundary wrapper production wire
 */

import { wrapSubProtocolBoundary } from './sub-protocol-boundary.js';

/**
 * runSettlementRetryBoundary — wraps the settlement-retry sub-protocol L3/L4 boundary
 *
 * Usage: called by the L4 communication transport / L5 sdk orchestrator when crossing the
 * settlement-retry sub-protocol boundary; SrError is automatically unwrapped as ProtocolError.
 *
 * @example
 * ```typescript
 * const result = await runSettlementRetryBoundary(
 * => executeSettlementRetry(input, deps),
 *     envelope.id,
 * );
 * // if executeSettlementRetry throws SrError → converted to ProtocolError('INTERNAL_ERROR', 'SR_*: ...')
 * ```
 *
 * @param op settlement-retry sub-protocol entry call (Promise-returning)
 * @param requestId Optional; propagated to ProtocolError.requestId on failure
 */
export async function runSettlementRetryBoundary<T>(
    op: () => Promise<T>,
    requestId?: string,
): Promise<T> {
    return wrapSubProtocolBoundary(op, requestId);
}

/**
 * runDisputeArbitrationBoundary — wraps the dispute-arbitration sub-protocol L3/L4 boundary
 *
 * Usage: called by the L4 communication transport / L5 sdk orchestrator when crossing the
 * dispute-arbitration sub-protocol boundary; DaError is automatically unwrapped as ProtocolError.
 *
 * @example
 * ```typescript
 * const result = await runDisputeArbitrationBoundary(
 * => runDisputeArbitration7Steps(input, deps),
 *     envelope.id,
 * );
 * // if runDisputeArbitration7Steps throws DaError → converted to ProtocolError('INTERNAL_ERROR', 'DA_*: ...')
 * ```
 *
 * @param op dispute-arbitration sub-protocol entry call (Promise-returning)
 * @param requestId Optional; propagated to ProtocolError.requestId on failure
 */
export async function runDisputeArbitrationBoundary<T>(
    op: () => Promise<T>,
    requestId?: string,
): Promise<T> {
    return wrapSubProtocolBoundary(op, requestId);
}

/**
 * runAuditShareBoundary — wraps the audit-share sub-protocol L3/L4 boundary
 *
 * Usage: called by the L4 communication transport / L5 sdk orchestrator when crossing the
 * audit-share sub-protocol boundary; AuditShareError is automatically unwrapped as ProtocolError.
 *
 * @example
 * ```typescript
 * const result = await runAuditShareBoundary(
 * => auditShareManager.verifyAuditRequest(request),
 *     envelope.id,
 * );
 * // if verifyAuditRequest throws AuditShareError → converted to ProtocolError('INTERNAL_ERROR', 'AUDIT_SHARE_*: ...')
 * ```
 *
 * @param op audit-share sub-protocol entry call (Promise-returning)
 * @param requestId Optional; propagated to ProtocolError.requestId on failure
 */
export async function runAuditShareBoundary<T>(
    op: () => Promise<T>,
    requestId?: string,
): Promise<T> {
    return wrapSubProtocolBoundary(op, requestId);
}

/**
 * runAuditTamperProofBoundary — wraps the audit-tamper-proof sub-protocol L3/L4 boundary
 *
 * Usage: called by the L4 communication transport / L5 sdk orchestrator when crossing the
 * audit-tamper-proof sub-protocol boundary; AuditError is automatically unwrapped as ProtocolError.
 *
 * Naming note: in the audit-tamper-proof v0.1 spec the L0 error class is named `AuditError`
 * (not `AtpError`), to distinguish it from audit-share's `AuditShareError`; this helper's
 * namespace uses `runAuditTamperProofBoundary` to distinguish it literally and avoid
 * confusion with the audit-share helper.
 *
 * @example
 * ```typescript
 * const result = await runAuditTamperProofBoundary(
 * => tamperProofAuditWriter.writeAuditEvent(event),
 *     envelope.id,
 * );
 * // if writeAuditEvent throws AuditError → converted to ProtocolError('INTERNAL_ERROR', 'AUDIT_*: ...')
 * ```
 *
 * @param op audit-tamper-proof sub-protocol entry call (Promise-returning)
 * @param requestId Optional; propagated to ProtocolError.requestId on failure
 */
export async function runAuditTamperProofBoundary<T>(
    op: () => Promise<T>,
    requestId?: string,
): Promise<T> {
    return wrapSubProtocolBoundary(op, requestId);
}

/**
 * runHashChainBoundary — wraps the hash-chain-canonicalize (hcc) sub-protocol L3/L4 boundary
 *
 * Usage: called by the L4 communication transport / L5 sdk orchestrator when crossing the
 * hcc sub-protocol boundary; HashChainError is automatically unwrapped as ProtocolError.
 *
 * @example
 * ```typescript
 * const result = await runHashChainBoundary(
 * => verifyHashChain(entries),
 *     envelope.id,
 * );
 * // if verifyHashChain throws HashChainError → converted to ProtocolError('INTERNAL_ERROR', 'HC_*: ...')
 * ```
 *
 * Note: the hcc primitives (verifyHashChain / appendHashChainEntry) are mostly synchronous
 * functions; this wrapper exposes an async interface (just wrap a sync op in an async lambda).
 *
 * @param op hcc sub-protocol entry call (Promise-returning)
 * @param requestId Optional; propagated to ProtocolError.requestId on failure
 */
export async function runHashChainBoundary<T>(
    op: () => Promise<T>,
    requestId?: string,
): Promise<T> {
    return wrapSubProtocolBoundary(op, requestId);
}

/**
 * runCredentialResolverBoundary — wraps the credential-resolver (CR) sub-protocol L3/L4 boundary
 *
 * Usage: called by the L4 communication transport / L5 sdk orchestrator when crossing the
 * credential-resolver sub-protocol boundary; CrError is automatically unwrapped as ProtocolError.
 *
 * @example
 * ```typescript
 * const result = await runCredentialResolverBoundary(
 * => resolveCredential(input, deps),
 *     envelope.id,
 * );
 * // if resolveCredential throws CrError → converted to ProtocolError('INTERNAL_ERROR', 'CR_*: ...')
 * ```
 *
 * @param op credential-resolver sub-protocol entry call (Promise-returning)
 * @param requestId Optional; propagated to ProtocolError.requestId on failure
 */
export async function runCredentialResolverBoundary<T>(
    op: () => Promise<T>,
    requestId?: string,
): Promise<T> {
    return wrapSubProtocolBoundary(op, requestId);
}
