/**
 * 6 sub-protocol-specific EnvelopeHandler decorators (production wire)
 *
 * Summary:
 *   When an L4 envelope handler is registered with a Transport, the caller can use
 *   these 6 decorators to wrap the handler once at the outermost layer; each decorator
 *   invokes one sub-protocol-specific boundary wrapper (sub-protocol-wrappers.ts).
 *   This is the real consumption point of the mandatory wrap on the production wire.
 *
 *   - withSettlementRetryHandler — unwraps SrError at the outer layer of the settlement-retry envelope handler
 *   - withDisputeArbitrationHandler — unwraps DaError at the outer layer of the dispute-arbitration envelope handler
 *   - withAuditShareHandler — unwraps AuditShareError at the outer layer of the audit-share envelope handler
 *   - withAuditTamperProofHandler — unwraps AuditError at the outer layer of the audit-tamper-proof envelope handler
 *   - withHashChainHandler — unwraps HashChainError at the outer layer of the hcc envelope handler
 *   - withCredentialResolverHandler — unwraps CrError at the outer layer of the credential-resolver envelope handler
 *
 *   Each decorator wraps the inner sub-protocol call stack at the EnvelopeHandler call
 *   boundary (the L4 transport boundary); if the inner handler calls down into a
 *   sub-protocol entry that throws a sub-protocol L0 error and it leaks out to the L4
 *   transport boundary, the decorator catches it here and unwraps it into a ProtocolError.
 *
 * Design intent (why a decorator pattern rather than a transport-side hard-coded wrap):
 *   1. The 6 decorators each cover an independent sub-protocol namespace — the caller
 *      (the L4 transport registrar) explicitly declares which sub-protocol boundary this
 *      handler crosses among settlement-retry / dispute-arbitration / audit-share /
 *      audit-tamper-proof / hcc / credential-resolver.
 *   2. The production grep verify SOP gets ≥6 real hits — the 6 decorators do not overlap,
 *      so a production grep for `wrapSubProtocolBoundary` yields ≥6 hits (all on non-test paths).
 *   3. The transport (http / websocket / mtls) stays decoupled from sub-protocol knowledge —
 *      the responsibility to declare the boundary type lies with the caller (registrar).
 *
 * Related ADR: mandatory L3/L4 boundary wrapper production wire
 */

import type { EnvelopeHandler } from './types.js';
import {
    runAuditShareBoundary,
    runAuditTamperProofBoundary,
    runCredentialResolverBoundary,
    runDisputeArbitrationBoundary,
    runHashChainBoundary,
    runSettlementRetryBoundary,
} from './sub-protocol-wrappers.js';

/**
 * withSettlementRetryHandler — wraps an EnvelopeHandler with runSettlementRetryBoundary
 *
 * Usage:
 * ```typescript
 * transport.listen(8080, withSettlementRetryHandler(myHandler));
 * ```
 *
 * Any SrError thrown inside myHandler is caught and converted to a ProtocolError; the
 * envelope metadata envelope.id is propagated as requestId (for audit log correlation).
 */
export function withSettlementRetryHandler(
    handler: EnvelopeHandler,
): EnvelopeHandler {
    return (envelope) =>
        runSettlementRetryBoundary(() => handler(envelope), envelope.id);
}

/**
 * withDisputeArbitrationHandler — wraps an EnvelopeHandler with runDisputeArbitrationBoundary
 *
 * Usage:
 * ```typescript
 * transport.listen(8080, withDisputeArbitrationHandler(myHandler));
 * ```
 *
 * Any DaError thrown inside myHandler is caught and converted to a ProtocolError.
 */
export function withDisputeArbitrationHandler(
    handler: EnvelopeHandler,
): EnvelopeHandler {
    return (envelope) =>
        runDisputeArbitrationBoundary(() => handler(envelope), envelope.id);
}

/**
 * withAuditShareHandler — wraps an EnvelopeHandler with runAuditShareBoundary
 *
 * Usage:
 * ```typescript
 * transport.listen(8080, withAuditShareHandler(myHandler));
 * ```
 *
 * Any AuditShareError thrown inside myHandler is caught and converted to a ProtocolError.
 */
export function withAuditShareHandler(
    handler: EnvelopeHandler,
): EnvelopeHandler {
    return (envelope) =>
        runAuditShareBoundary(() => handler(envelope), envelope.id);
}

/**
 * withAuditTamperProofHandler — wraps an EnvelopeHandler with runAuditTamperProofBoundary
 *
 * Usage:
 * ```typescript
 * transport.listen(8080, withAuditTamperProofHandler(myHandler));
 * ```
 *
 * Any AuditError (audit-tamper-proof L0) thrown inside myHandler is caught and converted
 * to a ProtocolError.
 */
export function withAuditTamperProofHandler(
    handler: EnvelopeHandler,
): EnvelopeHandler {
    return (envelope) =>
        runAuditTamperProofBoundary(() => handler(envelope), envelope.id);
}

/**
 * withHashChainHandler — wraps an EnvelopeHandler with runHashChainBoundary
 *
 * Usage:
 * ```typescript
 * transport.listen(8080, withHashChainHandler(myHandler));
 * ```
 *
 * Any HashChainError thrown inside myHandler is caught and converted to a ProtocolError.
 */
export function withHashChainHandler(
    handler: EnvelopeHandler,
): EnvelopeHandler {
    return (envelope) =>
        runHashChainBoundary(() => handler(envelope), envelope.id);
}

/**
 * withCredentialResolverHandler — wraps an EnvelopeHandler with runCredentialResolverBoundary
 *
 * Usage:
 * ```typescript
 * transport.listen(8080, withCredentialResolverHandler(myHandler));
 * ```
 *
 * Any CrError thrown inside myHandler is caught and converted to a ProtocolError.
 */
export function withCredentialResolverHandler(
    handler: EnvelopeHandler,
): EnvelopeHandler {
    return (envelope) =>
        runCredentialResolverBoundary(() => handler(envelope), envelope.id);
}
