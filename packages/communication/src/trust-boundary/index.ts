/**
 * trust-boundary primitive v0.1 — L4 communication public exports
 *
 * Design:
 * - Local exports for the L4 communication layer (re-exported by packages/communication/src/index.ts)
 * - Once the L0 types primary declaration is complete (packages/types/src/trust-boundary.ts),
 *   this module will switch to importing the L0 types (in a follow-up cleanup PR).
 */

export {
    LEGAL_TRANSITIONS,
    TB_DEFAULT_BOUNDS,
    TbProtocolError,
    toTbVersionString,
    toTrustBoundaryId,
    toUuidV4String,
    type BoundaryBindingProof,
    type LeaseExtensionProof,
    type TbErrorCode,
    type TbVersionString,
    type TransitionSource,
    type TrustBoundary,
    type TrustBoundaryAuditEvent,
    type TrustBoundaryEmergencyEvent,
    type TrustBoundaryEmergencyState,
    type TrustBoundaryId,
    type TrustBoundaryLifecycleEvent,
    type TrustBoundaryState,
    type UuidV4String,
} from './types.js';

export {
    InMemoryTrustBoundaryStorage,
    TestProofVerifier,
    TrustBoundaryLifecycleManager,
    assertInvariant,
    type BoundaryProofVerifier,
    type TrustBoundaryStorage,
} from './lifecycle-manager.js';

export {
    createHandshakeBoundaryMiddleware,
    type HandshakeBoundaryContext,
    type HandshakeBoundaryMiddleware,
} from './handshake-integration.js';
