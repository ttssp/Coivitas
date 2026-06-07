// Cross-layer port contracts (L0 pure types; the core guarantee of the no-reverse-dependency rule).
// None of the interfaces carry runtime dependencies; each implementor implements its own layer and injects the other via construction.
// Orchestration completes the wiring at L5 (@coivitas/sdk).

import type { IdentityStoreForAudit } from './audit.js';
import type { DID } from './base.js';
import type { ResolvedPublicKeys } from './identity.js';
import type { CloseReason, SessionRecord } from './session.js';

// Re-exported so downstream layers (L2/L3/L4) can reference them through the single ports entry point,
// avoiding the need for an implementor to take another detour through the identity.js / audit.js
// dependency just to obtain ResolvedPublicKeys / IdentityStoreForAudit.
export type { IdentityStoreForAudit, ResolvedPublicKeys };

// TokenFingerprintResolver — L3 Policy implementation.
// Function: given a capabilityTokenRef (urn:cap:<uuid>), returns the RFC 8785 canonicalize + SHA-256 hex fingerprint.
// Contract: token not found / already revoked → null.
// Consumer: L4 SessionManager / ensureSessionBinding.
export interface TokenFingerprintResolver {
    resolve(tokenId: string): Promise<string | null>;
}

// HandshakeAuthorizationValidator — L3 Policy implementation (R9-1).
// Function: on the handshake success path (after DID/nonce/expiry/verifyInitiator all pass, before SessionStore.create/resume)
// validates whether the principalDid / capabilityTokenId claimed by the Initiator truly belong to it.
// Consumer: L4 HandshakeResponder (via construction injection).
// Return value:
// - accepted:true → provides the verified principalDid / capabilityTokenId / capabilityTokenFingerprint (tokenId and fingerprint are both empty or both non-empty)
// - accepted:false → reason is for internal logging only, not returned in the ACK
export interface HandshakeAuthorizationValidator {
    validate(input: {
        initiatorDid: DID;
        principalDid: DID;
        // null is allowed only during the transition period (before token binding is merged).
        capabilityTokenId: string | null;
    }): Promise<
        | {
              accepted: true;
              principalDid: DID;
              capabilityTokenId: string | null;
              capabilityTokenFingerprint: string | null;
          }
        | { accepted: false; reason: string }
    >;
}

// SessionLifecyclePort — L4 SessionManager implementation.
// Function: L3 issues session lifecycle control commands through this interface.
// - markAuthorized: the Step 1.5 CAS fence (R7-4)
// - closeByToken: precise tokenId revocation fan-out
// - closeByPrincipal: principal-scoped revocation fan-out (transition-period NULL-token coverage)
// Consumer: L3 Policy (via construction injection).
export interface SessionLifecyclePort {
    markAuthorized(
        sessionId: string,
        expectedRevision: string,
    ): Promise<SessionRecord>;
    closeByToken(tokenId: string, reason?: CloseReason): Promise<string[]>;
    closeByPrincipal(
        principalDid: DID,
        reason?: CloseReason,
    ): Promise<string[]>;
}

// PublicKeyResolver — L2 Identity implementation (the key-rotation spec).
// Function: resolves the set of public keys usable by an agent at a given moment, including old keys within the Grace Period.
// Contract:
// - agent not found → null
// - ROTATING and now - rotationStartedAt ≤ MAX_GRACE_PERIOD_MS → returns previous + previousValidBefore
// - otherwise → returns current only
// Consumer: the L1/L2 signature verification path (CapabilityToken / Envelope / DelegationProof).
export interface PublicKeyResolver {
    resolvePublicKeys(did: DID, now?: Date): Promise<ResolvedPublicKeys | null>;
}
