import type { DID, Signature, Timestamp } from './base.js';

export interface PrincipalIdentity {
    did: DID;
    publicKey: string;
    displayName?: string;
    createdAt: Timestamp;
}

export interface ServiceEndpoint {
    id: string;
    type: string;
    url: string;
}

export interface BindingProof {
    principalDid: DID;
    agentDid: DID;
    issuedAt: Timestamp;
    expiresAt: Timestamp | null;
    signature: Signature;
}

/**
 * Key rotation proof (added).
 *
 * Triple signature: old key + new key + principal endorsement.
 * An attacker holding only the agent key (whether old or new) cannot forge this proof.
 */
export interface RotationProof {
    oldPublicKey: string;
    newPublicKey: string;
    oldKeySignature: Signature;
    newKeySignature: Signature;
    principalSignature: Signature;
    agentDid: DID;
    rotatedAt: Timestamp;
}

/**
 * Key rotation state (added).
 *
 * Authoritatively stored by the IdentityRegistry, not derived from document fields.
 *
 * @deprecated In v0.3.0, use ResolvedKeyRotationState instead.
 * This type is retained for AgentRegistryRecord backward compatibility and will be migrated uniformly later.
 */
export type KeyRotationState = 'ACTIVE' | 'ROTATING' | 'RETIRED';

/**
 * v0.3.0 resolved key-rotation state.
 *
 * The three enum values map to four fallback semantics:
 *
 * 1. STABLE — no rotation in progress; only current is valid
 * 2. ROTATING (exit-window phase) — rotation has been initiated but the Grace Period has not expired;
 *    during verification, current is tried first, and on failure falls back to previous (accepting only
 *    pre-existing artifacts whose signing time < rotationStartedAt)
 * 3. ROTATING (entry-window phase) — logically the same enum value as (2); the difference is that
 *    the orchestrator has completed the current-key switch (new envelopes are issued with current),
 *    but the remote verifier must still accept in-flight artifacts issued with the previous key
 * 4. FROZEN — the key is frozen (compromise / administrator lock); only current is valid,
 *    previous is not returned; any rotation operation is blocked until unfreeze
 *
 * Among the four states, (2) and (3) share the ROTATING enum value — the distinction relies on the
 * orchestrator's internal "has the signing key been switched" flag, which is not exposed in the resolution
 * result. The verifier only needs to know "previous is available when ROTATING" to handle both sub-phases correctly.
 *
 * Required in v0.3.0; the v0.1.0/v0.2.0 verifiers are not aware of this type.
 */
export type ResolvedKeyRotationState = 'STABLE' | 'ROTATING' | 'FROZEN';

/**
 * AgentIdentityDocument — breaking-format-change #1 (specVersion 0.2.0)
 *
 * New fields (specVersion 0.2.0):
 * - version: document version number, initially 1, incremented on any field change
 * - previousPublicKey: the previous version's public key, used for verification within the Grace Period
 * - rotationProof: the most recent rotation proof, present when version > 1
 *
 * Backward compatibility: 0.1.0 documents lack these three fields and are treated as version=1 + no rotation history.
 */
export interface AgentIdentityDocument {
    id: DID;
    specVersion: string;
    principalDid: DID;
    publicKey: string;
    bindingProof: BindingProof;
    capabilities?: string[];
    serviceEndpoints?: ServiceEndpoint[];
    createdAt: Timestamp;
    updatedAt: Timestamp;
    /** Added — defaults to 1; incremented on any field change*/
    version?: number;
    /** Added — when present, indicates at least one rotation has completed*/
    previousPublicKey?: string;
    /** Added — required when version > 1*/
    rotationProof?: RotationProof;
}

/**
 * The current authoritative Registry record for a given agent.
 *
 * The rotation-state fields are independent of the document, to avoid deriving state from field presence.
 */
export interface AgentRegistryRecord {
    did: DID;
    document: AgentIdentityDocument;
    status: 'active' | 'suspended' | 'deactivated';
    rotationState: KeyRotationState;
    rotationStartedAt: Timestamp | null;
    rotationCompletedAt: Timestamp | null;
}

/**
 * The dual-key resolution result during the Grace Period.
 *
 * v0.3.0 shape:
 * - current: the always-present, currently valid public key
 * - previous: returned only during ROTATING and while the Grace Period has not expired;
 *   absent when STABLE/FROZEN
 * - previousValidBefore: the cutoff (the old key only accepts pre-existing artifacts whose signing time ≤ this value);
 *   has a value only when previous is present
 * - rotationState: the three-state enum (mapping the four fallback semantics; see the ResolvedKeyRotationState docs)
 *
 * Design history: removing the previousValidBefore field was once considered, pushing the cutoff retrieval down
 * to the caller (passing it into the verifier separately from AgentRegistryRecord.rotationStartedAt), but the
 * verifier API provided no separate channel; no caller invoked it that way, causing the token-verifier to
 * fail-closed and reject valid old-key tokens within the Grace Period — violating the cutoff security invariant.
 * The field is therefore retained so that producer/consumer share the same type. The version field, by contrast,
 * was confirmed removed (version is not a security invariant).
 *
 * Required in v0.3.0; v0.1.0/v0.2.0 return the degraded current-only +
 * rotationState='STABLE' shape.
 */
export interface ResolvedPublicKeys {
    /** the currently valid public key (64-char hex Ed25519)*/
    current: string;
    /** the previous-generation public key; present only when ROTATING, used for fallback verification*/
    previous?: string;
    /**
     * the old key's validity cutoff (has a value only when previous is present)
     *
     * The old key only accepts pre-existing artifacts whose proof.created / token.issuedAt ≤ this instant,
     * rejecting Tokens/Envelopes newly issued with the old key after rotation began. This field is a fail-closed
     * security invariant, filled in by resolvePublicKeys directly from AgentRegistryRecord.rotationStartedAt.
     */
    previousValidBefore?: Timestamp;
    /** the current rotation state*/
    rotationState: ResolvedKeyRotationState;
}

/**
 * IdentityRegistry document-update event.
 *
 * The AgentCard cache listens to this event to invalidate itself automatically.
 */
export interface DocumentUpdatedEvent {
    did: DID;
    newVersion: number;
    changeType: 'field_update' | 'key_rotation' | 'endpoint_update';
}

/**
 * AgentCard — added.
 *
 * A derived view of AgentIdentityDocument, aimed at /.well-known/agent.json discovery.
 * Not an independent source of truth — publicKey/documentVersion/did must match the source document.
 */
export interface AgentCard {
    did: DID;
    specVersion: string;
    displayName?: string;
    description?: string;
    serviceEndpoints: ServiceEndpoint[];
    capabilitiesDeclared: string[];
    publicKey: string;
    /** references AgentIdentityDocument.version, used for cache-invalidation decisions*/
    documentVersion: number;
    updatedAt: Timestamp;
    signature: Signature;
}

/**
 * AgentCard signing payload.
 *
 * Signed by the agent's private key after canonicalize; does not include the signature field.
 */
export type AgentCardSignedPayload = Omit<AgentCard, 'signature'>;
