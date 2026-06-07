export type DID = string & { readonly __brand: 'DID' };

export type Signature = string & { readonly __brand: 'Signature' };

export type Hash = string & { readonly __brand: 'Hash' };

export type Timestamp = string & { readonly __brand: 'Timestamp' };

/**
 * Current default specVersion (frozen).
 *
 * New artifacts continue to use this version when they do **not** carry any
 * breaking-format-change fields. Artifacts carrying any of the
 * following fields MUST use SPEC_VERSION_0_2_0:
 *   - AgentIdentityDocument.{version, previousPublicKey, rotationProof}
 *   - CapabilityToken.delegationChain
 *   - Scope.type ∈ {temporal_scope, cumulative_limit}
 *   - EnvelopeHeader.capabilityTokenRef
 *   - ActionRecord.{delegationDepth, sessionId, actorSignature}
 */
export const SPEC_VERSION = '0.1.0' as const;

/** The 0.2.0 version, used for artifacts carrying breaking-format-change fields.*/
export const SPEC_VERSION_0_2_0 = '0.2.0' as const;

/** The 0.3.0 version.*/
export const SPEC_VERSION_0_3_0 = '0.3.0' as const;

/**
 * The specVersion enum that validators MUST accept, up to v1.0.0.
 * Tri-state coexistence: a 0.3.0 validator MUST accept 0.1.0 / 0.2.0 / 0.3.0 alike.
 */
export const SUPPORTED_SPEC_VERSIONS = ['0.1.0', '0.2.0', '0.3.0'] as const;
export type SupportedSpecVersion = (typeof SUPPORTED_SPEC_VERSIONS)[number];

/**
 * ActionVocabulary main enum (authorized actions must be typed).
 *
 * - Frozen baseline of 5 values (INQUIRY / QUOTE / CONFIRM / PUBLISH / RECORD);
 * - specVersion 0.3.0 adds `SESSION_SUPERSEDED` (control-plane session-supersession event,
 *   actor = `did:system:session-governor`), which appears only on the write side
 *   under specVersion 0.3.0; 0.1.0 / 0.2.0 validators fail-closed reject any
 *   ActionRecord carrying this action.
 */
export const ACTION_VOCABULARY = [
    'INQUIRY',
    'QUOTE',
    'CONFIRM',
    'PUBLISH',
    'RECORD',
    'SESSION_SUPERSEDED',
] as const;

/**
 * Handshake capability vocabulary (5-value business-plane subset).
 *
 * Source: communication.schema.json `handshakeChallenge.initiatorCapabilities.items.enum`.
 * Derivation: HANDSHAKE_CAPABILITY_VOCABULARY = ACTION_VOCABULARY \ ['SESSION_SUPERSEDED'].
 *
 * Purpose: before verifyEnvelope, HandshakeResponder.respond() explicitly checks
 * that every value in `challenge.initiatorCapabilities` is on this allowlist, as a
 * runtime mirror of the schema enum ban — the communication package has no AJV
 * path, so it must explicitly reject SESSION_SUPERSEDED here (control-plane actions
 * must not appear in handshake capability negotiation).
 *
 * Single-source check: the parity case in
 * packages/types/src/__tests__/action-vocabulary.test.ts asserts
 * HANDSHAKE_CAPABILITY_VOCABULARY = ACTION_VOCABULARY \ ['SESSION_SUPERSEDED'] to
 * prevent enum drift.
 */
export const HANDSHAKE_CAPABILITY_VOCABULARY = [
    'INQUIRY',
    'QUOTE',
    'CONFIRM',
    'PUBLISH',
    'RECORD',
] as const;
export type HandshakeCapability =
    (typeof HANDSHAKE_CAPABILITY_VOCABULARY)[number];

/**
 * MessageType constant array (runtime enum source)
 *
 * Baseline: 6 values.
 * v0.3.0: +2 values.
 *
 * Note: DISCOVERY_REQUEST / DISCOVERY_RESPONSE are legal only under specVersion >= 0.3.0.
 * specVersion 0.1.0/0.2.0 validators should return an ERROR envelope on receiving these two values.
 *
 * @frozen frozen
 */
export const MESSAGE_TYPES = [
    'HANDSHAKE_INIT',
    'HANDSHAKE_ACK',
    'NEGOTIATION_REQUEST',
    'NEGOTIATION_RESPONSE',
    'NEGOTIATION_CONFIRM',
    'ERROR',
    // Added in v0.2 (effective under specVersion >= 0.3.0)
    'DISCOVERY_REQUEST',
    'DISCOVERY_RESPONSE',
] as const;
