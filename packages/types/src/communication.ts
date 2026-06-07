import type { DID, Signature, Timestamp } from './base.js';

/**
 * MessageType union type (full set)
 *
 * v0.1 baseline (6 values, per the communication spec):
 *   HANDSHAKE_INIT / HANDSHAKE_ACK / NEGOTIATION_REQUEST /
 *   NEGOTIATION_RESPONSE / NEGOTIATION_CONFIRM / ERROR
 *
 * Added in v0.2 (per the discovery spec; effective under specVersion >= 0.3.0):
 *   DISCOVERY_REQUEST / DISCOVERY_RESPONSE
 *
 * Validation strategy:
 *   - specVersion 0.1.0/0.2.0 validators should return an ERROR envelope on receiving DISCOVERY_*.
 *   - specVersion 0.3.0 validators MUST accept these two values.
 *
 * SSOT dual source: this union must stay in sync with the base.ts MESSAGE_TYPES const array.
 * Both sides must be changed together. Parity test pending implementation (tracking: scope).
 *
 * Implementation anchor: the MESSAGE_TYPES constant in packages/types/src/base.ts (the schema enum array)
 *
 * @frozen (full set of 8 values)
 */
export type MessageType =
    | 'HANDSHAKE_INIT'
    | 'HANDSHAKE_ACK'
    | 'NEGOTIATION_REQUEST'
    | 'NEGOTIATION_RESPONSE'
    | 'NEGOTIATION_CONFIRM'
    | 'ERROR'
    // Added in v0.2 (usable only under specVersion >= 0.3.0)
    | 'DISCOVERY_REQUEST'
    | 'DISCOVERY_RESPONSE';

/**
 * EnvelopeHeader — breaking-format-change #4
 *
 * Adds the optional field capabilityTokenRef (a reference to CapabilityToken.id).
 * The verifier fetches the full Token and its delegation chain via tokenStore — the Envelope carries only the reference.
 * The signature coverage includes capabilityTokenRef.
 */
export interface EnvelopeHeader {
    senderDid: DID;
    recipientDid: DID;
    sessionId: string | null;
    sequenceNumber?: number;
    /**
     * Added — references the CapabilityToken.id authorizing this message.
     * Does not carry the delegation-chain data itself (avoids duplicating authorization-layer data at the transport layer).
     */
    capabilityTokenRef?: string;
}

export interface NegotiationEnvelope {
    id: string;
    specVersion: string;
    header: EnvelopeHeader;
    messageType: MessageType;
    body: Record<string, unknown>;
    signature: Signature;
    timestamp: Timestamp;
}

/**
 * HandshakeChallenge resume extension (session-persistence spec)
 *
 * A HANDSHAKE_INIT body field used to reconnect to an existing session.
 */
export interface HandshakeResumeHint {
    /** the previous session ID (the client declares the session it wishes to resume)*/
    previousSessionId: string;
    /** the last sequence number already processed (used to determine the replay starting point)*/
    lastSeenSequenceNumber?: number;
}

/**
 * HandshakeChallenge — HANDSHAKE_INIT body field
 *
 * Field-alignment strategy:
 * - The field set takes the extended version (including resumeSessionId / principalDid / capabilityTokenId)
 * - But principalDid is marked **optional** in this interface, because:
 *   1. The AJV layer communicationSchema.handshakeChallenge still does not list
 *      principalDid as required (schemas.ts:542-573)
 *   2. The L4 implementation packages/communication/src/handshake/initiator.ts
 *      currently does not send principalDid; responder.ts silently falls back to
 *      initiatorDid when it is missing
 *   3. The communication baseline version does not include principalDid
 *
 *   The contract must be able to describe the legal messages this repository
 *   actually produces today. The "mandatory principalDid" declared by
 *   session-persistence is a planning state (the "missing principal binding"
 *   rejection is not yet consistently landed across all 5 layers); freezing this
 *   field as required would write the contract in a future state — leaving this
 *   interface unable to accept the challenges it produces itself.
 *
 *   Once packages/communication + AJV + spec + tests are upgraded consistently
 *   across all four layers, change this field to required and remove this comment.
 *
 * Token-binding / resume differences (already effective):
 * - capabilityTokenId optional (urn:cap:<uuid v4>), used for the token-binding gate
 * - resumeSessionId optional; when non-empty, takes the resume path
 */
export interface HandshakeChallenge {
    /** unique challenge ID (UUID v4)*/
    challengeId: string;
    /** challenge initiator DID (did:agent)*/
    initiatorDid: DID;
    /** recipient DID (did:agent, the target)*/
    responderDid: DID;
    /**
     * Optional: the Principal for this handshake (did:key).
     * session-persistence plans to upgrade this to required,
     * but the L4 implementation has not yet caught up — see the SSOT alignment strategy above.
     */
    principalDid?: DID;
    /** single-use nonce (replay defense, 32 bytes hex = 64 chars)*/
    nonce: string;
    /** challenge creation time*/
    timestamp: Timestamp;
    /** challenge expiry time (recommended: timestamp + 60 seconds)*/
    expiresAt: Timestamp;
    /** capability set the initiator declares it supports (values must be within ACTION_VOCABULARY)*/
    initiatorCapabilities: string[];
    /**
     * Optional: the Initiator's intent to "reuse this session_id".
     * When non-empty, the Responder takes the resume flow; the fingerprint is not
     * carried in the challenge and is computed by the Responder from the parsed token.
     */
    resumeSessionId?: string;
    /**
     * Optional: the CapabilityToken.id for this handshake (urn:cap:<uuid v4>).
     * During the transition period it may be absent (creating a session with capability_token_id = NULL);
     * a later release makes it mandatory.
     */
    capabilityTokenId?: string;
}

/**
 * HandshakeResponse — the response field in the HANDSHAKE_ACK body
 *
 * For the AJV schema, see schemas.ts communicationSchema.handshakeResponse.
 *
 * When accepted=false, the Responder fills sessionId with an empty string (step 6),
 * and the Initiator must not read the sessionId field.
 */
export interface HandshakeResponse {
    /** corresponds to HandshakeChallenge.challengeId*/
    challengeId: string;
    /** session ID (a UUID v4 generated by the Responder; empty string when accepted=false)*/
    sessionId: string;
    /** Responder DID (did:agent)*/
    responderDid: DID;
    /** capability set the Responder declares it supports (values must be within ACTION_VOCABULARY)*/
    responderCapabilities: string[];
    /** original nonce (must match the challenge; replay defense)*/
    nonce: string;
    /** Responder signing time*/
    timestamp: Timestamp;
    /**
     * Optional: the CapabilityToken.id bound to this session (matching
     * challenge.capabilityTokenId, as a receipt that the Responder side has confirmed the token binding).
     */
    capabilityTokenId?: string;
}

/**
 * DISCOVERY_REQUEST message body
 *
 * Sends a discovery request via a NegotiationEnvelope.
 *
 * The requester queries the target agent's AgentCard through an established
 * session (or a bare Envelope without a session).
 *
 * Reserved early -> formalized as v0.2 (fields unchanged).
 *
 * Implementation anchor: packages/types/src/communication.ts
 *
 * @breaking N/A (internal to body)
 * @adr (v0.3.0)
 * @frozen
 */
export interface DiscoveryRequestBody {
    /** the agent DID the requester wishes to discover (did:agent:<40 hex chars>)*/
    targetDid: DID;

    /** request-initiation timestamp (ISO 8601 UTC; replay defense)*/
    requestedAt: Timestamp;
}

/**
 * DISCOVERY_RESPONSE message body
 *
 * The responder returns the discovered agent's AgentCard (JSON-serialized).
 * On receipt, the caller must verify the AgentCard's signature and
 * authoritative-source consistency per the discovery spec verification flow.
 *
 * Reserved early -> formalized and extended as v0.2.
 * Added in v0.2: documentVersion (source document version, a cache-optimization hint).
 *
 * Implementation anchor: packages/types/src/communication.ts
 *
 * @breaking N/A (internal to body)
 * @adr (v0.3.0)
 * @frozen
 */
export interface DiscoveryResponseBody {
    /** the discovered agent's DID (must match request.targetDid)*/
    agentDid: DID;

    /**
     * the serialized AgentCard JSON
     *
     * Contains the full AgentCard object (including the signature field).
     * After parsing, the recipient must run signature verification +
     * IdentityRegistry cross-verification per the discovery spec verification algorithm.
     *
     * Reasons for using a JSON string rather than an inline object:
     * 1. Keeps envelope.body flat (does not nest a complex signature object)
     * 2. The AgentCard's signed payload is based on RFC 8785 canonicalization,
     *    and inlining would introduce double-serialization ambiguity
     * 3. Compatible with the future multi-format (CBOR / Protobuf) extension path
     */
    agentCardJson: string;

    /** response-generation timestamp (ISO 8601 UTC)*/
    respondedAt: Timestamp;

    /**
     * Added in v0.2: source AgentIdentityDocument version
     *
     * For recipient cache optimization: if the recipient's locally cached AgentCard
     * has a documentVersion >= this value, it may skip full verification and use the
     * cache directly. This field is a hint; it does not replace the AgentCard's
     * internal documentVersion field (which remains the signature-protected authoritative value).
     *
     */
    documentVersion: number;
}
