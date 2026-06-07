/**
 * ActionVocabulary — SESSION_SUPERSEDED control-plane event type constants.
 *
 * Design constraints:
 * - reason is a schema field, not an error-code namespace; it is not mixed with PROTOCOL_ERROR_CODES
 * - only the control plane enters the chain; the related invariants are guaranteed by the recorder and not bypassed
 *
 * The main enum values are maintained centrally in base.ts ACTION_VOCABULARY; this module only carries the
 * structure specific to the single SESSION_SUPERSEDED value (actor DID, reason enum, params shape, type guards),
 * with the full unit tests and the recorder wiring landing separately.
 */

import type { DID, Timestamp } from './base.js';

// ---------------------------------------------------------------------------
// actor DID constant (design decision: did:system sub-method, does not extend didPattern, leaves it untouched)
// ---------------------------------------------------------------------------

/**
 * The only valid actor DID for SESSION_SUPERSEDED.
 *
 * Design rationale:
 * - the did:system:* sub-method is used for **control-plane** events (session lifecycle / ops-triggered ActionRecord)
 * - does **not** participate in BindingProof (does not issue an AgentIdentityDocument)
 * - does **not** enter federated DID resolution (is not resolved to a public key for envelope signature verification)
 * - does **not** issue envelopes / tokens; serves only as the identifier for ActionRecord.agentDid and ActionRecord.principalDid
 * - reuses the existing didPattern at schemas.ts:60 (`^did:[a-z][a-z0-9-]*:...$`), no need to extend the pattern
 *
 * Validation: the AJV schema, via if/then in the `action === 'SESSION_SUPERSEDED'` branch, enforces
 * agentDid === principalDid === SESSION_GOVERNOR_DID (the concrete rule lands inside schemas.ts ledgerSchema
 * actionRecord; this constant is the runtime reference source).
 */
export const SESSION_GOVERNOR_DID =
    'did:system:session-governor' as const satisfies string;

// ---------------------------------------------------------------------------
// reason enum (schema field, not an error code)
// ---------------------------------------------------------------------------

/**
 * The reason field enum for SESSION_SUPERSEDED.
 *
 * The 4 values cover the session-persistence control-plane events + token revocation / idle
 * / forced close:
 * - EXPLICIT_CLOSE: the business side actively calls close()
 * - TOKEN_REVOKED: CapabilityToken revocation cascades into SessionRegistry close + fresh handshake
 *   (positive hardening of Invariant 8)
 * - IDLE_EXPIRED: the sweeper advances an IDLE row to CLOSED (idleHardMs timeout)
 * - FORCED_CLOSE: ops / exception-path forced close (newSessionId may be null, no successor session exists)
 *
 * self-check: this enum appears only inside ActionRecord.parametersSummary.reason,
 * does **not** enter PROTOCOL_ERROR_CODES, and does not conflict with the error-code namespace.
 */
export const SESSION_SUPERSEDED_REASONS = [
    'EXPLICIT_CLOSE',
    'TOKEN_REVOKED',
    'IDLE_EXPIRED',
    'FORCED_CLOSE',
] as const;

export type SessionSupersededReason =
    (typeof SESSION_SUPERSEDED_REASONS)[number];

// ---------------------------------------------------------------------------
// params shape (written into ActionRecord.parametersSummary)
// ---------------------------------------------------------------------------

/**
 * The parametersSummary shape for SESSION_SUPERSEDED.
 *
 * - oldSessionId: the superseded old session ID (required, a sessionId string, non-empty)
 * - newSessionId: the successor session ID; may be null on the FORCED_CLOSE path (no successor session)
 *   under other reasons the schema enforces a non-empty string in the if/then branch
 * - reason: a 4-value enum (see SESSION_SUPERSEDED_REASONS)
 * - timestamp: the time the event occurred (ISO 8601, same shape as ActionRecord.timestamp)
 * - affectedAgentDid: the business agent DID affected by this supersede action (schema required).
 *   The governor lane's audit must perform subject-scope validation by affectedAgentDid, so it is mandatory.
 * - affectedPrincipalDid: the business principal DID affected by this supersede action (schema required).
 *   The governor lane allowlist scopes its audit by affectedPrincipalDid, so it is mandatory.
 *
 * Relationship to ActionRecord:
 * - this object is written **in its entirety** as ActionRecord.parametersSummary;
 * - the reason='TOKEN_REVOKED' path shares a transaction with SessionRegistry close+fresh (Invariant 8);
 *   SESSION_SUPERSEDED itself is an **audit side-channel**, written after the fact within ≤5s via outbox / reconciliation
 *   (breaking-format-change-v0.3.0 SLO, implemented by the recorder).
 *
 * The original interface was missing the affectedAgentDid /
 * affectedPrincipalDid fields (drift from the schemas.ts required requirement), so records written out by
 * SessionSupersedeRecorder were invisible to the governor lane's subject-scoped audit. This change promotes both fields to mandatory,
 * aligning with the schemas.ts parametersSummary required[].
 */
export interface SessionSupersededParams {
    oldSessionId: string;
    newSessionId: string | null;
    reason: SessionSupersededReason;
    timestamp: Timestamp;
    /** Existing schema requirement, previously undeclared in the interface. */
    affectedAgentDid: DID;
    /** Existing schema requirement, previously undeclared in the interface. */
    affectedPrincipalDid: DID;
}

// ---------------------------------------------------------------------------
// namespace-isolation declaration (same name as PROTOCOL_ERROR_CODES.SESSION_SUPERSEDED but semantically independent)
// ---------------------------------------------------------------------------

/**
 * The SESSION_SUPERSEDED literal constant within the ActionVocabulary main enum.
 *
 * Naming-coincidence warning: `PROTOCOL_ERROR_CODES` (schemas.ts L7-47) already contains an error code with the same name
 * `'SESSION_SUPERSEDED'` (returned when a business message is sent to a session that has already been superseded). The two:
 * - schema layer: live in two separate enum arrays, `ACTION_VOCABULARY` and `PROTOCOL_ERROR_CODES`; AJV does not mix them
 * - runtime: the reader routes by field type (ActionRecord.action vs ProtocolError.code), with no ambiguity
 * - signature preimage: only ActionRecord.action enters the hash chain; ProtocolError does not enter the chain
 */
export const ACTION_SESSION_SUPERSEDED = 'SESSION_SUPERSEDED' as const;

// ---------------------------------------------------------------------------
// type guards (runtime helpers; schema validation remains authoritative via AJV)
// ---------------------------------------------------------------------------

/** Determines whether a given string is a valid SESSION_SUPERSEDED reason enum value. */
export const isSessionSupersededReason = (
    value: unknown,
): value is SessionSupersededReason =>
    typeof value === 'string' &&
    (SESSION_SUPERSEDED_REASONS as readonly string[]).includes(value);

/** Determines whether a given DID is the only valid actor for SESSION_SUPERSEDED. */
export const isSessionGovernorDid = (
    did: DID | string,
): did is typeof SESSION_GOVERNOR_DID => did === SESSION_GOVERNOR_DID;
