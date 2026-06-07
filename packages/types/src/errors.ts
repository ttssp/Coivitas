/**
 * Complete enumeration of protocol error codes.
 *
 * Baseline 20 values + 21 added values + 12 v0.2 added values = 53 values.
 * Dual-source constraint: this union must stay in sync with the PROTOCOL_ERROR_CODES const array in schemas.ts.
 *
 * @frozen frozen (full set of 53 values; namespace reserved for future additions)
 */
export type ProtocolErrorCode =
    | 'IDENTITY_NOT_FOUND'
    | 'IDENTITY_ALREADY_EXISTS'
    | 'SIGNATURE_INVALID'
    | 'TOKEN_EXPIRED'
    | 'TOKEN_REVOKED'
    | 'SCOPE_EXCEEDED'
    | 'BINDING_PROOF_INVALID'
    | 'HANDSHAKE_FAILED'
    | 'HANDSHAKE_REJECTED'
    | 'HANDSHAKE_TIMEOUT'
    | 'INVALID_HANDSHAKE'
    | 'INVALID_MESSAGE'
    | 'SESSION_NOT_FOUND'
    | 'SESSION_CLOSED'
    | 'SPEC_VERSION_MISMATCH'
    | 'CLOCK_SKEW_EXCEEDED'
    | 'ACTION_REJECTED'
    | 'HUMAN_APPROVAL_REQUIRED'
    | 'INTERNAL_ERROR'
    | 'RATE_LIMIT_EXCEEDED'
    // Added (compatible with the frozen wire-format: adding new error codes is allowed)
    | 'AGENT_CARD_NOT_FOUND'
    | 'ATTENUATION_VIOLATED'
    | 'DELEGATION_CHAIN_INVALID'
    | 'DEPTH_EXCEEDED'
    | 'PARENT_TOKEN_REVOKED'
    | 'PARENT_TOKEN_NOT_FOUND'
    | 'PARENT_TOKEN_EXPIRED'
    | 'CYCLE_DETECTED'
    | 'ROOT_NOT_PRINCIPAL'
    | 'DELEGATOR_MISMATCH'
    | 'SCOPE_TYPE_UNKNOWN'
    | 'METER_INTEGRITY_COMPROMISED'
    | 'FEDERATED_RESOLUTION_FAILED'
    | 'FEDERATED_VERSION_CONFLICT'
    | 'TRANSPORT_ERROR'
    | 'SESSION_RESUMED'
    | 'SESSION_SUPERSEDED'
    | 'AUDIT_ACCESS_DENIED'
    // Key rotation Registry integration (newly added error codes are backward compatible)
    | 'VERSION_CONFLICT'
    | 'IDENTITY_DEACTIVATED'
    // Session persistence (newly added error codes are backward compatible)
    | 'SESSION_STATE_INVALID'
    | 'SESSION_IDLE_EXPIRED'
    | 'SESSION_DID_MISMATCH'
    | 'SESSION_TOKEN_MISMATCH'
    // Audit query API (newly added error codes are backward compatible)
    | 'AUDIT_SIGNATURE_INVALID'
    | 'AUDIT_TIMESTAMP_SKEW'
    | 'AUDIT_REQUESTER_UNKNOWN'
    | 'AUDIT_FORBIDDEN'
    | 'AUDIT_QUERY_MALFORMED'
    | 'AUDIT_RESOURCE_BINDING_MISMATCH'
    | 'AUDIT_SNAPSHOT_BOUNDARY_VIOLATED'
    | 'AUDIT_IDENTITY_UNVERIFIED'
    // Added in v0.2 (frozen)
    // nonce replay rejection
    | 'AUDIT_NONCE_REPLAY'
    // plugin registration conflict
    | 'SCOPE_PLUGIN_CONFLICT'
    // plugin sandbox violation
    | 'SCOPE_PLUGIN_SANDBOX_VIOLATION'
    // encrypted session handle already closed/revoked
    | 'SESSION_HANDLE_REVOKED'
    // AEAD decryption failed
    | 'DECRYPTION_FAILED'
    // key renegotiation failed
    | 'REKEY_FAILED'
    // peer does not support encryption but this side requires it
    | 'ENCRYPTION_REQUIRED'
    // encryption required but no CapabilityToken present
    | 'ENCRYPTION_REQUIRES_CAPABILITY_TOKEN'
    // EncryptedBody has invalid format
    | 'INVALID_ENCRYPTED_BODY'
    // encryption negotiation offer is invalid
    | 'INVALID_ENCRYPTION_OFFER'
    // unexpected receipt-of-receipt
    | 'UNEXPECTED_RECEIPT_FOR_RECEIPT'
    // discovery message type integration (aligned dual-source with schemas.ts)
    | 'DISCOVERY_NOT_SUPPORTED'
    | 'DISCOVERY_TARGET_MISMATCH'
    // completing the full set of encryption error codes
    // unsupported encryption protocol version
    | 'ENCRYPTION_UNSUPPORTED'
    // X25519 ECDH key agreement failed
    | 'KEY_AGREEMENT_FAILED'
    // AEAD nonce reuse (internal defense)
    | 'AEAD_NONCE_REUSED'
    // replay detection (sequenceNumber <= highest seen value)
    | 'ENCRYPTED_REPLAY_DETECTED'
    // validate returned accepted=false during rekey
    | 'REKEY_REJECTED_BY_AUTHORIZATION'
    // transcript_hash comparison failed (downgrade-attack defense)
    | 'ENCRYPTION_DOWNGRADE_DETECTED'
    // X25519 public key is all-zero or a small subgroup element
    | 'EPHEMERAL_KEY_INVALID'
    // local policy requires a receipt but none received before timeout
    | 'RECEIPT_REQUIRED'
    // generic receipt verification failure (external-facing)
    | 'RECEIPT_VERIFICATION_FAILED'
    // receipt signature invalid (internal)
    | 'RECEIPT_SIGNATURE_INVALID'
    // ackEnvelopeId mismatch (internal)
    | 'RECEIPT_ENVELOPE_MISMATCH'
    // sessionId mismatch (internal)
    | 'RECEIPT_SESSION_MISMATCH'
    // paramsHash mismatch (internal)
    | 'RECEIPT_PARAMS_HASH_MISMATCH'
    // receivedAt exceeds freshnessMs (internal)
    | 'RECEIPT_STALE'
    // exceeded receiptTimeoutMs
    | 'RECEIPT_TIMEOUT'
    // shape-sensing cross-detection
    | 'RECEIPT_SHAPE_WITHOUT_RECEIPT_TYPE'
    // type RECEIPT but shape does not match
    | 'INVALID_RECEIPT_PAYLOAD'
    // session key lost from memory
    | 'CRYPTO_STATE_LOST'
    // beforeExecute persistence failed (L3 recorder)
    | 'AUDIT_INTENT_PERSIST_FAILED'
    // beforeExecute timed out (L3 recorder)
    | 'AUDIT_INTENT_TIMEOUT'
    // afterExecute persistence failed (L3 recorder)
    | 'AUDIT_RECORD_UPDATE_FAILED'
    // irreversible non-idempotent executor barred (L3 policy)
    | 'POLICY_REQUIRES_OUTBOX'
    // ActionRecord.sessionId not in place (ENCRYPTION_* prefix)
    | 'ENCRYPTION_MIRROR_PROOF_UNAVAILABLE'
    // MeterFieldRef.source three-state extension
    // Only the 'action_record' evaluator currently ships; the other two states' evaluators throw this error code (fail-closed)
    | 'METRIC_SOURCE_NOT_IMPLEMENTED';

/**
 * Protocol error class.
 *
 * @frozen frozen (constructor signature unchanged)
 *
 * Design constraint: the `.detail: Record<string, unknown>` of the sub-protocol L0 error
 * classes (CrError/SrError/DaError) is incompatible with ProtocolError's `.detail: string`
 * (TS2416), so all sub-protocol L0 error classes stay as they are (CcrError + RfpError
 * extend ProtocolError, and 6 others extend Error); ProtocolError stays frozen and does not
 * introduce a `code: ProtocolErrorCode | string` revision.
 */
export class ProtocolError extends Error {
    public override readonly name = 'ProtocolError';

    public constructor(
        public readonly code: ProtocolErrorCode,
        public readonly detail: string,
        public readonly requestId?: string,
    ) {
        super(`[${code}] ${detail}`);
    }
}
