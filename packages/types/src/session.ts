// Session persistence types (L4).
// ⚠️ Internal breaking changes:
// - SessionState is extended from 'PENDING' | 'ACTIVE' | 'CLOSED' to 'CREATED' | 'ACTIVE' | 'IDLE' | 'CLOSED'
// - the SessionManager public API is fully asynchronous; SessionRecordStore adds the resume / claimForDispatch / markAuthorized / closeByToken / closeByPrincipal / supersedeAndCreate primitives
// Does not touch the wire-format freeze (the NegotiationEnvelope shell is unchanged).

// Naming convention:
// - the in-memory view remains under `Session` in `@coivitas/communication`
// (field set PENDING/ACTIVE/CLOSED + lastActiveAt, produced by SessionManager)
// - the persisted-row view is lifted up to L0 as `SessionRecord`
// (field set below; corresponds to the communication.sessions table + revision CAS fencing)
// The two models coexist until the persistence migration completes.

import type { DID, Timestamp } from './base.js';

// Four-state session state machine.
export type SessionState = 'CREATED' | 'ACTIVE' | 'IDLE' | 'CLOSED';

export type CloseReason =
    | 'IDLE_TIMEOUT'
    | 'EXPLICIT_CLOSE'
    | 'HANDSHAKE_REJECTED'
    | 'ERROR'
    | 'REVOKED_TOKEN';

// SessionRecord — the canonical view of a persisted session row (corresponds to a communication.sessions row).
// revision: a monotonically increasing version stamp (BIGINT), serialized as a string on the TS side to avoid JS Number precision loss.
export interface SessionRecord {
    sessionId: string;
    initiatorDid: DID;
    responderDid: DID;
    principalDid: DID;
    capabilityTokenId: string | null;
    capabilityTokenFingerprint: string | null;
    state: SessionState;
    negotiatedCapabilities: string[];
    establishedAt: Timestamp | null;
    lastSeenAt: Timestamp;
    lastAuthorizedAt: Timestamp;
    idleSince: Timestamp | null;
    closedAt: Timestamp | null;
    closeReason: CloseReason | null;
    supersedesSessionId: string | null;
    didPairKey: string;
    createdAt: Timestamp;
    updatedAt: Timestamp;
    revision: string;
}

// Create-session input.
// - initialState='CREATED' indicates a two-step handshake (a later activate() advances to ACTIVE)
// - initialState='ACTIVE' indicates a single-transaction atomic write (eliminating the CREATED→ACTIVE half-open window)
export interface SessionRecordCreateInput {
    sessionId: string;
    initiatorDid: DID;
    responderDid: DID;
    principalDid: DID;
    capabilityTokenId?: string;
    capabilityTokenFingerprint?: string;
    negotiatedCapabilities?: string[];
    initialState?: 'CREATED' | 'ACTIVE';
    supersedesSessionId?: string;
}

export interface SessionRecordUpdatePatch {
    state?: SessionState;
    negotiatedCapabilities?: string[];
    establishedAt?: Timestamp;
    lastSeenAt?: Timestamp;
    lastAuthorizedAt?: Timestamp;
    idleSince?: Timestamp | null;
    closedAt?: Timestamp;
    closeReason?: CloseReason;
}

export interface SessionRecordListActiveFilter {
    initiatorDid?: DID;
    responderDid?: DID;
    states?: SessionState[];
    limit?: number;
}

export interface SessionRecordCleanResult {
    markedStale: number; // CREATED timeout → CLOSED('HANDSHAKE_REJECTED')
    markedIdle: number; // ACTIVE idleSoft timeout → IDLE
    markedClosed: number; // IDLE idleHard timeout → CLOSED('IDLE_TIMEOUT')
}

// Resume-session input (the atomic resume primitive).
// - idleHardMs: the IDLE hard boundary; idle_since < now - idleHardMs is considered expired
// - expectedCapabilityToken*: optional token-binding check; when provided it must strictly equal the row (NULL semantics matched strictly)
export interface SessionRecordResumeInput {
    sessionId: string;
    expectedInitiatorDid: DID;
    expectedResponderDid: DID;
    expectedCapabilityTokenId?: string;
    expectedCapabilityTokenFingerprint?: string;
    idleHardMs: number;
    negotiatedCapabilities: string[];
    now?: Timestamp;
}

// SessionRecordStore — the session backend abstraction.
// Common implementation contract: every UPDATE must also execute revision = revision + 1.
export interface SessionRecordStore {
    create(input: SessionRecordCreateInput): Promise<SessionRecord>;

    get(sessionId: string): Promise<SessionRecord | null>;

    // Ordinary patch update (an illegal transition throws SESSION_STATE_INVALID; a CLOSED row throws SESSION_CLOSED).
    update(
        sessionId: string,
        patch: SessionRecordUpdatePatch,
    ): Promise<SessionRecord>;

    // The atomic resume primitive (validation + state transition completed in a single transaction).
    resume(input: SessionRecordResumeInput): Promise<SessionRecord>;

    // A primitive dedicated to the CLOSED-recovery path: atomically close the old row and insert a new one (supersedesSessionId is filled in automatically).
    supersedeAndCreate(params: {
        oldSessionId: string;
        fallbackCloseReason: CloseReason;
        newCreateInput: SessionRecordCreateInput;
        now?: Timestamp;
    }): Promise<SessionRecord>;

    // The only legal entry point for the atomic bind-claim on the ordinary message path.
    claimForDispatch(params: {
        sessionId: string;
        senderDid: DID;
        selfDid: DID;
        expectedCapabilityTokenId?: string;
        expectedCapabilityTokenFingerprint?: string;
        now?: Timestamp;
    }): Promise<SessionRecord>;

    // Called after L3 Policy authorization passes (CAS fencing).
    // CAS failure → throws SESSION_STATE_INVALID; the caller must discard the envelope and not write an ActionRecord.
    markAuthorized(params: {
        sessionId: string;
        expectedRevision: string;
        now?: Timestamp;
    }): Promise<SessionRecord>;

    // Precise tokenId-scoped revocation: close every live session bound to that token.
    closeByToken(params: {
        tokenId: string;
        reason?: CloseReason;
        now?: Timestamp;
    }): Promise<string[]>;

    // principal-scoped revocation (transition-period NULL-token coverage).
    closeByPrincipal(params: {
        principalDid: DID;
        reason?: CloseReason;
        now?: Timestamp;
    }): Promise<string[]>;

    listActive(
        filter?: SessionRecordListActiveFilter,
    ): Promise<SessionRecord[]>;

    cleanExpired(params: {
        createdTimeoutMs: number;
        idleSoftMs: number;
        idleHardMs: number;
        now?: Timestamp;
    }): Promise<SessionRecordCleanResult>;
}
