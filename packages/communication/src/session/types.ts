import type { DID, Timestamp } from '@coivitas/types';

/**
 * Four-state session state machine
 *
 * CREATED -> ACTIVE -> IDLE -> CLOSED; CREATED may go directly -> CLOSED (handshake rejected).
 */
export type SessionState = 'CREATED' | 'ACTIVE' | 'IDLE' | 'CLOSED';

/**
 * Session close reason
 */
export type CloseReason =
    | 'IDLE_TIMEOUT'
    | 'EXPLICIT_CLOSE'
    | 'HANDSHAKE_REJECTED'
    | 'ERROR'
    | 'REVOKED_TOKEN';

/**
 * Session encryption state
 *
 * OFF = encryption not enabled (non-encrypted handshake)
 * REQUIRED = encrypted session (handshake negotiation result is REQUIRED)
 *
 * Written by activate()/resume() after the handshake completes; immutable afterwards.
 */
export type EncryptionState = 'OFF' | 'REQUIRED';

/**
 * Persisted session record
 *
 * Stored in the PostgreSQL `sessions` table; revision serves as the CAS version stamp.
 * BIGINT is serialized as a string to avoid JS Number precision loss.
 */
export interface Session {
    sessionId: string;
    initiatorDid: DID;
    responderDid: DID;
    principalDid: DID;
    capabilityTokenId: string | null;
    capabilityTokenFingerprint: string | null;
    state: SessionState;
    negotiatedCapabilities: string[];
    /** Session encryption state; OFF=non-encrypted, REQUIRED=E2E encrypted session*/
    encryptionState: EncryptionState;
    /** Current-generation session key fingerprint (64-char hex); null when OFF*/
    sessionKeyFingerprint: string | null;
    /** Cumulative count of in-place re-handshakes (+1 after swapForDualKey); 0 when OFF*/
    rekeyCount: number;
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
    /** Monotonically increasing version stamp; BIGINT transmitted as a string*/
    revision: string;
}

export interface SessionCreateInput {
    sessionId: string;
    initiatorDid: DID;
    responderDid: DID;
    principalDid: DID;
    capabilityTokenId?: string;
    capabilityTokenFingerprint?: string;
    negotiatedCapabilities?: string[];
    /**
     * Session encryption state; defaults to 'OFF'.
     * Pass 'REQUIRED' when the handshake negotiation result is REQUIRED.
     */
    encryptionState?: EncryptionState;
    /**
     * First-generation session key fingerprint (64-char hex).
     * Required when encryptionState='REQUIRED'; must not be passed when 'OFF'.
     */
    sessionKeyFingerprint?: string;
    initialState?: 'CREATED' | 'ACTIVE';
    supersedesSessionId?: string;
}

export interface SessionUpdatePatch {
    state?: SessionState;
    negotiatedCapabilities?: string[];
    establishedAt?: Timestamp;
    lastSeenAt?: Timestamp;
    lastAuthorizedAt?: Timestamp;
    idleSince?: Timestamp | null;
    closedAt?: Timestamp;
    closeReason?: CloseReason;
    /** Update the key fingerprint after an in-place rekey*/
    sessionKeyFingerprint?: string | null;
    /** Set rekey_count to the new value after an in-place rekey completes*/
    rekeyCount?: number;
}

export interface SessionListActiveFilter {
    initiatorDid?: DID;
    responderDid?: DID;
    states?: SessionState[];
    limit?: number;
}

export interface SessionCleanResult {
    /** CREATED timeout -> CLOSED('HANDSHAKE_REJECTED')*/
    markedStale: number;
    /** ACTIVE exceeds soft timeout -> IDLE*/
    markedIdle: number;
    /** IDLE exceeds hard timeout -> CLOSED('IDLE_TIMEOUT')*/
    markedClosed: number;
}

export interface SessionResumeInput {
    sessionId: string;
    expectedInitiatorDid: DID;
    expectedResponderDid: DID;
    expectedCapabilityTokenId?: string;
    expectedCapabilityTokenFingerprint?: string;
    /** idle hard-expiry boundary (ms)*/
    idleHardMs: number;
    negotiatedCapabilities: string[];
    now?: Timestamp;
}

/**
 * Session storage layer interface.
 *
 * Every row-mutating UPDATE must also execute revision = revision + 1 (the basis of the CAS fence).
 * Implementations include InMemorySessionStore and PostgresSessionStore.
 */
export interface SessionStore {
    create(input: SessionCreateInput): Promise<Session>;
    get(sessionId: string): Promise<Session | null>;
    update(sessionId: string, patch: SessionUpdatePatch): Promise<Session>;
    resume(input: SessionResumeInput): Promise<Session>;

    /** Atomic primitive for the CLOSED-recovery path*/
    supersedeAndCreate(params: {
        oldSessionId: string;
        fallbackCloseReason: CloseReason;
        newCreateInput: SessionCreateInput;
        now?: Timestamp;
    }): Promise<Session>;

    /** Atomic binding-claim for the regular message path*/
    claimForDispatch(params: {
        sessionId: string;
        senderDid: DID;
        selfDid: DID;
        expectedCapabilityTokenId?: string;
        expectedCapabilityTokenFingerprint?: string;
        now?: Timestamp;
    }): Promise<Session>;

    /** CAS fencing after a successful L3 authorization*/
    markAuthorized(params: {
        sessionId: string;
        expectedRevision: string;
        now?: Timestamp;
    }): Promise<Session>;

    /** Cascade close on token revocation (exact tokenId)*/
    closeByToken(params: {
        tokenId: string;
        reason?: CloseReason;
        now?: Timestamp;
    }): Promise<string[]>;

    /** Cascade close by principal (covers transitional sessions with a NULL token)*/
    closeByPrincipal(params: {
        principalDid: DID;
        reason?: CloseReason;
        now?: Timestamp;
    }): Promise<string[]>;

    /** Clean up expired sessions (CREATED timeout + IDLE transition + idle hard-expiry close)*/
    cleanExpired(params: {
        createdTimeoutMs: number;
        idleSoftMs: number;
        idleHardMs: number;
        now?: Timestamp;
    }): Promise<SessionCleanResult>;

    /** List active sessions (for auditing and monitoring)*/
    listActive(filter?: SessionListActiveFilter): Promise<Session[]>;
}

export interface SessionManagerOptions {
    store: SessionStore;
    createdTimeoutMs?: number;
    idleSoftMs?: number;
    idleHardMs?: number;
    sweepIntervalMs?: number;
}
