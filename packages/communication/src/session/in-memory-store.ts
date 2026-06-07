import type { DID, Timestamp } from '@coivitas/types';
import { ProtocolError } from '@coivitas/types';
import type {
    Session,
    SessionStore,
    SessionCreateInput,
    SessionUpdatePatch,
    SessionResumeInput,
    SessionCleanResult,
    SessionListActiveFilter,
    CloseReason,
    EncryptionState,
} from './types.js';

const LIVE_STATES = new Set(['CREATED', 'ACTIVE', 'IDLE']);

/**
 * Safely increments the revision string.
 * Conclusion: parseInt must include a radix and a NaN guard, to prevent silently writing NaN+1=NaN when the revision field is corrupted.
 */
function bumpRevision(rev: string): string {
    const n = parseInt(rev, 10);
    if (isNaN(n))
        throw new ProtocolError(
            'SESSION_STATE_INVALID',
            `Invalid revision: ${rev}`,
        );
    return String(n + 1);
}

/**
 * Executes fn synchronously, capturing synchronous exceptions as a rejected Promise (satisfying the SessionStore interface's Promise contract).
 * Conclusion: the in-memory store has no I/O and all operations are synchronous; this helper converts synchronous throws into a rejected Promise,
 * avoiding the @typescript-eslint/require-await warning while keeping the interface contract correct.
 */
function wrap<T>(fn: () => T): Promise<T> {
    try {
        return Promise.resolve(fn());
    } catch (err) {
        return Promise.reject(err as Error);
    }
}

export class InMemorySessionStore implements SessionStore {
    readonly sessions = new Map<string, Session>();

    // ---------------------------------------------------------------------------
    // Public interface: all wrapped as Promises (synchronous Map operations satisfy the SessionStore interface contract)
    // ---------------------------------------------------------------------------

    create(input: SessionCreateInput): Promise<Session> {
        return wrap(() => this._create(input));
    }

    get(sessionId: string): Promise<Session | null> {
        const s = this.sessions.get(sessionId);
        return Promise.resolve(s ? { ...s } : null);
    }

    update(sessionId: string, patch: SessionUpdatePatch): Promise<Session> {
        return wrap(() => this._update(sessionId, patch));
    }

    resume(input: SessionResumeInput): Promise<Session> {
        return wrap(() => this._resume(input));
    }

    supersedeAndCreate(params: {
        oldSessionId: string;
        fallbackCloseReason: CloseReason;
        newCreateInput: SessionCreateInput;
        now?: Timestamp;
    }): Promise<Session> {
        return wrap(() => this._supersedeAndCreate(params));
    }

    claimForDispatch(params: {
        sessionId: string;
        senderDid: DID;
        selfDid: DID;
        expectedCapabilityTokenId?: string;
        expectedCapabilityTokenFingerprint?: string;
        now?: Timestamp;
    }): Promise<Session> {
        return wrap(() => this._claimForDispatch(params));
    }

    markAuthorized(params: {
        sessionId: string;
        expectedRevision: string;
        now?: Timestamp;
    }): Promise<Session> {
        return wrap(() => this._markAuthorized(params));
    }

    closeByToken(params: {
        tokenId: string;
        reason?: CloseReason;
        now?: Timestamp;
    }): Promise<string[]> {
        return wrap(() => this._closeByToken(params));
    }

    closeByPrincipal(params: {
        principalDid: DID;
        reason?: CloseReason;
        now?: Timestamp;
    }): Promise<string[]> {
        return wrap(() => this._closeByPrincipal(params));
    }

    listActive(filter?: SessionListActiveFilter): Promise<Session[]> {
        return Promise.resolve(this._listActive(filter));
    }

    cleanExpired(params: {
        createdTimeoutMs: number;
        idleSoftMs: number;
        idleHardMs: number;
        now?: Timestamp;
    }): Promise<SessionCleanResult> {
        return Promise.resolve(this._cleanExpired(params));
    }

    // ---------------------------------------------------------------------------
    // Private synchronous implementation
    // ---------------------------------------------------------------------------

    private _create(input: SessionCreateInput): Session {
        if (this.sessions.has(input.sessionId)) {
            throw new ProtocolError(
                'SESSION_STATE_INVALID',
                `Session ${input.sessionId} already exists`,
            );
        }
        const now = new Date().toISOString() as Timestamp;
        const isActive = input.initialState === 'ACTIVE';
        const parts = [input.initiatorDid, input.responderDid].sort();
        const didPairKey = `${parts[0]}\x00${parts[1]}`;

        // Encryption-state consistency check (aligned with chk_sessions_encryption_state_consistency)
        const encState: EncryptionState = input.encryptionState ?? 'OFF';
        if (encState === 'OFF' && input.sessionKeyFingerprint !== undefined) {
            throw new ProtocolError(
                'SESSION_STATE_INVALID',
                'sessionKeyFingerprint is not allowed to be passed when encryptionState=OFF',
            );
        }

        const session: Session = {
            sessionId: input.sessionId,
            initiatorDid: input.initiatorDid,
            responderDid: input.responderDid,
            principalDid: input.principalDid,
            capabilityTokenId: input.capabilityTokenId ?? null,
            capabilityTokenFingerprint:
                input.capabilityTokenFingerprint ?? null,
            state: isActive ? 'ACTIVE' : 'CREATED',
            negotiatedCapabilities: input.negotiatedCapabilities ?? [],
            encryptionState: encState,
            sessionKeyFingerprint:
                encState === 'REQUIRED'
                    ? (input.sessionKeyFingerprint ?? null)
                    : null,
            rekeyCount: 0,
            establishedAt: isActive ? now : null,
            lastSeenAt: now,
            lastAuthorizedAt: now,
            idleSince: null,
            closedAt: null,
            closeReason: null,
            supersedesSessionId: input.supersedesSessionId ?? null,
            didPairKey,
            createdAt: now,
            updatedAt: now,
            revision: '1',
        };
        this.sessions.set(session.sessionId, session);
        return { ...session };
    }

    private _update(sessionId: string, patch: SessionUpdatePatch): Session {
        const row = this.sessions.get(sessionId);
        if (!row) {
            throw new ProtocolError(
                'SESSION_NOT_FOUND',
                `Session ${sessionId} does not exist`,
            );
        }
        if (row.state === 'CLOSED') {
            throw new ProtocolError(
                'SESSION_CLOSED',
                `Session ${sessionId} is already closed`,
            );
        }
        const now = new Date().toISOString() as Timestamp;

        // Encryption fields handled separately (encryptionState itself is immutable; only fingerprint/rekeyCount are updated)
        const sessionKeyFingerprint = Object.prototype.hasOwnProperty.call(
            patch,
            'sessionKeyFingerprint',
        )
            ? (patch.sessionKeyFingerprint ?? null)
            : row.sessionKeyFingerprint;
        const rekeyCount =
            patch.rekeyCount !== undefined ? patch.rekeyCount : row.rekeyCount;

        const {
            sessionKeyFingerprint: _sfp,
            rekeyCount: _rc,
            ...restPatch
        } = patch;

        const updated: Session = {
            ...row,
            ...restPatch,
            sessionKeyFingerprint,
            rekeyCount,
            updatedAt: now,
            revision: bumpRevision(row.revision),
        };
        this.sessions.set(sessionId, updated);
        return { ...updated };
    }

    private _resume(input: SessionResumeInput): Session {
        const row = this.sessions.get(input.sessionId);
        if (!row) {
            throw new ProtocolError(
                'SESSION_NOT_FOUND',
                `Session ${input.sessionId} does not exist`,
            );
        }
        if (row.state === 'CLOSED') {
            throw new ProtocolError('SESSION_CLOSED', 'Session is already closed');
        }
        // Fix 3: resume is only allowed on IDLE sessions
        if (row.state !== 'IDLE') {
            throw new ProtocolError(
                'SESSION_STATE_INVALID',
                `resume is only allowed on IDLE sessions, current state: ${row.state}`,
            );
        }
        if (
            row.initiatorDid !== input.expectedInitiatorDid ||
            row.responderDid !== input.expectedResponderDid
        ) {
            throw new ProtocolError('SESSION_DID_MISMATCH', 'DID tuple mismatch');
        }
        // Fix 2: token binding check (same semantics as claimForDispatch)
        if (input.expectedCapabilityTokenId !== undefined) {
            if (
                row.capabilityTokenId !== input.expectedCapabilityTokenId ||
                row.capabilityTokenFingerprint !==
                    input.expectedCapabilityTokenFingerprint
            ) {
                throw new ProtocolError(
                    'SESSION_TOKEN_MISMATCH',
                    'Token binding mismatch',
                );
            }
        }
        // Fix 1: uniformly use input.now (avoids split-clock: inconsistency between the idle-expiry check and the write clock)
        const nowMs = input.now ? new Date(input.now).getTime() : Date.now();
        if (row.idleSince) {
            const elapsed = nowMs - new Date(row.idleSince).getTime();
            if (elapsed > input.idleHardMs) {
                const nowTs = new Date(nowMs).toISOString() as Timestamp;
                this.sessions.set(input.sessionId, {
                    ...row,
                    state: 'CLOSED',
                    closedAt: nowTs,
                    closeReason: 'IDLE_TIMEOUT',
                    idleSince: null,
                    updatedAt: nowTs,
                    revision: bumpRevision(row.revision),
                });
                throw new ProtocolError(
                    'SESSION_IDLE_EXPIRED',
                    'IDLE session has exceeded the hard timeout',
                );
            }
        }
        const now = new Date(nowMs).toISOString() as Timestamp;
        const updated: Session = {
            ...row,
            state: 'ACTIVE',
            negotiatedCapabilities: input.negotiatedCapabilities,
            lastSeenAt: now,
            lastAuthorizedAt: now,
            idleSince: null,
            establishedAt: row.establishedAt ?? now,
            updatedAt: now,
            revision: bumpRevision(row.revision),
        };
        this.sessions.set(input.sessionId, updated);
        return { ...updated };
    }

    private _supersedeAndCreate(params: {
        oldSessionId: string;
        fallbackCloseReason: CloseReason;
        newCreateInput: SessionCreateInput;
        now?: Timestamp;
    }): Session {
        const old = this.sessions.get(params.oldSessionId);
        if (!old) {
            throw new ProtocolError(
                'SESSION_NOT_FOUND',
                `Old session ${params.oldSessionId} does not exist`,
            );
        }
        if (old.state !== 'CLOSED') {
            const now = (params.now ?? new Date().toISOString()) as Timestamp;
            this.sessions.set(params.oldSessionId, {
                ...old,
                state: 'CLOSED',
                closedAt: now,
                closeReason: params.fallbackCloseReason,
                idleSince: null,
                updatedAt: now,
                revision: bumpRevision(old.revision),
            });
        }
        return this._create({
            ...params.newCreateInput,
            supersedesSessionId: params.oldSessionId,
        });
    }

    private _claimForDispatch(params: {
        sessionId: string;
        senderDid: DID;
        selfDid: DID;
        expectedCapabilityTokenId?: string;
        expectedCapabilityTokenFingerprint?: string;
        now?: Timestamp;
    }): Session {
        const row = this.sessions.get(params.sessionId);
        if (!row) {
            throw new ProtocolError(
                'SESSION_NOT_FOUND',
                `Session ${params.sessionId} does not exist`,
            );
        }
        if (row.state === 'CLOSED') {
            throw new ProtocolError('SESSION_CLOSED', 'Session is already closed');
        }
        if (row.state !== 'ACTIVE') {
            throw new ProtocolError(
                'SESSION_STATE_INVALID',
                'Session is not in ACTIVE state',
            );
        }
        const didMatch =
            (row.initiatorDid === params.senderDid &&
                row.responderDid === params.selfDid) ||
            (row.responderDid === params.senderDid &&
                row.initiatorDid === params.selfDid);
        if (!didMatch) {
            throw new ProtocolError('SESSION_DID_MISMATCH', 'DID tuple mismatch');
        }
        if (
            row.capabilityTokenId !==
                (params.expectedCapabilityTokenId ?? null) ||
            row.capabilityTokenFingerprint !==
                (params.expectedCapabilityTokenFingerprint ?? null)
        ) {
            throw new ProtocolError(
                'SESSION_TOKEN_MISMATCH',
                'Token binding mismatch',
            );
        }
        const now = (params.now ?? new Date().toISOString()) as Timestamp;
        const updated: Session = {
            ...row,
            lastSeenAt: now,
            updatedAt: now,
            revision: bumpRevision(row.revision),
        };
        this.sessions.set(params.sessionId, updated);
        return { ...updated };
    }

    private _markAuthorized(params: {
        sessionId: string;
        expectedRevision: string;
        now?: Timestamp;
    }): Session {
        const row = this.sessions.get(params.sessionId);
        if (!row) {
            throw new ProtocolError(
                'SESSION_NOT_FOUND',
                `Session ${params.sessionId} does not exist`,
            );
        }
        if (row.state === 'CLOSED') {
            throw new ProtocolError('SESSION_CLOSED', 'Session is already closed');
        }
        if (row.state !== 'ACTIVE') {
            throw new ProtocolError(
                'SESSION_STATE_INVALID',
                'Session is not in ACTIVE state',
            );
        }
        if (row.revision !== params.expectedRevision) {
            throw new ProtocolError(
                'SESSION_STATE_INVALID',
                `CAS failed: expected revision ${params.expectedRevision}, actual ${row.revision}`,
            );
        }
        const now = (params.now ?? new Date().toISOString()) as Timestamp;
        const updated: Session = {
            ...row,
            lastAuthorizedAt: now,
            updatedAt: now,
            revision: bumpRevision(row.revision),
        };
        this.sessions.set(params.sessionId, updated);
        return { ...updated };
    }

    private _closeByToken(params: {
        tokenId: string;
        reason?: CloseReason;
        now?: Timestamp;
    }): string[] {
        const now = (params.now ?? new Date().toISOString()) as Timestamp;
        const reason = params.reason ?? 'REVOKED_TOKEN';
        const closed: string[] = [];
        for (const [id, row] of this.sessions) {
            if (
                row.capabilityTokenId === params.tokenId &&
                LIVE_STATES.has(row.state)
            ) {
                this.sessions.set(id, {
                    ...row,
                    state: 'CLOSED',
                    closedAt: now,
                    closeReason: reason,
                    idleSince: null,
                    updatedAt: now,
                    revision: bumpRevision(row.revision),
                });
                closed.push(id);
            }
        }
        return closed;
    }

    private _closeByPrincipal(params: {
        principalDid: DID;
        reason?: CloseReason;
        now?: Timestamp;
    }): string[] {
        const now = (params.now ?? new Date().toISOString()) as Timestamp;
        const reason = params.reason ?? 'REVOKED_TOKEN';
        const closed: string[] = [];
        for (const [id, row] of this.sessions) {
            if (
                row.principalDid === params.principalDid &&
                LIVE_STATES.has(row.state)
            ) {
                this.sessions.set(id, {
                    ...row,
                    state: 'CLOSED',
                    closedAt: now,
                    closeReason: reason,
                    idleSince: null,
                    updatedAt: now,
                    revision: bumpRevision(row.revision),
                });
                closed.push(id);
            }
        }
        return closed;
    }

    private _listActive(filter?: SessionListActiveFilter): Session[] {
        const states = filter?.states ?? ['ACTIVE'];
        let results = Array.from(this.sessions.values()).filter((s) =>
            states.includes(s.state),
        );
        if (filter?.initiatorDid) {
            results = results.filter(
                (s) => s.initiatorDid === filter.initiatorDid,
            );
        }
        if (filter?.responderDid) {
            results = results.filter(
                (s) => s.responderDid === filter.responderDid,
            );
        }
        results.sort((a, b) => b.lastSeenAt.localeCompare(a.lastSeenAt));
        if (filter?.limit) {
            results = results.slice(0, filter.limit);
        }
        return results.map((s) => ({ ...s }));
    }

    private _cleanExpired(params: {
        createdTimeoutMs: number;
        idleSoftMs: number;
        idleHardMs: number;
        now?: Timestamp;
    }): SessionCleanResult {
        const now = params.now ? new Date(params.now).getTime() : Date.now();
        const nowTs = new Date(now).toISOString() as Timestamp;
        let markedStale = 0;
        let markedIdle = 0;
        let markedClosed = 0;

        // Pass 1: CREATED → CLOSED (stale handshake timeout)
        for (const [id, row] of this.sessions) {
            if (
                row.state === 'CREATED' &&
                now - new Date(row.createdAt).getTime() >
                    params.createdTimeoutMs
            ) {
                this.sessions.set(id, {
                    ...row,
                    state: 'CLOSED',
                    closedAt: nowTs,
                    closeReason: 'HANDSHAKE_REJECTED',
                    updatedAt: nowTs,
                    revision: bumpRevision(row.revision),
                });
                markedStale++;
            }
        }

        // Pass 2: ACTIVE → IDLE (soft timeout)
        for (const [id, row] of this.sessions) {
            if (
                row.state === 'ACTIVE' &&
                now - new Date(row.lastAuthorizedAt).getTime() >
                    params.idleSoftMs
            ) {
                this.sessions.set(id, {
                    ...row,
                    state: 'IDLE',
                    idleSince: nowTs,
                    updatedAt: nowTs,
                    revision: bumpRevision(row.revision),
                });
                markedIdle++;
            }
        }

        // Pass 3: IDLE → CLOSED (hard timeout)
        for (const [id, row] of this.sessions) {
            if (
                row.state === 'IDLE' &&
                row.idleSince &&
                now - new Date(row.idleSince).getTime() > params.idleHardMs
            ) {
                this.sessions.set(id, {
                    ...row,
                    state: 'CLOSED',
                    closedAt: nowTs,
                    closeReason: 'IDLE_TIMEOUT',
                    idleSince: null,
                    updatedAt: nowTs,
                    revision: bumpRevision(row.revision),
                });
                markedClosed++;
            }
        }

        return { markedStale, markedIdle, markedClosed };
    }
}
