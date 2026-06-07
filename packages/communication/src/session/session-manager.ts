import type { DID, Timestamp } from '@coivitas/types';
import { ProtocolError } from '@coivitas/types';

import type {
    CloseReason,
    Session,
    SessionCleanResult,
    SessionCreateInput,
    SessionListActiveFilter,
    SessionManagerOptions,
    SessionResumeInput,
    SessionStore,
} from './types.js';

export class SessionManager {
    private readonly store: SessionStore;
    private readonly createdTimeoutMs: number;
    private readonly idleSoftMs: number;
    private readonly idleHardMs: number;
    private readonly sweepIntervalMs: number;
    private sweepTimer: ReturnType<typeof setInterval> | null = null;

    constructor(options: SessionManagerOptions) {
        this.store = options.store;
        this.createdTimeoutMs = options.createdTimeoutMs ?? 60_000;
        this.idleSoftMs = options.idleSoftMs ?? 300_000;
        this.idleHardMs = options.idleHardMs ?? 1_800_000;
        this.sweepIntervalMs = options.sweepIntervalMs ?? 60_000;
    }

    async create(input: SessionCreateInput): Promise<Session> {
        return this.store.create(input);
    }

    async get(sessionId: string): Promise<Session | null> {
        return this.store.get(sessionId);
    }

    async activate(sessionId: string, negotiatedCapabilities: string[]): Promise<Session> {
        const session = await this.store.get(sessionId);
        if (!session) {
            throw new ProtocolError('SESSION_NOT_FOUND', `session ${sessionId} does not exist`);
        }
        const now = new Date().toISOString() as Timestamp;
        return this.store.update(sessionId, {
            state: 'ACTIVE',
            negotiatedCapabilities,
            establishedAt: now,
        });
    }

    async resume(input: Omit<SessionResumeInput, 'idleHardMs'>): Promise<Session> {
        return this.store.resume({ ...input, idleHardMs: this.idleHardMs });
    }

    async touch(sessionId: string): Promise<void> {
        const session = await this.store.get(sessionId);
        if (!session || session.state !== 'ACTIVE') return;
        await this.store.update(sessionId, {
            lastSeenAt: new Date().toISOString() as Timestamp,
        });
    }

    async close(sessionId: string, reason: CloseReason): Promise<void> {
        const session = await this.store.get(sessionId);
        if (!session) {
            throw new ProtocolError('SESSION_NOT_FOUND', `session ${sessionId} does not exist`);
        }
        // Idempotent: return immediately if already closed, no need to write again
        if (session.state === 'CLOSED') return;
        const now = new Date().toISOString() as Timestamp;
        await this.store.update(sessionId, {
            state: 'CLOSED',
            closedAt: now,
            closeReason: reason,
        });
    }

    async markAuthorized(sessionId: string, expectedRevision: string): Promise<Session> {
        return this.store.markAuthorized({ sessionId, expectedRevision });
    }

    async closeByToken(tokenId: string, reason?: CloseReason): Promise<string[]> {
        return this.store.closeByToken({ tokenId, reason });
    }

    async closeByPrincipal(principalDid: DID, reason?: CloseReason): Promise<string[]> {
        return this.store.closeByPrincipal({ principalDid, reason });
    }

    async listActive(filter?: SessionListActiveFilter): Promise<Session[]> {
        return this.store.listActive(filter);
    }

    async sweep(): Promise<SessionCleanResult> {
        return this.store.cleanExpired({
            createdTimeoutMs: this.createdTimeoutMs,
            idleSoftMs: this.idleSoftMs,
            idleHardMs: this.idleHardMs,
        });
    }

    start(): void {
        if (this.sweepIntervalMs === 0 || this.sweepTimer) return;
        this.sweepTimer = setInterval(() => {
            void this.sweep();
        }, this.sweepIntervalMs);
    }

    stop(): void {
        if (this.sweepTimer) {
            clearInterval(this.sweepTimer);
            this.sweepTimer = null;
        }
    }
}
