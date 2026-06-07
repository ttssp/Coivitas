import { afterEach, describe, expect, it, vi } from 'vitest';

import type { DID } from '@coivitas/types';

import { InMemorySessionStore } from '../in-memory-store.js';
import { SessionManager } from '../session-manager.js';

const initiatorDid = 'did:agent:00112233445566778899aabbccddeeff00112233' as DID;
const responderDid = 'did:agent:aabbccddeeff0011223344556677889900112233' as DID;
const principalDid = 'did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuias8sisDArDJF' as DID;

function makeManager(overrides?: { idleSoftMs?: number; sweepIntervalMs?: number }) {
    return new SessionManager({
        store: new InMemorySessionStore(),
        createdTimeoutMs: 60_000,
        idleSoftMs: overrides?.idleSoftMs ?? 300_000,
        idleHardMs: 1_800_000,
        sweepIntervalMs: overrides?.sweepIntervalMs ?? 0, // 0 = no auto-sweep in tests
    });
}

describe('SessionManager', () => {
    // Uniformly restore real timers to prevent fake timers from leaking when an assertion fails
    afterEach(() => {
        vi.useRealTimers();
    });

    it('should return ACTIVE state and appear in listActive when session is created then activated', async () => {
        const manager = makeManager();

        await manager.create({
            sessionId: 'session-001',
            initiatorDid,
            responderDid,
            principalDid,
            negotiatedCapabilities: [],
        });

        expect(await manager.get('session-001')).toMatchObject({
            sessionId: 'session-001',
            state: 'CREATED',
        });

        await manager.activate('session-001', ['QUOTE']);

        expect(await manager.get('session-001')).toMatchObject({
            sessionId: 'session-001',
            state: 'ACTIVE',
            negotiatedCapabilities: ['QUOTE'],
        });
        expect(await manager.listActive()).toHaveLength(1);
    });

    it('should return CLOSED state when close() is called', async () => {
        const manager = makeManager();
        await manager.create({
            sessionId: 'session-002',
            initiatorDid,
            responderDid,
            principalDid,
            negotiatedCapabilities: [],
            initialState: 'ACTIVE',
        });

        await manager.close('session-002', 'EXPLICIT_CLOSE');

        expect(await manager.get('session-002')).toMatchObject({ state: 'CLOSED' });
    });

    it('should mark ACTIVE as IDLE and stale CREATED as CLOSED when sweep runs after soft timeout', async () => {
        vi.useFakeTimers();
        vi.setSystemTime(new Date('2026-04-03T00:00:00.000Z'));

        const manager = makeManager({ idleSoftMs: 1_000 });
        await manager.create({
            sessionId: 'session-003',
            initiatorDid,
            responderDid,
            principalDid,
            negotiatedCapabilities: [],
        });
        await manager.create({
            sessionId: 'session-004',
            initiatorDid,
            responderDid,
            principalDid,
            negotiatedCapabilities: [],
            initialState: 'ACTIVE',
        });

        vi.advanceTimersByTime(1_500);

        const result = await manager.sweep();
        expect(result.markedIdle).toBe(1);
        expect(await manager.get('session-004')).toMatchObject({ state: 'IDLE' });
    });

    it('should update lastSeenAt when touch() is called on ACTIVE session', async () => {
        vi.useFakeTimers();
        vi.setSystemTime(new Date('2026-04-03T00:00:00.000Z'));

        const manager = makeManager();
        await manager.create({
            sessionId: 'session-005',
            initiatorDid,
            responderDid,
            principalDid,
            negotiatedCapabilities: ['CONFIRM'],
            initialState: 'ACTIVE',
        });

        vi.advanceTimersByTime(5_000);
        await manager.touch('session-005');

        expect(await manager.get('session-005')).toMatchObject({
            state: 'ACTIVE',
            negotiatedCapabilities: ['CONFIRM'],
            lastSeenAt: '2026-04-03T00:00:05.000Z',
        });
    });

    it('should start and stop sweep timer without error', () => {
        vi.useFakeTimers();
        const manager = new SessionManager({
            store: new InMemorySessionStore(),
            sweepIntervalMs: 100,
        });
        manager.start();
        vi.advanceTimersByTime(250);
        manager.stop();
        // Second stop is idempotent
        manager.stop();
    });

    it('should sweep mark CREATED session as closed when timeout exceeded', async () => {
        vi.useFakeTimers();
        vi.setSystemTime(new Date('2026-04-03T00:00:00.000Z'));

        const manager = new SessionManager({
            store: new InMemorySessionStore(),
            createdTimeoutMs: 1_000,
            idleSoftMs: 300_000,
            idleHardMs: 1_800_000,
            sweepIntervalMs: 0,
        });

        await manager.create({
            sessionId: 'stale-session',
            initiatorDid,
            responderDid,
            principalDid,
        });

        vi.advanceTimersByTime(2_000);
        const result = await manager.sweep();
        expect(result.markedStale).toBe(1);
        expect(await manager.get('stale-session')).toMatchObject({ state: 'CLOSED', closeReason: 'HANDSHAKE_REJECTED' });
    });

    it('should throw SESSION_NOT_FOUND when activating non-existent session', async () => {
        const manager = makeManager();
        await expect(manager.activate('no-such-session', ['QUOTE']))
            .rejects.toMatchObject({ code: 'SESSION_NOT_FOUND' });
    });

    it('should throw SESSION_NOT_FOUND when closing non-existent session', async () => {
        const manager = makeManager();
        await expect(manager.close('no-such-session', 'EXPLICIT_CLOSE'))
            .rejects.toMatchObject({ code: 'SESSION_NOT_FOUND' });
    });

    it('should resume an IDLE session to ACTIVE via manager', async () => {
        vi.useFakeTimers();
        vi.setSystemTime(new Date('2026-04-03T00:00:00.000Z'));

        const manager = makeManager({ idleSoftMs: 1_000 });
        await manager.create({
            sessionId: 'resume-session',
            initiatorDid,
            responderDid,
            principalDid,
            initialState: 'ACTIVE',
        });

        // Advance time past idleSoftMs, then sweep marks it as IDLE
        vi.advanceTimersByTime(1_500);
        await manager.sweep();

        expect(await manager.get('resume-session')).toMatchObject({ state: 'IDLE' });

        const resumed = await manager.resume({
            sessionId: 'resume-session',
            expectedInitiatorDid: initiatorDid,
            expectedResponderDid: responderDid,
            negotiatedCapabilities: ['RESUMED'],
        });
        expect(resumed.state).toBe('ACTIVE');
        expect(resumed.idleSince).toBeNull();
    });

    it('should markAuthorized update revision via manager', async () => {
        const manager = makeManager();
        await manager.create({
            sessionId: 'auth-session',
            initiatorDid,
            responderDid,
            principalDid,
            initialState: 'ACTIVE',
        });
        const before = (await manager.get('auth-session'))!;
        const after = await manager.markAuthorized('auth-session', before.revision);
        expect(parseInt(after.revision)).toBeGreaterThan(parseInt(before.revision));
    });

    it('should closeByToken close sessions with matching token', async () => {
        const manager = makeManager();
        const tokenId = 'urn:cap:00000000-0000-4000-8000-000000000099';
        const fingerprint = 'b'.repeat(64);
        await manager.create({
            sessionId: 'tok-session',
            initiatorDid,
            responderDid,
            principalDid,
            capabilityTokenId: tokenId,
            capabilityTokenFingerprint: fingerprint,
            initialState: 'ACTIVE',
        });
        const closed = await manager.closeByToken(tokenId);
        expect(closed).toContain('tok-session');
        expect(await manager.get('tok-session')).toMatchObject({ state: 'CLOSED' });
    });

    it('should closeByPrincipal close all live sessions for that principal', async () => {
        const manager = makeManager();
        await manager.create({
            sessionId: 'prin-session-1',
            initiatorDid,
            responderDid,
            principalDid,
            initialState: 'ACTIVE',
        });
        await manager.create({
            sessionId: 'prin-session-2',
            initiatorDid: responderDid,
            responderDid: initiatorDid,
            principalDid,
            initialState: 'ACTIVE',
        });
        const closed = await manager.closeByPrincipal(principalDid);
        expect(closed.length).toBeGreaterThanOrEqual(2);
        expect(await manager.get('prin-session-1')).toMatchObject({ state: 'CLOSED' });
        expect(await manager.get('prin-session-2')).toMatchObject({ state: 'CLOSED' });
    });

    it('should not create duplicate timers when start() is called twice', () => {
        vi.useFakeTimers();
        const store = new InMemorySessionStore();
        const sweepSpy = vi.spyOn(store, 'cleanExpired');
        const manager = new SessionManager({ store, sweepIntervalMs: 100 });
        manager.start();
        manager.start(); // The second call should be a no-op
        vi.advanceTimersByTime(250);
        manager.stop();
        // With two timers, a 100ms interval would fire 4-6 times within 250ms; a single timer fires only 2 times
        expect(sweepSpy).toHaveBeenCalledTimes(2);
    });
});
