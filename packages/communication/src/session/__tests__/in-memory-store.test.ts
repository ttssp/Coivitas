import { describe, it, expect, beforeEach } from 'vitest';
import type { DID, Timestamp } from '@coivitas/types';
import { InMemorySessionStore } from '../in-memory-store.js';
import type { SessionCreateInput } from '../types.js';

const A = 'did:agent:aaaa0000000000000000000000000000000000000000' as DID;
const B = 'did:agent:bbbb0000000000000000000000000000000000000000' as DID;
const P = 'did:key:pppp' as DID;

function makeInput(
    override?: Partial<SessionCreateInput> & { sessionId?: string },
): SessionCreateInput {
    return {
        sessionId: override?.sessionId ?? 'sess-001',
        initiatorDid: A,
        responderDid: B,
        principalDid: P,
        ...override,
    };
}

describe('InMemorySessionStore', () => {
    let store: InMemorySessionStore;
    beforeEach(() => {
        store = new InMemorySessionStore();
    });

    it('should create a CREATED session when given minimal input', async () => {
        const s = await store.create(makeInput());
        expect(s.state).toBe('CREATED');
        expect(s.revision).toBe('1');
        expect(s.didPairKey).toBeTruthy();
        expect(s.establishedAt).toBeNull();
    });

    it('should create ACTIVE session when initialState=ACTIVE', async () => {
        const s = await store.create(makeInput({ initialState: 'ACTIVE' }));
        expect(s.state).toBe('ACTIVE');
        expect(s.establishedAt).not.toBeNull();
    });

    it('should return null when getting non-existent session', async () => {
        const s = await store.get('nope');
        expect(s).toBeNull();
    });

    it('should increment revision on each update', async () => {
        await store.create(makeInput());
        const s = await store.update('sess-001', {
            negotiatedCapabilities: ['X'],
        });
        expect(s.revision).toBe('2');
        expect(s.negotiatedCapabilities).toEqual(['X']);
    });

    it('should throw SESSION_CLOSED when updating a closed session', async () => {
        await store.create(makeInput({ initialState: 'ACTIVE' }));
        await store.update('sess-001', {
            state: 'CLOSED',
            closedAt: new Date().toISOString() as Timestamp,
            closeReason: 'EXPLICIT_CLOSE',
        });
        await expect(store.update('sess-001', {})).rejects.toMatchObject({
            code: 'SESSION_CLOSED',
        });
    });

    it('should throw SESSION_NOT_FOUND when updating non-existent session', async () => {
        await expect(store.update('nope', {})).rejects.toMatchObject({
            code: 'SESSION_NOT_FOUND',
        });
    });

    it('should resume IDLE session back to ACTIVE atomically', async () => {
        await store.create(makeInput({ initialState: 'ACTIVE' }));
        await store.update('sess-001', {
            state: 'IDLE',
            idleSince: new Date().toISOString() as Timestamp,
        });
        const resumed = await store.resume({
            sessionId: 'sess-001',
            expectedInitiatorDid: A,
            expectedResponderDid: B,
            idleHardMs: 1_800_000,
            negotiatedCapabilities: ['Y'],
        });
        expect(resumed.state).toBe('ACTIVE');
        expect(resumed.idleSince).toBeNull();
        expect(resumed.negotiatedCapabilities).toEqual(['Y']);
    });

    it('should throw SESSION_IDLE_EXPIRED when idle past hard timeout', async () => {
        await store.create(makeInput({ initialState: 'ACTIVE' }));
        const oldTime = new Date(
            Date.now() - 2_000_000,
        ).toISOString() as Timestamp;
        await store.update('sess-001', {
            state: 'IDLE',
            idleSince: oldTime,
        });
        await expect(
            store.resume({
                sessionId: 'sess-001',
                expectedInitiatorDid: A,
                expectedResponderDid: B,
                idleHardMs: 1_800_000,
                negotiatedCapabilities: [],
            }),
        ).rejects.toMatchObject({ code: 'SESSION_IDLE_EXPIRED' });
    });

    it('should cleanExpired: CREATED→CLOSED, ACTIVE→IDLE, IDLE→CLOSED', async () => {
        const now = Date.now();
        // stale CREATED
        await store.create(makeInput({ sessionId: 's1' }));
        store.sessions.get('s1')!.createdAt = new Date(
            now - 70_000,
        ).toISOString() as Timestamp;
        // active to-idle
        await store.create(
            makeInput({ sessionId: 's2', initialState: 'ACTIVE' }),
        );
        store.sessions.get('s2')!.lastAuthorizedAt = new Date(
            now - 310_000,
        ).toISOString() as Timestamp;
        // idle to-close
        await store.create(
            makeInput({ sessionId: 's3', initialState: 'ACTIVE' }),
        );
        await store.update('s3', {
            state: 'IDLE',
            idleSince: new Date(now - 1_900_000).toISOString() as Timestamp,
        });

        const result = await store.cleanExpired({
            createdTimeoutMs: 60_000,
            idleSoftMs: 300_000,
            idleHardMs: 1_800_000,
        });
        expect(result.markedStale).toBe(1);
        expect(result.markedIdle).toBe(1);
        expect(result.markedClosed).toBe(1);
        expect((await store.get('s1'))?.state).toBe('CLOSED');
        expect((await store.get('s1'))?.closeReason).toBe('HANDSHAKE_REJECTED');
        expect((await store.get('s2'))?.state).toBe('IDLE');
        expect((await store.get('s3'))?.state).toBe('CLOSED');
        expect((await store.get('s3'))?.closeReason).toBe('IDLE_TIMEOUT');
    });

    it('should closeByToken close all live sessions with that token', async () => {
        const tokenId = 'urn:cap:00000000-0000-4000-8000-000000000001';
        const fp = 'a'.repeat(64);
        await store.create(
            makeInput({
                sessionId: 's1',
                capabilityTokenId: tokenId,
                capabilityTokenFingerprint: fp,
                initialState: 'ACTIVE',
            }),
        );
        await store.create(
            makeInput({
                sessionId: 's2',
                capabilityTokenId: tokenId,
                capabilityTokenFingerprint: fp,
                initialState: 'ACTIVE',
            }),
        );
        const closed = await store.closeByToken({ tokenId });
        expect(closed).toHaveLength(2);
        expect(closed).toContain('s1');
        expect(closed).toContain('s2');
        expect((await store.get('s1'))?.state).toBe('CLOSED');
    });

    it('should closeByPrincipal close all live sessions for that principal', async () => {
        await store.create(
            makeInput({ sessionId: 's1', initialState: 'ACTIVE' }),
        );
        await store.create(
            makeInput({ sessionId: 's2', initialState: 'ACTIVE' }),
        );
        const closed = await store.closeByPrincipal({ principalDid: P });
        expect(closed).toHaveLength(2);
        expect((await store.get('s1'))?.state).toBe('CLOSED');
    });

    it('should claimForDispatch update lastSeenAt and increment revision', async () => {
        await store.create(makeInput({ initialState: 'ACTIVE' }));
        const before = (await store.get('sess-001'))!.revision;
        const claimed = await store.claimForDispatch({
            sessionId: 'sess-001',
            senderDid: A,
            selfDid: B,
        });
        expect(parseInt(claimed.revision)).toBeGreaterThan(parseInt(before));
    });

    it('should markAuthorized pass CAS with correct revision', async () => {
        await store.create(makeInput({ initialState: 'ACTIVE' }));
        const claimed = await store.claimForDispatch({
            sessionId: 'sess-001',
            senderDid: A,
            selfDid: B,
        });
        const authorized = await store.markAuthorized({
            sessionId: 'sess-001',
            expectedRevision: claimed.revision,
        });
        expect(parseInt(authorized.revision)).toBeGreaterThan(
            parseInt(claimed.revision),
        );
    });

    it('should markAuthorized fail CAS with wrong revision', async () => {
        await store.create(makeInput({ initialState: 'ACTIVE' }));
        await expect(
            store.markAuthorized({
                sessionId: 'sess-001',
                expectedRevision: '999',
            }),
        ).rejects.toMatchObject({ code: 'SESSION_STATE_INVALID' });
    });

    it('should supersedeAndCreate close old and create new session', async () => {
        await store.create(
            makeInput({ sessionId: 'old', initialState: 'ACTIVE' }),
        );
        const newSess = await store.supersedeAndCreate({
            oldSessionId: 'old',
            fallbackCloseReason: 'EXPLICIT_CLOSE',
            newCreateInput: makeInput({ sessionId: 'new' }),
        });
        expect(newSess.supersedesSessionId).toBe('old');
        expect(newSess.state).toBe('CREATED');
        expect((await store.get('old'))?.state).toBe('CLOSED');
    });

    it('should listActive return only sessions in specified states', async () => {
        await store.create(
            makeInput({ sessionId: 's1', initialState: 'ACTIVE' }),
        );
        await store.create(
            makeInput({ sessionId: 's2', initialState: 'ACTIVE' }),
        );
        await store.update('s2', {
            state: 'IDLE',
            idleSince: new Date().toISOString() as Timestamp,
        });
        const active = await store.listActive({ states: ['ACTIVE'] });
        expect(active).toHaveLength(1);
        expect(active[0].sessionId).toBe('s1');
        const idle = await store.listActive({ states: ['IDLE'] });
        expect(idle).toHaveLength(1);
    });

    it('should listActive filter by responderDid', async () => {
        await store.create(
            makeInput({ sessionId: 's1', initialState: 'ACTIVE' }),
        );
        await store.create(
            makeInput({
                sessionId: 's2',
                initialState: 'ACTIVE',
                responderDid:
                    'did:agent:cccc0000000000000000000000000000000000000000' as DID,
            }),
        );
        const results = await store.listActive({
            states: ['ACTIVE'],
            responderDid: B,
        });
        expect(results).toHaveLength(1);
        expect(results[0].sessionId).toBe('s1');
    });

    it('should listActive respect limit', async () => {
        await store.create(
            makeInput({ sessionId: 's1', initialState: 'ACTIVE' }),
        );
        await store.create(
            makeInput({ sessionId: 's2', initialState: 'ACTIVE' }),
        );
        await store.create(
            makeInput({ sessionId: 's3', initialState: 'ACTIVE' }),
        );
        const results = await store.listActive({
            states: ['ACTIVE'],
            limit: 2,
        });
        expect(results).toHaveLength(2);
    });

    it('should listActive use default ACTIVE state when no filter provided', async () => {
        await store.create(
            makeInput({ sessionId: 's1', initialState: 'ACTIVE' }),
        );
        await store.create(makeInput({ sessionId: 's2' }));
        const results = await store.listActive();
        expect(results).toHaveLength(1);
        expect(results[0].sessionId).toBe('s1');
    });

    it('should throw SESSION_DID_MISMATCH when resume has wrong DIDs', async () => {
        await store.create(makeInput({ initialState: 'ACTIVE' }));
        await store.update('sess-001', {
            state: 'IDLE',
            idleSince: new Date().toISOString() as Timestamp,
        });
        await expect(
            store.resume({
                sessionId: 'sess-001',
                expectedInitiatorDid:
                    'did:agent:wrong0000000000000000000000000000000000000' as DID,
                expectedResponderDid: B,
                idleHardMs: 1_800_000,
                negotiatedCapabilities: [],
            }),
        ).rejects.toMatchObject({ code: 'SESSION_DID_MISMATCH' });
    });

    it('should throw SESSION_TOKEN_MISMATCH when claimForDispatch token does not match', async () => {
        const tokenId = 'urn:cap:00000000-0000-4000-8000-000000000001';
        const fp = 'a'.repeat(64);
        await store.create(
            makeInput({
                initialState: 'ACTIVE',
                capabilityTokenId: tokenId,
                capabilityTokenFingerprint: fp,
            }),
        );
        await expect(
            store.claimForDispatch({
                sessionId: 'sess-001',
                senderDid: A,
                selfDid: B,
                expectedCapabilityTokenId: 'urn:cap:different',
                expectedCapabilityTokenFingerprint: fp,
            }),
        ).rejects.toMatchObject({ code: 'SESSION_TOKEN_MISMATCH' });
    });

    it('should supersedeAndCreate skip closing when old session already CLOSED', async () => {
        await store.create(
            makeInput({ sessionId: 'old', initialState: 'ACTIVE' }),
        );
        await store.update('old', {
            state: 'CLOSED',
            closedAt: new Date().toISOString() as Timestamp,
            closeReason: 'EXPLICIT_CLOSE',
        });
        const oldRevisionBefore = (await store.get('old'))!.revision;
        const newSess = await store.supersedeAndCreate({
            oldSessionId: 'old',
            fallbackCloseReason: 'EXPLICIT_CLOSE',
            newCreateInput: makeInput({ sessionId: 'new' }),
        });
        expect(newSess.supersedesSessionId).toBe('old');
        // Old session revision should NOT increment since it was already CLOSED
        expect((await store.get('old'))!.revision).toBe(oldRevisionBefore);
    });

    it('should throw SESSION_NOT_FOUND when supersedeAndCreate with missing old session', async () => {
        await expect(
            store.supersedeAndCreate({
                oldSessionId: 'nonexistent',
                fallbackCloseReason: 'EXPLICIT_CLOSE',
                newCreateInput: makeInput({ sessionId: 'new' }),
            }),
        ).rejects.toMatchObject({ code: 'SESSION_NOT_FOUND' });
    });

    it('should throw SESSION_NOT_FOUND when claimForDispatch with missing session', async () => {
        await expect(
            store.claimForDispatch({
                sessionId: 'nope',
                senderDid: A,
                selfDid: B,
            }),
        ).rejects.toMatchObject({ code: 'SESSION_NOT_FOUND' });
    });

    it('should throw SESSION_CLOSED when claimForDispatch on closed session', async () => {
        await store.create(makeInput({ initialState: 'ACTIVE' }));
        await store.update('sess-001', {
            state: 'CLOSED',
            closedAt: new Date().toISOString() as Timestamp,
            closeReason: 'EXPLICIT_CLOSE',
        });
        await expect(
            store.claimForDispatch({
                sessionId: 'sess-001',
                senderDid: A,
                selfDid: B,
            }),
        ).rejects.toMatchObject({ code: 'SESSION_CLOSED' });
    });

    it('should throw SESSION_NOT_FOUND when markAuthorized with missing session', async () => {
        await expect(
            store.markAuthorized({ sessionId: 'nope', expectedRevision: '1' }),
        ).rejects.toMatchObject({ code: 'SESSION_NOT_FOUND' });
    });

    it('should throw SESSION_CLOSED when markAuthorized on closed session', async () => {
        await store.create(makeInput({ initialState: 'ACTIVE' }));
        await store.update('sess-001', {
            state: 'CLOSED',
            closedAt: new Date().toISOString() as Timestamp,
            closeReason: 'EXPLICIT_CLOSE',
        });
        await expect(
            store.markAuthorized({
                sessionId: 'sess-001',
                expectedRevision: '2',
            }),
        ).rejects.toMatchObject({ code: 'SESSION_CLOSED' });
    });

    it('should throw SESSION_NOT_FOUND when resume with missing session', async () => {
        await expect(
            store.resume({
                sessionId: 'nope',
                expectedInitiatorDid: A,
                expectedResponderDid: B,
                idleHardMs: 1_800_000,
                negotiatedCapabilities: [],
            }),
        ).rejects.toMatchObject({ code: 'SESSION_NOT_FOUND' });
    });

    it('should throw SESSION_CLOSED when resume on closed session', async () => {
        await store.create(makeInput({ initialState: 'ACTIVE' }));
        await store.update('sess-001', {
            state: 'CLOSED',
            closedAt: new Date().toISOString() as Timestamp,
            closeReason: 'EXPLICIT_CLOSE',
        });
        await expect(
            store.resume({
                sessionId: 'sess-001',
                expectedInitiatorDid: A,
                expectedResponderDid: B,
                idleHardMs: 1_800_000,
                negotiatedCapabilities: [],
            }),
        ).rejects.toMatchObject({ code: 'SESSION_CLOSED' });
    });

    it('should throw SESSION_DID_MISMATCH when claimForDispatch DID tuple mismatch', async () => {
        await store.create(makeInput({ initialState: 'ACTIVE' }));
        await expect(
            store.claimForDispatch({
                sessionId: 'sess-001',
                senderDid:
                    'did:agent:wrong0000000000000000000000000000000000000' as DID,
                selfDid:
                    'did:agent:wrong1000000000000000000000000000000000000' as DID,
            }),
        ).rejects.toMatchObject({ code: 'SESSION_DID_MISMATCH' });
    });

    it('should throw SESSION_STATE_INVALID when markAuthorized on non-ACTIVE session', async () => {
        await store.create(makeInput());
        // Session is in CREATED state
        await expect(
            store.markAuthorized({
                sessionId: 'sess-001',
                expectedRevision: '1',
            }),
        ).rejects.toMatchObject({ code: 'SESSION_STATE_INVALID' });
    });

    it('should throw SESSION_STATE_INVALID when claimForDispatch on CREATED session', async () => {
        await store.create(makeInput());
        await expect(
            store.claimForDispatch({
                sessionId: 'sess-001',
                senderDid: A,
                selfDid: B,
            }),
        ).rejects.toMatchObject({ code: 'SESSION_STATE_INVALID' });
    });

    it('should throw SESSION_STATE_INVALID when create duplicate sessionId', async () => {
        await store.create(makeInput());
        await expect(store.create(makeInput())).rejects.toMatchObject({
            code: 'SESSION_STATE_INVALID',
        });
    });

    // ─── encryptionState / sessionKeyFingerprint / rekeyCount ─────────
    describe('encryption fields', () => {
        const FP = 'a'.repeat(64); // 64-char hex fingerprint

        it('should default encryptionState to OFF when not specified', async () => {
            const s = await store.create(makeInput());
            expect(s.encryptionState).toBe('OFF');
            expect(s.sessionKeyFingerprint).toBeNull();
            expect(s.rekeyCount).toBe(0);
        });

        it('should store encryptionState=REQUIRED with fingerprint when specified', async () => {
            const s = await store.create(
                makeInput({
                    encryptionState: 'REQUIRED',
                    sessionKeyFingerprint: FP,
                }),
            );
            expect(s.encryptionState).toBe('REQUIRED');
            expect(s.sessionKeyFingerprint).toBe(FP);
            expect(s.rekeyCount).toBe(0);
        });

        it('should store encryptionState=REQUIRED with null fingerprint when fingerprint omitted', async () => {
            const s = await store.create(
                makeInput({ encryptionState: 'REQUIRED' }),
            );
            expect(s.encryptionState).toBe('REQUIRED');
            expect(s.sessionKeyFingerprint).toBeNull();
            expect(s.rekeyCount).toBe(0);
        });

        it('should throw SESSION_STATE_INVALID when fingerprint passed with encryptionState=OFF', async () => {
            await expect(
                store.create(
                    makeInput({
                        encryptionState: 'OFF',
                        sessionKeyFingerprint: FP,
                    }),
                ),
            ).rejects.toMatchObject({ code: 'SESSION_STATE_INVALID' });
        });

        it('should throw SESSION_STATE_INVALID when fingerprint passed without encryptionState (defaults to OFF)', async () => {
            await expect(
                store.create(makeInput({ sessionKeyFingerprint: FP })),
            ).rejects.toMatchObject({ code: 'SESSION_STATE_INVALID' });
        });

        it('should update sessionKeyFingerprint on in-place rekey', async () => {
            const s = await store.create(
                makeInput({
                    encryptionState: 'REQUIRED',
                    sessionKeyFingerprint: FP,
                    initialState: 'ACTIVE',
                }),
            );
            expect(s.sessionKeyFingerprint).toBe(FP);

            const newFP = 'b'.repeat(64);
            const updated = await store.update('sess-001', {
                sessionKeyFingerprint: newFP,
                rekeyCount: 1,
            });
            expect(updated.sessionKeyFingerprint).toBe(newFP);
            expect(updated.rekeyCount).toBe(1);
        });

        it('should set sessionKeyFingerprint to null when explicitly passed null', async () => {
            await store.create(
                makeInput({
                    encryptionState: 'REQUIRED',
                    sessionKeyFingerprint: FP,
                    initialState: 'ACTIVE',
                }),
            );
            const updated = await store.update('sess-001', {
                sessionKeyFingerprint: null,
            });
            expect(updated.sessionKeyFingerprint).toBeNull();
        });

        it('should not overwrite sessionKeyFingerprint when patch does not include the field', async () => {
            await store.create(
                makeInput({
                    encryptionState: 'REQUIRED',
                    sessionKeyFingerprint: FP,
                    initialState: 'ACTIVE',
                }),
            );
            // update only lastSeenAt — fingerprint must remain
            const updated = await store.update('sess-001', {
                lastSeenAt:
                    new Date().toISOString() as import('@coivitas/types').Timestamp,
            });
            expect(updated.sessionKeyFingerprint).toBe(FP);
        });

        it('should not overwrite rekeyCount when patch does not include the field', async () => {
            await store.create(
                makeInput({
                    encryptionState: 'REQUIRED',
                    initialState: 'ACTIVE',
                }),
            );
            await store.update('sess-001', { rekeyCount: 3 });
            // second update without rekeyCount — must retain 3
            const updated = await store.update('sess-001', {
                lastSeenAt:
                    new Date().toISOString() as import('@coivitas/types').Timestamp,
            });
            expect(updated.rekeyCount).toBe(3);
        });

        it('should propagate encryptionState through supersedeAndCreate', async () => {
            await store.create(
                makeInput({ sessionId: 'old', initialState: 'ACTIVE' }),
            );
            const newSess = await store.supersedeAndCreate({
                oldSessionId: 'old',
                fallbackCloseReason: 'EXPLICIT_CLOSE',
                newCreateInput: makeInput({
                    sessionId: 'new',
                    encryptionState: 'REQUIRED',
                    sessionKeyFingerprint: FP,
                }),
            });
            expect(newSess.encryptionState).toBe('REQUIRED');
            expect(newSess.sessionKeyFingerprint).toBe(FP);
            expect(newSess.rekeyCount).toBe(0);
        });

        it('should throw SESSION_STATE_INVALID when supersedeAndCreate has fingerprint with OFF state', async () => {
            await store.create(
                makeInput({ sessionId: 'old', initialState: 'ACTIVE' }),
            );
            await expect(
                store.supersedeAndCreate({
                    oldSessionId: 'old',
                    fallbackCloseReason: 'EXPLICIT_CLOSE',
                    newCreateInput: makeInput({
                        sessionId: 'new',
                        encryptionState: 'OFF',
                        sessionKeyFingerprint: FP,
                    }),
                }),
            ).rejects.toMatchObject({ code: 'SESSION_STATE_INVALID' });
        });
    });
});
