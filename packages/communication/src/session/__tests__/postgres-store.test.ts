import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import { Pool } from 'pg';
import { PostgresSessionStore } from '../postgres-store.js';
import type { SessionCreateInput } from '../types.js';
import type { DID, Timestamp } from '@coivitas/types';

const skip = !process.env['DATABASE_URL'];

// Use fixed DID-format strings to ensure all CHECK constraints are satisfied
const A = 'did:agent:aaaa0000000000000000000000000000000000000000' as DID;
const B = 'did:agent:bbbb0000000000000000000000000000000000000000' as DID;
const P = 'did:key:pppp0000000000000000000000000000000000000000' as DID;

// Multi-session cases under the same principal (cleanExpired / closeByPrincipal) need multiple
// non-conflicting DID pairs — uniq_sessions_live_per_pair enforces "a given (initiator,responder)
// pair can have only 1 session in the live period ({CREATED,ACTIVE,IDLE})" (sql/001-create-sessions.sql:74-76),
// so the unit tests cannot reuse the global A/B. The Ax/Bx below cover the three sessions of cleanExpired;
// closeByPrincipal uses only the first two.

function makeInput(override?: Partial<SessionCreateInput> & { sessionId?: string }): SessionCreateInput {
    return {
        sessionId: override?.sessionId ?? crypto.randomUUID(),
        initiatorDid: A,
        responderDid: B,
        principalDid: P,
        ...override,
    };
}

describe.skipIf(skip)('PostgresSessionStore', () => {
    let pool: Pool;
    let store: PostgresSessionStore;

    beforeAll(() => {
        pool = new Pool({ connectionString: process.env['DATABASE_URL'] });
        store = new PostgresSessionStore(pool);
    });

    afterAll(async () => {
        // Clean up all rows created by this suite (by principal_did, more stable than initiator_did,
        // because the multi-DID-pair cases only share the principal).
        await pool.query('DELETE FROM communication.sessions WHERE principal_did = $1', [P]);
        await pool.end();
    });

    beforeEach(async () => {
        await pool.query('DELETE FROM communication.sessions WHERE principal_did = $1', [P]);
    });

    it('should create CREATED session and return revision=1 when initialState not set', async () => {
        const s = await store.create(makeInput({ sessionId: 'a0000000-0000-4000-8000-000000000001' }));
        expect(s.state).toBe('CREATED');
        expect(s.revision).toBe('1');
        expect(s.establishedAt).toBeNull();
    });

    it('should create ACTIVE session when initialState=ACTIVE', async () => {
        const s = await store.create(makeInput({ sessionId: 'a0000000-0000-4000-8000-000000000002', initialState: 'ACTIVE' }));
        expect(s.state).toBe('ACTIVE');
        expect(s.establishedAt).not.toBeNull();
    });

    it('should update session and increment revision', async () => {
        const id = 'a0000000-0000-4000-8000-000000000003';
        await store.create(makeInput({ sessionId: id }));
        const s = await store.update(id, { negotiatedCapabilities: ['X'] });
        expect(s.revision).toBe('2');
        expect(s.negotiatedCapabilities).toEqual(['X']);
    });

    it('should throw SESSION_CLOSED when updating closed session', async () => {
        const id = 'a0000000-0000-4000-8000-000000000004';
        await store.create(makeInput({ sessionId: id, initialState: 'ACTIVE' }));
        await store.update(id, {
            state: 'CLOSED',
            closedAt: new Date().toISOString() as Timestamp,
            closeReason: 'EXPLICIT_CLOSE',
        });
        await expect(store.update(id, {})).rejects.toMatchObject({ code: 'SESSION_CLOSED' });
    });

    it('should resume IDLE session to ACTIVE', async () => {
        const id = 'a0000000-0000-4000-8000-000000000005';
        await store.create(makeInput({ sessionId: id, initialState: 'ACTIVE' }));
        await pool.query(
            "UPDATE communication.sessions SET state='IDLE', idle_since=NOW()-'10 minutes'::interval, updated_at=NOW(), revision=revision+1 WHERE session_id=$1",
            [id],
        );
        const resumed = await store.resume({
            sessionId: id,
            expectedInitiatorDid: A,
            expectedResponderDid: B,
            idleHardMs: 1_800_000,
            negotiatedCapabilities: ['Z'],
        });
        expect(resumed.state).toBe('ACTIVE');
        expect(resumed.idleSince).toBeNull();
        expect(resumed.negotiatedCapabilities).toEqual(['Z']);
    });

    it('should cleanExpired mark stale/idle/closed in single pass', async () => {
        // The three sessions need to coexist in live states ({CREATED,ACTIVE,IDLE}) simultaneously, each
        // covering one expiry semantic. The uniq_sessions_live_per_pair constraint requires only 1 row per
        // (initiator,responder) pair during the live period, so three distinct DID pairs must be used;
        // sharing principal P is still isolated via the beforeEach principal-level cleanup.
        const a1 = 'did:agent:aaaa0001000000000000000000000000000000' as DID;
        const b1 = 'did:agent:bbbb0001000000000000000000000000000000' as DID;
        const a2 = 'did:agent:aaaa0002000000000000000000000000000000' as DID;
        const b2 = 'did:agent:bbbb0002000000000000000000000000000000' as DID;
        const a3 = 'did:agent:aaaa0003000000000000000000000000000000' as DID;
        const b3 = 'did:agent:bbbb0003000000000000000000000000000000' as DID;
        const s1 = crypto.randomUUID();
        const s2 = crypto.randomUUID();
        const s3 = crypto.randomUUID();
        await store.create(makeInput({ sessionId: s1, initiatorDid: a1, responderDid: b1 })); // CREATED stale
        await pool.query("UPDATE communication.sessions SET created_at=NOW()-'2 minutes'::interval WHERE session_id=$1", [s1]);
        await store.create(makeInput({ sessionId: s2, initiatorDid: a2, responderDid: b2, initialState: 'ACTIVE' }));
        await pool.query("UPDATE communication.sessions SET last_authorized_at=NOW()-'10 minutes'::interval WHERE session_id=$1", [s2]);
        await store.create(makeInput({ sessionId: s3, initiatorDid: a3, responderDid: b3, initialState: 'ACTIVE' }));
        await pool.query(
            "UPDATE communication.sessions SET state='IDLE', idle_since=NOW()-'40 minutes'::interval, updated_at=NOW(), revision=revision+1 WHERE session_id=$1",
            [s3],
        );

        const result = await store.cleanExpired({
            createdTimeoutMs: 60_000,
            idleSoftMs: 300_000,
            idleHardMs: 1_800_000,
        });
        expect(result.markedStale).toBeGreaterThanOrEqual(1);
        expect(result.markedIdle).toBeGreaterThanOrEqual(1);
        expect(result.markedClosed).toBeGreaterThanOrEqual(1);
    });

    it('should claimForDispatch and markAuthorized CAS succeed', async () => {
        const id = 'a0000000-0000-4000-8000-000000000006';
        await store.create(makeInput({ sessionId: id, initialState: 'ACTIVE' }));
        const claimed = await store.claimForDispatch({ sessionId: id, senderDid: A, selfDid: B });
        const authorized = await store.markAuthorized({ sessionId: id, expectedRevision: claimed.revision });
        expect(parseInt(authorized.revision)).toBeGreaterThan(parseInt(claimed.revision));
    });

    it('should markAuthorized fail CAS with wrong revision', async () => {
        const id = 'a0000000-0000-4000-8000-000000000007';
        await store.create(makeInput({ sessionId: id, initialState: 'ACTIVE' }));
        await expect(store.markAuthorized({ sessionId: id, expectedRevision: '999' }))
            .rejects.toMatchObject({ code: 'SESSION_STATE_INVALID' });
    });

    it('should closeByPrincipal close all live sessions for that principal', async () => {
        // Two active sessions under the same principal must come from different (initiator,responder) pairs,
        // otherwise uniq_sessions_live_per_pair will conflict on the second create.
        const a1 = 'did:agent:aaaa0010000000000000000000000000000000' as DID;
        const b1 = 'did:agent:bbbb0010000000000000000000000000000000' as DID;
        const a2 = 'did:agent:aaaa0011000000000000000000000000000000' as DID;
        const b2 = 'did:agent:bbbb0011000000000000000000000000000000' as DID;
        const s1 = crypto.randomUUID();
        const s2 = crypto.randomUUID();
        await store.create(makeInput({ sessionId: s1, initiatorDid: a1, responderDid: b1, initialState: 'ACTIVE' }));
        await store.create(makeInput({ sessionId: s2, initiatorDid: a2, responderDid: b2, initialState: 'ACTIVE' }));
        const closed = await store.closeByPrincipal({ principalDid: P });
        expect(closed.length).toBeGreaterThanOrEqual(2);
    });

    it('should closeByToken close sessions with matching token', async () => {
        const id = crypto.randomUUID();
        const tokenId = 'urn:cap:00000000-0000-4000-8000-000000000099';
        const fingerprint = 'a'.repeat(64);
        await store.create(makeInput({ sessionId: id, initialState: 'ACTIVE', capabilityTokenId: tokenId, capabilityTokenFingerprint: fingerprint }));
        const closed = await store.closeByToken({ tokenId });
        expect(closed).toContain(id);
        const row = await store.get(id);
        expect(row?.state).toBe('CLOSED');
    });
});
