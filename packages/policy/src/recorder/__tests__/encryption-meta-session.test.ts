/**
 * encryption-meta-session unit tests
 *
 * Coverage:
 *   1. InMemoryEncryptionSessionMetaStore.upsert + getBySessionId (hit / miss)
 *   2. InMemoryEncryptionSessionMetaStore.listByDidPair (filter logic)
 *   3. EncryptionSessionMetaService.getSessionMeta (delegates to store)
 *   4. EncryptionSessionMetaService.isEncryptedSession (REQUIRED=true / OFF=false / not-found=false)
 *   5. EncryptionSessionMetaService.aggregateByDidPair (encrypted-ratio computation, totalCount=0 boundary)
 *
 * Firewall confirmation:
 *   - no ControlPlaneAuditAccessChecker import
 *   - no governor lane call
 *   - no IntegrityChecker / ActionRecorder constructor parameter expansion
 *   - no new ActionRecord field (hash chain unchanged)
 *   - no @coivitas/communication (L4) import
 */

import { describe, expect, it } from 'vitest';
import {
    EncryptionSessionMetaService,
    InMemoryEncryptionSessionMetaStore,
} from '../encryption-meta-session.js';
import type { EncryptionSessionMeta } from '../encryption-meta-session.js';

// ─────────────────────────────────────────────────────────────────────────────
// Test helpers
// ─────────────────────────────────────────────────────────────────────────────

function makeMeta(
    sessionId: string,
    encryptionState: 'OFF' | 'REQUIRED',
    fingerprint: string | null = null,
    rekeyCount = 0,
): EncryptionSessionMeta {
    return { sessionId, encryptionState, sessionKeyFingerprint: fingerprint, rekeyCount };
}

const DID_A = 'did:agent:alice';
const DID_B = 'did:agent:bob';
const DID_C = 'did:agent:carol';

function sessionId(initiator: string, responder: string, idx: number): string {
    return `${initiator}:${responder}:session-${idx}`;
}

// ─────────────────────────────────────────────────────────────────────────────
// InMemoryEncryptionSessionMetaStore
// ─────────────────────────────────────────────────────────────────────────────

describe('InMemoryEncryptionSessionMetaStore', () => {
    it('should return null when session not found', async () => {
        const store = new InMemoryEncryptionSessionMetaStore();
        expect(await store.getBySessionId('does-not-exist')).toBeNull();
    });

    it('should return upserted meta by sessionId', async () => {
        const store = new InMemoryEncryptionSessionMetaStore();
        const meta = makeMeta('sess-001', 'REQUIRED', 'a'.repeat(64), 2);
        store.upsert(meta);

        const result = await store.getBySessionId('sess-001');
        expect(result).not.toBeNull();
        expect(result?.encryptionState).toBe('REQUIRED');
        expect(result?.sessionKeyFingerprint).toBe('a'.repeat(64));
        expect(result?.rekeyCount).toBe(2);
    });

    it('should overwrite existing meta on upsert (same sessionId)', async () => {
        const store = new InMemoryEncryptionSessionMetaStore();
        store.upsert(makeMeta('sess-001', 'OFF'));
        store.upsert(makeMeta('sess-001', 'REQUIRED', 'b'.repeat(64), 1));

        const result = await store.getBySessionId('sess-001');
        expect(result?.encryptionState).toBe('REQUIRED');
        expect(result?.rekeyCount).toBe(1);
    });

    it('should isolate upserted copy (mutation after upsert does not affect stored record)', async () => {
        const store = new InMemoryEncryptionSessionMetaStore();
        const meta = makeMeta('sess-002', 'OFF');
        store.upsert(meta);
        // External mutation should not affect the stored copy
        meta.rekeyCount = 99;

        const result = await store.getBySessionId('sess-002');
        expect(result?.rekeyCount).toBe(0);
    });

    it('should list only sessions matching initiator:responder prefix', async () => {
        const store = new InMemoryEncryptionSessionMetaStore();
        // A↔B sessions
        store.upsert(makeMeta(sessionId(DID_A, DID_B, 1), 'REQUIRED', 'f'.repeat(64)));
        store.upsert(makeMeta(sessionId(DID_A, DID_B, 2), 'OFF'));
        // A↔C session — should NOT appear in A↔B query
        store.upsert(makeMeta(sessionId(DID_A, DID_C, 1), 'REQUIRED', 'e'.repeat(64)));

        const results = await store.listByDidPair(DID_A, DID_B);
        expect(results).toHaveLength(2);
        expect(results.every((r) => r.sessionId.startsWith(`${DID_A}:${DID_B}:`))).toBe(true);
    });

    it('should return empty array when no sessions exist for did pair', async () => {
        const store = new InMemoryEncryptionSessionMetaStore();
        const results = await store.listByDidPair(DID_A, DID_B);
        expect(results).toEqual([]);
    });
});

// ─────────────────────────────────────────────────────────────────────────────
// EncryptionSessionMetaService
// ─────────────────────────────────────────────────────────────────────────────

describe('EncryptionSessionMetaService', () => {
    function makeService(): {
        store: InMemoryEncryptionSessionMetaStore;
        service: EncryptionSessionMetaService;
    } {
        const store = new InMemoryEncryptionSessionMetaStore();
        const service = new EncryptionSessionMetaService(store);
        return { store, service };
    }

    // ── getSessionMeta ────────────────────────────────────────────────────────

    it('should return null from getSessionMeta when session does not exist', async () => {
        const { service } = makeService();
        expect(await service.getSessionMeta('no-such-session')).toBeNull();
    });

    it('should return full meta from getSessionMeta when session exists', async () => {
        const { store, service } = makeService();
        const meta = makeMeta('sess-A', 'REQUIRED', 'c'.repeat(64), 3);
        store.upsert(meta);

        const result = await service.getSessionMeta('sess-A');
        expect(result?.encryptionState).toBe('REQUIRED');
        expect(result?.sessionKeyFingerprint).toBe('c'.repeat(64));
        expect(result?.rekeyCount).toBe(3);
    });

    // ── isEncryptedSession ────────────────────────────────────────────────────

    it('should return true when encryptionState=REQUIRED', async () => {
        const { store, service } = makeService();
        store.upsert(makeMeta('sess-enc', 'REQUIRED', 'd'.repeat(64)));
        expect(await service.isEncryptedSession('sess-enc')).toBe(true);
    });

    it('should return false when encryptionState=OFF', async () => {
        const { store, service } = makeService();
        store.upsert(makeMeta('sess-off', 'OFF'));
        expect(await service.isEncryptedSession('sess-off')).toBe(false);
    });

    it('should return false when session does not exist (fail-safe)', async () => {
        const { service } = makeService();
        expect(await service.isEncryptedSession('non-existent')).toBe(false);
    });

    // ── aggregateByDidPair ────────────────────────────────────────────────────

    it('should return encryptedRatio=0 when no sessions exist for did pair', async () => {
        const { service } = makeService();
        const agg = await service.aggregateByDidPair(DID_A, DID_B);
        expect(agg.totalCount).toBe(0);
        expect(agg.encryptedCount).toBe(0);
        expect(agg.encryptedRatio).toBe(0);
        expect(agg.initiatorDid).toBe(DID_A);
        expect(agg.responderDid).toBe(DID_B);
    });

    it('should compute correct ratio when all sessions are encrypted', async () => {
        const { store, service } = makeService();
        store.upsert(makeMeta(sessionId(DID_A, DID_B, 1), 'REQUIRED', 'a'.repeat(64)));
        store.upsert(makeMeta(sessionId(DID_A, DID_B, 2), 'REQUIRED', 'b'.repeat(64)));

        const agg = await service.aggregateByDidPair(DID_A, DID_B);
        expect(agg.totalCount).toBe(2);
        expect(agg.encryptedCount).toBe(2);
        expect(agg.encryptedRatio).toBe(1.0);
    });

    it('should compute correct ratio when no sessions are encrypted', async () => {
        const { store, service } = makeService();
        store.upsert(makeMeta(sessionId(DID_A, DID_B, 1), 'OFF'));
        store.upsert(makeMeta(sessionId(DID_A, DID_B, 2), 'OFF'));
        store.upsert(makeMeta(sessionId(DID_A, DID_B, 3), 'OFF'));

        const agg = await service.aggregateByDidPair(DID_A, DID_B);
        expect(agg.totalCount).toBe(3);
        expect(agg.encryptedCount).toBe(0);
        expect(agg.encryptedRatio).toBe(0);
    });

    it('should compute 0.5 ratio for mixed sessions (2 encrypted, 2 plain)', async () => {
        const { store, service } = makeService();
        store.upsert(makeMeta(sessionId(DID_A, DID_B, 1), 'REQUIRED', 'f'.repeat(64)));
        store.upsert(makeMeta(sessionId(DID_A, DID_B, 2), 'REQUIRED', 'e'.repeat(64)));
        store.upsert(makeMeta(sessionId(DID_A, DID_B, 3), 'OFF'));
        store.upsert(makeMeta(sessionId(DID_A, DID_B, 4), 'OFF'));

        const agg = await service.aggregateByDidPair(DID_A, DID_B);
        expect(agg.totalCount).toBe(4);
        expect(agg.encryptedCount).toBe(2);
        expect(agg.encryptedRatio).toBeCloseTo(0.5);
    });

    it('should not count sessions from other did pairs in aggregation', async () => {
        const { store, service } = makeService();
        // A↔B: 1 encrypted
        store.upsert(makeMeta(sessionId(DID_A, DID_B, 1), 'REQUIRED', 'a'.repeat(64)));
        // A↔C: 3 unencrypted (should not affect A↔B aggregation)
        store.upsert(makeMeta(sessionId(DID_A, DID_C, 1), 'OFF'));
        store.upsert(makeMeta(sessionId(DID_A, DID_C, 2), 'OFF'));
        store.upsert(makeMeta(sessionId(DID_A, DID_C, 3), 'OFF'));

        const agg = await service.aggregateByDidPair(DID_A, DID_B);
        expect(agg.totalCount).toBe(1);
        expect(agg.encryptedCount).toBe(1);
        expect(agg.encryptedRatio).toBe(1.0);
    });

    it('should return sessionKeyFingerprint=null and rekeyCount=0 for OFF session', async () => {
        const { store, service } = makeService();
        store.upsert(makeMeta('sess-null', 'OFF', null, 0));

        const result = await service.getSessionMeta('sess-null');
        expect(result?.sessionKeyFingerprint).toBeNull();
        expect(result?.rekeyCount).toBe(0);
    });
});
