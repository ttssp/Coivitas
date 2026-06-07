/**
 * E2E Session Lineage tests
 *
 * Coverage:
 *   1. SESSION_SUPERSEDED events are written by SessionSupersedeRecorder (did:system:session-governor)
 *   2. The ActionRecord's agentDid / principalDid are both SESSION_GOVERNOR_DID
 *   3. actionType = 'SESSION_SUPERSEDED', and parametersSummary contains oldSessionId / reason
 *   4. Control-plane actions are not in capabilities[] (SESSION_GOVERNOR_DID holds no CapabilityToken)
 *   5. recordClose → FORCED_CLOSE reason (the schema only allows FORCED_CLOSE with a null
 *      newSessionId), and sessionCloseTotal increments correctly
 *   6. recordSupersede → TOKEN_REVOKED reason, with newSessionId pointing to the successor session
 *
 * Design decisions:
 *   - Gated by describeIfDatabase; everything is skipped when no DB is available.
 *   - An isolated test DB is created via createTestDatabase() (auto-migrate), with afterAll cleanup.
 *   - SessionSupersedeRecorder is injected with governorPrivateKey (a test-only Ed25519 key).
 *   - ActionRecorder.query is queried to verify the written ActionRecord fields.
 *   - _resetMetricsForTest() is reset in each beforeEach to keep counters isolated.
 *
 */

import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import { generateKeyPair } from '../../packages/crypto/src/index.js';
import { createTestDatabase } from '../../packages/shared/src/index.js';
import {
    ActionRecorder,
    type ControlPlaneActionRecorder,
} from '../../packages/policy/src/recorder/action-recorder.js';
import {
    SessionSupersedeRecorder,
    _resetMetricsForTest,
    getSessionCloseTotal,
    getSessionSupersedeTotal,
} from '../../packages/policy/src/recorder/session-supersede-recorder.js';
import { assertSchemaCompliant } from '../../packages/policy/src/audit-governor-lane/assert-schema-compliant.js';
import { InMemorySideTableAppender } from '../../packages/policy/src/audit-governor-lane/side-table.js';
import {
    ACTION_SESSION_SUPERSEDED,
    SESSION_GOVERNOR_DID,
} from '../../packages/types/src/index.js';
import type { DID } from '../../packages/types/src/index.js';
import type { DatabasePool } from '../../packages/shared/src/index.js';

// ─── DB gate ────────────────────────────────────────────────────────────────

const describeIfDatabase = process.env.DATABASE_URL ? describe : describe.skip;

// ─── E2E test suite ────────────────────────────────────────────────────────────

describeIfDatabase('session-lineage E2E', () => {
    let pool: DatabasePool;
    let cleanup: (() => Promise<void>) | undefined;
    let ledgerKey: { publicKey: string; privateKey: string };
    let governorKey: { publicKey: string; privateKey: string };
    let actionRecorder: ActionRecorder;
    let supersedeRecorder: SessionSupersedeRecorder;

    beforeAll(async () => {
        const db = await createTestDatabase();
        pool = db.pool;
        cleanup = db.cleanup;

        // Ledger signing key (used internally by ActionRecorder)
        ledgerKey = generateKeyPair();
        // Governor control-plane signing key (used by SessionSupersedeRecorder)
        governorKey = generateKeyPair();

        // SessionSupersedeRecorder only accepts a control-plane recorder.
        // The control-plane recorder must be injected with sessionOwnerResolver / assertSchemaCompliant / sideTableAppender.
        // Here we complete the wiring (a permissive resolver + an InMemory side-table stub).
        const permissiveResolver = {
            resolveOwner: () =>
                Promise.resolve({
                    agentDid:
                        'did:agent:1111222233334444555566667777888899990000' as DID,
                    principalDid:
                        'did:key:zStub00000000000000000000000000000000000000000' as DID,
                }),
        };
        actionRecorder = new ActionRecorder(pool, {
            kind: 'control-plane',
            ledgerPrivateKey: ledgerKey.privateKey.slice(0, 64),
            sessionOwnerResolver: permissiveResolver,
            assertSchemaCompliant,
            sideTableAppender: new InMemorySideTableAppender(),
        });
        supersedeRecorder = new SessionSupersedeRecorder(
            actionRecorder as ControlPlaneActionRecorder,
            governorKey.privateKey,
        );
    });

    // Every SessionSupersedeRecorder entry point must carry affectedAgentDid /
    // affectedPrincipalDid (required by the governor lane's subject-scoped audit). This e2e test
    // uses stable fixture DIDs so the hash chain assertions are reproducible.
    // The fixture must strictly match the schema pattern (^did:agent:[a-f0-9]{40}$).
    const affectedFixture = {
        affectedAgentDid:
            'did:agent:1111222233334444555566667777888899990000' as DID,
        affectedPrincipalDid:
            'did:key:zStub00000000000000000000000000000000000000000' as DID,
    };

    beforeEach(() => {
        // Reset counters before each test (module-level counters, to avoid cross-test interference)
        _resetMetricsForTest();
    });

    afterAll(async () => {
        await cleanup?.();
    });

    // -----------------------------------------------------------------------
    // Test 1: recordClose → FORCED_CLOSE writes an ActionRecord with agentDid=SESSION_GOVERNOR_DID
    // -----------------------------------------------------------------------
    it('should write SESSION_SUPERSEDED ActionRecord with agentDid=SESSION_GOVERNOR_DID on close', async () => {
        const oldSessionId = 'test-session-001-close';
        const timestamp = new Date().toISOString();

        const writeResult = await supersedeRecorder.recordClose(
            oldSessionId,
            timestamp,
            affectedFixture,
        );

        expect(writeResult.recordId).toBeTruthy();
        expect(writeResult.hash).toBeTruthy();

        // Query the ActionRecord to verify the written content
        const { records } = await actionRecorder.query({
            agentDid: SESSION_GOVERNOR_DID,
            actionType: ACTION_SESSION_SUPERSEDED,
        });

        // There should be at least 1 matching record
        expect(records.length).toBeGreaterThanOrEqual(1);

        const record = records.find((r) => r.sessionId === oldSessionId);
        expect(record).toBeDefined();
        expect(record?.agentDid).toBe(SESSION_GOVERNOR_DID);
        expect(record?.principalDid).toBe(SESSION_GOVERNOR_DID);
        expect(record?.actionType).toBe(ACTION_SESSION_SUPERSEDED);
        expect(record?.sessionId).toBe(oldSessionId);

        // recordClose now uses FORCED_CLOSE (the schema only allows FORCED_CLOSE with a
        // null newSessionId).
        const params = record?.parametersSummary as Record<string, unknown>;
        expect(params?.reason).toBe('FORCED_CLOSE');
        expect(params?.oldSessionId).toBe(oldSessionId);
        expect(params?.newSessionId).toBeNull();
    });

    // -----------------------------------------------------------------------
    // Test 2: recordSupersede → TOKEN_REVOKED, with newSessionId pointing to the successor session
    // -----------------------------------------------------------------------
    it('should write SESSION_SUPERSEDED with TOKEN_REVOKED reason and newSessionId', async () => {
        const oldSessionId = 'test-session-002-old';
        const newSessionId = 'test-session-002-new';
        const timestamp = new Date().toISOString();

        await supersedeRecorder.recordMarkAuthorized(
            oldSessionId,
            newSessionId,
            timestamp,
            affectedFixture,
        );

        const { records } = await actionRecorder.query({
            agentDid: SESSION_GOVERNOR_DID,
            actionType: ACTION_SESSION_SUPERSEDED,
        });

        const record = records.find((r) => r.sessionId === oldSessionId);
        expect(record).toBeDefined();
        expect(record?.agentDid).toBe(SESSION_GOVERNOR_DID);

        const params = record?.parametersSummary as Record<string, unknown>;
        expect(params?.reason).toBe('TOKEN_REVOKED');
        expect(params?.oldSessionId).toBe(oldSessionId);
        expect(params?.newSessionId).toBe(newSessionId);
    });

    // -----------------------------------------------------------------------
    // Test 3: Control-plane actions are not in capabilities (SESSION_GOVERNOR_DID has no CapabilityToken)
    // — verify that records with agentDid===SESSION_GOVERNOR_DID have no authorizationRef
    // -----------------------------------------------------------------------
    it('should write control-plane actions without authorizationRef (no CapabilityToken)', async () => {
        const oldSessionId = 'test-session-003-noCap';
        const timestamp = new Date().toISOString();

        await supersedeRecorder.recordClose(
            oldSessionId,
            timestamp,
            affectedFixture,
        );

        const { records } = await actionRecorder.query({
            agentDid: SESSION_GOVERNOR_DID,
            actionType: ACTION_SESSION_SUPERSEDED,
        });

        const record = records.find((r) => r.sessionId === oldSessionId);
        expect(record).toBeDefined();
        // Control-plane events have no CapabilityToken: authorizationRef must be null/undefined
        expect(record?.authorizationRef).toBeNull();
    });

    // -----------------------------------------------------------------------
    // Test 4: Counters — sessionCloseTotal / sessionSupersedeTotal increment correctly
    // -----------------------------------------------------------------------
    it('should increment sessionCloseTotal and sessionSupersedeTotal correctly', async () => {
        const ts = new Date().toISOString();

        // Both start at 0 (already reset in beforeEach)
        expect(getSessionSupersedeTotal()).toBe(0);
        expect(getSessionCloseTotal()).toBe(0);

        // recordClose → both +1
        await supersedeRecorder.recordClose(
            'session-ctr-close-a',
            ts,
            affectedFixture,
        );
        expect(getSessionSupersedeTotal()).toBe(1);
        expect(getSessionCloseTotal()).toBe(1);

        // recordMarkAuthorized (TOKEN_REVOKED) → supersedeTotal+1, closeTotal unchanged
        await supersedeRecorder.recordMarkAuthorized(
            'session-ctr-old-b',
            'session-ctr-new-b',
            ts,
            affectedFixture,
        );
        expect(getSessionSupersedeTotal()).toBe(2);
        expect(getSessionCloseTotal()).toBe(1); // TOKEN_REVOKED does not count toward closeTotal

        // recordClose again → both +1
        await supersedeRecorder.recordClose(
            'session-ctr-close-c',
            ts,
            affectedFixture,
        );
        expect(getSessionSupersedeTotal()).toBe(3);
        expect(getSessionCloseTotal()).toBe(2);
    });

    // -----------------------------------------------------------------------
    // Test 5: FORCED_CLOSE reason — newSessionId=null (no successor session)
    // -----------------------------------------------------------------------
    it('should write FORCED_CLOSE SESSION_SUPERSEDED with null newSessionId', async () => {
        const oldSessionId = 'test-session-005-forced';
        const timestamp = new Date().toISOString();

        // Write FORCED_CLOSE directly via recordSupersede
        await supersedeRecorder.recordSupersede({
            params: {
                oldSessionId,
                newSessionId: null,
                reason: 'FORCED_CLOSE',
                timestamp: timestamp as Parameters<
                    typeof supersedeRecorder.recordSupersede
                >[0]['params']['timestamp'],
                affectedAgentDid: affectedFixture.affectedAgentDid,
                affectedPrincipalDid: affectedFixture.affectedPrincipalDid,
            },
            sessionId: oldSessionId,
        });

        const { records } = await actionRecorder.query({
            agentDid: SESSION_GOVERNOR_DID,
            actionType: ACTION_SESSION_SUPERSEDED,
        });

        const record = records.find((r) => r.sessionId === oldSessionId);
        expect(record).toBeDefined();

        const params = record?.parametersSummary as Record<string, unknown>;
        expect(params?.reason).toBe('FORCED_CLOSE');
        expect(params?.newSessionId).toBeNull();

        // FORCED_CLOSE is also a close-type event, so closeTotal should increment
        expect(getSessionCloseTotal()).toBeGreaterThanOrEqual(1);
    });

    // -----------------------------------------------------------------------
    // Test 6: hash chain integrity — previousRecordHash is genuinely linked after consecutive writes
    // -----------------------------------------------------------------------
    // Revision rationale: the old version only asserted "both records were written", not
    // record_2.previousRecordHash === record_1.recordHash. If the hash chain link were ever
    // broken in a refactor (for example, previousRecordHash degrading to an empty string,
    // or unlocked writes causing a race condition), this test would still pass. The chain-link assertion is added.
    it('should maintain hash chain integrity across consecutive SESSION_SUPERSEDED records (record_2.previousRecordHash === record_1.recordHash)', async () => {
        const ts = new Date().toISOString();

        const result1 = await supersedeRecorder.recordClose(
            'chain-session-001',
            ts,
            affectedFixture,
        );
        const result2 = await supersedeRecorder.recordClose(
            'chain-session-002',
            ts,
            affectedFixture,
        );

        // The two records have different hashes (different oldSessionId → different payload → different hash)
        expect(result1.hash).not.toBe(result2.hash);
        expect(result1.recordId).not.toBe(result2.recordId);

        // Query to verify both records were written, sorted by created_at to obtain record_1 / record_2
        const { records } = await actionRecorder.query({
            agentDid: SESSION_GOVERNOR_DID,
            actionType: ACTION_SESSION_SUPERSEDED,
        });
        const chainRecords = records
            .filter(
                (r) =>
                    r.sessionId === 'chain-session-001' ||
                    r.sessionId === 'chain-session-002',
            )
            .sort((a, b) => a.createdAt.localeCompare(b.createdAt));
        expect(chainRecords).toHaveLength(2);
        expect(chainRecords[0]?.sessionId).toBe('chain-session-001');
        expect(chainRecords[1]?.sessionId).toBe('chain-session-002');

        // Key assertion: record_2.previousRecordHash === record_1.recordHash
        // This is the contract that the hash chain is genuinely linked; without this assertion, a disconnected chain would also pass the test.
        expect(chainRecords[1]?.previousRecordHash).toBe(
            chainRecords[0]?.recordHash,
        );
        // Also verify that result.hash matches the recordHash returned by the query
        expect(chainRecords[0]?.recordHash).toBe(result1.hash);
        expect(chainRecords[1]?.recordHash).toBe(result2.hash);
    });
});
