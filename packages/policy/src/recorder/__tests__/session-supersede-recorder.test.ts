/**
 * SessionSupersedeRecorder unit/integration tests
 *
 * Coverage:
 *   1. Unit: constructor parameter validation
 *   2. Unit: recordSupersede / recordClose / recordMarkAuthorized parameter passing
 *   3. Unit: counter increment logic (each reason type)
 *   4. Integration (DB required): write a SESSION_SUPERSEDED record -> read it back via ActionRecorder.query() -> round-trip PASS
 *   5. Integration (DB required): recordClose convenience method round-trip
 *   6. Integration (DB required): recordMarkAuthorized convenience method round-trip
 */

import {
    afterAll,
    afterEach,
    beforeAll,
    describe,
    expect,
    it,
    vi,
} from 'vitest';

import { generateKeyPair } from '@coivitas/crypto';
import { createTestDatabase } from '@coivitas/shared';
import { SESSION_GOVERNOR_DID, type DID } from '@coivitas/types';

import { ActionRecorder } from '../../index.js';
import {
    SessionSupersedeRecorder,
    _resetMetricsForTest,
    getSessionCloseTotal,
    getSessionSupersedeTotal,
} from '../session-supersede-recorder.js';
import { assertSchemaCompliant } from '../../audit-governor-lane/assert-schema-compliant.js';
import { InMemorySideTableAppender } from '../../audit-governor-lane/side-table.js';

// governor lane subject-scoped audit requires the affected DID fields.
// The unit tests use a stable fixture to avoid redeclaring it in every case.
// The fixture must strictly conform to the schema pattern:
// did:agent: 40 hex chars (^did:agent:[a-f0-9]{40}$); did:key:zXXX of length >= 32 (^did:key:z[1-9A-HJ-NP-Za-km-z]{32,}$)
const AFFECTED_FIXTURE = {
    affectedAgentDid:
        'did:agent:1111222233334444555566667777888899990000' as DID,
    affectedPrincipalDid:
        'did:key:zSpec00000000000000000000000000000000000000000' as DID,
};

// ---------------------------------------------------------------------------
// Pure unit tests (no DB required)
// ---------------------------------------------------------------------------

describe('SessionSupersedeRecorder (unit)', () => {
    afterEach(() => {
        _resetMetricsForTest();
    });

    it('should throw when governorPrivateKey is empty string', () => {
        const mockRecorder = {} as ActionRecorder;
        expect(() => new SessionSupersedeRecorder(mockRecorder, '')).toThrow(
            'governorPrivateKey is required',
        );
    });

    it('should call actionRecorder.record with SESSION_GOVERNOR_DID as both agentDid and principalDid', async () => {
        const recordMock = vi.fn().mockResolvedValue({
            recordId: 'test-record-id',
            hash: 'test-hash',
        });
        const mockRecorder = {
            kind: 'control-plane',
            record: recordMock,
        } as unknown as ActionRecorder;
        const recorder = new SessionSupersedeRecorder(
            mockRecorder,
            'a'.repeat(64),
        );

        await recorder.recordSupersede({
            params: {
                oldSessionId: 'old-session-1',
                newSessionId: 'new-session-1',
                reason: 'TOKEN_REVOKED',
                timestamp:
                    '2025-01-01T00:00:00.000Z' as import('@coivitas/types').Timestamp,
                affectedAgentDid: AFFECTED_FIXTURE.affectedAgentDid,
                affectedPrincipalDid: AFFECTED_FIXTURE.affectedPrincipalDid,
            },
        });

        expect(recordMock).toHaveBeenCalledOnce();
        const callArg = recordMock.mock.calls[0][0] as Record<string, unknown>;
        expect(callArg['agentDid']).toBe(SESSION_GOVERNOR_DID);
        expect(callArg['principalDid']).toBe(SESSION_GOVERNOR_DID);
        expect(callArg['actionType']).toBe('SESSION_SUPERSEDED');
    });

    it('should set sessionId to params.oldSessionId when sessionId not provided', async () => {
        const recordMock = vi.fn().mockResolvedValue({
            recordId: 'test-record-id',
            hash: 'test-hash',
        });
        const mockRecorder = {
            kind: 'control-plane',
            record: recordMock,
        } as unknown as ActionRecorder;
        const recorder = new SessionSupersedeRecorder(
            mockRecorder,
            'a'.repeat(64),
        );

        await recorder.recordSupersede({
            params: {
                oldSessionId: 'session-abc',
                newSessionId: null,
                reason: 'FORCED_CLOSE',
                timestamp:
                    '2025-01-01T00:00:00.000Z' as import('@coivitas/types').Timestamp,
                affectedAgentDid: AFFECTED_FIXTURE.affectedAgentDid,
                affectedPrincipalDid: AFFECTED_FIXTURE.affectedPrincipalDid,
            },
        });

        const callArg = recordMock.mock.calls[0][0] as Record<string, unknown>;
        expect(callArg['sessionId']).toBe('session-abc');
    });

    it('should use explicit sessionId when provided', async () => {
        const recordMock = vi.fn().mockResolvedValue({
            recordId: 'test-record-id',
            hash: 'test-hash',
        });
        const mockRecorder = {
            kind: 'control-plane',
            record: recordMock,
        } as unknown as ActionRecorder;
        const recorder = new SessionSupersedeRecorder(
            mockRecorder,
            'a'.repeat(64),
        );

        await recorder.recordSupersede({
            params: {
                oldSessionId: 'session-old',
                newSessionId: null,
                reason: 'IDLE_EXPIRED',
                timestamp:
                    '2025-01-01T00:00:00.000Z' as import('@coivitas/types').Timestamp,
                affectedAgentDid: AFFECTED_FIXTURE.affectedAgentDid,
                affectedPrincipalDid: AFFECTED_FIXTURE.affectedPrincipalDid,
            },
            sessionId: 'custom-session-id',
        });

        const callArg = recordMock.mock.calls[0][0] as Record<string, unknown>;
        expect(callArg['sessionId']).toBe('custom-session-id');
    });

    // ── counter tests ────────────────────────────────────────────────────────────

    it('should increment session_supersede_total for all reason types', async () => {
        const recordMock = vi
            .fn()
            .mockResolvedValue({ recordId: 'r1', hash: 'h1' });
        const mockRecorder = {
            kind: 'control-plane',
            record: recordMock,
        } as unknown as ActionRecorder;
        const recorder = new SessionSupersedeRecorder(
            mockRecorder,
            'a'.repeat(64),
        );

        const reasons = [
            'EXPLICIT_CLOSE',
            'TOKEN_REVOKED',
            'IDLE_EXPIRED',
            'FORCED_CLOSE',
        ] as const;
        for (const reason of reasons) {
            await recorder.recordSupersede({
                params: {
                    oldSessionId: 'session-x',
                    newSessionId: null,
                    reason,
                    timestamp:
                        '2025-01-01T00:00:00.000Z' as import('@coivitas/types').Timestamp,
                    affectedAgentDid: AFFECTED_FIXTURE.affectedAgentDid,
                    affectedPrincipalDid: AFFECTED_FIXTURE.affectedPrincipalDid,
                },
            });
        }

        expect(getSessionSupersedeTotal()).toBe(4);
    });

    it('should increment session_close_total only for EXPLICIT_CLOSE and FORCED_CLOSE', async () => {
        const recordMock = vi
            .fn()
            .mockResolvedValue({ recordId: 'r1', hash: 'h1' });
        const mockRecorder = {
            kind: 'control-plane',
            record: recordMock,
        } as unknown as ActionRecorder;
        const recorder = new SessionSupersedeRecorder(
            mockRecorder,
            'a'.repeat(64),
        );

        // TOKEN_REVOKED → should NOT increment close total
        await recorder.recordSupersede({
            params: {
                oldSessionId: 's1',
                newSessionId: 's2',
                reason: 'TOKEN_REVOKED',
                timestamp:
                    '2025-01-01T00:00:00.000Z' as import('@coivitas/types').Timestamp,
                affectedAgentDid: AFFECTED_FIXTURE.affectedAgentDid,
                affectedPrincipalDid: AFFECTED_FIXTURE.affectedPrincipalDid,
            },
        });
        expect(getSessionCloseTotal()).toBe(0);

        // IDLE_EXPIRED → should NOT increment close total
        await recorder.recordSupersede({
            params: {
                oldSessionId: 's3',
                newSessionId: null,
                reason: 'IDLE_EXPIRED',
                timestamp:
                    '2025-01-01T00:00:00.000Z' as import('@coivitas/types').Timestamp,
                affectedAgentDid: AFFECTED_FIXTURE.affectedAgentDid,
                affectedPrincipalDid: AFFECTED_FIXTURE.affectedPrincipalDid,
            },
        });
        expect(getSessionCloseTotal()).toBe(0);

        // EXPLICIT_CLOSE → should increment close total
        await recorder.recordSupersede({
            params: {
                oldSessionId: 's4',
                newSessionId: null,
                reason: 'EXPLICIT_CLOSE',
                timestamp:
                    '2025-01-01T00:00:00.000Z' as import('@coivitas/types').Timestamp,
                affectedAgentDid: AFFECTED_FIXTURE.affectedAgentDid,
                affectedPrincipalDid: AFFECTED_FIXTURE.affectedPrincipalDid,
            },
        });
        expect(getSessionCloseTotal()).toBe(1);

        // FORCED_CLOSE → should increment close total
        await recorder.recordSupersede({
            params: {
                oldSessionId: 's5',
                newSessionId: null,
                reason: 'FORCED_CLOSE',
                timestamp:
                    '2025-01-01T00:00:00.000Z' as import('@coivitas/types').Timestamp,
                affectedAgentDid: AFFECTED_FIXTURE.affectedAgentDid,
                affectedPrincipalDid: AFFECTED_FIXTURE.affectedPrincipalDid,
            },
        });
        expect(getSessionCloseTotal()).toBe(2);
        expect(getSessionSupersedeTotal()).toBe(4);
    });

    it('should call actionRecorder.record with FORCED_CLOSE and null newSessionId when recordClose is called', async () => {
        const recordMock = vi
            .fn()
            .mockResolvedValue({ recordId: 'r1', hash: 'h1' });
        const mockRecorder = {
            kind: 'control-plane',
            record: recordMock,
        } as unknown as ActionRecorder;
        const recorder = new SessionSupersedeRecorder(
            mockRecorder,
            'a'.repeat(64),
        );

        await recorder.recordClose(
            'my-session',
            '2025-06-01T12:00:00.000Z',
            AFFECTED_FIXTURE,
        );

        const callArg = recordMock.mock.calls[0][0] as Record<string, unknown>;
        const params = callArg['parametersSummary'] as Record<string, unknown>;
        // recordClose now uses FORCED_CLOSE (the schema only allows FORCED_CLOSE
        // with a null newSessionId); EXPLICIT_CLOSE requires a non-empty
        // newSessionId, so it no longer fits the recordClose convenience-method semantics.
        expect(params['reason']).toBe('FORCED_CLOSE');
        expect(params['newSessionId']).toBeNull();
        expect(params['oldSessionId']).toBe('my-session');
    });

    it('should call actionRecorder.record with TOKEN_REVOKED and newSessionId when recordMarkAuthorized is called', async () => {
        const recordMock = vi
            .fn()
            .mockResolvedValue({ recordId: 'r1', hash: 'h1' });
        const mockRecorder = {
            kind: 'control-plane',
            record: recordMock,
        } as unknown as ActionRecorder;
        const recorder = new SessionSupersedeRecorder(
            mockRecorder,
            'a'.repeat(64),
        );

        await recorder.recordMarkAuthorized(
            'old-session',
            'new-session',
            '2025-06-01T12:00:00.000Z',
            AFFECTED_FIXTURE,
        );

        const callArg = recordMock.mock.calls[0][0] as Record<string, unknown>;
        const params = callArg['parametersSummary'] as Record<string, unknown>;
        expect(params['reason']).toBe('TOKEN_REVOKED');
        expect(params['newSessionId']).toBe('new-session');
        expect(params['oldSessionId']).toBe('old-session');
    });
});

// ---------------------------------------------------------------------------
// Integration tests (DB required)
// ---------------------------------------------------------------------------

const describeIfDatabase = process.env.DATABASE_URL ? describe : describe.skip;

describeIfDatabase('SessionSupersedeRecorder (integration)', () => {
    let cleanup: (() => Promise<void>) | undefined;
    let actionRecorder: ActionRecorder;
    let ssRecorder: SessionSupersedeRecorder;
    let governorPrivateKey: string;

    beforeAll(async () => {
        const database = await createTestDatabase();
        cleanup = database.cleanup;

        // ledger key for ActionRecorder (writes ledger_signature)
        const ledger = generateKeyPair();
        const ledgerPrivateKey = ledger.privateKey.slice(0, 64);

        // The control-plane ActionRecorder needs a session owner
        // resolver + schema validation function. The integration test uses an InMemory implementation.
        // Note: in the integration test the sessionId is generated dynamically, and assertSessionBinding
        // throws when a sessionId is not found -- but these tests need to pass inside recorder.record.
        // To avoid disrupting the existing test logic (these tests verify the DB round-trip), we use a
        // permissive resolver implementation that returns AFFECTED_FIXTURE's owner for any sessionId.
        const permissiveResolver = {
            resolveOwner: () =>
                Promise.resolve({
                    agentDid: AFFECTED_FIXTURE.affectedAgentDid,
                    principalDid: AFFECTED_FIXTURE.affectedPrincipalDid,
                }),
        };

        // control-plane must inject a sideTableAppender
        // The test uses an InMemorySideTableAppender stub (does not pollute the shared schema)
        actionRecorder = new ActionRecorder(database.pool, {
            kind: 'control-plane',
            ledgerPrivateKey,
            sessionOwnerResolver: permissiveResolver,
            assertSchemaCompliant,
            sideTableAppender: new InMemorySideTableAppender(),
        });

        // governor key for SessionSupersedeRecorder (control-plane actor signing)
        const governor = generateKeyPair();
        governorPrivateKey = governor.privateKey.slice(0, 64);
        ssRecorder = new SessionSupersedeRecorder(
            actionRecorder,
            governorPrivateKey,
        );
    });

    afterAll(async () => {
        await cleanup?.();
    });

    afterEach(() => {
        _resetMetricsForTest();
    });

    it('should write SESSION_SUPERSEDED record and query it back (round-trip PASS)', async () => {
        const oldSessionId = `sess-${Date.now()}-rt`;
        const newSessionId = `sess-${Date.now()}-new`;
        const timestamp = new Date().toISOString();

        const result = await ssRecorder.recordSupersede({
            params: {
                oldSessionId,
                newSessionId,
                reason: 'TOKEN_REVOKED',
                timestamp:
                    timestamp as import('@coivitas/types').Timestamp,
                affectedAgentDid: AFFECTED_FIXTURE.affectedAgentDid,
                affectedPrincipalDid: AFFECTED_FIXTURE.affectedPrincipalDid,
            },
        });

        expect(result.recordId).toBeTruthy();
        expect(result.hash).toBeTruthy();

        // Query it back to verify
        const queryResult = await actionRecorder.query({
            agentDid: SESSION_GOVERNOR_DID,
            actionType: 'SESSION_SUPERSEDED',
        });

        const found = queryResult.records.find(
            (r) => r.recordId === result.recordId,
        );
        expect(found).toBeDefined();
        expect(found!.agentDid).toBe(SESSION_GOVERNOR_DID);
        expect(found!.principalDid).toBe(SESSION_GOVERNOR_DID);
        expect(found!.actionType).toBe('SESSION_SUPERSEDED');
        expect(found!.sessionId).toBe(oldSessionId);

        const params = found!.parametersSummary as Record<string, unknown>;
        expect(params['oldSessionId']).toBe(oldSessionId);
        expect(params['newSessionId']).toBe(newSessionId);
        expect(params['reason']).toBe('TOKEN_REVOKED');

        // Counter verification
        expect(getSessionSupersedeTotal()).toBe(1);
        expect(getSessionCloseTotal()).toBe(0);
    });

    it('should write and query recordClose round-trip', async () => {
        const oldSessionId = `sess-close-${Date.now()}`;
        const timestamp = new Date().toISOString();

        const result = await ssRecorder.recordClose(
            oldSessionId,
            timestamp,
            AFFECTED_FIXTURE,
        );

        expect(result.recordId).toBeTruthy();

        const queryResult = await actionRecorder.query({
            agentDid: SESSION_GOVERNOR_DID,
            actionType: 'SESSION_SUPERSEDED',
        });

        const found = queryResult.records.find(
            (r) => r.recordId === result.recordId,
        );
        expect(found).toBeDefined();
        expect(found!.sessionId).toBe(oldSessionId);

        const params = found!.parametersSummary as Record<string, unknown>;
        // recordClose's implementation uniformly uses FORCED_CLOSE
        expect(params['reason']).toBe('FORCED_CLOSE');
        expect(params['newSessionId']).toBeNull();

        expect(getSessionCloseTotal()).toBe(1);
    });

    it('should write and query recordMarkAuthorized round-trip', async () => {
        const oldSessionId = `sess-old-${Date.now()}`;
        const newSessionId = `sess-new-${Date.now()}`;
        const timestamp = new Date().toISOString();

        const result = await ssRecorder.recordMarkAuthorized(
            oldSessionId,
            newSessionId,
            timestamp,
            AFFECTED_FIXTURE,
        );

        expect(result.recordId).toBeTruthy();

        const queryResult = await actionRecorder.query({
            agentDid: SESSION_GOVERNOR_DID,
            actionType: 'SESSION_SUPERSEDED',
        });

        const found = queryResult.records.find(
            (r) => r.recordId === result.recordId,
        );
        expect(found).toBeDefined();
        const params = found!.parametersSummary as Record<string, unknown>;
        expect(params['reason']).toBe('TOKEN_REVOKED');
        expect(params['newSessionId']).toBe(newSessionId);
        expect(params['oldSessionId']).toBe(oldSessionId);
    });

    it('should write IDLE_EXPIRED record without incrementing close counter', async () => {
        const oldSessionId = `sess-idle-${Date.now()}`;
        const newSessionId = `sess-idle-new-${Date.now()}`;
        const timestamp = new Date().toISOString();

        // Only FORCED_CLOSE allows a null successor;
        // IDLE_EXPIRED must pass a non-empty newSessionId (idle expire produces a new session)
        await ssRecorder.recordSupersede({
            params: {
                oldSessionId,
                newSessionId,
                reason: 'IDLE_EXPIRED',
                timestamp:
                    timestamp as import('@coivitas/types').Timestamp,
                affectedAgentDid: AFFECTED_FIXTURE.affectedAgentDid,
                affectedPrincipalDid: AFFECTED_FIXTURE.affectedPrincipalDid,
            },
        });

        expect(getSessionSupersedeTotal()).toBe(1);
        expect(getSessionCloseTotal()).toBe(0);
    });

    it('should write FORCED_CLOSE record and increment both counters', async () => {
        const oldSessionId = `sess-forced-${Date.now()}`;
        const timestamp = new Date().toISOString();

        await ssRecorder.recordSupersede({
            params: {
                oldSessionId,
                newSessionId: null,
                reason: 'FORCED_CLOSE',
                timestamp:
                    timestamp as import('@coivitas/types').Timestamp,
                affectedAgentDid: AFFECTED_FIXTURE.affectedAgentDid,
                affectedPrincipalDid: AFFECTED_FIXTURE.affectedPrincipalDid,
            },
        });

        expect(getSessionSupersedeTotal()).toBe(1);
        expect(getSessionCloseTotal()).toBe(1);
    });
});
