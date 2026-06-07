/**
 * production-path integration tests.
 *
 * These tests directly cover three classes of fail-closed scenarios:
 *
 * Scenario 1: ControlPlaneActionRecorder write path enforces binding + schema validation
 *   - test: rejects mismatched affected DID via production write path
 *   - test: rejects malformed SESSION_SUPERSEDED payload via production write path
 *
 * Scenario 2: side-table verifyChain detects main-table tamper / missing rows
 *   - test: detects main-table record hash tamper (SIDE_TABLE_ROW_TAMPERED)
 *   - test: detects main-table record deletion (SIDE_TABLE_ANCHOR_MISSING)
 *
 * Scenario 3: createGovernorLaneRuntime() throws when durable deps are missing
 *   - test: throws when durableArbitrationStore is missing
 *   - test: throws when durableSideTableAppender is missing
 *
 * These tests do not depend on a DB -- they use mock/InMemory implementations to verify that the production path
 * must pass through the guard logic (not merely a unit test calling the guard functions directly).
 *
 */

import { describe, it, expect } from 'vitest';

import type { DatabasePool } from '@coivitas/shared';
import { ProtocolError, type DID } from '@coivitas/types';
import {
    ACTION_SESSION_SUPERSEDED,
    SESSION_GOVERNOR_DID,
} from '@coivitas/types';

import { ActionRecorder } from '../../recorder/action-recorder.js';
import { InMemorySideTableAppender } from '../side-table.js';
import { InMemoryOperatorArbitrationStateMachine } from '../arbitration.js';
import { InMemorySessionOwnerResolver } from '../session-owner-resolver.js';
import { assertSchemaCompliant } from '../assert-schema-compliant.js';
import { createGovernorLaneRuntime } from '../factory.js';
import type { MainTableRecordLoader } from '../types.js';

// ---------------------------------------------------------------------------
// test fixtures
// ---------------------------------------------------------------------------

const LEDGER_KEY_HEX = 'a'.repeat(64);
const dummyPool = {} as unknown as DatabasePool;

const AGENT_DID = 'did:agent:' + 'a'.repeat(40);
const PRINCIPAL_DID = 'did:key:z6MkpTHR8VNs5xAbcde';
const WRONG_AGENT_DID = 'did:agent:' + 'b'.repeat(40);
const WRONG_PRINCIPAL_DID = 'did:key:z6MkWrongKeyHere';

const SESSION_ID = 'session-test-001';

function makeResolver() {
    const resolver = new InMemorySessionOwnerResolver();
    resolver.register(SESSION_ID, {
        agentDid: AGENT_DID as DID,
        principalDid: PRINCIPAL_DID as DID,
    });
    return resolver;
}

function makeControlPlaneRecorder(resolver?: InMemorySessionOwnerResolver) {
    return new ActionRecorder(dummyPool, {
        kind: 'control-plane',
        ledgerPrivateKey: LEDGER_KEY_HEX,
        sessionOwnerResolver: resolver ?? makeResolver(),
        assertSchemaCompliant,
        sideTableAppender: new InMemorySideTableAppender(),
    });
}

// ---------------------------------------------------------------------------
// Scenario 1: production write path rejects mismatched binding / malformed payload
// ---------------------------------------------------------------------------

describe('ControlPlaneActionRecorder write-path enforcement', () => {
    it('should reject mismatched affectedAgentDid via production write path (SESSION_BINDING_MISMATCH)', async () => {
        // session-test-001's owner is AGENT_DID / PRINCIPAL_DID
        // The caller supplies WRONG_AGENT_DID -> binding mismatch -> fail-closed
        const recorder = makeControlPlaneRecorder();

        await expect(
            recorder.record({
                agentDid: SESSION_GOVERNOR_DID as unknown as DID,
                principalDid: SESSION_GOVERNOR_DID as unknown as DID,
                actionType: ACTION_SESSION_SUPERSEDED,
                actorPrivateKey: LEDGER_KEY_HEX,
                parametersSummary: {
                    oldSessionId: SESSION_ID,
                    newSessionId: 'session-new-001',
                    reason: 'EXPLICIT_CLOSE',
                    timestamp: '2026-05-05T10:00:00.000Z',
                    affectedAgentDid: WRONG_AGENT_DID,
                    affectedPrincipalDid: PRINCIPAL_DID,
                },
            }),
        ).rejects.toThrow('SESSION_BINDING_MISMATCH');
    });

    it('should reject mismatched affectedPrincipalDid via production write path (SESSION_BINDING_MISMATCH)', async () => {
        const recorder = makeControlPlaneRecorder();

        await expect(
            recorder.record({
                agentDid: SESSION_GOVERNOR_DID as unknown as DID,
                principalDid: SESSION_GOVERNOR_DID as unknown as DID,
                actionType: ACTION_SESSION_SUPERSEDED,
                actorPrivateKey: LEDGER_KEY_HEX,
                parametersSummary: {
                    oldSessionId: SESSION_ID,
                    newSessionId: 'session-new-001',
                    reason: 'EXPLICIT_CLOSE',
                    timestamp: '2026-05-05T10:00:00.000Z',
                    affectedAgentDid: AGENT_DID,
                    affectedPrincipalDid: WRONG_PRINCIPAL_DID,
                },
            }),
        ).rejects.toThrow('SESSION_BINDING_MISMATCH');
    });

    it('should reject unknown sessionId via production write path (SESSION_BINDING_MISMATCH)', async () => {
        const recorder = makeControlPlaneRecorder();

        await expect(
            recorder.record({
                agentDid: SESSION_GOVERNOR_DID as unknown as DID,
                principalDid: SESSION_GOVERNOR_DID as unknown as DID,
                actionType: ACTION_SESSION_SUPERSEDED,
                actorPrivateKey: LEDGER_KEY_HEX,
                parametersSummary: {
                    oldSessionId: 'non-existent-session',
                    newSessionId: 'session-new-001',
                    reason: 'EXPLICIT_CLOSE',
                    timestamp: '2026-05-05T10:00:00.000Z',
                    affectedAgentDid: AGENT_DID,
                    affectedPrincipalDid: PRINCIPAL_DID,
                },
            }),
        ).rejects.toThrow('SESSION_BINDING_MISMATCH');
    });

    it('should reject malformed SESSION_SUPERSEDED payload via production write path (AJV schema)', async () => {
        // affectedAgentDid does not match the did:agent:* pattern -> AJV rejects it
        const recorder = makeControlPlaneRecorder();

        await expect(
            recorder.record({
                agentDid: SESSION_GOVERNOR_DID as unknown as DID,
                principalDid: SESSION_GOVERNOR_DID as unknown as DID,
                actionType: ACTION_SESSION_SUPERSEDED,
                actorPrivateKey: LEDGER_KEY_HEX,
                parametersSummary: {
                    oldSessionId: SESSION_ID,
                    newSessionId: 'session-new-001',
                    reason: 'EXPLICIT_CLOSE',
                    timestamp: '2026-05-05T10:00:00.000Z',
                    affectedAgentDid: 'not-a-valid-did',
                    affectedPrincipalDid: PRINCIPAL_DID,
                },
            }),
        ).rejects.toThrow(/assertSchemaCompliant|AJV schema/);
    });

    it('should reject extra fields in parametersSummary via production write path (additionalProperties)', async () => {
        const recorder = makeControlPlaneRecorder();

        await expect(
            recorder.record({
                agentDid: SESSION_GOVERNOR_DID as unknown as DID,
                principalDid: SESSION_GOVERNOR_DID as unknown as DID,
                actionType: ACTION_SESSION_SUPERSEDED,
                actorPrivateKey: LEDGER_KEY_HEX,
                parametersSummary: {
                    oldSessionId: SESSION_ID,
                    newSessionId: 'session-new-001',
                    reason: 'EXPLICIT_CLOSE',
                    timestamp: '2026-05-05T10:00:00.000Z',
                    affectedAgentDid: AGENT_DID,
                    affectedPrincipalDid: PRINCIPAL_DID,
                    extraField: 'injected-payload',
                },
            }),
        ).rejects.toThrow(/assertSchemaCompliant|AJV schema/);
    });

    it('should throw ProtocolError with code INTERNAL_ERROR for binding mismatch', async () => {
        const recorder = makeControlPlaneRecorder();

        try {
            await recorder.record({
                agentDid: SESSION_GOVERNOR_DID as unknown as DID,
                principalDid: SESSION_GOVERNOR_DID as unknown as DID,
                actionType: ACTION_SESSION_SUPERSEDED,
                actorPrivateKey: LEDGER_KEY_HEX,
                parametersSummary: {
                    oldSessionId: SESSION_ID,
                    newSessionId: 'session-new-001',
                    reason: 'EXPLICIT_CLOSE',
                    timestamp: '2026-05-05T10:00:00.000Z',
                    affectedAgentDid: WRONG_AGENT_DID,
                    affectedPrincipalDid: PRINCIPAL_DID,
                },
            });
            expect.fail('should have thrown');
        } catch (err) {
            expect(err).toBeInstanceOf(ProtocolError);
            expect((err as ProtocolError).code).toBe('INTERNAL_ERROR');
            // The error message carries the SESSION_BINDING_MISMATCH tag
            expect((err as ProtocolError).message).toContain(
                'SESSION_BINDING_MISMATCH',
            );
        }
    });
});

// ---------------------------------------------------------------------------
// Scenario 2: side-table verifyChain detects main-table tamper / missing
// ---------------------------------------------------------------------------

// This group of tests covers the interface contract (types.ts + side-table.ts/arbitration.ts InMemory stub);
// the durable Postgres runtime implementation is follow-up work.
describe('side-table verifyChain main-table cross-verification', () => {
    it('should detect main-table record hash tamper (SIDE_TABLE_ROW_TAMPERED)', async () => {
        const appender = new InMemorySideTableAppender();

        // Append some entries
        await appender.append({
            recordId: 'rec-001',
            recordHash: 'hash-original-001',
            agentDid: AGENT_DID as DID,
            createdAt:
                '2026-05-05T10:00:00.000Z' as import('@coivitas/types').Timestamp,
        });
        await appender.append({
            recordId: 'rec-002',
            recordHash: 'hash-original-002',
            agentDid: AGENT_DID as DID,
            createdAt:
                '2026-05-05T10:01:00.000Z' as import('@coivitas/types').Timestamp,
        });

        // Mock main table loader: rec-002's hash has been tampered with
        const tamperedLoader: MainTableRecordLoader = {
            loadRecord: (recordId) => {
                if (recordId === 'rec-001') {
                    return Promise.resolve({ recordHash: 'hash-original-001' });
                }
                if (recordId === 'rec-002') {
                    // The main-table hash was changed!
                    return Promise.resolve({ recordHash: 'hash-TAMPERED-002' });
                }
                return Promise.resolve(null);
            },
        };

        const result = await appender.verifyChain(undefined, tamperedLoader);

        expect(result.valid).toBe(false);
        expect(result.brokenAt).toBe('rec-002');
        expect(result.errorCode).toBe('SIDE_TABLE_ROW_TAMPERED');
    });

    it('should detect main-table record deletion (SIDE_TABLE_ANCHOR_MISSING)', async () => {
        const appender = new InMemorySideTableAppender();

        await appender.append({
            recordId: 'rec-001',
            recordHash: 'hash-001',
            agentDid: AGENT_DID as DID,
            createdAt:
                '2026-05-05T10:00:00.000Z' as import('@coivitas/types').Timestamp,
        });
        await appender.append({
            recordId: 'rec-002',
            recordHash: 'hash-002',
            agentDid: AGENT_DID as DID,
            createdAt:
                '2026-05-05T10:01:00.000Z' as import('@coivitas/types').Timestamp,
        });

        // Mock main table loader: rec-002 has been deleted
        const deletedLoader: MainTableRecordLoader = {
            loadRecord: (recordId) => {
                if (recordId === 'rec-001') {
                    return Promise.resolve({ recordHash: 'hash-001' });
                }
                // rec-002 does not exist (deleted)
                return Promise.resolve(null);
            },
        };

        const result = await appender.verifyChain(undefined, deletedLoader);

        expect(result.valid).toBe(false);
        expect(result.brokenAt).toBe('rec-002');
        expect(result.errorCode).toBe('SIDE_TABLE_ANCHOR_MISSING');
    });

    it('should pass when main-table records match side-table snapshots', async () => {
        const appender = new InMemorySideTableAppender();

        await appender.append({
            recordId: 'rec-001',
            recordHash: 'hash-001',
            agentDid: AGENT_DID as DID,
            createdAt:
                '2026-05-05T10:00:00.000Z' as import('@coivitas/types').Timestamp,
        });
        await appender.append({
            recordId: 'rec-002',
            recordHash: 'hash-002',
            agentDid: AGENT_DID as DID,
            createdAt:
                '2026-05-05T10:01:00.000Z' as import('@coivitas/types').Timestamp,
        });

        // Mock main table loader: all hashes are correct
        const healthyLoader: MainTableRecordLoader = {
            loadRecord: (recordId) => {
                if (recordId === 'rec-001')
                    return Promise.resolve({ recordHash: 'hash-001' });
                if (recordId === 'rec-002')
                    return Promise.resolve({ recordHash: 'hash-002' });
                return Promise.resolve(null);
            },
        };

        const result = await appender.verifyChain(undefined, healthyLoader);
        expect(result.valid).toBe(true);
    });

    it('should still validate chain integrity even with main-table loader', async () => {
        const appender = new InMemorySideTableAppender();

        await appender.append({
            recordId: 'rec-001',
            recordHash: 'hash-001',
            agentDid: AGENT_DID as DID,
            createdAt:
                '2026-05-05T10:00:00.000Z' as import('@coivitas/types').Timestamp,
        });
        await appender.append({
            recordId: 'rec-002',
            recordHash: 'hash-002',
            agentDid: AGENT_DID as DID,
            createdAt:
                '2026-05-05T10:01:00.000Z' as import('@coivitas/types').Timestamp,
        });

        // Tamper with the side-table's internal prevRowHash (simulating the side-table itself being tampered with)
        appender._tamperPrevRowHash('rec-002', 'tampered-prev');

        // The main table loader returns correct hashes (but the side-table's own chain is broken)
        const healthyLoader: MainTableRecordLoader = {
            loadRecord: (recordId) => {
                if (recordId === 'rec-001')
                    return Promise.resolve({ recordHash: 'hash-001' });
                if (recordId === 'rec-002')
                    return Promise.resolve({ recordHash: 'hash-002' });
                return Promise.resolve(null);
            },
        };

        const result = await appender.verifyChain(undefined, healthyLoader);
        expect(result.valid).toBe(false);
        expect(result.errorCode).toBe('SIDE_TABLE_ANCHOR_MISMATCH');
    });

    it('should work without main-table loader (backward compatible)', async () => {
        const appender = new InMemorySideTableAppender();

        await appender.append({
            recordId: 'rec-001',
            recordHash: 'hash-001',
            agentDid: AGENT_DID as DID,
            createdAt:
                '2026-05-05T10:00:00.000Z' as import('@coivitas/types').Timestamp,
        });

        // No loader passed -> verify chain integrity only, no cross-table comparison
        const result = await appender.verifyChain();
        expect(result.valid).toBe(true);
    });
});

// ---------------------------------------------------------------------------
// Scenario 3: createGovernorLaneRuntime() throws when durable deps missing
// ---------------------------------------------------------------------------

// This group of tests covers the interface contract (types.ts + factory.ts durable deps required);
// the durable Postgres runtime implementation is follow-up work.
// The factory is already marked RUNTIME_DEFERRED, callable only in the test environment.
describe('createGovernorLaneRuntime factory durability enforcement', () => {
    const mockControlPlaneRecorder = {
        kind: 'control-plane' as const,
        record: () => Promise.resolve({ recordId: 'test', hash: 'test' }),
        query: () =>
            Promise.resolve({
                records: [] as never[],
                nextCursor: undefined,
            }),
        ledgerPublicKey: 'mock-pub-key',
        dbPool: {} as never,
    };

    it('should throw when durableArbitrationStore is missing (fail-closed)', () => {
        expect(() =>
            createGovernorLaneRuntime({
                controlPlaneRecorder: mockControlPlaneRecorder as never,
                sessionOwnerResolver: new InMemorySessionOwnerResolver(),
                governorPrivateKey: 'a'.repeat(64),
                durableArbitrationStore: undefined as never,
                durableSideTableAppender: new InMemorySideTableAppender(),
            }),
        ).toThrow('durable arbitration');
    });

    it('should throw when durableSideTableAppender is missing (fail-closed)', () => {
        expect(() =>
            createGovernorLaneRuntime({
                controlPlaneRecorder: mockControlPlaneRecorder as never,
                sessionOwnerResolver: new InMemorySessionOwnerResolver(),
                governorPrivateKey: 'a'.repeat(64),
                durableArbitrationStore:
                    new InMemoryOperatorArbitrationStateMachine(),
                durableSideTableAppender: undefined as never,
            }),
        ).toThrow('durable arbitration');
    });

    it('should succeed when all durable deps are provided', () => {
        const runtime = createGovernorLaneRuntime({
            controlPlaneRecorder: mockControlPlaneRecorder as never,
            sessionOwnerResolver: new InMemorySessionOwnerResolver(),
            governorPrivateKey: 'a'.repeat(64),
            durableArbitrationStore:
                new InMemoryOperatorArbitrationStateMachine(),
            durableSideTableAppender: new InMemorySideTableAppender(),
        });

        expect(runtime.arbitration).toBeDefined();
        expect(runtime.sideTable).toBeDefined();
        expect(runtime.sessionOwnerResolver).toBeDefined();
        expect(runtime.assertSchemaCompliant).toBeDefined();
    });

    it('should use the injected durable instances (not create internal InMemory)', () => {
        const arb = new InMemoryOperatorArbitrationStateMachine();
        const st = new InMemorySideTableAppender();

        const runtime = createGovernorLaneRuntime({
            controlPlaneRecorder: mockControlPlaneRecorder as never,
            sessionOwnerResolver: new InMemorySessionOwnerResolver(),
            governorPrivateKey: 'a'.repeat(64),
            durableArbitrationStore: arb,
            durableSideTableAppender: st,
        });

        // Verify these are the injected instances, not ones newly created inside the factory
        expect(runtime.arbitration).toBe(arb);
        expect(runtime.sideTable).toBe(st);
    });
});
