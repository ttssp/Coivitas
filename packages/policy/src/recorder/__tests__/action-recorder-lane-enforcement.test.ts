/**
 * ActionRecorder Lane Enforcement unit tests
 *
 * Goal: prove that ActionRecorder.record() enforces isolation of the business plane vs. the control
 *       plane by kind at runtime, even when the discriminated-union type information is erased on the
 *       caller side (mock recorder / plain ActionRecorder injection).
 *
 * No database dependency — only calls record() to make assertLaneAllowed throw;
 * the real INSERT path is covered by the action-recorder.test.ts integration test.
 *
 * The control-plane ActionRecorder constructor requires sessionOwnerResolver + assertSchemaCompliant,
 * and the tests inject mock implementations to satisfy the constructor requirements.
 *
 * Defense goal: the ActionRecorder kind must enforce lane separation,
 *   preventing an illegal control-plane write from even being constructed.
 */

import { describe, expect, it } from 'vitest';

import type { DatabasePool } from '@coivitas/shared';
import { ProtocolError } from '@coivitas/types';
import {
    ACTION_SESSION_SUPERSEDED,
    SESSION_GOVERNOR_DID,
    type DID,
} from '@coivitas/types';

import { ActionRecorder } from '../action-recorder.js';

// 64-hex string: a ledger private key of valid length for tests (it will not actually sign)
const LEDGER_KEY_HEX = 'a'.repeat(64);

// dummy pool -- assertLaneAllowed throws before withTransaction,
// so the pool is never used.
const dummyPool = {} as unknown as DatabasePool;

// The control-plane constructor requires these two deps
const mockSessionOwnerResolver = {
    resolveOwner: () => Promise.resolve(null),
};
const mockAssertSchemaCompliant = () => {
    /* no-op for lane enforcement tests*/
};
// The control-plane constructor requires sideTableAppender
const mockSideTableAppender = {
    append: () => Promise.resolve({ rowHash: 'mock-row-hash' }),
    verifyChain: () => Promise.resolve({ valid: true as const }),
};

describe('ActionRecorder lane enforcement (kind=standard)', () => {
    const standard = new ActionRecorder(dummyPool, {
        kind: 'standard',
        ledgerPrivateKey: LEDGER_KEY_HEX,
    });

    it('rejects writes with agentDid === SESSION_GOVERNOR_DID', async () => {
        await expect(
            standard.record({
                agentDid: SESSION_GOVERNOR_DID as unknown as DID,
                principalDid: 'did:key:agent-x' as DID,
                actionType: 'INQUIRY',
                actorPrivateKey: LEDGER_KEY_HEX,
            }),
        ).rejects.toThrowError(ProtocolError);
    });

    it('rejects writes with principalDid === SESSION_GOVERNOR_DID', async () => {
        await expect(
            standard.record({
                agentDid: 'did:key:agent-x' as DID,
                principalDid: SESSION_GOVERNOR_DID as unknown as DID,
                actionType: 'INQUIRY',
                actorPrivateKey: LEDGER_KEY_HEX,
            }),
        ).rejects.toThrowError(ProtocolError);
    });

    it('rejects writes with actionType === SESSION_SUPERSEDED', async () => {
        await expect(
            standard.record({
                agentDid: 'did:key:agent-x' as DID,
                principalDid: 'did:key:principal-x' as DID,
                actionType: ACTION_SESSION_SUPERSEDED,
                actorPrivateKey: LEDGER_KEY_HEX,
            }),
        ).rejects.toThrowError(ProtocolError);
    });

    it('error message includes diagnostic context for caller debugging', async () => {
        try {
            await standard.record({
                agentDid: SESSION_GOVERNOR_DID as unknown as DID,
                principalDid: SESSION_GOVERNOR_DID as unknown as DID,
                actionType: ACTION_SESSION_SUPERSEDED,
                actorPrivateKey: LEDGER_KEY_HEX,
            });
            expect.fail(
                'standard recorder must not accept SESSION_SUPERSEDED writes',
            );
        } catch (err) {
            expect(err).toBeInstanceOf(ProtocolError);
            const message = (err as ProtocolError).message;
            expect(message).toContain("kind='standard'");
            expect(message).toContain('control-plane');
            expect(message).toContain(ACTION_SESSION_SUPERSEDED);
        }
    });
});

describe('ActionRecorder lane enforcement (kind=control-plane)', () => {
    const cp = new ActionRecorder(dummyPool, {
        kind: 'control-plane',
        ledgerPrivateKey: LEDGER_KEY_HEX,
        sessionOwnerResolver: mockSessionOwnerResolver,
        assertSchemaCompliant: mockAssertSchemaCompliant,
        sideTableAppender: mockSideTableAppender,
    });

    it('rejects business-actor writes (agentDid !== SESSION_GOVERNOR_DID)', async () => {
        await expect(
            cp.record({
                agentDid: 'did:key:agent-x' as DID,
                principalDid: SESSION_GOVERNOR_DID as unknown as DID,
                actionType: ACTION_SESSION_SUPERSEDED,
                actorPrivateKey: LEDGER_KEY_HEX,
            }),
        ).rejects.toThrowError(ProtocolError);
    });

    it('rejects mismatched principal (principalDid !== SESSION_GOVERNOR_DID)', async () => {
        await expect(
            cp.record({
                agentDid: SESSION_GOVERNOR_DID as unknown as DID,
                principalDid: 'did:key:principal-x' as DID,
                actionType: ACTION_SESSION_SUPERSEDED,
                actorPrivateKey: LEDGER_KEY_HEX,
            }),
        ).rejects.toThrowError(ProtocolError);
    });

    it('rejects business action types even with governor DID', async () => {
        await expect(
            cp.record({
                agentDid: SESSION_GOVERNOR_DID as unknown as DID,
                principalDid: SESSION_GOVERNOR_DID as unknown as DID,
                actionType: 'INQUIRY',
                actorPrivateKey: LEDGER_KEY_HEX,
            }),
        ).rejects.toThrowError(ProtocolError);
    });

    it('error message includes diagnostic context', async () => {
        try {
            await cp.record({
                agentDid: 'did:key:agent-x' as DID,
                principalDid: 'did:key:principal-x' as DID,
                actionType: 'INQUIRY',
                actorPrivateKey: LEDGER_KEY_HEX,
            });
            expect.fail(
                'control-plane recorder must not accept business writes',
            );
        } catch (err) {
            expect(err).toBeInstanceOf(ProtocolError);
            const message = (err as ProtocolError).message;
            expect(message).toContain("kind='control-plane'");
            expect(message).toContain('SESSION_SUPERSEDED');
        }
    });
});

describe('ActionRecorder control-plane constructor enforces deps', () => {
    it('throws when sessionOwnerResolver is missing', () => {
        expect(
            () =>
                new ActionRecorder(dummyPool, {
                    kind: 'control-plane',
                    ledgerPrivateKey: LEDGER_KEY_HEX,
                    sessionOwnerResolver: undefined as never,
                    assertSchemaCompliant: mockAssertSchemaCompliant,
                    sideTableAppender: mockSideTableAppender,
                }),
        ).toThrow(/sessionOwnerResolver/);
    });

    it('throws when assertSchemaCompliant is missing', () => {
        expect(
            () =>
                new ActionRecorder(dummyPool, {
                    kind: 'control-plane',
                    ledgerPrivateKey: LEDGER_KEY_HEX,
                    sessionOwnerResolver: mockSessionOwnerResolver,
                    assertSchemaCompliant: undefined as never,
                    sideTableAppender: mockSideTableAppender,
                }),
        ).toThrow(/assertSchemaCompliant/);
    });

    it('throws when sideTableAppender is missing', () => {
        expect(
            () =>
                new ActionRecorder(dummyPool, {
                    kind: 'control-plane',
                    ledgerPrivateKey: LEDGER_KEY_HEX,
                    sessionOwnerResolver: mockSessionOwnerResolver,
                    assertSchemaCompliant: mockAssertSchemaCompliant,
                    sideTableAppender: undefined as never,
                }),
        ).toThrow(/sideTableAppender/);
    });
});

describe('SessionSupersedeRecorder constructor enforces control-plane recorder', () => {
    it('throws when injected ActionRecorder is kind=standard (regression test)', async () => {
        const { SessionSupersedeRecorder } =
            await import('../session-supersede-recorder.js');
        const standard = new ActionRecorder(dummyPool, {
            kind: 'standard',
            ledgerPrivateKey: LEDGER_KEY_HEX,
        });
        // Test the runtime check: ts-expect-error simulates a caller using an unsafe cast to bypass the type layer
        expect(
            () =>
                new SessionSupersedeRecorder(
                    // @ts-expect-error: intentionally pass a standard recorder to verify the runtime throw
                    standard,
                    LEDGER_KEY_HEX,
                ),
        ).toThrow(/control-plane/i);
    });

    it('accepts injected ActionRecorder when kind=control-plane', async () => {
        const { SessionSupersedeRecorder } =
            await import('../session-supersede-recorder.js');
        const { assertIsControlPlaneRecorder } =
            await import('../action-recorder.js');
        const cp = new ActionRecorder(dummyPool, {
            kind: 'control-plane',
            ledgerPrivateKey: LEDGER_KEY_HEX,
            sessionOwnerResolver: mockSessionOwnerResolver,
            assertSchemaCompliant: mockAssertSchemaCompliant,
            sideTableAppender: mockSideTableAppender,
        });
        expect(() => {
            assertIsControlPlaneRecorder(cp);
            return new SessionSupersedeRecorder(cp, LEDGER_KEY_HEX);
        }).not.toThrow();
    });
});

describe('ActionRecorder control-plane SESSION_SUPERSEDED schema enforcement', () => {
    const cp = new ActionRecorder(dummyPool, {
        kind: 'control-plane',
        ledgerPrivateKey: LEDGER_KEY_HEX,
        sessionOwnerResolver: mockSessionOwnerResolver,
        assertSchemaCompliant: mockAssertSchemaCompliant,
        sideTableAppender: mockSideTableAppender,
    });

    const baseInput = {
        agentDid: SESSION_GOVERNOR_DID as unknown as DID,
        principalDid: SESSION_GOVERNOR_DID as unknown as DID,
        actionType: ACTION_SESSION_SUPERSEDED,
        actorPrivateKey: LEDGER_KEY_HEX,
    };

    it('rejects SESSION_SUPERSEDED with no parametersSummary', async () => {
        await expect(cp.record(baseInput)).rejects.toThrowError(
            /parametersSummary/,
        );
    });

    it('rejects SESSION_SUPERSEDED missing affectedAgentDid', async () => {
        await expect(
            cp.record({
                ...baseInput,
                parametersSummary: {
                    oldSessionId: 'old-1',
                    reason: 'EXPLICIT_CLOSE',
                    timestamp: '2026-05-05T00:00:00.000Z',
                    affectedPrincipalDid: 'did:key:zPrincipal',
                },
            }),
        ).rejects.toThrowError(/affectedAgentDid/);
    });

    it('rejects SESSION_SUPERSEDED missing affectedPrincipalDid', async () => {
        await expect(
            cp.record({
                ...baseInput,
                parametersSummary: {
                    oldSessionId: 'old-1',
                    reason: 'EXPLICIT_CLOSE',
                    timestamp: '2026-05-05T00:00:00.000Z',
                    affectedAgentDid: 'did:agent:abc',
                },
            }),
        ).rejects.toThrowError(/affectedPrincipalDid/);
    });

    it('rejects SESSION_SUPERSEDED with empty-string required field', async () => {
        await expect(
            cp.record({
                ...baseInput,
                parametersSummary: {
                    oldSessionId: '',
                    reason: 'EXPLICIT_CLOSE',
                    timestamp: '2026-05-05T00:00:00.000Z',
                    affectedAgentDid: 'did:agent:abc',
                    affectedPrincipalDid: 'did:key:zP',
                },
            }),
        ).rejects.toThrowError(/oldSessionId/);
    });
});
