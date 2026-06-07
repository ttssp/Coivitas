/**
 * createGovernorLaneRuntime factory unit tests.
 *
 * Coverage:
 * - happy path: durable dependencies injected -> returns a complete runtime
 * - missing controlPlaneRecorder -> throw
 * - missing sessionOwnerResolver -> throw
 * - missing governorPrivateKey -> throw
 * - missing durableArbitrationStore -> throw (fail-closed)
 * - missing durableSideTableAppender -> throw (fail-closed)
 * - runtime component type checks
 *
 */

import { describe, it, expect } from 'vitest';
import type { DID } from '@coivitas/types';

import { createGovernorLaneRuntime } from '../factory.js';
import type { GovernorLaneDurableDeps } from '../factory.js';
import { InMemorySessionOwnerResolver } from '../session-owner-resolver.js';
import { InMemoryOperatorArbitrationStateMachine } from '../arbitration.js';
import { InMemorySideTableAppender } from '../side-table.js';

// mock control-plane recorder (no real DB needed)
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

function makeDeps(
    overrides: Partial<GovernorLaneDurableDeps> = {},
): GovernorLaneDurableDeps {
    return {
        controlPlaneRecorder: mockControlPlaneRecorder as never,
        sessionOwnerResolver: new InMemorySessionOwnerResolver(),
        governorPrivateKey: 'a'.repeat(64),
        durableArbitrationStore: new InMemoryOperatorArbitrationStateMachine(),
        durableSideTableAppender: new InMemorySideTableAppender(),
        ...overrides,
    };
}

describe('createGovernorLaneRuntime', () => {
    it('should return GovernorLaneRuntime with all components when durable deps provided', () => {
        const runtime = createGovernorLaneRuntime(makeDeps());

        expect(runtime.arbitration).toBeDefined();
        expect(runtime.sideTable).toBeDefined();
        expect(runtime.sessionOwnerResolver).toBeDefined();
        expect(runtime.assertSchemaCompliant).toBeDefined();
        expect(typeof runtime.assertSchemaCompliant).toBe('function');
    });

    it('should throw when controlPlaneRecorder is missing', () => {
        expect(() =>
            createGovernorLaneRuntime({
                ...makeDeps(),
                controlPlaneRecorder: undefined as never,
            }),
        ).toThrow('controlPlaneRecorder');
    });

    it('should throw when sessionOwnerResolver is missing', () => {
        expect(() =>
            createGovernorLaneRuntime({
                ...makeDeps(),
                sessionOwnerResolver: undefined as never,
            }),
        ).toThrow('sessionOwnerResolver');
    });

    it('should throw when governorPrivateKey is empty', () => {
        expect(() =>
            createGovernorLaneRuntime({
                ...makeDeps(),
                governorPrivateKey: '',
            }),
        ).toThrow('governorPrivateKey');
    });

    it('should throw when durableArbitrationStore is missing (fail-closed)', () => {
        expect(() =>
            createGovernorLaneRuntime({
                ...makeDeps(),
                durableArbitrationStore: undefined as never,
            }),
        ).toThrow('durable arbitration');
    });

    it('should throw when durableSideTableAppender is missing (fail-closed)', () => {
        expect(() =>
            createGovernorLaneRuntime({
                ...makeDeps(),
                durableSideTableAppender: undefined as never,
            }),
        ).toThrow('durable arbitration');
    });

    it('should use injected durable arbitration store', () => {
        const arb = new InMemoryOperatorArbitrationStateMachine();
        const runtime = createGovernorLaneRuntime(
            makeDeps({ durableArbitrationStore: arb }),
        );

        // arbitration is the injected instance, not one newly created inside the factory
        expect(runtime.arbitration).toBe(arb);
    });

    it('should use injected durable side-table appender', () => {
        const st = new InMemorySideTableAppender();
        const runtime = createGovernorLaneRuntime(
            makeDeps({ durableSideTableAppender: st }),
        );

        expect(runtime.sideTable).toBe(st);
    });

    it('should use injected sessionOwnerResolver', async () => {
        const resolver = new InMemorySessionOwnerResolver();
        resolver.register('session-1', {
            agentDid: 'did:agent:test' as DID,
            principalDid: 'did:key:z6Mk...' as DID,
        });

        const runtime = createGovernorLaneRuntime(
            makeDeps({ sessionOwnerResolver: resolver }),
        );

        const owner =
            await runtime.sessionOwnerResolver.resolveOwner('session-1');
        expect(owner).not.toBeNull();
        expect(owner?.agentDid).toBe('did:agent:test');
    });

    it('should provide working assertSchemaCompliant', () => {
        const runtime = createGovernorLaneRuntime(makeDeps());

        // non-SESSION_SUPERSEDED -> does not throw
        runtime.assertSchemaCompliant({
            agentDid: 'did:agent:any',
            principalDid: 'did:key:any',
            actionType: 'INQUIRY',
            parametersSummary: null,
        });
    });
});
