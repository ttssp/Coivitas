/**
 * factory.ts -- governor lane runtime factory.
 *
 * @warning RUNTIME_DEFERRED
 * ============================================================
 * createGovernorLaneRuntime() in this file is a TEST-ONLY factory.
 *
 * Current status:
 *   - In this repository, the only implementors of OperatorArbitrationStateMachine /
 *     SideTableAppender are the InMemory* stubs (in-memory state, lost on restart).
 *   - Every caller of this factory in the repository lives under __tests__/, with zero
 *     production callers.
 *   - Production deployment must wait for the durable PostgresSideTableAppender +
 *     PostgresOperatorArbitrationStateMachine implementations to land.
 *   - The production-path SideTableAppender injection point has migrated to the
 *     ActionRecorder(kind='control-plane') constructor required field
 *     `sideTableAppender`.
 *
 * If you are reading this comment and attempting to call createGovernorLaneRuntime in
 * production code: instead use the injection pattern that injects SideTableAppender
 * directly into the ActionRecorder constructor.
 *
 * Calling it outside a test environment throws fail-closed.
 * ============================================================
 *
 * Durability dependency enforcement patch:
 *   Removes the InMemory default fallback. The factory no longer creates InMemory* instances
 *   internally. Callers must explicitly inject durableArbitrationStore + durableSideTableAppender.
 *   Throws fail-closed when they are missing.
 *   The InMemory implementations remain usable but only as test fixtures (marked @internal).
 *
 * @internal Test-only factory.
 *
 */

import type {
    GovernorLaneDeps,
    GovernorLaneRuntime,
    OperatorArbitrationStateMachine,
    SideTableAppender,
} from './types.js';
import { assertSchemaCompliant } from './assert-schema-compliant.js';

/**
 * GovernorLaneDeps extension: durable deps are required.
 *
 * New fields:
 * - durableArbitrationStore: durable operator arbitration state machine (required)
 * - durableSideTableAppender: durable side-table appender (required)
 */
export interface GovernorLaneDurableDeps extends GovernorLaneDeps {
    /**
     * Durable operator arbitration state machine instance.
     * The InMemory version is only allowed in test fixtures.
     * The factory throws fail-closed when it is missing.
     */
    durableArbitrationStore: OperatorArbitrationStateMachine;

    /**
     * Durable side-table append-only appender.
     * The InMemory version is only allowed in test fixtures.
     * The factory throws fail-closed when it is missing.
     */
    durableSideTableAppender: SideTableAppender;
}

/**
 * Creates the complete governor lane runtime.
 *
 * It no longer uses InMemory components by default.
 * Callers must inject durable arbitration + side-table implementations.
 * Throws fail-closed when they are missing (the process must not start the governor lane
 * without a durability guarantee).
 *
 * @param deps dependency injection (including durable persistence components)
 * @returns GovernorLaneRuntime the complete component set
 * @throws Error when durable dependencies are missing (fail-closed)
 */
export function createGovernorLaneRuntime(
    deps: GovernorLaneDurableDeps,
): GovernorLaneRuntime {
    // RUNTIME_DEFERRED guard: fail-closed outside a test environment (production calls are forbidden until the durable implementations land)
    if (
        process.env.NODE_ENV !== 'test' &&
        process.env.COIVITAS_GOVERNOR_RUNTIME_TESTONLY !== 'true'
    ) {
        throw new Error(
            'createGovernorLaneRuntime is not wired for production use; ' +
                'production path must inject SideTableAppender directly into ' +
                "ActionRecorder(kind='control-plane'). " +
                'Set NODE_ENV=test or COIVITAS_GOVERNOR_RUNTIME_TESTONLY=true ' +
                'to use this factory in test fixtures.',
        );
    }

    // Validate required dependencies
    if (!deps.controlPlaneRecorder) {
        throw new Error(
            'createGovernorLaneRuntime: controlPlaneRecorder is required',
        );
    }
    if (!deps.sessionOwnerResolver) {
        throw new Error(
            'createGovernorLaneRuntime: sessionOwnerResolver is required',
        );
    }
    if (!deps.governorPrivateKey || deps.governorPrivateKey.length === 0) {
        throw new Error(
            'createGovernorLaneRuntime: governorPrivateKey is required (non-empty)',
        );
    }

    // durable deps are required (fail-closed)
    if (!deps.durableArbitrationStore) {
        throw new Error(
            'createGovernorLaneRuntime requires durable arbitration + side-table dependencies ' +
                '(in-memory only allowed in test fixtures). ' +
                'durableArbitrationStore is missing. ' +
                '(factory durability requirement; fail-closed).',
        );
    }
    if (!deps.durableSideTableAppender) {
        throw new Error(
            'createGovernorLaneRuntime requires durable arbitration + side-table dependencies ' +
                '(in-memory only allowed in test fixtures). ' +
                'durableSideTableAppender is missing. ' +
                '(factory durability requirement; fail-closed).',
        );
    }

    return {
        arbitration: deps.durableArbitrationStore,
        sideTable: deps.durableSideTableAppender,
        sessionOwnerResolver: deps.sessionOwnerResolver,
        assertSchemaCompliant,
    };
}
