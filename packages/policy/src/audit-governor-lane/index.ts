/**
 * audit-governor-lane -- complete governor lane protocol module.
 *
 * Runtime implementation.
 *
 */

// Factory
export {
    createGovernorLaneRuntime,
    type GovernorLaneDurableDeps,
} from './factory.js';

// Types
export type {
    ArbitrationErrorCode,
    ArbitrationRequest,
    ArbitrationResult,
    ArbitrationVerdict,
    ArbitratedState,
    AssertSchemaCompliantInput,
    ControlPlaneRequesterScopeChecker,
    CrossOrgErrorCode,
    GovernorLaneDeps,
    GovernorLaneErrorCode,
    GovernorLaneRuntime,
    MainTableRecordLoader,
    MirrorProofErrorCode,
    OperatorArbitrationStateMachine,
    SessionOwnerResolver,
    SideTableAppender,
    SideTableEntry,
    SideTableErrorCode,
    SideTableVerifyResult,
} from './types.js';

// Operator arbitration state machine
// InMemory* is an @internal stub (RUNTIME_DEFERRED, completed); Postgres* is the production implementation
export {
    InMemoryOperatorArbitrationStateMachine,
    InMemoryOperatorArbitrationStateMachine as __stubInMemoryOperatorArbitrationStateMachine,
    PostgresOperatorArbitrationStateMachine,
} from './arbitration.js';

// Shadow audit side table
// InMemory* is an @internal stub (RUNTIME_DEFERRED, completed); Postgres* is the production implementation
export {
    InMemorySideTableAppender,
    InMemorySideTableAppender as __stubInMemorySideTableAppender,
    PostgresSideTableAppender,
    SIDE_TABLE_GENESIS_HASH,
    computeRowHash,
} from './side-table.js';

// SessionOwnerResolver
export {
    InMemorySessionOwnerResolver,
    assertSessionBinding,
} from './session-owner-resolver.js';

// assertSchemaCompliant
export { assertSchemaCompliant } from './assert-schema-compliant.js';

// control-plane routes
export {
    GovernorLaneScopeChecker,
    assertLaneDispatchConsistency,
    assertUnsignedHeadNotGovernor,
    isGovernorLaneTarget,
} from './control-plane-routes.js';
