export {
    ActionRecorder,
    type ActionRecorderOptions,
    type ControlPlaneActionRecorder,
    assertIsControlPlaneRecorder,
} from './recorder/action-recorder.js';
export {
    IntegrityChecker,
    type IntegrityCheckerOptions,
} from './recorder/integrity-checker.js';
export { PolicyEngine } from './engine.js';
export type { PolicyRecorder } from './engine.js';
export { HumanCheckpoint } from './guard/human-checkpoint.js';
export { RuntimeGuard } from './guard/runtime-guard.js';
export {
    ScopeEvaluator,
    evaluateScope,
    evaluateTemporalScope,
} from './guard/scope-evaluator.js';
export { PostgresCumulativeTracker } from './guard/postgres-cumulative-tracker.js';
export {
    computeWindowStart,
    METER_FIELD_REGISTRY,
} from './guard/cumulative-tracker.js';
export type {
    CumulativeTracker,
    MeterFieldEntry,
} from './guard/cumulative-tracker.js';
export { TokenStore } from './guard/token-store.js';

// ScopeEvaluator plugin registry
export {
    BUILT_IN_SCOPE_TYPES,
    ScopeEvaluatorRegistry,
    createIsolatedRegistry,
    globalScopeEvaluatorRegistry,
} from './scope/scope-evaluator-registry.js';
export type { RegisterOptions } from './scope/scope-evaluator-registry.js';
export type {
    ActionRecordInput,
    ActionRecordQueryFilters,
    ExecuteWithPolicyResult,
    IntegrityCheckResult,
    PersistedActionRecord,
    RecordWriteResult,
    ResolveAgentPublicKey,
    ResolveControlPlanePublicKey,
} from './types.js';

// Audit access model
export type {
    ActionVocabulary,
    AuditAccessChecker,
    AuditAccessDecision,
    AuditAccessErrorCode,
    AuditIdentityResolution,
    AuditQueryParams,
    AuditResourceBinding,
    AuditSnapshotBoundary,
    IdentityStoreForAudit,
    SignedAuditQuery,
    VerifiedAuditRequest,
    // Added in v0.2
    AuditProofType,
    DelegatedAuditKey,
    DelegatedAuditKeyResolver,
    AuditEventRecord,
} from './audit/types.js';

// Record query API
// audit-access-model v0.2 governor lane minimal subset
export {
    registerActionRecordRoutes,
    PrincipalAuditAccessChecker,
    ControlPlaneAuditAccessChecker,
    type ControlPlaneAuditResolver,
    type RegisterActionRecordRoutesOptions,
} from './recorder/action-record-routes.js';

// audit-access-model v0.2 business lane middleware factory
export {
    createAuditAccessMiddleware,
    InMemoryAuditNonceStore,
    NullDelegatedAuditKeyResolver,
    NullAuditMetaLedger,
    type AuditNonceStore,
    type AuditMetaLedger,
    type AuditMetaLedgerEvent,
    type ActionRecordReader,
    type SnapshotAnchorResult,
    type AuditAccessMiddlewareOptions,
} from './recorder/audit-access-routes.js';

// SESSION_SUPERSEDED control-plane event writer
export {
    SessionSupersedeRecorder,
    getSessionSupersedeTotal,
    getSessionCloseTotal,
    _resetMetricsForTest,
    type SessionSupersedeRecordInput,
} from './recorder/session-supersede-recorder.js';

// audit-before-execute barrier
export {
    AuditBarrier,
    _resetHappensBeforeForTest,
    _resetIntentStatesForTest,
    type AuditBarrierRecord,
    type AuditBarrierOutcome,
} from './recorder/audit-barrier.js';

// Cross-trust-domain cumulative settle protocol (production implementation)
export {
    PendingReaper,
    RecipientSettleHandler,
    SenderSettleTracker,
    buildSettlePayload,
    dropDomainSchema,
    initDomainSchema,
    DEFAULT_CONFIG as SETTLE_DEFAULT_CONFIG,
    toISOString as settleToISOString,
} from './cross-domain-settle/index.js';
export type {
    CursorRow,
    ReconciliationCursor,
    ReconciliationResult,
    SettleProtocolConfig,
    SettleRecord,
    SettleRequest,
    SettleRow,
    SettleState,
} from './cross-domain-settle/index.js';
// EnvelopeLedger 4-state ledger
export {
    EnvelopeLedger,
    type EnvelopeLedgerOptions,
    LEDGER_CLAIM_STATUSES,
    isLedgerClaimStatus,
    parseLedgerClaimStatus,
    type LedgerClaimStatus,
    type EnvelopeLedgerEntry,
    type ClaimResult,
    type ClaimSuccess,
    type ClaimConflict,
    type ClaimConflictReason,
    type FinalizeResult,
    type FinalizeSuccess,
    type FinalizeFailure,
    type FinalizeFailureReason,
    type RejectResult,
    type RejectSuccess,
    type RejectFailure,
    type RejectFailureReason,
    type ExpireResult,
} from './envelope-ledger/index.js';

// Policy change audit middleware
export {
    PolicyChangeRecorder,
    type PolicyRecordInput,
    type PolicyRecordWriteResult,
    type WrapOperationOptions,
} from './middleware/policy-change-recorder.js';

// policy_change_records standalone read path
export {
    registerPolicyChangeRecordRoutes,
    type RegisterPolicyChangeRecordRoutesOptions,
} from './middleware/policy-change-record-routes.js';

// External witness evaluator stub (fail-closed; implemented)
export {
    MetricSourceNotImplemented,
    createExternalWitnessEvaluator,
    registerExternalWitnessEvaluator,
} from './scope/external-witness-evaluator.js';
export type { ExternalWitnessEvaluator } from './scope/external-witness-evaluator.js';

// Governor lane complete protocol module
// InMemory* implementations are @internal stubs.
// Production callers should use the __stub*-prefixed exports to make the stub nature explicit.
export {
    // Factory (@internal test-only)
    createGovernorLaneRuntime,
    // Operator arbitration state machine (InMemory* = @internal stub; Postgres* = production implementation)
    InMemoryOperatorArbitrationStateMachine,
    __stubInMemoryOperatorArbitrationStateMachine,
    PostgresOperatorArbitrationStateMachine,
    // Shadow-audit side table (InMemory* = @internal stub; Postgres* = production implementation)
    InMemorySideTableAppender,
    __stubInMemorySideTableAppender,
    PostgresSideTableAppender,
    SIDE_TABLE_GENESIS_HASH,
    computeRowHash,
    // SessionOwnerResolver
    InMemorySessionOwnerResolver,
    assertSessionBinding,
    // assertSchemaCompliant
    assertSchemaCompliant,
    // control-plane routing
    GovernorLaneScopeChecker,
    assertLaneDispatchConsistency,
    assertUnsignedHeadNotGovernor,
    isGovernorLaneTarget,
} from './audit-governor-lane/index.js';
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
    GovernorLaneDurableDeps,
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
} from './audit-governor-lane/index.js';

// dispute-arbitration v0.1 L3 state machine
// Three-layer enforcement: the algorithm-layer computeThreshold() lives here
export {
    validateStateTransition,
    computeThreshold,
    checkAndExpireDispute,
    computeDisputeFilingCanonicalHash,
    runDisputeArbitration7Steps,
    runDisputeExpiry,
} from './dispute-arbitration/index.js';
export type {
    MultisigPort,
    ArbitratorSelector,
    EvidenceStore,
    RevocationChecker,
    SignatureVerifier,
    AtpRecorder,
    DisputeStore,
    DisputeArbitrationInput,
    DisputeArbitrationResult,
} from './dispute-arbitration/index.js';

// audit-share v0.2 L3 manager
// 11-step fail-closed verifyAuditRequest + 6 DI ports
// AuditEventStore has the same name as in atp v0.1; audit-share uses the alias AuditShareEventStore to avoid conflicts.
export {
    AuditShareManager,
    type AuditShareManagerDeps,
    type AuditShareDelegatedKeyStore,
    type TenantAuditSharePolicyStore,
    type AuditEventStore as AuditShareEventStore,
    type HashChainVerifier,
    type ChallengeStore,
} from './audit-share/index.js';

// RevocationList full implementation (closes out the earlier stub)
export {
    RevocationApi,
    RevocationCache,
    RevocationListStore,
    createRevocationApi,
    REVOCATION_REASONS,
    isRevocationReason,
    parseRevocationReason,
} from './revocation/index.js';
export type {
    RevocationApiOptions,
    RevocationCacheOptions,
    RevocationListStoreOptions,
    IssuerSignaturePayload,
    RevocationCheckResult,
    RevocationErrorCode,
    RevocationFound,
    RevocationNotFound,
    RevocationQueryFilters,
    RevocationReason,
    RevocationRecord,
    RevocationWriteFailure,
    RevocationWriteInput,
    RevocationWriteResult,
    RevocationWriteSuccess,
} from './revocation/index.js';

// Audit Tamper-Proof (atp) v0.1
// fail-closed verification primitive (5 counterexample defenses);
// multi-tenant isolation; all 10 fields participate in the binding hash.
export {
    canonicalizeAuditPayload,
    buildTamperProofHashInput,
    InMemoryTenantResolver,
    assertDbRoleMatchesAuditClass,
    assertTenantScope,
    TamperProofAuditWriter,
    TamperProofAuditVerifier,
    InMemoryAuditEventStore,
    type TamperProofHashInputFields,
    type CallerPrincipal,
    type TenantResolver,
    type AuditEventStore,
    type WriteAuditEventInput,
    type WriteAuditEventOptions,
    type VerifyAuditEventOptions,
    type VerifyAuditEventResult,
} from './audit-tamper-proof/index.js';
