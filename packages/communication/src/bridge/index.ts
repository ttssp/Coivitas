/**
 * MCP Bridge — public exports
 *
 * Module composition:
 * - types (MCPMessage / MCPCallParams / MCPCallerSubject / error registry / lifecycle interfaces)
 * - server-adapter (McpSdkServer + transport lifecycle)
 * - cross-hop fail-closed guard (placeholder + helper)
 * - holder-binding-resolver (bindingRevocationResolver
 *   mandatory path + 5s timeout fail-closed)
 * - envelope-adapter (same-hop only; narrows scope;
 *   literally does **not** mint a sub-token / sign a holderProof / forward an envelope; fail-closed)
 * - outbox-manager (IDOR defense — 4-step ownership check)
 *   + SQL migration 025_mcp_outbox.sql + 026_mcp_binding_revocations.sql
 * - scope-validator (single outer SERIALIZABLE transaction)
 *   + SQL migration 028_mcp_quota_counter.sql + 029_mcp_quota_idempotency.sql
 *   + 030_mcp_value_counter.sql + 031_mcp_value_idempotency.sql
 *
 * Later:
 * - full conformance test coverage
 */

// types
export { MCP_ERROR, makeMcpError } from './types.js';
export type {
    MCPClientId,
    MCPServerId,
    MCPMessage,
    MCPCallParams,
    MCPCallArguments,
    MCPCallerSubjectKind,
    MCPCallerSubject,
    MCPErrorCode,
    MCPBridgeError,
    MCPEnvelopeAdapter,
    MCPServerTransportMode,
    MCPServerConfig,
    MCPServerLifecycleState,
    MCPServerLifecycle,
    MCPToolHandler,
    MCPToolDescriptor,
} from './types.js';

// server adapter
export { MCPServerAdapter, defaultFallbackHandler } from './server-adapter.js';

// cross-hop fail-closed guard
export {
    MCPCrossHopDeferredError,
    assertSameHop,
    checkSameHop,
} from './cross-hop-guard.js';

// holder binding resolver
export {
    DEFAULT_REVOCATION_RESOLVER_TIMEOUT_MS,
    isResolutionError,
    resolutionErrorToMcpError,
    resolveSenderForMCPCall,
    withTimeout,
} from './holder-binding-resolver.js';
export type {
    BindingRevocationResolver,
    DidPublicKeyResolver,
    HolderBindingRegistry,
    MCPClientBinding,
    MCPSenderResolution,
    MCPSenderResolutionError,
    MCPSenderResolutionResult,
    ResolvedAgentKey,
    RevocationStatus,
} from './holder-binding-resolver.js';

// envelope adapter (same-hop only; narrows scope)
export {
    extractMCPCallParams,
    incomingMCPCallToEnvelope,
    MCPEnvelopeAdapterImpl,
    outgoingEnvelopeToMCPResponse,
    processSingleHopMCPCall,
} from './envelope-adapter.js';
export type {
    IncomingMCPCallContext,
    MCPCallEnvelopeBody,
} from './envelope-adapter.js';

// outbox manager (IDOR defense)
export {
    createOutboxRow,
    defaultMockChallengeResolver,
    getOutboxByID,
    PostgresOutboxStore,
} from './outbox-manager.js';
export type {
    CreateOutboxRowInput,
    GetOutboxByIDDeps,
    GetOutboxByIDInput,
    GetOutboxByIDResult,
    OutboxChallengeResolver,
    OutboxRow,
    OutboxStore,
    PoPSignatureVerifier,
    SubjectKeyResolver,
} from './outbox-manager.js';

// scope validator (single outer SERIALIZABLE transaction)
export {
    DEFAULT_SERIALIZABLE_RETRY_MAX,
    validateScope,
} from './scope-validator.js';
export type {
    ScopeClaim,
    ScopeValidatorDeps,
    ValidateScopeInput,
    ValidateScopeResult,
} from './scope-validator.js';
