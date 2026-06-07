/**
 * @coivitas/communication — L4 communication layer
 *
 */

// ─── Envelope module ────────────────────────────────────────────────────────────────
export {
    buildEnvelope,
    parseEnvelope,
    verifyEnvelope,
    encryptEnvelopeBody,
    decryptEnvelopeBody,
} from './envelope.js';
export type {
    BuildEnvelopeParams,
    EnvelopeVerificationResult,
    VerifyEnvelopeOptions,
    EncryptEnvelopeBodyParams,
    DecryptEnvelopeBodyParams,
} from './envelope.js';
export {
    buildAuthorizationInsufficientEnvelope,
    buildErrorEnvelope,
    buildIdentityVerificationFailedEnvelope,
    buildInternalErrorEnvelope,
    buildInvalidEnvelopeEnvelope,
    buildSessionNotFoundEnvelope,
} from './error-envelope.js';
export type {
    BuildErrorEnvelopeParams,
    ErrorEnvelopeBody,
    StandardErrorCode,
} from './error-envelope.js';

// ─── Handshake module ────────────────────────────────────────────────────────────────
export { HandshakeInitiator } from './handshake/initiator.js';
export { HandshakeResponder } from './handshake/responder.js';
export type {
    HandshakeAckBody,
    HandshakeChallenge,
    HandshakeInitBody,
    HandshakeInitiatorOptions,
    HandshakeResponderOptions,
    HandshakeResponse,
    HandshakeResult,
    InitiateParams,
    NonceStore,
} from './handshake/types.js';

// ─── Session management module ─────────────────────────────────────────────────────────────
export { InMemorySessionStore } from './session/in-memory-store.js';
export { PostgresSessionStore } from './session/postgres-store.js';
export { SessionManager } from './session/session-manager.js';
export type {
    // Persistent session contract
    Session,
    SessionManagerOptions,
    SessionState,
    CloseReason,
    EncryptionState,
    SessionCreateInput,
    SessionUpdatePatch,
    SessionListActiveFilter,
    SessionCleanResult,
    SessionResumeInput,
    SessionStore,
} from './session/types.js';

// ─── Transport layer ────────────────────────────────────
export type { EnvelopeHandler, Transport } from './transport/types.js';
export { HttpTransport } from './transport/http.js';
export type { HttpTransportOptions } from './transport/http.js';
export { WebSocketTransport } from './transport/websocket.js';
export type { WebSocketTransportOptions } from './transport/websocket.js';

// ─── mTLS transport (sdk v0.2) ────────────────
// Node built-in tls mTLS server/client + TLS 1.3 cipher suite enforcement + ALPN HTTP/2
export {
    DEFAULT_TLS_1_3_CIPHERS,
    connectMtlsClient,
    createMtlsContext,
    createMtlsServer,
    extractPeerCertDer,
} from './transport/mtls.js';
export type { MtlsOptions } from './transport/mtls.js';

// ─── sub-protocol L0 error → ProtocolError L3/L4 boundary wrapper
// 6 sub-protocol L0 errors (CrError/HashChainError/AuditShareError/AuditError/SrError/DaError)
// catch + unwrap + re-throw as ProtocolError('INTERNAL_ERROR', '${subCode}: ${msg}')
// boundary-leak mitigation
export {
    isSubProtocolL0Error,
    subProtocolErrorCode,
    wrapSubProtocolBoundary,
    wrapSubProtocolBoundarySync,
} from './transport/sub-protocol-boundary.js';
export type { SubProtocolL0Error } from './transport/sub-protocol-boundary.js';

// ─── 6 sub-protocol-specific boundary wrapper helpers (production wire) ────
// Real consumption points of the mandatory L3/L4 boundary wrapper production wire;
// each helper corresponds to one sub-protocol entry boundary; a production grep verifies ≥6 hits.
export {
    runAuditShareBoundary,
    runAuditTamperProofBoundary,
    runCredentialResolverBoundary,
    runDisputeArbitrationBoundary,
    runHashChainBoundary,
    runSettlementRetryBoundary,
} from './transport/sub-protocol-wrappers.js';

// ─── 6 sub-protocol-specific EnvelopeHandler decorators (transport boundary) ─
// Wrapped once when L4 transport.listen() registers the envelope handler;
// any sub-protocol L0 error that leaks to the L4 transport boundary is converted to a ProtocolError automatically.
export {
    withAuditShareHandler,
    withAuditTamperProofHandler,
    withCredentialResolverHandler,
    withDisputeArbitrationHandler,
    withHashChainHandler,
    withSettlementRetryHandler,
} from './transport/sub-protocol-handler-decorator.js';

// ─── Discovery layer module ───────────────────────────────────────────────────
export { buildAgentCard, verifyAgentCard } from './discovery/agent-card.js';
export type {
    BuildAgentCardParams,
    VerifyAgentCardParams,
} from './discovery/agent-card.js';
export { AgentCardService } from './discovery/agent-card-service.js';
export type { AgentCardServiceOptions } from './discovery/agent-card-service.js';
export { createAgentCardRoute } from './discovery/agent-card-routes.js';

// ─── Discovery layer module ───────────────────────────────────────────────────
export {
    InMemoryAgentCardCache,
    DefaultDiscoveryService,
} from './discovery/discovery-service.js';
export type { DefaultDiscoveryServiceOptions } from './discovery/discovery-service.js';

// ─── Discovery layer module ───────────────────────────────────────────────────
export {
    EnvelopeDiscoveryDispatcher,
    validateDiscoveryResponseBody,
} from './discovery/envelope-discovery.js';
export type {
    DiscoveryErrorCode,
    DiscoveryHandler,
    DiscoveryDispatcher,
    DiscoveryDispatcherOptions,
} from './discovery/envelope-discovery.js';

// ─── Transport abstraction layer ──────────────────────────────────────────────
export {
    DefaultHttpClient,
    RedirectBlockedError,
} from './transport/abstract-http-client.js';
export type {
    DNSRebindingGuard,
    LockedConnection,
    IHttpClient,
    FetchOptions,
    HttpResponse,
    DefaultHttpClientOptions,
} from './transport/abstract-http-client.js';

// ─── E2E encryption layer ────────────────────────────────────────
// SessionRegistryImpl: the 13-invariant registry
// SessionCryptoHandleImpl: the encryption handle (Inv 3/4/7/8/13)
export { SessionRegistryImpl } from './session-registry.js';
export { SessionCryptoHandleImpl } from './session/crypto-state.js';

// ─── MCP Bridge ────────────────
// types + server-adapter + cross-hop fail-closed guard
// Upcoming: holder binding lookup + envelope adapter + outbox + scope validator
export {
    MCP_ERROR,
    makeMcpError,
    MCPServerAdapter,
    defaultFallbackHandler,
    MCPCrossHopDeferredError,
    assertSameHop,
    checkSameHop,
} from './bridge/index.js';

// ─── trust-boundary primitive v0.1
// L4 communication layer lifecycle invariant + handshake integration
// Covers lease-only + state-machine firewall (emergency suspend v0.1 placeholder)
// Once the L0 types main declaration is complete, trust-boundary/types.ts will be switched to import from L0
export {
    LEGAL_TRANSITIONS as TB_LEGAL_TRANSITIONS,
    TB_DEFAULT_BOUNDS,
    TbProtocolError,
    toTbVersionString,
    toTrustBoundaryId,
    toUuidV4String as toTbUuidV4String,
    InMemoryTrustBoundaryStorage,
    TestProofVerifier as TestTbProofVerifier,
    TrustBoundaryLifecycleManager,
    assertInvariant as assertTbInvariant,
    createHandshakeBoundaryMiddleware,
} from './trust-boundary/index.js';
export type {
    BoundaryBindingProof,
    LeaseExtensionProof,
    TbErrorCode,
    TbVersionString,
    TransitionSource,
    TrustBoundary,
    TrustBoundaryAuditEvent,
    TrustBoundaryEmergencyEvent,
    TrustBoundaryEmergencyState,
    TrustBoundaryId,
    TrustBoundaryLifecycleEvent,
    TrustBoundaryState,
    UuidV4String as TbUuidV4String,
    BoundaryProofVerifier,
    TrustBoundaryStorage,
    HandshakeBoundaryContext,
    HandshakeBoundaryMiddleware,
} from './trust-boundary/index.js';
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
} from './bridge/index.js';
