export { buildCliProgram } from './cli/program.js';
export * from './key-custody/index.js';
export { Orchestrator } from './orchestrator.js';

// ── cryptographic-verifier module (sdk v0.2 L5 orchestrator; transport library) ─
// VerifierFactory + 3 verifier (mTLS/JWT/OAuth2) + boundary check + brand types + SdkError
export * from './cryptographic-verifier/index.js';
export {
    ManagedServiceClient,
    ManagedServiceError,
} from './managed-service-client.js';
export type {
    ManagedServiceClientConfig,
    ManagedServiceErrorCode,
    RevocationResult,
} from './managed-service-client.js';
export type {
    BusinessHandler,
    BusinessHandlerContext,
    DelegationChainValidator,
    OrchestratorConfig,
    OrchestratorHandleResult,
    OrchestratorLogger,
    TokenStoreReader,
} from './orchestrator.js';
export { runGoldenPath } from './golden-path/index.js';
export type {
    GoldenPathContext,
    GoldenPathOptions,
    GoldenPathResult,
} from './golden-path/context.js';
export { ScenarioRunner } from './scenario-runner.js';
export type {
    ScenarioFile,
    ScenarioRunResult,
    ScenarioStep,
} from './scenario-runner.js';

// ── revocation module (RevocationList SDK Client) ───────────────────────
export type {
    RevocationListPort,
    RevocationClientErrorCode,
    CheckRevokedRequest,
    CheckRevokedResult,
    RevokeCredentialRequest,
    RevokeCredentialResult,
    ListRevocationsRequest,
    ListRevocationsResult,
} from './revocation/index.js';

export {
    RevocationClientError,
    RevocationListClient,
    InMemoryRevocationPort,
} from './revocation/index.js';

export type { RevocationListClientConfig } from './revocation/index.js';

// ── SSO SDK API─────────────────────────────────────────────────────
export type {
    SSOClientErrorCode,
    SSOClientConfig,
    InitiateLoginRequest,
    InitiateLoginResult,
    ResolveAuthenticationRequest,
    ResolveAuthenticationResult,
    LogoutRequest,
    LogoutResult,
} from './sso/index.js';

export { SSOClient, SSOClientError } from './sso/index.js';

// ── FederationMappingAdminClient ──────────────────────────────────────
export type {
    FederationMappingPort,
    FederationMappingCreateInput,
    FederationMappingPatch,
    FederationMappingErrorCode,
    FederationMappingAdminClientConfig,
    ListMappingsRequest,
    ListMappingsResult,
    GetMappingRequest,
    CreateMappingRequest,
    UpdateMappingRequest,
    DeleteMappingRequest,
} from './admin-console/index.js';

export {
    FederationMappingError,
    InMemoryFederationMappingPort,
    FederationMappingAdminClient,
} from './admin-console/index.js';
