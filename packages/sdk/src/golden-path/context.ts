import type { DatabasePool } from '@coivitas/shared';
import type {
    AgentCard,
    AgentIdentityDocument,
    CapabilityToken,
    DID,
    KeyRotationState,
    Timestamp,
} from '@coivitas/types';
import type {
    HandshakeResult,
    HttpTransport,
} from '@coivitas/communication';
import type { SessionRegistryImpl } from '@coivitas/communication';
import type {
    ActionRecorder,
    AuditBarrier,
    IntegrityChecker,
    PolicyEngine,
    RuntimeGuard,
    SessionSupersedeRecorder,
    TokenStore,
} from '@coivitas/policy';
import type {
    IdentityRegistry,
    RevocationList,
} from '@coivitas/identity';
import type { Orchestrator } from '../orchestrator.js';

export interface KeyPair {
    publicKey: string;
    privateKey: string;
}

export interface GoldenPathOptions {
    pool: DatabasePool;
    identityRegistryUrl?: string;
    ledgerPrivateKey?: string;
    /** (F1-twenty): governor public key (hex). If provided, IntegrityChecker can verify the
     *  SESSION_SUPERSEDED record; when omitted it is fail-closed (a governor record is treated as invalid).
*/
    governorPublicKey?: string;
    /** governor private key (hex); if governorPublicKey is set to an independent control-plane key (production model),
     *  Step 32 SessionSupersedeRecorder must sign the SESSION_SUPERSEDED record with the corresponding private key, otherwise
     *  IntegrityChecker.verifyIntegrity(SESSION_GOVERNOR_DID) rejects it as actor_signature invalid.
     *  When omitted, Step 32 falls back to ledgerPrivateKey (only suitable for the "governor and ledger share a key" development deployment).
     */
    governorPrivateKey?: string;
    verbose?: boolean;
}

export interface GoldenPathContext {
    pool: DatabasePool;
    identityRegistryUrl: string;
    ledgerPrivateKey: string;
    /** (F1-twenty): governor public key (hex); undefined means no governor record is expected.*/
    governorPublicKey?: string;
    /** Step 32 SessionSupersedeRecorder uses this private key to sign the SESSION_SUPERSEDED record.
     *  See the GoldenPathOptions.governorPrivateKey comment for details.
*/
    governorPrivateKey?: string;
    verbose: boolean;
    cleanups: Array<() => Promise<void>>;
    ownPool: boolean;

    identityRegistry?: IdentityRegistry;
    revocationList?: RevocationList;

    aliceKeyPair?: KeyPair;
    bobKeyPair?: KeyPair;
    aliceDid?: DID;
    bobDid?: DID;

    agentADid?: DID;
    agentAPrivateKey?: string;
    agentADocument?: AgentIdentityDocument;

    agentBDid?: DID;
    agentBPrivateKey?: string;
    agentBDocument?: AgentIdentityDocument;

    tokenA?: CapabilityToken;
    tokenB?: CapabilityToken;

    tokenStoreA?: TokenStore;
    tokenStoreB?: TokenStore;
    guardA?: RuntimeGuard;
    guardB?: RuntimeGuard;
    recorderA?: ActionRecorder;
    recorderB?: ActionRecorder;
    integrityCheckerA?: IntegrityChecker;
    integrityCheckerB?: IntegrityChecker;
    policyEngineA?: PolicyEngine;
    policyEngineB?: PolicyEngine;
    orchestratorA?: Orchestrator;
    orchestratorB?: Orchestrator;

    transportA?: HttpTransport;
    transportB?: HttpTransport;
    responderPort?: number;
    handshake?: HandshakeResult;
    sessionId?: string;
    negotiatedCapabilities?: string[];

    inquiryRequestId?: string;
    quoteRequestId?: string;
    confirmRequestId?: string;

    inquiryResponseBody?: Record<string, unknown>;
    confirmResponseBody?: Record<string, unknown>;

    recordIdA?: string;
    recordIdB?: string;

    revokedAt?: Timestamp;

    // ── Extensions (Step 16-25) ─────────────────────────────────────────────────
    // Step 16-17: AgentCard publication and discovery
    agentACard?: AgentCard;
    agentACardUrl?: string;
    discoveredAgentACard?: AgentCard;

    // Step 18-20: 3-layer delegation chain (Principal → Agent A → Agent B)
    tokenAB?: CapabilityToken;
    delegationCheckResult?: {
        allowed: boolean;
        delegationDepth?: number;
        reason?: string;
    };

    // Step 21-23: key rotation
    agentANewKeyPair?: { publicKey: string; privateKey: string };
    agentARotatingDocument?: AgentIdentityDocument;
    agentARotationState?: KeyRotationState;
    agentARotatedAt?: Timestamp;

    // Step 24-25: Scope extensions
    tokenATemporal?: CapabilityToken;
    tokenACumulative?: CapabilityToken;

    // ── Extensions (Step 26-32) ─────────────────────────────────────────────────
    // Step 26-27: E2E encrypted session registry (SessionRegistryImpl)
    encryptionRegistry?: SessionRegistryImpl;
    encryptionSessionId?: string;
    encryptionTokenId?: string;

    // Step 28: audit-before-execute barrier
    auditBarrier?: AuditBarrier;

    // Step 32: SESSION_SUPERSEDED control-plane writer
    sessionSupersedeRecorder?: SessionSupersedeRecorder;
}

export interface GoldenPathStepSummary {
    number: number;
    name: string;
    durationMs: number;
    passed: boolean;
    /** Explicit skip flag.
     *  true means the step is an intentional skip (a deferred step, etc.),
     *  distinct from "a failure with passed: false"; when a caller performs step trace / count
     *  validation, a skipped step should not be counted as a missed run. A skipped step always has durationMs 0.
*/
    skipped?: boolean;
    /** skip reason; only meaningful when skipped=true*/
    skipReason?: string;
}

export interface GoldenPathResult {
    success: boolean;
    steps: GoldenPathStepSummary[];
    totalDurationMs: number;
    coreFlowDurationMs: number;
    errors: Array<{ step: number; error: string }>;
}
