/**
 * audit-share L3 module exports (v0.2 baseline + v0.3 Step 0 + Step 10 true-consumption closure)
 *
 * v0.2 L3 main class + DI port interfaces:
 *   - AuditShareManager — 11-step verifyAuditRequest fail-closed
 *   - AuditShareDelegatedKeyStore — Step 3 port (audit-share namespace isolation;
 *     avoids name confusion with the audit-access v0.2 DelegatedAuditKeyResolver)
 *   - TenantAuditSharePolicyStore — Step 8 port (atp v0.1 multi-tenant linkage)
 *   - AuditEventStore — Step 9+11 port (hash chain entries + audit events)
 *   - HashChainVerifier — Step 10 port (hcc v0.1 verifyHashChain primitive)
 *   - ChallengeStore — Step 2 port (csp C1 reverse semantics; one-time nonce)
 *
 * v0.3 upgrade (true-consumption phase):
 *   - verifyAuditRequestV03 — Step 0 true-consumption closure (sdk verifier factory inside the
 *                              boundary; anti-spoofing) + Step 10 hcc v0.2 verifyHashChain
 *                              cryptographic enforce
 *   - RawTransportEvidence — 3 verifier-kind discriminator (mtls / jwt / oauth2;
 *                              caller cannot fabricate verifiedCtx)
 *   - AuditShareV3Result — happy-path return value (v0.2 baseline + verifierMetadata upgrade)
 *   - AuditShareVerifierMetadata — verifier metadata (kind + verifiedAt; cross-domain audit traceability)
 *
 * The L2 true verifier is in @coivitas/identity (cryptographic-verifier/; sdk v0.2 -)
 * The L1 verifyHashChain primitive is in @coivitas/crypto (hash-chain-canonicalize/; hcc v0.2)
 * L0 brand types + error class + AJV strict validator live in @coivitas/types
 *
 * Non-bypassable rule (carried over from v0.2):
 *   AuditEvaluatorNotImplemented is fully removed; verifyDelegatedAuditKey performs a real 5-step verify.
 *
 * anti-phantom-enforcement guard:
 *   v0.3 truly consumes the sdk verifier factory (does not accept a caller-supplied
 *   VerifiedTransportContext; the factory must be invoked inside the audit-share boundary)
 *   + truly consumes hcc v0.2 verifyHashChain
 *   (any HC_* error → wrap and throw AuditShareError; stub success is not allowed).
 */

// v0.2 baseline (carried over and maintained)
export {
    AuditShareManager,
    type AuditShareManagerDeps,
    type AuditShareDelegatedKeyStore,
    type TenantAuditSharePolicyStore,
    type AuditEventStore,
    type HashChainVerifier,
    type ChallengeStore,
} from './audit-share-manager.js';

// v0.3 upgrade (Step 0 + Step 10 true-consumption closure)
export { verifyAuditRequestV03 } from './verify-audit-request-v0.3.js';
export {
    type RawTransportEvidence,
    type TrustedVerifierConfig,
    type TrustedHashChainCheckpoint,
    type AuditShareV3Result,
    type AuditShareVerifierMetadata,
    type AuditEventField,
} from './types.js';
