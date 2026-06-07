// Aggregated exports for the baseline + extensions.
export * from './action-vocabulary.js';
export * from './authorization.js';
export * from './base.js';
export * from './communication.js';
export * from './errors.js';
export * from './identity.js';
export * from './ledger.js';
export * from './schemas.js';
export * from './validation.js';

// Modules added later.
export * from './audit.js';
export * from './discovery.js';
export * from './federation.js';
export * from './ports.js';
export * from './session.js';

// Modules added later (frozen).
export * from './encryption.js';
export * from './envelope-ledger.js';

// Modules added later.
export * from './lifecycle.js';
export * from './schemas/registry.js';

// Policy change-audit type constants.
// Note: the ACTION_POLICY_* constants do not enter ACTION_VOCABULARY / HANDSHAKE_CAPABILITY_VOCABULARY,
// to prevent the frozen enums from being spread by patches.
export * from './policy-change-record.js';

// Sub-protocol: Canonical Signed Payload (CSP) v0.1
// Triple defense: types (brand types, L1) + schema.json (L2) + csp-validation (AJV strict, L3)
export * from './canonical-signed-payload/index.js';

// Sub-protocol: ResolverFreshnessProof (RFP) v0.1
// L0 type layer (brand types + JSON Schema + AJV strict)
export * from './rfp.js';

// Sub-protocol:Audit Tamper-Proof (atp) v0.1
// L0 type layer (brand types + JSON Schema + AJV strict)
export * from './audit-tamper-proof/index.js';

// Sub-protocol:Hash Chain Canonicalize (HCC) v0.1
// L0 type layer (5 brand types + JSON Schema + AJV strict, 5 flags + 6 HccErrorCode entries);
// the triple defense reuses the csp pattern; namespace-isolated HC_* (does not conflict with CSP_* / RFP_* / TB_* / ATP_*)
export * from './hash-chain-canonicalize/index.js';

// Sub-protocol:Multisig (ms) v0.1
// Triple defense: types (brand types, L1) + multisig-token-v0.1.schema.json (L2) + multisig-validation (AJV strict, L3)
// 14 active MULTISIG_* error codes (frozen in v0.1)
export * from './multisig/index.js';

// Sub-protocol:ControllerChainResolution (CCR) v0.1
// L0 type layer (brand types + 12 CCR_* error codes + AJV strict; MAX_CHAIN_DEPTH=5)
// Namespace isolation: CCR_* is orthogonal to CSP_* / RFP_* / DELEGATION_* / ATP_* / HCC_* / MS_* / TB_*
export * from './controller-chain-resolution/index.js';

// Sub-protocol:Credential Resolver (CR) v0.1
// Triple defense: types (brand types, L1) + credential-resolver-v0.1.schema.json (L2) + cr-validation (AJV strict, L3)
// 14 CR_* error codes (frozen in v0.1)
// 5 design decisions:
// #1 OidcRawClaims/SamlRawClaims are nominally mutually incompatible
// #2 OidcPort/SamlPort.verifyCallback() are compile-time forced to return Normalized*Claims
// #3 federation_identity_links.user_id FK ON DELETE RESTRICT (audit completeness takes priority)
// #4 SAML > OIDC > DID multi-source priority (ordered by maturity of traditional enterprise federation deployments)
// #5 independent crVersion namespace (consistent with the existing sub-protocol pattern)
// Namespace isolation: CR_* is orthogonal to CSP_* / RFP_* / DELEGATION_* / ATP_* / HCC_* / MS_* / CCR_* / TB_*
export * from './credential-resolver/index.js';

// Sub-protocol:Settlement Retry (SR) v0.1
// Triple defense: types (brand types, L1) + schemas.ts (L2 JSON Schema) + L3 AJV strict, 4 flags (policy package)
// 14 SR_* error codes (frozen in v0.1; each code has ≥1 throw)
// 5 design decisions:
// #1 SHA-256(JCS) idempotency key (collision-resistant; no symmetric key)
// #2 exponential backoff + random jitter (avoids the thundering-herd effect; base_ms=1000; max_delay_ms=60000)
// #3 DEAD_LETTER triggers enqueueing into the manual-review queue
// #4 strict allowlist of state transitions (6 legal transitions; finite state machine)
// #5 independent srVersion namespace (orthogonal to the existing sub-protocols)
// Namespace isolation: SR_* is orthogonal to CSP_* / RFP_* / DELEGATION_* / ATP_* / HCC_* / MS_* / CCR_* / CR_* / TB_*
export * from './settlement-retry/index.js';

// Sub-protocol:Dispute Arbitration (DA) v0.1
// Triple defense: types (brand types, L1) + JSON Schema (L2) + AJV strict (L3 policy package)
// 15 DA_* error codes (frozen in v0.1; each code has ≥1 throw)
// Three-layer enforcement (core enforcement):
// L0 layer — constants MIN_ARBITRATOR_COUNT=3 + MAX=5 literals + JSDoc
// SQL DDL CHECK constraint — packages/sdk/sql/032_dispute_arbitration.sql
// algorithm throw — step 4 throws DA_ARBITRATOR_INSUFFICIENT if pool size < MIN=3, fail-closed
// Design decisions include: three-layer enforcement + 14-day hard cap + multisig N-of-M coupling
// Namespace isolation: DA_* is orthogonal to CSP_* / RFP_* / DELEGATION_* / ATP_* / HCC_* / MS_* / CCR_* / CR_* / SR_* / TB_*
export * from './dispute-arbitration/index.js';

// Sub-protocol:Audit Share (audit-share) v0.2
// L0 type layer (brand types + 14 AUDIT_SHARE_* error codes + JSON Schema + AJV strict)
// Namespace isolation: AUDIT_SHARE_* is orthogonal to CSP/RFP/DELEGATION/ATP/HCC/MS/CCR/CR/SR/DA/TB;
// the external alias `AuditShareVerifiedRequest` avoids a clash with audit.ts's same-named VerifiedAuditRequest
export * from './audit-share/index.js';

// sdk v0.2 L0 type layer (brand types + VerifierKind union + VerifiedTransportContext + 6 SdkErrorCode entries + SdkError class)
// Namespace isolation: SDK_* is orthogonal to CSP_* / RFP_* / HC_* / MS_* / CCR_* / CR_* / SR_* / DA_* / AUDIT_SHARE_* / TB_*
export * from './sdk/index.js';
