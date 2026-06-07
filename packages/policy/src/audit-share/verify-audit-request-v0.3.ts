/**
 * verifyAuditRequestV03 — audit-share v0.3 Step 0 true-consumption implementation
 *
 *   - Step 0 cryptographic enforce upgrade (true consumption of the sdk v0.2 verifier factory)
 *   - Step 10 full-stack cryptographic enforce upgrade (true consumption of hcc v0.2 verifyHashChain)
 *   - v0.3 adds 3 error codes (AUDIT_SHARE_VERIFIER_REQUIRED / AUDIT_SHARE_BOUNDARY_CHECK_FAILED /
 *     AUDIT_SHARE_CHAIN_IDENTITY_TAMPERED)
 *
 * Core of the v0.3 upgrade (vs v0.2 audit-share-manager.ts):
 *
 *   Step 0 (NEW; Step 0 true consumption):
 *     - the audit-share API accepts RawTransportEvidence (raw transport evidence; 3 verifier-kind discriminator)
 *     - the sdk v0.2 verifier factory is invoked inside the audit-share boundary (verifyMtlsAndDeriveDid /
 *       verifyJwtAndDeriveDid / verifyOAuth2AndDeriveDid) → true cryptographic identity derivation
 *     - the caller cannot fabricate a VerifiedTransportContext (cryptographic verify after the factory call; anti-spoofing)
 *     - Step 0.1 assertTrustedDidIsKindAndFresh 4-dimension boundary check
 *     - Step 0.2 assertCrossCheckMappingConsistent (consistency between verifier kind and verifiedSubject)
 *     - Step 0.3 L4 sub-protocol cross-check (verifiedCtx.trustedDid === request.requesterDid)
 *
 *   Steps 1-9 (carried over and maintained from v0.2; sustain):
 *     - pass through to the same algorithm as v0.2 AuditShareManager.verifyAuditRequest
 *     - Step 1 schema validate + Step 2 csp 5-field invariant + ... + Step 9 fetchByChainIdentity
 *
 *   Step 10 (Step 10 upgrade):
 *     - directly call @coivitas/crypto verifyHashChain (hcc v0.2 primitive; chainIdentity preimage cryptographic enforce)
 *     - catch HashChainError.code === 'HC_HASH_MISMATCH' OR 'HC_CHAIN_IDENTITY_SCHEMA_BREAKING'
 *       → throw AuditShareError 'AUDIT_SHARE_CHAIN_IDENTITY_TAMPERED'
 *     - catch other HC_* → throw AuditShareError 'AUDIT_SHARE_HASH_CHAIN_INVALID' (carried over from v0.2)
 *
 *   Step 11 (carried over and maintained from v0.2; sustain):
 *     - selective disclosure projection (returns only the disclosedClaims subset of fields)
 *     - adds verifierMetadata (kind + verifiedAt; cross-domain audit traceability)
 *
 * Architectural-layer dependency anchors (compliant with "strict bottom-up dependency"):
 *   - L3 policy → L2 identity (verifier factory + boundary check)
 *   - L3 policy → L1 crypto (verifyHashChain primitive)
 *   - L3 policy → L0 types (AuditShareError + brand types + AJV validator)
 *
 * Dependency-path note:
 *   - cryptographic-verifier is an abstract interface reference
 *   - on implementation it maps to the actual package path `@coivitas/identity` (the physical location
 *     of the verifier factory; the top level of `@coivitas/sdk` re-exports and passes through
 *     cryptographic-verifier; L3 policy must not import L5 sdk directly — a reverse dependency is illegal)
 *
 * Anti-phantom-enforcement guard:
 *   - true consumption of the sdk verifier factory (does not accept a caller-supplied
 *     VerifiedTransportContext; the factory must be invoked inside the audit-share boundary → true
 *     cryptographic identity derivation)
 *   - true consumption of hcc v0.2 verifyHashChain (a default stub PASS is not allowed; any HC_* error → wrap and throw AuditShareError)
 *   - every step is fail-closed throw (fail-degraded / fail-open / partial-PASS / WARNING-only are not allowed)
 *   - any step that fails → fatal AuditShareError (does not return ok = false and proceed to the next step)
 */

import { verifyHashChain } from '@coivitas/crypto';
import {
    assertCrossCheckMappingConsistent,
    assertTrustedDidIsKindAndFresh,
    verifyJwtAndDeriveDid,
    verifyMtlsAndDeriveDid,
    verifyOAuth2AndDeriveDid,
} from '@coivitas/identity';
import {
    AuditShareError,
    type AuditShareVerifiedRequest,
    type DID,
    type HashChainEntry as HccHashChainEntry,
    type Timestamp,
} from '@coivitas/types';

import {
    AuditShareManager,
    type AuditShareManagerDeps,
} from './audit-share-manager.js';
import type {
    AuditShareV3Result,
    RawTransportEvidence,
    TrustedHashChainCheckpoint,
    TrustedVerifierConfig,
} from './types.js';

/**
 * sdk v0.2 boundary check freshness tolerance default
 *
 * Kept consistent with the sdk v0.2 default 60s tolerance.
 */
const AUDIT_SHARE_V03_FRESHNESS_TOLERANCE_SECONDS = 60 as const;

/**
 * verifyAuditRequestV03 — audit-share v0.3 verifyAuditRequest 11-step algorithm (v0.3 upgrades Step 0 + Step 10)
 *
 * Core of the v0.3 upgrade:
 *   - Step 0: the audit-share API accepts raw transport evidence + internally invokes the sdk v0.2 verifier factory
 *     → true cryptographic enforce inside the boundary (the caller cannot fabricate a verified context; anti-spoofing)
 *   - boundary check pattern enforce (defense-in-depth; true consumption at L1+L2+L3)
 *
 * Carried over and maintained from v0.2: Steps 1-9 + Step 11 (Step 10 upgrades to hcc v0.2 verifyHashChain)
 *
 * @param request AuditShareVerifiedRequest (carried over and maintained from v0.2)
 * @param expectedAudience expected audience DID (the verifier-side expected audience; step 2 csp F2 enforce)
 * @param transportEvidence RawTransportEvidence (v0.3 NEW mandatory parameter; raw transport evidence;
 *                          NOT a pre-verified context; the caller cannot fabricate it)
 * @param deps AuditShareManagerDeps (DI container; 6 ports; carried over and maintained from v0.2)
 * @param now current-moment Timestamp (injected by the caller; enforced in steps 2+4)
 * @param trustedCheckpoint required trusted hash chain tail anchor (injected by the trusted ledger /
 *                          deployment side, not the request; must contain at least one tail-anchor field.
 *                          The last line of defense for audit truth does not allow returning ok:true with
 *                          no tail anchor — otherwise the fetch layer can return an internally self-consistent
 *                          prefix to hide subsequent audit records)
 * @returns AuditShareV3Result (ok: true + entries + auditEvents + verifierMetadata)
 * @throws AuditShareError fail-closed (any of Step 0-11 failing); includes the 3 error codes added in v0.3
 */
export async function verifyAuditRequestV03(
    request: AuditShareVerifiedRequest,
    expectedAudience: DID,
    transportEvidence: RawTransportEvidence,
    trustedVerifierConfig: TrustedVerifierConfig,
    deps: AuditShareManagerDeps,
    now: Timestamp,
    trustedCheckpoint: TrustedHashChainCheckpoint,
): Promise<AuditShareV3Result> {
    // ═══════════════════════════════════════════════════════════════════════
    // Step 0: invoke the sdk v0.2 verifier factory inside the audit-share boundary
    // → true cryptographic enforce (anti-spoofing)
    // ═══════════════════════════════════════════════════════════════════════

    // v0.3 design-layer constraint:
    // the verified context must be produced inside the audit-share boundary; not accepted from the caller
    // (a caller-provided one is outside the TypeScript boundary; can fabricate a fake context)

    // anti-phantom-enforcement guard: transportEvidence is mandatory; raw transport evidence (the caller cannot fabricate it)
    if (transportEvidence === null || transportEvidence === undefined) {
        throw new AuditShareError(
            'AUDIT_SHARE_VERIFIER_REQUIRED',
            'transportEvidence is required; raw transport evidence (mtls cert / jwt token / oauth2 access token)',
            'step-0-transport-evidence-required',
        );
    }
    // trustedVerifierConfig is mandatory (source of trust anchors)
    if (trustedVerifierConfig === null || trustedVerifierConfig === undefined) {
        throw new AuditShareError(
            'AUDIT_SHARE_VERIFIER_REQUIRED',
            'trustedVerifierConfig is required; trust anchors are provided by the trusted deployment configuration (CA/JWKS/issuer/audience/expectedDid); not controllable by the caller',
            'step-0-trusted-config-required',
        );
    }
    // evidence.kind and config.kind must match (prevents kind mismatch)
    if (transportEvidence.kind !== trustedVerifierConfig.kind) {
        throw new AuditShareError(
            'AUDIT_SHARE_VERIFIER_REQUIRED',
            `transportEvidence.kind (${transportEvidence.kind}) !== trustedVerifierConfig.kind (${trustedVerifierConfig.kind})`,
            'step-0-kind-mismatch',
        );
    }

    // ───────────────────────────────────────────────────────────────────────
    // Step 0.0: assemble the full VerifierContext (verified artifact + trusted deployment config trust anchors)
    // then invoke the sdk v0.2 verifier factory inside the audit-share boundary
    // ───────────────────────────────────────────────────────────────────────

    // The VerifierContext trust anchors (trustedRootCerts / jwks /
    // issuer / audience / introspection endpoint / expectedDid) all come from trustedVerifierConfig
    // (the trusted deployment config); the verified artifact (clientCert / jwt / accessToken) comes from transportEvidence.
    // The caller cannot inject self-controlled trust anchors → the factory always verifies against the deployer-constrained trust anchors.

    // produces a VerifiedTransportContext (5 fields; generated inside audit-share; the caller cannot fabricate it)
    let verifiedCtx;
    try {
        switch (transportEvidence.kind) {
            case 'mtls': {
                /* v8 ignore next 3 -- TS narrowing: kind match already guarded in Step 0*/
                const cfg = trustedVerifierConfig as Extract<
                    TrustedVerifierConfig,
                    { kind: 'mtls' }
                >;
                verifiedCtx = await verifyMtlsAndDeriveDid({
                    clientCert: transportEvidence.clientCert,
                    ...(transportEvidence.intermediateChain !== undefined && {
                        intermediateChain: transportEvidence.intermediateChain,
                    }),
                    trustedRootCerts: cfg.trustedRootCerts,
                    expectedDid: cfg.expectedDid,
                });
                break;
            }
            case 'jwt': {
                /* v8 ignore next 3*/
                const cfg = trustedVerifierConfig as Extract<
                    TrustedVerifierConfig,
                    { kind: 'jwt' }
                >;
                verifiedCtx = await verifyJwtAndDeriveDid({
                    jwt: transportEvidence.jwt,
                    jwks: cfg.jwks,
                    expectedIssuer: cfg.expectedIssuer,
                    expectedAudience: cfg.expectedAudience,
                    expectedDid: cfg.expectedDid,
                    ...(cfg.allowSymmetricAlg !== undefined && {
                        allowSymmetricAlg: cfg.allowSymmetricAlg,
                    }),
                });
                break;
            }
            case 'oauth2': {
                /* v8 ignore next 3*/
                const cfg = trustedVerifierConfig as Extract<
                    TrustedVerifierConfig,
                    { kind: 'oauth2' }
                >;
                verifiedCtx = await verifyOAuth2AndDeriveDid({
                    accessToken: transportEvidence.accessToken,
                    issuerUrl: cfg.issuerUrl,
                    introspectionEndpoint: cfg.introspectionEndpoint,
                    introspectionClientId: cfg.introspectionClientId,
                    introspectionClientSecret: cfg.introspectionClientSecret,
                    expectedAudience: cfg.expectedAudience,
                    expectedDid: cfg.expectedDid,
                });
                break;
            }
            default: {
                // unreachable (RawTransportEvidence discriminated union; exhaustive at TypeScript compile time)
                /* v8 ignore next 5*/
                const _exhaustive: never = transportEvidence;
                throw new AuditShareError(
                    'AUDIT_SHARE_VERIFIER_REQUIRED',
                    `unknown transportEvidence.kind: ${String(_exhaustive)}`,
                    'step-0-0-kind-unknown',
                );
            }
        }
    } catch (err) {
        // the sdk verifier factory throws SdkError OR other errors → wrap as AuditShareError fail-closed
        if (err instanceof AuditShareError) {
            // exhaustive fallback throw (the default branch above already wraps; here it is only a type-narrow)
            /* v8 ignore next 2*/
            throw err;
        }
        throw new AuditShareError(
            'AUDIT_SHARE_VERIFIER_REQUIRED',
            `sdk v0.2 verifier factory failed inside audit-share boundary (kind="${transportEvidence.kind}"): ${err instanceof Error ? err.message : String(err)}`,
            'step-0-0-factory-fail',
        );
    }

    // ───────────────────────────────────────────────────────────────────────
    // Step 0.1: sdk v0.2 assertTrustedDidIsKindAndFresh 4-dimension boundary check
    // ───────────────────────────────────────────────────────────────────────

    // - trustedDid is literally equal (request.requesterDid)
    // - verifierKind is within the expected kinds (audit-share v0.3 ACCEPTS all three: mTLS + JWT + OAuth2)
    // - verifiedAt freshness (60s tolerance; audit-context replay defense)
    // - sdkVersion === "2.0.0" (downgrade-attack defense)
    try {
        assertTrustedDidIsKindAndFresh(verifiedCtx, {
            did: request.requesterDid,
            verifierKinds: ['mtls', 'jwt', 'oauth2'] as const,
            freshnessToleranceSeconds:
                AUDIT_SHARE_V03_FRESHNESS_TOLERANCE_SECONDS,
        });
    } catch (err) {
        throw new AuditShareError(
            'AUDIT_SHARE_BOUNDARY_CHECK_FAILED',
            `assertTrustedDidIsKindAndFresh failed: ${err instanceof Error ? err.message : String(err)}`,
            'step-0-1-trusted-did-kind-fresh',
        );
    }

    // ───────────────────────────────────────────────────────────────────────
    // Step 0.2: sdk v0.2 assertCrossCheckMappingConsistent
    // ───────────────────────────────────────────────────────────────────────

    // - mtls kind → verifiedSubject must contain a DID token (extract DID + equality compare)
    // - jwt / oauth2 kind → verifiedSubject string-equals trustedDid (JWT sub claim / OAuth2 client_id verified)
    try {
        assertCrossCheckMappingConsistent(verifiedCtx);
    } catch (err) {
        throw new AuditShareError(
            'AUDIT_SHARE_BOUNDARY_CHECK_FAILED',
            `assertCrossCheckMappingConsistent failed: ${err instanceof Error ? err.message : String(err)}`,
            'step-0-2-cross-check-mapping',
        );
    }

    // ───────────────────────────────────────────────────────────────────────
    // Step 0.3: L4 sub-protocol cross-check (defense-in-depth)
    // ───────────────────────────────────────────────────────────────────────

    // verifiedCtx.trustedDid is literally equal to request.requesterDid
    // (already enforced by assertTrustedDidIsKindAndFresh; here the sub-protocol boundary verifies again — defense-in-depth L4 layer)
    if ((verifiedCtx.trustedDid as DID) !== request.requesterDid) {
        throw new AuditShareError(
            'AUDIT_SHARE_BOUNDARY_CHECK_FAILED',
            `L4 sub-protocol cross-check failed: verifiedCtx.trustedDid (${verifiedCtx.trustedDid}) !== request.requesterDid (${request.requesterDid})`,
            'step-0-3-l4-cross-check',
        );
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Steps 1-9: carried over and maintained from v0.2 (audit-share v0.2; sustain)
    // ═══════════════════════════════════════════════════════════════════════

    // pass through to the same algorithm as v0.2 AuditShareManager.verifyAuditRequest:
    // - Step 1 schema validate (AJV strict 4 flag; 3rd layer of the triple defense)
    // - Step 2 csp v0.1 5-field invariant verify (auditShareVersion + disclosedClaims +
    // audience + notAfter + challenge)
    // - Step 3 fetch AuditShareDelegatedKey by request.token
    // - Step 4 verifyAuditShareDelegatedKey 5-step fail-closed
    // - Step 5 key.delegatedTo === request.requesterDid
    // - Step 6 verify request.requesterSignature (Ed25519) + challenge consume race-condition guard
    // - Step 7 scope re-verify (toAuditShareScope factory; brand cast forbidden)
    // - Step 8 multi-tenant isolation cross-check (atp v0.1 linkage) + scope expansion defense
    // - Step 9 fetchByChainIdentity (SQL WHERE demoted to second line of defense; defense-in-depth)

    // Note: Step 10 is upgraded to hcc v0.2 — see the Step 10 section below; here the Step 10 inside
    // manager.verifyAuditRequest still uses the v0.2 hashChainVerifier port (deps.hashChainVerifier.verify);
    // the v0.3 verify then upgrades to the hcc v0.2 verifyHashChain primitive cryptographic enforce in the
    // Step 10 phase (double verify; defense-in-depth).

    const manager = new AuditShareManager(deps);
    const v02Result = await manager.verifyAuditRequest(
        request,
        expectedAudience,
        now,
    );
    // the v0.2 manager.verifyAuditRequest happy path returns ok: true + entries + auditEvents
    // (the failure path throws AuditShareError; it does not reach here)

    // TypeScript narrow — v0.2 AuditShareVerifyResult is a discriminated union (ok: true|false);
    // failures have already thrown, so here it must be the ok: true branch; the type guard narrows at
    // compile time + provides a runtime phantom fallback
    /* v8 ignore next 7 — manager failures already throw; the ok=false branch is unreachable here*/
    if (!v02Result.ok) {
        throw new AuditShareError(
            'AUDIT_SHARE_SCHEMA_INVALID',
            `phantom unreachable: v0.2 manager returned ok=false (expected throw): code="${v02Result.code}" reason="${v02Result.reason}"`,
            'step-9-phantom-ok-false',
        );
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Step 10: true consumption of the hcc v0.2 verifyHashChain primitive (core of the upgrade)
    // ═══════════════════════════════════════════════════════════════════════

    // Core of the v0.3 upgrade — chainIdentity preimage cryptographic enforce
    // - tampering with any entry's three chainIdentity fields → SHA-256 digest mismatch → throw HC_HASH_MISMATCH
    // (hcc v0.2 freezes HC_CHAIN_IDENTITY_PREIMAGE_FAILED — the L0 types union has been upgraded; here we catch HC_HASH_MISMATCH)
    // - hccVersion not "2.0.0" → throw HC_CHAIN_IDENTITY_SCHEMA_BREAKING (version invariant)

    // defense-in-depth: the Step 10 inside manager.verifyAuditRequest already goes through the v0.2 hashChainVerifier port;
    // v0.3 here additionally goes through the hcc v0.2 verifyHashChain primitive cryptographic enforce — second line of defense
    // (the L5 hash preimage is promoted to the first line of defense; the L6 SQL WHERE is demoted to the second line)

    // placeholder type-drift note (followup; not part of this change):
    // the internal audit-share v0.2 HashChainEntry placeholder has 7 fields (tenantId/auditClass/...);
    // the hcc v0.2 HashChainEntry has 8 fields (including chainIdentity / hccVersion / entryId / ...);
    // after SQL migration 028 lands, the actual table fields are already the hcc v0.2 8 fields
    // — here entries are in fact hcc v0.2 entries (at runtime); on the TypeScript static side the audit-share placeholder
    // is historical drift — followup: replace the internal audit-share v0.2 placeholder type with the hcc v0.2 brand re-export.

    // The structural cast here is cross-package type alignment, not a cryptographic brand boundary crossing (an exception to the no-brand-cast rule):
    // entries are fetched from the SQL migration 028 table (8 fields) → fields are consistent; the cast is TypeScript static-side alignment
    const hccEntries =
        v02Result.entries as unknown as readonly HccHashChainEntry[];
    try {
        // pass expectedChainIdentity to enforce scope isolation:
        // verifyHashChain asserts that every entry's chainIdentity equals the chainIdentity derived from the request scope,
        // and requires the chain to be non-empty (prevents a mixed chain or empty chain being judged valid when the fetch-layer query is wrong / poisoned).
        // The chainIdentity fields come from request.requestedScope (chainNamespace is mandatory + tenantId/auditClass optional).
        const scope = request.requestedScope;
        // chainNamespace is mandatory (the authoritative field for scope isolation); missing → fail-closed
        if (
            typeof scope.chainNamespace !== 'string' ||
            scope.chainNamespace.length === 0
        ) {
            throw new AuditShareError(
                'AUDIT_SHARE_HASH_CHAIN_INVALID',
                'requestedScope.chainNamespace missing; cannot enforce chain scope isolation',
                'step-10-scope-chain-namespace-required',
            );
        }
        // the trusted checkpoint tail anchor is required:
        // audit-share v0.3 is the last line of defense for audit truth. requireNonEmpty alone only blocks "deleting all rows",
        // it cannot block "non-empty tail truncation" (the fetch layer returns an internally self-consistent prefix → subsequent audit records are hidden yet ok:true).
        // Therefore the constraint is tightened: trustedCheckpoint is required and must contain at least one tail-anchor field; otherwise fail-closed,
        // returning success with no tail anchor is not allowed. The checkpoint comes from the trusted ledger / deployment side (not the request),
        // otherwise an attacker could supply their own self-consistent truncated checkpoint → the protection fails.
        const hasTailAnchor =
            trustedCheckpoint.expectedEntryCount !== undefined ||
            trustedCheckpoint.expectedLastChainPosition !== undefined ||
            trustedCheckpoint.expectedLastCanonicalPayloadHash !== undefined;
        if (!hasTailAnchor) {
            throw new AuditShareError(
                'AUDIT_SHARE_HASH_CHAIN_INVALID',
                'trustedCheckpoint must contain at least one tail anchor (expectedEntryCount / ' +
                    'expectedLastChainPosition / expectedLastCanonicalPayloadHash); ' +
                    'the last line of defense for audit truth does not allow returning success with no tail anchor (non-empty tail truncation protection)',
                'step-10-checkpoint-tail-anchor-required',
            );
        }
        verifyHashChain(hccEntries, {
            expectedChainIdentity: {
                chainNamespace: scope.chainNamespace,
                ...(scope.tenantId !== undefined && {
                    tenantId: scope.tenantId,
                }),
                ...(scope.auditClass !== undefined && {
                    auditClass: scope.auditClass,
                }),
            },
            checkpoint: {
                requireNonEmpty: true,
                ...(trustedCheckpoint.expectedEntryCount !== undefined && {
                    expectedEntryCount: trustedCheckpoint.expectedEntryCount,
                }),
                ...(trustedCheckpoint.expectedLastChainPosition !==
                    undefined && {
                    expectedLastChainPosition:
                        trustedCheckpoint.expectedLastChainPosition,
                }),
                ...(trustedCheckpoint.expectedLastCanonicalPayloadHash !==
                    undefined && {
                    expectedLastCanonicalPayloadHash:
                        trustedCheckpoint.expectedLastCanonicalPayloadHash,
                }),
            },
        });
    } catch (err) {
        // hcc v0.2 HashChainError → wrap as AuditShareError fail-closed
        const errAny = err as { code?: string; message?: string };
        const hcCode = errAny.code;
        const hcMessage = err instanceof Error ? err.message : String(err);

        // v0.3 new catch — chainIdentity preimage / schema breaking → AUDIT_SHARE_CHAIN_IDENTITY_TAMPERED
        // (error code added in v0.3)
        if (
            hcCode === 'HC_HASH_MISMATCH' ||
            hcCode === 'HC_CHAIN_IDENTITY_PREIMAGE_FAILED' ||
            hcCode === 'HC_CHAIN_IDENTITY_SCHEMA_BREAKING'
        ) {
            throw new AuditShareError(
                'AUDIT_SHARE_CHAIN_IDENTITY_TAMPERED',
                `chainIdentity preimage cryptographic enforce fail (hcc code="${hcCode}"): ${hcMessage}`,
                'step-10-chain-identity-tampered',
            );
        }

        // carried over and maintained from v0.2 — other HC_* errors → throw AUDIT_SHARE_HASH_CHAIN_INVALID
        throw new AuditShareError(
            'AUDIT_SHARE_HASH_CHAIN_INVALID',
            `hcc v0.2 verifyHashChain failed (hcc code="${hcCode ?? 'unknown'}"): ${hcMessage}`,
            'step-10-hash-chain-invalid',
        );
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Step 11: selective disclosure projection (carried over and maintained from v0.2) + verifierMetadata upgrade (v0.3 NEW)
    // ═══════════════════════════════════════════════════════════════════════

    // v0.2 manager.verifyAuditRequest already runs the project() selective disclosure projection in Step 11
    // (returns only the disclosedClaims subset of fields; carried over and maintained from v0.2);
    // the v0.3 wrapper layer adds verifierMetadata (kind + verifiedAt; cross-domain audit traceability).
    return {
        ok: true,
        entries: v02Result.entries,
        auditEvents: v02Result.auditEvents,
        verifierMetadata: {
            kind: verifiedCtx.verifierKind,
            verifiedAt: verifiedCtx.verifiedAt,
        },
    };
}
