/**
 * audit-share v0.3 L3 policy sub-module type definitions
 *
 * This module exports two types:
 *   - RawTransportEvidence — the raw transport evidence accepted by audit-share v0.3 (3 verifier-kind discriminator)
 *   - AuditShareV3Result — the verifyAuditRequestV03 happy-path return value (v0.2 baseline + verifierMetadata upgrade)
 *
 * Design intent:
 *   - the audit-share API no longer accepts a caller-supplied VerifiedTransportContext (the caller
 *     can fabricate a fake context; outside the TypeScript boundary; anti-spoofing)
 *   - the audit-share API accepts raw transport evidence (mtls cert + chain / jwt token + JWKS / oauth2
 *     introspection response) → invokes the sdk v0.2 verifier factory inside the audit-share boundary →
 *     true cryptographic enforce inside the boundary (the caller cannot fabricate a verified context)
 *
 * Architectural-layer dependencies (strict bottom-up dependency):
 *   - L3 policy → L2 identity (verifier factory + boundary check; exported by @coivitas/identity)
 *   - L3 policy → L1 crypto (verifyHashChain + HashChainError; exported by @coivitas/crypto)
 *   - L3 policy → L0 types (AuditShareError + brand types + AuditShareV3 error-code union)
 *   - the verifier factory physically lives in `@coivitas/identity` (passed through via the sdk-layer re-export)
 */

import type {
    AuditShareEventPayload,
    AuditShareHashChainEntry,
    DID,
    VerifierKind,
} from '@coivitas/types';

/**
 * RawTransportEvidence — the raw transport evidence accepted by audit-share v0.3
 *
 * Background for the design redesign:
 *
 * Flaw in the old design: RawTransportEvidence carried the full VerifierContext (including
 *   trusted root / JWKS / introspection endpoint / issuer / audience / expectedDid and other trust
 *   anchors), all provided by the caller → a malicious caller could pass a self-controlled
 *   CA/JWKS/introspection endpoint + a matching token/cert, and the in-boundary factory would verify
 *   against the attacker-chosen trust anchors → "calling the factory inside the boundary" did not
 *   actually close off the forgery risk.
 *
 * New design: RawTransportEvidence contains only the verified artifact observed at the boundary (it is
 *   reasonable for the caller to provide it, because it is the verified object itself); all trust
 *   anchors / verifier policy are constructed by audit-share from the trusted deployment
 *   configuration (TrustedVerifierConfig), beyond the caller's control.
 *
 * 3 verifier-kind discriminator:
 *   - 'mtls' → clientCert (DER/PEM; the client certificate being verified) + optional intermediateChain
 *     (the intermediate certificate chain provided by the caller; the CA root is still constrained by the
 *     trusted config, so there is no forgery risk)
 *   - 'jwt' → jwt (compact serialization; the token being verified)
 *   - 'oauth2' → accessToken (the bearer token being verified)
 */
export type RawTransportEvidence =
    | {
          readonly kind: 'mtls';
          readonly clientCert: Uint8Array | string;
          readonly intermediateChain?: (Uint8Array | string)[];
      }
    | { readonly kind: 'jwt'; readonly jwt: string }
    | { readonly kind: 'oauth2'; readonly accessToken: string };

/**
 * TrustedVerifierConfig — audit-share trusted deployment configuration (source of trust anchors)
 *
 * Key constraint: this config is constructed and injected by the deployer in a trusted context (a
 *   function parameter); semantically it is deployment configuration, not a request parameter.
 *   audit-share uses it + the verified artifact from RawTransportEvidence to assemble the full
 *   VerifierContext, then feeds it to the sdk verifier factory. The caller cannot inject
 *   self-controlled trust anchors through this channel.
 *
 * per-kind trust anchors (all authoritative sources):
 *   - mtls: trustedRootCerts (CA root pool) + expectedDid
 *   - jwt: jwks (JWKS endpoint / static key set) + expectedIssuer + expectedAudience + expectedDid + allowSymmetricAlg?
 *   - oauth2: issuerUrl + introspectionEndpoint + introspection client creds + expectedAudience + expectedDid
 */
export type TrustedVerifierConfig =
    | {
          readonly kind: 'mtls';
          readonly trustedRootCerts: (Uint8Array | string)[];
          readonly expectedDid: DID;
      }
    | {
          readonly kind: 'jwt';
          readonly jwks: string | { keys: unknown[] };
          readonly expectedIssuer: string;
          readonly expectedAudience: string;
          readonly expectedDid: DID;
          readonly allowSymmetricAlg?: boolean;
      }
    | {
          readonly kind: 'oauth2';
          readonly issuerUrl: string;
          readonly introspectionEndpoint: string;
          readonly introspectionClientId: string;
          readonly introspectionClientSecret: string;
          readonly expectedAudience: string;
          readonly expectedDid: DID;
      };

/**
 * TrustedHashChainCheckpoint — audit-share hash chain tail trusted anchor
 *
 * Security root cause: before this, verifyAuditRequestV03 only passed checkpoint.requireNonEmpty,
 *   which can only block "deleting all rows" and cannot block "non-empty tail truncation" (an attacker
 *   returns an internally self-consistent prefix: correct hash linkage + consistent chainIdentity +
 *   compliant canonicalPayload → passes). In the selective disclosure scenario, if the fetch/query
 *   layer returns a prefix, the missing tail audit records go undetected → the audit truth is
 *   selectively hidden.
 *
 * Key constraint: the checkpoint must come from a trusted source (a trusted ledger snapshot / the
 *   chain-tail state recorded by a monitoring system), injected by the deployer in a trusted context
 *   (a function parameter); semantically it is trusted deployment/ledger data, not a request parameter.
 *   If the checkpoint came from the request, an attacker could supply their own self-consistent
 *   truncated checkpoint → the protection fails (the same trust-boundary principle as
 *   [[TrustedVerifierConfig]]).
 *
 * Optionality (progressive rollout path): not all deployments have a trusted checkpoint source; when
 *   omitted it degrades to requireNonEmpty-only (only blocks deleting all rows); when provided it
 *   enforces tail verification (blocks non-empty tail truncation). Strongly recommended for the
 *   audit/ledger verification path.
 */
export interface TrustedHashChainCheckpoint {
    /** Expected total entry count (literally equal to entries.length; prevents truncation/insertion)*/
    readonly expectedEntryCount?: number;
    /** Expected last chainPosition (prevents tail truncation)*/
    readonly expectedLastChainPosition?: number;
    /** Expected last canonicalPayloadHash (externally anchors the tail; prevents tail truncation)*/
    readonly expectedLastCanonicalPayloadHash?: string;
}

/**
 * AuditShareVerifierMetadata — verifier metadata output by the verifyAuditRequestV03 happy path
 *
 * Structure of the verifierMetadata produced by Step 0:
 *   {
 *     kind: verifiedCtx.verifierKind,
 *     verifiedAt: verifiedCtx.verifiedAt,
 *   }
 *
 * Design intent: the caller can use verifierMetadata for cross-domain joint auditing / replay defense / freshness audit traceability.
 *   - kind: VerifierKind (mtls / jwt / oauth2; defense-in-depth metadata)
 *   - verifiedAt: ISO 8601 UTC (anchor for the sdk v0.2 freshness check)
 */
export interface AuditShareVerifierMetadata {
    readonly kind: VerifierKind;
    readonly verifiedAt: string;
}

/**
 * AuditShareV3Result — verifyAuditRequestV03 happy-path return value (v0.2 baseline + verifierMetadata upgrade)
 *
 * The v0.2 AuditShareVerifyResult.ok = true fields are carried over and maintained (entries + auditEvents);
 * v0.3 adds verifierMetadata (metadata produced by the Step 0 cryptographic verifier; cross-domain audit traceability).
 *
 * The failure path does not return ok = false but throws a fatal AuditShareError (fail-closed;
 * an auth primitive only accepts results that pass verification).
 */
export interface AuditShareV3Result {
    readonly ok: true;
    readonly entries: readonly AuditShareHashChainEntry[];
    /**
     * audit events after selective disclosure projection (Partial<AuditEvent> — contains only the
     * request.disclosedClaims subset of fields; follows the v0.2 projection semantics)
     */
    readonly auditEvents: readonly Partial<AuditShareEventPayload>[];
    /**
     * v0.3 NEW — metadata produced by the sdk v0.2 cryptographic verifier (produced in Step 0)
     */
    readonly verifierMetadata: AuditShareVerifierMetadata;
}

/**
 * AuditEventField re-export — the caller-side disclosedClaims projection fields
 *
 * Design intent: when the caller constructs disclosedClaims it does not need to import @coivitas/types
 *   directly; it can import uniformly from the audit-share policy sub-module.
 */
export type { AuditEventField } from '@coivitas/types';
