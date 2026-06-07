/**
 * Credential Resolver (CR) sub-protocol v0.1 — L0 type definitions
 *
 * Triple defense line (reuses the csp pattern):
 *   Layer 1 (this file): TypeScript brand type — compile-time guard (brand cast forbidden)
 *     - phantom-type only mode (consistent with the existing 4 brands in base.ts)
 *     - security defense = (a) compile-time nominal narrowing + (b) AJV strict schema validation
 *     - the form interface { readonly __brand: 'X' } is forbidden (it violates runtime property mode)
 *   Layer 2 (../schemas/credential-resolver-v0.1.schema.json): JSON Schema — runtime schema layer
 *   Layer 3 (cr-validation.ts): AJV strict mode with 4 flags — runtime schema engine layer
 *
 * Brand-cast guard: every brand type can only be obtained through a to*() factory function;
 *           direct brand casts such as `as TenantId` / `as UserId` / `as OidcRawClaims` are forbidden.
 *
 * Error-code namespace (frozen at 14 entries; CR_* prefix):
 *   orthogonal to the CSP_* / RFP_* / DELEGATION_* / ATP_* / HCC_* / MS_* / CCR_* / TB_* namespaces
 *   (csp v0.1 constraint 4).
 *   Every error code must have at least one throw site (anti-dead-code; avoids defining unused error codes).
 *
 * Design decisions:
 *   - OidcRawClaims/SamlRawClaims are independent brand interfaces;
 *     compile-time nominally incompatible (strong type isolation)
 *   - OidcPort/SamlPort.verifyCallback() is compile-time forced to return NormalizedOidcClaims/NormalizedSamlClaims;
 *     iss/aud extraction logic is pushed down to the port implementation layer
 *   - SQL RESTRICT (federation_identity_links.user_id FK ON DELETE RESTRICT);
 *     preferred over CASCADE intent (audit completeness takes priority)
 *   - SAML > OIDC > DID multi-source priority (ordered by maturity of traditional enterprise federation deployments)
 *   - independent crVersion namespace (consistent with each sub-protocol pattern)
 *
 * csp v0.1 5-constraint compliance:
 *   Constraint 1: FULL (ResolvedCredentialIntegrityProof = verify-time signed payload primitive)
 *           + NOT-APPLICABLE (FederationIdentityLink.signature = issuance-time signature primitive;
 *           determined by the CR sub-protocol itself; see the CCR v0.1 pattern)
 *   Constraint 2: FULL — triple defense line (this three-layer defense architecture)
 *   Constraint 3: FULL — RFC 8785 JCS canonicalize (top-level import; implemented in the crypto layer)
 *   Constraint 4: FULL — CR_* namespace; 14 error codes frozen at v0.1; each code has >=1 throw
 *   Constraint 5: FULL — each design decision references the csp pattern as its rationale
 *
 * Anti-phantom defenses:
 *   1. each of the 14 error codes greps for a throw with 100% PASS (verified by source grep; avoids dead error codes)
 *   2. each method of the port interfaces (FederationLinkResolver / OidcPort / SamlPort / RevocationChecker) greps for an active invocation with PASS
 *   3. docstring + algorithm implementation cross-grep reconciliation is 100% PASS
 *   4. L2 implementation does not promote and forcibly enforce fields not literally required by the L0 spec (does not reuse the csp/RFP/atp/hcc/ms/dc/CCR/tb namespaces)
 *   5. cross-spec alignment is phantom-verified bidirectionally
 */

// Note: brand types in this file use the inline phantom-type pattern (consistent with the existing pattern in base.ts / multisig / hcc):
// `type X = string & { readonly __brand: 'X' }`
// The generic Brand<T> alias is not used (existing codebase convention; phantom-only; no runtime field).

// TenantId reuses the atp pattern (atp already exports TenantId = UuidV4String;
// CR reuses the UuidV4String pattern;
// re-export rather than redefine to avoid a same-name conflict; sub-protocol isolation stays consistent with the spec text).

import type { TenantId } from '../audit-tamper-proof/types.js';
export type { TenantId } from '../audit-tamper-proof/types.js';
// Note: the TenantId factory function reuses atp's toTenantId (this CR factories.ts does not redefine toTenantId);
// consistent through the atp module export chain atp-validation → factories → cr-validation.

// ─── csp linkage types (consumer-side verify-time primitive) ─────────────────────

/**
 * Note: ResolvedCredentialIntegrityProof does not directly import the CanonicalSignedPayload type;
 * instead it inlines the mandatory 5-field invariant (csp v0.1 constraint 1 FULL coverage applies — CR consumer-side verify-time
 * primitive; ResolvedCredentialIntegrityProof = verify-time signed payload primitive;
 * verifier issues challenge → holder rebinds the 5 fields → verifier validates).
 *
 * This design differs from ms v0.1 (which embeds a CanonicalSignedPayload field):
 *   - in ms v0.1 the csp fields are embedded into the multisig token as a wrapper
 *   - in CR v0.1, ResolvedCredentialIntegrityProof is an independent verify-time payload; the 5-field invariant is inlined
 *
 * Field composition: ResolvedCredentialIntegrityProof's 5 fields + cspVersion metadata.
 */

// ─── Brand Types (layer 1 defense; brand-cast guard; phantom-type only mode) ───────────────

/**
 * UserId — application-layer user brand (federation_identity_links.user_id FK target;
 * application-layer reference type for managed_service.users.id)
 *
 * factory: toUserId().
 * This brand is the FK field of the federation user → app user mapping;
 * three-way reconciliation: types (UserId) + JSON Schema (uuid format) + SQL DDL (FK constraint).
 */
export type UserId = string & { readonly __brand: 'UserId' };

/**
 * FederationLinkId — federation_identity_links.id brand (UUID v4)
 *
 * factory: toFederationLinkId().
 */
export type FederationLinkId = string & {
    readonly __brand: 'FederationLinkId';
};

/**
 * CrVersion — CR protocol version brand (independent namespace)
 *
 * The only valid v0.1 value is "1.0.0".
 *
 * Rationale for an independent namespace:
 *   uniform with each sub-protocol's independent-namespace pattern;
 *   a CR protocol change does not trigger a global specVersion breaking change;
 *   the crVersion field appears as metadata in the ResolvedCredential interface; backward-compatible.
 */
export type CrVersion = string & { readonly __brand: 'CrVersion' };

/**
 * OidcRawClaims — raw claim brand returned by an OIDC IdP (phantom-type only)
 *
 * Compile-time nominally incompatible with SamlRawClaims;
 * parseOidcClaims(samlInput) is a direct compile error (strongest type isolation).
 *
 * Casting `as OidcRawClaims` is forbidden; must be constructed via the toOidcRawClaims() factory
 * (factory = AJV schema validation + forced narrowing + top-level import block;
 * security defense = (a) compile-time nominal narrowing + (b) AJV strict schema validation).
 *
 * Field set source: OIDC Core 1.0 Standard Claims + ID Token Claims;
 * adding a Record<string, unknown> catch-all field is forbidden (new IdP-specific claims go through the NormalizedOidcClaims extension layer).
 */
export interface OidcRawClaimsFields {
    /** Issuer (OIDC Core mandatory)*/
    readonly iss: string;
    /** Subject Identifier (OIDC Core mandatory)*/
    readonly sub: string;
    /** Audience(s) (OIDC Core mandatory; string OR string[])*/
    readonly aud: string | readonly string[];
    /** Expiration time (OIDC Core mandatory; Unix epoch seconds)*/
    readonly exp: number;
    /** Issued at (OIDC Core mandatory; Unix epoch seconds)*/
    readonly iat: number;
    /** Not before (optional; Unix epoch seconds)*/
    readonly nbf?: number;
    /** OIDC nonce (replay protection; optional)*/
    readonly nonce?: string;
    /** Standard Claim*/
    readonly email?: string;
    /** Standard Claim*/
    readonly email_verified?: boolean;
    /** Standard Claim*/
    readonly preferred_username?: string;
    /** Standard Claim*/
    readonly name?: string;
}
export type OidcRawClaims = OidcRawClaimsFields & {
    readonly __brand: 'OidcRawClaims';
};

/**
 * SamlRawClaims — raw attribute brand returned by a SAML IdP (phantom-type only)
 *
 * Compile-time nominally incompatible with OidcRawClaims (strong type isolation).
 *
 * Field set source: SAML 2.0 Core Subject + AttributeStatement;
 * adding a Record<string, unknown> catch-all field is forbidden (new IdP-specific attributes go through the NormalizedSamlClaims extension layer).
 *
 * The attributes field uses ReadonlyMap<string, ReadonlyArray<string>>:
 * a SAML AttributeStatement is a multi-value attribute (a single attribute may have multiple values);
 * the Map structure enforces key-value uniqueness + ReadonlyArray enforces immutability.
 */
export interface SamlRawClaimsFields {
    /** SAML 2.0 Subject NameID (mandatory)*/
    readonly nameId: string;
    /** SAML 2.0 NameID Format URI*/
    readonly nameIdFormat: string;
    /** SAML 2.0 Issuer URI (mandatory)*/
    readonly issuer: string;
    /** SAML 2.0 AudienceRestriction (mandatory)*/
    readonly audience: string;
    /** ISO 8601 (optional)*/
    readonly notBefore?: string;
    /** ISO 8601 (optional)*/
    readonly notOnOrAfter?: string;
    /** SAML 2.0 SessionIndex (optional)*/
    readonly sessionIndex?: string;
    /** SAML 2.0 AttributeStatement (multi-value)*/
    readonly attributes: ReadonlyMap<string, ReadonlyArray<string>>;
}
export type SamlRawClaims = SamlRawClaimsFields & {
    readonly __brand: 'SamlRawClaims';
};

/**
 * NormalizedOidcClaims — normalized claim after extraction by the OIDC port implementation layer
 *
 * OidcPort.verifyCallback() is compile-time forced to return this type (not OidcRawClaims);
 * iss/aud/exp/iat extraction + validation + normalization must be done in the port implementation layer;
 * the sdk-api layer no longer performs claim extraction (the existing path is pushed down to the port implementation layer).
 *
 * The source discriminator field is added (discriminated union support);
 * dual defense of compile-time narrowing + AJV oneOf discriminator: { propertyName: 'source' }.
 */
export interface NormalizedOidcClaimsFields {
    /** discriminator (discriminated union support; TypeScript narrowing)*/
    readonly source: 'oidc';
    /** from raw.iss (extracted by the port implementation layer)*/
    readonly issuer: string;
    /** from raw.sub*/
    readonly subject: string;
    /** from raw.aud (string | string[] → readonly string[] normalization)*/
    readonly audience: readonly string[];
    /** from raw.exp (Unix → Date conversion)*/
    readonly expiresAt: Date;
    /** from raw.iat*/
    readonly issuedAt: Date;
    /** from raw.nonce*/
    readonly nonce?: string;
    readonly email?: string;
    readonly emailVerified?: boolean;
    readonly preferredUsername?: string;
    readonly displayName?: string;
}
export type NormalizedOidcClaims = NormalizedOidcClaimsFields & {
    readonly __brand: 'NormalizedOidcClaims';
};

/**
 * NormalizedSamlClaims — normalized claim after extraction by the SAML port implementation layer
 *
 * The SAML-side equivalent of NormalizedOidcClaims;
 * the source discriminator field is added (discriminated union support).
 */
export interface NormalizedSamlClaimsFields {
    /** discriminator (discriminated union support; TypeScript narrowing)*/
    readonly source: 'saml';
    /** from raw.issuer*/
    readonly issuer: string;
    /** from raw.nameId*/
    readonly subject: string;
    /** from raw.nameIdFormat*/
    readonly subjectFormat: string;
    /** from raw.audience (single value → readonly string[] array normalization)*/
    readonly audience: readonly string[];
    readonly notBefore?: Date;
    readonly notOnOrAfter?: Date;
    readonly sessionIndex?: string;
    readonly attributes: ReadonlyMap<string, ReadonlyArray<string>>;
}
export type NormalizedSamlClaims = NormalizedSamlClaimsFields & {
    readonly __brand: 'NormalizedSamlClaims';
};

// ─── Constants (factory function dependencies + program constraints) ─────────────────────────────────

/**
 * MAX_FEDERATION_LINK_DEPTH — maximum federation chain depth (hard gate)
 *
 * Single-hop federation (OIDC issuer → SAML SP → CR consumer;
 * v0.1 implements single-hop; multi-hop is a candidate for evaluation in future versions).
 *
 * This constraint is a program-level enforced invariant (hard gate), executed at resolveCredential step 2.
 */
export const MAX_FEDERATION_LINK_DEPTH = 3 as const;

/**
 * Set of versions supported by CR (v0.1's only value "1.0.0"; independent namespace)
 *
 * Future CR v0.2+ extensions are added to this array; no global specVersion upgrade is triggered.
 */
export const CR_SUPPORTED_VERSIONS: readonly string[] = ['1.0.0'] as const;

/**
 * CR v0.1 current-version brand constant (factory function default value)
 *
 * Converted via the toCrVersion() factory.
 */
export const CR_VERSION_1_0_0_RAW = '1.0.0' as const;

/**
 * CR_VERSION_1_0_0 — branded v0.1 current-version constant
 *
 * Note: this is a module top-level constant and must be validated + branded through the toCrVersion() factory;
 * callers are not allowed to use the RAW string directly (brand cast forbidden).
 */
export const CR_VERSION_1_0_0: CrVersion = CR_VERSION_1_0_0_RAW as CrVersion;

/**
 * csp v0.1 current version (constraint on CR ResolvedCredentialIntegrityProof.cspVersion field)
 *
 * Used by the verifyResolvedCredential cspVersion check.
 */
export const CR_CSP_VERSION_1_0_0 = '1.0.0' as const;

/**
 * notAfter default freshness window (1 hour = 3600s = 3,600,000 ms)
 *
 * buildIntegrityProof default freshness window.
 * Adjustable in future versions (caller override allowed; this is the default value).
 */
export const CR_INTEGRITY_PROOF_DEFAULT_NOT_AFTER_MS = 3_600_000 as const;

// ─── FederationSource discriminated union ────────────────────────────────────

/**
 * FederationSource — federation source type discriminated union
 *
 * SAML > OIDC > DID priority (ordered by maturity of traditional enterprise federation deployments).
 *
 * v0.1 implementation scope:
 *   - 'oidc': OIDC IdP (Okta / Azure AD / Google Workspace) — FULL support
 *   - 'saml': SAML 2.0 IdP (ADFS / Shibboleth / Okta SAML) — FULL support
 *   - 'did': DID-based federation — candidate for a future-version extension (v0.1 throws CR_VERSION_UNSUPPORTED;
 *            v0.1 does not implement PoP credential verification; step 1)
 */
export type FederationSource = 'oidc' | 'saml' | 'did';

// ─── Error codes (frozen at 14 entries; CR_* prefix) ─────────────────

/**
 * CrErrorCode — CR error-code namespace (CR_* prefix; v0.1 frozen at 14 entries)
 *
 * Frozen: 14 error codes; renaming / removing / changing severity is not allowed (breaking-format-change guard);
 * future CR v0.2+ may only add new CR_* error codes.
 *
 * Every error code must have at least one throw site (anti-phantom code; avoids defining unused error codes):
 *
 *   CR_FEDERATION_LINK_INVALID → step 3 (federation_identity_links lookup returned no result)
 *   CR_OIDC_CLAIM_INVALID → step 4 (OIDC claim verification failed) + factory brand-cast guard
 *   CR_SAML_CLAIM_INVALID → step 4 (SAML claim verification failed) + factory brand-cast guard
 *   CR_FK_VIOLATION → step 3 (defense-in-depth; runtime FK violation)
 *   CR_PORT_CONTRACT_VIOLATION → verifyResolvedCredential (port implementation layer contract violation)
 *   CR_BRAND_TYPE_MISMATCH → step 1 (brand type compile-time check leaked to runtime)
 *   CR_PROVIDER_UNAVAILABLE → OidcPort / SamlPort IdP unreachable (fail-closed; behavioral-constraint comment)
 *   CR_CREDENTIAL_REVOKED → step 6 (realtime revocation check OR link.revoked flag)
 *   CR_POP_BINDING_INVALID → step 5 (PoP credential → challenge binding verification; deferred in v0.1)
 *   CR_VERSION_UNSUPPORTED → step 1 + (crVersion / cspVersion / source=did)
 *   CR_INTEGRITY_PROOF_INVALID → buildIntegrityProof + (verification failure)
 *   CR_FRESHNESS_INVALID → (integrity proof expired / RFP linkage in future versions)
 *   CR_FEDERATION_LINK_DEPTH_EXCEEDED → step 2 (hard gate)
 *   CR_SCHEMA_INVALID → AJV strict validation failure (factory brand-cast guard) + type guard fail-closed
 *
 * Namespace isolation contract (csp v0.1 constraint 4):
 *   orthogonal to the CSP_* / RFP_* / DELEGATION_* / ATP_* / HCC_* / MS_* / CCR_* / TB_* namespaces;
 *   reusing another sub-protocol namespace is forbidden; mapping a single CR_X error code to another namespace's error at the same time is forbidden.
 */
export type CrErrorCode =
    | 'CR_FEDERATION_LINK_INVALID'
    | 'CR_OIDC_CLAIM_INVALID'
    | 'CR_SAML_CLAIM_INVALID'
    | 'CR_FK_VIOLATION'
    | 'CR_PORT_CONTRACT_VIOLATION'
    | 'CR_BRAND_TYPE_MISMATCH'
    | 'CR_PROVIDER_UNAVAILABLE'
    | 'CR_CREDENTIAL_REVOKED'
    | 'CR_POP_BINDING_INVALID'
    | 'CR_VERSION_UNSUPPORTED'
    | 'CR_INTEGRITY_PROOF_INVALID'
    | 'CR_FRESHNESS_INVALID'
    | 'CR_FEDERATION_LINK_DEPTH_EXCEEDED'
    | 'CR_SCHEMA_INVALID';

/**
 * CrError — CR L0/L1/L2 exception class (extends Error; does not extend ProtocolError)
 *
 * Design trade-off (the L0 error class pattern across sub-protocols is not forcibly unified):
 *   - CrError extends Error, consistent with the hcc/ms L0 pattern; type-layer refactors /
 *     interface signature refactors must first Read the referencing line numbers + Grep the number of callers
 *   - ProtocolError is a frozen union; new sub-protocol error codes should not be pushed into that union
 *     (namespace reservation; ProtocolErrorCode stays frozen)
 *   - an inline refactor empirically hits a TS2416 type conflict (.detail: Record<string, unknown>
 *     is incompatible with ProtocolError .detail: string) → adopt the extends Error baseline +
 *     the L0 error class pattern across sub-protocols is not forcibly unified
 *
 * Namespace isolation contract (csp v0.1 constraint 4):
 *   CR_* is orthogonal to the CSP_* / RFP_* / DELEGATION_* / ATP_* / HCC_* / MS_* / CCR_* / TB_* / CryptoError namespaces;
 *   CrError is not mixed with CspError / HashChainError / MultisigError.
 *
 * message prefix is forced to `[CR] <code>: <detail summary>` (vitest `.toThrow(/CR_X/)` regex friendly +
 * consistent audit log routing; complies with csp anti-phantom legislation).
 */
export class CrError extends Error {
    public override readonly name = 'CrError';
    public readonly code: CrErrorCode;
    public readonly detail?: Record<string, unknown>;

    public constructor(code: CrErrorCode, detail?: Record<string, unknown>) {
        // message: `[CR] <code>` (consistent consumer try/catch routing;
        // detail is accessed through the .detail field; not mixed into the message string)
        super(`[CR] ${code}`);
        this.code = code;
        this.detail = detail;
    }
}

/**
 * assertNeverCrCode — CrErrorCode exhaustive switch guard
 *
 * TypeScript compile-time exhaustive check;
 * if the CrErrorCode union later expands without being handled in the switch → compile-time failure.
 *
 * Anti-phantom design (structurally prevents silent skips):
 *   - all 14 cases handle each code literally;
 *   - default → assertNeverCrCode (TypeScript compile-time exhaustive guard);
 *   - if the CrErrorCode union later expands → compile-time failure → forces the developer
 *     to update the switch in sync (silent skip not allowed).
 *
 * @throws CrError unreachable at runtime; if triggered, the type system has been bypassed
 */
export function assertNeverCrCode(code: never): never {
    throw new CrError('CR_SCHEMA_INVALID', {
        reason: 'assertNeverCrCode_unreachable',
        unexpectedCode: String(code),
    });
}

/**
 * CrErrorContext — handleCrError processing result
 *
 * handleCrError switch with 14 cases; HTTP status candidates are consistent with the mapping table.
 */
export interface CrErrorContext {
    /** error code (CR_*)*/
    readonly code: CrErrorCode;
    /** HTTP status code (4xx/5xx; candidate set; fail-closed)*/
    readonly httpStatus: 400 | 422 | 500 | 503;
    /** error message (literal description; reference for consumer try/catch routing)*/
    readonly message: string;
    /** severity (HIGH / CRITICAL / MED)*/
    readonly severity: 'CRITICAL' | 'HIGH' | 'MED';
}

/**
 * handleCrError — CrErrorCode switch with full coverage of 14 cases + assertNeverCrCode exhaustive
 *
 * Every CrErrorCode value must have a corresponding case; default → assertNeverCrCode ensures the compile-time exhaustive check.
 *
 * fail-closed principle: all errors map to 4xx/5xx; stubbing a 200 is not allowed.
 */
export function handleCrError(code: CrErrorCode): CrErrorContext {
    switch (code) {
        case 'CR_FEDERATION_LINK_INVALID':
            return {
                code,
                httpStatus: 422,
                message:
                    'Credential resolver: federation_identity_links lookup returned no result',
                severity: 'HIGH',
            };
        case 'CR_OIDC_CLAIM_INVALID':
            return {
                code,
                httpStatus: 422,
                message:
                    'Credential resolver: OIDC claim verification failed (issuer mismatch / expired / signature)',
                severity: 'HIGH',
            };
        case 'CR_SAML_CLAIM_INVALID':
            return {
                code,
                httpStatus: 422,
                message:
                    'Credential resolver: SAML claim verification failed (issuer mismatch / expired / signature)',
                severity: 'HIGH',
            };
        case 'CR_FK_VIOLATION':
            return {
                code,
                httpStatus: 500,
                message:
                    'Credential resolver: federation_identity_links.user_id FK violation (orphan / null; defense-in-depth)',
                severity: 'CRITICAL',
            };
        case 'CR_PORT_CONTRACT_VIOLATION':
            return {
                code,
                httpStatus: 500,
                message:
                    'Credential resolver: port implementation violated contract (returned unbranded type / invalid field)',
                severity: 'CRITICAL',
            };
        case 'CR_BRAND_TYPE_MISMATCH':
            return {
                code,
                httpStatus: 500,
                message:
                    'Credential resolver: brand type compile-time check leaked to runtime (NormalizedOidcClaims marker mismatch / source enum)',
                severity: 'CRITICAL',
            };
        case 'CR_PROVIDER_UNAVAILABLE':
            return {
                code,
                httpStatus: 503,
                message:
                    'Credential resolver: OIDC/SAML IdP upstream unavailable (fail-closed;no degradation)',
                severity: 'HIGH',
            };
        case 'CR_CREDENTIAL_REVOKED':
            return {
                code,
                httpStatus: 422,
                message:
                    'Credential resolver: federated credential revoked (realtime check OR link.revoked flag)',
                severity: 'CRITICAL',
            };
        case 'CR_POP_BINDING_INVALID':
            return {
                code,
                httpStatus: 422,
                message:
                    'Credential resolver: PoP credential → challenge binding verification failed (not implemented in v0.1)',
                severity: 'HIGH',
            };
        case 'CR_VERSION_UNSUPPORTED':
            return {
                code,
                httpStatus: 422,
                message:
                    'Credential resolver: crVersion / cspVersion not in supported set, OR source=did v0.1 not supported',
                severity: 'MED',
            };
        case 'CR_INTEGRITY_PROOF_INVALID':
            return {
                code,
                httpStatus: 422,
                message:
                    'Credential resolver: ResolvedCredentialIntegrityProof construction/verification failed (canonicalize / challenge mismatch / audience mismatch / signature)',
                severity: 'HIGH',
            };
        case 'CR_FRESHNESS_INVALID':
            return {
                code,
                httpStatus: 422,
                message:
                    'Credential resolver: integrityProof expired (notAfter < now) OR RFP freshness check failed',
                severity: 'HIGH',
            };
        case 'CR_FEDERATION_LINK_DEPTH_EXCEEDED':
            return {
                code,
                httpStatus: 422,
                message:
                    'Credential resolver: federation link depth exceeded MAX_FEDERATION_LINK_DEPTH (hard gate)',
                severity: 'CRITICAL',
            };
        case 'CR_SCHEMA_INVALID':
            return {
                code,
                httpStatus: 422,
                message:
                    'Credential resolver: input data failed AJV strict mode JSON Schema validation (factory brand-cast guard / type guard fail-closed)',
                severity: 'MED',
            };
        default:
            return assertNeverCrCode(code);
    }
}

// ─── FederationIdentityLink Interface ──────────────

/**
 * FederationIdentityLink — federation user → app user mapping record
 *
 * Persisted to the federation_identity_links table (created by 024_sso_federation.sql).
 *
 * Invariants:
 *   - iss/aud claim extraction is done in the OidcPort/SamlPort implementation layer
 *   - federation_identity_links.user_id FK is enforced (Schema/SQL/runtime triple defense line)
 *
 * user_id must carry FK REFERENCES managed_service.users(id) ON DELETE RESTRICT
 *   RESTRICT is preferred over CASCADE — audit completeness takes priority;
 *     atp v0.1 linkage (federation_identity_links is audit-relevant data;
 *     it should not be automatically cascade-deleted; RESTRICT forces the business layer to explicitly handle
 *     federation_identity_links revocation via the link.revoked = true path rather than physical deletion).
 *
 * Note: the signature field is the federation issuer's offline signature (issuance-time signature primitive;
 * not within the scope of the csp 5-field invariant;
 * the sub-protocol itself determines NOT-APPLICABLE; see the CCR v0.1 pattern).
 */
export interface FederationIdentityLink {
    /** federation_identity_links.id (PK; UUID v4 brand)*/
    readonly id: FederationLinkId;
    /** tenant isolation (multi-tenant; UUID v4 brand)*/
    readonly tenantId: TenantId;
    /** federation source type (oidc / saml / did)*/
    readonly source: FederationSource;
    /** federation issuer URI (OIDC iss / SAML Issuer / DID controller)*/
    readonly issuer: string;
    /** federation-side subject (OIDC sub / SAML NameID / DID identifier)*/
    readonly federatedSubject: string;
    /**
     * app user ID (FK → managed_service.users.id)
     * DDL must carry REFERENCES managed_service.users(id) ON DELETE RESTRICT
     */
    readonly userId: UserId;
    /**
     * federation issuer offline signature (issuance-time;
     * not within the scope of the csp 5-field invariant; NOT-APPLICABLE)
     * format: hex encoding of a 64-byte Ed25519 signature (128 lowercase hex chars)
     */
    readonly signature: string;
    /** link creation time (ISO 8601 UTC)*/
    readonly createdAt: string;
    /** link last-verified time (periodic verification; optional)*/
    readonly lastVerifiedAt?: string;
    /** whether the link is revoked (revoked = true → fail-closed reject)*/
    readonly revoked: boolean;
    /**
     * expected audience (authoritative source)
     *
     * The audience bound when the federation issuer issued the credential. Once configured it is the authoritative source:
     * audience validation must use this value (do not fall back to the caller-provided request.verifierDid),
     * to prevent audience-confusion (an attacker using a claim issued for the attacker's audience + setting verifierDid to match).
     * When not configured (for backward compatibility) it degrades to request.verifierDid (a weaker mode; deployments should configure it as soon as possible).
     */
    readonly expectedAudience?: string;
}

// ─── ResolvedCredentialIntegrityProof Interface ───

/**
 * ResolvedCredentialIntegrityProof — verify-time signed payload (csp constraint 1 FULL coverage)
 *
 * The CR resolver signs the resolution result as a whole, validated verify-time on the consumer side;
 * follows csp v0.1 constraint 1: the mandatory 5-field invariant + cspVersion metadata field.
 *
 * 5-field invariant:
 *   1. token: canonical identifier of the credential resolution result
 *      (token = CR-specific canonical identifier of the resolution result;
 *       CR token form: `cr:{linkId}:user={userId}`; upgrading to a hash digest is to be evaluated in future versions)
 *   2. disclosedClaims: set of disclosed normalized claims (selective disclosure on demand)
 *   3. challenge: verifier-side random challenge value (anti-replay-attack)
 *   4. audience: verifier DID (anti-audience-hijack)
 *   5. notAfter: expiration of the credential integrity proof's validity (ISO 8601; expired = CR_FRESHNESS_INVALID)
 *
 * metadata fields:
 *   - cspVersion: csp protocol version (mandatory; v0.1's only value "1.0.0")
 *   - proofSignature: Ed25519 signature (after JCS canonicalize; hex 128 chars)
 *   - resolverDid: signing resolver DID
 */
export interface ResolvedCredentialIntegrityProof {
    /**
     * token — canonical identifier of the credential resolution result (csp 5-field invariant field 1)
     *
     * token = CR-specific canonical identifier of the resolution result (not a CapabilityToken hash digest);
     * CR token form: `cr:{linkId}:user={userId}` (produced by buildIntegrityProof);
     * upgrading to a hash digest is to be evaluated in future versions.
     */
    readonly token: string;

    /**
     * disclosedClaims — set of disclosed normalized claims (csp 5-field invariant field 2)
     * contains issuer + subject + userId (selective disclosure on demand)
     */
    readonly disclosedClaims: readonly string[];

    /**
     * challenge — verifier-side random challenge value (csp 5-field invariant field 3)
     * anti-replay-attack; verifier generates + holder rebinds + verifier validates
     */
    readonly challenge: string;

    /**
     * audience — verifier DID (csp 5-field invariant field 4)
     * anti-audience-hijack; bound to a specific verifier
     * format: did:* DID string
     */
    readonly audience: string;

    /**
     * notAfter — expiration of the credential integrity proof's validity (csp 5-field invariant field 5)
     * ISO 8601; expired = CR_FRESHNESS_INVALID
     */
    readonly notAfter: string;

    /**
     * cspVersion — csp protocol version metadata (csp constraint 1 mandatory metadata)
     * v0.1's only value: "1.0.0" (CR_CSP_VERSION_1_0_0 constant)
     */
    readonly cspVersion: string;

    /**
     * proofSignature — credential integrity proof signature (Ed25519; after JCS canonicalize)
     * format: hex encoding of a 64-byte signature (128 lowercase hex chars)
     */
    readonly proofSignature: string;

    /**
     * resolverDid — the resolver DID that signed the credential integrity proof
     * semantically consistent with the RFP v0.1 resolverDid field
     * format: did:* DID string
     */
    readonly resolverDid: string;
}

// ─── ResolvedCredential Interface ─────────────────

/**
 * ResolvedCredential — final credential resolution result (used on the consumer side)
 *
 * Removed the three fields freshnessVerified + chainVerified + popBindingValid
 * (phantom invariants never checked in v0.1; to be reintroduced in future versions).
 */
export interface ResolvedCredential {
    /** CR protocol version (independent namespace; CrVersion brand)*/
    readonly crVersion: CrVersion;

    /** federation user → app user mapping record*/
    readonly link: FederationIdentityLink;

    /** federation source*/
    readonly source: FederationSource;

    /** normalized claims (OIDC OR SAML; after normalization by the port implementation layer)*/
    readonly normalizedClaims: NormalizedOidcClaims | NormalizedSamlClaims;

    /**
     * realtime revocation check result (true = not revoked)
     * Note: false will not appear — revocation directly throws CR_CREDENTIAL_REVOKED (fail-closed)
     */
    readonly notRevoked: boolean;

    /** verify-time signed payload (csp constraint 1 FULL coverage)*/
    readonly integrityProof: ResolvedCredentialIntegrityProof;

    /** resolution completion timestamp (ISO 8601 UTC)*/
    readonly resolvedAt: string;
}

// ─── CredentialResolutionRequest Interface ────────

/**
 * CredentialResolutionRequest — CR resolution request input (consumer-side call)
 *
 * The claims field is a discriminated union (NormalizedOidcClaims | NormalizedSamlClaims);
 * TypeScript narrows at compile time via the source field:
 *   request.source === 'oidc' → request.claims narrows to NormalizedOidcClaims
 *   request.source === 'saml' → request.claims narrows to NormalizedSamlClaims
 *
 * This narrowing defends against nominal mismatch (parseOidcClaims(samlInput) fails at compile time).
 */
export interface CredentialResolutionRequest {
    /** federation source type (oidc / saml; did throws CR_VERSION_UNSUPPORTED in v0.1)*/
    readonly source: FederationSource;

    /** consumer tenant (multi-tenant isolation)*/
    readonly tenantId: TenantId;

    /** verifier-side challenge value (random; anti-replay; bound to ResolvedCredential.integrityProof.challenge)*/
    readonly challenge: string;

    /** verifier DID (audience binding; format: did:* DID string)*/
    readonly verifierDid: string;

    /** input claims (OIDC OR SAML; TypeScript discriminated union compile-time narrowing)*/
    readonly claims: NormalizedOidcClaims | NormalizedSamlClaims;

    /** maximum allowed federation link depth specified by the caller (optional; defaults to MAX_FEDERATION_LINK_DEPTH)*/
    readonly maxLinkDepth?: number;
}

// ─── CredentialResolution Interface ───────────────

/**
 * CredentialResolution — top-level resolution transaction (includes audit event linkage)
 *
 * Note: atp v0.1 audit event recording is the caller's responsibility (the implementation-layer sso-callback handler);
 *     the resolver does not write audit events directly; interface boundaries stay clean.
 */
export interface CredentialResolution {
    /** CR protocol version (independent namespace)*/
    readonly crVersion: CrVersion;

    /** resolution request*/
    readonly request: CredentialResolutionRequest;

    /** resolution result (success path)*/
    readonly resolved: ResolvedCredential;

    /** atp v0.1 audit event ID (auditEvent.id; atp linkage)*/
    readonly auditEventId: string;
}
