/**
 * Credential Resolver (CR) sub-protocol v0.1 — L0 factory functions (no-brand-cast guard)
 *
 *
 * No-brand-cast guard: every brand type can only be obtained via a to*() factory function;
 *           direct brand casts like `as TenantId` / `as UserId` / `as OidcRawClaims` are strictly forbidden.
 *
 * Full canonical factory implementation (phantom-type pattern; no bare casts):
 *   security boundary = AJV strict schema validate + compile-time nominal narrow;
 *   no __brand field exists at runtime (consistent with the base.ts pattern);
 *   a single internal cast at the factory exit (protected by schema validate / format checks).
 *
 * Anti-phantom defense:
 *   - a single `as X` cast at the factory exit (TypeScript brand narrow; not counted as a counterexample — runtime validation + brand narrow);
 *   - `as unknown as X` double-cast bypass is strictly forbidden;
 *   - external `value as X` calls are strictly forbidden (must go through a factory function).
 */

import { validateCr } from './cr-validation.js';
import {
    CR_SUPPORTED_VERSIONS,
    CrError,
    type CrVersion,
    type FederationLinkId,
    type NormalizedOidcClaims,
    type NormalizedSamlClaims,
    type OidcRawClaims,
    type SamlRawClaims,
    type UserId,
} from './types.js';

// The TenantId factory reuses atp toTenantId (sub-protocol isolation);
// re-exported rather than redefined; atp already exports toTenantId(s: string): TenantId with UUID v4 validation.
export { toTenantId } from '../audit-tamper-proof/types.js';

// ─── UUID v4 + ISO 8601 + DID format regexes (factory-validation dependencies) ────────────────────

/**
 * Strict UUID v4 regex (RFC 4122):
 *   - 32 hex chars + 4 dashes
 *   - 13th char (version) = 4
 *   - 17th char (variant) ∈ {8, 9, a, b} (RFC 4122 variant 10xx)
 */
const UUID_V4_PATTERN =
    /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

/**
 * semver regex (X.Y.Z; CR crVersion semver format validation)
 */
const SEMVER_PATTERN = /^[0-9]+\.[0-9]+\.[0-9]+$/;

// ─── UUID-family brand factories (UserId / FederationLinkId; TenantId re-exported from atp) ─

/**
 * toUserId — UserId brand-type factory function (FK target of federation_identity_links.user_id)
 *
 * No-brand-cast guard: the only legal path to obtain a UserId; validates UUID v4 format at runtime.
 * Three-way reconciliation of types/Schema/SQL consistency (this is the types-layer check).
 *
 * @throws CrError(CR_SCHEMA_INVALID) if the format is non-compliant
 */
export function toUserId(s: string): UserId {
    if (typeof s !== 'string') {
        throw new CrError('CR_SCHEMA_INVALID', {
            reason: 'userId_must_be_string',
            received: typeof s,
        });
    }
    if (!UUID_V4_PATTERN.test(s)) {
        throw new CrError('CR_SCHEMA_INVALID', {
            reason: 'userId_not_uuid_v4',
            received: s,
        });
    }
    return s as UserId;
}

/**
 * toFederationLinkId — FederationLinkId brand-type factory function
 *
 * Enforced through the factory (no brand cast).
 *
 * @throws CrError(CR_SCHEMA_INVALID) if the format is non-compliant
 */
export function toFederationLinkId(s: string): FederationLinkId {
    if (typeof s !== 'string') {
        throw new CrError('CR_SCHEMA_INVALID', {
            reason: 'federationLinkId_must_be_string',
            received: typeof s,
        });
    }
    if (!UUID_V4_PATTERN.test(s)) {
        throw new CrError('CR_SCHEMA_INVALID', {
            reason: 'federationLinkId_not_uuid_v4',
            received: s,
        });
    }
    return s as FederationLinkId;
}

// ─── CrVersion brand factory (independent namespace) ───────────────

/**
 * toCrVersion — CrVersion brand-type factory function
 *
 * No-brand-cast guard: the only legal path to obtain a CrVersion;
 * validates semver format + the legal value set at runtime (v0.1 only "1.0.0").
 *
 * Independent crVersion namespace; consistent with the 8 sub-protocol patterns csp/tb/RFP/atp/hcc/ms/dc/CCR;
 * not coupled to token.specVersion.
 *
 * @throws CrError(CR_VERSION_UNSUPPORTED) if the format or version is non-compliant
 */
export function toCrVersion(s: string): CrVersion {
    if (typeof s !== 'string') {
        throw new CrError('CR_VERSION_UNSUPPORTED', {
            reason: 'crVersion_must_be_string',
            received: typeof s,
        });
    }
    if (!SEMVER_PATTERN.test(s)) {
        throw new CrError('CR_VERSION_UNSUPPORTED', {
            reason: 'crVersion_not_semver',
            received: s,
        });
    }
    if (!CR_SUPPORTED_VERSIONS.includes(s)) {
        throw new CrError('CR_VERSION_UNSUPPORTED', {
            reason: 'crVersion_not_in_supported_set',
            received: s,
            supported: CR_SUPPORTED_VERSIONS,
        });
    }
    return s as CrVersion;
}

// ─── OidcRawClaims / SamlRawClaims factories (nominal isolation) ────────

/**
 * toOidcRawClaims — OidcRawClaims brand-type factory function
 *
 * No-brand-cast guard: the only legal path to obtain an OidcRawClaims;
 * phantom-type pattern: the factory only runs schema validate + a forced type narrow;
 * appending a runtime __brand field is strictly forbidden; the double cast `as unknown as OidcRawClaims` is strictly forbidden.
 *
 * Security boundary = (a) compile-time nominal narrow + (b) AJV strict schema validate (runtime);
 * no __brand field exists at runtime (consistent with the base.ts pattern).
 *
 * @throws CrError(CR_OIDC_CLAIM_INVALID) if schema validate fails
 */
export function toOidcRawClaims(input: unknown): OidcRawClaims {
    const result = validateCr('OidcRawClaims', input);
    if (!result.valid) {
        throw new CrError('CR_OIDC_CLAIM_INVALID', {
            reason: 'oidc_raw_claims_schema_validate_failed',
            errors: result.errors,
        });
    }
    // phantom-type narrow: after AJV validate, input is type-asserted to OidcRawClaims
    // (no runtime field appended; security boundary = AJV strict schema validate + compile-time nominal narrow)
    return input as OidcRawClaims;
}

/**
 * toSamlRawClaims — SamlRawClaims brand-type factory function (SAML side)
 *
 * Same pattern as toOidcRawClaims.
 *
 * Note: SamlRawClaims.attributes has type ReadonlyMap<string, ReadonlyArray<string>>,
 * but the JSON Schema represents it as an object (key-value serialization); the factory accepts plain-object input
 * (the caller is responsible for serializing the Map to a plain object before passing it to validate;
 * the caller may also directly construct the OnboardOidcRawClaims form or the pure OidcRawClaims form — the runtime type is not enforced).
 *
 * @throws CrError(CR_SAML_CLAIM_INVALID) if schema validate fails
 */
export function toSamlRawClaims(input: unknown): SamlRawClaims {
    const result = validateCr('SamlRawClaims', input);
    if (!result.valid) {
        throw new CrError('CR_SAML_CLAIM_INVALID', {
            reason: 'saml_raw_claims_schema_validate_failed',
            errors: result.errors,
        });
    }
    return input as SamlRawClaims;
}

/**
 * toNormalizedOidcClaims — NormalizedOidcClaims brand-type factory function
 *
 * Two-layer guard of source discriminator + AJV validate;
 * phantom-only narrow (security boundary = AJV strict + nominal narrow).
 *
 * Note: for runtime objects like Date / readonly[] — the caller is responsible for converting the Unix epoch to Date before construction,
 * and normalizing audience string|string[] to readonly string[]; the factory validates via schema comparison against a plain object.
 *
 * @throws CrError(CR_BRAND_TYPE_MISMATCH) if source !== 'oidc'
 * @throws CrError(CR_OIDC_CLAIM_INVALID) if schema validate fails
 */
export function toNormalizedOidcClaims(input: unknown): NormalizedOidcClaims {
    if (typeof input !== 'object' || input === null) {
        throw new CrError('CR_BRAND_TYPE_MISMATCH', {
            reason: 'normalizedOidcClaims_input_not_object',
            received: typeof input,
        });
    }
    const obj = input as Record<string, unknown>;
    if (obj['source'] !== 'oidc') {
        throw new CrError('CR_BRAND_TYPE_MISMATCH', {
            reason: 'normalizedOidcClaims_source_mismatch',
            expected: 'oidc',
            received: String(obj['source']),
        });
    }
    const result = validateCr('NormalizedOidcClaims', input);
    if (!result.valid) {
        throw new CrError('CR_OIDC_CLAIM_INVALID', {
            reason: 'normalized_oidc_claims_schema_validate_failed',
            errors: result.errors,
        });
    }
    return input as NormalizedOidcClaims;
}

/**
 * toNormalizedSamlClaims — NormalizedSamlClaims brand-type factory function
 *
 * Same pattern as toNormalizedOidcClaims.
 *
 * @throws CrError(CR_BRAND_TYPE_MISMATCH) if source !== 'saml'
 * @throws CrError(CR_SAML_CLAIM_INVALID) if schema validate fails
 */
export function toNormalizedSamlClaims(input: unknown): NormalizedSamlClaims {
    if (typeof input !== 'object' || input === null) {
        throw new CrError('CR_BRAND_TYPE_MISMATCH', {
            reason: 'normalizedSamlClaims_input_not_object',
            received: typeof input,
        });
    }
    const obj = input as Record<string, unknown>;
    if (obj['source'] !== 'saml') {
        throw new CrError('CR_BRAND_TYPE_MISMATCH', {
            reason: 'normalizedSamlClaims_source_mismatch',
            expected: 'saml',
            received: String(obj['source']),
        });
    }
    const result = validateCr('NormalizedSamlClaims', input);
    if (!result.valid) {
        throw new CrError('CR_SAML_CLAIM_INVALID', {
            reason: 'normalized_saml_claims_schema_validate_failed',
            errors: result.errors,
        });
    }
    return input as NormalizedSamlClaims;
}
