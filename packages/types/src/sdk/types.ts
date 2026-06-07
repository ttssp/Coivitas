/**
 * SDK sub-protocol v0.2 L0 type definitions — cryptographic transport verify primitive
 *
 * sub-protocol — sdk v0.2
 * New sub-protocol: no v0.1 baseline (the sr v0.1 revocation phase + audit-share v0.2 step 0 commitment anchor are physically landed)
 *
 * Main contents of sdk v0.2:
 *   - TrustedSettlerDid brand type (DID & { __brand: 'TrustedSettlerDid' }; naked cast strictly forbidden)
 *   - CertSubjectDn / JwtSubject / OAuth2ClientId brand types (cryptographic verifier input evidence fields)
 *   - SdkVersionString brand type (sdkVersion metadata field; the only legal v0.2 value is "2.0.0")
 *   - VerifierKind union ('mtls' | 'jwt' | 'oauth2')
 *   - MtlsVerifierContext / JwtVerifierContext / OAuth2VerifierContext (inputs for the 3 verifier kinds)
 *   - VerifiedTransportContext (the verified context produced after the verifier succeeds)
 *   - SdkErrorCode union (6 SDK_*-prefixed items; frozen)
 *   - SdkError extends Error (does not inherit ProtocolError)
 *
 * Triple defense (reusing the csp pattern):
 *   Layer 1: TypeScript brand type (compile time; this file)
 *   Layer 2: factory-layer cryptographic verifier (runtime factory layer; packages/sdk/src/cryptographic-verifier/)
 *   Layer 3: boundary-layer cross-check mapping enforcement (L3 boundary layer; the sub-protocol consumption boundary)
 *
 * No brand cast: TrustedSettlerDid can only be constructed via one of the 3 cryptographic verifier factory kinds;
 *           a direct `did as TrustedSettlerDid` cast is strictly forbidden (I1 invariant).
 *
 * Error code namespace isolation (6 v0.2 items frozen; SDK_* prefix):
 *   - SDK_MTLS_VERIFY_FAILED — mTLS cert chain / cert parse failed (I2)
 *   - SDK_JWT_VERIFY_FAILED — JWT signature / exp / iss / aud verify failed (I4)
 *   - SDK_OAUTH2_VERIFY_FAILED — OAuth2 introspection failed (I6)
 *   - SDK_MAPPING_MISMATCH — cross-check mapping literal inequality (I3/I5/I7)
 *   - SDK_SCHEMA_VIOLATION — schema validation failed / sdkVersion is not "2.0.0" (I8/I9)
 *   - SDK_FIXTURE_CROSS_LANG_MISMATCH — cross-lang fixture consistency broken
 */

import type { DID } from '../base.js';

// ─── Brand Types (layer-1 defense; no brand cast) ───────────────────────────────────────

/**
 * TrustedSettlerDid — a trusted DID brand derived via a cryptographic verifier
 *
 * Design intent:
 *   - can only be constructed via the sdk v0.2 cryptographic verifier factory (mTLS / JWT / OAuth2);
 *     a raw DID `as TrustedSettlerDid` naked cast is strictly forbidden (I1 invariant)
 *   - cryptographic guard when the sub-protocol consumes a TrustedSettlerDid
 *     (the L3 boundary layer requires literal equality between the verifier identity and expectedDid)
 *   - the sr v0.1 revocation phase + audit-share v0.2 step 0 commitment anchor are physically landed
 */
export type TrustedSettlerDid = DID & { readonly __brand: 'TrustedSettlerDid' };

/**
 * CertSubjectDn — mTLS cert subject DN brand (a field after cert parsing)
 *
 * The cert subject DN is extracted, then enters cross-check mapping (verifies the SAN URI / CN field equals the DID).
 * factory path: packages/sdk/src/cryptographic-verifier/mtls.ts extractDidFromCertSubject()
 */
export type CertSubjectDn = string & { readonly __brand: 'CertSubjectDn' };

/**
 * JwtSubject — JWT verified payload.sub brand (a field after JWT signature + exp + iss verify)
 *
 * After jose@5 jwtVerify() built-in verify, payload.sub is extracted and enters cross-check mapping.
 * factory path: packages/sdk/src/cryptographic-verifier/jwt.ts verifyJwtAndDeriveDid()
 */
export type JwtSubject = string & { readonly __brand: 'JwtSubject' };

/**
 * OAuth2ClientId — OAuth2 introspection response client_id brand
 *
 * After a successful introspection response, client_id (or sub) is extracted and enters cross-check mapping.
 * factory path: packages/sdk/src/cryptographic-verifier/oauth2.ts verifyOAuth2AndDeriveDid()
 */
export type OAuth2ClientId = string & { readonly __brand: 'OAuth2ClientId' };

/**
 * SdkVersionString — sdk protocol version brand type
 *
 * The sdkVersion metadata field version brand; the only legal v0.2 value is "2.0.0".
 * A `s as SdkVersionString` naked cast is strictly forbidden (no brand cast).
 * factory path: toSdkVersionString() (L1 impl layer)
 */
export type SdkVersionString = string & {
    readonly __brand: 'SdkVersionString';
};

// ─── VerifierKind Union ───────────────────────────────────────────────────────

/**
 * VerifierKind — type discriminator union for the 3 cryptographic verifier kinds
 *
 * The verifierKind metadata field of verifiedTransportContext.
 * No fallback / unknown / partial verifier kind path is allowed.
 */
export type VerifierKind = 'mtls' | 'jwt' | 'oauth2';

// ─── Verifier Context Interfaces (3 kinds) ───────────────────────────────

/**
 * MtlsVerifierContext — mTLS verifier input context
 *
 * @peculiar/x509 cert parse + chain validation + DID extraction (I2+I3 invariants)
 */
export interface MtlsVerifierContext {
    /** mTLS client cert (DER bytes or PEM string; @peculiar/x509 parse)*/
    clientCert: Uint8Array | string;
    /** trust root CA cert (trusted root cert pool)*/
    trustedRootCerts: (Uint8Array | string)[];
    /** Optional: intermediate CA chain (cert chain verify)*/
    intermediateChain?: (Uint8Array | string)[];
    /** the expected DID (cross-check mapping literal-equality verify; I3 invariant)*/
    expectedDid: DID;
}

/**
 * JwtVerifierContext — JWT verifier input context
 *
 * jose@5 jwtVerify() built-in + signature verify + exp + iss + aud (I4+I5 invariants)
 */
export interface JwtVerifierContext {
    /** JWT compact serialization (header.payload.signature)*/
    jwt: string;
    /** JWKS endpoint URL (key rotation support) or a static JWK Set*/
    jwks: string | { keys: unknown[] };
    /** the expected issuer (iss claim verify; literal equality)*/
    expectedIssuer: string;
    /** the expected audience (aud claim verify; literal equality)*/
    expectedAudience: string;
    /** the expected DID (cross-check mapping sub claim literal-equality verify; I5 invariant)*/
    expectedDid: DID;
    /**
     * Allow symmetric algorithms (HS256/HS384/HS512; restricted context; default false)
     *
     * Design intent:
     *   - default false — the sub-protocol consumer baseline is asymmetric only (RS256/ES256/EdDSA)
     *   - true — the caller explicitly opts in (mTLS server-to-server only context; ok for a restricted deployment)
     *   - corresponds to JWT_ALG_ALLOWLIST.symmetric_restricted (verifyJwtAlgAllowed)
     */
    allowSymmetricAlg?: boolean;
}

/**
 * OAuth2VerifierContext — OAuth2 introspection verifier input context
 *
 * openid-client@6 introspection + active + aud + exp (I6+I7 invariants)
 */
export interface OAuth2VerifierContext {
    /** OAuth2 access token (Bearer token)*/
    accessToken: string;
    /**
     * OAuth2 issuer URL
     *
     * openid-client discovery() takes the issuer URL, fetches .well-known/openid-configuration,
     * and auto-discovers the introspection_endpoint. Do not pass the introspection endpoint itself (it would fetch metadata from the wrong location).
     */
    issuerUrl: string;
    /**
     * OAuth2 introspection endpoint URL (authority binding + optional explicit override)
     *
     * By default auto-discovered by discovery from the issuer metadata; this field is used to cache the authority binding,
     * and for non-standard deployments to explicitly specify the introspection endpoint.
     */
    introspectionEndpoint: string;
    /** OAuth2 client credentials (introspection endpoint authentication)*/
    introspectionClientId: string;
    introspectionClientSecret: string;
    /** the expected audience (introspection response aud claim verify)*/
    expectedAudience: string;
    /** the expected DID (cross-check mapping client_id or sub claim literal-equality verify; I7 invariant)*/
    expectedDid: DID;
}

// ─── VerifiedTransportContext (verifier success output) ────────────────────────

/**
 * VerifiedTransportContext — the verified context produced after the verifier succeeds
 *
 * All 5 fields present (I8 invariant); the only legal sdkVersion value is "2.0.0" (I9 invariant).
 *
 * Design intent:
 *   - the verifier factory success path produces TrustedSettlerDid + cryptographic-verified mapping fields
 *   - when the sub-protocol consumes it, it receives TrustedSettlerDid + verifier kind metadata via the transport context
 *   - the fields consumed by the L3 boundary layer's 4-dimension boundary check
 */
export interface VerifiedTransportContext {
    /** Trusted DID brand (derived by the cryptographic verifier; consumed literally by the sub-protocol)*/
    trustedDid: TrustedSettlerDid;
    /** Verifier kind (mTLS / JWT / OAuth2; defense-in-depth metadata)*/
    verifierKind: VerifierKind;
    /** Verifier-specific evidence (mTLS cert subject DN / JWT sub claim / OAuth2 client_id)*/
    verifiedSubject: CertSubjectDn | JwtSubject | OAuth2ClientId;
    /** Verifier timestamp (ISO 8601 UTC; defense-in-depth audit)*/
    verifiedAt: string;
    /** sdkVersion metadata (the only legal v0.2 value is "2.0.0"; I9 invariant)*/
    sdkVersion: string;
}

// ─── SDK error codes (SDK_* namespace isolation; 6 v0.2 items frozen) ─────────────────

/**
 * SdkErrorCode — sdk error code namespace (SDK_* prefix; 6 v0.2 items frozen)
 *
 * 6 SDK_*-prefixed items (no collision with HC_* / CSP_* / TB_* / RFP_* / AUDIT_* / TOKEN_*)
 *
 *   SDK_MTLS_VERIFY_FAILED → I2 mTLS cert chain / cert parse failed
 *   SDK_JWT_VERIFY_FAILED → I4 JWT signature / exp / iss / aud verify failed
 *   SDK_OAUTH2_VERIFY_FAILED → I6 OAuth2 introspection failed
 *   SDK_MAPPING_MISMATCH → I3/I5/I7 cross-check mapping literal inequality
 *   SDK_SCHEMA_VIOLATION → I8/I9 schema validation failed / sdkVersion is not "2.0.0"
 *   SDK_FIXTURE_CROSS_LANG_MISMATCH → cross-lang fixture consistency broken
 *
 * Frozen: 6 error codes; later v0.3+ may only add new ones.
 */
export type SdkErrorCode =
    | 'SDK_MTLS_VERIFY_FAILED'
    | 'SDK_JWT_VERIFY_FAILED'
    | 'SDK_OAUTH2_VERIFY_FAILED'
    | 'SDK_MAPPING_MISMATCH'
    | 'SDK_SCHEMA_VIOLATION'
    | 'SDK_FIXTURE_CROSS_LANG_MISMATCH';

// ─── SdkError class definition ─────────

/**
 * SdkError — sdk sub-protocol L0 error class
 *
 * extends Error (does not inherit ProtocolError).
 *
 * Namespace orthogonality: the SDK_* error codes do not collide with HC_* / CSP_* / the 9 CryptoError codes / RFP_* / TB_* etc.
 *
 * fail-closed is enforced; no fail-degraded path is allowed.
 */
export class SdkError extends Error {
    public override readonly name = 'SdkError';
    public readonly code: SdkErrorCode;

    public constructor(code: SdkErrorCode, message: string) {
        super(`[${code}] ${message}`);
        this.code = code;
    }
}
