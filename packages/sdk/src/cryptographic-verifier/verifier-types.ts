/**
 * cryptographic-verifier input/output type definitions
 *
 * Summary: 3 kinds of verifier context (input) + VerifiedTransportContext (output).
 *
 * Design notes:
 * - the input context carries the cryptographic credential extracted from the transport-layer
 *   incoming request (mTLS cert / JWT / OAuth2 access token) + expected mapping anchors
 *   (expectedDid / expectedIssuer / expectedAudience)
 * - the output VerifiedTransportContext has 5 mandatory fields (I8)
 * - sdkVersion is strictly constrained to "2.0.0" (I9; the only valid value)
 * - VerifierKind is a literal union of 3 values; no 4th value is allowed
 */

import type { DID } from '@coivitas/types';

import type {
    CertSubjectDn,
    JwtSubject,
    OAuth2ClientId,
    TrustedSettlerDid,
} from './brand-types.js';

/** verifier kind literal union (mTLS / JWT / OAuth2)*/
export type VerifierKind = 'mtls' | 'jwt' | 'oauth2';

/**
 * MtlsVerifierContext — mTLS verifier input context
 */
export interface MtlsVerifierContext {
    /** mTLS client cert (DER bytes or PEM string; parsed via @peculiar/x509)*/
    clientCert: Uint8Array | string;
    /** trusted root CA cert (trusted root cert pool)*/
    trustedRootCerts: (Uint8Array | string)[];
    /** Optional: intermediate CA chain (cert chain verify)*/
    intermediateChain?: (Uint8Array | string)[];
    /** expected DID (cross-check mapping, literal-equality verify)*/
    expectedDid: DID;
}

/**
 * JwtVerifierContext — JWT verifier input context
 */
export interface JwtVerifierContext {
    /** JWT compact serialization (header.payload.signature)*/
    jwt: string;
    /** JWKS endpoint URL (key rotation support) or a static JWK Set*/
    jwks: string | { keys: unknown[] };
    /** expected issuer (iss claim verify)*/
    expectedIssuer: string;
    /** expected audience (aud claim verify)*/
    expectedAudience: string;
    /** expected DID (cross-check mapping, sub claim equality verify)*/
    expectedDid: DID;
    /**
     * allow symmetric algorithms (HS256/HS384/HS512; restricted context; default false)
     *
     * Design intent:
     * - default false — the baseline on the sub-protocol consumer side is asymmetric only (RS256/ES256/EdDSA)
     * - true — explicitly enabled by the caller (mTLS server-to-server-only context)
     */
    allowSymmetricAlg?: boolean;
}

/**
 * OAuth2VerifierContext — OAuth2 introspection verifier input context
 */
export interface OAuth2VerifierContext {
    /** OAuth2 access token (Bearer token)*/
    accessToken: string;
    /**
     * OAuth2 issuer URL
     * discovery() takes the issuer URL, fetches .well-known/openid-configuration to auto-discover introspection_endpoint;
     * do not pass the introspection endpoint itself.
     */
    issuerUrl: string;
    /** OAuth2 introspection endpoint URL (authority binding + optional explicit override)*/
    introspectionEndpoint: string;
    /** OAuth2 client credentials (introspection endpoint authentication)*/
    introspectionClientId: string;
    introspectionClientSecret: string;
    /** expected audience (introspection response aud claim verify)*/
    expectedAudience: string;
    /** expected DID (cross-check mapping, client_id or sub claim equality verify)*/
    expectedDid: DID;
}

/**
 * VerifiedTransportContext — the verified context produced after a verifier succeeds
 *
 * Design intent:
 * - the verifier factory success path produces TrustedSettlerDid + cryptographically-verified mapping fields
 * - when consumed by the sub-protocol, the transport context carries TrustedSettlerDid + verifier-kind metadata
 *
 * sdkVersion invariant (I9): the only valid value is `"2.0.0"`
 */
export interface VerifiedTransportContext {
    /** Trusted DID brand (derived by the cryptographic verifier; consumed by the sub-protocol)*/
    trustedDid: TrustedSettlerDid;
    /** Verifier kind (mTLS / JWT / OAuth2; defense-in-depth metadata)*/
    verifierKind: VerifierKind;
    /** Verifier-specific evidence (mTLS cert subject DN / JWT sub claim / OAuth2 client_id)*/
    verifiedSubject: CertSubjectDn | JwtSubject | OAuth2ClientId;
    /** Verifier timestamp (ISO 8601 UTC; defense-in-depth audit + L3 freshness check)*/
    verifiedAt: string;
    /** sdkVersion metadata (the only valid value is "2.0.0")*/
    sdkVersion: string;
}

/**
 * VerifierFactoryInput — the dispatch union for the VerifierFactory entry point
 *
 * Design intent (orchestrator dispatches by VerifierKind):
 * - a discriminated union linking kind with the ctx fields; TypeScript type narrowing ensures the ctx type matches the kind
 * - VerifierFactory.verify(input) internally dispatches by input.kind to the 3 verifiers
 */
export type VerifierFactoryInput =
    | { kind: 'mtls'; ctx: MtlsVerifierContext }
    | { kind: 'jwt'; ctx: JwtVerifierContext }
    | { kind: 'oauth2'; ctx: OAuth2VerifierContext };
