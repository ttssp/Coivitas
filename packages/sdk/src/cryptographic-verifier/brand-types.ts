/**
 * cryptographic-verifier brand types — layer 1 of the sdk v0.2 triple-defense (L1 type)
 *
 * Summary: 4 brand types — TrustedSettlerDid / CertSubjectDn /
 *       JwtSubject / OAuth2ClientId.
 *
 * Design intent:
 * - A TrustedSettlerDid may only be constructed via the sdk v0.2 cryptographic verifier factory
 *   (mTLS / JWT / OAuth2); a raw DID must never be bare-cast to a TrustedSettlerDid
 *   (brand-cast guard; the ESLint @typescript-eslint/consistent-type-assertions rule rejects it)
 * - factory authority exception: the 3 factory implementation files (mtls-verifier.ts /
 *   jwt-verifier.ts / oauth2-verifier.ts) cast to TrustedSettlerDid internally at the end,
 *   which is the only legitimate origin of the brand guard (no other safe path); the ESLint
 *   allowlist anchors the path `packages/sdk/src/cryptographic-verifier/`
 */

import type { DID } from '@coivitas/types';

/**
 * TrustedSettlerDid — a trusted DID brand derived via the cryptographic verifier
 *
 * Brand-cast guard:
 * - factory path: verifyMtlsAndDeriveDid() / verifyJwtAndDeriveDid() / verifyOAuth2AndDeriveDid()
 * - bare casts are forbidden: `as TrustedSettlerDid` / `<TrustedSettlerDid>` type assertions
 *   (sub-protocol consumers / L3/L4 boundary implementations must not bypass the factory)
 */
export type TrustedSettlerDid = DID & { readonly __brand: 'TrustedSettlerDid' };

/**
 * CertSubjectDn — mTLS cert subject DN brand (field obtained after parsing the cert)
 *
 * Used for the VerifiedTransportContext.verifiedSubject field (when verifierKind === 'mtls').
 */
export type CertSubjectDn = string & { readonly __brand: 'CertSubjectDn' };

/**
 * JwtSubject — JWT verified payload.sub brand
 *
 * Obtained as payload.sub after jose@5 jwtVerify() completes signature + exp + iss + aud verification.
 * Used for the VerifiedTransportContext.verifiedSubject field (when verifierKind === 'jwt').
 */
export type JwtSubject = string & { readonly __brand: 'JwtSubject' };

/**
 * OAuth2ClientId — OAuth2 introspection response client_id brand
 *
 * Obtained as client_id or sub after openid-client@6 tokenIntrospection() completes active + aud + exp verification.
 * Used for the VerifiedTransportContext.verifiedSubject field (when verifierKind === 'oauth2').
 */
export type OAuth2ClientId = string & { readonly __brand: 'OAuth2ClientId' };
