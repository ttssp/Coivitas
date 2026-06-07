/**
 * cr-ports — Credential Resolver (CR) L2 minimal dependency-injection interface contracts
 *
 * 4 port interfaces (slimmed from 6 ports to 4 ports):
 *   - OidcPort: minimal OIDC IdP resolver interface contract
 *   - SamlPort: minimal SAML IdP resolver interface contract (the SAML-side equivalent)
 *   - FederationLinkResolver: federation_identity_links FK lookup port
 *   - CredentialRevocationChecker: federated credential revocation-check port (fail-closed)
 *
 * Design commitments:
 *   RfpVerifierPort + CcrChainResolverPort removed (to be reintroduced in a later version; no dead code kept now);
 *   the did source never enters this branch in v0.1 (step 1 throws CR_VERSION_UNSUPPORTED).
 *
 * fail-closed behavior constraints:
 *   Each port interface literally documents its fail-closed behavior constraints;
 *   return null + silent fallback to a default credential is strictly forbidden (violates the fail-closed pattern);
 *   stubbing a default verify ok / silently returning false on network failure is strictly forbidden.
 *
 * Note: these CR-specific port interfaces live in a different namespace from the existing
 *     packages/sdk/src/sso/ OidcPort / SamlPort — module-level isolation;
 *     no import conflicts; the two sets of ports each serve different sub-protocol verifyCallback paths.
 */

import type {
    FederationIdentityLink,
    FederationLinkId,
    NormalizedOidcClaims,
    NormalizedSamlClaims,
    TenantId,
} from '@coivitas/types';

/**
 * OidcPort — minimal OIDC IdP resolver interface contract
 *
 * Clarifying the interface contract: iss/aud claim extraction logic must be done in the port implementation layer;
 * the sdk-api layer is forbidden from extracting claims (the existing sdk-api.ts:504-563 path is pushed down to the port implementation layer).
 *
 * verifyCallback is compile-time forced to return NormalizedOidcClaims (not OidcRawClaims):
 * iss/aud/exp/iat extraction + validation + normalization must be done in the port implementation layer;
 * the sdk-api layer only receives and consumes NormalizedOidcClaims, doing no claim extraction.
 */
export interface OidcPort {
    /**
     * verifyCallback — OIDC callback verify entry point
     *
     * Behavior constraints (fail-closed):
     * - signature verification fails -> throw OR return a result with a fail flag (the caller throws CR_OIDC_CLAIM_INVALID)
     * - issuer not in the trust list -> throw CR_PROVIDER_UNAVAILABLE
     * - network failure -> throw (the caller catches -> CR_PROVIDER_UNAVAILABLE)
     * - return null + silent fallback to a default credential is strictly forbidden (violates fail-closed)
     *
     * @param rawCallback the raw callback payload (OIDC authorization code OR ID token, etc., IdP-implementation-specific)
     * @returns Promise<NormalizedOidcClaims> — the normalized claims (source='oidc')
     * @throws Error (the concrete type is defined by the implementation layer; the caller catches + wraps as CR_OIDC_CLAIM_INVALID / CR_PROVIDER_UNAVAILABLE)
     */
    verifyCallback(rawCallback: unknown): Promise<NormalizedOidcClaims>;
}

/**
 * SamlPort — minimal SAML IdP resolver interface contract (the SAML-side equivalent)
 *
 * Same pattern as OidcPort.
 */
export interface SamlPort {
    /**
     * verifyCallback — SAML callback verify entry point
     *
     * Behavior constraints (fail-closed):
     * - signature verification fails -> throw OR return a result with a fail flag (the caller throws CR_SAML_CLAIM_INVALID)
     * - return null + silent degradation is strictly forbidden
     *
     * @param rawCallback the raw callback payload (SAML Response XML or base64, etc., IdP-implementation-specific)
     * @returns Promise<NormalizedSamlClaims> — the normalized claims (source='saml')
     * @throws Error (the caller catches + wraps as CR_SAML_CLAIM_INVALID / CR_PROVIDER_UNAVAILABLE)
     */
    verifyCallback(rawCallback: unknown): Promise<NormalizedSamlClaims>;
}

/**
 * FederationLinkResolver — federation_identity_links FK lookup port
 *
 * FK integrity validation is enforced inside this port (one of the Schema/SQL/runtime triple defense layers);
 * the implementation layer must include the SQL FK constraint (SQL migration 030 candidate) +
 * a JOIN query (SELECT FROM federation_identity_links INNER JOIN managed_service.users)
 * that naturally catches FK violations (PostgreSQL 23503 foreign_key_violation).
 */
export interface FederationLinkResolver {
    /**
     * lookupLink — look up a link by issuer + federatedSubject
     *
     * Behavior constraints (fail-closed):
     * - link does not exist -> return null (the caller throws CR_FEDERATION_LINK_INVALID)
     * - link.userId does not exist in the users table (FK violation) -> throw CR_FK_VIOLATION
     * - returning a default link is strictly forbidden
     *
     * The implementation layer must include:
     *   - the FK SQL constraint (SQL migration 030 candidate)
     *   - a JOIN query (federation_identity_links INNER JOIN managed_service.users)
     *   - natural catching of FK violations (PostgreSQL 23503 foreign_key_violation)
     *
     * @param tenantId the tenant ID (multi-tenant isolation)
     * @param issuer federation issuer URI
     * @param federatedSubject the federation-side subject
     * @returns Promise<FederationIdentityLink | null> — null means no matching link; the caller throws CR_FEDERATION_LINK_INVALID
     * @throws Error (PostgreSQL FK violation, etc.; the caller catches + wraps as CR_FK_VIOLATION)
     */
    lookupLink(
        tenantId: TenantId,
        issuer: string,
        federatedSubject: string,
    ): Promise<FederationIdentityLink | null>;
}

/**
 * CredentialRevocationChecker — federated credential revocation-check port
 *
 * Behavior constraints (fail-closed):
 *   - network failure -> throw OR return true (treat as revoked; fail-closed pattern);
 *   - returning false on a network error (fail-open) is strictly forbidden;
 *   - if the implementation layer uses a cache, a cache miss must query upstream; a cache miss must not fall back to return false.
 */
export interface CredentialRevocationChecker {
    /**
     * isCredentialRevoked — check whether a federated credential has been revoked
     *
     * @param linkId federation_identity_links.id
     * @returns Promise<boolean> — true = revoked; the caller throws CR_CREDENTIAL_REVOKED
     * @throws Error (network failure / query error; fail-closed pattern; the caller catches + wraps as CR_CREDENTIAL_REVOKED or CR_PROVIDER_UNAVAILABLE)
     */
    isCredentialRevoked(linkId: FederationLinkId): Promise<boolean>;
}

/**
 * ResolverKeyMaterial — resolver signing key material (held on the CR-issuer side; should be HSM-isolated in production)
 *
 * The buildIntegrityProof implementation must include a real ed25519Sign + resolverPrivateKey injection + toSignature factory.
 *
 * Note: in a production deployment resolverPrivateKey should be HSM-isolated (it should not be passed
 * directly as a plaintext private key in production code); this interface is only for demo / test / production HSM adapter implementations.
 *
 * Design commitment: the implementation layer must not keep a placeholder PLACEHOLDER_SIGNATURE cast;
 * a real signResolvedCredentialIntegrityProof call is mandatory (L1 crypto primitive).
 */
export interface ResolverKeyMaterial {
    /** resolver DID (corresponds to the ResolvedCredentialIntegrityProof.resolverDid field; format: a did:* DID string) */
    readonly resolverDid: string;
    /** resolver private key (Ed25519 32-byte seed; Uint8Array; should be replaced by an HSM in production) */
    readonly resolverPrivateKey: Uint8Array;
}
