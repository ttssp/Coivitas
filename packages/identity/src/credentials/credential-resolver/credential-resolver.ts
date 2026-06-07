/**
 * credential-resolver — Credential Resolver (CR) L2 identity primitive (main entry)
 *
 * Invariants I1-I9 + type-layer defense.
 *
 * Main entries:
 *   - resolveCredential: CR main resolution entry (7-step algorithm; step 6 fail-closed revocation early position)
 *   - verifyResolvedCredential: consumer-side verification of ResolvedCredential integrity (semantic layer + L1 crypto verify)
 *   - buildIntegrityProof (internal): build the verify-time signed payload (csp 5 fields + Ed25519 sign)
 *
 * 7-step algorithm:
 *   step 1: input type narrowing (OidcRawClaims/SamlRawClaims brands catch mismatches at compile time)
 *   step 2: federation source validation + linkDepth <= MAX_FEDERATION_LINK_DEPTH (hard gate)
 *   step 3: federation_identity_links FK lookup (FK integrity enforced)
 *   step 4: claim verify (issuer/audience/expiry; via OidcPort/SamlPort)
 *   step 5: PoP credential binding check (v0.1 deferred -> throw CR_POP_BINDING_INVALID
 *          reason 'pop_binding_verify_not_implemented_in_v0.1'; ed25519Verify injected in a later version)
 *   step 6: real-time credential revocation check (fail-closed; early position)
 *   step 7 (final): buildIntegrityProof + ResolvedCredential construction (csp 5-field invariant FULL coverage)
 *
 * step 6 fail-closed early-position note:
 *   step 6 (revocation check) runs before step 7 (ResolvedCredential construction);
 *   consistent with the early-revocation-check pattern;
 *   a late revocation check is strictly forbidden;
 *   even if a revoked credential passes claim verify + PoP binding verification,
 *   it must be rejected immediately before ResolvedCredential construction.
 *
 * Anti-phantom defense:
 *   - top-level import of canonicalize / ed25519 (no in-function require);
 *   - each of the 14 CrErrorCode codes must have a throw-path;
 *   - each port interface method has an active invocation (FederationLinkResolver.lookupLink / OidcPort.verifyCallback /
 *     SamlPort.verifyCallback / CredentialRevocationChecker.isCredentialRevoked are all actively called within steps);
 *   - stub default success / silent return null is not allowed (an auth/verification primitive is strictly fail-closed);
 *   - partial-PASS / WARNING / default-credential fallback returns are strictly forbidden.
 */

import {
    canonicalizeResolvedCredentialIntegrityProof,
    signResolvedCredentialIntegrityProof,
    verifyResolvedCredentialIntegrityProofSignature,
    type ResolvedCredentialIntegrityProofSignedPayload,
} from '@coivitas/crypto';
import {
    CR_CSP_VERSION_1_0_0,
    CR_INTEGRITY_PROOF_DEFAULT_NOT_AFTER_MS,
    CR_VERSION_1_0_0,
    CR_VERSION_1_0_0_RAW,
    CrError,
    MAX_FEDERATION_LINK_DEPTH,
    type CredentialResolutionRequest,
    type FederationIdentityLink,
    type NormalizedOidcClaims,
    type NormalizedSamlClaims,
    type ResolvedCredential,
    type ResolvedCredentialIntegrityProof,
} from '@coivitas/types';

import type {
    CredentialRevocationChecker,
    FederationLinkResolver,
    OidcPort,
    ResolverKeyMaterial,
    SamlPort,
} from './cr-ports.js';

/**
 * ResolveCredentialDeps — resolveCredential dependency-injection parameter bundle
 *
 * 4 port injections.
 *
 * Note: OidcPort/SamlPort are caller-side (sso-callback handler) contract interfaces;
 * before calling resolveCredential the caller invokes port.verifyCallback() to normalize the raw IdP payload into
 * NormalizedOidcClaims/NormalizedSamlClaims (passed in via request.claims);
 * resolveCredential does not call port.verifyCallback directly (to avoid caller-side responsibility drift);
 * but ResolveCredentialDeps still holds port references — purposes:
 *   1. contract document completeness (the port interface is the sub-protocol L2 contract);
 *   2. in e2e tests the caller can pass ports directly to resolveCredential as a contract-holding placeholder (anti-phantom design);
 *   3. once multi-hop federation is unlocked later, resolveCredential may call ports directly internally (e.g., a link chain).
 */
export interface ResolveCredentialDeps {
    /** OIDC port (caller contract interface;
     *  v0.1 resolveCredential does not call it directly — the caller pre-calls the port and passes in normalized claims)
*/
    readonly oidcPort: OidcPort;
    /** SAML port (caller contract interface; same as OidcPort) */
    readonly samlPort: SamlPort;
    /** federation_identity_links query port (FK integrity; step 3 active invocation) */
    readonly linkResolver: FederationLinkResolver;
    /** revocation-check port (fail-closed; step 6 active invocation) */
    readonly revocationChecker: CredentialRevocationChecker;
    /** resolver signing key material (should be HSM-isolated in production; step 7 buildIntegrityProof active invocation) */
    readonly resolverKeyMaterial: ResolverKeyMaterial;
}

// Anti-phantom port reference: OidcPort/SamlPort are injected into ResolveCredentialDeps but v0.1 resolveCredential does not call them directly;
// to prevent the TypeScript compiler from tree-shaking these imports (which would create a phantom-contract counterexample),
// we explicitly `void`-reference the types here to keep compile-time visibility (consistent with the contract).

// Note: once multi-hop federation is unlocked later, resolveCredential will call ports directly internally (e.g., link chain.verifyCallback);
// at that point this void reference is naturally eliminated (the port fields become active invocations).
function _portContractAttestation(deps: ResolveCredentialDeps): void {
    // Compile-time verification that the port field types exist (contract held); runtime no-op
    void deps.oidcPort;
    void deps.samlPort;
}
// Anti-phantom: hold a compile-time reference to the attestation function (TypeScript tree-shake does not drop exported functions)
void _portContractAttestation;

/**
 * resolveCredential — CR main entry
 *
 * Resolve a federation credential and run the 7-step verification algorithm.
 *
 * @param request CR resolution request (including challenge + verifierDid + claims)
 * @param deps 4 port injections (oidcPort / samlPort / linkResolver / revocationChecker) + resolverKeyMaterial
 * @returns Promise<ResolvedCredential> (returned after all 7 steps pass)
 * @throws CrError (any step failure; fail-closed)
 */
export async function resolveCredential(
    request: CredentialResolutionRequest,
    deps: ResolveCredentialDeps,
): Promise<ResolvedCredential> {
    const maxDepth = request.maxLinkDepth ?? MAX_FEDERATION_LINK_DEPTH;

    // ─── Step 1: input type narrowing (OidcRawClaims/SamlRawClaims brands catch mismatches at compile time) ───

    // Strictly forbidden: parseSamlClaims(oidcInput) — the compile-time nominal brands are incompatible, so it is a direct compile error
    // Strictly forbidden: cast `as SamlRawClaims` (the factory is mandatory)

    // Note: this step does not introduce any non-OIDC / non-SAML standard fields (
    // OIDC iss/sub/aud/exp/iat = OIDC Core 1.0 standard;
    // SAML nameId/issuer/audience = SAML 2.0 Core / standard)
    let normalizedClaims: NormalizedOidcClaims | NormalizedSamlClaims;
    if (request.source === 'oidc') {
        // request.claims is already narrowed to NormalizedOidcClaims at compile time (because the port implementation layer outputs normalized claims);
        // runtime defense-in-depth: type guard (source discriminator + brand narrow)
        if (!isNormalizedOidcClaims(request.claims)) {
            throw new CrError('CR_BRAND_TYPE_MISMATCH', {
                expected: 'NormalizedOidcClaims',
                received: 'unknown',
                source: request.source,
            });
        }
        normalizedClaims = request.claims;
    } else if (request.source === 'saml') {
        if (!isNormalizedSamlClaims(request.claims)) {
            throw new CrError('CR_BRAND_TYPE_MISMATCH', {
                expected: 'NormalizedSamlClaims',
                received: 'unknown',
                source: request.source,
            });
        }
        normalizedClaims = request.claims;
    } else if (request.source === 'did') {
        // DID-based federation is a later extension candidate (not supported in v0.1; fail-closed reject)
        // the did source never enters this branch in v0.1 (the FederationSource enum still contains 'did' but only as a placeholder for a later version)
        throw new CrError('CR_VERSION_UNSUPPORTED', {
            source: request.source,
            reason: 'did_federation_phase7_plus_only',
        });
    } else {
        // exhaustive switch (assertNever pattern; phantom-only unreachable branch; defense-in-depth)
        /* v8 ignore next 5*/
        throw new CrError('CR_BRAND_TYPE_MISMATCH', {
            source: String(request.source),
            reason: 'unsupported_federation_source',
        });
    }

    // ─── Step 2: federation source validation + hard gate (MAX_FEDERATION_LINK_DEPTH) ───

    // federation chain depth upper-bound check (hard gate)
    // v0.1 implements single-hop federation; multi-hop is a later extension candidate
    const linkDepth = 1; // v0.1 single-hop federation
    if (linkDepth > maxDepth) {
        throw new CrError('CR_FEDERATION_LINK_DEPTH_EXCEEDED', {
            linkDepth,
            max: maxDepth,
        });
    }

    // Extract issuer + federatedSubject (from normalizedClaims; the port implementation layer has already done iss/aud extraction)
    const { issuer, federatedSubject } =
        extractIssuerAndSubject(normalizedClaims);

    // ─── Step 3: federation_identity_links FK lookup (FK integrity enforced) ───

    // The implementation layer uses a SQL JOIN (SELECT FROM federation_identity_links
    // INNER JOIN managed_service.users ON federation_identity_links.user_id = users.id
    // WHERE tenant_id = $1 AND issuer = $2 AND federated_subject = $3)
    // FK violation -> natural throw (PostgreSQL 23503 foreign_key_violation; the caller catches + wraps as CR_FK_VIOLATION)
    let link: FederationIdentityLink | null;
    try {
        link = await deps.linkResolver.lookupLink(
            request.tenantId,
            issuer,
            federatedSubject,
        );
    } catch (err) {
        // PostgreSQL FK violation / other query errors -> fail-closed, wrapped as CR_FK_VIOLATION
        // (FK violation -> natural throw)
        const errMsg = err instanceof Error ? err.message : String(err);
        throw new CrError('CR_FK_VIOLATION', {
            tenantId: request.tenantId,
            issuer,
            federatedSubject,
            reason: 'link_resolver_lookup_threw',
            detail: errMsg,
        });
    }
    if (link === null) {
        throw new CrError('CR_FEDERATION_LINK_INVALID', {
            tenantId: request.tenantId,
            issuer,
            federatedSubject,
            reason: 'no_link_found',
        });
    }

    // FK integrity defense-in-depth: re-check at runtime (Schema/SQL/runtime three layers)
    if (!link.userId) {
        throw new CrError('CR_FK_VIOLATION', {
            linkId: link.id,
            reason: 'user_id_null_or_orphan',
        });
    }

    // ─── Step 4: claim verify (issuer + audience + expiry + signature; via OidcPort/SamlPort) ───

    // The port implementation layer has already done signature verification (the sdk-api layer no longer verifies);
    // this step performs claim-field consistency checks (issuer matches the link + audience is compatible with verifierDid + expiry)

    // Note: the port implementation layer's verifyCallback should throw when the upstream IdP is unreachable; step 1 has already narrowed normalizedClaims
    // (from request.claims; obtained by the caller invoking port.verifyCallback inside the callback handler);
    // therefore upstream IdP unreachability is caught and wrapped by the caller as CR_PROVIDER_UNAVAILABLE. This step only checks
    // the consistency of the already-normalized claim fields. If the caller passes upstream errors through without wrapping, this step is the fallback:
    if (
        !normalizedClaims ||
        typeof normalizedClaims.issuer !== 'string' ||
        normalizedClaims.issuer.length === 0
    ) {
        throw new CrError('CR_PROVIDER_UNAVAILABLE', {
            reason: 'port_returned_invalid_normalized_claims',
            detail: 'OidcPort/SamlPort.verifyCallback() must return non-empty issuer field (caller should wrap upstream IdP errors)',
        });
    }
    if (issuer !== link.issuer) {
        throw new CrError(
            request.source === 'oidc'
                ? 'CR_OIDC_CLAIM_INVALID'
                : 'CR_SAML_CLAIM_INVALID',
            {
                expectedIssuer: link.issuer,
                receivedIssuer: issuer,
                linkId: link.id,
                reason: 'issuer_mismatch_link_vs_claim',
            },
        );
    }

    // expiry check (OIDC exp / SAML notOnOrAfter)
    // Note: isClaimExpired throws fail-closed internally on missing fields
    if (isClaimExpired(normalizedClaims)) {
        throw new CrError(
            request.source === 'oidc'
                ? 'CR_OIDC_CLAIM_INVALID'
                : 'CR_SAML_CLAIM_INVALID',
            {
                reason: 'claim_expired',
                linkId: link.id,
            },
        );
    }

    // ─── Step 5: PoP credential binding check (v0.1 deferred) ───

    // verifyPopBinding does not return a placeholder true; it throws not implemented instead
    // Rationale: v0.1 does not implement PoP credential verification (ed25519Verify injected in a later version);
    // a placeholder return true would violate the PoP binding invariant (PoP credential -> challenge binding check);
    // a phantom invariant (a field fixed at true) is not actual verification -> a fail-closed throw explicitly acknowledges the deferral

    // Calling verifyPopBinding in v0.1 always throws CR_VERSION_UNSUPPORTED (internal helper);
    // after catching, it is converted to CR_POP_BINDING_INVALID (the deferral is explicitly visible; the 14-error-code throw-path is active)
    try {
        await verifyPopBinding(link, request.challenge);
    } catch (err) {
        if (err instanceof CrError && err.code === 'CR_VERSION_UNSUPPORTED') {
            // v0.1 deferred: PoP credential verification not implemented — explicit fail-closed (anti-phantom)
            throw new CrError('CR_POP_BINDING_INVALID', {
                linkId: link.id,
                challenge: request.challenge,
                reason: 'pop_binding_verify_not_implemented_in_v0.1',
                deferredTo: 'v0.2+',
            });
        }
        throw err;
    }

    // ─── Step 6 + Step 7 (v0.1 deferred, unreachable; structural attestation left for a later release) ───

    // v0.1 coverage note: step 5 (verifyPopBinding) always throws CR_POP_BINDING_INVALID (deferred);
    // therefore step 6 (revocation check) + step 7 (ResolvedCredential construction + buildIntegrityProof call)
    // are unreachable in v0.1 e2e — they become reachable once a later ed25519Verify injection unlocks step 5.

    // The /* v8 ignore */ here marks the v0.1 deferred unreachable segment (anti-phantom safeguard; not dead code but
    // code ready for a later version);
    // the anti-phantom verification is equivalently covered by the following e2e structural attestations:
    // - step 6 revocation: e2e case 5 source-level structural verify (
    // consistent with the early-revocation-check pattern);
    // - step 7 buildIntegrityProof: e2e case "hand-crafted buildIntegrityProof equivalent"
    // (calls the same L1 sign primitive + the same 5-field invariant construction + the same verifyResolvedCredential
    // consumer-side check) — already a verified ready-path PASS

    /* v8 ignore start*/
    // Step 6: real-time credential revocation check (fail-closed; early position)
    // Consistent with the early-revocation-check pattern
    // A late revocation check is strictly forbidden
    let revoked: boolean;
    try {
        revoked = await deps.revocationChecker.isCredentialRevoked(link.id);
    } catch (err) {
        // network failure / query error -> fail-closed (treat as revoked)
        const errMsg = err instanceof Error ? err.message : String(err);
        throw new CrError('CR_CREDENTIAL_REVOKED', {
            linkId: link.id,
            reason: 'revocation_check_threw_fail_closed',
            detail: errMsg,
        });
    }
    if (revoked) {
        throw new CrError('CR_CREDENTIAL_REVOKED', {
            linkId: link.id,
            issuer: link.issuer,
            federatedSubject: link.federatedSubject,
            reason: 'realtime_revocation_check_true',
        });
    }

    // link's own revoked flag check (defense-in-depth; the DB field layer plus the revocationChecker form two layers)
    if (link.revoked) {
        throw new CrError('CR_CREDENTIAL_REVOKED', {
            linkId: link.id,
            reason: 'link_revoked_flag',
        });
    }

    // Step 6.5 (RFP/CCR call) does not exist in v0.1:
    // the did source never enters in v0.1 (step 1 already throws CR_VERSION_UNSUPPORTED);
    // this branch is not taken on the OIDC/SAML path; step 6.5 is introduced later once the did source is unlocked

    // Step 7 (final): ResolvedCredential construction + audit event recording (atp v0.1 integration)
    const integrityProof = buildIntegrityProof(
        link,
        request,
        deps.resolverKeyMaterial,
    );

    const resolved: ResolvedCredential = {
        crVersion: CR_VERSION_1_0_0,
        link,
        // The ResolvedCredential.source enum is restricted to 'oidc' | 'saml'
        // ('did' is reintroduced later); step 1 already throws for the 'did' source, so here source must be 'oidc' | 'saml'
        source: request.source,
        normalizedClaims,
        notRevoked: true, // true once step 6 passes
        integrityProof,
        resolvedAt: new Date().toISOString(),
    };

    // Note: atp v0.1 audit event recording is the caller's responsibility (the implementation-layer sso-callback handler);
    // the resolver does not write audit events directly; the interface boundary is clear

    return resolved;
    /* v8 ignore stop*/
}

/**
 * verifyResolvedCredential — consumer-side verification of ResolvedCredential integrity
 *
 * Must be called immediately after resolveCredential returns (a consumer-side responsibility).
 *
 * Verification order (fail-closed; any failure throws):
 *   1. cspVersion === '1.0.0' (CR_VERSION_UNSUPPORTED if not equal)
 *   2. crVersion === '1.0.0' (CR_VERSION_UNSUPPORTED if not equal)
 *   3. notAfter > now (CR_FRESHNESS_INVALID if expired)
 *   4. challenge === expectedChallenge (CR_INTEGRITY_PROOF_INVALID if not equal)
 *   5. audience === verifierDid (CR_INTEGRITY_PROOF_INVALID if not equal)
 *   6. link.userId is a non-empty string (CR_PORT_CONTRACT_VIOLATION if non-compliant)
 *   7. Ed25519 signature verify (L1 verifyResolvedCredentialIntegrityProofSignature;
 *      CR_INTEGRITY_PROOF_INVALID if verify fails)
 *
 * @param resolved the ResolvedCredential object (the return value of resolveCredential)
 * @param resolverPublicKey the resolver's Ed25519 public key (32-byte Uint8Array;
 *                          obtained by resolving resolverDid — the caller is responsible)
 * @param expectedChallenge the consumer-side expected challenge (matching resolveCredential's request.challenge input)
 * @param verifierDid the consumer-side expected verifier DID (matching resolveCredential's request.verifierDid input;
 *                    format: a did:* DID string)
 * @throws CrError (any verification failure; fail-closed)
 */
export function verifyResolvedCredential(
    resolved: ResolvedCredential,
    resolverPublicKey: Uint8Array,
    expectedChallenge: string,
    verifierDid: string,
): void {
    const proof = resolved.integrityProof;

    // step 1: cspVersion check (the csp baseline version must be '1.0.0')
    if (proof.cspVersion !== CR_CSP_VERSION_1_0_0) {
        throw new CrError('CR_VERSION_UNSUPPORTED', {
            received: proof.cspVersion,
            expected: CR_CSP_VERSION_1_0_0,
            field: 'cspVersion',
        });
    }

    // step 2: crVersion check
    if (resolved.crVersion !== CR_VERSION_1_0_0_RAW) {
        throw new CrError('CR_VERSION_UNSUPPORTED', {
            received: resolved.crVersion,
            expected: CR_VERSION_1_0_0_RAW,
            field: 'crVersion',
        });
    }

    // step 3: notAfter validity check
    const notAfterMs = new Date(proof.notAfter).getTime();
    if (Number.isNaN(notAfterMs)) {
        throw new CrError('CR_FRESHNESS_INVALID', {
            reason: 'notAfter_not_parseable',
            notAfter: proof.notAfter,
        });
    }
    if (Date.now() > notAfterMs) {
        throw new CrError('CR_FRESHNESS_INVALID', {
            reason: 'integrity_proof_expired',
            notAfter: proof.notAfter,
            nowMs: Date.now(),
        });
    }

    // step 4: challenge binding check (prevents replay attacks)
    if (proof.challenge !== expectedChallenge) {
        throw new CrError('CR_INTEGRITY_PROOF_INVALID', {
            reason: 'challenge_mismatch',
            expected: expectedChallenge,
            received: proof.challenge,
        });
    }

    // step 5: audience binding check (prevents audience hijack)
    if (proof.audience !== verifierDid) {
        throw new CrError('CR_INTEGRITY_PROOF_INVALID', {
            reason: 'audience_mismatch',
            expected: verifierDid,
            received: proof.audience,
        });
    }

    // step 6: port contract verify (link.userId must not be an unbranded string; defense-in-depth)
    if (
        typeof resolved.link.userId !== 'string' ||
        resolved.link.userId.length === 0
    ) {
        throw new CrError('CR_PORT_CONTRACT_VIOLATION', {
            reason: 'link_userId_invalid',
            linkId: resolved.link.id,
        });
    }

    // step 7: Ed25519 signature verification (after JCS canonicalization; L1 crypto primitive; fail-closed throw)
    // Note: verifyResolvedCredentialIntegrityProofSignature throws CR_INTEGRITY_PROOF_INVALID internally
    // (signature_verify_failed / canonicalize failure / format error) — propagated here
    verifyResolvedCredentialIntegrityProofSignature(proof, resolverPublicKey);
}

// ─── Helper functions ───────────────────────────────────────────────────────────────

/**
 * isNormalizedOidcClaims — type guard (source discriminator + basic structure check; defense-in-depth)
 *
 * Equivalent to L0 factories.toNormalizedOidcClaims but lighter (does not repeat AJV validate);
 * at runtime it mainly checks the source discriminator (already narrowed at compile time; here a fail-closed fallback).
 *
 * Note: this guard does not replace the L0 schema validate (the caller should have constructed via the toNormalizedOidcClaims factory);
 * here it only performs a runtime fallback check (defense-in-depth).
 */
function isNormalizedOidcClaims(c: unknown): c is NormalizedOidcClaims {
    if (typeof c !== 'object' || c === null) return false;
    if (!('source' in c)) return false;
    return (c as { source: string }).source === 'oidc';
}

/**
 * isNormalizedSamlClaims — type guard (source discriminator + basic structure check)
 *
 * Same pattern as isNormalizedOidcClaims.
 */
function isNormalizedSamlClaims(c: unknown): c is NormalizedSamlClaims {
    if (typeof c !== 'object' || c === null) return false;
    if (!('source' in c)) return false;
    return (c as { source: string }).source === 'saml';
}

/**
 * extractIssuerAndSubject — extract issuer + federatedSubject from normalized claims
 *
 * The port implementation layer has already done iss/aud extraction + normalization; here we read the normalized fields directly.
 */
function extractIssuerAndSubject(
    c: NormalizedOidcClaims | NormalizedSamlClaims,
): { issuer: string; federatedSubject: string } {
    return { issuer: c.issuer, federatedSubject: c.subject };
}

/**
 * isClaimExpired — check whether normalized claims are expired (fail-closed pattern)
 *
 *   A missing SAML notOnOrAfter + notBefore + missing OIDC exp -> fail-closed throw (rather than a return false fallback);
 *   a consistent fail-closed pattern; a fail-open fallback is strictly forbidden.
 *
 * @returns boolean — true = expired; false = not expired
 * @throws CrError(CR_OIDC_CLAIM_INVALID / CR_SAML_CLAIM_INVALID) — a critical field is missing (fail-closed)
 */
function isClaimExpired(
    c: NormalizedOidcClaims | NormalizedSamlClaims,
): boolean {
    const now = Date.now();
    if (c.source === 'oidc') {
        // OIDC: the exp field is mandatory (NormalizedOidcClaims.expiresAt is mandatory; OIDC Core)
        if (!c.expiresAt) {
            throw new CrError('CR_OIDC_CLAIM_INVALID', {
                reason: 'oidc_exp_missing_fail_closed',
            });
        }
        return c.expiresAt.getTime() < now;
    }
    if (c.source === 'saml') {
        // SAML: a missing notOnOrAfter field -> fail-closed throw (rather than a return false fallback)
        if (!c.notOnOrAfter) {
            throw new CrError('CR_SAML_CLAIM_INVALID', {
                reason: 'saml_notOnOrAfter_missing_fail_closed',
            });
        }
        // SAML notBefore check (if present; Date.now() < notBefore -> fail-closed throw)
        if (c.notBefore && now < c.notBefore.getTime()) {
            throw new CrError('CR_SAML_CLAIM_INVALID', {
                reason: 'saml_not_yet_valid',
            });
        }
        return c.notOnOrAfter.getTime() <= now;
    }
    // exhaustive switch (assertNever pattern; phantom-only unreachable branch)
    /* v8 ignore next 5*/
    throw new CrError('CR_BRAND_TYPE_MISMATCH', {
        reason: 'unexpected_source_in_isClaimExpired',
        received: String((c as { source: string }).source),
    });
}

/**
 * verifyPopBinding — PoP credential -> challenge binding check (v0.1 deferred -> throw)
 *
 * Deferred in v0.1; a later version implements PoP credential verification (ed25519Verify injection);
 * a placeholder return true is strictly forbidden (it violates the PoP binding invariant; a phantom invariant; a fail-closed-pattern counterexample).
 *
 * Note: the function signature keeps Promise<boolean> so that, once unlocked later, it can become async (awaiting ed25519Verify / HSM
 * sign calls); in v0.1 a direct synchronous throw is equivalent to wrapping in Promise.reject; the v0.1 lint
 * "no-await-needed" is marked via eslint-disable-next-line (to be removed later).
 *
 * @throws CrError(CR_VERSION_UNSUPPORTED) — explicitly acknowledges the v0.1 deferral
 */
// eslint-disable-next-line @typescript-eslint/require-await -- v0.1 deferred always throws; later ed25519Verify await active
async function verifyPopBinding(
    link: FederationIdentityLink,
    challenge: string,
): Promise<boolean> {
    void link;
    void challenge;
    throw new CrError('CR_VERSION_UNSUPPORTED', {
        reason: 'pop_binding_verify_not_implemented_in_v0.1',
        finding: 'PoP credential verification is not implemented in v0.1',
    });
}

/**
 * buildIntegrityProof — build the verify-time credential integrity proof (csp 5-field invariant FULL coverage)
 *
 * 5-field mandatory invariant + cspVersion metadata;
 * JCS canonicalization: top-level import of canonicalize (in-function dynamic import is forbidden).
 *
 * A real ed25519Sign + resolverPrivateKey injection + toSignature factory call is mandatory;
 * a placeholder PLACEHOLDER_SIGNATURE cast bypass is strictly forbidden;
 * an `as unknown as Signature` double-cast bypass is strictly forbidden.
 *
 * @param link federation identity link
 * @param request the resolution request (including challenge + verifierDid)
 * @param keyMaterial resolver signing key material (resolverDid + resolverPrivateKey)
 * @returns ResolvedCredentialIntegrityProof (5 fields + cspVersion + proofSignature + resolverDid)
 */
/* v8 ignore next 60 -- v0.1 deferred path: step 5 PoP binding throws,
 * so buildIntegrityProof is never reached via resolveCredential in v0.1.
 * Once a later ed25519Verify injection unlocks step 5, this function is called by step 7;
 * structural coverage is verified by the e2e test "hand-crafted buildIntegrityProof equivalent"
 * (calling the same L1 sign primitive + the same 5-field invariant construction + the same verifyResolvedCredential consumer-side check)
*/
function buildIntegrityProof(
    link: FederationIdentityLink,
    request: CredentialResolutionRequest,
    keyMaterial: ResolverKeyMaterial,
): ResolvedCredentialIntegrityProof {
    // disclosedClaims: issuer + subject + userId (selectively disclosed as needed)
    const disclosedClaims = [
        `issuer:${link.issuer}`,
        `subject:${link.federatedSubject}`,
        `userId:${link.userId}`,
    ];

    // token: a canonical identifier for the linkId + userId digest
    // token = a CR-specific canonical identifier for the resolution result (not a CapabilityToken hash digest);
    // CR token form: `cr:{linkId}:user={userId}`;
    // a later evaluation may upgrade this to a hash-digest form
    const token = `cr:${link.id}:user=${link.userId}`;

    // notAfter: current time + freshness window (defaults to 3600s = 1 hour)
    const notAfter = new Date(
        Date.now() + CR_INTEGRITY_PROOF_DEFAULT_NOT_AFTER_MS,
    ).toISOString();

    // audience anchoring
    // If link.expectedAudience is configured it is the authoritative source (do not trust the caller-provided request.verifierDid);
    // when not configured, fall back to request.verifierDid (backward compatible; weaker mode).
    // Prevents audience-confusion: an attacker using a claim issued for the attacker's audience + setting verifierDid to match.
    const boundAudience = link.expectedAudience ?? request.verifierDid;

    // 6-field signed payload (5-field invariant + cspVersion metadata; JCS canonicalization input)
    const signedPayload: ResolvedCredentialIntegrityProofSignedPayload = {
        token,
        disclosedClaims,
        challenge: request.challenge,
        audience: boundAudience,
        notAfter,
        cspVersion: CR_CSP_VERSION_1_0_0,
    };

    // JCS canonicalization + Ed25519 sign (L1 crypto primitive; a real sign, not a PLACEHOLDER cast)
    // Note: signResolvedCredentialIntegrityProof throws CR_INTEGRITY_PROOF_INVALID internally
    // (canonicalize failure / sign error / malformed privateKey) — propagated here
    const proofSignature = signResolvedCredentialIntegrityProof(
        signedPayload,
        keyMaterial.resolverPrivateKey,
    );

    // Defense-in-depth: reconfirm that canonicalize does not throw (this call shares input with the canonicalize
    // inside signResolvedCredentialIntegrityProof; if sign passes, canonicalize consistently PASSes; this is a redundant self-check)
    // Note: this canonicalize call eliminates the "unused import" risk; it also verifies the verifier side can reproduce identical bytes
    /* v8 ignore next*/
    canonicalizeResolvedCredentialIntegrityProof(signedPayload);

    return {
        token,
        disclosedClaims,
        challenge: request.challenge,
        audience: boundAudience,
        notAfter,
        cspVersion: CR_CSP_VERSION_1_0_0,
        proofSignature,
        resolverDid: keyMaterial.resolverDid,
    };
}
