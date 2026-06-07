/**
 * verify-jwt — JWT signature + exp + iss + aud verify + TrustedSettlerDid derivation
 *
 * Summary: verifyJwtAndDeriveDid implements the sdk v0.2 flow (Step 0-5),
 * based on jose@5 jwtVerify + remote JWKS.
 *
 * Basis:
 *   - sdk v0.2 JWT verifier factory flow
 *   - jose@^5 jwtVerify + algorithms passed explicitly
 *   - PKI threat model (Repudiation dimension — JWT signature verify)
 *   - alg allowlist asymmetric by default; symmetric_restricted requires explicit caller opt-in
 *
 * Security constraints:
 *   - verifyJwtAlgAllowed: Step 0 pre-flight alg check — anti JWT alg downgrade / 'none' attack
 *   - jose jwtVerify: algorithms passed the allowlist explicitly (two-layer defense-in-depth)
 *   - payload.sub required + non-empty string
 *   - cross-check mapping: payload.sub !== expectedDid -> throw SDK_MAPPING_MISMATCH
 *   - brand cast: `as TrustedSettlerDid` / `as JwtSubject` executed only after cryptographic verify passes (no brand coercion)
 */

import { jwtVerify, createRemoteJWKSet } from 'jose';
import type { JWTPayload } from 'jose';
import type {
    JwtVerifierContext,
    VerifiedTransportContext,
    TrustedSettlerDid,
    JwtSubject,
} from '@coivitas/types';
import { SdkError } from '@coivitas/types';
import {
    verifyJwtAlgAllowed,
    JWT_ALG_ALLOWLIST,
} from './jwt-helpers.js';

/**
 * verifyJwtAndDeriveDid — JWT signature + exp + iss + aud verify + TrustedSettlerDid derivation
 *
 * Summary: 5-step flow — alg allowlist pre-flight -> JWKS build -> jose jwtVerify -> sub claim verify -> cross-check mapping -> VerifiedTransportContext construction.
 * The L2 factory layer's cryptographic guard, the only legal TrustedSettlerDid construction path (the JWT path).
 *
 * Flow:
 *   Step 0: alg allowlist pre-flight enforce (verifyJwtAlgAllowed; anti alg downgrade / 'none' attack)
 *   Step 1: build JWKS (remote URL -> createRemoteJWKSet; static key set -> passed through directly)
 *   Step 2: jose@5 jwtVerify (signature + exp + iss + aud verify; algorithms passed the allowlist explicitly)
 *   Step 3: payload.sub required validation (non-empty string)
 *   Step 4: cross-check mapping literal equality (payload.sub === expectedDid)
 *   Step 5: construct VerifiedTransportContext (brand cast — only after cryptographic verify fully PASSes)
 *
 * @param ctx JwtVerifierContext (JWT + JWKS endpoint/static + expected iss/aud/DID + optional allowSymmetricAlg)
 * @returns VerifiedTransportContext (trustedDid = expectedDid as TrustedSettlerDid)
 * @throws SdkError 'SDK_JWT_VERIFY_FAILED' non-compliant alg / header decode failure / signature / exp / iss / aud verification failure
 * @throws SdkError 'SDK_MAPPING_MISMATCH' payload.sub !== expectedDid
 */
export async function verifyJwtAndDeriveDid(
    ctx: JwtVerifierContext,
): Promise<VerifiedTransportContext> {
    // Step 0: alg allowlist pre-flight enforce
    // anti JWT alg downgrade attack — an extra pre-flight defense-in-depth before jose jwtVerify
    // allowSymmetric default false (the sub-protocol consumer-side baseline is asymmetric only)
    verifyJwtAlgAllowed(ctx.jwt, {
        allowSymmetric: ctx.allowSymmetricAlg === true,
    });

    // Step 1: build JWKS (remote URL -> createRemoteJWKSet; static key set -> used directly)
    // remote JWKS: jose@5 createRemoteJWKSet auto-caches + tracks kid rotation
    const jwks =
        typeof ctx.jwks === 'string'
            ? createRemoteJWKSet(new URL(ctx.jwks))
            : (ctx.jwks as unknown as Parameters<typeof jwtVerify>[1]);

    // Step 2: jose@5 jwtVerify
    // algorithms passed the allowlist explicitly
    // when allowSymmetricAlg=true, allowlist = asymmetric + symmetric_restricted union
    const allowedAlgorithms: string[] =
        ctx.allowSymmetricAlg === true
            ? [
                  ...JWT_ALG_ALLOWLIST.asymmetric,
                  ...JWT_ALG_ALLOWLIST.symmetric_restricted,
              ]
            : [...JWT_ALG_ALLOWLIST.asymmetric];

    let verifyResult: { payload: JWTPayload };
    try {
        verifyResult = await jwtVerify(ctx.jwt, jwks, {
            issuer: ctx.expectedIssuer,
            audience: ctx.expectedAudience,
            algorithms: allowedAlgorithms,
        });
    } catch (err) {
        throw new SdkError(
            'SDK_JWT_VERIFY_FAILED',
            `JWT verify failed: ${(err as Error).message}`,
        );
    }

    const payload = verifyResult.payload;

    // Step 2-exp: exp claim required
    // jose.jwtVerify only checks expiry when exp is present; a missing exp passes through -> a never-expiring credential.
    // Aligned with the sdk jwt-verifier: fail-closed enforcement that exp is present and is a number.
    if (typeof payload.exp !== 'number') {
        throw new SdkError(
            'SDK_JWT_VERIFY_FAILED',
            'JWT payload.exp missing or not a number; non-expiring token rejected (fail-closed)',
        );
    }

    // Step 3: payload.sub required (the sub claim must be a non-empty string)
    if (!payload.sub || typeof payload.sub !== 'string') {
        throw new SdkError(
            'SDK_JWT_VERIFY_FAILED',
            'JWT payload.sub missing or not a non-empty string',
        );
    }

    // Step 4: cross-check mapping literal equality (no substring / prefix matching)
    if (payload.sub !== ctx.expectedDid) {
        throw new SdkError(
            'SDK_MAPPING_MISMATCH',
            `JWT payload.sub (${payload.sub}) does not match expected DID (${ctx.expectedDid})`,
        );
    }

    // Step 5: construct VerifiedTransportContext
    // brand cast: `as TrustedSettlerDid` / `as JwtSubject` executed only after cryptographic verify fully PASSes
    return {
        trustedDid: ctx.expectedDid as TrustedSettlerDid,
        verifierKind: 'jwt',
        verifiedSubject: payload.sub as JwtSubject,
        verifiedAt: new Date().toISOString(),
        sdkVersion: '2.0.0',
    };
}
