/**
 * JWT cryptographic verifier factory
 *
 * Summary: verifyJwtAndDeriveDid in 5 steps — alg allowlist enforce + JWKS build +
 *       jose@5 jwtVerify + sub claim cross-check + build the VerifiedTransportContext.
 *
 * Triple-defense L2 factory layer:
 * - jose@5 has built-in alg validation; here we add another layer of allowlist/denylist enforcement
 * - mint the TrustedSettlerDid brand after cryptographic verify (jose@5 jwtVerify) + sub claim
 *   equality are both enforced
 */

import { type JWTPayload, createRemoteJWKSet, jwtVerify } from 'jose';

import type {
    JwtVerifierContext,
    VerifiedTransportContext,
} from './verifier-types.js';
import type { JwtSubject, TrustedSettlerDid } from './brand-types.js';

import { SdkError } from './errors.js';
import { JWT_ALG_ALLOWLIST, verifyJwtAlgAllowed } from './jwt-helpers.js';

const SDK_V0_2_VERSION = '2.0.0' as const;

/**
 * verifyJwtAndDeriveDid — JWT signature/exp/iss/aud verify + TrustedSettlerDid derivation
 *
 * 5-step flow:
 * 1. alg allowlist pre-enforce (denylist 'none' attack defense)
 * 2. build JWKS (remote URL OR static key set)
 * 3. jose@5 jwtVerify (signature + exp + iss + aud verify + a second algorithms constraint)
 * 4. cross-check mapping (payload.sub === expectedDid)
 * 5. build the VerifiedTransportContext
 *
 * @throws SdkError SDK_JWT_VERIFY_FAILED / SDK_MAPPING_MISMATCH
 */
export async function verifyJwtAndDeriveDid(
    ctx: JwtVerifierContext,
): Promise<VerifiedTransportContext> {
    // Step 1: alg allowlist pre-enforce
    // - allowSymmetric=false by default → asymmetric only (RS256/ES256/EdDSA)
    // - caller explicitly sets allowSymmetricAlg=true → allows HS256/HS384/HS512 (mTLS context)
    verifyJwtAlgAllowed(ctx.jwt, {
        allowSymmetric: ctx.allowSymmetricAlg === true,
    });

    // Step 2: build JWKS (URL → remote with cache;object → static)
    const jwks =
        typeof ctx.jwks === 'string'
            ? createRemoteJWKSet(new URL(ctx.jwks))
            : ctx.jwks;

    // Step 3: jose@5 jwtVerify — explicit algorithms constraint (second-layer enforce, defense-in-depth)
    // - union when allowSymmetric=true; otherwise asymmetric only
    const allowedAlgorithms: string[] =
        ctx.allowSymmetricAlg === true
            ? [
                  ...JWT_ALG_ALLOWLIST.asymmetric,
                  ...JWT_ALG_ALLOWLIST.symmetric_restricted,
              ]
            : [...JWT_ALG_ALLOWLIST.asymmetric];

    let verifyResult: { payload: JWTPayload };
    try {
        verifyResult = await jwtVerify(
            ctx.jwt,
            jwks as Parameters<typeof jwtVerify>[1],
            {
                issuer: ctx.expectedIssuer,
                audience: ctx.expectedAudience,
                algorithms: allowedAlgorithms,
            },
        );
    } catch (err) {
        throw new SdkError(
            'SDK_JWT_VERIFY_FAILED',
            `JWT verify failed: ${(err as Error).message}`,
        );
    }

    const payload = verifyResult.payload;

    // Step 4-exp: exp claim is mandatory
    // jose.jwtVerify only checks expiry when exp is present; when exp is missing it passes → a signed
    // token without exp (with valid iss/aud/sub) would become a never-expiring credential. Fail-closed:
    // require exp to be present and a number.
    if (typeof payload.exp !== 'number') {
        throw new SdkError(
            'SDK_JWT_VERIFY_FAILED',
            'JWT payload.exp missing or not a number; non-expiring token rejected (fail-closed)',
        );
    }

    // Step 4a: sub claim is mandatory + must be a string
    if (typeof payload.sub !== 'string' || payload.sub.length === 0) {
        throw new SdkError(
            'SDK_JWT_VERIFY_FAILED',
            'JWT payload.sub missing or not a non-empty string',
        );
    }

    // Step 4b: cross-check mapping (string equality; substring / prefix matches are not allowed)
    if (payload.sub !== ctx.expectedDid) {
        throw new SdkError(
            'SDK_MAPPING_MISMATCH',
            `JWT payload.sub (${payload.sub}) does not match expected DID (${ctx.expectedDid})`,
        );
    }

    // Step 5: build the VerifiedTransportContext
    return {
        trustedDid: ctx.expectedDid as TrustedSettlerDid,
        verifierKind: 'jwt',
        verifiedSubject: payload.sub as JwtSubject,
        verifiedAt: new Date().toISOString(),
        sdkVersion: SDK_V0_2_VERSION,
    };
}
