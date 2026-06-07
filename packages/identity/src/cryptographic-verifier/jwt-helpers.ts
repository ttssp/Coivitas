/**
 * jwt-helpers — JWT alg allowlist/denylist + verifyJwtAlgAllowed
 *
 * Summary: a pre-flight alg check that prevents JWT alg downgrade / 'none' attacks, an extra line of defense outside jose jwtVerify.
 *
 * Basis:
 *   - sdk v0.2 (aligned with verifyJwtAlgAllowed)
 *   - transport library SOP (jose@5 algorithms passed explicitly; defense-in-depth)
 * - patch carry-over anchor (allowSymmetric default false)
 *
 * Security constraints:
 *   - JWT_ALG_DENYLIST includes 'none'/'NONE'/'None' — strictly forbidden by RFC 7518
 *   - symmetric off by default; the caller must explicitly set allowSymmetric=true to enable it
 *   - this module is side-effect-free; pure functions; safe to call repeatedly
 */

import { SdkError } from '@coivitas/types';

// ─── JWT algorithm allowlist ───────────────────

/**
 * JWT_ALG_ALLOWLIST — JWT signature algorithms permitted by sdk v0.2 (RFC 7518 JWA)
 *
 * asymmetric: RS256/384/512 (RSA PKCS#1; 2048+ key) + ES256/384/512 (EC P-256/P-384/P-521) + EdDSA (Ed25519)
 * symmetric_restricted: HS256/384/512 — limited to the mTLS server-to-server context; requires the caller to enable it explicitly
 */
export const JWT_ALG_ALLOWLIST = {
    /** default asymmetric algorithms (cross-spec consumer-side baseline)*/
    asymmetric: [
        'RS256',
        'RS384',
        'RS512',
        'ES256',
        'ES384',
        'ES512',
        'EdDSA',
    ] as const,
    /** symmetric algorithm (restricted context; mTLS server-to-server only; requires explicit caller opt-in)*/
    symmetric_restricted: ['HS256', 'HS384', 'HS512'] as const,
} as const;

/**
 * JWT_ALG_DENYLIST — JWT signature algorithms strictly forbidden by sdk v0.2
 *
 * 'none'/'NONE'/'None' — the unsigned mode strictly forbidden by RFC 7518;
 * jose@5 already rejects it built-in, and this denylist is an extra pre-flight defense-in-depth layer.
 */
export const JWT_ALG_DENYLIST = ['none', 'NONE', 'None'] as const;

// ─── verifyJwtAlgAllowed ───────────────────────────────────────────────────────

/**
 * verifyJwtAlgAllowed — JWT alg allowlist enforce
 *
 * Summary: a pre-flight alg check before the jose jwtVerify call, preventing alg downgrade attacks.
 * Order:
 *   Step 1: JWT header decode (base64url-decode the first segment; signature not verified)
 *   Step 2: denylist reject ('none' attack)
 *   Step 3: allowlist verify (asymmetric + optional symmetric_restricted)
 *
 * @param jwt JWT compact serialization (header.payload.signature)
 * @param options allowSymmetric: false (default) = asymmetric only; true = also allow HS256/384/512
 * @throws SdkError 'SDK_JWT_VERIFY_FAILED' on non-compliant alg / header parse failure
 */
export function verifyJwtAlgAllowed(
    jwt: string,
    options?: { allowSymmetric?: boolean },
): void {
    // Step 1: parse JWT header (decode the first base64url segment; signature not verified)
    const headerSeg = jwt.split('.')[0];
    if (!headerSeg) {
        throw new SdkError(
            'SDK_JWT_VERIFY_FAILED',
            'JWT compact serialization invalid (no header segment)',
        );
    }

    let header: { alg?: unknown };
    try {
        header = JSON.parse(
            Buffer.from(headerSeg, 'base64url').toString('utf-8'),
        ) as { alg?: unknown };
    } catch {
        throw new SdkError(
            'SDK_JWT_VERIFY_FAILED',
            'JWT header decode/parse failed (not valid base64url JSON)',
        );
    }

    const alg = header.alg;
    if (typeof alg !== 'string' || alg.length === 0) {
        throw new SdkError(
            'SDK_JWT_VERIFY_FAILED',
            'JWT header.alg missing or not a non-empty string',
        );
    }

    // Step 2: denylist reject (RFC 7518 'none' attack defense; pre-flight defense-in-depth)
    if ((JWT_ALG_DENYLIST as readonly string[]).includes(alg)) {
        throw new SdkError(
            'SDK_JWT_VERIFY_FAILED',
            `JWT alg "${alg}" is in denylist (RFC 7518 strictly forbids the 'none' alg)`,
        );
    }

    // Step 3: allowlist verify (asymmetric must be listed; symmetric requires explicit caller opt-in)
    const asymmetricOk = (
        JWT_ALG_ALLOWLIST.asymmetric as readonly string[]
    ).includes(alg);

    const symmetricOk =
        options?.allowSymmetric === true &&
        (JWT_ALG_ALLOWLIST.symmetric_restricted as readonly string[]).includes(
            alg,
        );

    if (!asymmetricOk && !symmetricOk) {
        throw new SdkError(
            'SDK_JWT_VERIFY_FAILED',
            `JWT alg "${alg}" not in allowlist — asymmetric: [${JWT_ALG_ALLOWLIST.asymmetric.join(', ')}]; symmetric_restricted (requires explicit opt-in): [${JWT_ALG_ALLOWLIST.symmetric_restricted.join(', ')}]`,
        );
    }
}
