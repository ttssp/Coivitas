/**
 * JWT helper functions
 *
 * Summary: JWT alg allowlist/denylist + verifyJwtAlgAllowed +
 *       createJwksWithRetry.
 *
 * Design intent:
 * - The alg allowlist guards against JWT alg downgrade attacks (RFC 7518 'none' attack + weak hashes)
 * - asymmetric only by default (RS256/ES256/EdDSA); symmetric (HS256+) is restricted and must be
 *   explicitly enabled by the caller (mTLS server-to-server only context)
 * - JWKS retry uses jose createRemoteJWKSet's built-in cache + cooldown + timeout
 */

import { createRemoteJWKSet } from 'jose';

import { SdkError } from './errors.js';

/**
 * JWT signature algorithm allowlist (RFC 7518 JWA)
 *
 * Design baseline:
 * - asymmetric (baseline for cross-spec consumers): RS256 (RSA 2048+) / ES256 (P-256) / EdDSA (Ed25519)
 * - symmetric_restricted (mTLS server-to-server only): HS256 / HS384 / HS512
 *
 * Not in this allowlist OR in the denylist → SDK_JWT_VERIFY_FAILED
 */
export const JWT_ALG_ALLOWLIST = {
    /** default asymmetric algorithms (baseline for cross-spec consumers) */
    asymmetric: [
        'RS256',
        'RS384',
        'RS512',
        'ES256',
        'ES384',
        'ES512',
        'EdDSA',
    ] as const,
    /** symmetric algorithms (restricted context; mTLS server-to-server only) */
    symmetric_restricted: ['HS256', 'HS384', 'HS512'] as const,
} as const;

/**
 * JWT signature algorithm denylist (RFC 7518 + historical vulnerabilities)
 *
 * - 'none' alg (forbidden by RFC 7518; rejected built-in by jose@5; enforced here as a second layer)
 * - case variants are rejected too (guards against case-sensitivity bypass)
 */
export const JWT_ALG_DENYLIST = ['none', 'NONE', 'None'] as const;

/**
 * verifyJwtAlgAllowed — JWT alg allowlist enforce (pre-check)
 *
 * Flow:
 * 1. Parse the JWT header (decode the base64url first segment; signature is not verified)
 * 2. denylist reject (RFC 7518 'none' attack defense)
 * 3. allowlist verify (asymmetric default + symmetric_restricted opt-in)
 *
 * @throws SdkError 'SDK_JWT_VERIFY_FAILED' when alg is not in the allowlist OR is in the denylist
 */
export function verifyJwtAlgAllowed(
    jwt: string,
    options?: { allowSymmetric?: boolean },
): void {
    // Step 1: parse JWT header (no signature verify)
    const segments = jwt.split('.');
    const headerSeg = segments[0];
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
            'JWT header decode/parse failed',
        );
    }

    const alg = header.alg;
    if (typeof alg !== 'string' || alg.length === 0) {
        throw new SdkError(
            'SDK_JWT_VERIFY_FAILED',
            'JWT header.alg missing or not string',
        );
    }

    // Step 2: denylist reject (RFC 7518 'none' attack)
    if ((JWT_ALG_DENYLIST as readonly string[]).includes(alg)) {
        throw new SdkError(
            'SDK_JWT_VERIFY_FAILED',
            `JWT alg "${alg}" is in denylist (RFC 7518 'none' attack defense)`,
        );
    }

    // Step 3: allowlist verify
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
            `JWT alg "${alg}" not in allowlist (asymmetric: ${JWT_ALG_ALLOWLIST.asymmetric.join(', ')}; symmetric_restricted: ${JWT_ALG_ALLOWLIST.symmetric_restricted.join(', ')})`,
        );
    }
}

/**
 * createJwksWithRetry — createRemoteJWKSet wrapper (cache + cooldown + timeout)
 *
 * SOP:
 * - cache TTL: 300s (default jose@5 cache; cacheMaxAge ms)
 * - cooldown: 60s (jose@5 cooldownDuration ms; circuit breaker semantics)
 * - timeout: 5s (jose@5 timeoutDuration ms; JWKS endpoint slow path)
 *
 * Note: jose has a built-in retry stage (on request failure + cooldown trigger); a full 5-state
 * circuit breaker is left to a future implementation (this helper already covers the three main
 * concerns: JWKS rotation + cache + timeout).
 */
export function createJwksWithRetry(
    jwksUrl: string,
    options?: {
        cacheTtlSeconds?: number;
        circuitBreakerCooldownSeconds?: number;
        timeoutSeconds?: number;
    },
): ReturnType<typeof createRemoteJWKSet> {
    return createRemoteJWKSet(new URL(jwksUrl), {
        cacheMaxAge: (options?.cacheTtlSeconds ?? 300) * 1000,
        cooldownDuration:
            (options?.circuitBreakerCooldownSeconds ?? 60) * 1000,
        timeoutDuration: (options?.timeoutSeconds ?? 5) * 1000,
    });
}
