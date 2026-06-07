/**
 * verify-oauth2 — OAuth2 introspection verify + TrustedSettlerDid derivation
 *
 * Conclusion: verifyOAuth2AndDeriveDid implements the sdk v0.2 flow (Steps 1-7),
 * built on the openid-client@6 functional API.
 * Includes a triple resilience guard: introspection cache + circuit breaker + rate limiter.
 *
 * Basis:
 *   - sdk v0.2 OAuth2 verifier factory flow
 *   - openid-client@6 functional API (replaces the v4/v5 class-based one)
 *   - PKI threat model (STRIDE DoS dimension — rate limit + circuit breaker)
 *   - 60s TTL cache + 5-failure circuit breaker + 100 req/s token bucket
 *
 * Security constraints:
 *   - introspection response active !== true → throw SDK_OAUTH2_VERIFY_FAILED (fail-closed)
 *   - aud claim does not contain expectedAudience → throw SDK_OAUTH2_VERIFY_FAILED (fail-closed)
 *   - exp expired → throw SDK_OAUTH2_VERIFY_FAILED (fail-closed)
 *   - client_id/sub !== expectedDid → throw SDK_MAPPING_MISMATCH
 *   - circuit breaker OPEN → fail-closed throw SDK_OAUTH2_VERIFY_FAILED (no upstream call)
 *   - rate limiter exceed → fail-closed throw SDK_OAUTH2_VERIFY_FAILED
 *   - brand cast: `as TrustedSettlerDid` / `as OAuth2ClientId` only after cryptographic verify passes (no forced brand cast)
 */

import * as oauth from 'openid-client';
import type {
    OAuth2VerifierContext,
    VerifiedTransportContext,
    TrustedSettlerDid,
    OAuth2ClientId,
} from '@coivitas/types';
import { SdkError } from '@coivitas/types';
import {
    OAuth2IntrospectionCache,
    OAuth2CircuitBreaker,
    OAuth2RateLimiter,
} from './oauth2-helpers.js';

// ─── module-level singleton instances (can be overridden via test injection) ───────────────
// Conclusion: a module-level singleton is the recommended pattern for the openid-client@6 functional API;
// the introspection call can be mocked/stubbed in tests.
// cache TTL = 60s
// circuitBreaker: 5 failures → OPEN 60s (STRIDE DoS mitigation)
// rateLimiter: 100 req/s token bucket (single module instance; multi-tenant scenarios need a per-tenant instance)

const _defaultCache = new OAuth2IntrospectionCache(60);
const _defaultCircuitBreaker = new OAuth2CircuitBreaker(5, 60);
const _defaultRateLimiter = new OAuth2RateLimiter(100, 100);

/**
 * verifyOAuth2AndDeriveDid — OAuth2 introspection verify + TrustedSettlerDid derivation
 *
 * Conclusion: 7-step flow — rate limit → circuit breaker → OIDC discovery → introspection (cached) →
 * active verify → aud verify → exp verify → cross-check mapping → VerifiedTransportContext construction.
 * The cryptographic guard in the L2 factory layer is the only legitimate construction path for TrustedSettlerDid (the OAuth2 path).
 *
 * Flow:
 *   Step 0: rate limit consume (OAuth2RateLimiter; abuse prevention)
 *   Step 1: circuit breaker execute wrapper (OAuth2CircuitBreaker; STRIDE DoS mitigation)
 *   Step 2: OIDC discovery (openid-client@6 functional API: oauth.discovery)
 *   Step 3: introspection call (cache getOrIntrospect → oauth.tokenIntrospection)
 *   Step 4: introspection response active === true required
 *   Step 5: aud claim must contain expectedAudience (both string OR string[] formats)
 *   Step 6: exp not expired verify
 *   Step 7: cross-check mapping literal equality (client_id or sub === expectedDid)
 *   Step 8: construct VerifiedTransportContext (brand cast — only after cryptographic verify fully PASSes)
 *
 * @param ctx OAuth2VerifierContext (access token + introspection endpoint + client credentials + expected aud/DID)
 * @param opts optional: dependency-injected cache / circuitBreaker / rateLimiter (for testing)
 * @returns VerifiedTransportContext (trustedDid = expectedDid as TrustedSettlerDid)
 * @throws SdkError 'SDK_OAUTH2_VERIFY_FAILED' introspection failure / active not true / aud mismatch / exp expired / circuit OPEN / rate exceeded
 * @throws SdkError 'SDK_MAPPING_MISMATCH' client_id/sub !== expectedDid
 */
export async function verifyOAuth2AndDeriveDid(
    ctx: OAuth2VerifierContext,
    opts?: {
        cache?: OAuth2IntrospectionCache;
        circuitBreaker?: OAuth2CircuitBreaker;
        rateLimiter?: OAuth2RateLimiter;
        /** For testing: replaces the OIDC discovery + introspection call as a whole (dependency injection port)*/
        introspectFn?: (token: string) => Promise<oauth.IntrospectionResponse>;
    },
): Promise<VerifiedTransportContext> {
    const cache = opts?.cache ?? _defaultCache;
    const circuitBreaker = opts?.circuitBreaker ?? _defaultCircuitBreaker;
    const rateLimiter = opts?.rateLimiter ?? _defaultRateLimiter;

    // Step 0: rate limit consume (OAuth2RateLimiter token bucket; over-limit throws SDK_OAUTH2_VERIFY_FAILED)
    rateLimiter.consume();

    // trust authority binding — cache key binding
    // Prevents an attacker from introspecting a token against a self-controlled endpoint and then reusing the cache hit under another authority.
    // issuerUrl is the real network authority (the discovery entry point); without it, issuer A's cache could be reused by issuer B.
    const authority = {
        issuerUrl: ctx.issuerUrl,
        introspectionEndpoint: ctx.introspectionEndpoint,
        introspectionClientId: ctx.introspectionClientId,
        expectedAudience: ctx.expectedAudience,
    };

    // Step 1-7: all run inside the circuit breaker execute wrapper (executed when CLOSED/HALF_OPEN; fail-closed when OPEN)
    const introspectionResult = await circuitBreaker.execute(async () => {
        // Test DI injection path: introspectFn bypasses the OIDC discovery + tokenIntrospection network calls
        if (opts?.introspectFn !== undefined) {
            return await cache.getOrIntrospect(
                authority,
                ctx.accessToken,
                opts.introspectFn,
            );
        }

        // Step 2: OIDC discovery (openid-client@6 functional API)
        // discovery takes the issuer URL and fetches .well-known/openid-configuration,
        // auto-discovering introspection_endpoint; do not pass introspectionEndpoint itself (it would fetch metadata from the wrong location).
        let config: oauth.Configuration;
        try {
            config = await oauth.discovery(
                new URL(ctx.issuerUrl),
                ctx.introspectionClientId,
                {
                    client_secret: ctx.introspectionClientSecret,
                },
            );
        } catch (err) {
            throw new SdkError(
                'SDK_OAUTH2_VERIFY_FAILED',
                `OAuth2 OIDC discovery failed: ${(err as Error).message}`,
            );
        }

        // Step 2.5: discovery metadata consistency check
        // The introspection_endpoint produced by discovery must match the configured introspectionEndpoint.
        // Otherwise an attacker-controlled issuer could point at an arbitrary endpoint in its metadata, while the cache key /
        // config assumes it is the trusted endpoint → trust domain mismatch. Any missing or mismatched value is fail-closed.
        const discoveredIntrospectionEndpoint =
            config.serverMetadata().introspection_endpoint;
        if (
            discoveredIntrospectionEndpoint === undefined ||
            discoveredIntrospectionEndpoint !== ctx.introspectionEndpoint
        ) {
            throw new SdkError(
                'SDK_OAUTH2_VERIFY_FAILED',
                `OAuth2 discovery introspection_endpoint mismatch: ` +
                    `discovered=${discoveredIntrospectionEndpoint ?? '(none)'}, ` +
                    `configured=${ctx.introspectionEndpoint}`,
            );
        }

        // Step 3: introspection call (cache hit skips the RTT; miss goes through a real introspection)
        return await cache.getOrIntrospect(
            authority,
            ctx.accessToken,
            async (token) => {
                try {
                    return await oauth.tokenIntrospection(config, token);
                } catch (err) {
                    throw new SdkError(
                        'SDK_OAUTH2_VERIFY_FAILED',
                        `OAuth2 tokenIntrospection failed: ${(err as Error).message}`,
                    );
                }
            },
        );
    });

    // Step 4: introspection response active === true required
    if (introspectionResult.active !== true) {
        throw new SdkError(
            'SDK_OAUTH2_VERIFY_FAILED',
            'OAuth2 introspection response active !== true (token revoked / expired / invalid)',
        );
    }

    // Step 5: aud claim required and must contain expectedAudience (string OR string[], RFC 7662 format)
    // Previously a missing aud skipped the check and proceeded to mapping,
    // letting a token with no bound audience (or an introspection server that omits aud) authenticate for this resource.
    // fail-closed: aud missing / not string|string[] / does not contain expectedAudience → throw.
    const aud = introspectionResult.aud as unknown;
    if (aud === undefined || aud === null) {
        throw new SdkError(
            'SDK_OAUTH2_VERIFY_FAILED',
            `OAuth2 introspection response missing aud claim; cannot bind token to expected audience (${ctx.expectedAudience}) — fail-closed`,
        );
    }
    const audMatches =
        (typeof aud === 'string' && aud === ctx.expectedAudience) ||
        (Array.isArray(aud) &&
            aud.every((a) => typeof a === 'string') &&
            (aud).includes(ctx.expectedAudience));
    if (!audMatches) {
        throw new SdkError(
            'SDK_OAUTH2_VERIFY_FAILED',
            `OAuth2 introspection aud (${JSON.stringify(aud)}) is not a string/string[] containing expected audience (${ctx.expectedAudience})`,
        );
    }

    // Step 6: exp not expired (introspection response exp claim; Unix timestamp in seconds)
    if (
        introspectionResult.exp !== undefined &&
        introspectionResult.exp * 1000 < Date.now()
    ) {
        throw new SdkError(
            'SDK_OAUTH2_VERIFY_FAILED',
            `OAuth2 access token expired (exp=${introspectionResult.exp}; now=${Math.floor(Date.now() / 1000)})`,
        );
    }

    // Step 7: cross-check mapping literal equality (client_id preferred; sub fallback)
    // No substring / prefix matching allowed; must be literally equal
    const candidate =
        (introspectionResult.client_id) ??
        (introspectionResult.sub);

    if (typeof candidate !== 'string' || candidate !== ctx.expectedDid) {
        throw new SdkError(
            'SDK_MAPPING_MISMATCH',
            `OAuth2 introspection client_id/sub (${candidate ?? 'undefined'}) does not match expected DID (${ctx.expectedDid})`,
        );
    }

    // Step 8: construct VerifiedTransportContext
    // brand cast: `as TrustedSettlerDid` / `as OAuth2ClientId` only after cryptographic verify fully PASSes
    return {
        trustedDid: ctx.expectedDid as TrustedSettlerDid,
        verifierKind: 'oauth2',
        verifiedSubject: candidate as OAuth2ClientId,
        verifiedAt: new Date().toISOString(),
        sdkVersion: '2.0.0',
    };
}
