/**
 * OAuth2 introspection cryptographic verifier factory
 *
 * Summary: verifyOAuth2AndDeriveDid in 7 steps — OIDC discover + introspection +
 *          triple verify of active/aud/exp + client_id/sub mapping cross-check +
 *          construct VerifiedTransportContext.
 *
 * Defense-in-depth L2 factory layer:
 * - openid-client@6 functional API (replacing the v4/v5 class-based API)
 * - 4-dimension verify of the introspection response: active + aud + exp + client_id/sub mapping
 * - mint the TrustedSettlerDid brand only after both the cryptographic verify
 *   (OAuth2 server-signed introspection response) and the mapping-equality check are enforced
 */

import * as oauth from 'openid-client';

import type {
    OAuth2VerifierContext,
    VerifiedTransportContext,
} from './verifier-types.js';
import type { OAuth2ClientId, TrustedSettlerDid } from './brand-types.js';

import { SdkError } from './errors.js';

const SDK_V0_2_VERSION = '2.0.0' as const;

/**
 * verifyOAuth2AndDeriveDid — OAuth2 introspection verify + TrustedSettlerDid derivation
 *
 * 7-step flow:
 * 1. OIDC discovery (openid-client@6 oauth.discovery)
 * 2. tokenIntrospection call (openid-client@6 oauth.tokenIntrospection)
 * 3. active === true is mandatory
 * 4. aud claim equality (string OR string[]; either one contains expectedAudience)
 * 5. exp not expired (introspection response exp claim; if expired → fail)
 * 6. cross-check mapping (client_id or sub claim === expectedDid)
 * 7. construct VerifiedTransportContext
 *
 * @throws SdkError SDK_OAUTH2_VERIFY_FAILED / SDK_MAPPING_MISMATCH
 */
export async function verifyOAuth2AndDeriveDid(
    ctx: OAuth2VerifierContext,
): Promise<VerifiedTransportContext> {
    // Step 1: OIDC discovery — openid-client@6 functional API
    // discovery takes the issuer URL (fetches .well-known/openid-configuration
    // to auto-discover introspection_endpoint); do not pass introspectionEndpoint itself.
    // Parameter order (v6): URL + clientId + clientMetadata (client_secret lives in metadata)
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

    // Step 2: introspection call — openid-client@6 functional API
    let introspectionResult: oauth.IntrospectionResponse;
    try {
        introspectionResult = await oauth.tokenIntrospection(
            config,
            ctx.accessToken,
        );
    } catch (err) {
        throw new SdkError(
            'SDK_OAUTH2_VERIFY_FAILED',
            `OAuth2 introspection failed: ${(err as Error).message}`,
        );
    }

    // Step 3: active === true is mandatory
    if (introspectionResult.active !== true) {
        throw new SdkError(
            'SDK_OAUTH2_VERIFY_FAILED',
            'OAuth2 introspection response active !== true (token revoked / expired / invalid)',
        );
    }

    // Step 4: aud claim equality (RFC 7662)
    // - aud may be a string OR string[] (RFC 7519)
    const aud = introspectionResult.aud;
    let audMatched = false;
    if (typeof aud === 'string') {
        audMatched = aud === ctx.expectedAudience;
    } else if (Array.isArray(aud)) {
        audMatched = aud.includes(ctx.expectedAudience);
    }
    if (!audMatched) {
        throw new SdkError(
            'SDK_OAUTH2_VERIFY_FAILED',
            `OAuth2 introspection aud (${JSON.stringify(aud)}) does not include expected audience (${ctx.expectedAudience})`,
        );
    }

    // Step 5: exp not expired (RFC 7662 + RFC 7519)
    // - exp is a NumericDate (seconds-resolution Unix epoch); < now → expired
    if (
        typeof introspectionResult.exp === 'number' &&
        introspectionResult.exp * 1000 < Date.now()
    ) {
        throw new SdkError(
            'SDK_OAUTH2_VERIFY_FAILED',
            `OAuth2 access token expired (exp=${introspectionResult.exp}, now=${Math.floor(Date.now() / 1000)})`,
        );
    }

    // Step 6: cross-check mapping (client_id preferred; fallback to sub)
    // - client_id is a standard RFC 7662 introspection response field
    // - sub is a standard RFC 7519 (JWT) field; optional in an OAuth2 introspection response
    const candidate =
        introspectionResult.client_id ?? introspectionResult.sub;
    if (typeof candidate !== 'string' || candidate !== ctx.expectedDid) {
        throw new SdkError(
            'SDK_MAPPING_MISMATCH',
            `OAuth2 introspection client_id/sub (${String(candidate)}) does not match expected DID (${ctx.expectedDid})`,
        );
    }

    // Step 7: construct VerifiedTransportContext
    return {
        trustedDid: ctx.expectedDid as TrustedSettlerDid,
        verifierKind: 'oauth2',
        verifiedSubject: candidate as OAuth2ClientId,
        verifiedAt: new Date().toISOString(),
        sdkVersion: SDK_V0_2_VERSION,
    };
}
