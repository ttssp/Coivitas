/**
 * VerifierFactory orchestrator (sdk v0.2 L5 orchestration layer)
 *
 * Summary: a single entry point `VerifierFactory.verify(input)` dispatches by input.kind
 *          to the 3 verifiers (mTLS / JWT / OAuth2). VerifierKind = 'mtls' | 'jwt' | 'oauth2'.
 *
 * Design intent:
 * - single entry point at the L5 sdk orchestration layer; sub-protocol consumers do not call
 *   verifyMtlsAndDeriveDid / verifyJwtAndDeriveDid / verifyOAuth2AndDeriveDid (the 3 factories)
 *   directly — reduces the call surface + centralizes the audit-log hook
 *   (later integrated with the hcc v0.2 hash chain primitive)
 * - dispatch by VerifierKind: a discriminated union (VerifierFactoryInput) →
 *   TypeScript narrowing guarantees the ctx field types match the kind
 * - the factory holds no state (no cache / no circuit breaker) — these helpers are provided
 *   separately in oauth2-helpers.ts (OAuth2CircuitBreaker / Cache / RateLimiter);
 *   the caller decides whether to wrap them
 *
 * Defense-in-depth overview:
 * - L1 type layer (compile-time): TrustedSettlerDid brand; a bare cast is rejected
 * - L2 factory layer (this orchestrator + the 3 verifiers): cryptographic verify
 * - L3 boundary layer (the sub-protocol call boundary): boundary-check.ts 4-dimension check
 * - L4 sub-protocol cross-check (internal to the sub-protocol): sr v0.1 audience cross-check, etc.
 * - L5 audit log (audit layer): hcc v0.2 hash chain entry (audit-log integration)
 */

import type {
    VerifiedTransportContext,
    VerifierFactoryInput,
    VerifierKind,
} from './verifier-types.js';

import { SdkError } from './errors.js';
import { verifyMtlsAndDeriveDid } from './mtls-verifier.js';
import { verifyJwtAndDeriveDid } from './jwt-verifier.js';
import { verifyOAuth2AndDeriveDid } from './oauth2-verifier.js';

/**
 * VerifierFactory — sdk v0.2 cryptographic verifier orchestrator (L5)
 *
 * Usage:
 * ```typescript
 * const factory = new VerifierFactory();
 * const ctx = await factory.verify({
 *     kind: 'jwt',
 *     ctx: { jwt, jwks, expectedIssuer, expectedAudience, expectedDid },
 * });
 * // ctx: VerifiedTransportContext { trustedDid, verifierKind: 'jwt', ... }
 * ```
 *
 * The current implementation is stateless (per-call factory dispatch); later, an
 * audit-log hook (integrated with the hcc v0.2 hash chain primitive) may instrument the verify()
 * entry point + the failure path.
 */
export class VerifierFactory {
    /**
     * The set of supported verifier kinds (the VerifierKind union)
     *
     * No 4th value is allowed; adding a new verifier kind requires re-freezing the spec and
     * recording the architecture decision.
     */
    public static readonly SUPPORTED_KINDS: readonly VerifierKind[] = [
        'mtls',
        'jwt',
        'oauth2',
    ] as const;

    /**
     * verify — single entry point, dispatch by VerifierKind
     *
     * @param input VerifierFactoryInput discriminated union
     * @returns VerifiedTransportContext with 5 fields (trustedDid + verifierKind + verifiedSubject + verifiedAt + sdkVersion)
     * @throws SdkError SDK_MTLS_VERIFY_FAILED / SDK_JWT_VERIFY_FAILED /
     *                  SDK_OAUTH2_VERIFY_FAILED / SDK_MAPPING_MISMATCH /
     *                  SDK_SCHEMA_VIOLATION
     */
    public async verify(
        input: VerifierFactoryInput,
    ): Promise<VerifiedTransportContext> {
        // dispatch by discriminated union kind (TS narrowing keeps the ctx types consistent)
        switch (input.kind) {
            case 'mtls':
                return verifyMtlsAndDeriveDid(input.ctx);
            case 'jwt':
                return verifyJwtAndDeriveDid(input.ctx);
            case 'oauth2':
                return verifyOAuth2AndDeriveDid(input.ctx);
            default: {
                // unreachable (the discriminated union is exhaustive); fail-closed fallback
                const _exhaustive: never = input;
                throw new SdkError(
                    'SDK_SCHEMA_VIOLATION',
                    `unsupported VerifierKind: ${JSON.stringify(_exhaustive)}`,
                );
            }
        }
    }
}
