import { randomUUID } from 'node:crypto';

import { verifyCapabilityToken } from '@coivitas/identity';
import type {
    CapabilityToken,
    DelegationChainValidationResult,
    DID,
    ResolvedPublicKeys,
    Timestamp,
} from '@coivitas/types';

import type { RuntimeGuardResult } from '../types.js';

import {
    ScopeEvaluator,
    type ScopeEvaluationResult,
} from './scope-evaluator.js';

// The authoritative RuntimeGuardResult type is defined in `../types.ts`, including the
// fields (`code`, `delegationDepth`). It is re-exported here so downstream consumers can access it
// via the original path.
export type { RuntimeGuardResult };

/**
 * Delegation chain validator signature (matches identity.validateDelegationChain; kept as a local
 * abstraction to ease test injection).
 *
 * The 2nd parameter was upgraded from resolvePublicKey(string) to resolvePublicKeys(ResolvedPublicKeys)
 * to support ROTATING dual-key fallback.
 */
export type RuntimeGuardDelegationValidator = (
    token: CapabilityToken,
    resolvePublicKeys: (did: DID) => Promise<ResolvedPublicKeys | null>,
    isRevoked?: (tokenId: string) => Promise<boolean>,
    now?: Timestamp,
    resolveToken?: (tokenId: string) => Promise<CapabilityToken | null>,
) => Promise<DelegationChainValidationResult>;

export interface RuntimeGuardDependencies {
    tokenStore: {
        getTokensForAgent(agentDid: DID): Promise<CapabilityToken[]>;
        /** Optional: look up a single token by tokenId — used by delegationChainValidator for parent-token snapshot comparison. */
        getToken?(tokenId: string): Promise<CapabilityToken | null>;
    };
    revocationChecker: (tokenId: string) => Promise<boolean>;
    scopeEvaluator?: ScopeEvaluator;
    now?: () => Timestamp;

    /**
     * When the recipient locally holds a delegated token, RuntimeGuard must use
     * validateDelegationChain rather than the synchronous verifyCapabilityToken
     * (the latter fails closed immediately when delegationChain is non-empty).
     *
     * Three-port collaboration:
     *  - delegationChainValidator: validates chain structure / attenuation / revocation
     *  - resolvePublicKeys: resolves the on-chain delegator's dual-key ResolvedPublicKeys (ROTATING fallback)
     *  - tokenStore.getToken: looks up the authoritative parent-token snapshot by tokenId (steps 4/5b/5d)
     *
     * When all three ports are injected, the delegation chain validation path is taken; if any is
     * missing, it fails closed (the current token candidate is skipped). When not injected, the
     * non-delegation behavior is preserved: tokens containing a delegationChain are filtered out by
     * verifyCapabilityToken (not a false rejection, but "delegation semantics not enabled").
     *
     * delegationDepth is passed through and returned by the allowed path of check(), for
     * PolicyEngine → ActionRecorder to write into ActionRecord.delegationDepth
     * (so the audit chain can trace the degree of authorization attenuation).
     */
    delegationChainValidator?: RuntimeGuardDelegationValidator;
    resolvePublicKeys?: (did: DID) => Promise<ResolvedPublicKeys | null>;
}

export class RuntimeGuard {
    private readonly scopeEvaluator: ScopeEvaluator;
    private readonly now: () => Timestamp;

    public constructor(
        private readonly dependencies: RuntimeGuardDependencies,
    ) {
        this.scopeEvaluator =
            dependencies.scopeEvaluator ?? new ScopeEvaluator();
        this.now =
            dependencies.now ?? (() => new Date().toISOString() as Timestamp);
    }

    public async check(
        action: string,
        params: Record<string, unknown>,
        agentDid: DID,
        /**
         * Optional: restrict authorization to the token with this tokenId only.
         *
         * Capability authorization closure requires: when the caller declares a token in
         * envelope.header.capabilityTokenRef, RuntimeGuard must make the authorization decision using
         * that token alone; otherwise the token-confusion attack of "narrow token passes
         * verifyCapability + wide token passes RuntimeGuard" becomes feasible.
         *
         * When not provided, the default behavior is preserved: scan all of the agent's tokens and take
         * the first usable one.
         */
        requestedTokenId?: string,
    ): Promise<RuntimeGuardResult> {
        const allTokens =
            await this.dependencies.tokenStore.getTokensForAgent(agentDid);
        const tokens =
            requestedTokenId === undefined
                ? allTokens
                : allTokens.filter((token) => token.id === requestedTokenId);

        if (tokens.length === 0) {
            return {
                allowed: false,
                reason:
                    requestedTokenId !== undefined
                        ? 'requested token not found for agent'
                        : 'no tokens found',
            };
        }

        let sawMatchingCapability = false;
        let lastScopeFailure: ScopeEvaluationResult | undefined;
        let sawRevoked = false;

        for (const token of tokens) {
            const hasChain =
                Array.isArray(token.delegationChain) &&
                token.delegationChain.length > 0;

            // depth is taken from the validator result (delegation chain path) or defaults to the
            // value of 0 (no-delegation-chain path).
            let chainDepth = 0;

            if (!hasChain) {
                const verification = verifyCapabilityToken(token, this.now());
                if (!verification.valid) {
                    continue;
                }
                // Single hop (no delegationChain) → depth=0 (authorized directly by the principal)
            } else {
                // A delegated token must go through validateDelegationChain.
                // When tokenStore.getToken is missing, it must skip (fail-closed):
                // the "if (resolveToken) { ... }" block inside validateDelegationChain contains
                // critical defenses such as steps 5b/5d and root-parent self-signing; if resolveToken
                // is undefined, all parent-token bindings and root-parent signature checks are
                // silently skipped — which amounts to bypassing the forged-root-parent attack fix.
                // No authoritative getToken injected = unable to perform spec step 4 "load all parent
                // tokens (authoritative verification)", so it must fail closed.
                const { delegationChainValidator, resolvePublicKeys } =
                    this.dependencies;
                if (
                    !delegationChainValidator ||
                    !resolvePublicKeys ||
                    !this.dependencies.tokenStore.getToken
                ) {
                    continue;
                }
                // The leaf token's own time window / JSON schema / scope-version gate
                // is guarded jointly by the internal constraints of validateDelegationChain plus the
                // chain signatures; additionally, expiresAt/issuedAt are checked here separately
                // (aligned with the public-key resolution path) to avoid wasting resources by feeding an expired
                // token into the chain validator.
                const nowMs = new Date(this.now()).getTime();
                if (new Date(token.issuedAt).getTime() > nowMs) continue;
                if (new Date(token.expiresAt).getTime() <= nowMs) continue;

                const chainResult = await delegationChainValidator(
                    token,
                    resolvePublicKeys,
                    this.dependencies.revocationChecker,
                    this.now(),
                    (id) => this.dependencies.tokenStore.getToken!(id),
                );
                if (!chainResult.valid) {
                    // Contract (cross-layer contract): cascading revocation must be explicitly
                    // propagated as token-revoked semantics — L3 returns code='TOKEN_REVOKED', the
                    // downstream L4 passes it through verbatim, and L5 exposes TOKEN_REVOKED. Other
                    // chain failure reasons (signature/attenuation/depth/etc.) semantically mean "this
                    // candidate token is unusable", so continue to the next token candidate, falling
                    // through to a no-matching-capability or scope failure; the original continue
                    // behavior is preserved to avoid affecting multi-token authorization.
                    if (chainResult.reason === 'PARENT_TOKEN_REVOKED') {
                        return {
                            allowed: false,
                            reason: 'parent token revoked',
                            code: 'TOKEN_REVOKED',
                            tokenId: token.id,
                        };
                    }
                    continue;
                }
                // depth is authoritatively returned by the identity validator (equivalent to chain
                // length - 1; 0 = no delegation chain, authorized directly by the principal).
                chainDepth = chainResult.depth ?? 0;
            }

            const matchingCapabilities = token.capabilities.filter(
                (capability) => capability.action === action,
            );
            if (matchingCapabilities.length === 0) {
                continue;
            }

            sawMatchingCapability = true;

            // Inject agentDid / recordId into params for cumulative_limit use.
            // New __recordId (check-and-reserve idempotency key):
            // - If the caller pre-injected a UUID into params.__recordId, the caller's value is used
            // (keeping the same recordId as the ActionRecord, satisfying the spec contract that
            // "reservation → settle idempotency keys are consistent");
            // - Otherwise a UUID is generated here (used only internally by the CumulativeLimit gate;
            // the caller cannot settle it).
            // TODO: replace with a typed EvaluationContext parameter.
            const recordId =
                typeof params['__recordId'] === 'string'
                    ? params['__recordId']
                    : randomUUID();
            const paramsWithAgent = {
                ...params,
                __agentDid: agentDid,
                __recordId: recordId,
            };
            const scopeResult = await this.scopeEvaluator.evaluateAll(
                matchingCapabilities.map((capability) => capability.scope),
                paramsWithAgent,
                new Date(this.now()),
            );
            if (!scopeResult.allowed) {
                lastScopeFailure = scopeResult;
                continue;
            }

            if (await this.dependencies.revocationChecker(token.id)) {
                sawRevoked = true;
                continue;
            }

            return {
                allowed: true,
                tokenId: token.id,
                delegationDepth: chainDepth,
            };
        }

        if (!sawMatchingCapability) {
            return {
                allowed: false,
                reason: 'no matching capability',
            };
        }

        if (sawRevoked) {
            return {
                allowed: false,
                reason: 'capability revoked',
            };
        }

        return {
            allowed: false,
            reason: `scope check failed: ${lastScopeFailure?.reason ?? 'unknown reason'}`,
        };
    }
}
