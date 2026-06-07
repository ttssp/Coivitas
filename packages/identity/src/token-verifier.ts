import { verify } from '@coivitas/crypto';
import {
    type CapabilityToken,
    type DID,
    type ResolvedPublicKeys,
    type Timestamp,
    validateAgainstSchema,
} from '@coivitas/types';

import { validateDelegationChain } from './delegation-validator.js';
import {
    extractPublicKeyFromDIDKey,
    isDidAgent,
    isDidKey,
    isTimestampExpired,
} from './did.js';
import { createCapabilityTokenPayload } from './token-issuer.js';

export interface TokenVerificationResult {
    valid: boolean;
    code?:
        | 'INVALID_TOKEN_FORMAT'
        | 'TOKEN_EXPIRED'
        | 'SIGNATURE_INVALID'
        | 'DELEGATION_CHAIN_INVALID';
    message?: string;
}

export interface TokenActionCheckResult {
    allowed: boolean;
    code?:
        | 'TOKEN_NOT_FOR_THIS_AGENT'
        | 'INVALID_ACTION'
        | 'SCOPE_EXCEEDED'
        /** encountered an unsupported new scope type (fail-closed)*/
        | 'SCOPE_TYPE_UNKNOWN';
    message?: string;
}

export function verifyCapabilityToken(
    token: CapabilityToken,
    now: Timestamp = new Date().toISOString() as Timestamp,
    resolvedKeys?: ResolvedPublicKeys,
): TokenVerificationResult {
    const schemaResult = validateAgainstSchema(token, 'capabilityToken');
    if (!schemaResult.valid) {
        return {
            valid: false,
            code: 'INVALID_TOKEN_FORMAT',
            message: schemaResult.errors
                .map((error) => `${error.instancePath} ${error.message}`.trim())
                .join('; '),
        };
    }

    // issuerDid format check:
    // when resolvedKeys is passed (the ROTATING scenario), the did:agent format is allowed;
    // otherwise did:key is strictly required (the public-key resolution path).
    if (resolvedKeys !== undefined) {
        if (!isDidKey(token.issuerDid) && !isDidAgent(token.issuerDid)) {
            return {
                valid: false,
                code: 'INVALID_TOKEN_FORMAT',
                message: 'issuerDid must use did:key or did:agent format.',
            };
        }
    } else {
        if (!isDidKey(token.issuerDid)) {
            return {
                valid: false,
                code: 'INVALID_TOKEN_FORMAT',
                message: 'issuerDid must use did:key format.',
            };
        }
        // Extra gate: verificationMethod cannot use did:agent (without resolvedKeys, the signature cannot be verified)
        if (isDidAgent(token.proof.verificationMethod.split('#')[0] ?? '')) {
            return {
                valid: false,
                code: 'INVALID_TOKEN_FORMAT',
                message:
                    'Non-delegated token cannot use did:agent verificationMethod without resolvedKeys; issuerDid must use did:key format.',
            };
        }
    }

    if (new Date(token.issuedAt).getTime() > new Date(now).getTime()) {
        return {
            valid: false,
            code: 'INVALID_TOKEN_FORMAT',
            message: 'issuedAt cannot be in the future.',
        };
    }

    if (isTimestampExpired(token.expiresAt, now)) {
        return {
            valid: false,
            code: 'TOKEN_EXPIRED',
            message: 'Capability token has expired.',
        };
    }

    // Delegation chain:
    // a child token with a delegationChain has its top-level proof signed by the final delegator (did:agent),
    // and verification requires asynchronous agent public-key resolution (IdentityRegistry). This synchronous verifier only covers
    // single-hop tokens (issuerDid is did:key). A delegation-chain token must go through
    // the full DelegationChainValidator path — rejected fail-closed here.
    if (token.delegationChain && token.delegationChain.length > 0) {
        return {
            valid: false,
            code: 'INVALID_TOKEN_FORMAT',
            message:
                'Delegated capability token (non-empty delegationChain) requires DelegationChainValidator; synchronous verifyCapabilityToken cannot resolve did:agent signer.',
        };
    }

    // Scope gate: a 0.1.0 token must not carry 0.2.0-only scope types.
    // Conclusion: temporal_scope/cumulative_limit were introduced in 0.2.0, so a 0.1.0 token containing such a type
    // is a format error (a non-compliant token) and must be rejected before signature verification, to avoid mistaking it for a signature failure.
    if (token.specVersion === '0.1.0') {
        const phase2ScopeTypes = ['temporal_scope', 'cumulative_limit'];
        for (const cap of token.capabilities) {
            if (phase2ScopeTypes.includes(cap.scope.type)) {
                return {
                    valid: false,
                    code: 'INVALID_TOKEN_FORMAT',
                    message: `Scope type '${cap.scope.type}' is not supported in specVersion 0.1.0 tokens.`,
                };
            }
        }
    }

    // Build the signing payload (shared by both verification branches)
    const payloadBytes = createCapabilityTokenPayload({
        id: token.id,
        specVersion: token.specVersion,
        issuerDid: token.issuerDid,
        principalDid: token.principalDid,
        issuedTo: token.issuedTo,
        issuedAt: token.issuedAt,
        expiresAt: token.expiresAt,
        capabilities: token.capabilities,
        revocationUrl: token.revocationUrl,
        // delegationChain was already rejected by the branch above; it must be undefined here,
        // so the signing payload is exactly identical to the single-hop case.
        delegationChain: token.delegationChain,
    });

    if (resolvedKeys !== undefined) {
        // ROTATING dual-key path: try current first, and try previous on failure when ROTATING
        const currentValid = verify(
            payloadBytes,
            token.proof.value,
            resolvedKeys.current,
        );
        if (currentValid) {
            return { valid: true };
        }
        if (
            resolvedKeys.rotationState === 'ROTATING' &&
            resolvedKeys.previous !== undefined
        ) {
            const previousValidBefore = resolvedKeys.previousValidBefore;
            // fail-closed: without a cutoff time, do not accept the old key (security constraint)
            if (previousValidBefore !== undefined) {
                // issuedAt must be <= previousValidBefore for the old key to be allowed for verification
                if (
                    new Date(token.issuedAt).getTime() <=
                    new Date(previousValidBefore).getTime()
                ) {
                    const previousValid = verify(
                        payloadBytes,
                        token.proof.value,
                        resolvedKeys.previous,
                    );
                    if (previousValid) {
                        return { valid: true };
                    }
                }
                // issuedAt > previousValidBefore → the old key does not accept this token, skip
            }
            // previousValidBefore is undefined → fail-closed, skip the old key
        }
        return {
            valid: false,
            code: 'SIGNATURE_INVALID',
            message: 'Capability token signature verification failed.',
        };
    }

    // Original path (did:key single key)
    const publicKey = extractPublicKeyFromDIDKey(token.issuerDid);
    const isValidSignature = verify(payloadBytes, token.proof.value, publicKey);

    if (!isValidSignature) {
        return {
            valid: false,
            code: 'SIGNATURE_INVALID',
            message: 'Capability token signature verification failed.',
        };
    }

    return { valid: true };
}

export function checkTokenForAction(
    token: CapabilityToken,
    action: string,
    params: Record<string, unknown>,
    agentDid: DID,
): TokenActionCheckResult {
    if (token.issuedTo !== agentDid) {
        return {
            allowed: false,
            code: 'TOKEN_NOT_FOR_THIS_AGENT',
            message: `Capability token was issued to ${token.issuedTo}, not ${agentDid}.`,
        };
    }

    const matches = token.capabilities.filter(
        (capability) => capability.action === action,
    );
    if (matches.length === 0) {
        return {
            allowed: false,
            code: 'INVALID_ACTION',
            message: `Capability token does not authorize action ${action}.`,
        };
    }

    for (const capability of matches) {
        const scope = capability.scope;

        if (scope.type === 'allowlist') {
            const fieldValue = params[scope.field];
            if (
                typeof fieldValue !== 'string' ||
                !scope.values.includes(fieldValue)
            ) {
                return {
                    allowed: false,
                    code: 'SCOPE_EXCEEDED',
                    message: `Field ${scope.field} is outside the allowlist.`,
                };
            }
            continue;
        }

        if (scope.type === 'numeric_limit') {
            const fieldValue = params[scope.field];
            if (fieldValue === undefined) {
                continue;
            }
            if (typeof fieldValue !== 'number' || fieldValue > scope.max) {
                return {
                    allowed: false,
                    code: 'SCOPE_EXCEEDED',
                    message: `Field ${scope.field} exceeds the numeric limit.`,
                };
            }
            continue;
        }

        // Versioned scope types (temporal_scope / cumulative_limit)
        // are evaluated by the RuntimeGuard + ScopeEvaluator;
        // this lightweight verifier does no semantic evaluation and must fail-closed on a new type.
        return {
            allowed: false,
            code: 'SCOPE_TYPE_UNKNOWN',
            message: `Unsupported scope type: ${(scope as { type: string }).type}`,
        };
    }

    return { allowed: true };
}

/**
 * Async version: when the token has a delegationChain, calls validateDelegationChain();
 * a chainless token goes straight through the synchronous verifyCapabilityToken path.
 *
 * Signature extension:
 *   validateDelegationChain() mandates resolveToken for a non-empty chain (fail-closed,
 *   see delegation-validator.ts:120); it also exposes the optional isRevoked / resolveKeyRotationState
 *   ports. As the identity layer's sole "async chained entry", this function must pass these ports through,
 *   otherwise all delegation-chain validation would be rejected at that gate as INVALID_TOKEN_FORMAT.
 *
 * @param token The token to validate
 * @param now Current time (default: Date.now())
 * @param resolvePublicKeys Resolves the dual-key result by DID; returns null for unknown DIDs
 * @param resolveToken Resolves the parent token by tokenId; required for a non-empty chain
 * @param isRevoked Optional: revocation-list lookup; by default does not check revocation
 */
export async function verifyCapabilityTokenWithChain(
    token: CapabilityToken,
    now: Timestamp = new Date().toISOString() as Timestamp,
    resolvePublicKeys: (did: DID) => Promise<ResolvedPublicKeys | null>,
    resolveToken?: (tokenId: string) => Promise<CapabilityToken | null>,
    isRevoked?: (tokenId: string) => Promise<boolean>,
): Promise<TokenVerificationResult> {
    // No delegation chain: take the synchronous path (behavior is exactly identical to verifyCapabilityToken)
    if (!token.delegationChain || token.delegationChain.length === 0) {
        return verifyCapabilityToken(token, now);
    }

    // Has a delegation chain: do basic checks (format, time) first, then validate the chain
    const schemaResult = validateAgainstSchema(token, 'capabilityToken');
    if (!schemaResult.valid) {
        return {
            valid: false,
            code: 'INVALID_TOKEN_FORMAT',
            message: schemaResult.errors
                .map((error) => `${error.instancePath} ${error.message}`.trim())
                .join('; '),
        };
    }

    if (new Date(token.issuedAt).getTime() > new Date(now).getTime()) {
        return {
            valid: false,
            code: 'INVALID_TOKEN_FORMAT',
            message: 'issuedAt cannot be in the future.',
        };
    }

    if (isTimestampExpired(token.expiresAt, now)) {
        return {
            valid: false,
            code: 'TOKEN_EXPIRED',
            message: 'Capability token has expired.',
        };
    }

    // Version gate: the delegation chain is a 0.2.0 feature; a 0.1.0 token with a non-empty chain is a format error
    if (token.specVersion === '0.1.0') {
        return {
            valid: false,
            code: 'INVALID_TOKEN_FORMAT',
            message:
                'delegationChain is not supported in specVersion 0.1.0 tokens.',
        };
    }

    const chainResult = await validateDelegationChain(
        token,
        resolvePublicKeys,
        isRevoked,
        now,
        resolveToken,
    );
    if (!chainResult.valid) {
        // Top-level proof.value verification has been pushed down into the validator, unifying
        // the protection of both the delegated/RuntimeGuard entry points. Here we echo finely based on chainResult.reason
        // — SIGNATURE_INVALID semantics are themselves part of the public contract
        // (TokenVerificationResult.code lists this), so there is no need to have it swallowed by DELEGATION_CHAIN_INVALID;
        // other chain-structure reasons are classified as DELEGATION_CHAIN_INVALID.
        const code: TokenVerificationResult['code'] =
            chainResult.reason === 'SIGNATURE_INVALID'
                ? 'SIGNATURE_INVALID'
                : 'DELEGATION_CHAIN_INVALID';
        return {
            valid: false,
            code,
            message:
                chainResult.reason ?? 'Delegation chain validation failed.',
        };
    }

    // Verify the top-level token.proof (actually signed by the delegation chain's last-hop delegatorDid).
    // validateDelegationChain only verifies the per-hop DelegationProof within the chain,
    // not the token's top-level proof.value.
    // The actual signer is extracted from the DID part of proof.verificationMethod (format: did:...:xxx#key-N).
    const signerDid = (token.proof.verificationMethod.split('#')[0] ??
        '') as DID;
    let topLevelPublicKey: string | null = null;
    let topLevelResolved: ResolvedPublicKeys | null = null;
    if (isDidKey(signerDid)) {
        topLevelPublicKey = extractPublicKeyFromDIDKey(signerDid);
    } else if (isDidAgent(signerDid)) {
        // resolvePublicKeys returns dual keys; the top-level token proof prefers current,
        // and on current-verification failure, if token.issuedAt ≤ previousValidBefore, falls back
        // to previous — symmetric with the chain validator's dual-key semantics (avoiding the case where chain validation passed using previous
        // while the top-level proof is still rejected under a single key).
        topLevelResolved = await resolvePublicKeys(signerDid);
        topLevelPublicKey = topLevelResolved?.current ?? null;
    }
    if (!topLevelPublicKey) {
        return {
            valid: false,
            code: 'SIGNATURE_INVALID',
            message: `Cannot resolve public key for top-level proof signer: ${signerDid}`,
        };
    }
    const payloadBytes = createCapabilityTokenPayload({
        id: token.id,
        specVersion: token.specVersion,
        issuerDid: token.issuerDid,
        principalDid: token.principalDid,
        issuedTo: token.issuedTo,
        issuedAt: token.issuedAt,
        expiresAt: token.expiresAt,
        capabilities: token.capabilities,
        revocationUrl: token.revocationUrl,
        delegationChain: token.delegationChain,
    });
    let topLevelValid = verify(
        payloadBytes,
        token.proof.value,
        topLevelPublicKey,
    );
    if (
        !topLevelValid &&
        topLevelResolved !== null &&
        topLevelResolved.previous !== undefined &&
        topLevelResolved.previousValidBefore !== undefined &&
        new Date(token.issuedAt).getTime() <=
            new Date(topLevelResolved.previousValidBefore).getTime()
    ) {
        topLevelValid = verify(
            payloadBytes,
            token.proof.value,
            topLevelResolved.previous,
        );
    }
    if (!topLevelValid) {
        return {
            valid: false,
            code: 'SIGNATURE_INVALID',
            message:
                'Capability token top-level proof signature verification failed.',
        };
    }

    return { valid: true };
}
