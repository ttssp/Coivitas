import { canonicalize, verify } from '@coivitas/crypto';
import {
    DC_VERSION,
    MAX_DELEGATION_DEPTH,
    type CapabilityToken,
    type DcErrorCode,
    type DelegationChainValidationResult,
    type DelegationProof,
    type DelegationProofSignedPayload,
    type DID,
    type ResolvedPublicKeys,
    type Timestamp,
    validateAgainstSchema,
} from '@coivitas/types';

import {
    createCapabilityTokenPayload,
    validateAttenuation,
} from './token-issuer.js';
import { verifyCapabilityToken } from './token-verifier.js';

/**
 * dc sub-protocol version (the authoritative definition is imported from the single source of truth `@coivitas/types`)
 *
 * The top-level re-export is purely a caller convenience; the authoritative source remains `@coivitas/types`.
 * Inline redefinition of the version number or a partial subset of DcErrorCode within this package is forbidden.
 */
export { DC_VERSION } from '@coivitas/types';
export type { DcErrorCode } from '@coivitas/types';

/**
 * Set of specVersion 0.2.0-only scope types (fail-closed requirement).
 * Tokens with specVersion='0.1.0' must not carry these types.
 */
const PHASE2_SCOPE_TYPES = new Set(['temporal_scope', 'cumulative_limit']);

/**
 * Extract the DID prefix from a verificationMethod (`did:xxx:xxxx#key-n` → `did:xxx:xxxx`).
 * Used in steps 8b/8c of the delegation-chain spec to check "proof signer === delegatorDid".
 */
function parseDidFromVerificationMethod(vm: string): string {
    return vm.split('#')[0] ?? '';
}

/**
 * Validate the delegation chain of a CapabilityToken (delegation-chain spec)
 *
 * @param token The token to validate (must carry a non-empty delegationChain)
 * @param resolvePublicKeys Resolves the dual-key result for a DID; returns null for unknown DIDs.
 *                          Under the ROTATING state, previous + previousValidBefore are available;
 *                          the validator tries current first, and falls back to previous when that
 *                          fails and proof.created ≤ previousValidBefore (key-rotation spec).
 * @param isRevoked Checks whether a tokenId has been revoked (default: nothing revoked)
 * @param now Current timestamp (default: Date.now())
 *
 * Validation logic:
 *  1. Depth check (≤ MAX_DELEGATION_DEPTH)
 *  2. Cycle detection (a delegateeId must not appear twice in the chain)
 *  3. Resolve the dual keys of all delegatorDids in parallel (ResolvedPublicKeys)
 *  4. For each chain node:
 *     4a. Verify the DelegationProof signature (dual-key: current first, then fallback to previous)
 *     4b. Verify attenuation: attenuatedCapabilities ⊆ parentCapabilities
 *     4c. Verify continuity: chain[i].attenuatedCapabilities matches chain[i+1].parentCapabilities
 *     4d. Revocation check: parentTokenId has not been revoked
 *     4e. Expiry check: child token expiresAt ≤ parentExpiresAt
 *  5. Root-node check: token.issuerDid === token.principalDid
 *  6. Leaf consistency: token.capabilities matches the attenuatedCapabilities of the last proof
 */
export async function validateDelegationChain(
    token: CapabilityToken,
    resolvePublicKeys: (did: DID) => Promise<ResolvedPublicKeys | null>,
    isRevoked?: (tokenId: string) => Promise<boolean>,
    now?: Timestamp,
    resolveToken?: (tokenId: string) => Promise<CapabilityToken | null>,
): Promise<DelegationChainValidationResult> {
    const chain = token.delegationChain;

    // No chain or empty chain → no validation needed (specVersion 0.1.0 tokens pass through)
    if (!chain || chain.length === 0) {
        return { valid: true, depth: 0 };
    }

    const depth = chain.length;

    // ── Format and version gates (delegation-chain spec, step 0) ────────
    // The three gates below were previously only run on the non-delegated path in
    // verifyCapabilityToken; the delegated path bypassed them (token-verifier.ts
    // fail-closes directly on a non-empty delegationChain, pushing validation
    // responsibility out to validateDelegationChain). Callers (Orchestrator
    // step3.5, the RuntimeGuard delegated branch) all depend on this function,
    // so it must cover everything in one place — otherwise any caller could accept
    // a token with an invalid format/version (the spec explicitly forbids fail-open).

    // 0a. Schema validation:
    // An attacker-crafted token may have missing fields or wrong types; schema is the first gatekeeper.
    const schemaResult = validateAgainstSchema(token, 'capabilityToken');
    if (!schemaResult.valid) {
        return { valid: false, depth, reason: 'INVALID_TOKEN_FORMAT' };
    }

    // 0b. specVersion + delegationChain consistency:
    // A specVersion='0.1.0' token must not carry a delegationChain (the 0.1.0
    // validator does not recognize the chain field, and an attacker could exploit this
    // mismatch to bypass delegation-chain validation).
    // This function only runs on a non-empty chain — so reject directly if token.specVersion==='0.1.0'.
    if (token.specVersion === '0.1.0') {
        return { valid: false, depth, reason: 'INVALID_TOKEN_FORMAT' };
    }

    // 0c. specVersion 0.2.0-only scope field protection:
    // Even if specVersion claims 0.2.0+, if any scope.type in token.capabilities belongs
    // to the 0.2.0 set while specVersion claims 0.1.0 (already rejected above); conversely a
    // 0.2.0+ token allows any 0.1.0/0.2.0 scope. PHASE2_SCOPE_TYPES is currently only a
    // placeholder for future multi-version extension.
    void PHASE2_SCOPE_TYPES;

    // 0d. A non-empty chain requires resolveToken (fail-closed, delegation-chain spec step 4).
    // Parent-token binding checks (5b/5d/tokenId-lock/root-parent verify/intermediate-parent verify)
    // must rely on resolveToken to authoritatively load the parent token. The public API keeps the
    // ?: optional type signature (the empty-chain case does not inject it and is unaffected),
    // but at runtime a non-empty chain must fail-closed: non-empty chain + resolveToken===undefined →
    // INVALID_TOKEN_FORMAT.
    // The TypeScript signature stays unchanged (?: optional); this is enforced only at runtime — so it
    // does not affect type compatibility for empty-chain callers.
    if (!resolveToken) {
        return { valid: false, depth, reason: 'INVALID_TOKEN_FORMAT' };
    }

    // 0e. A non-empty chain requires isRevoked (fail-closed; cascade-revocation defense).
    // Root cause: the original step 6 of validateDelegationChain only checked revocation inside
    // `if (isRevoked)`; if a non-empty-chain caller omitted isRevoked → cascade revocation was
    // silently bypassed (revoked parent tokens passed silently). The public API keeps the ?: optional
    // type signature (empty chains do not inject it, for compatibility); at runtime a non-empty chain +
    // isRevoked===undefined → fail-closed reject.
    // That is, if optional `isRevoked` is skipped, cascade revocation would be defeated, so it is forced non-undefined here.
    if (!isRevoked) {
        return { valid: false, depth, reason: 'INVALID_TOKEN_FORMAT' };
    }

    // 1. Depth check
    if (depth > MAX_DELEGATION_DEPTH) {
        return { valid: false, depth, reason: 'DEPTH_EXCEEDED' };
    }

    // 2. Cycle detection: a delegateeDid must not appear twice in the chain
    // Each delegatee may appear in the chain only once (prevents A→B→A style cycles)
    const seenDids = new Set<string>();
    // The root delegator must also not appear among the delegatees
    if (chain[0]) {
        seenDids.add(chain[0].delegatorDid);
    }
    for (const proof of chain) {
        if (seenDids.has(proof.delegateeDid)) {
            return { valid: false, depth, reason: 'CYCLE_DETECTED' };
        }
        seenDids.add(proof.delegateeDid);
    }

    // 3. Resolve the dual keys (ResolvedPublicKeys) of all delegatorDids in parallel.
    // Under ROTATING, previous + previousValidBefore are available for signature fallback;
    // the key-rotation cutoff safety invariant is enforced in section 4a.
    const uniqueDids = [...new Set(chain.map((p) => p.delegatorDid))];
    const keyEntries = await Promise.all(
        uniqueDids.map(async (did) => {
            const resolved = await resolvePublicKeys(did);
            return [did, resolved] as [DID, ResolvedPublicKeys | null];
        }),
    );
    const keyMap = new Map<string, ResolvedPublicKeys | null>(keyEntries);

    // Current timestamp (used for parent-token validity checks)
    const nowTs: Timestamp = now ?? (new Date().toISOString() as Timestamp);

    // 4. Validate layer by layer
    for (let i = 0; i < chain.length; i++) {
        const proof = chain[i] as DelegationProof;

        // 4a. Resolve the delegator's dual keys
        const resolvedKeys = keyMap.get(proof.delegatorDid);
        if (resolvedKeys === null || resolvedKeys === undefined) {
            return {
                valid: false,
                depth,
                reason: 'SIGNATURE_INVALID',
                brokenAtIndex: i,
            };
        }

        // 4a. Verify the DelegationProof signature (dual-key: try current first, then fall back to previous)
        // key-rotation: previous only accepts existing artifacts with
        // proof.created ≤ previousValidBefore (fail-closed).

        // The DelegationProofSignedPayload must be canonicalized per RFC 8785 JCS
        // (implemented by canonicalize) before the delegator signs it;
        // if the dcVersion field (optional in v0.3) is present → it must be included in the
        // signed payload bytes, otherwise the v0.3 producer-side sign and verify-side reconstruct
        // disagree → false SIGNATURE_INVALID (breaking backward compatibility / falsely rejecting a valid chain).

        // Compatibility guard:
        // - A v0.1 issuer omits dcVersion → dcVersion not included here → bytes match → signature PASS
        // - A v0.3+ issuer carries dcVersion → conditionally included here → bytes match → signature PASS

        // Strictly forbidden: unconditionally and permanently adding dcVersion — this would make existing
        // v0.1 tokens FAIL signature verification (breaking the v0.1 baseline compatibility promise).
        const signedPayload: DelegationProofSignedPayload = {
            parentTokenId: proof.parentTokenId,
            delegatorDid: proof.delegatorDid,
            delegateeDid: proof.delegateeDid,
            parentCapabilities: proof.parentCapabilities,
            parentExpiresAt: proof.parentExpiresAt,
            attenuatedCapabilities: proof.attenuatedCapabilities,
            ...(proof.dcVersion !== undefined
                ? { dcVersion: proof.dcVersion }
                : {}),
        };
        const payloadBytes = new TextEncoder().encode(
            canonicalize(signedPayload as unknown as Record<string, unknown>),
        );
        let signatureValid = verify(
            payloadBytes,
            proof.proof.value,
            resolvedKeys.current,
        );
        if (
            !signatureValid &&
            resolvedKeys.previous !== undefined &&
            resolvedKeys.previousValidBefore !== undefined &&
            proof.proof.created <= resolvedKeys.previousValidBefore
        ) {
            signatureValid = verify(
                payloadBytes,
                proof.proof.value,
                resolvedKeys.previous,
            );
        }
        if (!signatureValid) {
            return {
                valid: false,
                depth,
                reason: 'SIGNATURE_INVALID',
                brokenAtIndex: i,
            };
        }

        // 4a-bis. Cross-check: compare the snapshot fields in the proof against the authoritative parent token.
        // Implements steps 5b/5d/root-parent-signature of the delegation-chain spec.
        // If only capabilities and expiresAt are compared → an attacker who controls the tokenStore
        // could forge a "parent token" (self-signing arbitrary issuerDid/principalDid/issuedTo) to fool
        // chain validation, breaking the "principal is the authorization root" invariant.
        // resolveToken was already forced non-undefined by the 0d gate at the top of the function
        // (required for a non-empty chain), so no if-guard is needed here.
        const parentToken = await resolveToken(proof.parentTokenId);
        if (parentToken === null) {
            return {
                valid: false,
                depth,
                reason: 'PARENT_TOKEN_NOT_FOUND',
                brokenAtIndex: i,
            };
        }

        // 5b (spec): delegatorDid must === the parent token's
        // issuedTo — the delegator may only sign the proof if it is itself the holder of the parent token.
        if (proof.delegatorDid !== parentToken.issuedTo) {
            return {
                valid: false,
                depth,
                reason: 'DELEGATOR_MISMATCH',
                brokenAtIndex: i,
            };
        }

        // 5d (spec): the parent token must share the same root as the current child token.
        // This guarantees the whole chain shares a single principal — preventing an attacker from
        // splicing chain segments of different principals or impersonating someone else's authorization root.
        if (
            parentToken.issuerDid !== token.issuerDid ||
            parentToken.principalDid !== token.principalDid
        ) {
            return {
                valid: false,
                depth,
                reason: 'ROOT_NOT_PRINCIPAL',
                brokenAtIndex: i,
            };
        }

        // Verify the proof snapshot's capabilities match the real parent token
        if (
            !capabilitiesEqual(
                proof.parentCapabilities,
                parentToken.capabilities,
            )
        ) {
            return {
                valid: false,
                depth,
                reason: 'DELEGATION_CHAIN_INVALID',
                brokenAtIndex: i,
                detail: {
                    rule: 'capabilities_mismatch',
                    at: 'parentCapabilities',
                },
            };
        }
        // Verify the proof snapshot's expiresAt matches the real parent token
        if (proof.parentExpiresAt !== parentToken.expiresAt) {
            return {
                valid: false,
                depth,
                reason: 'DELEGATION_CHAIN_INVALID',
                brokenAtIndex: i,
                detail: {
                    rule: 'capabilities_mismatch',
                    at: 'parentCapabilities',
                },
            };
        }

        // The parent token's self-signature must be verified directly at every hop (delegation-chain spec steps 5e/5f).
        // The spec assumes resolveToken returns an "already-trusted" parent, but in real L5 scenarios
        // the tokenStore is often managed by an untrusted agent itself (both Orchestrator and RuntimeGuard
        // inject the recipient's local tokenStore), so we must perform signature verification directly at each layer.

        // ── Root parent (i === 0) ──────────────────────────────────────────────
        // By spec convention, the root parent token has an empty/undefined delegationChain, issuerDid=
        // principalDid (did:key), and is signed directly by the principal; verifyCapabilityToken
        // can fully validate its legitimacy.

        // ── Intermediate parent (i >= 1) ─────────────────────────────────────────────
        // Attack vector: an attacker forges P1' whose
        // { capabilities, expiresAt, issuerDid, principalDid, issuedTo }
        // all match the real, revoked P1 but uses a new tokenId + garbage proof.value,
        // making resolveToken(proof.parentTokenId) return P1':
        // 1) 5b/5d (issuerDid/principalDid/issuedTo) all align → pass
        // 2) capabilities/expiresAt snapshot → pass
        // 3) isRevoked(proof.parentTokenId=P1') → false (the revoke list only
        // records the real id) → cascade revocation bypassed
        //
        // Countermeasures:
        // - Lock the tokenId: parent.id === proof.parentTokenId, blocking the P1'→P1
        // substitution attack (tokenId is the primary key for revoke registration).
        // - Verify the signature directly: an intermediate parent is itself a delegated token, and its top-level
        // proof.value is signed by the previous-hop delegator (chain[i-1].delegatorDid) over
        // `createCapabilityTokenPayload(parent)`; verify directly with the previous-hop delegator's
        // public key already in keyMap, no longer relying on the parent's own
        // delegationChain (that chain is still used only as a snapshot reference, not recursed).
        // Recursively validating parent.delegationChain would introduce O(n²)
        // work scaled by depth, whereas the integrity of the leaf chain is already
        // guarded by steps 6/7 of this call (continuity and the attenuation rule, capabilitiesEqual) —
        // the consistency of an intermediate parent with its own chain is covered by the
        // "leaf chain explicitly declares every hop" property.
        if (parentToken.id !== proof.parentTokenId) {
            return {
                valid: false,
                depth,
                reason: 'DELEGATION_CHAIN_INVALID',
                brokenAtIndex: i,
                detail: {
                    rule: 'capabilities_mismatch',
                    at: 'parentCapabilities',
                },
            };
        }
        if (i === 0) {
            if (
                parentToken.delegationChain &&
                parentToken.delegationChain.length > 0
            ) {
                // The chain root's parent token must not be a delegated token (otherwise the
                // definition of "root parent" is violated — implying the chain was constructed incorrectly).
                return {
                    valid: false,
                    depth,
                    reason: 'ROOT_NOT_PRINCIPAL',
                    brokenAtIndex: 0,
                };
            }
            const rootVerification = verifyCapabilityToken(parentToken, nowTs);
            if (!rootVerification.valid) {
                return {
                    valid: false,
                    depth,
                    reason: 'SIGNATURE_INVALID',
                    brokenAtIndex: 0,
                };
            }
        } else {
            // The intermediate parent's top-level signature is signed by chain[i-1].delegatorDid; that
            // dual key already entered keyMap during the 3. parallel-resolution phase; if the parent is
            // itself delegated, its top-level proof necessarily corresponds to the "previous-hop delegator"
            // (consistent with the spec).
            const prevProof = chain[i - 1] as DelegationProof;
            const prevResolvedKeys = keyMap.get(prevProof.delegatorDid);
            /* c8 ignore start — keyMap already rejected missing public keys at the loop 4a entry; defensive here. */
            if (!prevResolvedKeys) {
                return {
                    valid: false,
                    depth,
                    reason: 'SIGNATURE_INVALID',
                    brokenAtIndex: i,
                };
            }
            /* c8 ignore stop*/
            const parentPayloadBytes = createCapabilityTokenPayload({
                id: parentToken.id,
                specVersion: parentToken.specVersion,
                issuerDid: parentToken.issuerDid,
                principalDid: parentToken.principalDid,
                issuedTo: parentToken.issuedTo,
                issuedAt: parentToken.issuedAt,
                expiresAt: parentToken.expiresAt,
                capabilities: parentToken.capabilities,
                revocationUrl: parentToken.revocationUrl,
                delegationChain: parentToken.delegationChain,
            });
            // Dual-key verification: try current first, fall back to previous (same cutoff guard as 4a)
            let parentSigValid = verify(
                parentPayloadBytes,
                parentToken.proof.value,
                prevResolvedKeys.current,
            );
            if (
                !parentSigValid &&
                prevResolvedKeys.previous !== undefined &&
                prevResolvedKeys.previousValidBefore !== undefined &&
                parentToken.issuedAt <= prevResolvedKeys.previousValidBefore
            ) {
                parentSigValid = verify(
                    parentPayloadBytes,
                    parentToken.proof.value,
                    prevResolvedKeys.previous,
                );
            }
            if (!parentSigValid) {
                return {
                    valid: false,
                    depth,
                    reason: 'SIGNATURE_INVALID',
                    brokenAtIndex: i,
                };
            }
        }

        // 4b. Attenuation check: attenuatedCapabilities ⊆ parentCapabilities
        // The 3-argument overload must be used to pass both specVersions, otherwise the
        // mixedVersion guard (inside token-issuer.ts) is effectively dead code on the caller side,
        // and the specVersion 0.2.0 scope injection path of a 0.1.0 parent + 0.2.0 child would be silently let through.
        // The parent's specVersion = the previous-hop parent token itself (i===0 → the true root parent;
        // i>=1 → an intermediate parent); the child's specVersion = the current child token (the leaf
        // token.specVersion was already verified as 0.2.0 in 0b).
        const attenResult = validateAttenuation(
            proof.parentCapabilities,
            proof.attenuatedCapabilities,
            {
                parentSpecVersion: parentToken.specVersion,
                childSpecVersion: token.specVersion,
            },
        );
        if (!attenResult.ok) {
            return {
                valid: false,
                depth,
                reason: 'ATTENUATION_VIOLATED',
                brokenAtIndex: i,
                detail: attenResult.detail,
            };
        }

        // 4c. Continuity: chain[i].attenuatedCapabilities must match the chain[i+1].parentCapabilities snapshot
        if (i + 1 < chain.length) {
            const nextProof = chain[i + 1] as DelegationProof;
            if (
                !capabilitiesEqual(
                    proof.attenuatedCapabilities,
                    nextProof.parentCapabilities,
                )
            ) {
                return {
                    valid: false,
                    depth,
                    reason: 'DELEGATION_CHAIN_INVALID',
                    brokenAtIndex: i + 1,
                    detail: {
                        rule: 'capabilities_mismatch',
                        at: 'continuity',
                    },
                };
            }
        }

        // 4d. Revocation check (if isRevoked was provided)
        if (isRevoked) {
            const revoked = await isRevoked(proof.parentTokenId);
            if (revoked) {
                return {
                    valid: false,
                    depth,
                    reason: 'PARENT_TOKEN_REVOKED',
                    brokenAtIndex: i,
                    revokedTokenId: proof.parentTokenId,
                };
            }
        }

        // 4e. Expiry check:
        // - token.expiresAt ≤ parentExpiresAt (cannot exceed the parent token's validity)
        // - parentExpiresAt > nowTs (the parent token has not yet expired)
        if (token.expiresAt > proof.parentExpiresAt) {
            return {
                valid: false,
                depth,
                reason: 'EXPIRY_EXCEEDED',
                brokenAtIndex: i,
            };
        }
        /* c8 ignore start — in real scenarios the first half (token.expiresAt > parentExpiresAt)
           already filters out "parent expired but child claims not expired" at the attenuation stage;
           this branch is a defensive assertion, ensuring rejection even if a caller constructs an
           abnormal "child expiresAt ≤ parent expiresAt ≤ now".
*/
        if (proof.parentExpiresAt <= nowTs) {
            return {
                valid: false,
                depth,
                reason: 'EXPIRY_EXCEEDED',
                brokenAtIndex: i,
            };
        }
        /* c8 ignore stop*/

        // delegatorDid must match the previous layer's delegateeDid (except for the root node)
        if (i > 0) {
            const prevProof = chain[i - 1] as DelegationProof;
            if (proof.delegatorDid !== prevProof.delegateeDid) {
                return {
                    valid: false,
                    depth,
                    reason: 'DELEGATOR_MISMATCH',
                    brokenAtIndex: i,
                };
            }
        }
    }

    // 5. Root-node check: token.issuerDid must equal token.principalDid (the root token is self-signed)
    if (token.issuerDid !== token.principalDid) {
        return { valid: false, depth, reason: 'ROOT_NOT_PRINCIPAL' };
    }

    // 6. Leaf check: the chain's final delegateeDid === token.issuedTo (the agent holding this delegated token)
    // Note: the root chain's delegatorDid is parentToken.issuedTo (i.e. the principal's own did:agent)
    // token.principalDid is did:key (the issuer), the root delegatorDid is did:agent
    // Spec convention: the chain's first proof.delegatorDid === token.issuedTo for the root token
    const lastProof = chain[chain.length - 1] as DelegationProof;
    if (lastProof.delegateeDid !== token.issuedTo) {
        return {
            valid: false,
            depth,
            reason: 'DELEGATOR_MISMATCH',
        };
    }

    // 7. Leaf consistency: token.capabilities must match the last proof's attenuatedCapabilities
    if (
        !capabilitiesEqual(token.capabilities, lastProof.attenuatedCapabilities)
    ) {
        return {
            valid: false,
            depth,
            reason: 'DELEGATION_CHAIN_INVALID',
            detail: {
                rule: 'capabilities_mismatch',
                at: 'leaf',
            },
        };
    }

    // 8. The root delegatorDid must match the holder of the root token
    // chain[0].delegatorDid is the agent that issued the first delegation (i.e. the root token's issuedTo)
    // This did must be the starting point among all delegatorDids
    // Check: the root proof's delegator (chain[0].delegatorDid) must hold the root token (issued by issuerDid/principalDid)
    // This constraint is implicitly guaranteed by signature verification: if public-key resolution is bound to delegatorDid, a valid signature means the identity binding already holds

    // Delegation-chain spec steps 8b/8c: verificationMethod-to-DID binding check.
    // Prevents a rewrap attack — where an attacker changes the leaf token's proof.verificationMethod
    // to point at a DID other than their own to bluff signature verification.

    // 8b: the leaf token's top-level proof vm DID must === the last-hop delegatorDid.
    // (the last-hop delegator signed the entire leaf token payload)
    const signerDid = parseDidFromVerificationMethod(
        token.proof.verificationMethod,
    );
    const lastProofForBinding = chain[chain.length - 1] as DelegationProof;
    if (signerDid !== lastProofForBinding.delegatorDid) {
        return {
            valid: false,
            depth,
            reason: 'SIGNATURE_INVALID',
            brokenAtIndex: chain.length - 1,
        };
    }

    // 8c: each DelegationProof's proof.vm DID must === that proof's delegatorDid.
    // That is: the signer of each hop's proof matches the delegator it declares.
    for (let k = 0; k < chain.length; k++) {
        const chainProof = chain[k] as DelegationProof;
        const proofSignerDid = parseDidFromVerificationMethod(
            chainProof.proof.verificationMethod,
        );
        if (proofSignerDid !== chainProof.delegatorDid) {
            return {
                valid: false,
                depth,
                reason: 'SIGNATURE_INVALID',
                brokenAtIndex: k,
            };
        }
    }

    // Leaf token top-level proof.value signature verification (delegation-chain spec step 9).
    // Before this, validateDelegationChain only verified each hop's inner DelegationProof signature + vm binding,
    // and it must also verify that the token's own proof.value was signed by the last-hop delegator — otherwise
    // a delegated token whose proof.value was tampered with in the recipient's local tokenStore could pass
    // RuntimeGuard authorization. Orchestrator step3.5 did the top-level verification separately; pushing it down
    // here protects both entry points (double guard).

    // Signer: per spec — the last-hop delegator signs the entire leaf token payload.
    // Use the dual-key resolution result; try current first, fall back to previous (same cutoff guard as 4a).
    const lastDelegatorResolved = keyMap.get(lastProofForBinding.delegatorDid);
    /* c8 ignore start — loop 4a already rejected a "keyMap missing delegatorDid"; this is a
       defensive guard; if someone removes the early rejection in 4a in the future, this remains the last
       line of defense for leaf signature verification.
*/
    if (!lastDelegatorResolved) {
        return {
            valid: false,
            depth,
            reason: 'SIGNATURE_INVALID',
            brokenAtIndex: chain.length - 1,
        };
    }
    /* c8 ignore stop*/
    const leafPayloadBytes = createCapabilityTokenPayload({
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
    let leafSigValid = verify(
        leafPayloadBytes,
        token.proof.value,
        lastDelegatorResolved.current,
    );
    if (
        !leafSigValid &&
        lastDelegatorResolved.previous !== undefined &&
        lastDelegatorResolved.previousValidBefore !== undefined &&
        token.issuedAt <= lastDelegatorResolved.previousValidBefore
    ) {
        leafSigValid = verify(
            leafPayloadBytes,
            token.proof.value,
            lastDelegatorResolved.previous,
        );
    }
    if (!leafSigValid) {
        return {
            valid: false,
            depth,
            reason: 'SIGNATURE_INVALID',
            brokenAtIndex: chain.length - 1,
        };
    }

    return { valid: true, depth };
}

/**
 * Compare the deep equality of two Capability arrays (order-independent)
 * Canonicalize first, then compare as JSON
 */
function capabilitiesEqual(
    a: CapabilityToken['capabilities'],
    b: CapabilityToken['capabilities'],
): boolean {
    if (a.length !== b.length) return false;
    // Sort after canonicalize, then compare (order-independent)
    const sortedA = [...a]
        .map((c) => canonicalize(c as unknown as Record<string, unknown>))
        .sort();
    const sortedB = [...b]
        .map((c) => canonicalize(c as unknown as Record<string, unknown>))
        .sort();
    return sortedA.every((v, i) => v === sortedB[i]);
}

// ════════════════════════════════════════════════════════════════════════════
// dc v0.3 fail-closed verification sequence (implementation order aligned with the spec)
// ════════════════════════════════════════════════════════════════════════════

// The spec's 9-step algorithm (fail-closed security semantics):
// Step 1: Depth check (≤ MAX_DELEGATION_DEPTH)
// Step 2: Root-token check (issuerDid === principalDid → ROOT_NOT_PRINCIPAL)
// Step 3: Load all parent tokens (authoritative check via resolveToken)
// Step 4: Parallel DID resolution (IdentityRegistry; ResolvedPublicKeys; Promise.all)
// Step 5: Verify each DelegationProof layer (5a signature / 5b/d binding / 5c JCS / 5d attenuation / 5e time)
// Step 6: Live revocation check (fail-closed; non-cacheable; before step 7/8; isRevoked)
// Step 7: Leaf capabilities consistency (capabilitiesEqual)
// Step 8: Cycle detection (seenDids Set; O(N), actually run early)
// Step 9: Token-Chain binding three constraints (rewrap-attack defense)

// Holding the fail-closed security semantics:
// - The step 6 live revocation check runs immediately after each chain layer's 5a-5e verification,
// i.e. step 6 runs before the layer-level substantive judgments of step 7 (leaf consistency) and
// step 8 (cycle detection). This interleaved per-layer pattern is STRONGER than the
// spec's literal sequential per-stage pattern: if any layer is revoked → abort immediately, no longer
// continuing subsequent-layer verification, minimizing the attack window.
// - Strictly no deferral: moving the revocation check after step 7/8 (explicitly forbidden by the spec) would
// run cycle detection and the leaf-capabilities check in an unrevoked-but-unverified state, violating the fail-closed principle.
// - Implementation note: the current implementation moves step 8 cycle detection to the chain-iteration entry
// — this is a fail-fast optimization (a cycle can obviously be rejected early without traversing every layer),
// and does not weaken the fail-closed semantics. Cycle detection itself does not depend on revocation state.

// ════════════════════════════════════════════════════════════════════════════
// dcVersion handling (v0.3 baseline; independent namespace)
// ════════════════════════════════════════════════════════════════════════════

/**
 * Resolve the dc sub-protocol version of a DelegationProof (dc v0.3)
 *
 * Version-resolution rule:
 *   - When absent, fall back to token.specVersion (v0.1 compatibility path)
 *   - When present, use dcVersion to identify the dc contract version (independent namespace; does not trigger a specVersion upgrade)
 *
 * Note: this function only returns metadata; it makes no semantic judgments. If the dc protocol introduces
 * version-dependent gates in the future (e.g. v0.4+ enforcing new fields), this can be extended on top of it.
 *
 * @since v0.3.0
 */
export function resolveDcVersion(
    proof: DelegationProof,
    token: CapabilityToken,
): string {
    return proof.dcVersion ?? token.specVersion;
}

// ════════════════════════════════════════════════════════════════════════════
// DcErrorCode exhaustive handlers (compile-time exhaustive guard)
// ════════════════════════════════════════════════════════════════════════════

/**
 * Exhaustive-switch fallback (compile-time + runtime double guard)
 *
 * Purpose:
 *   - compile-time: TypeScript's never inference forces callers to handle all DcErrorCode branches.
 *     If a new member is added to the DcErrorCode union and a caller misses it, the TS compiler errors.
 *   - runtime: fail-closed — if an uncovered code appears at runtime (theoretically unreachable),
 *     throw immediately rather than stubbing a default success.
 *
 * No stub default success: this function throws and never returns any "safe default".
 *
 */
export function assertNeverDcError(code: never): never {
    throw new Error(
        `[dc v${DC_VERSION}] Unhandled DcErrorCode in exhaustive switch: ${JSON.stringify(code)}. ` +
            `This indicates a new DcErrorCode was added to L0 SSOT but caller code was not updated. ` +
            `Per the L0 SSOT + L1 import convention, update L2 callers to handle the new code.`,
    );
}

/**
 * Human-readable message mapping for DcErrorCode (exhaustive-guard example + utility function)
 *
 * Usage (callers should import and use handleDcError rather than a custom switch;
 * if customizing, always fall back to assertNeverDcError, otherwise TS will warn at compile time):
 *
 * ```typescript
 * import { handleDcError } from '@coivitas/identity';
 *
 * const result = await validateDelegationChain(token, ...);
 * if (!result.valid && result.reason !== undefined) {
 *     const msg = handleDcError(result.reason);
 *     logger.warn(`Delegation chain rejected: ${msg}`);
 * }
 * ```
 *
 * fail-closed guard:
 *   - the default branch calls assertNeverDcError(code) — TS never inference prevents missed branches
 *   - never return vague strings like 'unknown error' (auth/verification
 *     primitive error codes must be explicitly classified, never silently swallowed)
 *
 * @since v0.3.0
 */
export function handleDcError(code: DcErrorCode): string {
    switch (code) {
        case 'DEPTH_EXCEEDED':
            return `Delegation chain length exceeds MAX_DELEGATION_DEPTH (${MAX_DELEGATION_DEPTH})`;
        case 'ATTENUATION_VIOLATED':
            return 'Child capabilities are not a strict subset of parent capabilities (attenuation rule)';
        case 'DELEGATION_CHAIN_INVALID':
            return 'Delegation chain has structural invariant violation (capability snapshot mismatch / continuity broken / leaf inconsistent)';
        case 'SIGNATURE_INVALID':
            return 'DelegationProof signature or leaf token top-level proof verification failed';
        case 'PARENT_TOKEN_REVOKED':
            return 'Upstream token in chain was revoked; cascade revocation fail-closed';
        case 'PARENT_TOKEN_NOT_FOUND':
            return 'Parent token referenced by parentTokenId could not be resolved';
        case 'PARENT_TOKEN_EXPIRED':
            return 'Parent token expiresAt has passed';
        case 'EXPIRY_EXCEEDED':
            return 'Child token expiresAt exceeds parent token expiresAt';
        case 'DELEGATOR_MISMATCH':
            return 'Delegator DID does not match parent token issuedTo, or chain continuity (delegateeDid → next delegatorDid) broken';
        case 'CYCLE_DETECTED':
            return 'Cycle detected in delegation chain (DID appears twice)';
        case 'ROOT_NOT_PRINCIPAL':
            return 'Root token issuerDid !== principalDid, or chain root is itself a delegated token';
        case 'INVALID_TOKEN_FORMAT':
            return 'Token failed schema validation, or specVersion=0.1.0 token carries delegationChain';
        case 'ROTATION_NOT_SUPPORTED':
            return 'Delegator key in ROTATING state but resolver did not provide ResolvedPublicKeys dual-key structure';
        default:
            return assertNeverDcError(code);
    }
}
