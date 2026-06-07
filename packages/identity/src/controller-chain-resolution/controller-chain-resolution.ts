/**
 * ControllerChainResolution (CCR) v0.1 — L2 core implementation
 *
 * Layer responsibilities:
 *   L0 (type layer) — brand type + 12 error codes + CcrError
 *   L2 (this file) — 9-step verification algorithm + port interfaces + factory
 *
 * 9-step verification algorithm (fail-closed; step 6 revocation runs early):
 *   Step 1 — load the root DID document + existence check
 *   Step 2 — root controller DID existence check
 *   Step 3 — load all controller DID documents in the chain + cycle detection (Set-based; primary defense; embedded in the load loop)
 *   Step 4 — parallel RFP freshness verify (referencing the RFP v0.1 integration)
 *   Step 5 — per-level chain signature verification (reuse cachedDocument; cache optimization)
 *   Step 6 — real-time chain revocation check (fail-closed; before steps 7/8/9)
 *   Step 7 — chain integrity root-end consistency (chain[0].controllerDid === targetDid.controller declaration;
 *            the chain is traversed starting from target.controller; chain[0] is target's direct parent controller;
 *            structurally identical, defense-in-depth)
 *   Step 8 — cycle detection defense-in-depth fallback
 *   Step 9 — chain-binding three constraints (root node + verificationMethod + chainStart bound to target.controller)
 *
 * Security constraints:
 *   - Every step failure must throw CcrError (no fail-open / fail-degraded)
 *   - No JSON.stringify fallback
 *   - step 6 revocation runs before steps 7/8/9 (a late revocation check leaves a window where a revoked controller is still accepted)
 *   - cachedDocument reuse strategy: populated during step 3 load; reused in step 5 + step 9 (no repeated resolve)
 *   - No brand casts such as `as CcrVersion` / `as DID`; must go through factory functions
 *   - Top-level import of canonicalize (no in-function dynamic import)
 *
 */

import AjvModule from 'ajv';
import type { ErrorObject } from 'ajv';
import addFormatsModule from 'ajv-formats';
import { canonicalize, verify, toBase64Url } from '@coivitas/crypto';
import type { DID, Timestamp, Signature } from '@coivitas/types';
import {
    CcrError,
    CCR_VERSION_1_0_0,
    MAX_CHAIN_DEPTH,
    toChainNodeId,
    toCspVersionString,
} from '@coivitas/types';
import type {
    ControllerChainResolution,
    ControllerChainResolutionRequest,
    ControllerChainNode,
    ChainIntegrityProof,
    ChainBinding,
} from '@coivitas/types';

// ---------------------------------------------------------------------------
// AJV strict mode initialization (all 4 flags on; module-level; no in-function initialization)
// ---------------------------------------------------------------------------

/**
 * AJV strict mode instance (4 flags: strict + validateFormats + strictSchema + strictNumbers).
 *
 * Third layer of the triple defense: the runtime schema engine layer.
 * Module-level initialization (no repeated construction inside functions).
 */
// ESM/CJS interop: under ESM, AjvModule's default export is not directly constructable.
// Follow the `as unknown as new(...)` pattern already proven in this project.
type AjvConstructor = new (options?: Record<string, unknown>) => {
    compile: (schema: unknown) => ((data: unknown) => boolean) & {
        errors?: Array<ErrorObject> | null;
    };
};
const AjvClass = AjvModule as unknown as AjvConstructor;
const ajv = new AjvClass({
    strict: true,
    allErrors: true,
    validateFormats: true,
    strictSchema: true,
    strictNumbers: true,
});
type AddFormatsFn = (ajv: unknown) => void;
const addFormats = addFormatsModule as unknown as AddFormatsFn;
addFormats(ajv);

// ---------------------------------------------------------------------------
// Port interface definitions (dependency injection; no hard-coded implementations)
// ---------------------------------------------------------------------------

/**
 * DidDocumentResolver — DID document resolver port interface.
 *
 * Injected into resolveControllerChain; no hard-coded resolver implementation.
 * When unreachable, resolve() returns null (the caller must throw CCR_RESOLVER_UNAVAILABLE).
 *
 */
export interface DidDocumentResolver {
    /**
     * Resolve a DID document.
     *
     * @param did target DID
     * @returns on success, the DID document object; if the resolver is unreachable, null
     */
    resolve(did: DID): Promise<Record<string, unknown> | null>;

    /**
     * Verify a DID document signature (verificationMethod signature validity).
     *
     * @param doc DID document object (including verificationMethod)
     * @returns true if the signature is valid; false if invalid (the caller must throw CCR_CHAIN_SIGNATURE_INVALID)
     */
    verifyDocumentSignature(doc: Record<string, unknown>): Promise<boolean>;
}

/**
 * RfpVerifierPort — RFP freshness proof fetcher port interface.
 *
 * Injected into resolveControllerChain; calls RFP v0.1 verifyResolverFreshness.
 * When unreachable, getResolverFreshnessProof() should throw (the caller's step 4 catch -> CCR_FRESHNESS_INVALID).
 *
 */
export interface RfpVerifierPort {
    /**
     * Fetch and verify the freshness proof for the given resolver DID.
     *
     * @param did controller DID
     * @returns a digest of the verified freshness proof
     */
    getResolverFreshnessProof(did: DID): Promise<{
        freshnessWindowMs: number;
        asOfTime: string;
        verified: boolean;
    }>;
}

/**
 * ControllerRevocationChecker — controller DID revocation-status checker port interface.
 *
 * Injected into resolveControllerChain; step 6 real-time revocation check.
 * fail-closed: any isControllerRevoked() exception -> the caller throws CCR_CONTROLLER_REVOKED.
 *
 */
export interface ControllerRevocationChecker {
    /**
     * Check whether the controller DID has been revoked.
     *
     * @param did controller DID
     * @returns true if revoked; false if not revoked
     */
    isControllerRevoked(did: DID): Promise<boolean>;
}

/**
 * CcrResolverOptions — resolveControllerChain extension options.
 *
 * Used to pass in the resolver DID + signing function (the buildChainIntegrityProof injection path).
 *
 * Producer-side fail-closed crypto enforcement:
 *   Production must provide resolverDid + signFn; if missing -> throw CcrError CCR_CHAIN_SIGNATURE_INVALID
 *   dev/test may explicitly opt in via allowPlaceholderSignature: true to take the placeholder path
 */
export interface CcrResolverOptions {
    /** The resolver DID that issues the integrity proof */
    resolverDid?: DID;
    /**
     * Ed25519 signing function (injects the resolver private-key path; no hard-coded private key).
     * Parameter message: Uint8Array; return value: a base64url-encoded signature string.
     */
    signFn?: (message: Uint8Array) => Promise<string>;
    /**
     * Producer-side fail-closed:
     *   Default false -> when signFn/resolverDid is missing, the producer side throws CcrError CCR_CHAIN_SIGNATURE_INVALID
     *   Explicit opt-in true -> dev/test environments allow the placeholder signature path (acknowledged as fail-closed at verify time)
     *   Production must never opt in true (the consumer-side verifyChainIntegrityProof still verifies fail-closed)
     */
    allowPlaceholderSignature?: boolean;
}

// ---------------------------------------------------------------------------
// resolveControllerChain — CCR main entry point
// ---------------------------------------------------------------------------

/**
 * resolveControllerChain — CCR main entry function.
 *
 * Entry point for the 9-step verification algorithm. After all steps pass, returns ControllerChainResolution;
 * if any step fails, throws CcrError (fail-closed; no fail-open / fail-degraded).
 *
 * @param request CCR resolution request (including challenge + verifierDid)
 * @param didResolver DID document resolver (injected; no hard-coding)
 * @param rfpVerifier RFP freshness verifier (injected; calls RFP v0.1 verifyResolverFreshness)
 * @param revocationChecker revocation checker (injected; fail-closed)
 * @param options optional extensions (the resolverDid + signFn injection path)
 * @returns ControllerChainResolution (returned after all 9 steps pass)
 * @throws CcrError (any step failure; fail-closed)
 *
 */
export async function resolveControllerChain(
    request: ControllerChainResolutionRequest,
    didResolver: DidDocumentResolver,
    rfpVerifier: RfpVerifierPort,
    revocationChecker: ControllerRevocationChecker,
    options?: CcrResolverOptions,
): Promise<ControllerChainResolution> {
    return runChainResolution9Steps(
        request,
        didResolver,
        rfpVerifier,
        revocationChecker,
        options,
    );
}

// ---------------------------------------------------------------------------
// 9-step verification algorithm (fail-closed; step 6 revocation runs early)
// ---------------------------------------------------------------------------

async function runChainResolution9Steps(
    request: ControllerChainResolutionRequest,
    didResolver: DidDocumentResolver,
    rfpVerifier: RfpVerifierPort,
    revocationChecker: ControllerRevocationChecker,
    options?: CcrResolverOptions,
): Promise<ControllerChainResolution> {
    const maxDepth = request.maxChainDepth ?? MAX_CHAIN_DEPTH;

    // === Step 1: load the root DID document + existence check ===
    // resolver unreachable (returns null) -> CCR_RESOLVER_UNAVAILABLE (fail-closed; no degradation)
    const rootDoc = await didResolver.resolve(request.targetDid);
    if (!rootDoc) {
        throw new CcrError('CCR_RESOLVER_UNAVAILABLE', {
            reason: 'root_did_unavailable',
            targetDid: request.targetDid,
        });
    }

    // === Step 2: root controller DID existence check ===
    // DID document missing the controller field -> CCR_CHAIN_BROKEN (chain structure incomplete)
    const rootControllerDid = rootDoc['controller'] as DID | undefined;
    if (!rootControllerDid) {
        throw new CcrError('CCR_CHAIN_BROKEN', {
            reason: 'missing_root_controller',
            targetDid: request.targetDid,
        });
    }

    // === Step 3: load all controller DID documents in the chain ===
    // The cycle check is embedded in the load loop (primary defense; detect while loading)
    // Set-based O(N) detection; an attacker constructing an A->B->A loop fails closed immediately on the first repeat

    // cachedDocument is populated here (cache optimization):
    // - step 5 chain signature verification reuses this field (no repeated resolve())
    // - step 9 verificationMethod binding check reuses this field
    const chainNodes: ControllerChainNode[] = [];
    const seenDidsStep3 = new Set<string>();
    let currentDid: DID | null = rootControllerDid;
    let depth = 0;

    while (currentDid !== null && depth <= maxDepth) {
        // cycle check (primary defense; embedded in the load loop)
        if (seenDidsStep3.has(currentDid)) {
            throw new CcrError('CCR_CHAIN_CYCLE', {
                duplicateDid: currentDid,
                depth,
                reason: 'cycle_detected_in_load_loop',
            });
        }
        seenDidsStep3.add(currentDid);

        const doc = await didResolver.resolve(currentDid);
        if (!doc) {
            throw new CcrError('CCR_RESOLVER_UNAVAILABLE', {
                reason: 'chain_node_did_unavailable',
                controllerDid: currentDid,
                depth,
            });
        }

        const nodeId = toChainNodeId(crypto.randomUUID());
        const resolvedAt = new Date().toISOString() as Timestamp;

        chainNodes.push({
            nodeId,
            controllerDid: currentDid,
            parentControllerDid:
                depth === 0 ? null : chainNodes[depth - 1]!.controllerDid,
            resolvedAt,
            freshnessProof: {
                freshnessWindowMs: 0,
                asOfTime: resolvedAt,
                verified: false,
            },
            documentVersion: (doc['versionId'] as string | undefined) ?? '1',
            isRoot: depth === 0,
            depth,
            cachedDocument: doc,
        });

        const nextController = doc['controller'] as DID | null | undefined;
        currentDid = nextController ?? null;
        depth++;
    }

    // Re-check the actual depth (defense-in-depth; the step 3 cycle check is already the primary defense)
    if (chainNodes.length > maxDepth) {
        throw new CcrError('CCR_CHAIN_DEPTH_EXCEEDED', {
            actual: chainNodes.length,
            max: maxDepth,
        });
    }

    // The chain must have at least one node
    // step 2 already guarantees rootControllerDid !== null; this is defense-in-depth
    /* c8 ignore start — step 2 guarantees rootControllerDid exists; chainNodes.length===0 is unreachable */
    if (chainNodes.length === 0) {
        throw new CcrError('CCR_CHAIN_BROKEN', {
            reason: 'empty_chain',
            targetDid: request.targetDid,
        });
    }
    /* c8 ignore stop*/

    // === Step 4: parallel RFP freshness verify (referencing the RFP v0.1 integration) ===
    // Run RFP freshness verify in parallel for each chain node's controller DID
    // Any node freshness verification failure = CCR_FRESHNESS_INVALID (fail-closed)
    const freshnessResults = await Promise.all(
        chainNodes.map(async (node, idx) => {
            try {
                const rfp = await rfpVerifier.getResolverFreshnessProof(
                    node.controllerDid,
                );
                const maxFw =
                    request.maxFreshnessWindowMs ?? rfp.freshnessWindowMs;

                if (rfp.freshnessWindowMs > maxFw) {
                    return {
                        nodeIdx: idx,
                        verified: false as const,
                        reason: 'freshness_window_exceeded',
                    };
                }

                const nowMs = Date.now();
                const asOfMs = new Date(rfp.asOfTime).getTime();
                if (nowMs - asOfMs > rfp.freshnessWindowMs) {
                    return {
                        nodeIdx: idx,
                        verified: false as const,
                        reason: 'stale',
                    };
                }

                return {
                    nodeIdx: idx,
                    verified: true as const,
                    freshnessWindowMs: rfp.freshnessWindowMs,
                    asOfTime: rfp.asOfTime,
                };
            } catch {
                return {
                    nodeIdx: idx,
                    verified: false as const,
                    reason: 'rfp_unavailable',
                };
            }
        }),
    );

    for (const result of freshnessResults) {
        if (!result.verified) {
            throw new CcrError('CCR_FRESHNESS_INVALID', {
                nodeIdx: result.nodeIdx,
                controllerDid: chainNodes[result.nodeIdx]!.controllerDid,
                reason: result.reason,
            });
        }
        // freshness passed: write back freshnessProof (after step 4 completes)
        const node = chainNodes[result.nodeIdx]!;
        node.freshnessProof = {
            freshnessWindowMs: result.freshnessWindowMs,
            asOfTime: result.asOfTime as Timestamp,
            verified: true,
        };
    }

    // === Step 5: per-level chain signature verification ===
    // Each node's controller DID document must have a valid signature (verificationMethod)
    // Cache optimization: reuse the cachedDocument cached during step 3 load (no repeated resolve())
    for (const node of chainNodes) {
        const doc = node.cachedDocument!;
        const valid = await didResolver.verifyDocumentSignature(doc);
        if (!valid) {
            throw new CcrError('CCR_CHAIN_SIGNATURE_INVALID', {
                reason: 'did_document_signature_invalid',
                controllerDid: node.controllerDid,
                depth: node.depth,
            });
        }
    }

    // === Step 6: real-time chain revocation check (fail-closed; early position) ===
    // Note: step 6 runs before step 7 (chain integrity) and step 8 (cycle detection)
    // The revocation check must come first; a revoked controller must be rejected immediately
    // Consistent with the early-revocation-check pattern
    // Honors the ControllerRevocationChecker interface promise "any isControllerRevoked() exception ->
    // the caller throws CCR_CONTROLLER_REVOKED"; the try/catch keeps that promise solid
    for (const node of chainNodes) {
        let revoked: boolean;
        try {
            revoked = await revocationChecker.isControllerRevoked(
                node.controllerDid,
            );
        } catch (e) {
            throw new CcrError('CCR_CONTROLLER_REVOKED', {
                controllerDid: node.controllerDid,
                depth: node.depth,
                reason: 'revocation_checker_error',
                underlying: e instanceof Error ? e.message : String(e),
            });
        }
        if (revoked) {
            throw new CcrError('CCR_CONTROLLER_REVOKED', {
                controllerDid: node.controllerDid,
                depth: node.depth,
            });
        }
    }

    // === Step 7: chain integrity root-end consistency ===
    // chain[0].controllerDid must equal the controller declared in the targetDid DID document
    // Semantics: the chain is traversed starting from targetDid.controller; chain[0] is targetDid's direct parent controller
    // Attack vector: the chain's first node disagreeing with targetDid's controller declaration -> forged-chain injection
    // Reuse rootDoc (step 1 already loaded the targetDid document; avoid a repeated resolve)
    //
    // The implementation takes the chain[0] (root-end) path, consistent with the structural identity chain[0] = target.controller.
    const targetDocController = rootDoc['controller'] as string | undefined;
    // Because step 3's chain loading starts from rootDoc['controller'],
    // chainNodes[0].controllerDid === targetDocController is structurally identical; defense-in-depth only
    /* c8 ignore start — chainNodes[0].controllerDid === rootDoc['controller'] is structurally identical; this branch is unreachable */
    if (chainNodes[0]!.controllerDid !== targetDocController) {
        throw new CcrError('CCR_CHAIN_BINDING_INVALID', {
            reason: 'chain_root_target_mismatch',
            chainRootControllerDid: chainNodes[0]!.controllerDid,
            targetDocController: targetDocController ?? null,
        });
    }
    /* c8 ignore stop*/

    // === Step 8: cycle detection defense-in-depth fallback ===
    // Guards against the edge case where a node is dynamically appended between step 3 and step 8
    // The step 3 Set-based check is already the primary defense; this is a defense-in-depth secondary line
    const seenDids = new Set<string>();
    for (const node of chainNodes) {
        /* c8 ignore start — step 3 is the primary defense and already rejects cycles; this defense-in-depth branch is unreachable */
        if (seenDids.has(node.controllerDid)) {
            throw new CcrError('CCR_CHAIN_CYCLE', {
                reason: 'cycle_detected_defense_in_depth',
                duplicateDid: node.controllerDid,
                depth: node.depth,
            });
        }
        /* c8 ignore stop*/
        seenDids.add(node.controllerDid);
    }

    // === Step 9: chain-binding three constraints ===
    // Constraint 1: the root node has isRoot === true AND parentControllerDid === null
    const rootBindingValid =
        chainNodes[0]?.isRoot === true &&
        chainNodes[0]?.parentControllerDid === null;

    // Constraint 2: every node has verificationMethod[0].controller === controllerDid
    // Cache optimization: reuse the cachedDocument cached during step 3 load (no repeated resolve())
    let verificationMethodBindingValid = true;
    for (const node of chainNodes) {
        const doc = node.cachedDocument!;
        const vmController = (
            doc['verificationMethod'] as
                | Array<Record<string, unknown>>
                | undefined
        )?.[0]?.['controller'];
        if (vmController !== node.controllerDid) {
            verificationMethodBindingValid = false;
            break;
        }
    }

    // Constraint 3: chain[0].controllerDid === the targetDid controller document declaration (verified in step 7; reconfirmed here)
    // The chain starts from targetDid.controller; chain[0] is targetDid's direct parent controller
    // Note: the `leafBindingValid` field name is a historical name; **its actual semantics** = chain[0] (the chain-start end) bound to target.controller;
    // renaming the field would be a breaking change, so the current name is kept.
    const leafBindingValid =
        chainNodes[0]!.controllerDid ===
        (rootDoc['controller'] as string | undefined);

    if (
        !rootBindingValid ||
        !verificationMethodBindingValid ||
        !leafBindingValid
    ) {
        throw new CcrError('CCR_CHAIN_BINDING_INVALID', {
            rootBindingValid,
            verificationMethodBindingValid,
            leafBindingValid,
        });
    }

    const chainBinding: ChainBinding = {
        rootBindingValid,
        verificationMethodBindingValid,
        leafBindingValid,
    };

    // === All 9 steps passed: build the chain integrity proof ===
    const integrityProof = await buildChainIntegrityProof(
        chainNodes,
        request,
        options,
    );

    const resolution: ControllerChainResolution = {
        ccrVersion: CCR_VERSION_1_0_0,
        rootControllerDid: chainNodes[0]!.controllerDid,
        chain: chainNodes,
        chainDepth: chainNodes.length,
        freshnessVerified: true,
        integrityProof,
        controllerSwitchImmediate: true, // immediate semantics
        resolvedAt: new Date().toISOString() as Timestamp,
        cycleAbsent: true,
        chainBinding,
    };

    return resolution;
}

// ---------------------------------------------------------------------------
// buildChainIntegrityProof — build the verify-time chain integrity proof
// ---------------------------------------------------------------------------

/**
 * buildChainIntegrityProof — build a chain integrity proof.
 *
 * 5-field mandatory invariant + cspVersion metadata.
 * JCS canonicalization: canonicalize (top-level import; no in-function dynamic import).
 * Ed25519 signing: injected via options.signFn (no hard-coded private key).
 *
 * @param chainNodes the list of verified chain nodes
 * @param request the original resolution request (including challenge + verifierDid)
 * @param options optional extensions (the resolverDid + signFn injection path)
 * @returns ChainIntegrityProof (5 fields + cspVersion + chainSignature + resolverDid)
 * @throws CcrError (CCR_CHAIN_SIGNATURE_INVALID) if JCS canonicalization fails
 *
 */
async function buildChainIntegrityProof(
    chainNodes: ControllerChainNode[],
    request: ControllerChainResolutionRequest,
    options?: CcrResolverOptions,
): Promise<ChainIntegrityProof> {
    // disclosedClaims: an ordered list of depth:controllerDid across all nodes
    const disclosedClaims = chainNodes.map(
        (n) => `${n.depth}:${n.controllerDid}`,
    );

    // token: a canonical identifier for the chain root controllerDid + depth digest
    const token = `ccr:${chainNodes[0]!.controllerDid}:depth=${chainNodes.length}`;

    // notAfter: current time + MIN(freshnessWindowMs across all nodes); take the strictest freshness
    const minFreshnessMs = Math.min(
        ...chainNodes.map((n) => n.freshnessProof.freshnessWindowMs),
    );
    const notAfter = new Date(
        Date.now() + minFreshnessMs,
    ).toISOString() as Timestamp;

    // 5-field ordered object (JCS canonicalization input; field order deterministic for RFC 8785)
    const signedPayload = {
        audience: request.verifierDid,
        challenge: request.challenge,
        cspVersion: '1.0.0',
        disclosedClaims,
        notAfter,
        token,
    };

    // JCS canonicalization (RFC 8785; canonicalize top-level import; no JSON.stringify fallback)
    // canonicalize never returns undefined — on failure it throws CryptoError (see packages/crypto/src/canonicalization.ts).
    // Here we catch CryptoError and convert it to CCR_CHAIN_SIGNATURE_INVALID (fail-closed).
    let canonical: string;
    try {
        canonical = canonicalize(
            signedPayload as unknown as Record<string, unknown>,
        );
        /* c8 ignore start -- canonicalize does not throw on a well-formed payload; this is a defensive fallback */
    } catch {
        throw new CcrError('CCR_CHAIN_SIGNATURE_INVALID', {
            reason: 'jcs_canonicalize_failed',
        });
    }
    /* c8 ignore stop*/

    const messageBytes = new TextEncoder().encode(canonical);

    // Ed25519 signing (via the options.signFn injection path; no hard-coded private key)
    //
    // Producer-side fail-closed crypto enforcement:
    // By default the producer side throws CcrError when signFn/resolverDid is missing (fail-closed)
    // dev/test may explicitly opt in via options.allowPlaceholderSignature = true to take the placeholder path
    // Production must never opt in (the consumer-side verifyChainIntegrityProof still verifies fail-closed; but the producer
    // side should not rely on verify always being called — true fail-closed must be enforced on the producer side)
    const allowPlaceholder = options?.allowPlaceholderSignature ?? false;
    if (!options?.signFn && !allowPlaceholder) {
        throw new CcrError('CCR_CHAIN_SIGNATURE_INVALID', {
            reason: 'sign_fn_missing_in_production',
            hint: 'Production must pass options.signFn (the Ed25519 injection path); dev/test must explicitly opt in via options.allowPlaceholderSignature = true',
        });
    }
    if (!options?.resolverDid && !allowPlaceholder) {
        throw new CcrError('CCR_CHAIN_SIGNATURE_INVALID', {
            reason: 'resolver_did_missing_in_production',
            hint: 'Production must pass options.resolverDid; dev/test must explicitly opt in via options.allowPlaceholderSignature = true',
        });
    }

    let chainSignature: Signature;
    const resolverDid: DID =
        options?.resolverDid ?? ('did:placeholder:ccr-resolver' as DID);

    if (options?.signFn) {
        const sigB64 = await options.signFn(messageBytes);
        chainSignature = sigB64 as unknown as Signature;
    } else {
        // dev/test explicit opt-in (allowPlaceholderSignature = true) takes the placeholder path
        // The consumer-side verifyChainIntegrityProof is still fail-closed (a placeholder sig is not a valid Ed25519 -> verify throws)
        chainSignature =
            'PLACEHOLDER_SIGNATURE_NO_SIGN_FN' as unknown as Signature;
    }

    return {
        token,
        disclosedClaims,
        challenge: request.challenge,
        audience: request.verifierDid,
        notAfter,
        // Construct cspVersion via the `toCspVersionString` factory;
        // brand casts like `'1.0.0' as CspVersionString` are strictly forbidden; the factory exit validates against the CSP_SUPPORTED_VERSIONS set
        cspVersion: toCspVersionString('1.0.0'),
        chainSignature,
        resolverDid,
    };
}

// ---------------------------------------------------------------------------
// verifyChainIntegrityProof — consumer-side verification of the chain integrity proof
// ---------------------------------------------------------------------------

/**
 * verifyChainIntegrityProof — consumer-side verification of the chain integrity proof.
 *
 * Must be called after resolveControllerChain returns (a consumer-side responsibility).
 * 4 checks (order: cheap -> expensive):
 *   1. cspVersion fixed at "1.0.0"
 *   2. notAfter validity check (the chain integrity proof has not expired)
 *   3. challenge binding check (replay defense)
 *   4. audience binding check (audience-hijack defense)
 *   5. Ed25519 signature verification (verify after JCS canonicalization)
 *
 * @param proof the chain integrity proof to verify
 * @param resolverPublicKey the resolver's Ed25519 public key (Uint8Array)
 * @param expectedChallenge the challenge generated on the verifier side (anti-replay)
 * @param verifierDid the verifier DID (audience binding)
 * @param nowMs the current time in milliseconds (defaults to Date.now(); for test injection)
 * @throws CcrError (any verification failure; fail-closed)
 *
 */
export async function verifyChainIntegrityProof(
    proof: ChainIntegrityProof,
    resolverPublicKey: Uint8Array,
    expectedChallenge: string,
    verifierDid: DID,
    nowMs?: number,
): Promise<void> {
    await Promise.resolve(); // satisfy @typescript-eslint/require-await; body is sync
    const now = nowMs ?? Date.now();

    // 1. cspVersion check (the csp baseline version must be '1.0.0')
    if (proof.cspVersion !== '1.0.0') {
        throw new CcrError('CCR_VERSION_UNSUPPORTED', {
            received: proof.cspVersion,
            supported: ['1.0.0'],
        });
    }

    // 2. notAfter validity check (the chain integrity proof has not expired)
    const notAfterMs = new Date(proof.notAfter).getTime();
    if (now > notAfterMs) {
        throw new CcrError('CCR_FRESHNESS_INVALID', {
            reason: 'integrity_proof_expired',
            notAfter: proof.notAfter,
            nowMs: now,
        });
    }

    // 3. challenge binding check (replay defense)
    // Use CCR_CHALLENGE_EXPIRED as the error code for a challenge mismatch
    if (proof.challenge !== expectedChallenge) {
        throw new CcrError('CCR_CHALLENGE_EXPIRED', {
            reason: 'challenge_mismatch',
            expected: expectedChallenge,
            received: proof.challenge,
        });
    }

    // 4. audience binding check (audience-hijack defense)
    // Use CCR_AUDIENCE_MISMATCH as the error code for an audience mismatch
    if (proof.audience !== verifierDid) {
        throw new CcrError('CCR_AUDIENCE_MISMATCH', {
            reason: 'audience_mismatch',
            expected: verifierDid,
            received: proof.audience,
        });
    }

    // 5. signature verification (Ed25519 verify after JCS canonicalization)
    const signedPayload = {
        audience: proof.audience,
        challenge: proof.challenge,
        cspVersion: proof.cspVersion,
        disclosedClaims: proof.disclosedClaims,
        notAfter: proof.notAfter,
        token: proof.token,
    };

    // canonicalize never returns undefined — on failure it throws CryptoError (see packages/crypto/src/canonicalization.ts).
    // Here we catch CryptoError and convert it to CCR_CHAIN_SIGNATURE_INVALID (fail-closed).
    let canonical: string;
    try {
        canonical = canonicalize(
            signedPayload as unknown as Record<string, unknown>,
        );
        /* c8 ignore start -- canonicalize does not throw on a well-formed payload; this is a defensive fallback */
    } catch {
        throw new CcrError('CCR_CHAIN_SIGNATURE_INVALID', {
            reason: 'jcs_canonicalize_failed_on_verify',
        });
    }
    /* c8 ignore stop*/

    const msgBytes = new TextEncoder().encode(canonical);

    // verify(message: Uint8Array, signature: string, publicKey: string): boolean
    // The publicKey parameter type is string (base64url); resolverPublicKey Uint8Array -> toBase64Url
    const publicKeyB64 = toBase64Url(resolverPublicKey);
    let sigValid: boolean;
    try {
        sigValid = verify(
            msgBytes,
            proof.chainSignature as string,
            publicKeyB64,
        );
    } catch {
        // verify threw internally (unexpected case) -> treat as a signature failure
        sigValid = false;
    }

    if (!sigValid) {
        throw new CcrError('CCR_CHAIN_SIGNATURE_INVALID', {
            reason: 'ed25519_verify_failed',
            resolverDid: proof.resolverDid,
        });
    }
}

// ---------------------------------------------------------------------------
// AJV schema validation utility (CCR_SCHEMA_INVALID throw path)
// ---------------------------------------------------------------------------

/**
 * validateCcrRequest — AJV strict mode schema validation (CCR_SCHEMA_INVALID throw path).
 *
 * Callers may optionally invoke this outside resolveControllerChain; this function ensures CCR_SCHEMA_INVALID has a real throw path.
 * Provides the ajv instance's 4-flag configuration (strict + validateFormats + strictSchema + strictNumbers).
 *
 * @param data the data to validate
 * @param schema the JSON Schema object
 * @throws CcrError (CCR_SCHEMA_INVALID) if the data does not conform to the schema
 */
export function validateCcrRequest(
    data: unknown,
    schema: Record<string, unknown>,
): void {
    const validate = ajv.compile(schema);
    const valid = validate(data);
    if (!valid) {
        throw new CcrError('CCR_SCHEMA_INVALID', {
            errors: validate.errors?.map((e: ErrorObject) => ({
                path: e.instancePath,
                message: e.message,
            })),
        });
    }
}
