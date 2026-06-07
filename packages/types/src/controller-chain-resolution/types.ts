/**
 * ControllerChainResolution (CCR) v0.1 — L0 type layer
 *
 * Triple defense (csp constraint 2 compliant; FULL):
 *   Layer 1 — brand types (compile-time; `as <X>` casts strictly forbidden; no-brand-cast guard)
 *   Layer 2 — JSON Schema format (runtime schema layer)
 *   Layer 3 — AJV strict mode (runtime schema-engine layer; all 4 flags on)
 *
 * Architecture decisions:
 *   ControllerDid reuses the DID brand (no new brand; consistent with dc v0.3 / RFP v0.1; favoring cross-spec generality)
 *   MAX_CHAIN_DEPTH = 5 (aligned with authorization.ts MAX_DELEGATION_DEPTH = 5)
 *   freshness verification delegated to RFP v0.1 verifyResolverFreshness (RFP linkage)
 *   controllerSwitchImmediate = true (immediate-switch semantics; chain-root changes take effect immediately)
 *   ccrVersion is an independent namespace (does not trigger a specVersion breaking change)
 *
 */

import { ProtocolError } from '../errors.js';
import type { DID, Timestamp, Signature } from '../base.js';
import {
    UuidV4String,
    toUuidV4String,
    CspVersionString,
} from '../canonical-signed-payload/types.js';

// ---------------------------------------------------------------------------
// MAX_CHAIN_DEPTH hard limit
// ---------------------------------------------------------------------------

/**
 * CCR chain depth hard cap.
 *
 * Value is 5, aligned with MAX_DELEGATION_DEPTH = 5 in authorization.ts.
 * Constraint: chain depth > MAX_CHAIN_DEPTH → CCR_CHAIN_DEPTH_EXCEEDED (fail-closed).
 *
 */
export const MAX_CHAIN_DEPTH = 5 as const;

// ---------------------------------------------------------------------------
// CcrVersion brand type
// ---------------------------------------------------------------------------

/**
 * CCR spec version brand type (independent namespace).
 *
 * ccrVersion evolves independently of specVersion; it does not trigger a breaking change.
 * No-brand-cast guard: the only legal path to obtain it is the toCcrVersion() factory function; a direct `as CcrVersion` cast is strictly forbidden.
 */
export type CcrVersion = string & { readonly __brand: 'CcrVersion' };

/**
 * CCR v0.1 version constant — "1.0.0".
 *
 * v0.1 freeze: the only legal CcrVersion value.
 */
export const CCR_VERSION_1_0_0 = '1.0.0' as CcrVersion;

/**
 * toCcrVersion — CcrVersion brand-type factory function.
 *
 * The only legal path to obtain a CcrVersion; validates semver format at runtime.
 * Callers are not allowed to do `s as CcrVersion` directly.
 *
 * @throws CcrError (CCR_VERSION_UNSUPPORTED) if the version is not "1.0.0"
 */
export function toCcrVersion(s: string): CcrVersion {
    if (!/^\d+\.\d+\.\d+$/.test(s)) {
        throw new CcrError('CCR_VERSION_UNSUPPORTED', {
            received: s,
            reason: 'invalid_semver_format',
        });
    }
    if (s !== '1.0.0') {
        throw new CcrError('CCR_VERSION_UNSUPPORTED', {
            received: s,
            supportedVersions: ['1.0.0'],
        });
    }
    return s as CcrVersion;
}

// ---------------------------------------------------------------------------
// ChainNodeId — reuses the UuidV4String brand
// ---------------------------------------------------------------------------

/**
 * ChainNodeId — unique identifier of a controller chain node.
 *
 * Reuses the UuidV4String brand (no new standalone brand; consistent with the csp v0.1 challenge field).
 * No-brand-cast guard: construct via the toChainNodeId() factory; a direct `as ChainNodeId` cast is strictly forbidden.
 */
export type ChainNodeId = UuidV4String;

/**
 * toChainNodeId — ChainNodeId factory function (UuidV4String reuse path).
 *
 * Delegates to toUuidV4String() for UUID v4 format validation.
 * On runtime validation failure, toUuidV4String throws CspError(CSP_CHALLENGE_INVALID) internally.
 */
export function toChainNodeId(s: string): ChainNodeId {
    return toUuidV4String(s);
}

// ---------------------------------------------------------------------------
// FreshnessProofSummary — per-node freshness proof summary
// ---------------------------------------------------------------------------

/**
 * FreshnessProofSummary — the RFP freshness proof summary for each chain node.
 *
 * Runtime in-memory field (populated by RFP linkage in step 4; not written to JSON Schema; not persisted).
 *
 */
export interface FreshnessProofSummary {
    /** RFP freshnessWindow in milliseconds (step-4 RFP return value)*/
    readonly freshnessWindowMs: number;
    /** RFP issuance time (step-4 RFP return value; ISO 8601 UTC)*/
    readonly asOfTime: Timestamp;
    /** whether freshness verification passed (must be true after step 4; otherwise CCR_FRESHNESS_INVALID has already been thrown)*/
    readonly verified: boolean;
}

// ---------------------------------------------------------------------------
// ControllerChainNode interface
// ---------------------------------------------------------------------------

/**
 * ControllerChainNode — a single node in the controller chain.
 *
 * The controllerDid type reuses the DID brand (no new ControllerDid brand).
 * cachedDocument: a runtime in-memory optimization field (cache optimization; populated during step-3 loading).
 *   - step-5 chain-signature verification reuses this field (no re-resolve)
 *   - the step-9 verificationMethod binding check reuses this field
 *
 */
export interface ControllerChainNode {
    /** unique node ID (UUID v4; ChainNodeId = UuidV4String)*/
    readonly nodeId: ChainNodeId;
    /** this node's controller DID (reuses the DID brand)*/
    readonly controllerDid: DID;
    /** parent node's controller DID (null for the root node)*/
    readonly parentControllerDid: DID | null;
    /** the node's DID-document resolution time (ISO 8601 UTC)*/
    readonly resolvedAt: Timestamp;
    /** RFP freshness proof summary (populated in step 4; runtime field)*/
    freshnessProof: FreshnessProofSummary;
    /** DID document version (W3C DID Core versionId; used for chain integrity)*/
    readonly documentVersion: string;
    /** whether this is the chain root node (depth === 0)*/
    readonly isRoot: boolean;
    /** chain depth (root = 0; max = MAX_CHAIN_DEPTH - 1 = 4)*/
    readonly depth: number;
    /**
     * the cached DID document (runtime in-memory field; populated during the step-3 load loop).
     *
     * Cache optimization required:
     *   - step 5 + step 9 must reuse this field (no repeated didResolver.resolve() calls)
     *   - not written to JSON Schema; not persisted to the SQL DDL
     */
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    cachedDocument: Record<string, any> | null;
}

// ---------------------------------------------------------------------------
// ChainBinding — chain-binding three-constraint result
// ---------------------------------------------------------------------------

/**
 * ChainBinding — step-9 three-constraint validation result (with audit trail).
 *
 * Immediate-switch semantics + controllerSwitchImmediate = true;
 *   chain-root changes take effect immediately; there is no grace period.
 *
 * Field name vs semantics:
 *   The `leafBindingValid` field name is carried over from v0.1 (to avoid breaking JSON Schema + e2e tests);
 *   **actual semantics** = chain[0] (the chain-start end; the target's direct parent controller) === targetDid.controller claim;
 *   chain[0] is the root from the chain (linked-list) viewpoint, not the root from the controller-tree viewpoint;
 *   the literal "leaf" naming is historical carryover; the integrator (caller) must reason about integration from the actual JSDoc semantics, not the literal name;
 *   the literal revision is deferred to v0.2 (a field-name change is a breaking change, deferred to v0.2).
 */
export interface ChainBinding {
    /** Constraint 1: root node isRoot === true AND parentControllerDid === null*/
    readonly rootBindingValid: boolean;
    /** Constraint 2: all nodes verificationMethod[0].controller === controllerDid*/
    readonly verificationMethodBindingValid: boolean;
    /**
     * Constraint 3: **actual semantics** = chain[0] (the chain-start end) controllerDid === targetDid.controller document claim.
     *
     * The historical name `leaf` is carried over from v0.1; in the chain data structure, chain[0] is the chain-start end
     * (the root from the linked-list viewpoint; the target's direct parent controller from the controller-tree viewpoint);
     * the v0.1 literal "leaf" is inverted relative to the implemented behavior;
     * the field name is retained (to avoid breaking JSON Schema serialization + e2e tests + downstream callers);
     * integrators reason about integration from the actual semantics in this JSDoc (not the literal field name).
     */
    readonly leafBindingValid: boolean;
}

// ---------------------------------------------------------------------------
// ChainIntegrityProof — chain integrity proof (csp 5-field invariant)
// ---------------------------------------------------------------------------

/**
 * ChainIntegrityProof — verify-time chain-integrity proof primitive.
 *
 * csp 5-field required invariant (FULL coverage; verify-time primitive).
 *   token — chain root DID + depth digest identifier
 *   disclosedClaims — ordered list of depth:controllerDid for all nodes
 *   challenge — verifier-side nonce (replay defense)
 *   audience — verifierDid (audience-hijack defense)
 *   notAfter — chain validity period (MIN(freshnessWindowMs across all nodes) + current time)
 * + cspVersion — csp baseline version ("1.0.0")
 * + ccrVersion — CCR spec version ("1.0.0"; independent namespace)
 *
 */
export interface ChainIntegrityProof {
    // === csp v0.1 5-field invariant (required) ===
    /** chain root DID + depth digest identifier (token, field 1/5)*/
    readonly token: string;
    /** ordered list of depth:controllerDid for all nodes (disclosedClaims, field 2/5)*/
    readonly disclosedClaims: readonly string[];
    /** verifier-side challenge (replay defense; field 3/5)*/
    readonly challenge: string;
    /** verifier DID (audience-hijack defense; field 4/5)*/
    readonly audience: DID;
    /** chain validity period (ISO 8601 UTC; field 5/5)*/
    readonly notAfter: Timestamp;
    // === csp metadata ===
    /** csp baseline version (fixed "1.0.0"; ccrVersion is independent of this)*/
    readonly cspVersion: CspVersionString;
    // === CCR-specific fields ===
    /** chain-integrity signature (Ed25519 hex; signed after JCS canonicalization)*/
    readonly chainSignature: Signature;
    /** the resolver DID that issued the proof*/
    readonly resolverDid: DID;
}

// ---------------------------------------------------------------------------
// ControllerChainResolutionRequest — resolution request input
// ---------------------------------------------------------------------------

/**
 * ControllerChainResolutionRequest — input to CCR resolveControllerChain().
 *
 */
export interface ControllerChainResolutionRequest {
    /** target DID (the leaf DID whose controller chain is to be resolved)*/
    readonly targetDid: DID;
    /** verifier-side challenge (UUID v4; replay defense)*/
    readonly challenge: string;
    /** verifier DID (audience binding)*/
    readonly verifierDid: DID;
    /** max chain-depth override (defaults to MAX_CHAIN_DEPTH = 5)*/
    readonly maxChainDepth?: number;
    /** max freshness-window milliseconds override (default: determined by the RFP return value)*/
    readonly maxFreshnessWindowMs?: number;
}

// ---------------------------------------------------------------------------
// ControllerChainResolution — resolution result output
// ---------------------------------------------------------------------------

/**
 * ControllerChainResolution — output of CCR resolveControllerChain().
 *
 * Returned after all 9 verification steps pass; any step failing throws CcrError (fail-closed).
 *
 */
export interface ControllerChainResolution {
    /** CCR spec version (independent namespace "1.0.0")*/
    readonly ccrVersion: CcrVersion;
    /** chain root node controller DID*/
    readonly rootControllerDid: DID;
    /** the full controller chain (ordered; index 0 = root)*/
    readonly chain: readonly ControllerChainNode[];
    /** actual chain depth (= chain.length)*/
    readonly chainDepth: number;
    /** whole-chain freshness verification result (must be true when all 9 steps pass)*/
    readonly freshnessVerified: boolean;
    /** chain-integrity proof (verify-time csp 5-field invariant)*/
    readonly integrityProof: ChainIntegrityProof;
    /**
     * controller-switch immediate-effect flag (immediate-switch semantics).
     * true = chain-root changes take effect immediately; there is no grace period.
     */
    readonly controllerSwitchImmediate: boolean;
    /** resolution completion time (ISO 8601 UTC)*/
    readonly resolvedAt: Timestamp;
    /** no cycle present (passes both step-3 and step-8 detection)*/
    readonly cycleAbsent: boolean;
    /** chain-binding three-constraint result (step-9 audit trail)*/
    readonly chainBinding: ChainBinding;
}

// ---------------------------------------------------------------------------
// CcrErrorCode union (v0.1 freeze; 12 items; CCR_* prefix isolation)
// ---------------------------------------------------------------------------

/**
 * Complete CCR error-code enum (v0.1 freeze; 12 items).
 *
 * Namespace: CCR_* prefix isolation (does not reuse CSP_* / RFP_* / DELEGATION_* / ATP_* / HCC_*).
 * Exhaustiveness guard: every error code has a corresponding throw path in controller-chain-resolution.ts.
 *
 */
export type CcrErrorCode =
    | 'CCR_CHAIN_DEPTH_EXCEEDED' // chain depth > MAX_CHAIN_DEPTH (step 3 + depth check)
    | 'CCR_CHAIN_BROKEN' // chain structure incomplete (step 1/2: root missing / controller missing)
    | 'CCR_FRESHNESS_INVALID' // any node fails freshness verification OR proof expired (step 4)
    | 'CCR_CONTROLLER_REVOKED' // any controller DID is revoked (early position in step 6)
    | 'CCR_CHAIN_CYCLE' // controller DID cycle (step-3 primary defense + step-8 fallback)
    | 'CCR_CHAIN_BINDING_INVALID' // any of the chain-binding three constraints fails (step 9)
    | 'CCR_CHAIN_SIGNATURE_INVALID' // DID document signature invalid OR integrity-proof signature invalid (step 5)
    | 'CCR_RESOLVER_UNAVAILABLE' // upstream resolver unreachable (step 1; fail-closed; no degradation)
    | 'CCR_VERSION_UNSUPPORTED' // ccrVersion / cspVersion not in the supported list (verifyChainIntegrityProof)
    | 'CCR_CHALLENGE_EXPIRED' // challenge mismatch (replay defense; verifyChainIntegrityProof)
    | 'CCR_AUDIENCE_MISMATCH' // audience DID mismatch (audience-hijack defense; verifyChainIntegrityProof)
    | 'CCR_SCHEMA_INVALID'; // AJV strict-mode schema validation failed

/**
 * assertNeverCcrCode — exhaustiveness-check utility.
 *
 * Ensures at compile time that every CcrErrorCode branch has a corresponding throw path.
 * Called by the default branch of the handleCcrError switch.
 */
export function assertNeverCcrCode(code: never): never {
    throw new Error(`Unhandled CcrErrorCode: ${String(code)}`);
}

// ---------------------------------------------------------------------------
// CcrError class (extends ProtocolError; RFP v0.1 pattern)
// ---------------------------------------------------------------------------

/**
 * CcrError — CCR-specific error class.
 *
 * Extends ProtocolError to support the generic instanceof ProtocolError catch path.
 * The precise error code is accessed via the ccrCode field (distinct from ProtocolError.code).
 *
 * ProtocolError.code uses 'FEDERATED_RESOLUTION_FAILED' as the aggregate code
 * (upper layers can catch and handle uniformly without knowing CCR details; consistent with the RfpError strategy).
 *
 * Must extend ProtocolError rather than Error;
 * this guarantees instanceof ProtocolError detection works correctly in L3/L4/L5 catch paths.
 *
 */
export class CcrError extends ProtocolError {
    public constructor(
        public readonly ccrCode: CcrErrorCode,
        public readonly ccrDetail?: Record<string, unknown>,
    ) {
        super(
            'FEDERATED_RESOLUTION_FAILED',
            `[${ccrCode}] ${ccrDetail ? JSON.stringify(ccrDetail) : ''}`,
        );
        this.ccrCode = ccrCode;
    }
}

// ---------------------------------------------------------------------------
// handleCcrError — exhaustive switch (assertNeverCcrCode call site)
// ---------------------------------------------------------------------------

/**
 * handleCcrError — CCR error-code routing (exhaustive switch; assertNeverCcrCode call site).
 *
 * If a new CcrErrorCode union member is added without a matching switch case, it fails at compile time (physically enforced completeness).
 * Recommended usage: callers branch directly on ccrCode; this function is the union-completeness guard entry point.
 *
 */
export function handleCcrError(code: CcrErrorCode): void {
    switch (code) {
        case 'CCR_CHAIN_DEPTH_EXCEEDED':
            return;
        case 'CCR_CHAIN_BROKEN':
            return;
        case 'CCR_FRESHNESS_INVALID':
            return;
        case 'CCR_CONTROLLER_REVOKED':
            return;
        case 'CCR_CHAIN_CYCLE':
            return;
        case 'CCR_CHAIN_BINDING_INVALID':
            return;
        case 'CCR_CHAIN_SIGNATURE_INVALID':
            return;
        case 'CCR_RESOLVER_UNAVAILABLE':
            return;
        case 'CCR_VERSION_UNSUPPORTED':
            return;
        case 'CCR_CHALLENGE_EXPIRED':
            return;
        case 'CCR_AUDIENCE_MISMATCH':
            return;
        case 'CCR_SCHEMA_INVALID':
            return;
        default:
            // assertNeverCcrCode call site (physically enforces union completeness)
            return assertNeverCcrCode(code);
    }
}
