/**
 * MCP Bridge — holder binding resolver
 *
 * `resolveSenderForMCPCall` 5 steps:
 *   1. binding lookup → null/expired → MCP_BINDING_EXPIRED_OR_MISSING
 *   2. revocation resolver mandatory path:
 *      - try/catch; resolver throw / timeout → mcp_error_binding_revocation_unreachable
 *   3. revocationStatus !== null → mcp_error_binding_revoked
 *   4. did resolver → null → MCP_AGENT_DID_UNRESOLVED
 *   5. all OK → { agentDid, verificationKey }
 *
 * Design point: binding lookup not only checks expiry + DID resolvability, it must also go through the
 * revocation resolver to verify whether the binding is already revoked — otherwise, after revocation, messages
 * would keep being accepted until the binding expires naturally (an enforcement gap).
 * Therefore the interface forces bindingRevocationResolver onto the mandatory path, and fails closed when the resolver is unavailable.
 *
 * Resolver implementation options:
 *   - HTTP GET /v1/mcp/bindings/{mcpClientId}/revocation
 *     → 200 {kind, timestamp, signature} or 404 (not revoked)
 *   - DB query against the mcp_binding_revocations table (self-hosted)
 *   - 5s timeout; timeout → fail-closed mcp_error_binding_revocation_unreachable
 *
 * **Not** implemented:
 *   - the PoP registration flow (MCPClientBinding.proofOfPossession field) — wholly DEFERRED to a later version;
 *     the registration init/challenge step must not be implemented
 *   - principalSignature verification — likewise, the registration flow is DEFERRED (lookup-time PoP / signature
 *     verification is not this interface's responsibility; it is handled by the later envelope verify path)
 *
 * **Implemented**:
 *   - the MCPClientBinding data model (only lookup-time fields, no proofOfPossession;
 *     the PoP framework is DEFERRED but the lookup interface is still normative)
 *   - the HolderBindingRegistry interface
 *   - the RevocationStatus type
 *   - the BindingRevocationResolver interface
 *   - the DidPublicKeyResolver interface
 *   - the resolveSenderForMCPCall function (5 steps)
 *   - the withTimeout helper (5s timeout fail-closed)
 */

import type { DID } from '@coivitas/types';

import {
    MCP_ERROR,
    type MCPClientId,
} from './types.js';

// ─── data model: holder binding (PoP fields removed) ──

/**
 * MCPClientBinding — data model
 *
 * Does **not** include the proofOfPossession field: wholly DEFERRED to a later version; registration-flow PoP **must not be implemented** for now.
 * The data model retains the 4 binding-payload fields + principalSignature (even though the registration flow is DEFERRED,
 * data persistence may still keep the signature field for future use; this module does not verify it).
 *
 * Note: the lookup interface only consumes mcpClientId / agentDid / notAfter; the other fields are transparent to this module.
 */
export interface MCPClientBinding {
    /** MCP client identifier (registry primary key) */
    mcpClientId: MCPClientId;
    /** principal-controlled AP did:agent */
    agentDid: DID;
    /** Unix epoch ms (data-model field; not consumed by lookup) */
    issuedAt: number;
    /** Unix epoch ms (mandatory for lookup; only > now counts as active) */
    notAfter: number;
    /**
     * principal's signature over the binding payload; Base64Url
     *
     * Note: this module's lookup interface does not verify the signature (it is for audit / persistence only);
     * the registration-flow PoP framework is DEFERRED to a later version.
     */
    principalSignature: string;
}

/**
 * HolderBindingRegistry — interface
 *
 * Minimal set (lookup-only):
 *   lookup(mcpClientId) → MCPClientBinding | null
 *
 * Registration-flow PoP / principalSignature verification is DEFERRED to a later version;
 * this interface only exposes lookup (the read side); register/revoke are out of this module's scope.
 *
 * Implementations may use: in-memory Map / PostgreSQL / external HTTP API. Interface fail-closed semantics:
 *   - lookup throws = the caller must propagate; this resolver does not catch (exceptions are treated as infrastructure failures and should crash)
 *   - lookup returns null = the binding does not exist (rejected in step 1)
 */
export interface HolderBindingRegistry {
    /**
     * Look up a binding by mcpClientId.
     *
     * Returning null means there is no binding (handled together with expiry by the caller).
     * Implementations should not perform expiry filtering inside this method — the expiry check is the resolver's job.
     */
    lookup(mcpClientId: MCPClientId): Promise<MCPClientBinding | null>;
}

// ─── data model: revocation status ──────────────────────

/**
 * RevocationStatus — wire shape
 *
 * `{kind: 'tombstone' | 'pending', timestamp, signature}` or null (not revoked).
 * This module does not verify the signature; the signature is only an audit / persistence field (verification is handled upstream).
 */
export interface RevocationStatus {
    /** 'tombstone' = permanently revoked; 'pending' = revocation in progress (likewise fail-closed rejects calls) */
    kind: 'tombstone' | 'pending';
    /** ISO-8601 / RFC3339 timestamp (time the revocation occurred; for audit) */
    timestamp: string;
    /** principal's signature over the revocation payload; Base64Url; this module does not verify it */
    signature: string;
}

/**
 * BindingRevocationResolver — revocation mandatory-path interface
 *
 * Mandatory path: lookup-time must query whether the binding has been revoked.
 *
 * Return values:
 *   - a RevocationStatus object → the binding is revoked (fail-closed reject)
 *   - null → not revoked (continue to the following steps)
 *   - throw / timeout → fail-closed `mcp_error_binding_revocation_unreachable`
 *
 * Implementation options:
 *   - HTTP GET `/v1/mcp/bindings/{mcpClientId}/revocation` with a 200/404 response
 *   - DB query against the `mcp_binding_revocations` table (self-hosted)
 *
 * The 5s timeout is enforced by the withTimeout helper inside resolveSenderForMCPCall;
 * an implementation's resolver may also carry its own internal timeout, but the **outer 5s is enforced**.
 */
export type BindingRevocationResolver = (
    mcpClientId: MCPClientId,
) => Promise<RevocationStatus | null>;

// ─── data model: did public key resolver ───────────────

/**
 * DidPublicKeyResolver — DID public-key resolver interface
 *
 * Conceptually corresponds to `(did: DID) => Promise<DIDDocument>` plus reading
 * `agentDoc.verificationMethod[0].publicKey`.
 *
 * This module simplifies it to returning `{ verificationKey: string } | null` (to avoid pulling in the full
 * DIDDocument field type — the full DIDDocument type is defined by the identity package, but this module only consumes publicKey);
 * an implementation's resolver may consume the DIDDocument internally, but the interface exposed to holder-binding-resolver
 * is the minimal necessary field (key-only).
 *
 * Returning null = the DID is not resolvable → fail-closed MCP_AGENT_DID_UNRESOLVED.
 */
export interface ResolvedAgentKey {
    /** Base64Url-encoded Ed25519 public key (same format used for envelope verification) */
    verificationKey: string;
}

export type DidPublicKeyResolver = (
    did: DID,
) => Promise<ResolvedAgentKey | null>;

// ─── public result types ──────────────────────────────────────────────────────

/**
 * resolveSenderForMCPCall success return
 */
export interface MCPSenderResolution {
    agentDid: DID;
    verificationKey: string;
}

/**
 * resolveSenderForMCPCall error return union
 *
 * 4 error codes:
 *   - MCP_BINDING_EXPIRED_OR_MISSING: binding null or notAfter ≤ now
 *   - mcp_error_binding_revocation_unreachable: resolver throw / timeout
 *   - mcp_error_binding_revoked: revocationStatus !== null
 *   - MCP_AGENT_DID_UNRESOLVED: did resolver returns null
 *
 * Note: these 4 internal_code values are the external contract values; the outer dispatcher converts them to MCP wire codes.
 */
export type MCPSenderResolutionError =
    | { error: 'MCP_BINDING_EXPIRED_OR_MISSING' }
    | { error: 'mcp_error_binding_revocation_unreachable' }
    | { error: 'mcp_error_binding_revoked' }
    | { error: 'MCP_AGENT_DID_UNRESOLVED' };

export type MCPSenderResolutionResult =
    | MCPSenderResolution
    | MCPSenderResolutionError;

// ─── 5s timeout helper (fail-closed) ──────────────────────

/**
 * Default revocation resolver timeout (5s) — a high-stake call limit.
 */
export const DEFAULT_REVOCATION_RESOLVER_TIMEOUT_MS = 5000;

/**
 * withTimeout — enforces that a single promise operation completes in ≤ ms milliseconds, otherwise rejects with 'timeout'.
 *
 * Uses the AbortController + setTimeout pattern.
 *
 * Note: the original promise is not truly aborted (once resolveSenderForMCPCall receives the timeout it has already
 * returned fail-closed; the resolver continuing to run internally does not affect the call result); this function only
 * guarantees the caller is not blocked indefinitely.
 */
export async function withTimeout<T>(
    promiseFactory: (signal: AbortSignal) => Promise<T>,
    ms: number,
): Promise<T> {
    const ctrl = new AbortController();
    let timer: ReturnType<typeof setTimeout> | null = null;
    const timeoutPromise = new Promise<never>((_resolve, reject) => {
        timer = setTimeout(() => {
            ctrl.abort();
            reject(new Error(`timeout after ${ms}ms`));
        }, ms);
    });
    try {
        return await Promise.race([promiseFactory(ctrl.signal), timeoutPromise]);
    } finally {
        if (timer !== null) clearTimeout(timer);
    }
}

// ─── public API: resolveSenderForMCPCall (5 steps) ──────────

/**
 * resolveSenderForMCPCall — full 5-step implementation.
 *
 * Steps:
 *   step 1: binding lookup → null/expired → MCP_BINDING_EXPIRED_OR_MISSING
 *   step 2: bindingRevocationResolver mandatory path + try/catch + fail-closed
 *           → mcp_error_binding_revocation_unreachable on throw/timeout
 *   step 3: revocationStatus !== null → mcp_error_binding_revoked
 *   step 4: didResolver → null → MCP_AGENT_DID_UNRESOLVED
 *   step 5: return { agentDid, verificationKey }
 *
 * fail-closed semantics:
 *   - any intermediate step fails → return error immediately; no partial-acceptance
 *   - revocation resolver unavailable = high-stake call fail-closed
 *
 * Performance:
 *   - revocation resolver 5s timeout
 *   - did resolver has no enforced timeout (the identity package already has a reasonable internal timeout)
 *
 * @param mcpClientId input (from the incoming MCP message)
 * @param bindings binding registry (read-only lookup)
 * @param didResolver DID public-key resolver (injected by the identity package)
 * @param bindingRevocationResolver revocation mandatory path
 * @param revocationTimeoutMs optional timeout override; defaults to 5000ms
 *
 * @returns success = `{ agentDid, verificationKey }`; failure = `{ error: <code> }`
 */
export async function resolveSenderForMCPCall(
    mcpClientId: MCPClientId,
    bindings: HolderBindingRegistry,
    didResolver: DidPublicKeyResolver,
    bindingRevocationResolver: BindingRevocationResolver,
    revocationTimeoutMs: number = DEFAULT_REVOCATION_RESOLVER_TIMEOUT_MS,
): Promise<MCPSenderResolutionResult> {
    // step 1: binding lookup + expired check
    const binding = await bindings.lookup(mcpClientId);
    const nowMs = Date.now();
    if (!binding || nowMs > binding.notAfter) {
        return { error: 'MCP_BINDING_EXPIRED_OR_MISSING' };
    }

    // step 2: mandatory path — bindingRevocationResolver
    // try/catch + 5s timeout fail-closed → mcp_error_binding_revocation_unreachable
    let revocationStatus: RevocationStatus | null;
    try {
        revocationStatus = await withTimeout<RevocationStatus | null>(
            (_signal) => bindingRevocationResolver(mcpClientId),
            revocationTimeoutMs,
        );
    } catch (_err) {
        // resolver throw / timeout / abort all fail closed
        return { error: 'mcp_error_binding_revocation_unreachable' };
    }

    // step 3: revocationStatus !== null → revoked
    if (revocationStatus !== null) {
        // binding is revoked - reject all MCP messages
        return { error: 'mcp_error_binding_revoked' };
    }

    // step 4: did resolver → null → DID not resolvable
    let resolvedKey: ResolvedAgentKey | null;
    try {
        resolvedKey = await didResolver(binding.agentDid);
    } catch (_err) {
        // a did resolver internal exception is folded into unresolved (equivalent to fail-closed)
        return { error: 'MCP_AGENT_DID_UNRESOLVED' };
    }
    if (!resolvedKey) {
        return { error: 'MCP_AGENT_DID_UNRESOLVED' };
    }

    // step 5: success
    return {
        agentDid: binding.agentDid,
        verificationKey: resolvedKey.verificationKey,
    };
}

// ─── type-guard helper (for tests / consumers) ──────────────────────────────

/**
 * Distinguish a success / error return (type guard).
 *
 * Success branch: has the `agentDid` field; error branch: has the `error` field.
 * The error-branch union contains 4 error codes.
 */
export function isResolutionError(
    result: MCPSenderResolutionResult,
): result is MCPSenderResolutionError {
    return 'error' in result;
}

// ─── error → MCPBridgeError (wire error-code mapping) ────────────────

/**
 * resolutionError → MCPBridgeError conversion (for the dispatcher; outer wire-error wrap)
 *
 * Mapping:
 *   MCP_BINDING_EXPIRED_OR_MISSING → BINDING_MISSING ('mcp_error_binding_missing')
 *   mcp_error_binding_revoked → BINDING_REVOKED
 *   mcp_error_binding_revocation_unreachable → BINDING_REVOCATION_UNREACHABLE
 *   MCP_AGENT_DID_UNRESOLVED → AGENT_DID_UNRESOLVED
 *
 * internal_code keeps its original value (for audit).
 */
export function resolutionErrorToMcpError(
    err: MCPSenderResolutionError,
): { mcp_code: string; internal_code: string; message: string } {
    switch (err.error) {
        case 'MCP_BINDING_EXPIRED_OR_MISSING':
            return {
                mcp_code: MCP_ERROR.BINDING_MISSING,
                internal_code: 'MCP_BINDING_EXPIRED_OR_MISSING',
                message: 'binding not found or expired',
            };
        case 'mcp_error_binding_revoked':
            return {
                mcp_code: MCP_ERROR.BINDING_REVOKED,
                internal_code: 'mcp_error_binding_revoked',
                message: 'binding has been revoked',
            };
        case 'mcp_error_binding_revocation_unreachable':
            return {
                mcp_code: MCP_ERROR.BINDING_REVOCATION_UNREACHABLE,
                internal_code: 'mcp_error_binding_revocation_unreachable',
                message:
                    'binding revocation resolver unreachable (5s timeout fail-closed)',
            };
        case 'MCP_AGENT_DID_UNRESOLVED':
            return {
                mcp_code: MCP_ERROR.AGENT_DID_UNRESOLVED,
                internal_code: 'MCP_AGENT_DID_UNRESOLVED',
                message: 'agent DID could not be resolved to a public key',
            };
    }
}
