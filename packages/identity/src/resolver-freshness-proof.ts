/**
 * Resolver Freshness Proof (RFP) v0.1 — L2 core implementation
 *
 * Layer responsibilities:
 *   L0 (packages/types/src/rfp.ts) — brand type + JSON Schema + AJV strict mode + RfpError
 *   L2 (this file) — 8-invariant validation + JCS canonicalized signature + Ed25519 verification + factory
 *
 * Strict order of the 8 invariants (fail-fast; expensive last):
 *   I_complete → AJV schema validation (required fields / format)
 *   I_ver → rfpVersion fixed at "1.0.0"
 *   I_csp → cspVersion fixed at "1.0.0"
 *   I_did → resolverDid must start with "did:"
 *   I_fw → freshnessWindow integer [1000, 3600000] (already covered by the L0 schema; second-line defense here)
 *   I_asof → asOfTime does not exceed the current time + 5s tolerance
 *   I_sig → Ed25519 signature verification (JCS 5-field canonicalization)
 *   I_asof_window → the proof has not expired (now - asOfTime <= freshnessWindow)
 *
 * Security constraints (fail-closed):
 *   - Any invariant failure must throw RfpError (fail-open / fail-degraded forbidden)
 *   - JSON.stringify fallback is forbidden (JCS canonicalization is mandatory)
 *   - resolveResolverPublicKey must not internally call verifyResolverFreshness (anti-recursion firewall)
 */

import {
    canonicalize,
    verify,
    sign,
    toBase64Url,
} from '@coivitas/crypto';
import type { DID, Timestamp } from '@coivitas/types';
import {
    validateRfpSchema,
    RfpError,
    toRfpVersionString,
    toCspVersionString,
    toFreshnessWindowMs,
    toSignature,
    assertNeverRfp,
} from '@coivitas/types';
import type {
    ResolverFreshnessProof,
    RfpErrorCode,
} from '@coivitas/types';

// ---------------------------------------------------------------------------
// RFP_HTTP_STATUS mapping
// ---------------------------------------------------------------------------

/**
 * RFP error code → HTTP status code mapping.
 *
 * Design principles:
 *   - structural errors (schema / version / DID / window) → 422 Unprocessable Entity
 *   - signature verification failure → 401 Unauthorized
 *   - freshness failures (expired / unreachable / quorum unmet) → 503 Service Unavailable
 *   - asOfTime exceeding the future tolerance → 422 (high likelihood of malicious data)
 *
 */
export const RFP_HTTP_STATUS: Record<RfpErrorCode, number> = {
    RFP_PROOF_INCOMPLETE: 422,
    RFP_VERSION_UNSUPPORTED: 422,
    RFP_CSP_VERSION_MISMATCH: 422,
    RFP_RESOLVER_DID_INVALID: 422,
    RFP_FRESHNESS_WINDOW_INVALID: 422,
    RFP_FRESHNESS_WINDOW_EXCESSIVE: 422,
    RFP_ASOF_FUTURE: 422,
    RFP_SIGNATURE_INVALID: 401,
    RFP_FRESHNESS_EXPIRED: 503,
    RFP_RESOLVER_UNREACHABLE: 503,
    RFP_QUORUM_FRESHNESS_UNMET: 503,
};

/**
 * getRfpHttpStatus — exhaustive-switch implementation, a real use site for assertNeverRfp
 *
 * Adding an exhaustive switch + a real use of assertNeverRfp → a compile-time failure when a new RfpErrorCode union member lacks an HTTP status
 *
 * Recommended usage: prefer a direct lookup on the RFP_HTTP_STATUS Record; if a new union case does not update the RFP_HTTP_STATUS
 * Record, it is caught by the TS Record<RfpErrorCode, number> type guard (the Record must be exhaustive);
 * this switch provides a supplementary runtime guard + a real use site for assertNeverRfp (physically enforcing that assertNeverRfp is not dead code)
 *
 */
export function getRfpHttpStatus(code: RfpErrorCode): number {
    switch (code) {
        case 'RFP_PROOF_INCOMPLETE':
        case 'RFP_VERSION_UNSUPPORTED':
        case 'RFP_CSP_VERSION_MISMATCH':
        case 'RFP_RESOLVER_DID_INVALID':
        case 'RFP_FRESHNESS_WINDOW_INVALID':
        case 'RFP_FRESHNESS_WINDOW_EXCESSIVE':
        case 'RFP_ASOF_FUTURE':
            return RFP_HTTP_STATUS[code]; // 422 Unprocessable Entity
        case 'RFP_SIGNATURE_INVALID':
            return RFP_HTTP_STATUS[code]; // 401 Unauthorized
        case 'RFP_FRESHNESS_EXPIRED':
        case 'RFP_RESOLVER_UNREACHABLE':
        case 'RFP_QUORUM_FRESHNESS_UNMET':
            return RFP_HTTP_STATUS[code]; // 503 Service Unavailable
        default:
            // assertNeverRfp real use site (physically enforced — a new RfpErrorCode union member without a switch case fails at compile time)
            return assertNeverRfp(code);
    }
}

// ---------------------------------------------------------------------------
// ResolverPublicKeyResolver interface (anti-recursion firewall)
// ---------------------------------------------------------------------------

/**
 * Resolver-node public-key resolution interface.
 *
 * Core constraints (v0.1 hard constraints):
 *   - Implementations must not call verifyResolverFreshness() inside resolvePublicKey
 *   - Violating this forms a circular dependency: verifyResolverFreshness calls resolvePublicKey → calls verifyResolverFreshness again
 *   - Public-key sources are limited to: local trust-anchor config / DID Document resolution (static) / out-of-band pre-provisioning
 *   - Return the raw Uint8Array bytes (Ed25519 32-byte public key)
 *   - If the DID is unknown or cannot be resolved → return null; do not throw (verifyResolverFreshness throws RfpError uniformly)
 *
 */
export interface ResolverPublicKeyResolver {
    /**
     * Resolve the raw Ed25519 public-key bytes (32 bytes) for a resolver DID.
     *
     * Implementation constraints:
     *   - Internal calls to verifyResolverFreshness() are forbidden (anti-recursion firewall)
     *   - Accessing local config / trust anchor / static DID Document reads is allowed
     *   - Depending on the content of the freshnessProof itself is not allowed (it would cause circular verification)
     *
     * @param resolverDid - the resolver DID whose public key is being looked up
     * @returns the raw Ed25519 public-key bytes (32 bytes), or null if unknown
     */
    resolvePublicKey(resolverDid: DID): Promise<Uint8Array | null>;
}

// ---------------------------------------------------------------------------
// JCS canonicalized signing payload type
// ---------------------------------------------------------------------------

/**
 * RFP signing payload — 5 fields (excluding the signature field).
 * After JCS canonicalization (RFC 8785), this serves as the Ed25519 signing input.
 *
 */
interface RfpSignPayload {
    rfpVersion: string;
    cspVersion: string;
    resolverDid: string;
    asOfTime: string;
    freshnessWindow: number;
}

// ---------------------------------------------------------------------------
// verifyResolverFreshness — 8-invariant validation (core primitive)
// ---------------------------------------------------------------------------

/**
 * verifyResolverFreshness — full RFP validation (the 8 invariants in strict order)
 *
 * Input: an untrusted rfp: unknown + a public-key resolver
 * Output: a validated ResolverFreshnessProof (all fields confirmed)
 * throws: RfpError (rfpCode), aborting immediately on any invariant failure (fail-closed)
 *
 * Execution order of the 8 invariants (fail-fast, expensive last):
 *   1. I_complete — AJV schema (field completeness + format)
 *   2. I_ver — rfpVersion === "1.0.0"
 *   3. I_csp — cspVersion === "1.0.0"
 *   4. I_did — resolverDid starts with "did:"
 *   5. I_fw — freshnessWindow integer [1000, 3600000]
 *   6. I_asof — asOfTime does not exceed the current time + 5s tolerance
 *   7. I_sig — Ed25519 signature verification (JCS 5-field canonicalization)
 *   8. I_asof_win — now - asOfTime <= freshnessWindow
 *
 * @param rfp - untrusted input (any unknown value)
 * @param publicKeyResolver - the public-key resolver (anti-recursion firewall interface)
 * @param nowMs - optional: the current time in milliseconds (for test injection; default Date.now())
 * @returns a validated ResolverFreshnessProof
 * @throws RfpError on any invariant failure
 *
 */
export async function verifyResolverFreshness(
    rfp: unknown,
    publicKeyResolver: ResolverPublicKeyResolver,
    nowMs: number = Date.now(),
): Promise<ResolverFreshnessProof> {
    // ─── I_complete: schema validation (required fields / format / AJV strict) ────────────
    // validateRfpSchema failure → throw RfpError('RFP_PROOF_INCOMPLETE')
    const validated = validateRfpSchema(rfp);

    // ─── I_ver: rfpVersion fixed at "1.0.0" ──────────────────────────────────
    if (validated.rfpVersion !== '1.0.0') {
        throw new RfpError(
            'RFP_VERSION_UNSUPPORTED',
            `rfpVersion must be "1.0.0", got: ${validated.rfpVersion}`,
            validated.resolverDid,
        );
    }

    // ─── I_csp: cspVersion fixed at "1.0.0" ──────────────────────────────────
    if (validated.cspVersion !== '1.0.0') {
        throw new RfpError(
            'RFP_CSP_VERSION_MISMATCH',
            `cspVersion must be "1.0.0", got: ${validated.cspVersion}`,
            validated.resolverDid,
        );
    }

    // ─── I_did: resolverDid must start with "did:" ────────────────────────────
    if (!validated.resolverDid.startsWith('did:')) {
        throw new RfpError(
            'RFP_RESOLVER_DID_INVALID',
            `resolverDid must start with "did:", got: ${validated.resolverDid}`,
            validated.resolverDid,
        );
    }

    // ─── I_fw: freshnessWindow integer [1000, 3600000] (second-line defense; already covered by L0) ──
    // The L0 AJV schema already constrains integer + minimum/maximum; this guards against schema-bypass cases.
    const fw = validated.freshnessWindow;
    if (!Number.isInteger(fw) || fw < 1_000 || fw > 3_600_000) {
        const code: RfpErrorCode =
            fw > 3_600_000 ? 'RFP_FRESHNESS_WINDOW_EXCESSIVE' : 'RFP_FRESHNESS_WINDOW_INVALID';
        throw new RfpError(
            code,
            `freshnessWindow must be integer in [1000, 3600000], got: ${fw}`,
            validated.resolverDid,
        );
    }

    // ─── I_asof: asOfTime does not exceed the current time + 5s tolerance ─────────────────────────
    const CLOCK_SKEW_TOLERANCE_MS = 5_000;
    const asOfMs = Date.parse(validated.asOfTime);
    if (isNaN(asOfMs)) {
        throw new RfpError(
            'RFP_PROOF_INCOMPLETE',
            `asOfTime is not a valid ISO 8601 date: ${validated.asOfTime}`,
            validated.resolverDid,
        );
    }
    if (asOfMs > nowMs + CLOCK_SKEW_TOLERANCE_MS) {
        throw new RfpError(
            'RFP_ASOF_FUTURE',
            `asOfTime ${validated.asOfTime} exceeds current time + 5s tolerance (nowMs=${nowMs})`,
            validated.resolverDid,
        );
    }

    // ─── I_sig: Ed25519 signature verification (expensive; placed in the last two positions) ────────────────────
    // 1. Resolve the public key (anti-recursion firewall via the ResolverPublicKeyResolver interface)
    const resolverPublicKey = await publicKeyResolver.resolvePublicKey(validated.resolverDid as DID);
    if (resolverPublicKey === null) {
        throw new RfpError(
            'RFP_RESOLVER_UNREACHABLE',
            `Cannot resolve public key for resolverDid: ${validated.resolverDid}`,
            validated.resolverDid,
        );
    }

    // 2. Construct the JCS signing payload (5 fields; no signature)
    const signPayload: RfpSignPayload = {
        rfpVersion: validated.rfpVersion,
        cspVersion: validated.cspVersion,
        resolverDid: validated.resolverDid,
        asOfTime: validated.asOfTime,
        freshnessWindow: validated.freshnessWindow,
    };

    // 3. JCS canonicalization (RFC 8785; JSON.stringify fallback forbidden)
    const canonicalJson = canonicalize(signPayload as unknown as Record<string, unknown>);
    const messageBytes = new TextEncoder().encode(canonicalJson);

    // 4. Ed25519 verification
    // verify(message: Uint8Array, signature: string, publicKey: string): boolean
    // The publicKey parameter is of type string (base64url); it must be converted from Uint8Array
    const publicKeyB64 = toBase64Url(resolverPublicKey);
    let sigValid: boolean;
    try {
        sigValid = verify(messageBytes, validated.signature, publicKeyB64);
    } catch {
        // An internal throw from verify (an unexpected case) → treated as signature failure
        sigValid = false;
    }

    if (!sigValid) {
        throw new RfpError(
            'RFP_SIGNATURE_INVALID',
            `Ed25519 signature verification failed for resolverDid: ${validated.resolverDid}`,
            validated.resolverDid,
        );
    }

    // ─── I_asof_window: now - asOfTime <= freshnessWindow ────────────────
    // Note: this invariant runs after signature verification (checking freshness is only meaningful once the signature confirms asOfTime was not tampered with)
    const ageMs = nowMs - asOfMs;
    if (ageMs > validated.freshnessWindow) {
        throw new RfpError(
            'RFP_FRESHNESS_EXPIRED',
            `RFP is stale: ageMs=${ageMs} > freshnessWindow=${validated.freshnessWindow} (resolverDid: ${validated.resolverDid})`,
            validated.resolverDid,
        );
    }

    // All 8 invariants passed → return the validated ResolverFreshnessProof
    return validated;
}

// ---------------------------------------------------------------------------
// createResolverFreshnessProof — factory function (resolver-node side)
// ---------------------------------------------------------------------------

/**
 * createResolverFreshnessProof parameters.
 *
 */
export interface CreateRfpParams {
    /** The resolver DID issuing the proof*/
    resolverDid: DID;
    /** The declared validity window (ms; [1000, 3600000]; default 300_000)*/
    freshnessWindowMs?: number;
    /** Issuance time (ISO 8601 UTC; default current time)*/
    asOfTime?: Timestamp;
    /**
     * Signing function (injected; implemented by the caller who holds the private key).
     * Signing input: the JCS-canonicalized UTF-8 bytes (the 5-field payload, no signature).
     * Signing output: a base64url-encoded Ed25519 signature string.
     *
     * Security constraint: the private key must not be passed into this function (inverted dependency; inject the signing behavior rather than key material).
     */
    sign: (message: Uint8Array) => Promise<string>;
}

/**
 * createResolverFreshnessProof — RFP factory function (resolver-node side)
 *
 * Produces a 6-field RFP object, completing JCS canonicalization + Ed25519 signing.
 * The private key never enters this function — it is held by the injected sign function (a clean security boundary).
 *
 * @param params - creation parameters (resolverDid + optional freshnessWindowMs + optional asOfTime + injected sign)
 * @returns a complete ResolverFreshnessProof (6 fields)
 * @throws RfpError('RFP_FRESHNESS_WINDOW_INVALID') if freshnessWindowMs is out of range
 *
 */
export async function createResolverFreshnessProof(
    params: CreateRfpParams,
): Promise<ResolverFreshnessProof> {
    const {
        resolverDid,
        freshnessWindowMs = 300_000,
        asOfTime = new Date().toISOString() as Timestamp,
        sign: signFn,
    } = params;

    // Validate the resolverDid format
    if (!resolverDid.startsWith('did:')) {
        throw new RfpError(
            'RFP_RESOLVER_DID_INVALID',
            `resolverDid must start with "did:", got: ${resolverDid}`,
        );
    }

    // Validate the freshnessWindow range (factory-function precondition check)
    const rfpFreshnessWindow = toFreshnessWindowMs(freshnessWindowMs);

    // Construct the signing payload (5 fields; no signature)
    const signPayload: RfpSignPayload = {
        rfpVersion: '1.0.0',
        cspVersion: '1.0.0',
        resolverDid,
        asOfTime,
        freshnessWindow: rfpFreshnessWindow,
    };

    // JCS canonicalization → UTF-8 bytes (JSON.stringify fallback forbidden)
    const canonicalJson = canonicalize(signPayload as unknown as Record<string, unknown>);
    const messageBytes = new TextEncoder().encode(canonicalJson);

    // Call the injected signing function
    const signatureRaw = await signFn(messageBytes);

    // Validate the signature output format (base64url)
    const signature = toSignature(signatureRaw);

    // Assemble the complete ResolverFreshnessProof (6 fields)
    return {
        rfpVersion: toRfpVersionString('1.0.0'),
        cspVersion: toCspVersionString('1.0.0'),
        resolverDid: resolverDid as DID,
        asOfTime,
        freshnessWindow: rfpFreshnessWindow,
        signature,
    };
}

// ---------------------------------------------------------------------------
// Consumer-side fail-closed enforcement helpers
// ---------------------------------------------------------------------------

/**
 * RFP consumer-side options.
 */
export interface RfpConsumerOptions {
    /**
     * Whether to require the RFP (default false: gradual-rollout phase; true: enforced mode).
     *
     * requireRfp = false: an old resolver (no RFP) emits a WARNING; not rejected.
     * requireRfp = true: no RFP → throw RfpError('RFP_PROOF_INCOMPLETE'); fail-closed.
     */
    requireRfp?: boolean;
    /**
     * The maximum allowed freshnessWindow (ms; default 3_600_000).
     * The consumer can set a stricter ceiling (e.g. 300_000 = 5 minutes).
     */
    maxAllowedFreshnessWindowMs?: number;
}

/**
 * verifyRfpForConsumer — consumer-side RFP fail-closed verification wrapper
 *
 * During federated-resolution quorum, the consumer consumes the RFP provided by resolver nodes.
 * This function wraps the consumer-side enforcement policy (the requireRfp option + maxAllowedFreshnessWindowMs).
 *
 * Behavior:
 *   - rfpPayload = null/undefined + requireRfp = true → throw RFP_PROOF_INCOMPLETE
 *   - rfpPayload = null/undefined + requireRfp = false → return null (the WARNING is already logged in the outer layer)
 *   - rfpPayload present → call verifyResolverFreshness() (fail-closed)
 *   - freshnessWindow > maxAllowedFreshnessWindowMs → throw RFP_FRESHNESS_WINDOW_EXCESSIVE
 *
 * @param rfpPayload - the RFP provided by a resolver node (or null/undefined indicating an old version with no RFP)
 * @param publicKeyResolver - the public-key resolver (same as verifyResolverFreshness)
 * @param options - consumer-side options
 * @param nowMs - the current time (injectable for testing)
 * @returns a validated ResolverFreshnessProof, or null (requireRfp = false + no RFP)
 * @throws RfpError on any verification failure (fail-closed)
 *
 */
export async function verifyRfpForConsumer(
    rfpPayload: unknown,
    publicKeyResolver: ResolverPublicKeyResolver,
    options: RfpConsumerOptions = {},
    nowMs: number = Date.now(),
): Promise<ResolverFreshnessProof | null> {
    const {
        requireRfp = false,
        maxAllowedFreshnessWindowMs = 3_600_000,
    } = options;

    // Handle a missing rfpPayload
    if (rfpPayload === null || rfpPayload === undefined) {
        if (requireRfp) {
            throw new RfpError(
                'RFP_PROOF_INCOMPLETE',
                'RFP is required but not provided by resolver (requireRfp=true)',
            );
        }
        // requireRfp = false → gradual-rollout mode; the caller logs a WARNING
        return null;
    }

    // Full 8-invariant validation
    const verified = await verifyResolverFreshness(rfpPayload, publicKeyResolver, nowMs);

    // Consumer-side extra constraint: maxAllowedFreshnessWindowMs
    if (verified.freshnessWindow > maxAllowedFreshnessWindowMs) {
        throw new RfpError(
            'RFP_FRESHNESS_WINDOW_EXCESSIVE',
            `freshnessWindow ${verified.freshnessWindow}ms exceeds consumer maxAllowed ${maxAllowedFreshnessWindowMs}ms`,
            verified.resolverDid,
        );
    }

    return verified;
}

// ---------------------------------------------------------------------------
// Quorum freshness aggregation decision (multi-node consumer side)
// ---------------------------------------------------------------------------

/**
 * Quorum RFP verification result (single node).
 */
export interface NodeRfpResult {
    nodeId: string;
    resolverDid: DID;
    rfpVerified: ResolverFreshnessProof | null;
    rfpError: RfpError | null;
}

/**
 * verifyQuorumFreshness — multi-node quorum freshnessProof aggregation verification
 *
 * During federated quorum resolution, verify the RFPs of multiple resolver nodes in parallel,
 * and decide whether the quorum freshness threshold is met.
 *
 * Behavior:
 *   - Verify all nodes' RFPs in parallel (fail-isolated per node)
 *   - Count the number of nodes that pass verification, validCount
 *   - validCount >= quorumThreshold → return NodeRfpResult[]
 *   - validCount < quorumThreshold → throw RfpError('RFP_QUORUM_FRESHNESS_UNMET')
 *
 * @param nodes - the list of { nodeId, resolverDid, rfpPayload } per node
 * @param publicKeyResolver - the public-key resolver
 * @param quorumThreshold - the quorum threshold (number of qualifying nodes; must be >= 1)
 * @param options - consumer-side options (passed through to verifyRfpForConsumer)
 * @param nowMs - the current time (injectable for testing)
 * @returns the list of per-node RFP verification results
 * @throws RfpError('RFP_QUORUM_FRESHNESS_UNMET') if quorum is not met
 *
 */
export async function verifyQuorumFreshness(
    nodes: Array<{ nodeId: string; resolverDid: DID; rfpPayload: unknown }>,
    publicKeyResolver: ResolverPublicKeyResolver,
    quorumThreshold: number,
    options: RfpConsumerOptions = {},
    nowMs: number = Date.now(),
): Promise<NodeRfpResult[]> {
    // Verify all nodes in parallel (per-node fail-isolated)
    const results: NodeRfpResult[] = await Promise.all(
        nodes.map(async ({ nodeId, resolverDid, rfpPayload }) => {
            try {
                const rfpVerified = await verifyRfpForConsumer(
                    rfpPayload,
                    publicKeyResolver,
                    options,
                    nowMs,
                );
                return { nodeId, resolverDid, rfpVerified, rfpError: null };
            } catch (err) {
                const rfpError =
                    err instanceof RfpError
                        ? err
                        : new RfpError(
                              'RFP_RESOLVER_UNREACHABLE',
                              `Unexpected error during RFP verification: ${String(err)}`,
                              resolverDid,
                          );
                return { nodeId, resolverDid, rfpVerified: null, rfpError };
            }
        }),
    );

    // Count the number of nodes that passed verification
    const validCount = results.filter((r) => r.rfpVerified !== null).length;

    if (validCount < quorumThreshold) {
        throw new RfpError(
            'RFP_QUORUM_FRESHNESS_UNMET',
            `Quorum freshness unmet: ${validCount} valid RFPs < threshold ${quorumThreshold} (total nodes: ${nodes.length})`,
        );
    }

    return results;
}
