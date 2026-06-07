// Federated DID resolution types (L2).
// This file is an implementation dependency of packages/identity/src/federation/*.
// persistentWatermark and dnsRebindingGuard are promoted to required (hard requirement, frozen).

import type { DID, Timestamp } from './base.js';
import type { AgentIdentityDocument } from './identity.js';

// ====== Configuration ======

export interface FederatedNode {
    id: string;
    url: string;
    weight?: number;
}

// Federated resolver configuration (hard-requirement version).
// Changes:
// - persistentWatermark promoted from SHOULD to MUST (defends against version-rollback attacks; required for production deployment)
// - dnsRebindingGuard newly added as MUST (defends against DNS rebinding attacks; runtime IP validation)
export interface FederatedResolverConfig {
    nodes: FederatedNode[];
    minResponses: number;
    timeoutMs: number;
    settleWindowMs?: number;
    cacheTtlMs: number;
    maxResponseBytes?: number;
    verifyDIDBinding: DIDBindingVerifier;
    healthCheck?: HealthCheckConfig;
    // MUST: persist the version watermark to defend against version-rollback attacks
    persistentWatermark: WatermarkStore;
    // MUST: runtime defense against DNS rebinding
    dnsRebindingGuard: DnsRebindingGuard;
    // Alert-event subscription hook: tests pass vi.fn() to capture alerts; in production, omitting it falls back to console.warn
    onAlert?: (event: FederationAlertEvent) => void;
}

// Version watermark persistence interface (MUST).
// Contract: setWatermark only writes when version > current value, to prevent concurrency races from rolling the watermark back.
export interface WatermarkStore {
    getWatermark(did: DID): Promise<number | undefined>;
    setWatermark(did: DID, version: number): Promise<void>;
}

// DNS rebinding defense interface (MUST).
// resolveAndValidate resolves hostname to IP and validates that none of the resolved results are private addresses.
// Throws on failure (fail-closed). Dual-stack hosts MUST validate results across all address families.
export interface DnsRebindingGuard {
    resolveAndValidate(hostname: string): Promise<string>;
}

// DID binding verifier (required dependency interface; corresponds to verifyDIDBinding for key rotation).
// - verify must, when v>1, load the full chain via getDocumentHistory and verify it hop by hop
// - both methods are required: a construction-time typeof === 'function' check blocks trivial stubs
export interface DIDBindingVerifier {
    verify(doc: AgentIdentityDocument): Promise<boolean>;
    getDocumentHistory(did: DID): Promise<AgentIdentityDocument[]>;
}

export interface HealthCheckConfig {
    probeIntervalMs: number;
    failureThreshold: number;
    recoveryThreshold: number;
    probePath: string;
}

// ---------------------------------------------------------------------------
// New interface in v0.2: QuorumPolicy
// ---------------------------------------------------------------------------

/**
 * Quorum voting policy (added in v0.2).
 *
 * Voting happens after signature verification passes, during version election.
 * Each validCandidate casts one vote for its document.version.
 *
 * @frozen no (may later extend with BFT policies)
 */
export interface QuorumPolicy {
    /**
     * Quorum threshold.
     *
     * Meaning: a version may be adopted only if it receives >= threshold votes.
     * Default: floor(N/2) + 1 (N = number of validCandidates participating in the vote).
     * Constraint: 1 <= threshold <= nodes.length and threshold > floor(nodes.length / 2).
     */
    threshold?: number;

    /**
     * Tie-breaking policy.
     *
     * When multiple versions all reach threshold:
     *   - 'highest_version': adopt the highest among those that qualify (default)
     *   - 'reject': refuse to adopt, return null + a QUORUM_VOTE_SPLIT alert
     */
    tieBreaker?: 'highest_version' | 'reject';
}

// ---------------------------------------------------------------------------
// New interface in v0.2: DNSRebindingGuard
// ---------------------------------------------------------------------------

/**
 * DNS rebinding runtime defense interface (added in v0.2).
 *
 * Every HTTP request must pass through this guard's validation before being issued:
 *   1. Resolve hostname to IP
 *   2. Verify the IP is not in an internal/reserved range
 *   3. Return the valid IP (the caller must connect using this IP rather than re-resolving)
 *
 * @frozen no (may later extend with allowlist/blocklist policies)
 */
export interface DNSRebindingGuard {
    /**
     * Resolve hostname and validate its legitimacy.
     *
     * @param hostname the hostname to resolve
     * @returns a valid IP address (IPv4 or IPv6)
     * @throws FEDERATION_DNS_REBINDING_BLOCKED when the IP is not valid
     */
    resolveAndValidate(hostname: string): Promise<string>;
}

// Node health state.
export type HealthState = 'HEALTHY' | 'DEGRADED' | 'UNHEALTHY';

// ====== Resolution results ======

export interface ResolutionCandidate {
    nodeId: string;
    document: AgentIdentityDocument;
    receivedAt: Timestamp;
}

export interface VersionConflict {
    did: DID;
    versionsByNode: Record<string, number>;
    conflictType: 'different_versions' | 'same_version_divergent_content';
    chosenVersion: number | null;
    observedAt: Timestamp;
}

// ====== Resolver interface ======

export interface FederatedResolver {
    resolve(did: DID): Promise<AgentIdentityDocument | null>;
    invalidateCache(did: DID): void;
    getMetrics(): FederatedResolverMetrics;
    close(): Promise<void>;
}

// ====== Metrics ======

/**
 * Node-level metrics.
 *
 * Fields added in v0.2: quorumParticipationCount / quorumDissenterCount
 *
 */
export interface NodeMetrics {
    requestTotal: number;
    success: number;
    timeout: number;
    signatureInvalid: number;
    otherFailure: number;
    availability: number;
    healthState: HealthState;

    /**
     * Added in v0.2: number of times this node participated in quorum voting.
     *
     */
    quorumParticipationCount: number;

    /**
     * Added in v0.2: number of times this node was in the minority.
     *
     */
    quorumDissenterCount: number;
}

/**
 * Resolver-level metrics.
 *
 * Fields added in v0.2: quorumVoteSplitCount / dnsRebindingBlockedCount / quorumReachedCount
 *
 */
export interface FederatedResolverMetrics {
    resolveTotal: number;
    resolveSuccess: number;
    resolveNull: number;
    resolveInternalError: number;
    latencyP50Ms: number;
    latencyP95Ms: number;
    latencyP99Ms: number;
    nodes: Record<string, NodeMetrics>;
    versionConflictCount: number;
    signatureInvalidCount: number;
    quorumUnmetCount: number;
    cacheHit: number;
    cacheMiss: number;

    /**
     * Added in v0.2: count of vote splits.
     *
     */
    quorumVoteSplitCount: number;

    /**
     * Added in v0.2: count of DNS rebinding interceptions.
     *
     */
    dnsRebindingBlockedCount: number;

    /**
     * Added in v0.2: number of times quorum was successfully reached.
     *
     */
    quorumReachedCount: number;
}

// ====== Alert events ======

// Alert events are consumed via the logger / metrics backend and are not propagated to the caller through the protocol layer.
export type FederationAlertEvent =
    | {
          kind: 'FEDERATION_SIGNATURE_INVALID';
          nodeId: string;
          did: DID;
          reason:
              | 'binding_proof_invalid'
              | 'malformed_document'
              | 'rotation_proof_malformed';
          observedAt: Timestamp;
      }
    | {
          kind: 'FEDERATION_VERSION_CONFLICT';
          did: DID;
          conflict: VersionConflict;
      }
    | {
          kind: 'FEDERATION_QUORUM_UNMET';
          did: DID;
          respondedNodes: number;
          validCandidates: number;
          required: number;
          observedAt: Timestamp;
      }
    | {
          kind: 'FEDERATION_VERSION_ROLLBACK';
          did: DID;
          incomingVersion: number;
          cachedVersion: number;
          observedAt: Timestamp;
      }
    | {
          kind: 'FEDERATION_NODE_ABUSE';
          nodeId: string;
          reason:
              | 'response_too_large'
              | 'malformed_json'
              | 'invalid_schema'
              | 'url_policy_violation'
              | 'redirect_blocked';
          observedAt: Timestamp;
      }
    | {
          kind: 'FEDERATION_NODE_HEALTH_CHANGED';
          nodeId: string;
          from: HealthState;
          to: HealthState;
          observedAt: Timestamp;
      }
    | {
          kind: 'FEDERATION_EPOCH_MISMATCH';
          did: DID;
          startEpoch: number;
          endEpoch: number;
          observedAt: Timestamp;
      }
    | {
          // alert that a DNS rebinding attack was intercepted
          kind: 'FEDERATION_DNS_REBINDING_BLOCKED';
          nodeId: string;
          hostname: string;
          reason: string;
          observedAt: Timestamp;
      };
