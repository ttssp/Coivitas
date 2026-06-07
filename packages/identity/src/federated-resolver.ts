// Federated DID resolver factory and implementation.
// Constructor + config validation
// TTL cache layer + single-flight + fanOut + queryNode + verifyDocumentSignature
// DNS rebinding MUST (runtime defense) + WatermarkStore MUST (mandatory at construction)
// Race-free DNS rebinding TOCTOU fix via undici pinIp dispatcher (hard precondition)

import type {
    AgentIdentityDocument,
    DID,
    DnsRebindingGuard,
    FederatedNode,
    FederatedResolver,
    FederatedResolverConfig,
    FederatedResolverMetrics,
    FederationAlertEvent,
    HealthCheckConfig,
    HealthState,
    NodeMetrics,
    ResolutionCandidate,
    Timestamp,
} from '@coivitas/types';
import { ProtocolError } from '@coivitas/types';
import { canonicalize, hash } from '@coivitas/crypto';
import {
    Agent as UndiciAgent,
    buildConnector,
    fetch as undiciFetch,
} from 'undici';
import { verifyBindingProof } from './binding.js';
import { createAgentDID } from './did.js';
import {
    MetricsAggregator,
    type MetricsAggregatorOptions,
} from './federated-resolver-metrics.js';

// ============================================================
// Internal types
// ============================================================

interface NodeState {
    node: FederatedNode;
    health: HealthState;
    consecutiveFailures: number;
    consecutiveSuccesses: number;
    // Health-rate sliding window: stores the most recent HEALTH_RATE_WINDOW results (true=success, false=failure)
    recentResults: boolean[];
    metrics: NodeMetrics;
}

interface CacheEntry {
    document: AgentIdentityDocument;
    cachedAt: number; // field required by the spec
    expiresAt: number;
}

const DEFAULT_MAX_RESPONSE_BYTES = 64 * 1024;

// SSRF protection: blocked high-risk service ports
const BLOCKED_PORTS = new Set([
    21, 22, 23, 25, 110, 143, 3306, 5432, 6379, 27017,
]);

// Health-rate sliding-window size (20 probe records)
const HEALTH_RATE_WINDOW = 20;

// Passive health-check default thresholds: only take effect when the caller does not configure healthCheck
const PASSIVE_HEALTH_CFG: HealthCheckConfig = {
    probeIntervalMs: 0,
    probePath: '',
    failureThreshold: 3,
    recoveryThreshold: 2,
};

// ============================================================
// DNS rebinding private-IP detection utility
// Covers IPv4/IPv6 private ranges + loopback + link-local + unique-local
// ============================================================

/**
 * Determine whether an IP string is a private/loopback/link-local address.
 * Covered ranges:
 *   IPv4: 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 0.0.0.0
 *   IPv6: ::1, ::, fc00::/7 (fd prefix), fe80::/10 (fe80-febf)
 */
export function isPrivateIP(ip: string): boolean {
    // Normalize: remove the IPv6 zone id + URL-style IPv6 brackets
    const normalized = ip
        .replace(/^\[/, '')
        .replace(/\]$/, '')
        .replace(/%.*$/, '')
        .toLowerCase();

    // IPv4 range check
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(normalized)) {
        if (normalized.startsWith('127.')) return true; // 127.0.0.0/8 loopback
        if (normalized === '0.0.0.0') return true; // unspecified
        if (normalized.startsWith('10.')) return true; // 10.0.0.0/8 RFC 1918
        if (/^172\.(1[6-9]|2\d|3[01])\./.test(normalized)) return true; // 172.16.0.0/12 RFC 1918
        if (normalized.startsWith('192.168.')) return true; // 192.168.0.0/16 RFC 1918
        if (normalized.startsWith('169.254.')) return true; // 169.254.0.0/16 link-local
        return false;
    }

    // IPv6 range check
    if (
        normalized === '::1' ||
        normalized === '0000:0000:0000:0000:0000:0000:0000:0001'
    )
        return true; // loopback
    if (
        normalized === '::' ||
        normalized === '0000:0000:0000:0000:0000:0000:0000:0000'
    )
        return true; // unspecified
    if (normalized.startsWith('fc') || normalized.startsWith('fd')) return true; // fc00::/7 unique-local
    if (/^fe[89ab][0-9a-f]/.test(normalized)) return true; // fe80::/10 link-local (fe80-febf)

    return false;
}

// ============================================================
// DnsRebindingGuard factory
// ============================================================

/**
 * Create a production-grade DnsRebindingGuard (using Node.js dns.promises).
 * dual-stack safety: resolves both IPv4 (A) and IPv6 (AAAA), rejecting on any private IP (fail-closed).
 * Production deployments should use this function to create the guard and inject it into FederatedResolverConfig.
 */
export function createDefaultDnsRebindingGuard(): DnsRebindingGuard {
    return {
        async resolveAndValidate(hostname: string): Promise<string> {
            // Strip brackets from IPv6 addresses, compatible with URL.hostname's "[::1]" format
            const bareHostname = hostname.replace(/^\[/, '').replace(/\]$/, '');

            // IP literal: validate directly, skipping DNS
            const isIPv4Literal = /^\d{1,3}(\.\d{1,3}){3}$/.test(bareHostname);
            const isIPv6Literal = bareHostname.includes(':');
            if (isIPv4Literal || isIPv6Literal) {
                if (isPrivateIP(bareHostname)) {
                    throw new Error(
                        `DNS rebinding blocked: IP literal ${hostname} is private`,
                    );
                }
                return bareHostname;
            }

            // Domain resolution: fetch both A + AAAA records
            // Dynamically import dns.promises so it can be mocked in tests
            const dns = await import('dns');
            const dnsPromises = dns.promises;
            const allAddresses: string[] = [];

            try {
                const v4 = await dnsPromises.resolve4(bareHostname);
                allAddresses.push(...v4);
            } catch {
                // An IPv4 resolution failure is not fatal; continue trying IPv6
            }

            try {
                const v6 = await dnsPromises.resolve6(bareHostname);
                allAddresses.push(...v6);
            } catch {
                // An IPv6 resolution failure is not fatal
            }

            if (allAddresses.length === 0) {
                throw new Error(
                    `DNS rebinding blocked: cannot resolve ${hostname}`,
                );
            }

            // Security requirement: no resolution result may be a private address (full dual-stack check)
            const privateAddrs = allAddresses.filter(isPrivateIP);
            if (privateAddrs.length > 0) {
                throw new Error(
                    `DNS rebinding blocked: ${hostname} resolves to private IPs: ${privateAddrs.join(', ')}`,
                );
            }

            return allAddresses[0]!;
        },
    };
}

/**
 * Create a null (allow-everything) DnsRebindingGuard.
 * Only for test environments or local development (explicitly marked as unsafe).
 * Production deployments must not use this guard.
 */
export function createNullDnsRebindingGuard(): DnsRebindingGuard {
    return {
        // eslint-disable-next-line @typescript-eslint/require-await
        async resolveAndValidate(hostname: string): Promise<string> {
            // Only strip the IPv6 brackets, return as is, perform no validation
            return hostname.replace(/^\[/, '').replace(/\]$/, '');
        },
    };
}

// ============================================================
// Factory function (external interface)
// ============================================================

export function createFederatedResolver(
    config: FederatedResolverConfig,
    metricsOptions?: MetricsAggregatorOptions,
): FederatedResolver {
    validateConfig(config);
    return new FederatedResolverImpl(config, metricsOptions);
}

// ============================================================
// Config validation
// Conclusion: validate in order — node count → minResponses range → two-node anti-degradation → verifyDIDBinding interface completeness
// → persistentWatermark MUST → dnsRebindingGuard MUST
// ============================================================

function validateConfig(cfg: FederatedResolverConfig): void {
    // Rule 1: the node list must not be empty
    if (!cfg.nodes || cfg.nodes.length < 1) {
        throw new ProtocolError(
            'INTERNAL_ERROR',
            'nodes.length >= 1 is required',
        );
    }

    // Rule 2: minResponses must not exceed the node count
    if (cfg.minResponses < 1 || cfg.minResponses > cfg.nodes.length) {
        throw new ProtocolError(
            'INTERNAL_ERROR',
            `minResponses must be between 1 and nodes.length (${cfg.nodes.length}), got ${cfg.minResponses}`,
        );
    }

    // Rule 3: when nodes=2, minResponses=1 is not caught by rule 2 (1 satisfies >=1 && <=2), so it needs a special case:
    // a two-node 1:1 fork cannot be resolved, so 2/2 must be required to detect content consistency (avoiding split-brain)
    if (cfg.nodes.length === 2 && cfg.minResponses !== 2) {
        throw new ProtocolError(
            'INTERNAL_ERROR',
            'When nodes.length === 2, minResponses must be 2 to prevent 1:1 fork degradation',
        );
    }

    // Rule 4: verifyDIDBinding must provide a complete interface (preventing a trivial stub)
    if (
        !cfg.verifyDIDBinding ||
        typeof cfg.verifyDIDBinding.verify !== 'function' ||
        typeof cfg.verifyDIDBinding.getDocumentHistory !== 'function'
    ) {
        throw new ProtocolError(
            'INTERNAL_ERROR',
            'verifyDIDBinding must provide verify and getDocumentHistory functions',
        );
    }

    // Rule 5: when the healthCheck field is present, each threshold must be a positive integer
    if (cfg.healthCheck) {
        const hc = cfg.healthCheck;
        if (!Number.isInteger(hc.probeIntervalMs) || hc.probeIntervalMs < 1) {
            throw new ProtocolError(
                'INTERNAL_ERROR',
                'invalid_federated_resolver_config: healthCheck.probeIntervalMs must be a positive integer',
            );
        }
        if (!Number.isInteger(hc.failureThreshold) || hc.failureThreshold < 1) {
            throw new ProtocolError(
                'INTERNAL_ERROR',
                'invalid_federated_resolver_config: healthCheck.failureThreshold must be a positive integer',
            );
        }
        if (
            !Number.isInteger(hc.recoveryThreshold) ||
            hc.recoveryThreshold < 1
        ) {
            throw new ProtocolError(
                'INTERNAL_ERROR',
                'invalid_federated_resolver_config: healthCheck.recoveryThreshold must be a positive integer',
            );
        }
    }

    // Rule 6: persistentWatermark is a hard requirement
    if (
        !cfg.persistentWatermark ||
        typeof cfg.persistentWatermark.getWatermark !== 'function' ||
        typeof cfg.persistentWatermark.setWatermark !== 'function'
    ) {
        throw new ProtocolError(
            'INTERNAL_ERROR',
            'persistentWatermark is required: must provide getWatermark and setWatermark functions',
        );
    }

    // Rule 7: dnsRebindingGuard is a hard requirement
    if (
        !cfg.dnsRebindingGuard ||
        typeof cfg.dnsRebindingGuard.resolveAndValidate !== 'function'
    ) {
        throw new ProtocolError(
            'INTERNAL_ERROR',
            'dnsRebindingGuard is required: must provide resolveAndValidate function',
        );
    }
}

// ============================================================
// Implementation class
// ============================================================

// Default alert handler: falls back to console.warn when there is no onAlert in production
function defaultAlertHandler(event: FederationAlertEvent): void {
    console.warn('[FederatedResolver]', JSON.stringify(event));
}

class FederatedResolverImpl implements FederatedResolver {
    private readonly cfg: FederatedResolverConfig & {
        maxResponseBytes: number;
    };
    private readonly nodeStates: Map<string, NodeState>;
    private readonly cache: Map<string, CacheEntry> = new Map();
    private readonly cacheEpoch: Map<string, number> = new Map();
    private readonly inflight: Map<
        string,
        Promise<AgentIdentityDocument | null>
    > = new Map();
    private readonly metricsAgg: MetricsAggregator;
    private readonly onAlert: (event: FederationAlertEvent) => void;
    private healthProbeTimer?: ReturnType<typeof setInterval>;

    private counters = {
        resolveTotal: 0,
        resolveSuccess: 0,
        resolveNull: 0,
        resolveInternalError: 0,
        versionConflictCount: 0,
        signatureInvalidCount: 0,
        quorumUnmetCount: 0,
        cacheHit: 0,
        cacheMiss: 0,
        // added counters (the instrumentation logic is spread across the
        // resolveInternal/quorum paths; to be filled in after the interplay is wired up)
        quorumVoteSplitCount: 0,
        dnsRebindingBlockedCount: 0,
        quorumReachedCount: 0,
    };

    constructor(
        config: FederatedResolverConfig,
        metricsOptions?: MetricsAggregatorOptions,
    ) {
        this.cfg = {
            maxResponseBytes: DEFAULT_MAX_RESPONSE_BYTES,
            ...config,
        };
        // Prefer the caller-injected onAlert; fall back to console.warn when not provided
        this.onAlert = config.onAlert ?? defaultAlertHandler;
        // Metrics aggregator: t-digest percentiles + OTel exporter (automatically noop when the endpoint is missing)
        this.metricsAgg = new MetricsAggregator(metricsOptions);

        // Initialize node state: all nodes start as HEALTHY
        this.nodeStates = new Map(
            config.nodes.map((n) => [
                n.id,
                {
                    node: n,
                    health: 'HEALTHY' as HealthState,
                    consecutiveFailures: 0,
                    consecutiveSuccesses: 0,
                    recentResults: [],
                    metrics: {
                        requestTotal: 0,
                        success: 0,
                        timeout: 0,
                        signatureInvalid: 0,
                        otherFailure: 0,
                        availability: 1,
                        healthState: 'HEALTHY' as HealthState,
                        // added fields;
                        // to be filled in after the selectByQuorum path is instrumented
                        quorumParticipationCount: 0,
                        quorumDissenterCount: 0,
                    },
                },
            ]),
        );

        // Seed OTel availability snapshot: an idle resolver should also be visible as 1.0 on the OTel
        // dashboard (healthy by default), rather than only appearing after the first resolve
        for (const [id, state] of this.nodeStates) {
            this.metricsAgg.setNodeAvailability(id, state.metrics.availability);
        }

        // A single-node configuration has no fault tolerance, so emit a warning
        if (config.nodes.length === 1) {
            console.warn(
                '[FederatedResolver] Single-node configuration: no fault tolerance',
            );
        }

        if (config.healthCheck) {
            this.startHealthProbe(config.healthCheck);
        }
    }

    // ============================================================
    // Public interface
    // ============================================================

    async resolve(did: DID): Promise<AgentIdentityDocument | null> {
        this.counters.resolveTotal++;
        const startMs = Date.now();

        try {
            // Step 0: cache-hit check
            const cached = this.getCached(did);
            if (cached) {
                this.counters.cacheHit++;
                this.metricsAgg.recordCacheHit();
                return cached;
            }
            this.counters.cacheMiss++;
            this.metricsAgg.recordCacheMiss();

            // Step 0.5: single-flight coalescing; concurrent requests for the same DID make only one upstream call
            const existing = this.inflight.get(did);
            if (existing) return existing;

            const promise = this.resolveInternal(did);
            this.inflight.set(did, promise);
            try {
                return await promise;
            } finally {
                this.inflight.delete(did);
            }
        } catch (e) {
            this.counters.resolveInternalError++;
            throw e;
        } finally {
            this.metricsAgg.recordResolveLatency(Date.now() - startMs);
        }
    }

    invalidateCache(did: DID): void {
        this.cache.delete(did);
        this.cacheEpoch.set(did, (this.cacheEpoch.get(did) ?? 0) + 1);
    }

    getMetrics(): FederatedResolverMetrics {
        const nodes: Record<string, NodeMetrics> = {};
        for (const [id, state] of this.nodeStates) {
            nodes[id] = { ...state.metrics };
            // Sync the current availability to the OTel observable-gauge snapshot
            this.metricsAgg.setNodeAvailability(id, state.metrics.availability);
        }
        const latency = this.metricsAgg.latencySnapshot();
        return {
            ...this.counters,
            latencyP50Ms: latency.latencyP50Ms,
            latencyP95Ms: latency.latencyP95Ms,
            latencyP99Ms: latency.latencyP99Ms,
            nodes,
        };
    }

    async close(): Promise<void> {
        if (this.healthProbeTimer) clearInterval(this.healthProbeTimer);
        this.cache.clear();
        this.inflight.clear();
        // Consume the typed ShutdownStatus, distinguishing completed vs timed_out
        const shutdownResult = await this.metricsAgg.shutdown();
        if (shutdownResult.status === 'timed_out') {
            // Log-level warn: OTel shutdown timed out but does not block close
            // (the caller does not reject; the underlying SDK keeps running in the background until Node exits)
            console.warn(
                `[FederatedResolver.close] OTel metrics shutdown timed out after ${shutdownResult.durationMs}ms (reason: ${shutdownResult.reason})`,
            );
        } else if (shutdownResult.status === 'error') {
            // Log-level warn: OTel shutdown errored but does not block close
            console.warn(
                `[FederatedResolver.close] OTel metrics shutdown error after ${shutdownResult.durationMs}ms:`,
                shutdownResult.error.message,
            );
        }
        // completed / noop: pass silently
    }

    // ============================================================
    // Cache operations
    // ============================================================

    private getCached(did: DID): AgentIdentityDocument | null {
        const entry = this.cache.get(did);
        if (!entry) return null;
        if (Date.now() > entry.expiresAt) {
            this.cache.delete(did);
            return null;
        }
        return entry.document;
    }

    private setCached(did: DID, document: AgentIdentityDocument): void {
        const now = Date.now();
        this.cache.set(did, {
            document,
            cachedAt: now,
            expiresAt: now + this.cfg.cacheTtlMs,
        });
    }

    // ============================================================
    // resolve internal flow
    // ============================================================

    private async resolveInternal(
        did: DID,
    ): Promise<AgentIdentityDocument | null> {
        // Re-check the cache (it may have been filled during the single-flight wait)
        // Note: do not touch the cacheMiss counter — the outer resolve() already incremented it; only add to cacheHit here
        const cached = this.getCached(did);
        if (cached) {
            this.counters.cacheHit++;
            this.metricsAgg.recordCacheHit();
            return cached;
        }

        const startEpoch = this.cacheEpoch.get(did) ?? 0;

        // Only send requests to HEALTHY / DEGRADED nodes
        const targets = [...this.nodeStates.values()].filter(
            (s) => s.health !== 'UNHEALTHY' && (s.node.weight ?? 1) > 0,
        );

        if (targets.length < this.cfg.minResponses) {
            this.emitAlert({
                kind: 'FEDERATION_QUORUM_UNMET',
                did,
                respondedNodes: 0,
                validCandidates: 0,
                required: this.cfg.minResponses,
                observedAt: new Date().toISOString() as Timestamp,
            });
            this.counters.quorumUnmetCount++;
            this.metricsAgg.recordQuorumUnmet();
            this.counters.resolveNull++;
            return null;
        }

        const result = await this.fanOut(did, targets, startEpoch);
        if (result !== null) {
            this.counters.resolveSuccess++;
        } else {
            this.counters.resolveNull++;
        }
        return result;
    }

    // ============================================================
    // fanOut: query all target nodes concurrently, then elect a leader after the settle window
    // ============================================================

    private async fanOut(
        did: DID,
        targets: NodeState[],
        startEpoch: number,
    ): Promise<AgentIdentityDocument | null> {
        const controller = new AbortController();
        const globalDeadline = Date.now() + this.cfg.timeoutMs;
        const settleWindowMs =
            this.cfg.settleWindowMs !== undefined
                ? this.cfg.settleWindowMs
                : Math.min(this.cfg.timeoutMs / 4, 1000);

        type NodeResult =
            | { kind: 'doc'; nodeId: string; document: AgentIdentityDocument }
            | { kind: 'not_found'; nodeId: string }
            | { kind: 'skip'; nodeId: string };

        const pending: Promise<NodeResult>[] = targets.map((s) =>
            this.queryNode(s, did, controller.signal).then(
                (raw) => {
                    if (raw.kind === 'not_found')
                        return {
                            kind: 'not_found' as const,
                            nodeId: s.node.id,
                        };
                    if (raw.kind === 'error')
                        return { kind: 'skip' as const, nodeId: s.node.id };
                    return {
                        kind: 'doc' as const,
                        nodeId: s.node.id,
                        document: raw.document,
                    };
                },
                () => ({ kind: 'skip' as const, nodeId: s.node.id }),
            ),
        );

        const validCandidates: ResolutionCandidate[] = [];
        let respondedNodes = 0;
        let all404 = true;
        let settleDeadline: number | null = null;
        let loopDeadline = globalDeadline;
        const done = new Set<number>();

        // Tagged-promise pattern: track which index completed
        const taggedPending = pending.map((p, i) => p.then((r) => ({ r, i })));

        // Track the current iteration's sleep-timer handle, so it can be cancelled when the loop exits, preventing a leak
        let sleepHandle: ReturnType<typeof setTimeout> | undefined;

        try {
            while (done.size < pending.length) {
                const now = Date.now();
                if (now >= loopDeadline) break;

                const remaining = taggedPending.filter((_, i) => !done.has(i));
                if (remaining.length === 0) break;

                const sleepPromise = new Promise<{ r: null; i: -1 }>(
                    (resolve) => {
                        sleepHandle = setTimeout(
                            () => resolve({ r: null, i: -1 }),
                            loopDeadline - now,
                        );
                    },
                );

                const { r, i } = await Promise.race([
                    ...remaining,
                    sleepPromise,
                ]);

                // Clear the current iteration's timer (if a node returned first, the sleep has not yet fired)
                clearTimeout(sleepHandle);
                sleepHandle = undefined;

                if (i === -1) break; // window timeout
                done.add(i);
                if (r === null) continue;

                if (r.kind === 'not_found') {
                    respondedNodes++;
                    continue;
                }
                // step 4: errors/timeouts/aborts reset all404, but are not counted in respondedNodes
                if (r.kind === 'skip') {
                    all404 = false;
                    continue;
                }

                all404 = false;
                respondedNodes++;

                const verdict = await this.verifyDocumentSignature(r.document);
                if (!verdict.ok) {
                    const reason = verdict.reason;
                    this.emitAlert({
                        kind: 'FEDERATION_SIGNATURE_INVALID',
                        nodeId: r.nodeId,
                        did,
                        reason,
                        observedAt: new Date().toISOString() as Timestamp,
                    });
                    this.counters.signatureInvalidCount++;
                    const ns = this.nodeStates.get(r.nodeId);
                    if (ns) ns.metrics.signatureInvalid++;
                    continue;
                }

                validCandidates.push({
                    nodeId: r.nodeId,
                    document: r.document,
                    receivedAt: new Date().toISOString() as Timestamp,
                });

                // Start the settle window once minResponses is reached
                if (
                    validCandidates.length >= this.cfg.minResponses &&
                    settleDeadline === null
                ) {
                    settleDeadline = Math.min(
                        Date.now() + settleWindowMs,
                        globalDeadline,
                    );
                    loopDeadline = settleDeadline;
                }
            }
        } finally {
            // Cancel the not-yet-fired sleep timer and notify all nodes to abort their requests
            clearTimeout(sleepHandle);
            controller.abort();
        }

        // All 404: no consistency exists, do not trigger a QUORUM_UNMET alert
        if (
            validCandidates.length === 0 &&
            all404 &&
            respondedNodes >= this.cfg.minResponses
        ) {
            return null;
        }

        if (validCandidates.length < this.cfg.minResponses) {
            this.emitAlert({
                kind: 'FEDERATION_QUORUM_UNMET',
                did,
                respondedNodes,
                validCandidates: validCandidates.length,
                required: this.cfg.minResponses,
                observedAt: new Date().toISOString() as Timestamp,
            });
            this.counters.quorumUnmetCount++;
            this.metricsAgg.recordQuorumUnmet();
            return null;
        }

        // Majority-vote leader election (< 3 nodes degrades to the highest version number)
        const chosen = this.selectByQuorum(
            did,
            validCandidates,
            targets.length,
        );
        if (!chosen) return null;

        // Version-rollback check (fail-closed)
        const cachedDoc = this.getCached(did);
        const cacheVersion = cachedDoc?.version ?? 0;
        const persistVersion =
            (await this.cfg.persistentWatermark.getWatermark(did)) ?? 0;
        const watermark = Math.max(cacheVersion, persistVersion);

        if (watermark > (chosen.version ?? 1)) {
            this.emitAlert({
                kind: 'FEDERATION_VERSION_ROLLBACK',
                did,
                incomingVersion: chosen.version ?? 1,
                cachedVersion: watermark,
                observedAt: new Date().toISOString() as Timestamp,
            });
            return null;
        }

        // Epoch check (prevents stale writes, fail-closed)
        if ((this.cacheEpoch.get(did) ?? 0) !== startEpoch) {
            this.emitAlert({
                kind: 'FEDERATION_EPOCH_MISMATCH',
                did,
                startEpoch,
                endEpoch: this.cacheEpoch.get(did) ?? 0,
                observedAt: new Date().toISOString() as Timestamp,
            });
            return null;
        }

        this.setCached(did, chosen);
        await this.cfg.persistentWatermark.setWatermark(
            did,
            chosen.version ?? 1,
        );

        return chosen;
    }

    // ============================================================
    // queryNode: a single-node HTTP GET that returns a structured result
    // Calls dnsRebindingGuard.resolveAndValidate before fetch to defend against DNS rebinding attacks
    // ============================================================

    private async queryNode(
        state: NodeState,
        did: DID,
        signal: AbortSignal,
    ): Promise<
        | { kind: 'doc'; document: AgentIdentityDocument }
        | { kind: 'not_found' }
        | { kind: 'error' }
    > {
        const { node, metrics } = state;
        metrics.requestTotal++;
        const url = `${node.url}/api/v1/identities/${encodeURIComponent(did)}`;

        let parsed: URL;
        try {
            parsed = new URL(url);
        } catch {
            this.emitAlert({
                kind: 'FEDERATION_NODE_ABUSE',
                nodeId: node.id,
                reason: 'url_policy_violation',
                observedAt: new Date().toISOString() as Timestamp,
            });
            metrics.otherFailure++;
            this.drivePassiveHealth(state, false);
            return { kind: 'error' };
        }

        // SSRF protection: reject IP literals (IPv4/IPv6)
        // Note: dnsRebindingGuard handles domain -> IP validation; the IP-literal fast rejection is still kept here
        const host = parsed.hostname;
        const isIPv4 = /^\d{1,3}(\.\d{1,3}){3}$/.test(host);
        const isIPv6 = host.includes(':');
        if (isIPv4 || isIPv6) {
            this.emitAlert({
                kind: 'FEDERATION_NODE_ABUSE',
                nodeId: node.id,
                reason: 'url_policy_violation',
                observedAt: new Date().toISOString() as Timestamp,
            });
            metrics.otherFailure++;
            this.drivePassiveHealth(state, false);
            return { kind: 'error' };
        }

        // SSRF protection: reject blocked high-risk ports
        const portNum = parseInt(parsed.port, 10);
        if (!isNaN(portNum) && BLOCKED_PORTS.has(portNum)) {
            this.emitAlert({
                kind: 'FEDERATION_NODE_ABUSE',
                nodeId: node.id,
                reason: 'url_policy_violation',
                observedAt: new Date().toISOString() as Timestamp,
            });
            metrics.otherFailure++;
            this.drivePassiveHealth(state, false);
            return { kind: 'error' };
        }

        // race-free DNS rebinding defense (hard precondition)
        //
        // Fixes the residual TOCTOU risk:
        // Old approach: there is a time window between the two steps resolveAndValidate(hostname) → fetch(url),
        // and an attacker controlling DNS could switch to RFC1918 at step 2, bypassing validation.

        // New approach (race-free):
        // Step 1: resolveAndValidate → obtain the validated pinIP (a non-private address)
        // Step 2: construct an undici.Agent whose custom connector replaces the TCP/TLS hostname
        // with pinIP (pinning the connection target), while keeping servername=the original hostname
        // to ensure TLS SNI and certificate validation are correct.
        // Step 3: issue the request via that dispatcher's undici.fetch; the fetch call stack
        // no longer triggers any OS DNS resolution, eliminating the TOCTOU window.
        let pinIP: string;
        try {
            pinIP = await this.cfg.dnsRebindingGuard.resolveAndValidate(
                parsed.hostname,
            );
        } catch (rebindErr: unknown) {
            const reason =
                rebindErr instanceof Error
                    ? rebindErr.message
                    : String(rebindErr);
            this.emitAlert({
                kind: 'FEDERATION_DNS_REBINDING_BLOCKED',
                nodeId: node.id,
                hostname: parsed.hostname,
                reason,
                observedAt: new Date().toISOString() as Timestamp,
            });
            metrics.otherFailure++;
            this.drivePassiveHealth(state, false);
            return { kind: 'error' };
        }

        // Construct the pinIp dispatcher: pin the TCP connection target to the validated IP, with SNI still the original hostname
        const pinnedHostname = parsed.hostname;
        const pinnedConnector = buildConnector({});
        const pinnedDispatcher = new UndiciAgent({
            connect: (opts, cb) => {
                // Replace the TCP connection target with the validated IP, eliminating fetch's internal second DNS resolution
                pinnedConnector(
                    {
                        ...opts,
                        hostname: pinIP,
                        servername: opts.servername ?? pinnedHostname,
                    },
                    cb,
                );
            },
        });

        try {
            const res = await undiciFetch(parsed.toString(), {
                signal,
                redirect: 'error',
                dispatcher: pinnedDispatcher,
            } as Parameters<typeof undiciFetch>[1]);

            if (res.status === 404) {
                // 404 means the node is reachable (counted toward availability), the DID simply does not exist
                metrics.success++;
                this.drivePassiveHealth(state, true);
                return { kind: 'not_found' };
            }

            if (!res.ok) {
                metrics.otherFailure++;
                this.drivePassiveHealth(state, false);
                return { kind: 'error' };
            }

            // Content-Length over-limit check
            const contentLength = res.headers.get('content-length');
            if (
                contentLength &&
                parseInt(contentLength, 10) > this.cfg.maxResponseBytes
            ) {
                this.emitAlert({
                    kind: 'FEDERATION_NODE_ABUSE',
                    nodeId: node.id,
                    reason: 'response_too_large',
                    observedAt: new Date().toISOString() as Timestamp,
                });
                metrics.otherFailure++;
                this.drivePassiveHealth(state, false);
                return { kind: 'error' };
            }

            let body: unknown;
            try {
                body = await res.json();
            } catch {
                this.emitAlert({
                    kind: 'FEDERATION_NODE_ABUSE',
                    nodeId: node.id,
                    reason: 'malformed_json',
                    observedAt: new Date().toISOString() as Timestamp,
                });
                metrics.otherFailure++;
                this.drivePassiveHealth(state, false);
                return { kind: 'error' };
            }

            const doc = body as AgentIdentityDocument;
            if (!doc || typeof doc !== 'object' || doc.id !== did) {
                this.emitAlert({
                    kind: 'FEDERATION_NODE_ABUSE',
                    nodeId: node.id,
                    reason: 'invalid_schema',
                    observedAt: new Date().toISOString() as Timestamp,
                });
                metrics.otherFailure++;
                this.drivePassiveHealth(state, false);
                return { kind: 'error' };
            }

            metrics.success++;
            this.drivePassiveHealth(state, true);
            return { kind: 'doc', document: doc };
        } catch (e: unknown) {
            const isAbort =
                e instanceof Error &&
                (e.name === 'AbortError' || e.message.includes('aborted'));
            if (isAbort) {
                metrics.timeout++;
                this.drivePassiveHealth(state, false);
                return { kind: 'error' };
            }
            if (e instanceof TypeError && e.message.includes('redirect')) {
                this.emitAlert({
                    kind: 'FEDERATION_NODE_ABUSE',
                    nodeId: node.id,
                    reason: 'redirect_blocked',
                    observedAt: new Date().toISOString() as Timestamp,
                });
            }
            metrics.otherFailure++;
            this.drivePassiveHealth(state, false);
            return { kind: 'error' };
        } finally {
            // Each request uses its own dispatcher; close it after the request to release connection-pool resources
            void pinnedDispatcher.close();
        }
    }

    // ============================================================
    // verifyDocumentSignature: V1a field consistency → V1b signature → V2 rotation schema → V3 DID binding
    // ============================================================

    private async verifyDocumentSignature(doc: AgentIdentityDocument): Promise<
        | { ok: true }
        | {
              ok: false;
              reason:
                  | 'binding_proof_invalid'
                  | 'malformed_document'
                  | 'rotation_proof_malformed';
          }
    > {
        // V1a: the bindingProof fields align with the document fields
        if (!doc.bindingProof)
            return { ok: false, reason: 'binding_proof_invalid' };
        if (doc.bindingProof.agentDid !== doc.id)
            return { ok: false, reason: 'binding_proof_invalid' };
        if (doc.bindingProof.principalDid !== doc.principalDid)
            return { ok: false, reason: 'binding_proof_invalid' };

        // V1b: bindingProof signature verification (verifyBindingProof is a synchronous function)
        const bindingValid = verifyBindingProof(doc.bindingProof);
        if (!bindingValid)
            return { ok: false, reason: 'binding_proof_invalid' };

        // V2: at v>1, a rotationProof schema must be carried
        if (doc.version !== undefined && doc.version > 1) {
            if (!doc.rotationProof)
                return { ok: false, reason: 'rotation_proof_malformed' };
        }

        // V3a: v=1 self-certification check (createAgentDID(publicKey) must match doc.id)
        // fromHex throws CryptoError for non-hex strings; the try/catch prevents a single node tampering with publicKey from rejecting the entire resolve
        if (!doc.version || doc.version === 1) {
            try {
                if (createAgentDID(doc.publicKey) !== doc.id) {
                    return { ok: false, reason: 'binding_proof_invalid' };
                }
            } catch {
                return { ok: false, reason: 'malformed_document' };
            }
        }

        // V3b: v>1 full rotation-chain verification (delegated to verifyDIDBinding)
        if (doc.version !== undefined && doc.version > 1) {
            const verified = await this.cfg.verifyDIDBinding.verify(doc);
            if (!verified)
                return { ok: false, reason: 'rotation_proof_malformed' };
        }

        return { ok: true };
    }

    // ============================================================
    // computeQuorumThreshold: quorum majority threshold calculation
    // Conclusion: threshold = ⌊n/2⌋+1, strictly greater than n/2, guaranteeing a unique majority
    // ============================================================

    private computeQuorumThreshold(n: number): number {
        return Math.floor(n / 2) + 1;
    }

    // ============================================================
    // selectByQuorum: majority-vote leader election
    // Conclusion:
    // - totalNodes < 3 → degrade to the highest version number + emit a QUORUM_UNMET fallback alert
    // - threshold = ⌊validCandidates.length/2⌋+1 (based on the actual valid-candidate count)
    // - no version reaches the threshold → vote_split → null + QUORUM_UNMET
    // - a minority version (votes < threshold) → FEDERATION_VERSION_CONFLICT(different_versions)
    // - the majority version's content hash is inconsistent → null + VERSION_CONFLICT(same_version_divergent_content)
    // - normal case: select and return the majority version
    // ============================================================

    private selectByQuorum(
        did: DID,
        candidates: ResolutionCandidate[],
        totalConfiguredNodes: number,
    ): AgentIdentityDocument | null {
        // Q0: < 3 total configured nodes → degrade (highest version number wins) and emit a fallback alert
        if (totalConfiguredNodes < 3) {
            this.emitAlert({
                kind: 'FEDERATION_QUORUM_UNMET',
                did,
                respondedNodes: candidates.length,
                validCandidates: candidates.length,
                required: this.computeQuorumThreshold(totalConfiguredNodes),
                observedAt: new Date().toISOString() as Timestamp,
            });
            this.counters.quorumUnmetCount++;
            // Degrade: highest version number wins; for the same version, check content consistency
            return this.selectHighestVersionFallback(did, candidates);
        }

        // Q1: group votes by version
        const n = candidates.length;
        const threshold = this.computeQuorumThreshold(n);
        const byVersion = new Map<number, ResolutionCandidate[]>();
        for (const c of candidates) {
            const v = c.document.version ?? 1;
            const arr = byVersion.get(v) ?? [];
            arr.push(c);
            byVersion.set(v, arr);
        }

        // Q2: find the versions that reach the threshold (strict majority)
        const qualifiedVersions: number[] = [];
        for (const [v, group] of byVersion) {
            if (group.length >= threshold) qualifiedVersions.push(v);
        }

        // Q3: vote_split — no version reaches the threshold
        if (qualifiedVersions.length === 0) {
            this.emitAlert({
                kind: 'FEDERATION_QUORUM_UNMET',
                did,
                respondedNodes: candidates.length,
                validCandidates: candidates.length,
                required: threshold,
                observedAt: new Date().toISOString() as Timestamp,
            });
            this.counters.quorumUnmetCount++;
            return null;
        }

        // Q4: pick the highest qualified version (a strict majority guarantees only one, but max is a fallback)
        const chosenVersion = Math.max(...qualifiedVersions);
        const winners = byVersion.get(chosenVersion)!;

        // Q5: minority-version alert (versions with votes < threshold)
        const versionsByNode: Record<string, number> = {};
        for (const c of candidates)
            versionsByNode[c.nodeId] = c.document.version ?? 1;
        let hasMinority = false;
        for (const [v, group] of byVersion) {
            if (v !== chosenVersion && group.length > 0) {
                hasMinority = true;
                break;
            }
        }
        if (hasMinority) {
            this.emitAlert({
                kind: 'FEDERATION_VERSION_CONFLICT',
                did,
                conflict: {
                    did,
                    versionsByNode,
                    conflictType: 'different_versions',
                    chosenVersion,
                    observedAt: new Date().toISOString() as Timestamp,
                },
            });
            this.counters.versionConflictCount++;
        }

        // Q6: same-version content-hash consistency check (a fork within the majority group → fail-closed)
        const hashes = new Set(
            winners.map((c) =>
                Buffer.from(
                    hash(
                        new TextEncoder().encode(
                            canonicalize(
                                c.document as unknown as Record<
                                    string,
                                    unknown
                                >,
                            ),
                        ),
                    ),
                ).toString('hex'),
            ),
        );
        if (hashes.size > 1) {
            this.emitAlert({
                kind: 'FEDERATION_VERSION_CONFLICT',
                did,
                conflict: {
                    did,
                    versionsByNode,
                    conflictType: 'same_version_divergent_content',
                    chosenVersion: null,
                    observedAt: new Date().toISOString() as Timestamp,
                },
            });
            this.counters.versionConflictCount++;
            return null;
        }

        // Q7: return the majority-version document
        return winners[0]?.document ?? null;
    }

    // ============================================================
    // selectHighestVersionFallback: < 3 nodes degradation path
    // Conclusion: highest version number wins; on a content fork within the same version, alert and reject
    // ============================================================

    private selectHighestVersionFallback(
        did: DID,
        candidates: ResolutionCandidate[],
    ): AgentIdentityDocument | null {
        const byVersion = new Map<number, ResolutionCandidate[]>();
        for (const c of candidates) {
            const v = c.document.version ?? 1;
            const arr = byVersion.get(v) ?? [];
            arr.push(c);
            byVersion.set(v, arr);
        }

        const maxVersion = Math.max(...byVersion.keys());
        const winners = byVersion.get(maxVersion)!;

        // Same-version hash consistency check
        const hashes = new Set(
            winners.map((c) =>
                Buffer.from(
                    hash(
                        new TextEncoder().encode(
                            canonicalize(
                                c.document as unknown as Record<
                                    string,
                                    unknown
                                >,
                            ),
                        ),
                    ),
                ).toString('hex'),
            ),
        );

        if (hashes.size > 1) {
            const versionsByNode: Record<string, number> = {};
            for (const c of candidates)
                versionsByNode[c.nodeId] = c.document.version ?? 1;
            this.emitAlert({
                kind: 'FEDERATION_VERSION_CONFLICT',
                did,
                conflict: {
                    did,
                    versionsByNode,
                    conflictType: 'same_version_divergent_content',
                    chosenVersion: null,
                    observedAt: new Date().toISOString() as Timestamp,
                },
            });
            this.counters.versionConflictCount++;
            this.metricsAgg.recordVersionConflict();
            return null;
        }

        if (byVersion.size > 1) {
            const versionsByNode: Record<string, number> = {};
            for (const c of candidates)
                versionsByNode[c.nodeId] = c.document.version ?? 1;
            this.emitAlert({
                kind: 'FEDERATION_VERSION_CONFLICT',
                did,
                conflict: {
                    did,
                    versionsByNode,
                    conflictType: 'different_versions',
                    chosenVersion: maxVersion,
                    observedAt: new Date().toISOString() as Timestamp,
                },
            });
            this.counters.versionConflictCount++;
            this.metricsAgg.recordVersionConflict();
        }

        return winners[0]?.document ?? null;
    }

    // ============================================================
    // Health probe (implemented in Task 04e)
    // Conclusion: setInterval-driven, performing an HTTP GET probe on all nodes each interval
    // State machine: HEALTHY → DEGRADED (first failure) → UNHEALTHY (reaching failureThreshold)
    // UNHEALTHY → HEALTHY (reaching recoveryThreshold successes)
    // ============================================================

    private startHealthProbe(cfg: HealthCheckConfig): void {
        // Fix 5: .unref() prevents the timer from blocking the Node.js event-loop exit (friendly to test-suite teardown)
        this.healthProbeTimer = setInterval(() => {
            for (const state of this.nodeStates.values()) {
                // weight=0 nodes skip health probing (never routed to)
                if ((state.node.weight ?? 1) === 0) continue;
                void this.probeNode(state, cfg);
            }
        }, cfg.probeIntervalMs).unref();
    }

    // probeNode: single-node health probe
    // Only a 2xx response with body.status === 'ok' counts as an active success
    private async probeNode(
        state: NodeState,
        cfg: HealthCheckConfig,
    ): Promise<void> {
        const url = state.node.url + cfg.probePath;
        try {
            const res = await fetch(url, { signal: AbortSignal.timeout(3000) });
            if (res.ok) {
                try {
                    const body = (await res.json()) as Record<string, unknown>;
                    if (body['status'] === 'ok') {
                        this.recordNodeSuccess(state, cfg);
                    } else {
                        this.recordNodeFailure(state, cfg);
                    }
                } catch {
                    // JSON parse failure → treated as a probe failure
                    this.recordNodeFailure(state, cfg);
                }
            } else {
                this.recordNodeFailure(state, cfg);
            }
        } catch {
            this.recordNodeFailure(state, cfg);
        }
    }

    // Fix 2: changeHealth — the unified entry point for state changes + alerts (required)
    private changeHealth(state: NodeState, to: HealthState): void {
        const from = state.health;
        state.health = to;
        state.metrics.healthState = to;
        this.emitAlert({
            kind: 'FEDERATION_NODE_HEALTH_CHANGED',
            nodeId: state.node.id,
            from,
            to,
            observedAt: new Date().toISOString() as Timestamp,
        });
    }

    // drivePassiveHealth: the passive health-check driving entry point
    // Called after each queryNode request completes, using the configured healthCheck thresholds or conservative defaults
    // Note: this method only drives the state machine; it does not update the metrics counters (queryNode manages those itself)
    // State-machine policy:
    // - UNHEALTHY: recovers only after consecutive successes reach recoveryThreshold (strict threshold)
    // - HEALTHY↔DEGRADED: uses the rolling-window failure rate (≥20% → DEGRADED; <10% → HEALTHY)
    // - HEALTHY/DEGRADED → UNHEALTHY: consecutive failures reach failureThreshold
    private drivePassiveHealth(state: NodeState, success: boolean): void {
        const cfg = this.cfg.healthCheck ?? PASSIVE_HEALTH_CFG;

        // Maintain the sliding window (the most recent HEALTH_RATE_WINDOW results)
        state.recentResults.push(success);
        if (state.recentResults.length > HEALTH_RATE_WINDOW) {
            state.recentResults.shift();
        }

        if (success) {
            state.consecutiveFailures = 0;
            state.consecutiveSuccesses++;
            if (state.health === 'UNHEALTHY') {
                // UNHEALTHY → HEALTHY: requires consecutive successes reaching recoveryThreshold
                if (state.consecutiveSuccesses >= cfg.recoveryThreshold) {
                    this.changeHealth(state, 'HEALTHY');
                }
            } else if (state.health === 'DEGRADED') {
                // DEGRADED → HEALTHY: once the window is full and the failure rate is < 10%
                const window = state.recentResults;
                if (window.length >= HEALTH_RATE_WINDOW) {
                    const failures = window.filter((r) => !r).length;
                    const failureRate = failures / window.length;
                    if (failureRate < 0.1) {
                        this.changeHealth(state, 'HEALTHY');
                    }
                }
            }
        } else {
            state.consecutiveSuccesses = 0;
            state.consecutiveFailures++;
            if (state.consecutiveFailures >= cfg.failureThreshold) {
                if (state.health !== 'UNHEALTHY') {
                    this.changeHealth(state, 'UNHEALTHY');
                }
            } else if (state.health === 'HEALTHY') {
                // HEALTHY → DEGRADED: once the window is full and the failure rate is ≥ 20%; or, while the window is not full, any failure degrades immediately
                const window = state.recentResults;
                if (window.length >= HEALTH_RATE_WINDOW) {
                    const failures = window.filter((r) => !r).length;
                    const failureRate = failures / window.length;
                    if (failureRate >= 0.2) {
                        this.changeHealth(state, 'DEGRADED');
                    }
                } else {
                    // Window not full: keep the conservative policy, degrade on any failure
                    this.changeHealth(state, 'DEGRADED');
                }
            }
        }
        this.updateAvailability(state);
    }

    // calcAvailability: definition
    // availability = success / (success + timeout + otherFailure + signatureInvalid)
    private calcAvailability(state: NodeState): number {
        const m = state.metrics;
        const total =
            m.success + m.timeout + m.otherFailure + m.signatureInvalid;
        if (total === 0) return 1;
        return m.success / total;
    }

    // Update a single node's availability: sync the local NodeMetrics + the OTel observable-gauge snapshot.
    // Must be called at every state-change point, so the OTel exporter can still pull the latest availability
    // even when the caller does not actively call getMetrics() (node availability is a key metric for the DHT decision gate).
    private updateAvailability(state: NodeState): void {
        const v = this.calcAvailability(state);
        state.metrics.availability = v;
        this.metricsAgg.setNodeAvailability(state.node.id, v);
    }

    // recordNodeSuccess: record an active-probe success, maintain the sliding window, and migrate back to HEALTHY once recoveryThreshold is reached
    private recordNodeSuccess(state: NodeState, cfg: HealthCheckConfig): void {
        state.consecutiveFailures = 0;
        state.consecutiveSuccesses++;
        state.metrics.success++;

        // Maintain the sliding window
        state.recentResults.push(true);
        if (state.recentResults.length > HEALTH_RATE_WINDOW)
            state.recentResults.shift();

        if (state.health === 'UNHEALTHY') {
            // UNHEALTHY → HEALTHY: requires consecutive successes reaching recoveryThreshold
            if (state.consecutiveSuccesses >= cfg.recoveryThreshold) {
                this.changeHealth(state, 'HEALTHY');
            }
        } else if (state.health === 'DEGRADED') {
            // DEGRADED → HEALTHY: once the window is full and the failure rate is < 10%
            const window = state.recentResults;
            if (window.length >= HEALTH_RATE_WINDOW) {
                const failures = window.filter((r) => !r).length;
                if (failures / window.length < 0.1) {
                    this.changeHealth(state, 'HEALTHY');
                }
            }
        }
        this.updateAvailability(state);
    }

    // recordNodeFailure: record an active-probe failure, maintain the sliding window, and drive HEALTHY→DEGRADED→UNHEALTHY by thresholds
    // State machine: HEALTHY --> UNHEALTHY : consecutive failures >= failureThreshold (skipping DEGRADED directly)
    private recordNodeFailure(state: NodeState, cfg: HealthCheckConfig): void {
        state.consecutiveSuccesses = 0;
        state.consecutiveFailures++;
        state.metrics.otherFailure++;

        // Maintain the sliding window
        state.recentResults.push(false);
        if (state.recentResults.length > HEALTH_RATE_WINDOW)
            state.recentResults.shift();

        if (state.consecutiveFailures >= cfg.failureThreshold) {
            // Reaching failureThreshold: switch directly to UNHEALTHY (skipping DEGRADED)
            if (state.health !== 'UNHEALTHY') {
                this.changeHealth(state, 'UNHEALTHY');
            }
        } else if (state.health === 'HEALTHY') {
            // First failure but below the threshold: HEALTHY → DEGRADED (active probing does not use the failure-rate window)
            this.changeHealth(state, 'DEGRADED');
        }
        this.updateAvailability(state);
    }

    // ============================================================
    // Utility methods
    // ============================================================

    private emitAlert(event: FederationAlertEvent): void {
        // Alerts are routed through the injected onAlert; production falls back to console.warn
        this.onAlert(event);
    }
}
