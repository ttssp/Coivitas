// Federated-resolver metrics collection infrastructure
// Upgrades the simplistic array-based percentile → t-digest accurate percentile + OTel exporter

// Design points:
// 1. LatencyTracker: a 5-minute rolling window; bucketed into N 1-minute t-digests, precisely aging out old data
// 2. OtelMetricsExporter: degrades to a noop (no throw) when the endpoint is missing, preserving compatibility
// 3. MetricsAggregator: combines the two, exposing record* + snapshot; the snapshot fields
// match the existing FederatedResolverMetrics (preserving the field-stability recommendation)
// 4. Configuration is all injected via env; explicit override is allowed at construction for testing

// Key invariants:
// - Any sample that is NaN / negative / non-finite is discarded (fail-closed, avoiding polluting percentiles)
// - For empty samples, percentile always returns 0 (consistent with old behavior)
// - Bucket switching is triggered lazily on the record path, avoiding a background timer blocking Node exit
// - shutdown must be idempotent

import type { ShutdownStatus } from '@coivitas/types';
import {
    metrics as otelMetrics,
    type Counter,
    type Histogram,
    type Meter,
    type ObservableGauge,
    type ObservableResult,
} from '@opentelemetry/api';
import { OTLPMetricExporter } from '@opentelemetry/exporter-metrics-otlp-http';
import {
    AggregationType,
    MeterProvider,
    PeriodicExportingMetricReader,
} from '@opentelemetry/sdk-metrics';
// tdigest is a CommonJS package; under NodeNext + esModuleInterop it must use default/named import
import { TDigest } from 'tdigest';

// ============================================================
// Configuration constants
// ============================================================

/** Total rolling-window duration (ms): consistent with the default 5 minutes*/
export const DEFAULT_WINDOW_MS = 5 * 60 * 1000;

/**
 * Bucket count: default 60 5-second buckets.
 *
 * 60 is chosen to keep the window-boundary drift under the "edge-sample aging" semantics within a ±5%
 * tolerance: 5 minutes / 60 = 5s bucket width ≤ 5% × 5min = 15s.
 *
 * env AP_FEDERATION_TDIGEST_BUCKETS can override it, with a ceiling of 300 (one bucket per second).
 */
export const DEFAULT_BUCKETS = 60;

/** env bucket-count ceiling: one bucket per second (300 under a 5-minute window)*/
export const MAX_BUCKETS = 300;

/** OTel export interval (ms): default 60s*/
export const DEFAULT_OTEL_EXPORT_INTERVAL_MS = 60_000;

/**
 * OTel shutdown / forceFlush hard-timeout upper bound (ms).
 *
 * Background: when the collector is unreachable, the OTLPMetricExporter's
 * `forceFlush()` / `shutdown()` waits for the HTTP request to time out before settling;
 * the default HTTP timeout can reach 10-30s, blocking CLI exit / graceful shutdown / rolling restarts.
 * Via Promise.race + an unref'd setTimeout it is forced to return within 2s,
 * with the remaining SDK promise continuing in the background (not cancelled), no longer blocking the caller.
 */
export const OTEL_SHUTDOWN_TIMEOUT_MS = 2_000;

/** OTel meter / instrument naming prefix*/
export const METRIC_NAMESPACE = 'coivitas.federation';

// ============================================================
// Types
// ============================================================

/** Options injectable at construction, to bypass env / shorten the window in unit tests*/
export interface MetricsAggregatorOptions {
    /** Total rolling-window duration (ms), default DEFAULT_WINDOW_MS*/
    windowMs?: number;
    /** Bucket count, default reads env AP_FEDERATION_TDIGEST_BUCKETS or DEFAULT_BUCKETS*/
    buckets?: number;
    /** OTel export endpoint; explicit undefined means disabled*/
    otelEndpoint?: string;
    /** OTel export interval*/
    otelExportIntervalMs?: number;
    /** Time source (for testing), default Date.now*/
    now?: () => number;
    /**
     * Test-only: inject a pre-configured PeriodicExportingMetricReader (with an InMemoryMetricExporter).
     * When this option is set, the otelEndpoint's OTLPMetricExporter is not created;
     * this allows hermetic OTel testing in a CI environment without a collector.
     */
    _testingReader?: PeriodicExportingMetricReader;
}

/** snapshot is a synonymous subset of FederatedResolverMetrics*/
export interface LatencySnapshot {
    latencyP50Ms: number;
    latencyP95Ms: number;
    latencyP99Ms: number;
}

// ============================================================
// LatencyTracker: t-digest accurate percentiles + rolling window
// ============================================================

/**
 * Multi-bucket t-digest rolling-window implementation.
 *
 * Internally maintains N time buckets (each covering windowMs/N); on record, maps the current time to a bucket
 * index; on query, merges all non-expired buckets into a single t-digest and then takes the percentile. This way old data
 * is discarded all at once when a bucket fully expires, with no per-sample splice (the old implementation's performance bottleneck).
 */
export class LatencyTracker {
    private readonly buckets: number;
    private readonly bucketDurationMs: number;
    private readonly digests: TDigest[];
    /** Each bucket's bound "start time", used to determine whether the bucket has fallen out of the window*/
    private readonly bucketStarts: number[];
    private readonly now: () => number;

    constructor(opts: {
        windowMs: number;
        buckets: number;
        now: () => number;
    }) {
        if (!Number.isFinite(opts.windowMs) || opts.windowMs <= 0) {
            throw new Error('LatencyTracker: windowMs must be positive');
        }
        if (!Number.isInteger(opts.buckets) || opts.buckets < 1) {
            throw new Error(
                'LatencyTracker: buckets must be a positive integer',
            );
        }
        this.buckets = opts.buckets;
        this.bucketDurationMs = opts.windowMs / opts.buckets;
        this.now = opts.now;
        this.digests = Array.from(
            { length: opts.buckets },
            () => new TDigest(),
        );
        // Initialize bucket starts to negative infinity (reset immediately when any sample arrives)
        this.bucketStarts = new Array<number>(opts.buckets).fill(-Infinity);
    }

    /** Record one latency sample (ms); non-finite or negative values are silently discarded*/
    record(ms: number): void {
        if (!Number.isFinite(ms) || ms < 0) return;
        const t = this.now();
        const idx = this.bucketIndex(t);
        const start = this.bucketStarts[idx];
        // Bucket expired or uninitialized: reset in place
        if (start === undefined || t - start >= this.bucketDurationMs) {
            this.digests[idx] = new TDigest();
            this.bucketStarts[idx] = this.alignBucketStart(t);
        }
        this.digests[idx]?.push(ms);
    }

    /** Take a percentile; empty samples always return 0 (compatible with old behavior)*/
    percentile(p: number): number {
        if (!Number.isFinite(p) || p < 0 || p > 100) {
            throw new Error(
                `LatencyTracker.percentile: p must be in [0,100], got ${p}`,
            );
        }
        const merged = this.snapshotDigest();
        if (this.isEmpty(merged)) return 0;
        const q = p / 100;
        const v = merged.percentile(q);
        // tdigest occasionally returns NaN / undefined when there are very few samples, so guard against it
        return typeof v === 'number' && Number.isFinite(v) ? v : 0;
    }

    /** Take P50/P95/P99 in one shot; slightly faster than 3 percentile calls (sharing the merge)*/
    snapshot(): LatencySnapshot {
        const merged = this.snapshotDigest();
        if (this.isEmpty(merged)) {
            return { latencyP50Ms: 0, latencyP95Ms: 0, latencyP99Ms: 0 };
        }
        const get = (q: number): number => {
            const v = merged.percentile(q);
            return typeof v === 'number' && Number.isFinite(v) ? v : 0;
        };
        return {
            latencyP50Ms: get(0.5),
            latencyP95Ms: get(0.95),
            latencyP99Ms: get(0.99),
        };
    }

    /** For testing / shutdown: clear all buckets*/
    reset(): void {
        for (let i = 0; i < this.buckets; i++) {
            this.digests[i] = new TDigest();
            this.bucketStarts[i] = -Infinity;
        }
    }

    private bucketIndex(t: number): number {
        const slot = Math.floor(t / this.bucketDurationMs);
        // Modulo to guarantee [0, buckets); JS modulo on negatives can still be negative, so add buckets then mod again
        return ((slot % this.buckets) + this.buckets) % this.buckets;
    }

    private alignBucketStart(t: number): number {
        return Math.floor(t / this.bucketDurationMs) * this.bucketDurationMs;
    }

    /**
     * Merge all non-expired buckets into a single t-digest.
     *
     * Expiry rule: a bucket is kept only if its **end time** (start + bucketDurationMs) is still > cutoff;
     * using the "bucket start" as the criterion would cause the bucket to be discarded entirely while it still has valid samples, making
     * the effective window one bucketDurationMs shorter (losing 1 minute of data with 5 buckets / 1-minute buckets).
     */
    private snapshotDigest(): TDigest {
        const t = this.now();
        const cutoff = t - this.buckets * this.bucketDurationMs;
        const merged = new TDigest();
        for (let i = 0; i < this.buckets; i++) {
            const start = this.bucketStarts[i];
            if (start === undefined) continue;
            const end = start + this.bucketDurationMs;
            // A bucket is only expired once its end time is earlier than (or equal to) the cutoff; this ensures that as long as
            // any sample in the bucket is still within [t-windowMs, t], it is included in the merge
            if (end <= cutoff) continue;
            // TDigest was filled at construction, and the loop index guarantees d is non-null; only skip empty digests
            const d = this.digests[i]!;
            if (d.size() === 0) continue;
            // tdigest@0.1.x toArray() returns [{mean, n}, ...]; merge by pushing each centroid
            for (const c of d.toArray()) {
                merged.push(c.mean, c.n);
            }
        }
        return merged;
    }

    private isEmpty(d: TDigest): boolean {
        // tdigest@0.1.x always exposes size(), returning the centroid count; an empty digest is 0
        return d.size() === 0;
    }
}

// ============================================================
// OtelMetricsExporter: an env-driven OTel meter
// ============================================================

/**
 * Promise.race hard-timeout helper.
 *
 * Purpose: wrap OTel forceFlush / shutdown to prevent the SDK promise from hanging for a long time
 * and blocking CLI exit / graceful shutdown / rolling restarts when the collector is unreachable.
 *
 * Implementation details:
 *   - The internal setTimeout calls .unref() so it does not block Node's natural exit
 *   - On timeout it returns a resolved promise (not a reject), consistent with the error-swallowing strategy
 *   - The SDK's internal promise keeps running in the background until it settles naturally (not forcibly cancelled)
 */
/** Sentinel marking the hard-timeout path (distinguishing completed vs timed_out) */
const HARD_TIMEOUT_SENTINEL = Symbol('hard_timeout');

function withHardTimeout<T>(
    promise: Promise<T>,
    timeoutMs: number,
): Promise<T | typeof HARD_TIMEOUT_SENTINEL> {
    return Promise.race([
        promise,
        new Promise<typeof HARD_TIMEOUT_SENTINEL>((resolve) => {
            const t = setTimeout(
                () => resolve(HARD_TIMEOUT_SENTINEL),
                timeoutMs,
            );
            // unref: once the timer fires it does not impede the Node process's natural exit;
            // under Node.js, setTimeout returns a NodeJS.Timeout object (which has an unref method),
            // so narrow the type via a typeof + in check and call it directly, with no forced assertion needed
            if (typeof t === 'object' && 'unref' in t) {
                t.unref();
            }
        }),
    ]);
}

/**
 * OTel exporter state fields, for stop / shutdown.
 */
interface OtelInternal {
    provider: MeterProvider;
    reader: PeriodicExportingMetricReader;
    meter: Meter;
    latencyHistogram: Histogram;
    versionConflictCounter: Counter;
    cacheHitCounter: Counter;
    cacheMissCounter: Counter;
    quorumUnmetCounter: Counter;
    signatureInvalidCounter: Counter;
    /** Per-node availability callback registration handle (observable gauge)*/
    availabilityGauge: ObservableGauge;
    /** Current per-node availability snapshot; read by the observable callback*/
    availabilitySnapshot: Map<string, number>;
    cacheHitRatioGauge: ObservableGauge;
    cacheCountSnapshot: { hit: number; miss: number };
}

/**
 * OTel metrics exporter. Degrades to noop when the endpoint is missing or explicitly disabled,
 * so all record* calls are safe and side-effect-free.
 */
export class OtelMetricsExporter {
    private readonly internal: OtelInternal | null;
    /** In-flight promise prevents concurrent double-shutdown */
    private shutdownInFlight: Promise<ShutdownStatus> | null = null;

    constructor(opts: {
        endpoint?: string;
        exportIntervalMs?: number;
        /**
         * Test-only: inject a pre-configured PeriodicExportingMetricReader.
         * When set, the endpoint is ignored and no OTLPMetricExporter is created;
         * used for hermetic OTel unit tests in a CI environment without a collector.
         */
        _testingReader?: PeriodicExportingMetricReader;
    }) {
        if (opts._testingReader) {
            // Test path: build internal with the injected reader (not relying on a real endpoint)
            this.internal = OtelMetricsExporter.buildInternalWithReader(
                opts._testingReader,
            );
            return;
        }
        if (!opts.endpoint) {
            this.internal = null;
            return;
        }
        this.internal = OtelMetricsExporter.buildInternal(
            opts.endpoint,
            opts.exportIntervalMs ?? DEFAULT_OTEL_EXPORT_INTERVAL_MS,
        );
    }

    /**
     * Production path: build the OTLPMetricExporter + reader from the endpoint URL,
     * then delegate to buildInternalWithReader.
     */
    private static buildInternal(
        endpoint: string,
        exportIntervalMs: number,
    ): OtelInternal {
        const normalizedUrl = normalizeOtlpMetricsUrl(endpoint);
        const exporter = new OTLPMetricExporter({ url: normalizedUrl });
        const reader = new PeriodicExportingMetricReader({
            exporter,
            exportIntervalMillis: exportIntervalMs,
        });
        // Process-exit strategy: sdk-metrics ≥ 2.7 automatically calls .unref() on the
        // setInterval handle inside onInitialized() (see PeriodicExportingMetricReader.js
        // L120), so enabling OTel does **not** block Node's natural exit. But the caller should still explicitly
        // await close() to ensure the last batch of data is flushed out.
        return OtelMetricsExporter.buildInternalWithReader(reader);
    }

    /**
     * Core provider + meter construction, shared by the production path and the test-injection path.
     * The reader is provided by the caller (buildInternal / the constructor's _testingReader path).
     */
    private static buildInternalWithReader(
        reader: PeriodicExportingMetricReader,
    ): OtelInternal {
        const provider = new MeterProvider({
            readers: [reader],
            // Explicitly register the latency histogram's explicit buckets (overriding the default ms range)
            views: [
                {
                    instrumentName: 'federation.resolve.latency_ms',
                    aggregation: {
                        type: AggregationType.EXPLICIT_BUCKET_HISTOGRAM,
                        options: {
                            boundaries: [
                                5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000,
                                10000,
                            ],
                        },
                    },
                },
            ],
        });

        const meter = provider.getMeter(METRIC_NAMESPACE);

        const latencyHistogram = meter.createHistogram(
            'federation.resolve.latency_ms',
            {
                description:
                    'Federated DID resolve end-to-end latency in milliseconds',
                unit: 'ms',
            },
        );
        const versionConflictCounter = meter.createCounter(
            'federation.version_conflict.total',
            {
                description:
                    'Number of version conflict events emitted by selectHighestVersion',
            },
        );
        const cacheHitCounter = meter.createCounter(
            'federation.cache.hit.total',
            {
                description: 'Resolver cache hits',
            },
        );
        const cacheMissCounter = meter.createCounter(
            'federation.cache.miss.total',
            {
                description: 'Resolver cache misses',
            },
        );
        const quorumUnmetCounter = meter.createCounter(
            'federation.quorum_unmet.total',
            { description: 'FEDERATION_QUORUM_UNMET alert counter' },
        );
        const signatureInvalidCounter = meter.createCounter(
            'federation.signature_invalid.total',
            { description: 'FEDERATION_SIGNATURE_INVALID alert counter' },
        );

        const availabilitySnapshot = new Map<string, number>();
        const availabilityGauge = meter.createObservableGauge(
            'federation.node.availability',
            {
                description:
                    'Per-node availability (success / total) over current window',
            },
        );
        availabilityGauge.addCallback((result: ObservableResult) => {
            for (const [nodeId, value] of availabilitySnapshot) {
                result.observe(value, { 'federation.node.id': nodeId });
            }
        });

        const cacheCountSnapshot = { hit: 0, miss: 0 };
        const cacheHitRatioGauge = meter.createObservableGauge(
            'federation.cache.hit_ratio',
            {
                description:
                    'Cache hit ratio = hit / (hit + miss); reported 0 when no traffic',
            },
        );
        cacheHitRatioGauge.addCallback((result: ObservableResult) => {
            const total = cacheCountSnapshot.hit + cacheCountSnapshot.miss;
            const ratio = total === 0 ? 0 : cacheCountSnapshot.hit / total;
            result.observe(ratio);
        });

        // The global metrics API is not registered forcibly (keeping this module self-contained), but if the caller wants a globally
        // accessible meter, they can call setGlobalMeterProvider with this provider externally
        // We do not modify global state here, to avoid polluting other OTel integrations
        void otelMetrics; // merely marks "global has been considered", for future extension

        return {
            provider,
            reader,
            meter,
            latencyHistogram,
            versionConflictCounter,
            cacheHitCounter,
            cacheMissCounter,
            quorumUnmetCounter,
            signatureInvalidCounter,
            availabilityGauge,
            availabilitySnapshot,
            cacheHitRatioGauge,
            cacheCountSnapshot,
        };
    }

    /** Whether OTel is actually enabled (the endpoint is configured)*/
    isEnabled(): boolean {
        return this.internal !== null;
    }

    recordResolveLatency(ms: number): void {
        if (!Number.isFinite(ms) || ms < 0) return;
        this.internal?.latencyHistogram.record(ms);
    }

    recordVersionConflict(): void {
        this.internal?.versionConflictCounter.add(1);
    }

    recordCacheHit(): void {
        if (!this.internal) return;
        this.internal.cacheHitCounter.add(1);
        this.internal.cacheCountSnapshot.hit++;
    }

    recordCacheMiss(): void {
        if (!this.internal) return;
        this.internal.cacheMissCounter.add(1);
        this.internal.cacheCountSnapshot.miss++;
    }

    recordQuorumUnmet(): void {
        this.internal?.quorumUnmetCounter.add(1);
    }

    recordSignatureInvalid(): void {
        this.internal?.signatureInvalidCounter.add(1);
    }

    setNodeAvailability(nodeId: string, value: number): void {
        if (!this.internal) return;
        if (!Number.isFinite(value)) return;
        this.internal.availabilitySnapshot.set(nodeId, value);
    }

    /**
     * Actively trigger one collect+export, used to wait for data to land in tests.
     * When not enabled it is a noop and returns a resolved promise.
     *
     * Fault tolerance: when the collector is unreachable, the OTLP exporter rejects or hangs for a long time;
     * metrics are a best-effort side channel and must not block the resolver's main flow.
     * withHardTimeout guarantees a return within OTEL_SHUTDOWN_TIMEOUT_MS; failures are simply swallowed,
     * as sdk-metrics already records the details via its diag logger.
     */
    async forceFlush(): Promise<void> {
        if (!this.internal) return;
        try {
            await withHardTimeout(
                this.internal.reader.forceFlush(),
                OTEL_SHUTDOWN_TIMEOUT_MS,
            );
        } catch {
            // Silently swallow the error — see the comment above
        }
    }

    /**
     * Idempotent shutdown; returns a typed ShutdownStatus.
     *
     * 4 outcomes:
     *   - completed: provider.shutdown() finished normally within the hard timeout
     *   - timed_out: the hard timeout was hit — underlying SDK resources may still be running in the background
     *   - error: a non-timeout exception
     *   - noop: OTel not enabled (never_started) or already shut down (already_shutdown)
     *
     * Fault tolerance: withHardTimeout guarantees the blocking upper bound is OTEL_SHUTDOWN_TIMEOUT_MS.
     * Repeated calls return the cached result (idempotent).
     */
    async shutdown(): Promise<ShutdownStatus> {
        if (!this.internal) {
            return { status: 'noop', reason: 'never_started' };
        }
        // In-flight promise prevents concurrent double-shutdown
        // All concurrent callers share the same promise; after the first call settles, subsequent calls return noop
        if (this.shutdownInFlight) {
            // Wait for the first shutdown to settle, then return noop
            await this.shutdownInFlight;
            return { status: 'noop', reason: 'already_shutdown' };
        }
        // Cache the promise before awaiting, to prevent a concurrency window
        this.shutdownInFlight = this.doShutdown();
        return this.shutdownInFlight;
    }

    /** The actual shutdown logic (called exactly once by shutdown())*/
    private async doShutdown(): Promise<ShutdownStatus> {
        const start = Date.now();
        try {
            const outcome = await withHardTimeout(
                this.internal!.provider.shutdown(),
                OTEL_SHUTDOWN_TIMEOUT_MS,
            );
            const elapsed = Date.now() - start;
            if (outcome === HARD_TIMEOUT_SENTINEL) {
                return {
                    status: 'timed_out',
                    durationMs: elapsed,
                    reason: 'hard_timeout',
                };
            }
            return { status: 'completed', durationMs: elapsed };
        } catch (err) {
            const elapsed = Date.now() - start;
            return {
                status: 'error',
                durationMs: elapsed,
                error: err instanceof Error ? err : new Error(String(err)),
            };
        }
    }
}

// ============================================================
// MetricsAggregator: the unified external entry point
// ============================================================

/**
 * The externally exposed metrics aggregator. The federated-resolver is its sole holder; the old percentile() /
 * latencySamples fields have all been moved out.
 *
 * Field naming matches FederatedResolverMetrics; snapshot()'s return must be merged with the resolver's
 * counters before being returned to the caller.
 */
export class MetricsAggregator {
    private readonly latency: LatencyTracker;
    private readonly otel: OtelMetricsExporter;

    constructor(opts: MetricsAggregatorOptions = {}) {
        const buckets = opts.buckets ?? readBucketsFromEnv() ?? DEFAULT_BUCKETS;
        const windowMs = opts.windowMs ?? DEFAULT_WINDOW_MS;
        const now = opts.now ?? (() => Date.now());

        this.latency = new LatencyTracker({ windowMs, buckets, now });

        // Test-only injection path: when _testingReader is present, pass it straight to OtelMetricsExporter,
        // bypassing endpoint / env reading, to avoid depending on a real collector
        if (opts._testingReader) {
            this.otel = new OtelMetricsExporter({
                _testingReader: opts._testingReader,
            });
            return;
        }

        // Distinguish "otelEndpoint not passed" vs "explicitly undefined":
        // - explicitly passing the key (even if undefined) → forcibly overrides env, usable to explicitly disable in test scenarios
        // - not passing the key → falls back to env (default behavior)
        const endpoint = Object.prototype.hasOwnProperty.call(
            opts,
            'otelEndpoint',
        )
            ? opts.otelEndpoint
            : readEndpointFromEnv();
        this.otel = new OtelMetricsExporter({
            endpoint,
            exportIntervalMs: opts.otelExportIntervalMs,
        });
    }

    /** Whether the OTel exporter is enabled (the endpoint configuration exists)*/
    isOtelEnabled(): boolean {
        return this.otel.isEnabled();
    }

    recordResolveLatency(ms: number): void {
        this.latency.record(ms);
        this.otel.recordResolveLatency(ms);
    }

    recordCacheHit(): void {
        this.otel.recordCacheHit();
    }

    recordCacheMiss(): void {
        this.otel.recordCacheMiss();
    }

    recordVersionConflict(): void {
        this.otel.recordVersionConflict();
    }

    recordQuorumUnmet(): void {
        this.otel.recordQuorumUnmet();
    }

    recordSignatureInvalid(): void {
        this.otel.recordSignatureInvalid();
    }

    /** Node availability (0..1); when OTel is not enabled, only cached locally (the resolver synthesizes the snapshot itself)*/
    setNodeAvailability(nodeId: string, value: number): void {
        this.otel.setNodeAvailability(nodeId, value);
    }

    /** Current-window percentile snapshot*/
    latencySnapshot(): LatencySnapshot {
        return this.latency.snapshot();
    }

    /** Active flush, used only in tests / before shutdown*/
    async forceFlush(): Promise<void> {
        await this.otel.forceFlush();
    }

    /**
     * Idempotent shutdown: close the OTel provider; **retain** the latency digest so the caller
     * can do a final getMetrics collection after close (a common practice in graceful-shutdown scenarios).
     *
     * Latency data lives in process memory and is cleared on process exit; it is explicitly specified as "reset on process restart".
     *
     * Returns a typed ShutdownStatus, so the caller can precisely distinguish
     * completed / timed_out / error / noop.
     */
    async shutdown(): Promise<ShutdownStatus> {
        return this.otel.shutdown();
    }
}

// ============================================================
// env-reading helpers + URL normalization (exported separately for testability)
// ============================================================

/**
 * Normalize the OTLP HTTP metrics endpoint.
 *
 * Background: `OTLPMetricExporter({ url })` sends the url directly as the **full request path** and does not
 * automatically append the standard OTLP metrics path `/v1/metrics`. If operators write the collector base URL
 * (e.g. `http://localhost:4318`), as is a common convention, export requests land at the
 * collector root path, the OTel collector typically returns 404, and the telemetry pipeline silently fails.
 *
 * Handling rules (leaving room for explicit operator override):
 *   - already ending with `/v1/metrics` (including an optional trailing slash) → unchanged
 *   - URL with no path or path === '/' → append `/v1/metrics`
 *   - other explicit paths (e.g. a reverse proxy rewriting the path) → keep the original value, leaving operators explicitly responsible
 *
 * On URL parse failure, return the original string (letting OTLPMetricExporter surface the error itself).
 */
export function normalizeOtlpMetricsUrl(endpoint: string): string {
    let parsed: URL;
    try {
        parsed = new URL(endpoint);
    } catch {
        return endpoint;
    }
    // Already explicitly carries a /v1/metrics path (tolerating a trailing slash) → leave unchanged
    if (
        parsed.pathname === '/v1/metrics' ||
        parsed.pathname === '/v1/metrics/'
    ) {
        return endpoint;
    }
    // Base URL only (path empty or '/') → append the standard OTLP metrics path
    if (parsed.pathname === '' || parsed.pathname === '/') {
        // The URL constructor normalizes 'http://x' to path = '/' as well
        parsed.pathname = '/v1/metrics';
        return parsed.toString();
    }
    // Other paths (reverse proxy / custom routing) → keep the operator's explicit configuration
    return endpoint;
}

export function readEndpointFromEnv(): string | undefined {
    const v = process.env['AP_FEDERATION_OTEL_EXPORTER_ENDPOINT'];
    if (typeof v !== 'string') return undefined;
    const trimmed = v.trim();
    return trimmed.length === 0 ? undefined : trimmed;
}

export function readBucketsFromEnv(): number | undefined {
    const v = process.env['AP_FEDERATION_TDIGEST_BUCKETS'];
    if (typeof v !== 'string') return undefined;
    const trimmed = v.trim();
    // Strictly match a pure non-negative integer literal; parseInt would accept suffix forms like "10ms" / "60_extra",
    // causing a config typo to silently take effect and change the window semantics (fail-closed is preferable to lenient)
    if (!/^\d+$/.test(trimmed)) return undefined;
    const n = Number.parseInt(trimmed, 10);
    if (!Number.isInteger(n) || n < 1 || n > MAX_BUCKETS) return undefined;
    return n;
}
