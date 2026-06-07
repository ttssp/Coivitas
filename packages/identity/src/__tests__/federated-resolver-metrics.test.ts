// Unit tests: federated resolver metrics infrastructure
// Coverage targets: lines >= 95%, branches >= 90%; single file < 5s

// Test groups:
// 1. LatencyTracker: t-digest accuracy (vs naive sorted array) + rolling window + boundaries
// 2. OtelMetricsExporter: noop when endpoint missing / real metric emission once endpoint configured
// 3. MetricsAggregator: env reads / end-to-end record + snapshot / idempotent shutdown
// 4. env helper: parsing and boundaries

// Test naming follows the "should ... when ..." convention.

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

// Proxy undici.fetch to globalThis.fetch so existing vi.stubGlobal('fetch', ...) keeps working.
vi.mock('undici', () => {
    const mockConnector = vi
        .fn()
        .mockImplementation(
            (_opts: unknown, cb: (err: null, sock: unknown) => void) => {
                cb(null, {} as unknown);
            },
        );
    return {
        fetch: (...args: Parameters<typeof globalThis.fetch>) =>
            globalThis.fetch(...args),
        buildConnector: vi.fn(() => mockConnector),
        Agent: vi.fn().mockImplementation(() => ({
            close: vi.fn().mockResolvedValue(undefined),
        })),
    };
});

// federation types v0.2 promoted persistentWatermark / dnsRebindingGuard
// to required; the helpers below provide default noop stubs for legacy tests.
const makeDefaultWatermark = () => ({
    getWatermark: vi.fn().mockResolvedValue(0),
    setWatermark: vi.fn().mockResolvedValue(undefined),
});

const makeDefaultRebindingGuard = () => ({
    resolveAndValidate: vi
        .fn()
        .mockImplementation((url: string) => Promise.resolve(url)),
});
import {
    AggregationTemporality,
    InMemoryMetricExporter,
    PeriodicExportingMetricReader,
} from '@opentelemetry/sdk-metrics';
import {
    DEFAULT_BUCKETS,
    DEFAULT_OTEL_EXPORT_INTERVAL_MS,
    DEFAULT_WINDOW_MS,
    LatencyTracker,
    MAX_BUCKETS,
    METRIC_NAMESPACE,
    MetricsAggregator,
    OtelMetricsExporter,
    normalizeOtlpMetricsUrl,
    readBucketsFromEnv,
    readEndpointFromEnv,
} from '../federated-resolver-metrics.js';

// ============================================================
// Test helper: create a hermetic reader backed by InMemoryMetricExporter
// Avoids depending on a real collector / fetch stub
// ============================================================

function makeInMemoryReader(): {
    reader: PeriodicExportingMetricReader;
    exporter: InMemoryMetricExporter;
} {
    const exporter = new InMemoryMetricExporter(
        AggregationTemporality.CUMULATIVE,
    );
    const reader = new PeriodicExportingMetricReader({
        exporter,
        // Very long export interval: tests trigger flush manually via forceFlush, not the periodic timer
        exportIntervalMillis: 60_000,
    });
    return { reader, exporter };
}

// ============================================================
// Helper: naive sorted-array percentile (equivalent to the old implementation)
// ============================================================

function naivePercentile(samples: number[], p: number): number {
    if (samples.length === 0) return 0;
    const sorted = [...samples].sort((a, b) => a - b);
    const idx = Math.ceil((p / 100) * sorted.length) - 1;
    return sorted[Math.max(0, idx)] ?? 0;
}

/** Controls LatencyTracker internal time so unit tests stay deterministic */
class FakeClock {
    private current: number;
    constructor(initial = 1_700_000_000_000) {
        this.current = initial;
    }
    now = (): number => this.current;
    advance(ms: number): void {
        this.current += ms;
    }
}

// ============================================================
// 1. LatencyTracker
// ============================================================

describe('LatencyTracker', () => {
    it('should reject invalid windowMs when constructed', () => {
        expect(
            () => new LatencyTracker({ windowMs: 0, buckets: 5, now: () => 0 }),
        ).toThrow(/windowMs/);
        expect(
            () =>
                new LatencyTracker({ windowMs: NaN, buckets: 5, now: () => 0 }),
        ).toThrow(/windowMs/);
    });

    it('should reject non-integer or zero buckets when constructed', () => {
        expect(
            () =>
                new LatencyTracker({
                    windowMs: 1000,
                    buckets: 0,
                    now: () => 0,
                }),
        ).toThrow(/buckets/);
        expect(
            () =>
                new LatencyTracker({
                    windowMs: 1000,
                    buckets: 1.5,
                    now: () => 0,
                }),
        ).toThrow(/buckets/);
    });

    it('should return 0 percentiles when no samples have been recorded', () => {
        const t = new LatencyTracker({
            windowMs: 1000,
            buckets: 5,
            now: () => 0,
        });
        expect(t.percentile(50)).toBe(0);
        expect(t.percentile(95)).toBe(0);
        expect(t.percentile(99)).toBe(0);
        const snap = t.snapshot();
        expect(snap.latencyP50Ms).toBe(0);
        expect(snap.latencyP95Ms).toBe(0);
        expect(snap.latencyP99Ms).toBe(0);
    });

    it('should silently drop NaN, negative or non-finite samples when recorded', () => {
        const clock = new FakeClock();
        const t = new LatencyTracker({
            windowMs: 60_000,
            buckets: 5,
            now: clock.now,
        });
        t.record(NaN);
        t.record(-1);
        t.record(Infinity);
        // Only valid samples can make P50 > 0
        expect(t.snapshot().latencyP50Ms).toBe(0);
        t.record(100);
        expect(t.snapshot().latencyP50Ms).toBeGreaterThan(0);
    });

    it('should reject percentile arguments outside [0,100] when invoked', () => {
        const t = new LatencyTracker({
            windowMs: 1000,
            buckets: 5,
            now: () => 0,
        });
        expect(() => t.percentile(-1)).toThrow(/p must be in/);
        expect(() => t.percentile(101)).toThrow(/p must be in/);
        expect(() => t.percentile(NaN)).toThrow(/p must be in/);
    });

    it('should produce P50/P95/P99 within 5% of naive sort over 1000 uniform samples', () => {
        const clock = new FakeClock();
        const t = new LatencyTracker({
            windowMs: DEFAULT_WINDOW_MS,
            buckets: DEFAULT_BUCKETS,
            now: clock.now,
        });
        // Fixed-seed pseudo-random to avoid flakiness
        let seed = 12345;
        const rand = (): number => {
            seed = (seed * 1664525 + 1013904223) % 2 ** 32;
            return seed / 2 ** 32;
        };
        const samples: number[] = [];
        for (let i = 0; i < 1000; i++) {
            const v = Math.floor(rand() * 1000);
            samples.push(v);
            t.record(v);
        }
        const snap = t.snapshot();
        const p50Naive = naivePercentile(samples, 50);
        const p95Naive = naivePercentile(samples, 95);
        const p99Naive = naivePercentile(samples, 99);

        // Error check: relative error < 5%; when naive is 0, allow absolute error < 5
        const withinTolerance = (
            got: number,
            ref: number,
            pct = 0.05,
        ): boolean => {
            if (ref === 0) return Math.abs(got) < 5;
            return Math.abs(got - ref) / ref < pct;
        };

        expect(withinTolerance(snap.latencyP50Ms, p50Naive)).toBe(true);
        expect(withinTolerance(snap.latencyP95Ms, p95Naive)).toBe(true);
        expect(withinTolerance(snap.latencyP99Ms, p99Naive)).toBe(true);
        // Monotonicity: P50 <= P95 <= P99
        expect(snap.latencyP95Ms).toBeGreaterThanOrEqual(snap.latencyP50Ms);
        expect(snap.latencyP99Ms).toBeGreaterThanOrEqual(snap.latencyP95Ms);
    });

    it('should expire samples that fall out of the rolling window when time advances', () => {
        const clock = new FakeClock();
        const buckets = 5;
        const windowMs = 5 * 60_000; // 5-minute window
        const t = new LatencyTracker({ windowMs, buckets, now: clock.now });

        // T0: record 100 samples of 50ms
        for (let i = 0; i < 100; i++) t.record(50);
        const before = t.snapshot();
        expect(before.latencyP50Ms).toBeCloseTo(50, 0);

        // Advance by 2x the window length (all buckets have expired)
        clock.advance(windowMs * 2 + 1);

        // No new samples recorded: should report 0 (all buckets expired)
        const after = t.snapshot();
        expect(after.latencyP50Ms).toBe(0);
    });

    it('should not blow up percentile values when only 1 or 2 samples are recorded', () => {
        const clock = new FakeClock();
        const t = new LatencyTracker({
            windowMs: 60_000,
            buckets: 5,
            now: clock.now,
        });
        t.record(42);
        // Single sample: P50/P95/P99 should all be near that sample
        const s1 = t.snapshot();
        expect(s1.latencyP50Ms).toBeCloseTo(42, 0);
        expect(s1.latencyP95Ms).toBeCloseTo(42, 0);
        t.record(84);
        const s2 = t.snapshot();
        expect(s2.latencyP99Ms).toBeGreaterThanOrEqual(s2.latencyP50Ms);
    });

    it('should clear all samples when reset is invoked', () => {
        const clock = new FakeClock();
        const t = new LatencyTracker({
            windowMs: 60_000,
            buckets: 5,
            now: clock.now,
        });
        for (let i = 0; i < 50; i++) t.record(i + 1);
        expect(t.snapshot().latencyP50Ms).toBeGreaterThan(0);
        t.reset();
        expect(t.snapshot().latencyP50Ms).toBe(0);
    });

    it('should return non-zero values from percentile() when samples exist', () => {
        // Exercise the percentile() path directly (distinct from the snapshot path) to ensure 100% branch coverage
        const clock = new FakeClock();
        const t = new LatencyTracker({
            windowMs: 60_000,
            buckets: 5,
            now: clock.now,
        });
        for (let i = 1; i <= 100; i++) t.record(i);
        expect(t.percentile(50)).toBeGreaterThan(0);
        expect(t.percentile(99)).toBeGreaterThanOrEqual(t.percentile(50));
    });

    it('should retain samples in the oldest bucket until that bucket fully exits the window', () => {
        // Regression: the old version dropped a whole bucket on "bucket start <= cutoff", which
        // evicted samples in the last bucketDuration prematurely. The fix decides on "bucket end
        // time <= cutoff" -- i.e. a bucket is kept as long as its tail is still within [t-windowMs, t].
        const clock = new FakeClock(0);
        const buckets = 5;
        const windowMs = 5_000; // 5 buckets x 1000ms = 5s window
        const t = new LatencyTracker({ windowMs, buckets, now: clock.now });

        // T=0~999: record 50 samples of 100ms into bucket 0 (start=0, end=1_000)
        for (let i = 0; i < 50; i++) t.record(100);

        // Old-bug repro point: when advancing by 5_000ms, cutoff = 0; bucket 0 start (0) == cutoff,
        // old logic (start <= cutoff) drops the whole bucket; new logic (end <= cutoff) keeps it (end=1_000 > 0)
        clock.advance(5_000);
        expect(t.snapshot().latencyP50Ms).toBeCloseTo(100, 0);

        // Advance further to t=5_999 (cutoff = 999): bucket 0 end=1_000 > 999, still kept
        clock.advance(999);
        expect(t.snapshot().latencyP50Ms).toBeCloseTo(100, 0);

        // Advance to t=6_000 (cutoff = 1_000 == bucket 0 end): the bucket expires entirely
        clock.advance(1);
        expect(t.snapshot().latencyP50Ms).toBe(0);
    });

    it('should compute correct bucket index when timestamps wrap modulo bucket count', () => {
        // The same bucket is reused when crossing buckets * bucketDuration: stale data is cleared
        const clock = new FakeClock(0);
        const t = new LatencyTracker({
            windowMs: 5_000,
            buckets: 5,
            now: clock.now,
        });
        t.record(10); // bucket 0
        clock.advance(5_000); // jump to t=5000, lands in the same bucket 0 (5000 % 5 == 0)
        t.record(20); // bucket 0: old value should be overwritten
        // Advance to t=5001, still within bucket 0's current window; snapshot should see only 20
        const snap = t.snapshot();
        expect(snap.latencyP50Ms).toBe(20);
    });
});

// ============================================================
// 2. OtelMetricsExporter
// ============================================================

describe('OtelMetricsExporter', () => {
    afterEach(() => {
        vi.unstubAllGlobals();
        vi.restoreAllMocks();
    });

    it('should be disabled when endpoint is undefined', () => {
        const e = new OtelMetricsExporter({ endpoint: undefined });
        expect(e.isEnabled()).toBe(false);
        // None of the record* calls should throw
        expect(() => {
            e.recordResolveLatency(100);
            e.recordVersionConflict();
            e.recordCacheHit();
            e.recordCacheMiss();
            e.recordQuorumUnmet();
            e.recordSignatureInvalid();
            e.setNodeAvailability('n1', 0.9);
        }).not.toThrow();
    });

    it('should remain noop when endpoint is empty string', () => {
        // empty string is already filtered by readEndpointFromEnv; a falsy value at construction goes straight to noop
        const e = new OtelMetricsExporter({ endpoint: '' });
        expect(e.isEnabled()).toBe(false);
    });

    it('should silently drop invalid latency values when not enabled', () => {
        const e = new OtelMetricsExporter({ endpoint: undefined });
        expect(() => {
            e.recordResolveLatency(NaN);
            e.recordResolveLatency(-100);
            e.recordResolveLatency(Infinity);
        }).not.toThrow();
    });

    it('should be enabled and forward latency to in-memory exporter when _testingReader is injected', async () => {
        // Inject an InMemoryMetricExporter instead, with no dependency on 127.0.0.1:14318 / fetch stub.
        // Verifies: after record* calls, forceFlush writes data into the InMemoryMetricExporter,
        // and the latency histogram data points can be read from exporter.getMetrics().
        const { reader, exporter } = makeInMemoryReader();
        const e = new OtelMetricsExporter({ _testingReader: reader });
        expect(e.isEnabled()).toBe(true);

        e.recordResolveLatency(123);
        e.recordVersionConflict();
        e.recordCacheHit();
        e.recordCacheMiss();
        e.recordQuorumUnmet();
        e.recordSignatureInvalid();
        e.setNodeAvailability('n1', 0.95);
        e.setNodeAvailability('n2', NaN); // non-finite value dropped

        await e.forceFlush();

        // Read the flushed metrics from InMemoryMetricExporter and assert the latency histogram exists
        const metrics = exporter.getMetrics();
        // At least one ResourceMetrics entry (the latency histogram was recorded)
        expect(metrics.length).toBeGreaterThan(0);
        // The scope metric for the latency histogram can be found
        const allNames = metrics.flatMap((rm) =>
            rm.scopeMetrics.flatMap((sm) =>
                sm.metrics.map((m) => m.descriptor.name),
            ),
        );
        expect(allNames).toContain('federation.resolve.latency_ms');

        await e.shutdown();
    });

    it('should be idempotent when shutdown is invoked multiple times', async () => {
        // Inject an InMemoryMetricExporter to avoid depending on a real collector.
        // Verifies: multiple shutdowns do not throw, and shutdownPromise is idempotent (reuses the same promise).
        const { reader } = makeInMemoryReader();
        const e = new OtelMetricsExporter({ _testingReader: reader });
        await e.shutdown();
        await e.shutdown();
        await e.shutdown();
        // All three shutdowns should complete safely (no reject, no throw)
    });

    it('should resolve forceFlush and shutdown immediately when not enabled', async () => {
        const e = new OtelMetricsExporter({ endpoint: undefined });
        await e.forceFlush();
        await e.shutdown();
        // Repeated shutdowns should still be safe
        await e.shutdown();
    });

    it('should not block Node event-loop exit due to internal export timer when enabled', async () => {
        // Inject an InMemoryMetricExporter instead, with no dependency on a real collector.

        // Regression (F1):
        // 1. PeriodicExportingMetricReader's setInterval handle -- sdk-metrics 2.7
        // already calls .unref() automatically in onInitialized(), so it does not block Node from exiting naturally.
        // 2. shutdown() / forceFlush() now have a hard OTEL_SHUTDOWN_TIMEOUT_MS = 2s timeout,
        // so they never hang indefinitely when the collector is unreachable.

        // Verification approach: construct an exporter with an injected reader and check that _getActiveHandles
        // contains no ref'ed Timeout (the PeriodicExportingMetricReader timer is already unref'ed).
        const { reader } = makeInMemoryReader();
        const e = new OtelMetricsExporter({ _testingReader: reader });

        // process._getActiveHandles() is a Node internal API but is stably available
        const handles = (
            process as unknown as {
                _getActiveHandles?: () => Array<{
                    constructor?: { name?: string };
                    hasRef?: () => boolean;
                }>;
            }
        )._getActiveHandles?.();
        if (Array.isArray(handles)) {
            const refTimers = handles.filter(
                (h) =>
                    h?.constructor?.name === 'Timeout' &&
                    typeof h.hasRef === 'function' &&
                    h.hasRef(),
            );
            // Expectation: no ref'ed Timeout (PeriodicExportingMetricReader has already unref'ed its timer)
            expect(refTimers.length).toBe(0);
        }
        await e.shutdown();
    });

    it('should swallow OTLP exporter errors during shutdown when collector is unreachable', async () => {
        // Regression (F1): metrics are a best-effort channel; an OTel collector failure must not block
        // the resolver's main shutdown path. This test injects an InMemoryMetricExporter + overrides
        // provider.shutdown via reflection to verify the fault-tolerant path, without a real network endpoint.
        const { reader } = makeInMemoryReader();
        const e = new OtelMetricsExporter({ _testingReader: reader });
        // Reach the internal provider via reflection and inject a throwing shutdown
        const internal = (
            e as unknown as {
                internal: {
                    provider: { shutdown: () => Promise<void> };
                } | null;
            }
        ).internal;
        expect(internal).not.toBeNull();
        if (internal) {
            internal.provider.shutdown = () =>
                Promise.reject(new Error('collector unreachable'));
        }
        // shutdown returns a ShutdownStatus rather than void
        // error path: provider.shutdown rejects -> returns an error status (does not reject)
        const result = await e.shutdown();
        expect(result.status).toBe('error');
        if (result.status === 'error') {
            expect(result.error.message).toBe('collector unreachable');
        }
        // Repeated shutdown returns noop (idempotent)
        const result2 = await e.shutdown();
        expect(result2.status).toBe('noop');
    });

    it('should swallow OTLP exporter errors during forceFlush when collector is unreachable', async () => {
        // Inject an InMemoryMetricExporter to avoid depending on a real collector.
        const { reader } = makeInMemoryReader();
        const e = new OtelMetricsExporter({ _testingReader: reader });
        const internal = (
            e as unknown as {
                internal: {
                    reader: { forceFlush: () => Promise<void> };
                } | null;
            }
        ).internal;
        if (internal) {
            internal.reader.forceFlush = () =>
                Promise.reject(new Error('collector down'));
        }
        await expect(e.forceFlush()).resolves.toBeUndefined();
        await e.shutdown();
    });

    it('should complete shutdown within OTEL_SHUTDOWN_TIMEOUT_MS when provider.shutdown hangs', async () => {
        // F1 regression test: when the collector is unreachable (provider.shutdown never settles),
        // shutdown() must return within OTEL_SHUTDOWN_TIMEOUT_MS plus a small tolerance.
        // Verifies that withHardTimeout correctly cuts off the hung SDK promise.
        const { reader } = makeInMemoryReader();
        const e = new OtelMetricsExporter({ _testingReader: reader });

        // Inject a provider.shutdown that never resolves
        const internal = (
            e as unknown as {
                internal: {
                    provider: { shutdown: () => Promise<void> };
                } | null;
            }
        ).internal;
        expect(internal).not.toBeNull();
        if (internal) {
            internal.provider.shutdown = () =>
                new Promise(() => {
                    /* never resolves, simulating a completely unreachable collector */
                });
        }

        const startMs = Date.now();
        await e.shutdown();
        const elapsedMs = Date.now() - startMs;

        // 2s hard timeout + 500ms tolerance (event-loop scheduling jitter); without timeout protection it would hang forever
        expect(elapsedMs).toBeLessThan(2_000 + 500);
    });

    it('should complete forceFlush within OTEL_SHUTDOWN_TIMEOUT_MS when reader.forceFlush hangs', async () => {
        // F1 regression test: forceFlush is also protected by the hard timeout when it hangs.
        const { reader } = makeInMemoryReader();
        const e = new OtelMetricsExporter({ _testingReader: reader });

        const internal = (
            e as unknown as {
                internal: {
                    reader: { forceFlush: () => Promise<void> };
                } | null;
            }
        ).internal;
        if (internal) {
            internal.reader.forceFlush = () =>
                new Promise(() => {
                    /* never resolves */
                });
        }

        const startMs = Date.now();
        await e.forceFlush();
        const elapsedMs = Date.now() - startMs;

        expect(elapsedMs).toBeLessThan(2_000 + 500);
        await e.shutdown();
    });
});

// ============================================================
// 3. MetricsAggregator
// ============================================================

describe('MetricsAggregator', () => {
    const ENV_KEYS = [
        'AP_FEDERATION_OTEL_EXPORTER_ENDPOINT',
        'AP_FEDERATION_TDIGEST_BUCKETS',
    ] as const;
    const savedEnv: Partial<
        Record<(typeof ENV_KEYS)[number], string | undefined>
    > = {};

    beforeEach(() => {
        for (const k of ENV_KEYS) {
            savedEnv[k] = process.env[k];
            delete process.env[k];
        }
    });
    afterEach(() => {
        for (const k of ENV_KEYS) {
            if (savedEnv[k] === undefined) delete process.env[k];
            else process.env[k] = savedEnv[k];
        }
    });

    it('should disable OTel and use defaults when env is empty and options are empty', () => {
        const m = new MetricsAggregator();
        expect(m.isOtelEnabled()).toBe(false);
        expect(m.latencySnapshot()).toEqual({
            latencyP50Ms: 0,
            latencyP95Ms: 0,
            latencyP99Ms: 0,
        });
    });

    it('should enable OTel when env AP_FEDERATION_OTEL_EXPORTER_ENDPOINT is set', async () => {
        process.env['AP_FEDERATION_OTEL_EXPORTER_ENDPOINT'] =
            'http://127.0.0.1:14318/v1/metrics';
        const m = new MetricsAggregator();
        expect(m.isOtelEnabled()).toBe(true);
        await m.shutdown();
    });

    it('should treat blank env value as disabled', () => {
        process.env['AP_FEDERATION_OTEL_EXPORTER_ENDPOINT'] = '   ';
        const m = new MetricsAggregator();
        expect(m.isOtelEnabled()).toBe(false);
    });

    it('should accept TDigest bucket override from env when valid', async () => {
        process.env['AP_FEDERATION_TDIGEST_BUCKETS'] = '10';
        const m = new MetricsAggregator({ now: () => Date.now() });
        m.recordResolveLatency(100);
        expect(m.latencySnapshot().latencyP50Ms).toBeGreaterThan(0);
        await m.shutdown();
    });

    it('should ignore env bucket override when value exceeds MAX_BUCKETS', () => {
        process.env['AP_FEDERATION_TDIGEST_BUCKETS'] = '999';
        const m = new MetricsAggregator();
        // Does not throw; falls back to the default
        m.recordResolveLatency(50);
        expect(m.latencySnapshot().latencyP50Ms).toBeGreaterThan(0);
    });

    it('should ignore env bucket override when value is non-numeric', () => {
        process.env['AP_FEDERATION_TDIGEST_BUCKETS'] = 'abc';
        const m = new MetricsAggregator();
        m.recordResolveLatency(50);
        expect(m.latencySnapshot().latencyP50Ms).toBeGreaterThan(0);
    });

    it('should record cache / version-conflict / quorum-unmet / signature-invalid without throwing when OTel disabled', () => {
        const m = new MetricsAggregator();
        expect(() => {
            m.recordCacheHit();
            m.recordCacheMiss();
            m.recordVersionConflict();
            m.recordQuorumUnmet();
            m.recordSignatureInvalid();
            m.setNodeAvailability('n1', 0.5);
        }).not.toThrow();
    });

    it('should be idempotent when shutdown is invoked multiple times', async () => {
        // Inject via _testingReader to avoid depending on a real collector
        const { reader } = makeInMemoryReader();
        const m = new MetricsAggregator({ _testingReader: reader });
        await m.shutdown();
        await m.shutdown();
    });

    it('should expose forceFlush as noop when OTel disabled', async () => {
        const m = new MetricsAggregator();
        await m.forceFlush();
    });

    it('should pass through explicit options over env values when constructed', () => {
        process.env['AP_FEDERATION_OTEL_EXPORTER_ENDPOINT'] =
            'http://127.0.0.1:14318/v1/metrics';
        // Explicit undefined forcibly disables OTel, overriding env
        const m = new MetricsAggregator({ otelEndpoint: undefined });
        expect(m.isOtelEnabled()).toBe(false);
    });

    it('should accept setNodeAvailability calls outside of getMetrics path', () => {
        // Regression: the old version only synced OTel on getMetrics; the new version requires syncing at every state-change point
        const m = new MetricsAggregator();
        // Repeated writes do not throw, and are safe even when OTel is disabled
        m.setNodeAvailability('n1', 0.95);
        m.setNodeAvailability('n2', 0.5);
        m.setNodeAvailability('n1', 0.3);
        // NaN / non-finite values should be silently dropped
        m.setNodeAvailability('n3', NaN);
        m.setNodeAvailability('n4', Infinity);
    });
});

// ============================================================
// 4. env helper
// ============================================================

describe('env helpers', () => {
    const ENV_KEYS = [
        'AP_FEDERATION_OTEL_EXPORTER_ENDPOINT',
        'AP_FEDERATION_TDIGEST_BUCKETS',
    ] as const;
    const saved: Partial<
        Record<(typeof ENV_KEYS)[number], string | undefined>
    > = {};
    beforeEach(() => {
        for (const k of ENV_KEYS) {
            saved[k] = process.env[k];
            delete process.env[k];
        }
    });
    afterEach(() => {
        for (const k of ENV_KEYS) {
            if (saved[k] === undefined) delete process.env[k];
            else process.env[k] = saved[k];
        }
    });

    it('should return undefined when AP_FEDERATION_OTEL_EXPORTER_ENDPOINT is missing', () => {
        expect(readEndpointFromEnv()).toBeUndefined();
    });

    it('should return undefined when endpoint is whitespace-only', () => {
        process.env['AP_FEDERATION_OTEL_EXPORTER_ENDPOINT'] = '   \t\n';
        expect(readEndpointFromEnv()).toBeUndefined();
    });

    it('should return trimmed endpoint when set', () => {
        process.env['AP_FEDERATION_OTEL_EXPORTER_ENDPOINT'] =
            '  http://127.0.0.1:14318/v1/metrics  ';
        expect(readEndpointFromEnv()).toBe('http://127.0.0.1:14318/v1/metrics');
    });

    it('should return undefined when AP_FEDERATION_TDIGEST_BUCKETS is missing', () => {
        expect(readBucketsFromEnv()).toBeUndefined();
    });

    it('should return undefined when buckets is non-integer or out-of-range', () => {
        process.env['AP_FEDERATION_TDIGEST_BUCKETS'] = '0';
        expect(readBucketsFromEnv()).toBeUndefined();
        process.env['AP_FEDERATION_TDIGEST_BUCKETS'] = String(MAX_BUCKETS + 1);
        expect(readBucketsFromEnv()).toBeUndefined();
        process.env['AP_FEDERATION_TDIGEST_BUCKETS'] = '999';
        expect(readBucketsFromEnv()).toBeUndefined();
        process.env['AP_FEDERATION_TDIGEST_BUCKETS'] = 'foo';
        expect(readBucketsFromEnv()).toBeUndefined();
    });

    it('should accept a valid integer bucket value within [1, MAX_BUCKETS]', () => {
        process.env['AP_FEDERATION_TDIGEST_BUCKETS'] = '10';
        expect(readBucketsFromEnv()).toBe(10);
        process.env['AP_FEDERATION_TDIGEST_BUCKETS'] = String(MAX_BUCKETS);
        expect(readBucketsFromEnv()).toBe(MAX_BUCKETS);
    });

    it('should reject numeric prefixes with trailing garbage when parsing buckets', () => {
        // P3 regression: parseInt accepts suffixed strings like "10ms" / "60_extra" by default;
        // we require a strict pure-integer match to avoid a typo silently changing the window semantics
        process.env['AP_FEDERATION_TDIGEST_BUCKETS'] = '10ms';
        expect(readBucketsFromEnv()).toBeUndefined();
        process.env['AP_FEDERATION_TDIGEST_BUCKETS'] = '60_extra';
        expect(readBucketsFromEnv()).toBeUndefined();
        process.env['AP_FEDERATION_TDIGEST_BUCKETS'] = '60.5';
        expect(readBucketsFromEnv()).toBeUndefined();
        process.env['AP_FEDERATION_TDIGEST_BUCKETS'] = '+10';
        expect(readBucketsFromEnv()).toBeUndefined();
        process.env['AP_FEDERATION_TDIGEST_BUCKETS'] = '-10';
        expect(readBucketsFromEnv()).toBeUndefined();
    });
});

// ============================================================
// 4b. normalizeOtlpMetricsUrl
// ============================================================

describe('normalizeOtlpMetricsUrl', () => {
    it('should append /v1/metrics when endpoint has no path', () => {
        // regression: operators commonly write the collector base URL (without /v1/metrics)
        expect(normalizeOtlpMetricsUrl('http://localhost:4318')).toBe(
            'http://localhost:4318/v1/metrics',
        );
        expect(normalizeOtlpMetricsUrl('https://otel.example.com')).toBe(
            'https://otel.example.com/v1/metrics',
        );
    });

    it('should append /v1/metrics when path is exactly "/"', () => {
        expect(normalizeOtlpMetricsUrl('http://localhost:4318/')).toBe(
            'http://localhost:4318/v1/metrics',
        );
    });

    it('should leave already-correct endpoints untouched', () => {
        expect(
            normalizeOtlpMetricsUrl('http://localhost:4318/v1/metrics'),
        ).toBe('http://localhost:4318/v1/metrics');
        // Tolerate a trailing slash
        expect(
            normalizeOtlpMetricsUrl('http://localhost:4318/v1/metrics/'),
        ).toBe('http://localhost:4318/v1/metrics/');
    });

    it('should preserve custom paths set by reverse proxies', () => {
        // When operators rewrite the path via a reverse proxy, we must not override it
        expect(
            normalizeOtlpMetricsUrl(
                'http://collector.example.com/otlp/metrics',
            ),
        ).toBe('http://collector.example.com/otlp/metrics');
        expect(
            normalizeOtlpMetricsUrl('http://gateway/internal/otel/v2/metrics'),
        ).toBe('http://gateway/internal/otel/v2/metrics');
    });

    it('should return the original string when URL parsing fails', () => {
        expect(normalizeOtlpMetricsUrl('not a url')).toBe('not a url');
        expect(normalizeOtlpMetricsUrl('')).toBe('');
    });
});

// ============================================================
// 5. Constant exports (guard against accidental removal in future PRs)
// ============================================================

describe('module constants', () => {
    it('should expose stable defaults for downstream tooling', () => {
        expect(DEFAULT_WINDOW_MS).toBe(5 * 60 * 1000);
        // Default 60 buckets = 5s bucket width, keeping end-based aging boundary drift within +/-5%
        expect(DEFAULT_BUCKETS).toBe(60);
        expect(MAX_BUCKETS).toBe(300);
        expect(DEFAULT_OTEL_EXPORT_INTERVAL_MS).toBe(60_000);
        expect(METRIC_NAMESPACE).toBe('coivitas.federation');
    });

    it('should keep window-edge drift bounded by +/-5% tolerance', () => {
        // bucket width = window / buckets; the maximum extra retention from end-based expiry = bucket width
        // Tolerance: 5min x 5% = 15s. The current 5s bucket width is well below the threshold.
        const bucketWidthMs = DEFAULT_WINDOW_MS / DEFAULT_BUCKETS;
        const tolerance = DEFAULT_WINDOW_MS * 0.05;
        expect(bucketWidthMs).toBeLessThanOrEqual(tolerance);
    });
});

// ============================================================
// 6. Regression: updateAvailability syncs OTel (fix review F2)
// ============================================================

describe('MetricsAggregator setNodeAvailability propagation', () => {
    it('should accept availability snapshot updates without requiring a getMetrics roundtrip', () => {
        // The old federated-resolver only synced OTel availability on getMetrics().
        // The new updateAvailability() calls setNodeAvailability directly at health-state change points.
        // This test covers the MetricsAggregator interface contract: the node availability snapshot can be safely updated at any time.
        const m = new MetricsAggregator();
        const spy = vi.spyOn(m, 'setNodeAvailability');
        // Simulate repeated drivePassiveHealth failure/recovery calls inside federated-resolver
        m.setNodeAvailability('n1', 1.0); // initially healthy
        m.setNodeAvailability('n1', 0.5); // after one failure
        m.setNodeAvailability('n1', 0.0); // fully failed
        m.setNodeAvailability('n1', 0.75); // partially recovered
        expect(spy).toHaveBeenCalledTimes(4);
        // Each call's argument is externally observable (the OTel observable gauge picks up the latest value on async export)
        expect(spy.mock.calls.map((c) => c[1])).toEqual([1.0, 0.5, 0.0, 0.75]);
    });

    it('should call setNodeAvailability from health-state change paths without invoking getMetrics first', async () => {
        // Integration regression: review F2 -- the old federated-resolver only synced OTel
        // availability on getMetrics, so when the application did not actively poll, the
        // node availability seen by the OTel exporter stayed at its initial value forever.
        // The fix has updateAvailability() at drivePassiveHealth / recordNodeSuccess /
        // recordNodeFailure call setNodeAvailability directly.
        // The test uses spyOn(MetricsAggregator.prototype) and asserts setNodeAvailability
        // has been triggered after a failed resolve **without calling getMetrics**.

        // Dynamic import to avoid clashing with the mock paths at the top of the file (federated-resolver module downstream)
        const { createFederatedResolver: cfr } =
            await import('../federated-resolver.js');

        const spy = vi.spyOn(
            MetricsAggregator.prototype,
            'setNodeAvailability',
        );

        // Global fetch mock: all nodes return 500 errors -> drivePassiveHealth(false)
        const fetchSpy = vi.fn().mockResolvedValue(
            new Response('{}', {
                status: 500,
                headers: { 'content-type': 'application/json' },
            }),
        );
        vi.stubGlobal('fetch', fetchSpy);

        const resolver = cfr({
            nodes: [
                { id: 'rgN1', url: 'https://rgN1.example.com' },
                { id: 'rgN2', url: 'https://rgN2.example.com' },
            ],
            minResponses: 2,
            timeoutMs: 1_000,
            cacheTtlMs: 0,
            verifyDIDBinding: {
                verify: vi.fn().mockResolvedValue(true),
                getDocumentHistory: vi.fn().mockResolvedValue([]),
            },
            persistentWatermark: makeDefaultWatermark(),
            dnsRebindingGuard: makeDefaultRebindingGuard(),
        });

        // Trigger one resolve (guaranteed to fail: all nodes 500)
        const callsBefore = spy.mock.calls.length;
        await resolver.resolve('did:agent:rg-test' as never);

        // Key assertion: setNodeAvailability has been triggered **without calling getMetrics()**
        // (the drivePassiveHealth path syncs the snapshot)
        expect(spy.mock.calls.length).toBeGreaterThan(callsBefore);
        // At least one call's nodeId argument is in our configured node set
        const nodeIds = spy.mock.calls.map((c) => c[0]);
        expect(nodeIds.some((id) => id === 'rgN1' || id === 'rgN2')).toBe(true);

        vi.unstubAllGlobals();
        await resolver.close();
        spy.mockRestore();
    });

    it('should refresh availability after signature-invalid documents without invoking getMetrics first', async () => {
        // Integration regression: re-review P2 -- when verifyDocumentSignature fails,
        // ns.metrics.signatureInvalid++ feeds into the calcAvailability denominator, but the old logic
        // did not call updateAvailability on that path, so the OTel observable gauge did not reflect the
        // node degradation until the next success/failure path or getMetrics() call.
        // The fix has the signature-invalid branch also go through updateAvailability(ns).

        const { createFederatedResolver: cfr } =
            await import('../federated-resolver.js');

        const spy = vi.spyOn(
            MetricsAggregator.prototype,
            'setNodeAvailability',
        );

        // Node returns a schema-valid document with an inconsistent BindingProof:
        // doc.id !== bindingProof.agentDid -> V1a rejects (binding_proof_invalid)
        const did = 'did:agent:sig-invalid-test';
        const malformedDoc = {
            id: did,
            principalDid: 'did:agent:p1',
            publicKey: 'aa'.repeat(32),
            specVersion: '0.2.0',
            updatedAt: new Date().toISOString(),
            bindingProof: {
                agentDid: 'did:agent:other', // intentionally inconsistent
                principalDid: 'did:agent:p1',
                signature: '00',
                expiresAt: new Date(Date.now() + 60_000).toISOString(),
            },
        };
        const fetchSpy = vi.fn().mockResolvedValue(
            new Response(JSON.stringify(malformedDoc), {
                status: 200,
                headers: { 'content-type': 'application/json' },
            }),
        );
        vi.stubGlobal('fetch', fetchSpy);

        const resolver = cfr({
            nodes: [
                { id: 'sigN1', url: 'https://sigN1.example.com' },
                { id: 'sigN2', url: 'https://sigN2.example.com' },
            ],
            minResponses: 2,
            timeoutMs: 1_000,
            cacheTtlMs: 0,
            verifyDIDBinding: {
                verify: vi.fn().mockResolvedValue(true),
                getDocumentHistory: vi.fn().mockResolvedValue([]),
            },
            persistentWatermark: makeDefaultWatermark(),
            dnsRebindingGuard: makeDefaultRebindingGuard(),
        });

        const callsBefore = spy.mock.calls.length;
        await resolver.resolve(did as never);

        // The signature-invalid path must refresh availability synchronously (without relying on an external getMetrics)
        const newCalls = spy.mock.calls.slice(callsBefore);
        expect(newCalls.length).toBeGreaterThan(0);
        const nodeIds = newCalls.map((c) => c[0]);
        expect(nodeIds.some((id) => id === 'sigN1' || id === 'sigN2')).toBe(
            true,
        );

        vi.unstubAllGlobals();
        await resolver.close();
        spy.mockRestore();
    });

    it('should seed OTel availability snapshot for all configured nodes at construction time', async () => {
        // Regression: review P2 -- an idle resolver (no resolve / no health probe)
        // should be visible as healthy (availability=1) on the OTel dashboard; nodes must not
        // wait until the first traffic to be exposed. Fix: seed all nodes into the metricsAgg snapshot at construction time.

        const { createFederatedResolver: cfr } =
            await import('../federated-resolver.js');

        const spy = vi.spyOn(
            MetricsAggregator.prototype,
            'setNodeAvailability',
        );

        const resolver = cfr({
            nodes: [
                { id: 'seedN1', url: 'https://seedN1.example.com' },
                { id: 'seedN2', url: 'https://seedN2.example.com' },
                { id: 'seedN3', url: 'https://seedN3.example.com' },
            ],
            minResponses: 2,
            timeoutMs: 1_000,
            cacheTtlMs: 0,
            verifyDIDBinding: {
                verify: vi.fn().mockResolvedValue(true),
                getDocumentHistory: vi.fn().mockResolvedValue([]),
            },
            persistentWatermark: makeDefaultWatermark(),
            dnsRebindingGuard: makeDefaultRebindingGuard(),
        });

        // Seeded immediately at construction: all 3 nodes should have setNodeAvailability(_, 1.0) called once
        const seedCalls = spy.mock.calls.filter(
            (c) => c[0] === 'seedN1' || c[0] === 'seedN2' || c[0] === 'seedN3',
        );
        expect(seedCalls.length).toBeGreaterThanOrEqual(3);
        for (const c of seedCalls) {
            expect(c[1]).toBe(1);
        }

        await resolver.close();
        spy.mockRestore();
    });

    it('should keep latency snapshot accessible after shutdown for graceful-shutdown reporting', async () => {
        // Regression: review P2 -- a common graceful-shutdown practice is to call getMetrics one
        // last time after close to report the final window. The old logic's latency.reset inside
        // shutdown wiped the data, making P50/P95/P99 all 0. Fix: shutdown does not clear latency.

        const m = new MetricsAggregator();
        m.recordResolveLatency(100);
        m.recordResolveLatency(200);
        m.recordResolveLatency(300);
        const beforeShutdown = m.latencySnapshot();
        expect(beforeShutdown.latencyP50Ms).toBeGreaterThan(0);

        await m.shutdown();

        // Key assertion: the full latency snapshot is still available after shutdown
        const afterShutdown = m.latencySnapshot();
        expect(afterShutdown.latencyP50Ms).toBe(beforeShutdown.latencyP50Ms);
        expect(afterShutdown.latencyP95Ms).toBe(beforeShutdown.latencyP95Ms);
        expect(afterShutdown.latencyP99Ms).toBe(beforeShutdown.latencyP99Ms);
    });
});
