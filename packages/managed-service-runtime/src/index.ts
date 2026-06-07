/**
 * @coivitas/managed-service-runtime
 *
 * Managed-service runtime (DID resolution + revocation service, free tier + pro tier).
 *
 * Module exports:
 * - auth-middleware : Bearer token authentication + tenant/api_key lookup
 * - rate-limiter : in-memory token bucket (FREE 100/min/IP; PRO 10000/min/key)
 * - usage-recorder : per-day aggregate INCR on managed_service.usage_log
 * - metrics : Prometheus exporter (resolver_* + revocation_*)
 * - resolver-server : Express factory for DID resolver
 * - revocation-server : Express factory for revocation checker (alpha stub)
 *
 */

export type {
    ApiKeyRecord,
    AuthContext,
    AuthenticatedRequest,
    AuthErrorCode,
    Endpoint,
    RateLimitQuota,
    TenantRecord,
    Tier,
} from './types.js';

export {
    createAuthMiddleware,
    computeKeyHash,
    type AuthMiddlewareConfig,
} from './auth-middleware.js';

export {
    createRateLimiter,
    DEFAULT_QUOTAS,
    snapshotBuckets,
    type RateLimiterConfig,
} from './rate-limiter.js';

export {
    UsageRecorder,
    formatBucketDay,
    type UsageRecord,
    type UsageRecorderConfig,
} from './usage-recorder.js';

export {
    createMetrics,
    createMetricsHandler,
    recordResolverRequest,
    recordRevocationCheck,
    statusLabel,
    tenantLabel,
    DEFAULT_DURATION_BUCKETS_MS,
    type CreateMetricsConfig,
    type Metrics,
} from './metrics.js';

export {
    createResolverApp,
    type ResolverServerConfig,
} from './resolver-server.js';

export {
    createRevocationApp,
    type RevocationChecker,
    type RevocationCheckResult,
    type RevocationServerConfig,
} from './revocation-server.js';
