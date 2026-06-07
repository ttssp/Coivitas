/**
 * Settlement Retry (SR) sub-protocol v0.1 — L3 policy module exports
 *
 * Public surface:
 *   executeSettlementRetry — the 9-step core algorithm (the main L3 implementation)
 *   computeIdempotencyKey — SHA-256(JCS) idempotency key derivation
 *   RetryAttemptWriter — the settlement_retries write port interface (L3 internal; injected via L5 DI)
 *   PgRetryAttemptWriter — PostgreSQL implementation of RetryAttemptWriter (constructed at L5; migration 031)
 *
 * L0 types (brand / error / port / schema / validation) are imported from @coivitas/types;
 * L3 only re-exports function entry points; L3 must not directly new Ajv (L0 <-> L3 dependency-layer inversion guard).
 *
 * persistRetryAttempt is a real-implementation closure; PgRetryAttemptWriter is exposed for L5 DI.
 */

export {
    executeSettlementRetry,
    computeIdempotencyKey,
} from './settlement-retry.js';

export type { RetryAttemptWriter } from './retry-attempt-writer.js';
export { PgRetryAttemptWriter } from './pg-retry-attempt-writer.js';
