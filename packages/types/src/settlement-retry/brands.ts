/**
 * Settlement Retry (SR) sub-protocol v0.1 — brand types, constants, factory functions
 *
 * Triple line of defense (reuses the csp pattern):
 *   Layer 1 (this file): TypeScript brand type — compile-time guard
 *   Layer 2 (schemas.ts): JSON Schema strict — runtime Schema layer
 *   Layer 3 (settlement-retry.ts L3): AJV strict mode 4 flags — runtime Schema engine layer
 *
 * Guard: every brand type can only be obtained through a to*() factory function;
 *           direct casts such as `'1.0.0' as SrVersion` are strictly forbidden.
 *
 * Error-code namespace (SR_* prefix; 14 items frozen in v0.1):
 *   orthogonal to CSP_* / RFP_* / DELEGATION_* / ATP_* / HCC_* / MS_* / CCR_* / CR_* / TB_*
 *
 * Quantity constraints:
 *   MAX_RETRY_ATTEMPTS = 3
 *   DEAD_LETTER_THRESHOLD = 5 (DEAD_LETTER threshold)
 *
 * Design decisions:
 *   - SHA-256(JCS) idempotency key — collision-resistant, no symmetric key
 *   - exponential backoff + random jitter — avoids the thundering-herd effect
 *   - DEAD_LETTER triggers enqueue into the manual-review queue
 *   - strict allowlist state transitions (finite state machine)
 *   - independent srVersion namespace (orthogonal to existing sub-protocols)
 */

// ─── Protocol-level constants ────────────────────

/**
 * Maximum number of retries
 *
 * Reaching this count triggers SR_RETRY_EXHAUSTED → transition to the DEAD_LETTER state.
 * Enforced at L3 executeSettlementRetry step 7.
 */
export const MAX_RETRY_ATTEMPTS = 3;

/**
 * DEAD_LETTER state threshold (consecutive failures beyond this value become non-retryable)
 */
export const DEAD_LETTER_THRESHOLD = 5;

/**
 * Set of versions supported by SR (v0.1 only value "1.0.0")
 *
 * Independent srVersion namespace; not coupled to cspVersion.
 */
export const SR_SUPPORTED_VERSIONS: readonly string[] = ['1.0.0'] as const;

/**
 * SR v0.1 current version
 */
export const SR_VERSION_CURRENT = '1.0.0' as const;

// ─── Brand Types (Layer 1 of defense; compile-time guard) ───────────────────────────────────────

/**
 * SrVersion — SR protocol version brand type (independent namespace)
 *
 * factory: toSrVersion().
 * v0.1 only legal value: "1.0.0"
 * Direct `as SrVersion` casts are not allowed.
 */
export type SrVersion = string & {
    readonly __brand: 'SrVersion';
};

/**
 * SR_VERSION_1_0_0 — v0.1 version constant (constructed via the factory to guarantee brand validity)
 *
 * Constructed through the toSrVersion() factory rather than a `'1.0.0' as SrVersion` cast,
 * keeping it consistent with the "no direct as SrVersion cast" convention and eliminating a rule exception.
 */
export const SR_VERSION_1_0_0: SrVersion = toSrVersion('1.0.0');

/**
 * OperationId — unique identifier of a settlement operation (UUID v4 brand)
 *
 * factory: toOperationId().
 * Direct `as OperationId` casts are not allowed.
 */
export type OperationId = string & {
    readonly __brand: 'OperationId';
};

/**
 * SrTenantId — multi-tenant isolation identifier (UUID v4 brand)
 *
 * Independently named to avoid clashing with the atp TenantId type.
 * factory: toSrTenantId().
 */
export type SrTenantId = string & {
    readonly __brand: 'SrTenantId';
};

/**
 * RetryAttemptId — unique identifier of a single retry record (UUID v4 brand)
 *
 * factory: toRetryAttemptId().
 * Direct `as RetryAttemptId` casts are not allowed.
 */
export type RetryAttemptId = string & {
    readonly __brand: 'RetryAttemptId';
};

/**
 * IdempotencyKey — SHA-256(JCS) hex string brand
 *
 * Format: 64 lowercase hex chars.
 * factory: toIdempotencyKey().
 * Direct `as IdempotencyKey` casts are not allowed.
 */
export type IdempotencyKey = string & {
    readonly __brand: 'IdempotencyKey';
};

/**
 * Currency — ISO 4217 three-letter uppercase currency code brand
 *
 * factory: toCurrency().
 * e.g. "USD", "EUR", "CNY"
 */
export type Currency = string & {
    readonly __brand: 'Currency';
};

/**
 * Amount — integer amount in minimum units brand (bigint-safe integer ≥ 1)
 *
 * Expressed in the smallest currency unit (e.g. cents).
 * factory: toAmount().
 */
export type Amount = number & {
    readonly __brand: 'Amount';
};

// ─── Factory Functions (guards; the only legal path for a brand cast) ──────────────────

/**
 * toSrVersion — SrVersion brand type factory function
 *
 * The only legal path to obtain an SrVersion; validates semver format + the set of legal values at runtime.
 * v0.1 only legal value: "1.0.0"
 *
 * @throws Error SR_VERSION_UNSUPPORTED if the format or version is non-compliant
 */
export function toSrVersion(s: string): SrVersion {
    if (!/^[0-9]+\.[0-9]+\.[0-9]+$/.test(s)) {
        throw new Error(
            `SR_VERSION_UNSUPPORTED: not valid semver (X.Y.Z): "${s}"`,
        );
    }
    if (!SR_SUPPORTED_VERSIONS.includes(s)) {
        throw new Error(
            `SR_VERSION_UNSUPPORTED: unsupported srVersion "${s}"; supported: ${SR_SUPPORTED_VERSIONS.join(', ')}`,
        );
    }
    return s as SrVersion;
}

/**
 * toOperationId — OperationId brand type factory function
 *
 * The only legal path to obtain an OperationId; validates UUID v4 format at runtime.
 *
 * @throws Error SR_SCHEMA_VIOLATION if the format is non-compliant
 */
export function toOperationId(s: string): OperationId {
    if (
        !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
            s,
        )
    ) {
        throw new Error(
            `SR_SCHEMA_VIOLATION: not valid UUID v4 for OperationId: "${s}"`,
        );
    }
    return s.toLowerCase() as OperationId;
}

/**
 * toSrTenantId — SrTenantId brand type factory function
 *
 * The only legal path to obtain an SrTenantId; validates UUID v4 format at runtime.
 *
 * @throws Error SR_SCHEMA_VIOLATION if the format is non-compliant
 */
export function toSrTenantId(s: string): SrTenantId {
    if (
        !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
            s,
        )
    ) {
        throw new Error(
            `SR_SCHEMA_VIOLATION: not valid UUID v4 for SrTenantId: "${s}"`,
        );
    }
    return s.toLowerCase() as SrTenantId;
}

/**
 * toRetryAttemptId — RetryAttemptId brand type factory function
 *
 * The only legal path to obtain a RetryAttemptId; validates UUID v4 format at runtime.
 *
 * @throws Error SR_SCHEMA_VIOLATION if the format is non-compliant
 */
export function toRetryAttemptId(s: string): RetryAttemptId {
    if (
        !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
            s,
        )
    ) {
        throw new Error(
            `SR_SCHEMA_VIOLATION: not valid UUID v4 for RetryAttemptId: "${s}"`,
        );
    }
    return s.toLowerCase() as RetryAttemptId;
}

/**
 * toIdempotencyKey — IdempotencyKey brand type factory function
 *
 * The only legal path to obtain an IdempotencyKey; validates the 64 lowercase hex format at runtime.
 * The actual key is generated by computeIdempotencyKey() at L3 (SHA-256 + JCS).
 *
 * @throws Error SR_SCHEMA_VIOLATION if the format is non-compliant
 */
export function toIdempotencyKey(s: string): IdempotencyKey {
    if (!/^[0-9a-f]{64}$/.test(s)) {
        throw new Error(
            `SR_SCHEMA_VIOLATION: IdempotencyKey must be 64 lowercase hex chars, got: "${s}"`,
        );
    }
    return s as IdempotencyKey;
}

/**
 * toCurrency — Currency brand type factory function
 *
 * The only legal path to obtain a Currency; validates ISO 4217 three-letter uppercase.
 *
 * @throws Error SR_SCHEMA_VIOLATION if the format is non-compliant
 */
export function toCurrency(s: string): Currency {
    if (!/^[A-Z]{3}$/.test(s)) {
        throw new Error(
            `SR_SCHEMA_VIOLATION: Currency must be 3 uppercase ASCII letters (ISO 4217): "${s}"`,
        );
    }
    return s as Currency;
}

/**
 * toAmount — Amount brand type factory function
 *
 * The only legal path to obtain an Amount; validates a positive integer in minimum units.
 *
 * @throws Error SR_SCHEMA_VIOLATION if the value is non-compliant
 */
export function toAmount(n: number): Amount {
    if (!Number.isInteger(n) || n < 1) {
        throw new Error(
            `SR_SCHEMA_VIOLATION: Amount must be a positive integer (≥ 1): ${n}`,
        );
    }
    if (!Number.isSafeInteger(n)) {
        throw new Error(
            `SR_SCHEMA_VIOLATION: Amount ${n} exceeds safe integer range`,
        );
    }
    return n as Amount;
}
