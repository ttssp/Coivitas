/**
 * Canonical Signed Payload (csp) v0.1 — L1 crypto layer types (single source for error codes + L1 import)
 *
 * Single source for the error-code union, avoiding a same-name/different-meaning dual source:
 *   - authoritative source of the 13-code CspErrorCode union: packages/types/src/canonical-signed-payload/types.ts
 *   - L1 does not inline-redefine error codes; it uniformly imports the 13 L0 codes (CSP_PAYLOAD_INCOMPLETE /
 *     CSP_SCHEMA_VIOLATION / CSP_CANONICALIZE_MISMATCH, etc.);
 *   - the error-code namespace is frozen and enforced.
 */

// single-source import for error codes (no inline redefinition at L1)
export type { CspErrorCode } from '@coivitas/types';
import type { CspErrorCode } from '@coivitas/types';

/**
 * CspError — CSP L1 crypto layer exception class
 *
 * Parallel to `CryptoError` (no inheritance; namespace isolation): CryptoError covers low-level
 * hex/base64url/sig format errors; CspError covers csp protocol layer invariant violations. The
 * error-code namespace isolation contract holds (CSP_* is orthogonal to the existing CryptoError
 * error-code set INVALID_KEY_FORMAT / INVALID_SIGNATURE_FORMAT and the other 9 codes).
 *
 * The code field type CspErrorCode points to the single-source 13-code union.
 */
export class CspError extends Error {
    public override readonly name = 'CspError';
    public readonly code: CspErrorCode;
    public override readonly cause?: Error;

    public constructor(code: CspErrorCode, message: string, cause?: Error) {
        super(message);
        this.code = code;
        this.cause = cause;
    }
}

/**
 * assertNever — exhaustive switch guard
 *
 * Usage: at the default branch of switch (errorCode) → assertNever(errorCode);
 * if the CspErrorCode union gains a new member that the switch does not cover → TypeScript compile-time failure
 * (the never type is not assignable). This is a structural safeguard against unhandled new error codes.
 *
 * Throws use the unified 13-code CSP_SCHEMA_VIOLATION.
 */
export function assertNever(value: never): never {
    throw new CspError(
        'CSP_SCHEMA_VIOLATION',
        `assertNever: unexpected CspErrorCode value (compile-time exhaustive switch escape; phantom enforcement guard): ${String(value)}`,
    );
}
