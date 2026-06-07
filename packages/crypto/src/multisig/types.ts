/**
 * Multisig sub-protocol (ms) v0.1 — L1 crypto layer types
 *
 * "Single source of error codes + L1 import" template:
 *   - L0 (@coivitas/types) is the single source for the 14-member MultisigErrorCode union
 *   - L1 must import the type; it must not redefine the union inline / as a partial subset
 *   - L2 e2e cross-package must cover all three cases: L0 schema reject + L1 throw + full-chain PASS
 *
 * Error-code namespaces (isolation contract):
 *   - MultisigError class inheritance + MultisigErrorCode union imported from @coivitas/types (single source, 14 codes)
 *   - Orthogonal to the existing CryptoError class + CryptoErrorCode namespace (INVALID_KEY_FORMAT / ... 9 codes)
 *   - Orthogonal to the CspError class + CspErrorCode namespace (13 codes)
 */

// Single source of error codes import (do not redefine the 14-member union inline at L1)
export type { MultisigErrorCode } from '@coivitas/types';
import type { MultisigErrorCode } from '@coivitas/types';

/**
 * MultisigError — Multisig L1 crypto layer exception class
 *
 * Sits alongside CryptoError / CspError (no inheritance; namespace isolation):
 *   - CryptoError: low-level hex/base64url/sig format errors (9 codes; reuses the existing packages/crypto/src/types.ts)
 *   - CspError: csp protocol layer invariant violations (13 codes; packages/crypto/src/canonical-signed-payload/types.ts)
 *   - MultisigError: ms protocol layer invariant violations (14 codes; this file)
 *
 * Error-code namespace isolation contract (MULTISIG_* is orthogonal to the CSP_* / CryptoError 9-code sets).
 */
export class MultisigError extends Error {
    public override readonly name = 'MultisigError';
    public readonly code: MultisigErrorCode;
    public override readonly cause?: Error;

    /**
     * MultisigError constructor
     *
     * The message prefix is forced to `<code>: <message>` (friendly to vitest `.toThrow(/MULTISIG_X/)`
     * regexes + consistent audit-log routing).
     * Single source of truth: error.message always contains the code prefix; the error.code field keeps the enum type.
     */
    public constructor(code: MultisigErrorCode, message: string, cause?: Error) {
        super(`${code}: ${message}`);
        this.code = code;
        this.cause = cause;
    }
}

/**
 * assertNeverMultisig — exhaustive switch guard
 *
 * Usage: at the end of switch (errorCode), default → assertNeverMultisig(errorCode);
 * if the MultisigErrorCode union gains a new member that the switch does not cover → TypeScript compile-time fail
 * (the never type is not assignable). This is a structural safeguard against forgetting to handle a new error code.
 *
 * Distinction from L0 assertNeverMultisigError:
 *   - L0 assertNeverMultisigError: exhaustive fallback for handleMultisigError in the types layer
 *   - L1 assertNeverMultisig: exhaustive fallback for mapMultisigErrorCodeToMessage in the crypto layer
 *   The two are independent but share the same union (L0 single source of 14 members; switch coverage stays consistent after import)
 */
export function assertNeverMultisig(value: never): never {
    throw new MultisigError(
        'MULTISIG_SCHEMA_VIOLATION',
        `assertNeverMultisig: unexpected MultisigErrorCode value (compile-time exhaustive switch escape; phantom enforcement guard): ${String(value)}`,
    );
}
