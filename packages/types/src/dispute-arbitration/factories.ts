/**
 * Dispute Arbitration L0 factory functions
 *
 * sub-protocol — dispute-arbitration v0.1
 *
 * Brand-cast guard: the sole construction entry point for brand types; a single cast inside the factory is compliant;
 * direct external casts such as `s as DisputeId` are forbidden.
 *
 * Every factory function performs runtime format validation; invalid format → throw DaError.
 */

import { DaError } from './errors.js';
import type {
    DisputeId,
    DaVersion,
    SettlementOperationId,
    CanonicalHashHex,
} from './types.js';
import { DA_SUPPORTED_VERSIONS, DA_VERSION_CURRENT } from './constants.js';

// ─── UUID v4 format validation ─────────────────────────────────────────────────────────

const UUID_V4_RE =
    /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

// ─── SHA-256 hex format validation ─────────────────────────────────────────────────────

const SHA256_HEX_RE = /^[0-9a-f]{64}$/i;

// ─── Factory functions ─────────────────────────────────────────────────────────────────

/**
 * toDisputeId — DisputeId brand factory
 *
 * Validates UUID v4 format; invalid → DA_FILING_INVALID.
 * The sole compliant construction path (brand cast forbidden).
 */
export function toDisputeId(value: string): DisputeId {
    if (!UUID_V4_RE.test(value)) {
        throw new DaError('DA_FILING_INVALID', {
            reason: 'dispute_id_must_be_uuid_v4',
            value,
        });
    }
    return value as DisputeId;
}

/**
 * toDaVersion — DaVersion brand factory
 *
 * Validates that the version is in the supported list; invalid → DA_VERSION_UNSUPPORTED.
 * The sole compliant construction path (brand cast forbidden).
 */
export function toDaVersion(value: string): DaVersion {
    if (!(DA_SUPPORTED_VERSIONS as readonly string[]).includes(value)) {
        throw new DaError('DA_VERSION_UNSUPPORTED', {
            reason: 'da_version_not_in_supported_list',
            value,
            supported: DA_SUPPORTED_VERSIONS,
        });
    }
    return value as DaVersion;
}

/**
 * toSettlementOperationId — SettlementOperationId brand factory
 *
 * Validates UUID v4 format; invalid → DA_FILING_INVALID.
 * The sole compliant construction path (brand cast forbidden).
 *
 * settlementOperationRef (optional; must be valid when provided).
 */
export function toSettlementOperationId(value: string): SettlementOperationId {
    if (!UUID_V4_RE.test(value)) {
        throw new DaError('DA_FILING_INVALID', {
            reason: 'settlement_operation_id_must_be_uuid_v4',
            value,
        });
    }
    return value as SettlementOperationId;
}

/**
 * toCanonicalHashHex — CanonicalHashHex brand factory
 *
 * Validates 64-character hex format (SHA-256 output); invalid → DA_CANONICAL_HASH_MISMATCH.
 * The sole compliant construction path (brand cast forbidden).
 *
 * SHA-256/JCS canonical hash.
 */
export function toCanonicalHashHex(value: string): CanonicalHashHex {
    if (!SHA256_HEX_RE.test(value)) {
        throw new DaError('DA_CANONICAL_HASH_MISMATCH', {
            reason: 'canonical_hash_must_be_sha256_hex_64',
            value,
        });
    }
    return value as CanonicalHashHex;
}

/**
 * DA_VERSION_1_0_0 — pre-built current-version constant
 *
 * Use the pre-validated constant directly; no need to call toDaVersion() each time.
 * The only valid daVersion value (v0.1 spec frozen).
 */
export const DA_VERSION_1_0_0: DaVersion = DA_VERSION_CURRENT as DaVersion;
