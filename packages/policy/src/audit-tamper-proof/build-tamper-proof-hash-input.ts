/**
 * atp v0.1 L3 buildTamperProofHashInput — shared helper (used by both writer and verifier)
 *
 * Priority 4 sub-protocol — audit-tamper-proof v0.1 L3
 *
 * Hash-input symmetry constraints (writer and verifier share the same construction):
 *   - Full 10-field binding (atpVersion + eventId + tenantId + auditClass + actorDid +
 *     action + target + canonicalPayload + previousHash + timestamp);
 *   - signature + tamperProofHash themselves are excluded from the hash input (signature = output of hash;
 *     tamperProofHash = output of hash);
 *   - GENESIS_MARKER = "0".repeat(64); when previousHash === null the marker is used as a placeholder;
 *   - Writer and verifier must never implement the hash input separately (asymmetry defense; writer writes new + verifier checks old →
 *     100% verify fail OR verifier accepts metadata tampering; the shared helper is mandatory).
 *
 * Pseudocode:
 *   buildTamperProofHashInput(ev) = JCS canonicalize({atpVersion, eventId, tenantId,
 *     auditClass, actorDid, action, target, canonicalPayload,
 *     previousHash: (ev.previousHash || GENESIS_MARKER), timestamp})
 *
 * Negative-case defense (fail-closed):
 *   canonicalize failure → canonicalizeAuditPayload throws AuditError(AUDIT_CANONICALIZE_BYPASS_DETECTED);
 *   this helper does not allow stubbed success / fallback; output must be a string.
 */

import type {
    AuditEvent,
    AuditEventHash,
} from '@coivitas/types';
import { ATP_GENESIS_MARKER } from '@coivitas/types';
import { canonicalizeAuditPayload } from './canonicalize-audit-payload.js';

/**
 * TamperProofHashInputFields — type alias for the buildTamperProofHashInput input subset
 *
 * The full 10 audit-metadata fields; signature + tamperProofHash are excluded (hash output, not input).
 * Used when the writer builds the candidate before the tamperProofHash + signature fields exist.
 */
export type TamperProofHashInputFields = Omit<
    AuditEvent,
    'tamperProofHash' | 'signature'
>;

/**
 * buildTamperProofHashInput — shared hash-input construction helper (used by both writer and verifier)
 *
 * Field-order convention (guaranteed by JCS canonicalize's internal lex sort; listed here for readability):
 *   action / actorDid / atpVersion / auditClass / canonicalPayload /
 *   eventId / previousHash / target / tenantId / timestamp
 *
 * (JCS output is deterministic; field names are lex-sorted; this helper does not rely on a sort-order parameter)
 *
 * @param ev audit event candidate (10 fields required; tamperProofHash + signature excluded)
 * @returns RFC 8785 JCS canonicalize string
 * @throws AuditError(AUDIT_CANONICALIZE_BYPASS_DETECTED) when canonicalize fails
 */
export function buildTamperProofHashInput(
    ev: TamperProofHashInputFields,
): string {
    // previousHash === null → use GENESIS_MARKER as placeholder ("(ev.previousHash || GENESIS_MARKER)")
    const previousHashOrMarker: AuditEventHash | string =
        ev.previousHash ?? ATP_GENESIS_MARKER;

    // All 10 fields bound (signature + tamperProofHash excluded; negative-case defense)
    return canonicalizeAuditPayload({
        atpVersion: ev.atpVersion,
        eventId: ev.eventId,
        tenantId: ev.tenantId,
        auditClass: ev.auditClass,
        actorDid: ev.actorDid,
        action: ev.action,
        target: ev.target,
        canonicalPayload: ev.canonicalPayload,
        previousHash: previousHashOrMarker,
        timestamp: ev.timestamp,
    });
}
