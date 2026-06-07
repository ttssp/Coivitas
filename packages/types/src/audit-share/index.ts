/**
 * audit-share v0.2 sub-protocol — L0 module exports
 *
 * Triple defense:
 *   Layer 1 (types.ts): TypeScript brand type — compile-time guard
 *   Layer 2 (schemas/audit-share-v0.2.schema.json): JSON Schema — runtime schema layer
 *   Layer 3 (audit-share-validation.ts): AJV strict mode 4 flags — runtime schema engine layer
 *
 * Namespace isolation (to avoid colliding with existing audit-access v0.2 types):
 *   The literal `VerifiedAuditRequest` is already taken by the audit-access v0.2 union type
 *   in packages/types/src/audit.ts; this sub-protocol:
 *     - internal type name: `VerifiedAuditRequest` (visible within types.ts)
 *     - public alias: `AuditShareVerifiedRequest` (exported by this index; re-exported by packages/types/src/index.ts)
 */

// only export the public alias + do not export the spec literal `VerifiedAuditRequest` (to avoid colliding with audit.ts)
export {
    // ─── Brand types ─────────────────────────────────────────────
    type AuditKeyId,
    type AuditShareVersion,
    type AuditShareScope,
    type AuditEventField,
    AUDIT_EVENT_FIELDS,
    AUDIT_SHARE_SUPPORTED_VERSIONS,
    AUDIT_SHARE_VERSION_1_0_0,
    AUDIT_SHARE_MIN_VALIDITY_WINDOW_MS,
    // ─── Error code union + class + switch + assertNever ────────
    type AuditShareErrorCode,
    AuditShareError,
    type AuditShareErrorContext,
    handleAuditShareError,
    assertNeverAuditShareCode,
    // ─── Placeholder types (atp/hcc brand pending integration) ────────────────
    // Name collision resolution: HashChainEntry collides with hcc + AuditEvent collides with atp;
    // audit-share renames them to the public aliases AuditShareHashChainEntry / AuditShareEventPayload to avoid this;
    // ParentWitness is an audit-share standalone type (no upstream name clash)
    type HashChainEntry as AuditShareHashChainEntry,
    type AuditEvent as AuditShareEventPayload,
    type ParentWitness,
    // ─── Core types ────────────────────────────────────
    type AuditShareVerifiedRequest,
    type AuditShareEntryWithWitness,
    type AuditShareVerifyResult,
    // ─── Factory functions (brand factory guards) ────────────────────────────
    toAuditKeyId,
    toAuditShareVersion,
    toAuditShareScope,
} from './types.js';

// defense layer 3 AJV strict mode validator
export {
    type AuditShareValidationResult,
    type AuditShareValidationError,
    validateAuditShareRequestSchema,
} from './audit-share-validation.js';
