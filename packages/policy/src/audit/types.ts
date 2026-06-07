/**
 * Audit access-control types — single-point re-export from @coivitas/types.
 *
 * This file no longer declares types independently; all audit types are exported in sync from the
 * upstream @coivitas/types.
 * History: ActionVocabulary / SignedAuditQuery / VerifiedAuditRequest, etc. were originally
 * redeclared here, and F-C flagged "dual source of truth + a 5-member union split from the upstream
 * 6-member one". This file was changed to a pure re-export.
 */

export type {
    ActionVocabulary,
    AuditQueryParams,
    AuditResourceBinding,
    AuditSnapshotBoundary,
    SignedAuditQuery,
    VerifiedAuditRequest,
    ControlPlaneAuditResolution,
    ControlPlaneRequesterScope,
    AuditAccessErrorCode,
    AuditAccessDecision,
    AuditAccessChecker,
    AuditIdentityResolution,
    IdentityStoreForAudit,
    // types added in v0.2
    AuditProofType,
    DelegatedAuditKey,
    DelegatedAuditKeyResolver,
    AuditEventRecord,
} from '@coivitas/types';
