/**
 * Audit Tamper-Proof (atp) v0.1 L3 module exports
 *
 * Priority 4 sub-protocol
 *
 * L3 implementation (packages/policy/src/audit-tamper-proof/):
 *   - canonicalize-audit-payload.ts: the only legal entry point for RFC 8785 JCS canonicalize
 *   - build-tamper-proof-hash-input.ts: shared hash-input construction helper (used by both writer and verifier;
 * all 10 fields bound; asymmetry defense)
 *   - multi-tenant-resolver.ts: caller principal → tenant mapping + scope assert
 *   - tamper-proof-audit-writer.ts: writeAuditEvent fail-closed pipeline
 *   - tamper-proof-audit-verifier.ts: verifyAuditEvent reverse hash chain replay
 *   - in-memory-audit-event-store.ts: @internal test stub (production uses PostgresAuditEventStore)
 *
 * 5 negative-case defenses honored strictly:
 *   - fail-closed: any AuditError throw → caller transaction ROLLBACK
 *   - no brand cast: input fields are all L0 brands; raw strings not accepted
 *   - top-level import canonicalize: the canonicalizeAuditPayload module imports @coivitas/crypto at top level
 *   - does not modify the audit-share / audit-access / EnvelopeLedger pipeline
 *   - partial-PASS: ACCEPTED-only verification primitive; all 17 handleAuditError cases are fatal
 */

export { canonicalizeAuditPayload } from './canonicalize-audit-payload.js';
export {
    buildTamperProofHashInput,
    type TamperProofHashInputFields,
} from './build-tamper-proof-hash-input.js';
export {
    InMemoryTenantResolver,
    assertDbRoleMatchesAuditClass,
    assertTenantScope,
    type CallerPrincipal,
    type TenantResolver,
} from './multi-tenant-resolver.js';
export {
    TamperProofAuditWriter,
    type AuditEventStore,
    type WriteAuditEventInput,
    type WriteAuditEventOptions,
} from './tamper-proof-audit-writer.js';
export {
    TamperProofAuditVerifier,
    type VerifyAuditEventOptions,
    type VerifyAuditEventResult,
} from './tamper-proof-audit-verifier.js';
export { InMemoryAuditEventStore } from './in-memory-audit-event-store.js';
