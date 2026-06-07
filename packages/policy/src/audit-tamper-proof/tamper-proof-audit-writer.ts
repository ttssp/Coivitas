/**
 * atp v0.1 L3 TamperProofAuditWriter — audit event write (fail-closed + multi-tenant + tamper-proof hash)
 *
 * audit-tamper-proof v0.1 L3 implementation
 *
 * steps 1-7:
 *   1. caller triggers the audit event (within the business transaction boundary)
 *   2. writer builds the AuditEvent candidate (PartialAuditEvent)
 * 3. writer-side advisory lock (per-(tenantId, audit_class); SERIALIZABLE transaction; composite key)
 *      + fetchLastTamperProofHash (latest per-(tenantId, audit_class) hash as previousHash; GENESIS = null)
 *   4. writer-side canonicalize payload (RFC 8785 JCS)
 * 5. writer-side compute tamperProofHash (buildTamperProofHashInput shared helper; all 10 fields bound)
 *   6. writer-side INSERT INTO managed_service.audit_events (atomic boundary; ROLLBACK on failure)
 *   7. writer-side commit transaction (audit write + business transaction atomic as one)
 *
 * 5 counterexample defenses:
 *   - fail-closed: any step failure throws AuditError + transaction ROLLBACK; fail-degraded is not allowed
 *   - no brand cast: input AuditEvent fields pass through both an L0 factory + JSON Schema validate (caller responsibility)
 *   - top-level import canonicalize: the canonicalizeAuditPayload module is imported at the top level (not dynamically inside a function body)
 *   - does not modify any file in the audit-share / audit-access pipeline
 *   - partial-PASS: ACCEPTED-only verification primitive; all 17 handleAuditError entries are fatal
 */

import { hash } from '@coivitas/crypto';
import type {
    AuditAction,
    AuditClass,
    AuditEvent,
    AuditEventHash,
    AuditEventId,
    AtpVersionString,
    DID,
    Signature,
    TenantId,
    Timestamp,
} from '@coivitas/types';
import {
    AuditError,
    ATP_VERSION_CURRENT,
    toAtpVersionString,
    toAuditEventHash,
    toAuditEventId,
    validateAuditEvent,
} from '@coivitas/types';

import { buildTamperProofHashInput } from './build-tamper-proof-hash-input.js';
import { canonicalizeAuditPayload } from './canonicalize-audit-payload.js';
import {
    assertDbRoleMatchesAuditClass,
    assertTenantScope,
    type CallerPrincipal,
    type TenantResolver,
} from './multi-tenant-resolver.js';

/**
 * AuditEventStore — audit event persistence interface (storage port; L3 test / production separation)
 *
 * production implementation PostgresAuditEventStore (026 migration + SERIALIZABLE + advisory lock);
 * test stub InMemoryAuditEventStore (@internal; mocks advisory lock ordering).
 *
 * fail-closed enforcement:
 *   - acquireAdvisoryLock failure → throw AuditError(AUDIT_ADVISORY_LOCK_FAILED) + ROLLBACK
 *   - fetchLastTamperProofHash failure → throw AuditError(AUDIT_FETCH_LAST_HASH_FAILED) + ROLLBACK
 *   - insertEvent failure → throw AuditError(AUDIT_FAIL_CLOSED) + ROLLBACK
 */
export interface AuditEventStore {
    /**
     * acquireAdvisoryLock — per-(tenantId, audit_class) advisory lock acquire
     *
     * behavior:
     *   pg_advisory_xact_lock(hashtext('atp_' || tenantId || '_' || auditClass))
     * within the SERIALIZABLE transaction boundary; composite key
     *
     * @throws AuditError(AUDIT_ADVISORY_LOCK_FAILED) when acquire fails
     */
    acquireAdvisoryLock(
        tenantId: TenantId,
        auditClass: AuditClass,
    ): Promise<void>;

    /**
     * fetchLastTamperProofHash — query the latest per-(tenantId, audit_class) tamperProofHash
     *
     * SQL:
     *   SELECT tamper_proof_hash FROM managed_service.audit_events
     *     WHERE tenant_id = $1 AND audit_class = $2
     *     ORDER BY created_at DESC LIMIT 1
     *
     * cross-tenant chain splicing attack defense:
     *   tenant B's first L1 event previousHash will not link to tenant A's last L1 event (scope isolation)
     *
     * @returns the latest hash or null (GENESIS; the first (tenantId, audit_class) event)
     * @throws AuditError(AUDIT_FETCH_LAST_HASH_FAILED) when the query fails
     */
    fetchLastTamperProofHash(
        tenantId: TenantId,
        auditClass: AuditClass,
    ): Promise<AuditEventHash | null>;

    /**
     * insertEvent — INSERT audit event into managed_service.audit_events (atomic boundary)
     *
     * behavior:
     *   - within the same SERIALIZABLE transaction
     *   - write failure → throw AuditError(AUDIT_FAIL_CLOSED) + business transaction ROLLBACK
     *   - does not introduce an events_dlq async retry path (v0.1 scope; evaluated in v0.2+)
     *
     * @throws AuditError(AUDIT_FAIL_CLOSED) when the INSERT fails
     */
    insertEvent(event: AuditEvent): Promise<void>;

    /**
     * fetchAllEvents — query the full per-(tenantId, audit_class) chain (for verifier-side reverse replay)
     *
     * SQL:
     *   SELECT * FROM managed_service.audit_events
     *     WHERE audit_class = event.auditClass AND tenant_id = event.tenantId
     *     ORDER BY timestamp ASC
     *
     * @returns audit event array in ascending time order (GENESIS first)
     * @throws AuditError(AUDIT_REVERSE_REPLAY_FAILED) when the query fails
     */
    fetchAllEvents(
        tenantId: TenantId,
        auditClass: AuditClass,
    ): Promise<readonly AuditEvent[]>;

    /**
     * fetchEventById — query single event for verify pipeline entry
     *
     * SQL:
     *   SELECT * FROM managed_service.audit_events WHERE event_id = $1 AND tenant_id = $2
     *
     * @returns the event if found; a tenantId mismatch is treated as not found (goes through fail-closed reject)
     */
    fetchEventById(
        eventId: AuditEventId,
        tenantId: TenantId,
    ): Promise<AuditEvent | null>;
}

/**
 * WriteAuditEventInput — writeAuditEvent input parameters (12-field candidate)
 *
 * the caller provides 8 application-layer fields (atpVersion default + tenantId + auditClass + actorDid +
 * action + target + payload + optional signature);
 * eventId / canonicalPayload / tamperProofHash / previousHash / timestamp are computed internally by the writer.
 *
 * fail-closed enforcement (counterexample defense):
 *   missing field / wrong type → throw AUDIT_SCHEMA_VIOLATION at the JSON Schema validate stage.
 */
export interface WriteAuditEventInput {
    /** Optional atpVersion (default ATP_VERSION_CURRENT = "1.0.0")*/
    readonly atpVersion?: AtpVersionString;
    /** Tenant scope (required non-empty; cross-tenant write forbidden)*/
    readonly tenantId: TenantId;
    /** Audit class (per-class independent hash chain)*/
    readonly auditClass: AuditClass;
    /** Actor DID (audit subject)*/
    readonly actorDid: DID;
    /** Audit action (application-layer defined; length [1, 256])*/
    readonly action: AuditAction;
    /** object affected by the audit event (target identifier)*/
    readonly target: string;
    /** application-layer payload (arbitrary JSON; canonicalized via RFC 8785 JCS)*/
    readonly payload: unknown;
    /** Optional Ed25519 signature (second piece of cryptographic tamper-proofing; optional in v0.1)*/
    readonly signature?: Signature | null;
}

/**
 * WriteAuditEventOptions — writeAuditEvent configuration
 */
export interface WriteAuditEventOptions {
    /** caller principal (DID + optional session + optional DB role)*/
    readonly caller: CallerPrincipal;
    /** tenant resolver (production PostgresTenantResolver; test InMemoryTenantResolver)*/
    readonly tenantResolver: TenantResolver;
    /** audit event store (production PostgresAuditEventStore; test InMemoryAuditEventStore)*/
    readonly store: AuditEventStore;
    /** Optional eventId generator (test override; production uses the DB gen_random_uuid return value)*/
    readonly generateEventId?: () => AuditEventId;
    /** Optional timestamp generator (test override; production uses server-side NOW())*/
    readonly generateTimestamp?: () => Timestamp;
}

/**
 * TamperProofAuditWriter — atp v0.1 audit event write core
 *
 * 5 counterexample defenses enforced (inline guards within this class; the caller cannot bypass them):
 *   - fail-closed: any step throwing AuditError triggers a caller-side transaction ROLLBACK
 *   - no brand cast: input fields are all L0 brand types; raw string is not accepted
 *   - top-level import canonicalize: the canonicalizeAuditPayload module is already imported at the top level
 *   - does not modify any audit-share / audit-access pipeline
 *   - partial-PASS: all 17 handleAuditError entries are fatal:true; ACCEPTED-only
 */
export class TamperProofAuditWriter {
    private readonly tenantResolver: TenantResolver;
    private readonly store: AuditEventStore;
    private readonly generateEventId: () => AuditEventId;
    private readonly generateTimestamp: () => Timestamp;

    public constructor(opts: {
        tenantResolver: TenantResolver;
        store: AuditEventStore;
        generateEventId?: () => AuditEventId;
        generateTimestamp?: () => Timestamp;
    }) {
        this.tenantResolver = opts.tenantResolver;
        this.store = opts.store;
        this.generateEventId =
            opts.generateEventId ?? defaultGenerateEventId;
        this.generateTimestamp =
            opts.generateTimestamp ?? defaultGenerateTimestamp;
    }

    /**
     * writeAuditEvent — atp audit event write main entry (step 1-7)
     *
     * full pipeline (fail-closed strictly enforced; any step failure throws + business transaction ROLLBACK):
     *   1. resolve tenant scope (multi-tenant isolation)
     *   2. assert input.tenantId === resolved tenantId
     *   3. assert DB role matches audit_class (skip if dbRole undefined)
     * 4. acquire advisory lock (per-(tenantId, audit_class))
     *   5. fetch last tamperProofHash → previousHash (per-(tenantId, audit_class))
     *   6. canonicalize payload (RFC 8785 JCS)
     *   7. compute tamperProofHash (buildTamperProofHashInput, all 10 fields bound)
     *   8. JSON Schema validate (third defense line, AJV strict; fail-closed fallback)
     *   9. insertEvent (atomic boundary)
     *
     * @returns the complete AuditEvent (returned after insertEvent succeeds)
     * @throws AuditError on any step failure (caller-side transaction ROLLBACK)
     */
    public async writeAuditEvent(
        input: WriteAuditEventInput,
        caller: CallerPrincipal,
    ): Promise<AuditEvent> {
        // step 1: multi-tenant scope resolve
        const resolvedTenant = await this.tenantResolver.resolveCallerTenant(
            caller,
        );

        // step 2: cross-tenant write forbidden
        assertTenantScope(input.tenantId, resolvedTenant);

        // step 3: DB role matches audit_class (skip if dbRole undefined)
        assertDbRoleMatchesAuditClass(caller.dbRole, input.auditClass);

        // step 4: per-(tenantId, audit_class) advisory lock
        await this.store.acquireAdvisoryLock(
            input.tenantId,
            input.auditClass,
        );

        // step 5: fetch last tamperProofHash (per-(tenantId, audit_class) scope)
        // prevHash declared at the top of the lexical scope; not shadowed inside the catch
        let previousHash: AuditEventHash | null;
        try {
            previousHash = await this.store.fetchLastTamperProofHash(
                input.tenantId,
                input.auditClass,
            );
        } catch (err) {
            if (err instanceof AuditError) {
                throw err;
            }
            throw new AuditError(
                'AUDIT_FETCH_LAST_HASH_FAILED',
                `fetchLastTamperProofHash failed (DB unreachable or query timeout): ${
                    err instanceof Error ? err.message : String(err)
                }`,
                { tenantId: input.tenantId, auditClass: input.auditClass },
            );
        }

        // step 6: canonicalize payload (RFC 8785 JCS)
        // canonicalizeAuditPayload failure throws AuditError(AUDIT_CANONICALIZE_BYPASS_DETECTED)
        const canonicalPayload = canonicalizeAuditPayload(input.payload);

        // step 7: build the AuditEvent candidate (10 metadata fields + 2 hash output fields)
        const atpVersion = input.atpVersion ?? toAtpVersionString(ATP_VERSION_CURRENT);
        const eventId = this.generateEventId();
        const timestamp = this.generateTimestamp(); // server-side NOW(); client values not accepted

        const candidateForHash = {
            atpVersion,
            eventId,
            tenantId: input.tenantId,
            auditClass: input.auditClass,
            actorDid: input.actorDid,
            action: input.action,
            target: input.target,
            canonicalPayload,
            previousHash,
            timestamp,
        } as const;

        // step 8: compute tamperProofHash (buildTamperProofHashInput, all 10 fields bound)
        const hashInput = buildTamperProofHashInput(candidateForHash);
        const tamperProofHashHex = hash(hashInput, 'hex');
        const tamperProofHash = toAuditEventHash(tamperProofHashHex);

        // step 9: build the complete AuditEvent
        const event: AuditEvent = {
            ...candidateForHash,
            tamperProofHash,
            signature: input.signature ?? null,
        };

        // step 10: JSON Schema validate (third defense line, AJV strict; fail-closed fallback)
        // counterexample defense strictly enforced: schema validate failure throws AuditError(AUDIT_SCHEMA_VIOLATION)
        const validateResult = validateAuditEvent(event);
        if (!validateResult.valid) {
            const firstErr = validateResult.errors[0];
            throw new AuditError(
                'AUDIT_SCHEMA_VIOLATION',
                `AuditEvent JSON Schema validate failed (third defense line): ${
                    firstErr?.instancePath ?? '/'
                }: ${firstErr?.message ?? 'unknown'}`,
                {
                    instancePath: firstErr?.instancePath,
                    keyword: firstErr?.keyword,
                    errorCount: validateResult.errors.length,
                },
            );
        }

        // step 11: INSERT event (atomic boundary; ROLLBACK on failure)
        try {
            await this.store.insertEvent(event);
        } catch (err) {
            if (err instanceof AuditError) {
                throw err;
            }
            throw new AuditError(
                'AUDIT_FAIL_CLOSED',
                `INSERT audit event failed (business transaction must ROLLBACK): ${
                    err instanceof Error ? err.message : String(err)
                }`,
                {
                    eventId,
                    tenantId: input.tenantId,
                    auditClass: input.auditClass,
                },
            );
        }

        return event;
    }
}

// ─── default ID / timestamp generation (injectable via test override) ────────────────────────

/**
 * defaultGenerateEventId — production-leaning UUID v4 (Node 20+ crypto.randomUUID)
 *
 * production store implementations should use the DB gen_random_uuid() return value;
 * this default is for in-memory tests / dev mode; it does not break the brand type guard.
 */
function defaultGenerateEventId(): AuditEventId {
    // Node 20+ built-in crypto.randomUUID (UUID v4)
    const uuid = globalThis.crypto.randomUUID();
    return toAuditEventId(uuid);
}

/**
 * defaultGenerateTimestamp — server-side NOW() (does not accept client-side forgery)
 */
function defaultGenerateTimestamp(): Timestamp {
    return new Date().toISOString() as Timestamp;
}
