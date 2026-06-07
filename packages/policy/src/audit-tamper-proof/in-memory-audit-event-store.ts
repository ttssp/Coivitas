/**
 * atp v0.1 L3 InMemoryAuditEventStore — @internal test stub
 *
 * audit-tamper-proof v0.1 L3 implementation
 *
 * For unit / integration tests only; production must implement PostgresAuditEventStore (026 migration +
 * SERIALIZABLE transaction + pg_advisory_xact_lock + ROW LEVEL SECURITY policy).
 *
 * 5 negative-case defenses enforced (a test stub must honor them strictly too):
 *   - fail-closed: insertEvent failure throws AuditError(AUDIT_FAIL_CLOSED); does not stub success
 *   - no brand cast: input event fields are all brand types; raw strings not accepted
 *   - top-level import canonicalize: this store never calls canonicalize directly (isolation layer; writer/verifier call it)
 *   - does not modify any EnvelopeLedger / audit-share pipeline
 *   - partial-PASS: no intermediate ok:true with warnings state
 *
 * Anti hard-delete guard:
 *   - this store exposes no deleteEvent / dropChain API (audit immutability);
 *   - production PostgresAuditEventStore enforces it via the 026 migration ON DELETE RESTRICT;
 *   - tenant hard-delete always fails (RESTRICT + event immutability; forbidden in atp v0.1).
 */

import type {
    AuditClass,
    AuditEvent,
    AuditEventHash,
    AuditEventId,
    TenantId,
} from '@coivitas/types';
import { AuditError } from '@coivitas/types';

import type { AuditEventStore } from './tamper-proof-audit-writer.js';

/**
 * InMemoryAuditEventStore — @internal test stub
 *
 * Data structures:
 *   - events: Map<eventId, AuditEvent> (primary store; id → event)
 *   - chainsByTenantClass: Map<"tenantId:auditClass", AuditEventId[]> (chain order; append only)
 *   - locks: Map<"tenantId:auditClass", Promise<void>> (advisory-lock queue simulation; sequential acquire)
 *
 * Lock-simulation semantics:
 *   acquireAdvisoryLock keeps the "previous lock-release Promise" in an in-memory Map;
 *   subsequent acquires wait for the prior release; this simulates PostgreSQL pg_advisory_xact_lock serialization semantics.
 *   Test callers must call releaseAdvisoryLock in a try/finally (test convenience method).
 */
export class InMemoryAuditEventStore implements AuditEventStore {
    private readonly events = new Map<string, AuditEvent>();
    private readonly chainsByTenantClass = new Map<string, AuditEventId[]>();
    private readonly lockHolders = new Map<
        string,
        { resolve: () => void; promise: Promise<void> } | null
    >();

    /**
     * acquireAdvisoryLock — simulates pg_advisory_xact_lock per-(tenantId, audit_class)
     *
     * The 1st caller resolves immediately; the 2nd+ caller waits for the previous release.
     * Test callers must call releaseAdvisoryLock after the writer flow ends (commit / rollback).
     */
    public async acquireAdvisoryLock(
        tenantId: TenantId,
        auditClass: AuditClass,
    ): Promise<void> {
        const key = `${tenantId}:${auditClass}`;
        const existingHolder = this.lockHolders.get(key);
        if (existingHolder !== undefined && existingHolder !== null) {
            // wait for the previous holder to release
            await existingHolder.promise;
        }
        // create a new holder
        let resolveFn!: () => void;
        const promise = new Promise<void>((resolve) => {
            resolveFn = resolve;
        });
        this.lockHolders.set(key, { resolve: resolveFn, promise });
    }

    /**
     * releaseAdvisoryLock — test helper; call release after the writer flow ends
     *
     * Production PostgresAuditEventStore releases automatically via transaction COMMIT / ROLLBACK;
     * the in-memory stub requires the caller to call it explicitly.
     */
    public releaseAdvisoryLock(
        tenantId: TenantId,
        auditClass: AuditClass,
    ): void {
        const key = `${tenantId}:${auditClass}`;
        const holder = this.lockHolders.get(key);
        if (holder !== undefined && holder !== null) {
            holder.resolve();
            this.lockHolders.set(key, null);
        }
    }

    /**
     * fetchLastTamperProofHash — latest tamperProofHash per-(tenantId, audit_class)
     *
     * eslint-disable-next-line @typescript-eslint/require-await (in-memory stub takes a synchronous path;
     * production PostgresAuditEventStore is async; the interface signature Promise<...> mandates await compatibility)
     */
    // eslint-disable-next-line @typescript-eslint/require-await
    public async fetchLastTamperProofHash(
        tenantId: TenantId,
        auditClass: AuditClass,
    ): Promise<AuditEventHash | null> {
        const key = `${tenantId}:${auditClass}`;
        const chain = this.chainsByTenantClass.get(key);
        if (chain === undefined || chain.length === 0) {
            return null; // GENESIS
        }
        const lastEventId = chain[chain.length - 1];
        /* v8 ignore next 8*/
        if (lastEventId === undefined) {
            throw new AuditError(
                'AUDIT_FETCH_LAST_HASH_FAILED',
                'chain index out of bounds (impossible path)',
                { tenantId, auditClass, chainLength: chain.length },
            );
        }
        const ev = this.events.get(lastEventId);
        /* v8 ignore next 8*/
        if (ev === undefined) {
            throw new AuditError(
                'AUDIT_FETCH_LAST_HASH_FAILED',
                `chain references unknown eventId="${lastEventId}" (storage state inconsistent)`,
                { tenantId, auditClass, lastEventId },
            );
        }
        return ev.tamperProofHash;
    }

    /**
     * insertEvent — append event to chain (atomic boundary; fail-closed negative-case defense)
     *
     * Strict negative-case defense: a duplicate eventId throws AuditError(AUDIT_FAIL_CLOSED);
     * anti hard-delete guard: no DELETE API exposed; chain append-only.
     */
    // eslint-disable-next-line @typescript-eslint/require-await
    public async insertEvent(event: AuditEvent): Promise<void> {
        if (this.events.has(event.eventId)) {
            throw new AuditError(
                'AUDIT_FAIL_CLOSED',
                `duplicate eventId="${event.eventId}" (insert reject;append-only)`,
                { eventId: event.eventId },
            );
        }
        this.events.set(event.eventId, event);
        const key = `${event.tenantId}:${event.auditClass}`;
        const chain = this.chainsByTenantClass.get(key) ?? [];
        chain.push(event.eventId);
        this.chainsByTenantClass.set(key, chain);
    }

    /**
     * fetchAllEvents — full chain per-(tenantId, audit_class) (GENESIS first; ASC by insert order)
     *
     * cross-tenant / cross-class fetch is strictly forbidden (multi-tenant isolation enforced);
     * returns only events within the (tenantId, audit_class) scope.
     */
    // eslint-disable-next-line @typescript-eslint/require-await
    public async fetchAllEvents(
        tenantId: TenantId,
        auditClass: AuditClass,
    ): Promise<readonly AuditEvent[]> {
        const key = `${tenantId}:${auditClass}`;
        const chain = this.chainsByTenantClass.get(key) ?? [];
        const result: AuditEvent[] = [];
        for (const eventId of chain) {
            const ev = this.events.get(eventId);
            /* v8 ignore next 8*/
            if (ev === undefined) {
                throw new AuditError(
                    'AUDIT_REVERSE_REPLAY_FAILED',
                    `chain references unknown eventId="${eventId}" (storage state inconsistent)`,
                    { tenantId, auditClass, eventId },
                );
            }
            result.push(ev);
        }
        return result;
    }

    /**
     * fetchEventById — single event fetch with tenantId scope (multi-tenant isolation enforced)
     *
     * tenantId mismatch → returns null (the caller takes the AUDIT_TENANT_SCOPE_VIOLATION path);
     * does not throw (an empty result is itself the fail-closed signal).
     */
    // eslint-disable-next-line @typescript-eslint/require-await
    public async fetchEventById(
        eventId: AuditEventId,
        tenantId: TenantId,
    ): Promise<AuditEvent | null> {
        const ev = this.events.get(eventId);
        if (ev === undefined) {
            return null;
        }
        if (ev.tenantId !== tenantId) {
            // cross-tenant query: treated as not found (multi-tenant isolation enforced);
            // the caller takes the AUDIT_TENANT_SCOPE_VIOLATION path
            return null;
        }
        return ev;
    }

    /**
     * _testForceCorruptEvent — TEST ONLY: simulates a DBA tampering with tamperProofHash;
     * used to test the reverse hash-chain replay guard (the AUDIT_TAMPER_DETECTED path).
     *
     * Must never be called by production code; strict negative-case defense: this function only exposes test-scenario tampered-event injection.
     */
    public _testForceCorruptEvent(
        eventId: AuditEventId,
        corruptedHash: AuditEventHash,
    ): void {
        const ev = this.events.get(eventId);
        if (ev === undefined) {
            throw new Error(
                `_testForceCorruptEvent: eventId="${eventId}" not found`,
            );
        }
        // directly replace the hash (simulates DBA UPDATE managed_service.audit_events SET tamper_proof_hash = '...')
        const corrupted: AuditEvent = {
            ...ev,
            tamperProofHash: corruptedHash,
        };
        this.events.set(eventId, corrupted);
    }

    /**
     * _testForceCorruptPreviousHash — TEST ONLY: simulates a DBA tampering with previousHash;
     * used to test the hash-chain BROKEN guard (the AUDIT_HASH_CHAIN_BROKEN path).
     */
    public _testForceCorruptPreviousHash(
        eventId: AuditEventId,
        corruptedPreviousHash: AuditEventHash | null,
    ): void {
        const ev = this.events.get(eventId);
        if (ev === undefined) {
            throw new Error(
                `_testForceCorruptPreviousHash: eventId="${eventId}" not found`,
            );
        }
        const corrupted: AuditEvent = {
            ...ev,
            previousHash: corruptedPreviousHash,
        };
        this.events.set(eventId, corrupted);
    }
}
