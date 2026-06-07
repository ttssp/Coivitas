/**
 * tenant-scoped audit hook implementation
 *
 * Responsibilities:
 *   - TenantAuditEvent: audit event (must include tenantId + actorDid + action + resource + timestamp)
 *   - TenantAuditHook: pre/post-call hook; automatically injects tenantId into the audit event
 *   - TenantAuditFilter: filters audit-query results by tenantId; prevents cross-tenant audit leakage
 *
 * Design constraints (fail-closed + audit invariant):
 *   - an audit event must include tenantId; missing tenantId -> fail-closed (TenantAuditFailedError)
 *   - an audit query must filter by tenantId; a cross-tenant query -> TenantAuditCrossLeakError
 *   - missing TenantContext -> fail-closed (tenant-less audit events are not allowed)
 *   - audit hook failure -> fail-closed (TENANT_AUDIT_FAILED; silently continuing is not allowed)
 *
 */

import type { DID, Timestamp } from '@coivitas/types';
import type { TenantContext, TenantId } from './types.js';
import { validateTenantContext } from './tenant-resolver.js';

// ── TenantAuditEvent ──────────────────────────────────────────────────────────

/**
 * tenant-scoped audit event (invariant: must include tenantId)
 *
 * Conclusion: every audit event must carry a tenantId;
 * every audit query must filter by tenantId (to prevent cross-tenant data leakage).
 */
export interface TenantAuditEvent {
    /** Event ID (UUID v4; globally unique) */
    readonly eventId: string;

    /**
     * Tenant ID (required; invariant: missing tenantId -> the audit event is invalid)
     *
     * Conclusion: TenantAuditEvent.tenantId is the core field for isolation;
     * every audit query must filter on this field.
     */
    readonly tenantId: TenantId;

    /** DID of the actor that initiated the operation (may be undefined for internal system operations) */
    readonly actorDid?: DID;

    /**
     * Operation type (e.g. 'key-custody.sign' / 'tenant.create' / 'rate-limit.check')
     */
    readonly action: string;

    /**
     * Target resource of the operation (e.g. key ID / tenant path / policy ID)
     * undefined indicates an operation that involves no specific resource (e.g. login / health check)
     */
    readonly resource?: string;

    /**
     * Operation outcome
     *   - 'success': the operation completed successfully
     *   - 'denied': the operation was denied (insufficient permissions / rate limit, etc.)
     *   - 'error': the operation was aborted due to an error
     */
    readonly outcome: 'success' | 'denied' | 'error';

    /** Event timestamp (ISO 8601; UTC) */
    readonly timestamp: Timestamp;

    /**
     * Additional context (passed through transparently; contains no security-sensitive information)
     */
    readonly context?: Record<string, string>;

    /**
     * Digital signature of the audit event (from the key-custody KMS; undefined = unsigned)
     * Signing audit events is recommended in production to prevent tampering.
     */
    readonly signature?: string;

    /** Key ID used for signing */
    readonly signingKeyId?: string;
}

// ── TenantAuditHook ───────────────────────────────────────────────────────────

/**
 * TenantAuditHook: pre/post-call hook definition
 *
 * pre-call hook: invoked before the operation runs (injects tenantId; fail-closed on missing TenantContext)
 * post-call hook: invoked after the operation runs (injects tenantId + outcome; fail-closed on missing TenantContext)
 *
 * Conclusion: a hook pattern is used instead of a decorator to support functional composition;
 * the two-phase hook allows recording the operation's duration and outcome.
 */
export interface TenantAuditHook {
    /**
     * pre-call hook: invoked before the operation runs
     *
     * @param ctx TenantContext (required; undefined -> fail-closed)
     * @param action operation type
     * @param resource target resource of the operation (optional)
     * @throws TenantContextMissingError if ctx is undefined
     * @throws TenantAuditFailedError if the audit event fails to be written
     */
    preCall(
        ctx: TenantContext | undefined,
        action: string,
        resource?: string,
    ): Promise<TenantAuditEvent>;

    /**
     * post-call hook: invoked after the operation runs
     *
     * @param ctx TenantContext (required; undefined -> fail-closed)
     * @param action operation type
     * @param outcome operation outcome
     * @param resource target resource of the operation (optional)
     * @param additionalContext additional context (optional)
     * @throws TenantContextMissingError if ctx is undefined
     * @throws TenantAuditFailedError if the audit event fails to be written
     */
    postCall(
        ctx: TenantContext | undefined,
        action: string,
        outcome: 'success' | 'denied' | 'error',
        resource?: string,
        additionalContext?: Record<string, string>,
    ): Promise<TenantAuditEvent>;
}

// ── TenantAuditFilter ─────────────────────────────────────────────────────────

/**
 * TenantAuditFilter: filters audit-query results by tenantId
 *
 * Conclusion: every audit query must go through this filter;
 * a query without a tenantId condition is rejected (to prevent cross-tenant data leakage).
 */
export interface TenantAuditFilter {
    /**
     * Filter audit events (a tenantId must be provided; otherwise fail-closed)
     *
     * @param events the raw list of audit events
     * @param tenantId filter condition (required; undefined -> TenantAuditCrossLeakError)
     * @returns the audit events belonging only to that tenant
     * @throws TenantAuditCrossLeakError if tenantId is not provided
     */
    filter(events: readonly TenantAuditEvent[], tenantId: TenantId | undefined): TenantAuditEvent[];

    /**
     * Validate that the query contains a tenantId filter condition
     *
     * @throws TenantAuditCrossLeakError if the query lacks a tenantId condition
     */
    validateQuery(query: AuditQuery): void;
}

/**
 * Audit query type (simplified)
 */
export interface AuditQuery {
    /** tenantId filter condition (must be provided; otherwise the cross-leak guard triggers) */
    readonly tenantId?: TenantId;
    /** Time-range filter (startTs / endTs; optional) */
    readonly startTs?: Timestamp;
    readonly endTs?: Timestamp;
    /** action-type filter (optional) */
    readonly action?: string;
    /** Pagination (optional) */
    readonly limit?: number;
    readonly offset?: number;
}

// ── Error types ───────────────────────────────────────────────────────────────

/**
 * TenantAuditFailedError: the audit event failed to be written (fail-closed)
 */
export class TenantAuditFailedError extends Error {
    readonly code = 'TENANT_AUDIT_FAILED' as const;

    constructor(
        public readonly tenantId: TenantId,
        cause: unknown,
    ) {
        super(
            `Audit event write failed for tenant "${tenantId}". ` +
            'Request aborted (fail-closed). ' +
            `Cause: ${cause instanceof Error ? cause.message : String(cause)}`,
        );
        this.name = 'TenantAuditFailedError';
        Object.setPrototypeOf(this, new.target.prototype);
    }
}

/**
 * TenantAuditCrossLeakError: the audit query is missing a tenantId filter condition
 *
 * Triggered when: an audit query has no tenantId condition (risk of cross-tenant data leakage).
 * Handling strategy: fail-closed; refuse to execute this query.
 */
export class TenantAuditCrossLeakError extends Error {
    readonly code = 'TENANT_UNAUTHORIZED' as const;

    constructor(message = 'Audit query must include a tenantId filter to prevent cross-tenant data leakage.') {
        super(message);
        this.name = 'TenantAuditCrossLeakError';
        Object.setPrototypeOf(this, new.target.prototype);
    }
}

// ── InMemoryTenantAuditHook ───────────────────────────────────────────────────

/**
 * InMemoryTenantAuditHook: in-memory audit-hook implementation
 *
 * Conclusion: production-grade in-memory implementation; suitable for tests + single-instance deployments;
 * production should replace it with a DB-write implementation (writing to the policy.audit_events table).
 *
 * Invariants (literal):
 *   - every audit event must include tenantId (asserted in createAuditEvent)
 *   - missing TenantContext -> fail-closed (TenantContextMissingError)
 *   - write failure -> fail-closed (TenantAuditFailedError)
 */
export class InMemoryTenantAuditHook implements TenantAuditHook {
    /** tenant-scoped audit-event store (key = tenantId) */
    private readonly tenantAuditEvents: Map<TenantId, TenantAuditEvent[]> = new Map();

    /**
     * pre-call hook: record the audit event before the operation runs
     */
    preCall(
        ctx: TenantContext | undefined,
        action: string,
        resource?: string,
    ): Promise<TenantAuditEvent> {
        try {
            // fail-closed on missing TenantContext
            validateTenantContext(ctx, `audit.preCall(${action})`);
        } catch (err) {
            return Promise.reject(err as Error);
        }

        const event = createAuditEvent({
            tenantId: ctx.tenantId,
            actorDid: ctx.actorDid,
            action: `${action}.pre`,
            resource,
            outcome: 'success',
        });

        this.appendEvent(ctx.tenantId, event);
        return Promise.resolve(event);
    }

    /**
     * post-call hook: record the audit event after the operation runs (includes outcome)
     */
    postCall(
        ctx: TenantContext | undefined,
        action: string,
        outcome: 'success' | 'denied' | 'error',
        resource?: string,
        additionalContext?: Record<string, string>,
    ): Promise<TenantAuditEvent> {
        try {
            // fail-closed on missing TenantContext
            validateTenantContext(ctx, `audit.postCall(${action})`);
        } catch (err) {
            return Promise.reject(err as Error);
        }

        const event = createAuditEvent({
            tenantId: ctx.tenantId,
            actorDid: ctx.actorDid,
            action: `${action}.post`,
            resource,
            outcome,
            context: additionalContext,
        });

        this.appendEvent(ctx.tenantId, event);
        return Promise.resolve(event);
    }

    /**
     * Get all audit events for a tenant (only the events belonging to that tenantId)
     *
     * Note: must be filtered through TenantAuditFilter; this method is for internal tests only.
     */
    getEventsForTenant(tenantId: TenantId): readonly TenantAuditEvent[] {
        return this.tenantAuditEvents.get(tenantId) ?? [];
    }

    /**
     * Clear all audit events for a tenant (tests only)
     */
    clearEventsForTenant(tenantId: TenantId): void {
        this.tenantAuditEvents.delete(tenantId);
    }

    /**
     * Internal: write an audit event (fail-closed)
     */
    private appendEvent(tenantId: TenantId, event: TenantAuditEvent): void {
        // Invariant: an audit event must include tenantId (already guaranteed by createAuditEvent)
        if (!event.tenantId) {
            throw new TenantAuditFailedError(
                tenantId,
                new Error('INVARIANT VIOLATION: audit event missing tenantId'),
            );
        }
        // Isolation assertion: event.tenantId must equal the passed-in tenantId (prevents cross-tenant writes)
        if (event.tenantId !== tenantId) {
            throw new TenantAuditFailedError(
                tenantId,
                new Error(
                    `INVARIANT VIOLATION: audit event tenantId mismatch. ` +
                    `Expected "${tenantId}", got "${event.tenantId}".`,
                ),
            );
        }

        let events = this.tenantAuditEvents.get(tenantId);
        if (!events) {
            events = [];
            this.tenantAuditEvents.set(tenantId, events);
        }
        events.push(event);
    }
}

// ── InMemoryTenantAuditFilter ─────────────────────────────────────────────────

/**
 * InMemoryTenantAuditFilter: filters audit-query results by tenantId
 *
 * Invariants:
 *   - filter() requires a tenantId; undefined -> TenantAuditCrossLeakError (fail-closed)
 *   - validateQuery() checks whether the query contains a tenantId condition
 */
export class InMemoryTenantAuditFilter implements TenantAuditFilter {
    /**
     * Filter audit events (tenant-scoped; fail-closed on missing tenantId)
     */
    filter(
        events: readonly TenantAuditEvent[],
        tenantId: TenantId | undefined,
    ): TenantAuditEvent[] {
        // missing tenantId -> fail-closed (cross-tenant leak guard)
        if (tenantId === undefined || tenantId === null) {
            throw new TenantAuditCrossLeakError();
        }
        return events.filter(e => e.tenantId === tenantId);
    }

    /**
     * Validate that the audit query contains a tenantId filter condition
     */
    validateQuery(query: AuditQuery): void {
        if (!query.tenantId) {
            throw new TenantAuditCrossLeakError(
                'AuditQuery must include a tenantId filter. ' +
                'Queries without tenantId are rejected to prevent cross-tenant data leakage.',
            );
        }
    }
}

// ── createAuditEvent factory function ─────────────────────────────────────────

/**
 * Create a TenantAuditEvent (invariant: must include tenantId; brand cast forbidden)
 *
 * Conclusion: the only way to create a TenantAuditEvent;
 * asserts that tenantId is non-empty at construction time (fail-closed).
 */
function createAuditEvent(params: {
    tenantId: TenantId;
    actorDid?: DID;
    action: string;
    resource?: string;
    outcome: 'success' | 'denied' | 'error';
    context?: Record<string, string>;
}): TenantAuditEvent {
    // Invariant assertion: tenantId must be present (fail-closed)
    if (!params.tenantId || typeof params.tenantId !== 'string') {
        throw new Error(
            'INVARIANT VIOLATION: TenantAuditEvent.tenantId must be a non-empty string. ' +
            'All audit events must be tenant-scoped.',
        );
    }

    return {
        eventId: generateEventId(),
        tenantId: params.tenantId,
        actorDid: params.actorDid,
        action: params.action,
        resource: params.resource,
        outcome: params.outcome,
        timestamp: new Date().toISOString() as Timestamp,
        context: params.context,
    };
}

/**
 * Generate a unique event ID (crypto.randomUUID, or a fallback)
 */
function generateEventId(): string {
    if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
        return crypto.randomUUID();
    }
    // Fallback: pseudo-random (only for test environments without crypto.randomUUID)
    return `evt-${Date.now()}-${Math.random().toString(36).slice(2)}`;
}
