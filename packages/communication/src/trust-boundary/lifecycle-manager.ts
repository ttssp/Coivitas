/**
 * TrustBoundaryLifecycleManager — L4 communication layer state machine main controller
 *
 * Covers:
 * - the 5-state state machine
 * - enforcement of the 8 legal transition allowlist
 * - the transition flow
 * - fail-closed enforcement of the 12 invariants (I_tb_ver + I1-I10 + I_tb_audit_src)
 * - the 17 TB_* error codes
 *
 * Design principles:
 * - fail-closed: any invariant violation = deny by default (no fail-degraded)
 * - auth/verification primitive: the transition handler strictly follows the allowlist
 * - anti-phantom: the transitionState switch case actively invokes all 8 paths
 * - storage abstraction: this class does not do PostgreSQL row locks directly; the caller
 *   (L5 SDK / handshake middleware) passes in an in-memory storage or injects a PG-backed
 *   implementation (row-level lock to be implemented later)
 *
 * brand cast guard:
 * - direct casts `as TrustBoundaryId` / `as TbVersionString` are not allowed
 * - the factories are the only legal path (toTrustBoundaryId / toTbVersionString)
 *
 * state-machine breaking-change firewall:
 * - emergency_suspended state is a v0.1 placeholder + fail-closed return TB_EMERGENCY_NOT_IMPLEMENTED
 * - multisig + arbitration + emergency suspend are deferred together to a later release
 */

import type { DID, Timestamp } from '@coivitas/types';

import {
    LEGAL_TRANSITIONS,
    TB_DEFAULT_BOUNDS,
    TbProtocolError,
    toTbVersionString,
    toTrustBoundaryId,
    toUuidV4String,
    type BoundaryBindingProof,
    type LeaseExtensionProof,
    type TransitionSource,
    type TrustBoundary,
    type TrustBoundaryAuditEvent,
    type TrustBoundaryEmergencyEvent,
    type TrustBoundaryEmergencyState,
    type TrustBoundaryId,
    type TrustBoundaryLifecycleEvent,
    type TrustBoundaryState,
} from './types.js';

// ─── storage abstraction (row-level lock injected by the caller) ──────────────

/**
 * trust-boundary storage abstraction (local memory or PostgreSQL row lock implementation)
 *
 * The caller passes in an in-memory storage or a PG-backed implementation:
 * - in-memory: test / single-process scenarios (returns a Map row reference)
 * - PG-backed: production scenarios (SELECT ... FOR UPDATE row lock; to be implemented)
 */
export interface TrustBoundaryStorage {
    /** load a boundary (returns undefined if it does not exist) */
    load(id: TrustBoundaryId): Promise<TrustBoundary | undefined>;
    /** save a boundary (insert / update; wrapped in a PG transaction in the real implementation) */
    save(boundary: TrustBoundary): Promise<void>;
    /** write an audit event (uses audit-tamper-proof + csp JCS canonicalization) */
    appendAuditEvent(event: TrustBoundaryAuditEvent): Promise<void>;
}

/**
 * in-memory storage implementation (default for test / single-process scenarios)
 *
 * Note: production scenarios must replace this with a PG-backed implementation (SELECT ... FOR UPDATE row lock).
 */
export class InMemoryTrustBoundaryStorage implements TrustBoundaryStorage {
    private readonly boundaries = new Map<TrustBoundaryId, TrustBoundary>();
    private readonly auditEvents: TrustBoundaryAuditEvent[] = [];

    // eslint-disable-next-line @typescript-eslint/require-await
    async load(id: TrustBoundaryId): Promise<TrustBoundary | undefined> {
        const tb = this.boundaries.get(id);
        // guard against deep mutation affecting the in-memory state
        return tb ? { ...tb } : undefined;
    }

    // eslint-disable-next-line @typescript-eslint/require-await
    async save(boundary: TrustBoundary): Promise<void> {
        this.boundaries.set(boundary.id, { ...boundary });
    }

    // eslint-disable-next-line @typescript-eslint/require-await
    async appendAuditEvent(event: TrustBoundaryAuditEvent): Promise<void> {
        this.auditEvents.push({ ...event });
    }

    /** test helper: read all audit events */
    getAuditEvents(): readonly TrustBoundaryAuditEvent[] {
        return [...this.auditEvents];
    }

    /** test helper: reset */
    clear(): void {
        this.boundaries.clear();
        this.auditEvents.length = 0;
    }
}

// ─── invariant verify helpers ──────────────────────────────────────────────────

/**
 * helper — time-related invariant validation (I5 + I8; depends on a trusted clock)
 *
 * Uses the server-side trusted clock (passed in) rather than Date.now() directly — tests can inject a frozen time.
 */
function nowToIso(now: () => Date): Timestamp {
    return now().toISOString() as Timestamp;
}

function isoToMs(ts: Timestamp): number {
    const ms = Date.parse(ts);
    if (!Number.isFinite(ms)) {
        throw new TbProtocolError(
            'TB_LIFECYCLE_INVALID',
            `timestamp invalid: ${ts}`,
            'I5',
        );
    }
    return ms;
}

// ─── invariant assert (strict fail-closed) ─────────────────────────────

/**
 * assertInvariant — full-field invariant validation of a TrustBoundary (I_tb_ver + I1-I6; runtime fail-closed)
 *
 * Covers:
 * - I_tb_ver: tbVersion semver + v0.1's single '1.0.0'
 * - I1: id UUID v4 (already validated by the brand factory; rechecked here)
 * - I2: principalSide / boundedSide DID brand + not equal
 * - I3: state ∈ the 5 states (discriminated union caught at compile time + rechecked at runtime)
 * - I5: lifecycleWindow notBefore < notAfter
 * - I6: bindingProofId consistent with state (required for active/suspended/revoked/expired; must be undefined for pending)
 *
 * Callers: L4 handshake / envelope receive path / state transition handler
 */
export function assertInvariant(boundary: TrustBoundary): void {
    // I_tb_ver — v0.1's single '1.0.0'; string comparison (the brand factory already enforces semver)
    if ((boundary.tbVersion as string) !== '1.0.0') {
        throw new TbProtocolError(
            'TB_VERSION_UNSUPPORTED',
            `tbVersion ${boundary.tbVersion} not supported (v0.1 only '1.0.0')`,
            'I_tb_ver',
        );
    }

    // I1 — the id brand is already enforced by the toTrustBoundaryId factory on the construction path; recheck the string length here
    if (typeof boundary.id !== 'string' || boundary.id.length === 0) {
        throw new TbProtocolError(
            'TB_ID_INVALID',
            'boundary id missing or empty',
            'I1',
        );
    }

    // I2 — the DID brand is enforced by the types layer; explicitly validate non-self-reference here
    if (boundary.principalSide === boundary.boundedSide) {
        throw new TbProtocolError(
            'TB_PARTY_SELF_REFERENTIAL',
            `principalSide === boundedSide (${boundary.principalSide}) — no self-referential trust`,
            'I2',
        );
    }

    // I3 — validate the 5 states (rechecked at runtime; prevents JSON deserialization from bypassing the TypeScript type)
    const validStates: readonly TrustBoundaryState[] = [
        'pending',
        'active',
        'suspended',
        'revoked',
        'expired',
    ];
    if (!validStates.includes(boundary.state)) {
        throw new TbProtocolError(
            'TB_STATE_INVALID',
            `state ${String(boundary.state)} ∉ {pending, active, suspended, revoked, expired}`,
            'I3',
        );
    }

    // I5 — lifecycleWindow ordering
    const notBeforeMs = isoToMs(boundary.lifecycleWindow.notBefore);
    const notAfterMs = isoToMs(boundary.lifecycleWindow.notAfter);
    if (notBeforeMs >= notAfterMs) {
        throw new TbProtocolError(
            'TB_LIFECYCLE_INVALID',
            `notBefore (${boundary.lifecycleWindow.notBefore}) >= notAfter (${boundary.lifecycleWindow.notAfter})`,
            'I5',
        );
    }

    // I6 — bindingProofId consistent with state
    if (boundary.state === 'pending' && boundary.bindingProofId !== undefined) {
        throw new TbProtocolError(
            'TB_BINDING_PROOF_UNEXPECTED',
            'pending state does not allow bindingProofId (should be undefined)',
            'I6',
        );
    }
    if (
        boundary.state !== 'pending' &&
        (boundary.bindingProofId === undefined || boundary.bindingProofId.length === 0)
    ) {
        throw new TbProtocolError(
            'TB_BINDING_PROOF_MISSING',
            `state ${boundary.state} requires bindingProofId`,
            'I6',
        );
    }
}

// ─── transition legality verify (I4 allowlist enforcement) ────────────────

/**
 * findLegalTransition — look up (from, event, to, transitionSource) in the LEGAL_TRANSITIONS allowlist
 *
 * Note: T6 and T7 share the same (from, event, to) tuple and are distinguished by transitionSource:
 * - T6 → transitionSource ∈ {'client', 'system'}
 * - T7 → transitionSource === 'sweeper'
 *
 * Anti-phantom design: this function + the LEGAL_TRANSITIONS const + the transitionState switch case
 * form three layers of active invocation; not a phantom data structure.
 *
 * Any from-event-to-source combination not in the allowlist = undefined → the caller throws TB_INVALID_TRANSITION.
 */
function findLegalTransition(
    from: TrustBoundaryState,
    event: TrustBoundaryLifecycleEvent | TrustBoundaryEmergencyEvent,
    to: TrustBoundaryState | TrustBoundaryEmergencyState,
    transitionSource: TransitionSource,
):
    | (typeof LEGAL_TRANSITIONS)[number]
    | undefined {
    // for multiple candidates, prefer matching by transitionSource (T6 vs T7 distinction):
    // - sweeper preferentially matches the T7 path
    // - client / system preferentially matches the T6 path
    const candidates = LEGAL_TRANSITIONS.filter(
        (t) => t.from === from && t.event === event && t.to === to,
    );
    if (candidates.length === 0) {
        return undefined;
    }
    if (candidates.length === 1) {
        return candidates[0];
    }
    // T6 (client/system) vs T7 (sweeper) distinction
    if (transitionSource === 'sweeper') {
        return candidates.find((t) => t.id === 'T7') ?? candidates[0];
    }
    return candidates.find((t) => t.id !== 'T7') ?? candidates[0];
}

// ─── verify abstraction (L4 does not do csp Ed25519 directly; injected by the caller) ─────────────────────

/**
 * BoundaryProofVerifier abstraction (L4 does not perform csp Ed25519 verify directly; injected by the caller)
 *
 * Implementation notes:
 * - Once the csp v0.1 L1 implementation is complete, this interface is implemented by the csp verify pipeline
 * - This L4 channel only does transition flow control + invariant enforcement + audit event writing
 * - The actual csp 5-field verify (JCS canonicalize + Ed25519 verify + strict equality of audience / notAfter / challenge) happens at L1
 *
 * Implements steps 8.1-8.6; the L4 channel calls verify() and, upon receiving the verdict, decides commit / reject.
 */
export interface BoundaryProofVerifier {
    /**
     * verify binding proof — the onTrustEstablished transition anchor
     *
     * Returns a verdict { ok: true } meaning the csp 5-field verification passed; { ok: false, code, message } meaning rejected.
     */
    verifyBindingProof(
        proof: BoundaryBindingProof,
        context: {
            readonly expectedAudience: string;
            readonly expectedChallenge: string;
            readonly expectedNotAfter: Timestamp;
        },
    ): Promise<
        | { ok: true }
        | { ok: false; code: 'TB_BOUNDARY_PROOF_VERIFY_FAILED' | 'TB_PAYLOAD_COVERAGE_INSUFFICIENT'; message: string }
    >;

    /** verify lease extension proof — the onLeaseExtended transition anchor */
    verifyLeaseExtensionProof(
        proof: LeaseExtensionProof,
        context: {
            readonly expectedAudience: string;
            readonly expectedChallenge: string;
            readonly expectedNotAfter: Timestamp;
        },
    ): Promise<
        | { ok: true }
        | { ok: false; code: 'TB_BOUNDARY_PROOF_VERIFY_FAILED' | 'TB_PAYLOAD_COVERAGE_INSUFFICIENT'; message: string }
    >;
}

/**
 * stub verifier (test default; declared as a stub — not for production use)
 *
 * Constraint: stub default success is not allowed for envelope / arbitration verification.
 * This stub is only for in-process tests — it returns a deterministic configured verdict (tests must explicitly set the ok field).
 */
export class TestProofVerifier implements BoundaryProofVerifier {
    /** test-controllable: rejects by default */
    public defaultVerdict: { ok: true } | { ok: false; code: 'TB_BOUNDARY_PROOF_VERIFY_FAILED'; message: string } =
        { ok: false, code: 'TB_BOUNDARY_PROOF_VERIFY_FAILED', message: 'TestProofVerifier rejects by default' };

    // eslint-disable-next-line @typescript-eslint/require-await
    async verifyBindingProof(
        _proof: BoundaryBindingProof,
        _context: {
            readonly expectedAudience: string;
            readonly expectedChallenge: string;
            readonly expectedNotAfter: Timestamp;
        },
    ): Promise<
        | { ok: true }
        | { ok: false; code: 'TB_BOUNDARY_PROOF_VERIFY_FAILED' | 'TB_PAYLOAD_COVERAGE_INSUFFICIENT'; message: string }
    > {
        return this.defaultVerdict;
    }

    // eslint-disable-next-line @typescript-eslint/require-await
    async verifyLeaseExtensionProof(
        _proof: LeaseExtensionProof,
        _context: {
            readonly expectedAudience: string;
            readonly expectedChallenge: string;
            readonly expectedNotAfter: Timestamp;
        },
    ): Promise<
        | { ok: true }
        | { ok: false; code: 'TB_BOUNDARY_PROOF_VERIFY_FAILED' | 'TB_PAYLOAD_COVERAGE_INSUFFICIENT'; message: string }
    > {
        return this.defaultVerdict;
    }
}

// ─── TrustBoundaryLifecycleManager main class ─────────────────────────────────

/**
 * TrustBoundaryLifecycleManager — state machine + lifecycle event main controller
 *
 * Required capabilities:
 * - createBoundary (the pending state starting point)
 * - transitionState (8 legal transition allowlist enforcement + I4 fail-closed)
 * - getCurrent (query the current state)
 * - assertInvariant (recheck of all invariants I_tb_ver + I1-I6)
 *
 * Anti-phantom design: the transitionState switch case actively invokes each of the 8 paths
 * - T1 onTrustEstablished: verifyBindingProof + I9 PoP + I7 coverage + I8 expiry
 * - T2 onLeaseExtended: verifyLeaseExtensionProof + I8 expiry
 * - T3 onSuspended: active → suspended; lifecycleWindow unchanged
 * - T4 onResumed: suspended → active; I5 not-expired check
 * - T5 onRevoked: {active, suspended} → revoked; cascading token revocation (hook to be implemented later)
 * - T6 onExpired: client/system actively expired; transitionSource = 'client' OR 'system'
 * - T7 onExpired (auto-sweep): server-side sweeper; transitionSource = 'sweeper'
 * - T8 onEmergencySuspended: state-machine breaking-change firewall; v0.1 placeholder fail-closed return
 */
export class TrustBoundaryLifecycleManager {
    private readonly storage: TrustBoundaryStorage;
    private readonly verifier: BoundaryProofVerifier;
    private readonly now: () => Date;
    private readonly maxLifecycleWindowMs: number;
    private readonly minWindowMs: number;

    constructor(opts: {
        readonly storage: TrustBoundaryStorage;
        readonly verifier: BoundaryProofVerifier;
        readonly now?: () => Date;
        readonly maxLifecycleWindowMs?: number;
        readonly minWindowMs?: number;
    }) {
        this.storage = opts.storage;
        this.verifier = opts.verifier;
        this.now = opts.now ?? (() => new Date());
        this.maxLifecycleWindowMs =
            opts.maxLifecycleWindowMs ?? TB_DEFAULT_BOUNDS.maxLifecycleWindowMs;
        this.minWindowMs = opts.minWindowMs ?? TB_DEFAULT_BOUNDS.minWindowMs;
    }

    /**
     * createBoundary — the tb lifecycle starting point (pending state)
     *
     * Implements steps 1-2:
     * - validate principalSide ≠ boundedSide (I2)
     * - server-enforced lifecycleWindow.notAfter = min(request.notAfter, now + maxLifecycleWindow) (I8)
     * - persist the pending state (I3 + I6 bindingProofId undefined)
     */
    async createBoundary(opts: {
        readonly id: string;
        readonly principalSide: DID;
        readonly boundedSide: DID;
        readonly boundaryScope: readonly string[];
        readonly requestedNotAfter: Timestamp;
    }): Promise<TrustBoundary> {
        const id = toTrustBoundaryId(opts.id);

        // I2 early validation (catch the error before persisting)
        if (opts.principalSide === opts.boundedSide) {
            throw new TbProtocolError(
                'TB_PARTY_SELF_REFERENTIAL',
                `principalSide === boundedSide (${opts.principalSide}) — no self-referential trust`,
                'I2',
            );
        }

        // I8 server-enforced expiry — truncate client requests beyond maxLifecycleWindow
        const nowMs = this.now().getTime();
        const requestedMs = isoToMs(opts.requestedNotAfter);
        const maxAllowedMs = nowMs + this.maxLifecycleWindowMs;
        const serverEnforcedMs = Math.min(requestedMs, maxAllowedMs);

        // I5 lifecycleWindow.notAfter > now + minWindow validation (clock skew protection)
        if (serverEnforcedMs <= nowMs + this.minWindowMs) {
            throw new TbProtocolError(
                'TB_LIFECYCLE_INVALID',
                `serverEnforced notAfter <= now + minWindow (${this.minWindowMs}ms)`,
                'I5',
            );
        }

        const notBefore = nowToIso(this.now);
        const notAfter = new Date(serverEnforcedMs).toISOString() as Timestamp;

        const boundary: TrustBoundary = {
            tbVersion: toTbVersionString('1.0.0'),
            id,
            principalSide: opts.principalSide,
            boundedSide: opts.boundedSide,
            boundaryScope: opts.boundaryScope,
            lifecycleWindow: { notBefore, notAfter },
            state: 'pending',
            stateEnteredAt: notBefore,
            // bindingProofId undefined (pending state I6)
        };

        // recheck all invariants
        assertInvariant(boundary);

        await this.storage.save(boundary);
        return boundary;
    }

    /**
     * getCurrent — query the current state
     *
     * Returns undefined if the boundary does not exist; the caller should throw TB_BOUNDARY_NOT_FOUND.
     */
    async getCurrent(id: TrustBoundaryId): Promise<TrustBoundary | undefined> {
        return this.storage.load(id);
    }

    /**
     * transitionState — the main state transition entry point (8 legal transition switch)
     *
     * Anti-phantom enforcement: every case has an active invocation + a complete verify path.
     * Any illegal transition = TB_INVALID_TRANSITION fail-closed.
     *
     * Implements invariant I4.
     */
    async transitionState(opts: {
        readonly id: TrustBoundaryId;
        readonly event: TrustBoundaryLifecycleEvent | TrustBoundaryEmergencyEvent;
        readonly actorDID: DID;
        readonly transitionSource: TransitionSource;
        /** binding proof — required for T1 onTrustEstablished */
        readonly bindingProof?: BoundaryBindingProof;
        /** lease extension proof — required for T2 onLeaseExtended */
        readonly leaseExtensionProof?: LeaseExtensionProof;
        /** expected newNotAfter for T2 onLeaseExtended (server-enforced) */
        readonly requestedNotAfter?: Timestamp;
        /** expected audience / challenge (verify-time context; required for T1 + T2 + T3 + T4) */
        readonly verifyContext?: {
            readonly expectedAudience: string;
            readonly expectedChallenge: string;
        };
    }): Promise<TrustBoundary> {
        const boundary = await this.storage.load(opts.id);
        if (!boundary) {
            throw new TbProtocolError(
                'TB_BOUNDARY_NOT_FOUND',
                `boundary ${opts.id} does not exist`,
            );
        }

        // T8 state-machine breaking-change firewall — emergency suspend is a fail-closed placeholder in v0.1
        if (opts.event === 'onEmergencySuspended') {
            // do not change storage state; only write the audit event placeholder + throw the fail-closed error
            throw new TbProtocolError(
                'TB_EMERGENCY_NOT_IMPLEMENTED',
                'onEmergencySuspended is a fail-closed placeholder in v0.1; not yet implemented',
                'I10',
            );
        }

        // compute the target state (transition allowlist lookup; anti-phantom switch case covers all paths)
        let toState: TrustBoundaryState;
        switch (opts.event) {
            case 'onTrustEstablished':
                toState = 'active';
                break;
            case 'onLeaseExtended':
                toState = 'active'; // self-loop
                break;
            case 'onSuspended':
                toState = 'suspended';
                break;
            case 'onResumed':
                toState = 'active';
                break;
            case 'onRevoked':
                toState = 'revoked';
                break;
            case 'onExpired':
                toState = 'expired';
                break;
            default: {
                const _exhaustive: never = opts.event;
                throw new TbProtocolError(
                    'TB_INVALID_TRANSITION',
                    `event ${String(_exhaustive)} is not in the legal transition list`,
                    'I4',
                );
            }
        }

        // I4 transition allowlist enforcement (look up the 8 legal transitions + T8 already rejected)
        // multiple candidates (T6/T7) preferentially matched by transitionSource
        const legal = findLegalTransition(
            boundary.state,
            opts.event,
            toState,
            opts.transitionSource,
        );
        if (!legal) {
            throw new TbProtocolError(
                'TB_INVALID_TRANSITION',
                `illegal transition: ${boundary.state} --${opts.event}--> ${toState}`,
                'I4',
            );
        }

        // I_tb_audit_src — transitionSource consistent with the transition kind
        // T1-T6: transitionSource ∈ {'client', 'system'}
        // T7 auto-sweep: transitionSource === 'sweeper'
        if (legal.id === 'T7' && opts.transitionSource !== 'sweeper') {
            throw new TbProtocolError(
                'TB_AUDIT_TRANSITION_SOURCE_INVALID',
                `T7 auto-sweep requires transitionSource = 'sweeper'; got = ${opts.transitionSource}`,
                'I_tb_audit_src',
            );
        }
        if (legal.id !== 'T7' && opts.transitionSource === 'sweeper') {
            throw new TbProtocolError(
                'TB_AUDIT_TRANSITION_SOURCE_INVALID',
                `non-T7 transitions do not allow transitionSource = 'sweeper'; T${legal.id.slice(1)} should be 'client' or 'system'`,
                'I_tb_audit_src',
            );
        }

        // dispatch by transition kind
        const beforeState = boundary.state;
        let nextBindingProofId = boundary.bindingProofId;
        let nextLifecycleWindow = boundary.lifecycleWindow;

        switch (legal.id) {
            case 'T1': {
                // onTrustEstablished — binding proof + I9 PoP + I7 coverage + I8 expiry
                if (!opts.bindingProof) {
                    throw new TbProtocolError(
                        'TB_PRINCIPAL_POP_MISSING',
                        'T1 onTrustEstablished requires bindingProof',
                        'I9',
                    );
                }
                if (!opts.verifyContext) {
                    throw new TbProtocolError(
                        'TB_PAYLOAD_COVERAGE_INSUFFICIENT',
                        'T1 onTrustEstablished requires verifyContext (expectedAudience + expectedChallenge)',
                        'I7',
                    );
                }
                // I7 coverage early validation — boundaryId consistent
                if (opts.bindingProof.boundaryId !== boundary.id) {
                    throw new TbProtocolError(
                        'TB_PAYLOAD_COVERAGE_INSUFFICIENT',
                        `bindingProof.boundaryId (${opts.bindingProof.boundaryId}) !== boundary.id (${boundary.id})`,
                        'I7',
                    );
                }
                // I8 server-enforced expiry — bindingProof.notAfter === server lifecycleWindow.notAfter
                if (opts.bindingProof.notAfter !== boundary.lifecycleWindow.notAfter) {
                    throw new TbProtocolError(
                        'TB_EXPIRY_CLIENT_CONTROLLED',
                        `bindingProof.notAfter (${opts.bindingProof.notAfter}) !== server-enforced notAfter (${boundary.lifecycleWindow.notAfter})`,
                        'I8',
                    );
                }
                // delegate to csp verify (Ed25519 + JCS + strict equality of audience / challenge)
                const verdict = await this.verifier.verifyBindingProof(
                    opts.bindingProof,
                    {
                        expectedAudience: opts.verifyContext.expectedAudience,
                        expectedChallenge: opts.verifyContext.expectedChallenge,
                        expectedNotAfter: boundary.lifecycleWindow.notAfter,
                    },
                );
                if (!verdict.ok) {
                    throw new TbProtocolError(verdict.code, verdict.message, 'I7 / I9');
                }
                // T1 transition — pending → active; write bindingProofId
                nextBindingProofId = toUuidV4String(crypto.randomUUID());
                break;
            }
            case 'T2': {
                // onLeaseExtended — active self-loop; lifecycleWindow.notAfter updated
                if (!opts.leaseExtensionProof) {
                    throw new TbProtocolError(
                        'TB_PAYLOAD_COVERAGE_INSUFFICIENT',
                        'T2 onLeaseExtended requires leaseExtensionProof',
                        'I7',
                    );
                }
                if (!opts.verifyContext) {
                    throw new TbProtocolError(
                        'TB_PAYLOAD_COVERAGE_INSUFFICIENT',
                        'T2 onLeaseExtended requires verifyContext',
                        'I7',
                    );
                }
                if (!opts.requestedNotAfter) {
                    throw new TbProtocolError(
                        'TB_LIFECYCLE_INVALID',
                        'T2 onLeaseExtended requires requestedNotAfter',
                        'I5',
                    );
                }
                // I8 server-enforced expiry — truncate client requests beyond maxLifecycleWindow
                const nowMs = this.now().getTime();
                const requestedMs = isoToMs(opts.requestedNotAfter);
                const serverEnforcedMs = Math.min(
                    requestedMs,
                    nowMs + this.maxLifecycleWindowMs,
                );
                if (serverEnforcedMs <= nowMs + this.minWindowMs) {
                    throw new TbProtocolError(
                        'TB_LIFECYCLE_INVALID',
                        `serverEnforced notAfter <= now + minWindow (${this.minWindowMs}ms)`,
                        'I5',
                    );
                }
                const newNotAfter = new Date(serverEnforcedMs).toISOString() as Timestamp;
                // I8 — leaseExtensionProof.notAfter === server-enforced
                if (opts.leaseExtensionProof.notAfter !== newNotAfter) {
                    throw new TbProtocolError(
                        'TB_EXPIRY_CLIENT_CONTROLLED',
                        `leaseExtensionProof.notAfter (${opts.leaseExtensionProof.notAfter}) !== server-enforced (${newNotAfter})`,
                        'I8',
                    );
                }
                // I7 boundary id consistent
                if (opts.leaseExtensionProof.boundaryId !== boundary.id) {
                    throw new TbProtocolError(
                        'TB_PAYLOAD_COVERAGE_INSUFFICIENT',
                        `leaseExtensionProof.boundaryId !== boundary.id`,
                        'I7',
                    );
                }
                const verdict = await this.verifier.verifyLeaseExtensionProof(
                    opts.leaseExtensionProof,
                    {
                        expectedAudience: opts.verifyContext.expectedAudience,
                        expectedChallenge: opts.verifyContext.expectedChallenge,
                        expectedNotAfter: newNotAfter,
                    },
                );
                if (!verdict.ok) {
                    throw new TbProtocolError(verdict.code, verdict.message, 'I7 / I8');
                }
                nextLifecycleWindow = {
                    notBefore: boundary.lifecycleWindow.notBefore,
                    notAfter: newNotAfter,
                };
                nextBindingProofId = toUuidV4String(crypto.randomUUID());
                break;
            }
            case 'T3': {
                // onSuspended — active → suspended; lifecycleWindow unchanged
                // lifecycleWindow strictly unchanged (per T3's final line "lifecycleWindow.notAfter unchanged");
                // the caller may record the suspend reason in the audit event; the boundary's main fields are not modified here
                nextBindingProofId = toUuidV4String(crypto.randomUUID());
                break;
            }
            case 'T4': {
                // onResumed — suspended → active; I5 not-expired check
                const nowMs = this.now().getTime();
                const notAfterMs = isoToMs(boundary.lifecycleWindow.notAfter);
                if (notAfterMs <= nowMs + this.minWindowMs) {
                    throw new TbProtocolError(
                        'TB_BOUNDARY_EXPIRED',
                        `suspended boundary has expired (use the T6 expired path); notAfter = ${boundary.lifecycleWindow.notAfter}`,
                        'I5',
                    );
                }
                nextBindingProofId = toUuidV4String(crypto.randomUUID());
                break;
            }
            case 'T5': {
                // onRevoked — {active, suspended} → revoked; terminal state
                // to be implemented later: cascading token revocation list (step 4.2)
                // boundedTokenId is not modified here / the token revocation list is not called directly — handled by the caller in a hook
                nextBindingProofId = toUuidV4String(crypto.randomUUID());
                break;
            }
            case 'T6':
            case 'T7': {
                // onExpired — {active, suspended} → expired; terminal state
                // T6: declared actively by client/system
                // T7: server-side sweeper detects lifecycleWindow.notAfter <= now
                if (legal.id === 'T7') {
                    // T7 must satisfy lifecycleWindow.notAfter <= now
                    const nowMs = this.now().getTime();
                    const notAfterMs = isoToMs(boundary.lifecycleWindow.notAfter);
                    if (notAfterMs > nowMs) {
                        throw new TbProtocolError(
                            'TB_LIFECYCLE_INVALID',
                            `T7 auto-sweep is not allowed to trigger too early; notAfter (${boundary.lifecycleWindow.notAfter}) > now`,
                            'I5',
                        );
                    }
                }
                // bindingProofId unchanged (no new signing event; implements step 3)
                break;
            }
            default: {
                // anti-phantom — unreachable; LEGAL_TRANSITIONS is already enumerated
                throw new TbProtocolError(
                    'TB_INVALID_TRANSITION',
                    `transition id ${legal.id} not covered within LEGAL_TRANSITIONS (code bug)`,
                    'I4',
                );
            }
        }

        // construct the new boundary state
        const next: TrustBoundary = {
            ...boundary,
            state: toState,
            stateEnteredAt: nowToIso(this.now),
            lifecycleWindow: nextLifecycleWindow,
            bindingProofId: nextBindingProofId,
        };

        // recheck all invariants (I_tb_ver + I1-I6; catches JSON deserialization bypassing the type)
        assertInvariant(next);

        // persist + audit event
        await this.storage.save(next);
        await this.storage.appendAuditEvent({
            type: opts.event as TrustBoundaryLifecycleEvent,
            boundaryId: boundary.id,
            transitionBefore: beforeState,
            transitionAfter: toState,
            transitionSource: opts.transitionSource,
            actorDID: opts.actorDID,
            timestamp: nowToIso(this.now),
            bindingProofId: nextBindingProofId,
        });

        return next;
    }
}
