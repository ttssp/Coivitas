/**
 * control-plane-scope.property.test.ts
 *
 * Property-based conformance fixture for the single-point row-level scope
 * integrity invariant gate (recordVisibleToScope).
 *
 * **This fixture is the sole authoritative definition of the row-level scope
 * integrity invariant.** Any surface that exposes a PersistedActionRecord on the
 * control-plane lane (list / get / verify / head / chain / future additions) must satisfy:
 *   - SQL predicate / handler behavior matches the return value of recordVisibleToScope() exactly;
 *   - when a ControlPlaneRequesterScope field is added, this fixture must extend the reject set and accept set in lockstep.
 *
 * Background: the same root cause recurred repeatedly when a newly added surface
 * dropped one scope field; switching to a property-based fixture that enforces
 * symmetry dramatically lowered the recurrence rate and ended the reliance on point patches.
 *
 * Strategy: no extra dependency such as fast-check is introduced (the repo has zero
 * property-test dependencies); instead vitest test.each enumerates the full
 * "enumeration + Cartesian product" of every scope-field reject/accept face. When a
 * field is added the table entries must be extended, otherwise the missing face passes silently.
 *
 * The 5-surface symmetry matrix (end-to-end assertions for the list/get/verify/head/chain
 * handlers) lives in the same-named describe in action-record-routes.unit.test.ts and
 * reuses the makePool/makeApp infrastructure.
 */

import { describe, expect, it } from 'vitest';

import { __testing__recordVisibleToScope as recordVisibleToScope } from '../action-record-routes.js';

// ═══════════════════════════════════════════════════════════════════════════
// Test constants
// ═══════════════════════════════════════════════════════════════════════════

const SCOPED_AGENT = 'did:agent:0000000000000000000000000000000000000001';
const FOREIGN_AGENT = 'did:agent:0000000000000000000000000000000000000002';
const SCOPED_PRINCIPAL = 'did:key:z6MkScopedPrincipalForPropertyTestFixture';
const FOREIGN_PRINCIPAL = 'did:key:z6MkForeignPrincipalForPropertyTestFixture';

interface MaybeRecord {
    parametersSummary: Record<string, unknown> | null | undefined;
}

interface QueryShape {
    affectedAgentDid?: string;
    affectedPrincipalDid?: string;
}

const makeRecord = (
    paramsAffectedAgent?: string | null,
    paramsAffectedPrincipal?: string | null,
): MaybeRecord => {
    if (paramsAffectedAgent === null && paramsAffectedPrincipal === null) {
        return { parametersSummary: null };
    }
    const params: Record<string, unknown> = {
        oldSessionId: '550e8400-e29b-41d4-a716-446655440200',
    };
    if (typeof paramsAffectedAgent === 'string') {
        params['affectedAgentDid'] = paramsAffectedAgent;
    }
    if (typeof paramsAffectedPrincipal === 'string') {
        params['affectedPrincipalDid'] = paramsAffectedPrincipal;
    }
    return { parametersSummary: params };
};

// ═══════════════════════════════════════════════════════════════════════════
// Reject-face enumeration (property = "if scope rejects the record on any field -> recordVisibleToScope returns false")

// Field dimensions (ControlPlaneRequesterScope currently has 2):
// - affectedAgentDid (required; query missing / record missing / mismatch -> reject)
// - affectedPrincipalDid (optional; if query passes it explicitly -> enforce row-level equality)

// When a metadata-driven quorum/role introduces a 3rd+ dimension, these table entries must be extended in lockstep.
// ═══════════════════════════════════════════════════════════════════════════

interface RejectCase {
    name: string;
    record: MaybeRecord;
    query: QueryShape;
    /** The scope dimension that was hit (for human readability + locating failures)*/
    rejectedField:
        | 'affectedAgentDid:query-missing'
        | 'affectedAgentDid:record-missing'
        | 'affectedAgentDid:mismatch'
        | 'affectedPrincipalDid:record-missing'
        | 'affectedPrincipalDid:mismatch'
        | 'parametersSummary:null';
}

const REJECT_CASES: RejectCase[] = [
    // ── affectedAgentDid dimension ────────────────────────────────────────────
    {
        name: 'query is missing affectedAgentDid -> reject (subject must be declared explicitly)',
        record: makeRecord(SCOPED_AGENT),
        query: {},
        rejectedField: 'affectedAgentDid:query-missing',
    },
    {
        name: 'record is missing parameters_summary.affectedAgentDid -> reject (fail-closed, historical/corrupt data)',
        record: makeRecord(undefined, SCOPED_PRINCIPAL),
        query: { affectedAgentDid: SCOPED_AGENT },
        rejectedField: 'affectedAgentDid:record-missing',
    },
    {
        name: 'record.affectedAgentDid != query.affectedAgentDid -> reject (cross-subject privilege escalation)',
        record: makeRecord(FOREIGN_AGENT),
        query: { affectedAgentDid: SCOPED_AGENT },
        rejectedField: 'affectedAgentDid:mismatch',
    },
    // ── affectedPrincipalDid dimension (query passes it explicitly -> enforce row-level) ─────────
    {
        name: 'query includes affectedPrincipalDid but record lacks the field -> reject (fail-closed, missing field is not allowed through)',
        record: makeRecord(SCOPED_AGENT),
        query: {
            affectedAgentDid: SCOPED_AGENT,
            affectedPrincipalDid: SCOPED_PRINCIPAL,
        },
        rejectedField: 'affectedPrincipalDid:record-missing',
    },
    {
        name: 'query.affectedPrincipalDid != record.affectedPrincipalDid -> reject (principal-dimension privilege escalation)',
        record: makeRecord(SCOPED_AGENT, FOREIGN_PRINCIPAL),
        query: {
            affectedAgentDid: SCOPED_AGENT,
            affectedPrincipalDid: SCOPED_PRINCIPAL,
        },
        rejectedField: 'affectedPrincipalDid:mismatch',
    },
    // ── parametersSummary entirely missing ────────────────────────────────────────
    {
        name: 'record.parameters_summary is entirely null -> reject (fail-closed fallback for historical data)',
        record: makeRecord(null, null),
        query: { affectedAgentDid: SCOPED_AGENT },
        rejectedField: 'parametersSummary:null',
    },
];

// ═══════════════════════════════════════════════════════════════════════════
// Accept-face enumeration (property = "if every scope field aligns with the row field -> recordVisibleToScope returns true")
// ═══════════════════════════════════════════════════════════════════════════

interface AcceptCase {
    name: string;
    record: MaybeRecord;
    query: QueryShape;
}

const ACCEPT_CASES: AcceptCase[] = [
    {
        name: 'query has affectedAgentDid only + record agent aligns (principal dimension is unconstrained)',
        record: makeRecord(SCOPED_AGENT),
        query: { affectedAgentDid: SCOPED_AGENT },
    },
    {
        name: 'query includes principal + record aligns on both fields',
        record: makeRecord(SCOPED_AGENT, SCOPED_PRINCIPAL),
        query: {
            affectedAgentDid: SCOPED_AGENT,
            affectedPrincipalDid: SCOPED_PRINCIPAL,
        },
    },
    {
        name: 'query has agent only + record includes principal (query omits principal -> row.principal unconstrained)',
        record: makeRecord(SCOPED_AGENT, FOREIGN_PRINCIPAL),
        query: { affectedAgentDid: SCOPED_AGENT },
    },
];

// ═══════════════════════════════════════════════════════════════════════════
// Property 1: reject-face symmetry
// ═══════════════════════════════════════════════════════════════════════════

describe('v0.5 recordVisibleToScope — reject-face symmetry property', () => {
    it.each(REJECT_CASES)(
        '$name → returns false (rejectedField=$rejectedField)',
        ({ record, query }) => {
            expect(recordVisibleToScope(record, query)).toBe(false);
        },
    );
});

// ═══════════════════════════════════════════════════════════════════════════
// Property 2: accept-face orthogonality
// ═══════════════════════════════════════════════════════════════════════════

describe('v0.5 recordVisibleToScope — accept-face orthogonality property', () => {
    it.each(ACCEPT_CASES)('$name → returns true', ({ record, query }) => {
        expect(recordVisibleToScope(record, query)).toBe(true);
    });
});

// ═══════════════════════════════════════════════════════════════════════════
// Property 3: single-field reject precedence (a reject on any dimension is false, independent of evaluation order)

// Invariant: if record/query mismatch on at least 1 of the N scope dimensions -> false.
// Any implementation that "drops a dimension" (such as the once-missing
// affectedPrincipalDid SQL predicate) is guaranteed to fail this property -- preventing the same root cause from recurring.
// ═══════════════════════════════════════════════════════════════════════════

describe('v0.5 recordVisibleToScope — multi-dimension simultaneous reject', () => {
    it('agent + principal both mismatch → reject (no dimension may be bypassed via another dimension dropping a field)', () => {
        const record = makeRecord(FOREIGN_AGENT, FOREIGN_PRINCIPAL);
        const query: QueryShape = {
            affectedAgentDid: SCOPED_AGENT,
            affectedPrincipalDid: SCOPED_PRINCIPAL,
        };
        expect(recordVisibleToScope(record, query)).toBe(false);
    });

    it('agent matches but principal mismatches → reject (principal dimension enforced independently)', () => {
        const record = makeRecord(SCOPED_AGENT, FOREIGN_PRINCIPAL);
        const query: QueryShape = {
            affectedAgentDid: SCOPED_AGENT,
            affectedPrincipalDid: SCOPED_PRINCIPAL,
        };
        expect(recordVisibleToScope(record, query)).toBe(false);
    });

    it('principal matches but agent mismatches → reject (agent dimension enforced independently)', () => {
        const record = makeRecord(FOREIGN_AGENT, SCOPED_PRINCIPAL);
        const query: QueryShape = {
            affectedAgentDid: SCOPED_AGENT,
            affectedPrincipalDid: SCOPED_PRINCIPAL,
        };
        expect(recordVisibleToScope(record, query)).toBe(false);
    });
});
