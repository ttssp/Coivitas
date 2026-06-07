/**
 * MCP Bridge — outbox manager
 *
 * Overview:
 *   - mcp_outbox persistence schema
 *   - getOutboxByID 4-step ownership check:
 *     1. PoP kind check (excludes 'tokenId'; only 'agentDid' / 'mcpClientId')
 *     2. PoP signature verification (the caller must sign the outbox-challenge with the corresponding subject key)
 *     3. ownership match (kind + value consistent with row.owner_subject_*)
 *     4. return row
 *   - owner subject write rules:
 *     - owner_subject_kind ∈ {'agentDid', 'mcpClientId'} (does **not** include 'tokenId')
 *     - owner_subject_value = corresponding subject value (defaults to envelope.sender)
 *     - owner_token_id = chain-audit association (**NOT** an authorization field)
 *
 * Implemented in this module:
 *   - OutboxRow (mcp_outbox table row shape)
 *   - OutboxStore (pg-abstracting interface; mockable in unit tests)
 *   - createOutboxRow (INSERT; forbids 'tokenId' as kind)
 *   - getOutboxByID (4-step ownership check)
 *   - resolveOutboxChallenge (placeholder mock; the real challenge endpoint is wired in later)
 *
 * Not yet implemented in this module:
 *   - the real challenge-endpoint HTTP server (introduced later; for now an in-embedded mock challenge store)
 *   - revocation chain-audit queries (associated with a separate audit ledger; not the outbox-manager's responsibility)
 *
 * Security invariants:
 *   - the callerSubject.kind === 'tokenId' path is **rejected outright** (IDOR defense)
 *   - owner_token_id **does not participate** in the ownership check (chain-audit association only)
 *   - tests use runtime readFileSync + regex to verify the source contains no code violating this constraint (pinned by a grep test)
 */

import type { PoolClient } from 'pg';

import {
    MCP_ERROR,
    makeMcpError,
    type MCPBridgeError,
    type MCPCallerSubject,
    type MCPCallerSubjectKind,
} from './types.js';

// ─── data model ──────────────────────────────────────────────────────────────

/**
 * OutboxRow — mcp_outbox table row shape
 *
 * - status: 'pending' / 'settled' / 'error'
 * - owner_subject_kind: 'agentDid' / 'mcpClientId' (excludes 'tokenId')
 * - owner_token_id: chain-audit association (**NOT** an ownership authorization field)
 *
 * Note: field names use camelCase (TypeScript style); DB row names use snake_case;
 * the mapping is done inside `rowToOutboxRow`.
 */
export interface OutboxRow {
    outboxId: string;
    envelopeId: string;
    status: 'pending' | 'settled' | 'error';
    settlementReceipt: unknown;
    errorObject: unknown;
    createdAt: string; // ISO-8601
    completedAt: string | null;

    // owner subject fields (the ownership check uses this pair of fields)
    ownerSubjectKind: MCPCallerSubjectKind;
    ownerSubjectValue: string;

    // chain-audit association (**NOT** an ownership authorization field)
    ownerTokenId: string;
}

/**
 * OutboxStore — pg-abstracting interface (implementations may inject a PoolClient / custom store)
 *
 * Unit tests can inject a vi.fn() mock; real runs inject a PoolClient-backed implementation.
 *
 * fail-closed semantics:
 *   - lookup throws = the caller must propagate (exceptions are treated as infrastructure failures)
 *   - lookup returns null = the outbox does not exist (→ mcp_error_outbox_not_found)
 */
export interface OutboxStore {
    /**
     * INSERT a new outbox row.
     *
     * Implementations run INSERT INTO communication.mcp_outbox VALUES (...)
     * owner_subject_kind = 'tokenId' is forbidden (CHECK constraint + application-layer guard, both)
     */
    insert(row: OutboxRow): Promise<void>;

    /**
     * SELECT * FROM communication.mcp_outbox WHERE outbox_id = $1
     *
     * Returning null means the outbox does not exist (→ mcp_error_outbox_not_found).
     */
    lookup(outboxId: string): Promise<OutboxRow | null>;
}

/**
 * ChallengeResolver — fetch outbox-specific challenge bytes from the challenge endpoint
 *
 * Called like `const challenge = await getOutboxChallenge(outboxId);`
 *
 * The placeholder mock impl returns deterministic challenge bytes (`outbox:<id>`);
 * the real HTTP /v1/mcp/outbox/<id>/challenge endpoint is wired in later.
 *
 * Note: the challenge must be bound to outboxId, otherwise an attacker could replay a challenge across outboxes.
 */
export type OutboxChallengeResolver = (outboxId: string) => Promise<Uint8Array>;

/**
 * SubjectKeyResolver — resolve the public key of a PoP-based subject
 *
 * - kind 'agentDid' → use the DID resolver to fetch the agent public key
 * - kind 'mcpClientId' → use the binding registry to look up the MCP client PoP key
 *
 * Returning null = the subject is not resolvable → fail-closed mcp_error_outbox_unauthorized.
 *
 * Note: this interface does not consume the 'tokenId' kind (forbidden at the type layer).
 */
export type SubjectKeyResolver = (
    subject: MCPCallerSubject,
) => Promise<Uint8Array | null>;

/**
 * PoPSignatureVerifier — Ed25519 verification interface
 *
 * Shaped like: `verifyEd25519(popSignature, challenge, subjectKey)`
 *
 * Implementations inject @coivitas/crypto verify; this module decouples the crypto dependency to ease unit testing.
 *
 * @param signature - PoP signature (Base64Url decoded → Uint8Array)
 * @param challenge - challenge bytes (bound to the outbox)
 * @param publicKey - subject public key
 * @returns true = verification passed; false = verification failed
 */
export type PoPSignatureVerifier = (
    signature: Uint8Array,
    challenge: Uint8Array,
    publicKey: Uint8Array,
) => boolean | Promise<boolean>;

// ─── public API: createOutboxRow (owner write rules) ─────

/**
 * createOutboxRow — INSERT a new outbox row
 *
 * owner write rules:
 *   - owner_subject_kind ∈ {'agentDid', 'mcpClientId'} (does **not** include 'tokenId')
 *   - owner_subject_value = corresponding subject value (defaults to envelope.sender)
 *   - owner_token_id = envelope.capabilityClaim.token.tokenId (kept as a chain-audit association)
 *
 * fail-closed semantics:
 *   - ownerSubject.kind === 'tokenId' → **rejected** (TypeScript type layer + runtime, both guarding)
 *   - any missing field → throw (the caller propagates; treated as input-validation failure)
 *
 * @param input outbox input
 * @param store OutboxStore instance (pg-backed or mock)
 * @returns on success, the OutboxRow (the caller can record outboxId for later queries)
 * @throws Error if ownerSubject.kind === 'tokenId'
 */
export interface CreateOutboxRowInput {
    outboxId: string;
    envelopeId: string;
    /** defaults to 'pending'; the caller specifies per scenario */
    status?: 'pending' | 'settled' | 'error';
    settlementReceipt?: unknown;
    errorObject?: unknown;
    /** ISO-8601 timestamp; if the caller omits it, new Date().toISOString() is used */
    createdAt?: string;
    completedAt?: string;

    /**
     * the 'tokenId' kind is forbidden;
     * even if the caller wrongly passes 'tokenId', runtime rejects it
     */
    ownerSubject: MCPCallerSubject;

    /** chain-audit association (NOT an authorization field) */
    ownerTokenId: string;
}

export async function createOutboxRow(
    input: CreateOutboxRowInput,
    store: OutboxStore,
): Promise<OutboxRow> {
    // runtime guard: forbid the 'tokenId' kind (the TypeScript type layer already forbids it, but runtime adds a second layer)
    // note: the MCPCallerSubjectKind type already disallows 'tokenId', but a caller may cast from unknown;
    // re-verify here at runtime to satisfy the IDOR defense invariant
    if ((input.ownerSubject.kind as string) === 'tokenId') {
        throw new Error(
            'ownerSubject.kind cannot be "tokenId" (IDOR defense)',
        );
    }
    if (
        input.ownerSubject.kind !== 'agentDid' &&
        input.ownerSubject.kind !== 'mcpClientId'
    ) {
        throw new Error(
            `unknown ownerSubject.kind: ${String(input.ownerSubject.kind)}`,
        );
    }

    const row: OutboxRow = {
        outboxId: input.outboxId,
        envelopeId: input.envelopeId,
        status: input.status ?? 'pending',
        settlementReceipt: input.settlementReceipt ?? null,
        errorObject: input.errorObject ?? null,
        createdAt: input.createdAt ?? new Date().toISOString(),
        completedAt: input.completedAt ?? null,
        ownerSubjectKind: input.ownerSubject.kind,
        ownerSubjectValue: input.ownerSubject.value,
        ownerTokenId: input.ownerTokenId,
    };

    await store.insert(row);
    return row;
}

// ─── public API: getOutboxByID (ownership check) ─

/**
 * GetOutboxByID input (PoP-based subject + signature)
 *
 * wire shape:
 *   {
 *     callerSubjectKind: 'agentDid' | 'mcpClientId', // excludes 'tokenId'
 *     callerSubjectValue: string,
 *     proofSignature: Base64Url // signs the challenge from the /outbox-challenge endpoint
 *   }
 *
 * This module accepts popSignature as a Uint8Array (the caller passes it in after Base64Url decoding);
 * this way outbox-manager is decoupled from base64 encoding details.
 */
export interface GetOutboxByIDInput {
    outboxId: string;
    callerSubject: MCPCallerSubject;
    popSignature: Uint8Array;
}

/**
 * GetOutboxByID dependencies (resolver + verifier; fully mockable in unit tests)
 */
export interface GetOutboxByIDDeps {
    store: OutboxStore;
    challengeResolver: OutboxChallengeResolver;
    subjectKeyResolver: SubjectKeyResolver;
    verifyPop: PoPSignatureVerifier;
}

/**
 * GetOutboxByID return type
 */
export type GetOutboxByIDResult =
    | { ok: true; row: OutboxRow }
    | { ok: false; error: MCPBridgeError };

/**
 * getOutboxByID — 4-step ownership check
 *
 * Flow:
 *   step 0: SELECT row → null → mcp_error_outbox_not_found
 *   step 1: callerSubject.kind ∈ {'agentDid', 'mcpClientId'}
 *           → 'tokenId' rejected → mcp_error_outbox_unauthorized
 *   step 2: challenge resolve + subject key resolve + PoP verification
 *           → any fail → mcp_error_outbox_unauthorized
 *   step 3: ownership match (kind + value vs row.owner_subject_*)
 *           → mismatch → mcp_error_outbox_unauthorized
 *   step 4: return row
 *
 * fail-closed semantics (including IDOR defense):
 *   - any intermediate step fails → return error immediately; no partial-acceptance
 *   - the error code is uniformly mcp_error_outbox_unauthorized (does not distinguish the specific failing step; anti-ownership-probe)
 *
 * IDOR defense key points:
 *   - row.owner_token_id **does not participate** in the ownership check (chain audit only)
 *   - even if the caller knows outboxId + tokenId, it cannot pass the ownership check
 *   - the caller must hold both (a) the PoP key (controlling the subject) + (b) an ownership match
 */
export async function getOutboxByID(
    input: GetOutboxByIDInput,
    deps: GetOutboxByIDDeps,
): Promise<GetOutboxByIDResult> {
    // step 0: look up the outbox row
    const row = await deps.store.lookup(input.outboxId);
    if (!row) {
        return {
            ok: false,
            error: makeMcpError(
                MCP_ERROR.OUTBOX_NOT_FOUND,
                'mcp_error_outbox_not_found',
                `outbox ${input.outboxId} not found`,
            ),
        };
    }

    // step 1: PoP kind check (does not accept 'tokenId')
    // invariant: the 'tokenId' kind is rejected outright (IDOR defense)

    // note: the MCPCallerSubjectKind type already forbids 'tokenId', but a caller may cast from unknown;
    // the runtime check here acts as defense-in-depth
    if (
        input.callerSubject.kind !== 'agentDid' &&
        input.callerSubject.kind !== 'mcpClientId'
    ) {
        return {
            ok: false,
            error: makeMcpError(
                MCP_ERROR.OUTBOX_UNAUTHORIZED,
                'mcp_error_outbox_unauthorized',
                `callerSubject.kind is invalid (must be 'agentDid' or 'mcpClientId'; 'tokenId' disabled)`,
            ),
        };
    }

    // step 2: PoP verification — challenge resolve + subject key resolve + verifyEd25519
    // three sub-steps
    let challenge: Uint8Array;
    let subjectKey: Uint8Array | null;
    try {
        challenge = await deps.challengeResolver(input.outboxId);
        subjectKey = await deps.subjectKeyResolver(input.callerSubject);
    } catch {
        // resolver exception → fail-closed unauthorized (does not leak internal error detail, anti-probe)
        return {
            ok: false,
            error: makeMcpError(
                MCP_ERROR.OUTBOX_UNAUTHORIZED,
                'mcp_error_outbox_unauthorized',
                'failed to resolve PoP challenge or subject key',
            ),
        };
    }
    if (!subjectKey) {
        return {
            ok: false,
            error: makeMcpError(
                MCP_ERROR.OUTBOX_UNAUTHORIZED,
                'mcp_error_outbox_unauthorized',
                'callerSubject public key is not resolvable',
            ),
        };
    }

    const popOk = await Promise.resolve(
        deps.verifyPop(input.popSignature, challenge, subjectKey),
    );
    if (!popOk) {
        return {
            ok: false,
            error: makeMcpError(
                MCP_ERROR.OUTBOX_UNAUTHORIZED,
                'mcp_error_outbox_unauthorized',
                'PoP signature verification failed',
            ),
        };
    }

    // step 3: ownership match
    // kind + value must **both** be consistent with row.owner_subject_*
    // invariant: row.ownerTokenId **does not participate** in the ownership check (IDOR defense)
    if (
        input.callerSubject.kind !== row.ownerSubjectKind ||
        input.callerSubject.value !== row.ownerSubjectValue
    ) {
        return {
            ok: false,
            error: makeMcpError(
                MCP_ERROR.OUTBOX_UNAUTHORIZED,
                'mcp_error_outbox_unauthorized',
                'callerSubject does not match row.owner_subject_*',
            ),
        };
    }

    // step 4: success
    return { ok: true, row };
}

// ─── PostgresOutboxStore adapter (pg PoolClient-backed) ──────────────────────

/**
 * PostgresOutboxStore — PoolClient-backed OutboxStore implementation
 *
 * The SQL is consistent with 025_mcp_outbox.sql;
 * uses the communication schema (the same schema as communication.sessions).
 *
 * Note: this class does not own the PoolClient lifecycle (the caller manages connect/release);
 * unit tests can inject a vi.fn() mock client.query.
 */
export class PostgresOutboxStore implements OutboxStore {
    constructor(private readonly client: PoolClient) {}

    async insert(row: OutboxRow): Promise<void> {
        // write all fields; status / owner_subject_kind are backstopped by CHECK constraints
        // owner_token_id is forbidden from the ownership check (chain audit only) — the SQL layer also adds no ownership association constraint
        await this.client.query(
            `INSERT INTO communication.mcp_outbox
                (outbox_id, envelope_id, status, settlement_receipt, error_object,
                 created_at, completed_at,
                 owner_subject_kind, owner_subject_value, owner_token_id)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
            [
                row.outboxId,
                row.envelopeId,
                row.status,
                row.settlementReceipt === null
                    ? null
                    : JSON.stringify(row.settlementReceipt),
                row.errorObject === null
                    ? null
                    : JSON.stringify(row.errorObject),
                row.createdAt,
                row.completedAt,
                row.ownerSubjectKind,
                row.ownerSubjectValue,
                row.ownerTokenId,
            ],
        );
    }

    async lookup(outboxId: string): Promise<OutboxRow | null> {
        const res = await this.client.query<Record<string, unknown>>(
            `SELECT outbox_id, envelope_id, status, settlement_receipt, error_object,
                    created_at, completed_at,
                    owner_subject_kind, owner_subject_value, owner_token_id
               FROM communication.mcp_outbox
              WHERE outbox_id = $1`,
            [outboxId],
        );
        if (res.rows.length === 0) return null;
        return rowToOutboxRow(res.rows[0]!);
    }
}

/**
 * rowToOutboxRow — DB row (snake_case) → TypeScript OutboxRow (camelCase)
 *
 * Field correspondence is consistent with 025_mcp_outbox.sql;
 * for timestamp fields (TIMESTAMPTZ) the pg driver returns a Date object → call .toISOString().
 */
function rowToOutboxRow(row: Record<string, unknown>): OutboxRow {
    const toIsoOpt = (v: unknown): string | null => {
        if (v == null) return null;
        if (v instanceof Date) return v.toISOString();
        if (typeof v === 'string') return v;
        return null;
    };
    const toIso = (v: unknown): string => {
        const iso = toIsoOpt(v);
        if (iso === null) {
            throw new Error(
                `rowToOutboxRow: required TIMESTAMPTZ missing: ${String(v)}`,
            );
        }
        return iso;
    };
    const toStr = (v: unknown): string => {
        if (typeof v === 'string') return v;
        throw new Error(
            `rowToOutboxRow: required string field missing: ${String(v)}`,
        );
    };
    const status = toStr(row['status']);
    if (status !== 'pending' && status !== 'settled' && status !== 'error') {
        throw new Error(`rowToOutboxRow: invalid status: ${status}`);
    }
    const ownerKind = toStr(row['owner_subject_kind']);
    if (ownerKind !== 'agentDid' && ownerKind !== 'mcpClientId') {
        // the DB CHECK already forbids 'tokenId', but runtime adds a second guard
        throw new Error(
            `rowToOutboxRow: invalid owner_subject_kind: ${ownerKind}`,
        );
    }
    return {
        outboxId: toStr(row['outbox_id']),
        envelopeId: toStr(row['envelope_id']),
        status,
        settlementReceipt: row['settlement_receipt'] ?? null,
        errorObject: row['error_object'] ?? null,
        createdAt: toIso(row['created_at']),
        completedAt: toIsoOpt(row['completed_at']),
        ownerSubjectKind: ownerKind,
        ownerSubjectValue: toStr(row['owner_subject_value']),
        ownerTokenId: toStr(row['owner_token_id']),
    };
}

// ─── default mock challenge resolver (placeholder mock; HTTP impl wired in later) ──────────

/**
 * defaultMockChallengeResolver — embedded deterministic challenge
 *
 * challenge = SHA-256('mcp-outbox-challenge:' || outboxId)
 *
 * This is a placeholder implementation (does not pull in the @noble/hashes dependency; uses Node's built-in crypto);
 * the real HTTP /v1/mcp/outbox/<id>/challenge endpoint is wired in later.
 *
 * Caution: this is **not** a secure challenge implementation — in a real deployment the challenge must:
 *   - be a server-side generated random nonce + time limit
 *   - be bound to outbox_id (to prevent cross-outbox replay)
 *   - be valid for only a short window (to prevent replay)
 *
 * The current placeholder only satisfies "challenge bytes are usable for verify"; it does **not** satisfy full
 * anti-replay semantics; the real integration is left for a later stage.
 */
export async function defaultMockChallengeResolver(
    outboxId: string,
): Promise<Uint8Array> {
    // use Node's built-in crypto to generate a deterministic challenge (avoid depending on @noble/hashes)
    const { createHash } = await import('node:crypto');
    const h = createHash('sha256');
    h.update('mcp-outbox-challenge:');
    h.update(outboxId);
    return h.digest();
}
