import { randomUUID } from 'node:crypto';

import type { PoolClient } from 'pg';

import { type DatabasePool, withTransaction } from '@coivitas/shared';
import type { DID, Timestamp } from '@coivitas/types';
import {
    ACTION_SESSION_SUPERSEDED,
    ProtocolError,
    SESSION_GOVERNOR_DID,
} from '@coivitas/types';

import type {
    ActionRecordInput,
    ActionRecordQueryFilters,
    ActionRecordQueryResult,
    PersistedActionRecord,
    RecordWriteResult,
} from '../types.js';
import type {
    SideTableAppender,
    SideTableEntry,
} from '../audit-governor-lane/types.js';
import { toTimestamp } from '../_shared/timestamp.js';
import { LEDGER_ENCODING } from './encoding-config.js';
import {
    buildUnsignedRecordPayload,
    computeRecordHash,
    createRecordSignature,
    derivePublicKeyFromPrivateKey,
    normalizeSigningPrivateKey,
    toPersistedRecord,
} from './shared.js';

interface ActionRecordRow {
    // BIGINT PRIMARY KEY; pg returns INT8 as a string by default to avoid JS
    // Number precision loss; the code explicitly promotes with BigInt(row.id) where comparison/arithmetic is needed.
    id: string;
    record_id: string;
    agent_did: string;
    principal_did: string;
    action_type: string;
    parameters_summary: Record<string, unknown> | null;
    authorization_ref: Record<string, unknown> | null;
    result_summary: Record<string, unknown> | null;
    record_hash: string;
    previous_record_hash: string;
    actor_signature: string;
    ledger_signature: string;
    delegation_depth: number | null;
    session_id: string | null;
    // The PG node driver returns a Date object for TIMESTAMPTZ by default; fromRow must normalize
    // with toTimestamp().
    created_at: string | Date;
}

/**
 * SessionOwnerResolver interface (a lightweight import used only inside action-recorder).
 * The full definition lives in audit-governor-lane/types.ts.
 */
interface ActionRecorderSessionOwnerResolver {
    resolveOwner(
        sessionId: string,
    ): Promise<{ agentDid: DID; principalDid: DID } | null>;
}

/**
 * assertSchemaCompliant function signature (a lightweight import used only inside action-recorder).
 * The full definition lives in audit-governor-lane/assert-schema-compliant.ts.
 */
type AssertSchemaCompliantFn = (input: {
    agentDid: string;
    principalDid: string;
    actionType: string;
    parametersSummary: Record<string, unknown> | null | undefined;
}) => void;

/**
 * ActionRecorder constructor options (discriminated union + lane enforcement).
 *
 * kind='standard':
 *   Business mode. Only the 5 non-governor business-lane actionTypes may be written
 *   (INQUIRY / QUOTE / CONFIRM / PUBLISH / RECORD).
 *   record() rejects writes with agentDid===SESSION_GOVERNOR_DID or
 *   actionType===SESSION_SUPERSEDED at runtime (fail-closed).
 *
 * kind='control-plane':
 *   Governance-channel mode. Only the SESSION_SUPERSEDED control-plane event may be written,
 *   and it requires agentDid===principalDid===SESSION_GOVERNOR_DID.
 *   record() rejects any business-lane actionType or non-governor DID at runtime (fail-closed).
 *   control-plane mode must inject sessionOwnerResolver and assertSchemaCompliant;
 *   record() invokes both guards before the INSERT. If they are missing, the constructor throws (fail-closed).
 *
 * Design notes:
 * - The kind discriminant aligns with IntegrityChecker's discriminated union.
 * - record adds lane runtime enforcement to
 *   prevent a standard recorder from silently writing control-plane events (trust boundary).
 * - The control-plane branch enforces assertSessionBinding + assertSchemaCompliant on the
 *   write path (strong validation on the production path).
 */
export type ActionRecorderOptions =
    | {
          kind: 'standard';
          ledgerPrivateKey?: string;
      }
    | {
          kind: 'control-plane';
          ledgerPrivateKey?: string;
          /**
           * control-plane must inject a SessionOwnerResolver.
           * Before the INSERT, record() uses the resolver to verify the affected DID matches the session owner.
           * If missing, the constructor throws (fail-closed).
           */
          sessionOwnerResolver: ActionRecorderSessionOwnerResolver;
          /**
           * control-plane must inject an AJV schema validation function.
           * Before the INSERT, record() runs full schema validation on parametersSummary.
           * If missing, the constructor throws (fail-closed).
           */
          assertSchemaCompliant: AssertSchemaCompliantFn;
          /**
           * control-plane must inject a SideTableAppender.
           * record() calls append() after the main-table INSERT and before returning.
           * If missing, the constructor throws (fail-closed).
           *
           * Currently the repo only ships an InMemorySideTableAppender stub;
           * production deployment must wait for a PostgresSideTableAppender to land.
           * Interface contract: PostgresSideTableAppender must share the same pg.PoolClient
           * as the main-table INSERT (atomic write in the same transaction).
           */
          sideTableAppender: SideTableAppender;
      };

/**
 * ControlPlaneActionRecorder — alias for `ActionRecorder & { kind: 'control-plane' }`.
 *
 * Lets the SessionSupersedeRecorder constructor reject a business-lane recorder at the
 * type level (not just a runtime throw). The caller must use `assertIsControlPlaneRecorder()`
 * to narrow `ActionRecorder` to `ControlPlaneActionRecorder` before injecting it.
 */
export type ControlPlaneActionRecorder = ActionRecorder & {
    readonly kind: 'control-plane';
};

/**
 * Type assertion: narrow `ActionRecorder` to `ControlPlaneActionRecorder` or throw.
 * Used for double defense (compile-time + runtime) on control-plane write paths such as SessionSupersedeRecorder.
 */
export function assertIsControlPlaneRecorder(
    recorder: ActionRecorder,
): asserts recorder is ControlPlaneActionRecorder {
    if (recorder.kind !== 'control-plane') {
        throw new Error(
            `ActionRecorder must be kind='control-plane' (got kind='${recorder.kind}'). ` +
                `The control-plane write path may only be held by a control-plane ActionRecorder ` +
                `(audit chain integrity contract).`,
        );
    }
}

export class ActionRecorder {
    private readonly ledgerPrivateKey: string;
    public readonly ledgerPublicKey: string;
    public readonly kind: 'standard' | 'control-plane';

    /**
     * The session-binding guard dependency in control-plane mode.
     * record() enforces assertSessionBinding before the INSERT.
     * In standard mode this is null (unused).
     */
    private readonly sessionOwnerResolver: ActionRecorderSessionOwnerResolver | null;

    /**
     * The AJV schema validation function in control-plane mode.
     * record() enforces it before the INSERT.
     * In standard mode this is null (unused).
     */
    private readonly schemaValidator: AssertSchemaCompliantFn | null;

    /**
     * The SideTableAppender in control-plane mode.
     * record() calls append() after the main-table INSERT.
     * In standard mode this is null (the business lane does not write the side-table).
     */
    private readonly sideTableAppender: SideTableAppender | null;

    public constructor(
        private readonly dbPool: DatabasePool,
        options: ActionRecorderOptions,
    ) {
        this.kind = options.kind;
        const configuredKey =
            options.ledgerPrivateKey ?? process.env.LEDGER_PRIVATE_KEY ?? '';
        if (configuredKey.length === 0) {
            throw new ProtocolError(
                'INTERNAL_ERROR',
                'LEDGER_PRIVATE_KEY is required.',
            );
        }

        // control-plane must inject the guard dependencies (fail-closed).
        if (options.kind === 'control-plane') {
            if (!options.sessionOwnerResolver) {
                throw new ProtocolError(
                    'INTERNAL_ERROR',
                    'ActionRecorder(kind=control-plane): sessionOwnerResolver is required ' +
                        '(write-path enforcement; fail-closed).',
                );
            }
            if (!options.assertSchemaCompliant) {
                throw new ProtocolError(
                    'INTERNAL_ERROR',
                    'ActionRecorder(kind=control-plane): assertSchemaCompliant is required ' +
                        '(write-path enforcement; fail-closed).',
                );
            }
            if (!options.sideTableAppender) {
                throw new ProtocolError(
                    'INTERNAL_ERROR',
                    'ActionRecorder(kind=control-plane): sideTableAppender is required ' +
                        '(production-path wiring; fail-closed).',
                );
            }
            this.sessionOwnerResolver = options.sessionOwnerResolver;
            this.schemaValidator = options.assertSchemaCompliant;
            this.sideTableAppender = options.sideTableAppender;
        } else {
            this.sessionOwnerResolver = null;
            this.schemaValidator = null;
            this.sideTableAppender = null;
        }

        this.ledgerPrivateKey = normalizeSigningPrivateKey(configuredKey);
        this.ledgerPublicKey = derivePublicKeyFromPrivateKey(configuredKey);
    }

    public async record(input: ActionRecordInput): Promise<RecordWriteResult> {
        // Lane enforcement:
        // The discriminated union's kind is not just a type-level annotation; at runtime it also rejects cross-channel writes by kind.
        // Defensive goal: prevent a SessionSupersedeRecorder injected into a standard recorder from
        // silently writing SESSION_SUPERSEDED, or a control-plane recorder being misused to write business-lane records.
        this.assertLaneAllowed(input);

        // The control-plane write path enforces the binding + schema guards.
        // These two guards run after assertLaneAllowed and before the DB transaction,
        // ensuring every control-plane INSERT must pass session-binding validation + AJV schema validation.
        // Bypassing SessionSupersedeRecorder and calling record() directly must also go through this guard layer.
        if (this.kind === 'control-plane') {
            // AJV schema validation (synchronous; assertSchemaCompliant throws internally for fail-closed)
            this.schemaValidator!({
                agentDid: input.agentDid as string,
                principalDid: input.principalDid as string,
                actionType: input.actionType,
                parametersSummary: input.parametersSummary ?? null,
            });

            // Session-binding validation (asynchronous; must query the session registry)
            // Hardened policy: a present sessionId alone triggers validation (fail-closed)
            // The original logic only validated when sessionId + affectedAgentDid + affectedPrincipalDid were all present,
            // so an attacker could omit one field to bypass validation. After hardening, a present sessionId must resolve and match.
            const params = input.parametersSummary;
            if (params !== null && params !== undefined) {
                const sessionId = params['oldSessionId'] as string | undefined;
                const affectedAgentDid = params['affectedAgentDid'] as
                    | string
                    | undefined;
                const affectedPrincipalDid = params['affectedPrincipalDid'] as
                    | string
                    | undefined;

                // A present sessionId resolves (no longer requires the triple to all be present)
                if (sessionId) {
                    const owner =
                        await this.sessionOwnerResolver!.resolveOwner(
                            sessionId,
                        );
                    if (owner === null) {
                        throw new ProtocolError(
                            'INTERNAL_ERROR',
                            `SESSION_BINDING_MISMATCH: sessionId '${sessionId}' not found in session registry. ` +
                                `Cannot verify affected DID binding (fail-closed). ` +
                                `(sessionId binding enforcement).`,
                        );
                    }
                    // When present, affectedAgentDid must match the session owner
                    if (
                        affectedAgentDid &&
                        affectedAgentDid !== (owner.agentDid as string)
                    ) {
                        throw new ProtocolError(
                            'INTERNAL_ERROR',
                            `SESSION_BINDING_MISMATCH: affectedAgentDid='${affectedAgentDid}' ` +
                                `does not match session owner agentDid='${owner.agentDid}' ` +
                                `for sessionId='${sessionId}' (fail-closed). ` +
                                `(sessionId binding enforcement).`,
                        );
                    }
                    // When present, affectedPrincipalDid must match the session owner
                    if (
                        affectedPrincipalDid &&
                        affectedPrincipalDid !== (owner.principalDid as string)
                    ) {
                        throw new ProtocolError(
                            'INTERNAL_ERROR',
                            `SESSION_BINDING_MISMATCH: affectedPrincipalDid='${affectedPrincipalDid}' ` +
                                `does not match session owner principalDid='${owner.principalDid}' ` +
                                `for sessionId='${sessionId}' (fail-closed). ` +
                                `(sessionId binding enforcement).`,
                        );
                    }
                }
            }
        }

        const recordId = input.recordId ?? randomUUID();
        const createdAt = (input.createdAt ??
            new Date().toISOString()) as Timestamp;

        return withTransaction(this.dbPool, async (client) => {
            await lockAgentChain(client, input.agentDid);

            const previousRecordHash = await loadPreviousRecordHash(
                client,
                input.agentDid,
            );
            const parametersSummary = input.parametersSummary ?? null;
            const authorizationRef = input.authorizationRef ?? null;
            const resultSummary = input.resultSummary ?? null;
            // Since v0.2.0 ledger records default to base64url;
            // callers can override explicitly via input.outputEncoding (for backward-compatible test purposes).
            const outputEncoding = input.outputEncoding ?? LEDGER_ENCODING;
            const unsignedPayload = buildUnsignedRecordPayload({
                recordId,
                agentDid: input.agentDid,
                principalDid: input.principalDid,
                actionType: input.actionType,
                parametersSummary,
                authorizationRef,
                resultSummary,
                previousRecordHash,
                createdAt,
                delegationDepth: input.delegationDepth,
                sessionId: input.sessionId,
            });
            const recordHash = computeRecordHash(
                unsignedPayload,
                previousRecordHash,
                outputEncoding,
            );
            const actorSignature = createRecordSignature(
                unsignedPayload,
                input.actorPrivateKey,
                outputEncoding,
            );
            const ledgerSignature = createRecordSignature(
                unsignedPayload,
                this.ledgerPrivateKey,
                outputEncoding,
            );

            await client.query(
                `
                INSERT INTO policy.action_records (
                    record_id,
                    agent_did,
                    principal_did,
                    action_type,
                    parameters_summary,
                    authorization_ref,
                    result_summary,
                    record_hash,
                    previous_record_hash,
                    actor_signature,
                    ledger_signature,
                    delegation_depth,
                    session_id,
                    created_at
                )
                VALUES ($1, $2, $3, $4, $5::jsonb, $6::jsonb, $7::jsonb, $8, $9, $10, $11, $12, $13, $14)
                `,
                [
                    recordId, // $1
                    input.agentDid, // $2
                    input.principalDid, // $3
                    input.actionType, // $4
                    JSON.stringify(parametersSummary), // $5
                    JSON.stringify(authorizationRef), // $6
                    JSON.stringify(resultSummary), // $7
                    recordHash, // $8
                    previousRecordHash, // $9
                    actorSignature, // $10
                    ledgerSignature, // $11
                    input.delegationDepth ?? null, // $12
                    input.sessionId ?? null, // $13
                    createdAt, // $14
                ],
            );

            // After the control-plane write, synchronously append the side-table to form a tamper-evidence anchor.
            // transactionClient = the current transaction's pg.PoolClient, passed to the appender for an atomic write.
            // The InMemory stub ignores the client parameter; PostgresSideTableAppender
            // must use this client to INSERT the side-table row within the same transaction.
            // If append fails, it throws -> the whole transaction rolls back (guaranteed at the Postgres level).
            if (this.sideTableAppender) {
                await this.sideTableAppender.append(
                    {
                        recordId,
                        recordHash,
                        agentDid: input.agentDid,
                        createdAt,
                    } as SideTableEntry,
                    client,
                );
            }

            return {
                recordId,
                hash: recordHash,
            };
        });
    }

    /**
     * Lane runtime enforcement (including full SESSION_SUPERSEDED schema validation).
     *
     * A standard recorder may only write the business lane:
     *   - actionType ∈ HANDSHAKE_CAPABILITY_VOCABULARY (5 business-lane verbs);
     *   - neither agentDid nor principalDid may equal SESSION_GOVERNOR_DID.
     * A control-plane recorder may only write the governance channel:
     *   - actionType === SESSION_SUPERSEDED;
     *   - agentDid === principalDid === SESSION_GOVERNOR_DID;
     *   - parametersSummary must contain oldSessionId / reason / timestamp /
     *     affectedAgentDid / affectedPrincipalDid (schema required);
     * otherwise governor lane subject-scoped audit cannot scope to the row.
     *
     * Any out-of-lane write throws ProtocolError(INTERNAL_ERROR) fail-closed (a caller-side programming
     * error, not exposed to the protocol peer), preventing a silently mismatched audit row from being
     * written after the discriminated union is erased on the caller side (e.g. SessionSupersedeRecorder
     * holding a plain ActionRecorder reference).
     */
    private assertLaneAllowed(input: ActionRecordInput): void {
        const isGovernorActor =
            (input.agentDid as string) === SESSION_GOVERNOR_DID;
        const isGovernorPrincipal =
            (input.principalDid as string) === SESSION_GOVERNOR_DID;
        const isControlPlaneActionType =
            input.actionType === ACTION_SESSION_SUPERSEDED;

        if (this.kind === 'standard') {
            if (
                isGovernorActor ||
                isGovernorPrincipal ||
                isControlPlaneActionType
            ) {
                throw new ProtocolError(
                    'INTERNAL_ERROR',
                    `ActionRecorder(kind='standard') cannot write control-plane events ` +
                        `(actionType=${input.actionType}, agentDid=${input.agentDid}). ` +
                        `Use SessionSupersedeRecorder + kind='control-plane' for governor events.`,
                );
            }
            return;
        }
        // kind === 'control-plane'
        if (
            !isGovernorActor ||
            !isGovernorPrincipal ||
            !isControlPlaneActionType
        ) {
            throw new ProtocolError(
                'INTERNAL_ERROR',
                `ActionRecorder(kind='control-plane') only accepts SESSION_SUPERSEDED ` +
                    `with agentDid===principalDid===SESSION_GOVERNOR_DID ` +
                    `(got actionType=${input.actionType}, agentDid=${input.agentDid}, ` +
                    `principalDid=${input.principalDid}).`,
            );
        }

        // The control-plane SESSION_SUPERSEDED parametersSummary
        // must satisfy the schema's required[] (any missing field is fail-closed) so that the governor
        // lane subject scope can reliably take effect.
        // It also validates the reason enum + the reason/newSessionId pairing
        // (the schema only allows FORCED_CLOSE with a null newSessionId).
        const params = input.parametersSummary;
        if (params === null || params === undefined) {
            throw new ProtocolError(
                'INTERNAL_ERROR',
                `ActionRecorder(kind='control-plane') requires parametersSummary ` +
                    `for SESSION_SUPERSEDED (oldSessionId / reason / timestamp / ` +
                    `affectedAgentDid / affectedPrincipalDid all required).`,
            );
        }
        const required = [
            'oldSessionId',
            'reason',
            'timestamp',
            'affectedAgentDid',
            'affectedPrincipalDid',
        ] as const;
        for (const field of required) {
            const value = params[field];
            if (
                value === undefined ||
                value === null ||
                (typeof value === 'string' && value.length === 0)
            ) {
                throw new ProtocolError(
                    'INTERNAL_ERROR',
                    `ActionRecorder(kind='control-plane') SESSION_SUPERSEDED ` +
                        `parametersSummary missing required field '${field}' ` +
                        `(governor lane subject-scoped audit cannot scope to this row).`,
                );
            }
        }
        // reason / newSessionId pairing constraint (schemas.ts if/then branch):
        // only FORCED_CLOSE allows newSessionId=null; every other reason requires a non-empty string successor ID.
        const reason = params['reason'];
        const newSessionId = params['newSessionId'];
        const validReasons = [
            'EXPLICIT_CLOSE',
            'TOKEN_REVOKED',
            'IDLE_EXPIRED',
            'FORCED_CLOSE',
        ];
        if (typeof reason !== 'string' || !validReasons.includes(reason)) {
            throw new ProtocolError(
                'INTERNAL_ERROR',
                `ActionRecorder(kind='control-plane') SESSION_SUPERSEDED ` +
                    `reason='${String(reason)}' is not in allowed enum ` +
                    `[${validReasons.join(', ')}].`,
            );
        }
        if (reason === 'FORCED_CLOSE') {
            if (
                newSessionId !== null &&
                !(typeof newSessionId === 'string' && newSessionId.length > 0)
            ) {
                throw new ProtocolError(
                    'INTERNAL_ERROR',
                    `ActionRecorder(kind='control-plane') SESSION_SUPERSEDED ` +
                        `FORCED_CLOSE: newSessionId must be null or a non-empty string.`,
                );
            }
        } else {
            if (typeof newSessionId !== 'string' || newSessionId.length === 0) {
                throw new ProtocolError(
                    'INTERNAL_ERROR',
                    `ActionRecorder(kind='control-plane') SESSION_SUPERSEDED ` +
                        `reason='${reason}' requires newSessionId to be a non-empty string ` +
                        `(only FORCED_CLOSE allows null successor).`,
                );
            }
        }
        // Note: write-path enforcement is in place.
        // The reverse session-binding check lives in the ActionRecorder kind='control-plane' branch
        // (this.sessionOwnerResolver.resolveOwner is enforced inside record(), before the DB transaction).
        // The remaining full AJV validation is also in that branch
        // (this.schemaValidator is enforced inside record(), before the DB transaction).
    }

    public async query(
        filters: ActionRecordQueryFilters = {},
    ): Promise<ActionRecordQueryResult> {
        const clauses: string[] = [];
        // values carries string/number/bigint together: after migration 005 the cursor id is a bigint
        const values: Array<string | number | bigint> = [];

        appendCondition(clauses, values, 'agent_did =', filters.agentDid);
        appendCondition(
            clauses,
            values,
            'principal_did =',
            filters.principalDid,
        );
        appendCondition(clauses, values, 'action_type =', filters.actionType);
        appendCondition(clauses, values, 'created_at >=', filters.createdFrom);
        appendCondition(clauses, values, 'created_at <=', filters.createdTo);

        if (filters.cursor !== undefined) {
            const { ts, id } = parseCursor(filters.cursor);
            values.push(ts, id);
            clauses.push(
                `(created_at, id) > ($${values.length - 1}::timestamptz, $${values.length})`,
            );
        }

        const limit = filters.limit ?? 100;
        // Fetch one extra row: if limit+1 rows come back, a next page truly exists
        values.push(limit + 1);

        const whereClause =
            clauses.length > 0 ? `WHERE ${clauses.join(' AND ')}` : '';
        // The default ASC matches the cursor-pagination convention; DESC is only for the "fetch the most recent N" case (no pagination)
        const orderClause =
            filters.order === 'desc'
                ? 'ORDER BY created_at DESC, id DESC'
                : 'ORDER BY created_at ASC, id ASC';
        const result = await this.dbPool.query<ActionRecordRow>(
            `
        SELECT
            id,
            record_id,
            agent_did,
            principal_did,
            action_type,
            parameters_summary,
            authorization_ref,
            result_summary,
            record_hash,
            previous_record_hash,
            actor_signature,
            ledger_signature,
            delegation_depth,
            session_id,
            created_at
        FROM policy.action_records
        ${whereClause}
        ${orderClause}
        LIMIT $${values.length}
        `,
            values,
        );

        const hasMore = result.rows.length > limit;
        const pageRows = hasMore ? result.rows.slice(0, limit) : result.rows;
        const records = pageRows.map(mapActionRecordRow);
        const lastRow = pageRows[pageRows.length - 1];
        const nextCursor =
            hasMore && lastRow !== undefined
                ? `${new Date(lastRow.created_at).toISOString()}|${lastRow.id}`
                : undefined;

        return { records, nextCursor };
    }
}

function appendCondition(
    clauses: string[],
    values: Array<string | number | bigint>,
    expression: string,
    value: string | undefined,
): void {
    if (value === undefined) {
        return;
    }

    values.push(value);
    clauses.push(`${expression} $${values.length}`);
}

async function lockAgentChain(
    client: PoolClient,
    agentDid: DID,
): Promise<void> {
    await client.query('SELECT pg_advisory_xact_lock(hashtext($1))', [
        agentDid,
    ]);
}

async function loadPreviousRecordHash(
    client: PoolClient,
    agentDid: DID,
): Promise<string> {
    const result = await client.query<{ record_hash: string }>(
        `
        SELECT record_hash
        FROM policy.action_records
        WHERE agent_did = $1
        ORDER BY created_at DESC, id DESC
        LIMIT 1
        `,
        [agentDid],
    );

    return result.rows[0]?.record_hash ?? '';
}

function parseCursor(cursor: string): { ts: string; id: bigint } {
    // After migration 005 the id is a bigint: parseInt loses precision above 2^53, so BigInt is required.
    const pipeIndex = cursor.indexOf('|');
    return {
        ts: cursor.slice(0, pipeIndex),
        id: BigInt(cursor.slice(pipeIndex + 1)),
    };
}

function mapActionRecordRow(row: ActionRecordRow): PersistedActionRecord {
    return toPersistedRecord({
        recordId: row.record_id,
        agentDid: row.agent_did as DID,
        principalDid: row.principal_did as DID,
        actionType: row.action_type,
        parametersSummary: row.parameters_summary,
        authorizationRef: row.authorization_ref,
        resultSummary: row.result_summary,
        previousRecordHash: row.previous_record_hash,
        recordHash: row.record_hash,
        actorSignature:
            row.actor_signature as PersistedActionRecord['actorSignature'],
        ledgerSignature:
            row.ledger_signature as PersistedActionRecord['ledgerSignature'],
        delegationDepth: row.delegation_depth ?? undefined,
        sessionId: row.session_id ?? undefined,
        createdAt: toTimestamp(row.created_at),
    });
}
