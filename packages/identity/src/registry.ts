import type { PoolClient } from 'pg';

import type { AgentIdentityDocument, DID } from '@coivitas/types';
import { ProtocolError } from '@coivitas/types';
import { type DatabasePool, withTransaction } from '@coivitas/shared';

import { verifyAgentIdentityDocument } from './did-agent.js';

// Corresponds to the SQL columns, including the added version, previous_document, rotation_state, rotation_started_at
interface AgentRow {
    did: string;
    document: AgentIdentityDocument;
    status: 'active' | 'suspended' | 'deactivated';
    version: number;
    previous_document: AgentIdentityDocument | null;
    rotation_state: 'ACTIVE' | 'ROTATING';
    rotation_started_at: string | null;
}

export class IdentityRegistry {
    public constructor(private readonly dbPool: DatabasePool) {}

    public async register(document: AgentIdentityDocument): Promise<void> {
        const verification = verifyAgentIdentityDocument(document);

        if (!verification.valid) {
            throw new ProtocolError(
                'BINDING_PROOF_INVALID',
                verification.errors
                    .map((error) => `${error.field}: ${error.message}`)
                    .join('; '),
            );
        }

        await withTransaction(this.dbPool, async (client) => {
            const existing = await client.query<{ status: AgentRow['status'] }>(
                'SELECT status FROM identity.agents WHERE did = $1',
                [document.id],
            );

            if (existing.rows.length > 0) {
                throw new ProtocolError(
                    'IDENTITY_ALREADY_EXISTS',
                    `Identity ${document.id} already exists.`,
                );
            }

            // version/rotation_state use the SQL DEFAULT (1/'ACTIVE'), no need to pass them explicitly
            await client.query(
                `
                INSERT INTO identity.agents (did, document, status)
                VALUES ($1, $2::jsonb, 'active')
                `,
                [document.id, JSON.stringify(document)],
            );
        });
    }

    // query() injects version from the SQL version column into the returned document, ensuring backward compatibility.
    // The originally registered document's JSONB may not contain a version field (createAgentIdentity does not set it).
    public async query(did: DID): Promise<AgentIdentityDocument | null> {
        const result = await this.dbPool.query<Pick<AgentRow, 'document' | 'version'>>(
            `
            SELECT document, version
            FROM identity.agents
            WHERE did = $1
              AND status = 'active'
            `,
            [did],
        );

        if (!result.rows[0]) return null;
        const { document, version } = result.rows[0];
        return { ...document, version };
    }

    // update() does not call verifyAgentIdentityDocument — that responsibility belongs to the caller (e.g. the completeKeyRotation flow).
    // Reason: unit tests use simplified documents (no rotationProof) to test the optimistic-lock logic; integration tests use real documents to cover legitimacy.

    // Extra checks on the key-rotation path:
    // - rotationProof.oldPublicKey must equal the publicKey currently stored in the DB (continuity)
    // - write rotation_state='ROTATING' + rotation_started_at=server time (the authoritative grace-period source)
    public async update(
        document: AgentIdentityDocument,
        expectedVersion: number,
    ): Promise<void> {
        const newVersion = document.version ?? (expectedVersion + 1);

        // Check that the document version must be expectedVersion + 1
        if (newVersion !== expectedVersion + 1) {
            throw new ProtocolError(
                'VERSION_CONFLICT',
                `Document version must be ${expectedVersion + 1}, got ${newVersion}.`,
            );
        }

        await withTransaction(this.dbPool, async (client) => {
            // FOR UPDATE locks the row, preventing concurrency
            const existing = await client.query<Pick<AgentRow, 'status' | 'version' | 'document' | 'rotation_state'>>(
                `
                SELECT status, version, document, rotation_state
                FROM identity.agents
                WHERE did = $1
                FOR UPDATE
                `,
                [document.id],
            );

            if (existing.rows.length === 0) {
                throw new ProtocolError(
                    'IDENTITY_NOT_FOUND',
                    `Identity ${document.id} was not found.`,
                );
            }

            // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
            const row = existing.rows[0]!;

            if (row.status === 'deactivated') {
                throw new ProtocolError(
                    'IDENTITY_DEACTIVATED',
                    `Identity ${document.id} is deactivated.`,
                );
            }

            // Determine whether this is the key-rotation path (publicKey changed)
            const isKeyRotation = document.publicKey !== row.document.publicKey;

            if (isKeyRotation) {
                // Key-continuity check: rotationProof.oldPublicKey must match the current DB public key
                // Prevents a forged rotation that is internally self-consistent but disconnected from on-chain history (step 4b)
                if (!document.rotationProof) {
                    throw new ProtocolError(
                        'BINDING_PROOF_INVALID',
                        'Key rotation requires rotationProof.',
                    );
                }
                if (document.rotationProof.oldPublicKey !== row.document.publicKey) {
                    throw new ProtocolError(
                        'BINDING_PROOF_INVALID',
                        `rotationProof.oldPublicKey does not match current stored publicKey.`,
                    );
                }

                // Optimistic lock: UPDATE ... WHERE version = $expectedVersion, rowCount=0 → concurrent conflict
                // Key rotation: write rotation_state='ROTATING', with rotation_started_at using server time (the authoritative source)
                const updateResult = await client.query(
                    `
                    UPDATE identity.agents
                    SET document             = $1::jsonb,
                        version              = $2,
                        previous_document    = $3::jsonb,
                        rotation_state       = 'ROTATING',
                        rotation_started_at  = NOW(),
                        updated_at           = NOW()
                    WHERE did = $4
                      AND version = $5
                    `,
                    [
                        JSON.stringify(document),
                        newVersion,
                        JSON.stringify(row.document),
                        document.id,
                        expectedVersion,
                    ],
                );

                if (updateResult.rowCount === 0) {
                    throw new ProtocolError(
                        'VERSION_CONFLICT',
                        `Expected version ${expectedVersion}, but concurrent update changed it.`,
                    );
                }
            } else {
                // Ordinary field-update path: does not modify rotation_state/rotation_started_at
                const updateResult = await client.query(
                    `
                    UPDATE identity.agents
                    SET document          = $1::jsonb,
                        version           = $2,
                        previous_document = $3::jsonb,
                        updated_at        = NOW()
                    WHERE did = $4
                      AND version = $5
                    `,
                    [
                        JSON.stringify(document),
                        newVersion,
                        JSON.stringify(row.document),
                        document.id,
                        expectedVersion,
                    ],
                );

                if (updateResult.rowCount === 0) {
                    throw new ProtocolError(
                        'VERSION_CONFLICT',
                        `Expected version ${expectedVersion}, but concurrent update changed it.`,
                    );
                }
            }
        });
    }

    // Return the DID's document version history (descending by version).
    // Note: the current schema only stores the two most recent versions (the current document + the previous-version snapshot).
    public async getDocumentHistory(did: DID): Promise<AgentIdentityDocument[]> {
        const result = await this.dbPool.query<Pick<AgentRow, 'document' | 'version' | 'previous_document'>>(
            `
            SELECT document, version, previous_document
            FROM identity.agents
            WHERE did = $1
            `,
            [did],
        );

        if (result.rows.length === 0) {
            return [];
        }

        // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
        const { document, version, previous_document } = result.rows[0]!;
        // Inject the SQL version column into the current document
        const current = { ...document, version };
        const history: AgentIdentityDocument[] = [current];

        if (previous_document !== null) {
            // previous_document jsonb is the previous-version snapshot from update (registry.ts:162/189
            // writes row.document into that column); the snapshot itself has no version column; the current schema only
            // keeps the two most recent versions, so previous.version = current.version - 1 holds reliably.
            // Without injecting it, history[1].version would be undefined, and consumers (e.g. key-rotation
            // history inspection) could not identify the version number.
            history.push({ ...previous_document, version: version - 1 });
        }

        // Sort descending by version (defensive sort)
        history.sort((a, b) => (b.version ?? 1) - (a.version ?? 1));
        return history;
    }

    public async deactivate(did: DID): Promise<void> {
        await withTransaction(this.dbPool, async (client) => {
            const existing = await lockAgentRow(client, did);

            if (!existing) {
                throw new ProtocolError(
                    'IDENTITY_NOT_FOUND',
                    `Identity ${did} was not found.`,
                );
            }

            if (existing.status === 'deactivated') {
                return;
            }

            await client.query(
                `
                UPDATE identity.agents
                SET status = 'deactivated',
                    updated_at = NOW()
                WHERE did = $1
                `,
                [did],
            );
        });
    }

    // Audit-only query: does not filter by status, returning identities in any status along with their triple-binding check result.
    // Triple binding: params.did === row.did === row.document.id, preventing DB data tampering or row-level contamination.
    // The caller (audit middleware) needs to read the full information of revoked/suspended identities, so it is not restricted to status='active'.
    public async queryForAudit(did: DID): Promise<{
        document: AgentIdentityDocument;
        status: 'active' | 'suspended' | 'deactivated';
    } | null> {
        const result = await this.dbPool.query<Pick<AgentRow, 'did' | 'document' | 'status' | 'version'>>(
            `SELECT did, document, status, version FROM identity.agents WHERE did = $1`,
            [did],
        );
        if (!result.rows[0]) return null;
        const row = result.rows[0];
        // Triple-binding check: params.did === row.did === document.id
        if (row.did !== did || row.did !== row.document.id) {
            throw new ProtocolError('BINDING_PROOF_INVALID', `Triple binding check failed for DID ${did}.`);
        }
        const verification = verifyAgentIdentityDocument(row.document);
        if (!verification.valid) {
            throw new ProtocolError(
                'BINDING_PROOF_INVALID',
                verification.errors.map((e) => `${e.field}: ${e.message}`).join('; '),
            );
        }
        return { document: { ...row.document, version: row.version }, status: row.status };
    }
}

async function lockAgentRow(
    client: PoolClient,
    did: DID,
): Promise<Pick<AgentRow, 'status'> | null> {
    const result = await client.query<Pick<AgentRow, 'status'>>(
        `
        SELECT status
        FROM identity.agents
        WHERE did = $1
        FOR UPDATE
        `,
        [did],
    );

    return result.rows[0] ?? null;
}
