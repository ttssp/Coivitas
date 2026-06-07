import type { DatabasePool } from '@coivitas/shared';
import type { CapabilityToken, DID, Timestamp } from '@coivitas/types';

interface TokenStoreRow {
    token_id: string;
    agent_did: string;
    token: CapabilityToken | string;
    valid_until: string | Date | null;
    created_at: string | Date;
}

export interface StoredToken {
    tokenId: string;
    agentDid: DID;
    token: CapabilityToken;
    validUntil: Timestamp | null;
    createdAt: Timestamp;
}

export class TokenStore {
    public constructor(private readonly pool: DatabasePool) {}

    public async store(
        agentDid: DID,
        token: CapabilityToken,
    ): Promise<StoredToken> {
        const validUntil = token.expiresAt ?? null;

        const result = await this.pool.query<TokenStoreRow>(
            `
            INSERT INTO policy.token_store (token_id, agent_did, token, valid_until)
            VALUES ($1, $2, $3::jsonb, $4)
            ON CONFLICT (token_id) DO UPDATE
            SET agent_did = EXCLUDED.agent_did,
                token = EXCLUDED.token,
                valid_until = EXCLUDED.valid_until
            RETURNING token_id, agent_did, token, valid_until, created_at
            `,
            [token.id, agentDid, JSON.stringify(token), validUntil],
        );

        return mapTokenStoreRow(result.rows[0]!);
    }

    public async getTokensForAgent(agentDid: DID): Promise<CapabilityToken[]> {
        const result = await this.pool.query<TokenStoreRow>(
            `
            SELECT token_id, agent_did, token, valid_until, created_at
            FROM policy.token_store
            WHERE agent_did = $1
            ORDER BY created_at ASC, id ASC
            `,
            [agentDid],
        );

        return result.rows.map((row) => parseToken(row.token));
    }

    public async getToken(tokenId: string): Promise<CapabilityToken | null> {
        const result = await this.pool.query<TokenStoreRow>(
            `
            SELECT token_id, agent_did, token, valid_until, created_at
            FROM policy.token_store
            WHERE token_id = $1
            `,
            [tokenId],
        );

        return result.rows[0] ? parseToken(result.rows[0].token) : null;
    }

    public async remove(tokenId: string): Promise<boolean> {
        const result = await this.pool.query(
            `
            DELETE FROM policy.token_store
            WHERE token_id = $1
            `,
            [tokenId],
        );

        return (result.rowCount ?? 0) > 0;
    }
}

function mapTokenStoreRow(row: TokenStoreRow): StoredToken {
    return {
        tokenId: row.token_id,
        agentDid: row.agent_did as DID,
        token: parseToken(row.token),
        validUntil:
            row.valid_until === null ? null : toTimestamp(row.valid_until),
        createdAt: toTimestamp(row.created_at),
    };
}

function parseToken(token: CapabilityToken | string): CapabilityToken {
    return typeof token === 'string'
        ? (JSON.parse(token) as CapabilityToken)
        : token;
}

function toTimestamp(value: string | Date): Timestamp {
    return (
        value instanceof Date
            ? value.toISOString()
            : new Date(value).toISOString()
    ) as Timestamp;
}
