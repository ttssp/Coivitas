import type { DatabasePool } from '@coivitas/shared';
import type { DID, Timestamp } from '@coivitas/types';

export interface RevokeTokenParams {
    tokenId: string;
    revokedBy: DID;
    reason?: string;
}

export interface RevocationRecord {
    tokenId: string;
    revokedBy: DID;
    revokedAt: Timestamp;
    reason: string | null;
}

export interface RevocationListOptions {
    cacheTtlMs?: number;
    now?: () => number;
}

interface RevocationRow {
    token_id: string;
    revoked_by: string;
    revoked_at: Date | string;
    reason: string | null;
}

interface RevocationCacheEntry {
    value: boolean;
    expiresAt: number;
}

export class RevocationList {
    private readonly cacheTtlMs: number;
    private readonly now: () => number;
    private readonly revokedCache = new Map<string, RevocationCacheEntry>();

    public constructor(
        private readonly pool: DatabasePool,
        options: RevocationListOptions = {},
    ) {
        this.cacheTtlMs = options.cacheTtlMs ?? 60_000;
        this.now = options.now ?? (() => Date.now());
    }

    public async revoke(params: RevokeTokenParams): Promise<RevocationRecord> {
        const result = await this.pool.query<RevocationRow>(
            `
            INSERT INTO identity.revocations (token_id, revoked_by, reason)
            VALUES ($1, $2, $3)
            ON CONFLICT (token_id) DO NOTHING
            RETURNING token_id, revoked_by, revoked_at, reason
            `,
            [params.tokenId, params.revokedBy, params.reason ?? null],
        );

        if (result.rowCount && result.rows[0]) {
            const record = mapRevocationRow(result.rows[0]);
            this.setCachedRevocation(params.tokenId, true);
            return record;
        }

        const existing = await this.getRevocation(params.tokenId);
        if (!existing) {
            throw new Error(
                `Failed to load revocation for token ${params.tokenId}.`,
            );
        }

        this.setCachedRevocation(params.tokenId, true);
        return existing;
    }

    public async isRevoked(tokenId: string): Promise<boolean> {
        const cached = this.getCachedRevocation(tokenId);
        if (cached !== null) {
            return cached;
        }

        const result = await this.pool.query<{ exists: boolean }>(
            `
            SELECT EXISTS(
                SELECT 1
                FROM identity.revocations
                WHERE token_id = $1
            ) AS exists
            `,
            [tokenId],
        );

        const value = Boolean(result.rows[0]?.exists);
        this.setCachedRevocation(tokenId, value);
        return value;
    }

    public async getRevocation(
        tokenId: string,
    ): Promise<RevocationRecord | null> {
        const result = await this.pool.query<RevocationRow>(
            `
            SELECT token_id, revoked_by, revoked_at, reason
            FROM identity.revocations
            WHERE token_id = $1
            `,
            [tokenId],
        );

        return result.rows[0] ? mapRevocationRow(result.rows[0]) : null;
    }

    public async getRevocations(
        since?: Timestamp,
    ): Promise<RevocationRecord[]> {
        const result = await this.pool.query<RevocationRow>(
            since
                ? `
                  SELECT token_id, revoked_by, revoked_at, reason
                  FROM identity.revocations
                  WHERE revoked_at >= $1
                  ORDER BY revoked_at ASC, id ASC
                  `
                : `
                  SELECT token_id, revoked_by, revoked_at, reason
                  FROM identity.revocations
                  ORDER BY revoked_at ASC, id ASC
                  `,
            since ? [since] : [],
        );

        return result.rows.map(mapRevocationRow);
    }

    private getCachedRevocation(tokenId: string): boolean | null {
        const cached = this.revokedCache.get(tokenId);
        if (!cached) {
            return null;
        }

        if (cached.expiresAt <= this.now()) {
            this.revokedCache.delete(tokenId);
            return null;
        }

        return cached.value;
    }

    private setCachedRevocation(tokenId: string, value: boolean): void {
        this.revokedCache.set(tokenId, {
            value,
            expiresAt: this.now() + this.cacheTtlMs,
        });
    }
}

function mapRevocationRow(row: RevocationRow): RevocationRecord {
    return {
        tokenId: row.token_id,
        revokedBy: row.revoked_by as DID,
        revokedAt: (row.revoked_at instanceof Date
            ? row.revoked_at.toISOString()
            : new Date(row.revoked_at).toISOString()) as Timestamp,
        reason: row.reason,
    };
}
