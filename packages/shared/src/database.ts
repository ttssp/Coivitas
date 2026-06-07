import { promises as fs } from 'node:fs';
import path from 'node:path';

import { Pool, type PoolClient, type PoolConfig } from 'pg';

// Note: do not register pgTypes.setTypeParser(20, ...) at module top level.
// That call is a process-wide global side effect that affects every query reading INT8, breaking
// modules like communication/session-store that rely on the default "BIGINT -> string" contract.
// Callers that need a bigint should convert explicitly at the read site with BigInt(row.id)
// (see packages/policy/src/recorder/*).

export type DatabasePool = Pool;

export interface CreatePoolConfig {
    connectionString?: string;
    max?: number;
}

export function createPool(config: CreatePoolConfig = {}): DatabasePool {
    const poolConfig: PoolConfig = {
        max: config.max ?? 10,
    };

    const connectionString =
        config.connectionString ?? process.env.DATABASE_URL;
    if (connectionString) {
        poolConfig.connectionString = connectionString;
    }

    return new Pool(poolConfig);
}

export async function runMigrations(
    pool: DatabasePool,
    migrationsDir: string,
): Promise<void> {
    const sqlFiles = await listMigrationFiles(migrationsDir);

    for (const filePath of sqlFiles) {
        const sql = await fs.readFile(filePath, 'utf8');
        if (sql.trim().length === 0) {
            continue;
        }

        await pool.query(sql);
    }
}

export async function withTransaction<T>(
    pool: DatabasePool,
    fn: (client: PoolClient) => Promise<T>,
): Promise<T> {
    const client = await pool.connect();

    try {
        await client.query('BEGIN');
        const result = await fn(client);
        await client.query('COMMIT');
        return result;
    } catch (error) {
        await client.query('ROLLBACK');
        throw error;
    } finally {
        client.release();
    }
}

async function listMigrationFiles(migrationsDir: string): Promise<string[]> {
    try {
        const entries = await fs.readdir(migrationsDir, {
            withFileTypes: true,
        });

        return entries
            .filter((entry) => entry.isFile() && entry.name.endsWith('.sql'))
            .map((entry) => path.join(migrationsDir, entry.name))
            .sort((left, right) => left.localeCompare(right));
    } catch (error) {
        if (isMissingDirectoryError(error)) {
            return [];
        }

        throw error;
    }
}

function isMissingDirectoryError(
    error: unknown,
): error is NodeJS.ErrnoException {
    return error instanceof Error && 'code' in error && error.code === 'ENOENT';
}
