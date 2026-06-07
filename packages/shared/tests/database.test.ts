import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { randomUUID } from 'node:crypto';

import { Pool } from 'pg';
import { afterEach, describe, expect, it } from 'vitest';

import { createPool, runMigrations, withTransaction } from '../src/database.js';

const describeIfDatabase = process.env.DATABASE_URL ? describe : describe.skip;

describeIfDatabase('database', () => {
    const poolsToClose = new Set<Pool>();
    const tablesToDrop = new Map<Pool, string[]>();

    afterEach(async () => {
        await Promise.all(
            Array.from(tablesToDrop.entries()).map(async ([pool, tables]) => {
                for (const table of tables) {
                    await pool.query(`DROP TABLE IF EXISTS "${table}"`);
                }
            }),
        );
        tablesToDrop.clear();

        await Promise.all(
            Array.from(poolsToClose).map(async (pool) => {
                await pool.end();
                poolsToClose.delete(pool);
            }),
        );
    });

    it('creates a pool using DATABASE_URL by default', async () => {
        const pool = createPool();
        poolsToClose.add(pool);

        const result = await pool.query<{ current_database: string }>(
            'SELECT current_database()',
        );

        expect(result.rows[0]?.current_database).toBeTruthy();
    });

    it('commits a successful transaction', async () => {
        const pool = createPool();
        poolsToClose.add(pool);
        const tableName = `transaction_commit_${randomUUID().replaceAll('-', '')}`;
        rememberTable(pool, tableName, tablesToDrop);

        await pool.query(`CREATE TABLE "${tableName}"(value TEXT NOT NULL)`);

        await withTransaction(pool, async (client) => {
            await client.query(
                `INSERT INTO "${tableName}"(value) VALUES ($1)`,
                ['committed'],
            );
        });

        const result = await pool.query<{ count: string }>(
            `SELECT COUNT(*)::text AS count FROM "${tableName}"`,
        );

        expect(result.rows[0]?.count).toBe('1');
    });

    it('rolls back a failed transaction', async () => {
        const pool = createPool();
        poolsToClose.add(pool);
        const tableName = `transaction_rollback_${randomUUID().replaceAll('-', '')}`;
        rememberTable(pool, tableName, tablesToDrop);

        await pool.query(`CREATE TABLE "${tableName}"(value TEXT NOT NULL)`);

        await expect(
            withTransaction(pool, async (client) => {
                await client.query(
                    `INSERT INTO "${tableName}"(value) VALUES ($1)`,
                    ['discarded'],
                );
                throw new Error('boom');
            }),
        ).rejects.toThrow('boom');

        const result = await pool.query<{ count: string }>(
            `SELECT COUNT(*)::text AS count FROM "${tableName}"`,
        );

        expect(result.rows[0]?.count).toBe('0');
    });

    it('runs SQL migrations in filename order', async () => {
        const pool = createPool();
        poolsToClose.add(pool);
        const tableName = `migration_order_${randomUUID().replaceAll('-', '')}`;
        rememberTable(pool, tableName, tablesToDrop);

        const tempDirectory = await mkdtemp(
            path.join(os.tmpdir(), 'shared-migrations-'),
        );

        try {
            await writeFile(
                path.join(tempDirectory, '001-create-table.sql'),
                `
                CREATE TABLE IF NOT EXISTS "${tableName}" (
                    id INTEGER PRIMARY KEY,
                    note TEXT NOT NULL
                );
                `,
                'utf8',
            );
            await writeFile(
                path.join(tempDirectory, '002-seed.sql'),
                `
                INSERT INTO "${tableName}" (id, note)
                VALUES (1, 'applied');
                `,
                'utf8',
            );

            await runMigrations(pool, tempDirectory);

            const result = await pool.query<{ note: string }>(
                `SELECT note FROM "${tableName}" WHERE id = 1`,
            );

            expect(result.rows[0]?.note).toBe('applied');
        } finally {
            await rm(tempDirectory, { recursive: true, force: true });
        }
    });
});

function rememberTable(
    pool: Pool,
    tableName: string,
    tablesToDrop: Map<Pool, string[]>,
): void {
    const tables = tablesToDrop.get(pool) ?? [];
    tables.push(tableName);
    tablesToDrop.set(pool, tables);
}
