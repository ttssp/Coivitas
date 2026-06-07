import { Pool } from 'pg';
import { afterEach, describe, expect, it } from 'vitest';

import {
    createTestDatabase,
    createTestServer,
    makeRequest,
} from '../src/test-utils.js';

const describeIfDatabase = process.env.DATABASE_URL ? describe : describe.skip;

describe('test-utils server helpers', () => {
    const activeServers: Array<{ close: () => Promise<void> }> = [];

    afterEach(async () => {
        await Promise.all(
            activeServers.splice(0).map(async (server) => server.close()),
        );
    });

    it('starts a test server on a random port and serves routes', async () => {
        const server = await createTestServer((app) => {
            app.get('/hello', (_request, response) => {
                response.status(200).json({ ok: true });
            });
        });
        activeServers.push(server);

        const response = await makeRequest(server.url, 'GET', '/hello');

        expect(response.status).toBe(200);
        expect(response.body).toEqual({ ok: true });
    });

    it('avoids port conflicts when servers start in parallel', async () => {
        const [firstServer, secondServer] = await Promise.all([
            createTestServer((app) => {
                app.get('/first', (_request, response) => {
                    response.status(200).json({ server: 'first' });
                });
            }),
            createTestServer((app) => {
                app.get('/second', (_request, response) => {
                    response.status(200).json({ server: 'second' });
                });
            }),
        ]);
        activeServers.push(firstServer, secondServer);

        expect(firstServer.url).not.toBe(secondServer.url);
    });
});

describeIfDatabase('test-utils database helpers', () => {
    const cleanupCallbacks: Array<() => Promise<void>> = [];

    afterEach(async () => {
        await Promise.all(
            cleanupCallbacks.splice(0).map(async (cleanup) => cleanup()),
        );
    });

    it('creates an isolated database and cleans it up', async () => {
        const context = await createTestDatabase();
        cleanupCallbacks.push(context.cleanup);

        const databaseNameResult = await context.pool.query<{
            current_database: string;
        }>('SELECT current_database()');
        const databaseName = databaseNameResult.rows[0]?.current_database;

        expect(databaseName).toMatch(/^coivitas_test_/);

        await context.pool.query(
            'CREATE TABLE shared_test_utils(value TEXT NOT NULL)',
        );
        await context.pool.query(
            'INSERT INTO shared_test_utils(value) VALUES ($1)',
            ['created'],
        );

        const rowCount = await context.pool.query<{ count: string }>(
            'SELECT COUNT(*)::text AS count FROM shared_test_utils',
        );
        expect(rowCount.rows[0]?.count).toBe('1');

        await context.cleanup();
        cleanupCallbacks.length = 0;

        const adminPool = new Pool({
            connectionString: createAdminConnectionString(),
        });

        try {
            const databaseLookup = await adminPool.query<{ exists: boolean }>(
                `
                SELECT EXISTS (
                    SELECT 1
                    FROM pg_database
                    WHERE datname = $1
                ) AS exists
                `,
                [databaseName],
            );

            expect(databaseLookup.rows[0]?.exists).toBe(false);
        } finally {
            await adminPool.end();
        }
    });
});

function createAdminConnectionString(): string {
    const url = new URL(
        process.env.DATABASE_URL ??
            'postgresql://coivitas:coivitas@127.0.0.1:5432/coivitas_dev',
    );
    url.pathname = `/${process.env.PGBOOTSTRAP_DB ?? 'postgres'}`;
    return url.toString();
}
