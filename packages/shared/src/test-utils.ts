import { randomBytes } from 'node:crypto';
import { once } from 'node:events';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import type { Application } from 'express';

import { Pool } from 'pg';

import { createPool, runMigrations, type DatabasePool } from './database.js';
import { createApp } from './server.js';

export interface TestDatabaseContext {
    pool: DatabasePool;
    cleanup: () => Promise<void>;
}

export interface TestServerContext {
    url: string;
    close: () => Promise<void>;
}

export interface TestResponse {
    status: number;
    body: unknown;
}

export async function createTestDatabase(): Promise<TestDatabaseContext> {
    const adminConnectionString = createAdminConnectionString();
    const databaseName = `coivitas_test_${randomBytes(6).toString('hex')}`;
    const databaseConnectionString =
        createDatabaseConnectionString(databaseName);
    const adminPool = new Pool({ connectionString: adminConnectionString });

    await adminPool.query(`CREATE DATABASE ${escapeIdentifier(databaseName)}`);

    const pool = createPool({
        connectionString: databaseConnectionString,
    });

    try {
        await runWorkspaceMigrations(pool);
    } catch (error) {
        await pool.end();
        await dropDatabase(adminPool, databaseName);
        await adminPool.end();
        throw error;
    }

    return {
        pool,
        cleanup: async () => {
            await pool.end();
            await dropDatabase(adminPool, databaseName);
            await adminPool.end();
        },
    };
}

export async function createTestServer(
    routes: (app: Application) => void,
): Promise<TestServerContext> {
    const app = createApp();
    routes(app);

    const server = app.listen(0, '127.0.0.1');
    await once(server, 'listening');

    const address = server.address();
    if (!address || typeof address === 'string') {
        throw new Error('Test server failed to bind to a TCP port');
    }

    return {
        url: `http://127.0.0.1:${address.port}`,
        close: async () => {
            server.closeAllConnections?.();
            await new Promise<void>((resolve, reject) => {
                server.close((error) => {
                    if (error) {
                        reject(error);
                        return;
                    }

                    resolve();
                });
            });
        },
    };
}

export async function makeRequest(
    url: string,
    method: string,
    requestPath: string,
    body?: unknown,
): Promise<TestResponse> {
    const response = await fetch(new URL(requestPath, url), {
        method,
        headers:
            body === undefined
                ? undefined
                : { 'content-type': 'application/json' },
        body: body === undefined ? undefined : JSON.stringify(body),
    });

    const contentType = response.headers.get('content-type') ?? '';
    const responseBody =
        response.status === 204
            ? null
            : contentType.includes('application/json')
              ? await response.json()
              : await response.text();

    return {
        status: response.status,
        body: responseBody,
    };
}

async function runWorkspaceMigrations(pool: DatabasePool): Promise<void> {
    const packagesDirectory = path.join(getRepositoryRoot(), 'packages');
    const packageEntries = await fs.readdir(packagesDirectory, {
        withFileTypes: true,
    });

    for (const entry of packageEntries
        .filter((candidate) => candidate.isDirectory())
        .sort((left, right) => left.name.localeCompare(right.name))) {
        await runMigrations(
            pool,
            path.join(packagesDirectory, entry.name, 'sql'),
        );
    }
}

function getRepositoryRoot(): string {
    const currentFile = fileURLToPath(import.meta.url);
    return path.resolve(path.dirname(currentFile), '../../..');
}

function createAdminConnectionString(): string {
    const databaseUrl = getBaseConnectionString();
    const url = new URL(databaseUrl);
    url.pathname = `/${process.env.PGBOOTSTRAP_DB ?? 'postgres'}`;
    return url.toString();
}

function createDatabaseConnectionString(databaseName: string): string {
    const databaseUrl = getBaseConnectionString();
    const url = new URL(databaseUrl);
    url.pathname = `/${databaseName}`;
    return url.toString();
}

function getBaseConnectionString(): string {
    return (
        process.env.DATABASE_URL ??
        'postgresql://coivitas:coivitas@127.0.0.1:5432/coivitas_dev'
    );
}

async function dropDatabase(
    adminPool: Pool,
    databaseName: string,
): Promise<void> {
    await adminPool.query(
        `
        SELECT pg_terminate_backend(pid)
        FROM pg_stat_activity
        WHERE datname = $1
          AND pid <> pg_backend_pid()
        `,
        [databaseName],
    );
    await adminPool.query(
        `DROP DATABASE IF EXISTS ${escapeIdentifier(databaseName)}`,
    );
}

function escapeIdentifier(identifier: string): string {
    return `"${identifier.replaceAll('"', '""')}"`;
}
