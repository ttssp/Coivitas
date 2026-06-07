import { mkdir, readFile, rename, unlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { createPool } from '@coivitas/shared';
import type { DatabasePool } from '@coivitas/shared';

const PRIVATE_KEY_HEADER = '-----BEGIN COIVITAS PRIVATE KEY-----';
const PRIVATE_KEY_FOOTER = '-----END COIVITAS PRIVATE KEY-----';

export function printOutput(value: unknown, asJson = false): void {
    if (asJson) {
        console.log(JSON.stringify(value, null, 2));
        return;
    }

    if (typeof value === 'string') {
        console.log(value);
        return;
    }

    console.log(JSON.stringify(value, null, 2));
}

export function resolveRegistryUrl(registryUrl?: string): string {
    const resolved = registryUrl ?? process.env.IDENTITY_REGISTRY_URL;
    if (!resolved) {
        throw new Error(
            'Identity registry URL is required. Pass --registry-url or set IDENTITY_REGISTRY_URL.',
        );
    }

    return resolved;
}

export async function postJson<TResponse>(
    url: string,
    pathname: string,
    payload: unknown,
): Promise<TResponse> {
    const response = await fetch(new URL(pathname, url), {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(payload),
    });

    if (!response.ok) {
        throw new Error(
            `HTTP ${response.status} while calling ${new URL(pathname, url).toString()}`,
        );
    }

    return (await response.json()) as TResponse;
}

export async function readJsonFile<T>(filePath: string): Promise<T> {
    return JSON.parse(await readFile(filePath, 'utf8')) as T;
}

export async function ensureKeyDirectory(): Promise<string> {
    const dir = path.join(os.homedir(), '.coivitas', 'keys');
    await mkdir(dir, { recursive: true });
    return dir;
}

export async function writePrivateKeyFile(
    did: string,
    privateKey: string,
): Promise<string> {
    const dir = await ensureKeyDirectory();
    const filePath = path.join(dir, sanitizeDidFilename(did) + '.pem');
    const pem = [PRIVATE_KEY_HEADER, privateKey, PRIVATE_KEY_FOOTER, ''].join(
        '\n',
    );

    await writeFile(filePath, pem, { mode: 0o600 });
    return filePath;
}

/**
 * Two-phase private key persistence: first write to `<did>.pem.pending`, then let the caller commit/rollback.
 *
 * Purpose: during key rotation, persist the new private key first (on failure → the registry is unchanged and there is no local side effect),
 * then commit and rename to the official .pem only after registry.update succeeds, guaranteeing that "whenever the registry
 * has published a new public key, the local side definitely holds the matching private key".
 */
export interface PendingKeyFile {
    pendingPath: string;
    finalPath: string;
    commit: () => Promise<string>;
    rollback: () => Promise<void>;
}

export async function stagePrivateKeyFile(
    did: string,
    privateKey: string,
): Promise<PendingKeyFile> {
    const dir = await ensureKeyDirectory();
    const finalPath = path.join(dir, sanitizeDidFilename(did) + '.pem');
    const pendingPath = finalPath + '.pending';
    const pem = [PRIVATE_KEY_HEADER, privateKey, PRIVATE_KEY_FOOTER, ''].join(
        '\n',
    );

    // 0o600 prevents other users from reading; write the pending file first so a failure does not pollute the existing .pem
    await writeFile(pendingPath, pem, { mode: 0o600 });

    return {
        pendingPath,
        finalPath,
        commit: async () => {
            // rename is atomic within the same directory and filesystem (POSIX guarantee)
            await rename(pendingPath, finalPath);
            return finalPath;
        },
        rollback: async () => {
            // Rollback should not throw (even if pending was already deleted)
            try {
                await unlink(pendingPath);
            } catch {
                /* noop*/
            }
        },
    };
}

export async function readPrivateKeyFile(filePath: string): Promise<string> {
    const raw = await readFile(filePath, 'utf8');
    return raw
        .replace(PRIVATE_KEY_HEADER, '')
        .replace(PRIVATE_KEY_FOOTER, '')
        .trim();
}

export function defaultPrivateKeyPath(did: string): string {
    return path.join(
        os.homedir(),
        '.coivitas',
        'keys',
        sanitizeDidFilename(did) + '.pem',
    );
}

export function createCliPool(): DatabasePool {
    if (!process.env.DATABASE_URL) {
        throw new Error(
            'DATABASE_URL is required for ledger and demo commands.',
        );
    }

    return createPool();
}

function sanitizeDidFilename(did: string): string {
    return did.replaceAll(':', '_');
}
