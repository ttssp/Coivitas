import { mkdir, readFile, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

// Mock createPool before importing runtime to avoid a real DB connection
vi.mock('@coivitas/shared', () => ({
    createPool: vi.fn(() => ({ end: vi.fn() })),
}));

import {
    createCliPool,
    defaultPrivateKeyPath,
    ensureKeyDirectory,
    postJson,
    printOutput,
    readJsonFile,
    readPrivateKeyFile,
    resolveRegistryUrl,
    stagePrivateKeyFile,
    writePrivateKeyFile,
} from './runtime.js';

// ---------------------------------------------------------------------------
// printOutput
// ---------------------------------------------------------------------------
describe('printOutput', () => {
    let logSpy: ReturnType<typeof vi.spyOn>;

    beforeEach(() => {
        logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    });

    afterEach(() => {
        vi.restoreAllMocks();
    });

    it('should print string value directly when asJson is false and value is string', () => {
        printOutput('hello world');
        expect(logSpy).toHaveBeenCalledWith('hello world');
    });

    it('should print JSON when asJson is true even for string value', () => {
        printOutput('hello', true);
        expect(logSpy).toHaveBeenCalledWith(JSON.stringify('hello', null, 2));
    });

    it('should print JSON when value is an object and asJson is false', () => {
        const obj = { key: 'value' };
        printOutput(obj);
        expect(logSpy).toHaveBeenCalledWith(JSON.stringify(obj, null, 2));
    });

    it('should print JSON when value is an object and asJson is true', () => {
        const obj = { a: 1 };
        printOutput(obj, true);
        expect(logSpy).toHaveBeenCalledWith(JSON.stringify(obj, null, 2));
    });

    it('should print JSON for number when asJson is false', () => {
        printOutput(42);
        expect(logSpy).toHaveBeenCalledWith(JSON.stringify(42, null, 2));
    });
});

// ---------------------------------------------------------------------------
// resolveRegistryUrl
// ---------------------------------------------------------------------------
describe('resolveRegistryUrl', () => {
    afterEach(() => {
        vi.unstubAllEnvs();
    });

    it('should return provided registryUrl option when given', () => {
        const url = 'https://registry.example.com';
        expect(resolveRegistryUrl(url)).toBe(url);
    });

    it('should fall back to IDENTITY_REGISTRY_URL env when option is omitted', () => {
        vi.stubEnv('IDENTITY_REGISTRY_URL', 'https://env.example.com');
        expect(resolveRegistryUrl()).toBe('https://env.example.com');
    });

    it('should throw when neither option nor env is set', () => {
        vi.stubEnv('IDENTITY_REGISTRY_URL', '');
        delete process.env.IDENTITY_REGISTRY_URL;
        expect(() => resolveRegistryUrl()).toThrow(/IDENTITY_REGISTRY_URL/);
    });
});

// ---------------------------------------------------------------------------
// postJson
// ---------------------------------------------------------------------------
describe('postJson', () => {
    afterEach(() => {
        vi.restoreAllMocks();
    });

    it('should call fetch with correct URL, POST method, JSON content-type, and JSON.stringify(payload) body', async () => {
        // F29 revision rationale: the old version only asserted "the return value equals
        // mockResponse"; fetch's wire contract (URL, method, headers, body) was not verified
        // at all. If postJson were changed to GET, or the endpoint drifted, or
        // content-type:application/json were lost, the CLI runtime would break but the test
        // would still pass. This assertion locks down the shape of the fetch call.
        const mockResponse = { id: 'abc123' };
        const fetchMock: ReturnType<typeof vi.fn> = vi.fn().mockResolvedValue({
            ok: true,
            json: () => Promise.resolve(mockResponse),
        });
        vi.stubGlobal('fetch', fetchMock);

        const payload = { name: 'test' };
        const result = await postJson(
            'https://api.example.com',
            '/api/v1/items',
            payload,
        );
        expect(result).toEqual(mockResponse);

        // Assert the wire contract
        expect(fetchMock).toHaveBeenCalledTimes(1);
        const firstCall = fetchMock.mock.calls[0] as [URL, RequestInit];
        const calledUrl = firstCall[0];
        const calledInit = firstCall[1];
        // The URL is the object resolved by new URL(pathname, base) (checked via toString)
        expect(calledUrl.toString()).toBe(
            'https://api.example.com/api/v1/items',
        );
        expect(calledInit.method).toBe('POST');
        expect(calledInit.headers).toEqual({
            'content-type': 'application/json',
        });
        expect(calledInit.body).toBe(JSON.stringify(payload));
    });

    it('should throw with HTTP status when response is not ok', async () => {
        vi.stubGlobal(
            'fetch',
            vi.fn().mockResolvedValue({
                ok: false,
                status: 502,
                json: () => Promise.resolve({}),
            }),
        );

        await expect(
            postJson('https://api.example.com', '/api/v1/items', {}),
        ).rejects.toThrow('HTTP 502');
    });

    it('should propagate network errors when fetch throws', async () => {
        vi.stubGlobal(
            'fetch',
            vi.fn().mockRejectedValue(new Error('ECONNREFUSED')),
        );

        await expect(
            postJson('https://api.example.com', '/api/v1/items', {}),
        ).rejects.toThrow('ECONNREFUSED');
    });
});

// ---------------------------------------------------------------------------
// readJsonFile
// ---------------------------------------------------------------------------
describe('readJsonFile', () => {
    it('should parse and return the JSON content from a valid file', async () => {
        const tmpFile = path.join(os.tmpdir(), `rjf-test-${Date.now()}.json`);
        await writeFile(tmpFile, JSON.stringify({ hello: 'world' }), 'utf8');

        const result = await readJsonFile<{ hello: string }>(tmpFile);
        expect(result).toEqual({ hello: 'world' });
    });

    it('should throw when file contains invalid JSON', async () => {
        const tmpFile = path.join(os.tmpdir(), `rjf-bad-${Date.now()}.json`);
        await writeFile(tmpFile, 'not-json', 'utf8');

        await expect(readJsonFile(tmpFile)).rejects.toThrow();
    });

    it('should throw when file does not exist', async () => {
        await expect(readJsonFile('/nonexistent/file.json')).rejects.toThrow();
    });
});

// ---------------------------------------------------------------------------
// ensureKeyDirectory
// ---------------------------------------------------------------------------
describe('ensureKeyDirectory', () => {
    let originalHome: string | undefined;

    beforeEach(() => {
        originalHome = process.env.HOME;
    });

    afterEach(() => {
        if (originalHome !== undefined) {
            process.env.HOME = originalHome;
        }
        vi.unstubAllEnvs();
    });

    it('should create and return the keys directory path', async () => {
        const tmpBase = path.join(os.tmpdir(), `ek-test-${Date.now()}`);
        await mkdir(tmpBase, { recursive: true });
        vi.stubEnv('HOME', tmpBase);

        // Force os.homedir() to return our tmp dir
        const homeSpy = vi.spyOn(os, 'homedir').mockReturnValue(tmpBase);

        const dir = await ensureKeyDirectory();
        expect(dir).toBe(path.join(tmpBase, '.coivitas', 'keys'));

        // Directory should now exist
        const { access } = await import('node:fs/promises');
        await expect(access(dir)).resolves.toBeUndefined();

        homeSpy.mockRestore();
    });
});

// ---------------------------------------------------------------------------
// writePrivateKeyFile
// ---------------------------------------------------------------------------
describe('writePrivateKeyFile', () => {
    it('should write PEM-wrapped private key and return the file path', async () => {
        const tmpBase = path.join(os.tmpdir(), `wpkf-${Date.now()}`);
        const homeSpy = vi.spyOn(os, 'homedir').mockReturnValue(tmpBase);

        const did = 'did:agent:test123';
        const privateKey = 'deadbeef1234';
        const filePath = await writePrivateKeyFile(did, privateKey);

        expect(filePath).toContain('did_agent_test123.pem');

        const content = await readFile(filePath, 'utf8');
        expect(content).toContain('BEGIN COIVITAS PRIVATE KEY');
        expect(content).toContain('END COIVITAS PRIVATE KEY');
        expect(content).toContain(privateKey);

        homeSpy.mockRestore();
    });
});

// ---------------------------------------------------------------------------
// stagePrivateKeyFile
// ---------------------------------------------------------------------------
describe('stagePrivateKeyFile', () => {
    it('should commit pending file to final path', async () => {
        const tmpBase = path.join(os.tmpdir(), `spkf-commit-${Date.now()}`);
        const homeSpy = vi.spyOn(os, 'homedir').mockReturnValue(tmpBase);

        const did = 'did:agent:commit';
        const pending = await stagePrivateKeyFile(did, 'abc123');

        expect(pending.pendingPath).toContain('.pending');

        // Pending file should exist
        const { access } = await import('node:fs/promises');
        await expect(access(pending.pendingPath)).resolves.toBeUndefined();

        // Commit should rename pending → final
        const finalPath = await pending.commit();
        expect(finalPath).toBe(pending.finalPath);
        await expect(access(finalPath)).resolves.toBeUndefined();

        homeSpy.mockRestore();
    });

    it('should rollback by deleting the pending file', async () => {
        const tmpBase = path.join(os.tmpdir(), `spkf-rollback-${Date.now()}`);
        const homeSpy = vi.spyOn(os, 'homedir').mockReturnValue(tmpBase);

        const did = 'did:agent:rollback';
        const pending = await stagePrivateKeyFile(did, 'xyz789');

        const { access } = await import('node:fs/promises');
        await expect(access(pending.pendingPath)).resolves.toBeUndefined();

        // Rollback should succeed without throwing
        await expect(pending.rollback()).resolves.toBeUndefined();

        // Pending file should no longer exist
        await expect(access(pending.pendingPath)).rejects.toThrow();

        homeSpy.mockRestore();
    });

    it('should not throw when rollback is called on already-deleted pending file', async () => {
        const tmpBase = path.join(os.tmpdir(), `spkf-dbl-${Date.now()}`);
        const homeSpy = vi.spyOn(os, 'homedir').mockReturnValue(tmpBase);

        const pending = await stagePrivateKeyFile('did:agent:dbl', 'key');

        // Delete manually first
        await pending.rollback();
        // Second rollback should be silent
        await expect(pending.rollback()).resolves.toBeUndefined();

        homeSpy.mockRestore();
    });
});

// ---------------------------------------------------------------------------
// readPrivateKeyFile
// ---------------------------------------------------------------------------
describe('readPrivateKeyFile', () => {
    it('should strip PEM headers and return just the hex key', async () => {
        const tmpFile = path.join(os.tmpdir(), `rpkf-${Date.now()}.pem`);
        const hex = 'cafebabe1234';
        const pem = [
            '-----BEGIN COIVITAS PRIVATE KEY-----',
            hex,
            '-----END COIVITAS PRIVATE KEY-----',
            '',
        ].join('\n');
        await writeFile(tmpFile, pem, 'utf8');

        const result = await readPrivateKeyFile(tmpFile);
        expect(result).toBe(hex);
    });
});

// ---------------------------------------------------------------------------
// defaultPrivateKeyPath
// ---------------------------------------------------------------------------
describe('defaultPrivateKeyPath', () => {
    it('should return path under ~/.coivitas/keys with sanitized DID filename', () => {
        const homeSpy = vi.spyOn(os, 'homedir').mockReturnValue('/fake/home');
        const did = 'did:agent:abc123';
        const keyPath = defaultPrivateKeyPath(did);
        expect(keyPath).toBe(
            '/fake/home/.coivitas/keys/did_agent_abc123.pem',
        );
        homeSpy.mockRestore();
    });
});

// ---------------------------------------------------------------------------
// createCliPool
// ---------------------------------------------------------------------------
describe('createCliPool', () => {
    afterEach(() => {
        vi.unstubAllEnvs();
    });

    it('should throw when DATABASE_URL is not set', () => {
        delete process.env.DATABASE_URL;
        vi.stubEnv('DATABASE_URL', '');
        // vitest stubEnv sets to empty string; we need to delete it
        delete process.env.DATABASE_URL;
        expect(() => createCliPool()).toThrow(/DATABASE_URL/);
    });

    it('should return a pool when DATABASE_URL is set', async () => {
        vi.stubEnv('DATABASE_URL', 'postgresql://localhost/test');
        const { createPool } = await import('@coivitas/shared');
        const pool = createCliPool();
        expect(pool).toBeDefined();
        expect(createPool).toHaveBeenCalled();
    });
});
