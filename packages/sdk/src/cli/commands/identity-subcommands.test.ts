/**
 * Additional action-path tests for the identity create / resolve subcommands.
 * Tests related to runIdentityRotate are already covered in identity.test.ts; this file only fills in the uncovered branches.
 */

import { mkdtemp, mkdir, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { generateKeyPair } from '@coivitas/crypto';
import {
    createAgentIdentity,
    didKeyFromPublicKey,
} from '@coivitas/identity';

// runtime mock: avoid real network/DB calls
vi.mock('../runtime.js', async (importOriginal) => {
    const actual = await importOriginal<typeof import('../runtime.js')>();
    return {
        ...actual,
        createCliPool: vi.fn(),
        resolveRegistryUrl: vi.fn().mockReturnValue('https://reg.example.com'),
        postJson: vi.fn(),
        writePrivateKeyFile: vi.fn().mockResolvedValue('/fake/path/key.pem'),
        readPrivateKeyFile: vi.fn(),
        defaultPrivateKeyPath: vi.fn().mockReturnValue('/fake/default.pem'),
    };
});

// identity package mock: resolveAgentDID avoids real HTTP
vi.mock('@coivitas/identity', async (importOriginal) => {
    const actual =
        await importOriginal<typeof import('@coivitas/identity')>();
    return {
        ...actual,
        resolveAgentDID: vi.fn(),
        IdentityRegistry: vi.fn(),
    };
});

import { createIdentityCommand } from './identity.js';
import {
    postJson,
    readPrivateKeyFile,
    writePrivateKeyFile,
    resolveRegistryUrl,
} from '../runtime.js';
import { resolveAgentDID } from '@coivitas/identity';

// ── Helper: write a PEM key file ─────────────────────────────────────────────────────
async function writeKey(filePath: string, hex: string): Promise<void> {
    const pem = [
        '-----BEGIN COIVITAS PRIVATE KEY-----',
        hex,
        '-----END COIVITAS PRIVATE KEY-----',
        '',
    ].join('\n');
    await mkdir(path.dirname(filePath), { recursive: true });
    await writeFile(filePath, pem, { mode: 0o600 });
}

let tmpHome: string;

beforeEach(async () => {
    tmpHome = await mkdtemp(path.join(os.tmpdir(), 'ap-cli-idcmd-'));
    vi.stubEnv('HOME', tmpHome);
    vi.stubEnv('USERPROFILE', tmpHome);
    vi.stubEnv('IDENTITY_REGISTRY_URL', 'https://reg.example.com');
});

afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllEnvs();
    process.exitCode = 0;
});

// ── identity create ───────────────────────────────────────────────────────────
describe('identity create subcommand', () => {
    it('should call postJson to register identity and writePrivateKeyFile to save key', async () => {
        const principal = generateKeyPair();
        const principalDid = didKeyFromPublicKey(
            Buffer.from(principal.publicKey, 'hex'),
        );
        const principalKeyFile = path.join(tmpHome, 'principal.pem');
        await writeKey(principalKeyFile, principal.privateKey);

        vi.mocked(readPrivateKeyFile).mockResolvedValue(principal.privateKey);
        vi.mocked(postJson).mockResolvedValue({
            did: 'did:agent:created',
        } as never);
        vi.mocked(writePrivateKeyFile).mockResolvedValue('/fake/agent.pem');

        const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

        const command = createIdentityCommand();
        await command.parseAsync(
            [
                'node',
                'identity',
                'create',
                '--name',
                'TestAgent',
                '--principal-did',
                principalDid,
                '--principal-key-file',
                principalKeyFile,
                '--registry-url',
                'https://reg.example.com',
            ],
            { from: 'node' },
        );

        expect(postJson).toHaveBeenCalledWith(
            'https://reg.example.com',
            '/api/v1/identities',
            expect.objectContaining({ principalDid }),
        );

        // F30 rationale: the old version only asserted that writePrivateKeyFile was called; if identity create
        // mistakenly wrote principalDid + principalPrivateKey to disk (mismatched DID/key),
        // the test would still pass. This assertion locks down credential integrity:
        // (1) first argument = the newly created agent's DID (i.e. the document.id submitted by postJson),
        // not principalDid
        // (2) second argument = the newly created agent's privateKey (also not principalPrivateKey)
        // For the actual implementation see packages/sdk/src/cli/commands/identity.ts:76-79
        expect(writePrivateKeyFile).toHaveBeenCalledTimes(1);
        const [savedDid, savedPrivateKey] =
            vi.mocked(writePrivateKeyFile).mock.calls[0]!;
        // must be in did:agent:* form (not the did:key:* principal)
        expect(savedDid).toMatch(/^did:agent:/);
        expect(savedDid).not.toBe(principalDid);
        // the principal private key must not be written to the agent's key file
        expect(savedPrivateKey).not.toBe(principal.privateKey);
        // the private key must be a hex string (the generateKeyPair output format)
        expect(typeof savedPrivateKey).toBe('string');
        expect(savedPrivateKey).toMatch(/^[0-9a-f]+$/);

        const output = logSpy.mock.calls.map((c) => String(c[0])).join('\n');
        expect(output).toContain('Agent identity created');
        expect(output).toContain('TestAgent');
    });

    it('should throw when resolveRegistryUrl throws (no registry configured)', async () => {
        vi.mocked(resolveRegistryUrl).mockImplementation(() => {
            throw new Error('Identity registry URL is required');
        });

        const principal = generateKeyPair();
        const principalDid = didKeyFromPublicKey(
            Buffer.from(principal.publicKey, 'hex'),
        );
        const principalKeyFile = path.join(tmpHome, 'principal.pem');
        await writeKey(principalKeyFile, principal.privateKey);
        vi.mocked(readPrivateKeyFile).mockResolvedValue(principal.privateKey);

        const command = createIdentityCommand();
        await expect(
            command.parseAsync(
                [
                    'node',
                    'identity',
                    'create',
                    '--name',
                    'TestAgent',
                    '--principal-did',
                    principalDid,
                    '--principal-key-file',
                    principalKeyFile,
                ],
                { from: 'node' },
            ),
        ).rejects.toThrow(/registry URL is required/);
    });

    it('should fall back to defaultPrivateKeyPath when --principal-key-file is omitted', async () => {
        const principal = generateKeyPair();
        const principalDid = didKeyFromPublicKey(
            Buffer.from(principal.publicKey, 'hex'),
        );

        vi.mocked(resolveRegistryUrl).mockReturnValue(
            'https://reg.example.com',
        );
        vi.mocked(readPrivateKeyFile).mockResolvedValue(principal.privateKey);
        vi.mocked(postJson).mockResolvedValue({ did: 'did:agent:x' } as never);
        vi.mocked(writePrivateKeyFile).mockResolvedValue('/fake/agent.pem');

        const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

        const command = createIdentityCommand();
        await command.parseAsync(
            [
                'node',
                'identity',
                'create',
                '--name',
                'DefaultKeyAgent',
                '--principal-did',
                principalDid,
                '--registry-url',
                'https://reg.example.com',
                // no --principal-key-file → defaultPrivateKeyPath used
            ],
            { from: 'node' },
        );

        // readPrivateKeyFile called once using the default path
        expect(readPrivateKeyFile).toHaveBeenCalledTimes(1);
        const output = logSpy.mock.calls.map((c) => String(c[0])).join('\n');
        expect(output).toContain('Agent identity created');
    });
});

// ── identity resolve ──────────────────────────────────────────────────────────
describe('identity resolve subcommand', () => {
    it('should print text summary when DID is found and --json not set', async () => {
        const principal = generateKeyPair();
        const principalDid = didKeyFromPublicKey(
            Buffer.from(principal.publicKey, 'hex'),
        );
        const identity = createAgentIdentity({
            principalDid,
            principalPrivateKey: principal.privateKey,
        });

        vi.mocked(resolveAgentDID).mockResolvedValue(
            identity.document as never,
        );
        vi.mocked(resolveRegistryUrl).mockReturnValue(
            'https://reg.example.com',
        );

        const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

        const command = createIdentityCommand();
        await command.parseAsync(
            ['node', 'identity', 'resolve', identity.document.id],
            { from: 'node' },
        );

        const output = logSpy.mock.calls.map((c) => String(c[0])).join('\n');
        expect(output).toContain('Agent Identity Document');
        expect(output).toContain(identity.document.id);
        expect(output).toContain(principalDid);
    });

    it('should print JSON when DID is found and --json is set', async () => {
        const principal = generateKeyPair();
        const principalDid = didKeyFromPublicKey(
            Buffer.from(principal.publicKey, 'hex'),
        );
        const identity = createAgentIdentity({
            principalDid,
            principalPrivateKey: principal.privateKey,
        });

        vi.mocked(resolveAgentDID).mockResolvedValue(
            identity.document as never,
        );
        vi.mocked(resolveRegistryUrl).mockReturnValue(
            'https://reg.example.com',
        );

        const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

        const command = createIdentityCommand();
        await command.parseAsync(
            ['node', 'identity', 'resolve', identity.document.id, '--json'],
            { from: 'node' },
        );

        const printed = logSpy.mock.calls.map((c) => String(c[0])).join('\n');
        const parsed = JSON.parse(printed) as { id: string };
        expect(parsed.id).toBe(identity.document.id);
    });

    it('should throw when DID resolves to null (not found)', async () => {
        vi.mocked(resolveAgentDID).mockResolvedValue(null as never);
        vi.mocked(resolveRegistryUrl).mockReturnValue(
            'https://reg.example.com',
        );

        const command = createIdentityCommand();
        await expect(
            command.parseAsync(
                ['node', 'identity', 'resolve', 'did:agent:nonexistent'],
                { from: 'node' },
            ),
        ).rejects.toThrow(/was not found/);
    });
});
