/**
 * Additional action-path tests for the token issue / verify / revoke subcommands.
 * runTokenDelegate-related tests are already covered in token.test.ts; this file only fills in the uncovered branches.
 */

import { mkdtemp, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { generateKeyPair } from '@coivitas/crypto';
import {
    createAgentIdentity,
    didKeyFromPublicKey,
    issueCapabilityToken,
} from '@coivitas/identity';
import type { CapabilityToken, Timestamp } from '@coivitas/types';

// mock runtime
vi.mock('../runtime.js', async (importOriginal) => {
    const actual = await importOriginal<typeof import('../runtime.js')>();
    return {
        ...actual,
        createCliPool: vi.fn(),
        postJson: vi.fn(),
        readJsonFile: vi.fn(),
        readPrivateKeyFile: vi.fn(),
        defaultPrivateKeyPath: vi.fn().mockReturnValue('/fake/default.pem'),
        resolveRegistryUrl: vi.fn().mockReturnValue('https://reg.example.com'),
        printOutput: vi.fn(),
    };
});

// mock identity for verifyCapabilityToken
vi.mock('@coivitas/identity', async (importOriginal) => {
    const actual =
        await importOriginal<typeof import('@coivitas/identity')>();
    return {
        ...actual,
        verifyCapabilityToken: vi.fn(),
        IdentityRegistry: vi.fn(),
    };
});

import { createTokenCommand } from './token.js';
import {
    postJson,
    readJsonFile,
    readPrivateKeyFile,
    resolveRegistryUrl,
    printOutput,
    defaultPrivateKeyPath,
} from '../runtime.js';
import { verifyCapabilityToken } from '@coivitas/identity';

let tmpHome: string;

beforeEach(async () => {
    tmpHome = await mkdtemp(path.join(os.tmpdir(), 'ap-cli-tokencmd-'));
    vi.stubEnv('HOME', tmpHome);
    vi.stubEnv('USERPROFILE', tmpHome);
});

afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllEnvs();
    process.exitCode = 0;
});

// helper: build a real token for use in tests
function buildRealToken(): CapabilityToken {
    const principal = generateKeyPair();
    const principalDid = didKeyFromPublicKey(
        Buffer.from(principal.publicKey, 'hex'),
    );
    const agent = createAgentIdentity({
        principalDid,
        principalPrivateKey: principal.privateKey,
    });
    return issueCapabilityToken({
        issuerDid: principalDid,
        issuedTo: agent.document.id,
        capabilities: [
            { action: 'INQUIRY', scope: { type: 'allowlist', values: ['a'] } },
        ],
        expiresAt: new Date(
            Date.now() + 3600 * 1000,
        ).toISOString() as Timestamp,
        revocationUrl: 'https://revocation.example.com/api/v1/revocations/{id}',
        issuerPrivateKey: principal.privateKey,
    });
}

// ── token issue ───────────────────────────────────────────────────────────────
describe('token issue subcommand', () => {
    it('should print JSON output when --json flag is set', async () => {
        const principal = generateKeyPair();
        const principalDid = didKeyFromPublicKey(
            Buffer.from(principal.publicKey, 'hex'),
        );
        const agent = createAgentIdentity({
            principalDid,
            principalPrivateKey: principal.privateKey,
        });

        vi.mocked(readPrivateKeyFile).mockResolvedValue(principal.privateKey);

        const command = createTokenCommand();
        await command.parseAsync(
            [
                'node',
                'token',
                'issue',
                '--issuer-did',
                principalDid,
                '--agent-did',
                agent.document.id,
                '--action',
                'INQUIRY',
                '--scope',
                '{"type":"allowlist","values":["a"]}',
                '--expires-in',
                '3600',
                '--json',
            ],
            { from: 'node' },
        );

        expect(printOutput).toHaveBeenCalledWith(
            expect.objectContaining({ issuerDid: principalDid }),
            true,
        );
    });

    it('should print text summary when --json not set', async () => {
        const principal = generateKeyPair();
        const principalDid = didKeyFromPublicKey(
            Buffer.from(principal.publicKey, 'hex'),
        );
        const agent = createAgentIdentity({
            principalDid,
            principalPrivateKey: principal.privateKey,
        });

        vi.mocked(readPrivateKeyFile).mockResolvedValue(principal.privateKey);

        const command = createTokenCommand();
        await command.parseAsync(
            [
                'node',
                'token',
                'issue',
                '--issuer-did',
                principalDid,
                '--agent-did',
                agent.document.id,
                '--action',
                'INQUIRY',
                '--scope',
                '{"type":"allowlist","values":["a"]}',
            ],
            { from: 'node' },
        );

        const textArg = vi.mocked(printOutput).mock.calls[0]![0] as string;
        expect(textArg).toContain('Capability token issued');
        expect(textArg).toContain('INQUIRY');
    });

    it('should use default key path when --issuer-key-file is omitted', async () => {
        const principal = generateKeyPair();
        const principalDid = didKeyFromPublicKey(
            Buffer.from(principal.publicKey, 'hex'),
        );
        const agent = createAgentIdentity({
            principalDid,
            principalPrivateKey: principal.privateKey,
        });

        vi.mocked(readPrivateKeyFile).mockResolvedValue(principal.privateKey);
        // Explicit re-mock: vi.restoreAllMocks() in afterEach clears the
        // defaultPrivateKeyPath.mockReturnValue config left over from the previous it
        vi.mocked(defaultPrivateKeyPath).mockReturnValue('/fake/default.pem');

        const command = createTokenCommand();
        await command.parseAsync(
            [
                'node',
                'token',
                'issue',
                '--issuer-did',
                principalDid,
                '--agent-did',
                agent.document.id,
                '--action',
                'INQUIRY',
                '--scope',
                '{"type":"allowlist","values":["a"]}',
            ],
            { from: 'node' },
        );

        // F31 revision rationale: the old version only asserted readPrivateKeyFile was
        // called once, without asserting the default path — if the token issue default
        // path drifted to undefined or a wrong DID, the test would still pass.
        // The actual implementation is in packages/sdk/src/cli/commands/token.ts:64-67:
        // readPrivateKeyFile(options.issuerKeyFile ?? defaultPrivateKeyPath(options.issuerDid))
        // This assertion locks down the fallback path contract:
        // (1) When --issuer-key-file is omitted, defaultPrivateKeyPath must be called
        // once with issuerDid as its argument
        // (2) readPrivateKeyFile's first argument must equal defaultPrivateKeyPath's return value
        // (the mock returns '/fake/default.pem')
        expect(readPrivateKeyFile).toHaveBeenCalledTimes(1);
        expect(defaultPrivateKeyPath).toHaveBeenCalledWith(principalDid);
        expect(readPrivateKeyFile).toHaveBeenCalledWith('/fake/default.pem');
        expect(printOutput).toHaveBeenCalled();
    });
});

// ── token verify ──────────────────────────────────────────────────────────────
describe('token verify subcommand', () => {
    it('should print valid=true result and not set exitCode when token is valid', async () => {
        const token = buildRealToken();
        const tokenFile = path.join(tmpHome, 'token.json');
        await writeFile(tokenFile, JSON.stringify(token), 'utf8');

        vi.mocked(readJsonFile).mockResolvedValue(token as never);
        vi.mocked(verifyCapabilityToken).mockReturnValue({
            valid: true,
        } as never);

        const command = createTokenCommand();
        await command.parseAsync(['node', 'token', 'verify', tokenFile], {
            from: 'node',
        });

        expect(printOutput).toHaveBeenCalledWith(
            expect.objectContaining({ valid: true }),
            true,
        );
        expect(process.exitCode).not.toBe(1);
    });

    it('should set process.exitCode to 1 when token is invalid', async () => {
        const token = buildRealToken();
        const tokenFile = path.join(tmpHome, 'token-invalid.json');
        await writeFile(tokenFile, JSON.stringify(token), 'utf8');

        vi.mocked(readJsonFile).mockResolvedValue(token as never);
        vi.mocked(verifyCapabilityToken).mockReturnValue({
            valid: false,
            reason: 'TOKEN_EXPIRED',
        } as never);

        const command = createTokenCommand();
        await command.parseAsync(['node', 'token', 'verify', tokenFile], {
            from: 'node',
        });

        expect(process.exitCode).toBe(1);
    });

    it('should pass --now timestamp override to verifyCapabilityToken', async () => {
        const token = buildRealToken();
        const tokenFile = path.join(tmpHome, 'token-now.json');
        await writeFile(tokenFile, JSON.stringify(token), 'utf8');

        vi.mocked(readJsonFile).mockResolvedValue(token as never);
        vi.mocked(verifyCapabilityToken).mockReturnValue({
            valid: true,
        } as never);

        const nowTs = '2025-01-01T00:00:00.000Z';
        const command = createTokenCommand();
        await command.parseAsync(
            ['node', 'token', 'verify', tokenFile, '--now', nowTs],
            { from: 'node' },
        );

        expect(verifyCapabilityToken).toHaveBeenCalledWith(
            expect.anything(),
            nowTs,
        );
    });
});

// ── token revoke ──────────────────────────────────────────────────────────────
describe('token revoke subcommand', () => {
    it('should call postJson to the revocation endpoint and print result', async () => {
        const tokenId = 'tok_revoke_test';
        const principalDid = 'did:key:zPrincipal';

        vi.mocked(postJson).mockResolvedValue({ revoked: true } as never);
        vi.mocked(resolveRegistryUrl).mockReturnValue(
            'https://reg.example.com',
        );

        const command = createTokenCommand();
        await command.parseAsync(
            [
                'node',
                'token',
                'revoke',
                tokenId,
                '--principal-did',
                principalDid,
                '--registry-url',
                'https://reg.example.com',
            ],
            { from: 'node' },
        );

        expect(postJson).toHaveBeenCalledWith(
            'https://reg.example.com',
            '/api/v1/revocations',
            expect.objectContaining({
                tokenId,
                revokedBy: principalDid,
                reason: 'MANUAL_REVOCATION',
            }),
        );
        expect(printOutput).toHaveBeenCalledWith(
            expect.objectContaining({ revoked: true }),
            true,
        );
    });

    it('should throw when registry URL is missing for revoke', async () => {
        vi.mocked(resolveRegistryUrl).mockImplementation(() => {
            throw new Error('Identity registry URL is required');
        });

        const command = createTokenCommand();
        await expect(
            command.parseAsync(
                [
                    'node',
                    'token',
                    'revoke',
                    'tok_123',
                    '--principal-did',
                    'did:key:z1',
                ],
                { from: 'node' },
            ),
        ).rejects.toThrow(/registry URL is required/);
    });
});
