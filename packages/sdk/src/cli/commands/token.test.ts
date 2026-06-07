import { mkdtemp, mkdir, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { generateKeyPair } from '@coivitas/crypto';
import {
    createAgentIdentity,
    didKeyFromPublicKey,
    issueCapabilityToken,
} from '@coivitas/identity';
import type {
    Capability,
    CapabilityToken,
    DID,
    Timestamp,
} from '@coivitas/types';

import { runTokenDelegate } from './token.js';

// Wrap the hex private key in a PEM-ish envelope, consistent with runtime.ts's readPrivateKeyFile.
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

// Build a delegatable parent Token — issued by the principal directly to intermediate agent A, then A delegates to delegatee B.
async function buildParent(): Promise<{
    parent: CapabilityToken;
    parentTokenPath: string;
    delegatorPrivateKey: string;
    delegateeDid: DID;
}> {
    const principal = generateKeyPair();
    const principalDid = didKeyFromPublicKey(
        Buffer.from(principal.publicKey, 'hex'),
    );
    const agentA = createAgentIdentity({
        principalDid,
        principalPrivateKey: principal.privateKey,
    });
    const agentB = createAgentIdentity({
        principalDid,
        principalPrivateKey: principal.privateKey,
    });

    const parent = issueCapabilityToken({
        issuerDid: principalDid,
        issuedTo: agentA.document.id,
        capabilities: [
            {
                action: 'INQUIRY',
                scope: { type: 'allowlist', values: ['a', 'b'] },
            },
        ],
        expiresAt: new Date(
            Date.now() + 24 * 60 * 60 * 1000,
        ).toISOString() as Timestamp,
        revocationUrl: 'https://revocation.example.com/api/v1/revocations/{id}',
        issuerPrivateKey: principal.privateKey,
    });

    const tmp = await mkdtemp(path.join(os.tmpdir(), 'ap-cli-delegate-'));
    const tokenPath = path.join(tmp, 'parent.json');
    await writeFile(tokenPath, JSON.stringify(parent), 'utf8');

    return {
        parent,
        parentTokenPath: tokenPath,
        delegatorPrivateKey: agentA.privateKey,
        delegateeDid: agentB.document.id,
    };
}

let tmpHome: string;

beforeEach(async () => {
    tmpHome = await mkdtemp(path.join(os.tmpdir(), 'ap-cli-delegate-home-'));
    vi.stubEnv('HOME', tmpHome);
    vi.stubEnv('USERPROFILE', tmpHome);
});

afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllEnvs();
    process.exitCode = 0;
});

describe('runTokenDelegate', () => {
    it('issues a child token whose chain depth is parent + 1', async () => {
        const { parent, parentTokenPath, delegatorPrivateKey, delegateeDid } =
            await buildParent();
        const delegatorKeyFile = path.join(tmpHome, 'delegator.pem');
        await writeKey(delegatorKeyFile, delegatorPrivateKey);

        const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

        const child = await runTokenDelegate({
            parentToken: parentTokenPath,
            delegateeDid,
            // Attenuation: keep only 'a'
            capabilities: JSON.stringify([
                {
                    action: 'INQUIRY',
                    scope: { type: 'allowlist', values: ['a'] },
                },
            ] satisfies Capability[]),
            expiresIn: '600',
            delegatorKeyFile,
            json: true,
        });

        expect(child.issuedTo).toBe(delegateeDid);
        expect(child.delegationChain?.length).toBe(1);
        expect(child.issuerDid).toBe(parent.issuerDid);
        expect(child.principalDid).toBe(parent.principalDid);
        expect(child.specVersion).toBe('0.2.0');

        const printed = logSpy.mock.calls[0]![0] as string;
        const parsed = JSON.parse(printed) as CapabilityToken;
        expect(parsed.id).toBe(child.id);
    });

    it('rejects when capabilities JSON is not an array', async () => {
        const { parentTokenPath, delegatorPrivateKey, delegateeDid } =
            await buildParent();
        const delegatorKeyFile = path.join(tmpHome, 'delegator.pem');
        await writeKey(delegatorKeyFile, delegatorPrivateKey);

        await expect(
            runTokenDelegate({
                parentToken: parentTokenPath,
                delegateeDid,
                capabilities: '{"action":"INQUIRY"}',
                expiresIn: '600',
                delegatorKeyFile,
            }),
        ).rejects.toThrow(/JSON array/);
    });

    it('rejects when --expires-in is non-positive', async () => {
        const { parentTokenPath, delegatorPrivateKey, delegateeDid } =
            await buildParent();
        const delegatorKeyFile = path.join(tmpHome, 'delegator.pem');
        await writeKey(delegatorKeyFile, delegatorPrivateKey);

        await expect(
            runTokenDelegate({
                parentToken: parentTokenPath,
                delegateeDid,
                capabilities:
                    '[{"action":"INQUIRY","scope":{"type":"allowlist","values":["a"]}}]',
                expiresIn: '0',
                delegatorKeyFile,
            }),
        ).rejects.toThrow(/positive number of seconds/);
    });

    it('surfaces SCOPE_EXCEEDED when child capabilities violate attenuation', async () => {
        const { parentTokenPath, delegatorPrivateKey, delegateeDid } =
            await buildParent();
        const delegatorKeyFile = path.join(tmpHome, 'delegator.pem');
        await writeKey(delegatorKeyFile, delegatorPrivateKey);

        // The parent Token's allowlist is ['a','b']; the child requests ['c'] — must be rejected
        await expect(
            runTokenDelegate({
                parentToken: parentTokenPath,
                delegateeDid,
                capabilities:
                    '[{"action":"INQUIRY","scope":{"type":"allowlist","values":["c"]}}]',
                expiresIn: '600',
                delegatorKeyFile,
            }),
        ).rejects.toMatchObject({ code: 'SCOPE_EXCEEDED' });
    });

    it('prints text summary (non-JSON path) when --json not set', async () => {
        const { parent, parentTokenPath, delegatorPrivateKey, delegateeDid } =
            await buildParent();
        const delegatorKeyFile = path.join(tmpHome, 'delegator.pem');
        await writeKey(delegatorKeyFile, delegatorPrivateKey);

        const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
        await runTokenDelegate({
            parentToken: parentTokenPath,
            delegateeDid,
            capabilities:
                '[{"action":"INQUIRY","scope":{"type":"allowlist","values":["a"]}}]',
            expiresIn: '600',
            delegatorKeyFile,
        });

        const output = logSpy.mock.calls
            .map((call) => String(call[0]))
            .join('\n');
        expect(output).toContain('Delegated capability token issued');
        expect(output).toContain(`Parent token:    ${parent.id}`);
        expect(output).toContain(`Delegatee DID:   ${delegateeDid}`);
        expect(output).toContain('Chain depth:     1');
    });

    it('drives the delegate wrapper through commander parseAsync', async () => {
        const { parentTokenPath, delegatorPrivateKey, delegateeDid } =
            await buildParent();
        const delegatorKeyFile = path.join(tmpHome, 'delegator.pem');
        await writeKey(delegatorKeyFile, delegatorPrivateKey);

        vi.spyOn(console, 'log').mockImplementation(() => {});
        const { createTokenCommand } = await import('./token.js');
        const command = createTokenCommand();
        await command.parseAsync(
            [
                'node',
                'token',
                'delegate',
                '--parent-token',
                parentTokenPath,
                '--delegatee-did',
                delegateeDid,
                '--capabilities',
                '[{"action":"INQUIRY","scope":{"type":"allowlist","values":["a"]}}]',
                '--expires-in',
                '600',
                '--delegator-key-file',
                delegatorKeyFile,
                '--json',
            ],
            { from: 'node' },
        );
        // No error thrown means the parseAsync → action → runTokenDelegate chain is fully wired
    });

    it('falls back to the default key file path under $HOME when --delegator-key-file omitted', async () => {
        const { parent, parentTokenPath, delegatorPrivateKey, delegateeDid } =
            await buildParent();
        const sanitized = parent.issuedTo.replaceAll(':', '_');
        const defaultKeyFile = path.join(
            tmpHome,
            '.coivitas',
            'keys',
            sanitized + '.pem',
        );
        await writeKey(defaultKeyFile, delegatorPrivateKey);

        vi.spyOn(console, 'log').mockImplementation(() => {});
        const child = await runTokenDelegate({
            parentToken: parentTokenPath,
            delegateeDid,
            capabilities:
                '[{"action":"INQUIRY","scope":{"type":"allowlist","values":["a"]}}]',
            expiresIn: '600',
        });
        expect(child.issuedTo).toBe(delegateeDid);
    });
});
