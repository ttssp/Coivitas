import { mkdtemp, readFile, writeFile, mkdir, access } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { canonicalize, generateKeyPair, sign } from '@coivitas/crypto';
import {
    createAgentIdentity,
    didKeyFromPublicKey,
    initiateKeyRotation,
} from '@coivitas/identity';
import type {
    AgentIdentityDocument,
    DID,
    Signature,
    Timestamp,
} from '@coivitas/types';

import { runIdentityRotate } from './identity.js';

// ── runtime.ts mock: inject a fake createCliPool (never touches real pg) ──────────────────
vi.mock('../runtime.js', async () => {
    const actual =
        await vi.importActual<typeof import('../runtime.js')>('../runtime.js');
    return {
        ...actual,
        createCliPool: vi.fn(),
    };
});

// ── identity package mock: replace IdentityRegistry to avoid triggering real pg queries ──────────────
vi.mock('@coivitas/identity', async () => {
    const actual = await vi.importActual<
        typeof import('@coivitas/identity')
    >('@coivitas/identity');
    return {
        ...actual,
        IdentityRegistry: vi.fn(),
    };
});

const runtime = await import('../runtime.js');
const identity = await import('@coivitas/identity');
const mockedCreatePool = runtime.createCliPool as unknown as ReturnType<
    typeof vi.fn
>;
const MockedRegistry = identity.IdentityRegistry as unknown as ReturnType<
    typeof vi.fn
>;

// ── Helper: use createAgentIdentity to generate a self-consistent fixture ───────────────────────────────
function makeFixture(): {
    doc: AgentIdentityDocument;
    agentPrivateKey: string;
    principalPrivateKey: string;
    principalDid: DID;
} {
    const principal = generateKeyPair();
    const principalDid = didKeyFromPublicKey(
        Buffer.from(principal.publicKey, 'hex'),
    );
    const created = createAgentIdentity({
        principalDid,
        principalPrivateKey: principal.privateKey,
        capabilities: ['INQUIRY'],
    });
    return {
        doc: created.document,
        agentPrivateKey: created.privateKey,
        principalPrivateKey: principal.privateKey,
        principalDid,
    };
}

// Write the hex private key in a PEM-ish wrapper, matching readPrivateKeyFile in runtime.ts.
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
let endSpy: ReturnType<typeof vi.fn>;

beforeEach(async () => {
    tmpHome = await mkdtemp(path.join(os.tmpdir(), 'ap-cli-rotate-'));
    vi.stubEnv('HOME', tmpHome);
    vi.stubEnv('USERPROFILE', tmpHome);
    vi.stubEnv('DATABASE_URL', 'postgresql://stub/test');
    endSpy = vi.fn().mockResolvedValue(undefined);
    mockedCreatePool.mockReturnValue({ end: endSpy });
});

afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllEnvs();
    MockedRegistry.mockReset();
    mockedCreatePool.mockReset();
    process.exitCode = 0;
});

describe('runIdentityRotate', () => {
    it('rotates the document, persists ROTATING, and writes the new key file', async () => {
        const { doc, agentPrivateKey, principalPrivateKey } = makeFixture();
        const update = vi.fn().mockResolvedValue(undefined);
        MockedRegistry.mockImplementation(() => ({
            query: vi.fn().mockResolvedValue(doc),
            update,
        }));

        const agentKeyFile = path.join(tmpHome, 'agent.pem');
        const principalKeyFile = path.join(tmpHome, 'principal.pem');
        await writeKey(agentKeyFile, agentPrivateKey);
        await writeKey(principalKeyFile, principalPrivateKey);

        const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

        await runIdentityRotate(
            {
                did: doc.id,
                currentKeyFile: agentKeyFile,
                principalKeyFile,
                json: true,
                yes: true,
            },
            // no confirm wired in -- the --yes path skips it entirely
        );

        // Registry.update must be called once, with the second argument = expectedVersion=1
        expect(update).toHaveBeenCalledTimes(1);
        const [persistedDoc, expectedVersion] = update.mock.calls[0]! as [
            AgentIdentityDocument,
            number,
        ];
        expect(expectedVersion).toBe(1);
        expect(persistedDoc.publicKey).not.toBe(doc.publicKey);
        expect(persistedDoc.previousPublicKey).toBe(doc.publicKey);
        expect(persistedDoc.rotationProof).toBeDefined();
        expect(persistedDoc.version).toBe(2);
        // Regression: what gets persisted must be the clean document produced by completeKeyRotation,
        // and must not carry the _rotatingState marker; otherwise the next query() load would wrongly think it is still mid-rotation.
        expect('_rotatingState' in persistedDoc).toBe(false);

        // the new private key is written to ~/.coivitas/keys/<did>.pem
        const sanitized = doc.id.replaceAll(':', '_');
        const expectedKeyPath = path.join(
            tmpHome,
            '.coivitas',
            'keys',
            sanitized + '.pem',
        );
        const written = await readFile(expectedKeyPath, 'utf8');
        expect(written).toContain('-----BEGIN COIVITAS PRIVATE KEY-----');
        // the persisted private key must be exactly the one used by initiateKeyRotation (128-char hex)
        const inner = written
            .replace('-----BEGIN COIVITAS PRIVATE KEY-----', '')
            .replace('-----END COIVITAS PRIVATE KEY-----', '')
            .trim();
        expect(inner).toMatch(/^[0-9a-f]{128}$/);

        // pool.end must be invoked in the finally block
        expect(endSpy).toHaveBeenCalledTimes(1);

        // the JSON output parses
        const printed = logSpy.mock.calls.find((args) =>
            String(args[0]).startsWith('{'),
        );
        expect(printed).toBeDefined();
        const json = JSON.parse(printed![0] as string) as Record<
            string,
            unknown
        >;
        expect(json['did']).toBe(doc.id);
        expect(json['newVersion']).toBe(2);
    });

    it('aborts when the operator declines confirmation', async () => {
        const { doc, agentPrivateKey, principalPrivateKey } = makeFixture();
        const update = vi.fn();
        MockedRegistry.mockImplementation(() => ({
            query: vi.fn().mockResolvedValue(doc),
            update,
        }));

        const agentKeyFile = path.join(tmpHome, 'agent.pem');
        const principalKeyFile = path.join(tmpHome, 'principal.pem');
        await writeKey(agentKeyFile, agentPrivateKey);
        await writeKey(principalKeyFile, principalPrivateKey);

        const confirm = vi.fn().mockResolvedValue(false);

        await expect(
            runIdentityRotate(
                {
                    did: doc.id,
                    currentKeyFile: agentKeyFile,
                    principalKeyFile,
                    yes: false,
                },
                { confirm },
            ),
        ).rejects.toThrow(/cancelled by operator/);

        expect(confirm).toHaveBeenCalledTimes(1);
        expect(update).not.toHaveBeenCalled();
        expect(endSpy).toHaveBeenCalledTimes(1);
    });

    it('rolls back the staged private key file when registry.update fails', async () => {
        const { doc, agentPrivateKey, principalPrivateKey } = makeFixture();
        const update = vi
            .fn()
            .mockRejectedValue(new Error('VERSION_CONFLICT: simulated'));
        MockedRegistry.mockImplementation(() => ({
            query: vi.fn().mockResolvedValue(doc),
            update,
        }));

        const agentKeyFile = path.join(tmpHome, 'agent.pem');
        const principalKeyFile = path.join(tmpHome, 'principal.pem');
        await writeKey(agentKeyFile, agentPrivateKey);
        await writeKey(principalKeyFile, principalPrivateKey);

        await expect(
            runIdentityRotate({
                did: doc.id,
                currentKeyFile: agentKeyFile,
                principalKeyFile,
                yes: true,
                json: false,
            }),
        ).rejects.toThrow(/VERSION_CONFLICT/);

        // after failure: .pem.pending must be cleaned up (rollback), and the final .pem must not exist
        const sanitized = doc.id.replaceAll(':', '_');
        const finalPath = path.join(
            tmpHome,
            '.coivitas',
            'keys',
            sanitized + '.pem',
        );
        const pendingPath = finalPath + '.pending';
        await expect(access(pendingPath)).rejects.toMatchObject({
            code: 'ENOENT',
        });
        await expect(access(finalPath)).rejects.toMatchObject({
            code: 'ENOENT',
        });
        // pool.end is still invoked
        expect(endSpy).toHaveBeenCalledTimes(1);
    });

    it('errors when the DID is unknown to the registry', async () => {
        MockedRegistry.mockImplementation(() => ({
            query: vi.fn().mockResolvedValue(null),
            update: vi.fn(),
        }));

        const { agentPrivateKey, principalPrivateKey } = makeFixture();
        const agentKeyFile = path.join(tmpHome, 'agent.pem');
        const principalKeyFile = path.join(tmpHome, 'principal.pem');
        await writeKey(agentKeyFile, agentPrivateKey);
        await writeKey(principalKeyFile, principalPrivateKey);

        await expect(
            runIdentityRotate({
                did: 'did:agent:0000000000000000000000000000000000000000',
                currentKeyFile: agentKeyFile,
                principalKeyFile,
                yes: true,
            }),
        ).rejects.toThrow(/was not found/);
    });

    it('prints text summary (non-JSON path) when --json not set', async () => {
        const { doc, agentPrivateKey, principalPrivateKey } = makeFixture();
        const update = vi.fn().mockResolvedValue(undefined);
        MockedRegistry.mockImplementation(() => ({
            query: vi.fn().mockResolvedValue(doc),
            update,
        }));

        const agentKeyFile = path.join(tmpHome, 'agent.pem');
        const principalKeyFile = path.join(tmpHome, 'principal.pem');
        await writeKey(agentKeyFile, agentPrivateKey);
        await writeKey(principalKeyFile, principalPrivateKey);

        const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
        await runIdentityRotate({
            did: doc.id,
            currentKeyFile: agentKeyFile,
            principalKeyFile,
            yes: true,
            json: false,
        });

        const output = logSpy.mock.calls
            .map((call) => String(call[0]))
            .join('\n');
        expect(output).toContain('Key rotation complete');
        expect(output).toContain(`DID:           ${doc.id}`);
        expect(output).toContain('New version:   2');
    });

    it('honours an injected registryFactory (custom test double)', async () => {
        const { doc, agentPrivateKey, principalPrivateKey } = makeFixture();
        const update = vi.fn().mockResolvedValue(undefined);
        const customRegistry = {
            query: vi.fn().mockResolvedValue(doc),
            update,
        };
        // deliberately make MockedRegistry not match -- must take the deps.registryFactory path
        MockedRegistry.mockImplementation(() => {
            throw new Error('default registry path should not be used');
        });

        const agentKeyFile = path.join(tmpHome, 'agent.pem');
        const principalKeyFile = path.join(tmpHome, 'principal.pem');
        await writeKey(agentKeyFile, agentPrivateKey);
        await writeKey(principalKeyFile, principalPrivateKey);

        vi.spyOn(console, 'log').mockImplementation(() => {});
        await runIdentityRotate(
            {
                did: doc.id,
                currentKeyFile: agentKeyFile,
                principalKeyFile,
                yes: true,
                json: true,
            },
            { registryFactory: () => customRegistry as never },
        );
        expect(customRegistry.query).toHaveBeenCalledWith(doc.id);
        expect(update).toHaveBeenCalledTimes(1);
    });

    it('rejects when --principal-key-file is missing', async () => {
        const { doc, agentPrivateKey } = makeFixture();
        MockedRegistry.mockImplementation(() => ({
            query: vi.fn().mockResolvedValue(doc),
            update: vi.fn(),
        }));

        const agentKeyFile = path.join(tmpHome, 'agent.pem');
        await writeKey(agentKeyFile, agentPrivateKey);

        await expect(
            runIdentityRotate({
                did: doc.id,
                currentKeyFile: agentKeyFile,
                yes: true,
            }),
        ).rejects.toThrow(/Principal key file is required/);
    });
});

describe('createIdentityCommand wiring (rotate subcommand registration)', () => {
    it('exposes rotate as a subcommand with required flags', () => {
        // Import the full createIdentityCommand only for structural assertions; do not trigger runIdentityRotate.
        // Avoid a top-level static import causing circular vi.mock resolution-order issues.
        // Use a dynamic import instead to get the current mock view.
        return import('./identity.js').then(({ createIdentityCommand }) => {
            const command = createIdentityCommand();
            const rotate = command.commands.find((c) => c.name() === 'rotate');
            expect(rotate).toBeDefined();
            const help = rotate!.helpInformation();
            expect(help).toContain('--did <did>');
            expect(help).toContain('--principal-key-file <path>');
            expect(help).toContain('--yes');
            expect(help).toContain('--json');
        });
    });

    it('drives the action wrapper through commander parseAsync (--yes)', async () => {
        const { doc, agentPrivateKey, principalPrivateKey } = makeFixture();
        const update = vi.fn().mockResolvedValue(undefined);
        MockedRegistry.mockImplementation(() => ({
            query: vi.fn().mockResolvedValue(doc),
            update,
        }));

        const agentKeyFile = path.join(tmpHome, 'agent.pem');
        const principalKeyFile = path.join(tmpHome, 'principal.pem');
        await writeKey(agentKeyFile, agentPrivateKey);
        await writeKey(principalKeyFile, principalPrivateKey);

        vi.spyOn(console, 'log').mockImplementation(() => {});
        const { createIdentityCommand } = await import('./identity.js');
        const command = createIdentityCommand();
        await command.parseAsync(
            [
                'node',
                'identity',
                'rotate',
                '--did',
                doc.id,
                '--current-key-file',
                agentKeyFile,
                '--principal-key-file',
                principalKeyFile,
                '--yes',
            ],
            { from: 'node' },
        );
        expect(update).toHaveBeenCalledTimes(1);
    });
});

// Sanity: buildPrincipalApproval and initiateKeyRotation must interoperate. If the spec ever changes
// the field order of the rotation payload, this assertion will fail first, signalling that the CLI buildPrincipalApproval needs to be updated in sync.
describe('rotation payload contract', () => {
    it('canonicalize over (agentDid,newPublicKey,oldPublicKey,rotatedAt) is what initiateKeyRotation expects', () => {
        const { doc, agentPrivateKey, principalPrivateKey, principalDid } =
            makeFixture();
        const newKey = generateKeyPair();
        const rotatedAt = '2026-04-24T00:00:00.000Z' as Timestamp;
        const bytes = new TextEncoder().encode(
            canonicalize({
                agentDid: doc.id,
                newPublicKey: newKey.publicKey,
                oldPublicKey: doc.publicKey,
                rotatedAt,
            }),
        );
        const principalApproval = sign(bytes, principalPrivateKey) as Signature;

        // should not throw SIGNATURE_INVALID
        expect(() =>
            initiateKeyRotation({
                currentDoc: doc,
                currentPrivateKey: agentPrivateKey,
                newKeyPair: newKey,
                principalApproval,
                rotatedAt,
            }),
        ).not.toThrow();
        // indirectly confirm principalDid comes from the fixture (protects makeFixture consistency)
        expect(doc.principalDid).toBe(principalDid);
    });
});
