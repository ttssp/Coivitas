import { afterEach, describe, expect, it, vi } from 'vitest';

import { buildAgentCard, verifyAgentCard } from '@coivitas/communication';
import { generateKeyPair } from '@coivitas/crypto';
import {
    createAgentIdentity,
    didKeyFromPublicKey,
} from '@coivitas/identity';
import type { AgentCard, AgentIdentityDocument } from '@coivitas/types';

import { createDiscoverCommand, fetchAgentCard } from './discover.js';

// IdentityRegistry cannot run against a real database in unit tests, so we mock resolveAgentDID.
vi.mock('@coivitas/identity', async () => {
    const actual = await vi.importActual<
        typeof import('@coivitas/identity')
    >('@coivitas/identity');
    return {
        ...actual,
        resolveAgentDID: vi.fn(),
    };
});

const identity = await import('@coivitas/identity');
const mockedResolveAgentDID = identity.resolveAgentDID as unknown as ReturnType<
    typeof vi.fn
>;

// Wrap a fixed Response as fetch's mockResolvedValue -- type-safe and keeps ESLint happy.
function stubFetchResponse(response: Response): void {
    const fetchMock = vi.fn<typeof fetch>().mockResolvedValue(response);
    vi.stubGlobal('fetch', fetchMock);
}

// Make fetch reject -- compatible with the require-await rule; use mockRejectedValue rather than a throwing async arrow.
function stubFetchReject(error: Error): void {
    const fetchMock = vi.fn<typeof fetch>().mockRejectedValue(error);
    vi.stubGlobal('fetch', fetchMock);
}

// Reuse createAgentIdentity to build a complete document (with a correct bindingProof), then derive the AgentCard.
function makeFixture(): {
    doc: AgentIdentityDocument;
    privateKey: string;
    card: AgentCard;
} {
    const principal = generateKeyPair();
    const principalDid = didKeyFromPublicKey(
        Buffer.from(principal.publicKey, 'hex'),
    );
    const created = createAgentIdentity({
        principalDid,
        principalPrivateKey: principal.privateKey,
        capabilities: ['INQUIRY'],
        serviceEndpoints: [
            {
                id: 'main',
                type: 'coivitas.v1',
                url: 'https://example.com/agent',
            },
        ],
    });

    const card = buildAgentCard({
        doc: created.document,
        privateKey: created.privateKey,
        displayName: 'Demo Agent',
        description: 'Test fixture',
    });

    return {
        doc: created.document,
        privateKey: created.privateKey,
        card,
    };
}

afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
    vi.unstubAllEnvs();
    mockedResolveAgentDID.mockReset();
    process.exitCode = 0;
});

describe('fetchAgentCard', () => {
    it('returns the card payload from a successful response', async () => {
        const { card } = makeFixture();
        const fetchMock = vi
            .fn<typeof fetch>()
            .mockResolvedValue(
                new Response(JSON.stringify(card), { status: 200 }),
            );
        vi.stubGlobal('fetch', fetchMock);

        const result = await fetchAgentCard('https://example.com/agent');
        expect(result).toEqual(card);
        const url = fetchMock.mock.calls[0]![0] as string;
        expect(url).toBe('https://example.com/agent/.well-known/agent.json');
    });

    it('throws a friendly error when the endpoint returns non-2xx', async () => {
        stubFetchResponse(new Response('boom', { status: 502 }));
        await expect(fetchAgentCard('https://example.com')).rejects.toThrow(
            /HTTP 502/,
        );
    });

    it('throws when the response body is not valid JSON', async () => {
        stubFetchResponse(new Response('<<<not json>>>', { status: 200 }));
        await expect(fetchAgentCard('https://example.com')).rejects.toThrow(
            /Invalid JSON/,
        );
    });

    it('throws when fetch itself rejects (network unreachable)', async () => {
        stubFetchReject(new Error('ECONNREFUSED'));
        await expect(fetchAgentCard('https://example.com')).rejects.toThrow(
            /Discovery endpoint unreachable/,
        );
    });
});

describe('discover command (CLI integration)', () => {
    it('prints text summary including signature verdict on the happy path', async () => {
        vi.stubEnv('IDENTITY_REGISTRY_URL', 'https://registry.example.com');
        const { doc, card } = makeFixture();

        mockedResolveAgentDID.mockResolvedValue(doc);
        stubFetchResponse(new Response(JSON.stringify(card), { status: 200 }));

        const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
        const command = createDiscoverCommand();
        await command.parseAsync(
            ['node', 'discover', 'https://example.com/agent'],
            { from: 'node' },
        );

        expect(process.exitCode).not.toBe(1);
        const output = logSpy.mock.calls
            .map((call) => String(call[0]))
            .join('\n');
        expect(output).toContain('AgentCard');
        expect(output).toContain(`DID:               ${card.did}`);
        expect(output).toContain('Signature Valid:   yes');
        expect(output).toContain('Capabilities:');
        // verifyAgentCard should genuinely be routed to the mocked resolveAgentDID
        expect(mockedResolveAgentDID).toHaveBeenCalledWith(
            card.did,
            'https://registry.example.com',
        );
    });

    it('prints JSON when --json is set', async () => {
        vi.stubEnv('IDENTITY_REGISTRY_URL', 'https://registry.example.com');
        const { doc, card } = makeFixture();

        mockedResolveAgentDID.mockResolvedValue(doc);
        stubFetchResponse(new Response(JSON.stringify(card), { status: 200 }));

        const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
        const command = createDiscoverCommand();
        await command.parseAsync(
            ['node', 'discover', 'https://example.com', '--json'],
            { from: 'node' },
        );

        const printed = logSpy.mock.calls[0]![0] as string;
        const parsed = JSON.parse(printed) as {
            endpoint: string;
            card: AgentCard;
            signatureValid: boolean;
        };
        expect(parsed.signatureValid).toBe(true);
        expect(parsed.card.did).toBe(card.did);
        expect(parsed.endpoint).toBe('https://example.com');
    });

    it('sets process.exitCode=1 when signature verification fails', async () => {
        vi.stubEnv('IDENTITY_REGISTRY_URL', 'https://registry.example.com');
        const { card } = makeFixture();

        // returns null -> step 4 of verifyAgentCard fails
        mockedResolveAgentDID.mockResolvedValue(null);
        stubFetchResponse(new Response(JSON.stringify(card), { status: 200 }));

        const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
        const command = createDiscoverCommand();
        await command.parseAsync(
            ['node', 'discover', 'https://example.com/agent'],
            { from: 'node' },
        );

        expect(process.exitCode).toBe(1);
        const output = logSpy.mock.calls
            .map((call) => String(call[0]))
            .join('\n');
        expect(output).toContain('Signature Valid:   NO');
    });

    it('errors when registry URL cannot be resolved (no env, no flag)', async () => {
        vi.stubEnv('IDENTITY_REGISTRY_URL', '');
        const { card } = makeFixture();
        stubFetchResponse(new Response(JSON.stringify(card), { status: 200 }));

        const command = createDiscoverCommand();
        await expect(
            command.parseAsync(['node', 'discover', 'https://example.com'], {
                from: 'node',
            }),
        ).rejects.toThrow(/Identity registry URL is required/);
    });

    // Ensure verifyAgentCard's expectedDid path is fed by --expected-did.
    it('honours --expected-did and rejects when card.did differs', async () => {
        vi.stubEnv('IDENTITY_REGISTRY_URL', 'https://registry.example.com');
        const { doc, card } = makeFixture();
        mockedResolveAgentDID.mockResolvedValue(doc);
        stubFetchResponse(new Response(JSON.stringify(card), { status: 200 }));

        const wrongDid = 'did:agent:0000000000000000000000000000000000000000';
        const command = createDiscoverCommand();
        const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
        await command.parseAsync(
            [
                'node',
                'discover',
                'https://example.com/agent',
                '--expected-did',
                wrongDid,
            ],
            { from: 'node' },
        );

        expect(process.exitCode).toBe(1);
        const output = logSpy.mock.calls
            .map((call) => String(call[0]))
            .join('\n');
        expect(output).toContain('Signature Valid:   NO');
    });
});

// Sanity check: verify that the buildAgentCard / verifyAgentCard pairing actually holds under the test fixture --
// otherwise none of the happy-path assertions above mean anything.
describe('fixture integrity', () => {
    it('buildAgentCard output validates against verifyAgentCard with the same doc', async () => {
        const { doc, card } = makeFixture();
        const ok = await verifyAgentCard(card, () => Promise.resolve(doc));
        expect(ok).toBe(true);
    });
});

describe('discover command output formatting (edge branches)', () => {
    it('falls back to "(none)" hints for empty endpoints/capabilities', async () => {
        vi.stubEnv('IDENTITY_REGISTRY_URL', 'https://registry.example.com');
        const { doc, card } = makeFixture();
        const stripped = {
            ...card,
            serviceEndpoints: [],
            capabilitiesDeclared: [],
        };
        // verifyAgentCard compares a subset of the source document -- using empty arrays leaves no difference on either side, so the logic passes
        const docStripped = {
            ...doc,
            serviceEndpoints: [],
            capabilities: [],
        };

        // Since we mutated the payload, it would need re-signing to pass verify; but this test only cares about the
        // formatting branch, so we mock resolveAgentDID to return a mismatching doc -> signature check is false, which
        // triggers the branch while still printing the (none) text. The signature-failure NO path is already covered by an earlier unit test.
        mockedResolveAgentDID.mockResolvedValue(docStripped);
        stubFetchResponse(
            new Response(JSON.stringify(stripped), { status: 200 }),
        );
        const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
        const command = createDiscoverCommand();
        await command.parseAsync(['node', 'discover', 'https://example.com'], {
            from: 'node',
        });

        const output = logSpy.mock.calls
            .map((call) => String(call[0]))
            .join('\n');
        expect(output).toContain('Service Endpoints: (none)');
        expect(output).toContain('Capabilities:       (none)');
    });
});
