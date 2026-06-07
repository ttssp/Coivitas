import { generateKeyPair } from '@coivitas/crypto';
import {
    createAgentIdentity,
    didKeyFromPublicKey,
    IdentityRegistry,
    issueCapabilityToken,
    RevocationList,
} from '@coivitas/identity';
import {
    ActionRecorder,
    IntegrityChecker,
    PolicyEngine,
    RuntimeGuard,
    TokenStore,
} from '@coivitas/policy';

import type { GoldenPathContext } from './context.js';
import { resolveDemoPublicKey } from './utils.js';

export function runStep0(ctx: GoldenPathContext): Promise<void> {
    const alice = generateKeyPair();
    const bob = generateKeyPair();

    ctx.aliceKeyPair = alice;
    ctx.bobKeyPair = bob;
    ctx.aliceDid = didKeyFromPublicKey(Buffer.from(alice.publicKey, 'hex'));
    ctx.bobDid = didKeyFromPublicKey(Buffer.from(bob.publicKey, 'hex'));

    return Promise.resolve();
}

export async function runStep1(ctx: GoldenPathContext): Promise<void> {
    assertContext(ctx.aliceDid, 'Alice DID is missing.');
    assertContext(ctx.aliceKeyPair, 'Alice key pair is missing.');

    ctx.identityRegistry ??= new IdentityRegistry(ctx.pool);
    ctx.revocationList ??= new RevocationList(ctx.pool);

    const agent = createAgentIdentity({
        principalDid: ctx.aliceDid,
        principalPrivateKey: ctx.aliceKeyPair.privateKey,
        capabilities: ['INQUIRY', 'CONFIRM', 'RECORD'],
        serviceEndpoints: [
            {
                id: 'negotiation',
                type: 'NegotiationEndpoint',
                // Placeholder URL: the actual transport uses the HandshakeInitiator's direct-connect loopback port;
                // the identity schema requires https, so a schema-valid placeholder value is used here.
                url: 'https://agent-a.local/negotiation',
            },
        ],
    });

    await ctx.identityRegistry.register(agent.document);

    ctx.agentADid = agent.document.id;
    ctx.agentAPrivateKey = agent.privateKey;
    ctx.agentADocument = agent.document;
    ctx.tokenStoreA = new TokenStore(ctx.pool);
    ctx.recorderA = new ActionRecorder(ctx.pool, {
        kind: 'standard',
        ledgerPrivateKey: ctx.ledgerPrivateKey,
    });
    ctx.guardA = new RuntimeGuard({
        tokenStore: ctx.tokenStoreA,
        revocationChecker: async (tokenId) =>
            await ctx.revocationList!.isRevoked(tokenId),
    });
    ctx.policyEngineA = new PolicyEngine({
        guard: ctx.guardA,
        recorder: ctx.recorderA,
    });
    // After the DU refactor, golden-path defaults to standard mode (business-chain verification).
    // governor-chain verification is not part of the golden-path default scenario; on encountering a governor DID it is fail-closed.
    ctx.integrityCheckerA = new IntegrityChecker(ctx.pool, {
        kind: 'standard',
        ledgerPrivateKey: ctx.ledgerPrivateKey,
        resolveIdentity: async (did) =>
            await resolveDemoPublicKey(did, ctx.identityRegistryUrl),
    });
}

export async function runStep2(ctx: GoldenPathContext): Promise<void> {
    assertContext(ctx.bobDid, 'Bob DID is missing.');
    assertContext(ctx.bobKeyPair, 'Bob key pair is missing.');
    ctx.identityRegistry ??= new IdentityRegistry(ctx.pool);
    ctx.revocationList ??= new RevocationList(ctx.pool);

    const agent = createAgentIdentity({
        principalDid: ctx.bobDid,
        principalPrivateKey: ctx.bobKeyPair.privateKey,
        capabilities: ['QUOTE', 'CONFIRM', 'RECORD'],
        serviceEndpoints: [
            {
                id: 'negotiation',
                type: 'NegotiationEndpoint',
                url: 'https://agent-b.local/negotiation',
            },
        ],
    });

    await ctx.identityRegistry.register(agent.document);

    ctx.agentBDid = agent.document.id;
    ctx.agentBPrivateKey = agent.privateKey;
    ctx.agentBDocument = agent.document;
    ctx.tokenStoreB = new TokenStore(ctx.pool);
    ctx.recorderB = new ActionRecorder(ctx.pool, {
        kind: 'standard',
        ledgerPrivateKey: ctx.ledgerPrivateKey,
    });
    ctx.guardB = new RuntimeGuard({
        tokenStore: ctx.tokenStoreB,
        revocationChecker: async (tokenId) =>
            await ctx.revocationList!.isRevoked(tokenId),
    });
    ctx.policyEngineB = new PolicyEngine({
        guard: ctx.guardB,
        recorder: ctx.recorderB,
    });
    // Same as step1, standard mode.
    ctx.integrityCheckerB = new IntegrityChecker(ctx.pool, {
        kind: 'standard',
        ledgerPrivateKey: ctx.ledgerPrivateKey,
        resolveIdentity: async (did) =>
            await resolveDemoPublicKey(did, ctx.identityRegistryUrl),
    });
}

export async function runStep3(ctx: GoldenPathContext): Promise<void> {
    assertContext(ctx.aliceDid, 'Alice DID is missing.');
    assertContext(ctx.agentADid, 'Agent-A DID is missing.');
    assertContext(ctx.aliceKeyPair, 'Alice key pair is missing.');
    assertContext(ctx.tokenStoreA, 'Token store A is missing.');

    const token = issueCapabilityToken({
        issuerDid: ctx.aliceDid,
        issuedTo: ctx.agentADid,
        capabilities: [
            {
                action: 'INQUIRY',
                scope: {
                    type: 'allowlist',
                    field: 'product_category',
                    values: ['electronics'],
                },
            },
            {
                action: 'INQUIRY',
                scope: {
                    type: 'numeric_limit',
                    field: 'quantity',
                    max: 500,
                },
            },
            {
                action: 'CONFIRM',
                scope: {
                    type: 'numeric_limit',
                    field: 'confirmed_price',
                    max: 10000,
                    currency: 'USD',
                },
            },
        ],
        expiresAt: new Date(
            Date.now() + 24 * 60 * 60 * 1000,
        ).toISOString() as never,
        // revocationUrl must be https; in the Demo environment revocation goes through the RevocationList API directly, so the URL is only a template placeholder.
        revocationUrl: 'https://revocations.local/api/v1/revocations/{id}',
        issuerPrivateKey: ctx.aliceKeyPair.privateKey,
    });

    await ctx.tokenStoreA.store(ctx.agentADid, token);
    ctx.tokenA = token;
}

export async function runStep4(ctx: GoldenPathContext): Promise<void> {
    assertContext(ctx.bobDid, 'Bob DID is missing.');
    assertContext(ctx.agentBDid, 'Agent-B DID is missing.');
    assertContext(ctx.bobKeyPair, 'Bob key pair is missing.');
    assertContext(ctx.tokenStoreB, 'Token store B is missing.');

    const token = issueCapabilityToken({
        issuerDid: ctx.bobDid,
        issuedTo: ctx.agentBDid,
        capabilities: [
            // Agent B, acting as the responder, needs local INQUIRY authorization so that on the recipient side
            // the PolicyEngine passes its independent check of "is this agent authorized to respond to this action".
            {
                action: 'INQUIRY',
                scope: {
                    type: 'allowlist',
                    field: 'product_category',
                    values: ['electronics'],
                },
            },
            {
                action: 'INQUIRY',
                scope: {
                    type: 'numeric_limit',
                    field: 'quantity',
                    max: 500,
                },
            },
            {
                action: 'QUOTE',
                scope: {
                    type: 'numeric_limit',
                    field: 'unit_price',
                    max: 1000,
                    currency: 'USD',
                },
            },
            {
                action: 'QUOTE',
                scope: {
                    type: 'numeric_limit',
                    field: 'quantity',
                    max: 500,
                },
            },
            {
                action: 'CONFIRM',
                scope: {
                    type: 'numeric_limit',
                    field: 'confirmed_price',
                    max: 10000,
                    currency: 'USD',
                },
            },
        ],
        expiresAt: new Date(
            Date.now() + 24 * 60 * 60 * 1000,
        ).toISOString() as never,
        revocationUrl: 'https://revocations.local/api/v1/revocations/{id}',
        issuerPrivateKey: ctx.bobKeyPair.privateKey,
    });

    await ctx.tokenStoreB.store(ctx.agentBDid, token);
    ctx.tokenB = token;
}

function assertContext<T>(
    value: T | undefined,
    message: string,
): asserts value is T {
    if (value === undefined) {
        throw new Error(message);
    }
}
