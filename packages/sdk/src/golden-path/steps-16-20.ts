/**
 * Golden Path extended Step 16-20 (a/b)
 *
 *   Step 16 Agent A publishes its AgentCard (/.well-known/agent.json)
 *   Step 17 Agent B discovers Agent A via DefaultDiscoveryService
 *   Step 18 Delegation chain: Principal -> Agent A (reuse Alice->A's tokenA, confirm chainLength=1)
 *   Step 19 Delegation chain: Agent A -> Agent B (delegateCapabilityToken sub-delegation + attenuation)
 *   Step 20 Agent B uses the sub-token through RuntimeGuard (with chain validator injected) -> delegationDepth=2
 *
 * Design notes:
 *   - Step 16 starts a standalone http.Server mounting /.well-known/agent.json instead of
 *     reusing Agent B's transport, to avoid polluting orchestrator routing.
 *   - Step 17 uses DefaultDiscoveryService.discoverFromEndpoint(); the resolver wraps
 *     IdentityRegistry as an adapter (satisfies the minimal FederatedResolver interface).
 *   - Step 19 uses delegateCapabilityToken(); attenuation rules are validated within the identity layer.
 *   - Step 20 reassembles a guardB instance with delegationChainValidator injected;
 *     the original guardB is left unchanged to avoid affecting the Step 6-11 response path.
 */

import { EventEmitter } from 'node:events';
import type { Server as HttpServer } from 'node:http';

import express from 'express';

import {
    AgentCardService,
    buildAgentCard,
    createAgentCardRoute,
    DefaultDiscoveryService,
} from '@coivitas/communication';
import {
    delegateCapabilityToken,
    validateDelegationChain,
} from '@coivitas/identity';
import type {
    AgentCard,
    AgentIdentityDocument,
    DID,
    FederatedResolver,
    FederatedResolverMetrics,
    ResolvedPublicKeys,
    Timestamp,
} from '@coivitas/types';
import { MAX_DELEGATION_DEPTH } from '@coivitas/types';

import type { GoldenPathContext } from './context.js';
import { resolveDemoPublicKey } from './utils.js';

// ── Step 16 ─────────────────────────────────────────────────────────────────

export async function runStep16(ctx: GoldenPathContext): Promise<void> {
    assertContext(ctx.agentADid, 'Agent-A DID is missing.');
    assertContext(ctx.agentAPrivateKey, 'Agent-A private key is missing.');
    assertContext(ctx.agentADocument, 'Agent-A document is missing.');

    // Build the AgentCard: the payload is grounded in the authoritative fields of AgentIdentityDocument; signed with Agent A's private key.
    const card = buildAgentCard({
        doc: ctx.agentADocument,
        privateKey: ctx.agentAPrivateKey,
        displayName: 'Agent A (Golden Path)',
        description: 'Demo responder for the golden-path walkthrough',
    });
    ctx.agentACard = card;

    // AgentCardService has caching + documentUpdated invalidation; the demo only needs a one-shot buildCard closure.
    const emitter = new EventEmitter();
    const service = new AgentCardService({
        agentDid: ctx.agentADid,
        buildCard: () => card,
        eventEmitter: emitter,
    });

    // Mount a minimal Express instance (without createApp's helmet/rate-limit wrapping),
    // exposing only /.well-known/agent.json; createAgentCardRoute expects an Express-shaped res.
    const app = express();
    app.get('/.well-known/agent.json', createAgentCardRoute(service));

    const server = app.listen(0, '127.0.0.1');
    await new Promise<void>((resolve, reject) => {
        server.once('listening', () => resolve());
        server.once('error', reject);
    });
    const address = server.address();
    if (!address || typeof address === 'string') {
        throw new Error('AgentCard server failed to bind.');
    }
    ctx.agentACardUrl = `http://127.0.0.1:${address.port}`;

    // Self-check: fetch ourselves directly to ensure the route can return a valid card; if it fails, Step 16 itself does not pass.
    const resp = await fetch(`${ctx.agentACardUrl}/.well-known/agent.json`);
    if (resp.status !== 200) {
        throw new Error(`AgentCard endpoint returned ${resp.status}.`);
    }
    const body = (await resp.json()) as AgentCard;
    if (body.did !== ctx.agentADid) {
        throw new Error(
            `AgentCard DID mismatch: expected ${ctx.agentADid}, got ${body.did}.`,
        );
    }

    ctx.cleanups.push(closeServer(server));
}

// ── Step 17 ─────────────────────────────────────────────────────────────────

export async function runStep17(ctx: GoldenPathContext): Promise<void> {
    assertContext(ctx.agentADid, 'Agent-A DID is missing.');
    assertContext(
        ctx.agentACardUrl,
        'Agent-A card URL is missing (Step 16 not run).',
    );
    assertContext(ctx.identityRegistry, 'IdentityRegistry missing.');

    // Adapter: DefaultDiscoveryService's FederatedResolver argument only needs resolve(did).
    // IdentityRegistry.lookup already returns AgentIdentityDocument | null.
    const registry = ctx.identityRegistry;
    const resolver: FederatedResolver = {
        resolve: async (did: DID): Promise<AgentIdentityDocument | null> =>
            await registry.query(did),
        invalidateCache: () => undefined,
        getMetrics: (): FederatedResolverMetrics => ({
            resolveTotal: 0,
            resolveSuccess: 0,
            resolveNull: 0,
            resolveInternalError: 0,
            versionConflictCount: 0,
            signatureInvalidCount: 0,
            quorumUnmetCount: 0,
            cacheHit: 0,
            cacheMiss: 0,
            latencyP50Ms: 0,
            latencyP95Ms: 0,
            latencyP99Ms: 0,
            // Counters for federated-resolution quorum stats (the Golden Path adapter
            // does not connect to real federated nodes, so these are all 0 placeholders)
            quorumVoteSplitCount: 0,
            dnsRebindingBlockedCount: 0,
            quorumReachedCount: 0,
            nodes: {},
        }),
        close: () => Promise.resolve(),
    };

    const discovery = new DefaultDiscoveryService({ resolver });
    // expectedDid binding: prevents the endpoint from returning another agent's card (card.did === expectedDid).
    const card = await discovery.discoverFromEndpoint(
        ctx.agentACardUrl,
        ctx.agentADid,
    );

    if (card.did !== ctx.agentADid) {
        throw new Error(
            `Discovery returned wrong DID: expected ${ctx.agentADid}, got ${card.did}.`,
        );
    }

    ctx.discoveredAgentACard = card;
}

// ── Step 18-20: delegation chain "issue -> validate -> revocation cascade" ────
// Task description (§ of phase2): "Step 18-20: issue -> validate -> revocation cascade"
// Step 18 issue: Principal -> Agent A (reuse Step 3's tokenA, confirm direct-issued shape)
// Step 19 validate: Agent A -> Agent B sub-delegation; in the real runner execution order,
// Step 14 has already revoked tokenA before Step 19, so Step 19's structural validation
// deliberately injects a "no revocation check" isRevoked stub (() => false), scoping
// validation to *structural* constraints such as chain signature / attenuation / parent
// snapshot consistency -- the functional check of revocation cascade is placed separately in Step 20.
// Step 20 revocation cascade: validateDelegationChain runs with the real revocationChecker;
// since Step 14 already put tokenA into the revocation list, the chain root is cascade-rejected
// and returns PARENT_TOKEN_REVOKED, aligning with the spec's revocation cascade semantics.

export function runStep18(ctx: GoldenPathContext): Promise<void> {
    // The Principal -> Agent A delegation was already completed in Step 3 (tokenA issued by Alice to Agent A).
    // Assert: tokenA is in "direct-issued" form (no delegationChain, issuer === principal).
    assertContext(ctx.tokenA, 'Token A is missing.');
    const chainLength = ctx.tokenA.delegationChain?.length ?? 0;
    if (chainLength !== 0) {
        throw new Error(
            `Expected direct-issued tokenA (chainLength=0), got ${chainLength}.`,
        );
    }
    if (ctx.tokenA.issuerDid !== ctx.tokenA.principalDid) {
        throw new Error(
            'tokenA issuer and principal must match for direct issuance.',
        );
    }
    return Promise.resolve();
}

export async function runStep19(ctx: GoldenPathContext): Promise<void> {
    assertContext(ctx.tokenA, 'Token A is missing.');
    assertContext(ctx.agentAPrivateKey, 'Agent-A private key is missing.');
    assertContext(ctx.agentBDid, 'Agent-B DID is missing.');
    assertContext(ctx.tokenStoreA, 'Token store A is missing.');
    assertContext(ctx.tokenStoreB, 'Token store B is missing.');
    assertContext(ctx.revocationList, 'Revocation list is missing.');

    // ── 19.a Agent A -> Agent B sub-delegation ──
    // delegateCapabilityToken validates internally:
    // - expiresAt <= parent.expiresAt
    // - attenuated is a subset of parent (here: INQUIRY only, quantity max attenuated down to 100)
    // - chainLength+1 <= MAX_DELEGATION_DEPTH
    const childExpiresAt = new Date(
        Math.min(
            Date.now() + 60 * 60 * 1000, // 1h child token
            new Date(ctx.tokenA.expiresAt).getTime(),
        ),
    ).toISOString() as Timestamp;

    const child = delegateCapabilityToken({
        parentToken: ctx.tokenA,
        delegatorPrivateKey: ctx.agentAPrivateKey,
        delegateeDid: ctx.agentBDid,
        attenuatedCapabilities: [
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
                    max: 100, // attenuation: parent 500 -> child 100
                },
            },
        ],
        expiresAt: childExpiresAt,
        revocationUrl: 'https://revocations.local/api/v1/revocations/{id}',
    });

    if ((child.delegationChain?.length ?? 0) !== 1) {
        throw new Error(
            `Expected child delegationChain length = 1, got ${child.delegationChain?.length}.`,
        );
    }
    if (
        child.delegationChain &&
        child.delegationChain.length > MAX_DELEGATION_DEPTH
    ) {
        throw new Error('Child exceeds MAX_DELEGATION_DEPTH.');
    }

    await ctx.tokenStoreB.store(ctx.agentBDid, child);
    ctx.tokenAB = child;

    // ── 19.b Validate tokenAB: chain signature + attenuation + root-parent verify all pass ──
    // Note: Step 14 has already revoked tokenA, so a revocationChecker returning true would fail validation.
    // Here we use a "no revocation check" isRevoked stub, validating purely the chain structure and signature --
    // the functional check of revocation cascade is placed in Step 20.
    // resolvePublicKeys returns ResolvedPublicKeys; the STABLE state wraps the string into a structure
    const resolvePublicKeys = async (
        did: DID,
    ): Promise<ResolvedPublicKeys | null> => {
        const key = await resolveDemoPublicKey(did, ctx.identityRegistryUrl);
        if (key === null) return null;
        return { current: key, rotationState: 'STABLE' };
    };
    const mergedGetToken = async (tokenId: string) => {
        const fromB = await ctx.tokenStoreB!.getToken(tokenId);
        if (fromB) return fromB;
        return await ctx.tokenStoreA!.getToken(tokenId);
    };

    const chainResult = await validateDelegationChain(
        child,
        resolvePublicKeys,
        () => Promise.resolve(false), // structural-only check, revocation check deferred to Step 20
        new Date().toISOString() as Timestamp,
        mergedGetToken,
    );
    if (!chainResult.valid) {
        throw new Error(
            `Delegation chain structural validation failed: reason=${chainResult.reason}, brokenAtIndex=${chainResult.brokenAtIndex ?? 'n/a'}.`,
        );
    }
    if (chainResult.depth !== 1) {
        throw new Error(`Expected chain depth=1, got ${chainResult.depth}.`);
    }
}

export async function runStep20(ctx: GoldenPathContext): Promise<void> {
    assertContext(ctx.tokenAB, 'tokenAB is missing (Step 19 not run).');
    assertContext(ctx.agentBDid, 'Agent-B DID is missing.');
    assertContext(ctx.tokenStoreA, 'Token store A is missing.');
    assertContext(ctx.tokenStoreB, 'Token store B is missing.');
    assertContext(ctx.revocationList, 'Revocation list is missing.');
    assertContext(ctx.tokenA, 'Token A is missing.');

    // Revocation cascade precondition: ensure parent tokenA is actually in the revoked state at this point (revoked in Step 14).
    const parentRevoked = await ctx.revocationList.isRevoked(ctx.tokenA.id);
    if (!parentRevoked) {
        throw new Error(
            'Precondition failed: Step 14 should have revoked tokenA before Step 20.',
        );
    }

    // Cross-store getToken, used by validateDelegationChain to resolve the parent.
    const mergedGetToken = async (tokenId: string) => {
        const fromB = await ctx.tokenStoreB!.getToken(tokenId);
        if (fromB) return fromB;
        return await ctx.tokenStoreA!.getToken(tokenId);
    };

    // Go directly through the validator to verify "cascade rejection" semantics (it exposes the
    // reason more precisely than guard.check, which on chain failure continues into "no matching capability").
    // resolvePublicKeys wraps a STABLE single-key structure
    const chainResult = await validateDelegationChain(
        ctx.tokenAB,
        async (did): Promise<ResolvedPublicKeys | null> => {
            const key = await resolveDemoPublicKey(
                did,
                ctx.identityRegistryUrl,
            );
            if (key === null) return null;
            return { current: key, rotationState: 'STABLE' };
        },
        async (tokenId) => await ctx.revocationList!.isRevoked(tokenId),
        new Date().toISOString() as Timestamp,
        mergedGetToken,
    );

    if (chainResult.valid) {
        throw new Error(
            'Expected cascade-revoked chain to be rejected, but validator returned valid.',
        );
    }
    if (chainResult.reason !== 'PARENT_TOKEN_REVOKED') {
        throw new Error(
            `Expected cascade reason PARENT_TOKEN_REVOKED, got ${chainResult.reason}.`,
        );
    }

    ctx.delegationCheckResult = {
        allowed: false,
        reason: chainResult.reason,
        delegationDepth: chainResult.depth,
    };
}

// ── helpers ─────────────────────────────────────────────────────────────────

function closeServer(server: HttpServer): () => Promise<void> {
    return async () => {
        server.closeAllConnections?.();
        await new Promise<void>((resolve, reject) => {
            server.close((err) => (err ? reject(err) : resolve()));
        });
    };
}

function assertContext<T>(
    value: T | undefined,
    message: string,
): asserts value is T {
    if (value === undefined) {
        throw new Error(message);
    }
}
