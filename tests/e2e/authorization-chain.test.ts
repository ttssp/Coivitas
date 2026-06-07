import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { generateKeyPair } from '../../packages/crypto/src/index.js';
import {
    createAgentIdentity,
    didKeyFromPublicKey,
    IdentityRegistry,
    isDidAgent,
    isDidKey,
    issueCapabilityToken,
    verifyCapabilityToken,
} from '../../packages/identity/src/index.js';
import {
    ActionRecorder,
    PolicyEngine,
    RuntimeGuard,
    TokenStore,
} from '../../packages/policy/src/index.js';
import { createTestDatabase } from '../../packages/shared/src/index.js';
import type { DID, Timestamp } from '../../packages/types/src/index.js';

type ChainVerificationCode =
    | 'TOKEN_NOT_FOUND'
    | 'TOKEN_SIGNATURE_INVALID'
    | 'ISSUER_IDENTITY_NOT_FOUND'
    | 'INVALID_PRINCIPAL_DID'
    | 'UNKNOWN_DID_FORMAT'
    | 'CHAIN_CYCLE_DETECTED'
    | 'CHAIN_DEPTH_EXCEEDED';

interface ChainNode {
    tokenId: string;
    issuerDid: DID;
}

interface ChainVerificationResult {
    valid: boolean;
    rootDid: DID | null;
    chainDepth: number;
    chain: ChainNode[];
    code?: ChainVerificationCode;
}

const describeIfDatabase = process.env.DATABASE_URL ? describe : describe.skip;

describeIfDatabase('authorization chain e2e', () => {
    let cleanup: (() => Promise<void>) | undefined;
    let registry: IdentityRegistry;
    let tokenStore: TokenStore;
    let recorder: ActionRecorder;
    let agentDid: DID;
    let principalDid: DID;
    let agentPrivateKey: string;
    let latestRecordId = '';

    beforeAll(async () => {
        const database = await createTestDatabase();
        cleanup = database.cleanup;

        registry = new IdentityRegistry(database.pool);
        tokenStore = new TokenStore(database.pool);

        const principal = generateKeyPair();
        principalDid = didKeyFromPublicKey(
            Buffer.from(principal.publicKey, 'hex'),
        );
        const agent = createAgentIdentity({
            principalDid,
            principalPrivateKey: principal.privateKey,
        });
        agentDid = agent.document.id;
        agentPrivateKey = agent.privateKey;
        await registry.register(agent.document);

        const ledger = generateKeyPair();
        recorder = new ActionRecorder(database.pool, {
            kind: 'standard',
            ledgerPrivateKey: ledger.privateKey.slice(0, 64),
        });

        // The token must be issued by the principal itself, so that verifyAuthorizationChainRoot can
        // trace the root back to principalDid (did:key). If issuerDid were a standalone did:key, the
        // short-circuit branch in verifyAuthorizationChainRoot would return that did as rootDid, which
        // contradicts the spec's "the root should be a human subject".
        const token = issueCapabilityToken({
            issuerDid: principalDid,
            issuedTo: agentDid,
            capabilities: [
                {
                    action: 'INQUIRY',
                    scope: {
                        type: 'allowlist',
                        field: 'recipient',
                        values: ['supplier-a'],
                    },
                },
            ],
            expiresAt: '2026-04-22T10:00:00.000Z' as Timestamp,
            revocationUrl: 'https://revocation.example.com/v1/{id}',
            issuerPrivateKey: principal.privateKey,
            issuedAt: '2026-04-21T10:00:00.000Z' as Timestamp,
        });
        await tokenStore.store(agentDid, token);

        const guard = new RuntimeGuard({
            tokenStore,
            revocationChecker: () => Promise.resolve(false),
            now: () => '2026-04-21T10:05:00.000Z' as Timestamp,
        });
        const engine = new PolicyEngine({
            guard,
            recorder,
        });

        const result = await engine.executeWithPolicy({
            action: 'INQUIRY',
            params: { recipient: 'supplier-a' },
            agentDid,
            principalDid,
            actorPrivateKey: agentPrivateKey,
            executor: () => Promise.resolve({ ok: true }),
        });

        if (!result.executed) {
            throw new Error(
                'Expected policy execution to succeed during authorization-chain setup.',
            );
        }

        latestRecordId = result.recordId;
    });

    afterAll(async () => {
        await cleanup?.();
    });

    it('traces ActionRecord.authorization_ref to a human principal root DID', async () => {
        const { records } = await recorder.query({
            agentDid,
            limit: 10,
        });
        const record = records.find(
            (candidate) => candidate.recordId === latestRecordId,
        );

        expect(record).toBeTruthy();
        const authorizationRef =
            record?.authorizationRef === null ||
            record?.authorizationRef === undefined
                ? null
                : (record.authorizationRef as { tokenId?: string });

        const verification = await verifyAuthorizationChainRoot(
            authorizationRef,
            tokenStore,
            registry,
            '2026-04-21T10:05:00.000Z' as Timestamp,
        );

        expect(verification.valid).toBe(true);
        expect(verification.rootDid).toBe(principalDid);
        expect(verification.chainDepth).toBe(1);
        expect(
            verification.chain.some((node) => node.issuerDid === principalDid),
        ).toBe(true);
    });

    it('fails cleanly when authorization_ref is missing a token id', async () => {
        await expect(
            verifyAuthorizationChainRoot(
                null,
                tokenStore,
                registry,
                '2026-04-21T10:05:00.000Z' as Timestamp,
            ),
        ).resolves.toEqual({
            valid: false,
            rootDid: null,
            chainDepth: 0,
            chain: [],
            code: 'TOKEN_NOT_FOUND',
        });
    });
});

async function verifyAuthorizationChainRoot(
    authorizationRef: { tokenId?: string } | null,
    tokenStore: TokenStore,
    identityRegistry: IdentityRegistry,
    now: Timestamp,
    maxDepth = 8,
): Promise<ChainVerificationResult> {
    const tokenId = authorizationRef?.tokenId;
    if (!tokenId) {
        return {
            valid: false,
            rootDid: null,
            chainDepth: 0,
            chain: [],
            code: 'TOKEN_NOT_FOUND',
        };
    }

    const chain: ChainNode[] = [];
    const visited = new Set<string>();
    const currentTokenId = tokenId;

    for (let depth = 0; depth < maxDepth; depth += 1) {
        if (visited.has(currentTokenId)) {
            return {
                valid: false,
                rootDid: null,
                chainDepth: depth,
                chain,
                code: 'CHAIN_CYCLE_DETECTED',
            };
        }
        visited.add(currentTokenId);

        const token = await tokenStore.getToken(currentTokenId);
        if (!token) {
            return {
                valid: false,
                rootDid: null,
                chainDepth: depth,
                chain,
                code: 'TOKEN_NOT_FOUND',
            };
        }

        chain.push({
            tokenId: currentTokenId,
            issuerDid: token.issuerDid,
        });

        const signatureCheck = verifyCapabilityToken(token, now);
        if (!signatureCheck.valid) {
            return {
                valid: false,
                rootDid: null,
                chainDepth: depth,
                chain,
                code: 'TOKEN_SIGNATURE_INVALID',
            };
        }

        if (isDidKey(token.issuerDid)) {
            return {
                valid: true,
                rootDid: token.issuerDid,
                chainDepth: depth + 1,
                chain,
            };
        }

        if (isDidAgent(token.issuerDid)) {
            const document = await identityRegistry.query(token.issuerDid);
            if (!document) {
                return {
                    valid: false,
                    rootDid: null,
                    chainDepth: depth,
                    chain,
                    code: 'ISSUER_IDENTITY_NOT_FOUND',
                };
            }

            if (!isDidKey(document.principalDid)) {
                return {
                    valid: false,
                    rootDid: null,
                    chainDepth: depth,
                    chain,
                    code: 'INVALID_PRINCIPAL_DID',
                };
            }

            chain.push({
                tokenId: `binding:${String(token.issuerDid)}`,
                issuerDid: document.principalDid,
            });
            return {
                valid: true,
                rootDid: document.principalDid,
                chainDepth: depth + 2,
                chain,
            };
        }

        return {
            valid: false,
            rootDid: null,
            chainDepth: depth,
            chain,
            code: 'UNKNOWN_DID_FORMAT',
        };
    }

    return {
        valid: false,
        rootDid: null,
        chainDepth: maxDepth,
        chain: [],
        code: 'CHAIN_DEPTH_EXCEEDED',
    };
}
