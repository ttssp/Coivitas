/**
 * Delegation chain E2E test
 *
 * Scenario (Principal → Agent A → Agent B → Agent C):
 *   1. Create a Principal (did:key) and three Agent identities (did:agent);
 *      register all Agent documents in the IdentityRegistry (real PostgreSQL).
 *   2. The Principal issues a Root Token to Agent A:
 *      - action=INQUIRY, allowlist {resource_type: [medical_records, billing_records]}
 *      - action=INQUIRY, temporal_scope {notBefore: T0, notAfter: T0+24h}
 *      Why two capabilities: validateAttenuation rule 2c
 *      requires a child not to introduce a scope dimension the parent lacks; if root only had allowlist,
 *      A→B adding temporal_scope would be rejected (ATTENUATION_VIOLATED). So root declares
 *      both dimensions up front (with looser windows), and later delegations only perform genuine attenuation.
 *   3. A→B delegation: keep allowlist unchanged, attenuate temporal_scope to a 1-hour window.
 *   4. B→C delegation: shrink allowlist to [medical_records]; temporal_scope keeps B's 1-hour window.
 *   5. Agent C holds the end-of-chain token and executes INQUIRY through RuntimeGuard+PolicyEngine:
 *      - expect executed=true
 *      - ActionRecord.delegationDepth === 2 (chain length = 2 DelegationProofs)
 *   6. Independently call validateDelegationChain and assert:
 *      - valid=true, depth=2
 *      - the attenuation rules are correct (the three-level allowlist/temporal_scope is a subset at each level)
 *   7. Revoke Agent A's token (i.e. rootToken.id); the revocation goes into the identity.revocations table.
 *   8. Agent C executes INQUIRY again:
 *      - expect executed=false, reason='capability revoked'
 *      - source of the cascade semantics: validateDelegationChain calls isRevoked on each hop's proof.parentTokenId;
 *        root revoked → the whole chain is PARENT_TOKEN_REVOKED → guard denies.
 *
 * Why all three levels share one IdentityRegistry: validateDelegationChain needs to resolve
 *   each delegator's (A / B) public key for chain-proof verification; the resolver reads the publicKey field
 *   from the document directly from the registry by did:agent.
 *
 * Gate: only runs when DATABASE_URL is present (aligned with the other policy-e2e / authorization-chain suites).
 */
import { randomUUID } from 'node:crypto';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import {
    canonicalize,
    generateKeyPair,
    sign,
} from '../../packages/crypto/src/index.js';
import {
    createAgentIdentity,
    delegateCapabilityToken,
    didKeyFromPublicKey,
    extractPublicKeyFromDIDKey,
    IdentityRegistry,
    RevocationList,
    validateDelegationChain,
} from '../../packages/identity/src/index.js';
import {
    ActionRecorder,
    PolicyEngine,
    RuntimeGuard,
    TokenStore,
} from '../../packages/policy/src/index.js';
import { createTestDatabase } from '../../packages/shared/src/index.js';
import type {
    Capability,
    CapabilityToken,
    DID,
    ResolvedPublicKeys,
    Timestamp,
} from '../../packages/types/src/index.js';
import { SPEC_VERSION_0_2_0 } from '../../packages/types/src/index.js';

// ─── Manually issue a specVersion 0.2.0 root token ─────────────────────────────
// issueCapabilityToken() always produces specVersion=0.1.0 and cannot carry temporal_scope
// (token-verifier rejects it with INVALID_TOKEN_FORMAT). To make the 3-hop chain carry both allowlist
// + temporal_scope, we construct a 0.2.0 root token directly here (issuer=principal did:key,
// self-signed). The signing payload is equivalent to createCapabilityTokenPayload (rule for the delegationChain
// field: a 0.2.0 root token has no chain → same as undefined, not written into the canonicalized JSON).
function buildPhase2RootToken(params: {
    principalDid: DID;
    principalPrivateKey: string;
    issuedTo: DID;
    capabilities: Capability[];
    issuedAt: Timestamp;
    expiresAt: Timestamp;
    revocationUrl: string;
}): CapabilityToken {
    const payload = {
        id: `urn:cap:${randomUUID()}`,
        specVersion: SPEC_VERSION_0_2_0,
        issuerDid: params.principalDid,
        principalDid: params.principalDid,
        issuedTo: params.issuedTo,
        issuedAt: params.issuedAt,
        expiresAt: params.expiresAt,
        capabilities: params.capabilities,
        revocationUrl: params.revocationUrl,
    };
    const payloadBytes = new TextEncoder().encode(
        canonicalize(payload as unknown as Record<string, unknown>),
    );
    return {
        ...payload,
        proof: {
            type: 'Ed25519Signature2026',
            created: params.issuedAt,
            verificationMethod: `${params.principalDid}#key-1`,
            value: sign(
                payloadBytes,
                params.principalPrivateKey,
            ) as CapabilityToken['proof']['value'],
        },
    } as CapabilityToken;
}

const describeIfDatabase = process.env.DATABASE_URL ? describe : describe.skip;

// ─── Test time anchors ──────────────────────────────────────────────────────────
// The root token's temporal_scope covers [T0, T0+24h); each delegation narrows it.
// NOW falls within every level's window, ensuring the scope checks pass (scope-evaluator compares by UTC semantics).
const T0 = '2026-04-21T10:00:00.000Z' as Timestamp;
const NOW = '2026-04-21T10:15:00.000Z' as Timestamp;
const ROOT_NOT_AFTER = '2026-04-22T10:00:00.000Z' as Timestamp; // T0 + 24h
const CHILD_NOT_AFTER = '2026-04-21T11:00:00.000Z' as Timestamp; // T0 + 1h (A→B window)
const ROOT_EXPIRES = '2026-04-22T10:00:00.000Z' as Timestamp;
const HOP1_EXPIRES = '2026-04-22T09:00:00.000Z' as Timestamp;
const HOP2_EXPIRES = '2026-04-22T08:00:00.000Z' as Timestamp;

// When pg does a server-side DROP DATABASE, the connection pool may still hold unfinished statements;
// after pool.end() returns, a residual client may throw 57P01 (terminating connection
// due to administrator command) on the next tick, which vitest treats as an Uncaught Exception → exit code 1.
// This error is a benign symptom of a teardown race and does not affect test assertions; silence 57P01 within afterAll.
const ADMIN_TERMINATION_CODE = '57P01';
function isAdminTermination(error: unknown): boolean {
    return (
        typeof error === 'object' &&
        error !== null &&
        'code' in error &&
        (error as { code?: unknown }).code === ADMIN_TERMINATION_CODE
    );
}

describeIfDatabase('delegation chain e2e', () => {
    let cleanup: (() => Promise<void>) | undefined;
    let pool: import('pg').Pool | undefined;
    let registry: IdentityRegistry;
    let tokenStore: TokenStore;
    let revocations: RevocationList;
    let recorder: ActionRecorder;

    let principalDid: DID;
    let agentA: { did: DID; privateKey: string };
    let agentB: { did: DID; privateKey: string };
    let agentC: { did: DID; privateKey: string };
    let rootToken: CapabilityToken;
    let hop1Token: CapabilityToken;
    let hop2Token: CapabilityToken;

    beforeAll(async () => {
        const database = await createTestDatabase();
        cleanup = database.cleanup;
        pool = database.pool;

        registry = new IdentityRegistry(database.pool);
        tokenStore = new TokenStore(database.pool);
        // The revocation cache defaults to 60s, which would make the second query of
        // "check not revoked → revoke → check again" return the cached false directly. The test flow must cross the
        // revoke boundary, so caching is explicitly disabled (TTL=0) to make isRevoked() hit the DB every time.
        revocations = new RevocationList(database.pool, { cacheTtlMs: 0 });

        const principal = generateKeyPair();
        principalDid = didKeyFromPublicKey(
            Buffer.from(principal.publicKey, 'hex'),
        );

        const created = {
            A: createAgentIdentity({
                principalDid,
                principalPrivateKey: principal.privateKey,
            }),
            B: createAgentIdentity({
                principalDid,
                principalPrivateKey: principal.privateKey,
            }),
            C: createAgentIdentity({
                principalDid,
                principalPrivateKey: principal.privateKey,
            }),
        };
        agentA = {
            did: created.A.document.id,
            privateKey: created.A.privateKey,
        };
        agentB = {
            did: created.B.document.id,
            privateKey: created.B.privateKey,
        };
        agentC = {
            did: created.C.document.id,
            privateKey: created.C.privateKey,
        };

        await registry.register(created.A.document);
        await registry.register(created.B.document);
        await registry.register(created.C.document);

        const ledger = generateKeyPair();
        recorder = new ActionRecorder(database.pool, {
            kind: 'standard',
            ledgerPrivateKey: ledger.privateKey.slice(0, 64),
        });

        // ── 1. Root token: Principal → Agent A (specVersion=0.2.0) ──
        // The two INQUIRY capabilities declare the allowlist dimension and the temporal_scope dimension respectively,
        // leaving room to attenuate both dimensions in later delegations.
        // 0.2.0 is required: 0.1.0 does not accept temporal_scope (a 0.2.0-exclusive scope).
        rootToken = buildPhase2RootToken({
            principalDid,
            principalPrivateKey: principal.privateKey,
            issuedTo: agentA.did,
            capabilities: [
                {
                    action: 'INQUIRY',
                    scope: {
                        type: 'allowlist',
                        field: 'resource_type',
                        values: ['medical_records', 'billing_records'],
                    },
                },
                {
                    action: 'INQUIRY',
                    scope: {
                        type: 'temporal_scope',
                        notBefore: T0,
                        notAfter: ROOT_NOT_AFTER,
                    },
                },
            ],
            issuedAt: T0,
            expiresAt: ROOT_EXPIRES,
            revocationUrl: 'https://revocation.example.com/v1/{id}',
        });
        await tokenStore.store(agentA.did, rootToken);

        // ── 2. A → B: allowlist unchanged, temporal_scope attenuated to a 1-hour window ──
        hop1Token = delegateCapabilityToken({
            parentToken: rootToken,
            delegatorPrivateKey: agentA.privateKey,
            delegateeDid: agentB.did,
            attenuatedCapabilities: [
                {
                    action: 'INQUIRY',
                    scope: {
                        type: 'allowlist',
                        field: 'resource_type',
                        values: ['medical_records', 'billing_records'],
                    },
                },
                {
                    action: 'INQUIRY',
                    scope: {
                        type: 'temporal_scope',
                        notBefore: T0,
                        notAfter: CHILD_NOT_AFTER,
                    },
                },
            ],
            expiresAt: HOP1_EXPIRES,
            revocationUrl: 'https://revocation.example.com/v1/{id}',
            issuedAt: T0,
        });
        await tokenStore.store(agentB.did, hop1Token);

        // ── 3. B → C: allowlist narrowed to [medical_records], temporal keeps B's ──
        hop2Token = delegateCapabilityToken({
            parentToken: hop1Token,
            delegatorPrivateKey: agentB.privateKey,
            delegateeDid: agentC.did,
            attenuatedCapabilities: [
                {
                    action: 'INQUIRY',
                    scope: {
                        type: 'allowlist',
                        field: 'resource_type',
                        values: ['medical_records'],
                    },
                },
                {
                    action: 'INQUIRY',
                    scope: {
                        type: 'temporal_scope',
                        notBefore: T0,
                        notAfter: CHILD_NOT_AFTER,
                    },
                },
            ],
            expiresAt: HOP2_EXPIRES,
            revocationUrl: 'https://revocation.example.com/v1/{id}',
            issuedAt: T0,
        });
        await tokenStore.store(agentC.did, hop2Token);
    });

    afterAll(async () => {
        // Before cleanup() runs pool.end(), install an error listener to swallow the 57P01 thrown by a
        // residual client during the server-side DROP DATABASE; other errors are still rethrown.
        // Order: pool error handler → pool.end() (inside cleanup) → dropDatabase.
        const swallow57P01 = (error: unknown): void => {
            if (!isAdminTermination(error)) throw error;
        };
        pool?.on('error', swallow57P01);
        try {
            await cleanup?.();
        } catch (error) {
            if (!isAdminTermination(error)) throw error;
        } finally {
            pool?.off('error', swallow57P01);
        }
    });

    // ─── Public-key resolver: read the publicKey of a did:agent document from the IdentityRegistry ─────
    // validateDelegationChain's signature resolution must support both did:agent (on-chain delegators)
    // and did:key (the principal's self-signed root token — used during verification).
    // did:key public keys are decoded from the DID itself, not via the registry.
    //
    // The 2nd argument of validateDelegationChain / RuntimeGuard is
    // ResolvedPublicKeys (a dual key containing current + previous + rotationState).
    // The e2e test involves no rotation, so every key is wrapped as a STABLE single key.
    function makeResolvePublicKeys(): (
        did: DID,
    ) => Promise<ResolvedPublicKeys | null> {
        return async (did: DID): Promise<ResolvedPublicKeys | null> => {
            let key: string | null;
            if (did.startsWith('did:key:')) {
                key = extractPublicKeyFromDIDKey(did);
            } else {
                const document = await registry.query(did);
                key = document?.publicKey ?? null;
            }
            return key === null
                ? null
                : { current: key, rotationState: 'STABLE' };
        };
    }

    function makeResolveToken(): (
        tokenId: string,
    ) => Promise<CapabilityToken | null> {
        return (tokenId) => tokenStore.getToken(tokenId);
    }

    it('validates 3-hop chain and records delegationDepth=2 when agent C executes INQUIRY', async () => {
        // 1. Validate the chain directly: valid=true, depth=2.
        const chainResult = await validateDelegationChain(
            hop2Token,
            makeResolvePublicKeys(),
            (id) => revocations.isRevoked(id),
            NOW,
            makeResolveToken(),
        );
        expect(chainResult.valid).toBe(true);
        expect(chainResult.depth).toBe(2);

        // 2. Attenuation-chain assertions: the three-level allowlist should converge at each level, and temporal_scope should narrow at each level.
        const rootAllowlist = (
            rootToken.capabilities[0]?.scope as {
                values: string[];
            }
        ).values;
        const hop1Allowlist = (
            hop1Token.capabilities[0]?.scope as {
                values: string[];
            }
        ).values;
        const hop2Allowlist = (
            hop2Token.capabilities[0]?.scope as {
                values: string[];
            }
        ).values;
        expect(new Set(rootAllowlist)).toEqual(
            new Set(['medical_records', 'billing_records']),
        );
        expect(new Set(hop1Allowlist)).toEqual(
            new Set(['medical_records', 'billing_records']),
        );
        expect(new Set(hop2Allowlist)).toEqual(new Set(['medical_records']));

        const rootTemporal = rootToken.capabilities[1]?.scope as {
            notAfter: string;
        };
        const hop1Temporal = hop1Token.capabilities[1]?.scope as {
            notAfter: string;
        };
        const hop2Temporal = hop2Token.capabilities[1]?.scope as {
            notAfter: string;
        };
        expect(rootTemporal.notAfter).toBe(ROOT_NOT_AFTER);
        expect(hop1Temporal.notAfter).toBe(CHILD_NOT_AFTER);
        expect(hop2Temporal.notAfter).toBe(CHILD_NOT_AFTER);
        expect(new Date(hop1Temporal.notAfter).getTime()).toBeLessThan(
            new Date(rootTemporal.notAfter).getTime(),
        );

        // 3. Execute INQUIRY end to end through the PolicyEngine (incl. RuntimeGuard), initiated by Agent C.
        const guard = new RuntimeGuard({
            tokenStore,
            revocationChecker: (id) => revocations.isRevoked(id),
            now: () => NOW,
            delegationChainValidator: validateDelegationChain,
            resolvePublicKeys: makeResolvePublicKeys(),
        });
        const engine = new PolicyEngine({ guard, recorder });

        const result = await engine.executeWithPolicy({
            action: 'INQUIRY',
            params: { resource_type: 'medical_records' },
            agentDid: agentC.did,
            principalDid,
            actorPrivateKey: agentC.privateKey,
            executor: () => Promise.resolve({ ok: true }),
        });

        expect(result.executed).toBe(true);
        if (!result.executed) {
            throw new Error(
                `Expected Agent C INQUIRY to succeed, got rejection: ${result.reason}`,
            );
        }
        expect(result.result).toEqual({ ok: true });

        // 4. ActionRecord.delegationDepth === 2: the authorization went through 2 delegations.
        const { records } = await recorder.query({
            agentDid: agentC.did,
            limit: 10,
        });
        const record = records.find((r) => r.recordId === result.recordId);
        expect(record).toBeDefined();
        expect(record?.delegationDepth).toBe(2);
    });

    it('cascades revocation: revoking root token denies Agent C INQUIRY', async () => {
        // Revoke the root token (held by Agent A); semantically "the Principal repeals the delegation root".
        await revocations.revoke({
            tokenId: rootToken.id,
            revokedBy: principalDid,
            reason: 'MANUAL_REVOCATION',
        });
        expect(await revocations.isRevoked(rootToken.id)).toBe(true);

        // validateDelegationChain internally checks isRevoked for each hop's proof.parentTokenId;
        // root revoked → the hop1 proof triggers PARENT_TOKEN_REVOKED → chainResult.valid=false.
        const chainResult = await validateDelegationChain(
            hop2Token,
            makeResolvePublicKeys(),
            (id) => revocations.isRevoked(id),
            NOW,
            makeResolveToken(),
        );
        expect(chainResult.valid).toBe(false);
        expect(chainResult.reason).toBe('PARENT_TOKEN_REVOKED');

        // The corresponding behavior on the guard path: "capability revoked".
        // (RuntimeGuard simply continues the loop on a chain failure; sawRevoked is flagged via
        // the top-level revocation check — see runtime-guard.ts.)
        const guard = new RuntimeGuard({
            tokenStore,
            revocationChecker: (id) => revocations.isRevoked(id),
            now: () => NOW,
            delegationChainValidator: validateDelegationChain,
            resolvePublicKeys: makeResolvePublicKeys(),
        });
        const engine = new PolicyEngine({ guard, recorder });

        const result = await engine.executeWithPolicy({
            action: 'INQUIRY',
            params: { resource_type: 'medical_records' },
            agentDid: agentC.did,
            principalDid,
            actorPrivateKey: agentC.privateKey,
            executor: () => Promise.resolve({ ok: true }),
        });

        expect(result.executed).toBe(false);
        if (result.executed) {
            throw new Error('Agent C INQUIRY should be denied after cascade.');
        }
        // Cross-layer contract: PARENT_TOKEN_REVOKED
        // must map to TOKEN_REVOKED semantics along the L3→L4→L5 path —
        // cascade revocation means "an ancestor token's revocation invalidates the child tokens as a whole" and must not be downgraded to
        // "no matching capability" (which would mean the agent was never authorized for this action at all).
        expect(result.reason).toBe('parent token revoked');
    });
});
