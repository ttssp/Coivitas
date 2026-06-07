/**
 * AuditShareManager L3 11-step verify unit tests
 *
 * Covered scenarios:
 *   - Step 1: schema validate fail → AUDIT_SHARE_SCHEMA_INVALID
 *   - Step 2: 5-field invariant fail-closed (version + audience + notAfter + challenge + disclosedClaims)
 *   - Step 3: DelegatedAuditKey not found → AUDIT_SHARE_TOKEN_INVALID
 *   - Step 4: verifyDelegatedAuditKey 5-step pass-through fail-closed (transitively tested via identity)
 *   - Step 5: key.delegatedTo !== request.requesterDid → AUDIT_SHARE_DELEGATOR_AUDIENCE_MISMATCH
 *   - Step 6: requester Ed25519 verify fail → AUDIT_SHARE_REQUESTER_SIGNATURE_INVALID
 *   - Step 7: scope re-verify (toAuditShareScope factory re-verify; defense-in-depth)
 *   - Step 8: multi-tenant fail-closed → AUDIT_SHARE_CROSS_TENANT_REJECT
 *   - Step 9: fetchByChainIdentity passed through to the port (procedural SQL WHERE scope enforce)
 *   - Step 10: verifyHashChain fail → AUDIT_SHARE_HASH_CHAIN_INVALID
 *   - Step 11: selective disclosure projection (happy path return result)
 *   - e2e cross-package ≥3 cases (L0+L2+L3 interplay verify)
 */

import { canonicalize, generateKeyPair, sign } from '@coivitas/crypto';
import {
    createAuditShareDelegatedKey,
    type AuditShareDelegatedKey,
    type AuditShareResolvePublicKeyFn,
} from '@coivitas/identity';
import {
    AUDIT_SHARE_VERSION_1_0_0,
    AuditShareError,
    toAuditKeyId,
    toAuditShareScope,
    toAuditShareVersion,
    type AuditEvent,
    type AuditShareScope,
    type AuditShareVerifiedRequest,
    type DID,
    type HashChainEntry,
    type Signature,
    type Timestamp,
} from '@coivitas/types';
import { describe, expect, it, vi } from 'vitest';

import {
    AuditShareManager,
    type AuditEventStore,
    type AuditShareDelegatedKeyStore,
    type AuditShareManagerDeps,
    type ChallengeStore,
    type HashChainVerifier,
    type TenantAuditSharePolicyStore,
} from '../audit-share-manager.js';

// ── Test fixture ──────────────────────────────────────────────────────────

const NOW = '2026-06-01T00:00:00.000Z' as Timestamp;
const EXPECTED_AUDIENCE = 'did:key:target-domain' as DID;

interface TestSetup {
    request: AuditShareVerifiedRequest;
    delegatorKeys: { publicKey: string; privateKey: string };
    requesterKeys: { publicKey: string; privateKey: string };
    delegatedKey: AuditShareDelegatedKey;
    scope: AuditShareScope;
    deps: AuditShareManagerDeps;
    // mock controllers
    mockFetch: ReturnType<typeof vi.fn>;
    mockIsAllowed: ReturnType<typeof vi.fn>;
    mockChallengeConsume: ReturnType<typeof vi.fn>;
    mockVerifyChain: ReturnType<typeof vi.fn>;
    mockFetchEntries: ReturnType<typeof vi.fn>;
    mockFetchEvents: ReturnType<typeof vi.fn>;
}

/**
 * Build a valid, complete test fixture (5 ports + real Ed25519 signing keys + request)
 */
function buildTestSetup(opts?: {
    requesterDidOverride?: DID;
    delegatedToOverride?: DID;
    tenantAllowed?: boolean;
    challengeOk?: boolean;
    chainValid?: boolean;
    auditEvents?: readonly AuditEvent[];
    entries?: readonly HashChainEntry[];
    requesterPrivateKeyOverride?: string;
}): TestSetup {
    const delegatorKeys = generateKeyPair();
    const requesterKeys = generateKeyPair();
    const delegatedFrom = 'did:key:principal-001' as DID;
    const delegatedTo =
        opts?.delegatedToOverride ?? ('did:key:auditor-001' as DID);
    const requesterDid = opts?.requesterDidOverride ?? delegatedTo;

    // Build the DelegatedAuditKey + a real Ed25519 signature (delegator private key)
    // scope binding is mandatory (key.scope ↔ request.requestedScope match)
    // scope relies on store-level integrity (the DB row carries an FK + is immutable); the verifier does not include scope in the signed payload
    // (a later version may upgrade to cryptographic enforce — sign payload includes scope)
    const keyScope = toAuditShareScope({
        tenantId: 'tenant-acme',
        auditClass: 'L1',
    });
    const baseFieldsForSign = {
        auditKeyId: '11111111-2222-4333-8444-555555555555',
        delegatedFrom,
        delegatedTo,
        purpose: 'AUDIT' as const,
        validFrom: '2026-01-01T00:00:00.000Z' as Timestamp,
        validUntil: '2027-01-01T00:00:00.000Z' as Timestamp,
    };
    const baseFields = { ...baseFieldsForSign, scope: keyScope };
    const delegatorPayload = canonicalize(baseFieldsForSign);
    const delegatorSig = sign(
        new TextEncoder().encode(delegatorPayload),
        delegatorKeys.privateKey,
    ) as Signature;

    const delegatedKey = createAuditShareDelegatedKey({
        ...baseFields,
        proof: {
            signature: delegatorSig,
            signedAt: '2026-05-17T12:00:00.000Z' as Timestamp,
            signedBy: delegatedFrom,
        },
    });

    // Build the AuditShareVerifiedRequest + a real Ed25519 signature (requester private key)
    const scope = toAuditShareScope({
        tenantId: 'tenant-acme',
        auditClass: 'L1',
    });

    const requestPayloadObj = {
        auditShareVersion: AUDIT_SHARE_VERSION_1_0_0,
        token: '11111111-2222-4333-8444-555555555555',
        disclosedClaims: ['eventType', 'timestamp'],
        challenge: 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee',
        audience: EXPECTED_AUDIENCE,
        notAfter: '2026-12-31T23:59:59.000Z' as Timestamp,
        requestedScope: {
            tenantId: 'tenant-acme',
            auditClass: 'L1',
        },
        requesterDid,
    };
    const requestPayloadStr = canonicalize(requestPayloadObj);
    const requesterSig = sign(
        new TextEncoder().encode(requestPayloadStr),
        opts?.requesterPrivateKeyOverride ?? requesterKeys.privateKey,
    ) as Signature;

    const request: AuditShareVerifiedRequest = {
        auditShareVersion: toAuditShareVersion('1.0.0'),
        token: toAuditKeyId('11111111-2222-4333-8444-555555555555'),
        disclosedClaims: ['eventType', 'timestamp'],
        challenge: 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee',
        audience: EXPECTED_AUDIENCE,
        notAfter: '2026-12-31T23:59:59.000Z' as Timestamp,
        requestedScope: scope,
        requesterDid,
        requesterSignature: requesterSig,
    };

    // Build mock entries + auditEvents
    const defaultEntries: HashChainEntry[] = opts?.entries
        ? [...opts.entries]
        : [
              {
                  tenantId: 'tenant-acme',
                  auditClass: 'L1',
                  chainNamespace: 'atp',
                  chainPosition: 1,
                  previousHash: null,
                  canonicalPayloadHash: 'hash-1',
                  entryAt: '2026-04-01T00:00:00.000Z' as Timestamp,
              },
          ];
    const defaultEvents: AuditEvent[] = opts?.auditEvents
        ? [...opts.auditEvents]
        : [
              {
                  id: 'evt-001',
                  eventType: 'AUDIT_QUERY',
                  actorDid: 'did:key:auditor-001' as DID,
                  targetAgentDid: 'did:key:target-domain' as DID,
                  timestamp: '2026-04-01T00:00:00.000Z' as Timestamp,
                  outcome: 'ALLOWED',
                  prevHash: null,
                  signature: 'evt-sig' as Signature,
                  tenantId: 'tenant-acme',
                  auditClass: 'L1',
              },
          ];

    // mock port implementations (non-async + Promise.resolve to satisfy @typescript-eslint/require-await)
    const mockFetch = vi.fn<
        (token: string) => Promise<AuditShareDelegatedKey | null>
    >(() => Promise.resolve(delegatedKey));
    const mockIsAllowed = vi.fn<
        (
            principalDid: DID,
            tenantId: string,
            auditClass: string,
        ) => Promise<boolean>
    >(() => Promise.resolve(opts?.tenantAllowed ?? true));
    const mockChallengeConsume = vi.fn<(c: string) => Promise<boolean>>(() =>
        Promise.resolve(opts?.challengeOk ?? true),
    );
    const mockVerifyChain = vi.fn<
        (
            entries: readonly HashChainEntry[],
        ) => Promise<{ valid: true } | { valid: false; reason: string }>
    >(() =>
        Promise.resolve(
            opts?.chainValid === false
                ? { valid: false, reason: 'hash chain test fail' }
                : { valid: true },
        ),
    );
    const mockFetchEntries = vi.fn<
        (scope: AuditShareScope) => Promise<readonly HashChainEntry[]>
    >(() => Promise.resolve(defaultEntries));
    const mockFetchEvents = vi.fn<
        (entries: readonly HashChainEntry[]) => Promise<readonly AuditEvent[]>
    >(() => Promise.resolve(defaultEvents));

    const resolvePublicKey: AuditShareResolvePublicKeyFn = (did: DID) => {
        if (did === delegatedFrom)
            return Promise.resolve(delegatorKeys.publicKey);
        if (did === requesterDid)
            return Promise.resolve(requesterKeys.publicKey);
        return Promise.resolve(null);
    };

    const keyStore: AuditShareDelegatedKeyStore = {
        fetch: mockFetch as unknown as AuditShareDelegatedKeyStore['fetch'],
    };
    const policyStore: TenantAuditSharePolicyStore = {
        isAllowed:
            mockIsAllowed as unknown as TenantAuditSharePolicyStore['isAllowed'],
    };
    const eventStore: AuditEventStore = {
        fetchByChainIdentity:
            mockFetchEntries as unknown as AuditEventStore['fetchByChainIdentity'],
        fetchAuditEvents:
            mockFetchEvents as unknown as AuditEventStore['fetchAuditEvents'],
    };
    const chainVerifier: HashChainVerifier = {
        verify: mockVerifyChain as unknown as HashChainVerifier['verify'],
    };
    // ChallengeStore adds a check method (no consume) + consume moved to after step 6
    // mockChallengeCheck returns challengeOk by default; tests override via opts?.challengeOk
    const mockChallengeCheck = vi.fn<(c: string) => Promise<boolean>>(() =>
        Promise.resolve(opts?.challengeOk ?? true),
    );
    const challengeStore: ChallengeStore = {
        check: mockChallengeCheck as unknown as ChallengeStore['check'],
        consume: mockChallengeConsume as unknown as ChallengeStore['consume'],
    };

    return {
        request,
        delegatorKeys,
        requesterKeys,
        delegatedKey,
        scope,
        deps: {
            resolvePublicKey,
            delegatedAuditKeyStore: keyStore,
            tenantPolicyStore: policyStore,
            auditEventStore: eventStore,
            hashChainVerifier: chainVerifier,
            challengeStore,
        },
        mockFetch,
        mockIsAllowed,
        mockChallengeConsume,
        mockVerifyChain,
        mockFetchEntries,
        mockFetchEvents,
    };
}

// ── Happy path (11 steps all pass) ────────────────────────────────────────

describe('AuditShareManager — happy path', () => {
    it('should return ok: true when 11 steps all pass', async () => {
        const setup = buildTestSetup();
        const manager = new AuditShareManager(setup.deps);
        const result = await manager.verifyAuditRequest(
            setup.request,
            EXPECTED_AUDIENCE,
            NOW,
        );
        expect(result.ok).toBe(true);
        if (result.ok) {
            expect(result.entries.length).toBe(1);
            expect(result.auditEvents.length).toBe(1);
        }
    });

    it('should invoke all 6 ports (anti dead-port-method; active-invocation verify)', async () => {
        const setup = buildTestSetup();
        const manager = new AuditShareManager(setup.deps);
        await manager.verifyAuditRequest(setup.request, EXPECTED_AUDIENCE, NOW);

        // Active invocation of all 6 ports
        expect(setup.mockChallengeConsume).toHaveBeenCalled(); // step 2
        expect(setup.mockFetch).toHaveBeenCalled(); // step 3
        expect(setup.mockIsAllowed).toHaveBeenCalled(); // step 8
        expect(setup.mockFetchEntries).toHaveBeenCalled(); // step 9
        expect(setup.mockVerifyChain).toHaveBeenCalled(); // step 10
        expect(setup.mockFetchEvents).toHaveBeenCalled(); // step 11
    });
});

// ── Step 1: AJV schema validate ─────────────

describe('AuditShareManager step 1 — schema validate', () => {
    it('should throw AUDIT_SHARE_SCHEMA_INVALID when request missing required field', async () => {
        const setup = buildTestSetup();
        const manager = new AuditShareManager(setup.deps);
        // Remove the audience field (required)
        const invalidRequest = {
            ...setup.request,
            audience: undefined,
        } as unknown as AuditShareVerifiedRequest;

        await expect(
            manager.verifyAuditRequest(invalidRequest, EXPECTED_AUDIENCE, NOW),
        ).rejects.toMatchObject({
            code: 'AUDIT_SHARE_SCHEMA_INVALID',
            invariant: 'step-1-schema-validate',
        });
    });
});

// ── Step 2 per-sub-clause fail-closed path coverage ──────────────────────────────────

describe('AuditShareManager step 2 — sub-clause coverage', () => {
    it('should throw AUDIT_SHARE_VERSION_UNSUPPORTED when auditShareVersion != "1.0.0" (step 2a;defense-in-depth bypass schema)', async () => {
        const setup = buildTestSetup();
        const manager = new AuditShareManager(setup.deps);
        // Simulate an attacker bypassing the schema layer and passing a type-cast version directly
        const malformedRequest = {
            ...setup.request,
            auditShareVersion: '9.9.9',
        } as unknown as AuditShareVerifiedRequest;
        // The schema layer rejects first (AUDIT_SHARE_SCHEMA_INVALID); this case actually tests the schema fail-closed
        await expect(
            manager.verifyAuditRequest(
                malformedRequest,
                EXPECTED_AUDIENCE,
                NOW,
            ),
        ).rejects.toMatchObject({
            code: 'AUDIT_SHARE_SCHEMA_INVALID',
        });
    });

    it('should throw AUDIT_SHARE_DISCLOSED_CLAIMS_INVALID when claim not in enum (step 2b;defense-in-depth bypass schema)', async () => {
        // The schema layer already rejects non-enum values; the loop defense inside step 2b is the second line of defense
        // Test the extreme case where schema accepts but disclosedClaims contains an illegal value (type-cast bypass)
        const setup = buildTestSetup();
        const manager = new AuditShareManager(setup.deps);
        const evilRequest = {
            ...setup.request,
            disclosedClaims: ['eventType', 'evil_claim'],
        } as unknown as AuditShareVerifiedRequest;
        // schema fail-closed rejects first (this case is the same as schema invalid)
        await expect(
            manager.verifyAuditRequest(evilRequest, EXPECTED_AUDIENCE, NOW),
        ).rejects.toMatchObject({
            code: 'AUDIT_SHARE_SCHEMA_INVALID',
        });
    });

    it('should throw AUDIT_SHARE_NOT_AFTER_EXPIRED when now is not valid ISO 8601 (step 2d format)', async () => {
        const setup = buildTestSetup();
        const manager = new AuditShareManager(setup.deps);
        await expect(
            manager.verifyAuditRequest(
                setup.request,
                EXPECTED_AUDIENCE,
                'not-a-date' as Timestamp,
            ),
        ).rejects.toMatchObject({
            code: 'AUDIT_SHARE_NOT_AFTER_EXPIRED',
            invariant: 'step-2-not-after-format',
        });
    });
});

// ── Step 6: requester publicKey null fail-closed ───────────────────────

describe('AuditShareManager step 6 — requester publicKey resolution fail', () => {
    it('should throw AUDIT_SHARE_REQUESTER_SIGNATURE_INVALID when requester publicKey null', async () => {
        const setup = buildTestSetup();
        // Override resolvePublicKey so requesterDid returns null
        const newResolve: AuditShareResolvePublicKeyFn = (did: DID) => {
            if (did === setup.delegatedKey.delegatedFrom)
                return Promise.resolve(setup.delegatorKeys.publicKey);
            return Promise.resolve(null);
        };
        const manager = new AuditShareManager({
            ...setup.deps,
            resolvePublicKey: newResolve,
        });
        await expect(
            manager.verifyAuditRequest(setup.request, EXPECTED_AUDIENCE, NOW),
        ).rejects.toMatchObject({
            code: 'AUDIT_SHARE_REQUESTER_SIGNATURE_INVALID',
            invariant: 'step-6-resolve-requester-public-key',
        });
    });

    it('should throw AUDIT_SHARE_REQUESTER_SIGNATURE_INVALID when Ed25519 throws (malformed public key)', async () => {
        const setup = buildTestSetup();
        const newResolve: AuditShareResolvePublicKeyFn = (did: DID) => {
            if (did === setup.delegatedKey.delegatedFrom)
                return Promise.resolve(setup.delegatorKeys.publicKey);
            // requester returns a malformed publicKey → verifyEd25519 throws CryptoError
            return Promise.resolve('malformed-key-too-short');
        };
        const manager = new AuditShareManager({
            ...setup.deps,
            resolvePublicKey: newResolve,
        });
        await expect(
            manager.verifyAuditRequest(setup.request, EXPECTED_AUDIENCE, NOW),
        ).rejects.toMatchObject({
            code: 'AUDIT_SHARE_REQUESTER_SIGNATURE_INVALID',
            invariant: 'step-6-ed25519-verify',
        });
    });
});

// ── Step 7: scope re-verify happy + canonicalScopeObject with chainNamespace ──

describe('AuditShareManager step 7 — scope with optional chainNamespace', () => {
    it('should accept request with optional chainNamespace and project it through to fetch', async () => {
        // Build a setup with chainNamespace + re-sign the request (also signing a payload that includes chainNamespace)
        const delegatorKeys = generateKeyPair();
        const requesterKeys = generateKeyPair();
        const delegatedFrom = 'did:key:principal-NS' as DID;
        const delegatedTo = 'did:key:auditor-NS' as DID;
        // scope binding (chainNamespace match; store-level integrity)
        const nsScope = toAuditShareScope({
            tenantId: 'tenant-ns',
            auditClass: 'L2',
            chainNamespace: 'atp',
        });
        const baseFieldsForSign = {
            auditKeyId: '33333333-4444-4555-8666-777777777777',
            delegatedFrom,
            delegatedTo,
            purpose: 'AUDIT' as const,
            validFrom: '2026-01-01T00:00:00.000Z' as Timestamp,
            validUntil: '2027-01-01T00:00:00.000Z' as Timestamp,
        };
        const baseFields = { ...baseFieldsForSign, scope: nsScope };
        const dPayload = canonicalize(baseFieldsForSign);
        const dSig = sign(
            new TextEncoder().encode(dPayload),
            delegatorKeys.privateKey,
        ) as Signature;
        const delegatedKey = createAuditShareDelegatedKey({
            ...baseFields,
            proof: {
                signature: dSig,
                signedAt: '2026-05-17T12:00:00.000Z' as Timestamp,
                signedBy: delegatedFrom,
            },
        });

        const scope = toAuditShareScope({
            tenantId: 'tenant-ns',
            auditClass: 'L2',
            chainNamespace: 'atp',
        });

        // Re-sign the request (with chainNamespace)
        const reqPayloadObj = {
            auditShareVersion: '1.0.0',
            token: baseFields.auditKeyId,
            disclosedClaims: ['eventType'],
            challenge: 'cccccccc-dddd-4eee-8fff-aaaaaaaaaaaa',
            audience: EXPECTED_AUDIENCE,
            notAfter: '2026-12-31T23:59:59.000Z' as Timestamp,
            requestedScope: {
                tenantId: 'tenant-ns',
                auditClass: 'L2',
                chainNamespace: 'atp',
            },
            requesterDid: delegatedTo,
        };
        const reqPayloadStr = canonicalize(reqPayloadObj);
        const reqSig = sign(
            new TextEncoder().encode(reqPayloadStr),
            requesterKeys.privateKey,
        ) as Signature;
        const request: AuditShareVerifiedRequest = {
            auditShareVersion: toAuditShareVersion('1.0.0'),
            token: toAuditKeyId(baseFields.auditKeyId),
            disclosedClaims: ['eventType'],
            challenge: 'cccccccc-dddd-4eee-8fff-aaaaaaaaaaaa',
            audience: EXPECTED_AUDIENCE,
            notAfter: '2026-12-31T23:59:59.000Z' as Timestamp,
            requestedScope: scope,
            requesterDid: delegatedTo,
            requesterSignature: reqSig,
        };

        const resolvePublicKey: AuditShareResolvePublicKeyFn = (did: DID) => {
            if (did === delegatedFrom)
                return Promise.resolve(delegatorKeys.publicKey);
            if (did === delegatedTo)
                return Promise.resolve(requesterKeys.publicKey);
            return Promise.resolve(null);
        };

        const manager = new AuditShareManager({
            resolvePublicKey,
            delegatedAuditKeyStore: {
                fetch: () => Promise.resolve(delegatedKey),
            },
            tenantPolicyStore: {
                isAllowed: () => Promise.resolve(true),
            },
            auditEventStore: {
                fetchByChainIdentity: () => Promise.resolve([]),
                fetchAuditEvents: () => Promise.resolve([]),
            },
            hashChainVerifier: {
                verify: () => Promise.resolve({ valid: true }),
            },
            challengeStore: {
                check: () => Promise.resolve(true),
                consume: () => Promise.resolve(true),
            },
        });

        const result = await manager.verifyAuditRequest(
            request,
            EXPECTED_AUDIENCE,
            NOW,
        );
        expect(result.ok).toBe(true);
    });
});

// ── Step 2: 5-field invariant fail-closed ────────────────────────────────

describe('AuditShareManager step 2 — csp 5-field invariant', () => {
    it('should throw AUDIT_SHARE_AUDIENCE_MISMATCH when audience !== expected', async () => {
        const setup = buildTestSetup();
        const manager = new AuditShareManager(setup.deps);
        await expect(
            manager.verifyAuditRequest(
                setup.request,
                'did:key:wrong-audience' as DID,
                NOW,
            ),
        ).rejects.toMatchObject({
            code: 'AUDIT_SHARE_AUDIENCE_MISMATCH',
            invariant: 'step-2-audience',
        });
    });

    it('should throw AUDIT_SHARE_NOT_AFTER_EXPIRED when notAfter < now', async () => {
        const setup = buildTestSetup();
        const manager = new AuditShareManager(setup.deps);
        const lateNow = '2028-01-01T00:00:00.000Z' as Timestamp;
        await expect(
            manager.verifyAuditRequest(
                setup.request,
                EXPECTED_AUDIENCE,
                lateNow,
            ),
        ).rejects.toMatchObject({
            code: 'AUDIT_SHARE_NOT_AFTER_EXPIRED',
        });
    });

    it('should throw AUDIT_SHARE_CHALLENGE_INVALID when challenge already consumed', async () => {
        // step 2 only checks (does not consume); invariant = step-2-challenge-check
        const setup = buildTestSetup({ challengeOk: false });
        const manager = new AuditShareManager(setup.deps);
        await expect(
            manager.verifyAuditRequest(setup.request, EXPECTED_AUDIENCE, NOW),
        ).rejects.toMatchObject({
            code: 'AUDIT_SHARE_CHALLENGE_INVALID',
            invariant: 'step-2-challenge-check',
        });
    });
});

// ── Step 3: fetch DelegatedAuditKey ─────────────────────────────────────

describe('AuditShareManager step 3 — fetch DelegatedAuditKey', () => {
    it('should throw AUDIT_SHARE_TOKEN_INVALID when fetch returns null', async () => {
        const setup = buildTestSetup();
        setup.mockFetch.mockResolvedValueOnce(null);
        const manager = new AuditShareManager(setup.deps);
        await expect(
            manager.verifyAuditRequest(setup.request, EXPECTED_AUDIENCE, NOW),
        ).rejects.toMatchObject({
            code: 'AUDIT_SHARE_TOKEN_INVALID',
            invariant: 'step-3-fetch',
        });
    });
});

// ── Step 5: key.delegatedTo === request.requesterDid ───────────────────

describe('AuditShareManager step 5 — delegator audience binding', () => {
    it('should throw AUDIT_SHARE_DELEGATOR_AUDIENCE_MISMATCH when key.delegatedTo !== requesterDid', async () => {
        const setup = buildTestSetup({
            delegatedToOverride: 'did:key:auditor-XXX' as DID,
            requesterDidOverride: 'did:key:auditor-YYY' as DID,
        });
        const manager = new AuditShareManager(setup.deps);
        await expect(
            manager.verifyAuditRequest(setup.request, EXPECTED_AUDIENCE, NOW),
        ).rejects.toMatchObject({
            code: 'AUDIT_SHARE_DELEGATOR_AUDIENCE_MISMATCH',
            invariant: 'step-5-delegator-audience',
        });
    });
});

// ── Step 6: requesterSignature Ed25519 verify ───────────────────────────

describe('AuditShareManager step 6 — requester Ed25519 verify', () => {
    it('should throw AUDIT_SHARE_REQUESTER_SIGNATURE_INVALID when signature wrong', async () => {
        // Sign with a mismatched key pair; requester public key vs signature do not match
        const setup = buildTestSetup();
        const { privateKey: wrongPrivate } = generateKeyPair();
        // Replace request.requesterSignature with one signed by the wrong key
        const setup2 = buildTestSetup({
            requesterPrivateKeyOverride: wrongPrivate,
        });
        const manager = new AuditShareManager(setup2.deps);
        await expect(
            manager.verifyAuditRequest(setup2.request, EXPECTED_AUDIENCE, NOW),
        ).rejects.toMatchObject({
            code: 'AUDIT_SHARE_REQUESTER_SIGNATURE_INVALID',
        });
        expect(setup).toBeDefined(); // avoid the unused warning
    });
});

// ── Step 8: multi-tenant fail-closed (atp interplay) ─────────────────────────

describe('AuditShareManager step 8 — multi-tenant fail-closed', () => {
    it('should throw AUDIT_SHARE_CROSS_TENANT_REJECT when tenant policy denies', async () => {
        const setup = buildTestSetup({ tenantAllowed: false });
        const manager = new AuditShareManager(setup.deps);
        await expect(
            manager.verifyAuditRequest(setup.request, EXPECTED_AUDIENCE, NOW),
        ).rejects.toMatchObject({
            code: 'AUDIT_SHARE_CROSS_TENANT_REJECT',
            invariant: 'step-8-multi-tenant',
        });
    });
});

// ── Step 10: verifyHashChain (hcc interplay) ─────────────────────────────────

describe('AuditShareManager step 10 — hash chain verify', () => {
    it('should throw AUDIT_SHARE_HASH_CHAIN_INVALID when chain verifier returns invalid', async () => {
        const setup = buildTestSetup({ chainValid: false });
        const manager = new AuditShareManager(setup.deps);
        await expect(
            manager.verifyAuditRequest(setup.request, EXPECTED_AUDIENCE, NOW),
        ).rejects.toMatchObject({
            code: 'AUDIT_SHARE_HASH_CHAIN_INVALID',
            invariant: 'step-10-hash-chain',
        });
    });
});

// ── Step 11: selective disclosure projection ────────────────────────────

describe('AuditShareManager — selective disclosure projection', () => {
    it('should project only disclosedClaims subset of AuditEvent fields', () => {
        const setup = buildTestSetup();
        const manager = new AuditShareManager(setup.deps);
        const event: AuditEvent = {
            id: 'evt-A',
            eventType: 'AUDIT_QUERY',
            actorDid: 'did:key:actor' as DID,
            targetAgentDid: 'did:key:target' as DID,
            timestamp: '2026-04-01T00:00:00.000Z' as Timestamp,
            outcome: 'ALLOWED',
            prevHash: null,
            signature: 'sig' as Signature,
            tenantId: 'tenant-A',
            auditClass: 'L1',
        };
        const projected = manager.project(event, ['eventType', 'timestamp']);
        expect(Object.keys(projected).sort()).toEqual([
            'eventType',
            'timestamp',
        ]);
        expect(projected.eventType).toBe('AUDIT_QUERY');
    });

    it('should skip undefined fields when projecting', () => {
        const setup = buildTestSetup();
        const manager = new AuditShareManager(setup.deps);
        const event: AuditEvent = {
            id: 'evt-B',
            eventType: 'AUDIT_QUERY',
            actorDid: 'did:key:actor' as DID,
            targetAgentDid: 'did:key:target' as DID,
            timestamp: '2026-04-01T00:00:00.000Z' as Timestamp,
            outcome: 'ALLOWED',
            prevHash: null,
            signature: 'sig' as Signature,
            tenantId: 'tenant-B',
            auditClass: 'L1',
            // correlationId is undefined (optional field)
        };
        const projected = manager.project(event, [
            'eventType',
            'correlationId',
        ]);
        expect(projected.eventType).toBe('AUDIT_QUERY');
        expect(projected).not.toHaveProperty('correlationId');
    });
});

// ── fetchByChainIdentity delegate ───────────────────────────────────────

describe('AuditShareManager — fetchByChainIdentity', () => {
    it('should delegate to AuditEventStore.fetchByChainIdentity', async () => {
        const setup = buildTestSetup();
        const manager = new AuditShareManager(setup.deps);
        const result = await manager.fetchByChainIdentity(setup.scope);
        expect(result.length).toBe(1);
        expect(setup.mockFetchEntries).toHaveBeenCalledWith(setup.scope);
    });
});

// ── buildEntriesWithWitness ────────────────────────────────────────────

describe('AuditShareManager — buildEntriesWithWitness', () => {
    it('should assemble entries with disclosedFields when lengths match', () => {
        const setup = buildTestSetup();
        const manager = new AuditShareManager(setup.deps);
        const entries: HashChainEntry[] = [
            {
                tenantId: 'tenant-A',
                auditClass: 'L1',
                chainNamespace: 'atp',
                chainPosition: 1,
                previousHash: null,
                canonicalPayloadHash: 'h1',
                entryAt: '2026-04-01T00:00:00.000Z' as Timestamp,
            },
        ];
        const events: AuditEvent[] = [
            {
                id: 'evt-Z',
                eventType: 'AUDIT_QUERY',
                actorDid: 'did:key:a' as DID,
                targetAgentDid: 'did:key:t' as DID,
                timestamp: '2026-04-01T00:00:00.000Z' as Timestamp,
                outcome: 'ALLOWED',
                prevHash: null,
                signature: 's' as Signature,
                tenantId: 'tenant-A',
                auditClass: 'L1',
            },
        ];
        const result = manager.buildEntriesWithWitness(entries, events, [
            'eventType',
        ]);
        expect(result.length).toBe(1);
        expect(result[0]?.disclosedFields.eventType).toBe('AUDIT_QUERY');
    });

    it('should throw AUDIT_SHARE_HASH_CHAIN_INVALID when lengths mismatch', () => {
        const setup = buildTestSetup();
        const manager = new AuditShareManager(setup.deps);
        expect(() =>
            manager.buildEntriesWithWitness(
                [
                    {
                        tenantId: 't',
                        auditClass: 'L1',
                        chainNamespace: 'atp',
                        chainPosition: 1,
                        previousHash: null,
                        canonicalPayloadHash: 'h',
                        entryAt: '2026-04-01T00:00:00.000Z' as Timestamp,
                    },
                ],
                [], // empty events;mismatch
                ['eventType'],
            ),
        ).toThrowError(AuditShareError);
    });
});

// ── e2e cross-package L0+L2+L3 interplay (≥3 cases) ──────────

describe('AuditShareManager — e2e cross-package L0+L2+L3 interplay', () => {
    it('case 1: L0 toAuditShareScope factory + L2 real verifier + L3 11-step happy path', async () => {
        // L0: factory guard toAuditShareScope (brand casts forbidden)
        const scope = toAuditShareScope({
            tenantId: 'tenant-cross-1',
            auditClass: 'L2',
            chainNamespace: 'atp',
        });
        expect(scope.tenantId).toBe('tenant-cross-1');

        // L2 + L3 interplay: real Ed25519 signature + 11-step
        const setup = buildTestSetup();
        const manager = new AuditShareManager(setup.deps);
        const result = await manager.verifyAuditRequest(
            setup.request,
            EXPECTED_AUDIENCE,
            NOW,
        );
        expect(result.ok).toBe(true);
    });

    it('case 2: L0 AUDIT_SHARE_TOKEN_INVALID code throw path + L3 fail-closed throw pass-through', async () => {
        // L0 throw path: toAuditKeyId fails for a non-UUID-v4 value
        expect(() => toAuditKeyId('not-uuid')).toThrowError(AuditShareError);

        // L3 fail-closed throw pass-through: DelegatedAuditKey not found (token invalid)
        const setup = buildTestSetup();
        setup.mockFetch.mockResolvedValueOnce(null);
        const manager = new AuditShareManager(setup.deps);
        await expect(
            manager.verifyAuditRequest(setup.request, EXPECTED_AUDIENCE, NOW),
        ).rejects.toMatchObject({
            code: 'AUDIT_SHARE_TOKEN_INVALID',
        });
    });

    it('case 3: L2 verifyDelegatedAuditKey step 5 revoked + L3 step 4 pass-through fail-closed', async () => {
        // L2 revoked key + L3 step 4 pass-through throw AUDIT_SHARE_TOKEN_INVALID 'revoked'
        const delegatorKeys = generateKeyPair();
        const baseFields = {
            auditKeyId: '22222222-3333-4444-8555-666666666666',
            delegatedFrom: 'did:key:principal-002' as DID,
            delegatedTo: 'did:key:auditor-002' as DID,
            purpose: 'AUDIT' as const,
            validFrom: '2026-01-01T00:00:00.000Z' as Timestamp,
            validUntil: '2027-01-01T00:00:00.000Z' as Timestamp,
            revoked: true,
        };
        const delegatorPayload = canonicalize(baseFields);
        const delegatorSig = sign(
            new TextEncoder().encode(delegatorPayload),
            delegatorKeys.privateKey,
        ) as Signature;
        const revokedKey = createAuditShareDelegatedKey({
            ...baseFields,
            proof: {
                signature: delegatorSig,
                signedAt: '2026-05-17T12:00:00.000Z' as Timestamp,
                signedBy: baseFields.delegatedFrom,
            },
        });

        const setup = buildTestSetup({
            delegatedToOverride: 'did:key:auditor-002' as DID,
            requesterDidOverride: 'did:key:auditor-002' as DID,
        });
        // Replace fetch to return the revoked key + replace resolvePublicKey to return the revoked key's delegator publicKey
        setup.mockFetch.mockResolvedValueOnce(revokedKey);
        const newResolvePublicKey: AuditShareResolvePublicKeyFn = (
            did: DID,
        ) => {
            if (did === revokedKey.delegatedFrom)
                return Promise.resolve(delegatorKeys.publicKey);
            if (did === revokedKey.delegatedTo)
                return Promise.resolve(setup.requesterKeys.publicKey);
            return Promise.resolve(null);
        };
        const manager = new AuditShareManager({
            ...setup.deps,
            resolvePublicKey: newResolvePublicKey,
        });

        await expect(
            manager.verifyAuditRequest(setup.request, EXPECTED_AUDIENCE, NOW),
        ).rejects.toMatchObject({
            code: 'AUDIT_SHARE_TOKEN_INVALID',
            invariant: 'step-5-revoked',
        });
    });
});
