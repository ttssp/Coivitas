import { describe, expect, it, vi } from 'vitest';
import { randomUUID } from 'node:crypto';

import { generateKeyPair, sign } from '@coivitas/crypto';
import {
    createCapabilityTokenPayload,
    delegateCapabilityToken,
    didKeyFromPublicKey,
    issueCapabilityToken,
    validateDelegationChain,
} from '@coivitas/identity';
import type { CapabilityToken, DID, Timestamp } from '@coivitas/types';
import { SPEC_VERSION_0_2_0 } from '@coivitas/types';

import { RuntimeGuard } from '../runtime-guard.js';
import { ScopeEvaluator } from '../scope-evaluator.js';

function createToken(action: string, max = 500) {
    const issuer = generateKeyPair();
    const issuerDid = didKeyFromPublicKey(Buffer.from(issuer.publicKey, 'hex'));
    const agentDid =
        'did:agent:00112233445566778899aabbccddeeff00112233' as DID;

    return {
        token: issueCapabilityToken({
            issuerDid,
            issuedTo: agentDid,
            capabilities: [
                {
                    action,
                    scope: {
                        type: 'numeric_limit',
                        field: 'amount',
                        max,
                    },
                },
            ],
            expiresAt: '2026-04-22T10:00:00.000Z' as Timestamp,
            revocationUrl: 'https://revocation.example.com/v1/{id}',
            issuerPrivateKey: issuer.privateKey,
            issuedAt: '2026-04-21T10:00:00.000Z' as Timestamp,
        }),
        agentDid,
    };
}

describe('RuntimeGuard', () => {
    it('returns the documented outcomes for missing, mismatched, scoped, revoked, and allowed tokens', async () => {
        const emptyGuard = new RuntimeGuard({
            tokenStore: {
                getTokensForAgent() {
                    return Promise.resolve([]);
                },
            },
            revocationChecker() {
                return Promise.resolve(false);
            },
            now: () => '2026-04-21T10:05:00.000Z' as Timestamp,
        });

        await expect(
            emptyGuard.check(
                'INQUIRY',
                { amount: 100 },
                'did:agent:00112233445566778899aabbccddeeff00112233' as DID,
            ),
        ).resolves.toEqual({
            allowed: false,
            reason: 'no tokens found',
        });

        const mismatch = createToken('QUOTE');
        const mismatchGuard = new RuntimeGuard({
            tokenStore: {
                getTokensForAgent() {
                    return Promise.resolve([mismatch.token]);
                },
            },
            revocationChecker() {
                return Promise.resolve(false);
            },
            now: () => '2026-04-21T10:05:00.000Z' as Timestamp,
        });

        await expect(
            mismatchGuard.check('INQUIRY', { amount: 100 }, mismatch.agentDid),
        ).resolves.toEqual({
            allowed: false,
            reason: 'no matching capability',
        });

        const scoped = createToken('INQUIRY');
        const scopedGuard = new RuntimeGuard({
            tokenStore: {
                getTokensForAgent() {
                    return Promise.resolve([scoped.token]);
                },
            },
            revocationChecker() {
                return Promise.resolve(false);
            },
            now: () => '2026-04-21T10:05:00.000Z' as Timestamp,
        });

        await expect(
            scopedGuard.check('INQUIRY', { amount: 700 }, scoped.agentDid),
        ).resolves.toEqual({
            allowed: false,
            reason: 'scope check failed: amount exceeds max 500',
        });

        const revokedGuard = new RuntimeGuard({
            tokenStore: {
                getTokensForAgent() {
                    return Promise.resolve([scoped.token]);
                },
            },
            revocationChecker() {
                return Promise.resolve(true);
            },
            now: () => '2026-04-21T10:05:00.000Z' as Timestamp,
        });

        await expect(
            revokedGuard.check('INQUIRY', { amount: 100 }, scoped.agentDid),
        ).resolves.toEqual({
            allowed: false,
            reason: 'capability revoked',
        });

        await expect(
            scopedGuard.check('INQUIRY', { amount: 100 }, scoped.agentDid),
        ).resolves.toEqual({
            allowed: true,
            tokenId: scoped.token.id,
            delegationDepth: 0,
        });
    });

    it('treats multiple matching capabilities on one token as AND semantics', async () => {
        const issuer = generateKeyPair();
        const issuerDid = didKeyFromPublicKey(
            Buffer.from(issuer.publicKey, 'hex'),
        );
        const agentDid =
            'did:agent:00112233445566778899aabbccddeeff00112233' as DID;
        const token = issueCapabilityToken({
            issuerDid,
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
                {
                    action: 'INQUIRY',
                    scope: {
                        type: 'numeric_limit',
                        field: 'amount',
                        max: 500,
                    },
                },
            ],
            expiresAt: '2026-04-22T10:00:00.000Z' as Timestamp,
            revocationUrl: 'https://revocation.example.com/v1/{id}',
            issuerPrivateKey: issuer.privateKey,
            issuedAt: '2026-04-21T10:00:00.000Z' as Timestamp,
        });

        const guard = new RuntimeGuard({
            tokenStore: {
                getTokensForAgent() {
                    return Promise.resolve([token]);
                },
            },
            revocationChecker() {
                return Promise.resolve(false);
            },
            now: () => '2026-04-21T10:05:00.000Z' as Timestamp,
        });

        await expect(
            guard.check(
                'INQUIRY',
                { recipient: 'supplier-a', amount: 500 },
                agentDid,
            ),
        ).resolves.toEqual({
            allowed: true,
            tokenId: token.id,
            delegationDepth: 0,
        });

        await expect(
            guard.check(
                'INQUIRY',
                { recipient: 'supplier-b', amount: 500 },
                agentDid,
            ),
        ).resolves.toEqual({
            allowed: false,
            reason: 'scope check failed: recipient is not in the allowlist',
        });
    });

    // ── Authorization closure: requestedTokenId filtering ─────
    it('should authorize only against the requested tokenId when supplied', async () => {
        // Construct two Tokens that both pass the action/scope checks, simulating a token-confusion attack:
        // the caller declares the "narrow" Token in the envelope; if RuntimeGuard scans the pool and takes the first usable one,
        // it may pick the "broad" Token, bypassing the envelope binding.
        const narrow = createToken('INQUIRY', 100);
        const broad = createToken('INQUIRY', 10_000);

        const guard = new RuntimeGuard({
            tokenStore: {
                getTokensForAgent() {
                    return Promise.resolve([narrow.token, broad.token]);
                },
            },
            revocationChecker() {
                return Promise.resolve(false);
            },
            now: () => '2026-04-21T10:05:00.000Z' as Timestamp,
        });

        // A request with amount=500 exceeds the limit under the narrow Token but passes under the broad Token.
        // Without requestedTokenId: scanning the pool, the narrow Token fails scope first, then the broad Token passes → allowed.
        await expect(
            guard.check('INQUIRY', { amount: 500 }, narrow.agentDid),
        ).resolves.toMatchObject({
            allowed: true,
            tokenId: broad.token.id,
        });

        // With requestedTokenId=narrow: only the narrow Token participates in evaluation, scope exceeded → denied.
        await expect(
            guard.check(
                'INQUIRY',
                { amount: 500 },
                narrow.agentDid,
                narrow.token.id,
            ),
        ).resolves.toMatchObject({
            allowed: false,
            reason: 'scope check failed: amount exceeds max 100',
        });

        // The same amount falls within the narrow Token's range: requestedTokenId=narrow allows it.
        await expect(
            guard.check(
                'INQUIRY',
                { amount: 50 },
                narrow.agentDid,
                narrow.token.id,
            ),
        ).resolves.toEqual({
            allowed: true,
            tokenId: narrow.token.id,
            delegationDepth: 0,
        });
    });

    it('should reject with requested-token-not-found reason when tokenId is not in the agent pool', async () => {
        const token = createToken('INQUIRY');
        const guard = new RuntimeGuard({
            tokenStore: {
                getTokensForAgent() {
                    return Promise.resolve([token.token]);
                },
            },
            revocationChecker() {
                return Promise.resolve(false);
            },
            now: () => '2026-04-21T10:05:00.000Z' as Timestamp,
        });

        await expect(
            guard.check(
                'INQUIRY',
                { amount: 100 },
                token.agentDid,
                'urn:cap:unknown-token-id',
            ),
        ).resolves.toEqual({
            allowed: false,
            reason: 'requested token not found for agent',
        });
    });

    // ── The injected clock must be passed through to evaluateAll ─────────────────────────
    it('should forward injected clock (dependencies.now) to temporal_scope evaluation', async () => {
        // Construct a temporal_scope token that is valid only within FROZEN_TIME
        const issuer = generateKeyPair();
        const issuerDid = didKeyFromPublicKey(
            Buffer.from(issuer.publicKey, 'hex'),
        );
        const agentDid =
            'did:agent:aabbccddeeff0011223344556677889900aabbcc' as DID;

        // The token itself is valid in 2026-04-21T10:00–11:00.
        // Note: temporal_scope is a 0.2.0-only scope; a 0.1.0 token containing it would be
        // blocked by the token-verifier's 0.1.0 gate, so we manually construct a 0.2.0
        // signed token to bypass issueCapabilityToken's SPEC_VERSION=0.1.0 default.
        const FROZEN_TIME = '2026-04-21T10:30:00.000Z' as Timestamp;
        const tokenPayload = {
            id: `urn:cap:${randomUUID()}`,
            specVersion: SPEC_VERSION_0_2_0,
            issuerDid,
            principalDid: issuerDid,
            issuedTo: agentDid,
            issuedAt: '2026-04-21T09:00:00.000Z' as Timestamp,
            expiresAt: '2026-04-21T12:00:00.000Z' as Timestamp,
            capabilities: [
                {
                    action: 'INQUIRY',
                    scope: {
                        type: 'temporal_scope' as const,
                        notBefore: '2026-04-21T10:00:00.000Z' as Timestamp,
                        notAfter: '2026-04-21T11:00:00.000Z' as Timestamp,
                    },
                },
            ],
            revocationUrl: 'https://revocation.example.com/v1/{id}',
        };
        const signatureValue = sign(
            createCapabilityTokenPayload(tokenPayload),
            issuer.privateKey,
        );
        const token: CapabilityToken = {
            ...tokenPayload,
            proof: {
                type: 'Ed25519Signature2026',
                created: tokenPayload.issuedAt,
                verificationMethod: `${issuerDid}#key-1`,
                value: signatureValue as CapabilityToken['proof']['value'],
            },
        };

        // evaluateAll spy: verify the now argument is passed in correctly
        const spyEvaluator = new ScopeEvaluator();
        const evaluateAllSpy = vi
            .spyOn(spyEvaluator, 'evaluateAll')
            .mockReturnValue({ allowed: true });

        const guard = new RuntimeGuard({
            tokenStore: {
                getTokensForAgent() {
                    return Promise.resolve([token]);
                },
            },
            revocationChecker() {
                return Promise.resolve(false);
            },
            now: () => FROZEN_TIME,
            scopeEvaluator: spyEvaluator,
        });

        await guard.check('INQUIRY', {}, agentDid);

        // Verify that when evaluateAll is called, the now argument equals the Date corresponding to dependencies.now()
        expect(evaluateAllSpy).toHaveBeenCalledOnce();
        const callArgs = evaluateAllSpy.mock.calls[0];
        // callArgs[2] is now: Date
        expect(callArgs[2]).toBeInstanceOf(Date);
        expect((callArgs[2] as Date).toISOString()).toBe(FROZEN_TIME);
    });

    // ─── A recipient-local delegated token must be able to pass authorization ─
    it('should authorize delegated recipient token via validateDelegationChain', async () => {
        // Scenario: the recipient agent holds a delegated token (not a root); the previous version of
        // RuntimeGuard used synchronous verifyCapabilityToken and fail-closed directly when delegationChain
        // was non-empty → the recipient could never pass step4. After the fix: when chain is non-empty,
        // it is routed to delegationChainValidator.
        const agentDid =
            'did:agent:aabbccddeeff0011223344556677889900aabbcc' as DID;

        // Construct a minimal delegated token shell (the chain validator is a mock and does not check contents)
        const issuer = generateKeyPair();
        const issuerDid = didKeyFromPublicKey(
            Buffer.from(issuer.publicKey, 'hex'),
        );
        const delegatorKeyPair = generateKeyPair();
        const delegatorDid =
            'did:agent:11223344556677889900aabbccddeeff11223344' as DID;
        const nowTs = '2026-04-21T10:05:00.000Z' as Timestamp;

        const tokenPayload = {
            id: `urn:cap:${randomUUID()}`,
            specVersion: SPEC_VERSION_0_2_0,
            issuerDid,
            principalDid: issuerDid,
            issuedTo: agentDid,
            issuedAt: '2026-04-21T10:00:00.000Z' as Timestamp,
            expiresAt: '2026-04-21T11:00:00.000Z' as Timestamp,
            capabilities: [
                {
                    action: 'INQUIRY',
                    scope: {
                        type: 'numeric_limit' as const,
                        field: 'amount',
                        max: 500,
                    },
                },
            ],
            revocationUrl: 'https://revocation.example.com/v1/{id}',
            delegationChain: [
                {
                    parentTokenId: 'urn:cap:parent-stub',
                    delegatorDid,
                    delegateeDid: agentDid,
                    parentCapabilities: [
                        {
                            action: 'INQUIRY',
                            scope: {
                                type: 'numeric_limit' as const,
                                field: 'amount',
                                max: 500,
                            },
                        },
                    ],
                    parentExpiresAt: '2026-04-21T12:00:00.000Z' as Timestamp,
                    attenuatedCapabilities: [
                        {
                            action: 'INQUIRY',
                            scope: {
                                type: 'numeric_limit' as const,
                                field: 'amount',
                                max: 500,
                            },
                        },
                    ],
                    proof: {
                        type: 'Ed25519Signature2026' as const,
                        created: '2026-04-21T10:00:00.000Z',
                        verificationMethod: `${delegatorDid}#key-1`,
                        value: 'a'.repeat(128),
                    },
                },
            ],
        };
        const payloadBytes = createCapabilityTokenPayload(tokenPayload);
        const sigValue = sign(payloadBytes, delegatorKeyPair.privateKey);
        const token: CapabilityToken = {
            ...tokenPayload,
            proof: {
                type: 'Ed25519Signature2026',
                created: tokenPayload.issuedAt,
                verificationMethod: `${delegatorDid}#key-1`,
                value: sigValue as CapabilityToken['proof']['value'],
            },
        };

        const validator = vi.fn(async () =>
            Promise.resolve({ valid: true, depth: 1 as const }),
        );

        const guard = new RuntimeGuard({
            tokenStore: {
                getTokensForAgent: () => Promise.resolve([token]),
                // The delegated path requires getToken; the test fixture has only one token.
                getToken: (id: string) =>
                    Promise.resolve(id === token.id ? token : null),
            },
            revocationChecker: () => Promise.resolve(false),
            now: () => nowTs,
            delegationChainValidator: validator,
            resolvePublicKeys: () =>
                Promise.resolve({
                    current: delegatorKeyPair.publicKey,
                    rotationState: 'STABLE' as const,
                }),
        });

        const result = await guard.check('INQUIRY', { amount: 200 }, agentDid);
        expect(result).toEqual({
            allowed: true,
            tokenId: token.id,
            delegationDepth: 1,
        });
        expect(validator).toHaveBeenCalledTimes(1);
    });

    it('should skip delegated recipient token when outside issuedAt/expiresAt window (early-exit)', async () => {
        // Covers runtime-guard.ts's delegated-token time-window early-exit path
        // (a lightweight gate before the validator, avoiding sending expired/inactive tokens into the chain validator).
        const agentDid =
            'did:agent:00aabbccddeeff00112233445566778899aabbcc' as DID;
        const delegatorKeyPair = generateKeyPair();
        const delegatorDid =
            'did:agent:11aabbccddeeff00112233445566778899aabbcd' as DID;

        const token = {
            id: `urn:cap:${randomUUID()}`,
            specVersion: SPEC_VERSION_0_2_0,
            issuerDid: delegatorDid,
            principalDid: delegatorDid,
            issuedTo: agentDid,
            issuedAt: '2026-04-21T10:00:00.000Z',
            // expiresAt < now → token expired, should be skipped directly before the chain validator
            expiresAt: '2026-04-21T10:02:00.000Z',
            capabilities: [
                {
                    action: 'INQUIRY',
                    scope: {
                        type: 'numeric_limit' as const,
                        field: 'amount',
                        max: 500,
                    },
                },
            ],
            revocationUrl: 'https://revocation.example.com/v1/{id}',
            delegationChain: [
                {
                    parentTokenId: 'urn:cap:parent-stub',
                    delegatorDid,
                    delegateeDid: agentDid,
                    parentCapabilities: [],
                    parentExpiresAt: '2026-04-21T12:00:00.000Z',
                    attenuatedCapabilities: [],
                    proof: {
                        type: 'Ed25519Signature2026',
                        created: '2026-04-21T10:00:00.000Z',
                        verificationMethod: `${delegatorDid}#key-1`,
                        value: 'a'.repeat(128),
                    },
                },
            ],
            proof: {
                type: 'Ed25519Signature2026',
                created: '2026-04-21T10:00:00.000Z',
                verificationMethod: `${delegatorDid}#key-1`,
                value: 'a'.repeat(128),
            },
        } as unknown as CapabilityToken;

        const validator = vi.fn(() =>
            Promise.resolve({ valid: true as const, depth: 1 as const }),
        );

        const guard = new RuntimeGuard({
            tokenStore: {
                getTokensForAgent: () => Promise.resolve([token]),
                // The delegated path requires getToken
                getToken: (id: string) =>
                    Promise.resolve(id === token.id ? token : null),
            },
            revocationChecker: () => Promise.resolve(false),
            // now far past expiresAt → triggers the pre-validator early exit
            now: () => '2026-04-22T00:00:00.000Z' as Timestamp,
            delegationChainValidator: validator,
            resolvePublicKeys: () =>
                Promise.resolve({
                    current: delegatorKeyPair.publicKey,
                    rotationState: 'STABLE' as const,
                }),
        });

        await expect(
            guard.check('INQUIRY', { amount: 100 }, agentDid),
        ).resolves.toEqual({
            allowed: false,
            reason: 'no matching capability',
        });
        // Expired tokens should not waste chain validator resources
        expect(validator).not.toHaveBeenCalled();
    });

    it('should skip delegated recipient token when before issuedAt (early-exit)', async () => {
        // Covers runtime-guard.ts's `new Date(token.issuedAt).getTime() > nowMs` branch
        const agentDid =
            'did:agent:22aabbccddeeff00112233445566778899aabbce' as DID;
        const delegatorKeyPair = generateKeyPair();
        const delegatorDid =
            'did:agent:33aabbccddeeff00112233445566778899aabbcf' as DID;

        const token = {
            id: `urn:cap:${randomUUID()}`,
            specVersion: SPEC_VERSION_0_2_0,
            issuerDid: delegatorDid,
            principalDid: delegatorDid,
            issuedTo: agentDid,
            // issuedAt is in the future → now < issuedAt → token not yet active
            issuedAt: '2026-04-22T00:00:00.000Z',
            expiresAt: '2026-04-23T00:00:00.000Z',
            capabilities: [
                {
                    action: 'INQUIRY',
                    scope: {
                        type: 'numeric_limit' as const,
                        field: 'amount',
                        max: 500,
                    },
                },
            ],
            revocationUrl: 'https://revocation.example.com/v1/{id}',
            delegationChain: [
                {
                    parentTokenId: 'urn:cap:parent-stub',
                    delegatorDid,
                    delegateeDid: agentDid,
                    parentCapabilities: [],
                    parentExpiresAt: '2026-04-23T12:00:00.000Z',
                    attenuatedCapabilities: [],
                    proof: {
                        type: 'Ed25519Signature2026',
                        created: '2026-04-22T00:00:00.000Z',
                        verificationMethod: `${delegatorDid}#key-1`,
                        value: 'a'.repeat(128),
                    },
                },
            ],
            proof: {
                type: 'Ed25519Signature2026',
                created: '2026-04-22T00:00:00.000Z',
                verificationMethod: `${delegatorDid}#key-1`,
                value: 'a'.repeat(128),
            },
        } as unknown as CapabilityToken;

        const validator = vi.fn(() =>
            Promise.resolve({ valid: true as const, depth: 1 as const }),
        );

        const guard = new RuntimeGuard({
            tokenStore: {
                getTokensForAgent: () => Promise.resolve([token]),
                // The delegated path requires getToken
                getToken: (id: string) =>
                    Promise.resolve(id === token.id ? token : null),
            },
            revocationChecker: () => Promise.resolve(false),
            now: () => '2026-04-21T10:05:00.000Z' as Timestamp,
            delegationChainValidator: validator,
            resolvePublicKeys: () =>
                Promise.resolve({
                    current: delegatorKeyPair.publicKey,
                    rotationState: 'STABLE' as const,
                }),
        });

        await expect(
            guard.check('INQUIRY', { amount: 100 }, agentDid),
        ).resolves.toEqual({
            allowed: false,
            reason: 'no matching capability',
        });
        expect(validator).not.toHaveBeenCalled();
    });

    it('should skip delegated recipient token when delegation dependencies are missing (falls through)', async () => {
        // When delegationChainValidator or resolvePublicKey is missing, RuntimeGuard treats the
        // delegated token as "delegation semantics not enabled" and skips it (without wrongly rejecting other tokens).
        const agentDid =
            'did:agent:bbccddeeff0011223344556677889900aabbccdd' as DID;

        // Just a minimal shell, no real signature needed — the guard will not call verifyCapabilityToken
        // (because chain is non-empty) nor call the validator (dependencies not injected).
        const token = {
            id: 'urn:cap:delegated-no-deps',
            specVersion: SPEC_VERSION_0_2_0,
            issuerDid: 'did:key:zStub' as DID,
            principalDid: 'did:key:zStub' as DID,
            issuedTo: agentDid,
            issuedAt: '2026-04-21T10:00:00.000Z',
            expiresAt: '2026-04-21T11:00:00.000Z',
            capabilities: [
                {
                    action: 'INQUIRY',
                    scope: {
                        type: 'numeric_limit' as const,
                        field: 'amount',
                        max: 500,
                    },
                },
            ],
            revocationUrl: 'https://revocation.example.com/v1/{id}',
            delegationChain: [
                {
                    parentTokenId: 'urn:cap:p',
                    delegatorDid: 'did:agent:xxx' as DID,
                    delegateeDid: agentDid,
                    parentCapabilities: [],
                    parentExpiresAt: '2026-04-21T12:00:00.000Z',
                    attenuatedCapabilities: [],
                    proof: {
                        type: 'Ed25519Signature2026',
                        created: '2026-04-21T10:00:00.000Z',
                        verificationMethod: 'did:agent:xxx#key-1',
                        value: 'x'.repeat(128),
                    },
                },
            ],
            proof: {
                type: 'Ed25519Signature2026',
                created: '2026-04-21T10:00:00.000Z',
                verificationMethod: 'did:agent:xxx#key-1',
                value: 'x'.repeat(128),
            },
        } as unknown as CapabilityToken;

        const guard = new RuntimeGuard({
            tokenStore: {
                getTokensForAgent: () => Promise.resolve([token]),
            },
            revocationChecker: () => Promise.resolve(false),
            now: () => '2026-04-21T10:05:00.000Z' as Timestamp,
            // missing delegationChainValidator + resolvePublicKey
        });

        await expect(
            guard.check('INQUIRY', { amount: 100 }, agentDid),
        ).resolves.toEqual({
            allowed: false,
            reason: 'no matching capability',
        });
    });

    // ─── When tokenStore.getToken is missing, the delegated token must fail-closed skip ──
    it('should skip delegated token when tokenStore.getToken is missing (critical chain not bypassable)', async () => {
        // Attack surface: if RuntimeGuard allows validator/resolvePublicKey to be injected but
        // continues validating when tokenStore.getToken is missing, the validator's internal `if (resolveToken)`
        // block is skipped wholesale — including the 5b/5d/root-parent self-signature defense (against root-parent forgery attacks).
        // Fix: when getToken is missing, fail-closed skip, handled the same as a missing validator/resolvePublicKey.
        const agentDid =
            'did:agent:ccddeeff11223344556677889900aabbccddeeff' as DID;

        const token = {
            id: 'urn:cap:delegated-missing-gettoken',
            specVersion: SPEC_VERSION_0_2_0,
            issuerDid: 'did:key:zStub' as DID,
            principalDid: 'did:key:zStub' as DID,
            issuedTo: agentDid,
            issuedAt: '2026-04-21T10:00:00.000Z',
            expiresAt: '2026-04-21T11:00:00.000Z',
            capabilities: [
                {
                    action: 'INQUIRY',
                    scope: {
                        type: 'numeric_limit' as const,
                        field: 'amount',
                        max: 500,
                    },
                },
            ],
            revocationUrl: 'https://revocation.example.com/v1/{id}',
            delegationChain: [
                {
                    parentTokenId: 'urn:cap:p',
                    delegatorDid: 'did:agent:xxx' as DID,
                    delegateeDid: agentDid,
                    parentCapabilities: [],
                    parentExpiresAt: '2026-04-21T12:00:00.000Z',
                    attenuatedCapabilities: [],
                    proof: {
                        type: 'Ed25519Signature2026',
                        created: '2026-04-21T10:00:00.000Z',
                        verificationMethod: 'did:agent:xxx#key-1',
                        value: 'x'.repeat(128),
                    },
                },
            ],
            proof: {
                type: 'Ed25519Signature2026',
                created: '2026-04-21T10:00:00.000Z',
                verificationMethod: 'did:agent:xxx#key-1',
                value: 'x'.repeat(128),
            },
        } as unknown as CapabilityToken;

        // validator is a fake validator that would admit — if RuntimeGuard did not perform
        // the getToken gate check, it would send the token into this validator and admit it.
        // After the fix: when getToken is missing, skip directly, and this validator is never called.
        const validatorCalled = vi.fn(() =>
            Promise.resolve({ valid: true as const, depth: 1 as const }),
        );

        const guard = new RuntimeGuard({
            tokenStore: {
                getTokensForAgent: () => Promise.resolve([token]),
                // intentionally do not inject getToken
            },
            revocationChecker: () => Promise.resolve(false),
            now: () => '2026-04-21T10:05:00.000Z' as Timestamp,
            delegationChainValidator: validatorCalled,
            resolvePublicKeys: () =>
                Promise.resolve({
                    current: '00'.repeat(32),
                    rotationState: 'STABLE' as const,
                }),
        });

        const result = await guard.check('INQUIRY', { amount: 100 }, agentDid);
        // Key assertion 1: allowed=false (the token was skipped)
        expect(result.allowed).toBe(false);
        // Key assertion 2: the validator was **never** called — proving the gate check
        // takes effect when getToken is missing, rather than ignoring the validator result after the fact.
        expect(validatorCalled).not.toHaveBeenCalled();
    });

    it('should skip non-delegated token when verifyCapabilityToken rejects (direct-path fall-through)', async () => {
        // Covers runtime-guard.ts's `if (!verification.valid) continue`
        // branch (non-delegated path): when the token's time window is not satisfied, the direct-path verifyCapabilityToken
        // returns invalid, and the guard should silently skip the token (symmetric with the skip behavior in the delegated path).
        const { token, agentDid } = createToken('INQUIRY');

        const guard = new RuntimeGuard({
            tokenStore: {
                getTokensForAgent: () => Promise.resolve([token]),
            },
            revocationChecker: () => Promise.resolve(false),
            // token.expiresAt = '2026-04-22T10:00:00Z'; intentionally set now past expiry
            now: () => '2026-04-23T00:00:00.000Z' as Timestamp,
        });

        await expect(
            guard.check('INQUIRY', { amount: 100 }, agentDid),
        ).resolves.toEqual({
            allowed: false,
            reason: 'no matching capability',
        });
    });

    it('should skip delegated recipient token when delegationChainValidator rejects chain', async () => {
        // Covers runtime-guard.ts's `if (!chainResult.valid) continue` branch:
        // when the validator explicitly returns valid:false, the guard should treat the token as unusable,
        // falling to "no matching capability" (consistent with the semantics when other tokens are absent).
        const agentDid =
            'did:agent:ccddeeff00112233445566778899aabbccddeeff' as DID;
        const delegatorKeyPair = generateKeyPair();
        const delegatorDid =
            'did:agent:ddeeff00112233445566778899aabbccddeeff00' as DID;

        const token = {
            id: `urn:cap:${randomUUID()}`,
            specVersion: SPEC_VERSION_0_2_0,
            issuerDid: delegatorDid,
            principalDid: delegatorDid,
            issuedTo: agentDid,
            issuedAt: '2026-04-21T10:00:00.000Z',
            expiresAt: '2026-04-21T11:00:00.000Z',
            capabilities: [
                {
                    action: 'INQUIRY',
                    scope: {
                        type: 'numeric_limit' as const,
                        field: 'amount',
                        max: 500,
                    },
                },
            ],
            revocationUrl: 'https://revocation.example.com/v1/{id}',
            delegationChain: [
                {
                    parentTokenId: 'urn:cap:parent-stub',
                    delegatorDid,
                    delegateeDid: agentDid,
                    parentCapabilities: [],
                    parentExpiresAt: '2026-04-21T12:00:00.000Z',
                    attenuatedCapabilities: [],
                    proof: {
                        type: 'Ed25519Signature2026',
                        created: '2026-04-21T10:00:00.000Z',
                        verificationMethod: `${delegatorDid}#key-1`,
                        value: 'a'.repeat(128),
                    },
                },
            ],
            proof: {
                type: 'Ed25519Signature2026',
                created: '2026-04-21T10:00:00.000Z',
                verificationMethod: `${delegatorDid}#key-1`,
                value: 'a'.repeat(128),
            },
        } as unknown as CapabilityToken;

        const validator = vi.fn(async () =>
            Promise.resolve({
                valid: false as const,
                reason: 'chain signature invalid',
            }),
        );

        const guard = new RuntimeGuard({
            tokenStore: {
                getTokensForAgent: () => Promise.resolve([token]),
                // The delegated path requires getToken
                getToken: (id: string) =>
                    Promise.resolve(id === token.id ? token : null),
            },
            revocationChecker: () => Promise.resolve(false),
            now: () => '2026-04-21T10:05:00.000Z' as Timestamp,
            delegationChainValidator: validator,
            resolvePublicKeys: () =>
                Promise.resolve({
                    current: delegatorKeyPair.publicKey,
                    rotationState: 'STABLE' as const,
                }),
        });

        const result = await guard.check('INQUIRY', { amount: 200 }, agentDid);
        expect(result).toEqual({
            allowed: false,
            reason: 'no matching capability',
        });
        expect(validator).toHaveBeenCalledTimes(1);
    });

    it('should forward tokenStore.getToken as resolveToken port when validating delegation chain', async () => {
        // Covers runtime-guard.ts's `(id) => this.dependencies.tokenStore.getToken!(id)`
        // arrow function: when tokenStore exposes getToken, the guard must wrap it as resolveToken
        // and pass it to the validator; here we assert that when the validator is called, the 5th argument is a callable function,
        // and that calling it passes through to tokenStore.getToken.
        const agentDid =
            'did:agent:eeff00112233445566778899aabbccddeeff0011' as DID;
        const delegatorKeyPair = generateKeyPair();
        const delegatorDid =
            'did:agent:ff00112233445566778899aabbccddeeff001122' as DID;

        const token = {
            id: `urn:cap:${randomUUID()}`,
            specVersion: SPEC_VERSION_0_2_0,
            issuerDid: delegatorDid,
            principalDid: delegatorDid,
            issuedTo: agentDid,
            issuedAt: '2026-04-21T10:00:00.000Z',
            expiresAt: '2026-04-21T11:00:00.000Z',
            capabilities: [
                {
                    action: 'INQUIRY',
                    scope: {
                        type: 'numeric_limit' as const,
                        field: 'amount',
                        max: 500,
                    },
                },
            ],
            revocationUrl: 'https://revocation.example.com/v1/{id}',
            delegationChain: [
                {
                    parentTokenId: 'urn:cap:parent-stub',
                    delegatorDid,
                    delegateeDid: agentDid,
                    parentCapabilities: [],
                    parentExpiresAt: '2026-04-21T12:00:00.000Z',
                    attenuatedCapabilities: [],
                    proof: {
                        type: 'Ed25519Signature2026',
                        created: '2026-04-21T10:00:00.000Z',
                        verificationMethod: `${delegatorDid}#key-1`,
                        value: 'a'.repeat(128),
                    },
                },
            ],
            proof: {
                type: 'Ed25519Signature2026',
                created: '2026-04-21T10:00:00.000Z',
                verificationMethod: `${delegatorDid}#key-1`,
                value: 'a'.repeat(128),
            },
        } as unknown as CapabilityToken;

        const parentToken = {
            id: 'urn:cap:parent-lookup',
        } as unknown as CapabilityToken;
        const getToken = vi.fn(() => Promise.resolve(parentToken));
        const validator = vi.fn(() =>
            Promise.resolve({ valid: true as const, depth: 1 as const }),
        );

        const guard = new RuntimeGuard({
            tokenStore: {
                getTokensForAgent: () => Promise.resolve([token]),
                getToken,
            },
            revocationChecker: () => Promise.resolve(false),
            now: () => '2026-04-21T10:05:00.000Z' as Timestamp,
            delegationChainValidator: validator,
            resolvePublicKeys: () =>
                Promise.resolve({
                    current: delegatorKeyPair.publicKey,
                    rotationState: 'STABLE' as const,
                }),
        });

        const result = await guard.check('INQUIRY', { amount: 200 }, agentDid);
        expect(result).toEqual({
            allowed: true,
            tokenId: token.id,
            delegationDepth: 1,
        });

        // The validator is called once; the 5th argument should be the resolveToken wrapper function
        expect(validator).toHaveBeenCalledTimes(1);
        const forwardedResolveToken = validator.mock.calls[0]?.[4] as
            | ((id: string) => Promise<CapabilityToken | null>)
            | undefined;
        expect(typeof forwardedResolveToken).toBe('function');

        // Calling this resolveToken should pass through to tokenStore.getToken
        const resolved = await forwardedResolveToken!('urn:cap:parent-lookup');
        expect(resolved).toBe(parentToken);
        expect(getToken).toHaveBeenCalledWith('urn:cap:parent-lookup');
    });

    // ─── Integration regression using the real validateDelegationChain ───────────
    // The root cause of this defect is pushed down to the identity/validator fix; RuntimeGuard itself is unchanged.
    // This test injects the real validator + a vm-tampered token: it verifies that "the pushed-down fix indeed makes
    // RuntimeGuard reject tokens whose proof vm does not match delegatorDid" (chain validation step 8c).
    it('rejects delegated token when chain proof verificationMethod mismatches delegatorDid (validator fix propagates)', async () => {
        const issuer = generateKeyPair();
        const issuerDid = didKeyFromPublicKey(
            Buffer.from(issuer.publicKey, 'hex'),
        );
        const delegator = generateKeyPair();
        const delegatorDid =
            'did:agent:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' as DID;
        const recipient = generateKeyPair();
        const recipientDid =
            'did:agent:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' as DID;
        const attackerDid =
            'did:agent:cccccccccccccccccccccccccccccccccccccccc' as DID;

        const now = '2026-04-22T10:00:00.000Z' as Timestamp;
        const rootToken = issueCapabilityToken({
            issuerDid,
            issuedTo: delegatorDid,
            capabilities: [
                {
                    action: 'INQUIRY',
                    scope: {
                        type: 'numeric_limit',
                        field: 'amount',
                        max: 1000,
                    },
                },
            ],
            expiresAt: '2030-01-01T00:00:00.000Z' as Timestamp,
            revocationUrl: 'https://revocation.example.com/v1/{id}',
            issuerPrivateKey: issuer.privateKey,
            issuedAt: '2026-01-01T00:00:00.000Z' as Timestamp,
        });

        const delegated = delegateCapabilityToken({
            parentToken: rootToken,
            delegatorPrivateKey: delegator.privateKey,
            delegateeDid: recipientDid,
            attenuatedCapabilities: [
                {
                    action: 'INQUIRY',
                    scope: {
                        type: 'numeric_limit',
                        field: 'amount',
                        max: 500,
                    },
                },
            ],
            expiresAt: '2029-01-01T00:00:00.000Z' as Timestamp,
            revocationUrl: 'https://revocation.example.com/v1/{id}',
            issuedAt: '2026-04-01T00:00:00.000Z' as Timestamp,
        });

        // Attack: replace chain[0].proof.verificationMethod with the attacker DID
        const originalProof = delegated.delegationChain![0]!;
        const tamperedToken: CapabilityToken = {
            ...delegated,
            delegationChain: [
                {
                    ...originalProof,
                    proof: {
                        ...originalProof.proof,
                        verificationMethod: `${attackerDid}#key-1`,
                    },
                },
            ],
        };

        void recipient; // recipient private key unused (recipientDid is enough in this test)

        const resolvePublicKey = (did: DID): Promise<string | null> => {
            if (did === delegatorDid)
                return Promise.resolve(delegator.publicKey);
            return Promise.resolve(null);
        };

        const guard = new RuntimeGuard({
            tokenStore: {
                getTokensForAgent: () => Promise.resolve([tamperedToken]),
                getToken: (id: string) =>
                    Promise.resolve(id === rootToken.id ? rootToken : null),
            },
            revocationChecker: () => Promise.resolve(false),
            now: () => now,
            delegationChainValidator: validateDelegationChain, // real validator
            resolvePublicKey,
        });

        const result = await guard.check(
            'INQUIRY',
            { amount: 100 },
            recipientDid,
        );
        // The validator returns invalid (SIGNATURE_INVALID from rule 8c) → RuntimeGuard
        // continues in the delegated-token loop → finally returns no matching capability.
        expect(result.allowed).toBe(false);
    });

    // ─── A recipient-local delegated token with tampered top-level proof → guard rejects ──
    // The validator pushed down leaf top-level proof.value verification; RuntimeGuard benefits automatically.
    it('rejects delegated token with tampered leaf top-level proof.value (validator propagates leaf proof check)', async () => {
        const issuer = generateKeyPair();
        const issuerDid = didKeyFromPublicKey(
            Buffer.from(issuer.publicKey, 'hex'),
        );
        const delegator = generateKeyPair();
        const delegatorDid =
            'did:agent:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' as DID;
        const recipientDid =
            'did:agent:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' as DID;

        const now = '2026-04-22T10:00:00.000Z' as Timestamp;
        const rootToken = issueCapabilityToken({
            issuerDid,
            issuedTo: delegatorDid,
            capabilities: [
                {
                    action: 'INQUIRY',
                    scope: {
                        type: 'numeric_limit',
                        field: 'amount',
                        max: 1000,
                    },
                },
            ],
            expiresAt: '2030-01-01T00:00:00.000Z' as Timestamp,
            revocationUrl: 'https://revocation.example.com/v1/{id}',
            issuerPrivateKey: issuer.privateKey,
            issuedAt: '2026-01-01T00:00:00.000Z' as Timestamp,
        });

        const delegated = delegateCapabilityToken({
            parentToken: rootToken,
            delegatorPrivateKey: delegator.privateKey,
            delegateeDid: recipientDid,
            attenuatedCapabilities: [
                {
                    action: 'INQUIRY',
                    scope: {
                        type: 'numeric_limit',
                        field: 'amount',
                        max: 500,
                    },
                },
            ],
            expiresAt: '2029-01-01T00:00:00.000Z' as Timestamp,
            revocationUrl: 'https://revocation.example.com/v1/{id}',
            issuedAt: '2026-04-01T00:00:00.000Z' as Timestamp,
        });

        // Attack: the top-level proof.value is replaced with garbage (the chain-internal proof is unchanged)
        const tamperedToken: CapabilityToken = {
            ...delegated,
            proof: {
                ...delegated.proof,
                value: '0'.repeat(128) as CapabilityToken['proof']['value'],
            },
        };

        const resolvePublicKey = (did: DID): Promise<string | null> => {
            if (did === delegatorDid)
                return Promise.resolve(delegator.publicKey);
            return Promise.resolve(null);
        };

        const guard = new RuntimeGuard({
            tokenStore: {
                getTokensForAgent: () => Promise.resolve([tamperedToken]),
                getToken: (id: string) =>
                    Promise.resolve(id === rootToken.id ? rootToken : null),
            },
            revocationChecker: () => Promise.resolve(false),
            now: () => now,
            delegationChainValidator: validateDelegationChain, // real validator
            resolvePublicKey,
        });

        const result = await guard.check(
            'INQUIRY',
            { amount: 100 },
            recipientDid,
        );
        expect(result.allowed).toBe(false);
    });

    // ─── Explicit propagation of PARENT_TOKEN_REVOKED cascade revocation ──────────────────────
    // When chainResult.reason === 'PARENT_TOKEN_REVOKED', it must fail-closed
    // and return code='TOKEN_REVOKED'.
    // This is real-time revocation query integration: a parent token is revoked → cascade-reject the current leaf token.
    it('should return TOKEN_REVOKED code when delegationChainValidator reports PARENT_TOKEN_REVOKED (cascade revocation)', async () => {
        // Scenario: the parent token is revoked → the validator returns PARENT_TOKEN_REVOKED
        // → RuntimeGuard must immediately return code='TOKEN_REVOKED' rather than continue to the next candidate.
        const agentDid =
            'did:agent:aabb0011223344556677889900aabbccddeeff01' as DID;
        const delegatorKeyPair = generateKeyPair();
        const delegatorDid =
            'did:agent:bbcc0011223344556677889900aabbccddeeff02' as DID;

        const token = {
            id: `urn:cap:cascade-revoked-leaf`,
            specVersion: SPEC_VERSION_0_2_0,
            issuerDid: delegatorDid,
            principalDid: delegatorDid,
            issuedTo: agentDid,
            issuedAt: '2026-04-21T10:00:00.000Z',
            expiresAt: '2026-04-21T11:00:00.000Z',
            capabilities: [
                {
                    action: 'INQUIRY',
                    scope: {
                        type: 'numeric_limit' as const,
                        field: 'amount',
                        max: 500,
                    },
                },
            ],
            revocationUrl: 'https://revocation.example.com/v1/{id}',
            delegationChain: [
                {
                    parentTokenId: 'urn:cap:parent-revoked',
                    delegatorDid,
                    delegateeDid: agentDid,
                    parentCapabilities: [],
                    parentExpiresAt: '2026-04-21T12:00:00.000Z',
                    attenuatedCapabilities: [],
                    proof: {
                        type: 'Ed25519Signature2026',
                        created: '2026-04-21T10:00:00.000Z',
                        verificationMethod: `${delegatorDid}#key-1`,
                        value: 'a'.repeat(128),
                    },
                },
            ],
            proof: {
                type: 'Ed25519Signature2026',
                created: '2026-04-21T10:00:00.000Z',
                verificationMethod: `${delegatorDid}#key-1`,
                value: 'a'.repeat(128),
            },
        } as unknown as CapabilityToken;

        // validator returns PARENT_TOKEN_REVOKED — simulating the parent token matching the real-time revocation list
        const validator = vi.fn(async () =>
            Promise.resolve({
                valid: false as const,
                reason: 'PARENT_TOKEN_REVOKED' as const,
            }),
        );

        const guard = new RuntimeGuard({
            tokenStore: {
                getTokensForAgent: () => Promise.resolve([token]),
                getToken: (id: string) =>
                    Promise.resolve(id === token.id ? token : null),
            },
            revocationChecker: () => Promise.resolve(false),
            now: () => '2026-04-21T10:05:00.000Z' as Timestamp,
            delegationChainValidator: validator,
            resolvePublicKeys: () =>
                Promise.resolve({
                    current: delegatorKeyPair.publicKey,
                    rotationState: 'STABLE' as const,
                }),
        });

        const result = await guard.check('INQUIRY', { amount: 200 }, agentDid);

        // Cascade revocation must be propagated explicitly
        expect(result.allowed).toBe(false);
        expect(result.reason).toBe('parent token revoked');
        expect(result.code).toBe('TOKEN_REVOKED');
        expect(result.tokenId).toBe(token.id);
        expect(validator).toHaveBeenCalledTimes(1);
    });

    // ─── Among multiple candidate tokens, PARENT_TOKEN_REVOKED fails closed immediately ─────
    // Verifies: even with other candidate tokens remaining, PARENT_TOKEN_REVOKED does not continue but returns immediately.
    // This differs from an ordinary chain failure (an ordinary failure continues to the next candidate).
    it('should immediately return TOKEN_REVOKED without trying other candidate tokens when PARENT_TOKEN_REVOKED (fail-closed cascade)', async () => {
        const agentDid =
            'did:agent:ccdd0011223344556677889900aabbccddeeff03' as DID;
        const delegatorKeyPair = generateKeyPair();
        const delegatorDid =
            'did:agent:ddee0011223344556677889900aabbccddeeff04' as DID;

        // First token: delegated, the validator reports PARENT_TOKEN_REVOKED
        const delegatedToken = {
            id: 'urn:cap:delegated-cascade-revoked',
            specVersion: SPEC_VERSION_0_2_0,
            issuerDid: delegatorDid,
            principalDid: delegatorDid,
            issuedTo: agentDid,
            issuedAt: '2026-04-21T10:00:00.000Z',
            expiresAt: '2026-04-21T11:00:00.000Z',
            capabilities: [
                {
                    action: 'INQUIRY',
                    scope: {
                        type: 'numeric_limit' as const,
                        field: 'amount',
                        max: 500,
                    },
                },
            ],
            revocationUrl: 'https://revocation.example.com/v1/{id}',
            delegationChain: [
                {
                    parentTokenId: 'urn:cap:parent-being-revoked',
                    delegatorDid,
                    delegateeDid: agentDid,
                    parentCapabilities: [],
                    parentExpiresAt: '2026-04-21T12:00:00.000Z',
                    attenuatedCapabilities: [],
                    proof: {
                        type: 'Ed25519Signature2026',
                        created: '2026-04-21T10:00:00.000Z',
                        verificationMethod: `${delegatorDid}#key-1`,
                        value: 'a'.repeat(128),
                    },
                },
            ],
            proof: {
                type: 'Ed25519Signature2026',
                created: '2026-04-21T10:00:00.000Z',
                verificationMethod: `${delegatorDid}#key-1`,
                value: 'a'.repeat(128),
            },
        } as unknown as CapabilityToken;

        // Second token: an ordinary directly-issued token (no delegationChain), which would normally pass,
        // but PARENT_TOKEN_REVOKED causes the guard to return early, so it should not be evaluated
        const directToken = createToken('INQUIRY', 1000);

        // Track which tokens are evaluated
        const evaluatedTokenIds: string[] = [];
        const validator = vi.fn(async (tok: CapabilityToken) => {
            evaluatedTokenIds.push(tok.id);
            return Promise.resolve({
                valid: false as const,
                reason: 'PARENT_TOKEN_REVOKED' as const,
            });
        });

        const guard = new RuntimeGuard({
            tokenStore: {
                getTokensForAgent: () =>
                    // delegated token first, direct token second
                    Promise.resolve([delegatedToken, directToken.token]),
                getToken: (id: string) =>
                    Promise.resolve(
                        id === delegatedToken.id ? delegatedToken : null,
                    ),
            },
            revocationChecker: () => Promise.resolve(false),
            now: () => '2026-04-21T10:05:00.000Z' as Timestamp,
            delegationChainValidator: validator,
            resolvePublicKeys: () =>
                Promise.resolve({
                    current: delegatorKeyPair.publicKey,
                    rotationState: 'STABLE' as const,
                }),
        });

        const result = await guard.check('INQUIRY', { amount: 200 }, agentDid);

        // Immediately return TOKEN_REVOKED without trying the direct token next
        expect(result.allowed).toBe(false);
        expect(result.code).toBe('TOKEN_REVOKED');
        expect(result.tokenId).toBe(delegatedToken.id);
        // The validator is called only once (it only processed the delegated token)
        expect(validator).toHaveBeenCalledTimes(1);
    });

    // ─── A multi-hop delegation chain (depth > 1) is still allowed after scope attenuation ──────────────────
    // Verifies: in a multi-hop delegation chain (depth=2), chainDepth is correctly propagated into RuntimeGuardResult.
    it('should return correct delegationDepth for multi-hop delegation chain (depth > 1)', async () => {
        // Scenario: a two-hop delegation chain with depth=2; RuntimeGuard should propagate the depth returned by the validator.
        const agentDid =
            'did:agent:eeff0011223344556677889900aabbccddeeff05' as DID;
        const delegatorKeyPair = generateKeyPair();
        const delegatorDid =
            'did:agent:ff000011223344556677889900aabbccddeeff06' as DID;

        const token = {
            id: 'urn:cap:multi-hop-depth-2',
            specVersion: SPEC_VERSION_0_2_0,
            issuerDid: delegatorDid,
            principalDid: delegatorDid,
            issuedTo: agentDid,
            issuedAt: '2026-04-21T10:00:00.000Z',
            expiresAt: '2026-04-21T11:00:00.000Z',
            capabilities: [
                {
                    action: 'INQUIRY',
                    scope: {
                        type: 'numeric_limit' as const,
                        field: 'amount',
                        max: 300,
                    },
                },
            ],
            revocationUrl: 'https://revocation.example.com/v1/{id}',
            // Two chain records → depth = 2
            delegationChain: [
                {
                    parentTokenId: 'urn:cap:root',
                    delegatorDid,
                    delegateeDid: 'did:agent:intermediate' as DID,
                    parentCapabilities: [],
                    parentExpiresAt: '2026-04-21T12:00:00.000Z',
                    attenuatedCapabilities: [],
                    proof: {
                        type: 'Ed25519Signature2026',
                        created: '2026-04-21T10:00:00.000Z',
                        verificationMethod: `${delegatorDid}#key-1`,
                        value: 'a'.repeat(128),
                    },
                },
                {
                    parentTokenId: 'urn:cap:intermediate',
                    delegatorDid: 'did:agent:intermediate' as DID,
                    delegateeDid: agentDid,
                    parentCapabilities: [],
                    parentExpiresAt: '2026-04-21T12:00:00.000Z',
                    attenuatedCapabilities: [],
                    proof: {
                        type: 'Ed25519Signature2026',
                        created: '2026-04-21T10:00:00.000Z',
                        verificationMethod: 'did:agent:intermediate#key-1',
                        value: 'b'.repeat(128),
                    },
                },
            ],
            proof: {
                type: 'Ed25519Signature2026',
                created: '2026-04-21T10:00:00.000Z',
                verificationMethod: `${delegatorDid}#key-1`,
                value: 'a'.repeat(128),
            },
        } as unknown as CapabilityToken;

        // The validator simulates a successful multi-hop validation, returning depth=2
        const validator = vi.fn(async () =>
            Promise.resolve({ valid: true as const, depth: 2 as const }),
        );

        const guard = new RuntimeGuard({
            tokenStore: {
                getTokensForAgent: () => Promise.resolve([token]),
                getToken: (id: string) =>
                    Promise.resolve(id === token.id ? token : null),
            },
            revocationChecker: () => Promise.resolve(false),
            now: () => '2026-04-21T10:05:00.000Z' as Timestamp,
            delegationChainValidator: validator,
            resolvePublicKeys: () =>
                Promise.resolve({
                    current: delegatorKeyPair.publicKey,
                    rotationState: 'STABLE' as const,
                }),
        });

        const result = await guard.check('INQUIRY', { amount: 200 }, agentDid);

        expect(result).toEqual({
            allowed: true,
            tokenId: token.id,
            delegationDepth: 2,
        });
        expect(validator).toHaveBeenCalledTimes(1);
    });

    // ─── Scope attenuation failure → fail-closed, no silent override ─────
    // Attenuation failure must fail-closed.
    // This test verifies: the delegated token passes chain validation, but the guard rejects when the scope limit is exceeded.
    it('should deny when delegated token scope is exceeded after chain validates (attenuation fail-closed)', async () => {
        const agentDid =
            'did:agent:0011223344556677889900aabbccddeeff000701' as DID;
        const delegatorKeyPair = generateKeyPair();
        const delegatorDid =
            'did:agent:1122334455667788990011aabbccddeeff000702' as DID;

        // token scope limit max=100, but the request amount=500 → scope fails
        const token = {
            id: 'urn:cap:attenuated-scope-fail',
            specVersion: SPEC_VERSION_0_2_0,
            issuerDid: delegatorDid,
            principalDid: delegatorDid,
            issuedTo: agentDid,
            issuedAt: '2026-04-21T10:00:00.000Z',
            expiresAt: '2026-04-21T11:00:00.000Z',
            capabilities: [
                {
                    action: 'INQUIRY',
                    // after attenuation max=100; the parent token may be max=500
                    scope: {
                        type: 'numeric_limit' as const,
                        field: 'amount',
                        max: 100,
                    },
                },
            ],
            revocationUrl: 'https://revocation.example.com/v1/{id}',
            delegationChain: [
                {
                    parentTokenId: 'urn:cap:parent-wider',
                    delegatorDid,
                    delegateeDid: agentDid,
                    parentCapabilities: [
                        {
                            action: 'INQUIRY',
                            scope: {
                                type: 'numeric_limit' as const,
                                field: 'amount',
                                max: 500,
                            },
                        },
                    ],
                    parentExpiresAt: '2026-04-21T12:00:00.000Z',
                    attenuatedCapabilities: [
                        {
                            action: 'INQUIRY',
                            scope: {
                                type: 'numeric_limit' as const,
                                field: 'amount',
                                max: 100,
                            },
                        },
                    ],
                    proof: {
                        type: 'Ed25519Signature2026',
                        created: '2026-04-21T10:00:00.000Z',
                        verificationMethod: `${delegatorDid}#key-1`,
                        value: 'a'.repeat(128),
                    },
                },
            ],
            proof: {
                type: 'Ed25519Signature2026',
                created: '2026-04-21T10:00:00.000Z',
                verificationMethod: `${delegatorDid}#key-1`,
                value: 'a'.repeat(128),
            },
        } as unknown as CapabilityToken;

        // chain validation passes
        const validator = vi.fn(async () =>
            Promise.resolve({ valid: true as const, depth: 1 as const }),
        );

        const guard = new RuntimeGuard({
            tokenStore: {
                getTokensForAgent: () => Promise.resolve([token]),
                getToken: (id: string) =>
                    Promise.resolve(id === token.id ? token : null),
            },
            revocationChecker: () => Promise.resolve(false),
            now: () => '2026-04-21T10:05:00.000Z' as Timestamp,
            delegationChainValidator: validator,
            resolvePublicKeys: () =>
                Promise.resolve({
                    current: delegatorKeyPair.publicKey,
                    rotationState: 'STABLE' as const,
                }),
        });

        const result = await guard.check(
            'INQUIRY',
            // request amount=500 exceeds the attenuated max=100 → scope rejects
            { amount: 500 },
            agentDid,
        );

        // attenuation fail-closed
        expect(result.allowed).toBe(false);
        expect(result.reason).toBe(
            'scope check failed: amount exceeds max 100',
        );
        expect(validator).toHaveBeenCalledTimes(1);
    });
});
