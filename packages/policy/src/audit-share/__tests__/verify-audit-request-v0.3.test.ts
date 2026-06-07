/**
 * verifyAuditRequestV03 — audit-share v0.3 Step 0 real-consumption closure tests
 *
 * Test cases (≥7 cases; covering ≥6 dimensions):
 *   1. case 1 mtls kind happy path → verifyMtlsAndDeriveDid really consumed + Step 0-11 all PASS + verifierMetadata
 *   2. case 2 jwt kind happy path → verifyJwtAndDeriveDid really consumed + Step 0-11 all PASS + verifierMetadata
 *   3. case 3 oauth2 kind happy path → verifyOAuth2AndDeriveDid really consumed + Step 0-11 all PASS + verifierMetadata
 *   4. case 4 boundary fail #1: verifier factory throws → AUDIT_SHARE_VERIFIER_REQUIRED
 *   5. case 5 boundary fail #2: assertTrustedDidIsKindAndFresh 4-dimension fail → AUDIT_SHARE_BOUNDARY_CHECK_FAILED
 *   6. case 6 cross-tenant audit spoofing: caller fabricates request.requesterDid that mismatches trustedDid
 *      → L4 sub-protocol cross-check throws AUDIT_SHARE_BOUNDARY_CHECK_FAILED (anti-spoofing)
 *   7. case 7 step 10 hcc v0.2 real consumption: hash chain entries contain a chainIdentity preimage tamper
 *      → throw AUDIT_SHARE_CHAIN_IDENTITY_TAMPERED (inheriting hcc v0.2 HC_HASH_MISMATCH / HC_CHAIN_IDENTITY_PREIMAGE_FAILED)
 *
 * Anti-phantom guard:
 *   - the real sdk verifier factory mock exercises the step 0 real-consumption path (vi.mock @coivitas/identity)
 *   - the real v0.2 manager mock skips the complex step 1-9 dependencies (vi.spyOn AuditShareManager.prototype.verifyAuditRequest)
 *   - the real hcc v0.2 verifyHashChain is injected via entries (a chainIdentity preimage tamper really triggers HC_HASH_MISMATCH)
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

import { appendHashChainEntry } from '@coivitas/crypto';
import {
    AuditShareError,
    type AuditShareVerifiedRequest,
    type ChainIdentity,
    type DID,
    type Timestamp,
    type VerifiedTransportContext,
} from '@coivitas/types';

import { AuditShareManager } from '../audit-share-manager.js';
import type {
    RawTransportEvidence,
    TrustedHashChainCheckpoint,
    TrustedVerifierConfig,
} from '../types.js';
import { verifyAuditRequestV03 } from '../verify-audit-request-v0.3.js';

// ─── sdk v0.2 verifier factory mock (vi.mock module level) ──────────────────

// Fully mock the @coivitas/identity surface — to avoid importActual triggering the
// @peculiar/x509 transitive import (tsyringe reflect-metadata missing; test env isolation; does not pollute production code)
vi.mock('@coivitas/identity', () => {
    // verifyAuditShareDelegatedKey is imported by audit-share-manager.ts — but this test already mocks the manager's
    // verifyAuditRequest behavior (vi.spyOn AuditShareManager.prototype), so the manager's internal import path
    // is not really consumed; the stub function here is just a placeholder
    return {
        verifyMtlsAndDeriveDid: vi.fn(),
        verifyJwtAndDeriveDid: vi.fn(),
        verifyOAuth2AndDeriveDid: vi.fn(),
        assertTrustedDidIsKindAndFresh: vi.fn(),
        assertCrossCheckMappingConsistent: vi.fn(),
        // imported internally by the audit-share v0.2 manager (this test mocks manager.verifyAuditRequest, skipping it entirely);
        // the stub here avoids an import-undefined error at runtime
        verifyAuditShareDelegatedKey: vi.fn(),
    };
});

import {
    assertCrossCheckMappingConsistent,
    assertTrustedDidIsKindAndFresh,
    verifyJwtAndDeriveDid,
    verifyMtlsAndDeriveDid,
    verifyOAuth2AndDeriveDid,
} from '@coivitas/identity';

// ─── Test fixtures ───────────────────────────────────────────────────────────

const REQUESTER_DID = 'did:agent:tenant-a:requester-001' as DID;
const AUDIENCE_DID = 'did:agent:tenant-a:auditor-001' as DID;
const NOW: Timestamp = '2026-05-20T10:00:00.000Z' as Timestamp;

const VERIFIED_AT_FRESH = new Date(Date.now() - 5000).toISOString(); // 5s old (within 60s tolerance)

function buildVerifiedCtx(
    overrides: Partial<VerifiedTransportContext> = {},
): VerifiedTransportContext {
    return {
        trustedDid: REQUESTER_DID as VerifiedTransportContext['trustedDid'],
        verifierKind: 'mtls',
        verifiedSubject:
            'URI:did:agent:tenant-a:requester-001' as VerifiedTransportContext['verifiedSubject'],
        verifiedAt: VERIFIED_AT_FRESH,
        sdkVersion: '2.0.0',
        ...overrides,
    };
}

function buildRequest(): AuditShareVerifiedRequest {
    // Request field construction — only for deps injection (the v0.2 manager mock skips real schema validation);
    // field values are merely type-conformant; real schema validation happens at the v0.2 manager stage (mocked away here)
    return {
        auditShareVersion:
            '1.0.0' as AuditShareVerifiedRequest['auditShareVersion'],
        token: 'audit-key-001' as AuditShareVerifiedRequest['token'],
        disclosedClaims: ['eventType', 'timestamp'],
        challenge: '550e8400-e29b-41d4-a716-446655440000',
        audience: AUDIENCE_DID,
        notAfter: '2026-05-21T10:00:00.000Z' as Timestamp,
        requestedScope: {
            tenantId: '11111111-1111-4111-8111-111111111111',
            auditClass: 'L2',
            chainNamespace: 'audit-share-v0.3-test',
        } as AuditShareVerifiedRequest['requestedScope'],
        requesterDid: REQUESTER_DID,
        requesterSignature: new Uint8Array(64).fill(
            0x01,
        ) as unknown as AuditShareVerifiedRequest['requesterSignature'],
    };
}

// evidence contains only the verified artifact; the trust anchor is split out into trustedVerifierConfig
function buildMtlsEvidence(): RawTransportEvidence {
    return { kind: 'mtls', clientCert: 'dummy-cert-pem' };
}

function buildJwtEvidence(): RawTransportEvidence {
    return { kind: 'jwt', jwt: 'header.payload.signature' };
}

function buildOAuth2Evidence(): RawTransportEvidence {
    return { kind: 'oauth2', accessToken: 'dummy-access-token' };
}

// trustedVerifierConfig — the trust anchor is provided by trusted deployment configuration
function buildMtlsConfig(): TrustedVerifierConfig {
    return {
        kind: 'mtls',
        trustedRootCerts: ['dummy-root-pem'],
        expectedDid: REQUESTER_DID,
    };
}

function buildJwtConfig(): TrustedVerifierConfig {
    return {
        kind: 'jwt',
        jwks: { keys: [] },
        expectedIssuer: 'https://issuer.example.com',
        expectedAudience: 'audit-share-v0.3',
        expectedDid: REQUESTER_DID,
    };
}

function buildOAuth2Config(): TrustedVerifierConfig {
    return {
        kind: 'oauth2',
        issuerUrl: 'https://issuer.example.com',
        introspectionEndpoint: 'https://issuer.example.com/introspect',
        introspectionClientId: 'audit-share-client',
        introspectionClientSecret: 'dummy-secret',
        expectedAudience: 'audit-share-v0.3',
        expectedDid: REQUESTER_DID,
    };
}

/**
 * Build a real hcc v0.2 chain (genesis + 1 next entry; with chainIdentity preimage)
 * — generated for real via appendHashChainEntry to ensure the verifyHashChain happy path PASSes
 */
function buildValidChain() {
    const chainIdentity: ChainIdentity = {
        chainNamespace: 'audit-share-v0.3-test',
        tenantId: '11111111-1111-4111-8111-111111111111',
        auditClass: 'L2',
    };
    const genesis = appendHashChainEntry(
        { event: 'genesis', actor: REQUESTER_DID },
        chainIdentity,
        undefined,
    );
    const entry1 = appendHashChainEntry(
        { event: 'audit-event-001', actor: REQUESTER_DID },
        chainIdentity,
        genesis,
    );
    return [genesis, entry1] as const;
}

/**
 * Build a trusted checkpoint tail anchor matching buildValidChain (2 entries) (required)
 * — minimal tail anchor: expectedEntryCount=2; harmless to pass it even in cases that throw before Step 10
 */
function buildCheckpoint(): TrustedHashChainCheckpoint {
    return { expectedEntryCount: 2 };
}

/**
 * Build a tampered chain — the three chainIdentity fields are rewritten by an attacker, canonicalPayloadHash not recomputed
 * → verifyHashChain detects a hash mismatch on recompute → throw HC_HASH_MISMATCH
 */
function buildTamperedChain() {
    const validChain = buildValidChain();
    // Tamper with entries[1]'s chainIdentity.chainNamespace (canonicalPayloadHash not correspondingly updated)
    const tamperedEntry1 = {
        ...validChain[1],
        chainIdentity: {
            ...validChain[1].chainIdentity,
            chainNamespace: 'TAMPERED-NAMESPACE', // attacker tampers with a chainIdentity field
        },
    };
    return [validChain[0], tamperedEntry1] as const;
}

// ─── Tests ───────────────────────────────────────────────────────────────────

describe('verifyAuditRequestV03 — v0.3 Step 0 real-consumption closure (≥7 cases; ≥6 dimensions)', () => {
    let managerSpy: ReturnType<typeof vi.spyOn>;
    const deps = {} as Parameters<typeof verifyAuditRequestV03>[3];

    beforeEach(() => {
        // mock the v0.2 manager.verifyAuditRequest happy-path return (skips the complex step 1-9 dependencies)
        managerSpy = vi.spyOn(
            AuditShareManager.prototype,
            'verifyAuditRequest',
        );
        managerSpy.mockResolvedValue({
            ok: true,
            entries: buildValidChain(),
            auditEvents: [{}, {}], // same length as entries; empty disclosed projection (test focus is not on disclosedClaims)
        } as Awaited<ReturnType<AuditShareManager['verifyAuditRequest']>>);
    });

    afterEach(() => {
        vi.clearAllMocks();
    });

    // ─── case 1: mtls kind happy path (verifyMtlsAndDeriveDid really consumed) ─────────

    it('case 1 — mtls kind happy path: verifyMtlsAndDeriveDid really consumed + all 11 steps PASS + verifierMetadata', async () => {
        const ctx = buildVerifiedCtx({ verifierKind: 'mtls' });
        vi.mocked(verifyMtlsAndDeriveDid).mockResolvedValue(ctx);
        vi.mocked(assertTrustedDidIsKindAndFresh).mockReturnValue(undefined);
        vi.mocked(assertCrossCheckMappingConsistent).mockReturnValue(undefined);

        const result = await verifyAuditRequestV03(
            buildRequest(),
            AUDIENCE_DID,
            buildMtlsEvidence(),
            buildMtlsConfig(),
            deps,
            NOW,
            buildCheckpoint(),
        );

        // Real-consumption verify: the sdk verifier factory is actually called (invoked inside the audit-share boundary)
        // the factory receives the context the boundary assembles (artifact + trusted-config trust anchor)
        expect(verifyMtlsAndDeriveDid).toHaveBeenCalledTimes(1);
        expect(verifyMtlsAndDeriveDid).toHaveBeenCalledWith({
            clientCert: 'dummy-cert-pem',
            trustedRootCerts: ['dummy-root-pem'],
            expectedDid: REQUESTER_DID,
        });
        // Real-consumption verify: the boundary check is actually called (4 dimensions + cross-check mapping)
        expect(assertTrustedDidIsKindAndFresh).toHaveBeenCalledTimes(1);
        expect(assertCrossCheckMappingConsistent).toHaveBeenCalledTimes(1);
        // verifierMetadata actually carries over the verifiedCtx fields
        expect(result.ok).toBe(true);
        expect(result.verifierMetadata.kind).toBe('mtls');
        expect(result.verifierMetadata.verifiedAt).toBe(VERIFIED_AT_FRESH);
    });

    // ─── case 2: jwt kind happy path ─────────────────────────────────────────

    it('case 2 — jwt kind happy path: verifyJwtAndDeriveDid really consumed + all 11 steps PASS + verifierMetadata', async () => {
        const ctx = buildVerifiedCtx({
            verifierKind: 'jwt',
            verifiedSubject:
                REQUESTER_DID as unknown as VerifiedTransportContext['verifiedSubject'],
        });
        vi.mocked(verifyJwtAndDeriveDid).mockResolvedValue(ctx);
        vi.mocked(assertTrustedDidIsKindAndFresh).mockReturnValue(undefined);
        vi.mocked(assertCrossCheckMappingConsistent).mockReturnValue(undefined);

        const result = await verifyAuditRequestV03(
            buildRequest(),
            AUDIENCE_DID,
            buildJwtEvidence(),
            buildJwtConfig(),
            deps,
            NOW,
            buildCheckpoint(),
        );

        expect(verifyJwtAndDeriveDid).toHaveBeenCalledTimes(1);
        expect(verifyMtlsAndDeriveDid).not.toHaveBeenCalled();
        expect(verifyOAuth2AndDeriveDid).not.toHaveBeenCalled();
        expect(result.ok).toBe(true);
        expect(result.verifierMetadata.kind).toBe('jwt');
    });

    // ─── case 3: oauth2 kind happy path ──────────────────────────────────────

    it('case 3 — oauth2 kind happy path: verifyOAuth2AndDeriveDid really consumed + all 11 steps PASS + verifierMetadata', async () => {
        const ctx = buildVerifiedCtx({
            verifierKind: 'oauth2',
            verifiedSubject:
                REQUESTER_DID as unknown as VerifiedTransportContext['verifiedSubject'],
        });
        vi.mocked(verifyOAuth2AndDeriveDid).mockResolvedValue(ctx);
        vi.mocked(assertTrustedDidIsKindAndFresh).mockReturnValue(undefined);
        vi.mocked(assertCrossCheckMappingConsistent).mockReturnValue(undefined);

        const result = await verifyAuditRequestV03(
            buildRequest(),
            AUDIENCE_DID,
            buildOAuth2Evidence(),
            buildOAuth2Config(),
            deps,
            NOW,
            buildCheckpoint(),
        );

        expect(verifyOAuth2AndDeriveDid).toHaveBeenCalledTimes(1);
        expect(verifyMtlsAndDeriveDid).not.toHaveBeenCalled();
        expect(verifyJwtAndDeriveDid).not.toHaveBeenCalled();
        expect(result.ok).toBe(true);
        expect(result.verifierMetadata.kind).toBe('oauth2');
    });

    // ─── case 4: boundary fail #1 — verifier factory throw ───────────────────

    it('case 4 — boundary fail #1: verifier factory throw (cert expired / invalid signature / wrong audience) → AUDIT_SHARE_VERIFIER_REQUIRED', async () => {
        // Real-consumption verification: factory throws → must catch and wrap as AUDIT_SHARE_VERIFIER_REQUIRED;
        // anti-phantom enforcement (a stub success is not allowed)
        vi.mocked(verifyMtlsAndDeriveDid).mockRejectedValue(
            new Error('cert expired'),
        );

        await expect(
            verifyAuditRequestV03(
                buildRequest(),
                AUDIENCE_DID,
                buildMtlsEvidence(),
                buildMtlsConfig(),
                deps,
                NOW,
                buildCheckpoint(),
            ),
        ).rejects.toMatchObject({
            code: 'AUDIT_SHARE_VERIFIER_REQUIRED',
            name: 'AuditShareError',
        });

        // The factory is actually called (real consumption; not a stub bypass)
        expect(verifyMtlsAndDeriveDid).toHaveBeenCalledTimes(1);
        // The boundary check should not be called (the factory failure already threw; short-circuit)
        expect(assertTrustedDidIsKindAndFresh).not.toHaveBeenCalled();
    });

    it('case 4b — boundary fail: transportEvidence undefined → AUDIT_SHARE_VERIFIER_REQUIRED (anti-phantom)', async () => {
        // caller bypasses transportEvidence (null/undefined) → must throw; anti-phantom
        await expect(
            verifyAuditRequestV03(
                buildRequest(),
                AUDIENCE_DID,
                undefined as unknown as RawTransportEvidence,
                buildMtlsConfig(),
                deps,
                NOW,
                buildCheckpoint(),
            ),
        ).rejects.toMatchObject({
            code: 'AUDIT_SHARE_VERIFIER_REQUIRED',
        });
        // The factory should not be called (transportEvidence is missing, short-circuit)
        expect(verifyMtlsAndDeriveDid).not.toHaveBeenCalled();
    });

    // ─── case 5: boundary fail #2 — assertTrustedDidIsKindAndFresh fail ──────

    it('case 5 — boundary fail #2: assertTrustedDidIsKindAndFresh 4-dimension fail → AUDIT_SHARE_BOUNDARY_CHECK_FAILED', async () => {
        const ctx = buildVerifiedCtx({ verifierKind: 'mtls' });
        vi.mocked(verifyMtlsAndDeriveDid).mockResolvedValue(ctx);
        // sdk boundary check throws — any of the 4 dimensions fails (e.g. sdkVersion downgrade or verifiedAt stale)
        vi.mocked(assertTrustedDidIsKindAndFresh).mockImplementation(() => {
            throw new Error(
                'sdkVersion downgrade detected (ctx.sdkVersion="1.0.0" !== "2.0.0")',
            );
        });

        await expect(
            verifyAuditRequestV03(
                buildRequest(),
                AUDIENCE_DID,
                buildMtlsEvidence(),
                buildMtlsConfig(),
                deps,
                NOW,
                buildCheckpoint(),
            ),
        ).rejects.toMatchObject({
            code: 'AUDIT_SHARE_BOUNDARY_CHECK_FAILED',
            name: 'AuditShareError',
        });

        // The factory is actually called + the boundary check is actually called (real-consumption verify chain)
        expect(verifyMtlsAndDeriveDid).toHaveBeenCalledTimes(1);
        expect(assertTrustedDidIsKindAndFresh).toHaveBeenCalledTimes(1);
        // cross-check mapping should not be called (assertTrustedDidIsKindAndFresh failed, short-circuit)
        expect(assertCrossCheckMappingConsistent).not.toHaveBeenCalled();
    });

    it('case 5b — boundary fail: assertCrossCheckMappingConsistent fail → AUDIT_SHARE_BOUNDARY_CHECK_FAILED', async () => {
        const ctx = buildVerifiedCtx({ verifierKind: 'mtls' });
        vi.mocked(verifyMtlsAndDeriveDid).mockResolvedValue(ctx);
        vi.mocked(assertTrustedDidIsKindAndFresh).mockReturnValue(undefined);
        vi.mocked(assertCrossCheckMappingConsistent).mockImplementation(() => {
            throw new Error(
                'mtls kind: extracted DID does not match trustedDid (spoofed cert subject)',
            );
        });

        await expect(
            verifyAuditRequestV03(
                buildRequest(),
                AUDIENCE_DID,
                buildMtlsEvidence(),
                buildMtlsConfig(),
                deps,
                NOW,
                buildCheckpoint(),
            ),
        ).rejects.toMatchObject({
            code: 'AUDIT_SHARE_BOUNDARY_CHECK_FAILED',
        });
    });

    // ─── case 6: cross-tenant audit spoofing (anti-spoofing) ──────────

    it('case 6 — cross-tenant spoofing: caller fabricate request.requesterDid mismatch verifiedCtx.trustedDid → L4 cross-check throw AUDIT_SHARE_BOUNDARY_CHECK_FAILED', async () => {
        // Attacker scenario: the caller submits request.requesterDid = "did:agent:tenant-A:victim",
        // but the mtls cert subject resolves to trustedDid = "did:agent:tenant-B:attacker"
        // → if the sdk boundary check (assertTrustedDidIsKindAndFresh) does not catch it (an extreme testing case),
        // the L4 sub-protocol cross-check must throw as a mandatory fallback (defense-in-depth)
        const ATTACKER_DID = 'did:agent:tenant-B:attacker-666' as DID;
        const ctx = buildVerifiedCtx({
            trustedDid: ATTACKER_DID as VerifiedTransportContext['trustedDid'], // verifier derives the attacker DID
            verifierKind: 'mtls',
        });
        vi.mocked(verifyMtlsAndDeriveDid).mockResolvedValue(ctx);
        // mock boundary check PASS (simulating an sdk boundary-check implementation bug or a mock that misses the check;
        // the L4 sub-protocol cross-check must catch it as a mandatory fallback)
        vi.mocked(assertTrustedDidIsKindAndFresh).mockReturnValue(undefined);
        vi.mocked(assertCrossCheckMappingConsistent).mockReturnValue(undefined);

        // request.requesterDid = victim; trustedDid = attacker → L4 cross-check fail
        await expect(
            verifyAuditRequestV03(
                buildRequest(), // request.requesterDid = REQUESTER_DID (victim;tenant-A)
                AUDIENCE_DID,
                buildMtlsEvidence(),
                buildMtlsConfig(),
                deps,
                NOW,
                buildCheckpoint(),
            ),
        ).rejects.toMatchObject({
            code: 'AUDIT_SHARE_BOUNDARY_CHECK_FAILED',
            name: 'AuditShareError',
        });

        // The factory is actually called (cryptographically derives the attacker DID); the boundary check is actually called;
        // the L4 sub-protocol cross-check (verifiedCtx.trustedDid !== request.requesterDid) actually provides the fallback
        expect(verifyMtlsAndDeriveDid).toHaveBeenCalledTimes(1);
        expect(assertTrustedDidIsKindAndFresh).toHaveBeenCalledTimes(1);
        expect(assertCrossCheckMappingConsistent).toHaveBeenCalledTimes(1);
    });

    // ─── case 7: step 10 hcc v0.2 chainIdentity preimage tamper ──────────────

    it('case 7 — step 10 hcc v0.2 real consumption: chainIdentity preimage tamper → AUDIT_SHARE_CHAIN_IDENTITY_TAMPERED (inheriting hcc v0.2 HC_HASH_MISMATCH)', async () => {
        // Set the sdk verifier to PASS entirely so Step 0 passes completely; the manager returns a tampered chain; Step 10 really consumes verifyHashChain
        const ctx = buildVerifiedCtx({ verifierKind: 'mtls' });
        vi.mocked(verifyMtlsAndDeriveDid).mockResolvedValue(ctx);
        vi.mocked(assertTrustedDidIsKindAndFresh).mockReturnValue(undefined);
        vi.mocked(assertCrossCheckMappingConsistent).mockReturnValue(undefined);

        // The manager mock returns entries whose chainIdentity has been tampered → hash mismatch when verifyHashChain is really consumed
        managerSpy.mockResolvedValue({
            ok: true,
            entries: buildTamperedChain(),
            auditEvents: [{}, {}],
        } as Awaited<ReturnType<AuditShareManager['verifyAuditRequest']>>);

        await expect(
            verifyAuditRequestV03(
                buildRequest(),
                AUDIENCE_DID,
                buildMtlsEvidence(),
                buildMtlsConfig(),
                deps,
                NOW,
                buildCheckpoint(),
            ),
        ).rejects.toMatchObject({
            code: 'AUDIT_SHARE_CHAIN_IDENTITY_TAMPERED',
            name: 'AuditShareError',
        });
    });

    // ─── case 8: checkpoint with no tail anchor → reject (non-empty tail-truncation protection) ──

    it('case 8 — should reject with AUDIT_SHARE_HASH_CHAIN_INVALID when checkpoint has no tail anchor', async () => {
        // Step 0 PASSes all the way to Step 10; but the checkpoint is empty (no tail anchor) → the audit-truth last line of defense rejects
        // (without a tail anchor, non-empty tail truncation is undetectable; returning ok:true is not allowed).
        const ctx = buildVerifiedCtx({ verifierKind: 'mtls' });
        vi.mocked(verifyMtlsAndDeriveDid).mockResolvedValue(ctx);
        vi.mocked(assertTrustedDidIsKindAndFresh).mockReturnValue(undefined);
        vi.mocked(assertCrossCheckMappingConsistent).mockReturnValue(undefined);

        await expect(
            verifyAuditRequestV03(
                buildRequest(),
                AUDIENCE_DID,
                buildMtlsEvidence(),
                buildMtlsConfig(),
                deps,
                NOW,
                {}, // checkpoint with no tail anchor
            ),
        ).rejects.toMatchObject({
            code: 'AUDIT_SHARE_HASH_CHAIN_INVALID',
            name: 'AuditShareError',
        });
    });

    // ─── Extra dimension: AuditShareError instance type guard ─────────────────────────

    it('extra dimension — all error throws are AuditShareError instances (not raw Error; namespace isolation guard)', async () => {
        vi.mocked(verifyMtlsAndDeriveDid).mockRejectedValue(
            new Error('cert chain validation failed'),
        );

        try {
            await verifyAuditRequestV03(
                buildRequest(),
                AUDIENCE_DID,
                buildMtlsEvidence(),
                buildMtlsConfig(),
                deps,
                NOW,
                buildCheckpoint(),
            );
            // Should not be reached
            expect.unreachable('Expected throw AuditShareError but did not');
        } catch (err) {
            expect(err).toBeInstanceOf(AuditShareError);
            expect((err as AuditShareError).code).toBe(
                'AUDIT_SHARE_VERIFIER_REQUIRED',
            );
            // message contains the step locator + real-consumption evidence (cert chain validation failed)
            expect((err as AuditShareError).message).toContain(
                'sdk v0.2 verifier factory',
            );
        }
    });
});
