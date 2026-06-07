/**
 * boundary-check unit test — L3 sub-protocol boundary check
 *
 * Test dimensions:
 * - assertTrustedDidMatchesExpected — baseline DID string equality
 * - assertTrustedDidIsKindAndFresh — 4-dimension check (trustedDid + kind + freshness + sdkVersion)
 * - extractDidFromCertSubjectDn — SAN URI preferred / CN fallback / multiple-DID conflict fail-closed
 * - assertCrossCheckMappingConsistent — consistency between verifier kind and verifiedSubject
 */

import { describe, expect, it } from 'vitest';

import type { DID } from '@coivitas/types';

import type {
    CertSubjectDn,
    JwtSubject,
    OAuth2ClientId,
    TrustedSettlerDid,
} from '../brand-types.js';
import type { VerifiedTransportContext } from '../verifier-types.js';

import { SdkError } from '../errors.js';
import {
    assertCrossCheckMappingConsistent,
    assertTrustedDidIsKindAndFresh,
    assertTrustedDidMatchesExpected,
    extractDidFromCertSubjectDn,
} from '../boundary-check.js';

const ALICE_DID = 'did:web:alice.example' as DID;
const ALICE_TRUSTED = ALICE_DID as TrustedSettlerDid;
const BOB_DID = 'did:web:bob.example' as DID;

function makeCtx(
    overrides?: Partial<VerifiedTransportContext>,
): VerifiedTransportContext {
    return {
        trustedDid: ALICE_TRUSTED,
        verifierKind: 'jwt',
        verifiedSubject: ALICE_DID as unknown as JwtSubject,
        verifiedAt: new Date().toISOString(),
        sdkVersion: '2.0.0',
        ...overrides,
    };
}

describe('assertTrustedDidMatchesExpected', () => {
    it('should not throw when trustedDid equals expectedDid', () => {
        expect(() =>
            assertTrustedDidMatchesExpected(ALICE_TRUSTED, ALICE_DID),
        ).not.toThrow();
    });

    it('should throw SdkError MAPPING_MISMATCH when trustedDid differs from expectedDid', () => {
        expect(() =>
            assertTrustedDidMatchesExpected(ALICE_TRUSTED, BOB_DID),
        ).toThrow(SdkError);
        expect(() =>
            assertTrustedDidMatchesExpected(ALICE_TRUSTED, BOB_DID),
        ).toThrow(/SDK_MAPPING_MISMATCH/);
    });
});

describe('assertTrustedDidIsKindAndFresh — 4-dimension check', () => {
    it('should pass when all 4 dimensions are valid', () => {
        const ctx = makeCtx();
        expect(() =>
            assertTrustedDidIsKindAndFresh(ctx, {
                did: ALICE_DID,
                verifierKinds: ['jwt'],
            }),
        ).not.toThrow();
    });

    it('should throw MAPPING_MISMATCH when trustedDid differs from expected.did', () => {
        const ctx = makeCtx();
        expect(() =>
            assertTrustedDidIsKindAndFresh(ctx, {
                did: BOB_DID,
                verifierKinds: ['jwt'],
            }),
        ).toThrow(/SDK_MAPPING_MISMATCH/);
    });

    it('should throw MAPPING_MISMATCH when verifierKind not in expected kinds', () => {
        const ctx = makeCtx({ verifierKind: 'jwt' });
        expect(() =>
            assertTrustedDidIsKindAndFresh(ctx, {
                did: ALICE_DID,
                verifierKinds: ['mtls'], // jwt is not in expected
            }),
        ).toThrow(/SDK_MAPPING_MISMATCH/);
    });

    it('should throw SCHEMA_VIOLATION when verifiedAt is stale beyond tolerance', () => {
        const staleTimestamp = new Date(Date.now() - 5 * 60 * 1000).toISOString(); // 5 min ago
        const ctx = makeCtx({ verifiedAt: staleTimestamp });
        expect(() =>
            assertTrustedDidIsKindAndFresh(ctx, {
                did: ALICE_DID,
                verifierKinds: ['jwt'],
                freshnessToleranceSeconds: 60, // 1 min tolerance
            }),
        ).toThrow(/SDK_SCHEMA_VIOLATION.*stale/);
    });

    it('should throw SCHEMA_VIOLATION when verifiedAt is in the future beyond tolerance', () => {
        const futureTimestamp = new Date(
            Date.now() + 5 * 60 * 1000,
        ).toISOString(); // 5 min future
        const ctx = makeCtx({ verifiedAt: futureTimestamp });
        expect(() =>
            assertTrustedDidIsKindAndFresh(ctx, {
                did: ALICE_DID,
                verifierKinds: ['jwt'],
                freshnessToleranceSeconds: 60,
            }),
        ).toThrow(/SDK_SCHEMA_VIOLATION.*future/);
    });

    it('should throw SCHEMA_VIOLATION when verifiedAt is not valid ISO 8601', () => {
        const ctx = makeCtx({ verifiedAt: 'not-a-timestamp' });
        expect(() =>
            assertTrustedDidIsKindAndFresh(ctx, {
                did: ALICE_DID,
                verifierKinds: ['jwt'],
            }),
        ).toThrow(/SDK_SCHEMA_VIOLATION.*ISO 8601/);
    });

    it('should throw SCHEMA_VIOLATION when sdkVersion is not "2.0.0"', () => {
        const ctx = makeCtx({ sdkVersion: '1.0.0' });
        expect(() =>
            assertTrustedDidIsKindAndFresh(ctx, {
                did: ALICE_DID,
                verifierKinds: ['jwt'],
            }),
        ).toThrow(/SDK_SCHEMA_VIOLATION.*sdkVersion/);
    });
});

describe('extractDidFromCertSubjectDn — DID extraction SOP', () => {
    it('should extract DID from SAN URI did: scheme when SAN URI is present', () => {
        const subject = 'CN=Alice, URI=did:web:alice.example, OU=Devices';
        expect(extractDidFromCertSubjectDn(subject)).toBe(
            'did:web:alice.example',
        );
    });

    it('should fallback to CN=did when SAN URI is absent', () => {
        const subject = 'CN=did:web:alice.example, OU=Devices, O=Acme';
        expect(extractDidFromCertSubjectDn(subject)).toBe(
            'did:web:alice.example',
        );
    });

    it('should prefer SAN URI when both SAN URI and CN=did are present', () => {
        // SAN URI preferred (RFC 5280 )
        const subject =
            'CN=did:web:fallback.example, URI=did:web:san-preferred.example, OU=Devices';
        expect(extractDidFromCertSubjectDn(subject)).toBe(
            'did:web:san-preferred.example',
        );
    });

    it('should throw SCHEMA_VIOLATION when no DID is found in subject', () => {
        const subject = 'CN=Alice, OU=Devices, O=Acme';
        expect(() => extractDidFromCertSubjectDn(subject)).toThrow(
            SdkError,
        );
        expect(() => extractDidFromCertSubjectDn(subject)).toThrow(
            /SDK_SCHEMA_VIOLATION/,
        );
    });

    it('should throw SCHEMA_VIOLATION when multiple distinct DIDs are present in SAN URI', () => {
        const subject =
            'URI=did:web:alice.example, URI=did:web:bob.example, OU=Devices';
        expect(() => extractDidFromCertSubjectDn(subject)).toThrow(
            /multiple distinct DIDs/,
        );
    });
});

describe('assertCrossCheckMappingConsistent — verifier kind consistency', () => {
    it('should pass jwt kind when verifiedSubject equals trustedDid', () => {
        const ctx = makeCtx({
            verifierKind: 'jwt',
            verifiedSubject: ALICE_DID as unknown as JwtSubject,
        });
        expect(() => assertCrossCheckMappingConsistent(ctx)).not.toThrow();
    });

    it('should throw MAPPING_MISMATCH for jwt kind when verifiedSubject differs from trustedDid', () => {
        const ctx = makeCtx({
            verifierKind: 'jwt',
            verifiedSubject: BOB_DID as unknown as JwtSubject,
        });
        expect(() => assertCrossCheckMappingConsistent(ctx)).toThrow(
            /SDK_MAPPING_MISMATCH/,
        );
    });

    it('should pass oauth2 kind when verifiedSubject equals trustedDid', () => {
        const ctx = makeCtx({
            verifierKind: 'oauth2',
            verifiedSubject: ALICE_DID as unknown as OAuth2ClientId,
        });
        expect(() => assertCrossCheckMappingConsistent(ctx)).not.toThrow();
    });

    it('should pass mtls kind when subject DN contains matching DID via SAN URI', () => {
        const ctx = makeCtx({
            verifierKind: 'mtls',
            verifiedSubject:
                'CN=Alice, URI=did:web:alice.example' as CertSubjectDn,
        });
        expect(() => assertCrossCheckMappingConsistent(ctx)).not.toThrow();
    });

    it('should throw MAPPING_MISMATCH for mtls kind when extracted DID differs from trustedDid', () => {
        const ctx = makeCtx({
            verifierKind: 'mtls',
            verifiedSubject:
                'CN=Alice, URI=did:web:bob.example' as CertSubjectDn,
        });
        expect(() => assertCrossCheckMappingConsistent(ctx)).toThrow(
            /SDK_MAPPING_MISMATCH/,
        );
    });

    it('should throw SCHEMA_VIOLATION for mtls kind when subject is empty', () => {
        const ctx = makeCtx({
            verifierKind: 'mtls',
            verifiedSubject: '' as CertSubjectDn,
        });
        expect(() => assertCrossCheckMappingConsistent(ctx)).toThrow(
            /SDK_SCHEMA_VIOLATION/,
        );
    });

    it('should not accept substring-style mtls subject that contains DID prefix only', () => {
        // Hardening follow-up — even if the subject contains a DID but not in a compliant format, extract must return the full DID
        // Here the subject contains the trustedDid as a substring, but the full trustedDid is "did:web:alice.example";
        // an attacker crafts "did:web:alice.examplespoofed" — extract takes the whole token
        const ctx = makeCtx({
            verifierKind: 'mtls',
            verifiedSubject:
                'URI=did:web:alice.examplespoofed' as CertSubjectDn,
        });
        // extract → "did:web:alice.examplespoofed" ≠ "did:web:alice.example" → throw
        expect(() => assertCrossCheckMappingConsistent(ctx)).toThrow(
            /SDK_MAPPING_MISMATCH/,
        );
    });
});
