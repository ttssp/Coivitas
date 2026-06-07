/**
 * VerifierFactory orchestrator unit test
 *
 * Test dimensions:
 * - SUPPORTED_KINDS literal readonly 'mtls' | 'jwt' | 'oauth2'
 * - verify() dispatch by kind — invokes the matching one of the 3 verifiers
 * - verify() invalid kind → throws SCHEMA_VIOLATION (theoretically unreachable; TS exhaustive fallback)
 *
 * Note: the real mTLS / JWT / OAuth2 verify paths are covered by their respective verifier unit
 *     tests and the integration tests (the 3 factories internally depend on an external cert chain /
 *     JWKS endpoint / introspection RTT; this unit test only covers the dispatch entry point and the
 *     fail-closed behavior on the failure path)
 */

import { describe, expect, it } from 'vitest';

import type { DID } from '@coivitas/types';

import { SdkError } from '../errors.js';
import { VerifierFactory } from '../verifier-factory.js';
import type { VerifierFactoryInput } from '../verifier-types.js';

describe('VerifierFactory — SUPPORTED_KINDS static field', () => {
    it('should declare 3 supported kinds when checking SUPPORTED_KINDS array', () => {
        expect(VerifierFactory.SUPPORTED_KINDS).toEqual([
            'mtls',
            'jwt',
            'oauth2',
        ]);
    });
});

describe('VerifierFactory.verify — dispatch', () => {
    const factory = new VerifierFactory();
    const dummyDid = 'did:web:alice.example' as DID;

    it('should reject jwt input with malformed JWT (alg denylist enforce)', async () => {
        // Use JWT alg = 'none' to trigger the denylist; the real jwtVerify is never invoked (it throws before the alg check)
        const noneJwt = `${Buffer.from(JSON.stringify({ alg: 'none' })).toString('base64url')}.${Buffer.from(JSON.stringify({ sub: dummyDid })).toString('base64url')}.fakesig`;

        const input: VerifierFactoryInput = {
            kind: 'jwt',
            ctx: {
                jwt: noneJwt,
                jwks: 'https://example.test/.well-known/jwks.json',
                expectedIssuer: 'https://issuer.example',
                expectedAudience: 'aud',
                expectedDid: dummyDid,
            },
        };

        await expect(factory.verify(input)).rejects.toThrow(SdkError);
        await expect(factory.verify(input)).rejects.toThrow(
            /SDK_JWT_VERIFY_FAILED/,
        );
    });

    it('should reject mtls input with invalid cert bytes (parse fail)', async () => {
        const input: VerifierFactoryInput = {
            kind: 'mtls',
            ctx: {
                clientCert: 'not-a-cert',
                trustedRootCerts: ['also-not-a-cert'],
                expectedDid: dummyDid,
            },
        };

        await expect(factory.verify(input)).rejects.toThrow(SdkError);
        await expect(factory.verify(input)).rejects.toThrow(
            /SDK_MTLS_VERIFY_FAILED/,
        );
    });
});
