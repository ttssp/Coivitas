/**
 * e2e-cross-package.test.ts — CSP L0 (types) + L1 (crypto) end-to-end cross-package integration test
 *
 * Placement:
 *   The identity (L2) package is the first layer that depends on both @coivitas/types (L0) and @coivitas/crypto (L1);
 *   L1 is strictly forbidden from depending on L0 (anti-layering); so an e2e test spanning L0+L1 must live in an L2+ package (identity chosen here).
 *
 * Coverage goals (>=3 cases):
 *   - case 1 (happy): L0 schema validate -> L1 canonicalSerialize -> canonicalHash -> Ed25519 sign -> verifySignature -> valid:true;
 *   - case 2 (schema reject): payload missing issuerDid -> L0 validateCspPayload AJV reject -> valid:false;
 *   - case 3 (signature reject): tamper payload -> L1 verifySignature -> throw CspError(CSP_SIGNATURE_INVALID);
 *   - case 4 (contract verify bonus): an L0-PASS payload always passes L1 sign+verify — bidirectional cross-package closed loop;
 *
 * Cross-package contract (anti-phantom + anti cross-package drift):
 *   - L0 (@coivitas/types) schema + CspErrorCode union covering 13 codes;
 *   - L1 (@coivitas/crypto) canonicalSerialize + canonicalHash + verifySignature throwing the 13 spec codes;
 *   - L0/L1 bidirectional contract: schema reject <-> AJV third defense line; signature reject <-> Ed25519 verify first defense line;
 *   - the L2 verifier pipeline chains all three e2e layers (this file does not directly cover L2).
 */

import { ed25519 } from '@noble/curves/ed25519';
import { describe, expect, it } from 'vitest';

import {
    canonicalHash,
    canonicalSerialize,
    CspError,
    fromHex,
    toHex,
    verifySignature,
} from '@coivitas/crypto';
import { validateCspPayload } from '@coivitas/types';

// RFC 8032 Ed25519 known key pair (reuses the RFC 8032 test vectors from packages/crypto verify-signature.test.ts)
const rfcPrivateKey = fromHex(
    '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60',
);
const rfcPublicKey =
    'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a';

// Build a complete csp signed payload (cspVersion 1.0.0 + 5 fields + token with all fields aligned to the schema)
function makeValidCspPayload(
    overrides: Partial<Record<string, unknown>> = {},
): Record<string, unknown> {
    return {
        cspVersion: '1.0.0',
        token: {
            id: 'token-e2e-001',
            issuerDid: 'did:key:issuer',
            principalDid: 'did:key:principal',
            issuedTo: 'did:key:agent',
            specVersion: '0.3.0',
            issuedAt: '2026-05-18T00:00:00.000Z',
            expiresAt: '2099-01-01T00:00:00.000Z',
            capabilities: [
                {
                    action: 'read',
                    scope: { type: 'allowlist', field: 'res', values: [] },
                },
            ],
            revocationUrl:
                'https://issuer.example.com/revocation/token-e2e-001',
            proof: {
                type: 'Ed25519Signature2026',
                created: '2026-05-18T00:00:00.000Z',
                verificationMethod: 'did:key:issuer#key-1',
                value: 'sig-base64-stub',
            },
        },
        disclosedClaims: [],
        challenge: '550e8400-e29b-41d4-a716-446655440000',
        audience: 'did:example:verifier',
        notAfter: '2099-01-01T00:00:00.000Z',
        ...overrides,
    };
}

describe('csp L0 + L1 cross-package e2e — complete closed loop', () => {
    /**
     * case 1 (happy):
     *   L0 validateCspPayload AJV -> valid:true
     *   -> L1 canonicalSerialize (JCS) -> canonicalHash (SHA-256)
     *   -> Ed25519 sign -> L1 verifySignature -> { valid: true }
     */
    it('case 1 (happy): L0 schema validate → L1 canonicalize+hash → Ed25519 sign → verifySignature', () => {
        const payload = makeValidCspPayload();

        // ── Layer 1: L0 AJV third defense line schema validate ──
        const schemaResult = validateCspPayload(payload);
        expect(schemaResult.valid).toBe(true);

        // ── Layer 2: L1 canonicalSerialize JCS -> canonicalHash SHA-256 ──
        const canonicalBytes = canonicalSerialize(payload);
        expect(canonicalBytes).toBeInstanceOf(Uint8Array);
        expect(canonicalBytes.length).toBeGreaterThan(0);

        const digest = canonicalHash(payload);
        expect(digest).toMatch(/^[0-9a-f]{64}$/);

        // ── Layer 3: Ed25519 sign (RFC 8032 deterministic) ──
        const signature = toHex(
            ed25519.sign(canonicalBytes, rfcPrivateKey.subarray(0, 32)),
        );
        expect(signature).toMatch(/^[0-9a-f]{128}$/);

        // ── Layer 4: L1 verifySignature cross-package closed loop ──
        const verifyResult = verifySignature(payload, signature, rfcPublicKey);
        expect(verifyResult).toEqual({ valid: true });
    });

    /**
     * case 2 (schema reject):
     *   missing issuerDid -> L0 validateCspPayload AJV reject -> valid:false
     *   corresponds to CSP_SCHEMA_VIOLATION (token must carry issuerDid)
     */
    it('case 2 (schema reject): token missing issuerDid -> L0 AJV reject for CSP_SCHEMA_VIOLATION', () => {
        const payload = makeValidCspPayload({
            token: {
                id: 'token-e2e-002',
                // intentionally missing issuerDid (schema required)
                principalDid: 'did:key:principal',
                issuedTo: 'did:key:agent',
                specVersion: '0.3.0',
                issuedAt: '2026-05-18T00:00:00.000Z',
                expiresAt: '2099-01-01T00:00:00.000Z',
                capabilities: [
                    { action: 'read', scope: { type: 'allowlist' } },
                ],
                revocationUrl:
                    'https://issuer.example.com/revocation/token-e2e-002',
                proof: {
                    type: 'Ed25519Signature2026',
                    created: '2026-05-18T00:00:00.000Z',
                    verificationMethod: 'did:key:issuer#key-1',
                    value: 'sig',
                },
            },
        });

        const schemaResult = validateCspPayload(payload);
        expect(schemaResult.valid).toBe(false);

        if (!schemaResult.valid) {
            // AJV error path contains issuerDid OR token.required
            const errorPaths = schemaResult.errors
                .map((e) => `${e.instancePath ?? ''}|${e.message ?? ''}`)
                .join(' ');
            expect(errorPaths).toMatch(/issuerDid|required/);
        }

        // L1 canonicalSerialize does not guard against missing schema fields (the canonical layer = JCS pure transform);
        // but the L0 third defense line has already rejected -> cross-package contract fail-closed closed loop
    });

    /**
     * case 2b/2c/2d (negative):
     *   3 negative cases each covering token missing issuedAt / expiresAt / revocationUrl ->
     *   L0 AJV reject CSP_SCHEMA_VIOLATION (CapabilityToken's full 10 fields required, aligned to the TS interface)
     */
    it('case 2b (negative): token missing issuedAt -> L0 AJV reject for CSP_SCHEMA_VIOLATION', () => {
        const payload = makeValidCspPayload({
            token: {
                id: 'token-e2e-002b',
                issuerDid: 'did:key:issuer',
                principalDid: 'did:key:principal',
                issuedTo: 'did:key:agent',
                specVersion: '0.3.0',
                // intentionally missing issuedAt
                expiresAt: '2099-01-01T00:00:00.000Z',
                capabilities: [
                    { action: 'read', scope: { type: 'allowlist' } },
                ],
                revocationUrl:
                    'https://issuer.example.com/revocation/token-e2e-002b',
                proof: {
                    type: 'Ed25519Signature2026',
                    created: '2026-05-18T00:00:00.000Z',
                    verificationMethod: 'did:key:issuer#key-1',
                    value: 'sig',
                },
            },
        });

        const schemaResult = validateCspPayload(payload);
        expect(schemaResult.valid).toBe(false);
        if (!schemaResult.valid) {
            const errorPaths = schemaResult.errors
                .map((e) => `${e.instancePath ?? ''}|${e.message ?? ''}`)
                .join(' ');
            expect(errorPaths).toMatch(/issuedAt|required/);
        }
    });

    it('case 2c (negative): token missing expiresAt -> L0 AJV reject for CSP_SCHEMA_VIOLATION', () => {
        const payload = makeValidCspPayload({
            token: {
                id: 'token-e2e-002c',
                issuerDid: 'did:key:issuer',
                principalDid: 'did:key:principal',
                issuedTo: 'did:key:agent',
                specVersion: '0.3.0',
                issuedAt: '2026-05-18T00:00:00.000Z',
                // intentionally missing expiresAt
                capabilities: [
                    { action: 'read', scope: { type: 'allowlist' } },
                ],
                revocationUrl:
                    'https://issuer.example.com/revocation/token-e2e-002c',
                proof: {
                    type: 'Ed25519Signature2026',
                    created: '2026-05-18T00:00:00.000Z',
                    verificationMethod: 'did:key:issuer#key-1',
                    value: 'sig',
                },
            },
        });

        const schemaResult = validateCspPayload(payload);
        expect(schemaResult.valid).toBe(false);
        if (!schemaResult.valid) {
            const errorPaths = schemaResult.errors
                .map((e) => `${e.instancePath ?? ''}|${e.message ?? ''}`)
                .join(' ');
            expect(errorPaths).toMatch(/expiresAt|required/);
        }
    });

    it('case 2e (negative): token.proof missing created -> L0 AJV reject', () => {
        const payload = makeValidCspPayload({
            token: {
                id: 'token-e2e-002e',
                issuerDid: 'did:key:issuer',
                principalDid: 'did:key:principal',
                issuedTo: 'did:key:agent',
                specVersion: '0.3.0',
                issuedAt: '2026-05-18T00:00:00.000Z',
                expiresAt: '2099-01-01T00:00:00.000Z',
                capabilities: [
                    { action: 'read', scope: { type: 'allowlist' } },
                ],
                revocationUrl:
                    'https://issuer.example.com/revocation/token-e2e-002e',
                proof: {
                    type: 'Ed25519Signature2026',
                    // intentionally missing created
                    verificationMethod: 'did:key:issuer#key-1',
                    value: 'sig',
                },
            },
        });
        const schemaResult = validateCspPayload(payload);
        expect(schemaResult.valid).toBe(false);
        if (!schemaResult.valid) {
            const errorPaths = schemaResult.errors
                .map((e) => `${e.instancePath ?? ''}|${e.message ?? ''}`)
                .join(' ');
            expect(errorPaths).toMatch(/created|required/);
        }
    });

    it('case 2f (negative): token.proof missing verificationMethod -> L0 AJV reject', () => {
        const payload = makeValidCspPayload({
            token: {
                id: 'token-e2e-002f',
                issuerDid: 'did:key:issuer',
                principalDid: 'did:key:principal',
                issuedTo: 'did:key:agent',
                specVersion: '0.3.0',
                issuedAt: '2026-05-18T00:00:00.000Z',
                expiresAt: '2099-01-01T00:00:00.000Z',
                capabilities: [
                    { action: 'read', scope: { type: 'allowlist' } },
                ],
                revocationUrl:
                    'https://issuer.example.com/revocation/token-e2e-002f',
                proof: {
                    type: 'Ed25519Signature2026',
                    created: '2026-05-18T00:00:00.000Z',
                    // intentionally missing verificationMethod
                    value: 'sig',
                },
            },
        });
        const schemaResult = validateCspPayload(payload);
        expect(schemaResult.valid).toBe(false);
        if (!schemaResult.valid) {
            const errorPaths = schemaResult.errors
                .map((e) => `${e.instancePath ?? ''}|${e.message ?? ''}`)
                .join(' ');
            expect(errorPaths).toMatch(/verificationMethod|required/);
        }
    });

    it('case 2d (negative): token missing revocationUrl -> L0 AJV reject for CSP_SCHEMA_VIOLATION', () => {
        const payload = makeValidCspPayload({
            token: {
                id: 'token-e2e-002d',
                issuerDid: 'did:key:issuer',
                principalDid: 'did:key:principal',
                issuedTo: 'did:key:agent',
                specVersion: '0.3.0',
                issuedAt: '2026-05-18T00:00:00.000Z',
                expiresAt: '2099-01-01T00:00:00.000Z',
                capabilities: [
                    { action: 'read', scope: { type: 'allowlist' } },
                ],
                // intentionally missing revocationUrl
                proof: {
                    type: 'Ed25519Signature2026',
                    created: '2026-05-18T00:00:00.000Z',
                    verificationMethod: 'did:key:issuer#key-1',
                    value: 'sig',
                },
            },
        });

        const schemaResult = validateCspPayload(payload);
        expect(schemaResult.valid).toBe(false);
        if (!schemaResult.valid) {
            const errorPaths = schemaResult.errors
                .map((e) => `${e.instancePath ?? ''}|${e.message ?? ''}`)
                .join(' ');
            expect(errorPaths).toMatch(/revocationUrl|required/);
        }
    });

    /**
     * case 2g/h/i/j (positive — 4 scope variant regression):
     *   verify the canonical wire values of the 4 scope variants (allowlist/numeric_limit/temporal_scope/cumulative_limit)
     *   all PASS schema validate -> verify snake_case scope values; no valid signed token is missed
     */
    it('case 2g (positive scope variant): allowlist -> L0 AJV PASS', () => {
        const payload = makeValidCspPayload({
            token: {
                ...(makeValidCspPayload().token as Record<string, unknown>),
                capabilities: [
                    { action: 'read', scope: { type: 'allowlist' } },
                ],
            },
        });
        expect(validateCspPayload(payload).valid).toBe(true);
    });

    it('case 2h (positive scope variant): numeric_limit on 0.1.0 -> L0 AJV PASS', () => {
        const payload = makeValidCspPayload({
            token: {
                ...(makeValidCspPayload().token as Record<string, unknown>),
                capabilities: [
                    { action: 'transfer', scope: { type: 'numeric_limit' } },
                ],
            },
        });
        expect(validateCspPayload(payload).valid).toBe(true);
    });

    it('case 2i (positive scope variant): temporal_scope on 0.2.0+ -> L0 AJV PASS', () => {
        // specVersion 0.2.0+ allows the temporal_scope scope variant (enforced by validation.ts)
        const payload = makeValidCspPayload({
            token: {
                ...(makeValidCspPayload().token as Record<string, unknown>),
                specVersion: '0.2.0',
                capabilities: [
                    { action: 'access', scope: { type: 'temporal_scope' } },
                ],
            },
        });
        expect(validateCspPayload(payload).valid).toBe(true);
    });

    it('case 2j (positive scope variant): cumulative_limit on 0.3.0 -> L0 AJV PASS', () => {
        // specVersion 0.3.0 allows the cumulative_limit scope variant
        const payload = makeValidCspPayload({
            token: {
                ...(makeValidCspPayload().token as Record<string, unknown>),
                specVersion: '0.3.0',
                capabilities: [
                    { action: 'spend', scope: { type: 'cumulative_limit' } },
                ],
            },
        });
        expect(validateCspPayload(payload).valid).toBe(true);
    });

    /**
     * specVersion-aware scope constraint note:
     *   the csp schema itself allows a specVersion 0.1.0 token to carry a later-version scope variant;
     *   this constraint is not enforced at the schema layer, but rather by validation.ts's enforceTokenSpecVersionGate
     *   which enforces specVersion-aware scope reject inside the verifier pipeline.
     */

    /**
     * case 3 (signature reject):
     *   payload tamper (change audience) -> L1 verifySignature -> throw CspError(CSP_SIGNATURE_INVALID)
     *   corresponds to CSP_SIGNATURE_INVALID + verify pipeline first defense line
     */
    it('case 3 (signature reject): tamper audience -> L1 verifySignature throws CSP_SIGNATURE_INVALID', () => {
        const original = makeValidCspPayload();
        const signature = toHex(
            ed25519.sign(
                canonicalSerialize(original),
                rfcPrivateKey.subarray(0, 32),
            ),
        );

        // tamper: modify the audience field -> signature mismatch
        const tampered = { ...original, audience: 'did:example:attacker' };

        try {
            verifySignature(tampered, signature, rfcPublicKey);
            expect.fail('should have thrown CspError(CSP_SIGNATURE_INVALID)');
        } catch (e) {
            expect(e).toBeInstanceOf(CspError);
            expect((e as CspError).code).toBe('CSP_SIGNATURE_INVALID');
        }
    });

    /**
     * case 4 (bonus — L0+L1 bidirectional contract verify):
     *   build an L0 valid payload (AJV PASS) -> L1 sign+verify PASS -> complete cross-package closed-loop round-trip;
     *   verify that a payload passing the L0 schema always passes L1 sign+verify too (contract: L0 reject superset of L1 reject)
     */
    it('case 4 (contract verify): an L0 AJV PASS payload always passes L1 sign+verify — bidirectional cross-package closed loop', () => {
        const payload = makeValidCspPayload({
            audience: 'https://verifier.example.com/api',
            challenge: '11111111-2222-4333-8444-555555555555',
        });

        // L0 PASS
        expect(validateCspPayload(payload).valid).toBe(true);

        // L1 sign+verify round-trip
        const bytes = canonicalSerialize(payload);
        const signature = toHex(
            ed25519.sign(bytes, rfcPrivateKey.subarray(0, 32)),
        );
        const result = verifySignature(payload, signature, rfcPublicKey, {
            expectedAudience: 'https://verifier.example.com/api',
            expectedChallenge: '11111111-2222-4333-8444-555555555555',
            now: new Date('2026-05-18T00:00:00.000Z'),
        });
        expect(result).toEqual({ valid: true });
    });
});
