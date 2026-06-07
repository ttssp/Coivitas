/**
 * multi-version-validators unit tests
 *
 * Coverage:
 *   1. xv-03 / xv-06 happy path (already integration-verified by conformance-suite.test.ts)
 *   2. unknown validatorVersion → throw (fail-closed, to avoid silently falling back to v0.3.0)
 *   3. schemaId outside the coverage set → return null (let the caller fall back)
 *   4. isSupportedValidatorVersion type guard
 */

import { describe, expect, it } from 'vitest';

import {
    isSupportedValidatorVersion,
    validateAgainstVersionedSchema,
    type ValidatorVersion,
} from './multi-version-validators.js';

describe('multi-version-validators (regression)', () => {
    describe('isSupportedValidatorVersion', () => {
        it('should return true for 0.1.0 / 0.2.0 / 0.3.0', () => {
            expect(isSupportedValidatorVersion('0.1.0')).toBe(true);
            expect(isSupportedValidatorVersion('0.2.0')).toBe(true);
            expect(isSupportedValidatorVersion('0.3.0')).toBe(true);
        });

        it('should return false for unsupported versions', () => {
            expect(isSupportedValidatorVersion('0.4.0')).toBe(false);
            expect(isSupportedValidatorVersion('1.0.0')).toBe(false);
            expect(isSupportedValidatorVersion('')).toBe(false);
            expect(isSupportedValidatorVersion('typo')).toBe(false);
        });
    });

    describe('validateAgainstVersionedSchema fail-closed', () => {
        const minimalEnvelope = {
            id: '550e8400-e29b-41d4-a716-09b200000003',
            specVersion: '0.3.0',
            header: {
                senderDid: 'did:agent:a3f1b2c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0',
                recipientDid:
                    'did:agent:b4e2c3d5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1',
                sessionId: '550e8400-e29b-41d4-a716-09b200000003',
                sequenceNumber: 1,
            },
            messageType: 'NEGOTIATION_REQUEST',
            body: { action: 'INQUIRY' },
        };

        it('should throw when validatorVersion is not supported (typo / future version)', () => {
            // Key: fail-closed ensures the acceptance gate does not silently fall back to v0.3.0 due to a typo
            expect(() =>
                validateAgainstVersionedSchema(
                    minimalEnvelope,
                    'negotiationEnvelope',
                    '0.4.0' as ValidatorVersion, // typo
                ),
            ).toThrow(/unsupported validatorVersion='0\.4\.0'/);

            expect(() =>
                validateAgainstVersionedSchema(
                    minimalEnvelope,
                    'negotiationEnvelope',
                    'invalid-version' as ValidatorVersion,
                ),
            ).toThrow(/unsupported validatorVersion/);
        });

        it('should return null for schemaId outside coverage set (caller fallback)', () => {
            const result = validateAgainstVersionedSchema(
                {},
                'capabilityToken', // not in the negotiationEnvelope/actionRecord coverage set
                '0.1.0',
            );
            expect(result).toBeNull();
        });

        it('should reject v0.3.0 envelope under v0.1.0 validator (xv-03 specVersion enum)', () => {
            const result = validateAgainstVersionedSchema(
                minimalEnvelope,
                'negotiationEnvelope',
                '0.1.0',
            );
            expect(result).not.toBeNull();
            expect(result?.valid).toBe(false);
            // expectedError contains 'specVersion must be equal to one of the allowed values'
            const allMessages = result?.errors
                .map((e) => e.message)
                .join(' | ');
            expect(allMessages).toMatch(/specVersion|allowed values/i);
        });
    });
});
