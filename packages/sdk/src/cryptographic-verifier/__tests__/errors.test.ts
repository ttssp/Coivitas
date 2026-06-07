/**
 * SdkError class unit test
 *
 * Test dimensions:
 * - extends Error pattern ( Alt α′ baseline)
 * - .code typed sub-code field
 * - .detail string
 * - .message format [<CODE>] <detail> ( hcc F1 lesson follow-up; regex-friendly)
 * - 6 frozen error code union literals
 */

import { describe, expect, it } from 'vitest';

import { SdkError, type SdkErrorCode } from '../errors.js';

describe('SdkError — class structure', () => {
    it('should be an Error instance when checking instanceof Error', () => {
        const err = new SdkError('SDK_JWT_VERIFY_FAILED', 'test detail');
        expect(err).toBeInstanceOf(Error);
        expect(err).toBeInstanceOf(SdkError);
    });

    it('should set name to "SdkError" when constructed', () => {
        const err = new SdkError('SDK_MAPPING_MISMATCH', 'detail');
        expect(err.name).toBe('SdkError');
    });

    it('should store typed code when constructed with each freeze code', () => {
        const codes: SdkErrorCode[] = [
            'SDK_MTLS_VERIFY_FAILED',
            'SDK_JWT_VERIFY_FAILED',
            'SDK_OAUTH2_VERIFY_FAILED',
            'SDK_MAPPING_MISMATCH',
            'SDK_SCHEMA_VIOLATION',
            'SDK_FIXTURE_CROSS_LANG_MISMATCH',
        ];
        for (const code of codes) {
            const err = new SdkError(code, 'detail');
            expect(err.code).toBe(code);
        }
    });

    it('should store detail when constructed', () => {
        const err = new SdkError('SDK_JWT_VERIFY_FAILED', 'exp expired');
        expect(err.detail).toBe('exp expired');
    });

    it('should format message as [<CODE>] <detail> when constructed', () => {
        const err = new SdkError('SDK_MTLS_VERIFY_FAILED', 'chain validation failed');
        expect(err.message).toBe(
            '[SDK_MTLS_VERIFY_FAILED] chain validation failed',
        );
    });

    it('should be regex-matchable on code prefix when checking toThrow pattern', () => {
        const fn = () => {
            throw new SdkError('SDK_OAUTH2_VERIFY_FAILED', 'active=false');
        };
        expect(fn).toThrow(/SDK_OAUTH2_VERIFY_FAILED/);
    });
});
