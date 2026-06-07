/**
 * sub-protocol L0 boundary wrapper unit test
 *
 * Test dimensions:
 * - wrapSubProtocolBoundary — catches the 6 sub-protocol L0 error classes + unwraps as ProtocolError
 * - ProtocolError pass-through (not wrapped in another layer)
 * - Other unknown errors → fallback ProtocolError('INTERNAL_ERROR', ...)
 * - requestId field pass-through (audit log correlation)
 * - The synchronous variant wrapSubProtocolBoundarySync is covered as well
 */

import { describe, expect, it } from 'vitest';

import {
    AuditError,
    AuditShareError,
    CrError,
    DaError,
    HashChainError,
    ProtocolError,
    SrError,
} from '@coivitas/types';

import {
    isSubProtocolL0Error,
    subProtocolErrorCode,
    wrapSubProtocolBoundary,
    wrapSubProtocolBoundarySync,
} from '../transport/sub-protocol-boundary.js';

describe('isSubProtocolL0Error — type guard', () => {
    it('should return true when error is CrError', () => {
        const err = new CrError('CR_OIDC_CLAIM_INVALID');
        expect(isSubProtocolL0Error(err)).toBe(true);
    });

    it('should return true when error is HashChainError', () => {
        const err = new HashChainError('HC_PREVIOUS_HASH_BROKEN', 'msg');
        expect(isSubProtocolL0Error(err)).toBe(true);
    });

    it('should return true when error is AuditShareError', () => {
        const err = new AuditShareError(
            'AUDIT_SHARE_SCHEMA_INVALID',
            'msg',
        );
        expect(isSubProtocolL0Error(err)).toBe(true);
    });

    it('should return true when error is AuditError', () => {
        const err = new AuditError('AUDIT_HASH_CHAIN_BROKEN', 'detail');
        expect(isSubProtocolL0Error(err)).toBe(true);
    });

    it('should return true when error is SrError', () => {
        const err = new SrError('SR_RETRY_EXHAUSTED');
        expect(isSubProtocolL0Error(err)).toBe(true);
    });

    it('should return true when error is DaError', () => {
        const err = new DaError('DA_STATE_TRANSITION_INVALID');
        expect(isSubProtocolL0Error(err)).toBe(true);
    });

    it('should return false when error is generic Error', () => {
        expect(isSubProtocolL0Error(new Error('generic'))).toBe(false);
    });

    it('should return false when error is ProtocolError', () => {
        expect(
            isSubProtocolL0Error(new ProtocolError('INTERNAL_ERROR', 'msg')),
        ).toBe(false);
    });

    it('should return false when value is non-Error (string/number/null)', () => {
        expect(isSubProtocolL0Error('string')).toBe(false);
        expect(isSubProtocolL0Error(42)).toBe(false);
        expect(isSubProtocolL0Error(null)).toBe(false);
        expect(isSubProtocolL0Error(undefined)).toBe(false);
    });
});

describe('subProtocolErrorCode — sub-code extraction', () => {
    it('should return SR_RETRY_EXHAUSTED when err is SrError with that code', () => {
        expect(subProtocolErrorCode(new SrError('SR_RETRY_EXHAUSTED'))).toBe(
            'SR_RETRY_EXHAUSTED',
        );
    });

    it('should return HC_PREVIOUS_HASH_BROKEN when err is HashChainError with that code', () => {
        expect(
            subProtocolErrorCode(
                new HashChainError('HC_PREVIOUS_HASH_BROKEN', 'msg'),
            ),
        ).toBe('HC_PREVIOUS_HASH_BROKEN');
    });
});

describe('wrapSubProtocolBoundary — async wrapper', () => {
    it('should pass through return value when op succeeds', async () => {
        const result = await wrapSubProtocolBoundary(async () => 42);
        expect(result).toBe(42);
    });

    it('should re-throw ProtocolError unchanged when op throws ProtocolError', async () => {
        const original = new ProtocolError('INVALID_MESSAGE', 'bad input', 'req-1');
        await expect(
            wrapSubProtocolBoundary(async () => {
                throw original;
            }),
        ).rejects.toBe(original);
    });

    it('should unwrap SrError as ProtocolError INTERNAL_ERROR when op throws SrError', async () => {
        const inner = new SrError('SR_RETRY_EXHAUSTED');
        await expect(
            wrapSubProtocolBoundary(async () => {
                throw inner;
            }),
        ).rejects.toBeInstanceOf(ProtocolError);

        try {
            await wrapSubProtocolBoundary(async () => {
                throw inner;
            });
        } catch (err) {
            expect(err).toBeInstanceOf(ProtocolError);
            expect((err as ProtocolError).code).toBe('INTERNAL_ERROR');
            expect((err as ProtocolError).detail).toContain('SR_RETRY_EXHAUSTED');
        }
    });

    it.each<[string, () => Error]>([
        ['CrError', () => new CrError('CR_OIDC_CLAIM_INVALID')],
        [
            'HashChainError',
            () => new HashChainError('HC_PREVIOUS_HASH_BROKEN', 'm'),
        ],
        [
            'AuditShareError',
            () => new AuditShareError('AUDIT_SHARE_SCHEMA_INVALID', 'm'),
        ],
        ['AuditError', () => new AuditError('AUDIT_HASH_CHAIN_BROKEN', 'd')],
        ['SrError', () => new SrError('SR_RETRY_EXHAUSTED')],
        ['DaError', () => new DaError('DA_STATE_TRANSITION_INVALID')],
    ])(
        'should unwrap %s as ProtocolError INTERNAL_ERROR with sub-code in detail',
        async (_name, makeErr) => {
            const inner = makeErr();
            try {
                await wrapSubProtocolBoundary(async () => {
                    throw inner;
                });
                expect.fail('expected throw');
            } catch (err) {
                expect(err).toBeInstanceOf(ProtocolError);
                const pe = err as ProtocolError;
                expect(pe.code).toBe('INTERNAL_ERROR');
                // detail contains the original sub-code (CR_* / HC_* / AUDIT_SHARE_* / AUDIT_* / SR_* / DA_*)
                expect(pe.detail).toMatch(
                    /^(CR|HC|AUDIT_SHARE|AUDIT|SR|DA)_/,
                );
            }
        },
    );

    it('should preserve requestId when wrapping sub-protocol error', async () => {
        try {
            await wrapSubProtocolBoundary(async () => {
                throw new SrError('SR_RETRY_EXHAUSTED');
            }, 'req-xyz');
            expect.fail('expected throw');
        } catch (err) {
            expect(err).toBeInstanceOf(ProtocolError);
            expect((err as ProtocolError).requestId).toBe('req-xyz');
        }
    });

    it('should wrap unknown Error as ProtocolError INTERNAL_ERROR with unknown prefix', async () => {
        try {
            await wrapSubProtocolBoundary(async () => {
                throw new Error('something else broke');
            });
            expect.fail('expected throw');
        } catch (err) {
            expect(err).toBeInstanceOf(ProtocolError);
            const pe = err as ProtocolError;
            expect(pe.code).toBe('INTERNAL_ERROR');
            expect(pe.detail).toContain('something else broke');
        }
    });

    it('should wrap non-Error throws as ProtocolError INTERNAL_ERROR', async () => {
        try {
            await wrapSubProtocolBoundary(async () => {
                // eslint-disable-next-line @typescript-eslint/only-throw-error
                throw 'string-throw';
            });
            expect.fail('expected throw');
        } catch (err) {
            expect(err).toBeInstanceOf(ProtocolError);
            expect((err as ProtocolError).detail).toContain('string-throw');
        }
    });
});

describe('wrapSubProtocolBoundarySync — sync wrapper', () => {
    it('should pass through return value when sync op succeeds', () => {
        const result = wrapSubProtocolBoundarySync(() => 'ok');
        expect(result).toBe('ok');
    });

    it('should re-throw ProtocolError unchanged when sync op throws ProtocolError', () => {
        const original = new ProtocolError('INVALID_MESSAGE', 'bad');
        expect(() =>
            wrapSubProtocolBoundarySync(() => {
                throw original;
            }),
        ).toThrow(original);
    });

    it('should unwrap CrError as ProtocolError INTERNAL_ERROR when sync op throws CrError', () => {
        expect(() =>
            wrapSubProtocolBoundarySync(() => {
                throw new CrError('CR_OIDC_CLAIM_INVALID');
            }),
        ).toThrow(ProtocolError);

        try {
            wrapSubProtocolBoundarySync(() => {
                throw new CrError('CR_OIDC_CLAIM_INVALID');
            });
        } catch (err) {
            expect((err as ProtocolError).detail).toContain(
                'CR_OIDC_CLAIM_INVALID',
            );
        }
    });
});
