/**
 * jwt-helpers unit test — JWT alg allowlist / denylist enforce
 *
 * Test dimensions:
 * - asymmetric default: RS256 / ES256 / EdDSA → PASS
 * - symmetric_restricted: HS256 (rejected by default; PASS when allowSymmetric=true)
 * - denylist: 'none' / 'NONE' / 'None' → reject
 * - malformed input: no header / malformed header / non-string alg / empty alg → reject
 */

import { describe, expect, it } from 'vitest';

import { SdkError } from '../errors.js';
import {
    JWT_ALG_ALLOWLIST,
    JWT_ALG_DENYLIST,
    verifyJwtAlgAllowed,
} from '../jwt-helpers.js';

/** Builds a fake JWT (header.payload.signature) — only the header segment is valid; signature is not verified */
function fakeJwt(headerObj: Record<string, unknown>): string {
    const header = Buffer.from(JSON.stringify(headerObj)).toString('base64url');
    const payload = Buffer.from(JSON.stringify({ sub: 'did:web:x' })).toString(
        'base64url',
    );
    const signature = 'fake-signature';
    return `${header}.${payload}.${signature}`;
}

describe('JWT_ALG_ALLOWLIST constant', () => {
    it('should contain RS256 ES256 EdDSA when checking asymmetric', () => {
        expect(JWT_ALG_ALLOWLIST.asymmetric).toContain('RS256');
        expect(JWT_ALG_ALLOWLIST.asymmetric).toContain('ES256');
        expect(JWT_ALG_ALLOWLIST.asymmetric).toContain('EdDSA');
    });

    it('should contain HS256 HS384 HS512 when checking symmetric_restricted', () => {
        expect(JWT_ALG_ALLOWLIST.symmetric_restricted).toContain('HS256');
        expect(JWT_ALG_ALLOWLIST.symmetric_restricted).toContain('HS384');
        expect(JWT_ALG_ALLOWLIST.symmetric_restricted).toContain('HS512');
    });
});

describe('JWT_ALG_DENYLIST constant', () => {
    it('should contain none NONE None when checking case variants', () => {
        expect(JWT_ALG_DENYLIST).toEqual(['none', 'NONE', 'None']);
    });
});

describe('verifyJwtAlgAllowed — asymmetric default', () => {
    it('should pass when alg is RS256', () => {
        expect(() => verifyJwtAlgAllowed(fakeJwt({ alg: 'RS256' }))).not.toThrow();
    });

    it('should pass when alg is ES256', () => {
        expect(() => verifyJwtAlgAllowed(fakeJwt({ alg: 'ES256' }))).not.toThrow();
    });

    it('should pass when alg is EdDSA', () => {
        expect(() => verifyJwtAlgAllowed(fakeJwt({ alg: 'EdDSA' }))).not.toThrow();
    });

    it('should reject HS256 when allowSymmetric is false (default)', () => {
        expect(() => verifyJwtAlgAllowed(fakeJwt({ alg: 'HS256' }))).toThrow(
            SdkError,
        );
        expect(() => verifyJwtAlgAllowed(fakeJwt({ alg: 'HS256' }))).toThrow(
            /SDK_JWT_VERIFY_FAILED/,
        );
    });
});

describe('verifyJwtAlgAllowed — symmetric_restricted opt-in', () => {
    it('should pass HS256 when allowSymmetric is true', () => {
        expect(() =>
            verifyJwtAlgAllowed(fakeJwt({ alg: 'HS256' }), {
                allowSymmetric: true,
            }),
        ).not.toThrow();
    });

    it('should still pass RS256 when allowSymmetric is true (union)', () => {
        expect(() =>
            verifyJwtAlgAllowed(fakeJwt({ alg: 'RS256' }), {
                allowSymmetric: true,
            }),
        ).not.toThrow();
    });
});

describe('verifyJwtAlgAllowed — denylist enforce', () => {
    it.each(['none', 'NONE', 'None'])(
        'should reject denylist alg %s when checking RFC 7518 none attack',
        (alg) => {
            expect(() =>
                verifyJwtAlgAllowed(fakeJwt({ alg }), {
                    allowSymmetric: true, // rejected even when allowSymmetric=true
                }),
            ).toThrow(/denylist/);
        },
    );
});

describe('verifyJwtAlgAllowed — malformed input', () => {
    it('should reject when JWT has no segments', () => {
        expect(() => verifyJwtAlgAllowed('')).toThrow(
            /no header segment|JWT compact serialization invalid/,
        );
    });

    it('should reject when JWT header is invalid base64url', () => {
        expect(() => verifyJwtAlgAllowed('!!notbase64!!.payload.sig')).toThrow(
            /decode|parse/,
        );
    });

    it('should reject when JWT header alg is missing', () => {
        expect(() => verifyJwtAlgAllowed(fakeJwt({}))).toThrow(
            /alg missing/,
        );
    });

    it('should reject when JWT header alg is empty string', () => {
        expect(() => verifyJwtAlgAllowed(fakeJwt({ alg: '' }))).toThrow(
            /alg missing/,
        );
    });

    it('should reject when JWT header alg is not string', () => {
        expect(() => verifyJwtAlgAllowed(fakeJwt({ alg: 123 }))).toThrow(
            /alg missing|not string/,
        );
    });

    it('should reject unknown alg KEYAK256 when checking allowlist', () => {
        expect(() =>
            verifyJwtAlgAllowed(fakeJwt({ alg: 'KEYAK256' })),
        ).toThrow(/not in allowlist/);
    });
});
