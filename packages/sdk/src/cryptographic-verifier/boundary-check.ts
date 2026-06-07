/**
 * sub-protocol L3 boundary check
 *
 * Summary: 4 boundary check functions — assertTrustedDidMatchesExpected (baseline) +
 *       assertTrustedDidIsKindAndFresh (4-dimension hardening) + extractDidFromCertSubjectDn +
 *       assertCrossCheckMappingConsistent (verifier kind / verifiedSubject consistency).
 *
 * Design intent (L3 boundary-layer guard; defense-in-depth):
 * - When a sub-protocol consumes a VerifiedTransportContext, re-verify at the boundary
 * - Even though the transport-layer verifier factory already enforces this, the sub-protocol
 *   boundary verifies again (to prevent transport context tampering / mocking / replay)
 */

import type { DID } from '@coivitas/types';

import type {
    VerifiedTransportContext,
    VerifierKind,
} from './verifier-types.js';
import type { TrustedSettlerDid } from './brand-types.js';

import { SdkError } from './errors.js';

const SDK_V0_2_VERSION = '2.0.0' as const;

/**
 * assertTrustedDidMatchesExpected — baseline boundary check pattern
 *
 * Design intent: when a sub-protocol consumes a TrustedSettlerDid, the boundary re-verifies
 *           that trustedDid is string-equal to expectedDid.
 */
export function assertTrustedDidMatchesExpected(
    trustedDid: TrustedSettlerDid,
    expectedDid: DID,
): void {
    if ((trustedDid as DID) !== expectedDid) {
        throw new SdkError(
            'SDK_MAPPING_MISMATCH',
            `TrustedSettlerDid boundary check failed: trustedDid (${trustedDid}) !== expectedDid (${expectedDid})`,
        );
    }
}

/**
 * assertTrustedDidIsKindAndFresh — hardened 4-dimension boundary check
 *
 * 4-dimension check:
 * 1. trustedDid string equality (baseline)
 * 2. verifierKind is within the expected kinds (guards against kind tampering / context mix-up)
 * 3. verifiedAt freshness (default 60s tolerance; guards against stale context replay)
 * 4. sdkVersion string equality "2.0.0" (guards against protocol version downgrade attack)
 *
 * @throws SdkError SDK_MAPPING_MISMATCH (DID mismatch / wrong kind) /
 *                  SDK_SCHEMA_VIOLATION (freshness / wrong sdkVersion)
 */
export function assertTrustedDidIsKindAndFresh(
    ctx: VerifiedTransportContext,
    expected: {
        did: DID;
        verifierKinds: readonly VerifierKind[];
        freshnessToleranceSeconds?: number;
    },
): void {
    // Step 1: trustedDid string equality
    if ((ctx.trustedDid as DID) !== expected.did) {
        throw new SdkError(
            'SDK_MAPPING_MISMATCH',
            `boundary check failed: ctx.trustedDid (${ctx.trustedDid}) !== expected.did (${expected.did})`,
        );
    }

    // Step 2: verifierKind is within the expected kinds
    if (!expected.verifierKinds.includes(ctx.verifierKind)) {
        throw new SdkError(
            'SDK_MAPPING_MISMATCH',
            `boundary check failed: ctx.verifierKind (${ctx.verifierKind}) not in expected kinds (${expected.verifierKinds.join(', ')})`,
        );
    }

    // Step 3: verifiedAt freshness (default 60s tolerance)
    const toleranceMs = (expected.freshnessToleranceSeconds ?? 60) * 1000;
    const verifiedAtMs = new Date(ctx.verifiedAt).getTime();
    if (Number.isNaN(verifiedAtMs)) {
        throw new SdkError(
            'SDK_SCHEMA_VIOLATION',
            `boundary check failed: ctx.verifiedAt (${ctx.verifiedAt}) is not a valid ISO 8601 timestamp`,
        );
    }
    const ageMs = Date.now() - verifiedAtMs;
    if (ageMs > toleranceMs) {
        throw new SdkError(
            'SDK_SCHEMA_VIOLATION',
            `boundary check failed: VerifiedTransportContext stale (age=${ageMs}ms > tolerance=${toleranceMs}ms; verifiedAt=${ctx.verifiedAt})`,
        );
    }
    if (ageMs < -toleranceMs) {
        // verifiedAt > now → clock skew / future timestamp (suspicious)
        throw new SdkError(
            'SDK_SCHEMA_VIOLATION',
            `boundary check failed: VerifiedTransportContext future timestamp (verifiedAt=${ctx.verifiedAt} > now)`,
        );
    }

    // Step 4: sdkVersion string equality (guards against protocol version downgrade)
    if (ctx.sdkVersion !== SDK_V0_2_VERSION) {
        throw new SdkError(
            'SDK_SCHEMA_VIOLATION',
            `boundary check failed: ctx.sdkVersion (${ctx.sdkVersion}) !== "${SDK_V0_2_VERSION}" (the only valid value for v0.2)`,
        );
    }
}

/**
 * extractDidFromCertSubjectDn — extract the DID token from an mtls cert subject DN string
 *
 * Design intent:
 * - The old cross-check only did a substring `subject.includes('did:')` → an attacker could craft
 *   trustedDid = did:tenantA + verifiedSubject = "CN=did:tenantB, OU=spoofed", which passes the
 *   substring check but whose actual DID does not match → breaking the cross-check mapping invariant
 * - This function extracts the DID + does an equality compare, fail-closed (multiple conflicting DIDs / not found → throw)
 *
 * Function naming:
 * - mtls-helpers.ts `extractDidFromCertSubject(cert: X509Certificate)` — factory entry point (X509 cert object)
 * - this function `extractDidFromCertSubjectDn(subject: string)` — boundary entry point (DN string; already serialized)
 *
 * Extraction SOP (RFC 4514 LDAP DN + RFC 5280 SAN URI dual anchor):
 * - prefer SAN URI did:scheme:id (RFC 5280)
 * - fallback CN=did:method:id (legacy cert format)
 *
 * DID character set — method `[a-z0-9]+` + method-specific-id `[a-zA-Z0-9._%-]+`
 *
 * @throws SdkError 'SDK_SCHEMA_VIOLATION' on parse fail / DID not found / multiple conflicting DIDs
 */
export function extractDidFromCertSubjectDn(subject: string): string {
    const didTokenPattern = String.raw`did:[a-z0-9]+:[a-zA-Z0-9._%-]+`;

    // strategy 1: SAN URI did:scheme:id (RFC 5280)
    const sanUriRegex = new RegExp(
        String.raw`(?:^|[\s,])URI(?:=|:)\s*(${didTokenPattern})`,
        'g',
    );
    const sanMatches = Array.from(subject.matchAll(sanUriRegex))
        .map((m) => m[1])
        .filter((x): x is string => typeof x === 'string');

    if (sanMatches.length > 1) {
        // Multiple SAN URI dids: distinct DID conflicts are not allowed (fail-closed)
        const uniq = new Set(sanMatches);
        if (uniq.size > 1) {
            throw new SdkError(
                'SDK_SCHEMA_VIOLATION',
                `mtls cert subject contains multiple distinct DIDs via SAN URI: ${Array.from(uniq).join(', ')}`,
            );
        }
    }
    if (sanMatches.length >= 1) {
        const first = sanMatches[0];
        if (first) return first;
    }

    // strategy 2: CN=did:method:id (legacy fallback;RFC 4514 LDAP DN)
    const cnDidRegex = new RegExp(
        String.raw`(?:^|[\s,])CN=\s*(${didTokenPattern})`,
    );
    const cnMatch = subject.match(cnDidRegex);
    if (cnMatch && cnMatch[1]) {
        return cnMatch[1];
    }

    // strategy 3: no DID found → fail-closed
    throw new SdkError(
        'SDK_SCHEMA_VIOLATION',
        `mtls cert subject (${subject}) does not contain a valid DID token (expected SAN URI did:<method>:<id> OR CN=did:<method>:<id>)`,
    );
}

/**
 * assertCrossCheckMappingConsistent — verifier kind / verifiedSubject consistency
 *
 * Design intent: prevent verifier kind / verifiedSubject type mix-up
 * - mtls kind → verifiedSubject is a cert subject DN string; extract DID + equality compare
 * - jwt kind → verifiedSubject must be === trustedDid (JWT sub claim already verified)
 * - oauth2 kind → verifiedSubject must be === trustedDid (introspection client_id/sub already verified)
 *
 * Hardening — mtls no longer does a substring check only; it extracts the DID + equality compare
 *
 * @throws SdkError SDK_MAPPING_MISMATCH / SDK_SCHEMA_VIOLATION
 */
export function assertCrossCheckMappingConsistent(
    ctx: VerifiedTransportContext,
): void {
    if (ctx.verifierKind === 'mtls') {
        const subject = ctx.verifiedSubject as string;
        if (!subject || subject.length === 0) {
            throw new SdkError(
                'SDK_SCHEMA_VIOLATION',
                'mtls kind: verifiedSubject empty (expected CertSubjectDn)',
            );
        }
        // Hardening — extract DID + equality compare
        const extractedDid = extractDidFromCertSubjectDn(subject);
        if (extractedDid !== (ctx.trustedDid as string)) {
            throw new SdkError(
                'SDK_MAPPING_MISMATCH',
                `mtls kind: extracted DID (${extractedDid}) from verifiedSubject (${subject}) !== trustedDid (${ctx.trustedDid})`,
            );
        }
        return;
    }

    if (ctx.verifierKind === 'jwt' || ctx.verifierKind === 'oauth2') {
        // jwt / oauth2: verifiedSubject is string-equal to trustedDid
        if ((ctx.verifiedSubject as string) !== (ctx.trustedDid as string)) {
            throw new SdkError(
                'SDK_MAPPING_MISMATCH',
                `${ctx.verifierKind} kind: verifiedSubject (${ctx.verifiedSubject}) !== trustedDid (${ctx.trustedDid})`,
            );
        }
        return;
    }

    // Unreachable (VerifierKind has only 3 values; this is a fail-closed fallback)
    throw new SdkError(
        'SDK_SCHEMA_VIOLATION',
        `unknown verifierKind: ${String(ctx.verifierKind)}`,
    );
}
