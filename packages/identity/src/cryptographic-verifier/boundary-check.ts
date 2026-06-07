/**
 * boundary-check — the boundary check pattern for sub-protocols that literally consume TrustedSettlerDid
 *
 * Summary: L3 boundary-layer guard; 4 functions implement the sdk v0.2 boundary check:
 *   - assertTrustedDidMatchesExpected: basic DID equality check
 *   - assertTrustedDidIsKindAndFresh: 4-dimension check — DID + kind + freshness + sdkVersion
 *   - extractDidFromCertSubjectDn: cert subject DN string -> DID extraction
 *   - assertCrossCheckMappingConsistent: verifier kind / verifiedSubject type cross-check
 *
 * Basis:
 *   - boundary check pattern
 *   - sr v0.1 step 4 audience cross-check pattern
 *   - STRIDE Repudiation dimension (freshness check)
 *   - mtls requires DID extraction + literal equality compare; no substring check allowed
 *   - the extractDidFromCertSubjectDn function name is distinct from extractDidFromCertSubject
 *
 * Security constraints:
 *   - assertTrustedDidMatchesExpected: DID mismatch -> throw SDK_MAPPING_MISMATCH
 *   - assertTrustedDidIsKindAndFresh: verifier kind mismatch -> throw SDK_MAPPING_MISMATCH
 *   - assertTrustedDidIsKindAndFresh: freshness stale (> 60s) -> throw SDK_SCHEMA_VIOLATION
 *   - assertTrustedDidIsKindAndFresh: future timestamp -> throw SDK_SCHEMA_VIOLATION
 *   - assertTrustedDidIsKindAndFresh: sdkVersion !== "2.0.0" -> throw SDK_SCHEMA_VIOLATION
 *   - extractDidFromCertSubjectDn: multiple DID conflict -> throw SDK_SCHEMA_VIOLATION
 *   - extractDidFromCertSubjectDn: DID not found -> throw SDK_SCHEMA_VIOLATION
 *   - assertCrossCheckMappingConsistent: mtls requires extractDidFromCertSubjectDn + literal equality -> throw SDK_MAPPING_MISMATCH
 */

import type { DID, VerifiedTransportContext } from '@coivitas/types';
import { SdkError } from '@coivitas/types';

// ─── assertTrustedDidMatchesExpected ─────────────────────────────────────────

/**
 * assertTrustedDidMatchesExpected — basic TrustedSettlerDid DID equality boundary check
 *
 * Summary: the simplest L3 boundary-layer check — trustedDid === expectedDid literal equality;
 * on mismatch, throw SDK_MAPPING_MISMATCH.
 * Follows the sr v0.1 step 4 audience cross-check pattern.
 *
 * @param trustedDid VerifiedTransportContext.trustedDid (derived by the cryptographic verifier)
 * @param expectedDid the expected DID (derived from the cryptographic authenticated context; must not be derived from the signedPayload body)
 * @throws SdkError 'SDK_MAPPING_MISMATCH' trustedDid !== expectedDid
 */
export function assertTrustedDidMatchesExpected(
    trustedDid: VerifiedTransportContext['trustedDid'],
    expectedDid: DID,
): void {
    if ((trustedDid as string) !== (expectedDid as string)) {
        throw new SdkError(
            'SDK_MAPPING_MISMATCH',
            `TrustedSettlerDid boundary check failed: trustedDid (${trustedDid}) !== expectedDid (${expectedDid})`,
        );
    }
}

// ─── assertTrustedDidIsKindAndFresh ──────────────────────────────────────────

/**
 * assertTrustedDidIsKindAndFresh — 4-dimension boundary check (fully detailed version)
 *
 * Summary: 4 dimensions checked in sequence:
 *   1. trustedDid literal equality (basic)
 *   2. verifierKind within expected kinds (anti transport-context kind tampering)
 *   3. verifiedAt freshness (default 60s tolerance; anti stale-context replay)
 *   4. sdkVersion === "2.0.0" (anti protocol-version downgrade attack)
 *
 * Basis:
 *   - sr v0.1 step 4 audience cross-check pattern
 *   - audit-share v0.3 step 0 cryptographic enforce
 *   - STRIDE Repudiation dimension (freshness check)
 *
 * @param ctx VerifiedTransportContext (produced by the transport-layer verifier factory)
 * @param expected expected DID + expected verifier kinds + freshness tolerance
 * @throws SdkError 'SDK_MAPPING_MISMATCH' DID mismatch / verifier kind mismatch
 * @throws SdkError 'SDK_SCHEMA_VIOLATION' freshness stale / future timestamp / sdkVersion mismatch
 */
export function assertTrustedDidIsKindAndFresh(
    ctx: VerifiedTransportContext,
    expected: {
        did: DID;
        verifierKinds: readonly ('mtls' | 'jwt' | 'oauth2')[];
        /** freshness tolerance (seconds; default 60s)*/
        freshnessToleranceSeconds?: number;
    },
): void {
    // Check 1: trustedDid literal equality (basic boundary)
    if ((ctx.trustedDid as string) !== (expected.did as string)) {
        throw new SdkError(
            'SDK_MAPPING_MISMATCH',
            `boundary check failed: ctx.trustedDid (${ctx.trustedDid}) !== expected.did (${expected.did})`,
        );
    }

    // Check 2: verifierKind within expected kinds (anti transport-context kind tampering/reuse)
    if (!expected.verifierKinds.includes(ctx.verifierKind)) {
        throw new SdkError(
            'SDK_MAPPING_MISMATCH',
            `boundary check failed: ctx.verifierKind (${ctx.verifierKind}) not in expected kinds (${expected.verifierKinds.join(', ')})`,
        );
    }

    // Check 3: verifiedAt freshness (anti stale-context replay; STRIDE Repudiation)
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
        // verifiedAt too old -> stale-context replay risk
        throw new SdkError(
            'SDK_SCHEMA_VIOLATION',
            `boundary check failed: VerifiedTransportContext stale (age=${ageMs}ms > tolerance=${toleranceMs}ms; verifiedAt=${ctx.verifiedAt})`,
        );
    }

    if (ageMs < -toleranceMs) {
        // verifiedAt in the future -> suspicious clock skew / future-timestamp attack
        throw new SdkError(
            'SDK_SCHEMA_VIOLATION',
            `boundary check failed: VerifiedTransportContext future timestamp (verifiedAt=${ctx.verifiedAt} is in the future)`,
        );
    }

    // Check 4: sdkVersion === "2.0.0" (I9 invariant — anti protocol-version downgrade attack)
    if (ctx.sdkVersion !== '2.0.0') {
        throw new SdkError(
            'SDK_SCHEMA_VIOLATION',
            `boundary check failed: ctx.sdkVersion (${ctx.sdkVersion}) !== "2.0.0" (the only legal value for v0.2)`,
        );
    }
}

// ─── extractDidFromCertSubjectDn ─────────────────────────────────────────────

/**
 * extractDidFromCertSubjectDn — cert subject DN string -> DID token extraction (boundary-check-specific)
 *
 * Summary: a boundary-check.ts-specific entry point, accepting a cert subject DN string (already serialized);
 * it and mtls-helpers.ts's extractDidFromCertSubject(X509Certificate) are two literally distinct functions,
 * corresponding to different call levels (inside the verifier factory vs the boundary-check boundary).
 *
 * Naming distinction:
 *   - `extractDidFromCertSubject(cert: X509Certificate)` — inside the verifier factory (X509 cert object)
 *   - `extractDidFromCertSubjectDn(subject: string)` — at the boundary-check boundary (literal DN string)
 *
 * DID regex:
 *   method part: `[a-z0-9]+` (lowercase alphanumeric)
 *   method-specific-id part: `[a-zA-Z0-9._%-]+` (RFC 3986 unreserved + percent-encoded + '.', '_', '-')
 *   e.g. `did:web:example.com` / `did:web:example.com%3A8080` / `did:key:z6Mk...`
 *
 * Extraction strategy (RFC 5280 SAN URI preferred; RFC 4514 CN= fallback):
 *   Strategy 1: `URI=did:...` or `URI:did:...` (SAN URI serialize format)
 *   Strategy 2: `CN=did:...` (LDAP DN CN= field fallback)
 *   Multiple SAN URI DID conflict (different DIDs) -> throw SDK_SCHEMA_VIOLATION (fail-closed)
 *
 * @param subject cert subject DN string (RFC 4514 LDAP DN format; e.g. "CN=did:example:123, O=Acme")
 * @throws SdkError 'SDK_SCHEMA_VIOLATION' DID not found / multiple DID URI conflict
 */
export function extractDidFromCertSubjectDn(subject: string): string {
    // DID Core spec method-specific-id character set
    const didTokenPattern = String.raw`did:[a-z0-9]+:[a-zA-Z0-9._%-]+`;

    // Strategy 1: SAN URI did:scheme:id (RFC 5280 SAN URI; higher priority than CN=)
    // cert subject DN string format: "CN=..., URI=did:..." or "URI:did:..."
    const sanUriRegex = new RegExp(
        String.raw`(?:^|[\s,])URI(?:=|:)\s*(${didTokenPattern})`,
        'g',
    );
    const sanMatches = Array.from(subject.matchAll(sanUriRegex)).map(
        (m) => m[1]!,
    );

    if (sanMatches.length > 1) {
        // Multiple SAN URI DIDs — check for conflict (different DIDs -> fail-closed)
        const uniq = new Set(sanMatches);
        if (uniq.size > 1) {
            throw new SdkError(
                'SDK_SCHEMA_VIOLATION',
                `mtls cert subject contains multiple distinct DID via SAN URI: ${Array.from(uniq).join(', ')} (expected exactly one)`,
            );
        }
    }

    if (sanMatches.length >= 1) {
        // SAN URI hit (single DID, or multiple SANs but the same DID)
        return sanMatches[0]!;
    }

    // Strategy 2: CN=did:<method>:<id> fallback (RFC 4514 LDAP DN CN field)
    const cnDidRegex = new RegExp(
        String.raw`(?:^|[\s,])CN=\s*(${didTokenPattern})`,
    );
    const cnMatch = subject.match(cnDidRegex);
    if (cnMatch?.[1]) {
        return cnMatch[1];
    }

    // Strategy 3: DID not discoverable -> fail-closed
    throw new SdkError(
        'SDK_SCHEMA_VIOLATION',
        `mtls cert subject (${subject}) does not contain a valid DID token (expected SAN URI "did:<method>:<id>" OR CN="did:<method>:<id>")`,
    );
}

// ─── assertCrossCheckMappingConsistent ───────────────────────────────────────

/**
 * assertCrossCheckMappingConsistent — verifier kind / verifiedSubject type cross-check
 *
 * Summary: defense-in-depth — literal cross-check of verifier kind against verifiedSubject, preventing kind/subject type mix-up.
 * The mtls path no longer relies on a substring check alone; it requires extractDidFromCertSubjectDn + literal equality compare.
 *
 * Check rules:
 *   - mtls kind: verifiedSubject must be a non-empty cert subject DN string -> extractDidFromCertSubjectDn -> literal equality compare to trustedDid
 *   - jwt kind: verifiedSubject literally === trustedDid (JWT payload.sub direct mapping)
 *   - oauth2 kind: verifiedSubject literally === trustedDid (introspection client_id/sub direct mapping)
 *
 * Basis:
 *   - I8 VerifiedTransportContext 5-field completeness
 *   - I3/I5/I7 cross-check mapping literal equality
 *
 * @param ctx VerifiedTransportContext (produced by the transport-layer verifier factory)
 * @throws SdkError 'SDK_SCHEMA_VIOLATION' verifiedSubject empty / unknown verifierKind
 * @throws SdkError 'SDK_MAPPING_MISMATCH' DID mismatch
 */
export function assertCrossCheckMappingConsistent(
    ctx: VerifiedTransportContext,
): void {
    if (ctx.verifierKind === 'mtls') {
        // mtls: verifiedSubject is a cert subject DN string
        const subject = ctx.verifiedSubject as string;
        if (!subject || subject.length === 0) {
            throw new SdkError(
                'SDK_SCHEMA_VIOLATION',
                'mtls kind: verifiedSubject empty (expected CertSubjectDn string)',
            );
        }
        // Requires extractDidFromCertSubjectDn + literal equality compare
        // Call extractDidFromCertSubjectDn (the string DN variant; distinct from the X509Certificate variant)
        const extractedDid = extractDidFromCertSubjectDn(subject);
        if (extractedDid !== (ctx.trustedDid as string)) {
            throw new SdkError(
                'SDK_MAPPING_MISMATCH',
                `mtls kind: extracted DID (${extractedDid}) from verifiedSubject (${subject}) !== trustedDid (${ctx.trustedDid})`,
            );
        }
    } else if (ctx.verifierKind === 'jwt' || ctx.verifierKind === 'oauth2') {
        // jwt / oauth2: verifiedSubject maps directly to the DID -> literal equality compare
        if ((ctx.verifiedSubject as string) !== (ctx.trustedDid as string)) {
            throw new SdkError(
                'SDK_MAPPING_MISMATCH',
                `${ctx.verifierKind} kind: verifiedSubject (${ctx.verifiedSubject}) !== trustedDid (${ctx.trustedDid})`,
            );
        }
    } else {
        // unknown verifierKind -> fail-closed (I8 invariant)
        throw new SdkError(
            'SDK_SCHEMA_VIOLATION',
            `unknown verifierKind: ${String(ctx.verifierKind)} (expected 'mtls' | 'jwt' | 'oauth2')`,
        );
    }
}
