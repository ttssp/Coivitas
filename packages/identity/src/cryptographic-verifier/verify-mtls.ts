/**
 * verify-mtls — mTLS cert mapping verify + TrustedSettlerDid derivation
 *
 * Summary: verifyMtlsAndDeriveDid implements the sdk v0.2 flow (Steps 1-6),
 * based on @peculiar/x509 cert parse + X509ChainBuilder
 * + the PKI threat model Spoofing/Tampering dimensions.
 *
 * Basis:
 *   - sdk v0.2 mTLS verifier factory flow
 *   - Node tls built-in mTLS + @peculiar/x509 cert parse
 *   - PKI threat model (chain validation covers the Spoofing / Tampering dimensions)
 *
 * Security constraints:
 *   - parseX509Cert: parse failure throws SDK_MTLS_VERIFY_FAILED (fail-closed)
 *   - validateCertChain: chain integrity + validity + signature verify — any fail -> throw SDK_MTLS_VERIFY_FAILED
 *   - cross-check mapping: certDid !== expectedDid -> throw SDK_MAPPING_MISMATCH
 *   - no substring / prefix matching — DID must be literally equal
 *   - brand cast: `as TrustedSettlerDid` executed only after Step 6 cryptographic verify passes (no brand coercion)
 */

import type {
    MtlsVerifierContext,
    VerifiedTransportContext,
    TrustedSettlerDid,
    CertSubjectDn,
} from '@coivitas/types';
import { SdkError } from '@coivitas/types';
import {
    parseX509Cert,
    validateCertChain,
    extractDidFromCertSubject,
} from './mtls-helpers.js';

/**
 * verifyMtlsAndDeriveDid — mTLS cert mapping verify + TrustedSettlerDid derivation
 *
 * Summary: 6-step flow — cert parse -> chain build -> chain validate -> DID extraction -> cross-check mapping -> VerifiedTransportContext construction.
 * The L2 factory layer's cryptographic guard, the only legal TrustedSettlerDid construction path.
 *
 * Flow:
 *   Step 1: parse client cert (@peculiar/x509)
 *   Step 2: build cert chain (client -> intermediate -> trusted root)
 *   Step 3: chain validation (signature verify + not expired + trusted root match)
 *   Step 4: extract DID from cert subject (SAN URI preferred; CN= field fallback)
 *   Step 5: cross-check mapping literal equality (certDid === expectedDid)
 *   Step 6: construct VerifiedTransportContext (brand cast — only after cryptographic verify passes)
 *
 * @param ctx MtlsVerifierContext (client cert bytes/PEM + trusted root certs + expected DID)
 * @returns VerifiedTransportContext (trustedDid = expectedDid as TrustedSettlerDid)
 * @throws SdkError 'SDK_MTLS_VERIFY_FAILED' cert parse fail / chain validate fail / DID not found
 * @throws SdkError 'SDK_MAPPING_MISMATCH' certDid !== expectedDid
 */
export async function verifyMtlsAndDeriveDid(
    ctx: MtlsVerifierContext,
): Promise<VerifiedTransportContext> {
    // Step 1: parse client cert (@peculiar/x509 X509Certificate construction)
    // parseX509Cert: DER Uint8Array or PEM string; parse failure throws SDK_MTLS_VERIFY_FAILED
    const clientCertObj = parseX509Cert(ctx.clientCert);

    // Step 2: build cert chain (client -> intermediate(s); excludes root — root is in trustedRoots)
    const intermediates = (ctx.intermediateChain ?? []).map(parseX509Cert);
    const chain = [clientCertObj, ...intermediates];

    // Step 3: chain validation via validateCertChain (X509ChainBuilder + validity + signature verify + trusted root match)
    const trustedRoots = ctx.trustedRootCerts.map(parseX509Cert);
    const chainValid = await validateCertChain(chain, trustedRoots);
    if (!chainValid) {
        throw new SdkError(
            'SDK_MTLS_VERIFY_FAILED',
            'mTLS cert chain validation failed (chain incomplete / cert expired / signature invalid / root not trusted)',
        );
    }

    // Step 4: extract DID from cert subject (SAN URI OID 2.5.29.17 preferred; CN= field fallback)
    // extractDidFromCertSubject: throws SDK_MTLS_VERIFY_FAILED if no DID found
    const certDid = extractDidFromCertSubject(clientCertObj);

    // Step 4b: extract cert subject DN string for VerifiedTransportContext.verifiedSubject
    // subjectName.toString() returns an RFC 4514 LDAP DN format string (e.g. "CN=did:example:123, O=...")
    const rawSubjectDn = clientCertObj.subjectName.toString();

    // The SAN-derived DID is preserved into verifiedSubject.
    // certDid may come from the SAN URI (not within the subject DN); if the DN string does not contain that DID,
    // append "URI=<certDid>" so the downstream extractDidFromCertSubjectDn SAN URI strategy can hit,
    // otherwise a SAN-only cert (CN has no DID) would be wrongly rejected by the boundary cross-check (even though SAN is the preferred mapping path).
    const certSubjectDn = (
        rawSubjectDn.includes(certDid)
            ? rawSubjectDn
            : `${rawSubjectDn}, URI=${certDid}`
    ) as CertSubjectDn;

    // Step 5: cross-check mapping literal equality (no substring / prefix matching)
    if (certDid !== ctx.expectedDid) {
        throw new SdkError(
            'SDK_MAPPING_MISMATCH',
            `mTLS cert subject DID (${certDid}) does not match expected DID (${ctx.expectedDid})`,
        );
    }

    // Step 6: construct VerifiedTransportContext
    // brand cast: `as TrustedSettlerDid` executed only after cryptographic verify fully PASSes
    // `as CertSubjectDn` is the brand cast for the certified subject DN string (post-verify safe)
    return {
        trustedDid: ctx.expectedDid as TrustedSettlerDid,
        verifierKind: 'mtls',
        verifiedSubject: certSubjectDn,
        verifiedAt: new Date().toISOString(),
        sdkVersion: '2.0.0',
    };
}
