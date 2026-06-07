/**
 * mTLS cryptographic verifier factory
 *
 * Summary: verifyMtlsAndDeriveDid in 6 steps — parse cert + build chain + validate chain +
 *       extract DID + cross-check mapping + build the VerifiedTransportContext.
 *
 * Triple-defense L2 factory layer:
 * - mint the TrustedSettlerDid brand after cryptographic verify (cert chain validation)
 * - factory authority cast: the trailing `ctx.expectedDid as TrustedSettlerDid` is the legitimate
 *   origin of the brand guard (after cert chain + mapping equality are both enforced); the ESLint
 *   allowlist anchors this factory file
 */

import type {
    MtlsVerifierContext,
    VerifiedTransportContext,
} from './verifier-types.js';
import type { CertSubjectDn, TrustedSettlerDid } from './brand-types.js';

import { SdkError } from './errors.js';
import {
    extractDidFromCertSubject,
    parseX509Cert,
    validateCertChain,
} from './mtls-helpers.js';

/** the only valid sdkVersion for sdk v0.2 (I9) */
const SDK_V0_2_VERSION = '2.0.0' as const;

/**
 * verifyMtlsAndDeriveDid — mTLS cert mapping verify + TrustedSettlerDid derivation
 *
 * 6-step flow:
 * 1. parse client cert (@peculiar/x509)
 * 2. build cert chain (client → intermediate → trusted root)
 * 3. chain validation (signature verify + validity period + trusted root match)
 * 4. extract DID from cert subject (prefer SAN URI did:; CN fallback)
 * 5. cross-check mapping (cert subject DID === expectedDid)
 * 6. build the 5 fields of the VerifiedTransportContext
 *
 * @throws SdkError SDK_MTLS_VERIFY_FAILED / SDK_MAPPING_MISMATCH
 */
export async function verifyMtlsAndDeriveDid(
    ctx: MtlsVerifierContext,
): Promise<VerifiedTransportContext> {
    // Step 1: parse client cert
    const clientCertObj = parseX509Cert(ctx.clientCert);

    // Step 2: build cert chain (client → intermediate → trusted root)
    const chain = [
        clientCertObj,
        ...(ctx.intermediateChain ?? []).map(parseX509Cert),
    ];
    const trustedRoots = ctx.trustedRootCerts.map(parseX509Cert);

    // Step 3: chain validation (cryptographic verify)
    const chainValid = await validateCertChain(chain, trustedRoots);
    if (!chainValid) {
        throw new SdkError(
            'SDK_MTLS_VERIFY_FAILED',
            'mTLS cert chain validation failed (any of signature / validity period / trusted root match failed)',
        );
    }

    // Step 4: extract DID from cert subject (prefer SAN URI; CN fallback)
    const certDid = extractDidFromCertSubject(clientCertObj);
    const certSubjectDn = clientCertObj.subject as CertSubjectDn;

    // Step 5: cross-check mapping (string equality)
    if (certDid !== ctx.expectedDid) {
        throw new SdkError(
            'SDK_MAPPING_MISMATCH',
            `mTLS cert subject DID (${certDid}) does not match expected DID (${ctx.expectedDid})`,
        );
    }

    // Step 6: build the VerifiedTransportContext
    // - the cast at the factory boundary is the legitimate origin of the brand guard (after cert chain + mapping are both verified)
    return {
        trustedDid: ctx.expectedDid as TrustedSettlerDid,
        verifierKind: 'mtls',
        verifiedSubject: certSubjectDn,
        verifiedAt: new Date().toISOString(),
        sdkVersion: SDK_V0_2_VERSION,
    };
}
