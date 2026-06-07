/**
 * mtls-helpers — mTLS X.509 cert parse / chain validation / DID extraction helpers
 *
 * Summary: three helper functions wrap the low-level @peculiar/x509 API for verifyMtlsAndDeriveDid to call.
 *
 * Basis:
 *   - sdk v0.2 (aligned helper functions)
 *   - transport library SOP (@peculiar/x509 cert parse + X509ChainBuilder)
 *   - PKI threat model (chain validation covers the Spoofing / Tampering dimensions)
 *
 * Security constraints:
 *   - parseX509Cert: parse failure must throw SDK_MTLS_VERIFY_FAILED (fail-closed)
 *   - validateCertChain: any non-compliant link returns false (does not throw; the caller throws uniformly)
 *   - extractDidFromCertSubject (X509 variant): if no DID, throw SDK_MTLS_VERIFY_FAILED
 *   - DID regex: `[a-z0-9]+` (method) + `[a-zA-Z0-9._%-]+` (method-specific-id) — RFC 3986 + DID Core spec
 *
 * Naming distinction:
 *   - extractDidFromCertSubject(cert: X509Certificate) — verifier factory entry; accepts an X509Certificate object
 *   - extractDidFromCertSubjectDn(subject: string) — boundary-check.ts entry; accepts a DN string
 *   The two functions are literally distinct identifiers; coexisting within the TS module produces no overload conflict.
 */

// @peculiar/x509 relies on a tsyringe reflect polyfill; it must be loaded before the x509 import,
// otherwise an ordinary consumer importing this module triggers x509 to throw at the module-load stage.
import 'reflect-metadata';
import {
    X509Certificate,
    X509ChainBuilder,
    BasicConstraintsExtension,
    KeyUsagesExtension,
    KeyUsageFlags,
    ExtendedKeyUsageExtension,
} from '@peculiar/x509';
import { SdkError } from '@coivitas/types';
import type { DID } from '@coivitas/types';

// ─── parseX509Cert ────────────────────────────────────────────────────────────

/**
 * parseX509Cert — parse X.509 cert (DER bytes OR PEM string) to X509Certificate instance
 *
 * Summary: the @peculiar/x509 X509Certificate constructor accepts Uint8Array (DER) or string (PEM).
 * On parse failure, immediately throw SDK_MTLS_VERIFY_FAILED (fail-closed).
 *
 * @param certInput DER Uint8Array or PEM string
 * @throws SdkError 'SDK_MTLS_VERIFY_FAILED' on parse fail / corrupted cert bytes
 */
export function parseX509Cert(certInput: Uint8Array | string): X509Certificate {
    try {
        return new X509Certificate(certInput);
    } catch (err) {
        throw new SdkError(
            'SDK_MTLS_VERIFY_FAILED',
            `X.509 cert parse failed: ${(err as Error).message}`,
        );
    }
}

// ─── validateCertChain ────────────────────────────────────────────────────────

/**
 * validateCertChain — chain validation via @peculiar/x509 X509ChainBuilder
 *
 * Summary: validates the integrity of the client -> (intermediate) -> root chain.
 * Validation dimensions:
 *   - chain link complete (each cert is signed by its parent)
 *   - not expired (cert.notBefore <= now <= cert.notAfter)
 *   - signature verify (each cert is verified against its parent's public key)
 *   - trusted root is at the tail of fullChain + within the trustedRoots set
 *
 * @param chain [clientCert, ...intermediates] — excludes root
 * @param trustedRoots list of trusted root CA certs
 * @returns true on PASS; false on any check fail
 */
export async function validateCertChain(
    chain: X509Certificate[],
    trustedRoots: X509Certificate[],
): Promise<boolean> {
    if (chain.length === 0) return false;

    if (trustedRoots.length === 0) return false;

    try {
        // Step 1: build the full chain (incl. root) with X509ChainBuilder
        const builder = new X509ChainBuilder({
            certificates: [
                ...trustedRoots,
                ...(chain.length > 1 ? chain.slice(1) : []),
            ],
        });
        const fullChain = await builder.build(chain[0]!);

        // Step 2: chain length at least 2 (client + root)
        if (fullChain.length < 2) return false;

        // Step 3: per-level validity + signature verify + RFC5280 purpose enforce
        // The identity verifier previously lacked RFC5280 validation,
        // so a holder of an ordinary leaf cert could sign a cert containing the target DID with the leaf private key
        // and pass it in as an intermediate, which would be accepted.
        // policy/audit-share import this identity verifier (the weak path), so it must align with the sdk version.
        // Counters CA-as-leaf / serverAuth-only / non-CA-intermediate attacks.
        const now = new Date();
        for (let i = 0; i < fullChain.length; i++) {
            const cert = fullChain[i]!;

            // Step 3.1: validity check (notBefore <= now <= notAfter)
            if (now < cert.notBefore || now > cert.notAfter) return false;

            // Step 3.2: signature verify (non-root signed by parent; root self-signed)
            const parent =
                i === fullChain.length - 1 ? cert : fullChain[i + 1]!;
            const sigOk = await cert.verify({
                publicKey: parent.publicKey,
                signatureOnly: true,
            });
            if (!sigOk) return false;

            // Step 3.3: strict RFC5280 enforcement (aligned with sdk mtls-helpers)
            // Use @peculiar/x509 typed getExtension(class constructor) to obtain the parsed subclass instance.
            // Do not use .find(e => e.type === OID) — that yields the base Extension, without the post-parse fields.
            const isLeaf = i === 0;

            // basicConstraints — leaf cA != true; CA cA = true + pathLen
            const bcExt = cert.getExtension(BasicConstraintsExtension);
            if (isLeaf) {
                // leaf: cA=false OR absent (counters the CA-as-leaf attack)
                if (bcExt && bcExt.ca === true) return false;
            } else {
                // intermediate + root: cA=true required (counters the non-CA-intermediate attack)
                if (!bcExt || bcExt.ca !== true) return false;
                // pathLenConstraint check (if present)
                if (typeof bcExt.pathLength === 'number') {
                    const remainingCaDepth = fullChain.length - 1 - i - 1;
                    if (bcExt.pathLength < remainingCaDepth) return false;
                }
            }

            // keyUsage — usages is a KeyUsageFlags numeric bitmask, so it must be tested with bitwise ops
            const kuExt = cert.getExtension(KeyUsagesExtension);
            if (!kuExt) return false; // strict RFC5280 — keyUsage required
            if (isLeaf) {
                if ((kuExt.usages & KeyUsageFlags.digitalSignature) === 0) {
                    return false;
                }
            } else {
                if ((kuExt.usages & KeyUsageFlags.keyCertSign) === 0) {
                    return false;
                }
            }

            // extendedKeyUsage — usages is an array of OID strings; leaf requires clientAuth (counters the serverAuth-only attack)
            if (isLeaf) {
                const ekuExt = cert.getExtension(ExtendedKeyUsageExtension);
                if (!ekuExt) return false; // leaf requires EKU
                // RFC5280 clientAuth OID: 1.3.6.1.5.5.7.3.2
                if (
                    !ekuExt.usages.some(
                        (u) => u === '1.3.6.1.5.5.7.3.2' || u === 'clientAuth',
                    )
                ) {
                    return false;
                }
            }
        }

        // Step 4: the tail cert is within the trustedRoots set (matches on both subject + serialNumber)
        const rootCandidate = fullChain[fullChain.length - 1]!;
        const trustedRootMatch = trustedRoots.some(
            (r) =>
                r.subject === rootCandidate.subject &&
                r.serialNumber === rootCandidate.serialNumber,
        );
        return trustedRootMatch;
    } catch {
        // chain build failure (e.g. broken chain / malformed) -> return false; the caller throws
        return false;
    }
}

// ─── extractDidFromCertSubject (X509Certificate variant) ──────────────────────

/**
 * extractDidFromCertSubject — extract the DID from an X509Certificate object
 *
 * Summary: extraction priority — SAN URI (did: scheme) preferred; CN= field fallback.
 *
 * Note: this function accepts an X509Certificate object (called inside the verifier factory).
 * Its counterpart, boundary-check.ts's extractDidFromCertSubjectDn(subject: string), is the DN string entry.
 *
 * DID regex: `did:[a-z0-9]+:[a-zA-Z0-9._%-]+`
 *   - method part: `[a-z0-9]+` (lowercase alphanumeric)
 *   - method-specific-id part: `[a-zA-Z0-9._%-]+` (RFC 3986 unreserved + percent-encoded + '.', '_', '-')
 *
 * @param cert @peculiar/x509 X509Certificate instance
 * @throws SdkError 'SDK_MTLS_VERIFY_FAILED' if no DID in SAN URI nor CN field
 */
export function extractDidFromCertSubject(cert: X509Certificate): DID {
    // DID Core spec method-specific-id character set
    const didPattern = /did:[a-z0-9]+:[a-zA-Z0-9._%-]+/;

    // Strategy 1: SAN (Subject Alternative Name) URI scheme `did:` (OID 2.5.29.17)
    const sanExt = cert.getExtension('2.5.29.17');
    if (sanExt) {
        const sanText = sanExt.toString();
        const didMatch = sanText.match(didPattern);
        if (didMatch?.[0]) {
            return didMatch[0] as DID;
        }
    }

    // Strategy 2: CN= field fallback (legacy cert; CN=did:<method>:<id>)
    const cnMatch = cert.subject.match(
        /(?:^|[\s,])CN=\s*(did:[a-z0-9]+:[a-zA-Z0-9._%-]+)/,
    );
    if (cnMatch?.[1]) {
        return cnMatch[1] as DID;
    }

    // No DID found in either the SAN URI or CN= -> fail-closed
    throw new SdkError(
        'SDK_MTLS_VERIFY_FAILED',
        `No DID found in cert subject (subject="${cert.subject}"); expected SAN URI scheme "did:" OR CN field with did:<method>:<id>`,
    );
}
