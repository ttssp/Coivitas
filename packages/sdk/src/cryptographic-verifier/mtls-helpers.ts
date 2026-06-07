/**
 * mTLS helper functions
 *
 * Summary: three helpers — parseX509Cert + validateCertChain + extractDidFromCertSubject —
 *       all fail-closed by throwing SDK_MTLS_VERIFY_FAILED.
 *
 * Design points:
 * - Uses @peculiar/x509 (DER + PEM dual parsing + X509ChainBuilder)
 * - Chain validation across 4 dimensions: complete chain links + signature verify + validity period + trusted root match
 * - DID extraction priority: SAN URI scheme `did:` (RFC 5280) → CN fallback (legacy PKI deployments)
 * - All error paths are fail-closed (no procedural fallback / TOFU)
 */

// @peculiar/x509 depends on the reflect polyfill via tsyringe; it must be loaded before the x509
// import, otherwise x509 throws at module-load time when an ordinary consumer imports this module.
import 'reflect-metadata';
import {
    X509Certificate,
    X509ChainBuilder,
    BasicConstraintsExtension,
    KeyUsagesExtension,
    KeyUsageFlags,
    ExtendedKeyUsageExtension,
} from '@peculiar/x509';

import type { DID } from '@coivitas/types';

import { SdkError } from './errors.js';

/**
 * parseX509Cert — parse X.509 cert (DER bytes OR PEM string) → X509Certificate
 *
 * Failure path:
 * - input is not valid X.509 cert bytes (DER / PEM) → SDK_MTLS_VERIFY_FAILED
 *
 * @throws SdkError 'SDK_MTLS_VERIFY_FAILED'
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

/**
 * validateCertChain — cert chain validation
 *
 * Validation dimensions (returns true only when all 4 dimensions PASS):
 * 1. The chain builds completely (X509ChainBuilder built from client cert + intermediates + roots)
 * 2. Per-level signature verify (cert.verify({ publicKey: parent.publicKey }))
 * 3. Per-level validity period (cert.notBefore ≤ now ≤ cert.notAfter)
 * 4. The trusted root is at the tail of fullChain + is within the trustedRoots set (subject + serialNumber match)
 *
 *
 * @returns true on PASS; false on any check fail (an exception also → false, fail-closed)
 */
export async function validateCertChain(
    chain: X509Certificate[],
    trustedRoots: X509Certificate[],
): Promise<boolean> {
    if (chain.length === 0 || trustedRoots.length === 0) return false;

    try {
        // Step 1: build the full chain with X509ChainBuilder
        // - the certificates pool is made of trustedRoots + chain.slice(1) (intermediates)
        // - chain[0] is the leaf (client cert); build() walks back from leaf to root
        const intermediates = chain.slice(1);
        const builder = new X509ChainBuilder({
            certificates: [...trustedRoots, ...intermediates],
        });
        const leaf = chain[0];
        if (!leaf) return false;
        const fullChain = await builder.build(leaf);

        // Step 2: chain length sanity (at least leaf + root = 2)
        if (fullChain.length < 2) return false;

        // Step 3: per-level signature + validity period + RFC5280 enforce
        // Strict RFC5280 enforcement — basicConstraints + keyUsage + EKU clientAuth are mandatory; no fallback
        const now = new Date();
        for (let i = 0; i < fullChain.length; i++) {
            const cert = fullChain[i];
            if (!cert) return false;

            // validity period (notBefore ≤ now ≤ notAfter)
            if (now < cert.notBefore || now > cert.notAfter) return false;

            // signature verify (root self-signs; non-root is signed by its parent)
            const parent = i === fullChain.length - 1 ? cert : fullChain[i + 1];
            if (!parent) return false;
            const sigOk = await cert.verify({
                publicKey: parent.publicKey,
                signatureOnly: true,
            });
            if (!sigOk) return false;

            // Strict RFC5280 enforce
            // Use @peculiar/x509 typed getExtension (class constructor) to get the parsed subclass instance.
            // Do not use .find(e => e.type === OID) — that returns the base Extension, without the parsed fields.
            const isLeaf = i === 0;
            const isRoot = i === fullChain.length - 1;

            // basicConstraints — leaf cA≠true; CA cA=true + pathLen
            const bcExt = cert.getExtension(BasicConstraintsExtension);
            if (isLeaf) {
                // leaf: cA=false OR absent (counters the CA-as-leaf attack)
                if (bcExt && bcExt.ca === true) return false;
            } else {
                // intermediate + root: cA=true is mandatory
                if (!bcExt || bcExt.ca !== true) return false;
                // pathLenConstraint check (if present)
                if (typeof bcExt.pathLength === 'number') {
                    const remainingCaDepth = fullChain.length - 1 - i - 1;
                    if (bcExt.pathLength < remainingCaDepth) return false;
                }
            }

            // keyUsage — usages is a KeyUsageFlags numeric bitmask; must be checked with bitwise ops
            const kuExt = cert.getExtension(KeyUsagesExtension);
            if (!kuExt) return false; // strict RFC5280 — keyUsage is mandatory
            if (isLeaf) {
                if ((kuExt.usages & KeyUsageFlags.digitalSignature) === 0) {
                    return false;
                }
            } else {
                if ((kuExt.usages & KeyUsageFlags.keyCertSign) === 0) {
                    return false;
                }
            }

            // extendedKeyUsage — usages is an array of OID strings; leaf must have clientAuth (counters the serverAuth-only attack)
            if (isLeaf) {
                const ekuExt = cert.getExtension(ExtendedKeyUsageExtension);
                if (!ekuExt) return false; // leaf must have EKU
                // RFC5280 clientAuth OID: 1.3.6.1.5.5.7.3.2
                if (
                    !ekuExt.usages.some(
                        (u) => u === '1.3.6.1.5.5.7.3.2' || u === 'clientAuth',
                    )
                ) {
                    return false;
                }
            }
            void isRoot; // root needs no extra check (subject+serial match is guarded in Step 4)
        }

        // Step 4: trusted root is at the tail of fullChain + is within the trustedRoots set
        const rootCandidate = fullChain[fullChain.length - 1];
        if (!rootCandidate) return false;
        const trustedRootMatch = trustedRoots.some(
            (r) =>
                r.subject === rootCandidate.subject &&
                r.serialNumber === rootCandidate.serialNumber,
        );
        return trustedRootMatch;
    } catch {
        // any step throwing an exception → fail-closed false
        return false;
    }
}

/**
 * extractDidFromCertSubject — extract the DID from a cert subject (X509Certificate)
 *
 * Extraction priority:
 * 1. SAN URI scheme `did:` (RFC 5280; did-resolution standardized)
 * 2. CN field fallback (compatible with legacy PKI deployments)
 *
 * DID character set follows the DID Core spec method-specific-id character set:
 * - method: `[a-z0-9]+`
 * - method-specific-id: `[a-zA-Z0-9._%-]+`
 *
 * @throws SdkError 'SDK_MTLS_VERIFY_FAILED' if no DID found in SAN URI OR CN
 */
export function extractDidFromCertSubject(cert: X509Certificate): DID {
    const didTokenPattern = /did:[a-z0-9]+:[a-zA-Z0-9._%-]+/;

    // Step 1: prefer SAN URI scheme did:
    // - @peculiar/x509 X509Certificate.getExtension('2.5.29.17') gets the SAN extension
    // - the SAN extension toString() contains URI entries (e.g. "URI:did:web:example.com")
    const sanExt = cert.getExtension('2.5.29.17');
    if (sanExt) {
        const sanText = sanExt.toString();
        const didMatch = sanText.match(didTokenPattern);
        if (didMatch) return didMatch[0] as DID;
    }

    // Step 2: CN fallback (parse CN=did:... from the cert.subject string)
    // - cert.subject format (RFC 4514): "CN=did:web:example.com, OU=..., O=..."
    const cnMatch = cert.subject.match(/CN=(did:[a-z0-9]+:[a-zA-Z0-9._%-]+)/);
    if (cnMatch && cnMatch[1]) return cnMatch[1] as DID;

    throw new SdkError(
        'SDK_MTLS_VERIFY_FAILED',
        `No DID found in cert subject (subject=${cert.subject}); expected SAN URI scheme "did:" OR CN field`,
    );
}
