/**
 * validate-cert-chain.test.ts — validateCertChain real-certificate-chain tests (non-mock)
 *
 * Conclusion: use @peculiar/x509 X509CertificateGenerator to genuinely generate a root->leaf
 *       certificate chain, and verify validateCertChain's real behavior for RFC5280 purpose enforcement.
 *
 * Background:
 *   The old implementation mistook KeyUsagesExtension.usages (a KeyUsageFlags numeric bitmask) for a
 *   string array and called .includes(), throwing TypeError on normal certificates that was swallowed
 *   by catch into false -> wrongly killing all valid clientAuth certificates.
 *   The old mtls tests fully mocked validateCertChain itself, so this bug was never covered by any test.
 *   This file uses real certificates to prove that, after the bitwise fix, a valid clientAuth leaf chain
 *   passes and various non-compliant chains are rejected.
 *
 * Coverage dimensions:
 *   - valid clientAuth leaf chain -> pass (bitwise-fix regression; the old implementation would wrongly kill it)
 *   - CA-as-leaf (leaf basicConstraints cA=true) -> reject
 *   - serverAuth-only leaf (EKU without clientAuth) -> reject
 *   - leaf missing keyUsage digitalSignature -> reject
 *   - non-CA intermediate (intermediate cA != true) -> reject
 *   - root not in the trustedRoots set -> reject
 */

import 'reflect-metadata'; // @peculiar/x509 depends on the reflect polyfill via tsyringe
import { describe, it, expect, beforeAll } from 'vitest';
import { webcrypto } from 'node:crypto';
import {
    X509CertificateGenerator,
    BasicConstraintsExtension,
    KeyUsagesExtension,
    KeyUsageFlags,
    ExtendedKeyUsageExtension,
    ExtendedKeyUsage,
    cryptoProvider,
    type X509Certificate,
    type Extension,
} from '@peculiar/x509';

import { validateCertChain } from '../cryptographic-verifier/mtls-helpers.js';

// @peculiar/x509 requires a WebCrypto engine to be injected (built into Node 20+).
// The identity tsconfig lib does not include DOM, so use the webcrypto runtime value + type inference, without writing DOM type annotations.
const wc = webcrypto as unknown as {
    subtle: {
        generateKey(
            algorithm: object,
            extractable: boolean,
            keyUsages: string[],
        ): Promise<unknown>;
    };
};
cryptoProvider.set(webcrypto as never);

const ALG = {
    name: 'ECDSA',
    namedCurve: 'P-256',
    hash: 'SHA-256',
} as const;

type KeyPair = { privateKey: unknown; publicKey: unknown };

async function genKeyPair(): Promise<KeyPair> {
    return (await wc.subtle.generateKey(ALG, false, [
        'sign',
        'verify',
    ])) as KeyPair;
}

/** Self-signed root CA (cA=true + keyCertSign) */
async function makeRoot(): Promise<{ cert: X509Certificate; keys: KeyPair }> {
    const keys = await genKeyPair();
    const cert = await X509CertificateGenerator.createSelfSigned({
        serialNumber: '01',
        name: 'CN=Test Root CA',
        notBefore: new Date(Date.now() - 3_600_000),
        notAfter: new Date(Date.now() + 3_600_000),
        signingAlgorithm: ALG,
        keys: keys as never,
        extensions: [
            new BasicConstraintsExtension(true, undefined, true),
            new KeyUsagesExtension(KeyUsageFlags.keyCertSign, true),
        ],
    });
    return { cert, keys };
}

/** A cert issued by an issuer (with controllable extensions) */
async function makeSigned(params: {
    name: string;
    serial: string;
    issuerCert: X509Certificate;
    issuerKeys: KeyPair;
    extensions: Extension[];
}): Promise<{ cert: X509Certificate; keys: KeyPair }> {
    const keys = await genKeyPair();
    const cert = await X509CertificateGenerator.create({
        serialNumber: params.serial,
        subject: params.name,
        issuer: params.issuerCert.subject,
        notBefore: new Date(Date.now() - 3_600_000),
        notAfter: new Date(Date.now() + 3_600_000),
        signingAlgorithm: ALG,
        publicKey: keys.publicKey as never,
        signingKey: params.issuerKeys.privateKey as never,
        extensions: params.extensions,
    });
    return { cert, keys };
}

/** A valid clientAuth leaf extension combination */
function validLeafExtensions(): Extension[] {
    return [
        new BasicConstraintsExtension(false, undefined, true),
        new KeyUsagesExtension(KeyUsageFlags.digitalSignature, true),
        new ExtendedKeyUsageExtension([ExtendedKeyUsage.clientAuth], true),
    ];
}

describe('validateCertChain — real-certificate RFC5280 purpose enforcement', () => {
    let root: { cert: X509Certificate; keys: KeyPair };

    beforeAll(async () => {
        root = await makeRoot();
    });

    it('should accept chain when leaf is a valid clientAuth cert signed by trusted root', async () => {
        const leaf = await makeSigned({
            name: 'CN=valid-client',
            serial: '10',
            issuerCert: root.cert,
            issuerKeys: root.keys,
            extensions: validLeafExtensions(),
        });
        const ok = await validateCertChain([leaf.cert], [root.cert]);
        expect(ok).toBe(true);
    });

    it('should reject chain when leaf carries basicConstraints cA=true (CA-as-leaf attack)', async () => {
        const leaf = await makeSigned({
            name: 'CN=ca-as-leaf',
            serial: '11',
            issuerCert: root.cert,
            issuerKeys: root.keys,
            extensions: [
                new BasicConstraintsExtension(true, undefined, true),
                new KeyUsagesExtension(KeyUsageFlags.digitalSignature, true),
                new ExtendedKeyUsageExtension(
                    [ExtendedKeyUsage.clientAuth],
                    true,
                ),
            ],
        });
        const ok = await validateCertChain([leaf.cert], [root.cert]);
        expect(ok).toBe(false);
    });

    it('should reject chain when leaf EKU lacks clientAuth (serverAuth-only attack)', async () => {
        const leaf = await makeSigned({
            name: 'CN=server-only',
            serial: '12',
            issuerCert: root.cert,
            issuerKeys: root.keys,
            extensions: [
                new BasicConstraintsExtension(false, undefined, true),
                new KeyUsagesExtension(KeyUsageFlags.digitalSignature, true),
                new ExtendedKeyUsageExtension(
                    [ExtendedKeyUsage.serverAuth],
                    true,
                ),
            ],
        });
        const ok = await validateCertChain([leaf.cert], [root.cert]);
        expect(ok).toBe(false);
    });

    it('should reject chain when leaf keyUsage lacks digitalSignature', async () => {
        const leaf = await makeSigned({
            name: 'CN=no-digsig',
            serial: '13',
            issuerCert: root.cert,
            issuerKeys: root.keys,
            extensions: [
                new BasicConstraintsExtension(false, undefined, true),
                // keyUsage contains only keyEncipherment, without digitalSignature
                new KeyUsagesExtension(KeyUsageFlags.keyEncipherment, true),
                new ExtendedKeyUsageExtension(
                    [ExtendedKeyUsage.clientAuth],
                    true,
                ),
            ],
        });
        const ok = await validateCertChain([leaf.cert], [root.cert]);
        expect(ok).toBe(false);
    });

    it('should reject chain when intermediate is not a CA (non-CA-intermediate attack)', async () => {
        // intermediate basicConstraints cA=false -> cannot act as an issuer
        const badIntermediate = await makeSigned({
            name: 'CN=fake-intermediate',
            serial: '20',
            issuerCert: root.cert,
            issuerKeys: root.keys,
            extensions: [
                new BasicConstraintsExtension(false, undefined, true),
                new KeyUsagesExtension(KeyUsageFlags.digitalSignature, true),
            ],
        });
        const leaf = await makeSigned({
            name: 'CN=leaf-under-fake-int',
            serial: '21',
            issuerCert: badIntermediate.cert,
            issuerKeys: badIntermediate.keys,
            extensions: validLeafExtensions(),
        });
        const ok = await validateCertChain(
            [leaf.cert, badIntermediate.cert],
            [root.cert],
        );
        expect(ok).toBe(false);
    });

    it('should reject chain when root is not in the trusted roots set', async () => {
        const otherRoot = await makeRoot();
        const leaf = await makeSigned({
            name: 'CN=client-under-untrusted-root',
            serial: '30',
            issuerCert: otherRoot.cert,
            issuerKeys: otherRoot.keys,
            extensions: validLeafExtensions(),
        });
        // leaf is signed by otherRoot, but trustedRoots contains only root -> reject
        const ok = await validateCertChain([leaf.cert], [root.cert]);
        expect(ok).toBe(false);
    });
});
