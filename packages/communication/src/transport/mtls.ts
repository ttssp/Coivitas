/**
 * mTLS transport — Node tls built-in mTLS server/client (L4 communication)
 *
 * Summary: createMtlsContext (shared server/client SecureContext construction) + TLS 1.3 cipher
 *          suite enforced by default + ALPN HTTP/2 / HTTP/1.1 dual-protocol support.
 *
 * Design highlights:
 * - Uses the Node standard library `node:tls` (no third-party TLS wrapper; minimized dependencies)
 * - TLS 1.3 minVersion (strictly enforced; legacy TLS 1.2- rejected by default)
 * - Default cipher suite: TLS_AES_256_GCM_SHA384 + TLS_CHACHA20_POLY1305_SHA256
 *   (the AEAD ciphers recommended for TLS 1.3; CBC mode not allowed)
 * - ALPN defaults to ['h2', 'http/1.1'] (HTTP/2 preferred; fallback to HTTP/1.1)
 * - mTLS is mutual server/client cert verification (requestCert + rejectUnauthorized)
 *
 * Related spec: sdk v0.2 (transport accompanying the mTLS verifier)
 * Related ADR: (Node tls + undici)
 */

import * as tls from 'node:tls';

/**
 * mTLS configuration
 */
export interface MtlsOptions {
    /** Client cert chain (PEM string OR Buffer; DER unsupported — PEM is the RFC 7468 standard transport format)*/
    cert: string | Buffer;
    /** Client private key (PEM string OR Buffer; encrypted PEM paired with passphrase)*/
    key: string | Buffer;
    /** Optional passphrase for encrypted PEM key*/
    passphrase?: string;
    /** CA chain (PEM string OR Buffer; system trust by default)*/
    ca?: string | Buffer | Array<string | Buffer>;
    /** TLS 1.3 cipher suites allowlist (colon-separated string; denylists legacy ciphers)*/
    ciphers?: string;
    /** TLS minimum version (default TLSv1.3; legacy TLS 1.2- rejected)*/
    minVersion?: 'TLSv1.3';
    /** Server name indication (SNI) — client only*/
    servername?: string;
    /** ALPN protocols (default ['h2', 'http/1.1'])*/
    ALPNProtocols?: string[];
}

/**
 * Default TLS 1.3 cipher suite (AEAD only; recommended for TLS 1.3)
 *
 * - TLS_AES_256_GCM_SHA384: AES-256-GCM + SHA-384 (NIST-recommended + HKDF)
 * - TLS_CHACHA20_POLY1305_SHA256: ChaCha20-Poly1305 (fast in software + mobile-friendly)
 *
 * Excludes TLS_AES_128_* (256-bit strength preferred); CBC mode not allowed (historical vulns such as BEAST/Lucky13).
 */
export const DEFAULT_TLS_1_3_CIPHERS =
    'TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256';

/**
 * createMtlsContext — TLS SecureContext construction (shared by server/client)
 *
 * Returns a tls.SecureContext; the caller (server: tls.createServer / client: tls.connect)
 * passes this context directly (the secureContext option).
 */
export function createMtlsContext(options: MtlsOptions): tls.SecureContext {
    return tls.createSecureContext({
        cert: options.cert,
        key: options.key,
        passphrase: options.passphrase,
        ca: options.ca,
        ciphers: options.ciphers ?? DEFAULT_TLS_1_3_CIPHERS,
        minVersion: options.minVersion ?? 'TLSv1.3',
    });
}

/**
 * createMtlsServer — mTLS TLS server construction (enforces mutual cert verification)
 *
 * Key server options (standard Node tls.createServer options):
 * - cert / key / passphrase: server-side cert + private key
 * - ca: trusted root CA chain (verifies the client cert)
 * - requestCert: true (requires the client to provide a cert)
 * - rejectUnauthorized: true (untrusted client cert -> connection refused)
 * - minVersion: 'TLSv1.3' (legacy TLS 1.2- rejected)
 * - ciphers: TLS 1.3 AEAD cipher suites
 * - ALPNProtocols: HTTP/2 + HTTP/1.1
 *
 * Returns a tls.Server instance; the caller starts it with .listen(port).
 */
export function createMtlsServer(options: MtlsOptions): tls.Server {
    return tls.createServer({
        // server-side cert + key (Node tls.createServer accepts SecureContextOptions directly)
        cert: options.cert,
        key: options.key,
        passphrase: options.passphrase,
        ca: options.ca,
        // Mandatory for an mTLS server — strictly require a client cert
        requestCert: true,
        rejectUnauthorized: true,
        ciphers: options.ciphers ?? DEFAULT_TLS_1_3_CIPHERS,
        minVersion: options.minVersion ?? 'TLSv1.3',
        ALPNProtocols: options.ALPNProtocols ?? ['h2', 'http/1.1'],
    });
}

/**
 * connectMtlsClient — mTLS TLS client connection (enforces server cert verification)
 *
 * Key client options:
 * - rejectUnauthorized: true (untrusted server cert -> connection refused)
 * - servername: SNI (validates the server cert subject)
 * - cert/key: client cert + private key (for server-side mTLS verification)
 *
 * Returns a tls.TLSSocket; the caller listens for the 'secureConnect' event to confirm a successful handshake.
 */
export function connectMtlsClient(
    port: number,
    host: string,
    options: MtlsOptions,
): tls.TLSSocket {
    return tls.connect({
        port,
        host,
        cert: options.cert,
        key: options.key,
        passphrase: options.passphrase,
        ca: options.ca,
        ciphers: options.ciphers ?? DEFAULT_TLS_1_3_CIPHERS,
        minVersion: options.minVersion ?? 'TLSv1.3',
        servername: options.servername ?? host,
        ALPNProtocols: options.ALPNProtocols ?? ['h2', 'http/1.1'],
        // Mandatory for an mTLS client — server cert verification
        rejectUnauthorized: true,
    });
}

/**
 * Extracts the raw DER bytes from the mTLS server peer cert (for consumption by the cryptographic-verifier)
 *
 * Design intent: after a successful server-side handshake, take the peer cert (client cert) from the socket
 *                and convert it to DER bytes for direct consumption by the sdk v0.2 cryptographic-verifier (verifyMtlsAndDeriveDid).
 *
 * Usage:
 * ```typescript
 * server.on('secureConnection', (socket) => {
 *   const certBytes = extractPeerCertDer(socket);
 *   if (!certBytes) {
 *     socket.destroy(new Error('no peer cert'));
 *     return;
 *   }
 *   // Pass to verifyMtlsAndDeriveDid({ clientCert: certBytes, ... })
 * });
 * ```
 *
 * @returns DER bytes or null (peer did not provide a cert OR socket already destroyed)
 */
export function extractPeerCertDer(socket: tls.TLSSocket): Uint8Array | null {
    const peerCert = socket.getPeerCertificate(false);
    if (!peerCert || Object.keys(peerCert).length === 0) {
        return null;
    }
    // tls.PeerCertificate.raw is a Buffer (DER bytes; X.509 ASN.1 DER format)
    const raw = peerCert.raw;
    if (!raw || raw.length === 0) {
        return null;
    }
    return new Uint8Array(raw.buffer, raw.byteOffset, raw.byteLength);
}
