/**
 * Revocation server startup entry point (for docker-compose / direct execution).
 *
 * env vars:
 * - DATABASE_URL : PostgreSQL connection string (required)
 * - REVOCATION_PORT : listen port (default 8081)
 * - MANAGED_SERVICE_TRUST_PROXY : trust proxy hop count (default "0" = false)
 * - MANAGED_SERVICE_ALLOW_STUB_REVOCATION : explicitly allow the stub revocation checker to start
 *                                                unset → fail-closed exit
 *                                                "1" → start the stub (development/CI only)
 *                                                purpose: prevent the stub from causing a silent false negative in production
 *                                                (the stub always returns revoked: false → revoked credentials still pass)
 */

import { createPool } from '@coivitas/shared';

import { createRevocationApp } from '../revocation-server.js';

function main(): void {
    const port = Number(process.env.REVOCATION_PORT ?? '8081');
    const databaseUrl = requireEnv('DATABASE_URL');

    // Fail-closed startup guard:
    // The stub revocation checker always returns revoked: false (silent false negative),
    // so revoked credentials still pass → it breaks the revocation mechanism. Without an explicit ALLOW_STUB → fail-closed exit.
    // The current bin does not support wiring a real RevocationList adapter (that wiring is part of the full production implementation),
    // so ALLOW_STUB is the only explicit entry point for development/CI.
    const allowStub = process.env.MANAGED_SERVICE_ALLOW_STUB_REVOCATION === '1';
    if (!allowStub) {
        console.error(
            '[revocation-server] the stub checker is disabled by default; to start in stub mode (development/CI), set MANAGED_SERVICE_ALLOW_STUB_REVOCATION=1',
        );
        console.error(
            '[revocation-server] production deployments must connect a real RevocationList adapter (not supported by the current alpha bin; use the SDK integration path directly)',
        );
        process.exit(1);
    }

    const pool = createPool({ connectionString: databaseUrl });

    const trustProxyRaw = process.env.MANAGED_SERVICE_TRUST_PROXY;
    const trustProxy =
        trustProxyRaw && trustProxyRaw !== '0' && trustProxyRaw !== ''
            ? Number(trustProxyRaw)
            : false;

    // Only starts when ALLOW_STUB=1; no checker passed → falls back to the stub (in-memory, always returns not-revoked)
    const app = createRevocationApp({ pool, trustProxy });

    const server = app.listen(port, () => {
        console.log(
            `[revocation-server] listening on :${port}; mode=STUB (MANAGED_SERVICE_ALLOW_STUB_REVOCATION=1; **NOT FOR PRODUCTION**)`,
        );
        console.log(
            '[revocation-server] STUB mode returns 503 + STUB_REVOCATION_NOT_FOR_PRODUCTION by design; provide a real revocation checker before production use',
        );
    });

    process.on('SIGTERM', () => {
        console.log('[revocation-server] SIGTERM received; closing...');
        server.close(() => {
            void pool.end();
        });
    });
}

function requireEnv(name: string): string {
    const v = process.env[name];
    if (!v) {
        console.error(`[revocation-server] missing env: ${name}`);
        process.exit(1);
    }
    return v;
}

try {
    main();
} catch (error) {
    console.error('[revocation-server] startup failed:', error);
    process.exit(1);
}
