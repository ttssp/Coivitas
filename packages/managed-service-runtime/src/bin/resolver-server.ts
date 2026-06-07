/**
 * Resolver server startup entry point (for docker-compose / direct execution).
 *
 * env vars:
 * - DATABASE_URL : PostgreSQL connection string (required)
 * - RESOLVER_PORT : listen port (default 8080)
 * - MANAGED_SERVICE_TRUST_PROXY : trust proxy hop count (default "0" = false)
 *                                            "1" = trust one hop (reverse proxy deployment)
 *                                            "0" / unset = do not trust X-Forwarded-For
 *                                            (secure default for directly-exposed-port deployments)
 * - MANAGED_SERVICE_ALLOW_STUB_RESOLVER : explicitly allow the stub resolver to start (development/CI only)
 *                                            unset → fail-closed exit
 *                                            "1" → start the stub (mode=STUB; resolve requests throw 502)
 *
 * **Important**:
 *   This bin currently does **not** wire a real FederatedResolver itself (it needs verifyDIDBinding +
 *   dnsRebindingGuard injected by the caller). Parameters such as FEDERATED_NODES are reserved for future
 *   expansion, and the current main manifest does **not accept FEDERATED_NODES as a production-ready signal** —
 *   without ALLOW_STUB set → fail-closed, to avoid a false-positive deployment that "claims federated but actually runs the stub."
 *   Production path: use the SDK integration (packages/sdk/src/managed-service-client.ts),
 *   where the caller is responsible for injecting a fully wired FederatedResolver.
 */

import { createPool } from '@coivitas/shared';
import type { FederatedResolver } from '@coivitas/types';

import { createResolverApp } from '../resolver-server.js';

function main(): void {
    const port = Number(process.env.RESOLVER_PORT ?? '8080');
    const databaseUrl = requireEnv('DATABASE_URL');

    // Hardened fail-closed startup guard:
    // An earlier revision only checked whether the FEDERATED_NODES env was present,
    // but the bin still used stubResolver unconditionally → setting FEDERATED_NODES would start with mode=federated
    // yet return 502 for every resolve request, a false-positive deployment.
    // Fix: remove the FEDERATED_NODES startup path; only accept an explicit ALLOW_STUB=1 (demo/CI).
    // The main deployment path goes through the SDK integration (the caller injects a fully wired FederatedResolver), not this bin.
    const allowStub = process.env.MANAGED_SERVICE_ALLOW_STUB_RESOLVER === '1';
    if (!allowStub) {
        console.error(
            '[resolver-server] the stub resolver is disabled by default; to start in stub mode (development/CI), set MANAGED_SERVICE_ALLOW_STUB_RESOLVER=1',
        );
        console.error(
            '[resolver-server] production deployments should use the SDK integration path packages/sdk/src/managed-service-client.ts',
        );
        console.error(
            '[resolver-server] (the SDK caller is responsible for injecting a fully wired FederatedResolver; this bin does not wire real federation nodes itself)',
        );
        process.exit(1);
    }

    const pool = createPool({ connectionString: databaseUrl });

    // alpha stage: the FederatedResolver is injected by the caller;
    // the current stub is a placeholder (only starts when MANAGED_SERVICE_ALLOW_STUB_RESOLVER=1).
    // **NOT FOR PRODUCTION**: production deployments go through the SDK integration path, not this bin.
    const stubResolver: FederatedResolver = {
        resolve: () => {
            throw new Error(
                '[resolver-server bin] FederatedResolver not wired; this is STUB mode (MANAGED_SERVICE_ALLOW_STUB_RESOLVER=1).',
            );
        },
        invalidateCache: () => undefined,
        getMetrics: () => ({
            resolveTotal: 0,
            resolveSuccess: 0,
            resolveNull: 0,
            resolveInternalError: 0,
            latencyP50Ms: 0,
            latencyP95Ms: 0,
            latencyP99Ms: 0,
            nodes: {},
            versionConflictCount: 0,
            signatureInvalidCount: 0,
            quorumUnmetCount: 0,
            cacheHit: 0,
            cacheMiss: 0,
            quorumVoteSplitCount: 0,
            dnsRebindingBlockedCount: 0,
            quorumReachedCount: 0,
        }),
        close: () => Promise.resolve(),
    };

    const trustProxyRaw = process.env.MANAGED_SERVICE_TRUST_PROXY;
    const trustProxy =
        trustProxyRaw && trustProxyRaw !== '0' && trustProxyRaw !== ''
            ? Number(trustProxyRaw)
            : false;

    const app = createResolverApp({
        pool,
        federatedResolver: stubResolver,
        trustProxy,
    });

    const server = app.listen(port, () => {
        // Only log STUB mode (avoids a false-positive federated label)
        console.log(
            `[resolver-server] listening on :${port}; mode=STUB (MANAGED_SERVICE_ALLOW_STUB_RESOLVER=1; **NOT FOR PRODUCTION**)`,
        );
    });

    process.on('SIGTERM', () => {
        console.log('[resolver-server] SIGTERM received; closing...');
        server.close(() => {
            void pool.end();
        });
    });
}

function requireEnv(name: string): string {
    const v = process.env[name];
    if (!v) {
        console.error(`[resolver-server] missing env: ${name}`);
        process.exit(1);
    }
    return v;
}

try {
    main();
} catch (error) {
    console.error('[resolver-server] startup failed:', error);
    process.exit(1);
}
