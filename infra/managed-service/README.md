# Managed Service Infrastructure (alpha)

Coivitas managed-service deployment: DID resolution + revocation checking (free tier + pro tier) + monitoring stack.

**Status** alpha (**NOT FOR PRODUCTION**)

---

## 1. Scope

This directory contains:

| File | Purpose |
| --- | --- |
| `docker-compose.yml` | 4 services: resolver / revocation / prometheus / grafana (postgres reused from the root compose) |
| `prometheus.yml` | scrape config (resolver:8080/metrics + revocation:8081/metrics) |
| `grafana/dashboards/coivitas-managed-service.json` | Dashboard: QPS / P99 / error rate / top 10 tenants |
| `grafana/provisioning/` | Grafana auto-provisioning: datasources/prometheus.yml + dashboards/dashboards.yml |
| `SLO.md` | SLO definitions, error budget, scale-up path, alpha-phase limitations |

Service source: `packages/managed-service-runtime/` (standalone npm package).

---

## 2. Alpha-phase limitations (important)

**This deployment is not production-grade; the deployer assumes all risk.**

1. No TLS termination: relies on an external reverse proxy (Caddy / nginx / Cloudflare Tunnel).
2. No secret management: DATABASE_URL / API key are read from `.env`.
3. The rate-limiter is in-memory (single instance); horizontal scaling requires Redis.
4. FederatedResolver wiring is a stub (clearly marked in `bin/resolver-server.ts`); it must be replaced before going live.
5. The revocation checker is a stub (always returns not-revoked); the full implementation goes through RevocationList.
6. Monitoring volumes have no off-site backup (Grafana / Prometheus retain data across restarts, but a host failure loses everything).
7. **No performance benchmark has been run.** The SLO P99 < 100ms is a design target, not measured in the alpha phase (see SLO.md §3).
8. **PRO tier rate-limit under shared NAT egress IP**: the rate-limit bucket
 is keyed by IP, so the documented PRO quota ("10000/min/key") cannot be
 fully realized when many PRO clients share a single egress IP — they fall
 back to the IP+FREE bucket (100/min). The alpha ships a single limiter for
 simplicity; full tier-aware distributed rate-limiting requires Redis plus
 reverse-proxy cooperation. **Workaround**: deploy PRO tenants behind a
 dedicated egress IP, or do PRO-key identification at the ingress proxy.
9. **`MANAGED_SERVICE_TRUST_PROXY` defaults to false** (the safe default for a directly-exposed-port deployment).
 When deployed behind a reverse proxy (nginx / Caddy / Cloudflare) it must be set explicitly to `1` (trust one hop),
 otherwise the real client IP forwarded by the reverse proxy is not recognized and all rate-limiting is computed
 against the reverse-proxy IP. Conversely, if a `>0` value is set while ports are exposed directly, clients can
 forge X-Forwarded-For to bypass IP rate-limiting.

---

## 3. Deployment steps

### 3.1 Prerequisites

From the repository root:

```bash
cp .env.example .env # configure PG / DATABASE_URL
pnpm install
pnpm build --filter @coivitas/managed-service-runtime
docker-compose up -d # start the root compose's Postgres
./scripts/db-migrate.sh # apply SQL 008 (managed_service schema)
```

### 3.2 Start the managed service

```bash
cd infra/managed-service/
docker-compose up -d
```

Service ports:

| service | port | purpose |
| --- | --- | --- |
| resolver | 8080 | GET /v1/resolve/:did + /metrics + /health |
| revocation | 8081 | GET /v1/revocation/:credentialId + /metrics + /health |
| prometheus | 9090 | scrape resolver + revocation |
| grafana | 3000 | admin/admin default; anonymous Viewer enabled; datasource + dashboard auto-provisioned |

**Note**: postgres 5432 is provided by the repository-root `docker-compose.yml`; this compose reaches it via `host.docker.internal:5432`. Linux users must uncomment `extra_hosts` in docker-compose.yml.

### 3.3 Smoke test

```bash
# health check
curl http://localhost:8080/health
# {"status":"ok","service":"resolver"}

curl http://localhost:8081/health
# {"status":"ok","service":"revocation"}

# /metrics text (Prometheus format)
curl http://localhost:8080/metrics | grep resolver_requests_total

# Note: a real /v1/resolve/:did requires FederatedResolver wiring (the alpha stub throws).
# The revocation-check stub path can be tested directly.
curl http://localhost:8081/v1/revocation/test-credential-id
# {"credentialId":"test-credential-id","revoked":false}
```

### 3.4 Register a tenant + API key (manual)

The alpha phase has no admin UI; use SQL directly:

```sql
-- create a PRO tenant
INSERT INTO managed_service.tenants (tenant_did, tier, display_name, contact_email)
VALUES ('did:agent:test-pro-tenant', 'PRO', 'Test Tenant', 'admin@example.com')
RETURNING id;

-- create an API key (key_hash = SHA-256 of "ap_live_test_key_123456")
INSERT INTO managed_service.api_keys (tenant_id, key_hash, key_prefix, description)
VALUES (
 '<tenant_id from above>',
 encode(sha256('ap_live_test_key_123456'::bytea), 'hex'),
 'ap_live_',
 'alpha test key'
);

-- query usage
SELECT tenant_id, endpoint, bucket_day, request_count, error_count
FROM managed_service.usage_log
ORDER BY bucket_day DESC LIMIT 10;
```

---

## 4. SLO + monitoring

See `SLO.md`. Summary:

- Resolver P99 < 100ms (design target, not measured)
- Availability > 99.5% / month
- Error rate < 0.5%
- Rate-limit 429 ratio (PRO) < 1%

Grafana dashboard path: `http://localhost:3000/d/coivitas-managed-service-alpha`

Alerting channels (Alertmanager / PagerDuty) are not configured in the alpha phase; to be added.

---

## 5. Scale-up path

See `SLO.md` §5. Summary:

| QPS | Deployment shape |
| --- | --- |
| < 500 | current docker-compose single instance |
| 500-2000 | dual instance + sticky LB |
| 2000-5000 | K8s + session affinity |
| > 5000 | move rate-limiter to Redis; usage-recorder batch flush |
| global | DNS geo routing; Postgres CRDT sync (future) |

---

## 6. Pre-production checklist (**must be completed**)

- Replace the FederatedResolver wiring stub (connect a real federation node)
- Replace the revocation-checker stub (connect RevocationList)
- Configure TLS termination (Caddy / nginx / mTLS)
- Move secret management out of `.env` (Vault / AWS Secret Manager)
- Run 5min/15min/30min load curves to calibrate SLO and buckets
- Connect Alertmanager / PagerDuty
- Multi-window multi-burn-rate alerting
- Disaster recovery: Postgres replica + off-site backup
- Move rate-limiter to Redis (start when QPS approaches 5000)
- Connect an OTel trace exporter (Jaeger / Tempo)

---

## 7. References

- `packages/managed-service-runtime/` — implementation source
- `packages/policy/sql/008-create-managed-service-tenants.sql` — SQL schema
