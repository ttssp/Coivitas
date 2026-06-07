# Managed Service SLO (alpha)

---

## 1. SLO definitions

| Metric | Target | Calculation | Alert threshold |
| --- | --- | --- | --- |
| Resolver P99 latency | < 100 ms | `histogram_quantile(0.99, rate(resolver_request_duration_ms_bucket[5m]))` | > 100 ms for 5 min |
| Resolver availability | > 99.5% / month | `1 - sum(rate(resolver_requests_total{status="5xx"}[30d])) / sum(rate(resolver_requests_total[30d]))` | < 99.5% / 30d |
| Revocation availability | > 99.5% / month | `1 - sum(rate(revocation_check_total{status="5xx"}[30d])) / sum(rate(revocation_check_total[30d]))` | < 99.5% / 30d |
| Error rate | < 0.5% | `sum(rate(...{status=~"4xx|5xx"}[5m])) / sum(rate(...[5m]))` | > 0.5% for 5 min |
| Rate-limit 429 ratio (PRO) | < 1% | should not hit the limiter under normal PRO usage | > 1% for 5 min (indicates the quota is too tight or a PRO client is being abused) |

---

## 2. Error budget

- Monthly (30d) availability target = 99.5%
- Monthly error budget = 30 \* 24 \* 60 = 43200 min \* (1 - 0.995) = **216 min** / month (~3.6 hours of allowed downtime per month)
- Error budget burned > 50% / month → trigger a product escalation meeting
- Error budget burned 100% / month → automatically start an incident review; no risky-change deployment allowed next month

---

## 3. Alpha-phase limitations (important)

> **This section explicitly marks what the current alpha phase does not do, to avoid over-claiming.**

1. **No performance benchmark**
 - The alpha phase has not run a measured P99 (requires a real federation-node deployment + load testing).
 - The SLO < 100ms is a design target, **not a guarantee**.
 - **Planned**: once a real federation node is deployed, run 5min/15min/30min load curves to calibrate buckets.
2. **Single-instance rate-limiter**
 - The in-memory token bucket does not support horizontal scaling.
 - **Scale-out path**:
 - single instance < 1000 QPS is sufficient today
 - 1000-5000 QPS: sticky session (route the same client to the same pod)
 - \> 5000 QPS: move to Redis (sliding window via INCR + EXPIRE)
3. **The revocation checker is a stub**
 - The current default implementation always returns not-revoked, **alpha demo only**.
 - **Before production** it must be replaced with a RevocationList adapter (`@coivitas/identity` implementation).
4. **Monitoring has no alerting channel**
 - Prometheus scraping + Grafana display are ready.
 - **Not configured**: Alertmanager / PagerDuty / Slack webhook.
 - **Planned**: configure Alertmanager rules based on the thresholds above.
5. **No SLO burn-rate alerting**
 - The alpha phase only watches instantaneous thresholds.
 - **Planned**: multi-window multi-burn-rate alerting (Google SRE workbook §5).

---

## 4. Observability (already available)

### 4.1 Metrics (Prometheus)

| Metric | Type | Labels | Purpose |
| --- | --- | --- | --- |
| `resolver_requests_total` | Counter | `tenant`, `tier`, `status` | QPS / error rate |
| `resolver_request_duration_ms` | Histogram | `tenant`, `tier`, buckets [10, 25, 50, 100, 250, 500, 1000] | P50 / P95 / P99 |
| `revocation_check_total` | Counter | `tenant`, `tier`, `status` | revocation-check QPS / error rate |
| `process_*` (prom-client defaults) | various | - | Node.js CPU / Memory / event loop lag |

### 4.2 Dashboard (Grafana)

`infra/managed-service/grafana/coivitas-managed-service.json` contains 4 panels:

1. **QPS by service / tier** (5m rate timeseries)
2. **Resolver P99 latency** (compared against the SLO threshold)
3. **Error rate** (4xx + 5xx / total, with red/yellow/green thresholds)
4. **Top 10 tenants by QPS (PRO tier)**

### 4.3 Logs (stdout)

- The alpha phase logs directly to stdout, collected by the docker / K8s log driver.
- No structured-logging library is introduced (pino / winston recommended for production).
- Key events:
 - `[auth-middleware] last_used_at update failed`
 - `[usage-recorder] failed to record usage`
 - `[resolver-server] startup failed` / `[revocation-server] startup failed`

### 4.4 Tracing (none yet)

- The alpha does not connect an OpenTelemetry trace exporter.
- **Planned**: the package already has `prom-client`; reuse its OTel-compatible API to connect Jaeger / Tempo.

---

## 5. Scale-up path

| Current | Trigger | Upgrade action |
| --- | --- | --- |
| single-instance docker-compose | QPS < 500 | keep |
| dual instance + LB | QPS 500-2000 | sticky session (rate-limiter still in-memory); HAProxy / Caddy |
| K8s + sticky | QPS 2000-5000 | session affinity by tenant_did header |
| K8s + Redis | QPS > 5000 | move rate-limiter to Redis; usage-recorder batch flush (cron job batch-writes every minute) |
| multi region | global distribution | DNS-based geo routing; CRDT-synced Postgres replica (future) |

---

## 6. References

- Google SRE Workbook §5 "Alerting on SLOs" — burn-rate alerting reference
