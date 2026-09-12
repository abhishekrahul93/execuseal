# Production observability

ExecuSeal exposes Prometheus text metrics at `GET /metrics`. The endpoint is
outside the public OpenAPI document and requires a dedicated `X-Metrics-Key`.
Do not reuse agent, reviewer, or administrator credentials.

```bash
curl -s http://127.0.0.1:8000/metrics \
  -H "X-Metrics-Key: $EXECUSEAL_METRICS_API_KEYS"
```

## Metric contract

| Metric | Type | Labels | Operational use |
|---|---|---|---|
| `execuseal_http_requests_total` | Counter | method, route, status | Traffic and error rates |
| `execuseal_http_request_duration_seconds` | Histogram | method, route | Latency percentiles and SLOs |
| `execuseal_auth_failures_total` | Counter | credential_type | Credential attacks or client misconfiguration |
| `execuseal_rate_limited_total` | Counter | identity_type | Throttling pressure |
| `execuseal_safety_decisions_total` | Counter | decision_type, action | Allow, review, and block trends |
| `execuseal_ready` | Gauge | none | Dependency and audit-chain readiness |

Labels are deliberately bounded. They never contain request IDs, identity IDs,
tool names, resource names, prompts, parameters, keys, or other user-controlled
values. The `/metrics` request itself is excluded from request metrics.

## Initial alert recommendations

Tune thresholds using real baseline traffic; do not copy these into production
without validating expected request volume.

- page when `execuseal_ready` remains `0` for five minutes
- page on a sustained 5xx ratio above 1%
- warn when p95 authorization latency exceeds the service SLO
- investigate sudden authentication-failure or rate-limit spikes
- investigate an unexpected change in the allow/review/block distribution

Liveness (`/healthz`) only proves the process can answer HTTP. Readiness
(`/readyz`) also checks the shared rate-limit database and verifies the audit
chain. A failed readiness check should remove the replica from traffic while
preserving it for diagnosis.

JSON request logs contain only method, path, response status, duration, and a
validated or generated request ID. Ingress should propagate `X-Request-ID` and
the log collector should apply retention and access controls appropriate for
security telemetry.
