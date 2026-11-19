# Service level objectives

These are pilot SLOs for a single-replica deployment with Postgres. They are
deliberately modest and measurable from the endpoints the service already
exposes. They are not a claim about model latency or about a multi-replica
cluster.

## SLIs and SLOs

| SLI | Definition | SLO (30 days) | Source |
|---|---|---|---|
| Availability | Fraction of `/readyz` probes returning 200 | **99.5%** | Load balancer / Prometheus blackbox |
| HTTP 5xx rate | 5xx / all `/v1` responses | **< 1%** | `sentinel_http_requests_total{status=~"5.."}` |
| Task creation latency | Time to `POST /v1/tasks` for the deterministic replay provider | **p95 < 1.5 s, p99 < 3 s** | `sentinel_http_request_duration_seconds_bucket{path="/v1/tasks"}` |
| Task completion rate | Tasks ending `completed` rather than `failed` (excluding deliberate holds/blocks) | **> 99%** of non-held, non-blocked runs | `sentinel_tasks_total{status}` |
| Audit verification | Fraction of verify requests reporting `ok=true` | **100%**; any failure is a critical incident | `sentinel_audit_verify_total{result}` |
| Approval backlog | Pending approvals older than the review target | **p95 < 4 business hours** | `sentinel_approvals_pending` + a queue-age query |
| Overload behaviour | 429 responses, not 5xx/timeouts, when the gate is full | **100%** of gate-full requests are 429 with `Retry-After` | `sentinel_http_requests_total{status="429"}` |

The latency SLO applies to the deterministic replay provider. A live model adds
its own latency; measure that separately and do not hide it inside this SLO.

## Error budget

- 99.5% availability over 30 days allows about **3 h 36 min** of unavailability.
- Spend policy: freeze feature releases when more than half the budget is spent
  in a week; spend the remaining budget on reliability work, not new endpoints.
- A failed audit verification does not consume the budget; it is an incident
  regardless of the availability number.

## Alerts

| Alert | Expression | Severity | First response |
|---|---|---|---|
| `SentinelAuditChainVerificationFailed` | any `result="failed"` increase over 5m | critical | Stop writes, snapshot DB, follow the audit incident runbook |
| `SentinelApprovalBacklog` | `sentinel_approvals_pending > 20` for 10m | warning | Page the reviewer rota; check whether the queue is stuck on one tool |
| `SentinelHighErrorRate` | 5xx ratio > 5% for 5m | warning | Inspect logs by `request_id`; check DB and circuit breaker |
| `SentinelDatabaseDown` | `sentinel_db_up == 0` for 1m | critical | Check Postgres; `/readyz` will be 503; scale API to zero if writes cannot be trusted |
| `SentinelCircuitOpen` | `sentinel_circuit_breaker_open == 1` for 5m | warning | Check the dependency; the breaker is protecting the service |

## Measurement caveats

- Metrics are per process. With N replicas, aggregate in Prometheus and expect
  the rate limiter and breaker to be per replica until shared state is added.
- The load-test report in `reports/load_test.md` is a single-node local
  measurement, not a capacity plan.
- Approval age is a process metric, not something the service enforces. It must
  be computed from `approval_requests.created_at` and a business-hours calendar.
- The latency SLO is about the service path, not the model. A live provider call
  can dominate end-to-end latency; record it with the provider identity that the
  trace already carries.
