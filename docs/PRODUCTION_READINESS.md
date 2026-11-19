# Production readiness

> Honest matrix, not a launch announcement. "Done" means a reviewer can run a
> command in this repository and see the property hold. "Partial" means the
> mechanism exists with a named operational limit. "Planned" means it does not
> exist and the gap is described.

Last reviewed: 2026-10-20 · release `0.2.0`

## Scorecard

| Dimension | State | Evidence | Remaining gap |
|---|---|---|---|
| Reproducible run | **Partial** | `docker compose config` validates; Dockerfile is non-root with a healthcheck; `make test`; `make eval`; `python scripts/api_smoke.py` | Image build was not executed in the author's environment (Docker daemon unavailable); not published to a registry |
| HTTP contract | **Done** | FastAPI + OpenAPI at `/docs`; versioned `/v1`; one error envelope; `test_api.py` | No gRPC; no generated client SDK |
| Authentication | **Partial** | Bearer API keys, constant-time compare, keys bound to tenant/role/subject; production refuses to start without keys | Static keys, no OIDC/SSO, no per-key revocation without redeploy |
| Authorization | **Done** | `viewer < operator < approver < admin`; 403 tested; approval requires `approver` | No per-object ACL; roles are global within a tenant |
| Tenant isolation | **Partial** | Tenant is taken from the key; every task/approval/audit query is scoped; cross-tenant reads and decisions tested | Application-level only; no Postgres row-level security defence in depth |
| Database evolution | **Done** | Alembic `upgrade head` / `downgrade base` tested on a temp database; Docker runs migrations before serving | No online schema-change playbook for very large tables |
| Postgres | **Partial** | `DATABASE_URL` + `psycopg` support; dialect-specific `FOR UPDATE` row lock for audit writes; a `postgres` CI job applies the migration chain and runs the HTTP lifecycle against Postgres | Not exercised on the author's Windows machine; no RLS or connection-pool tuning |
| Durable audit | **Done** | Hash chain ordered by explicit `seq`; tamper/deletion tests; NDJSON export with chain head and verdict | Tail truncation and full-genesis rewrite need an external anchor; HMAC key is optional |
| Retention | **Partial** | `python -m app.audit.cli prune` archives then deletes with a manifest; dry run is default | No immutable object storage / legal hold; no scheduled job shipped |
| Observability — logs | **Done** | JSON logs with `request_id`, `tenant_id`, `task_id`, route, status, duration | No log shipping configuration (Loki/CloudWatch) |
| Observability — metrics | **Done** | `/metrics` with HTTP, task, policy-decision, approval, audit, circuit-breaker, DB gauges; Prometheus config and alerts | No tracing (OpenTelemetry) |
| Observability — dashboards | **Done** | Provisioned Grafana dashboard and datasource in `deploy/grafana` | Dashboard is provisioned for the compose profile only |
| Health | **Done** | `/healthz` (liveness) and `/readyz` (DB + tools + policy; 503 when not ready) | — |
| Overload | **Partial** | Per-tenant token bucket; bounded task gate returns 429 + `Retry-After`; tested | In-process only; multi-replica needs Redis/queue |
| Dependency failure | **Partial** | Read-only retries with audit trail; per-tool circuit breaker; MCP server failure isolation | Breaker state is per process; no shared state across replicas |
| Concurrency | **Partial** | Per-task and per-approval transaction-scoped locks + Postgres `FOR UPDATE` row locks; 10-thread audit test and 6-thread double-approval race test pass | SQLite remains single-writer; very high write concurrency needs Postgres |
| Security controls | **Done** | Policy fail-closed, sandbox, read-only SQL, streaming HTTP cap + allow-list, redaction, input + indirect tool-output guardrails, optional SoD, secret-free logs | No external penetration test; no RBAC admin UI |
| Compliance export | **Partial** | Snapshot-consistent NDJSON audit export with chain verdict and head; retention manifest | No CEF/SIEM connector; no field-level encryption |
| Testing | **Done** | 483 passed, 3 skipped (symlink-disallowed environment); lint + format; eval gate 19/19; Phase 9 resume-after-approval tested end to end | No multi-replica chaos suite |
| CI | **Partial** | Lint, tests, eval gate, live-path stub, demos, API smoke, and a Postgres service job that runs migrations + HTTP lifecycle | Image build/publish and multi-replica chaos are not in CI yet |
| Documentation | **Done** | README, OPERATIONS, SECURITY, SLO, API, ARCHITECTURE, DEMO | No ADR index yet |
| Business evidence | **Partial** | 1,000-task simulated pilot with safety/latency metrics; report labels itself simulated | No customer pilot, no ROI measured against a baseline |

**Bottom line:** this is deployable and operable for a single-replica pilot with
a real database and an external reviewer. It is not yet a multi-tenant SaaS:
OIDC, shared rate limits, RLS, tracing, immutable audit storage and a customer
pilot are the named gaps.

## What a reviewer can verify in ten minutes

```bash
python -m pip install -e ".[dev,api]"
python -m pytest apps/api/app/tests -q            # 483 passed, 3 skipped
python -m app.evals.cli                           # 19/19, 16 gated metrics
python scripts/api_smoke.py                       # end-to-end HTTP lifecycle
python scripts/pilot_simulation.py --tasks 1000  # simulated pilot report
docker compose up --build                         # Postgres + API + migrations
```

## Deliberate non-claims

- Not "production-grade security software"; the threat model and limitations are
  in [SECURITY.md](SECURITY.md).
- Not a model-quality benchmark; the eval and pilot reports say
  `NOT a model-quality measurement`.
- Not a multi-replica service yet; the in-process limits are listed above and in
  the README's Honest limitations.
