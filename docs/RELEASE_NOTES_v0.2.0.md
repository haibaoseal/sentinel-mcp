# Release notes — v0.2.0

Release date: 2026-10-20

Theme: **from a governance core to a service another team can call.**

## Added

- **HTTP control plane** (`app/api/`): FastAPI, OpenAPI at `/docs`, versioned
  `/v1` routes for tasks, approvals, audit, tools and policy metadata.
- **Authentication and RBAC**: bearer API keys bound to tenant/role/subject;
  `viewer < operator < approver < admin`; production refuses to start without
  explicit keys.
- **Tenant isolation**: `AgentTask.tenant_id` and `ApprovalRequest.tenant_id`,
  scoped queries, cross-tenant reads return 404.
- **Observability**: structured JSON logs with request/tenant/task ids,
  Prometheus metrics, `/healthz` and `/readyz`, provisioned Grafana dashboard and
  Prometheus alert rules.
- **Operational safety**: per-tenant token bucket, bounded execution gate
  (429 + `Retry-After`), read-only tool retries with an audited `tool.retry`
  event, per-tool circuit breaker, transaction-scoped audit lock and Postgres
  `FOR UPDATE` row lock.
- **Schema management**: Alembic initial revision; Docker runs `upgrade head`
  before serving; test covers upgrade and downgrade.
- **Audit operations**: NDJSON export with chain verdict/head, `verify --all`,
  and archive-then-delete retention with a manifest.
- **Delivery**: Dockerfile (non-root, healthcheck), Compose stack with Postgres,
  optional Prometheus/Grafana profile, Makefile, operations/security/SLO/API/
  architecture/demo docs.
- **Evidence**: `scripts/api_smoke.py`, `scripts/load_test.py`,
  `scripts/pilot_simulation.py`; 1,000-task simulated pilot committed under
  `reports/`.

## Changed

- `AgentTask` gained `tenant_id`, `answer`, `termination`, `error`, `trace_json`;
  `ApprovalRequest` gained `tenant_id`.
- Approval execution now updates the originating task to `completed`/`rejected`/
  `failed` instead of leaving it at `waiting_approval`.
- `ConfigurationError` moved to `app.core.errors` so the service and the runtime
  share one typed error.
- `pyproject.toml` version is `0.2.0`; `[api]` and `[postgres]` extras added.
- CI install changed to `.[dev,api]` (see the workflow).

## Verification

```text
python -m pytest apps/api/app/tests -q
466 passed, 3 skipped
python -m ruff check apps/api/app mcp_servers scripts migrations
All checks passed
python -m app.evals.cli
19/19 scenarios, 16 gated metrics, no regression
python scripts/api_smoke.py
OK: HTTP service smoke test passed
python scripts/pilot_simulation.py --tasks 1000
1000 tasks, 600 high-risk prevented, 0 executed, 1000/1000 chains verified
```

## Upgrade notes

- Fresh database: `alembic upgrade head`.
- A 0.1.x development SQLite file has no `tenant_id`/`answer`/`trace_json` and no
  `alembic_version`. Stamp it at the baseline, then upgrade:
  `python -m alembic stamp ea3516f6309f` followed by
  `python -m alembic upgrade head`. This path is tested on a copy of the 0.1
  schema; the migration keeps existing rows and fills `tenant_id` with `default`.
- Set `SENTINEL_API_KEYS_JSON` before starting with `APP_ENV=production`.
- Set `AUTO_CREATE_SCHEMA=false` and `AUDIT_HMAC_KEY` in production.

## Known limitations

See the README's Honest limitations, `docs/PRODUCTION_READINESS.md` and
`docs/SECURITY.md`. The largest are: static keys instead of OIDC, per-process
rate limit/breaker, application-level tenant isolation (no RLS), no tracing, no
approval notifications or resume-after-approval, and no real customer pilot.
