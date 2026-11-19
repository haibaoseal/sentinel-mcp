# Operations

Audience: the person who has to run this after the author has gone home.

## Topology

```text
client ──HTTPS──► api (uvicorn, N replicas in principle)
                     │
                     ├── Postgres  (tasks, approvals, audit chain)
                     ├── /metrics ──► Prometheus ──► Grafana / alerts
                     └── outbound MCP servers / HTTP allow-list / sandbox
```

The service is stateless apart from the database and the sandbox directory. The
sandbox contains the files the filesystem tools may touch and the read-only SQL
fixture; it is not a general-purpose data store.

## Configuration

Every setting has a safe default for local development. Production must set the
first three explicitly.

| Variable | Default | Notes |
|---|---|---|
| `APP_ENV` | `development` | `production` disables the development API key and requires explicit keys |
| `DATABASE_URL` | `sqlite:///./sentinel_mcp.db` | Use `postgresql+psycopg://user:pass@host:5432/db` in production |
| `SENTINEL_API_KEYS_JSON` | empty | JSON list of `{"key","tenant","role","subject"}`; required in production |
| `AUDIT_HMAC_KEY` | empty | Set in production; see key rotation below |
| `AUTO_CREATE_SCHEMA` | `true` | Set `false` in production; run Alembic instead |
| `RATE_LIMIT_PER_MINUTE` | `120` | Per tenant, in-process |
| `MAX_CONCURRENT_TASKS` | `8` | Bounded gate; overflow is 429 |
| `ENABLE_TOOL_RETRIES` | `true` | Read-only tools only |
| `CIRCUIT_FAILURE_THRESHOLD` / `CIRCUIT_RECOVERY_SECONDS` | `3` / `15` | Per tool, in-process |
| `METRICS_TOKEN` | empty | If set, `/metrics` requires `Authorization: Bearer <token>` |
| `LOG_JSON` / `LOG_LEVEL` | `true` / `info` | Set `false` only for local debugging |
| `CORS_ORIGINS` | localhost:3000 | JSON list |
| `ENABLE_MCP_SERVERS` | `false` | Starting third-party servers is an explicit decision |

Generate a key with `openssl rand -hex 32`. One key per tenant per integration;
never share the admin key with a business service.

## First run

### Docker (recommended for a reviewer)

```bash
docker compose up --build
curl -s http://127.0.0.1:8080/healthz
curl -s http://127.0.0.1:8080/readyz
curl -s http://127.0.0.1:8080/metrics | head
```

The API container runs `alembic upgrade head` before uvicorn. The Postgres volume
is named `pgdata`; `docker compose down` keeps it, `docker compose down -v`
deletes it.

Observability profile:

```bash
docker compose --profile observability up --build
# Prometheus http://127.0.0.1:9090
# Grafana    http://127.0.0.1:3000  (admin / admin unless GRAFANA_PASSWORD is set)
```

### Local process

```bash
python -m pip install -e ".[dev,api]"
cp .env.example .env
python -m alembic upgrade head
python -m uvicorn app.api.asgi:app --host 127.0.0.1 --port 8000
```

If `AUTO_CREATE_SCHEMA=true`, the service creates missing tables at startup. That
is a development convenience; it is not a substitute for migrations.

## Migrations

```bash
python -m alembic current
python -m alembic upgrade head
python -m alembic downgrade -1          # one revision back
python -m alembic revision --autogenerate -m "describe the change"
```

Rules:

1. Every schema change is a revision in `migrations/versions/`; no hand-edited
   production database.
2. A 0.1 development database can be upgraded in place:
   `python -m alembic stamp ea3516f6309f` (the pre-service baseline), then
   `python -m alembic upgrade head`. The service-layer revision adds the new
   columns and keeps existing rows; `tenant_id` is filled with `default`.
3. The migration is tested on a temporary SQLite database in the test suite, and
   a `postgres` CI job applies the same chain and runs the HTTP lifecycle against
   Postgres. A local Postgres run before a release is still recommended.
4. Deploy order: migrate, then roll out the new image. The migration must be
   backward-compatible with the previous image for a rolling deploy; destructive
   changes need an expand/migrate/contract sequence.

## API keys and rotation

Keys are read at process start. To rotate:

1. Add the new key alongside the old one in `SENTINEL_API_KEYS_JSON`.
2. Roll the service; both keys are accepted.
3. Move clients to the new key.
4. Remove the old key and roll again.

There is no per-key revocation endpoint and no OIDC/SSO yet; that is a named gap
in [PRODUCTION_READINESS.md](PRODUCTION_READINESS.md). A key that leaks must be
removed by configuration change and redeploy, and the tenant's audit trail should
be reviewed for calls made with that key's subject.

## Audit HMAC key

`AUDIT_HMAC_KEY` binds every event hash to a key held outside the database. If it
is empty, the chain still detects modification, insertion and middle deletion,
but an attacker who can rewrite the whole table can rewrite the chain from
genesis.

**There is no online key rotation with key ids yet.** Rotating the key makes
previously written chains verify as `event_hash does not recompute`. The safe
procedure today is:

1. Export and verify every task with the old key.
2. Store the archives with the old key reference.
3. Change the key at a chain boundary (new database or a documented cut-over).
4. Keep the old key available offline for archive verification.

Do not rotate by deleting the old key and hoping nobody verifies history.

## Backup and restore

### Postgres

```bash
pg_dump --format=custom --file=sentinel-$(date +%F).dump "$DATABASE_URL"
pg_restore --clean --if-exists --dbname "$DATABASE_URL" sentinel-2026-10-20.dump
```

Back up before every migration and before running retention. The audit chain is
the evidence; a backup that excludes `audit_events` is not a backup of this
system.

### SQLite (development only)

Stop the process, then copy the database and its `-wal`/`-shm` files, or run:

```bash
sqlite3 sentinel_mcp.db "PRAGMA wal_checkpoint(TRUNCATE);"
cp sentinel_mcp.db sentinel_mcp.db.bak
```

## Audit verification, export and retention

```bash
# Verify every task; exits 1 if any chain fails.
python -m app.audit.cli verify --all

# Export one task as NDJSON (manifest with head + verified events).
python -m app.audit.cli export --task <task-id> --out audit-<task-id>.ndjson

# Retention: dry run first, then archive + delete.
python -m app.audit.cli prune --days 90 --archive-dir ./archive
python -m app.audit.cli prune --days 90 --archive-dir ./archive --yes
```

`prune` exports and verifies each task before deleting it, writes a manifest with
the cut-off and the archived files, and refuses to prune a broken chain unless
`--force` is given. It deletes rows; it does not replace immutable storage.

The HTTP equivalent is `GET /v1/audit/export?task_id=...` with
`X-Chain-Verified: true|false` and `X-Chain-Checked: <n>`.

## Health, metrics and alerts

| Probe | Meaning |
|---|---|
| `GET /healthz` | Process is alive; does not touch the database |
| `GET /readyz` | Database answers `SELECT 1`, at least one tool is registered, policy is loaded; 503 otherwise |
| `GET /metrics` | Prometheus exposition; optional bearer token |

Key series:

```text
sentinel_http_requests_total{method,path,status}
sentinel_http_request_duration_seconds_bucket{method,path}
sentinel_tasks_total{status,provider}
sentinel_task_duration_seconds_bucket{status}
sentinel_tasks_inflight
sentinel_approvals_pending
sentinel_approval_decisions_total{decision}
sentinel_audit_verify_total{result}
sentinel_audit_events
sentinel_circuit_breaker_open{tool}
sentinel_db_up
sentinel_tool_retries_total{tool}
```

Alerts shipped in `deploy/prometheus/alerts.yml`:

- audit verification failed (critical);
- approval backlog > 20 for 10 minutes;
- 5xx rate > 5% for 5 minutes;
- database unreachable;
- a circuit breaker open for 5 minutes.

## Common failures

| Symptom | Likely cause | Action |
|---|---|---|
| `401 UNAUTHENTICATED` | Missing/invalid bearer key | Check `SENTINEL_API_KEYS_JSON` and the client header |
| `403 FORBIDDEN` | Role too low | Use an `approver`/`admin` key for decisions |
| `404 TASK_NOT_FOUND` on a known id | Wrong tenant | Tenant is part of the key; cross-tenant reads intentionally look like 404 |
| `429 RATE_LIMITED` | Per-tenant budget | Read `Retry-After`; raise the budget only with capacity headroom |
| `429 TOO_MANY_CONCURRENT_TASKS` | All execution slots busy | Retry; scale replicas or raise `MAX_CONCURRENT_TASKS` with load evidence |
| `503 CIRCUIT_OPEN` | Tool dependency failing repeatedly | Check the dependency; wait `CIRCUIT_RECOVERY_SECONDS`; inspect `sentinel_circuit_breaker_open` |
| `/readyz` 503 | DB down or policy/tools failed to load | Check `sentinel_db_up`, logs, and the startup exception |
| `AUDIT_INTEGRITY_BROKEN` | Chain does not verify | Preserve the database, export, treat as a security incident |

## Incident response (audit chain)

1. Stop writes if the chain is compromised (scale the API to zero or revoke keys).
2. Take a database snapshot before touching anything.
3. Run `python -m app.audit.cli verify --all` and record the first bad sequence.
4. Export the affected tasks; the manifest records the head that was observed.
5. Do not "repair" the chain by rewriting events. Restore from a backup whose
   head matches an external record, or preserve the broken chain as evidence.
6. If the HMAC key is available, verify offline with the same key; if not, record
   that the chain was unkeyed.

## Scaling notes

- **API**: stateless; scale horizontally behind a load balancer. All replicas need
  the same `SENTINEL_API_KEYS_JSON`, `AUDIT_HMAC_KEY`, database and policy file.
- **Rate limit / gate / breaker**: per process. Two replicas mean two budgets and
  two breaker states. Move to Redis (limit/breaker) and a queue (gate) before
  claiming global limits.
- **Database**: Postgres is required for multi-writer production. SQLite is a
  single-writer development backend, even with WAL.
- **Audit writes**: Postgres `SELECT ... FOR UPDATE` on the task row serialises
  writers for one task across replicas. The per-process lock is an additional
  in-process guard, not a replacement.
- **Long agent runs**: `POST /v1/tasks` is synchronous. For long model latencies,
  put a queue in front and make the endpoint return `202` + a task id; that is not
  implemented yet and is called out in Production readiness.

## Release checklist

```bash
python -m pytest apps/api/app/tests -q
python -m ruff check apps/api/app mcp_servers scripts migrations
python -m ruff format --check apps/api/app mcp_servers scripts migrations
python -m app.evals.cli
python scripts/api_smoke.py
python -m alembic upgrade head          # on a copy, then on the target
python -m alembic check                 # fails if models and migrations drifted
docker compose config >/dev/null
```

Tag only after the above pass and the migration has been exercised against a
copy of the production database.
