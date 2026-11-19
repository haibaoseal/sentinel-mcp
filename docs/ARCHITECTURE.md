# Architecture

## Request lifecycle

```text
POST /v1/tasks
  │
  ├─ Auth: bearer key → Principal(tenant, role, subject)
  ├─ Limits: tenant token bucket, global execution gate (429 on overflow)
  ├─ INSERT AgentTask(tenant_id, status=running)
  │
  ├─ AgentLoop.run_traced
  │    ├─ input guardrail
  │    ├─ provider decision (replay or OpenAI-compatible model)
  │    ├─ for each proposed call:
  │    │    INSERT ToolCall + PolicyDecisionRecord
  │    │    INSERT AuditEvent(tool.proposed), AuditEvent(policy.evaluated)
  │    │    ├─ block → AuditEvent(tool.blocked); result blocked
  │    │    ├─ require_approval → INSERT ApprovalRequest
  │    │    │                     AuditEvent(approval.requested); result waiting
  │    │    └─ allow → ToolSource.execute (retry/breaker for reads)
  │    │                 AuditEvent(tool.executed|tool.failed)
  │    └─ output guardrail; Trace stored on the task
  │
  ├─ UPDATE AgentTask(status, answer, termination, trace_json)
  └─ COMMIT  ← decision, approval row, audit events and task state are one unit
```

A held call is decided later by `POST /v1/approvals/{id}/approve|reject`. That
request loads the approval, validates tool/argument binding, re-evaluates an edit,
executes through the **same** `Firewall.execute(..., approval_id=...)`, appends
`approval.*` events to the same chain, and updates the task status. There is no
second execution path.

## Components

| Component | Responsibility | Does not do |
|---|---|---|
| `api/` | HTTP, auth, tenancy, limits, serialization | execute tools, decide policy |
| `agent/loop.py` | turns provider output into `ToolRequest`s, builds trace | execute tools |
| `governance/firewall.py` | policy decision, approval hold, audit, the only execution call | know about HTTP or MCP |
| `policy/` | YAML rules, fail-closed evaluation, risk escalation | persist or execute |
| `approvals/` | queue reads, approve/reject, edit re-evaluation | bypass the firewall |
| `tools/` | descriptors + implementations, registry | policy or audit |
| `audit/` | hash chain writer/verifier, export/retention CLI | decide |
| `db/` | engine, session factory, models | business rules |
| `observability/` | JSON logs, Prometheus metrics | mutate state |
| `resilience.py` | read-only retry, per-tool breaker | retry writes |
| `mcp/` | inbound/outbound MCP transports | relax governance for remote tools |

## Transaction and concurrency model

- **One session per HTTP request**, closed by the dependency; endpoints commit.
- A task run and all its audit events share one transaction. If the run fails,
  the API rolls back and a failed task is written on a separate path; a partial
  decision without an audit row is not possible.
- **Audit `seq`** is allocated inside the transaction from `MAX(seq)` for the
  task. A unique `(task_id, seq)` constraint makes an interleaving bug a loud
  `IntegrityError` rather than a forked chain.
- **Per-task lock** is held for the life of the transaction, not just one
  insert. Releasing it after every insert deadlocks: the transaction keeps its
  write lock until commit, while the next writer waits for the process lock held
  by the first. The lock is released by Session `after_transaction_end`.
- **Postgres** additionally takes `SELECT ... FOR UPDATE` on the task row, which
  serialises writers across replicas. SQLite ignores it; the in-process lock plus
  SQLite's single writer is the development story.
- **Approval execution** is a separate transaction from the agent run. The run
  already ended as `waiting_approval`; the approval updates the task after the
  call succeeds. The original trace is not rewritten — it records what the agent
  run did, and the `approval.*` events record what happened later.
- **Rate limit and execution gate** are in-process. The API is synchronous;
  FastAPI runs sync endpoints in a thread pool, and the gate bounds how many
  agent runs occupy those threads. Multi-replica needs a shared limiter/queue.

## Data model

```text
AgentTask 1──n ToolCall 1──n PolicyDecisionRecord
    │            │
    │            └──1 ApprovalRequest (optional)
    │
    └──n AuditEvent (per-task hash chain, seq unique per task)
```

`AgentTask` carries `tenant_id`, status, provider/model, answer, termination,
error and the serialized trace. `ApprovalRequest` denormalises `tenant_id` for
queue queries; `task_id` remains the source of truth. `AuditEvent` stores the
hashed envelope fields plus the sanitized payload.

New columns since 0.1: `AgentTask.tenant_id`, `answer`, `termination`, `error`,
`trace_json`; `ApprovalRequest.tenant_id`. Revision `ea3516f6309f` is the 0.1
baseline and `b7a2c9d1e4f0` adds the service columns. A pre-0.2 development
database is upgraded by stamping the baseline and running `upgrade head`; that
path is tested against a copy of the 0.1 schema, and existing rows get
`tenant_id='default'`. There is no silent `create_all` alteration.

## Deployment

```text
[client] → [ingress/TLS] → [api replicas] → [Postgres]
                              │  │
                              │  └→ /metrics ← Prometheus → Grafana/alerts
                              └→ sandbox volume (filesystem/SQL tools)
```

The container runs migrations then uvicorn as a non-root user. The API is
stateless; the sandbox and database are the state. `AUTO_CREATE_SCHEMA=false` in
the image, so a missing migration is a startup failure rather than a silent
`create_all`.

## Why the service layer is separate from the core

The governance core can be imported as a library and is tested without FastAPI.
The service layer adds identity, tenancy, transport, limits and observability
without teaching the firewall about HTTP. That keeps the "single execution
boundary" claim testable at the library level, and it means the MCP server and
the REST API use the same `Runtime`/`Firewall` construction path.

## Known architectural limits

- The approval decision is out of band: the original run is not resumed.
- The audit chain is per task; there is no global cross-task ordering.
- The default SQLite backend is single-writer; Postgres is the production path.
- Tracing is span data stored with the task, not an OpenTelemetry export.
- Tenant isolation is application-level; RLS is planned.
