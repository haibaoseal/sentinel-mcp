# HTTP API

Base URL: `http://127.0.0.1:8080` under Docker, `http://127.0.0.1:8000` locally.
OpenAPI and the interactive schema are at `/docs`; the raw document is
`/openapi.json`.

Every endpoint under `/v1` requires `Authorization: Bearer <key>`. The key
determines the tenant, role and subject; no request can choose its own tenant.

## Error envelope

Every failure, including validation and authentication, uses one shape:

```json
{
  "error": {
    "code": "FORBIDDEN",
    "message": "role 'viewer' cannot perform this action; 'approver' or higher is required",
    "detail": {},
    "request_id": "6f1c0a7d9e3b4a2c8d5e"
  }
}
```

`code` is stable; `request_id` matches the access log line and the
`X-Request-ID` response header. Quote it when reporting a failure.

| Status | Codes |
|---|---|
| 400 | `INVALID_ARGS` |
| 401 | `UNAUTHENTICATED` |
| 403 | `FORBIDDEN`, `POLICY_BLOCKED` |
| 404 | `TASK_NOT_FOUND`, `APPROVAL_NOT_FOUND`, `TOOL_NOT_FOUND` |
| 409 | `APPROVAL_STATE`, `APPROVAL_MISMATCH`, `APPROVAL_REQUIRED` |
| 422 | `VALIDATION_ERROR` |
| 429 | `RATE_LIMITED`, `TOO_MANY_CONCURRENT_TASKS` |
| 500 | `INTERNAL_ERROR`, `AUDIT_INTEGRITY_BROKEN`, `CONFIGURATION_ERROR` |
| 502/503 | `TOOL_EXECUTION_FAILED`, `MCP_SERVER_ERROR`, `CIRCUIT_OPEN` |

## Tasks

### Create and run a task

`POST /v1/tasks` · role `operator` or higher · `201`

```bash
curl -sS -X POST http://127.0.0.1:8080/v1/tasks \
  -H "Authorization: Bearer $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{"request":"订单 ORD-1001 申请退款","title":"refund review"}'
```

```json
{
  "id": "7a1f...",
  "tenant_id": "tenant-a",
  "title": "refund review",
  "status": "waiting_approval",
  "answer": "该操作需要人工审批后才能继续（draft_refund），当前未自动执行。",
  "termination": "completed",
  "tool_call_count": 2,
  "pending_approval_count": 1,
  "audit_event_count": 6,
  "tool_calls": [
    {"tool_name": "search_knowledge_base", "status": "executed", "action_type": "read"},
    {"tool_name": "draft_refund", "status": "waiting_approval", "action_type": "financial"}
  ],
  "trace": {"status": "waiting_approval", "spans": ["..."]}
}
```

The call is synchronous. A long live-model run holds an execution slot; the
service returns `429 TOO_MANY_CONCURRENT_TASKS` when all slots are busy. An async
queue endpoint is future work.

`extra="forbid"`: an unknown field is `422 VALIDATION_ERROR`, not silently
ignored.

### List tasks

`GET /v1/tasks?status=waiting_approval&limit=20&offset=0` · role `viewer`

```json
{"items": [{"id": "...", "status": "waiting_approval"}], "total": 1, "limit": 20, "offset": 0}
```

### Get a task

`GET /v1/tasks/{id}` · role `viewer`

Returns the task summary, its tool calls (with risk reasons and status) and the
stored trace. A task from another tenant is `404`, not `403`.

### Get the trace

`GET /v1/tasks/{id}/trace` · role `viewer`

Returns the structured trace the run produced: model, policy, tool, retrieval,
guardrail and output spans. A run with no stored trace is `404 TRACE_NOT_FOUND`.

## Approvals

### List

`GET /v1/approvals?status=pending|approved|modified|rejected|executed|failed|all`

Role `viewer`. Results are tenant-scoped and oldest-first.

```json
{
  "items": [{
    "id": "b31c...",
    "task_id": "7a1f...",
    "status": "pending",
    "risk_level": "critical",
    "original_arguments": {"order_id": "ORD-1001"}
  }],
  "total": 1
}
```

### Approve

`POST /v1/approvals/{id}/approve` · role `approver` or higher · `200`

```json
{"comment": "checked with the customer"}
```

With an edit (the edited arguments are re-evaluated before execution):

```json
{"comment": "use the corrected order", "modified_arguments": {"order_id": "ORD-2002"}}
```

An edit that policy now blocks, or that raises the risk level, is refused; the
approval stays `pending` and the refusal is written to the audit chain. An
approval is bound to the proposal and cannot be replayed or moved to another
call.

### Reject

`POST /v1/approvals/{id}/reject` · role `approver` or higher · `200`

```json
{"comment": "wrong customer"}
```

Nothing executes. The task is marked `rejected` and the refusal is audited.

## Audit

### Events

`GET /v1/audit/events?task_id=<id>&event_type=tool.executed&limit=100&offset=0`

Role `viewer`. A `task_id` from another tenant is `404`.

### Verify

`GET /v1/audit/verify?task_id=<id>` · role `viewer`

```json
{"task_id": "7a1f...", "ok": true, "checked": 11, "first_bad_seq": null, "reason": null, "event_count": 11}
```

`ok=false` includes the exact `first_bad_seq` and a reason (`sequence gap`,
`prev_hash does not match predecessor`, `event_hash does not recompute`).

### Export

`GET /v1/audit/export?task_id=<id>` · role `viewer`

Newline-delimited JSON. The first line is a manifest with `chain_verified`,
`checked` and `head`; each following line is one event. Headers:

```text
X-Chain-Verified: true|false
X-Chain-Checked: 11
Content-Disposition: attachment; filename="audit-<id>.ndjson"
```

## Catalogue

| Endpoint | Role | Returns |
|---|---|---|
| `GET /v1/whoami` | any key | tenant, subject, role, key fingerprint |
| `GET /v1/tools` | viewer | every tool with action type, risk, source and approval flag |
| `GET /v1/policies` | viewer | policy version, sha256, rule count; raw YAML only for admin |

## Operations

| Endpoint | Auth | Notes |
|---|---|---|
| `GET /healthz` | none | process liveness; no DB access |
| `GET /readyz` | none | DB `SELECT 1`, tools > 0, policy loaded; 503 when not ready |
| `GET /metrics` | optional bearer | Prometheus exposition; protected by `METRICS_TOKEN` when set |
| `GET /` | none | service name, version, links |

## Pagination, rate limits and idempotency

- List endpoints use `limit` and `offset`; responses include `total`.
- Every authenticated response includes `X-Request-ID`.
- Task creation returns `X-RateLimit-Limit` and `X-RateLimit-Remaining`; a
  `429 RATE_LIMITED` or `429 TOO_MANY_CONCURRENT_TASKS` includes `Retry-After`.
- **There is no idempotency key.** A retried `POST /v1/tasks` creates a second
  task and a second audit chain. Add an `Idempotency-Key` header and a unique
  index before putting this behind an automatic retry layer.
