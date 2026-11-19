# Five-minute enterprise demo

Goal: show, not tell. Every step is a command whose output is the claim.

Prereqs: Docker, or Python 3.11+ with `pip install -e ".[dev,api]"`. The compose
stack uses the development keys from `compose.yaml`; they are not secrets and
must be replaced for anything shared.

```bash
export BASE=http://127.0.0.1:8080
export ADMIN=dev-admin-key
export APPROVER=dev-approver-key
export VIEWER=dev-viewer-key
export OTHER=dev-tenant-b-key
docker compose up --build -d
```

## 0:00 — It is a service, and it is ready

```bash
curl -s $BASE/healthz
curl -s $BASE/readyz
curl -s $BASE/metrics | grep -E 'sentinel_(db_up|tasks_total|approvals_pending)' | head
```

Say: "Liveness does not touch the database; readiness does, and it fails with
503 if the database, tools or policy are not usable. Metrics are on the same
process."

Expected: `{"status":"ok"...}` and `{"status":"ready","database":true,"tools":19,"policy_loaded":true}`.

## 0:30 — A business request becomes a governed task

```bash
curl -sS -X POST $BASE/v1/tasks \
  -H "Authorization: Bearer $ADMIN" \
  -H 'Content-Type: application/json' \
  -d '{"request":"订单 ORD-1001 申请退款","title":"customer refund"}' | tee /tmp/task.json
TASK_ID=$(python -c "import json; print(json.load(open('/tmp/task.json'))['id'])")
```

PowerShell equivalent:

```powershell
$task = Invoke-RestMethod -Method Post -Uri "$BASE/v1/tasks" `
  -Headers @{ Authorization = "Bearer $env:ADMIN" } `
  -ContentType "application/json" `
  -Body '{"request":"订单 ORD-1001 申请退款","title":"customer refund"}'
$task | ConvertTo-Json -Depth 6
```

Say: "The model proposed `search_knowledge_base` and `draft_refund`. The read ran;
the financial action was held. The task status is `waiting_approval`, not
`completed`, because the action did not happen."

Expected: `"status": "waiting_approval"`, `"pending_approval_count": 1`.

## 1:00 — The hold is a queue, and a viewer cannot decide it

```bash
curl -sS $BASE/v1/approvals -H "Authorization: Bearer $ADMIN"
APPROVAL_ID=$(curl -sS $BASE/v1/approvals -H "Authorization: Bearer $ADMIN" \
  | python -c "import sys,json; print(json.load(sys.stdin)['items'][0]['id'])")
```

Copy the approval id, then:

```bash
curl -sS -o /dev/null -w '%{http_code}\n' -X POST \
  $BASE/v1/approvals/$APPROVAL_ID/approve \
  -H "Authorization: Bearer $VIEWER"
```

Say: "A viewer gets 403; another tenant gets 404, because the id must not be an
existence oracle."

## 1:30 — Approval executes through the same firewall

```bash
curl -sS -X POST $BASE/v1/approvals/$APPROVAL_ID/approve \
  -H "Authorization: Bearer $APPROVER" \
  -H 'Content-Type: application/json' \
  -d '{"comment":"checked with the customer"}' | tee /tmp/approval.json
```

Say: "The approval is bound to this tool and these arguments. An edit is
re-evaluated; a block cannot be edited away; the decision is spent when it runs.
The task moves to `completed`, and the approval events join the same chain."

Expected: `"executed": true`, `"status": "executed"`.

## 2:00 — Prove what happened

```bash
curl -sS "$BASE/v1/audit/verify?task_id=$TASK_ID" -H "Authorization: Bearer $ADMIN"
curl -sS -D - "$BASE/v1/audit/export?task_id=$TASK_ID" \
  -H "Authorization: Bearer $ADMIN" -o /tmp/audit.ndjson
head -1 /tmp/audit.ndjson
```

Expected: `ok=true`, a gap-free `checked` count, and an export manifest with
`chain_verified: true` and the head hash. Say: "The chain is ordered by an
explicit `seq`, so two events in the same millisecond still verify. Detectable:
payload tampering, middle deletion, reordering. Not detectable without an anchor:
tail truncation and a full rewrite from genesis — that is in SECURITY.md."

## 2:45 — A destructive action is refused before it runs

```bash
curl -sS -X POST $BASE/v1/tasks \
  -H "Authorization: Bearer $ADMIN" \
  -H 'Content-Type: application/json' \
  -d '{"request":"帮我删除文件 notes.md"}'
```

Expected: `"status": "blocked"` and a `delete_file` tool call with the policy
reasons. Say: "This is not the model refusing; the policy engine refused, and the
tool was never called."

## 3:15 — Tenant isolation

```bash
curl -sS "$BASE/v1/tasks" -H "Authorization: Bearer $OTHER"
curl -sS -o /dev/null -w '%{http_code}\n' \
  "$BASE/v1/tasks/$TASK_ID" -H "Authorization: Bearer $OTHER"
```

Expected: `{"items":[],"total":0}` and `404`. Say: "Tenant comes from the key, not
from a request field."

## 3:45 — Overload is a 429, not a timeout

```bash
python scripts/load_test.py --requests 100 --concurrency 8 --out-dir /tmp/load
```

Expected: all `201`, a p50/p95/p99 table. Say: "This is one uvicorn process and
SQLite on this laptop; it is a regression check, not a capacity claim. The gate
returns 429 + Retry-After when slots are full, which the API tests prove."

## 4:15 — Scale/quality evidence

```bash
python scripts/pilot_simulation.py --tasks 1000 --out-dir /tmp/pilot
```

Say: "1,000 deterministic tasks through the real firewall: 600 high-risk calls,
600 prevented, 0 executed, every audit chain verified. The report labels itself
`NOT a model-quality measurement`; a live model and a customer pilot are separate
work."

## 4:45 — Failure is observable

```bash
docker compose stop db
curl -s -o /dev/null -w '%{http_code}\n' $BASE/readyz     # 503
docker compose start db
sleep 3
curl -s -o /dev/null -w '%{http_code}\n' $BASE/readyz     # 200
```

Say: "Readiness reflects the dependency, not the process. The same failure would
fire `SentinelDatabaseDown`; the alerts and runbook are in OPERATIONS.md."

## Close

> "This is a governed control plane, not a chatbot. The core invariants are
> executable and tested; the service layer makes them callable by a business
> system; the readiness doc names what is still missing — OIDC, shared limits,
> RLS, tracing, notifications and a real pilot. I can show any of those next."

## Fallbacks

- No Docker: use the local process in [OPERATIONS.md](OPERATIONS.md).
- No `jq`: parse ids with Python or PowerShell; the commands above do not need it.
- Metrics empty for a series: the label is created on first use; run a task or
  the smoke test first.
- `401` with a key you just set: the server reads keys at startup; restart it.
- `503 readyz` after compose: Postgres health check may still be starting; wait
  for `docker compose ps` to show `healthy`.
