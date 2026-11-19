"""End-to-end smoke test for the HTTP service.

Runs against an in-process app and a temporary SQLite database, so it needs no
server, no Postgres and no API key beyond the test fixture. Exit code is 0 only
if every step succeeds -- this is a check, not a printout.

    python scripts/api_smoke.py
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "apps" / "api"))

from app.api.main import create_app  # noqa: E402
from app.core.config import Settings  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

KEYS = [
    {"key": "smoke-admin-key", "tenant": "tenant-a", "role": "admin", "subject": "alice"},
    {"key": "smoke-approver-key", "tenant": "tenant-a", "role": "approver", "subject": "rita"},
    {"key": "smoke-other-key", "tenant": "tenant-b", "role": "admin", "subject": "carol"},
]
ADMIN = {"Authorization": "Bearer smoke-admin-key"}
APPROVER = {"Authorization": "Bearer smoke-approver-key"}
OTHER = {"Authorization": "Bearer smoke-other-key"}


def fail(message: str) -> int:
    print(f"FAIL: {message}", file=sys.stderr)
    return 1


def main() -> int:
    database = Path(tempfile.mkdtemp()) / "smoke.db"
    settings = Settings(
        _env_file=None,
        app_env="development",
        database_url=f"sqlite:///{database.as_posix()}",
        api_keys_json=json.dumps(KEYS),
        tool_sandbox_root=str(ROOT / "sandbox"),
        knowledge_root=str(ROOT / "knowledge"),
        rate_limit_per_minute=1000,
        max_concurrent_tasks=4,
        log_level="warning",
    )
    app = create_app(settings)

    with TestClient(app) as client:
        if client.get("/healthz").status_code != 200:
            return fail("healthz")
        ready = client.get("/readyz")
        if ready.status_code != 200 or ready.json()["tools"] < 10:
            return fail(f"readyz: {ready.text}")

        task_response = client.post(
            "/v1/tasks",
            json={"request": "订单 ORD-1001 申请退款", "title": "smoke refund"},
            headers=ADMIN,
        )
        if task_response.status_code != 201:
            return fail(f"create task: {task_response.text}")
        task = task_response.json()
        print(f"task       : {task['id']} status={task['status']} tools={task['tool_call_count']}")
        if task["status"] != "waiting_approval":
            return fail("a refund proposal was not held for approval")

        approvals = client.get("/v1/approvals", headers=APPROVER).json()
        if approvals["total"] != 1:
            return fail("the hold did not appear in the approval queue")
        approval = approvals["items"][0]

        if (
            client.post(
                f"/v1/approvals/{approval['id']}/approve", json={}, headers=OTHER
            ).status_code
            != 404
        ):
            return fail("another tenant could see or decide the approval")

        decision = client.post(
            f"/v1/approvals/{approval['id']}/approve",
            json={"comment": "smoke"},
            headers=APPROVER,
        )
        if decision.status_code != 200 or not decision.json()["executed"]:
            return fail(f"approve: {decision.text}")
        print(f"approval   : executed={decision.json()['executed']}")

        refreshed = client.get(f"/v1/tasks/{task['id']}", headers=ADMIN).json()
        if refreshed["status"] != "completed":
            return fail(f"task status after approval: {refreshed['status']}")
        print(f"task final : status={refreshed['status']}")

        verify = client.get(f"/v1/audit/verify?task_id={task['id']}", headers=ADMIN).json()
        if not verify["ok"]:
            return fail(f"audit chain: {verify}")
        print(f"audit      : ok checked={verify['checked']}")

        export = client.get(f"/v1/audit/export?task_id={task['id']}", headers=ADMIN)
        if export.status_code != 200 or export.headers.get("X-Chain-Verified") != "true":
            return fail("audit export")
        lines = [line for line in export.text.splitlines() if line.strip()]
        if len(lines) != verify["checked"] + 1:
            return fail("export row count does not match the chain")
        print(f"export     : {len(lines)} NDJSON records")

        metrics = client.get("/metrics")
        if metrics.status_code != 200 or "sentinel_tasks_total" not in metrics.text:
            return fail("metrics endpoint")
        print("metrics    : ok")

        if client.get("/v1/tasks", headers=OTHER).json()["total"] != 0:
            return fail("tenant-b can see tenant-a tasks")

    print("OK: HTTP service smoke test passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
