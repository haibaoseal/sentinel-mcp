"""Postgres smoke test: run the real service against a migrated Postgres.

CI starts a Postgres service, runs `alembic upgrade head`, then this script. It
does not create tables itself (`AUTO_CREATE_SCHEMA=false`), so a migration that
drifts from the models fails here rather than in a deployment.

    DATABASE_URL=postgresql+psycopg://... python scripts/postgres_smoke.py
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "apps" / "api"))

from app.api.main import create_app  # noqa: E402
from app.core.config import Settings  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

KEYS = [
    {"key": "pg-admin-key-123", "tenant": "pg-smoke", "role": "admin", "subject": "alice"},
    {"key": "pg-approver-key-1", "tenant": "pg-smoke", "role": "approver", "subject": "rita"},
    {"key": "pg-other-key-123", "tenant": "pg-other", "role": "admin", "subject": "carol"},
]
ADMIN = {"Authorization": "Bearer pg-admin-key-123"}
APPROVER = {"Authorization": "Bearer pg-approver-key-1"}
OTHER = {"Authorization": "Bearer pg-other-key-123"}


def main() -> int:
    database_url = os.getenv("DATABASE_URL", "")
    if not database_url.startswith("postgresql"):
        print("SKIPPED: DATABASE_URL is not a Postgres URL")
        return 77

    settings = Settings(
        _env_file=None,
        app_env="development",
        database_url=database_url,
        api_keys_json=json.dumps(KEYS),
        tool_sandbox_root=str(ROOT / "sandbox"),
        knowledge_root=str(ROOT / "knowledge"),
        auto_create_schema=False,
        rate_limit_per_minute=1000,
        max_concurrent_tasks=4,
        log_level="warning",
    )
    app = create_app(settings)
    with TestClient(app) as client:
        if client.get("/readyz").status_code != 200:
            print(f"FAIL: readyz {client.get('/readyz').text}", file=sys.stderr)
            return 1
        task = client.post(
            "/v1/tasks",
            json={"request": "订单 ORD-9001 申请退款"},
            headers=ADMIN,
        )
        if task.status_code != 201 or task.json()["status"] != "waiting_approval":
            print(f"FAIL: create task {task.status_code} {task.text}", file=sys.stderr)
            return 1
        task_id = task.json()["id"]
        approval = client.get("/v1/approvals", headers=APPROVER).json()["items"][0]
        if (
            client.post(
                f"/v1/approvals/{approval['id']}/approve", json={}, headers=OTHER
            ).status_code
            != 404
        ):
            print("FAIL: cross-tenant approval was reachable", file=sys.stderr)
            return 1
        decision = client.post(f"/v1/approvals/{approval['id']}/approve", json={}, headers=APPROVER)
        if decision.status_code != 200 or not decision.json()["executed"]:
            print(f"FAIL: approve {decision.status_code} {decision.text}", file=sys.stderr)
            return 1
        verify = client.get(f"/v1/audit/verify?task_id={task_id}", headers=ADMIN).json()
        if not verify["ok"]:
            print(f"FAIL: audit {verify}", file=sys.stderr)
            return 1
        if client.get("/v1/tasks", headers=OTHER).json()["total"] != 0:
            print("FAIL: tenant-b saw tenant-a tasks", file=sys.stderr)
            return 1
    print("OK: Postgres smoke test passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
