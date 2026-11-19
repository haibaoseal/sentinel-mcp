"""The migration chain must build the same schema the models describe.

A test that only calls `create_all` would never catch a migration that has
drifted from the models, which is exactly the failure a production deployment
discovers at startup. This runs the real Alembic command against a temporary
SQLite file.
"""

from __future__ import annotations

import os
import sqlite3
import subprocess
import sys
from pathlib import Path

from app.db.session import build_engine, missing_service_columns
from sqlalchemy import text

REPO_ROOT = Path(__file__).resolve().parents[4]


def _run_alembic(*args: str, database_url: str) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env["DATABASE_URL"] = database_url
    env["PYTHONPATH"] = str(REPO_ROOT / "apps" / "api")
    return subprocess.run(
        [sys.executable, "-m", "alembic", *args],
        cwd=REPO_ROOT,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )


def test_alembic_upgrade_builds_the_service_schema(tmp_path):
    db_path = tmp_path / "migrated.db"
    url = f"sqlite:///{db_path.as_posix()}"
    _run_alembic("upgrade", "head", database_url=url)

    with sqlite3.connect(db_path) as connection:
        tables = {
            row[0]
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        assert {
            "agent_tasks",
            "approval_requests",
            "audit_events",
            "tool_calls",
            "policy_decisions",
            "eval_runs",
        } <= tables
        task_columns = {row[1] for row in connection.execute("PRAGMA table_info(agent_tasks)")}
        assert {"tenant_id", "answer", "termination", "trace_json"} <= task_columns
        approval_columns = {
            row[1] for row in connection.execute("PRAGMA table_info(approval_requests)")
        }
        assert "tenant_id" in approval_columns


def test_alembic_downgrade_is_clean(tmp_path):
    db_path = tmp_path / "downgraded.db"
    url = f"sqlite:///{db_path.as_posix()}"
    _run_alembic("upgrade", "head", database_url=url)
    _run_alembic("downgrade", "base", database_url=url)

    with sqlite3.connect(db_path) as connection:
        tables = {
            row[0]
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
    assert tables == {"alembic_version"}


def test_legacy_dev_schema_is_reported_instead_of_failing_on_the_first_query(tmp_path):
    engine = build_engine(f"sqlite:///{(tmp_path / 'legacy.db').as_posix()}")
    with engine.begin() as connection:
        connection.execute(
            text("CREATE TABLE agent_tasks (id VARCHAR(64) PRIMARY KEY, title VARCHAR(255))")
        )
    missing = missing_service_columns(engine)
    assert "agent_tasks.tenant_id" in missing
    assert "agent_tasks.answer" in missing
    engine.dispose()
