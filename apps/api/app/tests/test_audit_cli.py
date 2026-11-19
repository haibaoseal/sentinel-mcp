"""Audit CLI tests: verify, export and retention.

Retention is the one operation that deletes evidence, so the tests assert both
that a dry run deletes nothing and that the destructive path archives before it
removes rows.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

from app.audit import cli
from app.audit.logger import AuditLogger
from app.core.config import reset_settings_cache
from app.db.models import AgentPlan, AgentTask, AuditEvent
from app.db.session import build_engine, build_session_factory, create_schema
from sqlalchemy import select


def _prepare(tmp_path, monkeypatch):
    db_path = tmp_path / "audit-cli.db"
    url = f"sqlite:///{db_path.as_posix()}"
    monkeypatch.setenv("DATABASE_URL", url)
    monkeypatch.setenv("AUTO_CREATE_SCHEMA", "true")
    reset_settings_cache()
    engine = build_engine(url)
    create_schema(engine)
    factory = build_session_factory(engine)
    with factory() as session:
        task = AgentTask(title="audit", user_request="x", status="completed")
        session.add(task)
        session.flush()
        session.add(AgentPlan(task_id=task.id, summary="plan", steps_json=[]))
        logger = AuditLogger(session)
        for index in range(3):
            logger.write(
                task_id=task.id,
                event_type=f"test.{index}",
                actor_type="test",
                payload={"index": index},
            )
        session.commit()
        task_id = task.id
    engine.dispose()
    return task_id, db_path


def test_verify_and_export_commands(tmp_path, monkeypatch, capsys):
    task_id, _ = _prepare(tmp_path, monkeypatch)

    assert cli.main(["verify", "--task", task_id]) == 0
    out = capsys.readouterr().out
    assert "1/1 chains verified" in out

    target = tmp_path / "export.ndjson"
    assert cli.main(["export", "--task", task_id, "--out", str(target)]) == 0
    lines = [json.loads(line) for line in target.read_text(encoding="utf-8").splitlines()]
    assert lines[0]["type"] == "manifest"
    assert lines[0]["checked"] == 3
    assert [row["seq"] for row in lines[1:]] == [1, 2, 3]


def test_prune_dry_run_deletes_nothing(tmp_path, monkeypatch, capsys):
    task_id, db_path = _prepare(tmp_path, monkeypatch)
    # Make the task look old.
    engine = build_engine(f"sqlite:///{db_path.as_posix()}")
    factory = build_session_factory(engine)
    with factory() as session:
        task = session.get(AgentTask, task_id)
        task.created_at = datetime.now(UTC) - timedelta(days=200)
        session.commit()
    engine.dispose()

    archive = tmp_path / "archive"
    assert cli.main(["prune", "--days", "90", "--archive-dir", str(archive)]) == 0
    assert "dry run" in capsys.readouterr().out
    engine = build_engine(f"sqlite:///{db_path.as_posix()}")
    factory = build_session_factory(engine)
    with factory() as session:
        assert session.get(AgentTask, task_id) is not None
        assert session.scalars(select(AuditEvent).where(AuditEvent.task_id == task_id)).all()
    engine.dispose()


def test_prune_archives_then_deletes(tmp_path, monkeypatch):
    task_id, db_path = _prepare(tmp_path, monkeypatch)
    engine = build_engine(f"sqlite:///{db_path.as_posix()}")
    factory = build_session_factory(engine)
    with factory() as session:
        task = session.get(AgentTask, task_id)
        task.created_at = datetime.now(UTC) - timedelta(days=200)
        session.commit()
    engine.dispose()

    archive = tmp_path / "archive"
    assert cli.main(["prune", "--days", "90", "--archive-dir", str(archive), "--yes"]) == 0

    engine = build_engine(f"sqlite:///{db_path.as_posix()}")
    factory = build_session_factory(engine)
    with factory() as session:
        assert session.get(AgentTask, task_id) is None
        assert not session.scalars(select(AuditEvent).where(AuditEvent.task_id == task_id)).all()
    engine.dispose()

    archived = list(archive.glob("*.ndjson"))
    manifests = list(archive.glob("retention-*.json"))
    assert archived and manifests
    manifest = json.loads(manifests[0].read_text(encoding="utf-8"))
    assert manifest["deleted"][0]["task_id"] == task_id
    assert manifest["deleted"][0]["archive"].endswith(".ndjson")
