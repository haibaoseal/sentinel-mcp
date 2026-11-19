"""Audit operations: verify, export and retention.

    python -m app.audit.cli verify --task <id>
    python -m app.audit.cli verify --all
    python -m app.audit.cli export --task <id> --out audit.ndjson
    python -m app.audit.cli prune --days 90 --archive-dir ./archive --yes

`prune` is deliberately two-phase: it exports and verifies every task before it
deletes anything, and it writes a manifest with the chain head so an operator can
prove what was removed. Deleting audit data is a compliance decision, which is
why the destructive path requires `--yes` and the default is a dry run.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.audit.logger import read_chain, verify_chain
from app.core.config import get_settings
from app.core.errors import SentinelError
from app.db.models import (
    AgentPlan,
    AgentTask,
    ApprovalRequest,
    AuditEvent,
    PolicyDecisionRecord,
    ToolCall,
)
from app.db.session import build_engine, build_session_factory

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_USAGE = 2


def _factory():
    settings = get_settings()
    engine = build_engine(settings.database_url)
    if settings.auto_create_schema:
        from app.db.session import create_schema

        create_schema(engine)
    return settings, build_session_factory(engine)


def _verify(session: Session, task_id: str, hmac_key: bytes | None) -> dict:
    events = read_chain(session, task_id)
    verdict = verify_chain(events, hmac_key=hmac_key)
    return {
        "task_id": task_id,
        "ok": verdict.ok,
        "checked": verdict.checked,
        "first_bad_seq": verdict.first_bad_seq,
        "reason": verdict.reason,
        "event_count": len(events),
        "head": events[-1].event_hash if events else None,
    }


def _export_task(session: Session, task_id: str, hmac_key: bytes | None) -> dict:
    events = read_chain(session, task_id)
    verdict = verify_chain(events, hmac_key=hmac_key)
    return {
        "manifest": {
            "type": "manifest",
            "task_id": task_id,
            "chain_verified": verdict.ok,
            "checked": verdict.checked,
            "head": events[-1].event_hash if events else None,
            "exported_at": datetime.now(UTC).isoformat(),
            "format": "sentinel-audit/1",
        },
        "events": [
            {
                "id": event.id,
                "task_id": event.task_id,
                "seq": event.seq,
                "event_type": event.event_type,
                "actor_type": event.actor_type,
                "actor_id": event.actor_id,
                "payload": event.payload_json,
                "prev_hash": event.prev_hash,
                "event_hash": event.event_hash,
                "created_at": event.created_at.isoformat() if event.created_at else None,
            }
            for event in events
        ],
        "verified": verdict.ok,
    }


def _write_ndjson(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(payload["manifest"], ensure_ascii=False) + "\n")
        for event in payload["events"]:
            handle.write(json.dumps(event, ensure_ascii=False, default=str) + "\n")


def cmd_verify(args) -> int:
    settings, factory = _factory()
    with factory() as session:
        if args.task:
            results = [_verify(session, args.task, settings.hmac_key_bytes)]
        else:
            task_ids = session.scalars(select(AgentTask.id)).all()
            results = [_verify(session, task_id, settings.hmac_key_bytes) for task_id in task_ids]
    failed = [row for row in results if not row["ok"]]
    for row in results:
        state = "ok" if row["ok"] else "FAILED"
        print(
            f"{state:6} task={row['task_id']} events={row['event_count']} "
            f"checked={row['checked']} head={str(row['head'])[:12]}"
            + (f" bad_seq={row['first_bad_seq']} reason={row['reason']}" if not row["ok"] else "")
        )
    print(f"{len(results) - len(failed)}/{len(results)} chains verified")
    return EXIT_OK if not failed else EXIT_FAILED


def cmd_export(args) -> int:
    settings, factory = _factory()
    with factory() as session:
        payload = _export_task(session, args.task, settings.hmac_key_bytes)
    if not payload["verified"]:
        print("refusing to export: chain does not verify", file=sys.stderr)
        return EXIT_FAILED
    _write_ndjson(Path(args.out), payload)
    print(f"exported {len(payload['events'])} events to {args.out}")
    return EXIT_OK


def cmd_prune(args) -> int:
    settings, factory = _factory()
    cutoff = datetime.now(UTC) - timedelta(days=args.days)
    archive = Path(args.archive_dir)
    with factory() as session:
        candidates = session.scalars(select(AgentTask).where(AgentTask.created_at < cutoff)).all()
        print(f"tasks older than {args.days} days: {len(candidates)}")
        if not candidates:
            return EXIT_OK
        manifests = []
        for task in candidates:
            payload = _export_task(session, task.id, settings.hmac_key_bytes)
            if not payload["verified"] and not args.force:
                print(
                    f"refusing to prune task {task.id}: chain does not verify",
                    file=sys.stderr,
                )
                return EXIT_FAILED
            if args.dry_run:
                manifests.append(
                    {
                        "task_id": task.id,
                        "event_count": len(payload["events"]),
                        "chain_verified": payload["verified"],
                    }
                )
                continue
            target = archive / f"{task.id}.ndjson"
            _write_ndjson(target, payload)
            _delete_task(session, task.id)
            manifests.append(
                {
                    "task_id": task.id,
                    "event_count": len(payload["events"]),
                    "chain_verified": payload["verified"],
                    "archive": str(target),
                }
            )
        if args.dry_run:
            for row in manifests:
                print(f"would archive {row['task_id']} ({row['event_count']} events)")
            print("dry run: nothing deleted; pass --yes to execute")
            return EXIT_OK
        session.commit()
        manifest_path = archive / f"retention-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}.json"
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        manifest_path.write_text(
            json.dumps(
                {
                    "cutoff": cutoff.isoformat(),
                    "days": args.days,
                    "deleted": manifests,
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
        print(f"pruned {len(manifests)} tasks; manifest: {manifest_path}")
    return EXIT_OK


def _delete_task(session: Session, task_id: str) -> None:
    """Delete one task and every row that points at it.

    Order matters because the FKs are not declared with ON DELETE CASCADE; doing
    this explicitly is also easier to audit than a cascade that silently removes
    more than the operator expected.
    """
    tool_call_ids = session.scalars(select(ToolCall.id).where(ToolCall.task_id == task_id)).all()
    if tool_call_ids:
        for decision in session.scalars(
            select(PolicyDecisionRecord).where(PolicyDecisionRecord.tool_call_id.in_(tool_call_ids))
        ):
            session.delete(decision)
    for approval in session.scalars(
        select(ApprovalRequest).where(ApprovalRequest.task_id == task_id)
    ):
        session.delete(approval)
    for tool_call in session.scalars(select(ToolCall).where(ToolCall.task_id == task_id)):
        session.delete(tool_call)
    for event in session.scalars(select(AuditEvent).where(AuditEvent.task_id == task_id)):
        session.delete(event)
    for plan in session.scalars(select(AgentPlan).where(AgentPlan.task_id == task_id)):
        session.delete(plan)
    task = session.get(AgentTask, task_id)
    if task is not None:
        session.delete(task)
    session.flush()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.audit.cli")
    sub = parser.add_subparsers(dest="command", required=True)

    verify = sub.add_parser("verify", help="verify one task or every task")
    verify.add_argument("--task", default=None)
    verify.add_argument(
        "--all", action="store_true", help="verify every task (default when --task is omitted)"
    )
    verify.set_defaults(func=cmd_verify)

    export = sub.add_parser("export", help="export one task as NDJSON")
    export.add_argument("--task", required=True)
    export.add_argument("--out", required=True)
    export.set_defaults(func=cmd_export)

    prune = sub.add_parser("prune", help="archive and delete tasks older than N days")
    prune.add_argument("--days", type=int, required=True)
    prune.add_argument("--archive-dir", required=True)
    prune.add_argument("--yes", dest="dry_run", action="store_false", default=True)
    prune.add_argument("--force", action="store_true", help="prune even if a chain fails")
    prune.set_defaults(func=cmd_prune)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except SentinelError as exc:
        print(f"failed: {exc.code}: {exc}", file=sys.stderr)
        return EXIT_FAILED
    except ValueError as exc:
        print(f"usage: {exc}", file=sys.stderr)
        return EXIT_USAGE


if __name__ == "__main__":
    raise SystemExit(main())
