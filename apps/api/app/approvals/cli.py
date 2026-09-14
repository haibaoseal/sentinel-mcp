"""The approval queue: list what the runtime is holding, and decide it.

    PYTHONPATH=apps/api python -m app.approvals.cli list
    PYTHONPATH=apps/api python -m app.approvals.cli list --task <task-id>
    PYTHONPATH=apps/api python -m app.approvals.cli list --all
    PYTHONPATH=apps/api python -m app.approvals.cli approve <id> --reviewer alice
    PYTHONPATH=apps/api python -m app.approvals.cli approve <id> --reviewer alice \\
        --set order_id=ORD-2002
    PYTHONPATH=apps/api python -m app.approvals.cli reject <id> --reviewer alice \\
        --comment "wrong order"
    PYTHONPATH=apps/api python -m app.approvals.cli request draft_refund \\
        --arg order_id=ORD-1001

``request`` exists so the hold can be demonstrated end to end without an agent
run: it proposes a call through the firewall and prints what governance did with
it. ``--set`` merges into the proposed arguments rather than replacing them, so an
edit cannot drop a field the reviewer did not retype. Exit codes: 0 decided or
listed, 1 refused (state, mismatch or policy), 2 bad usage.
"""

from __future__ import annotations

import argparse
import json
import sys

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.approvals.service import ApprovalService
from app.core.config import get_settings
from app.core.contracts import ToolRequest
from app.core.errors import SentinelError
from app.db.models import AgentTask, Base
from app.governance.firewall import Firewall
from app.policy.engine import PolicyEngine, load_policy_document
from app.runtime import build_registry

EXIT_OK = 0
EXIT_REFUSED = 1
EXIT_USAGE = 2


def _parse_pairs(pairs: list[str] | None) -> dict[str, object]:
    """``key=value`` -> dict, with JSON values when they parse.

    A reviewer editing a number or a boolean should not have to know that the
    queue stores JSON, and a string that happens to look like JSON should still be
    expressible by quoting it.
    """
    result: dict[str, object] = {}
    for pair in pairs or []:
        key, separator, raw = pair.partition("=")
        if not separator or not key:
            raise ValueError(f"expected key=value, got {pair!r}")
        try:
            result[key] = json.loads(raw)
        except ValueError:
            result[key] = raw
    return result


def _build():
    settings = get_settings()
    engine = create_engine(settings.database_url)
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    registry = build_registry(settings)
    firewall = Firewall(
        registry=registry,
        policy_engine=PolicyEngine(load_policy_document(settings.policy_path or None)),
        runtime_flags=settings.runtime_flags(),
        hmac_key=settings.hmac_key_bytes,
    )
    return firewall, factory


def _list(service: ApprovalService, task_id: str | None, *, everything: bool) -> int:
    rows = service.decided(task_id=task_id) if everything else service.pending(task_id=task_id)
    if not rows:
        print("no decided approvals" if everything else "no pending approvals")
        return EXIT_OK
    print(f"{len(rows)} {'decided' if everything else 'pending'} approval(s)")
    for row in rows:
        print()
        print(f"  id        : {row.id}")
        print(f"  status    : {row.status}")
        print(f"  tool      : {row.tool_call_id}  (task {row.task_id})")
        print(f"  risk      : {row.risk_level}")
        print(f"  requested : {row.created_at}")
        print(f"  arguments : {json.dumps(row.original_arguments_json, ensure_ascii=False)}")
        if row.modified_arguments_json is not None:
            print(f"  modified  : {json.dumps(row.modified_arguments_json, ensure_ascii=False)}")
        if row.reviewer_id:
            print(f"  reviewer  : {row.reviewer_id}")
        if row.review_comment:
            print(f"  comment   : {row.review_comment}")
        for reason in row.risk_reasons_json or []:
            print(f"    - {reason}")
    return EXIT_OK


def _request(firewall: Firewall, factory, tool: str, arguments: dict) -> int:
    descriptor = firewall.registry.describe(tool)
    with factory() as session:
        task = AgentTask(
            title=f"approval demo: {tool}",
            user_request=json.dumps(arguments, ensure_ascii=False),
            agent_type="approval-cli",
            status="running",
        )
        session.add(task)
        session.flush()
        result = firewall.execute(
            ToolRequest(
                task_id=task.id,
                tool_name=tool,
                action_type=descriptor.action_type if descriptor else "unknown",
                resource_type=descriptor.resource_type if descriptor else None,
                arguments=arguments,
                requested_by="cli",
            ),
            session=session,
        )
        session.commit()

    print(f"tool   : {tool}")
    print(f"status : {result.status}")
    if result.status == "waiting_approval":
        print(f"held   : approval {result.data.get('approval_id')} is pending")
        for reason in result.data.get("risk_reasons") or []:
            print(f"  - {reason}")
    elif result.status == "blocked":
        print(f"reason : {result.error}")
    else:
        print(f"data   : {json.dumps(result.data or {}, ensure_ascii=False)[:400]}")
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.approvals.cli")
    sub = parser.add_subparsers(dest="command", required=True)

    listing = sub.add_parser("list", help="show the pending approvals")
    listing.add_argument("--task", default=None)
    listing.add_argument(
        "--all", dest="everything", action="store_true", help="show decided ones too"
    )

    approve = sub.add_parser("approve", help="approve (and execute) a held call")
    approve.add_argument("approval_id")
    approve.add_argument("--reviewer", required=True)
    approve.add_argument(
        "--set",
        dest="sets",
        action="append",
        metavar="KEY=VALUE",
        help="change one argument; anything not named keeps its proposed value",
    )
    approve.add_argument("--comment", default=None)

    reject = sub.add_parser("reject", help="refuse a held call")
    reject.add_argument("approval_id")
    reject.add_argument("--reviewer", required=True)
    reject.add_argument("--comment", default=None)

    propose = sub.add_parser("request", help="propose a call so the hold can be seen")
    propose.add_argument("tool")
    propose.add_argument("--arg", dest="args", action="append", metavar="KEY=VALUE")

    args = parser.parse_args(argv)

    try:
        if args.command == "request":
            firewall, factory = _build()
            return _request(firewall, factory, args.tool, _parse_pairs(args.args))

        firewall, factory = _build()
        with factory() as session:
            service = ApprovalService(firewall=firewall, session=session)
            if args.command == "list":
                return _list(service, args.task, everything=args.everything)

            if args.command == "reject":
                outcome = service.reject(
                    args.approval_id, reviewer_id=args.reviewer, comment=args.comment
                )
            else:
                modified = None
                if args.sets:
                    # `--set` edits fields; every argument the reviewer did not name
                    # keeps the value the agent proposed. Passing only the named keys
                    # would silently drop the rest, which is how a "small edit" turns
                    # into a different call.
                    merged = dict(service.get(args.approval_id).original_arguments_json or {})
                    merged.update(_parse_pairs(args.sets))
                    modified = merged
                outcome = service.approve(
                    args.approval_id,
                    reviewer_id=args.reviewer,
                    modified_arguments=modified,
                    comment=args.comment,
                )
            session.commit()

        print(f"approval : {outcome.approval_id}")
        print(f"status   : {outcome.status}")
        print(f"executed : {outcome.executed}")
        if outcome.policy_decision:
            print(f"policy   : {outcome.policy_decision} (the edit was refused)")
        if outcome.reason:
            print(f"reason   : {outcome.reason}")
        if outcome.result is not None and outcome.result.data:
            print(f"data     : {json.dumps(outcome.result.data, ensure_ascii=False)[:400]}")
        return EXIT_OK if outcome.executed or args.command == "reject" else EXIT_REFUSED

    except SentinelError as exc:
        print(f"refused: {exc.code}: {exc}", file=sys.stderr)
        return EXIT_REFUSED
    except ValueError as exc:
        print(f"usage: {exc}", file=sys.stderr)
        return EXIT_USAGE


if __name__ == "__main__":
    raise SystemExit(main())
