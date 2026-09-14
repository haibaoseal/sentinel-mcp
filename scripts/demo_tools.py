"""Demo the real tools through the governed path.

Run: python scripts/demo_tools.py
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "apps" / "api"))

from app.core.config import Settings  # noqa: E402
from app.core.errors import SentinelError  # noqa: E402
from app.db.models import AgentTask, Base  # noqa: E402
from app.runtime import build_runtime  # noqa: E402
from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402


def main() -> int:
    settings = Settings(
        _env_file=None,
        agent_provider="replay",
        tool_sandbox_root=str(ROOT / "sandbox"),
        knowledge_root=str(ROOT / "knowledge"),
    )
    runtime = build_runtime(settings)
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)

    print("=" * 78)
    print("sentinel-mcp :: real tools, governed")
    print("=" * 78)
    print(f"registered : {', '.join(runtime.registry.names())}")
    print()

    registry = runtime.registry
    cases = [
        (
            "read-only SQL",
            "sql_query",
            {"query": "SELECT status, count(*) AS n FROM orders GROUP BY status"},
        ),
        ("SQL schema", "sql_schema", {}),
        ("SQL write (blocked by policy)", "sql_execute_write", {"query": "DELETE FROM orders"}),
        (
            "GitHub issues (labelled fixture)",
            "github_list_issues",
            {"owner": "openai", "repo": "openai-python"},
        ),
        (
            "GitHub comment (disabled)",
            "github_post_issue_comment",
            {"owner": "o", "repo": "r", "number": 1, "body": "hi"},
        ),
        ("HTTP to an unlisted host", "http_get", {"url": "https://example.invalid/x"}),
    ]

    from app.core.contracts import ToolRequest

    with Session(engine, expire_on_commit=False) as session:
        task = AgentTask(title="tool demo", user_request="tools", status="running")
        session.add(task)
        session.flush()

        for label, tool, arguments in cases:
            descriptor = registry.describe(tool)
            result = runtime.firewall.execute(
                ToolRequest(
                    task_id=task.id,
                    tool_name=tool,
                    action_type=descriptor.action_type if descriptor else "unknown",
                    arguments=arguments,
                ),
                session=session,
            )
            mark = {
                "success": "RAN     ",
                "waiting_approval": "APPROVAL",
                "blocked": "BLOCKED ",
                "failed": "FAILED  ",
            }
            print(f"[{mark.get(result.status, result.status)}] {label}")
            print(f"           tool={tool}  status={result.status}  source={result.source}")
            if result.status == "success":
                payload = result.data or {}
                if "rows" in payload:
                    print(f"           columns={payload['columns']}")
                    for row in payload["rows"][:5]:
                        print(f"             {row}")
                elif "issues" in payload:
                    source = payload.get("source")
                    note = str(payload.get("note"))[:70]
                    print(f"           source={source}  note={note}")
                elif "tables" in payload:
                    print(f"           tables={payload['tables']}")
            elif result.status == "blocked":
                print(f"           reason={str(result.error)[:120]}")
            else:
                print(f"           error={str(result.error)[:120]}")
            print()
        session.commit()

    print("=" * 78)
    print("Note the two distinct refusal layers on show:")
    print("  * sql_execute_write and github_post_issue_comment are refused by POLICY,")
    print("    and each tool also refuses independently if invoked directly.")
    print("  * sql_query runs on a connection opened mode=ro, so a write cannot occur")
    print("    there even if the policy layer were bypassed.")
    print("=" * 78)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SentinelError as exc:
        print(f"error: {exc}")
        raise SystemExit(1) from exc
