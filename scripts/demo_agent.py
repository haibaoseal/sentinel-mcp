"""Demonstrate the governed agent loop end to end.

Run: python scripts/demo_agent.py

Shows, against the real runtime (not mocks):
  1. a read-only request completing with retrieval,
  2. a financial action being held for human approval,
  3. a destructive action being blocked by policy,
  4. a tool failure being reported as a failure, not a success,
  5. the resulting audit chain verifying, and being ordered by seq not by clock.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "apps" / "api"))

from app.audit.logger import read_chain, verify_chain  # noqa: E402
from app.core.config import Settings  # noqa: E402
from app.db.models import AgentTask, AuditEvent, Base, ToolCall  # noqa: E402
from app.runtime import build_runtime  # noqa: E402
from sqlalchemy import create_engine, select  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

STATUS_MARK = {
    "completed": "OK      ",
    "waiting_approval": "APPROVAL",
    "blocked": "BLOCKED ",
    "failed": "FAILED  ",
}


def main() -> int:
    settings = Settings(
        _env_file=None,
        agent_provider="replay",
        tool_sandbox_root=str(ROOT / "sandbox"),
        knowledge_root=str(ROOT / "knowledge"),
    )
    runtime = build_runtime(settings)
    identity = runtime.provider.identity

    print("=" * 78)
    print("sentinel-mcp :: governed agent loop")
    print("=" * 78)
    print(f"provider   : {identity.provider}  model={identity.model}  live={identity.is_live}")
    print(f"tools      : {', '.join(runtime.registry.names())}")
    print(f"sandbox    : {settings.sandbox_path}")
    print()

    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)

    requests = [
        ("read-only policy question", "普通商品多久可以退货？"),
        ("financial action", "订单 ORD-1001 申请退款"),
        ("destructive action", "帮我删除文件 notes.md"),
        ("missing file", "读取 missing.md 的内容"),
    ]

    with Session(engine, expire_on_commit=False) as session:
        for label, request in requests:
            task = AgentTask(title=label, user_request=request, status="pending")
            session.add(task)
            session.flush()

            result = runtime.loop.run(task_id=task.id, user_request=request, session=session)

            print("-" * 78)
            print(f"[{STATUS_MARK.get(result.status, result.status)}] {label}")
            print(f"  request : {request}")
            print(f"  status  : {result.status}   termination: {result.termination}")
            print(f"  answer  : {result.answer}")
            for step in result.steps:
                if step.tool_name:
                    print(
                        f"    step {step.index}: {step.tool_name:24} -> {step.tool_status}"
                        + (f"  [{step.error_code}]" if step.error_code else "")
                    )

            calls = list(session.scalars(select(ToolCall).where(ToolCall.task_id == task.id)))
            events = list(session.scalars(select(AuditEvent).where(AuditEvent.task_id == task.id)))
            chain = read_chain(session, task.id)
            verdict = verify_chain(chain)

            print(f"  tool calls recorded : {len(calls)}")
            print(f"  audit events        : {len(events)}  seq={[e.seq for e in chain]}")
            print(f"  chain verifies      : {verdict.ok}")
        session.commit()

    # --- tamper demonstration ------------------------------------------------
    print()
    print("=" * 78)
    print("Tamper detection")
    print("=" * 78)
    with Session(engine, expire_on_commit=False) as session:
        # Pick a task whose chain is non-empty, rather than whichever task was
        # created last -- demonstrating tamper detection on an empty chain would
        # prove nothing.
        target = None
        for candidate in session.scalars(select(AgentTask)):
            if read_chain(session, candidate.id):
                target = candidate
                break
        if target is None:
            print("  no populated chain to demonstrate with")
        else:
            chain = read_chain(session, target.id)
            print(f"  task                : {target.title}")
            print(f"  events              : {len(chain)}  seq={[e.seq for e in chain]}")
            print(f"  honest chain        : {verify_chain(chain).ok}")
            chain[1].payload_json = {"tampered": True}
            session.flush()
            broken = verify_chain(read_chain(session, target.id))
            print(f"  after tampering     : ok={broken.ok} first_bad_seq={broken.first_bad_seq}")
            print(f"  reason              : {broken.reason}")

    print()
    print("=" * 78)
    print("Notes")
    print("=" * 78)
    print("  * The read-only request completes; the financial and destructive ones")
    print("    do not, and each reports why rather than claiming success.")
    print("  * Chain ordering uses an explicit per-task seq, so a chain of events")
    print("    that share a timestamp still verifies.")
    print("  * Set AGENT_PROVIDER=llm with LLM_API_KEY/LLM_MODEL to run a real model")
    print("    through this identical governance path.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
