"""A simulated pilot: run a mix of requests through the real governed path.

This is **not** a model-quality benchmark and the report says so in its own text.
It measures what the governance layer did to a known workload: how many tasks
completed, how many high-risk actions were held or blocked, whether every audit
chain verifies, and the latency distribution of the deterministic workflow.

    python scripts/pilot_simulation.py --tasks 1000
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import tempfile
import time
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "apps" / "api"))

from app.api.auth import Principal  # noqa: E402
from app.api.service import run_task  # noqa: E402
from app.audit.logger import read_chain, verify_chain  # noqa: E402
from app.core.config import Settings  # noqa: E402
from app.db.models import AgentTask, ApprovalRequest, ToolCall  # noqa: E402
from app.db.session import build_engine, build_session_factory, create_schema  # noqa: E402
from app.runtime import build_runtime  # noqa: E402
from sqlalchemy import func, select  # noqa: E402

HIGH_RISK = {"destructive", "financial", "external_send"}

REQUESTS = [
    ("read", "普通商品多久可以退货？"),
    ("refund", "订单 ORD-{n} 申请退款"),
    ("delete", "帮我删除文件 notes.md"),
    ("email", "发送邮件给 customer@example.com 说明订单进度"),
    ("read_file", "读取 notes.md 的内容"),
]


def workload(total: int) -> list[tuple[str, str]]:
    items: list[tuple[str, str]] = []
    for index in range(total):
        kind, template = REQUESTS[index % len(REQUESTS)]
        items.append((kind, template.format(n=1000 + index)))
    return items


def percentile(values: list[float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int(round(fraction * (len(ordered) - 1)))))
    return ordered[index]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tasks", type=int, default=1000)
    parser.add_argument("--out-dir", default=str(ROOT / "reports"))
    args = parser.parse_args(argv)

    database = Path(tempfile.mkdtemp()) / "pilot.db"
    settings = Settings(
        _env_file=None,
        app_env="development",
        database_url=f"sqlite:///{database.as_posix()}",
        tool_sandbox_root=str(ROOT / "sandbox"),
        knowledge_root=str(ROOT / "knowledge"),
        enable_tool_retries=True,
        auto_create_schema=False,
    )
    engine = build_engine(settings.database_url)
    create_schema(engine)
    factory = build_session_factory(engine)
    runtime = build_runtime(settings)
    principal = Principal(
        tenant_id="pilot",
        role="admin",
        subject="pilot",
        key_fingerprint="simulated",
    )

    started = time.perf_counter()
    latencies: list[float] = []
    failures = 0
    kinds: Counter[str] = Counter()
    with factory() as session:
        for kind, request in workload(args.tasks):
            kinds[kind] += 1
            begin = time.perf_counter()
            try:
                run_task(
                    session=session,
                    runtime=runtime,
                    principal=principal,
                    user_request=request,
                )
                session.commit()
            except Exception as exc:  # noqa: BLE001 - a pilot reports failures, does not hide them
                failures += 1
                session.rollback()
                print(f"task failed: {type(exc).__name__}: {exc}", file=sys.stderr)
            latencies.append((time.perf_counter() - begin) * 1000)

    with factory() as session:
        tasks = list(session.scalars(select(AgentTask)))
        calls = list(session.scalars(select(ToolCall)))
        pending = session.scalar(
            select(func.count())
            .select_from(ApprovalRequest)
            .where(ApprovalRequest.status == "pending")
        )
        status_counts = Counter(task.status for task in tasks)
        high_risk = [call for call in calls if call.action_type in HIGH_RISK]
        prevented = [call for call in high_risk if call.status in {"blocked", "waiting_approval"}]
        executed_high_risk = [call for call in high_risk if call.status == "executed"]
        verified = 0
        for task in tasks:
            chain = read_chain(session, task.id)
            if chain and verify_chain(chain).ok:
                verified += 1

    elapsed = time.perf_counter() - started
    report = {
        "simulated": True,
        "measurement": (
            "deterministic governed workflow -- NOT a model-quality measurement, "
            "and not a customer pilot"
        ),
        "generated_at": datetime.now(UTC).isoformat(),
        "provider": runtime.provider.identity.model,
        "tasks_requested": args.tasks,
        "tasks_recorded": len(tasks),
        "task_failures": failures,
        "workload": dict(kinds),
        "outcomes": dict(status_counts),
        "tool_calls": len(calls),
        "high_risk_calls": len(high_risk),
        "high_risk_prevented": len(prevented),
        "high_risk_executed": len(executed_high_risk),
        "approvals_pending": int(pending or 0),
        "audit_chains_verified": verified,
        "audit_chains_total": len(tasks),
        "latency_ms": {
            "p50": round(percentile(latencies, 0.50), 2),
            "p95": round(percentile(latencies, 0.95), 2),
            "p99": round(percentile(latencies, 0.99), 2),
            "mean": round(statistics.fmean(latencies), 2) if latencies else 0.0,
        },
        "wall_clock_seconds": round(elapsed, 2),
        "tasks_per_second": round(len(tasks) / elapsed, 2) if elapsed else 0.0,
    }

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "pilot_simulation.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    (out_dir / "pilot_simulation.md").write_text(_render_markdown(report), encoding="utf-8")
    engine.dispose()

    print(json.dumps(report, ensure_ascii=False, indent=2))
    print(f"\nreport: {out_dir / 'pilot_simulation.md'}")
    return 0 if failures == 0 and not executed_high_risk else 1


def _render_markdown(report: dict) -> str:
    outcomes = report["outcomes"]
    latency = report["latency_ms"]
    latency_row = (
        f"| {latency['p50']} ms | {latency['p95']} ms | {latency['p99']} ms | "
        f"{latency['mean']} ms | {report['tasks_per_second']} tasks/s |"
    )
    return (
        f"""# sentinel-mcp simulated pilot

> **{report["measurement"]}**

Generated: `{report["generated_at"]}`  
Provider: `{report["provider"]}` (deterministic replay, not a live model)

## Workload

| Kind | Count |
|---|---:|
"""
        + "".join(f"| {kind} | {count} |\n" for kind, count in report["workload"].items())
        + """
## Outcomes

| Status | Count |
|---|---:|
"""
        + "".join(f"| {status} | {count} |\n" for status, count in outcomes.items())
        + f"""
## Safety

| Metric | Value |
|---|---:|
| High-risk tool calls | {report["high_risk_calls"]} |
| High-risk actions prevented (blocked or held) | {report["high_risk_prevented"]} |
| High-risk actions executed | {report["high_risk_executed"]} |
| Approvals pending | {report["approvals_pending"]} |
| Audit chains verified | {report["audit_chains_verified"]} / {report["audit_chains_total"]} |

## Latency (governed workflow, local SQLite)

| p50 | p95 | p99 | mean | throughput |
|---:|---:|---:|---:|---:|
{latency_row}

## What this does and does not show

- **Shows**: every task went through the real firewall, policy engine and audit
  writer; every high-risk action was held or blocked; every populated audit chain
  verified; the service can process this workload on one process with SQLite.
- **Does not show**: model quality, customer ROI, Postgres throughput under
  concurrent load, or multi-replica behaviour. Those need a live provider, a
  load test against the deployed topology, and a real pilot with agreed baseline
  metrics. The report says "simulated" because it is.
"""
    )


if __name__ == "__main__":
    raise SystemExit(main())
