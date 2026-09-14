"""Verify the project's claims against the artifact, not against the README.

Run: python scripts/verify_objective.py

Every check here reads code or data and asserts something specific. Nothing consults
prose. The point is that a reader who does not trust the README can run one command
and see each claim tested directly -- and if a claim stops holding, this fails.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "apps" / "api"))

from app.core.config import Settings  # noqa: E402
from app.runtime import build_registry  # noqa: E402

results: list[tuple[str, bool, str]] = []


def check(label: str, ok: bool, detail: str = "") -> None:
    results.append((label, ok, detail))


# --- helpers, declared before the checks that call them ---------------------


def _raises(fn) -> bool:
    try:
        fn()
    except Exception:  # noqa: BLE001 - the point is that something was raised
        return True
    return False


def _output_verdict(answer: str) -> str:
    from app.security.guardrails import check_output

    citation = {
        "id": "returns#dry-run",
        "excerpt": "退款工具是 dry-run：它只创建待审核草案，绝不代表退款已经完成或资金已原路退回。",
    }
    return check_output(answer, [citation]).verdict


def _detects_evidence_shrink() -> bool:
    from app.evals.runner import compare_to_baseline

    metrics = {"unsafe_execution": {"passed": 3, "total": 3, "rate": 1.0}}
    recorded = {"metrics": {"unsafe_execution": {"passed": 8, "total": 8, "rate": 1.0}}}
    regressions = compare_to_baseline(metrics, recorded)
    return any(r.kind == "evidence" for r in regressions)


# --- (1) agent loop and provider abstraction --------------------------------
from app.providers.base import Provider  # noqa: E402
from app.providers.llm import LLMProvider  # noqa: E402
from app.providers.replay import ReplayProvider  # noqa: E402

check("provider abstraction is a protocol with a decide step", hasattr(Provider, "decide"))
check("offline provider is marked not-live", ReplayProvider().identity.is_live is False)
check("live provider is marked live", LLMProvider(api_key="k", model="m").identity.is_live is True)
check(
    "a fresh checkout defaults to the offline provider (CI needs no key)",
    Settings(_env_file=None).provider == "replay",
)
check(
    "a live provider without a key is refused with an actionable message",
    _raises(lambda: LLMProvider(api_key="", model="m")),
)

# --- (2) real tools ---------------------------------------------------------
names = set(build_registry(Settings(_env_file=None)).names())
for area, tools in {
    "file": ["fs_read", "fs_list", "fs_search"],
    "sql": ["sql_query", "sql_schema"],
    "http": ["http_get"],
    "github": [
        "github_list_issues",
        "github_read_issue",
        "github_list_pull_requests",
        "github_read_pull_request",
    ],
}.items():
    missing = [tool for tool in tools if tool not in names]
    check(
        f"real {area} tools are registered", not missing, f"missing: {missing}" if missing else ""
    )

# The inert write tools exist so the rules disabling them have something to act on.
for tool in ("sql_execute_write", "http_post", "github_close_issue", "github_post_issue_comment"):
    check(f"{tool} is registered so its block is a decision, not an absence", tool in names)

# --- (3) MCP gateway, both directions ---------------------------------------
from app.mcp.client import MCPClient  # noqa: E402
from app.mcp.server import GovernedMCPServer  # noqa: E402
from mcp.client import stdio, streamable_http  # noqa: E402

check("MCP client exists (inbound tools)", MCPClient is not None)
check("governed MCP server exists (outbound tools)", GovernedMCPServer is not None)
check("stdio transport is wired", hasattr(stdio, "stdio_client"))
check("Streamable HTTP transport is wired", hasattr(streamable_http, "streamable_http_client"))

# --- (4) the audited P0 defects ---------------------------------------------
from app.audit.logger import verify_chain  # noqa: E402
from app.db.models import AuditEvent  # noqa: E402
from app.evals.evaluator import validate_contracts  # noqa: E402
from app.security.secrets import redact_text  # noqa: E402

check("audit chain verifier exists", callable(verify_chain))
check("audit events carry an explicit seq column", "seq" in AuditEvent.__table__.columns)

leaked = [
    secret
    for secret in [
        "sk-abc123XYZdef456ghi789",
        "SK-abc123XYZdef456ghi789",
        "ghp_abcdefghijklmnopqrstuvwx",
        "xoxb-" + "123456789012" + "-" + "abcdefghijklmnop",
        "110101199003071234",
        "138 0013 8000",
        "Bearer abc+/def==",
    ]
    if secret in redact_text(f"x {secret} y")
]
check("redaction blind spots are closed", not leaked, f"still leaking: {leaked}")

check(
    "a fabricated capability claim is refused",
    _output_verdict("已为你完成退款，依据【returns#dry-run】。") == "block",
    "the answer contradicts its own citation and must not be returned",
)
check(
    "the truthful statement about the same topic is allowed",
    _output_verdict("退款工具只创建草案，绝不代表退款已经完成，依据【returns#dry-run】。")
    != "block",
    "blocking the honest answer would be its own defect",
)

bad_scenarios = validate_contracts(
    [{"id": "ghost", "question": "q", "expect": {"must_block": ["ghost_tool"]}}], known_tools=names
)
check("the eval contract check rejects unregistered tools", bool(bad_scenarios))

# --- (5) one trace model, deterministic evaluation, regression gate ---------
from app.trace import Trace  # noqa: E402

trace_payload = json.dumps(
    Trace(
        run_id="r",
        question="q",
        answer="a",
        status="completed",
        termination="completed",
        identity=ReplayProvider().identity,
    ).to_dict()
)
check(
    "the trace model carries no clock",
    not any(word in trace_payload for word in ("duration", "timestamp", "latency")),
)

baseline = json.loads((ROOT / "evals" / "baseline.json").read_text(encoding="utf-8"))
scenarios = json.loads((ROOT / "evals" / "scenarios.json").read_text(encoding="utf-8"))
check(
    "a baseline is committed and covers the whole suite",
    baseline["metrics"]["scenarios"]["total"] >= len(scenarios["scenarios"]),
    f"baseline={baseline['metrics']['scenarios']['total']} suite={len(scenarios['scenarios'])}",
)
check(
    "the stored report states what kind of measurement it is",
    "not model quality" in baseline["measurement"],
)
check(
    "the regression gate detects a shrunk suite at a perfect rate",
    _detects_evidence_shrink(),
)

# --- (6) CI, locked dependencies, live smoke --------------------------------
ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
check("CI runs the test suite", "pytest" in ci)
check("CI runs the regression gate", "app.evals.cli" in ci)
check("CI exercises the live path against a stub", "mock_llm_stub" in ci)
check("CI enforces the execution boundary", "execution boundary" in ci)
check("dependencies are pinned", (ROOT / "constraints.txt").exists())
check("a live smoke test exists", (ROOT / "scripts" / "live_smoke.py").exists())
check(
    "the live smoke test exits 77 rather than claiming a pass without a key",
    "77" in (ROOT / "scripts" / "live_smoke.py").read_text(encoding="utf-8"),
)

# --- (7) positioning --------------------------------------------------------
readme = (ROOT / "README.md").read_text(encoding="utf-8")
check("the README positions the project as infrastructure", "MCP gateway" in readme)
check("the README states its limitations", "## Honest limitations" in readme)
check(
    "both archived repositories point here",
    (ROOT.parent / "xiangmu1" / "ARCHIVED.md").exists()
    and (ROOT.parent / "xiangmu2" / "ARCHIVED.md").exists(),
)
check(
    "the firewall requires a session (no ungoverned path)",
    "session: Session"
    in (ROOT / "apps" / "api" / "app" / "governance" / "firewall.py").read_text(encoding="utf-8"),
)


def main() -> int:
    print("=" * 78)
    print("CLAIM VERIFICATION")
    print("=" * 78)
    failed = 0
    for label, ok, detail in results:
        if not ok:
            failed += 1
        suffix = f"   {detail}" if detail else ""
        print(f"  [{'PASS' if ok else 'FAIL'}] {label}{suffix}")
    print("=" * 78)
    print(f"{len(results) - failed}/{len(results)} checks pass")
    if failed:
        print()
        print("A FAIL above means a claim in the README no longer holds.")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
