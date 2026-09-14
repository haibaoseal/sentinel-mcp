"""Demonstrate the MCP gateway in both directions.

Run: python scripts/demo_mcp_gateway.py

Direction 1 (inbound): the agent reaches tools on a *remote* MCP server. They are
governed identically to local tools -- declared ones run, undeclared ones are held
for approval, and the server's own willingness to act is irrelevant.

Direction 2 (outbound): this runtime publishes its governed tools *as* an MCP
server. An external client (Cursor, Claude Desktop, another agent) connects over
stdio and still cannot reach a tool except through the firewall.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "apps" / "api"))

from app.audit.logger import read_chain, verify_chain  # noqa: E402
from app.core.config import Settings  # noqa: E402
from app.core.contracts import ToolRequest  # noqa: E402
from app.db.models import AgentTask, AuditEvent, Base, ToolCall  # noqa: E402
from app.governance.firewall import Firewall  # noqa: E402
from app.mcp.client import MCPClient, MCPServerSpec, MCPToolSource  # noqa: E402
from app.mcp.server import build_server_module  # noqa: E402
from app.policy.engine import PolicyEngine  # noqa: E402
from app.runtime import build_registry  # noqa: E402
from sqlalchemy import create_engine, select  # noqa: E402
from sqlalchemy.orm import Session, sessionmaker  # noqa: E402

DEMO_SERVER = ROOT / "mcp_servers" / "demo_server.py"


def main() -> int:
    settings = Settings(
        _env_file=None,
        agent_provider="replay",
        tool_sandbox_root=str(ROOT / "sandbox"),
        knowledge_root=str(ROOT / "knowledge"),
    )
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)

    print("=" * 78)
    print("sentinel-mcp :: MCP gateway")
    print("=" * 78)

    # ---------------------------------------------------------------- inbound
    client = MCPClient(
        MCPServerSpec(
            name="demo",
            transport="stdio",
            command=sys.executable,
            args=[str(DEMO_SERVER), "stdio"],
            # Operator declares intent for the tools it has reviewed. Everything
            # not declared stays `unknown`, which the policy holds for approval.
            tool_actions={"repo_stats": "read", "echo": "read"},
            tool_risks={"repo_stats": "low", "echo": "low"},
            startup_timeout=60.0,
            call_timeout=60.0,
        )
    )
    mcp_source = MCPToolSource([client])

    print("\nDIRECTION 1 -- the agent calls tools on a REMOTE MCP server")
    print("-" * 78)
    discovered = client.discover()
    print(f"server      : {DEMO_SERVER.name} (spawned as a subprocess over stdio)")
    print(f"tools found : {len(discovered)}")
    for descriptor in discovered:
        print(
            f"    {descriptor.name:34} action={descriptor.action_type:8} "
            f"risk={descriptor.risk_level:8} source={descriptor.source}"
        )
    print(
        "\n  Note: tools the operator did not map are `unknown` action type.\n"
        "  The policy engine escalates `unknown` to require_approval, so adding a\n"
        "  server makes its tools visible and reviewable -- not trusted."
    )

    registry = build_registry(settings)
    registry.add_source(mcp_source)
    firewall = Firewall(registry=registry, policy_engine=PolicyEngine())

    with Session(engine, expire_on_commit=False) as session:
        task = AgentTask(title="MCP inbound", user_request="diagnostics", status="running")
        session.add(task)
        session.flush()

        cases = [
            ("declared read tool (mcp.demo.repo_stats)", "mcp.demo.repo_stats", "read", {}),
            (
                "undeclared write tool (mcp.demo.scratch_write)",
                "mcp.demo.scratch_write",
                "unknown",
                {"name": "n.txt", "content": "x"},
            ),
            ("declared read tool (mcp.demo.echo)", "mcp.demo.echo", "read", {"payload": "hi"}),
        ]
        for label, tool, action, arguments in cases:
            result = firewall.execute(
                ToolRequest(
                    task_id=task.id, tool_name=tool, action_type=action, arguments=arguments
                ),
                session=session,
            )
            mark = {
                "success": "RAN     ",
                "waiting_approval": "APPROVAL",
                "blocked": "BLOCKED ",
                "failed": "FAILED  ",
            }
            print(f"\n  [{mark.get(result.status, result.status)}] {label}")
            print(f"      status={result.status}  source={result.source}")
            if result.status == "waiting_approval":
                print(f"      reasons={(result.data or {}).get('risk_reasons')}")
        session.commit()

        calls = list(session.scalars(select(ToolCall)))
        events = list(session.scalars(select(AuditEvent)))
        chain = read_chain(session, task.id)
        print(f"\n  remote calls recorded : {len(calls)}  (all with source provenance)")
        print(f"  audit events          : {len(events)}")
        print(f"  chain verifies        : {verify_chain(chain).ok}")

    # --------------------------------------------------------------- outbound
    print()
    print("DIRECTION 2 -- this runtime is itself an MCP server")
    print("-" * 78)
    server, governed = build_server_module(firewall=firewall, session_factory=factory)
    published = governed.tool_descriptors()
    print(f"published tools : {len(published)}")
    for spec in published[:4]:
        g = spec["governance"]
        print(
            f"    {spec['name']:38} action={g['action_type']:8} "
            f"risk={g['risk_level']:8} approval={g['requires_approval']}"
        )
    print(f"    ... and {max(0, len(published) - 4)} more")

    print(
        "\n  An external client reaches these only through the firewall. Governance\n"
        "  metadata is published so a client can warn its user before a gated call."
    )
    for label, exposed, arguments in [
        ("read tool", "sentinel_fs_read", {"path": "notes.md"}),
        ("destructive tool", "sentinel_delete_file", {"path": "notes.md"}),
        ("approval-gated tool", "sentinel_send_email", {"to": "a@example.com", "body": "hi"}),
    ]:
        result = governed.call(exposed, arguments)
        print(f"\n  [{result['status']:16}] {label}: {exposed}")
        if result.get("held_for_approval"):
            print(f"      reason: {result.get('reason')}")
        elif result.get("blocked_by_policy"):
            print(f"      reason: {result.get('reason')}")
        elif result.get("error"):
            print(f"      error : {result.get('error')}")

    print()
    print("=" * 78)
    print("Both directions are covered by tests that use a real transport:")
    print("  apps/api/app/tests/test_mcp_gateway.py  (inbound, 25 tests)")
    print("  apps/api/app/tests/test_mcp_server.py   (outbound, 15 tests)")
    print("=" * 78)

    client.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
