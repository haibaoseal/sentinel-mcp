"""Run this runtime as an MCP server.

    python -m app.mcp.serve --transport stdio
    python -m app.mcp.serve --transport http --port 8765

An external MCP client connects here and sees the governed tools. It cannot reach
a tool any other way: every call is routed through the firewall, so policy,
approval and the audit chain apply to a foreign client exactly as they apply to
the built-in agent loop.

Note on output: the stdio transport owns stdout. Anything printed there corrupts
the protocol, so all diagnostics go to stderr.
"""

from __future__ import annotations

import argparse
import sys

from app.core.config import get_settings
from app.db.session import build_engine, build_session_factory, create_schema
from app.governance.firewall import Firewall
from app.policy.engine import PolicyEngine, load_policy_document
from app.resilience import ToolResilience
from app.runtime import build_registry


def _build(enable_mcp_servers: bool = False):
    settings = get_settings()
    engine = build_engine(settings.database_url)
    if settings.auto_create_schema:
        create_schema(engine)
    factory = build_session_factory(engine)

    registry = build_registry(settings, enable_mcp=enable_mcp_servers)
    resilience = (
        ToolResilience(
            retry_attempts=settings.tool_retry_attempts,
            retry_base_delay=settings.tool_retry_base_delay,
            circuit_failure_threshold=settings.circuit_failure_threshold,
            circuit_recovery_seconds=settings.circuit_recovery_seconds,
        )
        if settings.enable_tool_retries
        else None
    )
    firewall = Firewall(
        registry=registry,
        policy_engine=PolicyEngine(load_policy_document(settings.policy_path or None)),
        runtime_flags=settings.runtime_flags(),
        hmac_key=settings.hmac_key_bytes,
        resilience=resilience,
    )
    return settings, firewall, factory


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.mcp.serve")
    parser.add_argument(
        "--transport",
        choices=("stdio", "http"),
        default="stdio",
        help="stdio for local clients, http for Streamable HTTP",
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--path", default="/mcp")
    parser.add_argument(
        "--name", default=None, help="server name shown to clients (default: app_name)"
    )
    parser.add_argument(
        "--with-mcp-servers",
        action="store_true",
        help="also expose tools reached through configured outbound MCP servers",
    )
    args = parser.parse_args(argv)

    settings, firewall, factory = _build(enable_mcp_servers=args.with_mcp_servers)

    # Imported here so that `--help` works without the optional dependency.
    from app.mcp.server import build_server_module

    server, governed = build_server_module(
        firewall=firewall,
        session_factory=factory,
        name=args.name or settings.app_name,
    )

    published = governed.tool_descriptors()
    gated = sum(1 for spec in published if spec["governance"]["requires_approval"])
    print(
        f"serving {len(published)} governed tools ({gated} require approval) over {args.transport}",
        file=sys.stderr,
    )
    for spec in published:
        print(
            f"  {spec['name']:40} action={spec['governance']['action_type']:12} "
            f"risk={spec['governance']['risk_level']}",
            file=sys.stderr,
        )

    if args.transport == "stdio":
        server.run("stdio")
    else:
        print(f"listening on http://{args.host}:{args.port}{args.path}", file=sys.stderr)
        server.run(
            "streamable-http", host=args.host, port=args.port, streamable_http_path=args.path
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
