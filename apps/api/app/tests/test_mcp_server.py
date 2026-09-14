"""Tests for the outbound half of the gateway: governed tools published as MCP.

The point of these tests is the property that makes the design worth having: an
*external* MCP client cannot reach a tool except through the firewall. So the
tests connect a real MCP client to a real MCP server over stdio and assert that
policy, approval and the audit chain all applied.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from app.core.config import Settings
from app.db.models import AgentTask, AuditEvent, Base, ToolCall
from app.governance.firewall import Firewall
from app.mcp.client import MCPClient, MCPServerSpec
from app.mcp.server import GOVERNED_PREFIX, GovernedMCPServer
from app.policy.engine import PolicyEngine
from app.runtime import build_registry
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

REPO_ROOT = Path(__file__).resolve().parents[4]


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    (sandbox / "notes.md").write_text("governed sandbox notes\n", encoding="utf-8")
    knowledge = tmp_path / "knowledge"
    knowledge.mkdir()
    (knowledge / "policy.md").write_text(
        "# 政策\n\n## 退货期限 {#standard-window}\n\n签收后 30 天内可申请退货。\n",
        encoding="utf-8",
    )
    return Settings(
        _env_file=None,
        tool_sandbox_root=str(sandbox),
        knowledge_root=str(knowledge),
        agent_provider="replay",
    )


@pytest.fixture
def engine(tmp_path: Path):
    db_path = tmp_path / "governed.db"
    eng = create_engine(f"sqlite+pysqlite:///{db_path}")
    Base.metadata.create_all(eng)
    yield eng
    eng.dispose()


@pytest.fixture
def session_factory(engine):
    return sessionmaker(bind=engine, expire_on_commit=False)


@pytest.fixture
def governed(settings, session_factory):
    registry = build_registry(settings)
    firewall = Firewall(registry=registry, policy_engine=PolicyEngine())
    return GovernedMCPServer(firewall=firewall, session_factory=session_factory)


# --- publication -------------------------------------------------------------


def test_publishes_every_registered_tool(governed, settings):
    published = {spec["upstream_name"] for spec in governed.tool_descriptors()}
    assert published == set(settings and build_registry(settings).names())


def test_published_names_are_flattened_and_prefixed(governed):
    for spec in governed.tool_descriptors():
        assert spec["name"].startswith(GOVERNED_PREFIX)
        assert "." not in spec["name"]


def test_governance_metadata_is_published(governed):
    """A client should be able to see which tools are gated before calling."""
    by_upstream = {spec["upstream_name"]: spec for spec in governed.tool_descriptors()}
    assert by_upstream["fs_read"]["governance"]["action_type"] == "read"
    assert by_upstream["delete_file"]["governance"]["risk_level"] == "critical"
    assert by_upstream["delete_file"]["governance"]["requires_approval"] is True


def test_description_states_the_governance_posture(governed):
    for spec in governed.tool_descriptors():
        assert "[governed:" in spec["description"]


def test_unknown_published_name_is_refused(governed):
    result = governed.call("sentinel_not_a_tool", {})
    assert result["status"] == "unknown_tool"
    assert "error" in result


# --- governance on the external path ----------------------------------------


def test_allowed_call_executes_and_is_audited(governed, engine):
    published = {spec["upstream_name"]: spec["name"] for spec in governed.tool_descriptors()}
    result = governed.call(published["fs_read"], {"path": "notes.md"})

    assert result["status"] == "success"
    assert "governed sandbox notes" in str(result["data"])

    with Session(engine) as session:
        calls = list(session.scalars(select(ToolCall)))
        assert len(calls) == 1
        assert calls[0].tool_name == "fs_read"
        events = [e.event_type for e in session.scalars(select(AuditEvent))]
        assert "tool.proposed" in events
        assert "policy.evaluated" in events
        assert "tool.executed" in events
        task = session.scalars(select(AgentTask)).one()
        assert task.agent_type == "mcp-client"


def test_destructive_call_is_blocked_not_executed(governed, engine):
    published = {spec["upstream_name"]: spec["name"] for spec in governed.tool_descriptors()}
    result = governed.call(published["delete_file"], {"path": "notes.md"})

    assert result["status"] == "blocked"
    assert result["blocked_by_policy"] is True
    assert "NOT" in result["note"] or "Nothing" in result["note"]

    with Session(engine) as session:
        call = session.scalars(select(ToolCall)).one()
        assert call.status == "blocked"
        assert call.status != "executed"


def test_approval_gated_call_is_held_and_reported_as_held(governed, engine):
    """A gated call must not be reported as an error, nor as a success.

    Returning "failed" would invite the client to retry a gated action; returning
    success would be a lie.
    """
    published = {spec["upstream_name"]: spec["name"] for spec in governed.tool_descriptors()}
    result = governed.call(published["send_email"], {"to": "a@example.com", "body": "hi"})

    assert result["status"] == "waiting_approval"
    assert result["held_for_approval"] is True
    assert result["reason"], "the client must be told why it was held"
    assert "NOT been executed" in result["note"]

    with Session(engine) as session:
        call = session.scalars(select(ToolCall)).one()
        assert call.status == "waiting_approval"


def test_failed_call_does_not_claim_success(governed, engine):
    published = {spec["upstream_name"]: spec["name"] for spec in governed.tool_descriptors()}
    result = governed.call(published["fs_read"], {"path": "missing.md"})
    assert result["status"] == "failed"
    assert "error" in result

    with Session(engine) as session:
        call = session.scalars(select(ToolCall)).one()
        assert call.status == "failed"
        assert call.error_code == "INVALID_ARGS"


def test_each_external_call_gets_its_own_task_and_chain(governed, engine):
    """A shared session across calls would let one failure poison the next."""
    published = {spec["upstream_name"]: spec["name"] for spec in governed.tool_descriptors()}
    governed.call(published["fs_read"], {"path": "notes.md"})
    governed.call(published["fs_read"], {"path": "notes.md"})

    with Session(engine) as session:
        tasks = list(session.scalars(select(AgentTask)))
        assert len(tasks) == 2
        from app.audit.logger import read_chain, verify_chain

        for task in tasks:
            assert verify_chain(read_chain(session, task.id)).ok


def test_audit_chain_verifies_after_a_governed_external_call(governed, engine):
    published = {spec["upstream_name"]: spec["name"] for spec in governed.tool_descriptors()}
    governed.call(published["fs_read"], {"path": "notes.md"})
    with Session(engine) as session:
        task = session.scalars(select(AgentTask)).one()
        from app.audit.logger import read_chain, verify_chain

        chain = read_chain(session, task.id)
        assert len(chain) >= 3
        assert verify_chain(chain).ok


def test_arguments_are_passed_through_to_the_tool(governed):
    published = {spec["upstream_name"]: spec["name"] for spec in governed.tool_descriptors()}
    result = governed.call(published["search_knowledge_base"], {"query": "退货期限", "top_k": 2})
    assert result["status"] == "success"
    citations = result["data"]["citations"]
    assert citations
    assert citations[0]["id"].endswith("standard-window")


# --- end to end over a real transport ---------------------------------------


STDIO_SERVER = """\
import sys
from pathlib import Path

sys.path.insert(0, {app_path!r})

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.config import Settings
from app.db.models import Base
from app.governance.firewall import Firewall
from app.mcp.server import build_server_module
from app.policy.engine import PolicyEngine
from app.runtime import build_registry

settings = Settings(
    _env_file=None,
    tool_sandbox_root={sandbox!r},
    knowledge_root={knowledge!r},
)
engine = create_engine({db_url!r})
Base.metadata.create_all(engine)
factory = sessionmaker(bind=engine, expire_on_commit=False)

firewall = Firewall(registry=build_registry(settings), policy_engine=PolicyEngine())
server, _ = build_server_module(firewall=firewall, session_factory=factory)
server.run("stdio")
"""


@pytest.fixture
def stdio_gateway(tmp_path, settings, engine):
    """Write a launcher and connect a real MCP client to it over stdio."""
    script = tmp_path / "gateway_stdio.py"
    script.write_text(
        STDIO_SERVER.format(
            app_path=str(REPO_ROOT / "apps" / "api"),
            sandbox=str(settings.tool_sandbox_root),
            knowledge=str(settings.knowledge_root),
            db_url=str(engine.url),
        ),
        encoding="utf-8",
    )
    client = MCPClient(
        MCPServerSpec(
            name="sentinel",
            transport="stdio",
            command=sys.executable,
            args=[str(script)],
            startup_timeout=60.0,
            call_timeout=60.0,
        )
    )
    client.connect()
    client.discover()
    yield client
    client.close()


def test_gateway_publishes_governed_tools_over_stdio(stdio_gateway):
    names = stdio_gateway.described_tools()
    assert any(name.endswith("fs_read") for name in names), names
    assert any(name.endswith("delete_file") for name in names), names


def test_external_client_call_is_governed_over_stdio(stdio_gateway, engine):
    """The end-to-end claim: a foreign MCP client reaches a tool only through policy.

    Name shape is ``mcp.<server>.<published>``, and the published name is the
    flattened upstream name with a ``sentinel_`` prefix, so a full name reads
    ``mcp.sentinel.sentinel_fs_read``. Verbose on purpose: the prefix makes it
    visible in a client's UI that the tool is mediated, while the audit log
    records the upstream name.
    """
    result = stdio_gateway.execute("mcp.sentinel.sentinel_fs_read", {"path": "notes.md"})
    assert "governed sandbox notes" in str(result)

    with Session(engine) as session:
        call = session.scalars(select(ToolCall)).one()
        assert call.tool_name == "fs_read"
        assert call.status == "executed"
        from app.audit.logger import read_chain, verify_chain

        assert verify_chain(read_chain(session, call.task_id)).ok


def test_external_client_destructive_call_is_blocked_over_stdio(stdio_gateway, engine):
    result = stdio_gateway.execute("mcp.sentinel.sentinel_delete_file", {"path": "notes.md"})
    # The tool reports a policy block as structured content, not as a crash.
    text = str(result)
    assert "blocked" in text.lower()

    with Session(engine) as session:
        call = session.scalars(select(ToolCall)).one()
        assert call.status == "blocked"
        assert call.status != "executed"
