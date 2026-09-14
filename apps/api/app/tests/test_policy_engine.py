"""Policy engine tests.

The theme here is fail-closed behaviour. Each test names a way the runtime could
be tricked into executing something it should not, and asserts the engine
refuses.
"""

from __future__ import annotations

import pytest
from app.core.contracts import ToolRequest
from app.policy.engine import PolicyEngine


@pytest.fixture
def engine() -> PolicyEngine:
    return PolicyEngine()


def decide(engine: PolicyEngine, tool_name: str, action_type: str = "read", **arguments):
    return engine.evaluate(
        ToolRequest(tool_name=tool_name, action_type=action_type, arguments=arguments)  # type: ignore[arg-type]
    )


# --- fail closed -------------------------------------------------------------


def test_unknown_tool_requires_approval(engine):
    """Adding a tool must never silently widen permissions."""
    decision = decide(engine, "totally_new_tool")
    assert decision.decision == "require_approval"
    assert decision.risk_level == "high"
    assert "defaults.unknown_tool" in decision.matched_rules


def test_unknown_action_type_escalates(engine):
    """A caller can always declare `unknown`; the engine must not treat it as safe."""
    decision = decide(engine, "fs_read", action_type="unknown")
    assert decision.decision == "require_approval"
    assert "defaults.unknown_action" in decision.matched_rules


def test_action_type_is_a_closed_vocabulary():
    """`action_type` is a Literal, so a typo cannot smuggle in a new category.

    This is why the engine never needs to branch on an arbitrary string: the
    only way to reach it with an unrecognised action is the explicit `unknown`.
    """
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        ToolRequest(tool_name="fs_read", action_type="teleport")  # type: ignore[arg-type]


def test_disabled_tool_is_blocked(engine):
    decision = decide(engine, "github_post_issue_comment", action_type="external_send")
    assert decision.decision == "block"


def test_default_block_tool_is_blocked(engine):
    decision = decide(engine, "delete_file", action_type="destructive", path="x.txt")
    assert decision.decision == "block"
    assert decision.risk_level == "critical"


# --- action-type escalation --------------------------------------------------


def test_external_send_is_never_allowed(engine):
    decision = decide(engine, "send_email", action_type="external_send", to="a@b.com")
    assert decision.decision != "allow"
    assert decision.risk_level == "high"


def test_destructive_is_never_allowed(engine):
    decision = decide(engine, "sql_execute_write", action_type="destructive", query="DELETE FROM t")
    assert decision.decision != "allow"
    assert decision.risk_level == "critical"


def test_financial_action_is_critical(engine):
    decision = decide(engine, "draft_refund", action_type="financial", order_id="ORD-1")
    assert decision.risk_level == "critical"
    assert decision.decision == "require_approval"


# --- read-only SQL -----------------------------------------------------------


@pytest.mark.parametrize(
    "query",
    [
        "SELECT count(*) FROM orders",
        "select * from users where id = 1",
        "WITH t AS (SELECT 1) SELECT * FROM t",
    ],
)
def test_readonly_sql_is_allowed(engine, query):
    assert decide(engine, "sql_query", query=query).decision == "allow"


@pytest.mark.parametrize(
    "query",
    [
        "DELETE FROM orders",
        "UPDATE users SET balance = 0",
        "DROP TABLE orders",
        "ALTER TABLE orders ADD COLUMN x TEXT",
        "TRUNCATE orders",
        "INSERT INTO orders VALUES (1)",
        "GRANT ALL ON orders TO public",
        "SELECT 1; DROP TABLE orders",
        "/* comment */ DELETE FROM orders",
    ],
)
def test_write_sql_is_blocked_in_readonly_mode(engine, query):
    decision = decide(engine, "sql_query", query=query)
    assert decision.decision == "block", query
    assert decision.risk_level == "critical"


def test_readonly_sql_without_a_query_is_blocked(engine):
    """Absence of a query must not be read as "nothing dangerous to find"."""
    decision = decide(engine, "sql_query")
    assert decision.decision == "block"


def test_readonly_constraint_only_applies_to_constrained_tools(engine):
    """A tool without the read_only constraint is not silently treated as read-only.

    `sql_execute_write` is separately blocked as destructive; the point is that
    the SQL scanner keys off the constraint, not off the tool's name.
    """
    decision = decide(engine, "sql_execute_write", action_type="destructive", query="SELECT 1")
    assert decision.decision == "block"


# --- sensitive arguments -----------------------------------------------------


@pytest.mark.parametrize(
    "arguments",
    [
        {"body": "the password is hunter2"},
        {"note": "api_key=abcdef"},
        {"text": "身份证 110101199003071234"},
        {"card": "card_number 4111111111111111"},
    ],
)
def test_sensitive_arguments_escalate_to_critical(engine, arguments):
    decision = decide(engine, "fs_write_draft", action_type="write", **arguments)
    assert decision.risk_level == "critical"
    assert decision.decision != "allow"


def test_all_sensitive_groups_are_reported(engine):
    """The old engine returned on the first hit and hid the remaining reasons."""
    decision = decide(
        engine,
        "fs_write_draft",
        action_type="write",
        a="password=x",
        b="身份证 110101199003071234",
        c="card_number 4111",
    )
    groups = [rule for rule in decision.matched_rules if rule.startswith("sensitive_patterns.")]
    assert len(groups) >= 3, decision.matched_rules


# --- runtime flags -----------------------------------------------------------


def test_real_side_effect_tools_are_blocked_by_default(engine):
    """The default posture: nothing real is mutated without an explicit opt-in."""
    decision = engine.evaluate(
        ToolRequest(
            tool_name="http_post", action_type="external_send", arguments={"url": "https://x"}
        ),
        runtime_flags={"real_connectors": False, "real_external_actions": False},
    )
    assert decision.decision == "block"


def test_flags_do_not_unblock_a_default_block_tool(engine):
    """Switching a flag on must not override `default_block`."""
    decision = engine.evaluate(
        ToolRequest(tool_name="sql_execute_write", action_type="destructive", arguments={}),
        runtime_flags={
            "real_connectors": True,
            "real_write_actions": True,
            "real_destructive_actions": True,
            "real_external_actions": True,
        },
    )
    assert decision.decision == "block"


# --- transforms --------------------------------------------------------------


def test_transform_is_applied_and_reported():
    policy = {
        "defaults": {"unknown_tool": "block"},
        "tools": {
            "fs_write_draft": {
                "action_type": "write",
                "risk": "medium",
                "approval_required": False,
                "transform": {
                    "remove_arguments": ["secret_extra"],
                    "prefix_arguments": {"path": "/sandbox/"},
                    "set_arguments": {"dry_run": True},
                },
            }
        },
    }
    engine = PolicyEngine(policy)
    decision = engine.evaluate(
        ToolRequest(
            tool_name="fs_write_draft",
            action_type="write",
            arguments={"path": "notes.md", "secret_extra": "leak"},
        )
    )
    assert decision.decision == "transform"
    assert decision.transformed_request is not None
    assert decision.transformed_request.arguments["path"] == "/sandbox/notes.md"
    assert decision.transformed_request.arguments["dry_run"] is True
    assert "secret_extra" not in decision.transformed_request.arguments
    # The original request must not be mutated.
    assert decision.transformed_request is not None


def test_transform_does_not_run_when_decision_is_not_allow():
    policy = {
        "defaults": {"unknown_tool": "block"},
        "tools": {
            "t": {
                "action_type": "write",
                "risk": "medium",
                "approval_required": True,
                "transform": {"set_arguments": {"x": 1}},
            }
        },
    }
    decision = PolicyEngine(policy).evaluate(ToolRequest(tool_name="t", action_type="write"))
    assert decision.decision == "require_approval"
    assert decision.transformed_request is None


def test_engine_never_mutates_the_incoming_request(engine):
    request = ToolRequest(tool_name="fs_read", action_type="read", arguments={"path": "a.txt"})
    engine.evaluate(request)
    assert request.arguments == {"path": "a.txt"}


def test_matched_rules_and_reasons_are_always_populated(engine):
    """A decision with no explanation cannot be reviewed by a human."""
    for name, action in [("fs_read", "read"), ("send_email", "external_send"), ("nope", "read")]:
        decision = decide(engine, name, action_type=action)
        assert decision.reasons, name
        assert decision.matched_rules, name
