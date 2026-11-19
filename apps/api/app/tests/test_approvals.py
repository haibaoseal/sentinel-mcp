"""The approval round trip.

These tests exist because "held for review" is only a control if a reviewer has
somewhere to decide and the decision has a way back into execution. Each one pins
a different way that could go wrong: the hold not being recorded, an approval
being reusable, an edit not being re-evaluated, an approval being transferable to
another call, and a ``block`` rule being relaxed by an approval.
"""

from __future__ import annotations

from typing import Any

import pytest
from app.approvals.service import ApprovalService
from app.audit.logger import read_chain, verify_chain
from app.core.contracts import ToolRequest
from app.core.errors import ApprovalMismatchError, ApprovalStateError, ToolExecutionError
from app.db.models import ApprovalRequest, PolicyDecisionRecord, ToolCall
from app.governance.firewall import Firewall
from app.policy.engine import PolicyEngine
from app.tools.registry import ToolRegistry
from app.tools.sources.local import LocalTool, LocalToolSource
from sqlalchemy import select


@pytest.fixture
def executions() -> list[dict[str, Any]]:
    """Every call that actually reached a tool, in order."""
    return []


@pytest.fixture
def firewall(session, executions) -> Firewall:
    def recorder(name: str):
        def run(arguments: dict[str, Any]) -> dict[str, Any]:
            executions.append({"tool": name, "arguments": dict(arguments)})
            return {"ok": True, "tool": name}

        return run

    def exploder(arguments: dict[str, Any]) -> dict[str, Any]:
        executions.append({"tool": "explode", "arguments": dict(arguments)})
        raise ToolExecutionError("the connector refused mid-flight")

    source = LocalToolSource(
        [
            LocalTool(
                name="explode",
                run=exploder,
                action_type="write",
                resource_type="file",
                risk_level="medium",
                requires_approval=True,
            ),
            LocalTool(
                name="draft_refund",
                run=recorder("draft_refund"),
                action_type="financial",
                resource_type="order",
                risk_level="high",
                requires_approval=True,
            ),
            LocalTool(
                name="write_file_draft",
                run=recorder("write_file_draft"),
                action_type="write",
                resource_type="file",
                risk_level="medium",
                requires_approval=True,
            ),
            LocalTool(
                name="delete_file",
                run=recorder("delete_file"),
                action_type="destructive",
                resource_type="file",
                risk_level="critical",
            ),
            LocalTool(
                name="fs_read",
                run=recorder("fs_read"),
                action_type="read",
                resource_type="file",
                risk_level="low",
            ),
        ],
        name="test",
    )
    return Firewall(registry=ToolRegistry([source]), policy_engine=PolicyEngine())


def _refund_request(task, **arguments) -> ToolRequest:
    return ToolRequest(
        task_id=task.id,
        tool_name="draft_refund",
        action_type="financial",
        resource_type="order",
        arguments={"order_id": "ORD-1001", **arguments},
        requested_by="agent",
    )


def _hold_tool(firewall, session, task, tool: str, action_type: str, arguments: dict):
    result = firewall.execute(
        ToolRequest(task_id=task.id, tool_name=tool, action_type=action_type, arguments=arguments),
        session=session,
    )
    assert result.status == "waiting_approval", result
    return session.get(ApprovalRequest, result.data["approval_id"])


def _hold(firewall, session, task, **arguments) -> ApprovalRequest:
    return _hold_tool(
        firewall, session, task, "draft_refund", "financial", {"order_id": "ORD-1001", **arguments}
    )


def _event_types(session, task_id) -> list[str]:
    return [event.event_type for event in read_chain(session, task_id)]


def test_a_held_call_creates_a_pending_approval(firewall, session, task, executions):
    result = firewall.execute(_refund_request(task), session=session)

    assert result.status == "waiting_approval"
    assert executions == [], "a held call must not reach the tool"

    rows = session.scalars(select(ApprovalRequest)).all()
    assert len(rows) == 1
    approval = rows[0]
    assert approval.status == "pending"
    assert approval.task_id == task.id
    assert approval.original_arguments_json == {"order_id": "ORD-1001"}
    assert approval.risk_level == "critical", "a financial action is critical risk"
    assert result.data["approval_id"] == approval.id, "the caller needs the id to act on it"

    events = _event_types(session, task.id)
    assert "approval.requested" in events
    assert verify_chain(read_chain(session, task.id)).ok


def test_approved_call_executes_through_the_firewall(firewall, session, task, executions):
    approval = _hold(firewall, session, task)
    service = ApprovalService(firewall=firewall, session=session)

    outcome = service.approve(approval.id, reviewer_id="alice", comment="checked the order")

    assert outcome.executed is True
    assert outcome.result is not None and outcome.result.status == "success"
    assert executions == [{"tool": "draft_refund", "arguments": {"order_id": "ORD-1001"}}]

    stored = session.get(ApprovalRequest, approval.id)
    assert stored.status == "executed"
    assert stored.reviewer_id == "alice"
    assert stored.review_comment == "checked the order"
    assert stored.reviewed_at is not None

    events = _event_types(session, task.id)
    assert "approval.approved" in events
    assert "approval.executed" in events
    assert verify_chain(read_chain(session, task.id)).ok

    # Two rows: the proposal that was held, and the approved execution. Keeping
    # them separate is what lets a reviewer see "held, then run" in the record.
    calls = session.scalars(select(ToolCall).where(ToolCall.task_id == task.id)).all()
    assert len(calls) == 2
    assert {call.status for call in calls} == {"waiting_approval", "executed"}


def test_rejected_call_never_executes(firewall, session, task, executions):
    approval = _hold(firewall, session, task)
    service = ApprovalService(firewall=firewall, session=session)

    outcome = service.reject(approval.id, reviewer_id="bob", comment="wrong customer")

    assert outcome.executed is False
    assert executions == []
    assert session.get(ApprovalRequest, approval.id).status == "rejected"
    assert "approval.rejected" in _event_types(session, task.id)

    with pytest.raises(ApprovalStateError):
        service.approve(approval.id, reviewer_id="alice")


def test_modified_arguments_are_what_executes(firewall, session, task, executions):
    approval = _hold(firewall, session, task)
    service = ApprovalService(firewall=firewall, session=session)

    outcome = service.approve(
        approval.id,
        reviewer_id="alice",
        modified_arguments={"order_id": "ORD-2002", "reason": "customer asked"},
    )

    assert outcome.executed is True
    assert executions == [
        {
            "tool": "draft_refund",
            "arguments": {"order_id": "ORD-2002", "reason": "customer asked"},
        }
    ], "the edited arguments must be what runs, not the original ones"

    stored = session.get(ApprovalRequest, approval.id)
    assert stored.status == "executed"
    assert stored.original_arguments_json == {"order_id": "ORD-1001"}
    assert stored.modified_arguments_json == {"order_id": "ORD-2002", "reason": "customer asked"}

    # The edit was a policy decision of its own, recorded under its own phase.
    # It is `require_approval` rather than `allow` because that is the baseline
    # for this tool -- the reviewer's decision is what supplies the approval.
    decisions = session.scalars(
        select(PolicyDecisionRecord).where(PolicyDecisionRecord.phase == "modified_approval")
    ).all()
    assert len(decisions) == 1
    assert decisions[0].decision == "require_approval"
    assert decisions[0].decision != "block"

    events = _event_types(session, task.id)
    assert "approval.modified" in events
    assert verify_chain(read_chain(session, task.id)).ok


def test_a_modification_that_escalates_risk_is_refused(firewall, session, task, executions):
    approval = _hold_tool(
        firewall, session, task, "write_file_draft", "write", {"path": "notes.md"}
    )
    assert approval.risk_level == "medium"
    service = ApprovalService(firewall=firewall, session=session)

    # A credential-shaped argument escalates the request, which is exactly the
    # kind of edit a reviewer must not be able to wave through.
    outcome = service.approve(
        approval.id,
        reviewer_id="alice",
        modified_arguments={"path": "notes.md", "content": "password=hunter2"},
    )

    assert outcome.executed is False
    assert outcome.reason is not None and "raises the risk" in outcome.reason
    assert executions == [], "the edit escalated risk, so nothing may run"

    stored = session.get(ApprovalRequest, approval.id)
    assert stored.status == "pending", "a refused edit must leave the request decidable"
    assert stored.modified_arguments_json is None, (
        "a refused edit must not become the arguments the approval covers"
    )

    events = _event_types(session, task.id)
    assert "approval.modification_refused" in events
    assert verify_chain(read_chain(session, task.id)).ok

    # And the request is still usable: approving the original proposal works.
    outcome = service.approve(approval.id, reviewer_id="alice")
    assert outcome.executed is True
    assert executions == [{"tool": "write_file_draft", "arguments": {"path": "notes.md"}}]


def test_an_edit_cannot_talk_policy_out_of_a_block(session, task, executions):
    """A reviewer supplies the approval a rule asks for; they cannot edit past a block."""

    def recorder(arguments: dict[str, Any]) -> dict[str, Any]:
        executions.append(dict(arguments))
        return {"ok": True}

    source = LocalToolSource(
        [
            LocalTool(
                name="query_tool",
                run=recorder,
                action_type="read",
                resource_type="database",
                risk_level="medium",
                requires_approval=True,
            )
        ],
        name="test",
    )
    policy = {
        "defaults": {"unknown_tool": "require_approval", "unknown_action": "require_approval"},
        "known_action_types": ["read", "write", "external_send", "destructive", "financial"],
        "tools": {
            "query_tool": {
                "action_type": "read",
                "risk": "medium",
                "approval_required": True,
                "constraints": {"read_only": True},
            }
        },
    }
    firewall = Firewall(registry=ToolRegistry([source]), policy_engine=PolicyEngine(policy))
    approval = _hold_tool(firewall, session, task, "query_tool", "read", {"query": "select 1"})
    service = ApprovalService(firewall=firewall, session=session)

    outcome = service.approve(
        approval.id, reviewer_id="alice", modified_arguments={"query": "drop table orders"}
    )

    assert outcome.executed is False
    assert outcome.policy_decision == "block"
    assert executions == [], "a block is not a control a reviewer can edit away"
    assert session.get(ApprovalRequest, approval.id).status == "pending"


def test_an_approval_cannot_be_replayed(firewall, session, task, executions):
    approval = _hold(firewall, session, task)
    service = ApprovalService(firewall=firewall, session=session)

    assert service.approve(approval.id, reviewer_id="alice").executed is True
    with pytest.raises(ApprovalStateError):
        service.approve(approval.id, reviewer_id="alice")
    assert len(executions) == 1, "a spent approval must not run the call twice"


def test_a_failed_execution_spends_the_decision(firewall, session, task, executions):
    """A tool that raised may still have applied part of its effect.

    So the decision is spent by the attempt it authorised: retrying needs a fresh
    proposal and a fresh decision, and a second approve must not re-run the call.
    """
    approval = _hold_tool(firewall, session, task, "explode", "write", {"path": "notes.md"})
    service = ApprovalService(firewall=firewall, session=session)

    outcome = service.approve(approval.id, reviewer_id="alice")

    assert outcome.executed is False
    assert outcome.result is not None and outcome.result.status == "failed"
    assert session.get(ApprovalRequest, approval.id).status == "failed"

    with pytest.raises(ApprovalStateError):
        service.approve(approval.id, reviewer_id="alice")
    assert len(executions) == 1, "the failed attempt must not be repeatable"

    events = _event_types(session, task.id)
    assert "approval.execution_failed" in events
    assert verify_chain(read_chain(session, task.id)).ok

    # It stays visible as decided, so a failure cannot look like work still queued.
    assert service.pending() == []
    assert [row.status for row in service.decided()] == ["failed"]


def test_an_approval_is_not_a_transferable_token(firewall, session, task, executions):
    approval = _hold(firewall, session, task)
    # Simulate a decision that exists but does not cover the call being made.
    approval.status = "approved"
    session.flush()

    with pytest.raises(ApprovalMismatchError):
        firewall.execute(
            _refund_request(task, reason="a different refund entirely"),
            session=session,
            approval_id=approval.id,
        )

    with pytest.raises(ApprovalMismatchError):
        firewall.execute(
            ToolRequest(
                task_id=task.id,
                tool_name="write_file_draft",
                action_type="write",
                arguments={"path": "notes.md"},
            ),
            session=session,
            approval_id=approval.id,
        )

    assert executions == []
    assert len(session.scalars(select(ApprovalRequest)).all()) == 1


def test_a_still_pending_approval_does_not_authorise_execution(firewall, session, task, executions):
    approval = _hold(firewall, session, task)

    with pytest.raises(ApprovalStateError):
        firewall.execute(_refund_request(task), session=session, approval_id=approval.id)

    assert executions == []


def test_a_block_rule_is_not_relaxed_by_an_approval(firewall, session, task, executions):
    approval = _hold(firewall, session, task)
    approval.status = "approved"
    session.flush()

    result = firewall.execute(
        ToolRequest(
            task_id=task.id,
            tool_name="delete_file",
            action_type="destructive",
            arguments={"path": "notes.md"},
        ),
        session=session,
        approval_id=approval.id,
    )

    assert result.status == "blocked", "default_block outranks any approval"
    assert executions == []


def test_separation_of_duties_refuses_self_approval(firewall, session, task, executions):
    task.user_id = "alice"
    session.flush()
    approval = _hold(firewall, session, task)

    service = ApprovalService(firewall=firewall, session=session, enforce_separation_of_duties=True)
    with pytest.raises(ApprovalStateError, match="separation-of-duties"):
        service.approve(approval.id, reviewer_id="alice")
    assert executions == []

    # A different reviewer can still approve.
    outcome = service.approve(approval.id, reviewer_id="bob")
    assert outcome.executed is True
    assert len(executions) == 1

    events = read_chain(session, task.id)
    assert any(event.event_type == "approval.self_approval_refused" for event in events)
    assert verify_chain(events).ok is True


def test_expire_stale_marks_old_pending_approvals_expired(firewall, session, task, executions):
    from datetime import timedelta

    from app.core.security import utcnow

    approval = _hold(firewall, session, task)
    approval.created_at = utcnow() - timedelta(hours=2)
    session.flush()

    service = ApprovalService(firewall=firewall, session=session)
    expired = service.expire_stale(max_age=timedelta(hours=1))
    assert [item.id for item in expired] == [approval.id]
    assert approval.status == "expired"
    assert task.status == "expired"
    assert executions == []

    events = read_chain(session, task.id)
    assert any(event.event_type == "approval.expired" for event in events)
    assert verify_chain(events).ok is True
