"""The execution boundary.

Every tool call in this system goes through ``Firewall.execute``. Nothing else
calls a ``ToolSource``. That is the invariant the CI boundary job enforces by
grepping for stray ``.execute(`` call sites.

Compared with the previous generation, three things changed deliberately:

1. **``session`` is required.** The old signature was
   ``intercept(request, session=None)`` and, when ``session`` was ``None``, the
   tool still ran while every audit write and approval record was skipped. A
   governance runtime cannot have an ungoverned entry point, so the parameter is
   now mandatory and there is no code path that executes without a record.

2. **Execution is delegated to a source, not a registry.** Local tools and
   remote MCP tools arrive through the same ``ToolSource`` protocol, so the
   policy decision cannot be bypassed by a tool that happens to live elsewhere.

3. **The decision and its persistence are one transaction.** The old code
   flushed between steps and could leave a ``ToolCall`` row with no matching
   ``PolicyDecisionRecord``. Here the caller's transaction is the unit.

4. **A hold is recorded, and an approval is checked rather than trusted.**
   ``require_approval`` writes an ``ApprovalRequest`` and returns
   ``waiting_approval``; ``execute`` accepts an optional ``approval_id``, and the
   call only runs when that approval exists, still authorises execution, covers a
   proposal for the *same* tool, and matches the arguments being executed to the
   character. A ``block`` is never relaxed by an approval, so this second entry
   into the same method cannot be turned into a bypass.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from app.audit.logger import AuditLogger, canonical_json
from app.core.contracts import ToolDescriptor, ToolRequest, ToolResult
from app.core.errors import (
    ApprovalMismatchError,
    ApprovalNotFoundError,
    ApprovalStateError,
    SentinelError,
    ToolExecutionError,
    ToolNotFoundError,
)
from app.core.security import new_id, utcnow
from app.db.models import ApprovalRequest, PolicyDecisionRecord, ToolCall
from app.policy.engine import PolicyDecision, PolicyEngine
from app.tools.registry import ToolRegistry


class Firewall:
    def __init__(
        self,
        *,
        registry: ToolRegistry,
        policy_engine: PolicyEngine | None = None,
        runtime_flags: dict[str, bool] | None = None,
        hmac_key: bytes | None = None,
    ) -> None:
        self.registry = registry
        self.policy_engine = policy_engine or PolicyEngine()
        self.runtime_flags = runtime_flags or {}
        self.hmac_key = hmac_key
        # Decision per tool_call_id, so a caller building a trace can record *why*
        # a call was allowed, blocked or held without re-evaluating the policy.
        # Re-evaluating would be wrong: policy can change between the decision and
        # the trace, and a trace must describe the decision that was actually made.
        self.decisions: dict[str, PolicyDecision] = {}
        self._decision_order: list[str] = []

    # -- public API ---------------------------------------------------------

    def execute(
        self, request: ToolRequest, *, session: Session, approval_id: str | None = None
    ) -> ToolResult:
        """Evaluate, record, and only then execute.

        Note the deliberate name change from ``intercept`` to ``execute``: the
        method does execute, and calling it ``intercept`` invited callers to
        believe it was a passive hook.

        ``approval_id`` is how a held call comes back: the caller presents a
        reviewer's decision, which is validated before the policy hold is
        relaxed. Omit it and a ``require_approval`` decision stays a hold.
        """
        decision = self.policy_engine.evaluate(request, runtime_flags=self.runtime_flags)
        descriptor = self.registry.describe(request.tool_name)
        tool_call_id = new_id()
        self.decisions[tool_call_id] = decision
        self._decision_order.append(tool_call_id)
        # Keep the map bounded: a long-lived process should not accumulate one entry
        # per call forever.
        while len(self._decision_order) > 1000:
            self.decisions.pop(self._decision_order.pop(0), None)

        tool_call = self._persist_proposal(session, request, decision, descriptor, tool_call_id)
        audit = AuditLogger(session, hmac_key=self.hmac_key)
        audit.write(
            task_id=request.task_id,
            event_type="tool.proposed",
            actor_type=request.requested_by,
            actor_id=request.user_id,
            payload={
                "tool_call_id": tool_call_id,
                "tool_name": request.tool_name,
                "action_type": request.action_type,
                "source": descriptor.source if descriptor else None,
                "arguments": request.arguments,
            },
        )
        audit.write(
            task_id=request.task_id,
            event_type="policy.evaluated",
            actor_type="policy",
            actor_id="policy-engine",
            payload={
                "tool_call_id": tool_call_id,
                "tool_name": request.tool_name,
                "decision": decision.decision,
                "risk_level": decision.risk_level,
                "reasons": decision.reasons,
                "matched_rules": decision.matched_rules,
            },
        )

        if decision.decision == "block":
            return self._blocked(session, tool_call, request, decision, audit, tool_call_id)

        if decision.decision == "require_approval":
            if approval_id is not None:
                # A reviewer has decided. Validate that decision against *this*
                # call before relaxing the hold, then run through the same path a
                # permitted call takes.
                self._authorise_with_approval(session, approval_id, request)
                return self._run(session, tool_call, request, decision, audit, tool_call_id)

            # Returning a terminal "waiting_approval" result is the whole point:
            # the caller must not be able to treat an unreviewed call as done.
            # The row written here is what an approval queue reads and what an
            # approved execution is checked against -- "held for review" with
            # nothing behind it is only a status string.
            approval = self._hold_for_review(session, request, decision, tool_call_id)
            audit.write(
                task_id=request.task_id,
                event_type="approval.requested",
                actor_type="policy",
                actor_id="policy-engine",
                payload={
                    "approval_id": approval.id,
                    "tool_call_id": tool_call_id,
                    "tool_name": request.tool_name,
                    "risk_level": decision.risk_level,
                    "reasons": decision.reasons,
                },
            )
            tool_call.status = "waiting_approval"
            session.flush()
            return ToolResult(
                tool_call_id=tool_call_id,
                status="waiting_approval",
                data={
                    "risk_reasons": decision.reasons,
                    "risk_level": decision.risk_level,
                    "approval_id": approval.id,
                },
                source=descriptor.source if descriptor else None,
            )

        return self._run(session, tool_call, request, decision, audit, tool_call_id)

    # -- branches -----------------------------------------------------------

    def _blocked(
        self,
        session: Session,
        tool_call: ToolCall,
        request: ToolRequest,
        decision,
        audit: AuditLogger,
        tool_call_id: str,
    ) -> ToolResult:
        tool_call.status = "blocked"
        audit.write(
            task_id=request.task_id,
            event_type="tool.blocked",
            actor_type="policy",
            actor_id="policy-engine",
            payload={
                "tool_call_id": tool_call_id,
                "tool_name": request.tool_name,
                "risk_level": decision.risk_level,
                "reasons": decision.reasons,
                "matched_rules": decision.matched_rules,
            },
        )
        session.flush()
        return ToolResult(
            tool_call_id=tool_call_id,
            status="blocked",
            error="; ".join(decision.reasons),
        )

    def _run(
        self,
        session: Session,
        tool_call: ToolCall,
        request: ToolRequest,
        decision,
        audit: AuditLogger,
        tool_call_id: str,
    ) -> ToolResult:
        executable = decision.transformed_request or request

        try:
            data = self.registry.execute(executable.tool_name, executable.arguments)
        except (SentinelError, ToolExecutionError, ToolNotFoundError) as exc:
            code = getattr(exc, "code", "TOOL_EXECUTION_FAILED")
            tool_call.status = "failed"
            tool_call.error_code = code
            audit.write(
                task_id=request.task_id,
                event_type="tool.failed",
                actor_type="tool",
                actor_id=executable.tool_name,
                payload={
                    "tool_call_id": tool_call_id,
                    "tool_name": executable.tool_name,
                    "error_code": code,
                    "error": str(exc),
                },
            )
            session.flush()
            return ToolResult(
                tool_call_id=tool_call_id, status="failed", error=str(exc), source=tool_call.source
            )

        tool_call.status = "executed"
        tool_call.executed_at = utcnow()
        audit.write(
            task_id=request.task_id,
            event_type="tool.executed",
            actor_type="tool",
            actor_id=executable.tool_name,
            payload={
                "tool_call_id": tool_call_id,
                "tool_name": executable.tool_name,
                "status": "success",
                "data": data,
            },
        )
        session.flush()
        return ToolResult(
            tool_call_id=tool_call_id, status="success", data=data, source=tool_call.source
        )

    # -- approval -----------------------------------------------------------

    def _hold_for_review(
        self,
        session: Session,
        request: ToolRequest,
        decision,
        tool_call_id: str,
    ) -> ApprovalRequest:
        """Record the hold so a reviewer has something to decide about."""
        approval = ApprovalRequest(
            tool_call_id=tool_call_id,
            task_id=request.task_id,
            requested_by_agent=request.requested_by,
            status="pending",
            original_arguments_json=request.arguments,
            risk_level=decision.risk_level,
            risk_reasons_json=decision.reasons,
        )
        session.add(approval)
        session.flush()
        return approval

    def _authorise_with_approval(
        self, session: Session, approval_id: str, request: ToolRequest
    ) -> ApprovalRequest:
        """Check a reviewer's decision before letting a held call run.

        Every branch fails closed, because an approval that could be reused is a
        transferable token: approve a harmless refund draft, then run whatever
        you like under it. So the approval must exist, still be in a state that
        authorises execution, belong to a proposal for *this* tool, and cover
        exactly the arguments being executed.
        """
        approval = session.get(ApprovalRequest, approval_id)
        if approval is None:
            raise ApprovalNotFoundError(f"no approval request {approval_id!r}")
        if approval.status not in {"approved", "modified"}:
            raise ApprovalStateError(
                f"approval {approval_id!r} is {approval.status!r}, which does not "
                "authorise execution"
            )

        proposal = session.get(ToolCall, approval.tool_call_id)
        if proposal is None or proposal.tool_name != request.tool_name:
            raise ApprovalMismatchError(
                f"approval {approval_id!r} was granted for a different tool"
            )

        expected = approval.modified_arguments_json
        if expected is None:
            expected = approval.original_arguments_json or {}
        if canonical_json(expected) != canonical_json(request.arguments):
            raise ApprovalMismatchError(
                f"the arguments being executed differ from the ones approval {approval_id!r} covers"
            )
        return approval

    # -- persistence --------------------------------------------------------

    def _persist_proposal(
        self,
        session: Session,
        request: ToolRequest,
        decision,
        descriptor: ToolDescriptor | None,
        tool_call_id: str,
    ) -> ToolCall:
        status = {
            "allow": "allowed",
            "transform": "allowed",
            "block": "blocked",
            "require_approval": "waiting_approval",
        }.get(decision.decision, "proposed")

        tool_call = ToolCall(
            id=tool_call_id,
            task_id=request.task_id,
            tool_name=request.tool_name,
            action_type=request.action_type,
            resource_type=request.resource_type,
            resource_id=request.resource_id,
            arguments_json=request.arguments,
            status=status,
            risk_level=decision.risk_level,
            risk_reasons_json=decision.reasons,
            source=descriptor.source if descriptor else None,
        )
        session.add(tool_call)
        session.flush()

        policy_record = PolicyDecisionRecord(
            tool_call_id=tool_call_id,
            decision=decision.decision,
            reason="; ".join(decision.reasons),
            matched_rules_json=decision.matched_rules,
            phase="proposal",
        )
        session.add(policy_record)
        session.flush()
        tool_call.policy_decision_id = policy_record.id
        session.flush()
        return tool_call
