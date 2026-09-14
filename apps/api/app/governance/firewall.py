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
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from app.audit.logger import AuditLogger
from app.core.contracts import ToolDescriptor, ToolRequest, ToolResult
from app.core.errors import SentinelError, ToolExecutionError, ToolNotFoundError
from app.core.security import new_id, utcnow
from app.db.models import PolicyDecisionRecord, ToolCall
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

    def execute(self, request: ToolRequest, *, session: Session) -> ToolResult:
        """Evaluate, record, and only then execute.

        Note the deliberate name change from ``intercept`` to ``execute``: the
        method does execute, and calling it ``intercept`` invited callers to
        believe it was a passive hook.
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
            # Returning a terminal "waiting_approval" result is the whole point:
            # the caller must not be able to treat an unreviewed call as done.
            tool_call.status = "waiting_approval"
            session.flush()
            return ToolResult(
                tool_call_id=tool_call_id,
                status="waiting_approval",
                data={"risk_reasons": decision.reasons, "risk_level": decision.risk_level},
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
