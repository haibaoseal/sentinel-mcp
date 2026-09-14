"""Human approval: the round trip a held call needs.

The firewall's ``require_approval`` branch writes an ``ApprovalRequest`` and
returns ``waiting_approval``. On its own that is only half a control: a reviewer
needs somewhere to decide, and the decision needs a way back into execution.
This module is the other half.

Three properties are deliberate:

1. **A decision is data, not a flag.** Approve, modify and reject are transitions
   on a persisted row, and each one is written to the same hash-chained audit log
   as the call it is about -- so "who let this run" is answerable from the chain
   alone.
2. **A modified argument set is re-evaluated.** Editing the parameters of a
   high-risk action is itself a decision policy has an opinion about, so the
   modified request goes back through the policy engine and is recorded under a
   distinct ``modified_approval`` phase. Two edits are refused: one that policy
   now *blocks* (a reviewer supplies the approval a ``require_approval`` rule
   asks for, but cannot edit away a ``default_block``), and one that raises the
   risk level above what the reviewer was shown. A refused edit executes nothing
   and leaves the request **pending**, so the reviewer can try a different change
   rather than losing the call -- and a refused edit never becomes the arguments
   the approval covers.
3. **Execution still goes through the firewall.** ``approve`` never calls a tool;
   it calls ``Firewall.execute(..., approval_id=...)``. An approved call takes the
   same path as a permitted one, writes the same records, and a ``block`` rule
   still wins.

Expiry is not implemented: the model lists an ``expired`` status, and a pending
request simply stays pending until someone decides.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.audit.logger import AuditLogger
from app.core.contracts import RISK_ORDER, ToolRequest, ToolResult
from app.core.errors import ApprovalNotFoundError, ApprovalStateError
from app.core.security import utcnow
from app.db.models import ApprovalRequest, PolicyDecisionRecord, ToolCall
from app.governance.firewall import Firewall

# Statuses this module writes. `pending` and the terminal ones come from the
# model's list; `executed` and `failed` are appended here because a reviewer
# looking at a queue needs to tell "approved but not run", "approved and run" and
# "run and failed" apart -- and because a decision that has been *spent* must not
# look decidable again.
PENDING = "pending"
APPROVED = "approved"
MODIFIED = "modified"
REJECTED = "rejected"
EXECUTED = "executed"
FAILED = "failed"

# The states that authorise execution. `executed` and `failed` are deliberately
# absent: a decision is spent by the attempt it authorises. Re-running after a
# failure would be wrong even when the tool reported an error, because a tool that
# raised may still have applied part of its effect.
AUTHORISING = (APPROVED, MODIFIED)


@dataclass(frozen=True)
class ApprovalOutcome:
    """What a reviewer's decision produced."""

    approval_id: str
    status: str
    executed: bool
    result: ToolResult | None = None
    reason: str | None = None
    policy_decision: str | None = None


class ApprovalService:
    def __init__(
        self,
        *,
        firewall: Firewall,
        session: Session,
        hmac_key: bytes | None = None,
    ) -> None:
        self.firewall = firewall
        self.session = session
        # Default to the firewall's key so approval events land in the same chain
        # as the calls they are about, verifiable with the same key.
        self.audit = AuditLogger(
            session, hmac_key=hmac_key if hmac_key is not None else firewall.hmac_key
        )

    # -- reads --------------------------------------------------------------

    def pending(self, *, task_id: str | None = None) -> list[ApprovalRequest]:
        statement = select(ApprovalRequest).where(ApprovalRequest.status == PENDING)
        if task_id is not None:
            statement = statement.where(ApprovalRequest.task_id == task_id)
        return list(self.session.scalars(statement.order_by(ApprovalRequest.created_at.asc())))

    def decided(self, *, task_id: str | None = None) -> list[ApprovalRequest]:
        """Everything a reviewer has already acted on, oldest first.

        A failed execution stays visible here: it is the one outcome that looks
        like it wants a retry, and it must not silently get one.
        """
        statement = select(ApprovalRequest).where(ApprovalRequest.status != PENDING)
        if task_id is not None:
            statement = statement.where(ApprovalRequest.task_id == task_id)
        return list(self.session.scalars(statement.order_by(ApprovalRequest.created_at.asc())))

    def get(self, approval_id: str) -> ApprovalRequest:
        approval = self.session.get(ApprovalRequest, approval_id)
        if approval is None:
            raise ApprovalNotFoundError(f"no approval request {approval_id!r}")
        return approval

    # -- decisions ----------------------------------------------------------

    def approve(
        self,
        approval_id: str,
        *,
        reviewer_id: str,
        modified_arguments: dict[str, Any] | None = None,
        comment: str | None = None,
    ) -> ApprovalOutcome:
        """Approve a held call -- optionally with edited arguments -- and run it."""
        approval = self._require_pending(approval_id)
        proposal = self._proposal_for(approval)
        changed = modified_arguments is not None
        final_arguments = (
            dict(modified_arguments)
            if modified_arguments is not None
            else dict(approval.original_arguments_json or {})
        )

        if changed:
            decision = self.firewall.policy_engine.evaluate(
                self._request_for(approval, proposal, final_arguments, reviewer_id),
                runtime_flags=self.firewall.runtime_flags,
            )
            self.session.add(
                PolicyDecisionRecord(
                    tool_call_id=proposal.id,
                    decision=decision.decision,
                    reason="; ".join(decision.reasons),
                    matched_rules_json=decision.matched_rules,
                    phase="modified_approval",
                )
            )
            self.session.flush()

            refusal = self._refusal_reason(decision, approval)
            if refusal is not None:
                # The attempt is recorded on the chain -- but deliberately *not*
                # stored as the arguments this approval covers, or a refused edit
                # would silently become the thing a later approve executes.
                self.audit.write(
                    task_id=approval.task_id,
                    event_type="approval.modification_refused",
                    actor_type="policy",
                    actor_id="policy-engine",
                    payload={
                        "approval_id": approval.id,
                        "tool_call_id": proposal.id,
                        "tool_name": proposal.tool_name,
                        "proposed_arguments": final_arguments,
                        "decision": decision.decision,
                        "risk_level": decision.risk_level,
                        "reasons": decision.reasons,
                        "refusal": refusal,
                    },
                )
                self.session.flush()
                return ApprovalOutcome(
                    approval_id=approval.id,
                    status=approval.status,
                    executed=False,
                    reason=refusal,
                    policy_decision=decision.decision,
                )

            approval.status = MODIFIED
            approval.modified_arguments_json = final_arguments
        else:
            approval.status = APPROVED

        approval.reviewer_id = reviewer_id
        approval.review_comment = comment
        approval.reviewed_at = utcnow()
        self.audit.write(
            task_id=approval.task_id,
            event_type="approval.modified" if changed else "approval.approved",
            actor_type="reviewer",
            actor_id=reviewer_id,
            payload={
                "approval_id": approval.id,
                "tool_call_id": proposal.id,
                "tool_name": proposal.tool_name,
                "arguments": final_arguments,
                "modified": changed,
                "comment": comment,
            },
        )
        self.session.flush()

        result = self.firewall.execute(
            self._request_for(approval, proposal, final_arguments, reviewer_id),
            session=self.session,
            approval_id=approval.id,
        )

        if result.status == "success":
            approval.status = EXECUTED
            self.audit.write(
                task_id=approval.task_id,
                event_type="approval.executed",
                actor_type="reviewer",
                actor_id=reviewer_id,
                payload={
                    "approval_id": approval.id,
                    "tool_call_id": result.tool_call_id,
                    "tool_name": proposal.tool_name,
                    "status": result.status,
                },
            )
        else:
            # The decision is spent either way. A tool that raised may still have
            # applied part of its effect, so "it failed, just try again" is not a
            # safe thing to offer from here: the chain records what happened, and
            # another attempt needs a fresh proposal and a fresh decision.
            approval.status = FAILED
            self.audit.write(
                task_id=approval.task_id,
                event_type="approval.execution_failed",
                actor_type="tool",
                actor_id=proposal.tool_name,
                payload={
                    "approval_id": approval.id,
                    "tool_call_id": result.tool_call_id,
                    "tool_name": proposal.tool_name,
                    "status": result.status,
                    "error": result.error,
                },
            )
        self.session.flush()

        return ApprovalOutcome(
            approval_id=approval.id,
            status=approval.status,
            executed=result.status == "success",
            result=result,
            reason=result.error,
        )

    def reject(
        self, approval_id: str, *, reviewer_id: str, comment: str | None = None
    ) -> ApprovalOutcome:
        """Refuse a held call. Nothing executes, and the refusal is auditable."""
        approval = self._require_pending(approval_id)
        proposal = self._proposal_for(approval)
        approval.status = REJECTED
        approval.reviewer_id = reviewer_id
        approval.review_comment = comment
        approval.reviewed_at = utcnow()
        self.audit.write(
            task_id=approval.task_id,
            event_type="approval.rejected",
            actor_type="reviewer",
            actor_id=reviewer_id,
            payload={
                "approval_id": approval.id,
                "tool_call_id": proposal.id,
                "tool_name": proposal.tool_name,
                "comment": comment,
            },
        )
        self.session.flush()
        return ApprovalOutcome(
            approval_id=approval.id,
            status=approval.status,
            executed=False,
            reason="rejected by reviewer",
        )

    # -- helpers ------------------------------------------------------------

    def _refusal_reason(self, decision, approval: ApprovalRequest) -> str | None:
        """Why an edit may not proceed, or ``None`` if it may.

        Both rules are about not letting a human edit *reduce* the controls the
        original proposal was subject to:

        - A ``block`` is never editable away. The reviewer supplies the approval a
          ``require_approval`` rule asks for; ``default_block``, a disabled tool
          and a refused connector flag are decisions that are not theirs to make.
        - An edit that raises the risk level is refused, because the reviewer
          opened the request against the risk they were shown.

        A result of ``require_approval`` is deliberately **not** a refusal: that
        is the baseline for a tool which requires approval at all, and the
        reviewer's decision is what supplies it.
        """
        if decision.decision == "block":
            return "policy blocks the modified request: " + "; ".join(decision.reasons)
        if decision.risk_rank > RISK_ORDER.get(approval.risk_level, 0):
            return (
                f"policy raises the risk of the modified request from "
                f"{approval.risk_level} to {decision.risk_level}: " + "; ".join(decision.reasons)
            )
        return None

    def _require_pending(self, approval_id: str) -> ApprovalRequest:
        approval = self.get(approval_id)
        if approval.status != PENDING:
            raise ApprovalStateError(
                f"approval {approval_id!r} is {approval.status!r}, not {PENDING!r}"
            )
        return approval

    def _proposal_for(self, approval: ApprovalRequest) -> ToolCall:
        proposal = self.session.get(ToolCall, approval.tool_call_id)
        if proposal is None:
            raise ApprovalNotFoundError(f"approval {approval.id!r} has no matching tool call")
        return proposal

    def _request_for(
        self,
        approval: ApprovalRequest,
        proposal: ToolCall,
        arguments: dict[str, Any],
        reviewer_id: str,
    ) -> ToolRequest:
        return ToolRequest(
            task_id=approval.task_id,
            tool_name=proposal.tool_name,
            action_type=proposal.action_type,
            resource_type=proposal.resource_type,
            resource_id=proposal.resource_id,
            arguments=arguments,
            requested_by="reviewer",
            user_id=reviewer_id,
        )
