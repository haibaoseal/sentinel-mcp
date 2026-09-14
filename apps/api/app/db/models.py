"""Persistence models.

The ``AuditEvent.seq`` column and its uniqueness constraint carry most of the
weight here: they are what make the hash chain orderable by data rather than by
a clock, and they turn any interleaving mistake into a loud IntegrityError
instead of a silently forked chain.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    JSON,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from app.core.security import utcnow


class Base(DeclarativeBase):
    pass


def _uuid() -> str:
    return str(uuid.uuid4())


class AgentTask(Base):
    __tablename__ = "agent_tasks"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=_uuid)
    user_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    title: Mapped[str] = mapped_column(String(255), default="Untitled task")
    user_request: Mapped[str] = mapped_column(Text, default="")
    agent_type: Mapped[str] = mapped_column(String(64), default="llm")
    # pending | running | waiting_approval | completed | failed | blocked | unsupported
    status: Mapped[str] = mapped_column(String(32), default="pending")
    # Which provider produced the plan. Recorded so a report can never confuse a
    # deterministic replay with a live model run.
    provider: Mapped[str | None] = mapped_column(String(64), nullable=True)
    model: Mapped[str | None] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    plans: Mapped[list[AgentPlan]] = relationship(back_populates="task")
    tool_calls: Mapped[list[ToolCall]] = relationship(back_populates="task")


class AgentPlan(Base):
    __tablename__ = "agent_plans"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=_uuid)
    task_id: Mapped[str] = mapped_column(ForeignKey("agent_tasks.id"), index=True)
    summary: Mapped[str] = mapped_column(Text, default="")
    steps_json: Mapped[list] = mapped_column(JSON, default=list)
    # The provider's own reasoning summary, when it supplies one. Never the raw
    # hidden chain of thought.
    rationale: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    task: Mapped[AgentTask] = relationship(back_populates="plans")


class ToolCall(Base):
    __tablename__ = "tool_calls"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=_uuid)
    task_id: Mapped[str] = mapped_column(ForeignKey("agent_tasks.id"), index=True)
    tool_name: Mapped[str] = mapped_column(String(128), index=True)
    action_type: Mapped[str] = mapped_column(String(32), default="unknown")
    resource_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    resource_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    arguments_json: Mapped[dict] = mapped_column(JSON, default=dict)
    # proposed | allowed | blocked | waiting_approval | executed | failed
    status: Mapped[str] = mapped_column(String(32), default="proposed")
    risk_level: Mapped[str] = mapped_column(String(16), default="medium")
    risk_reasons_json: Mapped[list] = mapped_column(JSON, default=list)
    # Provenance of the binding that served (or would have served) this call.
    source: Mapped[str | None] = mapped_column(String(64), nullable=True)
    policy_decision_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    error_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    executed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    task: Mapped[AgentTask] = relationship(back_populates="tool_calls")


class PolicyDecisionRecord(Base):
    __tablename__ = "policy_decisions"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=_uuid)
    tool_call_id: Mapped[str] = mapped_column(ForeignKey("tool_calls.id"), index=True)
    decision: Mapped[str] = mapped_column(String(32))
    reason: Mapped[str] = mapped_column(Text, default="")
    matched_rules_json: Mapped[list] = mapped_column(JSON, default=list)
    # Which evaluation phase produced this record: proposal | modified_approval
    phase: Mapped[str] = mapped_column(String(32), default="proposal")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ApprovalRequest(Base):
    __tablename__ = "approval_requests"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=_uuid)
    tool_call_id: Mapped[str] = mapped_column(ForeignKey("tool_calls.id"), index=True)
    task_id: Mapped[str | None] = mapped_column(
        ForeignKey("agent_tasks.id"), nullable=True, index=True
    )
    requested_by_agent: Mapped[str] = mapped_column(String(128), default="agent")
    # pending | approved | modified | rejected | expired
    status: Mapped[str] = mapped_column(String(32), default="pending", index=True)
    original_arguments_json: Mapped[dict] = mapped_column(JSON, default=dict)
    modified_arguments_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    risk_level: Mapped[str] = mapped_column(String(16), default="high")
    risk_reasons_json: Mapped[list] = mapped_column(JSON, default=list)
    reviewer_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    review_comment: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AuditEvent(Base):
    """One link in a per-task hash chain.

    ``seq`` is gap-free starting at 1 and unique per task. Both the writer and
    the verifier order by it, so chain validity never depends on timestamp
    resolution.
    """

    __tablename__ = "audit_events"
    __table_args__ = (
        UniqueConstraint("task_id", "seq", name="uq_audit_task_seq"),
        Index("ix_audit_task_seq", "task_id", "seq"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=_uuid)
    task_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    seq: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    event_type: Mapped[str] = mapped_column(String(64), index=True)
    actor_type: Mapped[str] = mapped_column(String(32), default="system")
    actor_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    payload_json: Mapped[dict] = mapped_column(JSON, default=dict)
    prev_hash: Mapped[str] = mapped_column(String(64), default="GENESIS")
    event_hash: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class EvalRun(Base):
    __tablename__ = "eval_runs"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(128), default="suite")
    suite_version: Mapped[str] = mapped_column(String(32), default="1")
    scenario_count: Mapped[int] = mapped_column(Integer, default=0)
    passed_count: Mapped[int] = mapped_column(Integer, default=0)
    metrics_json: Mapped[dict] = mapped_column(JSON, default=dict)
    report_json: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
