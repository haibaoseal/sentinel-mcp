"""Use cases behind the HTTP routes.

Keeping the orchestration here rather than in the route functions means the same
"create task, run the governed loop, persist the outcome" sequence can be tested
without an HTTP client, and the route layer stays a translation between JSON and
these functions.
"""

from __future__ import annotations

import time
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.agent.loop import AgentRunResult
from app.api.auth import Principal
from app.core.errors import TaskNotFoundError
from app.core.security import utcnow
from app.db.models import AgentTask, ApprovalRequest, AuditEvent, ToolCall
from app.governance.firewall import Firewall
from app.observability import metrics
from app.observability.logging import get_logger, task_id_var
from app.runtime import Runtime

logger = get_logger("sentinel.service")


def run_task(
    *,
    session: Session,
    runtime: Runtime,
    principal: Principal,
    user_request: str,
    title: str | None = None,
) -> AgentTask:
    task = AgentTask(
        tenant_id=principal.tenant_id,
        user_id=principal.subject,
        title=title or user_request[:120],
        user_request=user_request,
        agent_type="api",
        status="running",
        provider=runtime.provider.identity.provider,
        model=runtime.provider.identity.model,
    )
    session.add(task)
    session.flush()

    token = task_id_var.set(task.id)
    started = time.perf_counter()
    try:
        traced = runtime.loop.run_traced(
            task_id=task.id, user_request=user_request, session=session
        )
        task.status = traced.result.status
        task.answer = traced.result.answer
        task.termination = traced.result.termination
        task.error = traced.result.error
        task.trace_json = traced.trace.to_dict()
        task.resume_state_json = traced.result.resume_state
        task.completed_at = utcnow()
        session.flush()
    except Exception as exc:
        task.status = "failed"
        task.error = f"{type(exc).__name__}: {exc}"
        task.completed_at = utcnow()
        session.flush()
        duration = time.perf_counter() - started
        metrics.TASKS.labels(status="failed", provider=task.provider or "unknown").inc()
        metrics.TASK_DURATION.labels(status="failed").observe(duration)
        logger.exception("task failed", extra={"task_id": task.id, "error_code": "TASK_FAILED"})
        raise
    else:
        duration = time.perf_counter() - started
        metrics.TASKS.labels(status=task.status, provider=task.provider or "unknown").inc()
        metrics.TASK_DURATION.labels(status=task.status).observe(duration)
        logger.info(
            "task finished",
            extra={
                "task_id": task.id,
                "duration_ms": round(duration * 1000, 2),
                "event": "task.finished",
            },
        )
        return task
    finally:
        task_id_var.reset(token)


def resume_task_after_approval(
    *,
    session: Session,
    runtime: Runtime,
    task: AgentTask,
    approval_id: str,
    approved_result,
) -> AgentTask:
    """Continue a paused agent loop once its held tool call has been approved and executed."""
    if not task.resume_state_json:
        return task
    token = task_id_var.set(task.id)
    started = time.perf_counter()
    try:
        traced = runtime.loop.resume_traced(
            task_id=task.id,
            user_request=task.user_request,
            resume_state=task.resume_state_json,
            approved_result=approved_result,
            session=session,
            approval_id=approval_id,
        )
        task.status = traced.result.status
        task.answer = traced.result.answer
        task.termination = traced.result.termination
        task.error = traced.result.error
        task.trace_json = traced.trace.to_dict()
        task.resume_state_json = traced.result.resume_state
        task.completed_at = utcnow()
        session.flush()
    finally:
        duration = time.perf_counter() - started
        metrics.TASK_DURATION.labels(status=task.status).observe(duration)
        task_id_var.reset(token)
    return task


def get_task(session: Session, task_id: str, tenant_id: str) -> AgentTask:
    task = session.get(AgentTask, task_id)
    if task is None or task.tenant_id != tenant_id:
        # A cross-tenant lookup and a missing row deliberately look identical:
        # answering 403 here would confirm that the id exists.
        raise TaskNotFoundError(f"no task {task_id!r}")
    return task


def get_approval(session: Session, approval_id: str, tenant_id: str) -> ApprovalRequest:
    approval = session.get(ApprovalRequest, approval_id)
    if approval is None or approval.tenant_id != tenant_id:
        from app.core.errors import ApprovalNotFoundError

        raise ApprovalNotFoundError(f"no approval request {approval_id!r}")
    return approval


def _build_task_summary(
    task: AgentTask,
    *,
    tool_call_count: int,
    pending_approval_count: int,
    audit_event_count: int,
) -> dict[str, Any]:
    return {
        "id": task.id,
        "tenant_id": task.tenant_id,
        "title": task.title,
        "request": task.user_request,
        "status": task.status,
        "answer": task.answer,
        "termination": task.termination,
        "error": task.error,
        "provider": task.provider,
        "model": task.model,
        "created_at": task.created_at,
        "completed_at": task.completed_at,
        "tool_call_count": int(tool_call_count),
        "pending_approval_count": int(pending_approval_count),
        "audit_event_count": int(audit_event_count),
    }


def task_summary(session: Session, task: AgentTask) -> dict[str, Any]:
    tool_calls = session.scalar(
        select(func.count()).select_from(ToolCall).where(ToolCall.task_id == task.id)
    )
    pending = session.scalar(
        select(func.count())
        .select_from(ApprovalRequest)
        .where(ApprovalRequest.task_id == task.id, ApprovalRequest.status == "pending")
    )
    events = session.scalar(
        select(func.count()).select_from(AuditEvent).where(AuditEvent.task_id == task.id)
    )
    return _build_task_summary(
        task,
        tool_call_count=int(tool_calls or 0),
        pending_approval_count=int(pending or 0),
        audit_event_count=int(events or 0),
    )


def task_summaries(session: Session, tasks: list[AgentTask]) -> list[dict[str, Any]]:
    """Batch-load summary counts for a page of tasks in 3 grouped queries."""
    if not tasks:
        return []
    ids = [task.id for task in tasks]
    tool_counts = dict(
        session.execute(
            select(ToolCall.task_id, func.count())
            .where(ToolCall.task_id.in_(ids))
            .group_by(ToolCall.task_id)
        ).all()
    )
    pending_counts = dict(
        session.execute(
            select(ApprovalRequest.task_id, func.count())
            .where(ApprovalRequest.task_id.in_(ids), ApprovalRequest.status == "pending")
            .group_by(ApprovalRequest.task_id)
        ).all()
    )
    event_counts = dict(
        session.execute(
            select(AuditEvent.task_id, func.count())
            .where(AuditEvent.task_id.in_(ids))
            .group_by(AuditEvent.task_id)
        ).all()
    )
    return [
        _build_task_summary(
            task,
            tool_call_count=int(tool_counts.get(task.id, 0)),
            pending_approval_count=int(pending_counts.get(task.id, 0)),
            audit_event_count=int(event_counts.get(task.id, 0)),
        )
        for task in tasks
    ]


def task_detail(session: Session, task: AgentTask) -> dict[str, Any]:
    payload = task_summary(session, task)
    calls = session.scalars(
        select(ToolCall).where(ToolCall.task_id == task.id).order_by(ToolCall.created_at.asc())
    ).all()
    payload["tool_calls"] = [
        {
            "id": call.id,
            "tool_name": call.tool_name,
            "action_type": call.action_type,
            "status": call.status,
            "risk_level": call.risk_level,
            "risk_reasons": call.risk_reasons_json,
            "source": call.source,
            "error_code": call.error_code,
            "created_at": call.created_at,
            "executed_at": call.executed_at,
        }
        for call in calls
    ]
    payload["trace"] = task.trace_json
    return payload


def approval_summary(approval: ApprovalRequest) -> dict[str, Any]:
    return {
        "id": approval.id,
        "tenant_id": approval.tenant_id,
        "task_id": approval.task_id,
        "tool_call_id": approval.tool_call_id,
        "status": approval.status,
        "risk_level": approval.risk_level,
        "risk_reasons": approval.risk_reasons_json,
        "original_arguments": approval.original_arguments_json,
        "modified_arguments": approval.modified_arguments_json,
        "reviewer_id": approval.reviewer_id,
        "review_comment": approval.review_comment,
        "created_at": approval.created_at,
        "reviewed_at": approval.reviewed_at,
    }


def audit_event_dict(event: AuditEvent) -> dict[str, Any]:
    return {
        "id": event.id,
        "task_id": event.task_id,
        "seq": event.seq,
        "event_type": event.event_type,
        "actor_type": event.actor_type,
        "actor_id": event.actor_id,
        "payload": event.payload_json,
        "prev_hash": event.prev_hash,
        "event_hash": event.event_hash,
        "created_at": event.created_at,
    }


def result_to_dict(result: AgentRunResult) -> dict[str, Any]:
    return {
        "status": result.status,
        "answer": result.answer,
        "termination": result.termination,
        "error": result.error,
        "usage": result.usage,
    }


def firewall_for(runtime: Runtime) -> Firewall:
    return runtime.firewall
