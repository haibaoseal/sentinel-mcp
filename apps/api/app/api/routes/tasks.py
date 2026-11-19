"""Task endpoints: create a governed run, inspect its outcome and trace."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api import service
from app.api.auth import Principal, require_role
from app.api.deps import get_limiter, get_runtime, get_session, get_task_gate
from app.api.limits import TaskGate, TenantRateLimiter
from app.api.schemas import TaskCreate, TaskDetail, TaskList, TaskSummary
from app.db.models import AgentTask
from app.observability import metrics
from app.runtime import Runtime

router = APIRouter(prefix="/v1/tasks", tags=["tasks"])


@router.post(
    "",
    response_model=TaskDetail,
    status_code=status.HTTP_201_CREATED,
    summary="Create a task and run it through the governed agent loop",
)
def create_task(
    payload: TaskCreate,
    response: Response,
    session: Session = Depends(get_session),
    runtime: Runtime = Depends(get_runtime),
    principal: Principal = Depends(require_role("operator")),
    limiter: TenantRateLimiter = Depends(get_limiter),
    gate: TaskGate = Depends(get_task_gate),
) -> TaskDetail:
    limit = limiter.check(principal.tenant_id)
    response.headers["X-RateLimit-Limit"] = str(limiter.per_minute)
    response.headers["X-RateLimit-Remaining"] = str(limit.remaining)
    if not limit.allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={
                "code": "RATE_LIMITED",
                "message": (
                    f"tenant {principal.tenant_id!r} exceeded {limiter.per_minute} requests/min"
                ),
            },
            headers={"Retry-After": str(limit.retry_after_seconds)},
        )

    if not gate.acquire():
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={
                "code": "TOO_MANY_CONCURRENT_TASKS",
                "message": f"all {gate.max_concurrent} execution slots are busy; retry shortly",
            },
            headers={"Retry-After": "1"},
        )

    metrics.TASKS_INFLIGHT.inc()
    try:
        task = service.run_task(
            session=session,
            runtime=runtime,
            principal=principal,
            user_request=payload.request,
            title=payload.title,
        )
        payload_out = service.task_detail(session, task)
        session.commit()
        return TaskDetail.model_validate(payload_out)
    except Exception:
        # `service.run_task` already marked the task as failed and flushed any
        # tool-call / audit-chain records written before the crash. Commit them
        # so audit evidence is not silently erased; only roll back if the
        # transaction itself is broken.
        try:
            session.commit()
        except Exception:
            session.rollback()
        raise
    finally:
        metrics.TASKS_INFLIGHT.dec()
        gate.release()


@router.get("", response_model=TaskList, summary="List this tenant's tasks")
def list_tasks(
    status_filter: str | None = Query(default=None, alias="status"),
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_role("viewer")),
) -> TaskList:
    conditions = [AgentTask.tenant_id == principal.tenant_id]
    if status_filter:
        conditions.append(AgentTask.status == status_filter)
    total = session.scalar(select(func.count()).select_from(AgentTask).where(*conditions)) or 0
    rows = session.scalars(
        select(AgentTask)
        .where(*conditions)
        .order_by(AgentTask.created_at.desc())
        .limit(limit)
        .offset(offset)
    ).all()
    return TaskList(
        items=[
            TaskSummary.model_validate(item) for item in service.task_summaries(session, list(rows))
        ],
        total=int(total),
        limit=limit,
        offset=offset,
    )


@router.get("/{task_id}", response_model=TaskDetail, summary="Get a task and its tool calls")
def get_task(
    task_id: str,
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_role("viewer")),
) -> TaskDetail:
    task = service.get_task(session, task_id, principal.tenant_id)
    return TaskDetail.model_validate(service.task_detail(session, task))


@router.get("/{task_id}/trace", summary="Get the structured trace for a task")
def get_trace(
    task_id: str,
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_role("viewer")),
) -> dict:
    task = service.get_task(session, task_id, principal.tenant_id)
    if task.trace_json is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "TRACE_NOT_FOUND", "message": "this task has no stored trace"},
        )
    return task.trace_json
