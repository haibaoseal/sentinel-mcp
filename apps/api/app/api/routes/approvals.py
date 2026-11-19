"""Approval endpoints: the human side of a held call."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api import service
from app.api.auth import Principal, require_role
from app.api.deps import get_runtime, get_session, get_settings
from app.api.schemas import ApprovalDecision, ApprovalList, ApprovalOut, ApprovalResult
from app.approvals.service import ApprovalService
from app.core.config import Settings
from app.db.models import ApprovalRequest
from app.observability import metrics
from app.runtime import Runtime

router = APIRouter(prefix="/v1/approvals", tags=["approvals"])


@router.get("", response_model=ApprovalList, summary="List approvals for this tenant")
def list_approvals(
    status_filter: str | None = Query(default="pending", alias="status"),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_role("viewer")),
) -> ApprovalList:
    conditions = [ApprovalRequest.tenant_id == principal.tenant_id]
    if status_filter and status_filter != "all":
        conditions.append(ApprovalRequest.status == status_filter)
    total = (
        session.scalar(select(func.count()).select_from(ApprovalRequest).where(*conditions)) or 0
    )
    rows = session.scalars(
        select(ApprovalRequest)
        .where(*conditions)
        .order_by(ApprovalRequest.created_at.asc())
        .limit(limit)
        .offset(offset)
    ).all()
    return ApprovalList(
        items=[ApprovalOut.model_validate(service.approval_summary(row)) for row in rows],
        total=int(total),
    )


@router.get("/{approval_id}", response_model=ApprovalOut, summary="Get one approval")
def get_approval(
    approval_id: str,
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_role("viewer")),
) -> ApprovalOut:
    approval = service.get_approval(session, approval_id, principal.tenant_id)
    return ApprovalOut.model_validate(service.approval_summary(approval))


@router.post(
    "/{approval_id}/approve",
    response_model=ApprovalResult,
    summary="Approve a held call, optionally editing its arguments",
)
def approve(
    approval_id: str,
    decision: ApprovalDecision,
    session: Session = Depends(get_session),
    runtime: Runtime = Depends(get_runtime),
    settings: Settings = Depends(get_settings),
    principal: Principal = Depends(require_role("approver")),
) -> ApprovalResult:
    service.get_approval(session, approval_id, principal.tenant_id)
    outcome = ApprovalService(
        firewall=runtime.firewall,
        session=session,
        enforce_separation_of_duties=settings.enforce_separation_of_duties,
    ).approve(
        approval_id,
        reviewer_id=principal.subject,
        modified_arguments=decision.modified_arguments,
        comment=decision.comment,
    )
    task_id = service.get_approval(session, approval_id, principal.tenant_id).task_id
    session.commit()
    metric_label = outcome.status
    if outcome.status == "executed":
        metric_label = "modified" if decision.modified_arguments is not None else "approved"
    metrics.APPROVAL_DECISIONS.labels(decision=metric_label).inc()
    return ApprovalResult(
        approval_id=outcome.approval_id,
        status=outcome.status,
        executed=outcome.executed,
        task_id=task_id,
        reason=outcome.reason,
        policy_decision=outcome.policy_decision,
        data=outcome.result.data if outcome.result is not None else None,
    )


@router.post(
    "/{approval_id}/reject",
    response_model=ApprovalResult,
    summary="Reject a held call; nothing executes",
)
def reject(
    approval_id: str,
    decision: ApprovalDecision,
    session: Session = Depends(get_session),
    runtime: Runtime = Depends(get_runtime),
    principal: Principal = Depends(require_role("approver")),
) -> ApprovalResult:
    approval = service.get_approval(session, approval_id, principal.tenant_id)
    task_id = approval.task_id
    outcome = ApprovalService(firewall=runtime.firewall, session=session).reject(
        approval_id,
        reviewer_id=principal.subject,
        comment=decision.comment,
    )
    session.commit()
    metrics.APPROVAL_DECISIONS.labels(decision="rejected").inc()
    return ApprovalResult(
        approval_id=outcome.approval_id,
        status=outcome.status,
        executed=False,
        task_id=task_id,
        reason=outcome.reason,
    )
