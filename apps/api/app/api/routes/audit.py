"""Audit endpoints: read the chain, verify it, and export it for a SIEM."""

from __future__ import annotations

import json
from collections.abc import Iterator

from fastapi import APIRouter, Depends, Query, Response
from fastapi.responses import StreamingResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api import service
from app.api.auth import Principal, require_role
from app.api.deps import get_session, get_settings
from app.api.schemas import AuditEventOut, AuditList, AuditVerifyOut
from app.audit.logger import read_chain, verify_chain
from app.core.config import Settings
from app.db.models import AgentTask, AuditEvent
from app.observability import metrics

router = APIRouter(prefix="/v1/audit", tags=["audit"])


@router.get("/events", response_model=AuditList, summary="Read audit events for this tenant")
def list_events(
    task_id: str | None = None,
    event_type: str | None = None,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_role("viewer")),
) -> AuditList:
    conditions = [AgentTask.tenant_id == principal.tenant_id]
    if task_id is not None:
        service.get_task(session, task_id, principal.tenant_id)
        conditions.append(AuditEvent.task_id == task_id)
    if event_type:
        conditions.append(AuditEvent.event_type == event_type)

    base = select(AuditEvent).join(AgentTask, AuditEvent.task_id == AgentTask.id).where(*conditions)
    total = (
        session.scalar(
            select(func.count())
            .select_from(AuditEvent)
            .join(AgentTask, AuditEvent.task_id == AgentTask.id)
            .where(*conditions)
        )
        or 0
    )
    rows = session.scalars(
        base.order_by(AuditEvent.created_at.desc(), AuditEvent.seq.desc())
        .limit(limit)
        .offset(offset)
    ).all()
    return AuditList(
        items=[AuditEventOut.model_validate(service.audit_event_dict(row)) for row in rows],
        total=int(total),
        limit=limit,
        offset=offset,
    )


@router.get("/verify", response_model=AuditVerifyOut, summary="Verify one task's hash chain")
def verify(
    task_id: str,
    session: Session = Depends(get_session),
    settings: Settings = Depends(get_settings),
    principal: Principal = Depends(require_role("viewer")),
) -> AuditVerifyOut:
    service.get_task(session, task_id, principal.tenant_id)
    events = read_chain(session, task_id)
    verdict = verify_chain(events, hmac_key=settings.hmac_key_bytes)
    metrics.AUDIT_VERIFY.labels(result="ok" if verdict.ok else "failed").inc()
    return AuditVerifyOut(
        task_id=task_id,
        ok=verdict.ok,
        checked=verdict.checked,
        first_bad_seq=verdict.first_bad_seq,
        reason=verdict.reason,
        event_count=len(events),
    )


@router.get(
    "/export",
    summary="Export a task's audit chain as newline-delimited JSON",
    response_class=StreamingResponse,
)
def export(
    task_id: str,
    session: Session = Depends(get_session),
    settings: Settings = Depends(get_settings),
    principal: Principal = Depends(require_role("viewer")),
) -> Response:
    service.get_task(session, task_id, principal.tenant_id)
    events = read_chain(session, task_id)
    verdict = verify_chain(events, hmac_key=settings.hmac_key_bytes)
    metrics.AUDIT_VERIFY.labels(result="ok" if verdict.ok else "failed").inc()

    headers = {
        "Content-Disposition": f'attachment; filename="audit-{task_id}.ndjson"',
        "X-Chain-Verified": "true" if verdict.ok else "false",
        "X-Chain-Checked": str(verdict.checked),
    }
    head = events[-1].event_hash if events else None
    # Materialise the exact verified snapshot before leaving the request session
    # so the manifest (`checked`, `head`, `chain_verified`) and the streamed rows
    # can never disagree if new events are appended concurrently.
    snapshot = [service.audit_event_dict(event) for event in events]
    return StreamingResponse(
        _stream(task_id, verdict.ok, verdict.checked, head, snapshot),
        media_type="application/x-ndjson",
        headers=headers,
    )


def _stream(
    task_id: str,
    verified: bool,
    checked: int,
    head: str | None,
    events: list[dict],
) -> Iterator[str]:
    manifest = {
        "type": "manifest",
        "task_id": task_id,
        "chain_verified": verified,
        "checked": checked,
        "head": head,
        "format": "sentinel-audit/1",
    }
    yield json.dumps(manifest, ensure_ascii=False) + "\n"
    for event in events:
        yield json.dumps(event, ensure_ascii=False, default=str) + "\n"
