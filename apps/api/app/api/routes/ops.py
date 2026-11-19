"""Liveness, readiness and metrics endpoints.

These are intentionally separate:

- `/healthz` answers "is this process alive?" and must not touch the database;
- `/readyz` answers "can this process serve traffic?" and does touch it;
- `/metrics` is for Prometheus and may be protected by `METRICS_TOKEN`.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request, Response, status
from fastapi.responses import JSONResponse
from sqlalchemy import text

from app.api.auth import require_metrics_token
from app.api.schemas import HealthOut, ReadyOut
from app.observability import metrics

router = APIRouter(tags=["ops"])


@router.get("/healthz", response_model=HealthOut, summary="Liveness probe")
def healthz(request: Request) -> HealthOut:
    settings = request.app.state.settings
    return HealthOut(status="ok", version=settings.version, environment=settings.app_env)


@router.get("/readyz", response_model=ReadyOut, summary="Readiness probe")
def readyz(request: Request) -> Response:
    database = True
    try:
        with request.app.state.session_factory() as session:
            session.execute(text("SELECT 1"))
    except Exception:
        database = False
    tools = len(request.app.state.runtime.registry.descriptors())
    policy_loaded = request.app.state.runtime.firewall.policy_engine.policy is not None
    ready = database and tools > 0 and policy_loaded
    payload = ReadyOut(
        status="ready" if ready else "not_ready",
        database=database,
        tools=tools,
        policy_loaded=policy_loaded,
    )
    return JSONResponse(
        content=payload.model_dump(),
        status_code=status.HTTP_200_OK if ready else status.HTTP_503_SERVICE_UNAVAILABLE,
    )


@router.get("/metrics", summary="Prometheus metrics", dependencies=[Depends(require_metrics_token)])
def prometheus(request: Request) -> Response:
    metrics.refresh_business_gauges(request.app.state.session_factory)
    resilience = request.app.state.runtime.firewall.resilience
    if resilience is not None:
        for name in list(resilience._breakers):
            metrics.CIRCUIT_OPEN.labels(tool=name).set(
                1 if resilience.breaker(name).state == "open" else 0
            )
    return Response(content=metrics.render(), media_type=metrics.CONTENT_TYPE)
