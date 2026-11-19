"""HTTP middleware: correlation IDs, access logs, metrics and baseline headers."""

from __future__ import annotations

import re
import time
import uuid

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from app.observability import metrics
from app.observability.logging import (
    get_logger,
    request_id_var,
    task_id_var,
    tenant_id_var,
)

logger = get_logger("sentinel.http")
_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{8,128}$")


class RequestContextMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        incoming = request.headers.get("x-request-id", "")
        request_id = incoming if _REQUEST_ID_RE.match(incoming) else uuid.uuid4().hex
        request_token = request_id_var.set(request_id)
        tenant_token = tenant_id_var.set(None)
        task_token = task_id_var.set(None)
        request.state.request_id = request_id
        started = time.perf_counter()
        status_code = 500
        try:
            response = await call_next(request)
            status_code = response.status_code
            return response
        finally:
            duration = time.perf_counter() - started
            route = request.scope.get("route")
            path = getattr(route, "path", None) or "unmatched"
            metrics.HTTP_REQUESTS.labels(
                method=request.method, path=path, status=str(status_code)
            ).inc()
            metrics.HTTP_DURATION.labels(method=request.method, path=path).observe(duration)
            principal = getattr(request.state, "principal", None)
            if principal is not None:
                tenant_id_var.set(principal.tenant_id)
            logger.info(
                "request",
                extra={
                    "method": request.method,
                    "path": path,
                    "status_code": status_code,
                    "duration_ms": round(duration * 1000, 2),
                    "event": "http.request",
                },
            )
            request_id_var.reset(request_token)
            tenant_id_var.reset(tenant_token)
            task_id_var.reset(task_token)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Cache-Control", "no-store")
        request_id = getattr(request.state, "request_id", None)
        if request_id:
            response.headers["X-Request-ID"] = request_id
        return response
