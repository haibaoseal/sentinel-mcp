"""One error envelope for every failure.

A caller should never have to parse a stack trace or a framework-specific body to
learn whether a failure was authentication, validation, policy or an internal
bug. The `code` is stable and safe to assert on; the `request_id` is what ties a
user-visible failure to the server log line.
"""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.errors import SentinelError
from app.observability.logging import get_logger

logger = get_logger("sentinel.errors")


def _request_id(request: Request) -> str | None:
    return getattr(request.state, "request_id", None)


def _error_response(
    *,
    status_code: int,
    code: str,
    message: str,
    request: Request,
    detail: dict | None = None,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={
            "error": {
                "code": code,
                "message": message,
                "detail": detail or {},
                "request_id": _request_id(request),
            }
        },
        headers=headers,
    )


def install_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(SentinelError)
    async def sentinel_error(request: Request, exc: SentinelError) -> JSONResponse:
        return _error_response(
            status_code=exc.http_status,
            code=exc.code,
            message=str(exc),
            request=request,
            detail=exc.detail,
        )

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        detail = exc.detail
        if isinstance(detail, dict):
            code = str(detail.get("code", "HTTP_ERROR"))
            message = str(detail.get("message", detail))
            extra = {k: v for k, v in detail.items() if k not in {"code", "message"}}
        else:
            code = "HTTP_ERROR"
            message = str(detail)
            extra = {}
        return _error_response(
            status_code=exc.status_code,
            code=code,
            message=message,
            request=request,
            detail=extra,
            headers=getattr(exc, "headers", None),
        )

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
        return _error_response(
            status_code=422,
            code="VALIDATION_ERROR",
            message="request body does not match the schema",
            request=request,
            detail={"errors": jsonable_encoder(exc.errors())},
        )

    @app.exception_handler(Exception)
    async def unhandled(request: Request, exc: Exception) -> JSONResponse:
        logger.exception(
            "unhandled error",
            extra={"error_code": "INTERNAL_ERROR", "path": request.url.path},
        )
        return _error_response(
            status_code=500,
            code="INTERNAL_ERROR",
            message="internal server error; quote the request_id when reporting it",
            request=request,
        )
