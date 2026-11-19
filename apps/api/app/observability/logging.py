"""Structured logging with request-scoped correlation identifiers."""

from __future__ import annotations

import contextvars
import json
import logging
import sys
from datetime import UTC, datetime
from typing import Any

request_id_var: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "request_id", default=None
)
tenant_id_var: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "tenant_id", default=None
)
task_id_var: contextvars.ContextVar[str | None] = contextvars.ContextVar("task_id", default=None)

_CONFIGURED = False


class JsonFormatter(logging.Formatter):
    """One JSON object per line, so a log shipper never has to parse prose.

    Request/tenant/task identifiers come from context variables rather than
    being threaded through every function, which is what makes a log line from a
    deep helper still attributable to the request that caused it.
    """

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.now(UTC).isoformat(),
            "level": record.levelname.lower(),
            "logger": record.name,
            "message": record.getMessage(),
            "request_id": request_id_var.get(),
            "tenant_id": tenant_id_var.get(),
            "task_id": task_id_var.get(),
        }
        for key in ("method", "path", "status_code", "duration_ms", "event", "error_code"):
            value = getattr(record, key, None)
            if value is not None:
                payload[key] = value
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False, default=str)


class TextFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        suffix = (
            f" request={request_id_var.get()} tenant={tenant_id_var.get()} task={task_id_var.get()}"
        )
        base = super().format(record)
        return (
            base + suffix if any(v for v in (request_id_var.get(), tenant_id_var.get())) else base
        )


def configure_logging(level: str = "info", *, json_logs: bool = True) -> None:
    global _CONFIGURED
    if _CONFIGURED:
        return
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(
        JsonFormatter()
        if json_logs
        else TextFormatter("%(asctime)s %(levelname)s %(name)s %(message)s")
    )
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    # Uvicorn installs its own handlers; route them through the same formatter so
    # access logs are JSON too instead of a second, differently shaped stream.
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        logger = logging.getLogger(name)
        logger.handlers.clear()
        logger.propagate = True
    # The request middleware already emits one structured access line. The HTTP
    # client and uvicorn's own access logger would duplicate it at INFO.
    for noisy in ("httpx", "httpx2", "httpcore", "uvicorn.access"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
    _CONFIGURED = True


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
