"""FastAPI dependencies.

Everything stateful lives on `app.state` so a test can assemble an application
with an in-memory database and a replay provider without patching module globals.
"""

from __future__ import annotations

from collections.abc import Iterator

from fastapi import Request
from sqlalchemy.orm import Session

from app.api.limits import TaskGate, TenantRateLimiter
from app.core.config import Settings
from app.runtime import Runtime


def get_session(request: Request) -> Iterator[Session]:
    factory = request.app.state.session_factory
    session: Session = factory()
    try:
        yield session
    finally:
        session.close()


def get_settings(request: Request) -> Settings:
    return request.app.state.settings


def get_runtime(request: Request) -> Runtime:
    return request.app.state.runtime


def get_limiter(request: Request) -> TenantRateLimiter:
    return request.app.state.limiter


def get_task_gate(request: Request) -> TaskGate:
    return request.app.state.task_gate
