"""The HTTP service.

`create_app` is a factory, not a module-level singleton, so tests can assemble an
application with an in-memory database and a replay provider without touching the
developer's `.env` or database. `app.api.asgi` is the deployed entry point.

Service guarantees this layer adds on top of the governance core:

- every request is authenticated and every query is scoped to the key's tenant;
- roles are checked before a decision endpoint is reached;
- both a per-tenant request budget and a global concurrency gate return 429
  rather than letting the process accumulate unbounded work;
- every response carries a request id, and every failure uses one envelope.
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import auth
from app.api.errors import install_exception_handlers
from app.api.limits import TaskGate, TenantRateLimiter
from app.api.middleware import RequestContextMiddleware, SecurityHeadersMiddleware
from app.api.routes import approvals as approvals_routes
from app.api.routes import audit as audit_routes
from app.api.routes import catalog as catalog_routes
from app.api.routes import ops as ops_routes
from app.api.routes import tasks as tasks_routes
from app.core.config import Settings, get_settings
from app.core.errors import ConfigurationError
from app.db.session import (
    build_engine,
    build_session_factory,
    create_schema,
    missing_service_columns,
)
from app.observability.logging import configure_logging, get_logger
from app.runtime import Runtime, build_runtime

logger = get_logger("sentinel.app")


def create_app(
    settings: Settings | None = None,
    *,
    session_factory=None,
    runtime: Runtime | None = None,
) -> FastAPI:
    resolved = settings or get_settings()
    configure_logging(resolved.log_level, json_logs=resolved.log_json)
    keys = auth.load_api_keys(resolved)

    engine = None
    if session_factory is None:
        engine = build_engine(resolved.database_url)
        if resolved.auto_create_schema:
            # Development convenience only; production and Docker run Alembic
            # before the process starts.
            create_schema(engine)
            missing = missing_service_columns(engine)
            if missing:
                raise ConfigurationError(
                    "the database schema is older than this service: missing "
                    + ", ".join(missing)
                    + ". Recreate the development database or apply the 0.2 "
                    "migration before starting; `create_all` does not alter tables."
                )
        session_factory = build_session_factory(engine)

    if runtime is None:
        runtime = build_runtime(resolved, enable_mcp=resolved.enable_mcp_servers)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        logger.info(
            "service starting",
            extra={
                "event": "service.start",
                "error_code": None,
                "method": None,
                "path": None,
                "status_code": None,
                "duration_ms": None,
            },
        )
        yield
        if app.state.engine is not None:
            app.state.engine.dispose()
        logger.info("service stopped", extra={"event": "service.stop"})

    app = FastAPI(
        title="sentinel-mcp",
        version=resolved.version,
        description=(
            "A governed Model Context Protocol gateway with policy, human approval, "
            "hash-chained audit and deterministic evaluation. Every tool call passes "
            "through the firewall; every write is tenant-scoped and audited."
        ),
        lifespan=lifespan,
    )
    app.state.settings = resolved
    app.state.api_keys = keys
    app.state.session_factory = session_factory
    app.state.engine = engine
    app.state.runtime = runtime
    app.state.limiter = TenantRateLimiter(resolved.rate_limit_per_minute)
    app.state.task_gate = TaskGate(resolved.max_concurrent_tasks)

    # Last added is outermost: CORS handles preflight before auth; the request
    # context is outside security headers so even a header-only rejection has an
    # X-Request-ID.
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(RequestContextMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=resolved.cors_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
        expose_headers=["X-Request-ID", "X-RateLimit-Limit", "X-RateLimit-Remaining"],
    )

    install_exception_handlers(app)
    app.include_router(ops_routes.router)
    app.include_router(tasks_routes.router)
    app.include_router(approvals_routes.router)
    app.include_router(audit_routes.router)
    app.include_router(catalog_routes.router)

    @app.get("/", tags=["ops"], summary="Service metadata")
    def root() -> dict:
        return {
            "service": "sentinel-mcp",
            "version": resolved.version,
            "environment": resolved.app_env,
            "docs": "/docs",
            "health": "/healthz",
            "metrics": "/metrics",
            "api": "/v1",
        }

    return app


def run() -> None:
    """Console entry point: `sentinel-api`."""
    uvicorn.run(
        "app.api.asgi:app",
        host=os.getenv("API_HOST", "0.0.0.0"),
        port=int(os.getenv("API_PORT", "8000")),
        log_config=None,
    )


if __name__ == "__main__":  # pragma: no cover
    run()
