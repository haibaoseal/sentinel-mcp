"""Database engine and session wiring.

One place decides how a connection is opened, because the archived build opened
SQLite differently in three modules and the differences only showed up under
concurrency. Production uses Postgres; SQLite remains the zero-dependency
development and test backend.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import Engine, create_engine, event, inspect
from sqlalchemy.orm import Session, sessionmaker

from app.db.models import Base


def build_engine(database_url: str, *, echo: bool = False) -> Engine:
    kwargs: dict = {"echo": echo, "pool_pre_ping": True, "future": True}
    if database_url.startswith("sqlite"):
        # A FastAPI worker handles requests on several threads. The default
        # SQLite driver refuses a connection created on another thread, and the
        # default five-second busy timeout turns a short write burst into a
        # "database is locked" error.
        kwargs["connect_args"] = {"check_same_thread": False, "timeout": 30}

    engine = create_engine(database_url, **kwargs)
    if database_url.startswith("sqlite"):

        @event.listens_for(engine, "connect")
        def _sqlite_pragmas(dbapi_connection, _record):  # pragma: no cover - driver hook
            cursor = dbapi_connection.cursor()
            # WAL lets readers continue while one writer commits; busy_timeout
            # makes a competing writer wait instead of failing immediately.
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA busy_timeout=10000")
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

    return engine


def build_session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)


def create_schema(engine: Engine) -> None:
    """Development/test convenience. Production schema changes go through Alembic."""
    Base.metadata.create_all(engine)


def missing_service_columns(engine: Engine) -> list[str]:
    """Columns the 0.2 service needs but a 0.1 development database lacks.

    `create_all` does not alter an existing table, so a developer who keeps a
    pre-0.2 SQLite file would otherwise get a confusing `no such column` on the
    first request. Startup turns that into an instruction instead.
    """
    inspector = inspect(engine)
    expectations = {
        "agent_tasks": {"tenant_id", "answer", "termination", "trace_json"},
        "approval_requests": {"tenant_id"},
    }
    missing: list[str] = []
    tables = set(inspector.get_table_names())
    for table, columns in expectations.items():
        if table not in tables:
            continue
        present = {column["name"] for column in inspector.get_columns(table)}
        missing.extend(f"{table}.{column}" for column in sorted(columns - present))
    return missing


@contextmanager
def session_scope(factory: sessionmaker[Session]) -> Iterator[Session]:
    session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
