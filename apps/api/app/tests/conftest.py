import json
from pathlib import Path

import pytest
from app.api.main import create_app
from app.core.config import Settings
from app.db.models import AgentTask, Base
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

API_KEYS = [
    {"key": "admin-key-123456", "tenant": "tenant-a", "role": "admin", "subject": "alice"},
    {"key": "operator-key-1234", "tenant": "tenant-a", "role": "operator", "subject": "omar"},
    {"key": "approver-key-1234", "tenant": "tenant-a", "role": "approver", "subject": "rita"},
    {"key": "viewer-key-12345", "tenant": "tenant-a", "role": "viewer", "subject": "bob"},
    {"key": "other-key-123456", "tenant": "tenant-b", "role": "admin", "subject": "carol"},
]


@pytest.fixture
def engine():
    """A fresh in-memory database per test.

    In-memory rather than a file so no test can observe or mutate another test's
    state -- and so running the suite never touches a developer's real data.
    """
    eng = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(eng)
    yield eng
    eng.dispose()


@pytest.fixture
def session(engine):
    with Session(engine, expire_on_commit=False) as db:
        yield db


@pytest.fixture
def task(session):
    record = AgentTask(title="Test task", user_request="Handle email safely", status="pending")
    session.add(record)
    session.flush()
    return record


@pytest.fixture
def api_settings(tmp_path):
    return Settings(
        _env_file=None,
        app_env="development",
        database_url="sqlite+pysqlite:///:memory:",
        api_keys_json=json.dumps(API_KEYS),
        tool_sandbox_root=str(tmp_path / "sandbox"),
        knowledge_root=str(Path(__file__).resolve().parents[4] / "knowledge"),
        auto_create_schema=True,
        rate_limit_per_minute=1000,
        max_concurrent_tasks=8,
        log_json=True,
    )


@pytest.fixture
def api_app(api_settings):
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)
    app = create_app(api_settings, session_factory=factory)
    yield app
    engine.dispose()


@pytest.fixture
def client(api_app):
    with TestClient(api_app) as test_client:
        yield test_client


def auth(key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {key}"}
