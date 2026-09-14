import pytest
from app.db.models import AgentTask, Base
from sqlalchemy import create_engine
from sqlalchemy.orm import Session


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
