"""HTTP service tests: authentication, tenancy, approvals, audit and overload.

These exercise the properties an operator or a security reviewer would ask about,
not just the happy path: a viewer cannot approve, one tenant cannot see another's
audit, a full execution gate returns 429 instead of queueing forever, and an
export carries the chain verdict in a header.
"""

from __future__ import annotations

import json

from app.api.limits import TaskGate
from app.db.models import AgentTask

ADMIN = {"Authorization": "Bearer admin-key-123456"}
OPERATOR = {"Authorization": "Bearer operator-key-1234"}
APPROVER = {"Authorization": "Bearer approver-key-1234"}
VIEWER = {"Authorization": "Bearer viewer-key-12345"}
OTHER = {"Authorization": "Bearer other-key-123456"}


def _create_refund(client) -> dict:
    response = client.post(
        "/v1/tasks",
        json={"request": "订单 ORD-1001 申请退款", "title": "refund"},
        headers=ADMIN,
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_health_readiness_and_security_headers(client):
    health = client.get("/healthz")
    assert health.status_code == 200
    assert health.json()["status"] == "ok"
    assert health.headers["X-Request-ID"]
    assert health.headers["X-Content-Type-Options"] == "nosniff"
    ready = client.get("/readyz")
    assert ready.status_code == 200
    assert ready.json()["database"] is True
    assert ready.json()["tools"] >= 10
    assert ready.json()["policy_loaded"] is True


def test_authentication_and_role_enforcement(client):
    unauth = client.get("/v1/tasks")
    assert unauth.status_code == 401
    assert unauth.json()["error"]["code"] == "UNAUTHENTICATED"
    assert unauth.json()["error"]["request_id"]

    bad = client.get("/v1/tasks", headers={"Authorization": "Bearer not-a-real-key"})
    assert bad.status_code == 401

    # A viewer may read but may not create, and may not approve.
    assert client.get("/v1/tasks", headers=VIEWER).status_code == 200
    forbidden = client.post("/v1/tasks", json={"request": "hello"}, headers=VIEWER)
    assert forbidden.status_code == 403
    assert forbidden.json()["error"]["code"] == "FORBIDDEN"

    who = client.get("/v1/whoami", headers=OPERATOR)
    assert who.json()["role"] == "operator"
    assert who.json()["tenant_id"] == "tenant-a"


def test_task_approval_round_trip_updates_task_and_verifies_chain(client):
    task = _create_refund(client)
    assert task["status"] == "waiting_approval"
    assert task["pending_approval_count"] == 1
    assert task["tool_call_count"] >= 2
    task_id = task["id"]

    approvals = client.get("/v1/approvals", headers=APPROVER).json()
    assert approvals["total"] == 1
    approval = approvals["items"][0]
    assert approval["status"] == "pending"
    assert approval["risk_level"] == "critical"

    # A viewer cannot decide.
    assert (
        client.post(f"/v1/approvals/{approval['id']}/approve", json={}, headers=VIEWER).status_code
        == 403
    )

    decision = client.post(
        f"/v1/approvals/{approval['id']}/approve",
        json={"comment": "checked with the customer"},
        headers=APPROVER,
    )
    assert decision.status_code == 200, decision.text
    body = decision.json()
    assert body["executed"] is True
    assert body["status"] == "executed"
    assert body["task_id"] == task_id

    updated = client.get(f"/v1/tasks/{task_id}", headers=ADMIN).json()
    assert updated["status"] == "completed"
    assert "审批已由 rita 执行" in updated["answer"]

    verified = client.get(f"/v1/audit/verify?task_id={task_id}", headers=ADMIN).json()
    assert verified["ok"] is True
    assert verified["event_count"] >= 8
    assert verified["first_bad_seq"] is None


def test_approval_with_edited_arguments_is_reevaluated(client):
    task = _create_refund(client)
    approval = client.get("/v1/approvals", headers=APPROVER).json()["items"][0]
    response = client.post(
        f"/v1/approvals/{approval['id']}/approve",
        json={"modified_arguments": {"order_id": "ORD-2002", "reason": "customer request"}},
        headers=APPROVER,
    )
    assert response.status_code == 200, response.text
    assert response.json()["executed"] is True
    # The execution used the edited order id, and the change is on the chain.
    refreshed = client.get(f"/v1/approvals/{approval['id']}", headers=ADMIN).json()
    assert refreshed["modified_arguments"]["order_id"] == "ORD-2002"
    assert refreshed["status"] == "executed"
    verify = client.get(f"/v1/audit/verify?task_id={task['id']}", headers=ADMIN).json()
    assert verify["ok"] is True


def test_reject_does_not_execute_and_marks_task(client):
    task = _create_refund(client)
    approval = client.get("/v1/approvals", headers=APPROVER).json()["items"][0]
    response = client.post(
        f"/v1/approvals/{approval['id']}/reject",
        json={"comment": "wrong customer"},
        headers=APPROVER,
    )
    assert response.status_code == 200
    assert response.json()["executed"] is False
    assert response.json()["status"] == "rejected"
    updated = client.get(f"/v1/tasks/{task['id']}", headers=ADMIN).json()
    assert updated["status"] == "rejected"
    assert "拒绝" in updated["answer"]
    # Nothing was executed after the hold: the draft tool never ran.
    executed = [call for call in updated["tool_calls"] if call["status"] == "executed"]
    assert all(call["tool_name"] != "draft_refund" for call in executed)


def test_tenant_isolation_across_tasks_approvals_and_audit(client):
    task = _create_refund(client)
    approval = client.get("/v1/approvals", headers=APPROVER).json()["items"][0]

    assert client.get("/v1/tasks", headers=OTHER).json()["total"] == 0
    assert client.get(f"/v1/tasks/{task['id']}", headers=OTHER).status_code == 404
    assert client.get("/v1/approvals", headers=OTHER).json()["total"] == 0
    assert client.get(f"/v1/approvals/{approval['id']}", headers=OTHER).status_code == 404
    assert client.get(f"/v1/audit/events?task_id={task['id']}", headers=OTHER).status_code == 404
    assert client.get(f"/v1/audit/verify?task_id={task['id']}", headers=OTHER).status_code == 404
    # A cross-tenant approve must not be possible even for an admin of another tenant.
    other_approve = client.post(f"/v1/approvals/{approval['id']}/approve", json={}, headers=OTHER)
    assert other_approve.status_code == 404


def test_audit_export_is_ndjson_with_verdict_header(client):
    task = _create_refund(client)
    export = client.get(f"/v1/audit/export?task_id={task['id']}", headers=ADMIN)
    assert export.status_code == 200
    assert export.headers["X-Chain-Verified"] == "true"
    lines = [json.loads(line) for line in export.text.splitlines() if line.strip()]
    assert lines[0]["type"] == "manifest"
    assert lines[0]["chain_verified"] is True
    assert len(lines) == lines[0]["checked"] + 1
    assert [row["seq"] for row in lines[1:]] == list(range(1, len(lines)))


def test_metrics_expose_service_and_governance_series(client):
    _create_refund(client)
    metrics = client.get("/metrics")
    assert metrics.status_code == 200
    text = metrics.text
    for series in (
        "sentinel_http_requests_total",
        "sentinel_tasks_total",
        "sentinel_policy_decisions_total",
        "sentinel_approvals_pending",
        "sentinel_audit_events",
        "sentinel_db_up",
    ):
        assert series in text
    assert "sentinel_db_up 1.0" in text


def test_rate_limit_returns_429_with_retry_after(client, api_app):
    from app.api.limits import TenantRateLimiter

    api_app.state.limiter = TenantRateLimiter(1)
    first = client.post("/v1/tasks", json={"request": "帮我删除文件 notes.md"}, headers=ADMIN)
    assert first.status_code == 201
    second = client.post("/v1/tasks", json={"request": "帮我删除文件 notes.md"}, headers=ADMIN)
    assert second.status_code == 429
    assert second.json()["error"]["code"] == "RATE_LIMITED"
    assert "Retry-After" in second.headers


def test_execution_gate_returns_429_when_full(client, api_app):
    gate = TaskGate(1)
    assert gate.acquire() is True
    api_app.state.task_gate = gate
    try:
        response = client.post("/v1/tasks", json={"request": "hello"}, headers=ADMIN)
        assert response.status_code == 429
        assert response.json()["error"]["code"] == "TOO_MANY_CONCURRENT_TASKS"
    finally:
        gate.release()


def test_validation_errors_use_the_error_envelope(client):
    response = client.post(
        "/v1/tasks",
        json={"request": "hello", "unexpected": True},
        headers=ADMIN,
    )
    assert response.status_code == 422
    body = response.json()
    assert body["error"]["code"] == "VALIDATION_ERROR"
    assert body["error"]["request_id"]


def test_tools_policy_and_trace_endpoints(client):
    tools = client.get("/v1/tools", headers=VIEWER)
    assert tools.status_code == 200
    names = {tool["name"] for tool in tools.json()}
    assert {"fs_read", "draft_refund", "delete_file"} <= names

    policy = client.get("/v1/policies", headers=VIEWER).json()
    assert policy["rule_count"] > 0
    assert policy["raw"] is None  # raw YAML is admin-only
    admin_policy = client.get("/v1/policies", headers=ADMIN).json()
    assert "tools:" in admin_policy["raw"]

    task = _create_refund(client)
    trace = client.get(f"/v1/tasks/{task['id']}/trace", headers=ADMIN)
    assert trace.status_code == 200
    assert trace.json()["status"] == "waiting_approval"
    assert trace.json()["spans"]


def test_blocked_task_is_reported_as_blocked(client):
    response = client.post("/v1/tasks", json={"request": "帮我删除文件 notes.md"}, headers=ADMIN)
    assert response.status_code == 201
    body = response.json()
    assert body["status"] == "blocked"
    assert "delete_file" in [call["tool_name"] for call in body["tool_calls"]]
    assert body["tool_calls"][0]["status"] == "blocked"


def test_task_list_filters_by_status(client):
    _create_refund(client)
    waiting = client.get("/v1/tasks?status=waiting_approval", headers=ADMIN).json()
    assert waiting["total"] >= 1
    empty = client.get("/v1/tasks?status=no_such_status", headers=ADMIN).json()
    assert empty["total"] == 0


def test_database_rows_are_tenant_scoped(client, api_app):
    _create_refund(client)
    from sqlalchemy import select

    factory = api_app.state.session_factory
    with factory() as session:
        tasks = session.scalars(select(AgentTask)).all()
    assert tasks and all(task.tenant_id == "tenant-a" for task in tasks)


def test_production_refuses_to_start_without_explicit_keys():
    import pytest
    from app.api.main import create_app
    from app.core.config import Settings
    from app.core.errors import ConfigurationError

    settings = Settings(
        _env_file=None,
        app_env="production",
        database_url="sqlite+pysqlite:///:memory:",
        sentinel_api_keys_json="",
        api_keys_json="",
    )
    with pytest.raises(ConfigurationError, match="SENTINEL_API_KEYS_JSON"):
        create_app(settings)


def test_metrics_token_is_enforced_when_configured(api_settings):
    from app.api.main import create_app
    from app.db.models import Base
    from fastapi.testclient import TestClient
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool

    settings = api_settings.model_copy(update={"metrics_token": "scrape-secret"})
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)
    app = create_app(settings, session_factory=factory)
    with TestClient(app) as client:
        assert client.get("/metrics").status_code == 401
        authorized = client.get("/metrics", headers={"Authorization": "Bearer scrape-secret"})
        assert authorized.status_code == 200
    engine.dispose()


def test_duplicate_api_keys_are_rejected():
    import pytest
    from app.api.auth import load_api_keys
    from app.core.config import Settings
    from app.core.errors import ConfigurationError

    dup = json.dumps(
        [
            {"key": "same-secret-key", "tenant": "t1", "role": "viewer", "subject": "a"},
            {"key": "same-secret-key", "tenant": "t2", "role": "admin", "subject": "b"},
        ]
    )
    settings = Settings(_env_file=None, sentinel_api_keys_json=dup)
    with pytest.raises(ConfigurationError, match="duplicates"):
        load_api_keys(settings)


def test_policy_endpoint_exposes_filename_not_server_path(client):
    policy = client.get("/v1/policies", headers=VIEWER).json()
    assert "/" not in policy["path"] and "\\" not in policy["path"]


def test_failed_task_persists_failure_and_audit_trail_on_runtime_exception(api_app):
    from fastapi.testclient import TestClient
    from sqlalchemy import select

    original_run_traced = api_app.state.runtime.loop.run_traced

    def boom(*, task_id, user_request, session, scenario_id=None):
        from app.audit.logger import AuditLogger

        AuditLogger(session).write(
            task_id=task_id,
            event_type="test.before_crash",
            actor_type="system",
            payload={"step": 1},
        )
        raise RuntimeError("simulated provider crash")

    api_app.state.runtime.loop.run_traced = boom
    try:
        with TestClient(api_app, raise_server_exceptions=False) as client:
            resp = client.post("/v1/tasks", json={"request": "trigger crash"}, headers=ADMIN)
            assert resp.status_code == 500
    finally:
        api_app.state.runtime.loop.run_traced = original_run_traced

    with api_app.state.session_factory() as session:
        task = session.scalars(select(AgentTask)).one()
        assert task.status == "failed"
        assert "simulated provider crash" in (task.error or "")
        from app.audit.logger import read_chain, verify_chain

        chain = read_chain(session, task.id)
        assert len(chain) == 1
        assert chain[0].event_type == "test.before_crash"
        assert verify_chain(chain).ok is True
