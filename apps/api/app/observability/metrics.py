"""Prometheus metrics for the service layer.

The governance core is intentionally free of metrics dependencies; this module is
imported by the HTTP layer and by the firewall only when it is available. Metrics
are named for the questions an operator asks during an incident:

- Is the service accepting work? (`http_requests_total`, `tasks_inflight`)
- Is governance refusing things? (`policy_decisions_total`, `approvals_pending`)
- Is the audit chain intact? (`audit_verify_total`, `audit_events`)
- Is a dependency failing? (`circuit_breaker_open`, `tool_retries_total`)
"""

from __future__ import annotations

from prometheus_client import (
    CONTENT_TYPE_LATEST,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
)
from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from app.db.models import ApprovalRequest, AuditEvent

CONTENT_TYPE = CONTENT_TYPE_LATEST

HTTP_REQUESTS = Counter(
    "sentinel_http_requests_total",
    "HTTP requests by method, route template and status.",
    ["method", "path", "status"],
)
HTTP_DURATION = Histogram(
    "sentinel_http_request_duration_seconds",
    "HTTP request latency.",
    ["method", "path"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10),
)
TASKS = Counter(
    "sentinel_tasks_total",
    "Completed agent tasks by final status and provider.",
    ["status", "provider"],
)
TASK_DURATION = Histogram(
    "sentinel_task_duration_seconds",
    "Agent task wall-clock duration.",
    ["status"],
    buckets=(0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60),
)
TASKS_INFLIGHT = Gauge("sentinel_tasks_inflight", "Agent tasks currently executing.")
APPROVAL_DECISIONS = Counter(
    "sentinel_approval_decisions_total",
    "Human approval decisions.",
    ["decision"],
)
POLICY_DECISIONS = Counter(
    "sentinel_policy_decisions_total",
    "Policy engine decisions by outcome and risk level.",
    ["decision", "risk_level"],
)
AUDIT_VERIFY = Counter(
    "sentinel_audit_verify_total",
    "Audit-chain verification outcomes.",
    ["result"],
)
TOOL_RETRIES = Counter(
    "sentinel_tool_retries_total",
    "Retries of read-only tool calls.",
    ["tool"],
)
CIRCUIT_OPEN = Gauge(
    "sentinel_circuit_breaker_open",
    "1 when the circuit breaker for a tool is open.",
    ["tool"],
)
APPROVALS_PENDING = Gauge(
    "sentinel_approvals_pending",
    "Approval requests waiting for a human.",
)
AUDIT_EVENTS = Gauge(
    "sentinel_audit_events",
    "Stored audit events across all tasks.",
)
DB_UP = Gauge("sentinel_db_up", "1 when the configured database answers a trivial query.")


def refresh_business_gauges(factory: sessionmaker[Session]) -> None:
    """Refresh gauges that are cheaper to compute at scrape time than to maintain.

    A scrape every 15 seconds against two indexed counts is preferable to writing
    a gauge on every request and still being wrong after a crash. A failure here
    must not break the scrape: it sets `db_up` to 0 and leaves the rest alone.
    """
    try:
        with factory() as session:
            session.execute(select(1))
            APPROVALS_PENDING.set(
                session.scalar(
                    select(func.count())
                    .select_from(ApprovalRequest)
                    .where(ApprovalRequest.status == "pending")
                )
                or 0
            )
            AUDIT_EVENTS.set(session.scalar(select(func.count()).select_from(AuditEvent)) or 0)
            DB_UP.set(1)
    except Exception:
        DB_UP.set(0)


def render() -> bytes:
    return generate_latest()
