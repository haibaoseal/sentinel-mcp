"""Failure-handling tests: retry scope, breaker transitions, audit concurrency."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

import pytest
from app.audit.logger import AuditLogger, read_chain, verify_chain
from app.core.contracts import ToolRequest
from app.core.errors import CircuitOpenError, ToolExecutionError
from app.core.locks import TASK_LOCKS
from app.db.models import AgentTask, Base
from app.db.session import build_engine, build_session_factory
from app.governance.firewall import Firewall
from app.policy.engine import PolicyEngine
from app.resilience import CircuitBreaker, ToolResilience
from app.tools.registry import ToolRegistry
from app.tools.sources.local import LocalTool, LocalToolSource
from sqlalchemy.orm import Session


def _firewall(tool_fn, *, action_type="read", resilience=None) -> Firewall:
    source = LocalToolSource(
        [LocalTool(name="probe", run=tool_fn, action_type=action_type, risk_level="low")],
        name="test",
    )
    policy = {
        "version": 1,
        "tools": {"probe": {"risk": "low", "action_type": action_type}},
        "defaults": {"unknown_tool": "require_approval"},
    }
    return Firewall(
        registry=ToolRegistry([source]),
        policy_engine=PolicyEngine(policy),
        resilience=resilience,
    )


def _run(firewall: Firewall, session: Session, task: AgentTask, *, action_type="read"):
    return firewall.execute(
        ToolRequest(
            task_id=task.id,
            tool_name="probe",
            action_type=action_type,
            arguments={},
            requested_by="test",
        ),
        session=session,
    )


def test_read_only_tool_is_retried_and_the_retry_is_audited(session, task):
    calls = {"n": 0}

    def flaky(_args):
        calls["n"] += 1
        if calls["n"] < 3:
            raise ToolExecutionError("transient upstream failure")
        return {"ok": True}

    resilience = ToolResilience(
        retry_attempts=3, retry_base_delay=0.0, circuit_failure_threshold=10, sleep=lambda _: None
    )
    firewall = _firewall(flaky, resilience=resilience)
    result = _run(firewall, session, task)

    assert result.status == "success"
    assert calls["n"] == 3
    events = read_chain(session, task.id)
    retries = [event for event in events if event.event_type == "tool.retry"]
    assert len(retries) == 2
    executed = [event for event in events if event.event_type == "tool.executed"]
    assert executed[-1].payload_json["attempts"] == 3
    assert verify_chain(events).ok is True


def test_write_tool_is_not_retried(session, task):
    calls = {"n": 0}

    def always_fails(_args):
        calls["n"] += 1
        raise ToolExecutionError("do not retry writes")

    resilience = ToolResilience(retry_attempts=3, retry_base_delay=0.0, sleep=lambda _: None)
    firewall = _firewall(always_fails, action_type="write", resilience=resilience)
    result = _run(firewall, session, task, action_type="write")

    assert result.status == "failed"
    assert calls["n"] == 1


def test_circuit_breaker_opens_fails_fast_and_recovers():
    now = {"t": 0.0}
    breaker = CircuitBreaker(
        "upstream",
        failure_threshold=2,
        recovery_seconds=10.0,
        clock=lambda: now["t"],
    )
    breaker.allow()
    breaker.record_failure()
    assert breaker.state == "closed"
    breaker.allow()
    breaker.record_failure()
    assert breaker.state == "open"

    with pytest.raises(CircuitOpenError):
        breaker.allow()

    now["t"] = 11.0
    assert breaker.state == "half_open"
    breaker.allow()  # reserve the single probe
    breaker.record_success()
    assert breaker.state == "closed"


def test_resilience_opens_circuit_after_repeated_failures(session, task):
    calls = {"n": 0}

    def always_fails(_args):
        calls["n"] += 1
        raise ToolExecutionError("dependency down")

    resilience = ToolResilience(
        retry_attempts=1,
        retry_base_delay=0.0,
        circuit_failure_threshold=2,
        circuit_recovery_seconds=60,
    )
    firewall = _firewall(always_fails, resilience=resilience)
    assert _run(firewall, session, task).status == "failed"
    assert _run(firewall, session, task).status == "failed"
    assert resilience.breaker("probe").state == "open"

    before = calls["n"]
    result = _run(firewall, session, task)
    assert result.status == "failed"
    assert "circuit" in (result.error or "")
    assert calls["n"] == before  # the breaker stopped the call before it ran


def test_concurrent_audit_writes_same_task_stay_gap_free(tmp_path):
    engine = build_engine(f"sqlite:///{tmp_path / 'audit-concurrency.db'}")
    Base.metadata.create_all(engine)
    factory = build_session_factory(engine)

    with factory() as session:
        task = AgentTask(title="concurrency", user_request="x")
        session.add(task)
        session.commit()
        task_id = task.id

    def worker(index: int) -> None:
        with factory() as session:
            logger = AuditLogger(session)
            for seq in range(5):
                logger.write(
                    task_id=task_id,
                    event_type=f"worker.{index}.{seq}",
                    actor_type="test",
                    actor_id=f"w{index}",
                    payload={"i": index, "j": seq},
                )
            session.commit()

    with ThreadPoolExecutor(max_workers=10) as pool:
        list(pool.map(worker, range(10)))

    with factory() as session:
        events = read_chain(session, task_id)
        assert len(events) == 50
        assert [event.seq for event in events] == list(range(1, 51))
        assert verify_chain(events).ok is True

    engine.dispose()
    # Locks are reference-counted and dropped when the last holder leaves.
    assert TASK_LOCKS.size() == 0


def test_keyed_lock_registry_does_not_grow_without_bound(tmp_path):
    assert TASK_LOCKS.size() == 0
    for index in range(100):
        with TASK_LOCKS.hold(f"task-{index}"):
            pass
    assert TASK_LOCKS.size() == 0


def test_half_open_bug_exception_does_not_falsely_heal_breaker():
    now = {"t": 0.0}
    resilience = ToolResilience(
        retry_attempts=1,
        circuit_failure_threshold=1,
        circuit_recovery_seconds=10.0,
    )
    breaker = resilience.breaker("flaky_tool")
    breaker.clock = lambda: now["t"]

    with pytest.raises(ToolExecutionError):
        resilience.execute(
            tool_name="flaky_tool",
            action_type="read",
            fn=lambda: (_ for _ in ()).throw(ToolExecutionError("down")),
        )
    assert breaker.state == "open"

    now["t"] = 11.0
    assert breaker.state == "half_open"

    with pytest.raises(ValueError, match="bad caller input"):
        resilience.execute(
            tool_name="flaky_tool",
            action_type="read",
            fn=lambda: (_ for _ in ()).throw(ValueError("bad caller input")),
        )
    # Still half_open (not healed to closed), and probe slot is released.
    assert breaker.state == "half_open"
    resilience.execute(tool_name="flaky_tool", action_type="read", fn=lambda: "ok")
    assert breaker.state == "closed"


def test_retry_metric_labels_the_real_tool_name():
    from app.observability import metrics

    calls = {"n": 0}

    def flaky():
        calls["n"] += 1
        if calls["n"] == 1:
            raise ToolExecutionError("transient")
        return "ok"

    before = metrics.TOOL_RETRIES.labels(tool="labelled_probe")._value.get()
    resilience = ToolResilience(
        retry_attempts=2, retry_base_delay=0.0, circuit_failure_threshold=10, sleep=lambda _: None
    )
    resilience.execute(tool_name="labelled_probe", action_type="read", fn=flaky)
    after = metrics.TOOL_RETRIES.labels(tool="labelled_probe")._value.get()
    assert after == before + 1


def test_audit_logger_does_not_leak_transaction_listeners(tmp_path):
    engine = build_engine(f"sqlite:///{tmp_path / 'listener-leak.db'}")
    Base.metadata.create_all(engine)
    factory = build_session_factory(engine)

    with factory() as session:
        task = AgentTask(title="listeners", user_request="x")
        session.add(task)
        session.commit()

        logger = AuditLogger(session)
        for index in range(10):
            logger.write(
                task_id=task.id,
                event_type=f"step.{index}",
                actor_type="test",
                payload={"i": index},
            )
            session.commit()
        # Registered once for the lifetime of the session, not once per transaction.
        assert len(session.dispatch.after_transaction_end.listeners) == 1

    engine.dispose()


def test_concurrent_approval_executes_tool_only_once(tmp_path):
    from app.approvals.service import ApprovalService
    from app.core.errors import ApprovalStateError
    from app.core.locks import APPROVAL_LOCKS

    engine = build_engine(f"sqlite:///{tmp_path / 'approval-race.db'}")
    Base.metadata.create_all(engine)
    factory = build_session_factory(engine)

    executions = {"n": 0}

    def refund(_args):
        executions["n"] += 1
        return {"refunded": True}

    source = LocalToolSource(
        [
            LocalTool(
                name="draft_refund",
                run=refund,
                action_type="financial",
                risk_level="critical",
                requires_approval=True,
            )
        ],
        name="test",
    )
    policy = {
        "version": 1,
        "tools": {
            "draft_refund": {
                "risk": "critical",
                "action_type": "financial",
                "approval_required": True,
            }
        },
        "defaults": {"unknown_tool": "require_approval"},
    }
    firewall = Firewall(registry=ToolRegistry([source]), policy_engine=PolicyEngine(policy))

    with factory() as session:
        task = AgentTask(title="race", user_request="refund")
        session.add(task)
        session.flush()
        held = firewall.execute(
            ToolRequest(
                task_id=task.id,
                tool_name="draft_refund",
                action_type="financial",
                arguments={"order_id": "ORD-1"},
                requested_by="agent",
            ),
            session=session,
        )
        assert held.status == "waiting_approval"
        approval_id = held.data["approval_id"]
        session.commit()

    def try_approve(reviewer: str) -> str:
        with factory() as session:
            # Simulate a pre-check caching the row in the session identity map.
            from app.db.models import ApprovalRequest

            session.get(ApprovalRequest, approval_id)
            try:
                outcome = ApprovalService(firewall=firewall, session=session).approve(
                    approval_id, reviewer_id=reviewer
                )
                session.commit()
                return outcome.status
            except ApprovalStateError:
                session.rollback()
                return "already_decided"

    with ThreadPoolExecutor(max_workers=6) as pool:
        results = list(pool.map(try_approve, [f"rev-{i}" for i in range(6)]))

    assert executions["n"] == 1
    assert results.count("executed") == 1
    assert results.count("already_decided") == 5
    assert APPROVAL_LOCKS.size() == 0
    engine.dispose()
