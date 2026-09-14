"""Regression tests for audit-chain ordering.

These encode a specific bug that was measured in the previous codebase: the
writer chained by ``(created_at DESC, id DESC)`` while the verifier replayed by
``(created_at ASC, id ASC)``. When two events shared a timestamp -- routine
inside one request -- an *honestly written* chain failed verification.

A tamper-evident log that reports false positives trains its operators to
ignore it, so these tests exist to keep ordering a property of the data.
"""

from __future__ import annotations

from datetime import UTC, datetime

from app.audit.logger import (
    GENESIS_HASH,
    AuditLogger,
    compute_event_hash,
    read_chain,
    verify_chain,
)
from app.db.models import AuditEvent
from sqlalchemy import select


def test_seq_is_gap_free_and_starts_at_one(session, task):
    logger = AuditLogger(session)
    for index in range(5):
        logger.write(
            task_id=task.id,
            event_type=f"probe.event.{index}",
            actor_type="system",
            actor_id="test",
            payload={"i": index},
        )

    events = read_chain(session, task.id)
    assert [event.seq for event in events] == [1, 2, 3, 4, 5]
    assert events[0].prev_hash == GENESIS_HASH


def test_chain_verifies_when_every_event_shares_one_timestamp(session, task):
    """The exact regression: identical timestamps must not break the chain.

    This is the test the previous implementation would have failed, because it
    chained by ``(created_at DESC, id DESC)`` and replayed by
    ``(created_at ASC, id ASC)``.
    """
    logger = AuditLogger(session)
    frozen = datetime(2026, 1, 1, tzinfo=UTC)
    for index in range(4):
        event = logger.write(
            task_id=task.id,
            event_type=f"probe.event.{index}",
            actor_type="system",
            actor_id="test",
            payload={"i": index},
        )
        event.created_at = frozen
    session.flush()

    events = read_chain(session, task.id)
    # All four rows genuinely share one instant. Compare formatted instants
    # rather than datetimes because SQLite round-trips naive values, so equality
    # against a tz-aware object is not meaningful.
    instants = {event.created_at.isoformat()[:19] for event in events}
    assert len(instants) == 1, instants

    # And the clock is genuinely ambiguous here: every row ties on the first
    # ordering key, so a timestamp-based chain would have to fall back to id.
    assert len({event.created_at.isoformat()[:19] for event in events}) == 1

    verification = verify_chain(events)
    assert verification.ok, verification.reason
    assert verification.checked == 4


def test_chain_order_is_independent_of_timestamp_ordering(session, task):
    """Even if a clock goes backwards, seq defines the chain."""
    logger = AuditLogger(session)
    first = logger.write(
        task_id=task.id, event_type="a", actor_type="system", payload={}, actor_id="t"
    )
    second = logger.write(
        task_id=task.id, event_type="b", actor_type="system", payload={}, actor_id="t"
    )
    # Simulate a non-monotonic clock: the later event carries the earlier stamp.
    first.created_at = datetime(2030, 1, 1, tzinfo=UTC)
    second.created_at = datetime(2020, 1, 1, tzinfo=UTC)
    session.flush()

    assert verify_chain(read_chain(session, task.id)).ok


def test_tampering_with_a_payload_is_detected(session, task):
    logger = AuditLogger(session)
    for index in range(3):
        logger.write(
            task_id=task.id,
            event_type=f"probe.{index}",
            actor_type="system",
            payload={"amount": 1},
            actor_id="t",
        )
    session.flush()

    target = read_chain(session, task.id)[1]
    target.payload_json = {"amount": 999_999}
    session.flush()

    verification = verify_chain(read_chain(session, task.id))
    assert not verification.ok
    assert verification.first_bad_seq == 2
    assert verification.reason == "event_hash does not recompute"


def test_deleting_a_middle_event_is_detected(session, task):
    """Removal must be caught -- the chain is contiguous, so a hole shows up."""
    logger = AuditLogger(session)
    for index in range(4):
        logger.write(
            task_id=task.id,
            event_type=f"probe.{index}",
            actor_type="system",
            payload={},
            actor_id="t",
        )
    session.flush()

    middle = read_chain(session, task.id)[2]
    session.delete(middle)
    session.flush()

    verification = verify_chain(read_chain(session, task.id))
    assert not verification.ok
    assert verification.reason is not None
    assert "sequence gap" in verification.reason


def test_reordering_events_is_detected(session, task):
    logger = AuditLogger(session)
    for index in range(3):
        logger.write(
            task_id=task.id,
            event_type=f"probe.{index}",
            actor_type="system",
            payload={},
            actor_id="t",
        )
    session.flush()

    events = read_chain(session, task.id)
    shuffled = [events[0], events[2], events[1]]
    assert not verify_chain(shuffled).ok


def test_chains_are_independent_per_task(session, task):
    """One task's events must not be chained onto another's."""
    other = type(task)(title="Other", user_request="x", status="pending")
    session.add(other)
    session.flush()

    logger = AuditLogger(session)
    logger.write(task_id=task.id, event_type="a", actor_type="system", payload={}, actor_id="t")
    logger.write(task_id=other.id, event_type="b", actor_type="system", payload={}, actor_id="t")
    logger.write(task_id=task.id, event_type="c", actor_type="system", payload={}, actor_id="t")

    assert verify_chain(read_chain(session, task.id)).ok
    assert verify_chain(read_chain(session, other.id)).ok
    assert [event.seq for event in read_chain(session, other.id)] == [1]


def test_hmac_key_binds_the_chain(session, task):
    """With a key, an attacker without it cannot forge a consistent chain."""
    key = b"unit-test-key"
    logger = AuditLogger(session, hmac_key=key)
    logger.write(task_id=task.id, event_type="a", actor_type="system", payload={}, actor_id="t")
    session.flush()

    events = read_chain(session, task.id)
    assert verify_chain(events, hmac_key=key).ok
    # Verifying without the key must not succeed: the digest differs.
    assert not verify_chain(events).ok


def test_unkeyed_chain_is_rewritable_from_genesis(session, task):
    """Document the residual limitation rather than implying full protection.

    An unkeyed hash chain cannot resist an attacker who rewrites the entire
    table, because nothing outside the database pins the head. This test asserts
    that documented weakness so nobody mistakes the log for a notary.
    """
    logger = AuditLogger(session)
    logger.write(
        task_id=task.id, event_type="a", actor_type="system", payload={"v": 1}, actor_id="t"
    )
    session.flush()

    event = read_chain(session, task.id)[0]
    event.payload_json = {"v": 2}
    # Attack: recompute the whole chain from genesis with no key.
    from app.audit.logger import audit_event_hash_payload

    event.prev_hash = GENESIS_HASH
    event.event_hash = compute_event_hash(GENESIS_HASH, audit_event_hash_payload(event), key=None)
    session.flush()

    # Forged, and the unkeyed verifier accepts it -- which is exactly why the
    # README must not claim notarisation.
    assert verify_chain(read_chain(session, task.id)).ok


def test_secrets_are_redacted_before_storage(session, task):
    logger = AuditLogger(session)
    logger.write(
        task_id=task.id,
        event_type="probe.leak",
        actor_type="system",
        payload={"note": "token ghp_abcdefghijklmnopqrstuvwx", "password": "hunter2"},
        actor_id="t",
    )
    session.flush()

    stored = session.scalars(select(AuditEvent)).one()
    assert "ghp_abcdefghijklmnopqrstuvwx" not in str(stored.payload_json)
    assert "hunter2" not in str(stored.payload_json)
