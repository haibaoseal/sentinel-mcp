"""Hash-chained audit log.

Design notes that matter for the integrity claim
------------------------------------------------
The predecessor of this module chained events by reading the most recent row
ordered by ``(created_at DESC, id DESC)`` and replayed them ordered by
``(created_at ASC, id ASC)``. Those two orderings disagree whenever two events
share a timestamp, which happens routinely inside a single request. The result
was that an *honestly written* chain failed verification, and a tamper-evident
log that reports false positives is worse than no log at all.

The fix is to stop inferring order from a clock. Every row now carries an
explicit, gap-free ``seq`` per task, and both the writer and the verifier use it.
The chain is therefore a property of the data, not of timestamp resolution.

What this does and does not protect against
-------------------------------------------
It detects: modification of a stored payload, deletion of a middle event,
and reordering.
It does NOT protect against an attacker who can rewrite the whole table from
genesis, because the chain is unkeyed. That requires an external anchor (an
HMAC key held outside the database, or periodic digest publication). The code
says so out loud rather than implying otherwise in a README.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.security import new_id, utcnow
from app.db.models import AuditEvent

GENESIS_HASH = "GENESIS"


def canonical_json(payload: dict[str, Any]) -> str:
    """Deterministic serialisation. Sorted keys so field order cannot change a hash."""
    return json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str
    )


def event_hash_payload(
    *,
    event_id: str,
    task_id: str | None,
    seq: int,
    event_type: str,
    actor_type: str,
    actor_id: str | None,
    payload: dict[str, Any],
) -> dict[str, Any]:
    """The hashed envelope.

    ``seq`` is inside the envelope, so moving an event to a different position
    invalidates its own hash as well as its successor's ``prev_hash``.
    """
    return {
        "event_id": event_id,
        "task_id": task_id,
        "seq": seq,
        "event_type": event_type,
        "actor_type": actor_type,
        "actor_id": actor_id,
        "payload": payload,
    }


def compute_event_hash(
    prev_hash: str, envelope: dict[str, Any], *, key: bytes | None = None
) -> str:
    message = f"{prev_hash}{canonical_json(envelope)}".encode()
    if key is not None:
        return hmac.new(key, message, hashlib.sha256).hexdigest()
    return hashlib.sha256(message).hexdigest()


def audit_event_hash_payload(event: AuditEvent) -> dict[str, Any]:
    return event_hash_payload(
        event_id=event.id,
        task_id=event.task_id,
        seq=event.seq,
        event_type=event.event_type,
        actor_type=event.actor_type,
        actor_id=event.actor_id,
        payload=event.payload_json,
    )


@dataclass(frozen=True)
class ChainVerification:
    ok: bool
    checked: int
    first_bad_seq: int | None = None
    reason: str | None = None

    def __bool__(self) -> bool:  # allows `if verify_chain(...)`
        return self.ok


class AuditLogger:
    """Append-only writer.

    One instance per session. Sequence allocation reads ``MAX(seq)`` inside the
    caller's transaction; combined with the ``(task_id, seq)`` unique constraint
    that turns any interleaving bug into a loud IntegrityError rather than a
    silently forked chain.
    """

    def __init__(self, session: Session, *, hmac_key: bytes | None = None) -> None:
        self.session = session
        self.hmac_key = hmac_key

    def next_seq(self, task_id: str | None) -> int:
        current = self.session.scalar(
            select(func.max(AuditEvent.seq)).where(
                AuditEvent.task_id.is_(None) if task_id is None else AuditEvent.task_id == task_id
            )
        )
        return int(current or 0) + 1

    def previous_hash(self, task_id: str | None, seq: int) -> str:
        if seq <= 1:
            return GENESIS_HASH
        prior = self.session.scalars(
            select(AuditEvent)
            .where(
                AuditEvent.task_id.is_(None) if task_id is None else AuditEvent.task_id == task_id
            )
            .where(AuditEvent.seq == seq - 1)
            .limit(1)
        ).first()
        return prior.event_hash if prior else GENESIS_HASH

    def write(
        self,
        *,
        task_id: str | None,
        event_type: str,
        actor_type: str,
        payload: dict[str, Any],
        actor_id: str | None = None,
    ) -> AuditEvent:
        # Imported here to avoid a circular import: secrets imports nothing from
        # audit, but keeping the dependency local documents the direction.
        from app.security.secrets import sanitize_payload

        sanitized = sanitize_payload(payload)
        seq = self.next_seq(task_id)
        prev_hash = self.previous_hash(task_id, seq)
        event_id = new_id()
        envelope = event_hash_payload(
            event_id=event_id,
            task_id=task_id,
            seq=seq,
            event_type=event_type,
            actor_type=actor_type,
            actor_id=actor_id,
            payload=sanitized,
        )
        record = AuditEvent(
            id=event_id,
            task_id=task_id,
            seq=seq,
            event_type=event_type,
            actor_type=actor_type,
            actor_id=actor_id,
            payload_json=sanitized,
            prev_hash=prev_hash,
            event_hash=compute_event_hash(prev_hash, envelope, key=self.hmac_key),
            created_at=utcnow(),
        )
        self.session.add(record)
        self.session.flush()
        return record


def read_chain(session: Session, task_id: str) -> list[AuditEvent]:
    """Read events in chain order. ``seq`` is authoritative, never the clock."""
    return list(
        session.scalars(
            select(AuditEvent).where(AuditEvent.task_id == task_id).order_by(AuditEvent.seq.asc())
        )
    )


def verify_chain(events: list[AuditEvent], *, hmac_key: bytes | None = None) -> ChainVerification:
    """Verify an ordered event list.

    Checks, in order: sequence is gap-free from 1, each ``prev_hash`` matches the
    predecessor, and each ``event_hash`` recomputes. Returns the first offending
    sequence number so a reviewer can look at the exact row.
    """
    prev_hash = GENESIS_HASH
    for index, event in enumerate(events, start=1):
        if event.seq != index:
            return ChainVerification(
                ok=False,
                checked=index - 1,
                first_bad_seq=event.seq,
                reason=f"sequence gap: expected {index}, found {event.seq}",
            )
        if event.prev_hash != prev_hash:
            return ChainVerification(
                ok=False,
                checked=index - 1,
                first_bad_seq=event.seq,
                reason="prev_hash does not match predecessor",
            )
        expected = compute_event_hash(prev_hash, audit_event_hash_payload(event), key=hmac_key)
        if not hmac.compare_digest(event.event_hash, expected):
            return ChainVerification(
                ok=False,
                checked=index - 1,
                first_bad_seq=event.seq,
                reason="event_hash does not recompute",
            )
        prev_hash = event.event_hash
    return ChainVerification(ok=True, checked=len(events))
