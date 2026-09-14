"""Small shared primitives."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime


def utcnow() -> datetime:
    return datetime.now(UTC)


def new_id() -> str:
    return str(uuid.uuid4())


def redact_for_log(value: str, *, keep: int = 4) -> str:
    """Shorten a value for logs without pretending it is safe to print."""
    if not value:
        return ""
    if len(value) <= keep:
        return "*" * len(value)
    return f"{value[:keep]}…({len(value)} chars)"
