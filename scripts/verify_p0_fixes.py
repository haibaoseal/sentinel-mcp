"""Demonstrate that the two P0 defects reproduced in the archived repos are fixed.

Run: python scripts/verify_p0_fixes.py
"""

from __future__ import annotations

import sys
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "apps" / "api"))

from app.audit.logger import AuditLogger, read_chain, verify_chain  # noqa: E402
from app.db.models import AgentTask, Base  # noqa: E402
from app.security.secrets import redact_text  # noqa: E402
from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

engine = create_engine("sqlite+pysqlite:///:memory:")
Base.metadata.create_all(engine)

# Collected as we go, then turned into an exit code. An earlier version of this
# script only *printed* its findings, so CI's "Verify governance guarantees" step
# passed with redaction fully broken -- a demonstration standing in for a gate.
failures: list[str] = []

print("=" * 74)
print("P0-1  Audit chain: N events sharing one timestamp")
print("=" * 74)
with Session(engine) as s:
    task = AgentTask(title="verify", user_request="verify", status="pending")
    s.add(task)
    s.flush()
    logger = AuditLogger(s)
    frozen = datetime(2026, 1, 1, tzinfo=UTC)
    for i in range(5):
        ev = logger.write(
            task_id=task.id, event_type=f"e{i}", actor_type="system", payload={"i": i}, actor_id="t"
        )
        ev.created_at = frozen
    s.flush()
    events = read_chain(s, task.id)
    verdict = verify_chain(events)
    print(f"  events            : {len(events)}  (all created_at identical)")
    print(f"  seq               : {[e.seq for e in events]}")
    print(f"  chain verifies    : {verdict.ok}  (checked {verdict.checked})")
    print("  old repo verdict  : False   <-- legitimate chain reported as tampered")

    # tamper
    events[2].payload_json = {"i": "TAMPERED"}
    s.flush()
    bad = verify_chain(read_chain(s, task.id))
    print(
        f"  after tampering   : ok={bad.ok} first_bad_seq={bad.first_bad_seq} reason={bad.reason!r}"
    )

    if not verdict.ok:
        failures.append("an honest chain of same-timestamp events did not verify")
    if bad.ok:
        failures.append("payload tampering was not detected")

print()
print("=" * 74)
print("P0-2  Redaction: shapes the archived implementation leaked")
print("=" * 74)
cases = [
    ("openai lowercase", "sk-abc123XYZdef456ghi789"),
    ("openai UPPERCASE", "SK-abc123XYZdef456ghi789"),
    ("github token", "ghp_abcdefghijklmnopqrstuvwx"),
    ("slack token", "xoxb-" + "123456789012" + "-" + "abcdefghijklmnop"),
    ("google key", "AIzaSyA1B2C3D4E5F6G7H8I9J0KLMNOPQRSTUV"),
    ("aws key", "AKIAIOSFODNN7EXAMPLE"),
    ("azure 32-hex", "a1b2c3d4e5f60718293a4b5c6d7e8f90"),
    ("Bearer base64 tail", "Bearer abc+/def=="),
    ("jwt", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghijklmnopqrst"),
    ("cn national id", "110101199003071234"),
    ("cn mobile spaced", "138 0013 8000"),
    ("cn landline", "010-12345678"),
]
for label, secret in cases:
    out = redact_text(f"payload {secret} end")
    leaked = secret in out
    if leaked:
        failures.append(f"redaction leaked {label}")
    mark = "LEAK" if leaked else "ok  "
    print(f"  [{mark}] {label:20} -> {out}")

print()
print("=" * 74)
print("Note: 'Bearer abc+/def==' previously became '[REDACTED]+/def==' -- it")
print("looked redacted while leaking the tail. That class of bug is why the")
print("redaction tests assert the ABSENCE of a substring, not a marker.")
print("=" * 74)

if failures:
    print()
    print(f"FAILED ({len(failures)}):")
    for failure in failures:
        print(f"  - {failure}")
    # Exit non-zero so CI's "Verify governance guarantees" step is a gate rather
    # than a demonstration that always passes.
    raise SystemExit(1)
print("\nOK: the chain self-verifies, tampering is detected, and no listed shape leaked.")
