"""Simulated maintenance tools: the write, destructive and external-send paths.

Why these exist at all
----------------------
A governance runtime needs tools that *would* cause harm in order to demonstrate
that it stops them. The archived codebase had a policy rule named
``delete_file`` but no such tool, and a scenario asserting ``delete_file`` was
blocked; the assertion passed because the tool did not exist, so nothing could
run. That is a green cell covering a hole.

These tools are therefore real, registered, and reachable -- and they are
deliberately inert. ``send_email`` records an intent instead of sending, and
``delete_file`` refuses to delete. They exist so that a policy *decision* has a
consequence that can be observed and asserted, and so their refusal is a
property of the tool as well as the policy: two independent reasons no real
email is sent.

Every one of them is marked ``side_effect: real`` in the policy, which keeps it
behind an opt-in runtime flag as a third layer.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from app.core.errors import ToolArgumentError
from app.tools.sources.filesystem import FilesystemSandbox
from app.tools.sources.local import LocalTool, LocalToolSource


def build_maintenance_source(sandbox: FilesystemSandbox) -> LocalToolSource:
    def send_email(arguments: dict[str, Any]) -> dict[str, Any]:
        recipient = str(arguments.get("to", "")).strip()
        if not recipient or "@" not in recipient:
            raise ToolArgumentError("'to' must be a valid email address")
        body = str(arguments.get("body", ""))
        if len(body) > 20000:
            raise ToolArgumentError("email body exceeds 20000 characters")
        return {
            "sent": False,
            "recorded": True,
            "to": recipient,
            "subject": str(arguments.get("subject", "")),
            "body_bytes": len(body.encode("utf-8")),
            "recorded_at": datetime.now(UTC).isoformat(),
            "note": (
                "This is a simulation. No mail was transmitted. Reaching this point means "
                "the call passed policy and, where required, human approval."
            ),
        }

    def write_file_draft(arguments: dict[str, Any]) -> dict[str, Any]:
        target = sandbox.resolve(str(arguments.get("path", "")))
        content = str(arguments.get("content", ""))
        return {
            "path": sandbox.relative(target),
            "draft_id": f"draft-{abs(hash((str(target), content))) % 10**10}",
            "bytes": len(content.encode("utf-8")),
            "written": False,
            "note": "Draft only. Nothing was written to disk.",
        }

    def delete_file(arguments: dict[str, Any]) -> dict[str, Any]:
        """Always refuses, even if every guard upstream were bypassed.

        The policy already blocks this tool. Refusing here as well means the
        guarantee does not depend on a single layer being correct.
        """
        target = sandbox.resolve(str(arguments.get("path", "")))
        return {
            "deleted": False,
            "path": sandbox.relative(target),
            "note": (
                "Deletion is refused by the tool itself, independently of the policy "
                "decision that should already have blocked this call."
            ),
        }

    def draft_refund(arguments: dict[str, Any]) -> dict[str, Any]:
        order_id = str(arguments.get("order_id", "")).strip()
        if not order_id:
            # Deliberately loud: the archived provider called this with an empty
            # id and the run still reported success.
            raise ToolArgumentError("order_id is required; ask the user for an ORD-#### id")
        if not order_id.upper().startswith("ORD-"):
            raise ToolArgumentError(f"order_id must look like ORD-0000, got {order_id!r}")
        return {
            "draft_id": f"refund-{order_id}",
            "order_id": order_id.upper(),
            "reason": str(arguments.get("reason", "")),
            "executed": False,
            "note": (
                "Dry run. A refund draft was created for human review; no money moved "
                "and no refund was completed."
            ),
        }

    return LocalToolSource(
        [
            LocalTool(
                name="send_email",
                run=send_email,
                description="Record an email send intent. Simulated: nothing is transmitted.",
                action_type="external_send",
                resource_type="email",
                risk_level="high",
                requires_approval=True,
                parameters={
                    "type": "object",
                    "properties": {
                        "to": {"type": "string"},
                        "subject": {"type": "string"},
                        "body": {"type": "string"},
                    },
                    "required": ["to"],
                    "additionalProperties": False,
                },
            ),
            LocalTool(
                name="write_file_draft",
                run=write_file_draft,
                description="Draft a file write inside the sandbox without writing it.",
                action_type="write",
                resource_type="file",
                risk_level="medium",
                requires_approval=True,
                parameters={
                    "type": "object",
                    "properties": {"path": {"type": "string"}, "content": {"type": "string"}},
                    "required": ["path"],
                    "additionalProperties": False,
                },
            ),
            LocalTool(
                name="delete_file",
                run=delete_file,
                description="Request deletion of a sandboxed file. Refused by policy and tool.",
                action_type="destructive",
                resource_type="file",
                risk_level="critical",
                requires_approval=True,
                parameters={
                    "type": "object",
                    "properties": {"path": {"type": "string"}},
                    "required": ["path"],
                    "additionalProperties": False,
                },
            ),
            LocalTool(
                name="draft_refund",
                run=draft_refund,
                description="Create a refund draft for human review. Dry run: no money moves.",
                action_type="financial",
                resource_type="order",
                risk_level="high",
                requires_approval=True,
                parameters={
                    "type": "object",
                    "properties": {"order_id": {"type": "string"}, "reason": {"type": "string"}},
                    "required": ["order_id"],
                    "additionalProperties": False,
                },
            ),
        ],
        name="local:maintenance",
    )


def ensure_sandbox_sample(sandbox_root: Path) -> None:
    """Seed a couple of files so a fresh checkout has something to read."""
    sandbox_root.mkdir(parents=True, exist_ok=True)
    sample = sandbox_root / "notes.md"
    if not sample.exists():
        sample.write_text(
            "# Sandbox notes\n\nThis file exists so the filesystem tools have "
            "something to read in a fresh checkout.\n",
            encoding="utf-8",
        )
