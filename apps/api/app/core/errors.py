"""Typed errors.

Every error carries a stable machine code so the API, the evaluator and the
audit log never have to parse a human sentence to learn what happened. The
earlier codebase derived error codes from free text
(``message.upper().replace(" ", "_")``), which cannot be asserted against.
"""

from __future__ import annotations


class SentinelError(Exception):
    """Base class. ``code`` is stable and safe to assert on in tests."""

    code = "SENTINEL_ERROR"
    http_status = 500

    def __init__(self, message: str, *, detail: dict | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.detail = detail or {}

    def to_payload(self) -> dict:
        return {"error": {"code": self.code, "message": self.message, "detail": self.detail}}


class ToolNotFoundError(SentinelError):
    code = "TOOL_NOT_FOUND"
    http_status = 404


class ToolExecutionError(SentinelError):
    code = "TOOL_EXECUTION_FAILED"
    http_status = 502


class ToolArgumentError(SentinelError):
    """The caller supplied arguments the tool cannot accept.

    This exists as a distinct code because a failed tool call must never be
    reported as a successful run. The previous evaluator initialised
    ``runStatus = "passed"`` and never demoted it on a tool error, so an
    internal validation string was rendered to the user under a green badge.
    """

    code = "INVALID_ARGS"
    http_status = 400


class PolicyBlockedError(SentinelError):
    code = "POLICY_BLOCKED"
    http_status = 403


class ApprovalRequiredError(SentinelError):
    code = "APPROVAL_REQUIRED"
    http_status = 409


class ApprovalNotFoundError(SentinelError):
    code = "APPROVAL_NOT_FOUND"
    http_status = 404


class ApprovalStateError(SentinelError):
    """The approval is not in a state that authorises what was asked of it.

    Rejecting twice, approving something already executed, or executing an
    approval that is still ``pending`` all land here. It is a distinct code
    because "a reviewer has not decided yet" and "this decision was already
    spent" call for different actions from a caller.
    """

    code = "APPROVAL_STATE"
    http_status = 409


class ApprovalMismatchError(SentinelError):
    """An approval was presented for a call it does not cover.

    Raised when the tool or the arguments being executed differ from the ones the
    reviewer approved. Without this check, an approval would be a transferable
    token: approve a harmless refund draft, then run anything.
    """

    code = "APPROVAL_MISMATCH"
    http_status = 409


class TaskNotFoundError(SentinelError):
    code = "TASK_NOT_FOUND"
    http_status = 404


class AuditIntegrityError(SentinelError):
    code = "AUDIT_INTEGRITY_BROKEN"
    http_status = 500


class MCPServerError(SentinelError):
    """An MCP server failed to start, list tools, or complete a call."""

    code = "MCP_SERVER_ERROR"
    http_status = 502


class MCPToolNotAllowedError(SentinelError):
    """An MCP server advertised a tool that the allow-list rejects.

    Remote servers are untrusted. A server that adds a tool after startup, or
    advertises a name that collides with a local tool, must be refused rather
    than silently trusted.
    """

    code = "MCP_TOOL_NOT_ALLOWED"
    http_status = 403
