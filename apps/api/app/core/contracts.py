"""Core contracts for the governed tool runtime.

The important idea in this module is that governance must not know *where* a
tool lives. A tool may be a local Python object, a subprocess MCP server over
stdio, or a remote MCP server over HTTP. All three are described by the same
``ToolBinding`` and are therefore subject to the same policy decision, the same
approval workflow and the same audit record.

In the previous generation of this project the firewall called
``ToolRegistry.execute`` directly, which quietly made "governed" a property of
being registered in-process. Splitting description from execution is what lets
an untrusted remote MCP tool be governed on equal terms.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any, Literal, Protocol, runtime_checkable

from pydantic import BaseModel, Field

ActionType = Literal["read", "write", "external_send", "destructive", "financial", "unknown"]
RiskLevel = Literal["low", "medium", "high", "critical"]
Decision = Literal["allow", "block", "require_approval", "transform"]
ToolStatus = Literal["success", "failed", "blocked", "waiting_approval"]

RISK_ORDER: dict[str, int] = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def max_risk(*levels: str) -> RiskLevel:
    """Return the most severe level present. Unknown levels rank as 'low'."""
    highest = "low"
    for level in levels:
        if RISK_ORDER.get(level, 0) > RISK_ORDER.get(highest, 0):
            highest = level
    return highest  # type: ignore[return-value]


class ToolRequest(BaseModel):
    """A proposed tool call, before any governance decision."""

    task_id: str | None = None
    tool_name: str
    action_type: ActionType = "unknown"
    resource_type: str | None = None
    resource_id: str | None = None
    arguments: dict[str, Any] = Field(default_factory=dict)
    requested_by: str = "agent"
    user_id: str | None = None


class ToolResult(BaseModel):
    tool_call_id: str
    status: ToolStatus
    data: dict[str, Any] | None = None
    error: str | None = None
    # Which binding actually served this call. Populated so replay and eval can
    # distinguish "the local mock ran" from "a remote MCP server ran", which
    # matters when auditing a compromise.
    source: str | None = None


class ToolDescriptor(BaseModel):
    """Everything governance needs to reason about a tool without running it."""

    name: str
    description: str = ""
    action_type: ActionType = "unknown"
    resource_type: str = "unknown"
    risk_level: RiskLevel = "medium"
    requires_approval: bool = False
    argument_schema: dict[str, Any] = Field(default_factory=dict)
    # Provenance: "local", "mcp:stdio", "mcp:http". Shown in the UI so a
    # reviewer can see that remote tools are first-class here.
    source: str = "local"


class ToolExecution(BaseModel):
    """The outcome a binding reports, before it becomes a ToolResult."""

    data: dict[str, Any] = Field(default_factory=dict)


@runtime_checkable
class ToolSource(Protocol):
    """A supplier of executable tools.

    Implementations: ``LocalToolSource`` (in-process), ``MCPToolSource``
    (stdio or HTTP MCP server). Adding a source must never require touching the
    firewall, policy engine or audit logger.
    """

    name: str

    def descriptors(self) -> list[ToolDescriptor]:
        """Describe available tools. Must not execute anything."""
        ...

    def execute(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Run one tool. Raises ToolExecutionError on failure."""
        ...


# Signature for a single tool implementation inside a local source.
LocalToolFn = Callable[[dict[str, Any]], dict[str, Any]]


@runtime_checkable
class AsyncToolSource(Protocol):
    """Async variant, needed because MCP transports are inherently async."""

    name: str

    async def descriptors(self) -> list[ToolDescriptor]: ...

    async def execute(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]: ...


AsyncToolFn = Callable[[dict[str, Any]], Awaitable[dict[str, Any]]]
