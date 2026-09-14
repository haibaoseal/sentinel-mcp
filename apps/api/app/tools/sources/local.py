"""In-process tool source.

A tool is a descriptor plus a function. Registration is explicit so that the
set of things an agent can reach is reviewable by reading one file, rather than
being assembled by decorators scattered across a codebase.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

from app.core.contracts import ActionType, RiskLevel, ToolDescriptor
from app.core.errors import ToolArgumentError, ToolExecutionError, ToolNotFoundError


@dataclass(frozen=True)
class LocalTool:
    name: str
    run: Callable[[dict[str, Any]], dict[str, Any]]
    description: str = ""
    action_type: ActionType = "unknown"
    resource_type: str = "unknown"
    risk_level: RiskLevel = "medium"
    requires_approval: bool = False
    parameters: dict[str, Any] = field(default_factory=dict)

    def descriptor(self, *, source: str) -> ToolDescriptor:
        return ToolDescriptor(
            name=self.name,
            description=self.description,
            action_type=self.action_type,
            resource_type=self.resource_type,
            risk_level=self.risk_level,
            requires_approval=self.requires_approval,
            argument_schema=self.parameters,
            source=source,
        )


class LocalToolSource:
    """Serves tools that live in this process."""

    def __init__(self, tools: Iterable[LocalTool] = (), *, name: str = "local") -> None:
        self.name = name
        self._tools: dict[str, LocalTool] = {}
        for tool in tools:
            self.register(tool)

    def register(self, tool: LocalTool) -> None:
        if tool.name in self._tools:
            raise ValueError(f"duplicate local tool name: {tool.name}")
        self._tools[tool.name] = tool

    def descriptors(self) -> list[ToolDescriptor]:
        return [tool.descriptor(source=self.name) for tool in self._tools.values()]

    def execute(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        tool = self._tools.get(tool_name)
        if tool is None:
            raise ToolNotFoundError(f"local tool is not registered: {tool_name}")
        try:
            result = tool.run(arguments)
        except (ToolArgumentError, ToolExecutionError, ToolNotFoundError):
            raise
        except TypeError as exc:
            # A signature mismatch is a caller error, not an outage. Reporting it
            # as INVALID_ARGS keeps it distinguishable from a tool that ran and
            # failed, which the loop needs in order to decide whether to retry.
            raise ToolArgumentError(f"{tool_name} rejected its arguments: {exc}") from exc
        except Exception as exc:  # noqa: BLE001 - boundary: normalise unknown failures
            raise ToolExecutionError(f"{tool_name} failed: {exc}") from exc
        if not isinstance(result, dict):
            raise ToolExecutionError(f"{tool_name} returned {type(result).__name__}, expected dict")
        return result
