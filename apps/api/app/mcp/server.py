"""Expose governed tools as an MCP server.

This is the other direction of the gateway. Instead of an agent calling out to
MCP servers, an *external* MCP client -- Cursor, Claude Desktop, another agent
framework -- connects here and sees this runtime's tools. The point is that the
client cannot reach a tool any other way: every call it makes is routed through
the firewall, so policy, approval and the audit chain apply to a foreign client
exactly as they apply to the built-in loop.

That property is the reason this file contains no execution logic at all. Each
tool handler builds a ``ToolRequest`` and calls the firewall. If a handler ever
called a tool source directly, an external client would have an ungoverned path
into the system.

Approval semantics over a synchronous protocol
----------------------------------------------
MCP tool calls expect a result. When policy returns ``require_approval`` there is
nothing to return yet, so the handler answers with a structured "held" result and
``is_error=False``: it is not a failure, it is a governance outcome, and the
external client must report it as such rather than as a successful action. The
call is recorded as an ``ApprovalRequest`` -- the same queue
``python -m app.approvals.cli`` reads -- so a reviewer can approve or reject it.

What the client sees either way is a hold: a decision executes the call out of
band under the reviewer's identity, so this client does not receive the result on
the call it made. Reporting the hold as a success would be a lie; reporting it as
a failure would invite a retry of a gated action.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from app.core.contracts import ToolRequest
from app.db.models import AgentTask
from app.governance.firewall import Firewall

GOVERNED_PREFIX = "sentinel_"


class GovernedMCPServer:
    """Wraps a ``Firewall`` and publishes its registry as MCP tools.

    Construction is deliberately explicit about the session factory: the server
    needs a database session per call in order to write its audit record, and a
    long-lived shared session would let a failed call poison later ones.
    """

    def __init__(
        self,
        *,
        firewall: Firewall,
        session_factory,
        name: str = "sentinel-mcp",
        expose_prefix: bool = True,
        actor_id: str = "mcp-client",
    ) -> None:
        self.firewall = firewall
        self.session_factory = session_factory
        self.name = name
        self.expose_prefix = expose_prefix
        self.actor_id = actor_id

    # -- descriptions -------------------------------------------------------

    def tool_descriptors(self) -> list[dict[str, Any]]:
        """Describe tools for publication, including their governance metadata.

        The risk level and whether approval is required are published on purpose.
        An external client that can see which tools are gated can warn its user
        before calling; hiding the gating would make the refusal look arbitrary.
        """
        described: list[dict[str, Any]] = []
        for descriptor in self.firewall.registry.descriptors():
            exposed = self._exposed_name(descriptor.name)
            described.append(
                {
                    "name": exposed,
                    "upstream_name": descriptor.name,
                    "description": self._decorate(descriptor),
                    "input_schema": descriptor.argument_schema
                    or {"type": "object", "properties": {}},
                    "governance": {
                        "action_type": descriptor.action_type,
                        "risk_level": descriptor.risk_level,
                        "requires_approval": descriptor.requires_approval,
                        "source": descriptor.source,
                    },
                }
            )
        return described

    def _decorate(self, descriptor) -> str:
        note = (
            f"[governed: action={descriptor.action_type}, risk={descriptor.risk_level}"
            f"{', approval required' if descriptor.requires_approval else ''}] "
        )
        return note + (descriptor.description or "")

    def _exposed_name(self, upstream: str) -> str:
        # Slashes and dots are legal in MCP tool names but some hosts are fussy,
        # so the published name is flattened. The mapping is recorded on every
        # call so the audit log still names the real tool.
        if not self.expose_prefix:
            return upstream
        return GOVERNED_PREFIX + upstream.replace(".", "__").replace("/", "__")

    def _upstream_name(self, exposed: str) -> str | None:
        for descriptor in self.firewall.registry.descriptors():
            if self._exposed_name(descriptor.name) == exposed:
                return descriptor.name
        return None

    # -- execution ----------------------------------------------------------

    def call(self, exposed_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Route one external call through governance."""
        upstream = self._upstream_name(exposed_name)
        if upstream is None:
            return {
                "status": "unknown_tool",
                "tool": exposed_name,
                "error": f"no governed tool is published as {exposed_name!r}",
            }

        descriptor = self.firewall.registry.describe(upstream)
        session: Session = self.session_factory()
        try:
            task = AgentTask(
                title=f"MCP client call: {upstream}",
                user_request=json.dumps(arguments, ensure_ascii=False, default=str)[:2000],
                agent_type="mcp-client",
                status="running",
            )
            session.add(task)
            session.flush()

            request = ToolRequest(
                task_id=task.id,
                tool_name=upstream,
                action_type=descriptor.action_type if descriptor else "unknown",
                resource_type=descriptor.resource_type if descriptor else None,
                arguments=arguments if isinstance(arguments, dict) else {},
                requested_by="mcp-client",
                user_id=self.actor_id,
            )
            result = self.firewall.execute(request, session=session)
            session.commit()

            return self._render(exposed_name, upstream, result, task_id=task.id)
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def _render(self, exposed: str, upstream: str, result, *, task_id: str) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "tool": exposed,
            "upstream_tool": upstream,
            "task_id": task_id,
            "status": result.status,
        }
        if result.status == "success":
            payload["data"] = result.data
            payload["source"] = result.source
        elif result.status == "waiting_approval":
            # Not an error: the call is recorded and awaiting a human. Saying
            # "failed" would invite the client to retry a gated action.
            payload["held_for_approval"] = True
            payload["reason"] = (result.data or {}).get("risk_reasons") or []
            payload["approval_id"] = (result.data or {}).get("approval_id")
            payload["note"] = (
                "This action requires human approval and has NOT been executed. "
                "It is queued as a pending approval; a reviewer's decision runs it "
                "out of band, so this call will not return its result."
            )
        elif result.status == "blocked":
            payload["blocked_by_policy"] = True
            payload["reason"] = result.error
            payload["note"] = "Policy refused this action. Nothing was executed."
        else:
            payload["error"] = result.error
        return payload


def _handler_for(governed: GovernedMCPServer, upstream: str, exposed: str, schema: dict):
    """Build a handler whose signature matches the tool's published schema.

    The SDK derives the tool's argument model from the handler's *signature*, so a
    ``handler(**kwargs)`` wrapper is wrong: it makes the SDK demand a literal
    ``kwargs`` field and every real call fails validation. The signature is set
    explicitly from the schema -- ``__signature__`` gives the SDK a truthful view
    without generating source code.
    """
    import inspect

    properties: dict[str, Any] = (schema or {}).get("properties") or {}
    required = set((schema or {}).get("required") or [])

    def handler(**kwargs: Any) -> dict[str, Any]:
        return governed.call(exposed, kwargs)

    parameters = []
    for name, definition in properties.items():
        annotation: Any = str
        kind = (definition or {}).get("type")
        if kind == "integer":
            annotation = int
        elif kind == "number":
            annotation = float
        elif kind == "boolean":
            annotation = bool
        elif kind == "array":
            annotation = list
        elif kind == "object":
            annotation = dict
        # Optional parameters need a default, or the SDK's model rejects a call
        # that omitted them.
        default = (
            inspect.Parameter.empty if name in required else (definition or {}).get("default", None)
        )
        parameters.append(
            inspect.Parameter(
                name, inspect.Parameter.KEYWORD_ONLY, default=default, annotation=annotation
            )
        )

    handler.__signature__ = inspect.Signature(parameters)  # type: ignore[attr-defined]
    handler.__name__ = upstream.replace(".", "_")
    return handler


def build_server_module(
    *,
    firewall: Firewall,
    session_factory,
    name: str = "sentinel-mcp",
    repo_root: Path | None = None,
):
    """Create an ``MCPServer`` with the governed tools registered.

    Imports the SDK lazily so that importing this module does not require the MCP
    package -- the gateway's outbound half has no such dependency, and CI for one
    half should not depend on the other half's optional dependency.
    """
    from mcp.server import MCPServer

    server = MCPServer(
        name=name,
        title="sentinel-mcp governed tool gateway",
        instructions=(
            "Every tool here is mediated by a policy engine, may require human "
            "approval, and is written to a hash-chained audit log. A result with "
            "status 'waiting_approval' has NOT been executed."
        ),
    )
    governed = GovernedMCPServer(firewall=firewall, session_factory=session_factory, name=name)

    for spec in governed.tool_descriptors():
        server.add_tool(
            _handler_for(governed, spec["upstream_name"], spec["name"], spec["input_schema"]),
            name=spec["name"],
            description=spec["description"],
        )

    return server, governed
