"""MCP client: serve remote tools through the same governance path as local ones.

The security reasoning that shapes this file
-------------------------------------------
An MCP server is an *untrusted* dependency. It is a separate process or a remote
endpoint that chooses its own tool names, descriptions and schemas, and can
change all of them after we began trusting it. Two consequences are enforced here
rather than merely documented:

1. **A discovered tool is not a trusted tool.** Descriptors become
   ``action_type="unknown"`` unless an operator maps them explicitly, and the
   policy engine treats an unknown tool as ``require_approval``. So the default
   effect of plugging in a new MCP server is that its tools are *visible and
   reviewable* but cannot run unattended. There is deliberately no wildcard that
   grants a whole server.

2. **A server must not be able to shadow a local tool.** Names are namespaced
   ``mcp.<server>.<tool>`` and the registry refuses duplicates, so a server that
   advertises ``fs_read`` cannot quietly take over the local one.

Concurrency note worth reading
------------------------------
MCP transports are async and use anyio task groups. A task group must be entered
and exited by the *same task*, so the transport and the session cannot be opened
in one coroutine and used from another -- doing that produced a session that
reported success, then listed zero tools, and refused to close. This class
therefore runs one long-lived worker task that owns the whole connection, and
communicates with it over queues. Asynchrony is confined to this file; the
policy engine, firewall and audit log stay synchronous on purpose, because a
governance decision should not depend on an event loop being driven correctly.
"""

from __future__ import annotations

import asyncio
import re
import threading
from dataclasses import dataclass, field
from typing import Any, Literal

from app.core.contracts import ActionType, RiskLevel, ToolDescriptor
from app.core.errors import (
    MCPServerError,
    MCPToolNotAllowedError,
    ToolArgumentError,
    ToolExecutionError,
)

Transport = Literal["stdio", "http"]

# Environment variables an MCP server may inherit. An allow-list, not a
# deny-list: a subprocess that inherits the parent's environment receives every
# credential the operator happens to have exported, which is not what "start a
# tool server" should imply.
ENV_ALLOWLIST = ("PATH", "HOME", "USERPROFILE", "SYSTEMROOT", "TEMP", "TMP", "LANG", "LC_ALL")

# A remote tool description is the one field a server controls that is copied into
# the model's prompt, so it is bounded and flattened before it gets there.
MAX_DESCRIPTION_CHARS = 1000

# A result is returned to the model *and* written into the hash-chained audit
# payload, so an unbounded one is a memory and audit DoS rather than a convenience.
MAX_REMOTE_RESULT_BYTES = 512 * 1024


def clean_remote_description(text: str) -> str:
    """Bound and flatten a description supplied by a remote server.

    Two things are removed beyond the length cap. Control characters and newlines, so
    a description cannot fake a message boundary in the prompt. And the
    ``[governed: ...]`` prefix this codebase publishes on its own outbound tools, so a
    hostile server cannot make its description read as though this runtime wrote it.
    """
    flattened = " ".join(str(text).split())
    without_prefix = re.sub(r"\[governed:[^\]]*\]", "", flattened, flags=re.IGNORECASE)
    return without_prefix[:MAX_DESCRIPTION_CHARS]


@dataclass(frozen=True)
class MCPServerSpec:
    """How to reach one MCP server, plus its governance mapping."""

    name: str
    transport: Transport
    command: str = ""
    args: list[str] = field(default_factory=list)
    cwd: str | None = None
    env: dict[str, str] = field(default_factory=dict)
    url: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    # Tools not listed here are registered as `unknown`, which the policy engine
    # escalates to require_approval.
    tool_actions: dict[str, ActionType] = field(default_factory=dict)
    tool_risks: dict[str, RiskLevel] = field(default_factory=dict)
    startup_timeout: float = 45.0
    call_timeout: float = 60.0
    # Whether the host's HTTP proxy configuration applies to this server.
    #
    # Default False, and the default matters. A proxy configured for internet
    # traffic is frequently wrong for a local endpoint: on the machine this was
    # built on, a system proxy at 127.0.0.1:7897 answered localhost MCP requests
    # with 502 and an empty body while the MCP server logged nothing at all --
    # which looks exactly like a broken server. Set True only when a *remote* MCP
    # server genuinely has to be reached through a proxy.
    use_system_proxy: bool = False

    def validate(self) -> None:
        if not self.name or not all(ch.isalnum() or ch in "-_" for ch in self.name):
            raise MCPServerError(f"invalid MCP server name: {self.name!r}")
        if self.transport == "stdio" and not self.command:
            raise MCPServerError(f"MCP server {self.name!r} needs a command for stdio")
        if self.transport == "http" and not self.url:
            raise MCPServerError(f"MCP server {self.name!r} needs a url for HTTP")

    def child_environment(self) -> dict[str, str]:
        import os

        env = {key: os.environ[key] for key in ENV_ALLOWLIST if key in os.environ}
        env.update(self.env)
        return env


@dataclass
class _ToolRecord:
    remote_name: str
    qualified_name: str
    description: str
    input_schema: dict[str, Any]
    action_type: ActionType
    risk_level: RiskLevel


class MCPClient:
    """A long-lived connection to one MCP server.

    The connection is opened once, so a stdio subprocess is not respawned per
    call. All requests are serialised through the worker task, because an MCP
    session is a single stateful stream and interleaving two calls on it is a
    protocol error.
    """

    def __init__(self, spec: MCPServerSpec) -> None:
        spec.validate()
        self.spec = spec
        self._records: dict[str, _ToolRecord] = {}
        self._descriptors: dict[str, ToolDescriptor] = {}
        self._session: Any = None
        self._ready = threading.Event()
        self._stop = threading.Event()
        self._failure: BaseException | None = None
        self._thread: threading.Thread | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._requests: asyncio.Queue | None = None
        self._start_lock = threading.Lock()

    # -- lifecycle ----------------------------------------------------------

    def connect(self) -> None:
        with self._start_lock:
            if self._thread is not None and self._thread.is_alive():
                # A live thread is not the same thing as a working connection. When
                # an earlier attempt failed, its worker is still winding down, and
                # every later connect() used to return *success* against a dead
                # session because only thread liveness was consulted.
                if self._failure is not None:
                    raise MCPServerError(
                        f"MCP server {self.spec.name!r} is not connected: {self._failure}"
                    ) from self._failure
                # Another caller is starting or using this connection: wait for its
                # verdict instead of starting a second worker over the top of it.
                if not self._ready.wait(timeout=self.spec.startup_timeout):
                    raise MCPServerError(
                        f"MCP server {self.spec.name!r} did not become ready within "
                        f"{self.spec.startup_timeout}s"
                    )
                if self._failure is not None:
                    raise MCPServerError(
                        f"MCP server {self.spec.name!r} failed to start: {self._failure}"
                    ) from self._failure
                return

            self._ready.clear()
            self._stop.clear()
            self._failure = None
            self._thread = threading.Thread(
                target=self._serve,
                name=f"mcp-{self.spec.name}",
                daemon=True,
            )
            self._thread.start()

        if not self._ready.wait(timeout=self.spec.startup_timeout):
            raise MCPServerError(
                f"MCP server {self.spec.name!r} did not become ready within "
                f"{self.spec.startup_timeout}s"
            )
        if self._failure is not None:
            raise MCPServerError(
                f"MCP server {self.spec.name!r} failed to start: {self._failure}"
            ) from self._failure

    def _serve(self) -> None:
        """Owns the connection for its whole life: one task, one task group."""
        loop = asyncio.new_event_loop()
        self._loop = loop
        asyncio.set_event_loop(loop)
        self._requests = asyncio.Queue()
        try:
            loop.run_until_complete(self._session_worker())
        except BaseException as exc:  # noqa: BLE001 - reported through _failure
            self._failure = exc
        finally:
            self._ready.set()
            try:
                loop.close()
            except Exception:  # noqa: BLE001
                pass

    async def _session_worker(self) -> None:
        from contextlib import AsyncExitStack

        from mcp import ClientSession

        try:
            async with AsyncExitStack() as stack:
                try:
                    read, write = await stack.enter_async_context(self._transport_context())
                except Exception as exc:
                    self._failure = exc
                    self._ready.set()
                    return

                session = ClientSession(read, write)
                try:
                    await stack.enter_async_context(session)
                    await session.initialize()
                except Exception as exc:
                    self._failure = exc
                    self._ready.set()
                    return

                # Publish the session and signal readiness *before* serving, so
                # the caller never observes "ready" with no session attached.
                self._session = session
                self._ready.set()
                await self._request_loop(session)
        finally:
            self._session = None

    async def _request_loop(self, session) -> None:
        assert self._requests is not None
        while not self._stop.is_set():
            try:
                request = await asyncio.wait_for(self._requests.get(), timeout=0.25)
            except TimeoutError:
                continue
            kind, payload, future = request
            if future.cancelled():
                continue
            try:
                if kind == "list":
                    result = await session.list_tools()
                    future.set_result(list(result.tools))
                elif kind == "call":
                    name, arguments = payload
                    future.set_result(await session.call_tool(name, arguments))
                else:  # pragma: no cover - internal misuse
                    future.set_exception(MCPServerError(f"unknown request kind {kind!r}"))
            except Exception as exc:  # noqa: BLE001 - relayed to the caller
                future.set_exception(exc)

    def _transport_context(self):
        if self.spec.transport == "stdio":
            from mcp import StdioServerParameters
            from mcp.client.stdio import stdio_client

            return stdio_client(
                StdioServerParameters(
                    command=self.spec.command,
                    args=list(self.spec.args),
                    cwd=self.spec.cwd,
                    env=self.spec.child_environment(),
                )
            )
        from mcp.client.streamable_http import streamable_http_client

        return streamable_http_client(self.spec.url, http_client=self._http_client())

    def _http_client(self):
        """HTTP client for the Streamable HTTP transport.

        Constructed explicitly rather than letting the SDK build one, because the
        SDK default honours the host's proxy environment -- see the note on
        ``MCPServerSpec.use_system_proxy`` for why that silently breaks local
        endpoints.

        ``trust_env`` is passed to the constructor because it is a read-only
        property on the client once built.
        """
        from mcp.client.streamable_http import create_mcp_http_client

        if self.spec.use_system_proxy:
            return create_mcp_http_client(headers=dict(self.spec.headers) or None)

        import httpx2

        return httpx2.AsyncClient(
            headers=dict(self.spec.headers) or None,
            trust_env=False,
            timeout=httpx2.Timeout(30.0, read=self.spec.call_timeout),
        )

    def close(self) -> None:
        self._stop.set()
        thread = self._thread
        if thread is not None:
            thread.join(timeout=self.spec.call_timeout)
        self._thread = None
        self._loop = None
        self._requests = None
        self._records.clear()

    # -- request plumbing ---------------------------------------------------

    def _submit(self, kind: str, payload: Any, *, timeout: float) -> Any:
        loop = self._loop
        queue = self._requests
        if loop is None or queue is None or not loop.is_running():
            raise MCPServerError(f"MCP server {self.spec.name!r} is not connected")
        future = asyncio.run_coroutine_threadsafe(self._enqueue(queue, kind, payload), loop)
        try:
            return future.result(timeout=timeout)
        except TimeoutError as exc:
            # Deliberately *not* cancelling the future. The request is already in
            # flight; cancelling it made the worker raise InvalidStateError when the
            # late result arrived, which unwound the session and killed the child
            # process -- so one slow call destroyed the whole connection rather than
            # just failing. The result is dropped instead and the caller is told.
            raise MCPServerError(f"MCP {kind} on {self.spec.name!r} exceeded {timeout}s") from exc

    @staticmethod
    async def _enqueue(queue: asyncio.Queue, kind: str, payload: Any) -> Any:
        loop = asyncio.get_running_loop()
        future: asyncio.Future = loop.create_future()
        await queue.put((kind, payload, future))
        return await future

    # -- discovery ----------------------------------------------------------

    def discover(self) -> list[ToolDescriptor]:
        self.connect()
        if self._failure is not None:
            raise MCPServerError(
                f"MCP server {self.spec.name!r} failed: {self._failure}"
            ) from self._failure
        if self._records:
            return list(self._descriptors.values())
        try:
            tools = self._submit("list", None, timeout=self.spec.startup_timeout)
        except MCPServerError:
            raise
        except Exception as exc:
            raise MCPServerError(
                f"MCP server {self.spec.name!r} refused to list tools: {exc}"
            ) from exc
        return self._map_tools(tools)

    def _map_tools(self, tools: list[Any]) -> list[ToolDescriptor]:
        descriptors: list[ToolDescriptor] = []
        for tool in tools:
            remote_name = getattr(tool, "name", None)
            if not remote_name or not isinstance(remote_name, str):
                raise MCPToolNotAllowedError(
                    f"MCP server {self.spec.name!r} advertised a tool without a name"
                )
            if any(ch in remote_name for ch in ("/", "\\", " ", "\x00")):
                # Refused rather than sanitised: silently rewriting a name would
                # make the audit log disagree with the server's own view of what
                # it ran.
                raise MCPToolNotAllowedError(
                    f"MCP server {self.spec.name!r} advertised an unsafe tool name: {remote_name!r}"
                )

            qualified = f"mcp.{self.spec.name}.{remote_name}"
            action: ActionType = self.spec.tool_actions.get(remote_name, "unknown")
            risk: RiskLevel = self.spec.tool_risks.get(remote_name, "high")
            self._records[qualified] = _ToolRecord(
                remote_name=remote_name,
                qualified_name=qualified,
                description=clean_remote_description(getattr(tool, "description", "") or ""),
                input_schema=getattr(tool, "input_schema", None)
                or {"type": "object", "properties": {}},
                action_type=action,
                risk_level=risk,
            )
            descriptors.append(
                ToolDescriptor(
                    name=qualified,
                    description=self._records[qualified].description,
                    action_type=action,
                    resource_type="mcp",
                    risk_level=risk,
                    requires_approval=action
                    in {"write", "destructive", "external_send", "financial"},
                    argument_schema=self._records[qualified].input_schema,
                    source=f"mcp:{self.spec.transport}:{self.spec.name}",
                )
            )
        if descriptors and not hasattr(self, "_descriptors"):
            self._descriptors: dict[str, ToolDescriptor] = {}
        for descriptor in descriptors:
            self._descriptors[descriptor.name] = descriptor
        return descriptors

    # -- execution ----------------------------------------------------------

    def execute(self, qualified_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Call one remote tool. Reached only via the registry, i.e. via the firewall."""
        record = self._records.get(qualified_name)
        if record is None:
            raise MCPToolNotAllowedError(
                f"tool {qualified_name!r} was not advertised by server {self.spec.name!r}"
            )
        if not isinstance(arguments, dict):
            raise ToolArgumentError("MCP tool arguments must be an object")
        self.connect()

        try:
            result = self._submit(
                "call", (record.remote_name, arguments), timeout=self.spec.call_timeout
            )
        except MCPServerError:
            raise
        except Exception as exc:
            raise MCPServerError(
                f"MCP server {self.spec.name!r} failed calling {record.remote_name!r}: {exc}"
            ) from exc
        return self._unpack(record, result)

    def _unpack(self, record: _ToolRecord, result: Any) -> dict[str, Any]:
        """Normalise an MCP result into the dict shape tools return here."""
        content_parts: list[str] = []
        for block in getattr(result, "content", None) or []:
            text = getattr(block, "text", None)
            if isinstance(text, str):
                content_parts.append(text)
        text = "\n".join(content_parts)
        if len(text.encode("utf-8")) > MAX_REMOTE_RESULT_BYTES:
            # Bounded because this text is handed to the model *and* written into the
            # hash-chained audit payload; an unbounded result is a memory and audit
            # DoS from a server the operator only half trusts.
            raise ToolExecutionError(
                f"remote tool {record.qualified_name} returned "
                f"{len(text.encode('utf-8'))} bytes, above the "
                f"{MAX_REMOTE_RESULT_BYTES} byte limit"
            )
        structured = getattr(result, "structured_content", None)
        is_error = bool(getattr(result, "is_error", False))

        # A tool that reports an error payload instead of raising still counts as
        # a failure. Converting it to success is how a broken remote tool would
        # otherwise produce a confident answer.
        error_marker = None
        if isinstance(structured, dict) and "error" in structured:
            error_marker = str(structured["error"])

        if is_error or error_marker:
            raise ToolExecutionError(
                f"remote tool {record.qualified_name} reported an error: "
                f"{error_marker or text or 'no detail'}"
            )

        payload: dict[str, Any] = {
            "tool": record.qualified_name,
            "server": self.spec.name,
            "transport": self.spec.transport,
        }
        if isinstance(structured, dict):
            payload["structured"] = structured
        if text:
            payload["text"] = text
        if not text and not isinstance(structured, dict):
            raise ToolExecutionError(
                f"remote tool {record.qualified_name} returned no usable content"
            )
        return payload

    # -- introspection ------------------------------------------------------

    def described_tools(self) -> list[str]:
        return sorted(self._records)

    def remote_name_for(self, qualified_name: str) -> str | None:
        record = self._records.get(qualified_name)
        return record.remote_name if record else None


class MCPToolSource:
    """A ``ToolSource`` backed by one or more MCP servers.

    Presents remote tools under the same protocol as local ones, which is what
    lets the firewall, policy engine and approval workflow stay unaware that MCP
    exists at all.
    """

    def __init__(self, clients: list[MCPClient]) -> None:
        self._clients = clients
        self.name = "mcp"
        #: Servers that could not be reached during discovery, as
        #: ``"<server>: <reason>"``. Populated by ``descriptors()`` and reported rather
        #: than raised, so a broken third-party server degrades the tool list instead
        #: of the runtime.
        self.failures: list[str] = []

    def descriptors(self) -> list[ToolDescriptor]:
        descriptors: list[ToolDescriptor] = []
        seen: set[str] = set()
        self.failures = []
        for client in self._clients:
            try:
                discovered = client.discover()
            except (MCPServerError, MCPToolNotAllowedError) as exc:
                # One unreachable or misbehaving server must not take the runtime down.
                # The registry is built from every source at once, so an exception here
                # used to fail startup for the local tools as well -- a third-party
                # server that advertises a tool named `evil/x` could stop the agent.
                self.failures.append(f"{client.spec.name}: {exc}")
                continue
            for descriptor in discovered:
                if descriptor.name in seen:
                    raise MCPToolNotAllowedError(
                        f"two MCP servers advertised the same tool name: {descriptor.name}"
                    )
                seen.add(descriptor.name)
                descriptors.append(descriptor)
        return descriptors

    def execute(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        for client in self._clients:
            if client.remote_name_for(tool_name) is not None:
                return client.execute(tool_name, arguments)
        raise MCPToolNotAllowedError(f"no MCP server advertises tool {tool_name!r}")

    def close(self) -> None:
        for client in self._clients:
            client.close()
