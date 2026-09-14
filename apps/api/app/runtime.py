"""Assemble a runnable agent from configuration.

One function builds the whole graph so that every entry point -- CLI, HTTP API,
evaluation harness -- governs identically. If a caller could assemble its own
registry and skip the firewall, the boundary would be decorative.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from app.agent.loop import AgentLoop
from app.core.config import Settings, get_settings
from app.core.contracts import ToolSource
from app.core.errors import SentinelError
from app.governance.firewall import Firewall
from app.mcp.client import MCPClient, MCPServerSpec, MCPToolSource
from app.policy.engine import PolicyEngine, load_policy_document
from app.providers.base import Provider
from app.providers.replay import ReplayProvider
from app.tools.registry import ToolRegistry
from app.tools.sources.filesystem import FilesystemSandbox, build_filesystem_source
from app.tools.sources.github import build_github_source
from app.tools.sources.http import build_http_source
from app.tools.sources.knowledge import build_knowledge_source
from app.tools.sources.maintenance import build_maintenance_source
from app.tools.sources.sql import build_sql_source


class ConfigurationError(SentinelError):
    code = "CONFIGURATION_ERROR"
    http_status = 500


@dataclass
class Runtime:
    settings: Settings
    registry: ToolRegistry
    firewall: Firewall
    provider: Provider
    loop: AgentLoop


def build_provider(settings: Settings) -> Provider:
    name = settings.provider
    if name == "replay":
        return ReplayProvider()
    if name in {"llm", "openai"}:
        if not settings.llm_configured():
            # Fail with a sentence that says what to do, rather than an auth
            # error from a backend the operator cannot see.
            raise ConfigurationError(
                "AGENT_PROVIDER=llm requires LLM_API_KEY and LLM_MODEL; "
                "set them in .env or use AGENT_PROVIDER=replay"
            )
        from app.providers.llm import DEFAULT_BASE_URL, LLMProvider

        return LLMProvider(
            api_key=settings.llm_api_key,
            model=settings.llm_model,
            base_url=settings.llm_base_url or DEFAULT_BASE_URL,
            timeout=settings.llm_timeout_seconds,
            use_system_proxy=settings.llm_use_system_proxy,
        )
    raise ConfigurationError(f"unknown AGENT_PROVIDER {name!r}; expected 'replay' or 'llm'")


def parse_mcp_specs(settings: Settings) -> list[MCPServerSpec]:
    """Build MCP server specs from configuration.

    Two syntaxes, both comma-separated:

    - stdio: ``name=command arg1 arg2``  e.g. ``demo=python mcp_servers/demo_server.py stdio``
    - http:  ``name=url``                e.g. ``remote=http://127.0.0.1:8765/mcp``

    Governance mapping is deliberately *not* expressible here. Which remote tools
    may run unattended is decided in the policy file, so authorising a remote
    tool is a reviewable change rather than a command-line flag.
    """
    specs: list[MCPServerSpec] = []

    for entry in _split_entries(settings.mcp_stdio_servers):
        name, _, remainder = entry.partition("=")
        if not name.strip() or not remainder.strip():
            raise ConfigurationError(f"invalid MCP_STDIO_SERVERS entry: {entry!r}")
        parts = remainder.split()
        specs.append(
            MCPServerSpec(
                name=name.strip(),
                transport="stdio",
                command=parts[0],
                args=parts[1:],
            )
        )

    for entry in _split_entries(settings.mcp_http_servers):
        name, _, url = entry.partition("=")
        if not name.strip() or not url.strip():
            raise ConfigurationError(f"invalid MCP_HTTP_SERVERS entry: {entry!r}")
        specs.append(MCPServerSpec(name=name.strip(), transport="http", url=url.strip()))

    return specs


def _split_entries(value: str) -> list[str]:
    return [entry.strip() for entry in value.split(",") if entry.strip()]


def build_registry(
    settings: Settings,
    *,
    sandbox_root: Path | None = None,
    enable_mcp: bool = False,
) -> ToolRegistry:
    sandbox = FilesystemSandbox(sandbox_root or settings.sandbox_path)
    # Local sources first, so a remote server cannot take over a local name.
    sources: list[ToolSource] = [
        build_filesystem_source(sandbox),
        build_maintenance_source(sandbox),
        build_sql_source(sandbox.root / "commerce.db"),
        build_http_source(settings.http_allowlist),
        build_github_source(token=settings.github_token or None),
    ]
    knowledge = settings.knowledge_path
    if knowledge.is_dir():
        sources.append(build_knowledge_source(knowledge))

    if enable_mcp:
        specs = parse_mcp_specs(settings)
        if specs:
            sources.append(MCPToolSource([MCPClient(spec) for spec in specs]))

    return ToolRegistry(sources)


def build_runtime(
    settings: Settings | None = None,
    *,
    sandbox_root: Path | None = None,
    enable_mcp: bool = False,
) -> Runtime:
    resolved = settings or get_settings()
    policy = load_policy_document(resolved.policy_path or None)
    registry = build_registry(resolved, sandbox_root=sandbox_root, enable_mcp=enable_mcp)
    firewall = Firewall(
        registry=registry,
        policy_engine=PolicyEngine(policy),
        runtime_flags=resolved.runtime_flags(),
        hmac_key=resolved.hmac_key_bytes,
    )
    provider = build_provider(resolved)
    loop = AgentLoop(provider=provider, firewall=firewall, max_turns=resolved.max_agent_turns)
    return Runtime(
        settings=resolved, registry=registry, firewall=firewall, provider=provider, loop=loop
    )
