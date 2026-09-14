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
from app.core.errors import SentinelError
from app.governance.firewall import Firewall
from app.policy.engine import PolicyEngine, load_policy_document
from app.providers.base import Provider
from app.providers.replay import ReplayProvider
from app.tools.registry import ToolRegistry
from app.tools.sources.filesystem import FilesystemSandbox, build_filesystem_source
from app.tools.sources.knowledge import build_knowledge_source
from app.tools.sources.maintenance import build_maintenance_source


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
        )
    raise ConfigurationError(f"unknown AGENT_PROVIDER {name!r}; expected 'replay' or 'llm'")


def build_registry(settings: Settings, *, sandbox_root: Path | None = None) -> ToolRegistry:
    sandbox = FilesystemSandbox(sandbox_root or settings.sandbox_path)
    sources = [build_filesystem_source(sandbox), build_maintenance_source(sandbox)]
    knowledge = settings.knowledge_path
    if knowledge.is_dir():
        sources.append(build_knowledge_source(knowledge))
    return ToolRegistry(sources)


def build_runtime(settings: Settings | None = None, *, sandbox_root: Path | None = None) -> Runtime:
    resolved = settings or get_settings()
    policy = load_policy_document(resolved.policy_path or None)
    registry = build_registry(resolved, sandbox_root=sandbox_root)
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
