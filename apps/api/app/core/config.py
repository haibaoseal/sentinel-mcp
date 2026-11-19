"""Runtime configuration.

Everything a deployment needs to change is here and has a safe default. The
important property is that **an empty ``.env`` is fully functional**: the default
provider needs no key and no network, and every real-world side effect is off.
That is what lets CI and a reviewer run the whole system.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

# Path resolution lives in one place. Having config.py and the eval modules each
# compute the repository root independently is how the knowledge base silently
# stopped loading: the two guesses disagreed by one directory, and the only symptom
# was an agent that answered every policy question with "no actionable steps".
from app.core.paths import (
    REPO_ROOT,
)
from app.core.paths import (
    resolve_config_path as _resolve,
)

__all__ = ["Settings", "get_settings", "reset_settings_cache", "REPO_ROOT"]


class Settings(BaseSettings):
    # ``env_file`` is intentionally a tuple: tests pass ``Settings(_env_file=None)``
    # so that constructing settings explicitly can never be polluted by a
    # developer's local ``.env``. The archived codebase had tests that silently
    # read ``.env``, which meant the suite asserted different defaults on
    # different machines.
    model_config = SettingsConfigDict(
        env_file=(".env",), env_prefix="", case_sensitive=False, extra="ignore"
    )

    app_name: str = "sentinel-mcp"
    app_env: str = "development"
    version: str = "0.2.0"
    log_level: str = "info"

    database_url: str = "sqlite:///./sentinel_mcp.db"
    # Development convenience: create tables from the models on startup. In a
    # real deployment this is False and `alembic upgrade head` is the only way
    # the schema changes. Docker sets it to False.
    auto_create_schema: bool = True

    # --- HTTP service ------------------------------------------------------
    # JSON list of {"key", "tenant", "role", "subject"}. Empty is allowed only
    # outside production, where a single labelled development key is issued so a
    # fresh checkout can be explored; production refuses to start without keys.
    # JSON list of {"key", "tenant", "role", "subject"}. The `SENTINEL_` prefix is
    # the documented deployment name; the unprefixed field is kept for tests and
    # for callers that construct Settings directly.
    sentinel_api_keys_json: str = ""
    api_keys_json: str = ""
    # Per-tenant request budget per minute. In-process; a multi-replica
    # deployment needs a shared limiter (Redis) and the OPERATIONS doc says so.
    rate_limit_per_minute: int = 120
    max_concurrent_tasks: int = 8
    # Optional bearer token required by /metrics. Prometheus usually scrapes
    # over a private network; this is for deployments that cannot.
    metrics_token: str = ""
    log_json: bool = True

    # Optional separation-of-duties guard: when True, the principal who created
    # a task cannot approve its own high-risk tool call.
    enforce_separation_of_duties: bool = False

    # --- tool resilience ---------------------------------------------------
    enable_tool_retries: bool = True
    tool_retry_attempts: int = 2
    tool_retry_base_delay: float = 0.05
    circuit_failure_threshold: int = 3
    circuit_recovery_seconds: float = 15.0

    # --- agent provider ----------------------------------------------------
    # "replay" is deterministic and offline. "llm" uses an OpenAI-compatible
    # endpoint. Anything else is rejected at startup rather than at first use.
    agent_provider: str = "replay"
    llm_api_key: str = ""
    llm_model: str = ""
    llm_base_url: str = ""
    llm_timeout_seconds: float = 60.0
    # Whether the host's HTTP proxy configuration applies to model requests.
    # Default False: a proxy meant for internet traffic is frequently wrong for a
    # local or custom base URL, and the failure -- a bare 502 with an empty body --
    # is indistinguishable from a broken backend.
    llm_use_system_proxy: bool = False
    max_agent_turns: int = 8

    # --- real side effects, all off by default -----------------------------
    enable_real_connectors: bool = False
    enable_real_write_actions: bool = False
    enable_real_destructive_actions: bool = False
    enable_real_external_actions: bool = False

    # --- tool sandbox ------------------------------------------------------
    tool_sandbox_root: str = "./sandbox"
    knowledge_root: str = "./knowledge"
    policy_path: str = ""
    # Optional HMAC key binding the audit chain. Empty means unkeyed, which
    # detects tampering but not a full rewrite from genesis.
    audit_hmac_key: str = ""

    http_allowlist: list[str] = Field(default_factory=lambda: ["api.github.com"])
    http_timeout_seconds: float = 10.0
    # Read-only GitHub access. Absent means the connector serves a labelled fixture,
    # so a fresh checkout demonstrates the governed path with no network and no
    # credential. Read from the environment only; never returned by an API or
    # written into an audit payload.
    github_token: str = ""
    github_timeout_seconds: float = 15.0

    mcp_stdio_servers: str = ""
    mcp_http_servers: str = ""
    # Off by default: starting a third-party server is an explicit deployment
    # decision, not something a service should do because a config string exists.
    enable_mcp_servers: bool = False

    cors_origins: list[str] = Field(
        default_factory=lambda: ["http://localhost:3000", "http://127.0.0.1:3000"]
    )

    # -- helpers ------------------------------------------------------------

    @property
    def is_production(self) -> bool:
        return self.app_env.strip().lower() in {"production", "prod"}

    @property
    def effective_api_keys_json(self) -> str:
        return self.sentinel_api_keys_json.strip() or self.api_keys_json.strip()

    @property
    def sandbox_path(self) -> Path:
        return _resolve(self.tool_sandbox_root)

    @property
    def knowledge_path(self) -> Path:
        return _resolve(self.knowledge_root)

    @property
    def hmac_key_bytes(self) -> bytes | None:
        return self.audit_hmac_key.encode() if self.audit_hmac_key else None

    @property
    def provider(self) -> str:
        return self.agent_provider.strip().lower()

    def runtime_flags(self) -> dict[str, bool]:
        """Flags handed to the policy engine, which fails closed on each."""
        return {
            "real_connectors": self.enable_real_connectors,
            "real_write_actions": self.enable_real_write_actions,
            "real_destructive_actions": self.enable_real_destructive_actions,
            "real_external_actions": self.enable_real_external_actions,
        }

    def llm_configured(self) -> bool:
        return bool(self.llm_api_key and self.llm_model)


@lru_cache
def get_settings() -> Settings:
    return Settings()


def reset_settings_cache() -> None:
    """Test hook: settings are cached, and tests change the environment."""
    get_settings.cache_clear()
