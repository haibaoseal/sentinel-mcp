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

REPO_ROOT = Path(__file__).resolve().parents[3]


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
    version: str = "0.1.0"
    log_level: str = "info"

    database_url: str = "sqlite:///./sentinel_mcp.db"

    # --- agent provider ----------------------------------------------------
    # "replay" is deterministic and offline. "llm" uses an OpenAI-compatible
    # endpoint. Anything else is rejected at startup rather than at first use.
    agent_provider: str = "replay"
    llm_api_key: str = ""
    llm_model: str = ""
    llm_base_url: str = ""
    llm_timeout_seconds: float = 60.0
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

    mcp_stdio_servers: str = ""
    mcp_http_servers: str = ""

    cors_origins: list[str] = Field(
        default_factory=lambda: ["http://localhost:3000", "http://127.0.0.1:3000"]
    )

    # -- helpers ------------------------------------------------------------

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


def _resolve(value: str) -> Path:
    """Resolve a configured path against the repository root.

    Absolute paths are honoured as-is. A path that is only *accidentally*
    absolute -- ``/sandbox`` or ``\\sandbox`` on Windows -- is treated as
    relative to the repository root, because that is what a config author
    almost certainly meant and silently reading ``C:\\sandbox`` would be a
    confusing way to fail.
    """
    raw = value.strip()
    path = Path(raw).expanduser()
    if path.is_absolute():
        drive, tail = path.drive, str(path)[len(path.drive) :]
        # A bare root like "/sandbox" or "\sandbox" has no meaningful drive
        # anchor, so treat it as repo-relative.
        if tail.startswith(("/", "\\")) and not drive:
            path = REPO_ROOT / tail.lstrip("/\\")
        else:
            return path.resolve()
    return (REPO_ROOT / path).resolve()


@lru_cache
def get_settings() -> Settings:
    return Settings()


def reset_settings_cache() -> None:
    """Test hook: settings are cached, and tests change the environment."""
    get_settings.cache_clear()
