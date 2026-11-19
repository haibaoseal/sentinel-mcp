"""Authentication and role checks for the HTTP service.

The model is deliberately small enough to audit:

- a key maps to exactly one tenant, one role and one subject;
- the tenant is taken from the key, never from a request body or query string;
- a caller with a lower role can never reach a higher-role route;
- an unknown or revoked key gets the same 401 response, so the endpoint is not
  an oracle for which keys exist.

Keys live in `SENTINEL_API_KEYS_JSON`, not in the database, because bootstrapping
a credential store before anyone can authenticate is how a "temporary" admin key
ends up in production.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.core.config import Settings
from app.core.errors import ConfigurationError
from app.observability.logging import get_logger

logger = get_logger("sentinel.auth")

ROLE_ORDER: dict[str, int] = {"viewer": 1, "operator": 2, "approver": 3, "admin": 4}

_bearer = HTTPBearer(auto_error=False)


@dataclass(frozen=True)
class ApiKey:
    key: str
    tenant: str
    role: str
    subject: str

    @property
    def fingerprint(self) -> str:
        return hashlib.sha256(self.key.encode()).hexdigest()[:12]


@dataclass(frozen=True)
class Principal:
    tenant_id: str
    role: str
    subject: str
    key_fingerprint: str

    def at_least(self, role: str) -> bool:
        return ROLE_ORDER.get(self.role, 0) >= ROLE_ORDER[role]


def load_api_keys(settings: Settings) -> list[ApiKey]:
    configured = settings.effective_api_keys_json
    if configured:
        try:
            raw = json.loads(configured)
        except json.JSONDecodeError as exc:
            raise ConfigurationError(f"SENTINEL_API_KEYS_JSON is not valid JSON: {exc}") from exc
        if not isinstance(raw, list) or not raw:
            raise ConfigurationError("SENTINEL_API_KEYS_JSON must be a non-empty JSON list")
        keys: list[ApiKey] = []
        seen_keys: set[str] = set()
        for index, item in enumerate(raw):
            if not isinstance(item, dict):
                raise ConfigurationError(f"api key #{index} must be an object")
            try:
                key = str(item["key"])
                tenant = str(item["tenant"])
                role = str(item["role"])
                subject = str(item["subject"])
            except KeyError as exc:
                raise ConfigurationError(f"api key #{index} is missing {exc.args[0]!r}") from exc
            if not key or len(key) < 8:
                raise ConfigurationError(f"api key #{index} is too short (min 8 characters)")
            if key in seen_keys:
                raise ConfigurationError(f"api key #{index} duplicates an earlier key")
            seen_keys.add(key)
            if role not in ROLE_ORDER:
                raise ConfigurationError(
                    f"api key #{index} has unknown role {role!r}; "
                    f"expected one of {sorted(ROLE_ORDER)}"
                )
            if not tenant or not subject:
                raise ConfigurationError(f"api key #{index} needs a tenant and a subject")
            keys.append(ApiKey(key=key, tenant=tenant, role=role, subject=subject))
        return keys

    if settings.is_production:
        raise ConfigurationError(
            "SENTINEL_API_KEYS_JSON is required when APP_ENV=production; "
            "the development key is never issued in production"
        )

    logger.warning(
        "no SENTINEL_API_KEYS_JSON configured; issuing the development admin key "
        "(tenant=dev, role=admin). Never use this outside local development."
    )
    return [ApiKey(key="dev-admin-key", tenant="dev", role="admin", subject="dev-admin")]


def _principal_from_credentials(
    credentials: HTTPAuthorizationCredentials | None, keys: list[ApiKey]
) -> Principal:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": "UNAUTHENTICATED", "message": "Bearer token required"},
            headers={"WWW-Authenticate": "Bearer"},
        )
    presented = credentials.credentials
    matched: ApiKey | None = None
    for key in keys:
        # compare_digest on every candidate, without early exit on the first
        # match or mismatch, keeps the loop's timing independent of which key matched.
        if hmac.compare_digest(presented, key.key):
            matched = key
    if matched is not None:
        return Principal(
            tenant_id=matched.tenant,
            role=matched.role,
            subject=matched.subject,
            key_fingerprint=matched.fingerprint,
        )
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail={"code": "UNAUTHENTICATED", "message": "invalid API key"},
        headers={"WWW-Authenticate": "Bearer"},
    )


def get_settings(request: Request) -> Settings:
    return request.app.state.settings


def get_api_keys(request: Request) -> list[ApiKey]:
    return request.app.state.api_keys


def get_principal(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
    keys: list[ApiKey] = Depends(get_api_keys),
) -> Principal:
    principal = _principal_from_credentials(credentials, keys)
    request.state.principal = principal
    return principal


def require_role(minimum: str):
    """Dependency factory. `admin` satisfies every lower role."""

    def dependency(principal: Principal = Depends(get_principal)) -> Principal:
        if not principal.at_least(minimum):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "code": "FORBIDDEN",
                    "message": f"role {principal.role!r} cannot perform this action; "
                    f"{minimum!r} or higher is required",
                },
            )
        return principal

    return dependency


def require_metrics_token(request: Request) -> None:
    """Optional protection for /metrics.

    Prometheus usually runs inside the same private network, so the default is
    open. A deployment that exposes the endpoint publicly sets
    `METRICS_TOKEN` and scrapes with `Authorization: Bearer <token>`.
    """
    settings: Settings = request.app.state.settings
    if not settings.metrics_token:
        return
    header = request.headers.get("authorization", "")
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not hmac.compare_digest(token, settings.metrics_token):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": "UNAUTHENTICATED", "message": "metrics token required"},
            headers={"WWW-Authenticate": "Bearer"},
        )
