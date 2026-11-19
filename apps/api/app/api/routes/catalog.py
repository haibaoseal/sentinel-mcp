"""Read-only catalog endpoints: what tools exist and which policy is loaded."""

from __future__ import annotations

import hashlib
from pathlib import Path

import yaml
from fastapi import APIRouter, Depends

from app.api.auth import Principal, get_principal, require_role
from app.api.deps import get_runtime, get_settings
from app.api.schemas import PolicyOut, ToolOut, WhoAmIOut
from app.core.config import Settings
from app.policy.engine import DEFAULT_POLICY_PATH
from app.runtime import Runtime

router = APIRouter(prefix="/v1", tags=["catalog"])


@router.get("/whoami", response_model=WhoAmIOut, summary="Show the authenticated principal")
def whoami(principal: Principal = Depends(get_principal)) -> WhoAmIOut:
    return WhoAmIOut(
        tenant_id=principal.tenant_id,
        subject=principal.subject,
        role=principal.role,
        key_fingerprint=principal.key_fingerprint,
    )


@router.get("/tools", response_model=list[ToolOut], summary="List governed tools and their risk")
def list_tools(
    runtime: Runtime = Depends(get_runtime),
    principal: Principal = Depends(require_role("viewer")),
) -> list[ToolOut]:
    return [
        ToolOut(
            name=descriptor.name,
            description=descriptor.description,
            action_type=descriptor.action_type,
            resource_type=descriptor.resource_type,
            risk_level=descriptor.risk_level,
            requires_approval=descriptor.requires_approval,
            source=descriptor.source,
        )
        for descriptor in runtime.registry.descriptors()
    ]


@router.get("/policies", response_model=PolicyOut, summary="Show the loaded policy version")
def get_policy(
    runtime: Runtime = Depends(get_runtime),
    settings: Settings = Depends(get_settings),
    principal: Principal = Depends(require_role("viewer")),
) -> PolicyOut:
    path = Path(settings.policy_path) if settings.policy_path else DEFAULT_POLICY_PATH
    # Read from the live PolicyEngine in memory rather than re-reading disk so
    # the reported version/hash always reflects what the firewall is enforcing.
    document = runtime.firewall.policy_engine.policy
    rendered = yaml.safe_dump(document, allow_unicode=True, sort_keys=False)
    return PolicyOut(
        version=str(document.get("version", "1")),
        path=path.name,
        rule_count=len(document.get("tools", {}) or {}),
        sha256=hashlib.sha256(rendered.encode()).hexdigest(),
        # Raw YAML can contain environment-specific host allow-lists; viewers see
        # the version hash, admins can retrieve the document for review.
        raw=rendered if principal.role == "admin" else None,
    )
