"""Request and response contracts for the HTTP API.

`extra="forbid"` on request bodies is intentional: a typo in a field name should
be a 422, not a silently ignored parameter. Response models are permissive about
optional fields but explicit about types, which is what makes the generated
OpenAPI document usable by another team.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

Role = Literal["viewer", "operator", "approver", "admin"]


class TaskCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    request: str = Field(min_length=1, max_length=8000, description="Natural-language request")
    title: str | None = Field(default=None, max_length=255)


class ToolCallOut(BaseModel):
    id: str
    tool_name: str
    action_type: str
    status: str
    risk_level: str
    risk_reasons: list[str] = Field(default_factory=list)
    source: str | None = None
    error_code: str | None = None
    created_at: datetime | None = None
    executed_at: datetime | None = None


class TaskSummary(BaseModel):
    id: str
    tenant_id: str
    title: str
    request: str
    status: str
    answer: str | None = None
    termination: str | None = None
    error: str | None = None
    provider: str | None = None
    model: str | None = None
    created_at: datetime | None = None
    completed_at: datetime | None = None
    tool_call_count: int = 0
    pending_approval_count: int = 0
    audit_event_count: int = 0


class TaskDetail(TaskSummary):
    tool_calls: list[ToolCallOut] = Field(default_factory=list)
    trace: dict[str, Any] | None = None


class TaskList(BaseModel):
    items: list[TaskSummary]
    total: int
    limit: int
    offset: int


class ApprovalOut(BaseModel):
    id: str
    tenant_id: str
    task_id: str | None = None
    tool_call_id: str
    status: str
    risk_level: str
    risk_reasons: list[str] = Field(default_factory=list)
    original_arguments: dict[str, Any] = Field(default_factory=dict)
    modified_arguments: dict[str, Any] | None = None
    reviewer_id: str | None = None
    review_comment: str | None = None
    created_at: datetime | None = None
    reviewed_at: datetime | None = None


class ApprovalDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    comment: str | None = Field(default=None, max_length=2000)
    modified_arguments: dict[str, Any] | None = None
    resume: bool = Field(
        default=False,
        description="When true and approved, resume the paused agent loop with the tool result.",
    )


class ApprovalList(BaseModel):
    items: list[ApprovalOut]
    total: int


class ApprovalResult(BaseModel):
    approval_id: str
    status: str
    executed: bool
    task_id: str | None = None
    reason: str | None = None
    policy_decision: str | None = None
    data: dict[str, Any] | None = None
    resumed: bool = False
    task_status: str | None = None
    task_answer: str | None = None


class ToolOut(BaseModel):
    name: str
    description: str
    action_type: str
    resource_type: str
    risk_level: str
    requires_approval: bool
    source: str


class PolicyOut(BaseModel):
    version: str
    path: str
    rule_count: int
    sha256: str
    raw: str | None = None


class AuditEventOut(BaseModel):
    id: str
    task_id: str | None = None
    seq: int
    event_type: str
    actor_type: str
    actor_id: str | None = None
    payload: dict[str, Any] = Field(default_factory=dict)
    prev_hash: str
    event_hash: str
    created_at: datetime | None = None


class AuditList(BaseModel):
    items: list[AuditEventOut]
    total: int
    limit: int
    offset: int


class AuditVerifyOut(BaseModel):
    task_id: str
    ok: bool
    checked: int
    first_bad_seq: int | None = None
    reason: str | None = None
    event_count: int


class HealthOut(BaseModel):
    status: str
    version: str
    environment: str


class ReadyOut(BaseModel):
    status: str
    database: bool
    tools: int
    policy_loaded: bool


class WhoAmIOut(BaseModel):
    tenant_id: str
    subject: str
    role: str
    key_fingerprint: str


class ErrorBody(BaseModel):
    code: str
    message: str
    detail: dict[str, Any] = Field(default_factory=dict)
    request_id: str | None = None
