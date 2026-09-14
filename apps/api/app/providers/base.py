"""Provider abstraction: what a model is allowed to see and decide.

Why this layer exists
---------------------
A project that claims to evaluate agent behaviour has to be able to run the same
agent loop against a real model *and* against a deterministic stand-in, without
the governance path differing between them. Otherwise the eval numbers describe
a code path nobody ships.

So the loop talks to a ``Provider`` and nothing else. Two implementations ship:

- ``ReplayProvider`` decides from an explicit, typed policy. It uses no network
  and no key, and it is what CI runs. It is *not* a fake model pretending to be
  smart -- it is a scripted workflow whose decisions are written down, so that a
  test failure is reproducible.
- ``LLMProvider`` calls an OpenAI-compatible endpoint. DeepSeek, Kimi, Qwen and
  local gateways all speak this protocol, so the base URL is configurable rather
  than hardcoded.

Two rules keep the abstraction honest:

1. A provider never executes a tool. It only *proposes*. Execution is the
   firewall's job, which is what makes the policy decision meaningful.
2. ``ProviderIdentity`` travels with every run, so a report can never confuse a
   replay with a live model run. Fixture scores must not be presentable as model
   quality, and the only way to guarantee that is to record which one produced
   the trace.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, Literal, Protocol, runtime_checkable

from pydantic import BaseModel, Field

Role = Literal["system", "user", "assistant", "tool"]


class ProviderMessage(BaseModel):
    """One turn of conversation handed to the provider."""

    role: Role
    content: str = ""
    # Populated on a ``tool`` message so the model can see what its call returned.
    tool_call_id: str | None = None
    tool_name: str | None = None
    # Populated on the ``assistant`` message that requested tool calls.
    #
    # This is required by OpenAI-compatible APIs: a tool result message must follow
    # an assistant message whose ``tool_calls`` array contains a matching id. The
    # loop originally described its calls in prose instead, which works against a
    # permissive stub but is rejected by a real vendor -- and it also means the
    # provider cannot tell which tools have already run, so it re-proposes them.
    tool_calls: list[ProviderToolCall] = Field(default_factory=list)


class ProviderToolCall(BaseModel):
    """A tool call the provider *proposes*. Nothing has run yet."""

    id: str
    tool_name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    # Optional provider-supplied rationale. This is a summary the model chose to
    # emit, never hidden chain-of-thought.
    rationale: str | None = None


class ProviderToolSpec(BaseModel):
    """A tool description, in the shape a provider can be shown."""

    name: str
    description: str = ""
    parameters: dict[str, Any] = Field(default_factory=dict)


class ProviderToolResult(BaseModel):
    """The outcome of one executed call, fed back to the provider."""

    tool_call_id: str
    tool_name: str
    status: str
    content: str
    error: str | None = None


class ProviderDecision(BaseModel):
    """What the provider wants to do next.

    Exactly one of ``tool_calls`` or ``final_answer`` is meaningful. A provider
    that returns neither is treated as a protocol violation by the loop rather
    than as a silent completion.
    """

    kind: Literal["tool_calls", "final_answer"]
    tool_calls: list[ProviderToolCall] = Field(default_factory=list)
    final_answer: str | None = None
    # Free-form usage reporting, when the backend supplies it.
    usage: dict[str, int] | None = None


class ProviderIdentity(BaseModel):
    """Provenance for a run.

    ``is_live`` is the load-bearing field: any surface that shows a score must
    consult it before implying the number measures model quality.
    """

    provider: str
    model: str | None = None
    is_live: bool = False
    base_url: str | None = None


class ProviderError(Exception):
    """Raised when a backend fails. Distinct from a policy block."""

    def __init__(self, message: str, *, retryable: bool = False) -> None:
        super().__init__(message)
        self.retryable = retryable


@runtime_checkable
class Provider(Protocol):
    """The only thing the agent loop knows about a model."""

    @property
    def identity(self) -> ProviderIdentity: ...

    def decide(
        self,
        *,
        messages: Sequence[ProviderMessage],
        tools: Sequence[ProviderToolSpec],
    ) -> ProviderDecision:
        """Given the conversation so far, propose the next action."""
        ...
