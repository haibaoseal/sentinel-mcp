"""OpenAI-compatible chat-completions provider.

Speaks the wire protocol directly over httpx rather than binding to a vendor
SDK. Two reasons: DeepSeek, Kimi, Qwen, vLLM and most self-hosted gateways all
implement this protocol, so ``LLM_BASE_URL`` is the only thing that changes
between them; and the request/response shape stays visible in this file, which
matters for a project whose subject is validating what a model asked for.

Scope note: this provider only *proposes* tool calls. It has no reference to the
tool registry and cannot execute anything, which is what keeps the policy
decision meaningful.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any

import httpx

from app.providers.base import (
    ProviderDecision,
    ProviderError,
    ProviderIdentity,
    ProviderMessage,
    ProviderToolCall,
    ProviderToolSpec,
)

DEFAULT_BASE_URL = "https://api.openai.com/v1"
DEFAULT_TIMEOUT_SECONDS = 60.0
MAX_ATTEMPTS = 3


class LLMProvider:
    """A real model behind an OpenAI-compatible endpoint."""

    def __init__(
        self,
        *,
        api_key: str,
        model: str,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        temperature: float = 0.0,
        client: httpx.Client | None = None,
    ) -> None:
        if not api_key:
            raise ProviderError("LLM provider requires an API key", retryable=False)
        if not model:
            raise ProviderError("LLM provider requires a model name", retryable=False)
        self._api_key = api_key
        self._model = model
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout
        self._temperature = temperature
        self._client = client
        self._identity = ProviderIdentity(
            provider="llm", model=model, is_live=True, base_url=self._base_url
        )

    @property
    def identity(self) -> ProviderIdentity:
        return self._identity

    def decide(
        self,
        *,
        messages: Sequence[ProviderMessage],
        tools: Sequence[ProviderToolSpec],
    ) -> ProviderDecision:
        payload: dict[str, Any] = {
            "model": self._model,
            "messages": [_encode_message(message) for message in messages],
            # Temperature 0 by default: an eval that cannot be reproduced is not
            # an eval. Callers that want variety must ask for it explicitly.
            "temperature": self._temperature,
        }
        if tools:
            payload["tools"] = [
                {
                    "type": "function",
                    "function": {
                        "name": spec.name,
                        "description": spec.description,
                        "parameters": spec.parameters
                        or {"type": "object", "properties": {}, "additionalProperties": False},
                    },
                }
                for spec in tools
            ]
            payload["tool_choice"] = "auto"

        body = self._post("/chat/completions", payload)
        return _decode_decision(body, advertised={spec.name for spec in tools})

    # -- transport ----------------------------------------------------------

    def _post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        url = f"{self._base_url}{path}"
        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
        }
        last_error: Exception | None = None

        for _attempt in range(1, MAX_ATTEMPTS + 1):
            try:
                if self._client is not None:
                    response = self._client.post(
                        url, json=payload, headers=headers, timeout=self._timeout
                    )
                else:
                    response = httpx.post(url, json=payload, headers=headers, timeout=self._timeout)
            except httpx.TimeoutException as exc:
                last_error = ProviderError(
                    f"LLM request timed out after {self._timeout}s", retryable=True
                )
                last_error.__cause__ = exc
                continue
            except httpx.HTTPError as exc:
                last_error = ProviderError(f"LLM transport error: {exc}", retryable=True)
                last_error.__cause__ = exc
                continue

            if response.status_code == 429 or response.status_code >= 500:
                last_error = ProviderError(
                    f"LLM backend returned {response.status_code}: {_safe_body(response)}",
                    retryable=True,
                )
                continue
            if response.status_code >= 400:
                # 4xx other than 429 will not succeed on retry; fail loudly with
                # the backend's own message so a misconfigured model name is
                # obvious rather than looking like a transient outage.
                raise ProviderError(
                    f"LLM backend rejected the request ({response.status_code}): "
                    f"{_safe_body(response)}",
                    retryable=False,
                )

            try:
                parsed = response.json()
            except ValueError as exc:
                raise ProviderError(
                    "LLM backend returned a non-JSON body", retryable=False
                ) from exc
            if not isinstance(parsed, dict):
                raise ProviderError(
                    "LLM backend returned an unexpected JSON shape", retryable=False
                )
            return parsed

        assert last_error is not None
        raise last_error


def _encode_message(message: ProviderMessage) -> dict[str, Any]:
    if message.role == "tool":
        return {
            "role": "tool",
            "tool_call_id": message.tool_call_id or "",
            "content": message.content,
        }
    return {"role": message.role, "content": message.content}


def _decode_decision(body: dict[str, Any], *, advertised: set[str]) -> ProviderDecision:
    choices = body.get("choices")
    if not isinstance(choices, list) or not choices:
        raise ProviderError("LLM response contained no choices", retryable=False)

    message = choices[0].get("message") or {}
    raw_calls = message.get("tool_calls") or []
    usage = _decode_usage(body.get("usage"))

    calls: list[ProviderToolCall] = []
    for index, raw in enumerate(raw_calls):
        function = raw.get("function") or {}
        name = function.get("name")
        if not name:
            continue
        if advertised and name not in advertised:
            # A model that invents a tool name must not be able to reach the
            # registry by accident. Surfacing it as a protocol error is clearer
            # than silently dropping it.
            raise ProviderError(
                f"model proposed tool {name!r}, which was not offered", retryable=False
            )
        calls.append(
            ProviderToolCall(
                id=str(raw.get("id") or f"call-{index}"),
                tool_name=name,
                arguments=_decode_arguments(function.get("arguments")),
            )
        )

    if calls:
        return ProviderDecision(kind="tool_calls", tool_calls=calls, usage=usage)

    content = message.get("content")
    if not isinstance(content, str) or not content.strip():
        raise ProviderError("LLM returned neither a tool call nor an answer", retryable=False)
    return ProviderDecision(kind="final_answer", final_answer=content, usage=usage)


def _decode_arguments(raw: Any) -> dict[str, Any]:
    """Tool arguments arrive as a JSON *string* in this protocol.

    A model under time pressure emits invalid JSON surprisingly often, so this
    reports a clear protocol error instead of letting a ``json.JSONDecodeError``
    escape from deep inside the loop.
    """
    if raw is None or raw == "":
        return {}
    if isinstance(raw, dict):
        return raw
    if not isinstance(raw, str):
        raise ProviderError(
            f"tool arguments had unexpected type {type(raw).__name__}", retryable=False
        )
    try:
        decoded = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ProviderError(f"tool arguments were not valid JSON: {exc}", retryable=False) from exc
    if not isinstance(decoded, dict):
        raise ProviderError("tool arguments were not a JSON object", retryable=False)
    return decoded


def _decode_usage(raw: Any) -> dict[str, int] | None:
    if not isinstance(raw, dict):
        return None
    usage: dict[str, int] = {}
    for key in ("prompt_tokens", "completion_tokens", "total_tokens"):
        value = raw.get(key)
        if isinstance(value, int):
            usage[key] = value
    return usage or None


def _safe_body(response: httpx.Response) -> str:
    """Truncate an error body and never echo an auth header back."""
    try:
        text = response.text
    except Exception:  # pragma: no cover - defensive
        return "<unreadable body>"
    return text[:500]
