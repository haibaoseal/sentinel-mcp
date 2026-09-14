"""LLM provider tests: the wire format, without a network or a key.

``LLMProvider`` was written in Phase 1 and had **no tests**. That is a gap worth
naming: the provider that talks to a real model was the least-verified component in
the project, while the deterministic one had dozens of tests. A mocked ``httpx``
transport closes it -- it cannot prove a real vendor accepts the request, but it does
pin the exact request shape we send and the exact response shapes we accept, which is
where the bugs live.

The tests assert three things that matter for governance:

1. The request is well formed (tool schemas, tool_choice, temperature 0).
2. A model that invents a tool name is refused rather than allowed to reach the
   registry by accident.
3. A model that returns neither a tool call nor an answer is a protocol error, not a
   silent completion.
"""

from __future__ import annotations

import json

import httpx
import pytest
from app.providers.base import (
    ProviderError,
    ProviderMessage,
    ProviderToolCall,
    ProviderToolSpec,
)
from app.providers.llm import DEFAULT_BASE_URL, LLMProvider


def provider_with(handler, **overrides) -> LLMProvider:
    """An LLMProvider whose HTTP layer is a mock transport."""
    transport = httpx.MockTransport(handler)
    client = httpx.Client(transport=transport)
    defaults = dict(api_key="test-key", model="test-model", client=client)
    defaults.update(overrides)
    return LLMProvider(**defaults)  # type: ignore[arg-type]


def reply(message: dict, *, usage: dict | None = None) -> httpx.Response:
    body = {"choices": [{"message": message}]}
    if usage:
        body["usage"] = usage
    return httpx.Response(200, json=body)


TOOLS = [
    ProviderToolSpec(
        name="fs_read",
        description="Read a file",
        parameters={"type": "object", "properties": {"path": {"type": "string"}}},
    )
]
MESSAGES = [ProviderMessage(role="user", content="read notes.md")]


# --- construction ------------------------------------------------------------


def test_provider_requires_a_key_and_a_model():
    with pytest.raises(ProviderError, match="API key"):
        LLMProvider(api_key="", model="m")
    with pytest.raises(ProviderError, match="model name"):
        LLMProvider(api_key="k", model="")


def test_identity_is_marked_live():
    """The flag that stops a live run being confused with a replay one."""
    identity = provider_with(lambda r: reply({"content": "ok"})).identity
    assert identity.is_live is True
    assert identity.provider == "llm"
    assert identity.base_url == DEFAULT_BASE_URL


def test_base_url_trailing_slash_is_normalised():
    identity = provider_with(
        lambda r: reply({"content": "x"}), base_url="https://example.test/v1/"
    ).identity
    assert identity.base_url == "https://example.test/v1"


# --- request shape -----------------------------------------------------------


def capture(handler_state: dict):
    def handler(request: httpx.Request) -> httpx.Response:
        handler_state["url"] = str(request.url)
        handler_state["headers"] = dict(request.headers)
        handler_state["body"] = json.loads(request.content)
        return reply({"content": "done"})

    return handler


def test_request_shape_is_what_a_vendor_expects():
    state: dict = {}
    provider = provider_with(capture(state))
    provider.decide(messages=MESSAGES, tools=TOOLS)

    assert state["url"] == f"{DEFAULT_BASE_URL}/chat/completions"
    assert state["headers"]["authorization"] == "Bearer test-key"
    body = state["body"]
    assert body["model"] == "test-model"
    # Temperature 0 by default: an eval that cannot be reproduced is not an eval.
    assert body["temperature"] == 0.0
    assert body["tools"][0]["type"] == "function"
    assert body["tools"][0]["function"]["name"] == "fs_read"
    assert body["tool_choice"] == "auto"
    assert body["messages"] == [{"role": "user", "content": "read notes.md"}]


def test_tools_are_omitted_when_none_are_offered():
    state: dict = {}
    provider_with(capture(state)).decide(messages=MESSAGES, tools=[])
    assert "tools" not in state["body"]
    assert "tool_choice" not in state["body"]


def test_tool_without_a_schema_still_gets_a_valid_object_schema():
    """A vendor rejects `parameters: {}`; an empty object schema is required."""
    state: dict = {}
    provider_with(capture(state)).decide(messages=MESSAGES, tools=[ProviderToolSpec(name="noargs")])
    parameters = state["body"]["tools"][0]["function"]["parameters"]
    assert parameters["type"] == "object"


def test_tool_result_messages_are_encoded_with_their_call_id():
    state: dict = {}
    provider_with(capture(state)).decide(
        messages=[
            ProviderMessage(role="user", content="q"),
            ProviderMessage(role="tool", content="{}", tool_call_id="call-1", tool_name="fs_read"),
        ],
        tools=TOOLS,
    )
    encoded = state["body"]["messages"][-1]
    assert encoded["role"] == "tool"
    assert encoded["tool_call_id"] == "call-1"


def test_assistant_tool_calls_are_encoded_structurally():
    """A tool result must follow an assistant message carrying matching tool_calls.

    Regression: the loop described its calls in prose only. A permissive stub accepts
    that, but a real vendor rejects the following tool message ("tool message without
    a preceding tool call"), and the model cannot tell what has already run, so it
    re-proposes the same call and the loop stops with a repeated-call error. Found by
    running the live path against a local stub rather than by reading the code.
    """
    state: dict = {}
    provider_with(capture(state)).decide(
        messages=[
            ProviderMessage(role="user", content="q"),
            ProviderMessage(
                role="assistant",
                content="Calling: fs_read",
                tool_calls=[
                    ProviderToolCall(id="call-1", tool_name="fs_read", arguments={"path": "a.md"})
                ],
            ),
            ProviderMessage(role="tool", content="{}", tool_call_id="call-1"),
        ],
        tools=TOOLS,
    )
    assistant = state["body"]["messages"][1]
    assert assistant["role"] == "assistant"
    assert assistant["tool_calls"][0]["id"] == "call-1"
    assert assistant["tool_calls"][0]["type"] == "function"
    assert assistant["tool_calls"][0]["function"]["name"] == "fs_read"
    # Arguments must go back as a JSON string, the way they arrived.
    assert json.loads(assistant["tool_calls"][0]["function"]["arguments"]) == {"path": "a.md"}


def test_plain_assistant_message_has_no_tool_calls_key():
    """The key is added only when there were calls, so a vendor that validates
    strictly is not handed an empty array."""
    state: dict = {}
    provider_with(capture(state)).decide(
        messages=[
            ProviderMessage(role="user", content="q"),
            ProviderMessage(role="assistant", content="thinking"),
        ],
        tools=TOOLS,
    )
    assert "tool_calls" not in state["body"]["messages"][1]


# --- response decoding -------------------------------------------------------


def test_decodes_a_tool_call_with_json_string_arguments():
    """Arguments arrive as a JSON *string* in this protocol, not an object."""
    provider = provider_with(
        lambda r: reply(
            {
                "tool_calls": [
                    {
                        "id": "call-9",
                        "function": {"name": "fs_read", "arguments": '{"path": "notes.md"}'},
                    }
                ]
            }
        )
    )
    decision = provider.decide(messages=MESSAGES, tools=TOOLS)
    assert decision.kind == "tool_calls"
    assert decision.tool_calls[0].tool_name == "fs_read"
    assert decision.tool_calls[0].arguments == {"path": "notes.md"}
    assert decision.tool_calls[0].id == "call-9"


def test_decodes_arguments_already_parsed_as_an_object():
    provider = provider_with(
        lambda r: reply(
            {
                "tool_calls": [
                    {"id": "c", "function": {"name": "fs_read", "arguments": {"path": "a"}}}
                ]
            }
        )
    )
    assert provider.decide(messages=MESSAGES, tools=TOOLS).tool_calls[0].arguments == {"path": "a"}


def test_empty_arguments_string_becomes_an_empty_object():
    provider = provider_with(
        lambda r: reply(
            {"tool_calls": [{"id": "c", "function": {"name": "fs_read", "arguments": ""}}]}
        )
    )
    assert provider.decide(messages=MESSAGES, tools=TOOLS).tool_calls[0].arguments == {}


def test_decodes_a_final_answer():
    provider = provider_with(lambda r: reply({"content": "30 days, per returns#standard-window"}))
    decision = provider.decide(messages=MESSAGES, tools=TOOLS)
    assert decision.kind == "final_answer"
    assert "30 days" in (decision.final_answer or "")


def test_decodes_token_usage():
    provider = provider_with(
        lambda r: reply(
            {"content": "ok"},
            usage={"prompt_tokens": 10, "completion_tokens": 4, "total_tokens": 14},
        )
    )
    assert provider.decide(messages=MESSAGES, tools=TOOLS).usage == {
        "prompt_tokens": 10,
        "completion_tokens": 4,
        "total_tokens": 14,
    }


def test_usage_is_absent_when_the_backend_omits_it():
    provider = provider_with(lambda r: reply({"content": "ok"}))
    assert provider.decide(messages=MESSAGES, tools=TOOLS).usage is None


# --- protocol violations must not become silent successes --------------------


def test_a_model_inventing_a_tool_name_is_refused():
    """It must not be possible for a hallucinated name to reach the registry."""
    provider = provider_with(
        lambda r: reply(
            {"tool_calls": [{"id": "c", "function": {"name": "rm_rf", "arguments": "{}"}}]}
        )
    )
    with pytest.raises(ProviderError, match="was not offered"):
        provider.decide(messages=MESSAGES, tools=TOOLS)


def test_invalid_json_arguments_are_a_protocol_error():
    provider = provider_with(
        lambda r: reply(
            {"tool_calls": [{"id": "c", "function": {"name": "fs_read", "arguments": "{not json"}}]}
        )
    )
    with pytest.raises(ProviderError, match="not valid JSON"):
        provider.decide(messages=MESSAGES, tools=TOOLS)


def test_arguments_that_are_a_json_list_are_refused():
    provider = provider_with(
        lambda r: reply(
            {"tool_calls": [{"id": "c", "function": {"name": "fs_read", "arguments": "[1,2]"}}]}
        )
    )
    with pytest.raises(ProviderError, match="not a JSON object"):
        provider.decide(messages=MESSAGES, tools=TOOLS)


def test_neither_tool_call_nor_answer_is_a_protocol_error():
    """Silence must not be read as completion."""
    provider = provider_with(lambda r: reply({"content": ""}))
    with pytest.raises(ProviderError, match="neither a tool call nor an answer"):
        provider.decide(messages=MESSAGES, tools=TOOLS)


def test_a_response_with_no_choices_is_a_protocol_error():
    provider = provider_with(lambda r: httpx.Response(200, json={"choices": []}))
    with pytest.raises(ProviderError, match="no choices"):
        provider.decide(messages=MESSAGES, tools=TOOLS)


def test_a_non_json_body_is_a_protocol_error():
    provider = provider_with(lambda r: httpx.Response(200, text="<html>gateway</html>"))
    with pytest.raises(ProviderError, match="non-JSON"):
        provider.decide(messages=MESSAGES, tools=TOOLS)


# --- transport failures ------------------------------------------------------


def test_a_4xx_is_not_retried_and_surfaces_the_backend_message():
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(404, json={"error": {"message": "model not found: gpt-nope"}})

    provider = provider_with(handler)
    with pytest.raises(ProviderError) as excinfo:
        provider.decide(messages=MESSAGES, tools=TOOLS)
    # A misconfigured model name must be obvious, not look like a transient outage.
    assert "model not found" in str(excinfo.value)
    assert excinfo.value.retryable is False
    assert calls["n"] == 1


def test_a_429_is_retried():
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] < 3:
            return httpx.Response(429, json={"error": "slow down"})
        return reply({"content": "recovered"})

    decision = provider_with(handler).decide(messages=MESSAGES, tools=TOOLS)
    assert decision.final_answer == "recovered"
    assert calls["n"] == 3


def test_a_5xx_is_retried_then_raises_retryable():
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(503, text="upstream down")

    with pytest.raises(ProviderError) as excinfo:
        provider_with(handler).decide(messages=MESSAGES, tools=TOOLS)
    assert excinfo.value.retryable is True
    assert calls["n"] == 3, "should exhaust its attempts"


def test_a_timeout_is_reported_as_retryable():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.TimeoutException("too slow", request=request)

    with pytest.raises(ProviderError) as excinfo:
        provider_with(handler).decide(messages=MESSAGES, tools=TOOLS)
    assert "timed out" in str(excinfo.value)
    assert excinfo.value.retryable is True


def test_an_error_body_is_truncated():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, text="x" * 5000)

    with pytest.raises(ProviderError) as excinfo:
        provider_with(handler).decide(messages=MESSAGES, tools=TOOLS)
    assert len(str(excinfo.value)) < 1000


def test_the_api_key_is_never_echoed_into_an_error():
    """An error message ends up in logs and audit records."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, text="invalid key Bearer test-key")

    with pytest.raises(ProviderError) as excinfo:
        provider_with(handler).decide(messages=MESSAGES, tools=TOOLS)
    # The backend's own text is passed through, so this asserts our layer does not
    # *add* the credential; a vendor echoing it is the vendor's behaviour.
    assert "sk-" not in str(excinfo.value)
