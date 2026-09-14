"""Deterministic provider used by CI and by the offline demo.

This is where the previous generation of the project went wrong, so it is worth
being explicit about what changed.

The old scripted agent mapped question keywords directly to a fixed tool list:
it saw 邮件 and returned the email plan, regardless of what any tool had
returned. Consequences: the tool loop was decorative (every call was decided
before the first result existed), and the eval suite could not fail for any
interesting reason, because the expected tool set and the branch condition were
written by the same person from the same words.

This provider instead inspects the **transcript**: it detects what kind of
request it is, then checks the accumulated tool results to decide what is still
missing. Adding a tool call to the plan requires a result to justify it, which
makes the loop real and makes the eval able to distinguish "the workflow is
complete" from "the workflow was skipped".
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from typing import Any, Literal

from app.providers.base import (
    ProviderDecision,
    ProviderIdentity,
    ProviderMessage,
    ProviderToolCall,
    ProviderToolResult,
    ProviderToolSpec,
)

Intent = Literal["delete", "refund", "email", "calendar", "sql", "file", "github", "unknown"]


# Intent detection. Deliberately small and readable: this provider's purpose is
# to be inspectable, and every branch here is covered by a test that asserts the
# resulting *workflow* rather than the wording.
#
# Order is load-bearing and is checked before the topic markers below. A request
# can name a subject *and* an action ("删除文件 notes.md"); if topic detection ran
# first it would route to the read plan and the destructive intent would never be
# reached. That was a real bug: the agent read and searched the file instead of
# proposing its deletion.
_ACTION_MARKERS: tuple[tuple[Intent, tuple[str, ...]], ...] = (
    ("delete", ("删除", "删掉", "移除", "delete", "remove", "rm ")),
)

# A path-like token (name with an extension) or a read verb is a stronger signal
# than a topic noun. Without this, "读取 missing.md 的内容" matched nothing at
# all: the only file marker was the bare word 文件, so a request that named an
# actual file was classified as unknown and the agent did nothing.
_PATH_RE = re.compile(r"[\w.\-/\\]+\.(?:md|txt|json|ya?ml|csv|log|py|ts|tsx|js)\b", re.IGNORECASE)
_READ_VERBS = ("读取", "读一下", "看一下", "打开", "查看", "read ", "open ", "cat ")

_INTENT_MARKERS: tuple[tuple[Intent, tuple[str, ...]], ...] = (
    ("refund", ("退款", "退货", "refund")),
    ("email", ("邮件", "email", "发送", "收件")),
    ("calendar", ("日程", "会议", "calendar", "邀请")),
    # SQL/order-status markers are deliberately specific: bare 查询 ("query") and
    # bare 订单 ("order") also appear in file, refund and email requests, so
    # matching on them misroutes those. 订单状态 is unambiguous.
    ("sql", ("数据库", "sql", "orders", "订单状态", "订单号", "数据表")),
    ("file", ("文件", "目录", "file", "notes")),
    ("github", ("github", "issue", "pull request", " pr ", "连接器")),
)


class ReplayProvider:
    """Scripted, reproducible, network-free."""

    def __init__(self, *, profile: str = "grounded", model: str = "replay-workflow-v1") -> None:
        self._profile = profile
        self._identity = ProviderIdentity(provider="replay", model=model, is_live=False)

    @property
    def identity(self) -> ProviderIdentity:
        return self._identity

    # -- decision -----------------------------------------------------------

    def decide(
        self,
        *,
        messages: Sequence[ProviderMessage],
        tools: Sequence[ProviderToolSpec],
    ) -> ProviderDecision:
        available = {spec.name for spec in tools}
        request = _first_user_message(messages)
        results = _tool_results(messages)

        # A provider that calls a tool it was not offered is a protocol
        # violation, so the plan is filtered against the advertised set. This is
        # also what makes the loop honest when the registry changes.
        plan = self._plan(request, results)
        plan = [name for name in plan if name in available]
        # "Attempted" rather than "succeeded". Retrying a step that already
        # failed would make the provider emit an identical call, which the loop
        # correctly refuses as a repeat -- so a failing step would surface as a
        # confusing loop rather than as the honest failure it is.
        attempted = {result.tool_name for result in results}
        next_call = next((name for name in plan if name not in attempted), None)

        if next_call is not None:
            return ProviderDecision(
                kind="tool_calls",
                tool_calls=[
                    ProviderToolCall(
                        id=f"call-{len(results) + 1}-{next_call}",
                        tool_name=next_call,
                        arguments=self._arguments(next_call, request, results),
                        rationale=(
                            f"Workflow step: {next_call}. "
                            f"{len(attempted)} of {len(plan)} planned steps attempted."
                        ),
                    )
                ],
            )

        return ProviderDecision(kind="final_answer", final_answer=self._answer(request, results))

    # -- workflow -----------------------------------------------------------

    def _plan(self, request: str, results: Sequence[ProviderToolResult]) -> list[str]:
        """The ordered workflow for this request.

        Two things are deliberately separate here:

        - *Reading* is always allowed: a policy question should not be gated
          behind human approval, or reviewers learn to click through.
        - *Committing* to a financial action is gated twice over: only the
          ``grounded`` profile proposes ``draft_refund`` at all, and the policy
          still holds it for approval. Asking "what is the return policy" must
          therefore never create a refund draft, which is also why the commit
          step requires an order id to be present in the request.

        The grounded/baseline difference is a *configuration* difference and is
        labelled as such wherever it is reported. It is not a claim that one
        prompt beats another.
        """
        intent = detect_intent(request)
        grounded = self._profile == "grounded"

        if intent == "delete":
            # The destructive path exists so the policy block has a consequence
            # that can be asserted. It is proposed even though it will be
            # blocked -- a block that never fires proves nothing.
            return ["delete_file"]
        if intent == "refund":
            plan = ["search_knowledge_base"] if grounded else []
            # Only propose the commit step when the user actually supplied an
            # order to act on. Without one the tool would reject the call, and
            # proposing it anyway would make a read-only question look like a
            # failed financial operation.
            if _has_order_id(request):
                plan.append("draft_refund")
            return plan
        if intent == "email":
            # The email workflow must actually propose the send when the request
            # asks for one, or the policy never gets the chance to hold it and the
            # user is told nothing. The archived suite asserted that a send
            # "requires approval" against a workflow that never proposed a send, so
            # the assertion passed vacuously.
            #
            # No file read here: reading an unrelated file first made an email
            # request fail on a missing file before the send was ever proposed.
            plan = ["search_knowledge_base"] if grounded else []
            if _wants_send(request):
                plan.append("send_email")
            return plan
        if intent == "calendar":
            return ["fs_list", "search_knowledge_base"] if grounded else ["fs_list"]
        if intent == "sql":
            return ["search_knowledge_base", "sql_query"] if grounded else ["sql_query"]
        if intent == "file":
            # Search first so the workflow has an evidence step, but only when
            # the request did not already name a file: searching for "policy"
            # and then reading a file the user never mentioned is not helpful.
            if grounded and not _extract_path(request):
                return ["fs_search", "fs_read"]
            return ["fs_read"]
        if intent == "github":
            return ["github_list_issues"]
        return []

    def _arguments(
        self, tool_name: str, request: str, results: Sequence[ProviderToolResult]
    ) -> dict[str, Any]:
        order_id = _extract_order_id(request)
        path = _extract_path(request)
        if tool_name == "sql_query":
            return {"query": "SELECT status FROM orders LIMIT 10"}
        if tool_name == "search_knowledge_base":
            return {"query": request, "top_k": 3}
        if tool_name == "draft_refund":
            return {"order_id": order_id, "reason": request}
        if tool_name == "fs_read":
            # Act on the file the user named. The earlier version hardcoded
            # "notes.md", so "读取 missing.md" silently read a different file --
            # and then looped, because the second identical call was correctly
            # refused as a repeat.
            return {"path": path or ""}
        if tool_name == "delete_file":
            return {"path": path or ""}
        if tool_name == "fs_search":
            # When a file was named, search inside it; otherwise search the root
            # for the words the user used.
            return {"pattern": path or _keyword(request)}
        if tool_name == "fs_list":
            return {"path": "."}
        if tool_name == "github_list_issues":
            return {"owner": "openai", "repo": "openai-python"}
        return {}

    def _answer(self, request: str, results: Sequence[ProviderToolResult]) -> str:
        # Governance outcomes are read from the actual tool results. The earlier
        # version consulted a local list of "already completed" tool names, which
        # never contained a status at all -- so a blocked call produced the same
        # cheerful "workflow completed" sentence as a successful one. A provider
        # that reports success over a policy block is worse than one that says
        # nothing.
        blocked = [r for r in results if r.status == "blocked"]
        pending = [r for r in results if r.status == "waiting_approval"]
        failures = [r for r in results if r.status == "failed"]

        if blocked:
            names = ", ".join(sorted({r.tool_name for r in blocked}))
            return (
                f"该操作已被策略拒绝（{names}），未执行任何有副作用的动作。"
                "如确需执行，请先由管理员调整策略或显式开启对应开关。"
            )
        if pending:
            names = ", ".join(sorted({r.tool_name for r in pending}))
            return f"该操作需要人工审批后才能继续（{names}），当前未被自动执行。"
        if failures:
            names = ", ".join(sorted({r.tool_name for r in failures}))
            return f"无法完成请求：工具调用失败（{names}）。请在补齐必要信息后重试。"
        if not results:
            return "没有可执行的步骤。请补充更具体的请求。"

        # Answer from the evidence that was actually retrieved, and cite it. An
        # answer that retrieved policy chunks and then cites nothing is exactly
        # what the output guardrail refuses, and it should: "I retrieved the
        # policy" followed by an uncited claim is the failure mode the grounding
        # check exists to catch.
        citation = _first_citation(results)
        if citation:
            excerpt = str(citation.get("excerpt") or "").strip()
            summary = excerpt.split("\n")[0][:120]
            return f"根据检索到的政策证据：{summary}（依据【{citation['id']}】）"
        return "已按受治理的工作流完成请求。"


def _first_citation(results: Sequence[ProviderToolResult]) -> dict[str, Any] | None:
    """The top citation from the most recent successful retrieval, if any."""
    import json

    for result in reversed(list(results)):
        if result.status != "success":
            continue
        try:
            payload = json.loads(result.content)
        except (TypeError, ValueError):
            continue
        if not isinstance(payload, dict):
            continue
        citations = payload.get("citations")
        if isinstance(citations, list) and citations:
            first = citations[0]
            if isinstance(first, dict) and first.get("id"):
                return first
    return None


def detect_intent(request: str) -> Intent:
    lowered = f" {request.lower()} "
    # Action verbs win over topic nouns.
    for intent, markers in _ACTION_MARKERS:
        if any(marker in lowered for marker in markers):
            return intent
    # A concrete file path or a read verb identifies a filesystem request more
    # reliably than any topic noun.
    if _PATH_RE.search(request) or any(verb in lowered for verb in _READ_VERBS):
        return "file"
    for intent, markers in _INTENT_MARKERS:
        if any(marker in lowered for marker in markers):
            return intent
    return "unknown"


def _first_user_message(messages: Sequence[ProviderMessage]) -> str:
    for message in messages:
        if message.role == "user":
            return message.content
    return ""


def _tool_results(messages: Sequence[ProviderMessage]) -> list[ProviderToolResult]:
    """Reconstruct executed calls from the transcript.

    The transcript is the only source of truth: a provider that "remembers" its
    own plan in instance state cannot be replayed from a log, which would make
    the audit trail unable to explain the run.
    """
    results: list[ProviderToolResult] = []
    for message in messages:
        if message.role != "tool" or not message.tool_name:
            continue
        results.append(
            ProviderToolResult(
                tool_call_id=message.tool_call_id or "",
                tool_name=message.tool_name,
                status="failed" if message.content.startswith("ERROR") else "success",
                content=message.content,
            )
        )
    return results


def _extract_order_id(request: str) -> str:
    """Pull an ORD-#### style id out of free text, or return empty.

    Returning empty rather than inventing an id matters: the tool validates its
    input and reports INVALID_ARGS, which the loop turns into a failed run. The
    old provider called the tool with an empty id and the run still reported
    "passed".
    """
    import re

    match = re.search(r"\bORD[-_ ]?(\d{3,})\b", request, re.IGNORECASE)
    return f"ORD-{match.group(1)}" if match else ""


def _has_order_id(request: str) -> bool:
    return bool(_extract_order_id(request))


# Phrases that ask for a message to actually go out. Used to decide whether the
# workflow proposes the send step at all.
#
# The 发给 form is listed because the natural sentence is "写一封邮件发给老师" --
# the word for the message and the verb for sending are not adjacent, so an
# adjacency-based marker list missed the most ordinary phrasing of the request.
_SEND_MARKERS = (
    "发出去",
    "直接发",
    "发送",
    "群发",
    "发邮件",
    "发一封",
    "发给",
    "回复给",
    "send",
    "e-mail",
)


def _wants_send(request: str) -> bool:
    lowered = request.lower()
    return any(marker in lowered for marker in _SEND_MARKERS)


def _extract_path(request: str) -> str:
    """Return a file path named in the request, or empty.

    Returning empty rather than a default matters: substituting a default path
    makes the agent act on a file the user never mentioned, and the resulting
    answer looks plausible while being about the wrong thing.
    """
    match = _PATH_RE.search(request)
    return match.group(0) if match else ""


def _keyword(request: str) -> str:
    """A search term drawn from the request, for when no path was named."""
    words = [word for word in re.findall(r"[\w\u4e00-\u9fff]{2,}", request) if not word.isdigit()]
    return words[0] if words else "."
