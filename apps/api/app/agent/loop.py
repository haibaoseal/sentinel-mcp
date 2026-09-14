"""The agent loop.

This is the component the whole project exists to govern, so its shape is
deliberate:

- The loop is **stateless between turns**. Everything the provider needs is in
  the message list, which means a run can be reconstructed from its transcript.
  A provider that keeps its plan in instance state cannot be replayed from a
  log, and an unexplainable audit trail is not an audit trail.
- The loop **never executes a tool**. It asks the firewall, which applies policy
  and writes the audit record. The firewall is the only caller of a tool source.
- A **failed tool call is never reported as success**. The predecessor started
  from ``status = "passed"`` and only demoted it on max-turns or a guardrail
  block, so an internal validation error reached a user under a green badge.
- **Repeating an identical call is detected.** A model that loops on the same
  call with the same arguments is stopped, rather than burning turns until the
  limit and reporting a generic timeout.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy.orm import Session

from app.core.contracts import ToolRequest
from app.governance.firewall import Firewall
from app.providers.base import (
    Provider,
    ProviderError,
    ProviderMessage,
    ProviderToolResult,
    ProviderToolSpec,
)
from app.security.guardrails import GuardrailResult, check_input, check_output

SYSTEM_PROMPT = (
    "You are a tool-using assistant operating under a governance layer.\n"
    "Rules you must follow:\n"
    "1. Use the provided tools when they can answer the question. Do not invent facts.\n"
    "2. Every tool call is reviewed by a policy engine. It may be blocked or held for "
    "human approval; if that happens, tell the user plainly instead of claiming success.\n"
    "3. If a tool reports an error, say what failed. Never describe a failed or "
    "unexecuted action as completed.\n"
    "4. When you state a policy fact, cite the evidence id in the form [chunk-id] "
    "using only ids returned by the knowledge base tool this turn.\n"
    "5. If you cannot establish an answer from the tools, say so and ask for what "
    "you need rather than guessing."
)

TERMINATION_MAX_TURNS = "max_turns"
TERMINATION_REPEATED_CALL = "repeated_call"
TERMINATION_PROVIDER_ERROR = "provider_error"
TERMINATION_COMPLETED = "completed"
TERMINATION_GUARDRAIL = "guardrail"


@dataclass
class LoopStep:
    """One turn's worth of observable activity."""

    index: int
    decision_kind: str
    tool_name: str | None = None
    tool_status: str | None = None
    tool_call_id: str | None = None
    error_code: str | None = None
    detail: str | None = None


@dataclass
class AgentRunResult:
    status: str
    answer: str
    steps: list[LoopStep] = field(default_factory=list)
    tool_results: list[ProviderToolResult] = field(default_factory=list)
    termination: str = TERMINATION_COMPLETED
    usage: dict[str, int] | None = None
    error: str | None = None
    # The guardrail verdict for the run, when one was reached. Exposed so a caller
    # can see what was checked and not only what failed.
    guardrail: Any = None


class AgentLoop:
    def __init__(
        self,
        *,
        provider: Provider,
        firewall: Firewall,
        max_turns: int = 8,
    ) -> None:
        if max_turns < 1:
            raise ValueError("max_turns must be at least 1")
        self.provider = provider
        self.firewall = firewall
        self.max_turns = max_turns

    def specs(self) -> list[ProviderToolSpec]:
        return [
            ProviderToolSpec(
                name=descriptor.name,
                description=descriptor.description,
                parameters=descriptor.argument_schema
                or {"type": "object", "properties": {}, "additionalProperties": False},
            )
            for descriptor in self.firewall.registry.descriptors()
        ]

    def run(self, *, task_id: str, user_request: str, session: Session) -> AgentRunResult:
        # Screen the request before any tool is proposed. A detected injection is a
        # *blocking* input finding, not a warning: the archived design treated
        # detection as advisory and then relied on the policy engine alone, which
        # meant an injection that only manipulated wording had no effect at all.
        input_check = check_input(user_request)
        if not input_check.allowed:
            return AgentRunResult(
                status="blocked",
                answer=(
                    "请求已被输入防护拦截：检测到试图改变指令或获取系统提示的内容。"
                    if _looks_chinese(user_request)
                    else "Request blocked by the input guardrail: it attempts to change "
                    "instructions or extract the system prompt."
                ),
                steps=[
                    LoopStep(
                        index=0,
                        decision_kind="guardrail",
                        error_code="INPUT_GUARDRAIL_BLOCK",
                        detail=input_check.summary(),
                    )
                ],
                termination=TERMINATION_GUARDRAIL,
                guardrail=input_check,
            )

        messages: list[ProviderMessage] = [
            ProviderMessage(role="system", content=SYSTEM_PROMPT),
            ProviderMessage(role="user", content=user_request),
        ]
        specs = self.specs()
        steps: list[LoopStep] = []
        results: list[ProviderToolResult] = []
        seen_calls: set[tuple[str, str]] = set()
        citations: list[dict[str, Any]] = []
        usage: dict[str, int] | None = None

        for turn in range(1, self.max_turns + 1):
            try:
                decision = self.provider.decide(messages=messages, tools=specs)
            except ProviderError as exc:
                steps.append(
                    LoopStep(
                        index=turn,
                        decision_kind="error",
                        error_code="PROVIDER_ERROR",
                        detail=str(exc),
                    )
                )
                return AgentRunResult(
                    status="failed",
                    answer=f"模型调用失败：{exc}",
                    steps=steps,
                    tool_results=results,
                    termination=TERMINATION_PROVIDER_ERROR,
                    usage=usage,
                    error=str(exc),
                )

            if decision.usage:
                usage = {**(usage or {}), **decision.usage}

            if decision.kind == "final_answer":
                steps.append(LoopStep(index=turn, decision_kind="final_answer"))
                status = _status_from(results)
                answer = decision.final_answer or ""
                # The model's closing text is only trustworthy when the run
                # actually succeeded. Overriding it for *every* non-completed
                # status is what stops a blocked or approval-held run from
                # telling the user it worked -- the same defect class that let an
                # internal validation string reach a user under a green badge.
                if status != "completed":
                    answer = _governed_answer(status, results, answer)

                # Screen the answer itself.
                #
                # Grounding applies only to a *substantive, model-authored* answer.
                # Two cases must not be grounded, or they get refused for the wrong
                # reason: a governance refusal (there is nothing to cite when the
                # answer is "this was blocked"), and a conversational reply. The
                # capability-claim check still runs on both, because "I did it" is
                # never acceptable to overstate.
                governance_answer = status != "completed"
                output_check = check_output(
                    answer,
                    citations,
                    policy_relevant=bool(citations) and not governance_answer,
                )
                if not output_check.allowed:
                    steps.append(
                        LoopStep(
                            index=turn,
                            decision_kind="guardrail",
                            error_code="OUTPUT_GUARDRAIL_BLOCK",
                            detail=output_check.summary(),
                        )
                    )
                    status = "failed" if status == "completed" else status
                    answer = _guardrail_refusal(output_check, answer)
                    return AgentRunResult(
                        status=status,
                        answer=answer,
                        steps=steps,
                        tool_results=results,
                        termination=TERMINATION_GUARDRAIL,
                        usage=usage,
                        guardrail=output_check,
                    )

                return AgentRunResult(
                    status=status,
                    answer=answer,
                    steps=steps,
                    tool_results=results,
                    termination=TERMINATION_COMPLETED,
                    usage=usage,
                    guardrail=output_check,
                )

            messages.append(
                ProviderMessage(role="assistant", content=_describe_calls(decision.tool_calls))
            )

            for call in decision.tool_calls:
                signature = (call.tool_name, _stable(call.arguments))
                if signature in seen_calls:
                    steps.append(
                        LoopStep(
                            index=turn,
                            decision_kind="tool_calls",
                            tool_name=call.tool_name,
                            error_code="REPEATED_CALL",
                            detail="identical call already made with identical arguments",
                        )
                    )
                    return AgentRunResult(
                        status="failed",
                        answer=(
                            f"已停止：模型重复请求同一个工具调用（{call.tool_name}），"
                            "说明它无法从已有结果继续。"
                        ),
                        steps=steps,
                        tool_results=results,
                        termination=TERMINATION_REPEATED_CALL,
                        usage=usage,
                    )
                seen_calls.add(signature)

                outcome = self._invoke(call, task_id=task_id, session=session)
                results.append(outcome)
                # Remember any evidence this call retrieved, so the output
                # guardrail can check the answer against the same chunks the agent
                # actually saw. Without this the grounding check has nothing to
                # compare against and silently passes everything.
                citations.extend(_citations_from(outcome))
                steps.append(
                    LoopStep(
                        index=turn,
                        decision_kind="tool_calls",
                        tool_name=call.tool_name,
                        tool_status=outcome.status,
                        tool_call_id=outcome.tool_call_id,
                        error_code=outcome.error,
                        detail=call.rationale,
                    )
                )
                messages.append(
                    ProviderMessage(
                        role="tool",
                        content=_tool_content(outcome),
                        tool_call_id=call.id,
                        tool_name=call.tool_name,
                    )
                )

        steps.append(
            LoopStep(
                index=self.max_turns,
                decision_kind="error",
                error_code="MAX_TURNS",
                detail=f"loop did not finish within {self.max_turns} turns",
            )
        )
        return AgentRunResult(
            status="failed",
            answer=f"未能在 {self.max_turns} 轮内完成请求。",
            steps=steps,
            tool_results=results,
            termination=TERMINATION_MAX_TURNS,
            usage=usage,
        )

    # -- helpers ------------------------------------------------------------

    def _invoke(self, call, *, task_id: str, session: Session) -> ProviderToolResult:
        """Route one proposed call through governance."""
        descriptor = self.firewall.registry.describe(call.tool_name)
        request = ToolRequest(
            task_id=task_id,
            tool_name=call.tool_name,
            action_type=descriptor.action_type if descriptor else "unknown",
            resource_type=descriptor.resource_type if descriptor else None,
            arguments=call.arguments,
            requested_by="agent",
        )
        result = self.firewall.execute(request, session=session)
        return ProviderToolResult(
            tool_call_id=result.tool_call_id,
            tool_name=call.tool_name,
            status=result.status,
            content=_render(result),
            error=result.error,
        )


def _citations_from(outcome: ProviderToolResult) -> list[dict[str, Any]]:
    """Pull citation objects out of a tool result, if it carried any.

    Reads the structured payload the knowledge tool returns rather than scraping
    the rendered text, so a change to presentation cannot silently disable
    grounding.
    """
    import json

    if outcome.status != "success":
        return []
    try:
        payload = json.loads(outcome.content)
    except (ValueError, TypeError):
        return []
    if not isinstance(payload, dict):
        return []
    found: list[dict[str, Any]] = []
    for key in ("citations", "structured"):
        value = payload.get(key)
        if isinstance(value, dict):
            value = value.get("citations")
        if isinstance(value, list):
            found.extend(item for item in value if isinstance(item, dict) and item.get("id"))
    return found


def _guardrail_refusal(check: GuardrailResult, model_answer: str) -> str:
    """Replace an answer the output guardrail refused.

    Grounding is skipped for governance answers, so what reaches here is an
    unsupported capability claim or a policy answer whose citations do not hold up.
    The message names which, because a refusal the user cannot act on is barely
    better than the false answer it replaced.
    """
    blocking = [f for f in check.findings if f.severity in {"high", "critical"}]
    if any(f.name.startswith("unsupported_capability_claim") for f in blocking):
        return (
            "已拦截该回答：它声称完成了某个动作，但工具能力不允许这样做，"
            "且所引用的证据并不支持该说法。退款、删除与发送类操作均为 dry-run，"
            "本系统不会声称它们已经完成。"
        )
    if any(f.name.startswith("citation") or f.name == "answer_has_no_citation" for f in blocking):
        return "已拦截该回答：其中的引用无法支持所陈述的内容，因此未予返回。"
    return "已拦截该回答：它未通过输出防护检查。"


def _looks_chinese(text: str) -> bool:
    return any("\u4e00" <= ch <= "\u9fff" for ch in text or "")


def _render(result) -> str:
    import json

    if result.status == "success":
        return json.dumps(result.data or {}, ensure_ascii=False, default=str)
    if result.status == "blocked":
        return f"BLOCKED BY POLICY: {result.error}"
    if result.status == "waiting_approval":
        return f"HELD FOR HUMAN APPROVAL: {result.error or 'pending review'}"
    return f"ERROR: {result.error or 'tool failed'}"


def _tool_content(outcome: ProviderToolResult) -> str:
    """Prefix kept consistent with the replay provider's transcript parsing.

    ``ERROR`` marks a genuine failure. Blocked and approval-held calls are not
    failures -- they are governance outcomes the model must report accurately.
    """
    if outcome.status == "failed":
        return f"ERROR {outcome.content}"
    return outcome.content


def _status_from(results: Sequence[ProviderToolResult]) -> str:
    """Derive run status from what actually happened.

    Order matters: a governance refusal outranks a failure, because the run did
    what it was supposed to do. Anything failed or never executed must not be
    reported as a completed run.
    """
    if not results:
        return "completed"
    statuses = {result.status for result in results}
    if "failed" in statuses:
        return "failed"
    if "blocked" in statuses:
        return "blocked"
    if "waiting_approval" in statuses:
        return "waiting_approval"
    return "completed"


def _governed_answer(status: str, results: Sequence[ProviderToolResult], model_answer: str) -> str:
    """Replace a model's success claim when governance intervened.

    Each status gets its own sentence, because "it failed", "it needs a human"
    and "policy forbade it" call for different user actions. The tool's own error
    text is preserved where present, since that is what says what to fix.
    """

    def names(predicate) -> str:
        return ", ".join(sorted({r.tool_name for r in results if predicate(r)}))

    if status == "blocked":
        blocked = names(lambda r: r.status == "blocked")
        return (
            f"该操作已被策略拒绝（{blocked}），未执行任何有副作用的动作。"
            "如确需执行，请先调整策略或显式开启对应开关。"
        )
    if status == "waiting_approval":
        pending = names(lambda r: r.status == "waiting_approval")
        return f"该操作需要人工审批后才能继续（{pending}），当前未被自动执行。"
    if status == "failed":
        failures = [r for r in results if r.status == "failed"]
        details = "; ".join(f"{r.tool_name}: {_humanise(r.content)}" for r in failures)
        if details:
            return f"未能完成请求。工具调用失败：{details}"
        return f"未能完成请求。模型回答为：{model_answer}"
    return model_answer


def _humanise(content: str) -> str:
    """Strip the transcript's ERROR marker for user-facing text.

    Both spellings are handled because the transcript marker (``ERROR ``) and the
    renderer's own label (``ERROR: ``) can stack on a failed call.
    """
    text = content.strip()
    while True:
        stripped = text
        for prefix in ("ERROR: ", "ERROR "):
            if stripped.startswith(prefix):
                stripped = stripped[len(prefix) :].strip()
        if stripped == text:
            return text
        text = stripped


def _stable(arguments: dict[str, Any]) -> str:
    import json

    return json.dumps(arguments, sort_keys=True, ensure_ascii=False, default=str)


def _describe_calls(calls) -> str:
    if not calls:
        return ""
    return "Calling: " + ", ".join(f"{call.tool_name}({_stable(call.arguments)})" for call in calls)
