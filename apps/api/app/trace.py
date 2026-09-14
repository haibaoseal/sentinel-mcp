"""One trace model for every kind of run.

Why a single model matters
--------------------------
A report is only useful if the same structure describes a deterministic replay and
a live model run. If replay traces and live traces have different shapes, then any
comparison between them is a comparison of two code paths, not of two behaviours.

So both produce a ``Trace``. The differences are *recorded as data*, never implied
by shape:

- ``identity.is_live`` says which produced it. Any surface that shows a score must
  consult it before implying the number measures model quality. That is the single
  field that stops a fixture score being presented as a model result.
- The spans carry the policy decision, the tool outcome and the guardrail checks that
  actually ran, so a trace is evidence rather than a log. The inputs needed to *rerun*
  a scenario live in ``evals/scenarios.json``, not in the trace.

Timing is deliberately **excluded** from evaluation
--------------------------------------------------
Spans carry no wall-clock duration, and every span is ordered deterministically, so two
runs of the same scenario produce byte-identical traces once the top-level ``run_id``
(the task's uuid) is removed. A duration would make even that impossible -- the archived
project had a test that "verified determinism" while its DTO contained timestamps, which
meant the assertion could only ever compare fields that happened to be stable. Where
latency matters it belongs in a separate operational metric, not in a value that an
eval score depends on.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

from app.providers.base import ProviderIdentity

SpanType = Literal["run", "model", "tool", "policy", "retrieval", "guardrail", "output"]
SpanStatus = Literal["ok", "error", "blocked", "held"]


@dataclass
class TraceSpan:
    """One observable unit of work.

    A span records what happened and why, in a shape a reviewer can read without
    the source. ``detail`` fields are intentionally explicit rather than a
    free-form blob: a test can assert on them, and so can a human.
    """

    span_type: SpanType
    name: str
    status: SpanStatus = "ok"
    parent: str | None = None
    # Tool spans
    tool_name: str | None = None
    tool_source: str | None = None
    arguments: dict[str, Any] | None = None
    error_code: str | None = None
    # Policy spans
    decision: str | None = None
    risk_level: str | None = None
    matched_rules: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    # Retrieval spans
    citations: list[dict[str, Any]] = field(default_factory=list)
    # Guardrail spans
    guardrail_verdict: str | None = None
    guardrail_findings: list[dict[str, Any]] = field(default_factory=list)
    guardrail_checks: list[dict[str, Any]] = field(default_factory=list)
    # Model spans
    model: str | None = None
    usage: dict[str, int] | None = None

    def to_dict(self) -> dict[str, Any]:
        # Drop None/empty so a trace diff shows real changes rather than noise.
        payload: dict[str, Any] = {"type": self.span_type, "name": self.name, "status": self.status}
        for key, value in (
            ("parent", self.parent),
            ("tool_name", self.tool_name),
            ("tool_source", self.tool_source),
            ("arguments", self.arguments),
            ("error_code", self.error_code),
            ("decision", self.decision),
            ("risk_level", self.risk_level),
            ("model", self.model),
            ("usage", self.usage),
            ("guardrail_verdict", self.guardrail_verdict),
        ):
            if value not in (None, {}, []):
                payload[key] = value
        for key, value in (
            ("matched_rules", self.matched_rules),
            ("reasons", self.reasons),
            ("citations", self.citations),
            ("guardrail_findings", self.guardrail_findings),
            ("guardrail_checks", self.guardrail_checks),
        ):
            if value:
                payload[key] = value
        return payload


@dataclass
class Trace:
    """The complete, structured record of one agent run."""

    run_id: str
    question: str
    answer: str
    status: str
    termination: str
    identity: ProviderIdentity
    spans: list[TraceSpan] = field(default_factory=list)
    scenario_id: str | None = None

    # -- accessors used by the evaluator -----------------------------------

    @property
    def is_live(self) -> bool:
        return self.identity.is_live

    def spans_of(self, span_type: SpanType) -> list[TraceSpan]:
        return [span for span in self.spans if span.span_type == span_type]

    @property
    def proposed_tools(self) -> list[str]:
        return [span.tool_name for span in self.spans_of("tool") if span.tool_name]

    @property
    def executed_tools(self) -> list[str]:
        return [
            span.tool_name
            for span in self.spans_of("tool")
            if span.tool_name and span.status == "ok"
        ]

    @property
    def blocked_tools(self) -> list[str]:
        return [
            span.tool_name
            for span in self.spans_of("tool")
            if span.tool_name and span.status == "blocked"
        ]

    @property
    def held_tools(self) -> list[str]:
        return [
            span.tool_name
            for span in self.spans_of("tool")
            if span.tool_name and span.status == "held"
        ]

    @property
    def citations(self) -> list[dict[str, Any]]:
        found: list[dict[str, Any]] = []
        for span in self.spans_of("retrieval"):
            found.extend(span.citations)
        return found

    @property
    def citation_ids(self) -> list[str]:
        return [str(c.get("id")) for c in self.citations if c.get("id")]

    @property
    def guardrail_findings(self) -> list[dict[str, Any]]:
        found: list[dict[str, Any]] = []
        for span in self.spans_of("guardrail"):
            found.extend(span.guardrail_findings)
        return found

    @property
    def guardrail_verdict(self) -> str | None:
        verdicts = [
            span.guardrail_verdict for span in self.spans_of("guardrail") if span.guardrail_verdict
        ]
        if "block" in verdicts:
            return "block"
        if "warn" in verdicts:
            return "warn"
        return verdicts[0] if verdicts else None

    @property
    def error_codes(self) -> list[str]:
        return [span.error_code for span in self.spans if span.error_code]

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "scenario_id": self.scenario_id,
            "question": self.question,
            "answer": self.answer,
            "status": self.status,
            "termination": self.termination,
            "identity": {
                "provider": self.identity.provider,
                "model": self.identity.model,
                "is_live": self.identity.is_live,
            },
            "spans": [span.to_dict() for span in self.spans],
        }


class TraceBuilder:
    """Accumulates spans for one run.

    A builder rather than a mutable trace, so that span construction happens in one
    place and the loop cannot accidentally emit an inconsistent shape.
    """

    def __init__(
        self,
        *,
        run_id: str,
        question: str,
        identity: ProviderIdentity,
        scenario_id: str | None = None,
    ) -> None:
        self._trace = Trace(
            run_id=run_id,
            question=question,
            answer="",
            status="running",
            termination="completed",
            identity=identity,
            scenario_id=scenario_id,
        )
        self._root = TraceSpan(span_type="run", name="agent.run")
        self._trace.spans.append(self._root)

    @property
    def root_id(self) -> str:
        return self._root.name

    def add(self, span: TraceSpan) -> TraceSpan:
        if span.parent is None:
            span.parent = self._root.name
        self._trace.spans.append(span)
        return span

    def model_span(
        self, *, name: str, model: str | None, usage: dict[str, int] | None = None
    ) -> TraceSpan:
        return self.add(TraceSpan(span_type="model", name=name, model=model, usage=usage))

    def tool_span(
        self,
        *,
        tool_name: str,
        status: SpanStatus,
        source: str | None = None,
        arguments: dict[str, Any] | None = None,
        error_code: str | None = None,
    ) -> TraceSpan:
        return self.add(
            TraceSpan(
                span_type="tool",
                name=tool_name,
                status=status,
                tool_name=tool_name,
                tool_source=source,
                arguments=arguments,
                error_code=error_code,
            )
        )

    def policy_span(self, *, span: TraceSpan) -> TraceSpan:
        return self.add(span)

    def guardrail_span(
        self,
        *,
        name: str,
        verdict: str,
        findings: list[dict[str, Any]],
        checks: list[dict[str, Any]],
    ) -> TraceSpan:
        return self.add(
            TraceSpan(
                span_type="guardrail",
                name=name,
                status="blocked" if verdict == "block" else "ok",
                guardrail_verdict=verdict,
                guardrail_findings=findings,
                guardrail_checks=checks,
            )
        )

    def finish(self, *, answer: str, status: str, termination: str) -> Trace:
        self._trace.answer = answer
        self._trace.status = status
        self._trace.termination = termination
        return self._trace
