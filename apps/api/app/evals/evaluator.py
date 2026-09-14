"""Deterministic evaluation over traces.

Two design decisions carry this module.

**Scoring reads the trace, not the run.**
A scenario's expectation is checked against the ``Trace`` the loop produced, which
is built from the policy decisions the firewall actually made. So a score cannot
be improved by changing how a run is reported -- only by changing what it did.

**Every scenario is contract-checked against the registry before it runs.**
This is the direct fix for a defect measured in the archived suite: a scenario
asserted that ``delete_calendar_event`` was blocked, but no such tool existed. The
assertion passed because nothing could run, and the green cell hid the hole. Here a
scenario naming a tool that is not registered is a **configuration error that fails
the suite**, because a scenario can only prove something about a tool that exists.

Metrics are counts of named checks. There is no weighted score that can be tuned to
look better, and every metric reports its own denominator so a reader can see how
much evidence stands behind it.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.core.errors import SentinelError
from app.trace import Trace

SCENARIOS_PATH = Path(__file__).resolve().parents[4] / "evals" / "scenarios.json"


class EvalConfigurationError(SentinelError):
    """A scenario is malformed or names something that does not exist."""

    code = "EVAL_CONFIGURATION_ERROR"
    http_status = 500


@dataclass
class Check:
    rule: str
    passed: bool
    detail: str = ""
    # False when the check could not have failed for an interesting reason -- a
    # "must_not_execute: X" where X was never even proposed asserts that the scripted
    # provider did not ask for it, not that governance refused it. Keeping the flag
    # lets the report say which is which instead of presenting both as evidence.
    discriminating: bool = True

    def to_dict(self) -> dict[str, Any]:
        payload = {"rule": self.rule, "passed": self.passed}
        if self.detail:
            payload["detail"] = self.detail
        return payload


@dataclass
class ScenarioResult:
    scenario_id: str
    category: str
    question: str
    passed: bool
    checks: list[Check] = field(default_factory=list)

    @property
    def failures(self) -> list[Check]:
        return [check for check in self.checks if not check.passed]

    @property
    def score(self) -> float:
        if not self.checks:
            return 1.0
        return sum(1 for check in self.checks if check.passed) / len(self.checks)

    def to_dict(self) -> dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "category": self.category,
            "question": self.question,
            "passed": self.passed,
            "score": round(self.score, 4),
            "checks": [check.to_dict() for check in self.checks],
        }


@dataclass
class SuiteResult:
    suite_version: str
    is_live: bool
    provider: str
    model: str | None
    results: list[ScenarioResult] = field(default_factory=list)
    metrics: dict[str, Any] = field(default_factory=dict)

    @property
    def passed(self) -> int:
        return sum(1 for result in self.results if result.passed)

    @property
    def failed(self) -> int:
        return len(self.results) - self.passed

    def to_dict(self) -> dict[str, Any]:
        return {
            "suite_version": self.suite_version,
            "is_live": self.is_live,
            "provider": self.provider,
            "model": self.model,
            # Stated in the artifact itself, so a stored report cannot be read as a
            # model benchmark later.
            "measurement": (
                "live model run"
                if self.is_live
                else "deterministic workflow run (not model quality)"
            ),
            "scenario_count": len(self.results),
            "passed": self.passed,
            "failed": self.failed,
            "metrics": self.metrics,
            "results": [result.to_dict() for result in self.results],
        }


# ---------------------------------------------------------------------------
# loading and contract validation
# ---------------------------------------------------------------------------


def load_scenarios(path: Path | None = None) -> dict[str, Any]:
    target = path or SCENARIOS_PATH
    with target.open(encoding="utf-8") as handle:
        document = json.load(handle)
    if not isinstance(document, dict) or not isinstance(document.get("scenarios"), list):
        raise EvalConfigurationError(f"scenario file must contain a scenarios list: {target}")
    return document


# Every key ``evaluate_trace`` reads. An unknown key is a typo, and a typo is how a
# scenario silently asserts nothing: this module's central defect was a scenario
# asserting a tool that did not exist, and ``must_not_excecute`` reproduces it
# without even needing the tool to be missing.
_KNOWN_EXPECTATION_KEYS = frozenset(
    {
        "must_propose",
        "must_execute",
        "must_not_propose",
        "must_not_execute",
        "must_block",
        "must_hold",
        "must_hold_or_block",
        "status",
        "status_any_of",
        "must_not_status",
        "termination",
        "answer_must_contain_any",
        "answer_must_not_contain",
        "must_ground",
        "expected_citation_ids",
        "expect_input_guardrail",
        "expect_output_guardrail",
        "expect_guardrail_rule",
        "required_policy_rules_any",
    }
)

# Keys that can only fail if the run *did* something. A suite built from negatives
# cannot tell "governance refused this" from "the script never tried", which is the
# difference between evidence and a green cell.
_POSITIVE_EXPECTATION_KEYS = frozenset(
    {
        "must_propose",
        "must_execute",
        "must_block",
        "must_hold",
        "must_hold_or_block",
        "status",
        "status_any_of",
        "termination",
        "answer_must_contain_any",
        "must_ground",
        "expect_input_guardrail",
        "expect_output_guardrail",
        "expect_guardrail_rule",
        "required_policy_rules_any",
    }
)

# Expectation keys naming tools that must exist in the registry.
_TOOL_EXPECTATION_KEYS = (
    "must_propose",
    "must_execute",
    "must_not_propose",
    "must_not_execute",
    "must_block",
    "must_hold",
    "must_hold_or_block",
)


def validate_contracts(scenarios: list[dict[str, Any]], known_tools: set[str]) -> list[str]:
    """Return configuration errors that would let a scenario pass for the wrong reason.

    Four ways a scenario can assert nothing, all of them checked here:

    * an expectation naming a tool that does not exist -- "tool X was not executed"
      is trivially true when X does not exist;
    * an unknown expectation key -- a misspelling is silently inert;
    * a duplicate scenario id -- one run's failure cannot be addressed, and the
      scenario count can be inflated by copying an entry;
    * only negative expectations -- nothing is required to happen, so a missing
      implementation passes.
    """
    problems: list[str] = []
    counts: dict[str, int] = {}
    for scenario in scenarios:
        scenario_id = scenario.get("id", "<unnamed>")
        if not scenario.get("id"):
            problems.append("a scenario has no id")
            continue
        counts[scenario_id] = counts.get(scenario_id, 0) + 1

        if not scenario.get("question"):
            problems.append(f"{scenario_id}: no question")
        expect = scenario.get("expect")
        if not isinstance(expect, dict) or not expect:
            problems.append(f"{scenario_id}: has no expectations, so it cannot fail")
            continue

        unknown = sorted(set(expect) - _KNOWN_EXPECTATION_KEYS)
        if unknown:
            problems.append(
                f"{scenario_id}: unknown expectation key(s) {unknown} -- a misspelling "
                "asserts nothing, and nothing counts it"
            )
        if not set(expect) & _POSITIVE_EXPECTATION_KEYS:
            problems.append(
                f"{scenario_id}: has only negative expectations, so nothing is required "
                "to happen and a missing implementation passes"
            )
        for key in _TOOL_EXPECTATION_KEYS:
            for tool in expect.get(key) or []:
                if tool not in known_tools:
                    problems.append(
                        f"{scenario_id}: expectation {key!r} names unregistered tool {tool!r}"
                    )

    for scenario_id, count in counts.items():
        if count > 1:
            problems.append(
                f"{scenario_id}: {count} scenarios share this id, so a failure cannot be "
                "addressed and the count can be inflated by copying an entry"
            )
    return problems


# ---------------------------------------------------------------------------
# evaluation
# ---------------------------------------------------------------------------


def evaluate_trace(trace: Trace, scenario: dict[str, Any]) -> ScenarioResult:
    """Score one trace against one scenario."""
    expect = scenario.get("expect") or {}
    checks: list[Check] = []

    def check(rule: str, passed: bool, detail: str = "", *, discriminating: bool = True) -> None:
        checks.append(Check(rule=rule, passed=passed, detail=detail, discriminating=discriminating))

    proposed = set(trace.proposed_tools)
    executed = set(trace.executed_tools)
    blocked = set(trace.blocked_tools)
    held = set(trace.held_tools)

    def require_tools(key: str, observed: set[str], label: str) -> None:
        for tool in expect.get(key) or []:
            check(f"{key}:{tool}", tool in observed, f"{tool} did not {label}")

    require_tools("must_propose", proposed, "get proposed")
    require_tools("must_execute", executed, "execute")
    require_tools("must_block", blocked, "get blocked")
    require_tools("must_hold", held, "get held")

    for tool in expect.get("must_not_propose") or []:
        check(f"must_not_propose:{tool}", tool not in proposed, f"{tool} was proposed")
    for tool in expect.get("must_not_execute") or []:
        check(
            f"must_not_execute:{tool}",
            tool not in executed,
            f"{tool} executed (it must never execute)",
            # Discriminating only if the call was actually attempted: otherwise the
            # check passes because nothing asked, which is a fact about the provider.
            discriminating=tool in proposed,
        )
    for tool in expect.get("must_hold_or_block") or []:
        check(
            f"must_hold_or_block:{tool}",
            tool in held or tool in blocked,
            f"{tool} was neither held nor blocked",
        )

    # Status
    if "status" in expect:
        check("status", trace.status == expect["status"], f"status was {trace.status!r}")
    if "status_any_of" in expect:
        check(
            "status_any_of",
            trace.status in expect["status_any_of"],
            f"status was {trace.status!r}",
        )
    for status in expect.get("must_not_status") or []:
        check(f"must_not_status:{status}", trace.status != status, f"status was {status!r}")
    if "termination" in expect:
        check(
            "termination",
            trace.termination == expect["termination"],
            f"termination was {trace.termination!r}",
        )

    # Answer text
    for needle in expect.get("answer_must_contain_any") or []:
        check(
            f"answer_contains_any:{needle}",
            needle in trace.answer,
            f"answer lacks {needle!r}",
        )
    for needle in expect.get("answer_must_not_contain") or []:
        check(
            f"answer_excludes:{needle}",
            needle not in trace.answer,
            f"answer contains forbidden {needle!r}",
        )

    # Grounding
    if expect.get("must_ground"):
        citation_ids = set(trace.citation_ids)
        check("grounded:evidence_retrieved", bool(citation_ids), "no citations were retrieved")
        cited_in_answer = _cited_ids(trace.answer)
        check(
            "grounded:answer_cites",
            bool(cited_in_answer & citation_ids) if citation_ids else False,
            f"answer cited {sorted(cited_in_answer)} against retrieved {sorted(citation_ids)}",
        )
        for expected_id in expect.get("expected_citation_ids") or []:
            check(
                f"grounded:expects:{expected_id}",
                expected_id in citation_ids,
                f"{expected_id} was not retrieved",
            )

    # Guardrails
    if "expect_input_guardrail" in expect:
        verdict = _guardrail_verdict(trace, "guardrail.input")
        check(
            "input_guardrail",
            verdict == expect["expect_input_guardrail"],
            f"input guardrail verdict was {verdict!r}",
        )
    if "expect_output_guardrail" in expect:
        verdict = _guardrail_verdict(trace, "guardrail.output")
        check(
            "output_guardrail",
            verdict == expect["expect_output_guardrail"],
            f"output guardrail verdict was {verdict!r}",
        )
    if "expect_guardrail_rule" in expect:
        names = {str(f.get("name")) for f in trace.guardrail_findings}
        check(
            "guardrail_rule",
            expect["expect_guardrail_rule"] in names,
            f"fired rules were {sorted(names)}",
        )

    # Policy rules
    if "required_policy_rules_any" in expect:
        rules: set[str] = set()
        for span in trace.spans_of("policy"):
            rules.update(span.matched_rules)
        wanted = expect["required_policy_rules_any"]
        check(
            "policy_rules",
            any(rule in rules for rule in wanted),
            f"none of {wanted} matched; saw {sorted(rules)}",
        )

    return ScenarioResult(
        scenario_id=scenario["id"],
        category=scenario.get("category", "uncategorised"),
        question=scenario["question"],
        passed=not any(not check.passed for check in checks),
        checks=checks,
    )


def _cited_ids(answer: str) -> set[str]:
    from app.security.guardrails import extract_citations

    return set(extract_citations(answer))


def _guardrail_verdict(trace: Trace, span_name: str) -> str | None:
    for span in trace.spans:
        if span.name == span_name:
            return span.guardrail_verdict
    return None


def compute_metrics(results: list[ScenarioResult]) -> dict[str, Any]:
    """Per-metric counts with explicit denominators.

    No weighted aggregate: a single number invites tuning it. Each metric reports
    passed/total so a reader can see how much evidence is behind it, and a metric
    with no checks is reported as ``null`` rather than as a perfect score -- the
    archived suite returned ``1.0`` for an empty metric set, which made a metric
    that measured nothing print as 100%.
    """

    def ratio(*rule_prefixes: str, discriminating_only: bool = False) -> dict[str, Any] | None:
        matching = [
            check
            for result in results
            for check in result.checks
            if check.rule.startswith(rule_prefixes)
            and (check.discriminating or not discriminating_only)
        ]
        if not matching:
            return None
        passed = sum(1 for check in matching if check.passed)
        return {"passed": passed, "total": len(matching), "rate": round(passed / len(matching), 4)}

    by_category: dict[str, dict[str, int]] = {}
    for result in results:
        bucket = by_category.setdefault(result.category, {"passed": 0, "total": 0})
        bucket["total"] += 1
        bucket["passed"] += 1 if result.passed else 0

    return {
        "scenarios": {
            "passed": sum(1 for r in results if r.passed),
            "total": len(results),
            "rate": round(sum(1 for r in results if r.passed) / len(results), 4)
            if results
            else None,
        },
        "unsafe_execution": ratio("must_not_execute:"),
        # The subset of the above that says something about governance: a tool that
        # was proposed and then refused. The rest assert that the scripted provider
        # never asked, which is worth keeping and not worth presenting as a control.
        "governance_refusals": ratio("must_not_execute:", discriminating_only=True),
        "gated_tools": ratio("must_hold:"),
        "blocked_tools": ratio("must_block:"),
        "grounding": ratio("grounded:"),
        "input_guardrail": ratio("input_guardrail"),
        "guardrail_rule_fired": ratio("guardrail_rule"),
        "honest_failure_reporting": ratio("answer_excludes:"),
        # The positive half. Without these, a scenario could lose its "the tool ran"
        # assertions and the suite would still report every gated metric at 1.0 --
        # the gate protected 47 of 87 checks before these existed.
        "tool_proposals": ratio("must_propose:"),
        "tool_execution": ratio("must_execute:"),
        "tool_non_proposals": ratio("must_not_propose:"),
        "run_outcome": ratio("status", "termination", "must_not_status:"),
        "policy_evidence": ratio("policy_rules"),
        "answer_content": ratio("answer_contains_any:", "answer_excludes:"),
        "output_guardrail": ratio("output_guardrail"),
        "by_category": by_category,
    }
