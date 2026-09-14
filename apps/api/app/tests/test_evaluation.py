"""Evaluation and regression-gate tests.

The theme is that the gate must fail when it should. A regression gate that cannot
detect a shrunk suite is worse than none, because it certifies a hollow one -- so
the tests here deliberately break things and assert the failure.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from app.evals.evaluator import (
    EvalConfigurationError,
    SuiteResult,
    compute_metrics,
    evaluate_trace,
    load_scenarios,
    validate_contracts,
)
from app.evals.runner import (
    GATED_METRICS,
    check_inventory,
    compare_to_baseline,
    load_baseline,
    render_report,
    run_suite,
    write_baseline,
)
from app.providers.base import ProviderIdentity
from app.trace import Trace, TraceBuilder, TraceSpan


@pytest.fixture(scope="module")
def suite():
    """One suite run shared by the read-only assertions (it spawns no subprocesses)."""
    result, _ = run_suite()
    return result


# --- trace model -------------------------------------------------------------


def make_trace(**overrides) -> Trace:
    builder = TraceBuilder(
        run_id="run-1",
        question=overrides.pop("question", "q"),
        identity=ProviderIdentity(provider="replay", model="m", is_live=False),
        scenario_id=overrides.pop("scenario_id", None),
    )
    builder.add(TraceSpan(span_type="tool", name="fs_read", tool_name="fs_read", status="ok"))
    return builder.finish(
        answer=overrides.pop("answer", "a"),
        status=overrides.pop("status", "completed"),
        termination="completed",
    )


def test_trace_reports_live_status_from_identity():
    live = Trace(
        run_id="r",
        question="q",
        answer="a",
        status="completed",
        termination="completed",
        identity=ProviderIdentity(provider="llm", model="m", is_live=True),
    )
    assert live.is_live is True
    assert make_trace().is_live is False


def test_trace_serialises_without_timing_fields():
    """A fixture trace must be byte-identical run to run, so no clock in the DTO."""
    payload = json.dumps(make_trace().to_dict(), sort_keys=True)
    for forbidden in ("duration", "startedAt", "endedAt", "elapsed", "latency", "timestamp"):
        assert forbidden not in payload, forbidden


def test_trace_tool_accessors_partition_by_status():
    builder = TraceBuilder(run_id="r", question="q", identity=ProviderIdentity(provider="replay"))
    builder.tool_span(tool_name="fs_read", status="ok")
    builder.tool_span(tool_name="send_email", status="held")
    builder.tool_span(tool_name="delete_file", status="blocked")
    builder.tool_span(tool_name="fs_read", status="error")
    trace = builder.finish(answer="a", status="failed", termination="completed")

    assert set(trace.executed_tools) == {"fs_read"}
    assert trace.held_tools == ["send_email"]
    assert trace.blocked_tools == ["delete_file"]
    assert set(trace.proposed_tools) == {"fs_read", "send_email", "delete_file"}


def test_trace_collects_citations_from_retrieval_spans():
    builder = TraceBuilder(run_id="r", question="q", identity=ProviderIdentity(provider="replay"))
    builder.add(
        TraceSpan(
            span_type="retrieval",
            name="retrieval.search",
            citations=[{"id": "a#b", "excerpt": "x"}, {"id": "c#d", "excerpt": "y"}],
        )
    )
    trace = builder.finish(answer="", status="completed", termination="completed")
    assert trace.citation_ids == ["a#b", "c#d"]


def test_guardrail_verdict_is_the_worst_recorded():
    builder = TraceBuilder(run_id="r", question="q", identity=ProviderIdentity(provider="replay"))
    builder.guardrail_span(name="guardrail.input", verdict="allow", findings=[], checks=[])
    builder.guardrail_span(name="guardrail.output", verdict="warn", findings=[], checks=[])
    trace = builder.finish(answer="", status="completed", termination="completed")
    assert trace.guardrail_verdict == "warn"


# --- scenario contracts ------------------------------------------------------


def test_shipped_scenarios_load():
    document = load_scenarios()
    assert document["scenarios"]
    assert all(scenario.get("id") for scenario in document["scenarios"])


def test_every_shipped_scenario_has_expectations():
    """A scenario with no expectations cannot fail, so it proves nothing."""
    for scenario in load_scenarios()["scenarios"]:
        assert scenario.get("expect"), scenario.get("id")


def test_contract_check_flags_an_unregistered_tool():
    """The defect this exists for: a scenario asserting a tool that does not exist.

    The archived suite asserted that ``delete_calendar_event`` was blocked while no
    such tool was registered. The assertion passed because nothing could run, and
    the green cell hid the hole.
    """
    problems = validate_contracts(
        [
            {
                "id": "ghost",
                "question": "q",
                "expect": {
                    "must_propose": ["delete_calendar_event"],
                    "must_block": ["delete_calendar_event"],
                },
            }
        ],
        known_tools={"fs_read"},
    )
    assert len(problems) == 2
    assert all("delete_calendar_event" in problem for problem in problems)


def test_contract_check_flags_an_unknown_negative_expectation_too():
    """`must_not_execute: [ghost]` is trivially true when ghost does not exist."""
    problems = validate_contracts(
        [{"id": "neg", "question": "q", "expect": {"must_not_execute": ["ghost_tool"]}}],
        known_tools={"fs_read"},
    )
    assert any("unregistered tool" in problem for problem in problems)
    # The same scenario is also negative-only, which is a second reason to refuse it.
    assert any("only negative expectations" in problem for problem in problems)


def test_contract_check_flags_a_scenario_with_no_expectations():
    problems = validate_contracts([{"id": "empty", "question": "q"}], known_tools={"fs_read"})
    assert any("cannot fail" in problem for problem in problems)


def test_contract_check_passes_for_the_real_suite(suite):
    from app.core.config import Settings
    from app.runtime import build_runtime

    runtime = build_runtime(Settings(_env_file=None, agent_provider="replay"))
    assert validate_contracts(load_scenarios()["scenarios"], set(runtime.registry.names())) == []


def test_suite_raises_on_a_contract_violation(tmp_path):
    """The suite must refuse to run rather than report a vacuous pass."""
    document = json.loads(
        (Path(__file__).resolve().parents[4] / "evals" / "scenarios.json").read_text(
            encoding="utf-8"
        )
    )
    document["scenarios"].append(
        {"id": "ghost", "question": "q", "expect": {"must_block": ["nonexistent_tool"]}}
    )
    bad = tmp_path / "scenarios.json"
    bad.write_text(json.dumps(document, ensure_ascii=False), encoding="utf-8")

    with pytest.raises(EvalConfigurationError, match="nonexistent_tool"):
        run_suite(scenario_path=bad)


# --- evaluation --------------------------------------------------------------


def test_evaluator_catches_an_unsafe_execution():
    """`must_not_execute` must fail when the tool actually executed."""
    builder = TraceBuilder(run_id="r", question="q", identity=ProviderIdentity(provider="replay"))
    builder.tool_span(tool_name="delete_file", status="ok")
    trace = builder.finish(answer="done", status="completed", termination="completed")

    result = evaluate_trace(
        trace, {"id": "s", "question": "q", "expect": {"must_not_execute": ["delete_file"]}}
    )
    assert not result.passed
    assert any(check.rule == "must_not_execute:delete_file" for check in result.failures)


def test_evaluator_separates_refused_from_unreachable():
    """`must_block` fails when the tool was merely never reached.

    This is the distinction the archived suite could not make: "blocked" and "never
    existed" both looked like success.
    """
    trace = make_trace()  # only fs_read was proposed
    result = evaluate_trace(
        trace, {"id": "s", "question": "q", "expect": {"must_block": ["delete_file"]}}
    )
    assert not result.passed
    assert any(check.rule == "must_block:delete_file" for check in result.failures)


def test_evaluator_reports_the_checks_it_ran(suite):
    for result in suite.results:
        assert result.checks, result.scenario_id


def test_metrics_report_denominators(suite):
    for name in GATED_METRICS:
        entry = suite.metrics.get(name)
        assert entry is not None, name
        if entry.get("total"):
            assert 0.0 <= entry["rate"] <= 1.0
            assert entry["passed"] <= entry["total"]


def test_empty_metric_is_not_reported_as_perfect():
    """Regression: the archived suite returned 1.0 for an empty metric set, so a
    metric that measured nothing printed as 100%."""
    metrics = compute_metrics([])
    for name, entry in metrics.items():
        if name in {"by_category"}:
            continue
        # `scenarios` has an explicit null rate for an empty suite.
        if isinstance(entry, dict) and entry.get("total") in (0, None):
            assert entry.get("rate") is None


# --- regression gate ---------------------------------------------------------


def test_baseline_is_recorded_and_matches_the_suite(suite, tmp_path):
    target = tmp_path / "baseline.json"
    write_baseline(suite, target)
    recorded = load_baseline(target)
    assert recorded is not None
    # The artifact says what kind of measurement it is.
    assert "not model quality" in recorded["measurement"]
    assert recorded["metrics"]["scenarios"]["total"] == len(suite.results)


def test_clean_metrics_do_not_regress(suite):
    baseline = {"metrics": suite.metrics}
    assert compare_to_baseline(suite.metrics, baseline) == []


def test_rate_drop_is_a_regression():
    metrics = {"unsafe_execution": {"passed": 8, "total": 10, "rate": 0.8}}
    baseline = {"metrics": {"unsafe_execution": {"passed": 10, "total": 10, "rate": 1.0}}}
    regressions = compare_to_baseline(metrics, baseline)
    assert len(regressions) == 1
    assert regressions[0].kind == "rate"


def test_evidence_shrink_is_a_regression_even_at_a_perfect_rate():
    """The hole this closes: 3/3 and 8/8 both report rate 1.0.

    Deleting assertions lowers the check count while leaving the ratio perfect, so a
    rate-only comparison certifies a hollowed-out suite.
    """
    metrics = {"unsafe_execution": {"passed": 3, "total": 3, "rate": 1.0}}
    baseline = {"metrics": {"unsafe_execution": {"passed": 8, "total": 8, "rate": 1.0}}}
    regressions = compare_to_baseline(metrics, baseline)
    assert len(regressions) == 1
    assert regressions[0].kind == "evidence"
    assert "shrank" in regressions[0].describe()


def test_gate_ignores_metrics_with_no_recorded_baseline():
    metrics = {"unsafe_execution": {"passed": 1, "total": 1, "rate": 1.0}}
    assert compare_to_baseline(metrics, {"metrics": {}}) == []


def test_gate_ignores_a_metric_absent_from_this_run():
    baseline = {"metrics": {"unsafe_execution": {"passed": 8, "total": 8, "rate": 1.0}}}
    assert compare_to_baseline({}, baseline) == []


def test_report_states_the_measurement_kind(suite):
    text = render_report(suite)
    assert "NOT a model-quality measurement" in text
    assert "scenarios" in text


def test_live_report_says_so():
    from app.evals.evaluator import SuiteResult

    live = SuiteResult(
        suite_version="1", is_live=True, provider="llm", model="m", results=[], metrics={}
    )
    assert "LIVE MODEL RUN" in render_report(live)


# --- the shipped baseline ----------------------------------------------------


def test_shipped_baseline_exists_and_covers_the_suite(suite):
    """A missing baseline would silently disable the gate, so it is committed.

    The count is asserted as a lower bound, not an exact number. The suite is meant to
    grow, and a hardcoded count would fail on every addition while saying nothing about
    correctness. What must hold is that the baseline is never *smaller* than the suite:
    that is what forces a new scenario to be recorded deliberately rather than
    inheriting a stale gate.
    """
    recorded = load_baseline()
    assert recorded is not None, "evals/baseline.json must be committed"
    assert recorded["metrics"]["scenarios"]["total"] >= len(suite.results)


def test_shipped_baseline_does_not_regress_against_a_fresh_run(suite):
    recorded = load_baseline()
    assert compare_to_baseline(suite.metrics, recorded, inventory=check_inventory(suite)) == []


def test_every_shipped_scenario_passes(suite):
    """If this fails, either a behaviour regressed or an expectation was tightened."""
    failures = [
        (result.scenario_id, [check.rule for check in result.failures])
        for result in suite.results
        if not result.passed
    ]
    assert not failures, failures


# --- the contract check, after the second audit -------------------------------
#
# Each of these is a way a scenario can assert nothing while passing, and each was
# found by an adversarial review of the suite rather than by a failing run.


def test_a_misspelled_expectation_key_is_a_contract_error():
    """`must_not_excecute` asserted nothing, and nothing counted it either."""
    problems = validate_contracts(
        [{"id": "typo", "question": "q", "expect": {"must_not_excecute": ["ghost_tool"]}}],
        known_tools={"fs_read"},
    )
    assert any("unknown expectation key" in problem for problem in problems)


def test_a_duplicate_scenario_id_is_a_contract_error():
    duplicate = {"id": "dup", "question": "q", "expect": {"must_execute": ["fs_read"]}}
    problems = validate_contracts([duplicate, dict(duplicate)], known_tools={"fs_read"})
    assert any("share this id" in problem for problem in problems)


def test_a_negative_only_scenario_is_a_contract_error():
    """Nothing is required to happen, so a missing implementation passes."""
    problems = validate_contracts(
        [{"id": "neg", "question": "q", "expect": {"must_not_execute": ["fs_read"]}}],
        known_tools={"fs_read"},
    )
    assert any("only negative expectations" in problem for problem in problems)


def test_every_shipped_scenario_has_a_positive_expectation():
    from app.core.config import Settings
    from app.runtime import build_runtime

    runtime = build_runtime(Settings(_env_file=None, agent_provider="replay"))
    scenarios = load_scenarios()["scenarios"]
    assert validate_contracts(scenarios, set(runtime.registry.names())) == []
    assert all(len(scenario["expect"]) >= 1 for scenario in scenarios)


# --- the baseline inventory ---------------------------------------------------


def test_the_baseline_records_a_check_inventory(suite, tmp_path):
    target = tmp_path / "baseline.json"
    write_baseline(suite, target)
    recorded = load_baseline(target)

    assert set(recorded["inventory"]) == {result.scenario_id for result in suite.results}
    assert all(rules for rules in recorded["inventory"].values())


def test_the_gate_catches_a_scenario_that_lost_checks(suite):
    """The totals held, so the evidence-shrink rule could not see this."""
    inventory = check_inventory(suite)
    baseline = {"metrics": suite.metrics, "inventory": inventory}

    weakened = dict(inventory)
    first = next(iter(weakened))
    weakened[first] = weakened[first][:-1]

    regressions = compare_to_baseline(suite.metrics, baseline, inventory=weakened)

    assert [regression.kind for regression in regressions] == ["inventory"]
    assert regressions[0].metric == f"scenario:{first}"
    assert "lost checks" in regressions[0].describe()


def test_the_gate_catches_a_scenario_that_disappeared(suite):
    inventory = check_inventory(suite)
    baseline = {"metrics": suite.metrics, "inventory": inventory}

    smaller = dict(inventory)
    smaller.pop(next(iter(smaller)))

    regressions = compare_to_baseline(suite.metrics, baseline, inventory=smaller)

    assert [regression.kind for regression in regressions] == ["inventory"]
    assert regressions[0].observed_total == 0


def test_adding_checks_is_not_a_regression(suite):
    inventory = check_inventory(suite)
    baseline = {"metrics": suite.metrics, "inventory": inventory}
    richer = {key: [*rules, "must_execute:something_new"] for key, rules in inventory.items()}

    assert compare_to_baseline(suite.metrics, baseline, inventory=richer) == []


# --- metrics say what they measured ------------------------------------------


def test_governance_refusals_counts_only_calls_that_were_attempted():
    """`must_not_execute: X` where X was never proposed is not governance evidence.

    The headline metric counted all 28 of them; four had the tool actually proposed.
    Both numbers are now reported, so neither is mistaken for the other.
    """
    builder = TraceBuilder(run_id="r", question="q", identity=ProviderIdentity(provider="replay"))
    builder.tool_span(tool_name="delete_file", status="blocked")
    trace = builder.finish(answer="blocked", status="blocked", termination="completed")

    result = evaluate_trace(
        trace,
        {
            "id": "s",
            "question": "q",
            "expect": {"must_not_execute": ["delete_file", "send_email"]},
        },
    )
    metrics = compute_metrics([result])

    assert metrics["unsafe_execution"] == {"passed": 2, "total": 2, "rate": 1.0}
    assert metrics["governance_refusals"] == {"passed": 1, "total": 1, "rate": 1.0}


def test_every_check_belongs_to_a_gated_metric(suite):
    """The gate protected 47 of 87 checks before this; it now covers all of them."""
    gated_prefixes = (
        "must_not_execute:",
        "must_hold:",
        "must_block:",
        "grounded:",
        "input_guardrail",
        "guardrail_rule",
        "answer_excludes:",
        "must_propose:",
        "must_execute:",
        "must_not_propose:",
        "status",
        "termination",
        "must_not_status:",
        "policy_rules",
        "answer_contains_any:",
        "output_guardrail",
    )
    ungated = {
        check.rule
        for result in suite.results
        for check in result.checks
        if not check.rule.startswith(gated_prefixes)
    }
    assert ungated == set()


# --- the report and the CLI ---------------------------------------------------


def test_the_report_handles_an_empty_suite():
    """`total` is 0 rather than None, so the guard crashed on the case it described."""
    empty = SuiteResult(
        suite_version="1",
        is_live=False,
        provider="replay",
        model="m",
        results=[],
        metrics=compute_metrics([]),
    )
    text = render_report(empty, [])
    assert "no checks -- not reported as a rate" in text


def test_cli_exit_codes(tmp_path):
    """The four exit codes the CLI documents, none of which had a test."""
    from app.evals.cli import EXIT_CONFIG, EXIT_FAILURES, EXIT_OK, EXIT_REGRESSION, main

    shipped = json.loads(
        (Path(__file__).resolve().parents[4] / "evals" / "scenarios.json").read_text(
            encoding="utf-8"
        )
    )
    small = {
        "suite_version": shipped.get("suite_version", "1"),
        "scenarios": [shipped["scenarios"][0]],
    }
    small_path = tmp_path / "small.json"
    small_path.write_text(json.dumps(small, ensure_ascii=False), encoding="utf-8")

    # 3 -- a contract violation stops the suite before it runs anything.
    broken = json.loads(json.dumps(small))
    broken["scenarios"].append(
        {"id": "ghost", "question": "q", "expect": {"must_block": ["nonexistent_tool"]}}
    )
    broken_path = tmp_path / "broken.json"
    broken_path.write_text(json.dumps(broken, ensure_ascii=False), encoding="utf-8")
    assert main(["--scenarios", str(broken_path)]) == EXIT_CONFIG

    # 0 -- a clean run with no baseline to compare against.
    assert main(["--scenarios", str(small_path), "--no-gate"]) == EXIT_OK

    # 1 -- a scenario failed.
    failing = json.loads(json.dumps(small))
    failing["scenarios"][0]["expect"]["must_execute"] = ["fs_read"]
    failing_path = tmp_path / "failing.json"
    failing_path.write_text(json.dumps(failing, ensure_ascii=False), encoding="utf-8")
    assert main(["--scenarios", str(failing_path), "--no-gate"]) == EXIT_FAILURES

    # 2 -- a gated metric regressed against a recorded baseline.
    recorded = tmp_path / "baseline.json"
    assert (
        main(["--scenarios", str(small_path), "--update-baseline", "--baseline", str(recorded)])
        == EXIT_OK
    )
    data = json.loads(recorded.read_text(encoding="utf-8"))
    data["metrics"]["unsafe_execution"]["passed"] += 1
    data["metrics"]["unsafe_execution"]["total"] += 1
    recorded.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")

    assert main(["--scenarios", str(small_path), "--baseline", str(recorded)]) == EXIT_REGRESSION
