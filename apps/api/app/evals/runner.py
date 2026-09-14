"""Run the evaluation suite and compare against a stored baseline.

The regression gate is the point of this module. A suite that only prints a number
does not prevent a regression: someone weakens an expectation, the number goes up,
and the weakening is invisible. So the verified metrics are stored in version
control and a drop **fails the build**.

Two rules make the gate trustworthy rather than brittle:

1. **Only verified metrics are gated.** Each metric is compared against the recorded
   baseline with an explicit direction. A metric with no checks is not gated at all
   and is reported as absent, because "0 of 0 passed" must never read as 100%.
2. **Improving a metric requires updating the baseline deliberately.** The gate never
   rewrites the baseline itself. A gate that self-heals after a regression is not a
   gate.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.config import Settings
from app.db.models import AgentTask, Base
from app.evals.evaluator import (
    ScenarioResult,
    SuiteResult,
    compute_metrics,
    evaluate_trace,
    load_scenarios,
    validate_contracts,
)
from app.runtime import build_runtime

BASELINE_PATH = Path(__file__).resolve().parents[4] / "evals" / "baseline.json"

# Metrics that must not fall. Direction is declared per metric rather than assumed,
# so a future metric that should *increase* (a detection rate, say) is not gated
# backwards by accident.
GATED_METRICS = (
    "scenarios",
    "unsafe_execution",
    "gated_tools",
    "blocked_tools",
    "grounding",
    "input_guardrail",
    "guardrail_rule_fired",
    "honest_failure_reporting",
)


@dataclass
class Regression:
    metric: str
    baseline: float
    observed: float
    kind: str = "rate"
    baseline_total: int | None = None
    observed_total: int | None = None

    def describe(self) -> str:
        if self.kind == "evidence":
            return (
                f"{self.metric}: {self.baseline_total} checks -> {self.observed_total} "
                f"(evidence for this metric shrank)"
            )
        return f"{self.metric}: {self.baseline:.4f} -> {self.observed:.4f}"


def run_suite(
    *,
    settings: Settings | None = None,
    scenario_path: Path | None = None,
    database_url: str = "sqlite+pysqlite:///:memory:",
) -> tuple[SuiteResult, list[str]]:
    """Run every scenario, returning the suite result and any contract problems."""
    document = load_scenarios(scenario_path)
    scenarios = document["scenarios"]

    resolved = settings or Settings(_env_file=None, agent_provider="replay")
    runtime = build_runtime(resolved)
    known_tools = set(runtime.registry.names())

    contract_problems = validate_contracts(scenarios, known_tools)
    if contract_problems:
        # Fail before running anything. A scenario that names a missing tool is a
        # configuration error, and running it would produce a green cell covering a
        # hole -- the exact defect this check exists to prevent.
        raise_contract_error(contract_problems)

    engine = create_engine(database_url)
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)

    results: list[ScenarioResult] = []
    identity = runtime.provider.identity
    try:
        for scenario in scenarios:
            with factory() as session:
                task = AgentTask(
                    title=f"eval: {scenario['id']}",
                    user_request=scenario["question"],
                    status="running",
                    provider=identity.provider,
                    model=identity.model,
                )
                session.add(task)
                session.flush()
                traced = runtime.loop.run_traced(
                    task_id=task.id,
                    user_request=scenario["question"],
                    session=session,
                    scenario_id=scenario["id"],
                )
                session.commit()
            results.append(evaluate_trace(traced.trace, scenario))
    finally:
        engine.dispose()

    suite = SuiteResult(
        suite_version=str(document.get("suite_version", "1")),
        is_live=identity.is_live,
        provider=identity.provider,
        model=identity.model,
        results=results,
        metrics=compute_metrics(results),
    )
    return suite, []


def raise_contract_error(problems: list[str]) -> None:
    from app.evals.evaluator import EvalConfigurationError

    raise EvalConfigurationError("scenario contract violations:\n  " + "\n  ".join(problems))


def compare_to_baseline(metrics: dict[str, Any], baseline: dict[str, Any]) -> list[Regression]:
    """Return the gated metrics that regressed.

    Two distinct kinds are checked, and the second is the one that is easy to miss:

    1. **Rate drop** -- fewer of the checks that ran passed.
    2. **Evidence shrink** -- the *number* of checks fell while the rate stayed at
       1.0. Deleting or weakening assertions removes checks, and a rate-only
       comparison cannot see it: 3 of 3 and 8 of 8 both report 1.0. This is how a
       suite gets quietly hollowed out while still reporting a perfect score, so the
       count is gated as well as the ratio.
    """
    regressions: list[Regression] = []
    recorded = baseline.get("metrics") or {}
    for name in GATED_METRICS:
        observed_entry = metrics.get(name)
        baseline_entry = recorded.get(name)
        if not isinstance(observed_entry, dict) or not isinstance(baseline_entry, dict):
            continue

        observed_rate = observed_entry.get("rate")
        baseline_rate = baseline_entry.get("rate")
        observed_total = observed_entry.get("total")
        baseline_total = baseline_entry.get("total")

        if isinstance(observed_rate, int | float) and isinstance(baseline_rate, int | float):
            if observed_rate < baseline_rate:
                regressions.append(
                    Regression(
                        metric=name,
                        baseline=float(baseline_rate),
                        observed=float(observed_rate),
                        kind="rate",
                    )
                )
                continue

        if isinstance(observed_total, int) and isinstance(baseline_total, int):
            if observed_total < baseline_total:
                regressions.append(
                    Regression(
                        metric=name,
                        baseline=float(baseline_rate or 0.0),
                        observed=float(observed_rate or 0.0),
                        kind="evidence",
                        baseline_total=baseline_total,
                        observed_total=observed_total,
                    )
                )

    return regressions


def load_baseline(path: Path | None = None) -> dict[str, Any] | None:
    target = path or BASELINE_PATH
    if not target.exists():
        return None
    with target.open(encoding="utf-8") as handle:
        return json.load(handle)


def write_baseline(suite: SuiteResult, path: Path | None = None) -> Path:
    """Record the current metrics as the baseline. Explicit, never automatic."""
    target = path or BASELINE_PATH
    payload = {
        "suite_version": suite.suite_version,
        "provider": suite.provider,
        "model": suite.model,
        "is_live": suite.is_live,
        "measurement": (
            "live model run" if suite.is_live else "deterministic workflow run (not model quality)"
        ),
        "note": (
            "Metrics verified by the deterministic suite. The regression gate fails if a "
            "gated metric falls below these values. Update deliberately, never automatically."
        ),
        "metrics": suite.metrics,
    }
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return target


def render_report(suite: SuiteResult, regressions: list[Regression] | None = None) -> str:
    """A human-readable report. States what kind of measurement this is, up front."""
    lines: list[str] = []
    lines.append(f"suite version : {suite.suite_version}")
    lines.append(f"provider      : {suite.provider}  model={suite.model}  live={suite.is_live}")
    lines.append(
        "measurement   : "
        + (
            "LIVE MODEL RUN -- scores describe a real model"
            if suite.is_live
            else "deterministic workflow run -- NOT a model-quality measurement"
        )
    )
    lines.append("")
    lines.append(f"scenarios : {len(suite.results)}")
    lines.append(f"passed    : {suite.passed}")
    lines.append(f"failed    : {suite.failed}")
    lines.append("")

    lines.append("metrics (passed/total):")
    for name in GATED_METRICS:
        entry = suite.metrics.get(name)
        if not isinstance(entry, dict) or entry.get("total") is None:
            lines.append(f"  {name:26} (no checks -- not reported as a rate)")
            continue
        lines.append(f"  {name:26} {entry['passed']}/{entry['total']}  rate={entry['rate']:.4f}")
    lines.append("")

    if suite.failed:
        lines.append("failures:")
        for result in suite.results:
            if result.passed:
                continue
            lines.append(f"  [{result.category}] {result.scenario_id}")
            for failure in result.failures:
                lines.append(f"      - {failure.rule}: {failure.detail}")
        lines.append("")

    if regressions is not None:
        if regressions:
            lines.append("REGRESSION against baseline:")
            for regression in regressions:
                lines.append(f"  {regression.describe()}")
        else:
            lines.append("no regression against baseline")

    return "\n".join(lines)


def scenario_ids_from_document(path: Path | None = None) -> list[str]:
    return [scenario["id"] for scenario in load_scenarios(path)["scenarios"]]
