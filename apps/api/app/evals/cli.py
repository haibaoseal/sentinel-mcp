"""Run the deterministic evaluation suite and enforce the regression gate.

    python -m app.evals.cli                 # run, compare to baseline, exit 1 on regression
    python -m app.evals.cli --json          # machine-readable report
    python -m app.evals.cli --update-baseline
    python -m app.evals.cli --no-gate       # report only

Exit codes: 0 clean, 1 a scenario failed, 2 a gated metric regressed,
3 a scenario contract violation (an expectation naming a tool that does not exist).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from app.evals.evaluator import EvalConfigurationError
from app.evals.runner import (
    compare_to_baseline,
    load_baseline,
    render_report,
    run_suite,
    write_baseline,
)

EXIT_OK = 0
EXIT_FAILURES = 1
EXIT_REGRESSION = 2
EXIT_CONFIG = 3


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.evals.cli")
    parser.add_argument("--json", action="store_true", help="print the report as JSON")
    parser.add_argument(
        "--update-baseline",
        action="store_true",
        help="record the current metrics as the baseline (deliberate act, never automatic)",
    )
    parser.add_argument(
        "--no-gate", action="store_true", help="report only, do not fail on regression"
    )
    parser.add_argument("--baseline", type=Path, default=None)
    args = parser.parse_args(argv)

    try:
        suite, _ = run_suite()
    except EvalConfigurationError as exc:
        print(f"CONFIGURATION ERROR\n{exc}", file=sys.stderr)
        return EXIT_CONFIG

    if args.update_baseline:
        path = write_baseline(suite, args.baseline)
        print(render_report(suite))
        print(f"\nbaseline written to {path}")
        return EXIT_OK if suite.failed == 0 else EXIT_FAILURES

    regressions = []
    if not args.no_gate:
        baseline = load_baseline(args.baseline)
        if baseline is None:
            print(
                "note: no baseline recorded, so the regression gate is inactive.\n"
                "      run with --update-baseline to record one.\n",
                file=sys.stderr,
            )
        else:
            regressions = compare_to_baseline(suite.metrics, baseline)

    if args.json:
        payload = suite.to_dict()
        payload["regressions"] = [
            {"metric": r.metric, "baseline": r.baseline, "observed": r.observed}
            for r in regressions
        ]
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    else:
        print(render_report(suite, None if args.no_gate else regressions))

    if regressions:
        return EXIT_REGRESSION
    if suite.failed:
        return EXIT_FAILURES
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
