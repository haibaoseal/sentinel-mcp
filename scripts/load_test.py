"""A small HTTP load test with p50/p95/p99 and an error budget.

It starts a real uvicorn process against a temporary SQLite database, sends a
fixed number of requests at a fixed concurrency, and writes a report. This is a
single-node measurement; the report says so, because a laptop number presented as
production capacity is the kind of overclaim this project exists to avoid.

    python scripts/load_test.py --requests 200 --concurrency 10
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import statistics
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]
API_KEYS = json.dumps(
    [{"key": "load-admin-key", "tenant": "load", "role": "admin", "subject": "load"}]
)
HEADERS = {"Authorization": "Bearer load-admin-key"}


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def wait_for(url: str, process: subprocess.Popen, timeout: float = 30.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"uvicorn exited with {process.returncode}")
        try:
            response = httpx.get(url, timeout=1.0, trust_env=False)
            if response.status_code == 200:
                return
        except Exception:
            pass
        time.sleep(0.2)
    raise RuntimeError(f"server did not become healthy within {timeout}s")


def percentile(values: list[float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int(round(fraction * (len(ordered) - 1)))))
    return ordered[index]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--requests", type=int, default=200)
    parser.add_argument("--concurrency", type=int, default=10)
    parser.add_argument("--out-dir", default=str(ROOT / "reports"))
    args = parser.parse_args(argv)

    database = Path(tempfile.mkdtemp()) / "load.db"
    port = free_port()
    env = os.environ.copy()
    env.update(
        {
            "PYTHONPATH": str(ROOT / "apps" / "api"),
            "APP_ENV": "development",
            "LOG_LEVEL": "warning",
            "LOG_JSON": "true",
            "DATABASE_URL": f"sqlite:///{database.as_posix()}",
            "AUTO_CREATE_SCHEMA": "true",
            "SENTINEL_API_KEYS_JSON": API_KEYS,
            "TOOL_SANDBOX_ROOT": str(ROOT / "sandbox"),
            "KNOWLEDGE_ROOT": str(ROOT / "knowledge"),
            "RATE_LIMIT_PER_MINUTE": "100000",
            "MAX_CONCURRENT_TASKS": "16",
            "METRICS_TOKEN": "",
        }
    )
    log_path = Path(tempfile.mkdtemp()) / "uvicorn.log"
    log_file = log_path.open("w", encoding="utf-8")
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "app.api.asgi:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--log-level",
            "warning",
        ],
        cwd=ROOT,
        env=env,
        stdout=log_file,
        stderr=subprocess.STDOUT,
    )

    base = f"http://127.0.0.1:{port}"
    try:
        try:
            wait_for(f"{base}/healthz", process)
        except Exception:
            log_file.flush()
            print(log_path.read_text(encoding="utf-8", errors="replace"), file=sys.stderr)
            raise
        # Warm up the connection pool and the import path once.
        with httpx.Client(timeout=30.0, trust_env=False) as client:
            for _ in range(5):
                client.post(
                    f"{base}/v1/tasks",
                    json={"request": "普通商品多久可以退货？"},
                    headers=HEADERS,
                )

            latencies: list[float] = []
            statuses: dict[str, int] = {}
            errors: list[str] = []

            def one(_index: int) -> None:
                started = time.perf_counter()
                try:
                    response = client.post(
                        f"{base}/v1/tasks",
                        json={"request": "普通商品多久可以退货？", "title": "load"},
                        headers=HEADERS,
                    )
                    statuses[str(response.status_code)] = (
                        statuses.get(str(response.status_code), 0) + 1
                    )
                    if response.status_code >= 500:
                        errors.append(response.text[:200])
                except Exception as exc:  # noqa: BLE001 - the report needs the error
                    statuses["exception"] = statuses.get("exception", 0) + 1
                    errors.append(f"{type(exc).__name__}: {exc}")
                finally:
                    latencies.append((time.perf_counter() - started) * 1000)

            started = time.perf_counter()
            with ThreadPoolExecutor(max_workers=args.concurrency) as pool:
                list(pool.map(one, range(args.requests)))
            elapsed = time.perf_counter() - started
    finally:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
        log_file.close()

    failures = sum(count for status, count in statuses.items() if status.startswith("5"))
    failures += statuses.get("exception", 0)
    report = {
        "simulated": True,
        "measurement": "single-node HTTP load test against local SQLite -- not production capacity",
        "generated_at": datetime.now(UTC).isoformat(),
        "requests": args.requests,
        "concurrency": args.concurrency,
        "statuses": statuses,
        "failures": failures,
        "latency_ms": {
            "p50": round(percentile(latencies, 0.50), 2),
            "p95": round(percentile(latencies, 0.95), 2),
            "p99": round(percentile(latencies, 0.99), 2),
            "mean": round(statistics.fmean(latencies), 2) if latencies else 0.0,
        },
        "wall_clock_seconds": round(elapsed, 2),
        "requests_per_second": round(args.requests / elapsed, 2) if elapsed else 0.0,
        "errors": errors[:5],
    }
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "load_test.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    (out_dir / "load_test.md").write_text(_render_markdown(report), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    if failures:
        print(f"server log: {log_path}", file=sys.stderr)
        return 1
    return 0


def _render_markdown(report: dict) -> str:
    latency = report["latency_ms"]
    statuses = ", ".join(f"{key}={value}" for key, value in sorted(report["statuses"].items()))
    row = (
        f"| {latency['p50']} ms | {latency['p95']} ms | {latency['p99']} ms | "
        f"{latency['mean']} ms | {report['requests_per_second']} req/s |"
    )
    return f"""# sentinel-mcp HTTP load test

> **{report["measurement"]}**

- Requests: `{report["requests"]}` at concurrency `{report["concurrency"]}`
- Statuses: `{statuses}`
- Failures: `{report["failures"]}`

| p50 | p95 | p99 | mean | throughput |
|---:|---:|---:|---:|---:|
{row}

## Honest scope

This is one uvicorn worker, one SQLite file, on the machine that generated the
report. It is useful for catching a regression in the service path and for
putting a number on the local workflow. It is **not** a production capacity
claim: Postgres, multiple replicas, connection pooling and the real model
provider all change the result. The report is labelled `simulated` for that
reason.

The p95/p99 tail here is dominated by SQLite's single-writer lock: each task
writes several audit events in one transaction, so extra concurrency queues on
the database rather than on the HTTP layer. Postgres write concurrency is the
measurement that matters for production and is not claimed here.
"""


if __name__ == "__main__":
    raise SystemExit(main())
