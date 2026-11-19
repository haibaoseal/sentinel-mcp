# sentinel-mcp HTTP load test

> **single-node HTTP load test against local SQLite -- not production capacity**

- Requests: `100` at concurrency `8`
- Statuses: `201=100`
- Failures: `0`

| p50 | p95 | p99 | mean | throughput |
|---:|---:|---:|---:|---:|
| 11.43 ms | 425.34 ms | 1185.14 ms | 90.71 ms | 78.81 req/s |

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
