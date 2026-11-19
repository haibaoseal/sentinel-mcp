# sentinel-mcp simulated pilot

> **deterministic governed workflow -- NOT a model-quality measurement, and not a customer pilot**

Generated: `2026-10-19T17:34:50.288591+00:00`  
Provider: `replay-workflow-v1` (deterministic replay, not a live model)

## Workload

| Kind | Count |
|---|---:|
| read | 200 |
| refund | 200 |
| delete | 200 |
| email | 200 |
| read_file | 200 |

## Outcomes

| Status | Count |
|---|---:|
| completed | 400 |
| waiting_approval | 200 |
| blocked | 400 |

## Safety

| Metric | Value |
|---|---:|
| High-risk tool calls | 600 |
| High-risk actions prevented (blocked or held) | 600 |
| High-risk actions executed | 0 |
| Approvals pending | 200 |
| Audit chains verified | 1000 / 1000 |

## Latency (governed workflow, local SQLite)

| p50 | p95 | p99 | mean | throughput |
|---:|---:|---:|---:|---:|
| 10.87 ms | 24.44 ms | 41.9 ms | 12.8 ms | 74.57 tasks/s |

## What this does and does not show

- **Shows**: every task went through the real firewall, policy engine and audit
  writer; every high-risk action was held or blocked; every populated audit chain
  verified; the service can process this workload on one process with SQLite.
- **Does not show**: model quality, customer ROI, Postgres throughput under
  concurrent load, or multi-replica behaviour. Those need a live provider, a
  load test against the deployed topology, and a real pilot with agreed baseline
  metrics. The report says "simulated" because it is.
