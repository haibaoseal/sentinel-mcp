# sentinel-mcp

**A governed Model Context Protocol gateway: policy, human approval, hash-chained audit and deterministic evaluation for tool-calling agents.**

The premise of this project is that the hard part of shipping an agent is not making it call tools. It is controlling *which* tools it may call, proving *what* it did afterwards, and being able to say with evidence whether a change made it safer or less safe.

`sentinel-mcp` sits between an agent and every tool it can reach — local Python functions and remote MCP servers alike — and makes each proposed call pass a policy decision, an optional human approval, and an append-only audit chain.

> **Status: Phases 0–2 of a staged build.** The governance core (policy engine, audit chain, redaction), the provider-abstracted agent loop and the real tools (sandboxed filesystem, BM25 retrieval) are implemented and tested. The MCP transports are next. See [Roadmap](#roadmap).

## Why this exists

Most agent projects demonstrate that a model *can* act. Very few demonstrate that you can stop it, review it, and audit it. This one is a governance layer, not a chatbot, and it treats tool execution as a privileged operation rather than a function call.

## The one design decision that matters

Governance must not know **where** a tool lives.

A tool may be a local Python object, a subprocess MCP server over stdio, or a remote MCP server over HTTP. All three are described by the same `ToolDescriptor` and served through the same `ToolSource` protocol, so all three are subject to the *same* policy decision, the *same* approval workflow and the *same* audit record.

Earlier versions of this codebase called a registry directly, which quietly made "governed" a property of being registered in-process. Splitting *description* from *execution* is what allows an untrusted remote tool to be governed on equal terms — and it is why adding MCP support did not require touching the policy engine, the approval service or the audit log.

```text
LLM agent ──► ToolRequest
                 │
                 ▼
        ┌─────────────────┐
        │  PolicyEngine   │  YAML rules, fails closed on unknown tools
        └────────┬────────┘
     allow ◄─────┼─────► block / require_approval
                 ▼
        ┌─────────────────┐
        │ ApprovalService │  human review; modifications re-evaluated
        └────────┬────────┘
                 ▼
        ┌─────────────────┐        ┌──────────────┐  ┌──────────────┐
        │    Firewall     │───────►│ LocalTool    │  │ MCPToolSource│──► stdio / HTTP
        └────────┬────────┘        │ Source       │  └──────────────┘
                 ▼                 └──────────────┘
        ┌─────────────────┐
        │   AuditLogger   │  per-task hash chain, ordered by explicit seq
        └─────────────────┘
```

## Safety posture

The default posture of a fresh checkout is that **nothing real happens**:

- No real email is sent, no real file is deleted, no production database is mutated.
- Real connectors, real writes, real destructive actions and real external actions are each behind a separate opt-in flag.
- Tools that are absent from the ruleset are **not** allowed to run unattended — they fall through to `require_approval`.
- Switching a runtime flag on never overrides a `default_block` rule.

These are enforced in code and asserted in tests, not merely documented.

## Quick start

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# POSIX:   source .venv/bin/activate
python -m pip install -e ".[dev]"

python -m pytest apps/api/app/tests   # 183 tests
python -m ruff check apps/api/app scripts
python -m ruff format --check apps/api/app scripts
```

### Watch the agent get governed

```bash
python scripts/demo_agent.py     # four requests, four different governance outcomes
python scripts/verify_p0_fixes.py  # audit-chain and redaction guarantees, live
```

`demo_agent.py` runs the whole stack — provider, loop, policy, approval, audit — and prints:

| Request | Outcome |
|---|---|
| 普通商品多久可以退货？ | `completed` — retrieves policy evidence and answers |
| 订单 ORD-1001 申请退款 | `waiting_approval` — financial action held for a human |
| 帮我删除文件 notes.md | `blocked` — with all three policy reasons listed |
| 读取 missing.md 的内容 | `failed` — reports the tool error, does **not** claim success |

Each of those four runs leaves a hash chain that verifies, and the script then tampers with one event to show detection at the exact sequence number.

### Point it at a real model

The loop is provider-agnostic. Any OpenAI-compatible endpoint works:

```bash
# .env
AGENT_PROVIDER=llm
LLM_API_KEY=sk-...
LLM_MODEL=deepseek-chat
LLM_BASE_URL=https://api.deepseek.com/v1   # Kimi, Qwen, vLLM, a local gateway…
```

The governance path is byte-for-byte the same one the offline provider uses, so an eval result is comparable between the two. `ProviderIdentity.is_live` records which one produced any given trace, which is what stops a replay score being presented as model quality.

## Design notes worth reading

### The agent loop is stateless between turns

Everything the provider needs is in the message list, so a run can be reconstructed from its transcript. A provider that keeps its plan in instance state cannot be replayed from a log — and an unexplainable audit trail is not an audit trail.

### The loop never executes a tool

It asks the firewall, which applies policy and writes the audit record. The firewall is the only caller of a tool source, and CI fails if a stray `.execute(` appears anywhere else.

### A failed, blocked or held call is never reported as success

The loop derives run status from what actually happened and **overrides the model's closing text** whenever the status is not `completed`. This is a deliberate answer to a specific defect: the archived implementation started from `status = "passed"`, so an internal schema-validation string reached a user under a green badge.

### Retrieval uses BM25, not overlap

Raw token overlap with no IDF means high-frequency function characters decide the ranking. Measured on the archived code: 64% of one query's score came from single characters, and an unrelated question ("今天天气怎么样") returned three "citations" because the only filter was `score > 0`. Matching now keys off CJK bigrams with real IDF and a relative relevance floor, so an unrelated question returns nothing — which is the honest answer.

### The filesystem sandbox resolves before it compares

Path checks run on the *resolved* path with `strict=False`, so containment does not depend on the target existing. Checking the raw string would accept `../../etc/passwd`; checking after an existence test would report an escape attempt as "file not found", which is both a worse message and a weaker boundary.


## What is verified, and how

This project's central claim is that its safety properties are measured rather than asserted. Concretely:

| Property | How it is checked |
|---|---|
| An honest audit chain verifies even when all events share a timestamp | `test_audit_chain.py::test_chain_verifies_when_every_event_shares_one_timestamp` |
| Payload tampering is detected at the exact sequence number | `test_audit_chain.py::test_tampering_with_a_payload_is_detected` |
| Deleting a middle event is detected | `test_audit_chain.py::test_deleting_a_middle_event_is_detected` |
| Secrets and Chinese PII are redacted (15 credential shapes, 7 PII shapes) | `test_redaction.py` — asserts the **absence** of a discriminating substring |
| Unknown tools, unknown actions and destructive tools fail closed | `test_policy_engine.py` |
| Read-only SQL cannot be escaped by stacked statements or comments | `test_policy_engine.py` |
| A failed tool call is never answered with the model's success claim | `test_agent_loop.py::test_failed_run_is_not_reported_as_success` |
| A repeated identical call stops the loop instead of burning turns | `test_agent_loop.py::test_identical_repeated_call_is_detected_before_the_turn_limit` |
| Every executed call has a matching audit record and a verifying chain | `test_agent_loop.py::test_every_executed_call_has_an_audit_record` |
| Path traversal, absolute paths and symlink escape are refused | `test_filesystem_sandbox.py` |
| Citation line ranges point at the cited content | `test_knowledge_retrieval.py::test_line_range_points_at_the_real_content` |
| An unrelated question returns no citations instead of weak matches | `test_knowledge_retrieval.py::test_unrelated_query_returns_nothing` |

### Two defects these tests exist to prevent

Both were measured in the predecessor codebase and are worth naming, because they are the reason several of these tests assert absence rather than presence:

1. **A tamper-evident log that cried wolf.** The chain was written ordered by `(created_at DESC, id DESC)` and verified ordered by `(created_at ASC, id ASC)`. Inside a single request, events routinely share a timestamp — so *honestly written* chains failed verification. A log that reports false positives trains its operators to ignore it. Fixed by ordering on an explicit, gap-free `seq` column, and by a uniqueness constraint that turns any interleaving bug into a loud `IntegrityError` rather than a silently forked chain.

2. **A redactor that produced false confidence.** `Bearer abc+/def==` was rewritten to `[REDACTED]+/def==` — it *looked* redacted while leaking the tail, because the character class stopped at `+`. Uppercase `SK-`, `ghp_`, `xoxb-`, Azure-style hex keys, Chinese national ID numbers and space-separated phone numbers all passed through untouched. The test that "verified" this probed only the four shapes its own regexes already covered, so it could never discover a gap. The replacement redacts by shape and case-insensitively, normalises key names (`x-api-key`, `X_API_KEY` and `apiKey` are one key), masks non-string values under sensitive keys, and is tested by asserting that a discriminating substring is **gone**.

## Honest limitations

Stated plainly, because overclaiming safety is worse than having none:

- **The audit chain is unkeyed by default.** It detects modification, deletion and reordering of stored events. It cannot resist an attacker who rewrites the entire table from genesis, because nothing outside the database pins the head. An optional HMAC key closes that gap; it is not on by default. `test_unkeyed_chain_is_rewritable_from_genesis` asserts this weakness so it cannot be quietly forgotten.
- **Redaction is deny-by-shape.** It recognises enumerated formats. A secret in a format nobody anticipated will pass through. It raises the cost of a leak; it does not make one impossible.
- **This is a governance prototype**, not certified security software. Production use would need RBAC, tenant isolation, immutable external audit storage, and rate limiting.
- **The offline provider is a scripted workflow, not a model.** It decides from accumulated tool results rather than from question keywords, so the loop is genuinely iterative — but its "intelligence" is written down, not learned. Scores from it must never be presented as model quality, which is why `ProviderIdentity.is_live` travels with every run.
- **No MCP transports yet.** Phase 3. Nothing here claims MCP support today.

## Roadmap

| Phase | Scope | State |
|---|---|---|
| 0 | Governance core: contracts, policy engine, audit chain, redaction, CI | **done** |
| 1 | Provider-abstracted agent loop (real model when a key is present, deterministic replay otherwise) | **done** |
| 2 | Real tools: sandboxed filesystem, BM25 knowledge retrieval, maintenance tools | **done** |
| 3 | MCP gateway: client and server, stdio and Streamable HTTP transports | in progress |
| 4 | Per-id citation binding, contradiction-aware output guardrails, bilingual injection detection | planned |
| 5 | Unified trace DTO, deterministic evaluation, regression gate that fails CI on a score drop | planned |
| 6 | End-to-end tests, live smoke test, deployment | planned |
| 7 | Positioning and interview narrative | planned |

Note that Phase 4 and Phase 3 are partly independent, and Phase 4 fixes are
already justified by measurement rather than speculation: the archived guardrail
allowed "退款草案会直接完成退款" to pass while citing the very excerpt that
contradicts it, and its injection detector did not catch the plain English
phrase "Ignore all previous instructions".

## Repository layout

```text
apps/api/app/
  core/       contracts (ToolRequest, ToolDescriptor, ToolSource), config, typed errors
  policy/     YAML rules + evaluator
  audit/      hash-chained append-only log
  security/   secret and PII redaction
  providers/  Provider protocol, offline ReplayProvider, OpenAI-compatible LLMProvider
  agent/      the governed agent loop
  governance/ the firewall: the single execution boundary
  tools/      registry + sources (filesystem sandbox, BM25 knowledge, maintenance)
  db/         SQLAlchemy models
  tests/      pytest suite
knowledge/    versioned policy documents that citations point into
sandbox/      the only directory the filesystem tools can touch
scripts/      operator-facing verification and demo scripts
```

## Licence

MIT.
