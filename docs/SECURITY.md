# Security model

This document describes the trust boundaries and the controls that are actually
enforced in code. It is not a certification and it is not a claim that the system
is unhackable. The known gaps are listed at the end and mirrored in the README's
Honest limitations.

## Trust boundaries

```text
untrusted user / business client
        │  bearer key (identity, tenant, role)
        ▼
  HTTP API  ── validates input, scopes every query by tenant, checks role
        │
        ▼
  Agent loop ── provider may be a live model; its output is untrusted text
        │  ToolRequest
        ▼
  Firewall ── policy decision + approval hold + audit write (one transaction)
        │
        ├── local tools (sandboxed filesystem, read-only SQL, HTTP allow-list)
        └── remote MCP servers (stdio/HTTP) — untrusted remote code
        │
        ▼
  Postgres / SQLite — the audit chain and approval state
```

The API key is the only identity the service trusts. The model is not trusted to
classify a tool correctly, the remote MCP server is not trusted to describe a
tool honestly, and retrieved text is data, not instruction.

## Authentication

- `Authorization: Bearer <key>` (or `X-API-Key` is not accepted; only Bearer).
- Keys are configured in `SENTINEL_API_KEYS_JSON`, never stored in the database.
- Each key maps to exactly one `tenant`, one `role` and one `subject`.
- Key comparison is `hmac.compare_digest` over every candidate, without an early
  exit on the first mismatch.
- An unknown key and a missing key both return `401` with the same body shape;
  the response does not reveal whether a key exists.
- Production (`APP_ENV=production`) refuses to start with no configured keys.
  The development `dev-admin-key` is issued only outside production and is
  logged as a warning at startup.

**Not implemented:** OIDC/SSO, short-lived tokens, per-key revocation lists,
key-scoped permissions beyond the role, and audit of authentication failures
(beyond the structured access log).

## Authorization

Roles are ordered; a higher role satisfies every lower requirement.

| Capability | viewer | operator | approver | admin |
|---|:---:|:---:|:---:|:---:|
| Read tasks, traces, approvals, audit, tools, policy metadata | ✓ | ✓ | ✓ | ✓ |
| Create a task (`POST /v1/tasks`) | — | ✓ | ✓ | ✓ |
| Approve/reject an approval | — | — | ✓ | ✓ |
| Read raw policy YAML | — | — | — | ✓ |
| `/metrics` | network/token | network/token | network/token | network/token |

`/healthz` and `/readyz` are unauthenticated because a load balancer must reach
them before a credential exists. They expose no tenant data.

## Tenant isolation

The tenant is taken from the API key, never from a request body or query string.
Every task, approval, audit, trace and policy query filters by that tenant. A
cross-tenant read returns `404`, not `403`, so an id cannot be probed for
existence. A cross-tenant approve is tested and returns `404`.

**Gap:** this is application-level enforcement. A future query that forgets the
tenant filter would not be stopped by the database. Postgres row-level security
is the intended defence in depth; it is not implemented.

## Approval safety

A `require_approval` decision writes an `ApprovalRequest` and returns
`waiting_approval`. An approval is **checked, not trusted**:

- the approval must exist and be in `approved` or `modified`;
- it must cover a proposal for the same tool;
- the arguments being executed must match the approved arguments exactly;
- a `block` decision is never relaxed by an approval;
- a decision is spent by the attempt it authorises (`executed`/`failed`), so it
  cannot be replayed; it is bound to the proposal, so it cannot be transferred;
- an edited argument set is re-evaluated by the policy engine and refused if it
  raises the risk above what the reviewer saw.

Reviewer identity is the key's `subject`; the decision and execution are written
to the same hash chain as the original proposal.

## Audit integrity

- Every task has a chain ordered by an explicit, gap-free `seq` (not a clock).
- `event_hash = H(prev_hash || canonical_envelope)`, optionally HMAC-SHA256 with
  `AUDIT_HMAC_KEY`.
- Verification checks sequence continuity, `prev_hash`, and `event_hash`, and
  reports the exact first bad sequence.
- Payloads are redacted before hashing and storage; the audit chain stores the
  redacted form.
- `GET /v1/audit/export` streams NDJSON with a manifest containing the chain head
  and verdict; the response headers carry `X-Chain-Verified` and `X-Chain-Checked`.

**Limits:**

- The chain is unkeyed by default; a full rewrite from genesis is undetectable
  without an external anchor.
- Deleting the **tail** of a chain is not detected: the validator requires a
  gap-free sequence from 1, and a shorter prefix still satisfies it.
- There is no online HMAC key rotation with key ids. Rotating the key makes old
  chains fail verification; export and archive first.
- Retention deletes rows after archiving them to local NDJSON; that is not
  immutable/WORM storage.

## Tool execution controls

| Control | Implementation |
|---|---|
| Single execution boundary | Only `Firewall.execute` calls `ToolRegistry.execute`; CI greps for other call sites (a regression guard, not a runtime invariant) |
| Fail closed | Unknown tools and unknown action types require approval; missing runtime flags deny |
| Filesystem | Resolved-path containment, link-like entries skipped and named, `O_NOFOLLOW` where available |
| SQL | SQLite opened with `mode=ro` and `PRAGMA query_only`; `ATTACH`/`DETACH`/`VACUUM` refused at the tool layer |
| HTTP | Host allow-list, resolved private/loopback/link-local refusal, no redirects, `trust_env=False`, response size cap |
| MCP | Namespaced names, duplicate-name refusal, unmapped tools default to `unknown` → approval, child environment allow-list, bounded descriptions and results |
| Prompt injection | Bilingual input screening with normalisation; advisory for retrieved text, blocking for the user request |
| Output claims | Pattern-based capability/citation checks; explicitly not entailment |

## Secrets and data handling

- Secrets come from the environment; `.env` is gitignored.
- `AUDIT_HMAC_KEY`, `GITHUB_TOKEN`, `LLM_API_KEY` and API keys are never returned
  by an endpoint.
- Audit payloads, replay and eval Markdown are redacted by shape (credentials,
  JWTs, cloud keys, cards, SSNs, IBANs, Chinese PII).
- Redaction is deny-by-shape: an unanticipated format can pass.
- Logs contain method, route, status, duration and ids; request bodies and
  authorization headers are not logged.

## Threat model (summary)

| Threat | Control | Residual risk |
|---|---|---|
| Prompt injection makes the agent call a destructive tool | Policy fail-closed, approval, block, guardrail input screen | A novel phrasing can influence the model; the firewall remains the boundary |
| Malicious remote MCP server advertises a dangerous tool | Unmapped tools default to `unknown` → approval; namespacing; no wildcard grants | Operator mapping a tool to `read` grants it; mapping is a trust decision |
| Stolen API key | Tenant/role scoping, audit subject, rotation by config | No short-lived tokens or revocation endpoint; a leaked key works until redeploy |
| Cross-tenant data access | Tenant from key, scoped queries, 404 on mismatch | Application-level only; no RLS |
| Approval replay / transfer | Exact argument match, same-tool binding, spent decision | — |
| Audit tampering | Hash chain, HMAC option, export with head | Tail truncation; full-genesis rewrite without an anchor |
| SSRF via `http_get` | Allow-list + resolved address check + no redirects | DNS rebinding window between check and connect |
| Path traversal / junction escape | Resolved-path containment, link-like skip, `O_NOFOLLOW` | Resolve-then-open race; needs `openat` traversal |
| Secret leakage into audit | Shape-based redaction before hash/storage | Unknown formats pass; redaction can damage evidence |
| Overload / denial of service | Per-tenant token bucket, bounded gate, 429 | In-process only; no global quota across replicas |

## Incident response

1. **Suspected key compromise**: remove the key from configuration, redeploy,
   review the tenant's audit events for that `subject`, notify the tenant owner.
2. **Audit verification failure**: stop writes, snapshot the database, run
   `python -m app.audit.cli verify --all`, export affected tasks, preserve the
   broken chain. Do not rewrite events.
3. **Tool dependency compromise / circuit open**: disable the tool in policy
   (`enabled: false` or `default_block: true`), redeploy the policy, review calls
   made while it was enabled.
4. **Cross-tenant finding**: treat as a critical incident; preserve logs, verify
   every query in the affected path, add a regression test before restoring
   service.

## Reporting

This is a portfolio project; there is no bug bounty. Open an issue with a minimal
reproduction and the expected/actual behaviour. Please do not include real
credentials or personal data in a report.
