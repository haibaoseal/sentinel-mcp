"""Policy rules: the declarative half of governance.

Rules live in YAML so that a reviewer can change what the runtime allows
without reading Python. The engine's job is to be total: for any request it
returns a decision, and the *absence* of a rule never silently means "allow".
Unknown tools and unknown action types therefore fail closed.
"""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

from app.core.contracts import RISK_ORDER, ToolRequest, max_risk

DEFAULT_POLICY_PATH = Path(__file__).with_name("default_policy.yaml")

# SQL verbs that mutate state or schema. Anchored on word boundaries so that a
# column literally named "created_at" does not trip the "create" rule.
SQL_WRITE_PATTERN = re.compile(
    r"\b(insert|update|delete|drop|alter|truncate|create|grant|revoke|replace)\b",
    re.IGNORECASE,
)

# Statements that only read. Anything not matching this, in a read-only tool,
# is refused rather than pattern-matched for bad verbs.
SQL_READ_PREFIXES = ("select", "with", "explain", "show", "describe", "pragma")


class PolicyDecision(BaseModel):
    decision: str
    risk_level: str
    reasons: list[str] = Field(default_factory=list)
    matched_rules: list[str] = Field(default_factory=list)
    transformed_request: ToolRequest | None = None

    @property
    def risk_rank(self) -> int:
        return RISK_ORDER.get(self.risk_level, 0)


@lru_cache
def load_policy_document(path: str | None = None) -> dict[str, Any]:
    target = Path(path) if path else DEFAULT_POLICY_PATH
    with target.open(encoding="utf-8") as handle:
        document = yaml.safe_load(handle) or {}
    if not isinstance(document, dict):
        raise ValueError(f"policy root must be a mapping, got {type(document).__name__}")
    return document


class PolicyEngine:
    """Evaluates a proposal against the YAML rule set.

    The engine is deliberately pure: it never touches a database and never
    executes a tool, so it can be tested exhaustively and reused by the CLI,
    the API and the MCP gateway without divergence.
    """

    def __init__(self, policy: dict[str, Any] | None = None) -> None:
        self.policy = policy if policy is not None else load_policy_document()

    # -- public API ---------------------------------------------------------

    def evaluate(
        self, request: ToolRequest, *, runtime_flags: dict[str, bool] | None = None
    ) -> PolicyDecision:
        reasons: list[str] = []
        matched: list[str] = []
        tools = self.policy.get("tools", {})
        rule = tools.get(request.tool_name)

        if rule is None:
            decision = str(self.policy.get("defaults", {}).get("unknown_tool", "require_approval"))
            risk = "high"
            reasons.append(f"Unknown tool {request.tool_name!r} must be reviewed before execution.")
            matched.append("defaults.unknown_tool")
        else:
            matched.append(f"tools.{request.tool_name}")
            risk = str(rule.get("risk", "medium"))
            decision = self._base_decision(rule, request, reasons, matched)

        risk = self._escalate_action_type(request, decision, risk, reasons, matched)
        # Escalation deliberately returns only risk; the decision floor is applied
        # here so there is exactly one place a caller can audit. `unknown` is the
        # "caller did not classify" marker and must never be treated as safe.
        if request.action_type == "unknown" and decision != "block":
            decision = "require_approval"
        if request.action_type == "external_send" and decision == "allow":
            decision = "require_approval"
        if request.action_type == "destructive" and decision != "block":
            decision = "require_approval"
        if request.action_type == "financial" and decision == "allow":
            decision = "require_approval"

        decision, risk = self._scan_sensitive_arguments(request, decision, risk, reasons, matched)
        decision, risk = self._enforce_sql_read_only(request, decision, risk, reasons, matched)

        if runtime_flags:
            decision, risk = self._enforce_runtime_flags(
                request, rule, decision, risk, reasons, matched, runtime_flags
            )

        transformed = self._build_transformed_request(request, rule)
        if transformed is not None and decision == "allow":
            decision = "transform"
            reasons.append("Policy transformed the request before execution.")
            matched.append(f"tools.{request.tool_name}.transform")

        # Only expose a rewritten request when it will actually be executed.
        # Attaching it to a block/approval decision would hand the caller a
        # payload that never went through review, which is how a "modified"
        # request could be mistaken for an authorised one.
        if decision not in {"allow", "transform"}:
            transformed = None

        return PolicyDecision(
            decision=decision,
            risk_level=risk,
            reasons=reasons,
            matched_rules=matched,
            transformed_request=transformed,
        )

    # -- rule helpers -------------------------------------------------------

    def _base_decision(
        self,
        rule: dict[str, Any],
        request: ToolRequest,
        reasons: list[str],
        matched: list[str],
    ) -> str:
        if rule.get("enabled", True) is False:
            reasons.append(f"{request.tool_name} is disabled by policy.")
            matched.append(f"tools.{request.tool_name}.enabled")
            return "block"
        if bool(rule.get("default_block", False)):
            reasons.append(
                f"{request.tool_name} is marked default_block because it can cause "
                "irreversible changes."
            )
            # Record the specific rule, not just the tool. A trace that says only
            # "tools.delete_file matched" cannot distinguish "the tool is known"
            # from "this rule is what blocked it", which is the question a reviewer
            # is actually asking.
            matched.append(f"tools.{request.tool_name}.default_block")
            return "block"
        if bool(rule.get("approval_required", False)):
            reasons.append(
                f"{request.tool_name} is a {rule.get('action_type')} action and requires approval."
            )
            return "require_approval"
        reasons.append(f"{request.tool_name} is allowed by policy.")
        return "allow"

    def _escalate_action_type(
        self,
        request: ToolRequest,
        current: str,
        risk: str,
        reasons: list[str],
        matched: list[str],
    ) -> str:
        # `unknown` is the marker for "caller did not classify this action", not a
        # real category. It must never count as recognised, otherwise the
        # fail-closed escalation below silently does nothing. (The ruleset lists
        # it for documentation; this set is the authority.)
        unrecognised = {"unknown"}
        known = set(self.policy.get("known_action_types") or []) - unrecognised
        if not known:
            known = {"read", "write", "external_send", "destructive", "financial"}
        if request.action_type in unrecognised or request.action_type not in known:
            risk = max_risk(risk, "high")
            if current != "block":
                current = "require_approval"
            reasons.append(f"Unrecognised action_type {request.action_type!r} requires approval.")
            matched.append("defaults.unknown_action")
        if request.action_type == "external_send":
            risk = max_risk(risk, self._configured_risk("sends_message", "high"))
            reasons.append("External send actions can affect people outside the system.")
            matched.append("risk_escalation.sends_message")
        if request.action_type == "destructive":
            risk = max_risk(risk, self._configured_risk("destructive_action", "critical"))
            reasons.append("Destructive actions are critical risk.")
            matched.append("risk_escalation.destructive_action")
        if request.action_type == "financial":
            risk = max_risk(risk, self._configured_risk("financial_action", "critical"))
            reasons.append("Financial actions move value and are treated as critical risk.")
            matched.append("risk_escalation.financial_action")
        return risk

    def _configured_risk(self, key: str, floor: str) -> str:
        """The higher of the built-in floor and what the ruleset asks for.

        This is what makes ``risk_escalation`` in the YAML a control rather than
        documentation: it was three hardcoded levels with six keys beside them, three
        of which nothing read. Configuration may raise a level and never lower one --
        a ruleset that says ``destructive_action: low`` must not be able to switch a
        critical escalation off.
        """
        configured = str((self.policy.get("risk_escalation") or {}).get(key, floor))
        return max_risk(floor, configured)

    def _scan_sensitive_arguments(
        self,
        request: ToolRequest,
        decision: str,
        risk: str,
        reasons: list[str],
        matched: list[str],
    ) -> tuple[str, str]:
        """Escalate when arguments look like they carry regulated data.

        Note this scans *all* groups rather than returning on the first hit; the
        earlier implementation returned early, so a request containing both a
        password and an ID number reported only one reason and hid the other.
        """
        serialized = json.dumps(request.arguments, ensure_ascii=False, default=str).lower()
        hits: list[str] = []
        for group in self.policy.get("sensitive_patterns", []) or []:
            name = str(group.get("name", "unnamed"))
            for pattern in group.get("patterns", []) or []:
                if str(pattern).lower() in serialized:
                    hits.append(name)
                    break
        if not hits:
            return decision, risk

        risk = max_risk(risk, "critical")
        if decision == "allow":
            decision = "require_approval"
        for name in hits:
            reasons.append(f"Arguments may contain sensitive data matching pattern group {name!r}.")
            matched.append(f"sensitive_patterns.{name}")
        return decision, risk

    def _enforce_sql_read_only(
        self,
        request: ToolRequest,
        decision: str,
        risk: str,
        reasons: list[str],
        matched: list[str],
    ) -> tuple[str, str]:
        rule = (self.policy.get("tools", {}) or {}).get(request.tool_name) or {}
        constraints = rule.get("constraints") or {}
        if not constraints.get("read_only"):
            return decision, risk

        query = str(request.arguments.get("query") or request.arguments.get("sql") or "").strip()
        if not query:
            reasons.append(f"{request.tool_name} is read-only but no query was supplied.")
            matched.append(f"tools.{request.tool_name}.constraints.read_only")
            return "block", max_risk(risk, "high")

        lowered = query.lower().lstrip("(").strip()
        if not lowered.startswith(SQL_READ_PREFIXES):
            reasons.append(
                f"{request.tool_name} is read-only; only SELECT-style statements are permitted."
            )
            matched.append(f"tools.{request.tool_name}.constraints.read_only")
            return "block", "critical"
        if SQL_WRITE_PATTERN.search(query):
            reasons.append("Query contains a write or schema-changing SQL keyword.")
            matched.append(f"tools.{request.tool_name}.constraints.read_only")
            return "block", "critical"
        if ";" in query.rstrip("; \n\t"):
            reasons.append("Stacked SQL statements are refused in read-only mode.")
            matched.append(f"tools.{request.tool_name}.constraints.read_only")
            return "block", "critical"
        return decision, risk

    def _enforce_runtime_flags(
        self,
        request: ToolRequest,
        rule: dict[str, Any] | None,
        decision: str,
        risk: str,
        reasons: list[str],
        matched: list[str],
        flags: dict[str, bool],
    ) -> tuple[str, str]:
        """Refuse real-world side effects unless explicitly switched on.

        Every branch here is fail-closed. The default posture of this project is
        that no real email is sent, no real file is deleted and no production
        database is mutated, and that posture is enforced in code rather than
        documented in a README.
        """
        if not flags.get("real_connectors", False):
            # A tool that declared itself mock-only is fine; a tool that talks to
            # the outside world is not.
            if (rule or {}).get("requires_real_connector"):
                reasons.append("Real connectors are disabled by default.")
                matched.append("connectors.defaults.real_connectors_enabled")
                return "block", max_risk(risk, "high")

        if request.action_type == "write" and not flags.get("real_write_actions", False):
            if (rule or {}).get("side_effect") == "real":
                reasons.append("Real write actions are disabled by default.")
                matched.append("connectors.defaults.real_write_actions_enabled")
                return "block", max_risk(risk, "high")

        if request.action_type == "destructive" and not flags.get(
            "real_destructive_actions", False
        ):
            if (rule or {}).get("side_effect") == "real":
                reasons.append("Real destructive actions are disabled by default.")
                matched.append("connectors.defaults.real_destructive_actions_enabled")
                return "block", "critical"

        if request.action_type == "external_send" and not flags.get("real_external_actions", False):
            if (rule or {}).get("side_effect") == "real":
                reasons.append("Real external actions are disabled by default.")
                matched.append("connectors.defaults.real_external_actions_enabled")
                return "block", max_risk(risk, "high")

        return decision, risk

    def _build_transformed_request(
        self, request: ToolRequest, rule: dict[str, Any] | None
    ) -> ToolRequest | None:
        if not rule or "transform" not in rule:
            return None
        transform = rule["transform"] or {}
        new_request = request.model_copy(deep=True)
        arguments = dict(new_request.arguments)
        for key in transform.get("remove_arguments", []) or []:
            arguments.pop(key, None)
        for key, value in (transform.get("set_arguments", {}) or {}).items():
            arguments[key] = value
        for key, prefix in (transform.get("prefix_arguments", {}) or {}).items():
            if key in arguments:
                arguments[key] = f"{prefix}{arguments[key]}"
        new_request.arguments = arguments
        return new_request
