"""Guardrails: input screening, output grounding, and capability boundaries.

Two defects from the archived implementation shape this module, and both were
measured rather than assumed.

**1. The output guardrail was three literal strings.** It blocked
``退款已完成|已经退款成功|资金已退回`` and nothing else, so an answer that said
"退款草案审核通过后资金会在三个工作日内退回" was allowed -- *while citing the
excerpt that says the opposite* ("绝不代表退款已经完成或资金已退回"). The check
now works in two layers: a capability-claim check that fires when an answer
asserts a completed action its cited evidence does not support, and a per-citation
grounding check.

**2. Citation binding was a union check.** The old guardrail concatenated every
cited excerpt and tested patterns against the joined blob, which made the inline
``【id】`` attribution decorative: an answer could cite the *wrong* chunk and still
pass as long as *some* cited chunk happened to contain the phrase. Worse,
``demo-runtime`` fell back to ``citations[0]`` when a preferred id was missing, so
a renamed heading silently produced wrong citations that still passed.

That is why ``check_citation_grounding`` here is **per id**: a sentence's own
citations must support it, and a citation that supports nothing fails.

Scope, stated honestly: this is pattern-based, not entailment. It catches
contradictions in a bounded, named, testable way. It is not a fact-checker and it
does not pretend to be one -- the firewall and policy engine remain the execution
boundary, and these checks are defence in depth on the *text* of an answer.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal

import yaml

Verdict = Literal["allow", "warn", "block"]

PATTERN_FILE = Path(__file__).with_name("guardrail_patterns.yaml")

# Citation markers: 【chunk-id】 and [chunk-id]. The bracketed form is accepted
# because models emit it by default, but only when the content looks like one of
# our chunk ids (``document#anchor``), so ordinary bracketed prose is ignored.
CJK_CITATION_RE = re.compile(r"【([^【】\n]{1,120}#[^【】\n]{1,120})】")
ASCII_CITATION_RE = re.compile(r"\[([A-Za-z0-9._\-/]{1,64}#[A-Za-z0-9._\-]{1,64})\]")

# Sentence splitting for CJK and Latin. Kept deliberately simple: the unit only
# needs to be small enough that one sentence's citations are a fair test of that
# sentence's claims.
SENTENCE_SPLIT_RE = re.compile(r"(?<=[。！？!?；;\n])|(?<=\.)\s+")

# Terms carrying no claim content. Used only to decide whether a sentence is
# substantive enough to require evidence.
# Terms that are part of *writing* a citation rather than content. Stripped before
# deciding whether a fragment carries prose, so "（依据【id】）" is recognised as a
# citation marker and not as a sentence.
_CITATION_CONNECTIVES = (
    "依据",
    "根据",
    "见",
    "参考",
    "来源",
    "出处",
    "依据于",
    "per",
    "see",
    "source",
    "according to",
)

# Stopwords carrying no claim content, used only to decide whether a sentence is
# substantive enough to require evidence.
_STOPWORDS = frozenset(
    [
        "the",
        "a",
        "an",
        "and",
        "or",
        "of",
        "to",
        "in",
        "on",
        "for",
        "is",
        "are",
        "was",
        "were",
        "be",
        "been",
        "it",
        "this",
        "that",
        "these",
        "those",
        "as",
        "by",
        "with",
        "at",
        "from",
        "you",
        "your",
        "we",
        "our",
        "i",
        "me",
        "my",
        "根据",
        "依据",
        "以上",
        "如下",
        "说明",
        "如下所示",
        "通常",
        "可以",
        "需要",
        "建议",
        "我们",
        "你们",
        "他们",
        "这个",
        "那个",
        "以及",
        "并且",
        "但是",
        "如果",
        "那么",
    ]
)


class GuardrailError(Exception):
    """Raised when the pattern file is unusable. Fail loud, never fail open."""


def load_patterns(path: Path | None = None) -> dict[str, Any]:
    target = path or PATTERN_FILE
    with target.open(encoding="utf-8") as handle:
        document = yaml.safe_load(handle) or {}
    if not isinstance(document, dict):
        raise GuardrailError(f"guardrail pattern root must be a mapping: {target}")
    _validate(document)
    return document


def _validate(document: dict[str, Any]) -> None:
    """Compile every pattern at load time.

    A broken regex must fail at startup, not silently disable a guardrail the first
    time an answer happens to exercise it.
    """
    for section in ("injection_patterns", "capability_claims", "sensitive_echo_patterns"):
        for entry in document.get(section) or []:
            if not entry.get("name"):
                raise GuardrailError(f"{section}: entry without a name")
            for key in ("patterns", "claim_patterns", "evidence_support_patterns", "pattern"):
                for expression in _as_pattern_list(entry.get(key)):
                    try:
                        re.compile(expression)
                    except re.error as exc:
                        raise GuardrailError(
                            f"{section}.{entry['name']}.{key}: invalid regex {expression!r}: {exc}"
                        ) from exc


def _as_pattern_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(item) for item in value]
    return [str(value)]


@lru_cache
def _compiled(path: str | None = None) -> dict[str, Any]:
    """Compile once. Returned structure holds compiled regexes, not strings."""
    document = load_patterns(Path(path) if path else None)
    compiled: dict[str, Any] = {
        "injection_patterns": [
            {
                "name": entry["name"],
                "severity": entry.get("severity", "medium"),
                "reason": entry.get("reason", ""),
                "patterns": [re.compile(p) for p in _as_pattern_list(entry.get("patterns"))],
            }
            for entry in document.get("injection_patterns") or []
        ],
        "capability_claims": [
            {
                "name": entry["name"],
                "severity": entry.get("severity", "high"),
                "reason": entry.get("reason", ""),
                "claim_patterns": [
                    re.compile(p) for p in _as_pattern_list(entry.get("claim_patterns"))
                ],
                "evidence_support_patterns": [
                    re.compile(p) for p in _as_pattern_list(entry.get("evidence_support_patterns"))
                ],
            }
            for entry in document.get("capability_claims") or []
        ],
        "sensitive_echo_patterns": [
            {
                "name": entry["name"],
                "severity": entry.get("severity", "high"),
                "pattern": re.compile(entry["pattern"]),
            }
            for entry in document.get("sensitive_echo_patterns") or []
        ],
    }
    return compiled


# Negation markers. An evidence excerpt can contain completion words *and deny
# them*: "绝不代表退款已经完成" is a denial, not a statement that the refund
# completed. Matching the words without checking polarity made the first version of
# this file conclude that a denial supported the very claim it denies -- the same
# class of error as the union-check defect, which is looking at the wrong thing.
_NEGATION_MARKERS = (
    "绝不",
    "不代表",
    "不会",
    "不能",
    "尚未",
    "未曾",
    "并未",
    "不予",
    "拒绝",
    "没有",
    "未能",
    "不含",
    "不包括",
    "仅",
    "只",
    "not ",
    "never ",
    "no ",
    "cannot ",
    "won't ",
    "will not ",
    "does not ",
    "doesn't ",
    "isn't ",
    "hasn't ",
    "merely ",
    "only ",
)
# How far back to look for a negator. Wider for claims than for a single phrase,
# because Chinese negation reaches across a clause: in
# "绝不代表退款已经完成或资金已原路退回" the 绝不 governs both halves, so the
# second completion phrase sits further from the negator than the first.
_NEGATION_WINDOW = 12
_CLAIM_NEGATION_WINDOW = 24

# A negator governs its own clause and no further.
#
# Looking back across punctuation is how a fabricated completion passed the
# capability check: in "本政策只说明一件事：您的退款已经完成。" a stray 只 twelve
# characters earlier counted as the negator, so the claim was read as a denial and
# allowed. Commas end the lookback for the same reason.
_CLAUSE_BOUNDARY_CHARS = "。！？；：，,;:!?\n"


def _is_negated(text: str, start: int, *, window: int = _NEGATION_WINDOW) -> bool:
    """Whether the phrase beginning at ``start`` is negated nearby, in its clause."""
    preceding = text[max(0, start - window) : start].lower()
    boundary = max(preceding.rfind(char) for char in _CLAUSE_BOUNDARY_CHARS)
    if boundary >= 0:
        preceding = preceding[boundary + 1 :]
    return any(marker in preceding for marker in _NEGATION_MARKERS)


def _match_is_negated(text: str, match: re.Match[str], *, window: int) -> bool:
    """Whether a match is negated, checking both before it and inside it.

    Checking inside matters because a subject-anchored pattern can start far
    earlier than the phrase it is really about. In
    "退款工具只创建草案，绝不代表退款已经完成" the pattern begins at 退款工具 and
    swallows the negator, so a start-relative check alone sees no negation and
    treats a denial as a claim.
    """
    start = match.start()
    if _is_negated(text, start, window=window):
        return True
    inside = text[start : match.end()].lower()
    return any(marker in inside for marker in _NEGATION_MARKERS)


def _find_positive_claim(patterns: tuple, text: str) -> re.Match[str] | None:
    """First match that is an *asserted* claim rather than a denial.

    The answer itself can contain the completion words while denying them:
    "退款工具只创建草案，绝不代表退款已经完成" is the truthful statement, and
    treating it as a claim makes the guardrail block the honest answer while
    letting the fabricated one through -- which is exactly backwards.
    """
    for pattern in patterns:
        for match in pattern.finditer(text or ""):
            if not _match_is_negated(text, match, window=_CLAIM_NEGATION_WINDOW):
                return match
    return None


def _evidence_supports(patterns: tuple, evidence: str) -> bool:
    """Whether any match is a *positive* statement rather than a denial.

    Polarity matters: without this check an excerpt that explicitly denies
    completion counts as support for claiming it.
    """
    for pattern in patterns:
        for match in pattern.finditer(evidence or ""):
            if not _match_is_negated(evidence, match, window=_CLAIM_NEGATION_WINDOW):
                return True
    return False


# ---------------------------------------------------------------------------
# result types
# ---------------------------------------------------------------------------


@dataclass
class Finding:
    name: str
    severity: str
    reason: str
    detail: str = ""
    matched: str = ""


@dataclass
class GuardrailResult:
    verdict: Verdict
    findings: list[Finding] = field(default_factory=list)
    checks: list[dict[str, Any]] = field(default_factory=list)

    @property
    def allowed(self) -> bool:
        return self.verdict != "block"

    def summary(self) -> str:
        if not self.findings:
            return "no guardrail findings"
        return "; ".join(f"[{f.severity}] {f.name}: {f.detail or f.reason}" for f in self.findings)

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "findings": [
                {
                    "name": f.name,
                    "severity": f.severity,
                    "reason": f.reason,
                    "detail": f.detail,
                    "matched": f.matched,
                }
                for f in self.findings
            ],
            # ``checks`` records passes as well as failures, so a reader can see
            # what was actually verified rather than only what broke.
            "checks": self.checks,
        }


def _worst(findings: list[Finding]) -> Verdict:
    if any(f.severity == "critical" for f in findings):
        return "block"
    if any(f.severity == "high" for f in findings):
        return "block"
    if findings:
        return "warn"
    return "allow"


# ---------------------------------------------------------------------------
# input guardrail
# ---------------------------------------------------------------------------

# Invisible characters a pattern cannot see and a reader cannot either. Stripped
# before matching, because "忽\u200b略" and "忽 略" are the same instruction to a
# model and different strings to a regular expression.
_ZERO_WIDTH = dict.fromkeys(map(ord, "\u200b\u200c\u200d\u2060\ufeff"), None)


def normalise_for_matching(text: str) -> str:
    """Fold the spellings a model reads as one instruction into one string.

    Three evasions measured against the shipped patterns were all spelling:
    full-width Latin (``Ｉｇｎｏｒｅ``), zero-width characters inside a keyword, and a
    newline or space inserted between a verb and its object. NFKC folds the first,
    stripping zero-width characters handles the second, and collapsing whitespace
    handles the third. It is normalisation, not understanding -- a paraphrase still
    has to be caught by a pattern.
    """
    folded = unicodedata.normalize("NFKC", text or "")
    stripped = folded.translate(_ZERO_WIDTH)
    return re.sub(r"\s+", " ", stripped).strip()


def check_input(text: str) -> GuardrailResult:
    """Screen text for injection attempts.

    The agent loop calls this on the *user request only* (``AgentLoop.run_traced``).
    Tool output, retrieved knowledge chunks and remote tool descriptions reach the
    model without passing through here -- a gap stated in the README's limitations,
    not a property of this function. It previously claimed to screen "user or
    tool-supplied" text, which nothing did.
    """
    findings: list[Finding] = []
    if not text or not text.strip():
        return GuardrailResult(verdict="allow", checks=[{"rule": "input_nonempty", "passed": True}])

    screened = normalise_for_matching(text)
    rules = _compiled()["injection_patterns"]
    for rule in rules:
        for pattern in rule["patterns"]:
            match = pattern.search(screened)
            if match:
                findings.append(
                    Finding(
                        name=rule["name"],
                        severity=rule["severity"],
                        reason=rule["reason"],
                        detail=f"matched {match.group(0)!r}",
                        matched=match.group(0),
                    )
                )
                break  # one hit per rule is enough

    return GuardrailResult(
        verdict=_worst(findings),
        findings=findings,
        checks=[{"rule": "input_screened", "passed": not findings, "rules_applied": len(rules)}],
    )


def check_tool_output(tool_name: str, text: str) -> GuardrailResult:
    """Screen tool-supplied text for indirect prompt injection attempts.

    Advisory (returns ``warn`` rather than ``block``) so legitimate documents
    that merely *mention* injection phrases are not silently discarded; the loop
    audits the hit and injects a data-boundary reminder before the next model
    turn.
    """
    if not text or not text.strip():
        return GuardrailResult(
            verdict="allow",
            checks=[{"rule": "tool_output_screened", "tool": tool_name, "passed": True}],
        )

    screened = normalise_for_matching(text)
    rules = _compiled()["injection_patterns"]
    findings: list[Finding] = []
    for rule in rules:
        for pattern in rule["patterns"]:
            match = pattern.search(screened)
            if match:
                findings.append(
                    Finding(
                        name=f"indirect_{rule['name']}",
                        severity="medium",
                        reason=(
                            f"Tool {tool_name!r} returned text matching injection pattern "
                            f"{rule['name']!r}."
                        ),
                        detail=f"matched {match.group(0)!r}",
                        matched=match.group(0),
                    )
                )
                break

    return GuardrailResult(
        verdict="warn" if findings else "allow",
        findings=findings,
        checks=[
            {
                "rule": "tool_output_screened",
                "tool": tool_name,
                "passed": not findings,
                "rules_applied": len(rules),
            }
        ],
    )


def check_sensitive_echo(text: str) -> GuardrailResult:
    """Advisory scan for credentials echoed into an answer.

    Advisory, never blocking: redaction at the persistence boundary and the
    policy engine are the controls. A warning here is a signal to a reviewer.
    """
    findings: list[Finding] = []
    for rule in _compiled()["sensitive_echo_patterns"]:
        match = rule["pattern"].search(text or "")
        if match:
            findings.append(
                Finding(
                    name=rule["name"],
                    severity="medium",  # downgraded: advisory by construction
                    reason="Answer appears to echo protected data.",
                    detail=f"matched {rule['name']}",
                    matched=match.group(0)[:80],
                )
            )
    return GuardrailResult(verdict="warn" if findings else "allow", findings=findings)


# ---------------------------------------------------------------------------
# citation extraction and per-id grounding
# ---------------------------------------------------------------------------


def extract_citations(answer: str) -> list[str]:
    """Citation ids in order of first appearance."""
    ids = CJK_CITATION_RE.findall(answer or "") + ASCII_CITATION_RE.findall(answer or "")
    return list(dict.fromkeys(ids))


def split_claims(answer: str) -> list[str]:
    """Sentences that carry a citation, with their citation attached.

    A trailing citation-only fragment is merged into the sentence before it. A
    quoted excerpt often carries its own sentence punctuation, so
    "根据证据：X。Y（依据【id】）" splits into three parts and the citation ends up
    alone in the last one. Checking that fragment against the excerpt asks whether
    the citation *marker* is supported by the excerpt -- it is not, and the honest
    answer gets refused as a result.
    """
    parts = [
        part.strip() for part in SENTENCE_SPLIT_RE.split(answer or "") if part and part.strip()
    ]
    # Merge first across *all* fragments, then drop the ones without citations. The
    # fragment preceding a trailing citation is often uncited itself (it is the
    # quoted excerpt), so filtering before merging would throw away the sentence the
    # citation belongs to and leave the marker standing alone.
    merged: list[str] = []
    for part in parts:
        without_markers = ASCII_CITATION_RE.sub("", CJK_CITATION_RE.sub("", part))
        # Connectives are part of how a citation is *written*, not content, so they
        # are stripped before deciding whether the fragment says anything.
        for connective in _CITATION_CONNECTIVES:
            without_markers = without_markers.replace(connective, "")
        prose = without_markers.strip("（）()［］[] 　，,。.；;：:")
        if extract_citations(part) and not prose and merged:
            merged[-1] = f"{merged[-1]}{part}"
            continue
        merged.append(part)
    return [part for part in merged if extract_citations(part)]


def _content_terms(text: str) -> set[str]:
    """Terms that carry claim content, for grounding comparison.

    Latin words of length >= 3 plus CJK bigrams. Single CJK characters are excluded
    because they match almost anything and would make every sentence look grounded.
    """
    lowered = (text or "").lower()
    terms = {word for word in re.findall(r"[a-z0-9]{3,}", lowered) if word not in _STOPWORDS}
    for run in re.findall(r"[\u3400-\u4dbf\u4e00-\u9fff\uf900-\ufaff]+", lowered):
        terms.update(run[i : i + 2] for i in range(len(run) - 1))
        for index in range(len(run) - 1):
            bigram = run[index : index + 2]
            if bigram in _STOPWORDS:
                terms.discard(bigram)
    return terms


def check_citation_grounding(
    answer: str,
    citations: list[dict[str, Any]],
    *,
    min_overlap: float = 0.25,
) -> GuardrailResult:
    """Verify each cited chunk actually supports the sentence citing it.

    Per-id, not union: a sentence's *own* citations must support it. A citation
    that supports nothing in the answer is reported too, because citing a chunk
    that says nothing about the claim is a way of laundering an unsupported
    statement through a check that only looks for "did they cite anything".
    """
    findings: list[Finding] = []
    checks: list[dict[str, Any]] = []

    if not citations:
        return GuardrailResult(
            verdict="warn",
            findings=[
                Finding(
                    name="no_evidence_retrieved",
                    severity="medium",
                    reason="No evidence was retrieved for this answer.",
                    detail="the knowledge base returned nothing for this question",
                )
            ],
            checks=[{"rule": "evidence_retrieved", "passed": False}],
        )

    available = {str(c.get("id")): c for c in citations}
    used = extract_citations(answer)
    checks.append({"rule": "evidence_retrieved", "passed": True, "count": len(citations)})

    if not used:
        return GuardrailResult(
            verdict="block",
            findings=[
                Finding(
                    name="answer_has_no_citation",
                    severity="high",
                    reason="A policy answer must cite the evidence it relies on.",
                    detail="answer used no evidence identifier",
                )
            ],
            checks=checks + [{"rule": "answer_cites_evidence", "passed": False}],
        )

    unknown = [cited for cited in used if cited not in available]
    checks.append({"rule": "citations_within_retrieval", "passed": not unknown, "unknown": unknown})
    if unknown:
        findings.append(
            Finding(
                name="citation_not_in_retrieval",
                severity="high",
                reason="Answer cited evidence that was not retrieved this turn.",
                detail=f"unknown citation ids: {', '.join(unknown)}",
            )
        )

    supported_count = 0
    for sentence in split_claims(answer):
        cited_here = [cited for cited in extract_citations(sentence) if cited in available]
        if not cited_here:
            continue
        claim_terms = _content_terms(sentence)
        if not claim_terms:
            continue
        # Every id the sentence names must carry some of its content. Checking each
        # one separately is the fix for the union-check defect.
        for cited in cited_here:
            excerpt = str(available[cited].get("excerpt") or "")
            excerpt_terms = _content_terms(excerpt)
            if not excerpt_terms:
                continue
            overlap = len(claim_terms & excerpt_terms) / max(1, len(claim_terms))
            passed = overlap >= min_overlap
            checks.append(
                {
                    "rule": "sentence_supported_by_citation",
                    "citation": cited,
                    "passed": passed,
                    "overlap": round(overlap, 3),
                    "sentence": sentence[:160],
                }
            )
            if passed:
                supported_count += 1
            else:
                findings.append(
                    Finding(
                        name="citation_does_not_support_sentence",
                        severity="high",
                        reason="A cited chunk does not support the sentence citing it.",
                        detail=(
                            f"{cited} overlaps the sentence by only {overlap:.0%} "
                            f"(need {min_overlap:.0%})"
                        ),
                        matched=sentence[:200],
                    )
                )

    unused = [
        cited for cited in used if cited in available and cited not in _cited_in_sentences(answer)
    ]
    if unused:
        checks.append({"rule": "every_citation_is_used", "passed": False, "unused": unused})
        findings.append(
            Finding(
                name="citation_not_referenced_by_any_sentence",
                severity="medium",
                reason="Some cited chunks are not tied to any sentence.",
                detail=f"unused citations: {', '.join(unused)}",
            )
        )
    else:
        checks.append({"rule": "every_citation_is_used", "passed": True})

    checks.append(
        {"rule": "sentences_supported", "passed": supported_count > 0, "count": supported_count}
    )
    return GuardrailResult(verdict=_worst(findings), findings=findings, checks=checks)


def _cited_in_sentences(answer: str) -> set[str]:
    used: set[str] = set()
    for sentence in split_claims(answer):
        used.update(extract_citations(sentence))
    return used


# ---------------------------------------------------------------------------
# capability boundary
# ---------------------------------------------------------------------------


def check_capability_claims(answer: str, evidence: str) -> GuardrailResult:
    """Block an answer that claims a completed action its evidence does not support.

    This is the check that catches "退款草案审核通过后资金会在三个工作日内退回"
    hanging off an excerpt that explicitly denies it. The logic is polarity-based:
    if the answer asserts completion and the evidence for that topic does not also
    assert completion, the answer is contradicting its own citation.
    """
    findings: list[Finding] = []
    checks: list[dict[str, Any]] = []

    for rule in _compiled()["capability_claims"]:
        claim_match = _find_positive_claim(rule["claim_patterns"], answer)
        if claim_match is None:
            continue

        supported = _evidence_supports(rule["evidence_support_patterns"], evidence or "")
        checks.append(
            {
                "rule": f"capability_claim:{rule['name']}",
                "passed": supported,
                "matched": claim_match.group(0),
            }
        )
        if not supported:
            findings.append(
                Finding(
                    name=f"unsupported_capability_claim:{rule['name']}",
                    severity=rule["severity"],
                    reason=rule["reason"],
                    detail=(
                        f"answer claims {claim_match.group(0)!r} but no cited excerpt supports it"
                    ),
                    matched=claim_match.group(0),
                )
            )

    return GuardrailResult(verdict=_worst(findings), findings=findings, checks=checks)


# ---------------------------------------------------------------------------
# composite output guardrail
# ---------------------------------------------------------------------------


def check_output(
    answer: str,
    citations: list[dict[str, Any]],
    *,
    policy_relevant: bool = True,
) -> GuardrailResult:
    """Screen an answer before it is returned to a caller.

    ``policy_relevant=False`` skips grounding, because a greeting or a
    clarification question has nothing to ground. Capability claims and sensitive
    echo are always checked -- those are about what the agent says it did, which is
    never acceptable to overstate.
    """
    findings: list[Finding] = []
    checks: list[dict[str, Any]] = []

    evidence_text = "\n".join(str(c.get("excerpt") or "") for c in citations or [])

    capability = check_capability_claims(answer, evidence_text)
    findings.extend(capability.findings)
    checks.extend(capability.checks)

    echo = check_sensitive_echo(answer)
    # Sensitive echo is advisory: keep the finding, keep the verdict at warn.
    if echo.findings:
        for finding in echo.findings:
            finding.severity = "low"
        findings.extend(echo.findings)

    if policy_relevant:
        grounding = check_citation_grounding(answer, citations or [])
        findings.extend(grounding.findings)
        checks.extend(grounding.checks)
    else:
        checks.append(
            {"rule": "grounding_skipped", "passed": True, "reason": "not policy relevant"}
        )

    blocking = [f for f in findings if f.severity in {"high", "critical"}]
    verdict: Verdict = "block" if blocking else ("warn" if findings else "allow")
    return GuardrailResult(verdict=verdict, findings=findings, checks=checks)
