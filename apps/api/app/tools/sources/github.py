"""Read-only GitHub tools.

Read-only by construction, not by configuration
----------------------------------------------
Three of the rules the archived connector had, kept and made structural:

1. **Only GET.** There is no code path here that issues any other method, so a
   comment, a merge or an issue close cannot happen even if a caller asks. Those are
   external actions and belong to a different tool under a different policy decision.
2. **Live access is opt-in and needs a token.** With no token the tools serve a
   fixture, so a fresh checkout demonstrates the whole governed path without network
   access -- and `source` in the result says which mode answered, so a reviewer is
   never misled about whether real data was fetched.
3. **Rate limits are surfaced, not swallowed.** GitHub's unauthenticated limit is
   small, and a 403 that looks like "no data" is how an agent ends up reporting an
   empty issue list as a fact.

A PAT is read from the environment only and is never returned in a result or written
to an audit payload. Responses are passed through the project's redaction at the
persistence boundary regardless.
"""

from __future__ import annotations

import json
from typing import Any

import httpx

from app.core.errors import ToolArgumentError, ToolExecutionError
from app.tools.sources.local import LocalTool, LocalToolSource

GITHUB_API = "https://api.github.com"
MAX_ITEMS = 50
DEFAULT_TIMEOUT = 15.0

# Fixture used when no token is configured, so the governed path is demonstrable
# offline. Clearly labelled in every result.
FIXTURE_ISSUES = [
    {"number": 1, "title": "Policy engine should explain matched rules", "state": "open"},
    {"number": 2, "title": "Replay should show hash verification", "state": "open"},
]
FIXTURE_PULLS = [
    {"number": 7, "title": "Add connector safety documentation", "state": "open"},
    {"number": 8, "title": "Add read-only connector tests", "state": "open"},
]


def _validate_repo(arguments: dict[str, Any]) -> tuple[str, str]:
    owner = str(arguments.get("owner", "")).strip()
    repo = str(arguments.get("repo", "")).strip()
    if not owner or not repo:
        raise ToolArgumentError("owner and repo are required")
    # Refuse anything that could turn a path segment into a different request.
    for label, value in (("owner", owner), ("repo", repo)):
        if any(ch in value for ch in "/\\?#\x00") or value in {".", ".."}:
            raise ToolArgumentError(f"{label} contains characters that are not allowed: {value!r}")
    return owner, repo


def build_github_source(
    *, token: str | None = None, timeout: float = DEFAULT_TIMEOUT
) -> LocalToolSource:
    """Build the connector.

    ``token`` present means live read-only calls are permitted. Absent means the
    fixture is served and every result says so.
    """

    def _request(path: str) -> dict[str, Any]:
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "sentinel-mcp-readonly",
        }
        if token:
            # Sent to the allow-listed api.github.com only. Never echoed back.
            headers["Authorization"] = f"Bearer {token}"

        try:
            # No redirect following: a redirect away from the API host would be a
            # request to a destination policy never approved.
            with httpx.Client(timeout=timeout, follow_redirects=False, trust_env=False) as client:
                response = client.get(f"{GITHUB_API}{path}", headers=headers)
        except httpx.TimeoutException as exc:
            raise ToolExecutionError(f"GitHub API timed out after {timeout}s") from exc
        except httpx.HTTPError as exc:
            raise ToolExecutionError(f"GitHub API request failed: {exc}") from exc

        if response.status_code == 403 and "rate limit" in response.text.lower():
            remaining = response.headers.get("x-ratelimit-remaining", "0")
            reset = response.headers.get("x-ratelimit-reset", "unknown")
            # Surfaced explicitly: an agent must not report an empty list as a fact
            # when the truth is that the API refused to answer.
            raise ToolExecutionError(
                f"GitHub rate limit reached (remaining={remaining}, reset={reset}). "
                "Configure GITHUB_TOKEN to raise the limit."
            )
        if response.status_code == 404:
            raise ToolArgumentError(f"GitHub resource not found: {path}")
        if response.status_code >= 400:
            raise ToolExecutionError(
                f"GitHub API returned {response.status_code}: {response.text[:200]}"
            )
        try:
            return response.json()
        except json.JSONDecodeError as exc:
            raise ToolExecutionError("GitHub API returned a non-JSON body") from exc

    def _mode() -> str:
        return "github" if token else "fixture"

    def list_issues(arguments: dict[str, Any]) -> dict[str, Any]:
        owner, repo = _validate_repo(arguments)
        limit = _limit(arguments)
        if not token:
            return {
                "issues": FIXTURE_ISSUES[:limit],
                "count": len(FIXTURE_ISSUES[:limit]),
                "repo": f"{owner}/{repo}",
                "source": "fixture",
                "note": "No GITHUB_TOKEN configured; this is sample data, not live GitHub data.",
            }
        payload = _request(f"/repos/{owner}/{repo}/issues?per_page={limit}&state=all")
        issues = [_shape_issue(item) for item in payload][:limit]
        return {
            "issues": issues,
            "count": len(issues),
            "repo": f"{owner}/{repo}",
            "source": "github",
        }

    def read_issue(arguments: dict[str, Any]) -> dict[str, Any]:
        owner, repo = _validate_repo(arguments)
        number = _issue_number(arguments)
        if not token:
            match = next((i for i in FIXTURE_ISSUES if i["number"] == number), FIXTURE_ISSUES[0])
            return {
                "issue": match,
                "repo": f"{owner}/{repo}",
                "source": "fixture",
                "note": "No GITHUB_TOKEN configured; this is sample data, not live GitHub data.",
            }
        return {
            "issue": _shape_issue(_request(f"/repos/{owner}/{repo}/issues/{number}")),
            "repo": f"{owner}/{repo}",
            "source": "github",
        }

    def list_pull_requests(arguments: dict[str, Any]) -> dict[str, Any]:
        owner, repo = _validate_repo(arguments)
        limit = _limit(arguments)
        if not token:
            return {
                "pull_requests": FIXTURE_PULLS[:limit],
                "count": len(FIXTURE_PULLS[:limit]),
                "repo": f"{owner}/{repo}",
                "source": "fixture",
                "note": "No GITHUB_TOKEN configured; this is sample data, not live GitHub data.",
            }
        payload = _request(f"/repos/{owner}/{repo}/pulls?per_page={limit}&state=all")
        pulls = [_shape_pull(item) for item in payload][:limit]
        return {
            "pull_requests": pulls,
            "count": len(pulls),
            "repo": f"{owner}/{repo}",
            "source": "github",
        }

    def read_pull_request(arguments: dict[str, Any]) -> dict[str, Any]:
        owner, repo = _validate_repo(arguments)
        number = _issue_number(arguments, key="pull_number")
        if not token:
            match = next((p for p in FIXTURE_PULLS if p["number"] == number), FIXTURE_PULLS[0])
            return {
                "pull_request": match,
                "repo": f"{owner}/{repo}",
                "source": "fixture",
                "note": "No GITHUB_TOKEN configured; this is sample data, not live GitHub data.",
            }
        return {
            "pull_request": _shape_pull(_request(f"/repos/{owner}/{repo}/pulls/{number}")),
            "repo": f"{owner}/{repo}",
            "source": "github",
        }

    common = {
        "type": "object",
        "properties": {"owner": {"type": "string"}, "repo": {"type": "string"}},
        "required": ["owner", "repo"],
        "additionalProperties": False,
    }
    with_number = {
        "type": "object",
        "properties": {
            "owner": {"type": "string"},
            "repo": {"type": "string"},
            "number": {"type": "integer"},
        },
        "required": ["owner", "repo", "number"],
        "additionalProperties": False,
    }
    comment_parameters = {
        "type": "object",
        "properties": {
            "owner": {"type": "string"},
            "repo": {"type": "string"},
            "number": {"type": "integer"},
            "body": {"type": "string"},
        },
        "required": ["owner", "repo", "number", "body"],
        "additionalProperties": False,
    }

    def _write_refusal(action: str):
        """Registered, reachable, and inert.

        These exist so the policy rules disabling them have something to act on. A
        rule for a tool that does not exist proves nothing: "it did not run" is true
        for the wrong reason, which is precisely the trap the archived project fell
        into with a `delete_file` policy rule and no such tool.
        """

        def refuse(arguments: dict[str, Any]) -> dict[str, Any]:
            _validate_repo(arguments)
            return {
                "performed": False,
                "action": action,
                "note": (
                    "Refused by the tool itself, independently of the policy rule that "
                    "should already have blocked this call. This connector is read-only: "
                    "no code path here issues a non-GET request."
                ),
            }

        return refuse

    return LocalToolSource(
        [
            LocalTool(
                name="github_list_issues",
                run=list_issues,
                description="List issues in a repository (read-only).",
                action_type="read",
                resource_type="github_issue",
                risk_level="low",
                parameters=common,
            ),
            LocalTool(
                name="github_read_issue",
                run=read_issue,
                description="Read one issue (read-only).",
                action_type="read",
                resource_type="github_issue",
                risk_level="low",
                parameters=with_number,
            ),
            LocalTool(
                name="github_list_pull_requests",
                run=list_pull_requests,
                description="List pull requests in a repository (read-only).",
                action_type="read",
                resource_type="github_pull_request",
                risk_level="low",
                parameters=common,
            ),
            LocalTool(
                name="github_read_pull_request",
                run=read_pull_request,
                description="Read one pull request (read-only).",
                action_type="read",
                resource_type="github_pull_request",
                risk_level="low",
                parameters=with_number,
            ),
            # Registered but disabled by the ruleset. Reachable in principle, so the
            # refusal is a decision rather than an absence.
            LocalTool(
                name="github_post_issue_comment",
                run=_write_refusal("comment"),
                description="Post an issue comment. Disabled by policy; refused by the tool.",
                action_type="external_send",
                resource_type="github_issue",
                risk_level="high",
                requires_approval=True,
                parameters=comment_parameters,
            ),
            LocalTool(
                name="github_close_issue",
                run=_write_refusal("close"),
                description="Close an issue. Disabled by policy; refused by the tool.",
                action_type="destructive",
                resource_type="github_issue",
                risk_level="critical",
                requires_approval=True,
                parameters=with_number,
            ),
        ],
        name="local:github",
    )


def _limit(arguments: dict[str, Any]) -> int:
    raw = arguments.get("limit", 20)
    try:
        value = int(raw)
    except (TypeError, ValueError) as exc:
        raise ToolArgumentError("limit must be an integer") from exc
    return max(1, min(value, MAX_ITEMS))


def _issue_number(arguments: dict[str, Any], *, key: str = "number") -> int:
    if key not in arguments:
        raise ToolArgumentError(f"{key} is required")
    try:
        value = int(arguments[key])
    except (TypeError, ValueError) as exc:
        raise ToolArgumentError(f"{key} must be a positive integer") from exc
    if value < 1:
        raise ToolArgumentError(f"{key} must be a positive integer")
    return value


def _shape_issue(item: dict[str, Any]) -> dict[str, Any]:
    """Keep a small, stable subset. Never a raw upstream payload."""
    return {
        "number": item.get("number"),
        "title": item.get("title"),
        "state": item.get("state"),
        "author": (item.get("user") or {}).get("login"),
        "labels": [
            label.get("name") for label in item.get("labels") or [] if isinstance(label, dict)
        ],
        "created_at": item.get("created_at"),
        "is_pull_request": "pull_request" in item,
    }


def _shape_pull(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "number": item.get("number"),
        "title": item.get("title"),
        "state": item.get("state"),
        "author": (item.get("user") or {}).get("login"),
        "draft": item.get("draft"),
        "created_at": item.get("created_at"),
        "merged_at": item.get("merged_at"),
    }
