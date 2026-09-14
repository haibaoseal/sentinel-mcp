"""Tests for the read-only SQL, HTTP and GitHub tools.

Each of these tools has a property that must hold even if the caller is hostile,
and the tests are written as attempts against that property:

- SQL: a write must fail *at the connection*, not merely be pattern-matched away.
- HTTP: a private address must be unreachable even when the request is well formed.
- GitHub: a non-GET operation must not exist, and a rate limit must not look like
  an empty result.
"""

from __future__ import annotations

import socket
import sqlite3
from pathlib import Path

import httpx
import pytest
from app.core.errors import ToolArgumentError, ToolExecutionError
from app.tools.sources.github import build_github_source
from app.tools.sources.http import build_http_source
from app.tools.sources.sql import build_sql_source, seed_database

# --- SQL ---------------------------------------------------------------------


@pytest.fixture
def sql_source(tmp_path: Path):
    return build_sql_source(tmp_path / "commerce.db")


def test_read_query_returns_rows_and_columns(sql_source):
    result = sql_source.execute("sql_query", {"query": "SELECT order_id, status FROM orders"})
    assert result["columns"] == ["order_id", "status"]
    assert result["row_count"] == 5
    assert all(isinstance(row, list) for row in result["rows"])


def test_seed_is_idempotent(tmp_path):
    path = tmp_path / "db.sqlite"
    seed_database(path)
    seed_database(path)
    connection = sqlite3.connect(path)
    try:
        count = connection.execute("SELECT count(*) FROM orders").fetchone()[0]
    finally:
        connection.close()
    assert count == 5


@pytest.mark.parametrize(
    "query",
    [
        "INSERT INTO orders VALUES ('X','x','x',1,'2026-01-01',NULL)",
        "UPDATE orders SET status = 'delivered'",
        "DELETE FROM orders",
        "DROP TABLE orders",
        "ALTER TABLE orders ADD COLUMN sneaky TEXT",
        "CREATE TABLE evil (x TEXT)",
    ],
)
def test_writes_fail_at_the_connection(sql_source, query):
    """The guarantee is structural: a read-only connection cannot be talked into a write.

    The policy engine also refuses these, which is why this test reaches the tool
    directly -- it verifies the layer that does not depend on pattern matching.
    """
    with pytest.raises((ToolExecutionError, ToolArgumentError)):
        sql_source.execute("sql_query", {"query": query})

    # And the data is genuinely untouched.
    check = sql_source.execute("sql_query", {"query": "SELECT count(*) AS n FROM orders"})
    assert check["rows"][0][0] == 5


def test_attach_is_refused(sql_source, tmp_path):
    """ATTACH would open a second, writable database -- a way around mode=ro.

    The target is a directory that really exists, so the refusal comes from the
    tool rather than from the filesystem. Pointing at ``/tmp/evil.db`` made this
    test pass on Windows for the wrong reason and fail on Linux, where an attached
    database was created.
    """
    target = tmp_path / "evil.db"
    with pytest.raises((ToolExecutionError, ToolArgumentError)):
        sql_source.execute("sql_query", {"query": f"ATTACH DATABASE '{target.as_posix()}' AS evil"})

    assert not target.exists(), "the refusal must happen before a file is created"


def test_row_limit_is_clamped(sql_source):
    result = sql_source.execute("sql_query", {"query": "SELECT * FROM orders", "row_limit": 2})
    assert result["row_count"] == 2
    assert result["truncated"] is True


def test_truncated_means_there_was_more(sql_source):
    """A result exactly as long as the limit is the whole result, not a truncation.

    The flag used to be ``len(rows) == row_limit``, so a complete five-row answer at
    a limit of five reported itself as truncated.
    """
    whole = sql_source.execute("sql_query", {"query": "SELECT * FROM orders", "row_limit": 5})
    assert whole["row_count"] == 5
    assert whole["truncated"] is False

    clipped = sql_source.execute("sql_query", {"query": "SELECT * FROM orders", "row_limit": 4})
    assert clipped["row_count"] == 4
    assert clipped["truncated"] is True


def test_absurd_row_limit_is_clamped_not_rejected(sql_source):
    result = sql_source.execute("sql_query", {"query": "SELECT * FROM orders", "row_limit": 10**9})
    assert result["row_limit"] <= 200


def test_invalid_sql_is_a_caller_error(sql_source):
    with pytest.raises(ToolArgumentError):
        sql_source.execute("sql_query", {"query": "SELECT FROM WHERE"})


def test_empty_query_is_refused(sql_source):
    with pytest.raises(ToolArgumentError, match="non-empty"):
        sql_source.execute("sql_query", {"query": "  "})


def test_schema_tool_lists_tables_and_columns(sql_source):
    result = sql_source.execute("sql_schema", {})
    assert set(result["tables"]) == {"orders", "refunds"}
    columns = {column["column"] for column in result["schema"]["orders"]}
    assert {"order_id", "status", "total_cents"} <= columns


def test_schema_tool_refuses_unexpected_arguments(sql_source):
    """It takes none, and refusing is louder than silently discarding a request."""
    with pytest.raises(ToolArgumentError, match="takes no arguments"):
        sql_source.execute("sql_schema", {"query": "DROP TABLE orders"})


def test_database_file_exists_after_build(tmp_path):
    path = tmp_path / "commerce.db"
    build_sql_source(path)
    assert path.exists()


# --- HTTP --------------------------------------------------------------------


@pytest.fixture
def http_source():
    return build_http_source(["example.com"])


@pytest.fixture(autouse=True)
def public_dns(monkeypatch):
    """Resolve ``example.com`` to a public address for the HTTP tests.

    Without this the tests are not hermetic, and the reason is interesting: on the
    machine this was written, ``example.com`` resolves into ``198.18.0.0/15``, a
    benchmarking range that ``ipaddress`` reports as non-public. The SSRF guard
    therefore refused it -- correctly, and before any request. Pinning the resolution
    keeps the tests about our own logic rather than about one host's DNS.
    """
    real_getaddrinfo = socket.getaddrinfo

    def fake(host, *args, **kwargs):
        if host == "example.com":
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]
        return real_getaddrinfo(host, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", fake)


def test_host_outside_the_allowlist_is_refused(http_source):
    with pytest.raises(ToolArgumentError, match="not on the allow-list"):
        http_source.execute("http_get", {"url": "https://evil.test/x"})


def test_non_http_scheme_is_refused(http_source):
    with pytest.raises(ToolArgumentError, match="only http and https"):
        http_source.execute("http_get", {"url": "file:///etc/passwd"})


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/admin",
        "http://localhost:8000/",
        "http://169.254.169.254/latest/meta-data/",  # cloud metadata
        "http://10.0.0.1/",
        "http://192.168.1.1/",
    ],
)
def test_private_and_loopback_addresses_are_refused(url):
    """The check a name-based allow-list cannot make.

    These are refused *before* any request, so a DNS name that resolves inward, a
    loopback literal, and the cloud metadata endpoint are all unreachable.
    """
    source = build_http_source(
        [entry.split("//")[1].split("/")[0].split(":")[0] for entry in [url]]
    )
    with pytest.raises(ToolArgumentError, match="not on the allow-list|non-public"):
        source.execute("http_get", {"url": url})


def test_a_name_resolving_to_loopback_is_refused():
    """localhost is on the allow-list here, but resolves inward, so it is refused."""
    source = build_http_source(["localhost"])
    with pytest.raises(ToolArgumentError, match="non-public"):
        source.execute("http_get", {"url": "http://localhost:9/"})


def test_missing_url_is_refused(http_source):
    with pytest.raises(ToolArgumentError, match="non-empty"):
        http_source.execute("http_get", {"url": ""})


def test_allowlisted_public_host_is_fetched(monkeypatch):
    """The happy path, with the network stubbed so the test is hermetic."""
    source = build_http_source(["example.com"])

    class FakeResponse:
        status_code = 200
        headers = {"content-type": "text/plain"}
        encoding = "utf-8"
        content = b"hello"
        is_redirect = False
        url = "https://example.com/"

    class FakeClient:
        def __init__(self, **kwargs):
            assert kwargs.get("follow_redirects") is False, "redirects must not be followed"

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def get(self, url, headers=None):
            return FakeResponse()

    monkeypatch.setattr(httpx, "Client", FakeClient)
    result = source.execute("http_get", {"url": "https://example.com/"})
    assert result["status"] == 200
    assert result["body"] == "hello"


def test_redirect_is_refused_rather_than_followed(monkeypatch):
    """A redirect target was never on the allow-list, so following one is a bypass."""
    source = build_http_source(["example.com"])

    class FakeResponse:
        status_code = 302
        headers = {"location": "http://169.254.169.254/"}
        encoding = "utf-8"
        content = b""
        is_redirect = True
        url = "https://example.com/"

    class FakeClient:
        def __init__(self, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def get(self, url, headers=None):
            return FakeResponse()

    monkeypatch.setattr(httpx, "Client", FakeClient)
    with pytest.raises(ToolExecutionError, match="redirect"):
        source.execute("http_get", {"url": "https://example.com/"})


def test_oversized_response_is_refused(monkeypatch):
    source = build_http_source(["example.com"])
    from app.tools.sources import http as http_module

    class FakeResponse:
        status_code = 200
        headers = {"content-type": "application/octet-stream"}
        encoding = None
        content = b"x" * (http_module.MAX_RESPONSE_BYTES + 1)
        is_redirect = False
        url = "https://example.com/"

    class FakeClient:
        def __init__(self, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def get(self, url, headers=None):
            return FakeResponse()

    monkeypatch.setattr(httpx, "Client", FakeClient)
    with pytest.raises(ToolExecutionError, match="above the .* byte limit"):
        source.execute("http_get", {"url": "https://example.com/"})


def test_client_does_not_trust_the_environment_proxy(monkeypatch):
    """A proxy must not be able to answer on an allow-listed host's behalf."""
    captured: dict = {}
    source = build_http_source(["example.com"])

    class FakeResponse:
        status_code = 200
        headers = {}
        encoding = "utf-8"
        content = b"ok"
        is_redirect = False
        url = "https://example.com/"

    class FakeClient:
        def __init__(self, **kwargs):
            captured.update(kwargs)

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def get(self, url, headers=None):
            return FakeResponse()

    monkeypatch.setattr(httpx, "Client", FakeClient)
    source.execute("http_get", {"url": "https://example.com/"})
    assert captured.get("trust_env") is False


# --- GitHub ------------------------------------------------------------------


def test_github_serves_a_labelled_fixture_without_a_token():
    """Offline by default, and every result says which mode answered."""
    source = build_github_source(token=None)
    result = source.execute("github_list_issues", {"owner": "openai", "repo": "openai-python"})
    assert result["source"] == "fixture"
    assert "not live GitHub data" in result["note"]
    assert result["count"] >= 1


def test_github_read_tools_are_the_only_enabled_ones():
    """The connector exposes four read tools plus two disabled write tools.

    The write tools exist so the policy rules disabling them have something to act
    on -- a rule for a tool that does not exist proves nothing. What matters is that
    they are inert, which the next test asserts.
    """
    descriptors = {d.name: d for d in build_github_source().descriptors()}
    assert set(descriptors) == {
        "github_list_issues",
        "github_read_issue",
        "github_list_pull_requests",
        "github_read_pull_request",
        "github_post_issue_comment",
        "github_close_issue",
    }
    for name in (
        "github_list_issues",
        "github_read_issue",
        "github_list_pull_requests",
        "github_read_pull_request",
    ):
        assert descriptors[name].action_type == "read"
    assert descriptors["github_post_issue_comment"].action_type == "external_send"
    assert descriptors["github_close_issue"].action_type == "destructive"


@pytest.mark.parametrize(
    "tool,arguments",
    [
        (
            "github_post_issue_comment",
            {"owner": "a", "repo": "b", "number": 1, "body": "hi"},
        ),
        ("github_close_issue", {"owner": "a", "repo": "b", "number": 1}),
    ],
)
def test_github_write_tools_refuse_even_when_invoked_directly(tool, arguments):
    """Inert independently of the policy layer that should block them first.

    Two independent reasons no comment is posted: the ruleset disables these, and the
    tool has no non-GET code path. The second is what makes the guarantee structural
    rather than a matter of the ruleset being correct.
    """
    result = build_github_source(token="ghp_x").execute(tool, arguments)
    assert result["performed"] is False
    assert "read-only" in result["note"]


def test_github_write_tools_still_validate_their_arguments():
    """Inert is not the same as unvalidated: a bad repo must still be refused."""
    with pytest.raises(ToolArgumentError, match="not allowed"):
        build_github_source().execute(
            "github_close_issue", {"owner": "../x", "repo": "b", "number": 1}
        )


def test_github_rejects_a_path_like_repo_argument():
    source = build_github_source()
    with pytest.raises(ToolArgumentError, match="not allowed"):
        source.execute("github_list_issues", {"owner": "openai", "repo": "../evil"})


def test_github_requires_owner_and_repo():
    source = build_github_source()
    with pytest.raises(ToolArgumentError, match="owner and repo"):
        source.execute("github_list_issues", {"owner": "openai"})


def test_github_issue_number_must_be_positive():
    source = build_github_source()
    with pytest.raises(ToolArgumentError, match="positive integer"):
        source.execute("github_read_issue", {"owner": "a", "repo": "b", "number": 0})


def test_github_live_mode_reports_its_source(monkeypatch):
    """With a token the result says `github`, so a fixture is never mistaken for live data."""
    source = build_github_source(token="ghp_testtoken_not_real")
    payload = [{"number": 5, "title": "t", "state": "open", "user": {"login": "someone"}}]

    class FakeResponse:
        status_code = 200
        headers = {}
        text = "[]"

        def json(self):
            return payload

    class FakeClient:
        def __init__(self, **kwargs):
            assert kwargs.get("follow_redirects") is False

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def get(self, url, headers=None):
            assert headers.get("Authorization") == "Bearer ghp_testtoken_not_real"
            return FakeResponse()

    monkeypatch.setattr(httpx, "Client", FakeClient)
    result = source.execute("github_list_issues", {"owner": "openai", "repo": "openai-python"})
    assert result["source"] == "github"
    assert result["issues"][0]["number"] == 5


def test_github_rate_limit_is_surfaced_not_reported_as_empty(monkeypatch):
    """An empty list and a refusal must not look the same to an agent."""
    source = build_github_source(token="ghp_x")

    class FakeResponse:
        status_code = 403
        headers = {"x-ratelimit-remaining": "0", "x-ratelimit-reset": "1700000000"}
        text = '{"message": "API rate limit exceeded for 1.2.3.4"}'

        def json(self):
            return {}

    class FakeClient:
        def __init__(self, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def get(self, url, headers=None):
            return FakeResponse()

    monkeypatch.setattr(httpx, "Client", FakeClient)
    with pytest.raises(ToolExecutionError, match="rate limit"):
        source.execute("github_list_issues", {"owner": "a", "repo": "b"})


def test_github_token_never_appears_in_a_result(monkeypatch):
    """A credential must not reach an answer, an audit payload or a log."""
    token = "ghp_thisMustNotEscape1234567890"
    source = build_github_source(token=token)

    class FakeResponse:
        status_code = 200
        headers = {}
        text = "[]"

        def json(self):
            # The single-issue endpoint returns an object, unlike the list endpoints.
            return {"number": 1, "title": "t", "state": "open", "user": {"login": "u"}}

    class FakeClient:
        def __init__(self, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def get(self, url, headers=None):
            return FakeResponse()

    monkeypatch.setattr(httpx, "Client", FakeClient)
    result = source.execute("github_read_issue", {"owner": "a", "repo": "b", "number": 1})
    assert token not in str(result)


def test_github_upstream_payload_is_shaped_not_passed_through(monkeypatch):
    """A raw upstream payload could carry anything; only a stable subset is returned."""
    source = build_github_source(token="ghp_x")

    class FakeResponse:
        status_code = 200
        headers = {}
        text = "[]"

        def json(self):
            # Object, not list: this is the single-issue endpoint.
            return {
                "number": 3,
                "title": "t",
                "state": "open",
                "user": {"login": "u", "email": "secret@example.com"},
                "body": "long body",
                "labels": [{"name": "bug"}, "not-a-dict"],
                "_links": {"self": {"href": "x"}},
            }

    class FakeClient:
        def __init__(self, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def get(self, url, headers=None):
            return FakeResponse()

    monkeypatch.setattr(httpx, "Client", FakeClient)
    issue = source.execute("github_read_issue", {"owner": "a", "repo": "b", "number": 3})["issue"]
    assert issue["labels"] == ["bug"]
    assert "secret@example.com" not in str(issue)
    assert "_links" not in issue
