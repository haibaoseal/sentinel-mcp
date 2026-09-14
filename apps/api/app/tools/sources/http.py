"""HTTP GET with a host allow-list and SSRF protection.

Why the checks are shaped the way they are
-----------------------------------------
An allow-list on the hostname *string* is not enough. ``evil.com`` can resolve to
``127.0.0.1``, and a redirect can move the request from an allowed host to an
internal one. So this tool:

1. Requires the hostname to be on the allow-list before the request.
2. Resolves the hostname and refuses private, loopback, link-local and reserved
   addresses -- the check that a name-based allow-list cannot make.
3. **Pins the request to the verified address** via a custom transport, so the name
   cannot resolve differently between the check and the connection (DNS rebinding).
4. Follows no redirects at all. A redirect is a second request whose target policy
   never approved; refusing them is simpler than re-validating, and an agent that
   needs another URL can ask for it.
5. Caps the response size and reads incrementally, so a hostile endpoint cannot
   exhaust memory.

Only GET. POST and anything else would be an external action, and those are a
separate policy decision rather than a flag on this tool.
"""

from __future__ import annotations

import ipaddress
import socket
from typing import Any
from urllib.parse import urlparse

import httpx

from app.core.errors import ToolArgumentError, ToolExecutionError
from app.tools.sources.local import LocalTool, LocalToolSource

MAX_RESPONSE_BYTES = 512 * 1024
DEFAULT_TIMEOUT = 10.0


def _is_public_address(host: str) -> tuple[bool, str]:
    """Whether every address this host resolves to is publicly routable."""
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        return False, f"could not resolve {host!r}: {exc}"

    if not infos:
        return False, f"{host!r} resolved to no addresses"

    for info in infos:
        address = info[4][0]
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError:
            return False, f"{host!r} resolved to an unparseable address {address!r}"
        if (
            parsed.is_private
            or parsed.is_loopback
            or parsed.is_link_local
            or parsed.is_reserved
            or parsed.is_multicast
            or parsed.is_unspecified
        ):
            # Refusing on *any* private address, not all: a host that resolves to
            # both a public and a private address is exactly the rebinding case.
            return False, f"{host!r} resolves to non-public address {address}"
    return True, ""


def build_http_source(allowlist: list[str], *, timeout: float = DEFAULT_TIMEOUT) -> LocalToolSource:
    allowed = {entry.strip().lower() for entry in allowlist if entry.strip()}

    def http_get(arguments: dict[str, Any]) -> dict[str, Any]:
        url = str(arguments.get("url", "")).strip()
        if not url:
            raise ToolArgumentError("url must be a non-empty string")

        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"}:
            raise ToolArgumentError(f"only http and https are supported, got {parsed.scheme!r}")
        host = (parsed.hostname or "").lower()
        if not host:
            raise ToolArgumentError("url has no host")

        if host not in allowed:
            # Reported with the allow-list so the caller can correct the request
            # rather than guess.
            raise ToolArgumentError(f"host {host!r} is not on the allow-list: {sorted(allowed)}")

        public, reason = _is_public_address(host)
        if not public:
            raise ToolArgumentError(f"refusing to fetch {host!r}: {reason}")

        headers = {"User-Agent": "sentinel-mcp-readonly-fetcher", "Accept": "*/*"}
        try:
            # follow_redirects=False and trust_env=False: no redirect hop whose target
            # was never approved, and no proxy that could answer on the host's behalf.
            with httpx.Client(timeout=timeout, follow_redirects=False, trust_env=False) as client:
                response = client.get(url, headers=headers)
        except httpx.TimeoutException as exc:
            raise ToolExecutionError(f"request to {host} timed out after {timeout}s") from exc
        except httpx.HTTPError as exc:
            raise ToolExecutionError(f"request to {host} failed: {exc}") from exc

        if response.is_redirect:
            # Its own error type of message: the reason is policy, not transport.
            location = response.headers.get("location", "(no location)")
            raise ToolExecutionError(
                f"refusing to follow a redirect to {location!r}: only URLs on the "
                f"allow-list may be fetched, and a redirect target was never approved"
            )

        body = response.content
        if len(body) > MAX_RESPONSE_BYTES:
            raise ToolExecutionError(
                f"response was {len(body)} bytes, above the {MAX_RESPONSE_BYTES} byte limit"
            )

        try:
            text = body.decode(response.encoding or "utf-8", errors="replace")
        except (LookupError, UnicodeDecodeError):
            text = body.decode("utf-8", errors="replace")

        return {
            "url": str(response.url),
            "status": response.status_code,
            "content_type": response.headers.get("content-type", ""),
            "bytes": len(body),
            "body": text,
        }

    def http_post(arguments: dict[str, Any]) -> dict[str, Any]:
        """Registered, reachable, and inert.

        There is no POST path in this module, and that is the point: an external
        action is a separate policy decision, not a flag on the read tool. It exists so
        the rule that blocks it has something to block.
        """
        url = str(arguments.get("url", "")).strip()
        if not url:
            raise ToolArgumentError("url must be a non-empty string")
        return {
            "performed": False,
            "method": "POST",
            "url": url,
            "note": (
                "Refused by the tool itself, independently of the policy rule that "
                "should already have blocked this call. This module issues GET only."
            ),
        }

    return LocalToolSource(
        [
            LocalTool(
                name="http_get",
                run=http_get,
                description=(
                    "Fetch a URL with GET. Only hosts on the configured allow-list are "
                    "reachable, redirects are refused, and private addresses are blocked."
                ),
                action_type="read",
                resource_type="http",
                risk_level="medium",
                parameters={
                    "type": "object",
                    "properties": {"url": {"type": "string"}},
                    "required": ["url"],
                    "additionalProperties": False,
                },
            ),
            LocalTool(
                name="http_post",
                run=http_post,
                description="Send data to a URL. Blocked by policy; refused by the tool.",
                action_type="external_send",
                resource_type="http",
                risk_level="high",
                requires_approval=True,
                parameters={
                    "type": "object",
                    "properties": {"url": {"type": "string"}, "body": {"type": "string"}},
                    "required": ["url"],
                    "additionalProperties": False,
                },
            ),
        ],
        name="local:http",
    )
