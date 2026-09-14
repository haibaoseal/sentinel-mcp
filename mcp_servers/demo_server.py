"""A demo MCP server exposing diagnostics for this repository.

Used by the MCP gateway demo and the integration tests. It is a *real* MCP
server: it speaks the protocol over stdio or Streamable HTTP, so the client under
test exercises the actual transport rather than a stubbed session.

Two tools are deliberately included:

- ``repo_stats`` is read-only and the policy maps it to ``read``, so it runs
  unattended.
- ``scratch_write`` writes a file inside a directory it creates. The policy maps
  it to ``write`` with ``side_effect: real``, so it is refused unless an operator
  opts in. It exists so the gateway can demonstrate that a *remote* tool's
  declared intent is honoured by local policy, not by the remote server's word.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from mcp.server import MCPServer

SERVER_NAME = "sentinel-demo"

server = MCPServer(
    name=SERVER_NAME,
    title="Sentinel demo MCP server",
    instructions=(
        "Diagnostics for the sentinel-mcp repository. All tools are read-only "
        "except scratch_write, which is refused unless explicitly enabled."
    ),
)


def _repo_root() -> Path:
    # The server may be launched from anywhere; anchor on this file so a stdio
    # child process works regardless of its working directory.
    return Path(__file__).resolve().parents[1]


@server.tool(
    name="repo_stats",
    description="Return file and line counts for the repository, by directory.",
)
def repo_stats(include_tests: bool = False) -> dict[str, Any]:
    root = _repo_root() / "apps" / "api" / "app"
    if not root.is_dir():
        return {"error": "application package not found", "root": str(root)}

    by_area: dict[str, dict[str, int]] = {}
    total_files = 0
    total_lines = 0
    for path in sorted(root.rglob("*.py")):
        relative = path.relative_to(root)
        area = relative.parts[0] if len(relative.parts) > 1 else "(root)"
        if area == "tests" and not include_tests:
            continue
        try:
            lines = len(path.read_text(encoding="utf-8").splitlines())
        except (UnicodeDecodeError, OSError):
            continue
        entry = by_area.setdefault(area, {"files": 0, "lines": 0})
        entry["files"] += 1
        entry["lines"] += lines
        total_files += 1
        total_lines += lines

    return {
        "root": str(root),
        "include_tests": include_tests,
        "by_area": by_area,
        "total_files": total_files,
        "total_lines": total_lines,
    }


@server.tool(
    name="count_pattern",
    description="Count lines matching a regular expression in the repository source.",
)
def count_pattern(pattern: str, max_files: int = 200) -> dict[str, Any]:
    import re

    if not pattern:
        return {"error": "pattern must be a non-empty string"}
    try:
        compiled = re.compile(pattern)
    except re.error as exc:
        return {"error": f"invalid regular expression: {exc}"}

    root = _repo_root() / "apps" / "api" / "app"
    matches: list[dict[str, Any]] = []
    scanned = 0
    for path in sorted(root.rglob("*.py")):
        if scanned >= max_files:
            break
        scanned += 1
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for number, line in enumerate(text.splitlines(), start=1):
            if compiled.search(line):
                matches.append(
                    {
                        "path": str(path.relative_to(root)),
                        "line": number,
                        "text": line.strip()[:200],
                    }
                )
                if len(matches) >= 200:
                    break
    return {"pattern": pattern, "count": len(matches), "matches": matches, "files_scanned": scanned}


@server.tool(
    name="scratch_write",
    description=(
        "Write a note into the server's scratch directory. This tool has real "
        "side effects and is expected to be refused by an upstream policy."
    ),
)
def scratch_write(name: str, content: str) -> dict[str, Any]:
    if not name or "/" in name or "\\" in name or name.startswith("."):
        return {"error": "name must be a plain file name"}
    scratch = Path(os.environ.get("MCP_SCRATCH_DIR", _repo_root() / ".mcp-scratch"))
    scratch.mkdir(parents=True, exist_ok=True)
    target = scratch / name
    target.write_text(content, encoding="utf-8")
    return {"written": True, "path": str(target), "bytes": len(content.encode("utf-8"))}


@server.tool(
    name="echo",
    description="Return the supplied payload unchanged. Useful for transport checks.",
)
def echo(payload: str = "") -> dict[str, Any]:
    return {"echo": payload, "length": len(payload)}


def main() -> None:
    """Entry point.

    ``MCPServer.run`` is the synchronous runner the SDK provides; the async
    ``run_stdio_async`` / ``run_streamable_http_async`` variants are coroutines
    and must be awaited. Calling one of those from a plain ``main`` returns a
    coroutine object, so the process starts, prints a RuntimeWarning and exits 0
    -- which looks like success while the server never served anything.
    """
    import sys

    transport = sys.argv[1] if len(sys.argv) > 1 else "stdio"
    if transport == "http":
        port = int(sys.argv[2]) if len(sys.argv) > 2 else 8765
        server.run("streamable-http", host="127.0.0.1", port=port)
    else:
        server.run("stdio")


if __name__ == "__main__":
    main()
