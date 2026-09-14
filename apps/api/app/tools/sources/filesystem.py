"""Sandbox-confined filesystem tools.

Security note that shapes the whole module: every path is resolved and then
checked to be *inside* the configured sandbox root. Checks are performed on the
resolved path, not the raw string, which is what defeats ``..`` traversal and
symlink escape -- a string-prefix check on the raw input would pass
``../../etc/passwd`` happily.

The sandbox root is created if missing and is never the repository root unless
an operator explicitly configures it that way.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from app.core.errors import ToolArgumentError, ToolExecutionError
from app.tools.sources.local import LocalTool, LocalToolSource

DEFAULT_MAX_BYTES = 256 * 1024
MAX_LIST_ENTRIES = 500


class FilesystemSandbox:
    def __init__(self, root: Path | str, *, max_bytes: int = DEFAULT_MAX_BYTES) -> None:
        self.root = Path(root).expanduser().resolve()
        self.max_bytes = max_bytes
        self.root.mkdir(parents=True, exist_ok=True)

    def resolve(self, raw: str) -> Path:
        """Resolve a caller-supplied path inside the sandbox or refuse it."""
        if not isinstance(raw, str) or not raw.strip():
            raise ToolArgumentError("path must be a non-empty string")
        if "\x00" in raw:
            raise ToolArgumentError("path contains a NUL byte")

        # strict=False so the containment check is purely lexical and does not
        # depend on the target existing. If the check ran after an existence
        # test, a non-existent escaping path would be reported as "missing"
        # rather than as an escape attempt, which is both a worse error message
        # and a weaker boundary.
        candidate = (self.root / raw).resolve(strict=False)
        if candidate != self.root and not candidate.is_relative_to(self.root):
            # Deliberately report the *resolved* target so an operator reading
            # the audit log can see what was attempted.
            raise ToolArgumentError(f"path escapes the sandbox: {candidate}")
        return candidate

    def relative(self, path: Path) -> str:
        try:
            return str(path.relative_to(self.root))
        except ValueError:
            return str(path)


def build_filesystem_source(sandbox: FilesystemSandbox) -> LocalToolSource:
    def list_files(arguments: dict[str, Any]) -> dict[str, Any]:
        target = sandbox.resolve(str(arguments.get("path", ".")))
        if not target.exists():
            raise ToolArgumentError(f"path does not exist: {sandbox.relative(target)}")
        if not target.is_dir():
            raise ToolArgumentError(f"not a directory: {sandbox.relative(target)}")

        entries = []
        for child in sorted(target.iterdir())[:MAX_LIST_ENTRIES]:
            entries.append(
                {
                    "name": child.name,
                    "path": sandbox.relative(child),
                    "type": "dir" if child.is_dir() else "file",
                    "size": child.stat().st_size if child.is_file() else None,
                }
            )
        return {"path": sandbox.relative(target), "entries": entries, "count": len(entries)}

    def read_file(arguments: dict[str, Any]) -> dict[str, Any]:
        target = sandbox.resolve(str(arguments.get("path", "")))
        if not target.exists():
            raise ToolArgumentError(f"file does not exist: {sandbox.relative(target)}")
        if not target.is_file():
            raise ToolArgumentError(f"not a regular file: {sandbox.relative(target)}")

        size = target.stat().st_size
        if size > sandbox.max_bytes:
            raise ToolArgumentError(
                f"file is {size} bytes, above the {sandbox.max_bytes} byte limit"
            )
        try:
            content = target.read_text(encoding="utf-8")
        except UnicodeDecodeError as exc:
            raise ToolExecutionError("file is not valid UTF-8 text") from exc
        return {
            "path": sandbox.relative(target),
            "content": content,
            "bytes": size,
            "truncated": False,
        }

    def search_files(arguments: dict[str, Any]) -> dict[str, Any]:
        pattern = str(arguments.get("pattern", "")).strip()
        if not pattern:
            raise ToolArgumentError("pattern must be a non-empty string")
        if len(pattern) > 200:
            raise ToolArgumentError("pattern is too long")
        try:
            compiled = re.compile(pattern, re.IGNORECASE)
        except re.error as exc:
            raise ToolArgumentError(f"pattern is not a valid regular expression: {exc}") from exc

        start = sandbox.resolve(str(arguments.get("path", ".")))
        if not start.is_dir():
            raise ToolArgumentError(f"not a directory: {sandbox.relative(start)}")

        matches: list[dict[str, Any]] = []
        scanned = 0
        for candidate in sorted(start.rglob("*")):
            if len(matches) >= 100:
                break
            if not candidate.is_file() or candidate.stat().st_size > sandbox.max_bytes:
                continue
            scanned += 1
            try:
                text = candidate.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue
            for number, line in enumerate(text.splitlines(), start=1):
                if compiled.search(line):
                    matches.append(
                        {
                            "path": sandbox.relative(candidate),
                            "line": number,
                            "text": line[:300],
                        }
                    )
                    if len(matches) >= 100:
                        break
        return {
            "pattern": pattern,
            "matches": matches,
            "count": len(matches),
            "files_scanned": scanned,
        }

    return LocalToolSource(
        [
            LocalTool(
                name="fs_list",
                run=list_files,
                description="List files and directories inside the tool sandbox.",
                action_type="read",
                resource_type="file",
                risk_level="low",
                parameters={
                    "type": "object",
                    "properties": {"path": {"type": "string", "default": "."}},
                    "additionalProperties": False,
                },
            ),
            LocalTool(
                name="fs_read",
                run=read_file,
                description="Read a UTF-8 text file inside the tool sandbox.",
                action_type="read",
                resource_type="file",
                risk_level="medium",
                parameters={
                    "type": "object",
                    "properties": {"path": {"type": "string"}},
                    "required": ["path"],
                    "additionalProperties": False,
                },
            ),
            LocalTool(
                name="fs_search",
                run=search_files,
                description="Search file contents inside the sandbox with a regular expression.",
                action_type="read",
                resource_type="file",
                risk_level="low",
                parameters={
                    "type": "object",
                    "properties": {
                        "pattern": {"type": "string"},
                        "path": {"type": "string", "default": "."},
                    },
                    "required": ["pattern"],
                    "additionalProperties": False,
                },
            ),
        ],
        name="local:fs",
    )
