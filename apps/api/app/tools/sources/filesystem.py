"""Sandbox-confined filesystem tools.

Security note that shapes the whole module: every path is resolved and then
checked to be *inside* the configured sandbox root. Checks are performed on the
resolved path, not the raw string, which is what defeats ``..`` traversal and
symlink escape -- a string-prefix check on the raw input would pass
``../../etc/passwd`` happily.

Every entry point goes through ``FilesystemSandbox.check``, including each file
``fs_search`` walks. It did not, and that was a real escape: a directory junction
inside the sandbox (``mklink /J``, no privilege needed on Windows) was followed by
the walk, so ``fs_read`` and ``fs_list`` refused a path while ``fs_search``
returned the contents behind it. Directory entries that are symlinks, junctions or
any other reparse point are now skipped and reported rather than followed, and
every candidate is re-checked before it is opened.

The sandbox root is created if missing and is never the repository root unless an
operator explicitly configures it that way.
"""

from __future__ import annotations

import os
import re
import stat
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from app.core.errors import ToolArgumentError, ToolExecutionError
from app.tools.sources.local import LocalTool, LocalToolSource

DEFAULT_MAX_BYTES = 256 * 1024
MAX_LIST_ENTRIES = 500
MAX_FILES_SCANNED = 2000
MAX_MATCHES = 100


def is_link_like(path: Path) -> bool:
    """True for a symlink, a Windows junction, or any other reparse point.

    ``Path.is_symlink()`` is not enough on Windows: a junction is a reparse point
    that Python does not treat as a symlink, and ``rglob`` follows it. Inspection
    failure counts as link-like, so an entry that cannot be examined is skipped
    rather than followed.
    """
    try:
        info = path.lstat()
    except OSError:
        return True
    if path.is_symlink():
        return True
    attributes = getattr(info, "st_file_attributes", 0)
    return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))


def read_text_without_following_links(path: Path) -> str:
    """Read a file, refusing to follow a final-component symlink where the OS can.

    The path was resolved and checked a moment ago; this closes the window in which
    the named file could be swapped for a link pointing outside the sandbox.
    ``O_NOFOLLOW`` does not exist on Windows, so there the check is the resolved
    path alone. Intermediate directories are still resolved-then-opened on every
    platform, which the README lists as a limitation rather than hiding it.
    """
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, encoding="utf-8") as handle:
        return handle.read()


class FilesystemSandbox:
    def __init__(self, root: Path | str, *, max_bytes: int = DEFAULT_MAX_BYTES) -> None:
        self.root = Path(root).expanduser().resolve()
        self.max_bytes = max_bytes
        self.root.mkdir(parents=True, exist_ok=True)

    def check(self, path: Path) -> Path:
        """Resolve a path and refuse it if it lands outside the sandbox.

        The single containment predicate. ``resolve(strict=False)`` keeps the check
        purely lexical, so containment does not depend on the target existing: an
        existence test first would report a non-existent escape attempt as
        "missing", which is both a worse message and a weaker boundary.
        """
        resolved = Path(path).resolve(strict=False)
        if resolved != self.root and not resolved.is_relative_to(self.root):
            # Deliberately report the *resolved* target so an operator reading
            # the audit log can see what was attempted.
            raise ToolArgumentError(f"path escapes the sandbox: {resolved}")
        return resolved

    def resolve(self, raw: str) -> Path:
        """Resolve a caller-supplied path inside the sandbox or refuse it."""
        if not isinstance(raw, str) or not raw.strip():
            raise ToolArgumentError("path must be a non-empty string")
        if "\x00" in raw:
            raise ToolArgumentError("path contains a NUL byte")
        return self.check(self.root / raw)

    def walk(self, start: Path) -> tuple[Iterator[Path], list[str]]:
        """Walk ``start`` without following links, collecting skipped entries.

        The returned list grows as the iterator is consumed, and each yielded path
        has already been re-checked for containment.
        """
        skipped: list[str] = []

        def files() -> Iterator[Path]:
            stack = [start]
            while stack:
                current = stack.pop()
                try:
                    children = sorted(current.iterdir())
                except OSError:
                    continue
                for child in children:
                    if is_link_like(child):
                        skipped.append(self.relative(child))
                        continue
                    if child.is_dir():
                        stack.append(child)
                        continue
                    try:
                        yield self.check(child)
                    except ToolArgumentError:
                        # A candidate that resolves outside is skipped and named,
                        # never opened. Reaching this needs a filesystem the plain
                        # listing misrepresents -- a bind mount, a short name, or a
                        # swap between listing and resolve.
                        skipped.append(self.relative(child))

        return files(), skipped

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
            content = read_text_without_following_links(target)
        except UnicodeDecodeError as exc:
            raise ToolExecutionError("file is not valid UTF-8 text") from exc
        except OSError as exc:
            raise ToolExecutionError(f"could not read the file: {exc}") from exc
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
        truncated = False
        candidates, skipped = sandbox.walk(start)
        for candidate in candidates:
            if len(matches) >= MAX_MATCHES or scanned >= MAX_FILES_SCANNED:
                truncated = True
                break
            try:
                if not candidate.is_file() or candidate.stat().st_size > sandbox.max_bytes:
                    continue
            except OSError:
                continue
            scanned += 1
            try:
                text = read_text_without_following_links(candidate)
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
                    if len(matches) >= MAX_MATCHES:
                        break
        return {
            "pattern": pattern,
            "matches": matches,
            "count": len(matches),
            "files_scanned": scanned,
            # Named rather than silently dropped: a skipped entry means something in
            # the tree is a link or resolves outside the sandbox, which is worth a
            # reviewer looking at even though nothing was read through it.
            "skipped": skipped,
            "truncated": truncated,
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
