"""Filesystem sandbox tests.

The sandbox is a real security boundary, so these tests are written as escape
attempts: traversal, absolute paths, symlinks, oversized reads, and binary
files. A path check on the raw string passes ``../../etc/passwd`` happily, which
is why the implementation resolves first and compares resolved paths.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from app.core.errors import ToolArgumentError, ToolNotFoundError
from app.tools.sources.filesystem import FilesystemSandbox, build_filesystem_source


@pytest.fixture
def sandbox(tmp_path: Path) -> FilesystemSandbox:
    root = tmp_path / "sandbox"
    root.mkdir()
    (root / "notes.md").write_text("policy notes\nsecond line\n", encoding="utf-8")
    (root / "sub").mkdir()
    (root / "sub" / "deep.md").write_text("deep content\n", encoding="utf-8")
    return FilesystemSandbox(root)


@pytest.fixture
def source(sandbox: FilesystemSandbox):
    return build_filesystem_source(sandbox)


# --- normal operation --------------------------------------------------------


def test_lists_and_reads_inside_the_sandbox(source, sandbox):
    listed = source.execute("fs_list", {"path": "."})
    assert {entry["name"] for entry in listed["entries"]} >= {"notes.md", "sub"}

    read = source.execute("fs_read", {"path": "notes.md"})
    assert read["content"].startswith("policy notes")
    assert read["bytes"] > 0


def test_reads_a_nested_file(source):
    assert "deep content" in source.execute("fs_read", {"path": "sub/deep.md"})["content"]


def test_search_reports_file_and_line(source):
    result = source.execute("fs_search", {"pattern": "second"})
    assert result["count"] == 1
    assert result["matches"][0]["path"] == "notes.md"
    assert result["matches"][0]["line"] == 2


# --- escape attempts ---------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        "../outside.txt",
        "../../etc/passwd",
        "sub/../../outside.txt",
        "sub/../../../etc/passwd",
        # A backslash separates path components only on Windows. On POSIX this is
        # one filename that happens not to exist -- a different refusal, and the
        # correct one -- so the case is asserted where it means something.
        pytest.param(
            "..\\..\\outside.txt",
            marks=pytest.mark.skipif(
                os.name != "nt", reason="backslash is not a path separator on POSIX"
            ),
        ),
    ],
)
def test_traversal_is_refused(source, path):
    with pytest.raises(ToolArgumentError, match="escapes the sandbox"):
        source.execute("fs_read", {"path": path})


def test_traversal_that_stays_inside_is_allowed(source, sandbox):
    """Traversal is only refused when it actually leaves the root.

    ``sub/../notes.md`` resolves back inside the sandbox, so it must work.
    Refusing it would break ordinary relative paths, and a sandbox that rejects
    legitimate input gets disabled by its users.
    """
    result = source.execute("fs_read", {"path": "sub/../notes.md"})
    assert "policy notes" in result["content"]


def test_absolute_path_outside_the_sandbox_is_refused(source, sandbox, tmp_path):
    outside = tmp_path / "outside.txt"
    outside.write_text("secret\n", encoding="utf-8")
    with pytest.raises(ToolArgumentError, match="escapes the sandbox"):
        source.execute("fs_read", {"path": str(outside)})


def test_symlink_escape_is_refused(source, sandbox, tmp_path):
    """A symlink inside the root pointing outside it must not be followed."""
    outside = tmp_path / "outside.txt"
    outside.write_text("secret\n", encoding="utf-8")
    link = sandbox.root / "link.md"
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are not permitted in this environment")

    with pytest.raises(ToolArgumentError, match="escapes the sandbox"):
        source.execute("fs_read", {"path": "link.md"})


def test_nul_byte_is_refused(source):
    with pytest.raises(ToolArgumentError, match="NUL"):
        source.execute("fs_read", {"path": "notes.md\x00.txt"})


def test_empty_path_is_refused(source):
    with pytest.raises(ToolArgumentError):
        source.execute("fs_read", {"path": ""})


def test_oversized_file_is_refused(tmp_path):
    root = tmp_path / "small"
    root.mkdir()
    (root / "big.txt").write_text("x" * 5000, encoding="utf-8")
    source = build_filesystem_source(FilesystemSandbox(root, max_bytes=1000))

    with pytest.raises(ToolArgumentError, match="above the .* byte limit"):
        source.execute("fs_read", {"path": "big.txt"})


def test_non_utf8_file_reports_a_tool_error_not_a_crash(tmp_path):
    from app.core.errors import ToolExecutionError

    root = tmp_path / "bin"
    root.mkdir()
    (root / "blob.bin").write_bytes(b"\xff\xfe\x00\x01\x02")
    source = build_filesystem_source(FilesystemSandbox(root))

    with pytest.raises(ToolExecutionError, match="not valid UTF-8"):
        source.execute("fs_read", {"path": "blob.bin"})


def test_directory_read_is_refused(source):
    with pytest.raises(ToolArgumentError, match="not a regular file"):
        source.execute("fs_read", {"path": "sub"})


def test_invalid_regex_is_reported_as_a_caller_error(source):
    with pytest.raises(ToolArgumentError, match="regular expression"):
        source.execute("fs_search", {"pattern": "([unclosed"})


def test_unknown_tool_name_is_not_found(source):
    with pytest.raises(ToolNotFoundError):
        source.execute("fs_delete_everything", {})


# --- the sandbox itself ------------------------------------------------------


def test_sandbox_root_is_created_when_missing(tmp_path):
    target = tmp_path / "does" / "not" / "exist"
    sandbox = FilesystemSandbox(target)
    assert sandbox.root.is_dir()
    assert sandbox.root == target.resolve()


def test_resolve_returns_paths_inside_the_root(sandbox):
    resolved = sandbox.resolve("sub/deep.md")
    assert resolved.is_relative_to(sandbox.root)
    assert sandbox.relative(resolved) == os.path.join("sub", "deep.md")


def test_descriptors_declare_provenance(source):
    assert {d.name for d in source.descriptors()} == {"fs_list", "fs_read", "fs_search"}
    assert all(d.source == "local:fs" for d in source.descriptors())
