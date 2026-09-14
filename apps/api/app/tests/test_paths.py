"""Path resolution, because getting it wrong fails silently.

A multi-component absolute path used to be treated as repository-relative, so a
``/tmp/pytest-0/knowledge`` root resolved to ``<repo>/tmp/pytest-0/knowledge``.
The knowledge source was never registered, and the only symptom was an agent
answering every policy question with "no actionable steps" -- the failure this
module's own docstring warns about. CI on Linux caught it, which is the reason the
suite runs on two platforms.
"""

from __future__ import annotations

from pathlib import Path

from app.core.paths import REPO_ROOT, is_accidentally_absolute, resolve_config_path


def test_a_relative_path_resolves_against_the_repository_root():
    assert resolve_config_path("knowledge") == REPO_ROOT / "knowledge"


def test_a_multi_component_absolute_path_is_honoured():
    """The case that broke CI: a real absolute path must not be folded back in."""

    resolved = resolve_config_path("/tmp/pytest-0/knowledge")

    assert resolved.name == "knowledge"
    assert "pytest-0" in str(resolved)
    assert not str(resolved).startswith(str(REPO_ROOT))


def test_only_a_bare_root_counts_as_accidentally_absolute():
    assert is_accidentally_absolute(Path("/sandbox")) is True
    assert is_accidentally_absolute(Path("/tmp/pytest-0/knowledge")) is False
    assert is_accidentally_absolute(Path("sandbox")) is False


def test_a_drive_letter_is_never_accidental():
    assert is_accidentally_absolute(Path("C:/sandbox")) is False
    assert resolve_config_path("C:/sandbox").name == "sandbox"
