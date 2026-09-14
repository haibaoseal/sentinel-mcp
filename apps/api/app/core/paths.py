"""Repository-relative paths.

One definition, because two independent guesses is how the knowledge base silently
failed to load: ``config.py`` computed the repository root as ``parents[3]`` (which
is ``apps/``) while the evaluation module computed ``parents[4]`` for the same
directory. The first was wrong, the registry came back without a knowledge source,
and the only symptom was an agent that answered every policy question with "no
actionable steps".

``parents[4]`` from ``apps/api/app/core/paths.py`` is the repository root:
``core`` -> ``app`` -> ``api`` -> ``apps`` -> repository.
"""

from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[4]

KNOWLEDGE_DIR = REPO_ROOT / "knowledge"
SANDBOX_DIR = REPO_ROOT / "sandbox"
EVALS_DIR = REPO_ROOT / "evals"
SCENARIOS_FILE = EVALS_DIR / "scenarios.json"
BASELINE_FILE = EVALS_DIR / "baseline.json"


def is_accidentally_absolute(path: Path) -> bool:
    """Whether an absolute path is a bare root such as ``/sandbox``.

    A single-component rooted path is what a config author usually means as
    repository-relative: on Windows ``/sandbox`` reads as ``C:\\sandbox``, which
    nobody intends, and the module docstring's examples are exactly this shape.
    Anything deeper is honoured as written. Reading ``/tmp/pytest-0/knowledge`` as
    ``<repo>/tmp/pytest-0/knowledge`` is how a knowledge root silently disappeared
    -- the knowledge source was never registered and every policy question came back
    with "no actionable steps", which is the failure this module exists to prevent.
    """
    if path.drive or not path.root:
        return False
    return len([part for part in path.parts if part not in ("/", "\\")]) == 1


def resolve_config_path(value: str) -> Path:
    """Resolve a configured path against the repository root.

    An absolute path is honoured unless it is a bare root (see
    ``is_accidentally_absolute``), in which case it is read as repository-relative.
    A relative path is always repository-relative, which is what ``./sandbox`` in
    ``.env.example`` means.
    """
    raw = value.strip()
    path = Path(raw).expanduser()
    if path.is_absolute():
        if is_accidentally_absolute(path):
            return (REPO_ROOT / str(path).lstrip("/\\")).resolve()
        return path.resolve()
    return (REPO_ROOT / path).resolve()
