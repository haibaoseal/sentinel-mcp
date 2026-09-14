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


def resolve_config_path(value: str) -> Path:
    """Resolve a configured path against the repository root.

    Absolute paths are honoured. A path that is only *accidentally* absolute --
    ``/sandbox`` or ``\\\\sandbox`` -- is treated as repository-relative, because that
    is what a config author almost certainly meant and silently reading ``C:\\\\sandbox``
    would be a confusing way to fail.
    """
    raw = value.strip()
    path = Path(raw).expanduser()
    if path.is_absolute():
        drive, tail = path.drive, str(path)[len(path.drive) :]
        if tail.startswith(("/", "\\")) and not drive:
            return (REPO_ROOT / tail.lstrip("/\\")).resolve()
        return path.resolve()
    return (REPO_ROOT / path).resolve()
