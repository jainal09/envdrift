"""Shared fixtures and helpers for the detect-secrets scanner tests."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from envdrift.scanner import detect_secrets as detect_secrets_module
from envdrift.scanner.detect_secrets import (
    _get_detect_secrets_version,
    _version_warnings,
)

# The real probe and warning builder, bound before ``no_version_probe`` replaces the module's.
REAL_VERSION_WARNINGS = _version_warnings
PINNED = _get_detect_secrets_version()


def installed_git_version() -> tuple[int, int] | None:
    """The ``(major, minor)`` of the git on PATH, None when it is missing or cannot be read."""
    try:
        output = subprocess.run(
            ["git", "--version"], capture_output=True, text=True, timeout=10
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    found = re.match(r"git version (\d+)\.(\d+)", output)
    return (int(found[1]), int(found[2])) if found else None


# ``GIT_CONFIG_COUNT``, which carries the ``core.quotepath`` setting into the git that
# detect-secrets runs, arrived in git 2.31: an older git ignores it, so a non-ASCII name stays
# quoted there and the file is reported, not scanned. A git that cannot be asked is taken to read it.
_GIT_VERSION = installed_git_version()
requires_git_config_env = pytest.mark.skipif(
    _GIT_VERSION is not None and _GIT_VERSION < (2, 31),
    reason="git before 2.31 ignores GIT_CONFIG_COUNT, which carries the core.quotepath setting",
)


@pytest.fixture(autouse=True)
def no_version_probe(monkeypatch: pytest.MonkeyPatch):
    """Keep the scan tests off the real ``--version`` probe, which would eat a mocked run.

    Tests of the version check itself call the real ``_version_warnings`` directly.
    """
    monkeypatch.setattr(detect_secrets_module, "_version_warnings", lambda: [])
    detect_secrets_module._installed_versions.clear()
    yield
    detect_secrets_module._installed_versions.clear()


def version_run(stdout: str = f"{PINNED}\n", returncode: int = 0, stderr: str = ""):
    return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)


def init_repo(path: Path) -> Path:
    """Make ``path`` a git repository and return it."""
    if shutil.which("git") is None:
        pytest.skip("git not available")
    subprocess.run(["git", "init", "-q"], cwd=path, check=True, capture_output=True)
    return path


def add_files(repo: Path, *names: str) -> None:
    """Create each file (a one-line placeholder) and ``git add`` it."""
    for name in names:
        file = repo / name
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text("x = 1\n")
    # A name is not a pathspec: ``:magic/app.cfg`` would otherwise be read as pathspec magic.
    subprocess.run(
        ["git", "--literal-pathspecs", "add", "--", *names],
        cwd=repo,
        check=True,
        capture_output=True,
    )


def fake_detect_secrets(report: dict[str, Any] | None = None, stderr: str = ""):
    """A ``subprocess.run`` that answers detect-secrets with ``report`` and runs git for real."""
    real_run = subprocess.run
    calls: list[tuple[list[str], dict[str, Any]]] = []

    def run(args: list[str], **kwargs: Any):
        if "detect_secrets" in args:
            calls.append((args, kwargs))
            return version_run(json.dumps(report or {"results": {}}), stderr=stderr)
        return real_run(args, **kwargs)

    return run, calls
