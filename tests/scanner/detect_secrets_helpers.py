"""Shared fixtures and helpers for the detect-secrets scanner tests."""

from __future__ import annotations

import json
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
    subprocess.run(["git", "add", "--", *names], cwd=repo, check=True, capture_output=True)


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
