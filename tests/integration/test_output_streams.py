"""Real-CLI tests for the stdout/stderr contract."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

pytestmark = [pytest.mark.integration]


def _run_envdrift(
    args: list[str],
    cwd: Path,
    envdrift_cmd: list[str],
    integration_env: dict[str, str],
) -> subprocess.CompletedProcess[str]:
    """Run the installed envdrift entry point with both streams captured."""
    return subprocess.run(
        [*envdrift_cmd, *args],
        cwd=cwd,
        env=integration_env,
        capture_output=True,
        text=True,
        timeout=30,
    )


def test_human_error_is_written_only_to_stderr(
    tmp_path: Path,
    envdrift_cmd: list[str],
    integration_env: dict[str, str],
) -> None:
    """#654: human errors follow the Unix stderr convention."""
    result = _run_envdrift(
        ["sync", "--verify", "--provider", "azur"],
        tmp_path,
        envdrift_cmd,
        integration_env,
    )

    assert result.returncode == 1
    assert result.stdout == ""
    assert "[ERROR] No sync configuration found" in result.stderr


def test_successful_diff_keeps_stderr_quiet(
    tmp_path: Path,
    envdrift_cmd: list[str],
    integration_env: dict[str, str],
) -> None:
    """A happy-path diff can have stdout redirected without exposing diagnostics."""
    (tmp_path / "a.env").write_text("VALUE=same\n", encoding="utf-8")
    (tmp_path / "b.env").write_text("VALUE=same\n", encoding="utf-8")

    result = _run_envdrift(
        ["diff", "a.env", "b.env"],
        tmp_path,
        envdrift_cmd,
        integration_env,
    )

    assert result.returncode == 0
    assert "No drift detected" in result.stdout
    assert result.stderr == ""


def test_human_warning_is_written_only_to_stderr(
    tmp_path: Path,
    envdrift_cmd: list[str],
    integration_env: dict[str, str],
) -> None:
    """Human warnings stay visible without contaminating a command result."""
    (tmp_path / "a.env").write_text("VALUE=one\n", encoding="utf-8")
    (tmp_path / "b.env").write_text("VALUE=two\n", encoding="utf-8")

    result = _run_envdrift(
        ["diff", "a.env", "b.env", "--schema", "missing.module:Settings"],
        tmp_path,
        envdrift_cmd,
        integration_env,
    )

    assert result.returncode == 0
    assert "Drift detected" in result.stdout
    assert "Could not load schema" not in result.stdout
    assert "[WARN] Could not load schema" in result.stderr
