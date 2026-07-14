"""Real-CLI tests for the stdout/stderr contract."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

pytestmark = [pytest.mark.integration]


def _flat(output: str) -> str:
    """Normalize Rich output for substring assertions at narrow widths."""
    return " ".join(output.split())


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
    assert "[ERROR] No sync configuration found" in _flat(result.stderr)


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
    assert "No drift detected" in _flat(result.stdout)
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
    assert "Drift detected" in _flat(result.stdout)
    assert "Could not load schema" not in _flat(result.stdout)
    assert "[WARN] Could not load schema" in _flat(result.stderr)


def test_guard_usage_error_is_written_only_to_stderr(
    tmp_path: Path,
    envdrift_cmd: list[str],
    integration_env: dict[str, str],
) -> None:
    """Guard operational errors follow the human-diagnostic stream contract."""
    result = _run_envdrift(
        ["guard", "missing.env", "--native-only", "--no-auto-install"],
        tmp_path,
        envdrift_cmd,
        integration_env,
    )

    assert result.returncode == 6
    assert result.stdout == ""
    assert "Error: Path not found: missing.env" in _flat(result.stderr)


def test_guard_human_findings_report_stays_on_stdout(
    tmp_path: Path,
    envdrift_cmd: list[str],
    integration_env: dict[str, str],
) -> None:
    """Guard findings are product output, not diagnostics."""
    secret = "wJalrXUtnFEMI/" + "K7MDENG/bPxRfiCYEXAMPLEKEY"
    (tmp_path / "config.py").write_text(f'aws_secret_access_key = "{secret}"\n', encoding="utf-8")

    result = _run_envdrift(
        ["guard", "config.py", "--native-only", "--no-auto-install"],
        tmp_path,
        envdrift_cmd,
        integration_env,
    )

    assert result.returncode == 1
    assert "aws-secret-access-key" in _flat(result.stdout)
    assert result.stderr == ""


def test_guard_json_payload_stays_on_stdout(
    tmp_path: Path,
    envdrift_cmd: list[str],
    integration_env: dict[str, str],
) -> None:
    """Guard JSON remains a complete, parseable stdout document."""
    secret = "wJalrXUtnFEMI/" + "K7MDENG/bPxRfiCYEXAMPLEKEY"
    (tmp_path / "config.py").write_text(f'aws_secret_access_key = "{secret}"\n', encoding="utf-8")

    result = _run_envdrift(
        ["guard", "config.py", "--native-only", "--no-auto-install", "--json"],
        tmp_path,
        envdrift_cmd,
        integration_env,
    )

    payload = json.loads(result.stdout)
    assert result.returncode == 1
    assert payload["exit_code"] == 1
    assert any(finding["rule_id"] == "aws-secret-access-key" for finding in payload["findings"])
    assert result.stderr == ""
