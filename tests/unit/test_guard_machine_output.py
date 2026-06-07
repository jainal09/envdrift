"""Machine-readable output contract for the guard CLI (#413).

Focused on a single responsibility: ``guard``'s ``--json`` / ``--sarif`` output
must stay a valid machine-readable document on every exit path (error, empty,
early-exit) so a CI consumer that always parses guard stdout never trips over
human-readable prose or a Rich traceback.
"""

from __future__ import annotations

import json
import shutil
import subprocess

import pytest
from typer.testing import CliRunner

from envdrift.cli import app

runner = CliRunner()


def _init_empty_git_repo(path) -> None:
    """Initialise an empty git repo with no staged files at ``path``."""
    subprocess.run(["git", "init", "-q"], cwd=path, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=path, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=path, check=True)


def test_guard_missing_config_emits_json_error(tmp_path):
    """--json --config <missing> exits 1 with a JSON error, not a traceback.

    Uses the real load_config so a ConfigNotFoundError is raised at the real
    call site; the command must convert it to a clean ``{"error": ...}`` document
    on stdout instead of letting a Rich traceback contaminate machine output.
    """
    missing = tmp_path / "nope.toml"
    target = tmp_path / "a.env"
    target.write_text("FOO=bar\n")

    result = runner.invoke(
        app, ["guard", "--native-only", "--json", "--config", str(missing), str(target)]
    )
    assert result.exit_code == 1
    payload = json.loads(result.stdout)
    assert "error" in payload
    assert "Could not load config" in payload["error"]
    assert "Traceback" not in result.stdout


def test_guard_malformed_config_emits_json_error(tmp_path):
    """--json --config <malformed.toml> exits 1 with a JSON error."""
    bad = tmp_path / "envdrift.toml"
    bad.write_text("[guard\n")  # missing closing bracket -> TOMLDecodeError
    target = tmp_path / "a.env"
    target.write_text("FOO=bar\n")

    result = runner.invoke(
        app, ["guard", "--native-only", "--json", "--config", str(bad), str(target)]
    )
    assert result.exit_code == 1
    payload = json.loads(result.stdout)
    assert "error" in payload
    assert "Traceback" not in result.stdout


def test_guard_path_not_found_emits_json_error(tmp_path):
    """--json with a non-existent path emits a JSON error, not prose."""
    missing = tmp_path / "does-not-exist"

    result = runner.invoke(app, ["guard", "--native-only", "--json", str(missing)])
    assert result.exit_code == 1
    payload = json.loads(result.stdout)
    assert "error" in payload
    assert "Path not found" in payload["error"]


def test_guard_path_not_found_emits_valid_sarif(tmp_path):
    """--sarif with a non-existent path emits a schema-valid SARIF error doc.

    A SARIF consumer must receive ``executionSuccessful: false`` with an error
    notification, not a bare ``{"error": ...}`` object that fails SARIF schema
    validation (mirrors the empty/success SARIF path).
    """
    missing = tmp_path / "does-not-exist"

    result = runner.invoke(app, ["guard", "--native-only", "--sarif", str(missing)])
    assert result.exit_code == 1
    payload = json.loads(result.stdout)
    # Shaped like a SARIF document, not a bare error object.
    assert payload["version"] == "2.1.0"
    assert "error" not in payload
    invocation = payload["runs"][0]["invocations"][0]
    assert invocation["executionSuccessful"] is False
    notification = invocation["toolConfigurationNotifications"][0]
    assert notification["level"] == "error"
    assert "Path not found" in notification["message"]["text"]


@pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
def test_guard_staged_no_files_emits_empty_json(tmp_path, monkeypatch):
    """--json --staged with nothing staged emits valid empty-findings JSON.

    Drives a real empty git repo so the early-exit branch is exercised without
    mocking; previously this branch printed ``No staged files to scan.`` prose,
    breaking any consumer that always parses guard stdout as JSON.
    """
    _init_empty_git_repo(tmp_path)
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(app, ["guard", "--json", "--staged"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["findings"] == []
    assert payload["summary"]["total"] == 0
    assert "No staged files" not in result.stdout


@pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
def test_guard_staged_no_files_emits_valid_sarif(tmp_path, monkeypatch):
    """--sarif --staged with nothing staged emits a schema-valid empty SARIF doc."""
    _init_empty_git_repo(tmp_path)
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(app, ["guard", "--sarif", "--staged"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["version"] == "2.1.0"
    assert payload["runs"][0]["results"] == []
    assert "No staged files" not in result.stdout
