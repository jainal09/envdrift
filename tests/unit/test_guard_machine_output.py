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


def _stage_clean_file(path, name: str = "clean.env") -> None:
    """Write a secret-free file under ``path`` and ``git add`` it (staged)."""
    target = path / name
    # No secret-shaped values: guard must finish with an empty-findings doc so
    # the assertion isolates the success-path *progress* leak, not findings.
    target.write_text("HELLO=world\n")
    subprocess.run(["git", "add", name], cwd=path, check=True)


def _commit_pr_base_history(path) -> str:
    """Build a two-commit history with one changed file; return the base SHA.

    ``<base_sha>...HEAD`` then yields exactly one changed ``.env`` file, so the
    ``--pr-base`` success path (files present to scan) is exercised against a
    real git history. The changed file is secret-free so guard finishes with an
    empty-findings doc and the assertion isolates the progress-prose leak.
    """
    base = path / "base.env"
    base.write_text("BASE=1\n")
    subprocess.run(["git", "add", "base.env"], cwd=path, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "base"], cwd=path, check=True)
    base_sha = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=path, capture_output=True, text=True, check=True
    ).stdout.strip()
    changed = path / "changed.env"
    changed.write_text("HELLO=world\n")
    subprocess.run(["git", "add", "changed.env"], cwd=path, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "change"], cwd=path, check=True)
    return base_sha


def _assert_clean_json(result) -> None:
    """Assert ``result`` is a single parseable empty-findings JSON doc, exit 0.

    Shared success-path contract: ``json.loads`` of raw stdout must succeed (no
    progress prose leaking ahead of the JSON), findings are empty, and no
    ``Scanning ...`` sentence reached stdout (#413).
    """
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["findings"] == []
    assert "Scanning" not in result.stdout


def _assert_valid_sarif(result) -> None:
    """Assert ``result`` is a single schema-valid empty SARIF doc, exit 0.

    Shared success-path contract for ``--sarif`` (counterpart of
    :func:`_assert_clean_json`): SARIF ``version`` is present, the run has no
    results, and no ``Scanning ...`` prose leaked onto stdout (#413).
    """
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["version"] == "2.1.0"
    assert payload["runs"][0]["results"] == []
    assert "Scanning" not in result.stdout


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


def test_guard_human_error_preserves_bracketed_literal(tmp_path):
    """Human-mode error prose keeps bracketed literals intact (no Rich eating).

    The ``_emit_error`` human branch interpolates the dynamic ``message`` into
    Rich markup. A bracketed literal (e.g. a TOML section name like
    ``[vault.sync]`` embedded in a path) must be escaped so Rich renders it
    verbatim instead of interpreting it as a console tag and silently dropping
    it. Without ``rich.markup.escape`` the ``[vault.sync]`` segment vanishes
    from stdout; this asserts it survives.
    """
    missing = tmp_path / "[vault.sync].env"

    result = runner.invoke(app, ["guard", "--native-only", str(missing)])
    assert result.exit_code == 1
    # The bracketed literal must appear verbatim, not be swallowed as markup.
    # Rich falls back to an 80-col width under the non-tty CliRunner capture and
    # soft-wraps the path mid-string (inserting newlines), so a long tmp_path can
    # split the literal across lines -- normalize whitespace before asserting. The
    # behavior under test is markup-escaping (does "[vault.sync]" survive Rich?),
    # not line wrapping.
    normalized = "".join(result.stdout.split())
    assert "[vault.sync].env" in normalized


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


@pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
def test_guard_staged_with_files_emits_clean_json(tmp_path, monkeypatch):
    """--json --staged WITH a staged file emits a single parseable JSON doc.

    Exercises the success path (files present to scan), which previously printed
    ``Scanning N staged file(s)...`` to stdout ahead of the JSON, breaking
    ``guard --json --staged > out.json && jq . out.json``. ``json.loads`` of the
    raw stdout must succeed with no ``Scanning`` prose leaking onto stdout.
    """
    _init_empty_git_repo(tmp_path)
    _stage_clean_file(tmp_path)
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(app, ["guard", "--native-only", "--json", "--staged"])
    _assert_clean_json(result)


@pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
def test_guard_staged_with_files_emits_valid_sarif(tmp_path, monkeypatch):
    """--sarif --staged WITH a staged file emits a single schema-valid SARIF doc."""
    _init_empty_git_repo(tmp_path)
    _stage_clean_file(tmp_path)
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(app, ["guard", "--native-only", "--sarif", "--staged"])
    _assert_valid_sarif(result)


@pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
def test_guard_pr_base_with_files_emits_clean_json(tmp_path, monkeypatch):
    """--json --pr-base WITH changed files emits a single parseable JSON doc.

    Builds a real two-commit history so ``<base>...HEAD`` yields a changed file,
    exercising the ``--pr-base`` success path that previously printed
    ``Scanning N file(s) changed since ...`` to stdout ahead of the JSON.
    """
    _init_empty_git_repo(tmp_path)
    base_sha = _commit_pr_base_history(tmp_path)
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(app, ["guard", "--native-only", "--json", "--pr-base", base_sha])
    _assert_clean_json(result)


@pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
def test_guard_pr_base_with_files_emits_valid_sarif(tmp_path, monkeypatch):
    """--sarif --pr-base WITH changed files emits a single schema-valid SARIF doc."""
    _init_empty_git_repo(tmp_path)
    base_sha = _commit_pr_base_history(tmp_path)
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(app, ["guard", "--native-only", "--sarif", "--pr-base", base_sha])
    _assert_valid_sarif(result)
