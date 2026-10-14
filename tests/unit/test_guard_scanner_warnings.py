"""A non-fatal scanner warning reaches every output mode of ``envdrift guard``.

The detect-secrets version check is the first user: when the installed package is not the
pinned version its severities may be inaccurate. The scan still ran and its findings
stand, so the warning is shown (human panel, ``--json``, ``--sarif``, and on stderr in the
machine modes) without changing the exit code. Only the engine's *result* is stubbed, the
input of the CLI behaviour under test; the formatting and the exit code are the real ones.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from envdrift.cli import app
from envdrift.config import EnvdriftConfig
from envdrift.scanner.base import (
    AggregatedScanResult,
    FindingSeverity,
    ScanFinding,
    ScanResult,
)
from envdrift.utils.text import strip_ansi

runner = CliRunner()

WARNING = (
    "The installed version is 1.4.0, but envdrift grades findings against version 1.5.0. "
    "Another version can rename or add detectors, so severities may be inaccurate. "
    "Install the pinned version: pip install detect-secrets==1.5.0"
)


def _result(*, findings: list[ScanFinding] | None = None, error: str | None = None):
    found = findings or []
    results = [
        ScanResult(scanner_name="native", files_scanned=1),
        ScanResult(scanner_name="detect-secrets", findings=found, error=error, warnings=[WARNING]),
    ]
    return AggregatedScanResult(
        results=results,
        total_findings=len(found),
        unique_findings=found,
        scanners_used=["native", "detect-secrets"],
        total_duration_ms=5,
    )


def _patch_engine(monkeypatch: pytest.MonkeyPatch, result: AggregatedScanResult) -> None:
    class DummyScanner:
        def __init__(self, name: str):
            self.name = name

    class DummyEngine:
        def __init__(self, _guard_config):
            self.scanners = [DummyScanner(r.scanner_name) for r in result.results]

        def get_scanner_info(self):
            return []

        def scan(self, _paths, on_scanner_complete=None):
            return result

        def check_combined_files_security(self):
            return []

    monkeypatch.setattr("envdrift.cli_commands.guard.load_config", lambda _p=None: EnvdriftConfig())
    monkeypatch.setattr("envdrift.cli_commands.guard.ScanEngine", DummyEngine)


def _finding(severity: FindingSeverity) -> ScanFinding:
    return ScanFinding(
        file_path=Path("config.py"),
        line_number=1,
        rule_id="detect-secrets-private-key",
        rule_description="Private Key",
        description="Secret detected by Private Key",
        severity=severity,
        scanner="detect-secrets",
    )


def _flat(text: str) -> str:
    """Panel text without its borders, colour escapes (FORCE_COLOR) and line wraps."""
    return " ".join(strip_ansi(text).replace("│", " ").split())


def test_json_output_carries_the_warning_and_stays_clean(tmp_path: Path, monkeypatch):
    _patch_engine(monkeypatch, _result())

    result = runner.invoke(app, ["guard", str(tmp_path), "--json"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)  # stdout stays a parseable document
    detect_secrets = next(r for r in payload["scanner_results"] if r["name"] == "detect-secrets")
    assert detect_secrets["warnings"] == [WARNING]
    assert detect_secrets["error"] is None
    assert payload["exit_code"] == 0
    assert payload["has_blocking_findings"] is False


def test_json_output_repeats_the_warning_on_stderr(tmp_path: Path, monkeypatch):
    """stdout is usually redirected to a file; stderr keeps the warning in the CI log."""
    _patch_engine(monkeypatch, _result())

    result = runner.invoke(app, ["guard", str(tmp_path), "--json"])

    assert result.exit_code == 0, result.output
    assert f"Warning: detect-secrets: {WARNING}" in result.stderr


def test_sarif_output_carries_the_warning_and_stays_clean(tmp_path: Path, monkeypatch):
    _patch_engine(monkeypatch, _result())

    result = runner.invoke(app, ["guard", str(tmp_path), "--sarif"])

    assert result.exit_code == 0, result.output
    invocation = json.loads(result.stdout)["runs"][0]["invocations"][0]
    assert invocation["executionSuccessful"] is True
    assert invocation["exitCode"] == 0
    assert invocation["toolExecutionNotifications"] == [
        {"level": "warning", "message": {"text": f"detect-secrets: {WARNING}"}}
    ]
    assert f"Warning: detect-secrets: {WARNING}" in result.stderr


def test_human_output_shows_the_warning_in_a_panel_and_not_on_stderr(tmp_path: Path, monkeypatch):
    _patch_engine(monkeypatch, _result())

    result = runner.invoke(app, ["guard", str(tmp_path)])

    assert result.exit_code == 0, result.output
    output = _flat(result.stdout)
    assert "Scanner Warnings" in output
    assert "The installed version is 1.4.0" in output
    assert "pip install detect-secrets==1.5.0" in output
    assert "No secrets or policy violations detected" in output
    # The panel is the human surface; stderr is only for the machine modes.
    assert "Warning:" not in result.stderr


def test_the_warning_never_changes_the_exit_code(tmp_path: Path, monkeypatch):
    """Findings decide the verdict, as without the warning."""
    _patch_engine(monkeypatch, _result(findings=[_finding(FindingSeverity.CRITICAL)]))

    plain = runner.invoke(app, ["guard", str(tmp_path), "--json"])
    ci = runner.invoke(app, ["guard", str(tmp_path), "--json", "--ci", "--fail-on", "critical"])

    assert plain.exit_code == 1
    assert ci.exit_code == 1
    assert json.loads(ci.stdout)["exit_code"] == 1


def test_a_warned_scan_that_failed_still_exits_scan_error(tmp_path: Path, monkeypatch):
    _patch_engine(monkeypatch, _result(error="boom"))

    result = runner.invoke(app, ["guard", str(tmp_path), "--json"])

    assert result.exit_code == 5
    payload = json.loads(result.stdout)
    detect_secrets = next(r for r in payload["scanner_results"] if r["name"] == "detect-secrets")
    assert detect_secrets["error"] == "boom"
    assert detect_secrets["warnings"] == [WARNING]


def test_a_run_without_warnings_prints_none(tmp_path: Path, monkeypatch):
    clean = AggregatedScanResult(
        results=[ScanResult(scanner_name="native", files_scanned=1)],
        total_findings=0,
        unique_findings=[],
        scanners_used=["native"],
        total_duration_ms=5,
    )
    _patch_engine(monkeypatch, clean)

    machine = runner.invoke(app, ["guard", str(tmp_path), "--json"])
    human = runner.invoke(app, ["guard", str(tmp_path)])

    assert machine.exit_code == 0, machine.output
    assert human.exit_code == 0, human.output
    assert "Warning:" not in machine.stderr
    assert json.loads(machine.stdout)["scanner_results"][0]["warnings"] == []
    assert "Scanner Warnings" not in human.stdout


def test_a_warning_with_colour_escapes_reaches_stderr_as_plain_text(tmp_path: Path, monkeypatch):
    """The text of a warning can come from a tool's output (an unreadable version probe).

    The JSON and SARIF documents and the panel strip terminal escapes; stderr must too, or a
    CI log would carry them.
    """
    dirty = "\x1b[31mcould not read\x1b[0m the version"
    scanned = AggregatedScanResult(
        results=[ScanResult(scanner_name="detect-secrets", files_scanned=1, warnings=[dirty])],
        total_findings=0,
        unique_findings=[],
        scanners_used=["detect-secrets"],
        total_duration_ms=5,
    )
    _patch_engine(monkeypatch, scanned)

    result = runner.invoke(app, ["guard", str(tmp_path), "--json"])

    assert result.exit_code == 0, result.output
    assert "\x1b" not in result.stderr
    assert "Warning: detect-secrets: could not read the version" in result.stderr
    assert json.loads(result.stdout)["scanner_results"][0]["warnings"] == [
        "could not read the version"
    ]
